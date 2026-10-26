"""Link safety: reputation checks, domain tiers and the sandboxed fetcher.

This is the ONLY network path for outbound page/feed URLs (keyed APIs go through
api_client.py). Every URL, and every redirect hop, is checked before it is fetched or
alerted on:

  1. URL shape: http/https only, no credentials, default ports only.
  2. Lookalikes: IDN/punycode hosts and close imitations of official domains -> BLOCK.
     Other brand-containing domains -> LOOKALIKE? flag (review, never block).
  3. domain_tiers: BLOCKED is never fetched; PLATFORM is never trusted.
  4. Google Safe Browsing: a match blocks that URL; an UNKNOWN domain is also added as
     BLOCKED. Service down -> UNKNOWN (fail closed).
  5. Domain age via RDAP: younger than 30 days -> NEW DOMAIN flag.

The fetcher resolves DNS once, refuses non-public addresses (SSRF) and connects to the
vetted IP itself (no second lookup, so DNS rebinding can't swap in a private address),
re-checks each redirect hop (max 5), follows robots.txt per RFC 9309 and a per-host
interval, sends no cookies or auth, reads at most 2 MB, and only accepts HTML / feeds /
JSON (text/plain and octet-stream only for feed URLs from config/sources.yaml).

Every block writes a filtered_items row. Every fetch attempt writes a fetch_log row.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urldefrag, urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpcore
import httpx

from radar import store
from radar.api_client import (
    USER_AGENT,
    ApiClient,
    GoogleSafeBrowsing,
    NoCookieJar,
    RdapDomainAge,
    ReputationUnavailable,
)
from radar.config import CONFIG_DIR, load_yaml
from radar.domains import domain_label, host_chain, normalize_host, registrable_domain

ROBOTS_AGENT = "GiveawayRadarBot"
ROBOTS_MAX_CHARS = 500 * 1024  # RFC 9309: parse at least 500 KiB

MAX_REDIRECTS = 5
TIMEOUT_S = 10.0
MAX_BYTES = 2 * 1024 * 1024
NEW_DOMAIN_DAYS = 30
ALLOWED_PORTS = (None, 80, 443)
REDIRECT_CODES = (301, 302, 303, 307, 308)

ALLOWED_TYPES = frozenset({
    "text/html",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/xml",
    "text/xml",
    "application/json",
})
FEED_ONLY_TYPES = frozenset({"text/plain", "application/octet-stream"})

# Warning badges shown on alerts and queue items.
NEW_DOMAIN = "NEW DOMAIN"
LOOKALIKE = "LOOKALIKE?"
NOT_TRUSTED = "NOT TRUSTED"


# --- errors -----------------------------------------------------------------------------


class GuardError(Exception):
    pass


class Blocked(GuardError):
    """A guardrail refused this URL. Always recorded in filtered_items."""

    def __init__(
        self, url: str, rule: str, reason: str, *, domain: str | None = None,
        tier: str | None = None,
    ) -> None:
        super().__init__(f"{rule}: {reason}")
        self.url, self.rule, self.reason = url, rule, reason
        self.domain, self.tier = domain, tier


class FetchFailed(GuardError):
    """Network problem (DNS, timeout, connection). Not a guardrail decision."""


# --- reputation service interfaces (real clients live in api_client.py) -----------------


class SafeBrowsing(Protocol):
    def is_unsafe(self, url: str) -> bool:
        """True on a match. Raises ReputationUnavailable when the service is down."""
        ...


class DomainAge(Protocol):
    def registered_at(self, domain: str) -> datetime | None:
        """Registration date, None if the registry has none. Raises ReputationUnavailable."""
        ...


Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


# --- DNS pinning transport ----------------------------------------------------------------


class PinnedBackend(httpcore.SyncBackend):
    """Connects only to IPs that url_guard resolved and vetted for that host.

    Never performs its own DNS lookup. TLS SNI and certificate checks still use the
    hostname: httpcore takes server_hostname from the request origin, not from here.
    """

    def __init__(self, pins: dict[str, list[str]]) -> None:
        super().__init__()
        self._pins = pins

    def connect_tcp(
        self, host: str, port: int, timeout: float | None = None,
        local_address: str | None = None, socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        ips = self._pins.get(normalize_host(host).strip("[]"))
        if not ips:
            raise httpcore.ConnectError(f"refusing to connect: {host} was not vetted")
        error: Exception | None = None
        for ip in ips:
            if not is_public_ip(ipaddress.ip_address(ip)):  # defence in depth
                raise httpcore.ConnectError(f"refusing to connect to non-public {ip}")
            try:
                return self.open_tcp(ip, port, timeout, local_address, socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                error = exc
        raise error or httpcore.ConnectError("no address to connect to")

    def open_tcp(
        self, ip: str, port: int, timeout: float | None, local_address: str | None,
        socket_options: Any,
    ) -> httpcore.NetworkStream:
        return super().connect_tcp(ip, port, timeout, local_address, socket_options)


@contextmanager
def _map_core_errors(request: httpx.Request) -> Iterator[None]:
    try:
        yield
    except httpcore.TimeoutException as exc:
        raise httpx.TimeoutException(str(exc), request=request) from exc
    except (httpcore.NetworkError, httpcore.ProtocolError, httpcore.UnsupportedProtocol,
            httpcore.ProxyError) as exc:
        raise httpx.TransportError(str(exc), request=request) from exc


class _CoreStream(httpx.SyncByteStream):
    def __init__(self, response: httpcore.Response, request: httpx.Request) -> None:
        self._response = response
        self._request = request

    def __iter__(self) -> Iterator[bytes]:
        with _map_core_errors(self._request):
            yield from self._response.iter_stream()

    def close(self) -> None:
        self._response.close()


class PinnedTransport(httpx.BaseTransport):
    """httpx transport over an httpcore pool whose backend is PinnedBackend."""

    def __init__(self, pins: dict[str, list[str]], backend: PinnedBackend | None = None) -> None:
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(),
            network_backend=backend or PinnedBackend(pins),
            retries=0,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with _map_core_errors(request):
            response = self._pool.handle_request(core_request)
        return httpx.Response(response.status, headers=response.headers,
                              stream=_CoreStream(response, request),
                              extensions=response.extensions)

    def close(self) -> None:
        self._pool.close()


# --- config and results -----------------------------------------------------------------


@dataclass(frozen=True)
class GuardConfig:
    official_domains: frozenset[str]
    deceptive_affixes: tuple[str, ...]
    brand_names: tuple[str, ...]
    platform_domains: frozenset[str]
    feed_urls: frozenset[str]
    min_host_interval_s: float = 5.0

    @classmethod
    def load(cls, config_dir: Path = CONFIG_DIR) -> GuardConfig:
        names = load_yaml("protected_names.yaml", config_dir)
        domains = load_yaml("domains.yaml", config_dir).get("domains") or []
        sources = load_yaml("sources.yaml", config_dir)
        limits = sources.get("rate_limits") or {}
        return cls(
            official_domains=frozenset(
                normalize_host(d) for d in names.get("official_domains") or []
            ),
            deceptive_affixes=tuple(a.lower() for a in names.get("deceptive_affixes") or []),
            brand_names=tuple(b.lower() for b in names.get("brand_names") or []),
            platform_domains=frozenset(
                normalize_host(d["domain"]) for d in domains if d.get("tier") == "PLATFORM"
            ),
            feed_urls=frozenset(f["url"] for f in sources.get("feeds") or []),
            min_host_interval_s=float(limits.get("per_host_min_interval_seconds", 5)),
        )


@dataclass
class GuardResult:
    url: str
    host: str
    domain: str
    tier: str  # TRUSTED / PLATFORM / LINK_HUB / UNKNOWN
    flags: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    domain_age_days: int | None = None

    @property
    def trusted(self) -> bool:
        """Only a TRUSTED domain with no warning flags. PLATFORM is never trusted."""
        return self.tier == "TRUSTED" and not self.flags


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    content_type: str
    body: bytes
    truncated: bool
    guard: GuardResult
    hops: list[str]

    def text(self) -> str:
        m = re.search(r"charset=[\"']?([\w.-]+)", self.content_type, re.I)
        try:
            return self.body.decode(m.group(1) if m else "utf-8", errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


# --- helpers ----------------------------------------------------------------------------


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_idn(host: str) -> bool:
    return any(ord(c) > 127 for c in host) or any(
        label.startswith("xn--") for label in host.split(".")
    )


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is not None and not is_public_ip(embedded):
            return False
    return ip.is_global and not ip.is_multicast


def _media_type(content_type: str) -> str:
    return content_type.split(";", 1)[0].strip().lower()


# --- the guard --------------------------------------------------------------------------


class UrlGuard:
    """One instance per run. Holds per-run state: DNS pins, robots rules, host timers."""

    def __init__(
        self,
        conn: Any,
        config: GuardConfig,
        *,
        safe_browsing: SafeBrowsing,
        domain_age: DomainAge,
        resolver: Resolver = system_resolver,
        transport: httpx.BaseTransport | None = None,
        backend_cls: type[PinnedBackend] = PinnedBackend,
        clock: Callable[[], datetime] = store.utcnow,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._conn = conn
        self.config = config
        self._sb = safe_browsing
        self._age = domain_age
        self._resolver = resolver
        self._clock = clock
        self._sleep = sleep
        self._monotonic = monotonic
        self._pins: dict[str, list[str]] = {}
        self._robots: dict[str, RobotFileParser] = {}
        self._last_request: dict[str, float] = {}
        self._owned: list[Any] = []
        if transport is None:
            # Production path: connect only to the IPs _vet_dns pinned for each host.
            transport = PinnedTransport(self._pins, backend=backend_cls(self._pins))
        self._client = httpx.Client(
            transport=transport,
            follow_redirects=False,
            trust_env=False,  # no proxies or .netrc credentials from the environment
            timeout=httpx.Timeout(TIMEOUT_S),
            cookies=NoCookieJar(),
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
        )

    @classmethod
    def from_env(cls, conn: Any, config: GuardConfig | None = None) -> UrlGuard:
        """Production guard. Needs SAFE_BROWSING_API_KEY (MissingConfigError if unset)."""
        api = ApiClient()
        try:
            sb = GoogleSafeBrowsing(api)
        except Exception:
            api.close()
            raise
        guard = cls(conn, config or GuardConfig.load(), safe_browsing=sb,
                    domain_age=RdapDomainAge(api))
        guard._owned.append(api)
        return guard

    def close(self) -> None:
        self._client.close()
        for resource in self._owned:
            resource.close()

    # --- checks -------------------------------------------------------------------------

    def check(self, url: str) -> GuardResult:
        """Check a URL without fetching it (e.g. before alerting). Raises Blocked."""
        try:
            return self._evaluate(url)
        except Blocked as b:
            store.record_filtered(self._conn, b.url, b.rule, b.reason)
            raise

    def lookalike_block_reason(self, host: str) -> str | None:
        """Why `host` is a hard lookalike of an official domain, else None."""
        domain = registrable_domain(host)
        if domain in self.config.official_domains:
            return None  # the official domain itself or a real subdomain of it
        label = domain_label(host).replace("-", "").replace("_", "")
        dotted = f".{host}."
        for official in sorted(self.config.official_domains):
            if levenshtein(domain, official) <= 2:
                return f"{domain} is within edit distance 2 of official {official}"
            brand = domain_label(official)
            for affix in self.config.deceptive_affixes:
                if label in (brand + affix, affix + brand):
                    return f"{domain} is official brand {brand!r} plus {affix!r}"
            if f".{official}." in dotted:
                return f"official domain {official} embedded in hostname {host}"
        return None

    def _evaluate(self, url: str) -> GuardResult:
        url = urldefrag(url).url
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise Blocked(url, "bad_url", f"unparseable URL ({exc})") from None
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise Blocked(url, "scheme", f"scheme {scheme or '(none)'!r} not allowed")
        if parts.username or parts.password:
            raise Blocked(url, "bad_url", "credentials embedded in URL")
        if not parts.hostname:
            raise Blocked(url, "bad_url", "no hostname")
        if port not in ALLOWED_PORTS:
            raise Blocked(url, "port", f"non-default port {port}")

        host = normalize_host(parts.hostname)
        if is_idn(host):
            raise Blocked(url, "lookalike_idn", f"IDN/punycode hostname {host}", domain=host)
        try:
            literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None = (
                ipaddress.ip_address(host)
            )
        except ValueError:
            literal = None
        if literal is not None and not is_public_ip(literal):
            raise Blocked(url, "private_ip", f"non-public address {host}", domain=host)

        domain = registrable_domain(host)
        tier = store.get_domain_tier(self._conn, host) or "UNKNOWN"
        if tier == "BLOCKED":
            raise Blocked(url, "blocked_domain", f"{host} is BLOCKED", domain=domain, tier=tier)
        if any(h in self.config.platform_domains for h in host_chain(host)):
            tier = "PLATFORM"  # never trusted, whatever the table says

        if tier != "TRUSTED":
            reason = self.lookalike_block_reason(host)
            if reason:
                raise Blocked(url, "lookalike_official", reason, domain=domain, tier=tier)

        result = GuardResult(url=url, host=host, domain=domain, tier=tier)

        verdict = self._safe_browsing_verdict(url)
        if verdict == "match":
            if tier == "UNKNOWN":
                store.block_domain_from_guard(self._conn, domain, f"Safe Browsing match: {url}")
                reason = "Google Safe Browsing match; domain added as BLOCKED"
            else:
                # Shared hosts in domain_tiers (TRUSTED, PLATFORM, LINK_HUB) are never
                # blocked wholesale for one bad URL; this URL stays blocked via the cache.
                reason = f"Google Safe Browsing match; URL blocked ({tier} domain kept)"
            raise Blocked(url, "safe_browsing", reason, domain=domain, tier=tier)
        if verdict is None:
            result.reasons.append("safe_browsing_unavailable")
            result.flags.append(NOT_TRUSTED)
            if tier == "TRUSTED":
                result.tier = "UNKNOWN"

        if literal is None:
            age = self._domain_age_days(domain)
            result.domain_age_days = age
            if age is None:
                result.reasons.append("domain_age_unknown")
            elif age < NEW_DOMAIN_DAYS:
                result.flags.append(NEW_DOMAIN)

        if result.tier not in ("TRUSTED", "PLATFORM") and any(
            b in host for b in self.config.brand_names
        ):
            result.flags.append(LOOKALIKE)
            result.reasons.append("brand_name_in_domain")
        if result.tier == "UNKNOWN" and NOT_TRUSTED not in result.flags:
            result.flags.append(NOT_TRUSTED)
        return result

    def _safe_browsing_verdict(self, url: str) -> str | None:
        """'match' / 'clean', or None when the service is down and nothing is cached."""
        cached = store.get_cached_check(self._conn, "safe_browsing", url, now=self._clock())
        if cached:
            return cached["verdict"]
        try:
            verdict = "match" if self._sb.is_unsafe(url) else "clean"
        except ReputationUnavailable:
            return None
        store.put_check(self._conn, "safe_browsing", url, verdict, now=self._clock())
        return verdict

    def _domain_age_days(self, domain: str) -> int | None:
        cached = store.get_cached_check(self._conn, "rdap", domain, now=self._clock())
        if cached:
            registered = cached["verdict"]
        else:
            try:
                when = self._age.registered_at(domain)
            except ReputationUnavailable:
                return None
            registered = when.isoformat() if when else "unknown"
            store.put_check(self._conn, "rdap", domain, registered, now=self._clock())
        if registered == "unknown":
            return None
        return (self._clock() - datetime.fromisoformat(registered)).days

    # --- fetching -----------------------------------------------------------------------

    def fetch(self, url: str) -> FetchResult:
        """Fetch a page or feed through every guardrail. Raises Blocked or FetchFailed."""
        return self._fetch_chain(url)

    def _blocked(self, b: Blocked) -> Blocked:
        store.record_filtered(self._conn, b.url, b.rule, b.reason)
        store.log_fetch(self._conn, b.url, b.domain, b.tier, f"BLOCK:{b.rule}")
        return b

    def _fetch_chain(self, url: str, *, robots_txt: bool = False) -> FetchResult:
        """Follow up to MAX_REDIRECTS, guarding every hop. `robots_txt=True` is the
        internal fetch of a robots.txt file (no robots check; non-text bodies skipped)."""
        requested = urldefrag(url).url
        current = requested
        hops: list[str] = []
        for _ in range(MAX_REDIRECTS + 1):
            try:
                guard = self._evaluate(current)
                self._vet_dns(current, guard)
                if not robots_txt:
                    self._check_robots(current, guard)
            except Blocked as b:
                raise self._blocked(b) from None
            response = self._send(current, guard)
            hops.append(current)
            try:
                location = response.headers.get("location")
                if response.status_code in REDIRECT_CODES and location:
                    store.log_fetch(self._conn, current, guard.domain, guard.tier, "REDIRECT",
                                    response.status_code)
                    current = urldefrag(urljoin(current, location)).url
                    continue
                content_type = response.headers.get("content-type", "")
                if robots_txt:
                    read = _media_type(content_type).startswith("text/") or not content_type
                else:
                    self._check_content_type(requested, current, content_type, guard)
                    read = True
                body, truncated = self._read_capped(response, current, guard) if read else (
                    b"", False)
            finally:
                response.close()
            store.log_fetch(self._conn, current, guard.domain, guard.tier,
                            "FLAG" if guard.flags else "ALLOW", response.status_code)
            return FetchResult(requested, current, response.status_code, content_type, body,
                               truncated, guard, hops)
        raise self._blocked(Blocked(requested, "redirect_limit",
                                    f"more than {MAX_REDIRECTS} redirects (last: {current})"))

    def _vet_dns(self, url: str, guard: GuardResult) -> None:
        """Resolve once, refuse non-public answers, and pin the vetted IPs for connecting."""
        try:
            ipaddress.ip_address(guard.host)
            ips = [guard.host]
        except ValueError:
            try:
                ips = self._resolver(guard.host)
            except OSError:
                store.log_fetch(self._conn, url, guard.domain, guard.tier, "ERROR:dns")
                raise FetchFailed(f"DNS lookup failed for {guard.host}") from None
        if not ips:
            raise FetchFailed(f"DNS lookup returned nothing for {guard.host}")
        vetted: list[str] = []
        for ip_s in ips:
            ip = ipaddress.ip_address(ip_s.split("%", 1)[0])
            if not is_public_ip(ip):
                self._pins.pop(guard.host, None)
                raise Blocked(url, "private_ip", f"{guard.host} resolves to non-public {ip}",
                              domain=guard.domain, tier=guard.tier)
            vetted.append(str(ip))
        self._pins[guard.host] = vetted

    # --- robots.txt (RFC 9309) ------------------------------------------------------------

    def _check_robots(self, url: str, guard: GuardResult) -> None:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        rp = self._robots.get(origin)
        if rp is None:
            rp = self._robots[origin] = self._load_robots(origin)
        if getattr(rp, "unreachable", False):
            raise Blocked(url, "robots_unreachable",
                          f"{origin}/robots.txt unreachable (5xx/network); retry next run",
                          domain=guard.domain, tier=guard.tier)
        if not rp.can_fetch(ROBOTS_AGENT, url):
            raise Blocked(url, "robots", f"disallowed by {origin}/robots.txt",
                          domain=guard.domain, tier=guard.tier)

    def _load_robots(self, origin: str) -> RobotFileParser:
        """2xx: obey. 4xx: no restrictions. 5xx/network: refuse for this run only.

        Successful results are cached in url_checks (kind 'robots', 24h TTL, as RFC 9309
        recommends); unreachable results are kept in memory for this run only.
        """
        cached = store.get_cached_check(self._conn, "robots", origin, now=self._clock())
        if cached:
            return _robots_parser(cached["verdict"], cached["detail"])
        verdict, text = self._fetch_robots(origin)
        if verdict != "unreachable":
            store.put_check(self._conn, "robots", origin, verdict, text, now=self._clock())
        return _robots_parser(verdict, text)

    def _fetch_robots(self, origin: str) -> tuple[str, str | None]:
        try:
            res = self._fetch_chain(f"{origin}/robots.txt", robots_txt=True)
        except (FetchFailed, Blocked):
            return "unreachable", None
        if 200 <= res.status_code < 300:
            return "rules", res.text()[:ROBOTS_MAX_CHARS]
        if 400 <= res.status_code < 500:
            return "allow_all", None
        return "unreachable", None

    # --- request plumbing -----------------------------------------------------------------

    def _throttle(self, url: str, host: str) -> None:
        """Wait so requests to one host are at least the configured interval (or the
        site's robots.txt Crawl-delay, if longer) apart."""
        interval = self.config.min_host_interval_s
        parts = urlsplit(url)
        rp = self._robots.get(f"{parts.scheme}://{parts.netloc}")
        crawl_delay = rp.crawl_delay(ROBOTS_AGENT) if rp else None
        if crawl_delay:
            interval = max(interval, float(crawl_delay))
        last = self._last_request.get(host)
        if last is not None:
            wait = interval - (self._monotonic() - last)
            if wait > 0:
                self._sleep(wait)
        self._last_request[host] = self._monotonic()

    def _send(self, url: str, guard: GuardResult) -> httpx.Response:
        self._throttle(url, guard.host)
        try:
            request = self._client.build_request("GET", url)
            return self._client.send(request, stream=True)
        except httpx.HTTPError as exc:
            store.log_fetch(self._conn, url, guard.domain, guard.tier, "ERROR:network")
            raise FetchFailed(f"{type(exc).__name__} fetching {url}") from None

    def _check_content_type(
        self, requested: str, url: str, content_type: str, guard: GuardResult
    ) -> None:
        media = _media_type(content_type)
        allowed = ALLOWED_TYPES | (
            FEED_ONLY_TYPES if requested in self.config.feed_urls else frozenset()
        )
        if media not in allowed:
            raise self._blocked(Blocked(url, "content_type",
                                        f"content type {media or '(missing)'!r} not allowed",
                                        domain=guard.domain, tier=guard.tier))

    def _read_capped(
        self, response: httpx.Response, url: str, guard: GuardResult
    ) -> tuple[bytes, bool]:
        """Read at most MAX_BYTES of decoded body within TIMEOUT_S. Truncate, never reject."""
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding in ("", "identity"):
            decoder = None
        elif encoding in ("gzip", "x-gzip"):
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif encoding == "deflate":
            decoder = zlib.decompressobj()
        else:
            raise self._blocked(Blocked(url, "content_encoding",
                                        f"unsupported content-encoding {encoding!r}",
                                        domain=guard.domain, tier=guard.tier))
        deadline = self._monotonic() + TIMEOUT_S
        out = bytearray()
        try:
            for chunk in response.iter_raw():
                if decoder is not None:
                    # max_length bounds memory even for a decompression bomb.
                    chunk = decoder.decompress(chunk, MAX_BYTES - len(out) + 1)
                out += chunk
                if len(out) > MAX_BYTES:
                    return bytes(out[:MAX_BYTES]), True
                if self._monotonic() > deadline:
                    raise FetchFailed(f"timed out reading {url}")
        except (httpx.HTTPError, zlib.error) as exc:
            store.log_fetch(self._conn, url, guard.domain, guard.tier, "ERROR:read")
            raise FetchFailed(f"{type(exc).__name__} reading {url}") from None
        return bytes(out), False


def _robots_parser(verdict: str, text: str | None) -> RobotFileParser:
    rp = RobotFileParser()
    if verdict == "rules":
        rp.parse((text or "").splitlines())
    elif verdict == "allow_all":
        rp.allow_all = True
    else:
        rp.disallow_all = True
        rp.unreachable = True  # type: ignore[attr-defined]
    return rp
