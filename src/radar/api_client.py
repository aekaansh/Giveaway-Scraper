"""Client for keyed/official APIs. With url_guard, the ONLY modules that make network calls
(the Anthropic SDK in classify.py is the one other exception).

- Fixed host allowlist (ALLOWED_HOSTS). RDAP registry hosts are the single dynamic part:
  they are taken only from IANA's RDAP bootstrap file (data.iana.org), never from a page.
- HTTPS only, no redirects followed, no cookies, no proxies from the environment.
- Keys come from environment variables only and never appear in errors or logs: error
  messages name the host and status, never the URL, query string or headers.
- Any URL found in API results is untrusted and must go through url_guard before fetching.
"""

from __future__ import annotations

from datetime import datetime
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any
from urllib.parse import urlsplit

import httpx

from radar.config import require_env

USER_AGENT = (
    "GiveawayRadarBot/0.1 (+https://github.com/aekaansh/Giveaway-Scraper; "
    "read-only personal giveaway alert bot)"
)
TIMEOUT_S = 10.0
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

ALLOWED_HOSTS = frozenset({
    "api.search.brave.com",  # Brave Search API
    "www.googleapis.com",  # YouTube Data API v3
    "youtube.googleapis.com",  # YouTube Data API v3 (alternate host)
    "safebrowsing.googleapis.com",  # Google Safe Browsing
    "data.iana.org",  # RDAP bootstrap registry
    "discord.com",  # Discord webhooks (path-restricted below)
    "discordapp.com",
})
DISCORD_HOSTS = frozenset({"discord.com", "discordapp.com"})
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


class ApiError(Exception):
    """An API call failed or was refused. The message never contains secrets."""


class NoCookieJar(CookieJar):
    """A jar whose policy accepts and returns no cookies (no persistent sessions)."""

    def __init__(self) -> None:
        super().__init__(policy=DefaultCookiePolicy(allowed_domains=[]))


class ApiClient:
    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._client = httpx.Client(
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(TIMEOUT_S),
            cookies=NoCookieJar(),
            headers={"User-Agent": USER_AGENT},
        )
        self._rdap_hosts: frozenset[str] = frozenset()

    def close(self) -> None:
        self._client.close()

    def _check_url(self, url: str) -> str:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https":
            raise ApiError(f"API calls must use https (host {host or '?'})")
        if parts.username or parts.password or parts.port not in (None, 443):
            raise ApiError(f"refusing API URL with credentials or custom port (host {host})")
        if host not in ALLOWED_HOSTS and host not in self._rdap_hosts:
            raise ApiError(f"host {host or '?'} is not on the API allowlist")
        if host in DISCORD_HOSTS and not parts.path.startswith("/api/webhooks/"):
            raise ApiError("only Discord webhook paths are allowed")
        return host

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: Any = None,
        ok_statuses: tuple[int, ...] = (),
    ) -> httpx.Response:
        """Send one request. Raises ApiError on transport errors, redirects, non-2xx
        statuses (unless listed in ok_statuses) or oversized bodies."""
        host = self._check_url(url)
        try:
            with self._client.stream(method, url, params=params, headers=headers,
                                     json=json) as response:
                body = bytearray()
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise ApiError(f"{host} response larger than {MAX_RESPONSE_BYTES} bytes")
        except httpx.HTTPError as exc:
            # `from None`: httpx errors embed the full URL, which may carry an API key.
            raise ApiError(f"{host} request failed ({type(exc).__name__})") from None
        status = response.status_code
        if 300 <= status < 400:
            raise ApiError(f"{host} answered with a redirect (HTTP {status}); not followed")
        if not (200 <= status < 300) and status not in ok_statuses:
            raise ApiError(f"{host} returned HTTP {status}")
        return httpx.Response(status, headers=response.headers, content=bytes(body),
                              request=response.request)

    def get_json(self, url: str, **kwargs: Any) -> Any:
        response = self.request("GET", url, **kwargs)
        try:
            return response.json()
        except ValueError:
            raise ApiError(f"{urlsplit(url).hostname} returned invalid JSON") from None

    def allow_rdap_hosts_from_bootstrap(self, bootstrap: dict[str, Any]) -> dict[str, str]:
        """Allow the https RDAP servers named in IANA's bootstrap file. Returns tld -> base URL."""
        bases: dict[str, str] = {}
        for tlds, urls in bootstrap.get("services", []):
            https = [u for u in urls if u.startswith("https://")]
            if https:
                for tld in tlds:
                    bases[tld.lower()] = https[0]
        self._rdap_hosts = frozenset(
            (urlsplit(u).hostname or "").lower() for u in bases.values()
        )
        return bases


# --- keys (from env only) ---------------------------------------------------------------


def brave_headers() -> dict[str, str]:
    return {"X-Subscription-Token": require_env("BRAVE_API_KEY"), "Accept": "application/json"}


def youtube_params() -> dict[str, str]:
    return {"key": require_env("YOUTUBE_API_KEY")}


# --- reputation services used by url_guard ----------------------------------------------


class ReputationUnavailable(Exception):
    """A reputation service could not be reached or returned garbage."""


class GoogleSafeBrowsing:
    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api: ApiClient, api_key: str | None = None) -> None:
        self._api = api
        self._key = api_key or require_env("SAFE_BROWSING_API_KEY")

    def is_unsafe(self, url: str) -> bool:
        body = {
            "client": {"clientId": "giveaway-radar", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            data = self._api.request(
                "POST", self.ENDPOINT, params={"key": self._key}, json=body
            ).json()
        except (ApiError, ValueError) as exc:
            raise ReputationUnavailable(f"Safe Browsing unavailable: {exc}") from None
        return bool(data.get("matches"))


class RdapDomainAge:
    """Domain registration date via RDAP, using IANA's bootstrap file to pick the registry
    server directly (no rdap.org redirect service, so no redirects are needed)."""

    def __init__(self, api: ApiClient) -> None:
        self._api = api
        self._bases: dict[str, str] | None = None

    def _base_for(self, domain: str) -> str | None:
        if self._bases is None:
            try:
                bootstrap = self._api.get_json(RDAP_BOOTSTRAP_URL)
            except ApiError as exc:
                raise ReputationUnavailable(f"RDAP bootstrap unavailable: {exc}") from None
            self._bases = self._api.allow_rdap_hosts_from_bootstrap(bootstrap)
        return self._bases.get(domain.rsplit(".", 1)[-1].lower())

    def registered_at(self, domain: str) -> datetime | None:
        base = self._base_for(domain)
        if base is None:
            return None  # TLD has no RDAP service: age unknown
        url = base.rstrip("/") + "/domain/" + domain
        try:
            response = self._api.request("GET", url, ok_statuses=(404,),
                                         headers={"Accept": "application/rdap+json"})
            if response.status_code == 404:
                return None
            data = response.json()
        except (ApiError, ValueError) as exc:
            raise ReputationUnavailable(f"RDAP unavailable: {exc}") from None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration" and event.get("eventDate"):
                return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
        return None
