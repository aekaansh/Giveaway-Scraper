"""Shared url_guard test harness: MockTransport routes, fake resolver and fake
reputation services. Tests never touch the network."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import httpx

from radar import store
from radar.api_client import ReputationUnavailable
from radar.url_guard import GuardConfig, PinnedBackend, UrlGuard

PUBLIC_IP = "93.184.216.34"
FEED_URL = "https://feeds.example/giveaways.txt"
NOW = datetime(2026, 10, 26, 12, 0, tzinfo=store.utcnow().tzinfo)

Route = httpx.Response | Callable[[httpx.Request], httpx.Response]


class FakeSafeBrowsing:
    def __init__(self, unsafe: set[str] | None = None, down: bool = False) -> None:
        self.unsafe = unsafe or set()
        self.down = down
        self.calls: list[str] = []

    def is_unsafe(self, url: str) -> bool:
        self.calls.append(url)
        if self.down:
            raise ReputationUnavailable("down")
        return url in self.unsafe


class FakeDomainAge:
    def __init__(self, ages_days: dict[str, int] | None = None, down: bool = False) -> None:
        self.ages_days = ages_days or {}
        self.down = down

    def registered_at(self, domain: str) -> datetime | None:
        if self.down:
            raise ReputationUnavailable("down")
        return NOW - timedelta(days=self.ages_days.get(domain, 3650))


class Harness:
    def __init__(
        self,
        conn: sqlite3.Connection,
        routes: dict[str, Route] | None = None,
        *,
        sb: FakeSafeBrowsing | None = None,
        age: FakeDomainAge | None = None,
        dns: dict[str, list[str]] | None = None,
        interval: float = 0.0,
        resolver: Callable[[str], list[str]] | None = None,
        backend_cls: type[PinnedBackend] | None = None,
    ) -> None:
        self.routes = routes or {}
        self.requests: list[httpx.Request] = []
        self.sb = sb or FakeSafeBrowsing()
        self.sleeps: list[float] = []
        self.clock_s = 0.0
        dns = dns or {}
        config = GuardConfig(
            official_domains=frozenset({"pokemon.com", "pokemoncenter.com", "tcgplayer.com"}),
            deceptive_affixes=("official", "giveaway", "support", "claim", "prize"),
            brand_names=("pokemon", "pkmn", "tcg"),
            platform_domains=frozenset({"youtube.com", "instagram.com", "reddit.com"}),
            feed_urls=frozenset({FEED_URL}),
            min_host_interval_s=interval,
        )
        network: dict[str, Any] = (
            {"backend_cls": backend_cls} if backend_cls
            else {"transport": httpx.MockTransport(self._handle)}
        )
        self.guard = UrlGuard(
            conn,
            config,
            safe_browsing=self.sb,
            domain_age=age or FakeDomainAge(),
            resolver=resolver or (lambda host: dns.get(host, [PUBLIC_IP])),
            **network,
            clock=lambda: NOW,
            sleep=self.sleeps.append,
            monotonic=lambda: self.clock_s,
        )

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        route = self.routes.get(str(request.url))
        if route is None:
            response = httpx.Response(404, headers={"content-type": "text/html"}, text="nope")
        else:
            response = route(request) if callable(route) else route
        # Re-serve as a fresh *streaming* response like a real transport: a Response built
        # with content=bytes is pre-read and would raise StreamConsumed on iter_raw().
        raw = b"".join(response.stream)  # raw (still-encoded) bytes, not .content
        return httpx.Response(response.status_code, headers=response.headers,
                              stream=_OneShot(raw))


class _OneShot(httpx.SyncByteStream):
    def __init__(self, data: bytes) -> None:
        self._data = data

    def __iter__(self):
        yield self._data


def html(body: str = "<html>giveaway</html>", **headers: str) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8", **headers},
                          content=body.encode())


def redirect(to: str, code: int = 302) -> httpx.Response:
    return httpx.Response(code, headers={"location": to})


def filtered(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return conn.execute("SELECT url, rule FROM filtered_items ORDER BY id").fetchall()
