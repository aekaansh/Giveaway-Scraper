"""Brave and YouTube adapters against saved API responses (no network)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from radar.adapters.brave import ENDPOINT, BraveAdapter
from radar.adapters.youtube import API, YouTubeAdapter
from radar.api_client import ApiClient, ApiError
from radar.config import MissingConfigError

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def api_with(routes: dict[str, dict], seen: list[httpx.Request]) -> ApiClient:
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        base = str(request.url).split("?", 1)[0]
        if base not in routes:
            return httpx.Response(404)
        return httpx.Response(200, json=routes[base])

    return ApiClient(transport=httpx.MockTransport(handle))


def test_brave_results_parsed_and_deduplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BRAVE_API_KEY", "test-brave-key")
    seen: list[httpx.Request] = []
    sleeps: list[float] = []
    api = api_with({ENDPOINT: fixture_json("brave_search.json")}, seen)
    items = BraveAdapter(api, ["q1", "q2"], sleep=sleeps.append).fetch()

    assert [i.url for i in items] == [
        "https://gleam.io/aB3dE/pokemon-151-booster-bundle-giveaway",
        "https://www.instagram.com/pokeshop/p/Cxyz123/",
    ]
    first = items[0]
    assert first.external_id == f"brave:{first.url}"
    assert first.title == "Win a Pokemon 151 Booster Bundle & more"  # tags/entities stripped
    assert "<strong>" not in first.body
    assert all(i.account is None for i in items)  # search results say nothing about posters
    assert len(seen) == 2 and sleeps == [pytest.approx(1.1)]  # polite between queries
    assert seen[0].headers["X-Subscription-Token"] == "test-brave-key"
    assert seen[0].url.params["country"] == "US"


def test_brave_needs_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    with pytest.raises(MissingConfigError):
        BraveAdapter(api_with({}, []), ["q"]).fetch()


def test_brave_http_error_names_host_not_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BRAVE_API_KEY", "secret-brave-key")
    with pytest.raises(ApiError) as exc:
        BraveAdapter(api_with({}, []), ["q"]).fetch()
    assert "api.search.brave.com" in str(exc.value)
    assert "secret-brave-key" not in str(exc.value)


def test_youtube_videos_with_channel_account(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YOUTUBE_API_KEY", "test-yt-key")
    seen: list[httpx.Request] = []
    api = api_with({
        f"{API}/search": fixture_json("youtube_search.json"),
        f"{API}/videos": fixture_json("youtube_videos.json"),
        f"{API}/channels": fixture_json("youtube_channels.json"),
    }, seen)
    now = datetime(2026, 11, 7, 12, tzinfo=UTC)
    items = YouTubeAdapter(api, ["q"], now=now).fetch()

    assert [i.url for i in items] == ["https://www.youtube.com/watch?v=vid111",
                                      "https://www.youtube.com/watch?v=vid222"]
    a, b = items
    assert a.external_id == "youtube:vid111"
    assert a.title == "Charizard ETB GIVEAWAY & pack opening"
    assert a.account is not None
    assert a.account.platform == "youtube" and a.account.handle == "@CardShopTV"
    assert a.account.followers == 48000
    assert a.account.created_at == datetime(2019, 3, 1, tzinfo=UTC)
    assert a.account.is_original_post is True
    # Hidden subscriber count -> unknown; no custom handle -> channel id.
    assert b.account is not None
    assert b.account.followers is None and b.account.handle == "UCbbb"

    search = seen[0]
    assert search.url.params["key"] == "test-yt-key"
    assert search.url.params["publishedAfter"] == "2026-10-31T12:00:00Z"
    assert search.url.params["regionCode"] == "US"
    assert seen[1].url.params["id"] == "vid111,vid222"


def test_youtube_no_results_makes_no_further_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YOUTUBE_API_KEY", "k")
    seen: list[httpx.Request] = []
    api = api_with({f"{API}/search": {"items": []}}, seen)
    assert YouTubeAdapter(api, ["q"]).fetch() == []
    assert len(seen) == 1
