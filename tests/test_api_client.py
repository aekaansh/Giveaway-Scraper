"""api_client tests: allowlist, no redirects, keys never leak. No network (MockTransport)."""

from __future__ import annotations

import json

import httpx
import pytest

from radar.api_client import (
    RDAP_BOOTSTRAP_URL,
    ApiClient,
    ApiError,
    GoogleSafeBrowsing,
    RdapDomainAge,
    ReputationUnavailable,
    brave_headers,
    youtube_params,
)
from radar.config import MissingConfigError

BOOTSTRAP = {
    "services": [
        [["com", "net"], ["http://insecure.example/", "https://rdap.verisign.com/com/v1/"]],
        [["io"], ["https://rdap.identitydigital.services/rdap/"]],
    ]
}


def client(handler) -> tuple[ApiClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    return ApiClient(transport=httpx.MockTransport(wrapped)), seen


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/api",
        "http://api.search.brave.com/res/v1/web/search",  # not https
        "https://api.search.brave.com:8443/x",
        "https://user:pw@api.search.brave.com/x",
        "https://discord.com/channels/123",  # discord: webhook paths only
        "https://rdap.verisign.com/com/v1/domain/x.com",  # not allowed before bootstrap
    ],
)
def test_refuses_urls_outside_allowlist(url: str) -> None:
    api, seen = client(lambda r: httpx.Response(200, json={}))
    with pytest.raises(ApiError):
        api.get_json(url)
    assert seen == []


def test_allowed_host_gets_json_and_honest_user_agent() -> None:
    api, seen = client(lambda r: httpx.Response(200, json={"web": {"results": []}}))
    data = api.get_json("https://api.search.brave.com/res/v1/web/search", params={"q": "x"})
    assert data == {"web": {"results": []}}
    assert seen[0].headers["user-agent"].startswith("GiveawayRadarBot/")
    assert "cookie" not in seen[0].headers


def test_redirects_are_not_followed() -> None:
    api, seen = client(lambda r: httpx.Response(302, headers={"location": "https://evil.example/"}))
    with pytest.raises(ApiError, match="redirect"):
        api.get_json("https://www.googleapis.com/youtube/v3/search")
    assert len(seen) == 1


def test_errors_never_contain_keys_or_query() -> None:
    api, _ = client(lambda r: httpx.Response(403, text="bad key SECRET"))
    with pytest.raises(ApiError) as exc:
        api.get_json("https://www.googleapis.com/youtube/v3/search", params={"key": "SECRET"})
    assert "SECRET" not in str(exc.value)
    assert "googleapis" in str(exc.value) and "403" in str(exc.value)

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    api, _ = client(boom)
    with pytest.raises(ApiError) as exc:
        api.get_json("https://www.googleapis.com/youtube/v3/search", params={"key": "SECRET"})
    assert "SECRET" not in str(exc.value)
    assert exc.value.__cause__ is None and exc.value.__suppress_context__


def test_discord_webhook_url_never_in_errors() -> None:
    hook = "https://discord.com/api/webhooks/123/TOKEN-abc"
    api, _ = client(lambda r: httpx.Response(500))
    with pytest.raises(ApiError) as exc:
        api.request("POST", hook, json={"content": "hi"})
    assert "TOKEN" not in str(exc.value) and "123" not in str(exc.value)


def test_oversized_response_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    import radar.api_client as mod

    monkeypatch.setattr(mod, "MAX_RESPONSE_BYTES", 10)
    api, _ = client(lambda r: httpx.Response(200, content=b"x" * 100))
    with pytest.raises(ApiError, match="larger"):
        api.request("GET", "https://www.googleapis.com/x")


def test_keys_come_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    monkeypatch.delenv("YOUTUBE_API_KEY", raising=False)
    with pytest.raises(MissingConfigError, match="BRAVE_API_KEY"):
        brave_headers()
    with pytest.raises(MissingConfigError, match="YOUTUBE_API_KEY"):
        youtube_params()
    monkeypatch.setenv("BRAVE_API_KEY", "b")
    monkeypatch.setenv("YOUTUBE_API_KEY", "y")
    assert brave_headers()["X-Subscription-Token"] == "b"
    assert youtube_params() == {"key": "y"}


# --- Safe Browsing ----------------------------------------------------------------------


def test_safe_browsing_parses_matches() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["key"] == "k123"
        url = json.loads(request.content)["threatInfo"]["threatEntries"][0]["url"]
        return httpx.Response(200, json={"matches": [{"threat": {"url": url}}]}
                              if "bad" in url else {})

    api, _ = client(handler)
    sb = GoogleSafeBrowsing(api, api_key="k123")
    assert sb.is_unsafe("https://bad.example/")
    assert not sb.is_unsafe("https://good.example/")


def test_safe_browsing_down_raises_unavailable_without_key() -> None:
    api, _ = client(lambda r: httpx.Response(500))
    with pytest.raises(ReputationUnavailable) as exc:
        GoogleSafeBrowsing(api, api_key="SECRET-KEY").is_unsafe("https://x.example/")
    assert "SECRET-KEY" not in str(exc.value)


def test_safe_browsing_requires_env_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    api, _ = client(lambda r: httpx.Response(200, json={}))
    with pytest.raises(MissingConfigError, match="SAFE_BROWSING_API_KEY"):
        GoogleSafeBrowsing(api)


# --- RDAP via IANA bootstrap -------------------------------------------------------------


def rdap_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url == RDAP_BOOTSTRAP_URL:
        return httpx.Response(200, json=BOOTSTRAP)
    if url.endswith("/domain/missing.com"):
        return httpx.Response(404)
    if url.startswith("https://rdap.verisign.com/com/v1/domain/"):
        return httpx.Response(200, json={"events": [
            {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
            {"eventAction": "registration", "eventDate": "2001-05-04T00:00:00Z"},
        ]})
    return httpx.Response(599)


def test_rdap_uses_bootstrap_server_directly() -> None:
    api, seen = client(rdap_handler)
    rdap = RdapDomainAge(api)
    assert rdap.registered_at("old.com").year == 2001
    assert rdap.registered_at("missing.com") is None
    assert rdap.registered_at("unknown.zz") is None  # TLD without RDAP service
    urls = [str(r.url) for r in seen]
    assert urls.count(RDAP_BOOTSTRAP_URL) == 1  # bootstrap loaded once
    assert "https://rdap.verisign.com/com/v1/domain/old.com" in urls
    assert not any("insecure.example" in u for u in urls)


def test_rdap_bootstrap_only_allows_https_servers() -> None:
    api, _ = client(rdap_handler)
    RdapDomainAge(api).registered_at("old.com")
    with pytest.raises(ApiError):
        api.get_json("http://insecure.example/domain/x.com")
    with pytest.raises(ApiError):
        api.get_json("https://not-in-bootstrap.example/domain/x.com")


def test_rdap_redirect_not_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == RDAP_BOOTSTRAP_URL:
            return httpx.Response(200, json=BOOTSTRAP)
        return httpx.Response(302, headers={"location": "https://evil.example/"})

    api, seen = client(handler)
    with pytest.raises(ReputationUnavailable):
        RdapDomainAge(api).registered_at("old.com")
    assert not any(r.url.host == "evil.example" for r in seen)


def test_rdap_bootstrap_down_is_unavailable() -> None:
    api, _ = client(lambda r: httpx.Response(503))
    with pytest.raises(ReputationUnavailable):
        RdapDomainAge(api).registered_at("old.com")


def test_gzip_response_is_decoded_once() -> None:
    import gzip

    payload = gzip.compress(json.dumps({"web": {"results": []}}).encode())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-encoding": "gzip",
                                            "content-type": "application/json"},
                              content=payload)

    api, _ = client(handler)
    assert api.get_json("https://api.search.brave.com/res/v1/web/search") == {
        "web": {"results": []}}
