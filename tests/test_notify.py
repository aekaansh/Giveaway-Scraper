"""Discord notifier: payload shape, untrusted-text neutralising, the odds badge, digest."""

from __future__ import annotations

import json

import httpx
import pytest

from radar.api_client import ApiClient, ApiError
from radar.notify import FEW_ENTRANTS, Notifier, OddsHint, badges, safe_text

WEBHOOK = "https://discord.com/api/webhooks/123/secret-token"


def notifier(status: int = 204) -> tuple[Notifier, list[dict]]:
    sent: list[dict] = []

    def handle(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(status)

    api = ApiClient(transport=httpx.MockTransport(handle))
    return Notifier(api, WEBHOOK, sleep=lambda s: None), sent


def giveaway(**kw) -> dict:
    base = {
        "id": 1, "url": "https://gleam.io/aB3dE/pokemon-151", "domain": "gleam.io",
        "tier": "TRUSTED", "platform": None, "account_handle": None,
        "title": "151 Booster Bundle", "summary": "Win a bundle.", "deadline": "2026-11-30",
        "scam_likelihood": "low", "flags_json": "[]", "entry_count": None,
        "account_followers": None, "domain_age_days": 4000, "account_age_days": None,
    }
    return {**base, **kw}


def test_alert_has_final_url_domain_tier_age_and_no_mentions() -> None:
    n, sent = notifier()
    n.send_alert(giveaway(), [])
    payload = sent[0]
    assert payload["allowed_mentions"] == {"parse": []}
    embed = payload["embeds"][0]
    assert embed["url"] == "https://gleam.io/aB3dE/pokemon-151"
    fields = {f["name"]: f["value"] for f in embed["fields"]}
    assert fields["Where"] == "gleam.io"
    assert fields["Tier"] == "TRUSTED"
    assert fields["Age"] == "domain 4000d old"
    assert fields["Deadline"] == "2026-11-30"


def test_platform_alert_shows_account_handle_and_age() -> None:
    n, sent = notifier()
    n.send_alert(giveaway(tier="PLATFORM", platform="youtube", account_handle="cardshoptv",
                          domain="www.youtube.com", account_age_days=2800,
                          account_followers=48000), [])
    fields = {f["name"]: f["value"] for f in sent[0]["embeds"][0]["fields"]}
    assert fields["Where"] == "@​cardshoptv on youtube"
    assert fields["Age"] == "account 2800d old"
    assert fields["Size"] == "48,000 followers"


def test_untrusted_text_cannot_inject_links_or_pings() -> None:
    evil = "[Claim here](https://evil.example) @everyone visit http://phish.example now"
    out = safe_text(evil, 500)
    assert "](" not in out and "\\[" in out
    assert "https://" not in out and "http://" not in out
    assert "@everyone" not in out


def test_badges_include_flags_scam_and_few_entrants() -> None:
    odds = OddsHint(max_entries=500, max_followers=5000)
    g = giveaway(flags_json=json.dumps(["NEW DOMAIN"]), scam_likelihood="high", entry_count=120)
    assert badges(g, odds) == ["NEW DOMAIN", "SCAM SIGNALS", FEW_ENTRANTS]


@pytest.mark.parametrize(
    ("entries", "followers", "expected"),
    [
        (120, None, FEW_ENTRANTS),
        (5000, 100, None),  # an entry count wins over a small account
        (None, 3000, FEW_ENTRANTS),
        (None, 90000, None),
        (None, None, None),  # unknown numbers never produce a badge
    ],
)
def test_odds_badge(entries, followers, expected) -> None:
    assert OddsHint(500, 5000).badge(entries, followers) == expected


def test_failure_raises_api_error_without_webhook_secret() -> None:
    n, _ = notifier(status=500)
    with pytest.raises(ApiError) as exc:
        n.send_alert(giveaway(), [])
    assert "secret-token" not in str(exc.value)


def test_digest_lists_items_soonest_first_and_fits_discord_limit() -> None:
    n, sent = notifier()
    items = [giveaway(id=i, url=f"https://shop{i}.example/g", domain=f"shop{i}.example",
                      tier="UNKNOWN", title="x" * 50, deadline=f"2026-11-{10 + i % 20:02d}",
                      flags_json=json.dumps(["NOT TRUSTED"]))
             for i in range(40)]
    n.send_digest(items, 40, OddsHint())
    content = sent[0]["content"]
    assert len(content) <= 2000
    assert content.startswith("**Review queue digest:** 40 item(s)")
    assert "<https://shop0.example/g>" in content
    assert "more on the dashboard" in content
    assert sent[0]["allowed_mentions"] == {"parse": []}
