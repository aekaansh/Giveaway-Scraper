"""End-to-end polling cycle on fixtures: fake adapters, the real url_guard (MockTransport),
a fake classifier and a fake notifier. No network, no Turso."""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from guard_harness import NOW, Harness, html, redirect

from radar import admin_store, run
from radar.accounts import AccountInfo
from radar.adapters.base import RawItem
from radar.api_client import ApiError
from radar.classify import ClassifyError, Giveaway
from radar.notify import FEW_ENTRANTS, OddsHint
from radar.run import Cycle, RunConfig, canonical_key, handle_from_url

FIXTURES = Path(__file__).parent / "fixtures"
GLEAM = "https://gleam.io/aB3dE/pokemon-151-booster-bundle-giveaway"
SHOP = "https://cardboardkingdom.example/pages/giveaway"
INSTA = "https://www.instagram.com/pokeshop/p/Cxyz123/"
YT = "https://www.youtube.com/watch?v=vid111"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def verdict(**kw: Any) -> Giveaway:
    base = dict(is_giveaway=True, is_pokemon_tcg=True, title="151 Booster Bundle",
                summary="Win a bundle.", deadline="2026-11-30", us_eligible="yes",
                poster_is_host=True, scam_likelihood="low", scam_reasons=[])
    return Giveaway(**{**base, **kw})


class FakeAdapter:
    name = "fake"

    def __init__(self, *items: RawItem) -> None:
        self.items = list(items)

    def fetch(self) -> list[RawItem]:
        return list(self.items)


_VERDICT = object()


class FakeClassifier:
    """Returns `by_url[url]`, else `default` (a Giveaway, None for "no verdict", or an
    exception to raise)."""

    def __init__(self, by_url: dict[str, Any] | None = None, default: Any = _VERDICT) -> None:
        self.by_url = by_url or {}
        self.default = verdict() if default is _VERDICT else default
        self.calls: list[dict[str, Any]] = []

    def classify(self, **kw: Any) -> Giveaway | None:
        self.calls.append(kw)
        result = self.by_url.get(kw["url"], self.default)
        if isinstance(result, Exception):
            raise result
        return result


class FakeNotifier:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.alerts: list[tuple[dict[str, Any], list[str]]] = []
        self.digests: list[tuple[list[dict[str, Any]], int]] = []

    def send_alert(self, giveaway: dict[str, Any], badge_list: list[str]) -> None:
        if self.fail:
            raise ApiError("discord.com returned HTTP 500")
        self.alerts.append((giveaway, badge_list))

    def send_digest(self, items: list[dict[str, Any]], total: int, odds: OddsHint) -> None:
        if self.fail:
            raise ApiError("discord.com returned HTTP 500")
        self.digests.append((items, total))


def item(url: str, **kw: Any) -> RawItem:
    return RawItem(source="fake", external_id=kw.pop("external_id", f"fake:{url}"), url=url,
                   title=kw.pop("title", "Pokemon giveaway"), body=kw.pop("body", "Enter now"),
                   **kw)


def gleam_page(text: str = "Win a Pokemon 151 Booster Bundle. US residents.") -> Any:
    return html(f"<html><body><h1>Giveaway</h1><p>{text}</p></body></html>")


def run_cycle(conn: sqlite3.Connection, h: Harness, *items: RawItem,
              classifier: FakeClassifier | None = None, notifier: FakeNotifier | None = None,
              now=NOW, config: RunConfig | None = None) -> tuple[run.RunStats, FakeNotifier]:
    notifier = notifier or FakeNotifier()
    stats = Cycle(conn, guard=h.guard, classifier=classifier or FakeClassifier(),
                  notifier=notifier, config=config or RunConfig(), now=now
                  ).run([FakeAdapter(*items)])
    return stats, notifier


def queue(conn: sqlite3.Connection) -> list[tuple[str, list[str]]]:
    return [(url, json.loads(reasons)) for url, reasons in conn.execute(
        "SELECT g.url, q.reasons_json FROM review_queue q JOIN giveaways g"
        " ON g.id = q.giveaway_id ORDER BY q.id")]


def rules(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT rule FROM filtered_items ORDER BY id")]


@pytest.fixture
def trusted_gleam(conn: sqlite3.Connection) -> sqlite3.Connection:
    admin_store.trust_domain(conn, "gleam.io")
    return conn


# --- alerts and idempotency -----------------------------------------------------------


def test_run_twice_alerts_only_once(trusted_gleam: sqlite3.Connection) -> None:
    conn = trusted_gleam
    h = Harness(conn, {GLEAM: gleam_page()})
    classifier = FakeClassifier()
    notifier = FakeNotifier()
    first, _ = run_cycle(conn, h, item(GLEAM), classifier=classifier, notifier=notifier)
    second, _ = run_cycle(conn, h, item(GLEAM), classifier=classifier, notifier=notifier)
    # Same giveaway found again under another source id / tracking params: still one alert.
    third, _ = run_cycle(conn, h, item(GLEAM + "?utm_source=x", external_id="other:1"),
                         classifier=classifier, notifier=notifier)

    assert len(notifier.alerts) == 1
    sent, badge_list = notifier.alerts[0]
    assert sent["url"] == GLEAM and sent["tier"] == "TRUSTED" and badge_list == []
    assert first.alerts_sent == 1 and second.alerts_sent == 0 and third.alerts_sent == 0
    assert second.items_found == 0  # already processed: not classified again
    assert len(classifier.calls) == 2
    assert queue(conn) == []
    log = conn.execute("SELECT items_found, alerts_sent, finished_at FROM run_log").fetchall()
    assert [(r[0], r[1]) for r in log] == [(1, 1), (0, 0), (1, 0)]
    assert all(r[2] for r in log)


def test_discord_failure_leaves_alert_pending_for_next_run(
    trusted_gleam: sqlite3.Connection,
) -> None:
    conn = trusted_gleam
    h = Harness(conn, {GLEAM: gleam_page()})
    stats, _ = run_cycle(conn, h, item(GLEAM), notifier=FakeNotifier(fail=True))
    assert stats.alerts_sent == 0 and any("discord" in e for e in stats.errors)
    retry = FakeNotifier()
    stats, _ = run_cycle(conn, h, notifier=retry)
    assert stats.alerts_sent == 1 and retry.alerts[0][0]["url"] == GLEAM
    stats, _ = run_cycle(conn, h, notifier=retry)
    assert len(retry.alerts) == 1


def test_pending_alert_rechecked_before_sending(trusted_gleam: sqlite3.Connection) -> None:
    conn = trusted_gleam
    h = Harness(conn, {GLEAM: gleam_page()})
    run_cycle(conn, h, item(GLEAM), notifier=FakeNotifier(fail=True))
    admin_store.block_domain(conn, "gleam.io", "marked Scam on the dashboard")
    notifier = FakeNotifier()
    run_cycle(conn, h, notifier=notifier)
    assert notifier.alerts == []
    assert queue(conn) == [(GLEAM, ["BLOCKED BEFORE ALERT: blocked_domain"])]


# --- deterministic rules beat the classifier ------------------------------------------


def test_scam_phrase_overrides_low_llm_verdict(trusted_gleam: sqlite3.Connection) -> None:
    conn = trusted_gleam
    h = Harness(conn, {GLEAM: gleam_page("You won! Just pay shipping to claim your box.")})
    stats, notifier = run_cycle(conn, h, item(GLEAM),
                                classifier=FakeClassifier(default=verdict(scam_likelihood="low")))
    assert notifier.alerts == []
    assert queue(conn) == [(GLEAM, ["SCAM SIGNALS"])]
    assert conn.execute("SELECT scam_likelihood FROM giveaways").fetchone()[0] == "high"
    assert "scam_phrase:fee" in rules(conn)


def test_llm_medium_on_trusted_domain_goes_to_review(trusted_gleam: sqlite3.Connection) -> None:
    conn = trusted_gleam
    h = Harness(conn, {GLEAM: gleam_page()})
    _, notifier = run_cycle(conn, h, item(GLEAM),
                            classifier=FakeClassifier(default=verdict(scam_likelihood="medium")))
    assert notifier.alerts == [] and queue(conn) == [(GLEAM, ["SCAM SCORE NOT LOW"])]
    assert "held_back:scam_score_not_low" in rules(conn)


def test_no_classifier_verdict_goes_to_review(trusted_gleam: sqlite3.Connection) -> None:
    conn = trusted_gleam
    h = Harness(conn, {GLEAM: gleam_page()})
    _, notifier = run_cycle(conn, h, item(GLEAM), classifier=FakeClassifier(default=None))
    assert notifier.alerts == []
    assert queue(conn)[0][1][-1] == "NO CLASSIFIER VERDICT"


# --- tiers and widgets ----------------------------------------------------------------


def test_unknown_domain_goes_to_review(conn: sqlite3.Connection) -> None:
    h = Harness(conn, {SHOP: html(fixture("no_widgets.html"))})
    _, notifier = run_cycle(conn, h, item(SHOP))
    assert notifier.alerts == []
    assert queue(conn) == [(SHOP, ["NOT TRUSTED"])]
    assert "held_back:not_trusted" in rules(conn)


def test_gleam_widget_on_unknown_shop_is_the_alert_target(
    trusted_gleam: sqlite3.Connection,
) -> None:
    conn = trusted_gleam
    h = Harness(conn, {
        SHOP: html(fixture("js_only_shop.html")),
        GLEAM: gleam_page("Pokemon 151 bundle. Total entries: 87"),
    })
    classifier = FakeClassifier()
    _, notifier = run_cycle(conn, h, item(SHOP), classifier=classifier)

    assert len(notifier.alerts) == 1
    sent, badge_list = notifier.alerts[0]
    assert sent["url"] == GLEAM and sent["host_url"] == SHOP
    assert sent["entry_count"] == 87
    assert badge_list == [FEW_ENTRANTS]
    # The widget page was classified together with the host page.
    assert [u for u, _ in classifier.calls[0]["pages"]] == [SHOP, GLEAM]
    assert conn.execute("SELECT host_url, widget_url FROM widget_links").fetchall() == [
        (SHOP, GLEAM)]


def test_widget_on_new_domain_shop_is_held_back(trusted_gleam: sqlite3.Connection) -> None:
    from guard_harness import FakeDomainAge

    conn = trusted_gleam
    h = Harness(conn, {SHOP: html(fixture("js_only_shop.html")), GLEAM: gleam_page()},
                age=FakeDomainAge({"cardboardkingdom.example": 5}))
    _, notifier = run_cycle(conn, h, item(SHOP))
    assert notifier.alerts == []
    assert queue(conn) == [(GLEAM, ["NEW DOMAIN"])]


def test_guardrail_block_writes_filtered_and_skips_classifier(conn: sqlite3.Connection) -> None:
    h = Harness(conn)
    classifier = FakeClassifier()
    url = "https://pokemon-claim.com/win"
    stats, _ = run_cycle(conn, h, item(url), classifier=classifier)
    assert classifier.calls == [] and queue(conn) == []
    assert rules(conn) == ["lookalike_official"]
    # Final decision: never re-checked on later runs.
    stats, _ = run_cycle(conn, h, item(url), classifier=classifier)
    assert stats.items_found == 0


def test_link_hub_page_never_alerted(conn: sqlite3.Connection) -> None:
    admin_store.set_domain_tier(conn, "linktr.ee", "LINK_HUB")
    url = "https://linktr.ee/pokeshop"
    h = Harness(conn, {url: html("<a href='https://a.example'>a</a>")})
    classifier = FakeClassifier()
    _, notifier = run_cycle(conn, h, item(url), classifier=classifier)
    assert notifier.alerts == [] and queue(conn) == [] and classifier.calls == []
    assert rules(conn) == ["link_hub_unresolved"]


# --- PLATFORM posts: judged by account, never fetched ---------------------------------


def test_instagram_link_not_fetched_and_unknown_account_reviewed(
    conn: sqlite3.Connection,
) -> None:
    h = Harness(conn, {INSTA: html("should never be read")})
    _, notifier = run_cycle(conn, h, item(INSTA))
    assert all(r.url.host != "www.instagram.com" for r in h.requests)
    assert notifier.alerts == []
    assert queue(conn) == [(INSTA, ["ORIGINAL POST UNKNOWN"])]
    row = conn.execute("SELECT platform, account_handle, tier FROM giveaways").fetchone()
    assert row == ("instagram", "pokeshop", "PLATFORM")


def test_known_instagram_account_pings(conn: sqlite3.Connection) -> None:
    admin_store.add_known_account(conn, "instagram", "pokeshop")
    h = Harness(conn)
    _, notifier = run_cycle(conn, h, item(INSTA))
    assert [g["url"] for g, _ in notifier.alerts] == [INSTA]


def test_shortener_to_instagram_judged_as_platform_post(conn: sqlite3.Connection) -> None:
    admin_store.set_domain_tier(conn, "bit.ly", "LINK_HUB")
    admin_store.add_known_account(conn, "instagram", "pokeshop")
    short = "https://bit.ly/abc"
    h = Harness(conn, {short: redirect(INSTA)})
    _, notifier = run_cycle(conn, h, item(short))
    assert [g["url"] for g, _ in notifier.alerts] == [INSTA]  # the resolved URL, not bit.ly
    assert all(r.url.host != "www.instagram.com" for r in h.requests)


def test_reddit_thread_without_account_goes_to_review(conn: sqlite3.Connection) -> None:
    url = "https://www.reddit.com/r/PokemonTCG/comments/abc/giveaway/"
    _, notifier = run_cycle(conn, Harness(conn), item(url))
    assert notifier.alerts == [] and queue(conn) == [(url, ["ACCOUNT UNKNOWN"])]


def yt_item(days_old: int, followers: int | None = 48000, original: bool = True) -> RawItem:
    account = AccountInfo("youtube", "@CardShopTV", created_at=NOW - timedelta(days=days_old),
                          followers=followers, is_original_post=original)
    return item(YT, account=account, author="@CardShopTV")


def test_established_youtube_channel_original_post_pings(conn: sqlite3.Connection) -> None:
    _, notifier = run_cycle(conn, Harness(conn), yt_item(800))
    assert len(notifier.alerts) == 1
    sent, _ = notifier.alerts[0]
    assert sent["account_handle"] == "cardshoptv" and sent["account_age_days"] == 800
    assert sent["account_followers"] == 48000


def test_classifier_can_only_tighten_original_post(conn: sqlite3.Connection) -> None:
    classifier = FakeClassifier(default=verdict(poster_is_host=False))
    _, notifier = run_cycle(conn, Harness(conn), yt_item(800), classifier=classifier)
    assert notifier.alerts == [] and queue(conn) == [(YT, ["NOT ORIGINAL POST"])]


def test_new_youtube_channel_goes_to_review(conn: sqlite3.Connection) -> None:
    _, notifier = run_cycle(conn, Harness(conn), yt_item(10))
    assert notifier.alerts == [] and queue(conn) == [(YT, ["ACCOUNT TOO NEW (10d)"])]


@pytest.mark.parametrize("followers", [100, 1_000_000, None])
def test_odds_hint_never_changes_the_ping_decision(
    conn: sqlite3.Connection, followers: int | None,
) -> None:
    _, notifier = run_cycle(conn, Harness(conn), yt_item(800, followers=followers))
    assert len(notifier.alerts) == 1  # pinged either way
    badge_list = notifier.alerts[0][1]
    assert (FEW_ENTRANTS in badge_list) == (followers == 100)


def test_odds_hint_does_not_rescue_a_held_back_post(conn: sqlite3.Connection) -> None:
    _, notifier = run_cycle(conn, Harness(conn), yt_item(10, followers=50))
    assert notifier.alerts == [] and len(queue(conn)) == 1


# --- classifier outcomes --------------------------------------------------------------


@pytest.mark.parametrize(
    ("v", "rule"),
    [
        (verdict(is_giveaway=False), "not_giveaway"),
        (verdict(is_pokemon_tcg=False), "not_giveaway"),
        (verdict(us_eligible="no"), "region"),
        (verdict(deadline="2026-10-01"), "expired"),  # before NOW (2026-10-26)
    ],
)
def test_dropped_items_are_logged_and_not_queued(
    trusted_gleam: sqlite3.Connection, v: Giveaway, rule: str,
) -> None:
    conn = trusted_gleam
    h = Harness(conn, {GLEAM: gleam_page()})
    stats, notifier = run_cycle(conn, h, item(GLEAM), classifier=FakeClassifier(default=v))
    assert notifier.alerts == [] and queue(conn) == []
    assert rules(conn) == [rule]
    assert run_cycle(conn, h, item(GLEAM))[0].items_found == 0  # final decision


def test_classifier_outage_retries_next_run(trusted_gleam: sqlite3.Connection) -> None:
    conn = trusted_gleam
    h = Harness(conn, {GLEAM: gleam_page()})
    down = FakeClassifier(default=ClassifyError("Anthropic API unreachable"))
    stats, notifier = run_cycle(conn, h, item(GLEAM), classifier=down)
    assert notifier.alerts == [] and stats.errors
    assert conn.execute("SELECT COUNT(*) FROM raw_items").fetchone()[0] == 0
    _, notifier = run_cycle(conn, h, item(GLEAM))
    assert len(notifier.alerts) == 1


def test_robots_unreachable_retries_next_run(conn: sqlite3.Connection) -> None:
    import httpx

    h = Harness(conn, {"https://cardboardkingdom.example/robots.txt": httpx.Response(503)})
    stats, _ = run_cycle(conn, h, item(SHOP))
    assert conn.execute("SELECT COUNT(*) FROM raw_items").fetchone()[0] == 0
    assert "robots_unreachable" in rules(conn)


def test_per_run_cap_defers_the_rest(trusted_gleam: sqlite3.Connection) -> None:
    conn = trusted_gleam
    urls = [f"https://gleam.io/G{i}/giveaway" for i in range(3)]
    h = Harness(conn, {u: gleam_page() for u in urls})
    items = [item(u) for u in urls]
    stats, n1 = run_cycle(conn, h, *items, config=RunConfig(max_new_items=2))
    assert stats.processed == 2 and stats.deferred == 1 and len(n1.alerts) == 2
    stats, n2 = run_cycle(conn, h, *items, config=RunConfig(max_new_items=2))
    assert stats.items_found == 1 and len(n2.alerts) == 1


def test_adapter_error_recorded_and_run_continues(trusted_gleam: sqlite3.Connection) -> None:
    class Broken:
        name = "broken"

        def fetch(self) -> list[RawItem]:
            raise ApiError("api.search.brave.com returned HTTP 429")

    conn = trusted_gleam
    h = Harness(conn, {GLEAM: gleam_page()})
    notifier = FakeNotifier()
    stats = Cycle(conn, guard=h.guard, classifier=FakeClassifier(), notifier=notifier,
                  config=RunConfig(), now=NOW).run([Broken(), FakeAdapter(item(GLEAM))])
    assert stats.errors == ["broken: api.search.brave.com returned HTTP 429"]
    assert len(notifier.alerts) == 1
    errors = conn.execute("SELECT errors FROM run_log").fetchone()[0]
    assert "429" in errors


# --- digest ---------------------------------------------------------------------------


def test_daily_digest_sent_once_per_day_after_the_hour(conn: sqlite3.Connection) -> None:
    h = Harness(conn, {SHOP: html(fixture("no_widgets.html"))})
    notifier = FakeNotifier()
    run_cycle(conn, h, item(SHOP), notifier=notifier)  # NOW is 12:00 UTC: too early
    assert notifier.digests == []
    afternoon = NOW.replace(hour=15)
    run_cycle(conn, h, notifier=notifier, now=afternoon)
    run_cycle(conn, h, notifier=notifier, now=afternoon + timedelta(minutes=60))
    assert len(notifier.digests) == 1
    items, total = notifier.digests[0]
    assert total == 1 and items[0]["url"] == SHOP
    run_cycle(conn, h, notifier=notifier, now=afternoon + timedelta(days=1))
    assert len(notifier.digests) == 2


def test_digest_lists_soonest_deadline_first(conn: sqlite3.Connection) -> None:
    urls = {f"https://shop{i}.example/g": d
            for i, d in enumerate(["2026-12-20", None, "2026-11-02"])}
    h = Harness(conn, {u: html("<p>giveaway</p>") for u in urls})
    classifier = FakeClassifier({u: verdict(deadline=d) for u, d in urls.items()})
    notifier = FakeNotifier()
    run_cycle(conn, h, *(item(u) for u in urls), classifier=classifier, notifier=notifier,
              now=NOW.replace(hour=15))
    items, _ = notifier.digests[0]
    assert [i["deadline"] for i in items] == ["2026-11-02", "2026-12-20", None]


# --- helpers and entrypoint -----------------------------------------------------------


def test_canonical_key_drops_tracking_and_trailing_slash() -> None:
    assert canonical_key("https://www.Shop.example/g/?utm_source=x&b=2&a=1&fbclid=z") == (
        "shop.example/g?a=1&b=2")
    assert canonical_key("https://www.youtube.com/watch?v=abc&si=xyz") == (
        "youtube.com/watch?v=abc")


@pytest.mark.parametrize(
    ("url", "handle"),
    [
        ("https://www.instagram.com/pokeshop/p/xyz/", "pokeshop"),
        ("https://www.instagram.com/p/xyz/", None),
        ("https://x.com/PokeShop/status/123", "pokeshop"),
        ("https://www.tiktok.com/@poke.shop/video/1", "poke.shop"),
        ("https://www.youtube.com/@CardShopTV", "cardshoptv"),
        ("https://www.reddit.com/r/PokemonTCG/comments/abc/", None),
        ("https://www.youtube.com/watch?v=abc", None),
    ],
)
def test_handle_from_url(url: str, handle: str | None) -> None:
    assert handle_from_url(url) == handle


def test_pause_stops_before_any_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run, "load_dotenv_if_present", lambda: None)
    monkeypatch.setenv("PAUSE", "1")

    def no_connect(*a: Any, **k: Any) -> None:
        raise AssertionError("must not connect while paused")

    monkeypatch.setattr(run.db, "connect", no_connect)
    assert run.main(["--once"]) == 0


def test_unreachable_database_exits_with_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(run, "load_dotenv_if_present", lambda: None)

    def down(*a: Any, **k: Any) -> None:
        raise run.db.DatabaseUnavailable("Turso database is unreachable (ConnectError).")

    monkeypatch.setattr(run.db, "connect", down)
    assert run.main(["--once"]) == 2
    assert "unreachable" in capsys.readouterr().err


def test_run_config_loads_repo_config() -> None:
    cfg = RunConfig.load()
    assert cfg.eligible_countries == ("US",)
    assert cfg.odds == OddsHint(500, 5000)
    assert cfg.max_new_items == 25
