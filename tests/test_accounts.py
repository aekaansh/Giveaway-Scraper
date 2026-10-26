from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest
from guard_harness import NOW, Harness

from radar import admin_store
from radar.accounts import (
    ACCOUNT_TOO_NEW,
    NOT_ORIGINAL,
    ORIGINAL_UNKNOWN,
    SCAM_SIGNALS,
    AccountInfo,
    evaluate_account,
    lookalike_of,
    record_held_back,
)

POST = "https://www.instagram.com/p/abc123/"


def old_original(handle: str, **kw) -> AccountInfo:
    return AccountInfo("instagram", handle, created_at=NOW - timedelta(days=800),
                       is_original_post=True, **kw)


def test_known_account_pings(conn: sqlite3.Connection) -> None:
    admin_store.add_known_account(conn, "instagram", "@PokeShopUS")
    info = AccountInfo("instagram", "pokeshopus")  # nothing else known about it
    v = evaluate_account(conn, info, "medium", now=NOW)
    assert v.known and v.ping and v.failing == []


def test_known_account_with_scam_phrases_goes_to_review(conn: sqlite3.Connection) -> None:
    admin_store.add_known_account(conn, "instagram", "pokeshopus")
    v = evaluate_account(conn, AccountInfo("instagram", "pokeshopus"), "high", now=NOW)
    assert v.known and not v.ping and v.failing == [SCAM_SIGNALS]


def test_unknown_account_passing_all_rules_pings(conn: sqlite3.Connection) -> None:
    v = evaluate_account(conn, old_original("cardshop_nyc", followers=12000), "low", now=NOW)
    assert not v.known and v.ping
    assert v.followers == 12000 and v.age_days == 800


@pytest.mark.parametrize(
    ("info", "scam", "signal"),
    [
        (AccountInfo("instagram", "newshop", created_at=NOW - timedelta(days=10),
                     is_original_post=True), "low", ACCOUNT_TOO_NEW),
        (AccountInfo("instagram", "fan123", created_at=NOW - timedelta(days=900),
                     is_original_post=False), "low", NOT_ORIGINAL),
        (AccountInfo("instagram", "someone"), "low", ORIGINAL_UNKNOWN),
        (AccountInfo("instagram", "shop", created_at=NOW - timedelta(days=900),
                     is_original_post=True), "medium", "SCAM SCORE NOT LOW"),
        (AccountInfo("instagram", "shop", created_at=NOW - timedelta(days=900),
                     is_original_post=True), "high", SCAM_SIGNALS),
    ],
)
def test_unknown_account_failing_a_rule_goes_to_review(
    conn: sqlite3.Connection, info: AccountInfo, scam: str, signal: str
) -> None:
    v = evaluate_account(conn, info, scam, now=NOW)
    assert not v.ping
    assert any(f.startswith(signal) for f in v.failing), v.failing


def test_unknown_age_does_not_fail_age_rule(conn: sqlite3.Connection) -> None:
    info = AccountInfo("youtube", "bigcollector", is_original_post=True)
    assert evaluate_account(conn, info, "low", now=NOW).ping


@pytest.mark.parametrize(
    "handle",
    ["pokeshopus_giveaway", "pokeshop.us", "p0keshopus", "pokeshopuss", "official_pokeshopus",
     "pokeshopus.official", "P0KESH0PUS"],
)
def test_lookalike_of_known_handle_goes_to_review(conn: sqlite3.Connection, handle: str) -> None:
    admin_store.add_known_account(conn, "instagram", "pokeshopus")
    v = evaluate_account(conn, old_original(handle), "low", now=NOW)
    assert v.lookalike_of == "pokeshopus"
    assert not v.ping
    assert any(f.startswith("LOOKALIKE HANDLE") for f in v.failing)


def test_unrelated_handles_are_not_lookalikes() -> None:
    known = ["pokeshopus", "cardkingdom"]
    assert lookalike_of("pokeshopus", known) is None  # exact = the real account
    assert lookalike_of("tcgdaily", known) is None
    assert lookalike_of("cardshopnyc", known) is None


def test_short_handles_use_tighter_distance() -> None:
    assert lookalike_of("abd", ["abc"]) == "abc"
    assert lookalike_of("xyz", ["abc"]) is None
    assert lookalike_of("abcxy", ["abc"]) is None


def test_lookalike_check_is_per_platform(conn: sqlite3.Connection) -> None:
    admin_store.add_known_account(conn, "youtube", "pokeshopus")
    v = evaluate_account(conn, old_original("pokeshopus_giveaway"), "low", now=NOW)
    assert v.lookalike_of is None


def test_guard_flags_block_ping(conn: sqlite3.Connection) -> None:
    admin_store.add_known_account(conn, "instagram", "pokeshopus")
    v = evaluate_account(conn, AccountInfo("instagram", "pokeshopus"), "low",
                         guard_flags=["NOT TRUSTED"], now=NOW)
    assert not v.ping


def test_platform_url_never_trusted_so_account_decides(conn: sqlite3.Connection) -> None:
    admin_store.set_domain_tier(conn, "instagram.com", "PLATFORM")
    result = Harness(conn).guard.check(POST)
    assert result.tier == "PLATFORM" and not result.trusted
    assert evaluate_account(conn, old_original("cardshop_nyc"), "low",
                            guard_flags=result.flags, now=NOW).ping


def test_held_back_post_writes_filtered_items(conn: sqlite3.Connection) -> None:
    admin_store.add_known_account(conn, "instagram", "pokeshopus")
    info = AccountInfo("instagram", "pokeshopus_giveaway", created_at=NOW - timedelta(days=3),
                       is_original_post=False)
    v = evaluate_account(conn, info, "high", now=NOW)
    record_held_back(conn, POST, v)
    rules = [r[0] for r in conn.execute("SELECT rule FROM filtered_items ORDER BY id")]
    assert rules == ["account:scam_signals", "account:lookalike_handle",
                     "account:account_too_new", "account:not_original_post"]


def test_pinged_post_writes_nothing(conn: sqlite3.Connection) -> None:
    v = evaluate_account(conn, old_original("cardshop_nyc"), "low", now=NOW)
    record_held_back(conn, POST, v)
    assert conn.execute("SELECT COUNT(*) FROM filtered_items").fetchone()[0] == 0
