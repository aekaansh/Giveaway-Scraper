from __future__ import annotations

import sqlite3
from datetime import timedelta

from radar import admin_store, store


def _tier_row(conn: sqlite3.Connection, domain: str) -> tuple:
    return conn.execute(
        "SELECT tier, added_by, note FROM domain_tiers WHERE domain = ?", (domain,)
    ).fetchone()


def test_tier_lookup_walks_parent_domains(conn: sqlite3.Connection) -> None:
    admin_store.set_domain_tier(conn, "gleam.io", "TRUSTED")
    assert store.get_domain_tier(conn, "gleam.io") == "TRUSTED"
    assert store.get_domain_tier(conn, "www.gleam.io") == "TRUSTED"
    assert store.get_domain_tier(conn, "gleam.io.evil.com") is None
    assert store.get_domain_tier(conn, "unknown.example") is None


def test_most_specific_tier_wins_but_blocked_anywhere_wins(conn: sqlite3.Connection) -> None:
    admin_store.set_domain_tier(conn, "example.com", "PLATFORM")
    admin_store.set_domain_tier(conn, "shop.example.com", "TRUSTED")
    assert store.get_domain_tier(conn, "shop.example.com") == "TRUSTED"
    admin_store.set_domain_tier(conn, "example.com", "BLOCKED")
    assert store.get_domain_tier(conn, "shop.example.com") == "BLOCKED"


def test_private_suffix_subdomains_are_separate(conn: sqlite3.Connection) -> None:
    store.block_domain_from_guard(conn, "evil.github.io", "test")
    assert store.get_domain_tier(conn, "evil.github.io") == "BLOCKED"
    assert store.get_domain_tier(conn, "good.github.io") is None


def test_guard_block_tightens_trusted(conn: sqlite3.Connection) -> None:
    admin_store.trust_domain(conn, "shop.example")
    store.block_domain_from_guard(conn, "shop.example", "safe browsing match")
    assert _tier_row(conn, "shop.example")[:2] == ("BLOCKED", "url_guard")


def test_guard_block_keeps_existing_human_block(conn: sqlite3.Connection) -> None:
    admin_store.block_domain(conn, "bad.example", note="marked scam")
    store.block_domain_from_guard(conn, "bad.example", "safe browsing match")
    assert _tier_row(conn, "bad.example") == ("BLOCKED", "human", "marked scam")


def test_check_cache_respects_ttl(conn: sqlite3.Connection) -> None:
    now = store.utcnow()
    store.put_check(conn, "safe_browsing", "https://a.example/", "clean", now=now)
    assert store.get_cached_check(conn, "safe_browsing", "https://a.example/", now=now)
    later = now + timedelta(hours=25)
    assert store.get_cached_check(conn, "safe_browsing", "https://a.example/", now=later) is None
    store.put_check(conn, "safe_browsing", "https://a.example/", "match", now=later)
    hit = store.get_cached_check(conn, "safe_browsing", "https://a.example/", now=later)
    assert hit is not None and hit["verdict"] == "match"


def test_known_accounts_case_and_at_insensitive(conn: sqlite3.Connection) -> None:
    admin_store.add_known_account(conn, "YouTube", "@SomeShop")
    assert store.is_known_account(conn, "youtube", "someshop")
    assert store.is_known_account(conn, "youtube", "@SOMESHOP")
    assert not store.is_known_account(conn, "instagram", "someshop")
    assert store.list_known_handles(conn, "youtube") == ["someshop"]


def test_logs_and_run_log(conn: sqlite3.Connection) -> None:
    store.log_fetch(conn, "https://a.example/", "a.example", None, "ALLOW", 200)
    store.record_filtered(conn, "https://b.example/", "scheme", "ftp not allowed")
    run_id = store.start_run(conn)
    store.finish_run(conn, run_id, items_found=3, alerts_sent=1, errors=["x"])
    assert conn.execute("SELECT COUNT(*) FROM fetch_log").fetchone()[0] == 1
    assert conn.execute("SELECT rule FROM filtered_items").fetchone()[0] == "scheme"
    row = conn.execute("SELECT items_found, alerts_sent, errors FROM run_log").fetchone()
    assert row == (3, 1, '["x"]')
