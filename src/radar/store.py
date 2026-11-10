"""Database reads/writes for the polling path (run, adapters, url_guard, scoring, notify).

Never writes TRUSTED tiers or known_accounts: those are human-only and live in
admin_store.py, which polling code must not import. The single exception allowed here
is `block_domain_from_guard`, used by url_guard after a Safe Browsing match
(tightening only, never loosening).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from radar.domains import host_chain, normalize_host

TIERS = ("TRUSTED", "PLATFORM", "LINK_HUB", "BLOCKED")
CHECK_TTL = timedelta(hours=24)


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def rows(cursor: Any) -> list[dict[str, Any]]:
    """Fetch all rows as dicts (works for sqlite3 and turso_serverless cursors)."""
    names = [d[0] for d in cursor.description or ()]
    return [dict(zip(names, r, strict=True)) for r in cursor.fetchall()]


# --- domain tiers / known accounts (read-only here) ---------------------------------


def get_domain_tier(conn: Any, host: str) -> str | None:
    """Tier for a host, checking the host and each parent up to the registrable domain.

    BLOCKED anywhere in the chain wins. Otherwise the most specific entry wins.
    None means UNKNOWN (not in the table).
    """
    chain = host_chain(host)
    placeholders = ",".join("?" for _ in chain)
    found = dict(
        conn.execute(
            f"SELECT domain, tier FROM domain_tiers WHERE domain IN ({placeholders})", chain
        ).fetchall()
    )
    if "BLOCKED" in found.values():
        return "BLOCKED"
    for h in chain:
        if h in found:
            return found[h]
    return None


def is_known_account(conn: Any, platform: str, handle: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM known_accounts WHERE platform = ? AND handle = ?",
        (platform.lower(), normalize_handle(handle)),
    ).fetchone()
    return row is not None


def list_known_handles(conn: Any, platform: str) -> list[str]:
    cur = conn.execute("SELECT handle FROM known_accounts WHERE platform = ?", (platform.lower(),))
    return [r[0] for r in cur.fetchall()]


def normalize_handle(handle: str) -> str:
    return handle.strip().lstrip("@").lower()


def block_domain_from_guard(conn: Any, domain: str, note: str) -> None:
    """url_guard only: mark a domain BLOCKED after a Safe Browsing match.

    Tightening only. It may overwrite any tier with BLOCKED, never the reverse.
    """
    now = iso(utcnow())
    conn.execute(
        "INSERT INTO domain_tiers (domain, tier, added_by, added_at, note)"
        " VALUES (?, 'BLOCKED', 'url_guard', ?, ?)"
        " ON CONFLICT(domain) DO UPDATE SET tier = 'BLOCKED', added_by = 'url_guard',"
        " added_at = excluded.added_at, note = excluded.note"
        " WHERE domain_tiers.tier != 'BLOCKED'",
        (normalize_host(domain), now, note),
    )
    conn.commit()


# --- reputation cache (url_checks, 24h TTL) ----------------------------------------


def get_cached_check(
    conn: Any, kind: str, key: str, *, now: datetime | None = None, ttl: timedelta = CHECK_TTL
) -> dict[str, Any] | None:
    """A cached reputation result younger than `ttl`, else None."""
    cur = conn.execute(
        "SELECT verdict, detail, checked_at FROM url_checks WHERE kind = ? AND check_key = ?",
        (kind, key),
    )
    found = rows(cur)
    if not found:
        return None
    row = found[0]
    checked = datetime.fromisoformat(row["checked_at"])
    if (now or utcnow()) - checked > ttl:
        return None
    return row


def put_check(
    conn: Any, kind: str, key: str, verdict: str, detail: str | None = None,
    *, now: datetime | None = None,
) -> None:
    conn.execute(
        "INSERT INTO url_checks (kind, check_key, verdict, detail, checked_at)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(kind, check_key) DO UPDATE SET verdict = excluded.verdict,"
        " detail = excluded.detail, checked_at = excluded.checked_at",
        (kind, key, verdict, detail, iso(now or utcnow())),
    )
    conn.commit()


# --- monitoring logs ----------------------------------------------------------------


def log_fetch(
    conn: Any, url: str, domain: str | None, tier: str | None, verdict: str,
    status_code: int | None = None,
) -> None:
    conn.execute(
        "INSERT INTO fetch_log (url, domain, tier, verdict, status_code, fetched_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (url, domain, tier, verdict, status_code, iso(utcnow())),
    )
    conn.commit()


def record_filtered(conn: Any, url: str, rule: str, reason: str) -> None:
    """Every item dropped or held back by a guardrail gets one row here."""
    conn.execute(
        "INSERT INTO filtered_items (url, rule, reason, created_at) VALUES (?, ?, ?, ?)",
        (url, rule, reason, iso(utcnow())),
    )
    conn.commit()


def record_widget_link(conn: Any, host_url: str, widget_url: str, kind: str) -> None:
    """Remember that `host_url` embeds the giveaway widget at `widget_url`."""
    conn.execute(
        "INSERT OR IGNORE INTO widget_links (host_url, widget_url, kind, found_at)"
        " VALUES (?, ?, ?, ?)",
        (host_url, widget_url, kind, iso(utcnow())),
    )
    conn.commit()


# --- items, giveaways, review queue -------------------------------------------------


def raw_item_exists(conn: Any, external_id: str) -> bool:
    row = conn.execute("SELECT 1 FROM raw_items WHERE external_id = ?", (external_id,)).fetchone()
    return row is not None


def insert_raw_item(
    conn: Any, *, source: str, external_id: str, url: str, title: str | None,
    body: str | None, author: str | None, published_at: str | None,
) -> int:
    """Mark a source item as processed (dedup key: external_id). Returns its id."""
    conn.execute(
        "INSERT OR IGNORE INTO raw_items"
        " (source, external_id, url, title, body, author, published_at, fetched_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (source, external_id, url, title, body, author, published_at, iso(utcnow())),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM raw_items WHERE external_id = ?", (external_id,)).fetchone()
    return int(row[0])


GIVEAWAY_FIELDS = (
    "raw_item_id", "url", "host_url", "domain", "tier", "platform", "account_handle", "title",
    "summary", "region", "deadline", "scam_likelihood", "flags_json", "alert_eligible",
    "entry_count", "account_followers", "domain_age_days", "account_age_days",
)


def insert_giveaway(conn: Any, canonical_key: str, **fields: Any) -> int | None:
    """Insert a new giveaway. Returns its id, or None if this canonical_key already exists
    (the same giveaway found again: nothing new to alert or queue)."""
    unknown = set(fields) - set(GIVEAWAY_FIELDS)
    if unknown:
        raise ValueError(f"unknown giveaway fields: {sorted(unknown)}")
    if conn.execute(
        "SELECT 1 FROM giveaways WHERE canonical_key = ?", (canonical_key,)
    ).fetchone():
        return None
    cols = ["canonical_key", *fields, "created_at"]
    cur = conn.execute(
        f"INSERT INTO giveaways ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
        [canonical_key, *fields.values(), iso(utcnow())],
    )
    conn.commit()
    return int(cur.lastrowid)


def enqueue_review(conn: Any, giveaway_id: int, reasons: list[str], deadline: str | None) -> None:
    now = iso(utcnow())
    conn.execute(
        "INSERT OR IGNORE INTO review_queue"
        " (giveaway_id, status, reasons_json, deadline, created_at, updated_at)"
        " VALUES (?, 'new', ?, ?, ?, ?)",
        (giveaway_id, json.dumps(reasons), deadline, now, now),
    )
    conn.commit()


def pending_alerts(conn: Any) -> list[dict[str, Any]]:
    """Giveaways that passed the ping rules but haven't been sent to Discord yet."""
    return rows(conn.execute(
        "SELECT * FROM giveaways WHERE alert_eligible = 1 AND alerted_at IS NULL ORDER BY id"
    ))


def mark_alerted(conn: Any, giveaway_id: int) -> None:
    conn.execute("UPDATE giveaways SET alerted_at = ? WHERE id = ?",
                 (iso(utcnow()), giveaway_id))
    conn.commit()


def demote_to_review(conn: Any, giveaway: dict[str, Any], reasons: list[str]) -> None:
    """A pending alert that failed its final check goes to the review queue instead."""
    conn.execute("UPDATE giveaways SET alert_eligible = 0 WHERE id = ?", (giveaway["id"],))
    conn.commit()
    enqueue_review(conn, giveaway["id"], reasons, giveaway.get("deadline"))


def review_queue_items(conn: Any, limit: int) -> tuple[list[dict[str, Any]], int]:
    """New queue items, soonest deadline first (no deadline last), and the total count."""
    total = conn.execute("SELECT COUNT(*) FROM review_queue WHERE status = 'new'").fetchone()[0]
    items = rows(conn.execute(
        "SELECT g.*, q.reasons_json FROM review_queue q JOIN giveaways g ON g.id = q.giveaway_id"
        " WHERE q.status = 'new'"
        " ORDER BY q.deadline IS NULL, q.deadline, q.created_at LIMIT ?",
        (limit,),
    ))
    return items, int(total)


def get_state(conn: Any, key: str) -> str | None:
    row = conn.execute("SELECT value FROM notify_state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_state(conn: Any, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO notify_state (key, value, updated_at) VALUES (?, ?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value, iso(utcnow())),
    )
    conn.commit()


# --- run log ------------------------------------------------------------------------


def start_run(conn: Any) -> int:
    cur = conn.execute("INSERT INTO run_log (started_at) VALUES (?)", (iso(utcnow()),))
    conn.commit()
    return int(cur.lastrowid)


def finish_run(
    conn: Any, run_id: int, *, items_found: int, alerts_sent: int, errors: list[str]
) -> None:
    conn.execute(
        "UPDATE run_log SET finished_at = ?, items_found = ?, alerts_sent = ?, errors = ?"
        " WHERE id = ?",
        (iso(utcnow()), items_found, alerts_sent, json.dumps(errors) if errors else None, run_id),
    )
    conn.commit()
