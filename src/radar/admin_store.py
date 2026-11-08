"""Human-only writes: domain_tiers and known_accounts, seeding, export/import.

Called ONLY from dashboard buttons and `radar.admin` commands run by the human.
Polling-path modules must never import this module (enforced by tests/test_import_graph.py).
"""

from __future__ import annotations

import re
from typing import Any

from radar.domains import normalize_host
from radar.store import TIERS, iso, normalize_handle, rows, utcnow

EXPORT_TABLES = (
    "sources",
    "raw_items",
    "giveaways",
    "review_queue",
    "entries_log",
    "url_checks",
    "fetch_log",
    "filtered_items",
    "domain_tiers",
    "known_accounts",
    "run_log",
    "widget_links",
    "notify_state",
)
UNREVIEWED = "UNREVIEWED"
_COLUMN_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


def set_domain_tier(
    conn: Any, domain: str, tier: str, *, added_by: str = "human", note: str | None = None
) -> None:
    """Insert or overwrite a domain's tier (human decision, so it may loosen too)."""
    tier = tier.upper()
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {TIERS}, got {tier!r}")
    conn.execute(
        "INSERT INTO domain_tiers (domain, tier, added_by, added_at, note) VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(domain) DO UPDATE SET tier = excluded.tier, added_by = excluded.added_by,"
        " added_at = excluded.added_at, note = excluded.note",
        (normalize_host(domain), tier, added_by, iso(utcnow()), note),
    )
    conn.commit()


def trust_domain(conn: Any, domain: str, note: str | None = None) -> None:
    set_domain_tier(conn, domain, "TRUSTED", note=note)


def block_domain(conn: Any, domain: str, note: str | None = None) -> None:
    set_domain_tier(conn, domain, "BLOCKED", note=note)


def add_known_account(conn: Any, platform: str, handle: str, note: str | None = None) -> None:
    conn.execute(
        "INSERT INTO known_accounts (platform, handle, added_by, added_at, note)"
        " VALUES (?, ?, 'human', ?, ?)"
        " ON CONFLICT(platform, handle) DO UPDATE SET note = excluded.note",
        (platform.lower(), normalize_handle(handle), iso(utcnow()), note),
    )
    conn.commit()


# --- seeding (inserts missing rows, never overwrites) -------------------------------


def seed_domain_tiers(conn: Any, entries: list[dict[str, Any]]) -> tuple[int, list[str]]:
    """Insert missing domain_tiers rows from seed data.

    Existing rows (including human edits) are never touched. Entries whose note
    contains UNREVIEWED are skipped so drafted lists can't go live before approval.
    Returns (inserted count, skipped-unreviewed domains).
    """
    inserted = 0
    skipped: list[str] = []
    now = iso(utcnow())
    for e in entries:
        domain = normalize_host(e["domain"])
        tier = str(e["tier"]).upper()
        note = e.get("note")
        if tier not in TIERS:
            raise ValueError(f"seed entry {domain}: bad tier {tier!r}")
        if note and UNREVIEWED in str(note).upper():
            skipped.append(domain)
            continue
        cur = conn.execute(
            "INSERT OR IGNORE INTO domain_tiers (domain, tier, added_by, added_at, note)"
            " VALUES (?, ?, 'seed', ?, ?)",
            (domain, tier, now, note),
        )
        inserted += cur.rowcount
    conn.commit()
    return inserted, skipped


def seed_known_accounts(conn: Any, entries: list[dict[str, Any]]) -> int:
    inserted = 0
    now = iso(utcnow())
    for e in entries:
        cur = conn.execute(
            "INSERT OR IGNORE INTO known_accounts (platform, handle, added_by, added_at, note)"
            " VALUES (?, ?, 'seed', ?, ?)",
            (str(e["platform"]).lower(), normalize_handle(e["handle"]), now, e.get("note")),
        )
        inserted += cur.rowcount
    conn.commit()
    return inserted


# --- backup ---------------------------------------------------------------------------


def export_all(conn: Any) -> dict[str, list[dict[str, Any]]]:
    return {t: rows(conn.execute(f"SELECT * FROM {t}")) for t in EXPORT_TABLES}


def import_all(conn: Any, data: dict[str, list[dict[str, Any]]]) -> dict[str, int]:
    """Restore an export into a migrated DB. Rows with the same key are replaced."""
    counts: dict[str, int] = {}
    for table in EXPORT_TABLES:
        table_rows = data.get(table, [])
        for row in table_rows:
            cols = list(row)
            bad = [c for c in cols if not _COLUMN_RE.match(c)]
            if bad:
                raise ValueError(f"import file has invalid column names in {table}: {bad}")
            conn.execute(
                f"INSERT OR REPLACE INTO {table} ({', '.join(cols)})"
                f" VALUES ({', '.join('?' for _ in cols)})",
                [row[c] for c in cols],
            )
        counts[table] = len(table_rows)
    conn.commit()
    return counts
