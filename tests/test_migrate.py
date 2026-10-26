from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from radar import db
from radar.config import MissingConfigError
from radar.migrate import discover, migrate, split_statements

EXPECTED_TABLES = {
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
    "schema_version",
}


def _tables(c: sqlite3.Connection) -> set[str]:
    rows = c.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {r[0] for r in rows}


def test_migrations_apply_cleanly_to_empty_db() -> None:
    c = sqlite3.connect(":memory:")
    applied = migrate(c)
    assert applied == [m.version for m in discover()]
    assert _tables(c) >= EXPECTED_TABLES


def test_migrate_is_idempotent() -> None:
    c = sqlite3.connect(":memory:")
    migrate(c)
    assert migrate(c) == []
    versions = c.execute("SELECT version FROM schema_version").fetchall()
    assert len(versions) == len(discover())


def test_no_personal_data_tables() -> None:
    c = sqlite3.connect(":memory:")
    migrate(c)
    assert "user_profile" not in _tables(c)
    for (table,) in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
        cols = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
        assert not cols & {"email", "address", "full_name", "phone"}, table


def test_new_migration_applied_after_existing(tmp_path: Path) -> None:
    (tmp_path / "001_a.sql").write_text("CREATE TABLE a (x INTEGER);", encoding="utf-8")
    c = sqlite3.connect(":memory:")
    assert migrate(c, tmp_path) == [1]
    (tmp_path / "002_b.sql").write_text("CREATE TABLE b (y INTEGER);", encoding="utf-8")
    assert migrate(c, tmp_path) == [2]
    assert {"a", "b"} <= _tables(c)


def test_bad_migration_filename_rejected(tmp_path: Path) -> None:
    (tmp_path / "init.sql").write_text("SELECT 1;", encoding="utf-8")
    with pytest.raises(ValueError, match="NNN_name.sql"):
        discover(tmp_path)


def test_split_statements_strips_comments() -> None:
    sql = "-- header\nCREATE TABLE t (x INTEGER); -- trailing\n\nCREATE INDEX i ON t (x);\n"
    assert split_statements(sql) == ["CREATE TABLE t (x INTEGER)", "CREATE INDEX i ON t (x)"]


def test_turso_backend_requires_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DB_BACKEND", "turso")
    with pytest.raises(MissingConfigError, match="TURSO_DATABASE_URL"):
        db.connect()


def test_unknown_backend_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DB_BACKEND", "postgres")
    with pytest.raises(ValueError, match="DB_BACKEND"):
        db.connect()


def test_sqlite_backend_default(tmp_path: Path) -> None:
    c = db.connect(str(tmp_path / "x.db"))
    migrate(c)
    assert "domain_tiers" in _tables(c)
    c.close()
