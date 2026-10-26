"""Apply pending `migrations/NNN_name.sql` files in order, tracked in `schema_version`.

Idempotent: every run calls `migrate()` first. Never edit an applied migration; add a
new file instead. Each migration and its version row are committed together.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_NAME_RE = re.compile(r"^(\d{3})_([a-z0-9_]+)\.sql$")


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path


def discover(migrations_dir: Path = MIGRATIONS_DIR) -> list[Migration]:
    found: list[Migration] = []
    for path in sorted(migrations_dir.glob("*.sql")):
        m = _NAME_RE.match(path.name)
        if not m:
            raise ValueError(f"Bad migration filename {path.name!r}; expected NNN_name.sql")
        found.append(Migration(int(m.group(1)), m.group(2), path))
    versions = [m.version for m in found]
    if len(versions) != len(set(versions)):
        raise ValueError("Duplicate migration version numbers")
    return found


def split_statements(sql: str) -> list[str]:
    """Split a migration into statements (comments stripped, split on semicolons)."""
    lines = [line.split("--", 1)[0] for line in sql.splitlines()]
    return [stmt.strip() for stmt in "\n".join(lines).split(";") if stmt.strip()]


def applied_versions(conn: Any) -> set[int]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version ("
        " version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    conn.commit()
    return {row[0] for row in conn.execute("SELECT version FROM schema_version").fetchall()}


def migrate(conn: Any, migrations_dir: Path = MIGRATIONS_DIR) -> list[int]:
    """Apply pending migrations. Returns the versions applied by this call."""
    done = applied_versions(conn)
    newly: list[int] = []
    for mig in discover(migrations_dir):
        if mig.version in done:
            continue
        try:
            for stmt in split_statements(mig.path.read_text(encoding="utf-8")):
                conn.execute(stmt)
            conn.execute(
                "INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)",
                (mig.version, mig.name, datetime.now(UTC).isoformat(timespec="seconds")),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        newly.append(mig.version)
    return newly
