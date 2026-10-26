"""Connection factory. The ONLY module that opens database connections.

DB_BACKEND=turso uses the hosted Turso database; DB_BACKEND=sqlite (default) uses a
local file or `:memory:`. Both speak DB-API 2.0 with `?` placeholders, so the rest of
the code (store.py, admin_store.py) is backend-agnostic.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from radar.config import require_env

DEFAULT_SQLITE_PATH = "radar.db"


class DatabaseUnavailable(RuntimeError):
    """The configured database could not be reached. The run must stop and send nothing."""


def backend() -> str:
    value = os.environ.get("DB_BACKEND", "sqlite").strip().lower() or "sqlite"
    if value not in ("sqlite", "turso"):
        raise ValueError(f"DB_BACKEND must be 'sqlite' or 'turso', got {value!r}")
    return value


def connect(sqlite_path: str | None = None) -> Any:
    """Open one connection for the whole run. Caller closes it at the end."""
    if backend() == "turso":
        return _connect_turso()
    path = sqlite_path or os.environ.get("SQLITE_PATH", "").strip() or DEFAULT_SQLITE_PATH
    return sqlite3.connect(path)


def _connect_turso() -> Any:
    import turso_serverless

    url = require_env("TURSO_DATABASE_URL")
    token = require_env("TURSO_AUTH_TOKEN")
    try:
        conn = turso_serverless.connect(url, auth_token=token)
        conn.execute("SELECT 1").fetchone()
    except Exception as exc:  # network/auth errors surface as many types
        # Never include the URL or token in the message.
        raise DatabaseUnavailable(
            f"Turso database is unreachable ({type(exc).__name__}). "
            "Nothing was fetched or sent; the next run will catch up."
        ) from exc
    return conn
