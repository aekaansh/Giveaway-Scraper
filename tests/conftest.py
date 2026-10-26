"""Shared fixtures. Tests never touch the network or Turso: in-memory SQLite only."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator

import pytest

from radar.migrate import migrate


@pytest.fixture(autouse=True)
def _no_real_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    # Guard against a developer's .env pointing tests at Turso or pausing them.
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.delenv("TURSO_DATABASE_URL", raising=False)
    monkeypatch.delenv("TURSO_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("PAUSE", raising=False)


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(":memory:")
    migrate(c)
    yield c
    c.close()
