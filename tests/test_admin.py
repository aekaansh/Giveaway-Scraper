from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from radar import admin, admin_store, store
from radar.config import CONFIG_DIR


def test_seed_never_overwrites_human_edit(conn: sqlite3.Connection) -> None:
    admin_store.block_domain(conn, "gleam.io", note="human decision")
    inserted, _ = admin_store.seed_domain_tiers(
        conn, [{"domain": "gleam.io", "tier": "TRUSTED", "note": "giveaway platform"}]
    )
    assert inserted == 0
    row = conn.execute("SELECT tier, added_by, note FROM domain_tiers").fetchone()
    assert row == ("BLOCKED", "human", "human decision")


def test_seed_is_idempotent(conn: sqlite3.Connection) -> None:
    entries = [{"domain": "kingsumo.com", "tier": "TRUSTED"}]
    assert admin_store.seed_domain_tiers(conn, entries) == (1, [])
    assert admin_store.seed_domain_tiers(conn, entries) == (0, [])


def test_seed_skips_unreviewed(conn: sqlite3.Connection) -> None:
    entries = [{"domain": "shop.example", "tier": "TRUSTED", "note": "UNREVIEWED - draft"}]
    assert admin_store.seed_domain_tiers(conn, entries) == (0, ["shop.example"])
    assert store.get_domain_tier(conn, "shop.example") is None


def test_seed_rejects_bad_tier(conn: sqlite3.Connection) -> None:
    with pytest.raises(ValueError, match="bad tier"):
        admin_store.seed_domain_tiers(conn, [{"domain": "a.example", "tier": "SAFE"}])


def test_seed_command_with_real_config(conn: sqlite3.Connection, capsys) -> None:
    admin.seed(conn, CONFIG_DIR)
    for official in ("pokemon.com", "pokemoncenter.com", "tcgplayer.com", "gleam.io"):
        assert store.get_domain_tier(conn, official) == "TRUSTED"
    assert store.get_domain_tier(conn, "instagram.com") == "PLATFORM"
    assert store.get_domain_tier(conn, "bit.ly") == "LINK_HUB"
    # Drafted shops stay out until the human approves them.
    assert store.get_domain_tier(conn, "trollandtoad.com") is None
    assert conn.execute("SELECT COUNT(*) FROM known_accounts").fetchone()[0] == 0
    assert "UNREVIEWED" in capsys.readouterr().out


def test_set_domain_tier_rejects_unknown_tier(conn: sqlite3.Connection) -> None:
    with pytest.raises(ValueError):
        admin_store.set_domain_tier(conn, "a.example", "UNKNOWN")


def test_export_import_round_trip(conn: sqlite3.Connection) -> None:
    admin_store.trust_domain(conn, "gleam.io", "platform")
    admin_store.add_known_account(conn, "youtube", "@shop")
    store.record_filtered(conn, "https://x.example/", "lookalike_official", "near miss")
    data = json.loads(json.dumps(admin_store.export_all(conn)))

    fresh = sqlite3.connect(":memory:")
    from radar.migrate import migrate

    migrate(fresh)
    counts = admin_store.import_all(fresh, data)
    assert counts["domain_tiers"] == 1 and counts["known_accounts"] == 1
    assert admin_store.export_all(fresh) == data


def test_import_rejects_injected_column_names(conn: sqlite3.Connection) -> None:
    bad = {"domain_tiers": [{"domain) VALUES (1); DROP TABLE run_log; --": "x"}]}
    with pytest.raises(ValueError, match="invalid column"):
        admin_store.import_all(conn, bad)


def test_cli_migrate_seed_export_against_sqlite_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "radar.db"))
    monkeypatch.setattr(admin, "load_dotenv_if_present", lambda: None)
    assert admin.main(["migrate"]) == 0
    assert admin.main(["migrate"]) == 0
    assert "none pending" in capsys.readouterr().out
    assert admin.main(["seed"]) == 0
    assert admin.main(["block-domain", "gleam.io", "--note", "test"]) == 0
    assert admin.main(["seed"]) == 0  # second seed must not undo the block
    c = sqlite3.connect(tmp_path / "radar.db")
    assert store.get_domain_tier(c, "gleam.io") == "BLOCKED"
    c.close()
    out = tmp_path / "dump.json"
    assert admin.main(["export", "--out", str(out)]) == 0
    assert json.loads(out.read_text("utf-8"))["domain_tiers"]


def test_cli_turso_without_credentials_fails_clearly(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setenv("DB_BACKEND", "turso")
    monkeypatch.setattr(admin, "load_dotenv_if_present", lambda: None)
    assert admin.main(["migrate"]) == 2
    assert "TURSO_DATABASE_URL" in capsys.readouterr().err
