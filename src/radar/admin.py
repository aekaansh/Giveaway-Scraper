"""Human-run admin CLI: migrate, seed, export, import, trust/block domains, trust accounts.

    uv run python -m radar.admin migrate
    uv run python -m radar.admin seed
    uv run python -m radar.admin export [--out FILE]
    uv run python -m radar.admin import FILE
    uv run python -m radar.admin trust-domain DOMAIN [--note TEXT]
    uv run python -m radar.admin block-domain DOMAIN [--note TEXT]
    uv run python -m radar.admin trust-account PLATFORM HANDLE [--note TEXT]

Output is counts and domains only, never secrets or full rows.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from radar import admin_store, db
from radar.config import CONFIG_DIR, MissingConfigError, load_dotenv_if_present, load_yaml
from radar.migrate import migrate
from radar.store import iso, utcnow


def seed(conn: Any, config_dir: Path = CONFIG_DIR) -> None:
    official = load_yaml("protected_names.yaml", config_dir).get("official_domains") or []
    entries = [{"domain": d, "tier": "TRUSTED", "note": "official domain"} for d in official]
    entries += load_yaml("domains.yaml", config_dir).get("domains") or []
    inserted, skipped = admin_store.seed_domain_tiers(conn, entries)
    print(f"domain_tiers: {inserted} inserted, {len(entries) - inserted - len(skipped)} existed")
    if skipped:
        print(f"skipped {len(skipped)} UNREVIEWED entries: {', '.join(skipped)}")
    accounts = load_yaml("known_accounts.yaml", config_dir).get("accounts") or []
    print(f"known_accounts: {admin_store.seed_known_accounts(conn, accounts)} inserted")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="radar.admin", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate", help="apply pending schema migrations")
    sub.add_parser("seed", help="insert missing seed rows from config/*.yaml")
    exp = sub.add_parser("export", help="dump all tables to JSON")
    exp.add_argument("--out", type=Path)
    imp = sub.add_parser("import", help="restore a JSON export")
    imp.add_argument("file", type=Path)
    for name in ("trust-domain", "block-domain"):
        sp = sub.add_parser(name)
        sp.add_argument("domain")
        sp.add_argument("--note")
    ta = sub.add_parser("trust-account")
    ta.add_argument("platform")
    ta.add_argument("handle")
    ta.add_argument("--note")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    load_dotenv_if_present()
    try:
        conn = db.connect()
    except (MissingConfigError, db.DatabaseUnavailable) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        applied = migrate(conn)
        if args.cmd == "migrate":
            print(f"applied migrations: {applied or 'none pending'}")
        elif args.cmd == "seed":
            seed(conn)
        elif args.cmd == "export":
            out = args.out or Path(f"radar-export-{iso(utcnow()).replace(':', '')}.json")
            data = admin_store.export_all(conn)
            out.write_text(json.dumps(data, indent=1), encoding="utf-8")
            print(f"exported {sum(len(v) for v in data.values())} rows to {out}")
        elif args.cmd == "import":
            counts = admin_store.import_all(conn, json.loads(args.file.read_text("utf-8")))
            print(f"imported {sum(counts.values())} rows")
        elif args.cmd == "trust-domain":
            admin_store.trust_domain(conn, args.domain, args.note)
            print(f"{args.domain} -> TRUSTED")
        elif args.cmd == "block-domain":
            admin_store.block_domain(conn, args.domain, args.note)
            print(f"{args.domain} -> BLOCKED")
        elif args.cmd == "trust-account":
            admin_store.add_known_account(conn, args.platform, args.handle, args.note)
            print(f"{args.platform}:{args.handle} added to known_accounts")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
