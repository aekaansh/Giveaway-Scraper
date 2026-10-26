"""Polling-path modules must never import admin_store (or admin, which imports it).

Human-only lists (TRUSTED/BLOCKED domains, known_accounts) are written only by the
dashboard and `radar.admin`. url_guard's single tightening exception goes through
`store.block_domain_from_guard` instead.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "radar"
HUMAN_ONLY = {"admin_store", "admin"}
# Modules allowed to import human-only code. Everything else counts as polling path.
ALLOWED_IMPORTERS = {SRC / "admin.py", SRC / "admin_store.py"}


def _imported_radar_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] == "radar":
                    found.update(parts[1:])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            parts = mod.split(".") if mod else []
            if node.level > 0 or (parts and parts[0] == "radar"):
                found.update(p for p in parts if p != "radar")
                found.update(alias.name for alias in node.names)
        elif (
            isinstance(node, ast.Call)
            and getattr(node.func, "attr", getattr(node.func, "id", "")) in
            ("import_module", "__import__")
        ):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.update(arg.value.split("."))
    return found


def test_polling_path_does_not_import_admin_store() -> None:
    offenders = {}
    for path in SRC.rglob("*.py"):
        if path in ALLOWED_IMPORTERS:
            continue
        bad = _imported_radar_modules(path) & HUMAN_ONLY
        if bad:
            offenders[str(path.relative_to(SRC))] = sorted(bad)
    assert not offenders, f"polling-path modules import human-only code: {offenders}"


NETWORK_MODULES = {
    "httpx", "httpcore", "socket", "ssl", "requests", "urllib3", "aiohttp", "websockets",
    "http.client", "urllib.request", "ftplib", "smtplib", "telnetlib", "playwright",
}
NETWORK_ALLOWED = {SRC / "url_guard.py", SRC / "api_client.py"}
# Library-level exceptions: (module, allowed file, why).
SPECIAL_ALLOWED = {
    "anthropic": SRC / "classify.py",  # the Anthropic SDK stays in classify.py
    "tldextract": SRC / "domains.py",  # offline PSL snapshot only (checked below)
}


def _external_imports(path: Path) -> set[str]:
    """Top-level and dotted names of every absolute import in a file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
        else:
            continue
        for mod in mods:
            parts = mod.split(".")
            names.update(".".join(parts[: i + 1]) for i in range(len(parts)))
    return names


def test_only_url_guard_and_api_client_make_network_calls() -> None:
    offenders = {}
    for path in SRC.rglob("*.py"):
        imported = _external_imports(path)
        bad = set()
        if path not in NETWORK_ALLOWED:
            bad |= imported & NETWORK_MODULES
        for lib, allowed in SPECIAL_ALLOWED.items():
            if lib in imported and path != allowed:
                bad.add(lib)
        if bad:
            offenders[str(path.relative_to(SRC))] = sorted(bad)
    assert not offenders, f"network-capable imports outside the allowed modules: {offenders}"


def test_tldextract_never_fetches_suffix_list() -> None:
    from radar import domains

    assert domains._extract.suffix_list_urls == ()


def test_network_detector_catches_dotted_and_from_imports(tmp_path: Path) -> None:
    for src in ("import urllib.request", "from urllib import request",
                "from http.client import HTTPSConnection", "import httpx as h"):
        f = tmp_path / "m.py"
        f.write_text(src, encoding="utf-8")
        assert _external_imports(f) & NETWORK_MODULES, src


def test_detector_catches_each_import_form(tmp_path: Path) -> None:
    forms = [
        "import radar.admin_store",
        "from radar import admin_store",
        "from radar.admin_store import trust_domain",
        "from . import admin_store",
        "from .admin_store import trust_domain",
        "import importlib\nimportlib.import_module('radar.admin_store')",
    ]
    for i, src in enumerate(forms):
        f = tmp_path / f"m{i}.py"
        f.write_text(src, encoding="utf-8")
        assert "admin_store" in _imported_radar_modules(f), src
