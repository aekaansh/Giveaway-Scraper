"""Environment variables and YAML config loading.

Secrets are read only from environment variables (locally from `.env`). A missing
required variable raises MissingConfigError with a message naming the variable.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"


class MissingConfigError(RuntimeError):
    """A required environment variable is not set."""


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise MissingConfigError(
            f"Missing required environment variable {name}. "
            f"Set it in your local .env (see .env.example) or as a GitHub Actions / "
            f"Streamlit secret."
        )
    return value


def paused() -> bool:
    """True when PAUSE=1: every entrypoint must check this before fetching anything."""
    return os.environ.get("PAUSE", "").strip() == "1"


def load_dotenv_if_present() -> None:
    """Load the local .env (developer machine only). CI provides real env vars instead."""
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env", override=False)


def load_yaml(name: str, config_dir: Path | None = None) -> dict[str, Any]:
    path = (config_dir or CONFIG_DIR) / name
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}
