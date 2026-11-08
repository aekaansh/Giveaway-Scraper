"""Discord webhook alerts and the daily review-queue digest.

- Posts the FINAL resolved URL only (never a shortener or redirecting link).
- Every alert shows the full real domain or account handle, tier, domain/account age and
  warning badges (NEW DOMAIN, LOOKALIKE?, NOT TRUSTED, SCAM SIGNALS, FEW ENTRANTS ...).
- Page-derived text is untrusted: Discord markdown is escaped, raw URLs are broken so they
  don't become links, and mentions are disabled (`allowed_mentions`), so a page can't
  smuggle in a clickable phishing link or an @everyone ping.
- FEW ENTRANTS is a display-only hint. It never decides whether something is sent.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from radar.api_client import ApiClient
from radar.config import require_env

FEW_ENTRANTS = "FEW ENTRANTS"
SCAM_SIGNALS = "SCAM SIGNALS"
DIGEST_LIMIT = 15
MAX_CONTENT = 2000
SEND_INTERVAL_S = 0.6  # Discord allows about 5 webhook posts per 2 seconds
NO_MENTIONS = {"parse": []}

_MARKDOWN = re.compile(r"([\\*_~`|>\[\]()#<])")
_SCHEME = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*):/")


@dataclass(frozen=True)
class OddsHint:
    max_entries: int = 500
    max_followers: int = 5000

    @classmethod
    def from_config(cls, cfg: dict[str, Any] | None) -> OddsHint:
        cfg = cfg or {}
        return cls(int(cfg.get("max_entries", 500)), int(cfg.get("max_followers", 5000)))

    def badge(self, entry_count: int | None, followers: int | None) -> str | None:
        """FEW ENTRANTS when the widget shows few total entries, or (no entry count) the
        posting account is small. Unknown numbers never produce a badge."""
        if entry_count is not None:
            return FEW_ENTRANTS if entry_count <= self.max_entries else None
        if followers is not None and followers <= self.max_followers:
            return FEW_ENTRANTS
        return None


def badges(giveaway: dict[str, Any], odds: OddsHint) -> list[str]:
    found = list(json.loads(giveaway.get("flags_json") or "[]"))
    if giveaway.get("scam_likelihood") == "high" and SCAM_SIGNALS not in found:
        found.append(SCAM_SIGNALS)
    hint = odds.badge(giveaway.get("entry_count"), giveaway.get("account_followers"))
    if hint:
        found.append(hint)
    return found


def safe_text(text: str | None, limit: int) -> str:
    """Untrusted text made inert for Discord: no markdown, links or mentions."""
    value = re.sub(r"\s+", " ", text or "").strip()[:limit]
    value = _MARKDOWN.sub(r"\\\1", value)
    value = _SCHEME.sub(lambda m: f"{m.group(1)}:​/", value)
    return value.replace("@", "@​")


def who(giveaway: dict[str, Any]) -> str:
    """The full real domain, or the account handle for PLATFORM posts."""
    if giveaway.get("platform") and giveaway.get("account_handle"):
        return f"@{giveaway['account_handle']} on {giveaway['platform']}"
    return str(giveaway.get("domain"))


def age_text(giveaway: dict[str, Any]) -> str:
    if giveaway.get("tier") == "PLATFORM":
        days, label = giveaway.get("account_age_days"), "account"
    else:
        days, label = giveaway.get("domain_age_days"), "domain"
    return f"{label} {days}d old" if days is not None else f"{label} age unknown"


def numbers_text(giveaway: dict[str, Any]) -> str | None:
    parts = []
    if giveaway.get("entry_count") is not None:
        parts.append(f"{giveaway['entry_count']:,} entries")
    if giveaway.get("account_followers") is not None:
        parts.append(f"{giveaway['account_followers']:,} followers")
    return ", ".join(parts) or None


class Notifier:
    def __init__(
        self, api: ApiClient, webhook_url: str | None = None, *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._api = api
        self._url = webhook_url or require_env("DISCORD_WEBHOOK")
        self._sleep = sleep
        self._sent = 0

    def _post(self, payload: dict[str, Any]) -> None:
        """Raises ApiError (host + status only, never the webhook URL) on failure."""
        if self._sent:
            self._sleep(SEND_INTERVAL_S)
        self._api.request("POST", self._url, json={**payload, "allowed_mentions": NO_MENTIONS})
        self._sent += 1

    def send_alert(self, giveaway: dict[str, Any], badge_list: list[str]) -> None:
        fields = [
            {"name": "Where", "value": safe_text(who(giveaway), 200), "inline": True},
            {"name": "Tier", "value": safe_text(giveaway.get("tier"), 20), "inline": True},
            {"name": "Age", "value": age_text(giveaway), "inline": True},
            {"name": "Deadline", "value": giveaway.get("deadline") or "not stated",
             "inline": True},
        ]
        numbers = numbers_text(giveaway)
        if numbers:
            fields.append({"name": "Size", "value": numbers, "inline": True})
        if badge_list:
            fields.append({"name": "Warnings",
                           "value": safe_text(" · ".join(badge_list), 1000), "inline": False})
        embed = {
            "title": safe_text(giveaway.get("title") or "Pokemon TCG giveaway", 240),
            "url": giveaway["url"],
            "description": safe_text(giveaway.get("summary"), 1000),
            "fields": fields,
        }
        self._post({"content": f"New giveaway: {giveaway['url']}", "embeds": [embed]})

    def send_digest(self, items: list[dict[str, Any]], total: int, odds: OddsHint) -> None:
        lines = [f"**Review queue digest:** {total} item(s) waiting, soonest deadline first."]
        for g in items:
            badge_list = badges(g, odds)
            line = (
                f"• {g.get('deadline') or 'no deadline'} · {safe_text(who(g), 120)}"
                f" · {g.get('tier')}"
                + (f" · {safe_text(', '.join(badge_list), 200)}" if badge_list else "")
                + f" · <{g['url']}>"
            )
            if sum(len(x) + 1 for x in lines) + len(line) > MAX_CONTENT - 40:
                break
            lines.append(line)
        shown = len(lines) - 1
        if shown < total:
            lines.append(f"…and {total - shown} more on the dashboard.")
        self._post({"content": "\n".join(lines)})
