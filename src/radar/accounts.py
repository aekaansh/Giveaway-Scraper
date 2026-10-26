"""Account signals for posts on PLATFORM domains (instagram.com, youtube.com, ...).

A PLATFORM domain says nothing about who posted, so the ACCOUNT is judged instead.
Ping Discord only if:
  - the account is in known_accounts (and the post has no scam signals), OR
  - all of: not a lookalike of a known handle, account older than 90 days (when the age
    is available), this is the ORIGINAL giveaway post, and a low scam score.
Anything else goes to the review queue with the failing signals shown. Follower count
and verified status are shown on the alert/queue item but don't gate the ping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from radar import store
from radar.store import normalize_handle
from radar.url_guard import levenshtein

MIN_ACCOUNT_AGE_DAYS = 90
# Affixes that turn a known handle into an impersonation ("pokeshop_giveaway").
HANDLE_AFFIXES = ("official", "giveaway", "giveaways", "support", "claim", "prize",
                  "prizes", "winner", "winners", "real", "team", "help", "admin")
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})

# Failing-signal labels (shown in the review queue).
LOOKALIKE_HANDLE = "LOOKALIKE HANDLE"
ACCOUNT_TOO_NEW = "ACCOUNT TOO NEW"
NOT_ORIGINAL = "NOT ORIGINAL POST"
ORIGINAL_UNKNOWN = "ORIGINAL POST UNKNOWN"
SCAM_SIGNALS = "SCAM SIGNALS"
SCAM_NOT_LOW = "SCAM SCORE NOT LOW"
GUARD_FLAGS = "URL FLAGGED"


@dataclass
class AccountInfo:
    platform: str
    handle: str
    created_at: datetime | None = None
    followers: int | None = None
    verified: bool | None = None
    is_original_post: bool | None = None  # None = could not tell


@dataclass
class AccountVerdict:
    ping: bool
    known: bool
    failing: list[str] = field(default_factory=list)
    lookalike_of: str | None = None
    age_days: int | None = None
    followers: int | None = None
    verified: bool | None = None


def skeleton(handle: str) -> str:
    """Handle reduced to compare impersonations: lowercase, no separators, de-leeted."""
    h = normalize_handle(handle).translate(_LEET)
    return re.sub(r"[._\-\s]", "", h).replace("rn", "m")


def lookalike_of(handle: str, known_handles: list[str]) -> str | None:
    """The known handle this one imitates, or None. An exact match is not a lookalike."""
    h = normalize_handle(handle)
    hs = skeleton(h)
    for known in known_handles:
        k = normalize_handle(known)
        if h == k:
            return None
    for known in known_handles:
        k = normalize_handle(known)
        ks = skeleton(k)
        if not ks:
            continue
        if hs == ks:
            return k
        limit = 2 if len(ks) >= 6 else 1
        if levenshtein(hs, ks) <= limit:
            return k
        for affix in HANDLE_AFFIXES:
            if hs in (ks + affix, affix + ks):
                return k
    return None


def evaluate_account(
    conn: Any,
    info: AccountInfo,
    scam_level: str,
    *,
    guard_flags: list[str] | None = None,
    now: datetime | None = None,
) -> AccountVerdict:
    platform = info.platform.lower()
    age_days = (
        ((now or store.utcnow()) - info.created_at).days if info.created_at else None
    )
    verdict = AccountVerdict(
        ping=False,
        known=store.is_known_account(conn, platform, info.handle),
        age_days=age_days,
        followers=info.followers,
        verified=info.verified,
    )
    # Signals that block a ping for every account, known or not.
    if scam_level == "high":
        verdict.failing.append(SCAM_SIGNALS)
    if guard_flags:
        verdict.failing.append(f"{GUARD_FLAGS}: {', '.join(guard_flags)}")

    if verdict.known:
        verdict.ping = not verdict.failing
        return verdict

    verdict.lookalike_of = lookalike_of(info.handle, store.list_known_handles(conn, platform))
    if verdict.lookalike_of:
        verdict.failing.append(f"{LOOKALIKE_HANDLE} of @{verdict.lookalike_of}")
    if age_days is not None and age_days < MIN_ACCOUNT_AGE_DAYS:
        verdict.failing.append(f"{ACCOUNT_TOO_NEW} ({age_days}d)")
    if info.is_original_post is False:
        verdict.failing.append(NOT_ORIGINAL)
    elif info.is_original_post is None:
        verdict.failing.append(ORIGINAL_UNKNOWN)
    if scam_level != "low" and SCAM_SIGNALS not in verdict.failing:
        verdict.failing.append(SCAM_NOT_LOW)
    verdict.ping = not verdict.failing
    return verdict


def record_held_back(conn: Any, url: str, verdict: AccountVerdict) -> None:
    """A post sent to review instead of pinged: one filtered_items row per failing signal."""
    if verdict.ping:
        return
    for signal in verdict.failing:
        base = next((s for s in _SIGNALS if signal.startswith(s)), "other")
        store.record_filtered(conn, url, "account:" + base.lower().replace(" ", "_"), signal)


_SIGNALS = (LOOKALIKE_HANDLE, ACCOUNT_TOO_NEW, NOT_ORIGINAL, ORIGINAL_UNKNOWN, SCAM_SIGNALS,
            SCAM_NOT_LOW, GUARD_FLAGS)
