"""Deterministic scam-phrase rules. They override the LLM: a classifier verdict can only
raise scam_likelihood, never lower what these rules (or url_guard) raised.

Rules match PHRASES that ask something of the entrant, not single words. Benign phrases
("winner will be DM'd", "free shipping", "we cover shipping") are masked out before
matching so they can't trigger a rule.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from radar import store

LEVELS = ("low", "medium", "high")
# Used when the classifier gave no verdict: never assume "low".
DEFAULT_LEVEL = "medium"


def _phrase(text: str) -> str:
    """Plain phrase -> regex: words separated by any whitespace/hyphens, word-bounded."""
    words = [re.escape(w) for w in text.split()]
    return r"\b" + r"[\s\-]+".join(words) + r"\b"


SCAM_RULES: dict[str, list[str]] = {
    "fee": [
        _phrase("pay shipping"),
        _phrase("pay for shipping"),
        _phrase("pay the shipping"),
        _phrase("shipping fee"),
        _phrase("cover shipping"),
        _phrase("cover the shipping"),
        _phrase("processing fee"),
        _phrase("handling fee"),
        _phrase("claim fee"),
        _phrase("small fee"),
        _phrase("send payment"),
        _phrase("pay to claim"),
    ],
    "claim_by_dm": [
        r"\b(dm|message|text|whatsapp|telegram)(\s+(us|me|the\s+page|admin))?\s+to\s+claim\b",
        r"\bcontact(\s+(us|me|admin))?\s+to\s+claim(\s+your\s+prize)?\b",
    ],
    "crypto_payment": [
        _phrase("connect wallet"),
        _phrase("connect your wallet"),
        _phrase("seed phrase"),
        _phrase("recovery phrase"),
        _phrase("send crypto"),
        r"\busdt\b",
        _phrase("gift card code"),
        r"\b(cash\s?app|venmo|zelle)\b[^.!?\n]{0,30}\bto\s+claim\b",
    ],
    "credentials": [
        _phrase("enter your password"),
        _phrase("verify your card"),
        _phrase("card details to claim"),
        _phrase("card number to claim"),
    ],
}

BENIGN_PHRASES: list[str] = [
    r"\bwinners?\s+(will\s+|shall\s+)?be\s+(dm'?d|dm'?ed|messaged|contacted)"
    r"(\s+(by|via)\s+dm)?\b",
    r"\bwinners?\s+(will\s+be\s+)?contacted\s+(by|via)\s+dm\b",
    r"\b(we|we'll|we\s+will|i|i'll|i\s+will)\s+(dm|message|contact)\s+(the\s+)?winners?\b",
    _phrase("free shipping"),
    r"\b(we|we'll|we\s+will|i|i'll|i\s+will)\s+(cover|pay(\s+for)?)\s+(the\s+|all\s+)?shipping\b",
    r"\bshipping\s+(is\s+)?(covered|free|on\s+us)\b",
    r"\bno\s+(shipping|processing|handling|claim)\s+fees?\b",
    r"\bno\s+fees?\b",
]

_SCAM_RES = {rule: [re.compile(p) for p in pats] for rule, pats in SCAM_RULES.items()}
_BENIGN_RES = [re.compile(p) for p in BENIGN_PHRASES]


@dataclass(frozen=True)
class PhraseHit:
    rule: str
    phrase: str


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", text).lower()


def _mask_benign(text: str) -> str:
    for rx in _BENIGN_RES:
        text = rx.sub(lambda m: " " * len(m.group(0)), text)
    return text


def find_scam_phrases(text: str) -> list[PhraseHit]:
    masked = _mask_benign(normalize(text))
    hits: list[PhraseHit] = []
    for rule, regexes in _SCAM_RES.items():
        for rx in regexes:
            m = rx.search(masked)
            if m:
                hits.append(PhraseHit(rule, m.group(0)))
    return hits


def rule_level(hits: list[PhraseHit]) -> str:
    return "high" if hits else "low"


def raise_only(*levels: str | None) -> str:
    """The highest of the given levels. None (missing verdict) counts as DEFAULT_LEVEL."""
    resolved = [lvl if lvl in LEVELS else DEFAULT_LEVEL for lvl in levels] or [DEFAULT_LEVEL]
    return max(resolved, key=LEVELS.index)


def final_scam_likelihood(
    llm_level: str | None, hits: list[PhraseHit], guard_level: str = "low"
) -> str:
    """Combine verdicts. The LLM can only raise; rules and the guard set the floor."""
    return raise_only(llm_level, rule_level(hits), guard_level)


def record_hits(conn: Any, url: str, hits: list[PhraseHit]) -> None:
    """One filtered_items row per rule that fired on this item."""
    for rule in dict.fromkeys(h.rule for h in hits):
        phrases = ", ".join(repr(h.phrase) for h in hits if h.rule == rule)
        store.record_filtered(conn, url, f"scam_phrase:{rule}", f"matched {phrases}")
