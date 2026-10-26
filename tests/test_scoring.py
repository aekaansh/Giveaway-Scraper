from __future__ import annotations

import sqlite3

import pytest

from radar.scoring import final_scam_likelihood, find_scam_phrases, raise_only, record_hits

SCAM_TEXTS = [
    ("fee", "Congrats! You won, just pay shipping and it's yours."),
    ("fee", "Winner must cover shipping ($9.99)."),
    ("fee", "A small fee is required to release the prize."),
    ("fee", "There is a $4 processing fee."),
    ("fee", "Please send payment for insurance."),
    ("fee", "Pay to claim your booster box"),
    ("fee", "Shipping-fee applies to all winners"),
    ("claim_by_dm", "Winners: DM to claim within 24h"),
    ("claim_by_dm", "Message us to claim your Charizard!"),
    ("claim_by_dm", "Contact to claim your prize"),
    ("crypto_payment", "Connect wallet to receive your NFT card"),
    ("crypto_payment", "Send your seed phrase to verify"),
    ("crypto_payment", "Send 5 USDT to unlock"),
    ("crypto_payment", "Reply with a gift card code"),
    ("crypto_payment", "Send $5 via Cash App to claim"),
    ("crypto_payment", "venmo me to claim"),
    ("credentials", "Enter your password to verify entry"),
    ("credentials", "Verify your card to receive the package"),
    ("credentials", "Provide card details to claim"),
]

BENIGN_TEXTS = [
    "Winner will be DM'd on Friday.",
    "Winner will be DM’d on Friday.",
    "Winners will be contacted by DM.",
    "Winner contacted by DM after the draw.",
    "We'll message the winner on Instagram.",
    "Free shipping to the US!",
    "We cover shipping for the winner.",
    "We will pay for shipping.",
    "Shipping is covered. No fees, ever.",
    "No shipping fee. Open to US residents 18+.",
    "Enter via the Gleam widget below. Good luck!",
    "Share this post to get a bonus entry.",
]


@pytest.mark.parametrize(("rule", "text"), SCAM_TEXTS)
def test_scam_phrases_flagged(rule: str, text: str) -> None:
    hits = find_scam_phrases(text)
    assert rule in {h.rule for h in hits}, hits
    assert final_scam_likelihood("low", hits) == "high"


@pytest.mark.parametrize("text", BENIGN_TEXTS)
def test_benign_phrases_not_flagged(text: str) -> None:
    assert find_scam_phrases(text) == []


def test_benign_mask_does_not_hide_scam_in_same_text() -> None:
    text = "Free shipping on our store! Giveaway winner must pay shipping fee of $6."
    assert {h.rule for h in find_scam_phrases(text)} == {"fee"}


def test_single_words_alone_do_not_trigger() -> None:
    assert find_scam_phrases("shipping, fee, claim, wallet, card, password, DM") == []


def test_llm_cannot_lower_rule_or_guard_verdicts() -> None:
    hits = find_scam_phrases("pay shipping to claim")
    assert final_scam_likelihood("low", hits) == "high"
    assert final_scam_likelihood("low", [], guard_level="medium") == "medium"
    assert final_scam_likelihood("high", []) == "high"  # LLM may raise
    assert final_scam_likelihood("low", []) == "low"


def test_missing_or_garbage_llm_verdict_is_not_low() -> None:
    assert raise_only(None) == "medium"
    assert raise_only("definitely-safe") == "medium"
    assert final_scam_likelihood(None, []) == "medium"


def test_record_hits_writes_filtered_items(conn: sqlite3.Connection) -> None:
    hits = find_scam_phrases("DM to claim. Small fee applies. Shipping fee $5.")
    record_hits(conn, "https://x.example/post", hits)
    rows = conn.execute("SELECT url, rule, reason FROM filtered_items ORDER BY rule").fetchall()
    assert [r[1] for r in rows] == ["scam_phrase:claim_by_dm", "scam_phrase:fee"]
    assert all(r[0] == "https://x.example/post" for r in rows)
    assert "small fee" in rows[1][2] and "shipping fee" in rows[1][2]
