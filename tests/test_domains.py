from __future__ import annotations

import pytest

from radar.domains import domain_label, host_chain, registrable_domain


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("shop.example.co.uk", "example.co.uk"),
        ("WWW.Pokemon.COM.", "pokemon.com"),
        ("evil.github.io", "evil.github.io"),  # private suffix honoured
        ("win.scam.example", "scam.example"),  # unknown TLD: last two labels
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        ("localhost", "localhost"),
    ],
)
def test_registrable_domain(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected


def test_host_chain() -> None:
    assert host_chain("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]
    assert host_chain("example.com") == ["example.com"]
    assert host_chain("win.scam.example") == ["win.scam.example", "scam.example"]
    assert host_chain("10.0.0.1") == ["10.0.0.1"]


def test_domain_label() -> None:
    assert domain_label("shop.pokemoncenter.com") == "pokemoncenter"
