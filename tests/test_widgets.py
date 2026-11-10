from __future__ import annotations

import sqlite3
from pathlib import Path

import httpx
import pytest
from guard_harness import FakeSafeBrowsing, Harness, filtered, html

from radar import admin_store
from radar.url_guard import FetchResult, PlatformLink
from radar.widgets import MAX_WIDGETS_PER_PAGE, discover_widgets, entry_count, extract_widgets

FIXTURES = Path(__file__).parent / "fixtures"
SHOP = "https://cardboardkingdom.example/pages/giveaway"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_gleam_widget_extracted_from_js_only_shop_page() -> None:
    scan = extract_widgets(fixture("js_only_shop.html"), SHOP)
    assert [(w.kind, w.url, w.source) for w in scan.widgets] == [
        ("gleam", "https://gleam.io/aB3dE/pokemon-151-booster-bundle-giveaway", "inline")
    ]
    assert [w.url for w in scan.loaders] == ["https://widget.gleamjs.io/e.js"]


def test_iframe_anchor_and_data_attribute_widgets() -> None:
    scan = extract_widgets(fixture("embedded_widgets.html"), "https://shop.example/giveaways")
    assert [(w.kind, w.url, w.source) for w in scan.widgets] == [
        ("gleam", "https://gleam.io/Xy12Z/charizard-etb-giveaway", "anchor"),
        ("kingsumo", "https://kingsumo.com/g/abc123/pokemon-etb-giveaway/embed", "iframe"),
        ("viralsweep", "https://app.viralsweep.com/sweeps/full/12345-67890", "data-attr"),
        # Found by the inline pass inside a javascript: link (JS-only pages hide widgets
        # in code); it still goes through url_guard like any other URL.
        ("gleam", "https://gleam.io/zzz", "inline"),
    ]
    assert [w.kind for w in scan.loaders] == ["viralsweep"]


def test_decoys_are_not_widgets() -> None:
    urls = {w.url for w in extract_widgets(fixture("embedded_widgets.html"),
                                           "https://shop.example/").widgets}
    assert not any("claim-prize.example" in u for u in urls)  # lookalike host
    assert "https://gleam.io/pricing" not in urls
    assert not any(u.startswith("javascript:") for u in urls)
    assert not any("pokemon.com" in u for u in urls)
    assert len(urls) == 4  # the #enter duplicate collapsed into one


def test_page_without_widgets() -> None:
    scan = extract_widgets(fixture("no_widgets.html"), "https://news.example/")
    assert scan.widgets == [] and scan.loaders == []


def test_relative_and_protocol_relative_urls_resolved() -> None:
    page = '<iframe src="//gleam.io/AbCdE/embed"></iframe>'
    assert extract_widgets(page, "https://shop.example/x").widgets[0].url == (
        "https://gleam.io/AbCdE/embed"
    )


def test_discover_fetches_widget_through_guard_and_records_link(
    conn: sqlite3.Connection,
) -> None:
    admin_store.trust_domain(conn, "gleam.io")
    widget_url = "https://gleam.io/aB3dE/pokemon-151-booster-bundle-giveaway"
    h = Harness(conn, {SHOP: html(fixture("js_only_shop.html")),
                       widget_url: html("<h1>Pokemon 151 Booster Bundle</h1>")})
    page = h.guard.fetch(SHOP)
    assert page.guard.tier == "UNKNOWN"
    found = discover_widgets(h.guard, conn, page)
    assert len(found) == 1
    assert found[0].result is not None and found[0].result.guard.trusted
    assert "Booster Bundle" in found[0].result.text()
    links = conn.execute("SELECT host_url, widget_url, kind FROM widget_links").fetchall()
    assert links == [(SHOP, widget_url, "gleam")]
    assert widget_url in h.sb.calls  # the widget URL itself went through Safe Browsing


def test_blocked_widget_is_reported_and_filtered(conn: sqlite3.Connection) -> None:
    widget_url = "https://gleam.io/aB3dE/pokemon-151-booster-bundle-giveaway"
    admin_store.trust_domain(conn, "gleam.io")
    h = Harness(conn, {SHOP: html(fixture("js_only_shop.html"))},
                sb=FakeSafeBrowsing(unsafe={widget_url}))
    found = discover_widgets(h.guard, conn, h.guard.fetch(SHOP))
    assert found[0].result is None and "safe_browsing" in (found[0].error or "")
    assert (widget_url, "safe_browsing") in filtered(conn)


def test_platform_pages_are_not_scanned(conn: sqlite3.Connection) -> None:
    admin_store.set_domain_tier(conn, "youtube.com", "PLATFORM")
    url = "https://www.youtube.com/watch?v=abc"
    h = Harness(conn, {url: html(fixture("embedded_widgets.html"))})
    # PLATFORM pages are never fetched in the first place...
    with pytest.raises(PlatformLink):
        h.guard.fetch(url)
    assert h.requests == []
    # ...and a PLATFORM page handed in anyway is not scanned.
    guard = h.guard.check(url)
    page = FetchResult(url, url, 200, "text/html", fixture("embedded_widgets.html").encode(),
                       False, guard, [url])
    assert discover_widgets(h.guard, conn, page) == []
    assert conn.execute("SELECT COUNT(*) FROM widget_links").fetchone()[0] == 0


def test_widget_fetches_capped_per_page(conn: sqlite3.Connection) -> None:
    links = "".join(f'<a href="https://gleam.io/W{i:04d}/g{i}">x</a>' for i in range(12))
    h = Harness(conn, {SHOP: html(links)})
    found = discover_widgets(h.guard, conn, h.guard.fetch(SHOP))
    assert len(found) == MAX_WIDGETS_PER_PAGE
    widget_requests = [r for r in h.requests
                       if r.url.host == "gleam.io" and r.url.path != "/robots.txt"]
    assert len(widget_requests) == MAX_WIDGETS_PER_PAGE


def test_non_html_widget_response_not_saved(conn: sqlite3.Connection) -> None:
    widget_url = "https://gleam.io/aB3dE/pokemon-151-booster-bundle-giveaway"
    h = Harness(conn, {SHOP: html(fixture("js_only_shop.html")),
                       widget_url: httpx.Response(200, headers={"content-type": "application/zip"},
                                                  content=b"PK")})
    found = discover_widgets(h.guard, conn, h.guard.fetch(SHOP))
    assert found[0].result is None
    assert (widget_url, "content_type") in filtered(conn)


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        ('<script>var c = {"total_entries": 342, "x": 1}</script>', 342),
        ('{"entry_count":"1250"}', 1250),
        ("<div>Total entries: 1,204</div>", 1204),
        ("<span>87 total entries</span>", 87),
        ("<p>2,500 entries so far</p>", 2500),
    ],
)
def test_entry_count_read_from_widget_page(page: str, expected: int) -> None:
    assert entry_count(page) == expected


@pytest.mark.parametrize(
    "page",
    [
        "<li>Visit our shop: +5 entries</li><li>Follow us: 3 entries</li>",
        "<p>Earn bonus entries by sharing!</p>",
        "",
    ],
)
def test_entry_count_ignores_per_action_bonuses(page: str) -> None:
    assert entry_count(page) is None


def test_malformed_urls_are_skipped_not_raised() -> None:
    page = '<a href="http://[not-an-ip]/x">x</a><script>u="https://[gleam.io/x"</script>'
    scan = extract_widgets(page, "https://shop.example/")
    assert scan.widgets == []
