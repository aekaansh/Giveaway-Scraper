"""url_guard tests. No network: httpx MockTransport, a fake resolver and fake reputation
services. Every scenario from CLAUDE.md "Testing requirements" for url_guard is here."""

from __future__ import annotations

import gzip
import socket
import sqlite3
from datetime import timedelta
from typing import Any

import httpcore
import httpx
import pytest
from guard_harness import (
    FEED_URL,
    NOW,
    PUBLIC_IP,
    FakeDomainAge,
    FakeSafeBrowsing,
    Harness,
    Route,
    filtered,
    html,
    redirect,
)

from radar import admin_store, store
from radar.config import CONFIG_DIR, MissingConfigError
from radar.url_guard import (
    LOOKALIKE,
    MAX_BYTES,
    NEW_DOMAIN,
    NOT_TRUSTED,
    USER_AGENT,
    Blocked,
    FetchFailed,
    GuardConfig,
    PinnedBackend,
    PlatformLink,
    UrlGuard,
    is_public_ip,
    levenshtein,
)

# --- URL shape ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "ftp://files.example/prize.zip",
        "//no-scheme.example/",
    ],
)
def test_blocked_schemes(conn: sqlite3.Connection, url: str) -> None:
    h = Harness(conn)
    with pytest.raises(Blocked) as exc:
        h.guard.fetch(url)
    assert exc.value.rule == "scheme"
    assert filtered(conn)[0][1] == "scheme"
    assert h.requests == []


@pytest.mark.parametrize(
    ("url", "rule"),
    [
        ("https://user:pw@shop.example/", "bad_url"),
        ("https://shop.example:8443/", "port"),
        ("http://[::1", "bad_url"),
    ],
)
def test_bad_url_shapes(conn: sqlite3.Connection, url: str, rule: str) -> None:
    with pytest.raises(Blocked) as exc:
        Harness(conn).guard.check(url)
    assert exc.value.rule == rule


# --- SSRF -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://10.0.0.8/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://0.0.0.0/",
    ],
)
def test_private_ip_literals_blocked(conn: sqlite3.Connection, url: str) -> None:
    h = Harness(conn)
    with pytest.raises(Blocked) as exc:
        h.guard.fetch(url)
    assert exc.value.rule == "private_ip"
    assert h.requests == []


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.0.10", "169.254.169.254", "fd00::1",
                                "100.64.0.1"])
def test_hostname_resolving_to_private_ip_blocked(conn: sqlite3.Connection, ip: str) -> None:
    h = Harness(conn, {"https://intranet.example/": html()}, dns={"intranet.example": [ip]})
    with pytest.raises(Blocked) as exc:
        h.guard.fetch("https://intranet.example/")
    assert exc.value.rule == "private_ip"
    assert h.requests == []


def test_any_private_address_in_dns_answer_blocks(conn: sqlite3.Connection) -> None:
    h = Harness(conn, dns={"mixed.example": [PUBLIC_IP, "127.0.0.1"]})
    with pytest.raises(Blocked):
        h.guard.fetch("https://mixed.example/")


def test_redirect_to_private_ip_blocked(conn: sqlite3.Connection) -> None:
    h = Harness(
        conn,
        {"https://shop.example/win": redirect("http://metadata.internal/")},
        dns={"metadata.internal": ["169.254.169.254"]},
    )
    with pytest.raises(Blocked) as exc:
        h.guard.fetch("https://shop.example/win")
    assert exc.value.rule == "private_ip"
    assert [str(r.url) for r in h.requests if r.url.path != "/robots.txt"] == [
        "https://shop.example/win"
    ]


def test_dns_failure_is_fetch_failure_not_guardrail(conn: sqlite3.Connection) -> None:
    def boom(host: str) -> list[str]:
        raise OSError("nxdomain")

    h = Harness(conn)
    h.guard._resolver = boom
    with pytest.raises(FetchFailed):
        h.guard.fetch("https://gone.example/")
    assert filtered(conn) == []


def test_is_public_ip_rejects_embedded_private_v4() -> None:
    import ipaddress

    assert not is_public_ip(ipaddress.ip_address("::ffff:10.0.0.1"))
    assert not is_public_ip(ipaddress.ip_address("2002:7f00:1::"))  # 6to4 of 127.0.0.1
    assert is_public_ip(ipaddress.ip_address(PUBLIC_IP))


# --- redirects ----------------------------------------------------------------------


def test_redirect_to_blocked_domain(conn: sqlite3.Connection) -> None:
    admin_store.block_domain(conn, "scam.example", note="marked scam")
    h = Harness(conn, {"https://bit.ly/abc": redirect("https://win.scam.example/claim", 301)})
    admin_store.set_domain_tier(conn, "bit.ly", "LINK_HUB")
    with pytest.raises(Blocked) as exc:
        h.guard.fetch("https://bit.ly/abc")
    assert exc.value.rule == "blocked_domain"
    assert filtered(conn) == [("https://win.scam.example/claim", "blocked_domain")]
    log = conn.execute("SELECT url, tier, verdict FROM fetch_log ORDER BY id").fetchall()
    assert ("https://bit.ly/abc", "LINK_HUB", "REDIRECT") in log
    assert ("https://win.scam.example/claim", "BLOCKED", "BLOCK:blocked_domain") in log


def _chain(n: int) -> dict[str, Route]:
    routes: dict[str, Route] = {
        f"https://hop.example/{i}": redirect(f"https://hop.example/{i + 1}") for i in range(n)
    }
    routes[f"https://hop.example/{n}"] = html()
    return routes


def test_five_redirects_allowed(conn: sqlite3.Connection) -> None:
    res = Harness(conn, _chain(5)).guard.fetch("https://hop.example/0")
    assert res.final_url == "https://hop.example/5"
    assert len(res.hops) == 6


def test_sixth_redirect_blocked(conn: sqlite3.Connection) -> None:
    with pytest.raises(Blocked) as exc:
        Harness(conn, _chain(6)).guard.fetch("https://hop.example/0")
    assert exc.value.rule == "redirect_limit"
    assert filtered(conn) == [("https://hop.example/0", "redirect_limit")]


def test_shortener_resolves_to_final_url(conn: sqlite3.Connection) -> None:
    admin_store.set_domain_tier(conn, "bit.ly", "LINK_HUB")
    admin_store.trust_domain(conn, "gleam.io")
    h = Harness(conn, {
        "https://bit.ly/g": redirect("https://gleam.io/abc/pokemon-giveaway", 301),
        "https://gleam.io/abc/pokemon-giveaway": html(),
    })
    res = h.guard.fetch("https://bit.ly/g")
    assert res.final_url == "https://gleam.io/abc/pokemon-giveaway"
    assert res.guard.tier == "TRUSTED" and res.guard.trusted
    assert res.hops[0] == "https://bit.ly/g"
    # The shortener hop itself was checked by Safe Browsing too.
    assert "https://bit.ly/g" in h.sb.calls


# --- lookalikes ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["https://xn--pokmon-dva.com/giveaway", "https://pokémon.com/", "https://shop.xn--80ak6aa92e.com/"],
)
def test_punycode_and_idn_blocked(conn: sqlite3.Connection, url: str) -> None:
    with pytest.raises(Blocked) as exc:
        Harness(conn).guard.check(url)
    assert exc.value.rule == "lookalike_idn"


@pytest.mark.parametrize(
    "url",
    [
        "https://pokemonn.com/",  # distance 1
        "https://pokernon.com/",  # m -> rn, distance 2
        "https://pokemon.co/",
        "https://tcgp1ayer.com/",
        "https://pokemoncenter.co/",
        "https://pokemon-claim.com/",
        "https://pokemonofficial.net/",
        "https://claim-tcgplayer.com/",
        "https://pokemon.com.prize-desk.net/",  # official domain embedded in hostname
    ],
)
def test_near_miss_of_official_domain_blocked(conn: sqlite3.Connection, url: str) -> None:
    with pytest.raises(Blocked) as exc:
        Harness(conn).guard.check(url)
    assert exc.value.rule == "lookalike_official"
    assert filtered(conn)[0][1] == "lookalike_official"


@pytest.mark.parametrize(
    "url", ["https://pokemoncardshopuk.com/giveaway", "https://pkmnshop.example/", "https://tcgvault.example/"]
)
def test_legit_shop_with_brand_name_flagged_not_blocked(conn: sqlite3.Connection, url: str) -> None:
    result = Harness(conn).guard.check(url)
    assert LOOKALIKE in result.flags and NOT_TRUSTED in result.flags
    assert not result.trusted
    assert filtered(conn) == []


def test_official_domains_and_subdomains_not_blocked(conn: sqlite3.Connection) -> None:
    admin_store.trust_domain(conn, "pokemon.com")
    g = Harness(conn).guard
    assert g.check("https://www.pokemon.com/us/").trusted
    assert g.check("https://play.pokemon.com/").trusted


@pytest.mark.parametrize(
    "url",
    ["https://www.pokemon.com/us/", "https://press.pokemon.com/en", "https://pokemon.com/",
     "https://www.tcgplayer.com/", "https://shop.pokemoncenter.com/x"],
)
def test_real_subdomains_of_official_domains_not_blocked_even_untiered(
    conn: sqlite3.Connection, url: str
) -> None:
    # pokemon.com deliberately NOT in domain_tiers, so the lookalike rules (including
    # "official domain embedded in another hostname") actually run against these hosts.
    result = Harness(conn).guard.check(url)
    assert result.tier == "UNKNOWN"
    assert filtered(conn) == []


def test_embedded_official_domain_rule_only_hits_other_registrable_domains(
    conn: sqlite3.Connection,
) -> None:
    g = Harness(conn).guard
    assert g.lookalike_block_reason("press.pokemon.com") is None
    assert g.lookalike_block_reason("www.pokemon.com") is None
    assert "embedded" in (g.lookalike_block_reason("www.pokemon.com.win-now.net") or "")
    assert "embedded" in (g.lookalike_block_reason("pokemon.com.example.org") or "")


def test_human_trusted_domain_skips_lookalike_heuristic(conn: sqlite3.Connection) -> None:
    admin_store.trust_domain(conn, "pokemongo.com", note="reviewed by human")
    assert Harness(conn).guard.check("https://pokemongo.com/").trusted


def test_levenshtein() -> None:
    assert levenshtein("pokemon.com", "pokemon.com") == 0
    assert levenshtein("pokernon.com", "pokemon.com") == 2
    assert levenshtein("", "abc") == 3


# --- reputation -----------------------------------------------------------------------


def test_safe_browsing_match_blocks_and_marks_unknown_domain(conn: sqlite3.Connection) -> None:
    url = "https://free-cards.example/claim"
    h = Harness(conn, sb=FakeSafeBrowsing(unsafe={url}))
    with pytest.raises(Blocked) as exc:
        h.guard.fetch(url)
    assert exc.value.rule == "safe_browsing"
    assert store.get_domain_tier(conn, "free-cards.example") == "BLOCKED"
    row = conn.execute("SELECT added_by FROM domain_tiers").fetchone()
    assert row == ("url_guard",)
    assert [r for r in h.requests if r.url.host == "free-cards.example"] == []


def test_safe_browsing_match_on_shared_trusted_host_blocks_url_only(
    conn: sqlite3.Connection,
) -> None:
    admin_store.trust_domain(conn, "gleam.io")
    bad = "https://gleam.io/evil/fake"
    h = Harness(conn, sb=FakeSafeBrowsing(unsafe={bad}))
    with pytest.raises(Blocked):
        h.guard.check(bad)
    assert store.get_domain_tier(conn, "gleam.io") == "TRUSTED"
    assert h.guard.check("https://gleam.io/good/real").trusted
    assert filtered(conn) == [(bad, "safe_browsing")]
    # The bad URL stays blocked on later checks (cached match), without a new lookup.
    with pytest.raises(Blocked):
        h.guard.check(bad)
    assert h.sb.calls.count(bad) == 1


@pytest.mark.parametrize(
    ("domain", "tier", "url"),
    [
        ("reddit.com", "PLATFORM", "https://www.reddit.com/r/x/comments/abc/scam/"),
        ("bit.ly", "LINK_HUB", "https://bit.ly/3scam"),
    ],
)
def test_safe_browsing_match_on_platform_or_link_hub_blocks_url_only(
    conn: sqlite3.Connection, domain: str, tier: str, url: str
) -> None:
    admin_store.set_domain_tier(conn, domain, tier)
    h = Harness(conn, sb=FakeSafeBrowsing(unsafe={url}))
    with pytest.raises(Blocked) as exc:
        h.guard.fetch(url)
    assert exc.value.rule == "safe_browsing"
    assert store.get_domain_tier(conn, domain) == tier
    assert filtered(conn) == [(url, "safe_browsing")]
    assert h.requests == []


def test_reputation_down_fails_closed(conn: sqlite3.Connection) -> None:
    admin_store.trust_domain(conn, "gleam.io")
    h = Harness(conn, sb=FakeSafeBrowsing(down=True))
    result = h.guard.check("https://gleam.io/abc")
    assert result.tier == "UNKNOWN"
    assert not result.trusted
    assert NOT_TRUSTED in result.flags
    assert "safe_browsing_unavailable" in result.reasons


def test_reputation_down_uses_fresh_cache(conn: sqlite3.Connection) -> None:
    admin_store.trust_domain(conn, "gleam.io")
    url = "https://gleam.io/abc"
    store.put_check(conn, "safe_browsing", url, "clean", now=NOW - timedelta(hours=2))
    h = Harness(conn, sb=FakeSafeBrowsing(down=True))
    assert h.guard.check(url).trusted
    assert h.sb.calls == []


def test_reputation_down_ignores_stale_cache(conn: sqlite3.Connection) -> None:
    admin_store.trust_domain(conn, "gleam.io")
    url = "https://gleam.io/abc"
    store.put_check(conn, "safe_browsing", url, "clean", now=NOW - timedelta(hours=30))
    assert not Harness(conn, sb=FakeSafeBrowsing(down=True)).guard.check(url).trusted


def test_cached_match_blocks_without_calling_service(conn: sqlite3.Connection) -> None:
    url = "https://phish.example/"
    store.put_check(conn, "safe_browsing", url, "match", now=NOW)
    h = Harness(conn)
    with pytest.raises(Blocked):
        h.guard.check(url)
    assert h.sb.calls == []


def test_safe_browsing_results_are_cached(conn: sqlite3.Connection) -> None:
    h = Harness(conn)
    h.guard.check("https://shop.example/a")
    h.guard.check("https://shop.example/a")
    assert h.sb.calls == ["https://shop.example/a"]


def test_new_domain_flagged_not_blocked(conn: sqlite3.Connection) -> None:
    h = Harness(conn, age=FakeDomainAge({"brand-new.example": 5}))
    result = h.guard.check("https://brand-new.example/giveaway")
    assert NEW_DOMAIN in result.flags
    assert result.domain_age_days == 5
    assert filtered(conn) == []


def test_rdap_down_age_unknown(conn: sqlite3.Connection) -> None:
    result = Harness(conn, age=FakeDomainAge(down=True)).guard.check("https://x.example/")
    assert result.domain_age_days is None
    assert "domain_age_unknown" in result.reasons
    assert NEW_DOMAIN not in result.flags


# --- tiers ----------------------------------------------------------------------------


def test_platform_domain_never_trusted(conn: sqlite3.Connection) -> None:
    admin_store.set_domain_tier(conn, "youtube.com", "PLATFORM")
    result = Harness(conn).guard.check("https://www.youtube.com/watch?v=abc")
    assert result.tier == "PLATFORM"
    assert not result.trusted


def test_platform_domain_never_trusted_even_if_table_says_trusted(
    conn: sqlite3.Connection,
) -> None:
    admin_store.trust_domain(conn, "instagram.com", note="mistake")
    result = Harness(conn).guard.check("https://www.instagram.com/p/xyz/")
    assert result.tier == "PLATFORM"
    assert not result.trusted


def test_platform_page_never_fetched(conn: sqlite3.Connection) -> None:
    url = "https://www.instagram.com/pokeshop/p/xyz/"
    h = Harness(conn, {url: html()})
    with pytest.raises(PlatformLink) as exc:
        h.guard.fetch(url)
    assert exc.value.url == url and exc.value.guard.tier == "PLATFORM"
    assert h.requests == []  # not even robots.txt
    assert filtered(conn) == []  # not a guardrail drop
    verdicts = [r[0] for r in conn.execute("SELECT verdict FROM fetch_log")]
    assert verdicts == ["SKIP:platform"]


def test_shortener_redirect_to_platform_stops_before_platform(
    conn: sqlite3.Connection,
) -> None:
    admin_store.set_domain_tier(conn, "bit.ly", "LINK_HUB")
    short, target = "https://bit.ly/abc", "https://www.instagram.com/pokeshop/"
    h = Harness(conn, {short: redirect(target), target: html()})
    with pytest.raises(PlatformLink) as exc:
        h.guard.fetch(short)
    assert exc.value.url == target  # the resolved URL, for judging the account
    assert exc.value.hops == [short]
    assert all(r.url.host != "www.instagram.com" for r in h.requests)


def test_unknown_domain_not_trusted(conn: sqlite3.Connection) -> None:
    result = Harness(conn).guard.check("https://random-shop.example/")
    assert result.tier == "UNKNOWN"
    assert NOT_TRUSTED in result.flags


# --- response handling --------------------------------------------------------------


def test_oversize_response_truncated(conn: sqlite3.Connection) -> None:
    big = b"a" * (MAX_BYTES + 500_000)
    h = Harness(conn, {"https://shop.example/": httpx.Response(
        200, headers={"content-type": "text/html"}, content=big)})
    res = h.guard.fetch("https://shop.example/")
    assert res.truncated
    assert len(res.body) == MAX_BYTES


def test_gzip_bomb_truncated_not_expanded(conn: sqlite3.Connection) -> None:
    bomb = gzip.compress(b"\0" * (50 * 1024 * 1024))
    h = Harness(conn, {"https://shop.example/": httpx.Response(
        200, headers={"content-type": "text/html", "content-encoding": "gzip"}, content=bomb)})
    res = h.guard.fetch("https://shop.example/")
    assert res.truncated and len(res.body) == MAX_BYTES


def test_gzip_body_decoded(conn: sqlite3.Connection) -> None:
    h = Harness(conn, {"https://shop.example/": httpx.Response(
        200, headers={"content-type": "text/html", "content-encoding": "gzip"},
        content=gzip.compress(b"<p>hello</p>"))})
    assert h.guard.fetch("https://shop.example/").text() == "<p>hello</p>"


@pytest.mark.parametrize(
    "ctype", ["application/pdf", "application/zip", "application/x-msdownload", "image/png", ""]
)
def test_disallowed_content_type(conn: sqlite3.Connection, ctype: str) -> None:
    headers = {"content-type": ctype} if ctype else {}
    h = Harness(conn, {"https://shop.example/f": httpx.Response(200, headers=headers,
                                                                 content=b"%PDF")})
    with pytest.raises(Blocked) as exc:
        h.guard.fetch("https://shop.example/f")
    assert exc.value.rule == "content_type"
    assert filtered(conn) == [("https://shop.example/f", "content_type")]


@pytest.mark.parametrize("ctype", ["application/rss+xml", "application/atom+xml",
                                   "application/json", "text/xml; charset=utf-8"])
def test_feed_and_json_types_allowed(conn: sqlite3.Connection, ctype: str) -> None:
    h = Harness(conn, {"https://api.example/x": httpx.Response(
        200, headers={"content-type": ctype}, content=b"<rss/>")})
    assert h.guard.fetch("https://api.example/x").status_code == 200


def test_text_plain_allowed_only_for_listed_feed(conn: sqlite3.Connection) -> None:
    plain = httpx.Response(200, headers={"content-type": "text/plain"}, content=b"<rss/>")
    h = Harness(conn, {FEED_URL: plain, "https://other.example/feed.txt": plain})
    assert h.guard.fetch(FEED_URL).body == b"<rss/>"
    with pytest.raises(Blocked) as exc:
        h.guard.fetch("https://other.example/feed.txt")
    assert exc.value.rule == "content_type"


def test_unsupported_content_encoding_blocked(conn: sqlite3.Connection) -> None:
    h = Harness(conn, {"https://shop.example/": httpx.Response(
        200, headers={"content-type": "text/html", "content-encoding": "br"}, content=b"x")})
    with pytest.raises(Blocked) as exc:
        h.guard.fetch("https://shop.example/")
    assert exc.value.rule == "content_encoding"


# --- request hygiene -------------------------------------------------------------------


def test_no_cookies_no_auth_honest_user_agent(conn: sqlite3.Connection) -> None:
    h = Harness(conn, {
        "https://shop.example/a": httpx.Response(
            302, headers={"location": "/b", "set-cookie": "session=abc; Path=/"}),
        "https://shop.example/b": html(),
    })
    h.guard.fetch("https://shop.example/a")
    h.guard.fetch("https://shop.example/a")
    pages = [r for r in h.requests if r.url.path != "/robots.txt"]
    assert len(pages) == 4
    for r in pages:
        assert "cookie" not in r.headers
        assert "authorization" not in r.headers
        assert r.headers["user-agent"] == USER_AGENT


def test_robots_disallow_blocks(conn: sqlite3.Connection) -> None:
    robots = httpx.Response(200, headers={"content-type": "text/plain"},
                            text="User-agent: *\nDisallow: /private\n")
    h = Harness(conn, {"https://shop.example/robots.txt": robots,
                       "https://shop.example/public": html()})
    assert h.guard.fetch("https://shop.example/public").status_code == 200
    with pytest.raises(Blocked) as exc:
        h.guard.fetch("https://shop.example/private/giveaway")
    assert exc.value.rule == "robots"
    robots_fetches = [r for r in h.requests if r.url.path == "/robots.txt"]
    assert len(robots_fetches) == 1  # cached per origin


@pytest.mark.parametrize("status", [404, 410, 401, 403])
def test_robots_4xx_means_no_restrictions(conn: sqlite3.Connection, status: int) -> None:
    # RFC 9309 2.3.1.3: any 4xx (including 401/403) -> robots.txt "unavailable" -> allowed.
    h = Harness(conn, {"https://shop.example/robots.txt": httpx.Response(status),
                       "https://shop.example/": html()})
    assert h.guard.fetch("https://shop.example/").status_code == 200


@pytest.mark.parametrize("status", [500, 503])
def test_robots_5xx_refuses_this_run_and_retries_next_run(
    conn: sqlite3.Connection, status: int
) -> None:
    routes: dict[str, Route] = {"https://shop.example/robots.txt": httpx.Response(status),
                                "https://shop.example/": html()}
    h = Harness(conn, routes)
    with pytest.raises(Blocked) as exc:
        h.guard.fetch("https://shop.example/")
    assert exc.value.rule == "robots_unreachable"
    assert filtered(conn)[-1] == ("https://shop.example/", "robots_unreachable")
    with pytest.raises(Blocked):  # same run: not re-fetched
        h.guard.fetch("https://shop.example/")
    assert len([r for r in h.requests if r.url.path == "/robots.txt"]) == 1
    # Unreachable is not cached across runs: the next run (new guard) tries again.
    assert store.get_cached_check(conn, "robots", "https://shop.example", now=NOW) is None
    routes["https://shop.example/robots.txt"] = httpx.Response(404)
    assert Harness(conn, routes).guard.fetch("https://shop.example/").status_code == 200


def test_robots_network_failure_refuses_this_run(conn: sqlite3.Connection) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    h = Harness(conn, {"https://shop.example/robots.txt": down,
                       "https://shop.example/": html()})
    with pytest.raises(Blocked) as exc:
        h.guard.fetch("https://shop.example/")
    assert exc.value.rule == "robots_unreachable"


def test_robots_result_cached_across_runs_for_24h(conn: sqlite3.Connection) -> None:
    robots = httpx.Response(200, headers={"content-type": "text/plain"},
                            text="User-agent: *\nDisallow: /private\n")
    routes: dict[str, Route] = {"https://shop.example/robots.txt": robots,
                                "https://shop.example/a": html()}
    first = Harness(conn, routes)
    first.guard.fetch("https://shop.example/a")
    cached = store.get_cached_check(conn, "robots", "https://shop.example", now=NOW)
    assert cached is not None and cached["verdict"] == "rules"
    second = Harness(conn, routes)  # next run
    with pytest.raises(Blocked) as exc:
        second.guard.fetch("https://shop.example/private/x")
    assert exc.value.rule == "robots"
    assert [r for r in second.requests if r.url.path == "/robots.txt"] == []


def test_robots_with_non_text_type_treated_as_no_rules(conn: sqlite3.Connection) -> None:
    h = Harness(conn, {
        "https://shop.example/robots.txt": httpx.Response(
            200, headers={"content-type": "application/pdf"}, content=b"Disallow: /"),
        "https://shop.example/": html(),
    })
    assert h.guard.fetch("https://shop.example/").status_code == 200
    assert filtered(conn) == []


def test_per_host_interval_and_crawl_delay(conn: sqlite3.Connection) -> None:
    robots = httpx.Response(200, headers={"content-type": "text/plain"},
                            text="User-agent: *\nCrawl-delay: 12\n")
    h = Harness(conn, {"https://a.example/robots.txt": robots, "https://a.example/": html(),
                       "https://b.example/": html()}, interval=5)
    h.guard.fetch("https://a.example/")
    h.guard.fetch("https://a.example/")
    h.guard.fetch("https://b.example/")
    assert 12 in h.sleeps  # second request to a.example waited for Crawl-delay
    assert 5 in h.sleeps  # robots.txt -> page on a.example within one fetch


def test_fetch_log_records_tier_and_verdict(conn: sqlite3.Connection) -> None:
    h = Harness(conn, {"https://pokemoncardshopuk.com/": html()})
    h.guard.fetch("https://pokemoncardshopuk.com/")
    rows = conn.execute(
        "SELECT url, domain, tier, verdict, status_code FROM fetch_log ORDER BY id"
    ).fetchall()
    url = "https://pokemoncardshopuk.com/"
    assert (url, "pokemoncardshopuk.com", "UNKNOWN", "FLAG", 200) in rows


# --- every guardrail drop writes filtered_items ----------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "ftp://a.example/",
        "https://u:p@a.example/",
        "https://a.example:8080/",
        "https://xn--pokmon-dva.com/",
        "https://pokémon.com/",
        "https://pokemonn.com/",
        "https://pokemon-claim.com/",
        "https://pokemon.com.prize-desk.net/",
        "http://127.0.0.1/",
        "http://[::ffff:10.0.0.1]/",
        "https://blocked.example/",
        "https://phish.example/",
    ],
)
def test_every_check_block_writes_filtered_items(conn: sqlite3.Connection, url: str) -> None:
    admin_store.block_domain(conn, "blocked.example")
    h = Harness(conn, sb=FakeSafeBrowsing(unsafe={"https://phish.example/"}))
    with pytest.raises(Blocked) as exc:
        h.guard.check(url)
    assert filtered(conn) == [(url, exc.value.rule)]


# --- DNS rebinding: connect to the vetted IP, never re-resolve -------------------------


class FakeNetStream(httpcore.NetworkStream):
    """Speaks just enough HTTP/1.1 for one request per connection (Connection: close)."""

    def __init__(self) -> None:
        self.written = b""
        self.to_read = b""
        self.sni: str | None = None

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.written += buffer
        if b"\r\n\r\n" in self.written and not self.to_read:
            path = self.written.split(b" ", 2)[1]
            status, body = ((b"404 Not Found", b"") if path == b"/robots.txt"
                            else (b"200 OK", b"<html>pinned</html>"))
            self.to_read = (b"HTTP/1.1 " + status + b"\r\nContent-Type: text/html\r\n"
                            b"Content-Length: " + str(len(body)).encode() +
                            b"\r\nConnection: close\r\n\r\n" + body)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        chunk, self.to_read = self.to_read[:max_bytes], self.to_read[max_bytes:]
        return chunk

    def close(self) -> None:
        pass

    def start_tls(self, ssl_context: Any, server_hostname: str | None = None,
                  timeout: float | None = None) -> httpcore.NetworkStream:
        self.sni = server_hostname  # pretend TLS; record which name SNI/cert check used
        return self

    def get_extra_info(self, info: str) -> Any:
        return None


def recording_backend() -> tuple[type[PinnedBackend], list[tuple[str, int, FakeNetStream]]]:
    opened: list[tuple[str, int, FakeNetStream]] = []

    class Recording(PinnedBackend):
        def open_tcp(self, ip: str, port: int, timeout: Any, local_address: Any,
                     socket_options: Any) -> httpcore.NetworkStream:
            stream = FakeNetStream()
            opened.append((ip, port, stream))
            return stream

    return Recording, opened


class RebindingResolver:
    """First answer public, every later answer private (classic DNS rebinding)."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, host: str) -> list[str]:
        self.calls.append(host)
        return [PUBLIC_IP] if len(self.calls) == 1 else ["127.0.0.1"]


@pytest.fixture
def no_system_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any DNS lookup outside the guard's resolver fails the test."""

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("unexpected DNS lookup outside url_guard's resolver")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def test_connects_to_vetted_ip_without_second_lookup(
    conn: sqlite3.Connection, no_system_dns: None
) -> None:
    store.put_check(conn, "robots", "https://rebind.example", "allow_all", now=NOW)
    backend, opened = recording_backend()
    resolver = RebindingResolver()
    h = Harness(conn, resolver=resolver, backend_cls=backend)
    res = h.guard.fetch("https://rebind.example/giveaway")
    assert res.text() == "<html>pinned</html>"
    assert resolver.calls == ["rebind.example"]  # resolved exactly once
    assert [(ip, port) for ip, port, _ in opened] == [(PUBLIC_IP, 443)]
    stream = opened[0][2]
    assert stream.sni == "rebind.example"  # TLS hostname is the real host, not the IP
    assert b"\r\nHost: rebind.example\r\n" in stream.written


def test_second_resolution_returning_private_ip_is_blocked(
    conn: sqlite3.Connection, no_system_dns: None
) -> None:
    store.put_check(conn, "robots", "https://rebind.example", "allow_all", now=NOW)
    backend, opened = recording_backend()
    resolver = RebindingResolver()
    h = Harness(conn, resolver=resolver, backend_cls=backend)
    h.guard.fetch("https://rebind.example/a")  # resolution 1: public, connected
    with pytest.raises(Blocked) as exc:  # resolution 2: rebound to 127.0.0.1
        h.guard.fetch("https://rebind.example/b")
    assert exc.value.rule == "private_ip"
    assert resolver.calls == ["rebind.example", "rebind.example"]
    assert [ip for ip, _, _ in opened] == [PUBLIC_IP]  # never connected to 127.0.0.1
    assert filtered(conn)[-1] == ("https://rebind.example/b", "private_ip")


def test_rebinding_between_page_and_robots_hop_fails_closed(
    conn: sqlite3.Connection, no_system_dns: None
) -> None:
    backend, opened = recording_backend()
    resolver = RebindingResolver()
    h = Harness(conn, resolver=resolver, backend_cls=backend)
    # The page host is vetted first (public); its robots.txt hop then gets the rebound
    # private answer. robots.txt is unreachable -> the page is refused, nothing connects.
    with pytest.raises(Blocked) as exc:
        h.guard.fetch("http://rebind.example/giveaway")
    assert exc.value.rule == "robots_unreachable"
    assert opened == []
    assert ("http://rebind.example/robots.txt", "private_ip") in filtered(conn)


def test_pinned_backend_refuses_unvetted_host_and_private_pin() -> None:
    with pytest.raises(httpcore.ConnectError, match="not vetted"):
        PinnedBackend({}).connect_tcp("unvetted.example", 443)
    with pytest.raises(httpcore.ConnectError, match="non-public"):
        PinnedBackend({"evil.example": ["10.0.0.1"]}).connect_tcp("evil.example", 443)


def test_from_env_requires_safe_browsing_key(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    with pytest.raises(MissingConfigError, match="SAFE_BROWSING_API_KEY"):
        UrlGuard.from_env(conn)


def test_guard_config_loads_repo_config() -> None:
    cfg = GuardConfig.load(CONFIG_DIR)
    assert {"pokemon.com", "pokemoncenter.com", "tcgplayer.com"} <= cfg.official_domains
    assert "youtube.com" in cfg.platform_domains
    # Reddit RSS stays out until its robots.txt has been checked (Phase 2).
    assert not any("reddit.com" in u for u in cfg.feed_urls)
