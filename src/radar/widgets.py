"""Find embedded Gleam / KingSumo / ViralSweep giveaway widgets in raw (no-JS) HTML.

Many shop pages render their giveaway with JavaScript, so the visible text says nothing
but the raw HTML still carries the widget URL: in an iframe/script src, an anchor, a
data-* attribute, or inside an inline script/JSON blob (often with escaped slashes).

Extraction is pure parsing (no network). `discover_widgets` then passes each widget URL
through url_guard, fetches it, and records the host->widget link.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urldefrag, urljoin, urlsplit

from selectolax.lexbor import LexborHTMLParser

from radar import store
from radar.domains import registrable_domain
from radar.url_guard import Blocked, FetchFailed, FetchResult, UrlGuard

WIDGET_DOMAINS = {
    "gleam.io": "gleam",
    "kingsumo.com": "kingsumo",
    "viralsweep.com": "viralsweep",
}
# Script loaders: evidence that a widget exists, but not a giveaway page to fetch.
LOADER_DOMAINS = {"gleamjs.io": "gleam"}
STATIC_SUFFIXES = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
                   ".woff", ".woff2", ".ttf", ".map")
# First path segments on widget hosts that are site pages, not giveaways.
NON_CAMPAIGN_SEGMENTS = frozenset({
    "", "login", "signup", "register", "pricing", "features", "blog", "help", "support",
    "about", "terms", "privacy", "legal", "careers", "contact", "app", "examples",
})
URL_ATTRS = ("src", "href", "action")
MAX_WIDGETS_PER_PAGE = 5
SCAN_TIERS = ("UNKNOWN", "TRUSTED")

# Absolute URLs in raw text, tolerating JSON-escaped slashes (https:\/\/gleam.io\/...).
_INLINE_URL = re.compile(r"https?:(?:\\?/){2}[^\s\"'<>`]+", re.IGNORECASE)


@dataclass(frozen=True)
class Widget:
    kind: str  # gleam / kingsumo / viralsweep
    url: str
    source: str  # iframe / script / anchor / data-attr / inline


@dataclass
class WidgetScan:
    widgets: list[Widget] = field(default_factory=list)
    loaders: list[Widget] = field(default_factory=list)  # loader scripts only


@dataclass
class WidgetFetch:
    widget: Widget
    result: FetchResult | None
    error: str | None = None


def _clean(raw: str) -> str:
    value = raw.strip().replace("\\/", "/").replace("\\u002F", "/").replace("\\u002f", "/")
    value = value.replace("&amp;", "&")
    return value.rstrip("\\),;.]}")


def _classify(raw: str, base_url: str, source: str) -> tuple[str, Widget] | None:
    """('widget'|'loader', Widget) for a widget-host URL, else None."""
    value = _clean(raw)
    if not value or value.lower().startswith(("javascript:", "data:", "mailto:")):
        return None
    url = urldefrag(urljoin(base_url, value)).url
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    domain = registrable_domain(parts.hostname)
    if domain in LOADER_DOMAINS:
        return "loader", Widget(LOADER_DOMAINS[domain], url, source)
    kind = WIDGET_DOMAINS.get(domain)
    if kind is None:
        return None
    path = parts.path.lower()
    if path.endswith(STATIC_SUFFIXES):
        return "loader", Widget(kind, url, source)
    first = path.strip("/").split("/", 1)[0]
    if first in NON_CAMPAIGN_SEGMENTS:
        return None
    return "widget", Widget(kind, url, source)


def _source_for(tag: str, attr: str) -> str:
    if attr.startswith("data-"):
        return "data-attr"
    return {"iframe": "iframe", "script": "script", "a": "anchor"}.get(tag, tag)


def extract_widgets(html: str, base_url: str) -> WidgetScan:
    """All widget URLs in raw HTML, deduplicated, in document order."""
    scan = WidgetScan()
    seen: set[str] = set()

    def add(candidate: tuple[str, Widget] | None) -> None:
        if candidate is None:
            return
        bucket, widget = candidate
        if widget.url in seen:
            return
        seen.add(widget.url)
        (scan.widgets if bucket == "widget" else scan.loaders).append(widget)

    tree = LexborHTMLParser(html)
    for node in tree.css("*"):
        for attr, value in (node.attributes or {}).items():
            if not value or not (attr in URL_ATTRS or attr.startswith("data-")):
                continue
            add(_classify(value, base_url, _source_for(node.tag, attr)))
    # Inline scripts / JSON blobs / anything the attribute pass didn't see.
    for match in _INLINE_URL.finditer(html):
        add(_classify(match.group(0), base_url, "inline"))
    return scan


def discover_widgets(guard: UrlGuard, conn: Any, page: FetchResult) -> list[WidgetFetch]:
    """For an UNKNOWN or TRUSTED page fetched without JS: find embedded widgets, record the
    host->widget link, and fetch each widget through the guard (every guardrail applies)."""
    if page.guard.tier not in SCAN_TIERS:
        return []
    scan = extract_widgets(page.text(), page.final_url)
    fetched: list[WidgetFetch] = []
    for widget in scan.widgets[:MAX_WIDGETS_PER_PAGE]:
        store.record_widget_link(conn, page.final_url, widget.url, widget.kind)
        try:
            fetched.append(WidgetFetch(widget, guard.fetch(widget.url)))
        except (Blocked, FetchFailed) as exc:
            fetched.append(WidgetFetch(widget, None, error=str(exc)))
    return fetched
