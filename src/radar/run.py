"""One polling cycle: sources -> url_guard -> widgets -> classifier -> rules -> Discord/queue.

    uv run python -m radar.run --once

Idempotent: a source item is marked processed (raw_items) only once it reached a final
decision, giveaways are unique by canonical URL, and an alert's `alerted_at` is set only
after Discord accepted it. Running twice on the same input never alerts twice; transient
failures (network, robots.txt 5xx, model unreachable) are simply retried next run.

Pings go out only for a TRUSTED domain with no warning flags and a low scam score, or a
PLATFORM post whose account passes accounts.py. Everything else goes to the review queue.
PAUSE=1 stops everything before any connection or fetch. Logs counts and URLs only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit

from radar import db, store
from radar.accounts import AccountInfo, evaluate_account, record_held_back
from radar.adapters.base import RawItem, SourceAdapter
from radar.api_client import ApiError
from radar.classify import ClassifyError, Giveaway, visible_text
from radar.config import (
    CONFIG_DIR,
    MissingConfigError,
    load_dotenv_if_present,
    load_yaml,
    paused,
)
from radar.domains import domain_label, normalize_host
from radar.migrate import migrate
from radar.notify import OddsHint, badges
from radar.scoring import final_scam_likelihood, find_scam_phrases, record_hits
from radar.url_guard import (
    NOT_TRUSTED,
    Blocked,
    FetchFailed,
    FetchResult,
    GuardResult,
    PlatformLink,
    UrlGuard,
)
from radar.widgets import discover_widgets, entry_count

SCAM_SIGNALS = "SCAM SIGNALS"
SCAM_NOT_LOW = "SCAM SCORE NOT LOW"
NO_VERDICT = "NO CLASSIFIER VERDICT"
ACCOUNT_UNKNOWN = "ACCOUNT UNKNOWN"
# Guard rules that mean "try again next run", not "drop this URL".
RETRY_RULES = frozenset({"robots_unreachable"})

_TRACKING_PARAM = re.compile(r"^(utm_.*|fbclid|gclid|igshid|igsh|mc_cid|mc_eid|ref_src|si)$",
                             re.IGNORECASE)
_PLATFORM_NAMES = {"twitter": "x"}
_RESERVED_PATHS = frozenset({
    "p", "reel", "reels", "tv", "explore", "stories", "i", "home", "search", "hashtag",
    "intent", "share", "status", "watch", "shorts", "channel", "c", "user", "r", "video",
    "groups", "events", "permalink.php", "login", "accounts",
})


# --- interfaces (real implementations: classify.Classifier, notify.Notifier) ---------------


class ClassifierLike(Protocol):
    def classify(self, *, url: str, domain: str, title: str, snippet: str,
                 pages: list[tuple[str, str]]) -> Giveaway | None: ...


class NotifierLike(Protocol):
    def send_alert(self, giveaway: dict[str, Any], badge_list: list[str]) -> None: ...
    def send_digest(self, items: list[dict[str, Any]], total: int, odds: OddsHint) -> None: ...


@dataclass(frozen=True)
class RunConfig:
    eligible_countries: tuple[str, ...] = ("US",)
    max_new_items: int = 25
    digest_hour_utc: int = 14
    odds: OddsHint = field(default_factory=OddsHint)

    @classmethod
    def load(cls, config_dir: Path = CONFIG_DIR) -> RunConfig:
        sources = load_yaml("sources.yaml", config_dir)
        region = sources.get("region") or {}
        limits = sources.get("limits") or {}
        return cls(
            eligible_countries=tuple(region.get("eligible_countries") or ["US"]),
            max_new_items=int(limits.get("max_new_items_per_run", 25)),
            digest_hour_utc=int((sources.get("digest") or {}).get("hour_utc", 14)),
            odds=OddsHint.from_config(sources.get("odds_hint")),
        )


@dataclass
class RunStats:
    items_found: int = 0  # new (never seen) source items this run
    processed: int = 0
    deferred: int = 0  # over the per-run cap, picked up next run
    queued: int = 0
    alerts_sent: int = 0
    errors: list[str] = field(default_factory=list)


# --- helpers ------------------------------------------------------------------------------


def canonical_key(url: str) -> str:
    """Dedup key: host without www, path without trailing slash, tracking params dropped."""
    parts = urlsplit(url)
    host = normalize_host(parts.hostname or "").removeprefix("www.")
    path = parts.path.rstrip("/") or "/"
    query = urlencode(sorted(
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not _TRACKING_PARAM.match(k)
    ))
    return f"{host}{path}" + (f"?{query}" if query else "")


def platform_name(host: str) -> str:
    label = domain_label(host)
    return _PLATFORM_NAMES.get(label, label)


def handle_from_url(url: str) -> str | None:
    """The posting account in a platform URL, when the URL names one.

    instagram.com/<handle>/..., x.com/<handle>/status/..., tiktok.com/@<handle>/...,
    youtube.com/@<handle>. Post-only URLs (instagram.com/p/<id>, reddit threads) -> None.
    """
    segments = [s for s in urlsplit(url).path.split("/") if s]
    if not segments:
        return None
    first = segments[0]
    if first.startswith("@") and len(first) > 1:
        return first[1:].lower()
    if first.lower() in _RESERVED_PATHS or not re.fullmatch(r"[A-Za-z0-9._]{2,40}", first):
        return None
    return first.lower()


def _deadline(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


# --- one cycle ----------------------------------------------------------------------------


@dataclass
class _Target:
    """What the alert/queue item points at (the widget for embedded giveaways)."""
    url: str
    guard: GuardResult
    host_url: str | None = None
    extra_flags: list[str] = field(default_factory=list)


class Cycle:
    def __init__(
        self, conn: Any, *, guard: UrlGuard, classifier: ClassifierLike,
        notifier: NotifierLike, config: RunConfig, now: datetime | None = None,
    ) -> None:
        self.conn = conn
        self.guard = guard
        self.classifier = classifier
        self.notifier = notifier
        self.config = config
        self.now = now or store.utcnow()
        self.stats = RunStats()

    def run(self, adapters: Sequence[SourceAdapter]) -> RunStats:
        run_id = store.start_run(self.conn)
        try:
            items = self._collect(adapters)
            for item in items:
                if self.stats.processed >= self.config.max_new_items:
                    self.stats.deferred += 1
                    continue
                self.stats.processed += 1
                try:
                    self.process(item)
                except (FetchFailed, ClassifyError) as exc:
                    self.stats.errors.append(f"{type(exc).__name__}: {exc}")
            self.send_pending_alerts()
            self.maybe_send_digest()
        finally:
            store.finish_run(self.conn, run_id, items_found=self.stats.items_found,
                             alerts_sent=self.stats.alerts_sent, errors=self.stats.errors)
        return self.stats

    def _collect(self, adapters: Sequence[SourceAdapter]) -> list[RawItem]:
        items: list[RawItem] = []
        seen: set[str] = set()
        for adapter in adapters:
            try:
                found = adapter.fetch()
            except (ApiError, MissingConfigError) as exc:
                self.stats.errors.append(f"{adapter.name}: {exc}")
                continue
            for item in found:
                if item.external_id in seen or store.raw_item_exists(self.conn, item.external_id):
                    continue
                seen.add(item.external_id)
                items.append(item)
        self.stats.items_found = len(items)
        return items

    def _done(self, item: RawItem) -> int:
        """Mark the source item processed so later runs skip it."""
        return store.insert_raw_item(
            self.conn, source=item.source, external_id=item.external_id, url=item.url,
            title=item.title, body=item.body[:4000], author=item.author,
            published_at=item.published_at,
        )

    # --- per item -----------------------------------------------------------------------

    def process(self, item: RawItem) -> None:
        pages: list[tuple[str, str]] = []
        widget_htmls: list[str] = []
        try:
            page = self.guard.fetch(item.url)
        except PlatformLink as link:
            target = _Target(link.url, link.guard)
        except Blocked as b:
            if b.rule not in RETRY_RULES:
                self._done(item)  # url_guard already wrote the filtered_items row
            return
        else:
            target = self._page_target(item, page, pages, widget_htmls)
            if target is None:
                return

        verdict = self.classifier.classify(
            url=target.url, domain=target.guard.host, title=item.title, snippet=item.body,
            pages=pages,
        )
        if verdict is not None and not (verdict.is_giveaway and verdict.is_pokemon_tcg):
            store.record_filtered(self.conn, target.url, "not_giveaway",
                                  "classifier: not a Pokemon TCG giveaway")
            self._done(item)
            return
        if verdict is not None and verdict.us_eligible == "no":
            store.record_filtered(self.conn, target.url, "region",
                                  f"not open to {'/'.join(self.config.eligible_countries)}")
            self._done(item)
            return
        deadline = _deadline(verdict.deadline) if verdict else None
        if deadline is not None and deadline < self.now.date():
            store.record_filtered(self.conn, target.url, "expired", f"deadline {deadline}")
            self._done(item)
            return

        self._decide(item, target, verdict, pages, deadline, widget_htmls)

    def _page_target(
        self, item: RawItem, page: FetchResult, pages: list[tuple[str, str]],
        widget_htmls: list[str],
    ) -> _Target | None:
        if page.guard.tier == "LINK_HUB":
            # A link-in-bio page that didn't redirect anywhere: there is no single final
            # destination to judge or post, so it is never alerted on.
            store.record_filtered(self.conn, page.final_url, "link_hub_unresolved",
                                  "link-in-bio page with no single destination")
            self._done(item)
            return None
        html = page.text()
        pages.append((page.final_url, visible_text(html)))
        target = _Target(page.final_url, page.guard)
        for found in discover_widgets(self.guard, self.conn, page):
            if found.result is None:
                continue
            widget_html = found.result.text()
            widget_htmls.append(widget_html)
            pages.append((found.result.final_url, visible_text(widget_html)))
            if target.host_url is None and found.result.guard.tier == "TRUSTED":
                # The entry happens on the widget, so the widget is what gets judged and
                # posted. The host page's own warnings still hold the ping back, except
                # NOT TRUSTED (nobody enters on the host page).
                target = _Target(found.result.final_url, found.result.guard,
                                 host_url=page.final_url,
                                 extra_flags=[f for f in page.guard.flags if f != NOT_TRUSTED])
        return target

    def _decide(
        self, item: RawItem, target: _Target, verdict: Giveaway | None,
        pages: list[tuple[str, str]], deadline: date | None, widget_htmls: list[str],
    ) -> None:
        url, guard = target.url, target.guard
        flags = list(dict.fromkeys(guard.flags + target.extra_flags))

        text = "\n".join([item.title, item.body, *(t for _, t in pages)])
        hits = find_scam_phrases(text)
        record_hits(self.conn, url, hits)
        # What the content says (rules + classifier) decides the scam reasons shown. The
        # stored level also counts guard warnings, so a flagged domain is never "low".
        content_scam = final_scam_likelihood(verdict.scam_likelihood if verdict else None,
                                             hits)
        scam = final_scam_likelihood(content_scam, hits, "medium" if flags else "low")

        platform = handle = None
        followers = account_age = None
        if guard.tier == "PLATFORM":
            platform = platform_name(guard.host)
            ping, reasons, handle, followers, account_age = self._judge_account(
                item, url, platform, verdict, content_scam, flags)
        else:
            reasons = list(flags)
            if guard.tier != "TRUSTED" and NOT_TRUSTED not in reasons:
                reasons.append(NOT_TRUSTED)
            if content_scam == "high":
                reasons.append(SCAM_SIGNALS)
            elif content_scam != "low":
                reasons.append(SCAM_NOT_LOW)
            ping = guard.tier == "TRUSTED" and not reasons
            self._record_held_back(url, reasons, hits_recorded=bool(hits))
        if verdict is None:
            ping = False
            reasons.append(NO_VERDICT)

        display = [r for r in reasons if r not in (SCAM_SIGNALS,)]
        raw_id = self._done(item)
        giveaway_id = store.insert_giveaway(
            self.conn, canonical_key(url),
            raw_item_id=raw_id, url=url, host_url=target.host_url, domain=guard.host,
            tier=guard.tier, platform=platform, account_handle=handle,
            title=(verdict.title if verdict else item.title)[:300],
            summary=(verdict.summary if verdict else item.body)[:1000],
            region=(self.config.eligible_countries[0]
                    if verdict and verdict.us_eligible == "yes" else None),
            deadline=deadline.isoformat() if deadline else None,
            scam_likelihood=scam,
            flags_json=json.dumps(display),
            alert_eligible=1 if ping else 0,
            entry_count=next((n for n in map(entry_count, widget_htmls) if n is not None),
                             None),
            account_followers=followers,
            domain_age_days=guard.domain_age_days,
            account_age_days=account_age,
        )
        if giveaway_id is not None and not ping:
            store.enqueue_review(self.conn, giveaway_id, reasons,
                                 deadline.isoformat() if deadline else None)
            self.stats.queued += 1

    def _judge_account(
        self, item: RawItem, url: str, platform: str, verdict: Giveaway | None, scam: str,
        flags: list[str],
    ) -> tuple[bool, list[str], str | None, int | None, int | None]:
        info = item.account if item.account and item.account.platform == platform else None
        if info is None:
            handle = handle_from_url(url)
            if handle is None:
                store.record_filtered(self.conn, url, "account:unknown",
                                      "platform post without an identifiable account")
                return False, [ACCOUNT_UNKNOWN, *flags], None, None, None
            info = AccountInfo(platform, handle)  # nothing else is known about it
        if verdict is not None and verdict.poster_is_host is not True and (
            info.is_original_post
        ):
            # The classifier can only tighten "original post", never assert it.
            info = AccountInfo(info.platform, info.handle, info.created_at, info.followers,
                               info.verified,
                               None if verdict.poster_is_host is None else False)
        result = evaluate_account(self.conn, info, scam, guard_flags=flags, now=self.now)
        record_held_back(self.conn, url, result)
        return (result.ping, list(result.failing), store.normalize_handle(info.handle),
                result.followers, result.age_days)

    def _record_held_back(self, url: str, reasons: list[str], *, hits_recorded: bool) -> None:
        """One filtered_items row per reason a non-platform item was held back from a
        ping (scam phrase hits already have their own rows)."""
        for reason in reasons:
            if reason == SCAM_SIGNALS and hits_recorded:
                continue
            store.record_filtered(self.conn, url, f"held_back:{_slug(reason)}", reason)

    # --- alerts and digest --------------------------------------------------------------

    def send_pending_alerts(self) -> None:
        for giveaway in store.pending_alerts(self.conn):
            # Re-check right before alerting (cached, so usually free). A block or any
            # new warning sends it to review instead.
            try:
                check = self.guard.check(giveaway["url"])
            except Blocked as b:
                store.demote_to_review(self.conn, giveaway, [f"BLOCKED BEFORE ALERT: {b.rule}"])
                self.stats.queued += 1
                continue
            new_flags = [f for f in check.flags
                         if f not in json.loads(giveaway["flags_json"] or "[]")]
            if new_flags or check.tier != giveaway["tier"]:
                store.demote_to_review(self.conn, giveaway,
                                       new_flags or [f"TIER CHANGED TO {check.tier}"])
                self.stats.queued += 1
                continue
            try:
                self.notifier.send_alert(giveaway, badges(giveaway, self.config.odds))
            except ApiError as exc:
                self.stats.errors.append(f"discord: {exc}")
                return  # leave the rest pending; the next run retries them
            store.mark_alerted(self.conn, giveaway["id"])
            self.stats.alerts_sent += 1

    def maybe_send_digest(self) -> None:
        today = self.now.date().isoformat()
        if self.now.hour < self.config.digest_hour_utc:
            return
        if store.get_state(self.conn, "digest_date") == today:
            return
        items, total = store.review_queue_items(self.conn, limit=15)
        if total:
            try:
                self.notifier.send_digest(items, total, self.config.odds)
            except ApiError as exc:
                self.stats.errors.append(f"discord digest: {exc}")
                return
        store.set_state(self.conn, "digest_date", today)


# --- entrypoint ---------------------------------------------------------------------------


def _production(conn: Any) -> tuple[list[SourceAdapter], UrlGuard, Any, Any, list[Any]]:
    from radar.adapters.brave import BraveAdapter
    from radar.adapters.youtube import YouTubeAdapter
    from radar.api_client import ApiClient
    from radar.classify import Classifier
    from radar.notify import Notifier

    sources = load_yaml("sources.yaml")
    region = (sources.get("region") or {}).get("country", "US")
    api = ApiClient()
    owned: list[Any] = [api]
    brave = sources.get("brave") or {}
    youtube = sources.get("youtube") or {}
    adapters: list[SourceAdapter] = [
        BraveAdapter(api, brave.get("queries") or [], country=region,
                     count=int(brave.get("count", 20)),
                     freshness=str(brave.get("freshness", "pw"))),
        YouTubeAdapter(api, youtube.get("queries") or [], region=region,
                       max_results=int(youtube.get("max_results", 15)),
                       published_within_days=int(youtube.get("published_within_days", 7))),
    ]
    guard = UrlGuard.from_env(conn)
    owned.append(guard)
    return adapters, guard, Classifier(), Notifier(api), owned


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="radar.run", description="One polling cycle.")
    parser.add_argument("--once", action="store_true", required=True,
                        help="run a single cycle and exit (the only mode)")
    parser.parse_args(argv)
    load_dotenv_if_present()
    if paused():
        print("PAUSE=1: nothing fetched or sent.")
        return 0
    try:
        conn = db.connect()
    except (MissingConfigError, db.DatabaseUnavailable) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    owned: list[Any] = []
    try:
        migrate(conn)
        try:
            adapters, guard, classifier, notifier, owned = _production(conn)
        except MissingConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        stats = Cycle(conn, guard=guard, classifier=classifier, notifier=notifier,
                      config=RunConfig.load()).run(adapters)
    finally:
        for resource in owned:
            resource.close()
        conn.close()
    print(f"new items: {stats.items_found} (processed {stats.processed}, deferred "
          f"{stats.deferred}) | queued: {stats.queued} | alerts sent: {stats.alerts_sent} "
          f"| errors: {len(stats.errors)}")
    for err in stats.errors:
        print(f"  - {err}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
