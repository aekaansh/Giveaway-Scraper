"""Brave Search API adapter: web results for the configured giveaway queries.

Instagram/TikTok/X/Reddit posts enter the pipeline only as links found here (Reddit's
robots.txt disallows all crawling, so there are no Reddit feeds). The links are never
fetched: url_guard refuses PLATFORM pages and run.py judges the posting account instead.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from radar.adapters.base import RawItem, plain_text
from radar.api_client import ApiClient, brave_headers

ENDPOINT = "https://api.search.brave.com/res/v1/web/search"
# Brave's free plan allows about one request per second.
MIN_INTERVAL_S = 1.1


class BraveAdapter:
    name = "brave"

    def __init__(
        self,
        api: ApiClient,
        queries: list[str],
        *,
        country: str = "US",
        count: int = 20,
        freshness: str = "pw",
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._api = api
        self._queries = queries
        self._country = country
        self._count = count
        self._freshness = freshness
        self._sleep = sleep

    def fetch(self) -> list[RawItem]:
        headers = brave_headers()
        items: list[RawItem] = []
        seen: set[str] = set()
        for i, query in enumerate(self._queries):
            if i:
                self._sleep(MIN_INTERVAL_S)
            data = self._api.get_json(ENDPOINT, headers=headers, params={
                "q": query,
                "country": self._country,
                "search_lang": "en",
                "count": self._count,
                "freshness": self._freshness,
                "safesearch": "moderate",
            })
            for result in _web_results(data):
                url = result.get("url")
                if not isinstance(url, str) or not url or url in seen:
                    continue
                seen.add(url)
                items.append(RawItem(
                    source=self.name,
                    external_id=f"brave:{url}",
                    url=url,
                    title=plain_text(result.get("title")),
                    body=plain_text(result.get("description")),
                    published_at=result.get("page_age"),
                ))
        return items


def _web_results(data: Any) -> list[dict[str, Any]]:
    web = data.get("web") if isinstance(data, dict) else None
    results = web.get("results") if isinstance(web, dict) else None
    return [r for r in results or [] if isinstance(r, dict)]
