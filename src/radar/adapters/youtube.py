"""YouTube Data API v3 adapter: recent videos for the configured giveaway queries.

Quota (10,000 units/day): search.list costs 100 per query, videos.list and channels.list
1 each, so two queries hourly use about 4,900 units a day.

The channel is the account behind the post: its creation date and subscriber count feed
the PLATFORM account rules. The API doesn't expose verified status. A video uploaded by
the channel is its own post, so is_original_post starts True; run.py still requires the
classifier to agree that the uploader runs the giveaway (it can only tighten this).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from radar import store
from radar.accounts import AccountInfo
from radar.adapters.base import RawItem, plain_text
from radar.api_client import ApiClient, youtube_params

API = "https://www.googleapis.com/youtube/v3"


class YouTubeAdapter:
    name = "youtube"

    def __init__(
        self,
        api: ApiClient,
        queries: list[str],
        *,
        region: str = "US",
        max_results: int = 15,
        published_within_days: int = 7,
        now: datetime | None = None,
    ) -> None:
        self._api = api
        self._queries = queries
        self._region = region
        self._max_results = max_results
        self._within = timedelta(days=published_within_days)
        self._now = now

    def fetch(self) -> list[RawItem]:
        key = youtube_params()
        after = store.iso((self._now or store.utcnow()) - self._within).replace("+00:00", "Z")
        video_ids: list[str] = []
        for query in self._queries:
            data = self._api.get_json(f"{API}/search", params={
                **key,
                "part": "snippet",
                "q": query,
                "type": "video",
                "order": "date",
                "maxResults": self._max_results,
                "publishedAfter": after,
                "regionCode": self._region,
                "relevanceLanguage": "en",
            })
            for entry in _items(data):
                vid = (entry.get("id") or {}).get("videoId")
                if isinstance(vid, str) and vid not in video_ids:
                    video_ids.append(vid)
        if not video_ids:
            return []

        videos = []
        for chunk in _chunks(video_ids, 50):
            videos += _items(self._api.get_json(f"{API}/videos", params={
                **key, "part": "snippet", "id": ",".join(chunk),
            }))
        channel_ids = list(dict.fromkeys(
            (v.get("snippet") or {}).get("channelId") for v in videos
        ))
        channels: dict[str, dict[str, Any]] = {}
        for chunk in _chunks([c for c in channel_ids if isinstance(c, str)], 50):
            for ch in _items(self._api.get_json(f"{API}/channels", params={
                **key, "part": "snippet,statistics", "id": ",".join(chunk),
            })):
                channels[ch.get("id")] = ch

        items: list[RawItem] = []
        for video in videos:
            vid = video.get("id")
            snippet = video.get("snippet") or {}
            if not isinstance(vid, str):
                continue
            account = _account(channels.get(snippet.get("channelId")),
                               snippet.get("channelId"))
            items.append(RawItem(
                source=self.name,
                external_id=f"youtube:{vid}",
                url=f"https://www.youtube.com/watch?v={vid}",
                title=plain_text(snippet.get("title")),
                body=plain_text(snippet.get("description")),
                author=account.handle if account else None,
                published_at=snippet.get("publishedAt"),
                account=account,
            ))
        return items


def _account(channel: dict[str, Any] | None, channel_id: Any) -> AccountInfo | None:
    if not isinstance(channel_id, str):
        return None
    snippet = (channel or {}).get("snippet") or {}
    stats = (channel or {}).get("statistics") or {}
    handle = snippet.get("customUrl") or channel_id
    created = snippet.get("publishedAt")
    subscribers = None
    if not stats.get("hiddenSubscriberCount") and str(stats.get("subscriberCount", "")).isdigit():
        subscribers = int(stats["subscriberCount"])
    return AccountInfo(
        platform="youtube",
        handle=handle,
        created_at=_parse_time(created),
        followers=subscribers,
        verified=None,  # not exposed by the Data API
        is_original_post=True,
    )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _items(data: Any) -> list[dict[str, Any]]:
    items = data.get("items") if isinstance(data, dict) else None
    return [i for i in items or [] if isinstance(i, dict)]


def _chunks(values: list[str], size: int) -> list[list[str]]:
    return [values[i:i + size] for i in range(0, len(values), size)]
