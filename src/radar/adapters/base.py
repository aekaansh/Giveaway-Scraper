"""The item every adapter returns, and the adapter interface.

Adapters only call keyed APIs through api_client. They never fetch the URLs they find:
every URL in an API result is untrusted and goes through url_guard in run.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import unescape
from typing import Protocol

from radar.accounts import AccountInfo


@dataclass
class RawItem:
    source: str  # adapter name, e.g. "brave" / "youtube"
    external_id: str  # dedup key, unique across sources (prefixed with the source name)
    url: str
    title: str = ""
    body: str = ""  # search snippet or post description
    author: str | None = None
    published_at: str | None = None
    # Account data from an official API (e.g. YouTube channel). None when the source
    # says nothing about the poster (e.g. a search-result link to an Instagram post).
    account: AccountInfo | None = None


class SourceAdapter(Protocol):
    name: str

    def fetch(self) -> list[RawItem]: ...


_TAG = re.compile(r"<[^>]+>")


def plain_text(value: str | None) -> str:
    """API snippets carry <strong> highlights and HTML entities: strip them."""
    return unescape(_TAG.sub("", value or "")).strip()
