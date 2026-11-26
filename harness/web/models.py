from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SearchResult:
    title: str
    url: str
    content: str
    engine: str = ""
    score: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title, "url": self.url, "snippet": self.content,
            "engine": self.engine, "score": self.score,
        }


@dataclass(frozen=True)
class WebPage:
    url: str
    canonical_url: str
    title: str
    text: str
    content_type: str
    fetched_at: str
    content_hash: str

    def as_dict(self, source_id: str) -> dict[str, Any]:
        return {
            "source_id": source_id, "url": self.url,
            "canonical_url": self.canonical_url, "title": self.title,
            "text": self.text, "content_type": self.content_type,
            "fetched_at": self.fetched_at, "content_hash": self.content_hash,
        }
