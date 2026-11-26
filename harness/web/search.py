from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import aiohttp

from harness.web.models import SearchResult


class SearchError(RuntimeError):
    pass


class SearXNGSearch:
    def __init__(self, base_url: str, timeout_seconds: int = 8):
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("SearXNG base_url must be an HTTP(S) URL.")
        if parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("SearXNG must be bound to loopback; remote search endpoints are not accepted.")
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    async def search(self, query: str, limit: int = 5, language: str = "auto", safe_search: int = 1):
        query = query.strip()
        if not query or len(query) > 500:
            raise ValueError("Search query must contain 1–500 characters.")
        if not 1 <= limit <= 10:
            raise ValueError("Search result limit must be between 1 and 10.")
        params = {"q": query, "format": "json", "language": language, "safesearch": safe_search}
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(f"{self.base_url}/search", params=params) as response:
                    if response.status != 200:
                        raise SearchError(f"SearXNG returned HTTP {response.status}.")
                    payload = await response.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            if isinstance(exc, SearchError):
                raise
            raise SearchError(f"SearXNG request failed: {exc}") from exc
        results = []
        for item in payload.get("results", [])[:limit]:
            url = item.get("url", "")
            if not url.startswith(("http://", "https://")):
                continue
            results.append(SearchResult(
                title=str(item.get("title") or "")[:500],
                url=url[:4096],
                content=str(item.get("content") or "")[:1500],
                engine=str(item.get("engine") or "")[:80],
                score=item.get("score") if isinstance(item.get("score"), (int, float)) else None,
            ))
        return results
