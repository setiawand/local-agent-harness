from __future__ import annotations

import asyncio
import hashlib
from urllib.parse import urljoin

import aiohttp

from harness.web.extractor import extract_page
from harness.web.models import WebPage
from harness.web.security import PinnedPublicResolver, WebSecurityError, validate_public_target


class FetchError(RuntimeError):
    pass


class SafeWebFetcher:
    def __init__(
        self, timeout_seconds: int = 10, max_redirects: int = 3,
        max_response_bytes: int = 2_097_152, max_content_chars: int = 12_000,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes
        self.max_content_chars = max_content_chars
        self._semaphore = asyncio.Semaphore(max_concurrent)\n        self.allowed_schemes = allowed_schemes or {"http", "https"}

    async def fetch(self, url: str) -> WebPage:
        async with self._semaphore:
            current = url
            for redirect_count in range(self.max_redirects + 1):
                try:
                    current, _, _ = await validate_public_target(current, self.allowed_schemes)
                    timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
                    connector = aiohttp.TCPConnector(
                        resolver=PinnedPublicResolver(), use_dns_cache=False,
                        limit=2, ssl=True,
                    )
                    async with aiohttp.ClientSession(
                        timeout=timeout, connector=connector,
                        trust_env=False, auto_decompress=True,
                        headers={"User-Agent": "LocalAgentHarness/1.1 (+self-hosted research)"},
                    ) as session:
                        async with session.get(
                            current, allow_redirects=False,
                            headers={"Accept": "text/html,text/plain;q=0.9"},
                        ) as response:
                            if response.status in {301, 302, 303, 307, 308}:
                                location = response.headers.get("Location")
                                if not location or redirect_count >= self.max_redirects:
                                    raise FetchError("Redirect limit reached or Location missing.")
                                current = urljoin(current, location)
                                continue
                            if response.status != 200:
                                raise FetchError(f"Target returned HTTP {response.status}.")
                            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                            if content_type not in {"text/html", "application/xhtml+xml", "text/plain"}:
                                raise FetchError(f"Unsupported content type: {content_type or 'unknown'}.")
                            body = bytearray()
                            async for chunk in response.content.iter_chunked(65536):
                                body.extend(chunk)
                                if len(body) > self.max_response_bytes:
                                    raise FetchError("Response exceeds the 2 MiB decompressed size limit.")
                            raw = bytes(body)
                            if content_type == "text/plain":
                                text = raw.decode("utf-8", errors="replace")[:self.max_content_chars]
                                from datetime import datetime, timezone
                                from harness.web.models import WebPage
                                return WebPage(
                                    url=current, canonical_url=current, title=current,
                                    text=text, content_type=content_type,
                                    fetched_at=datetime.now(timezone.utc).isoformat(),
                                    content_hash=hashlib.sha256(raw).hexdigest(),
                                )
                            return extract_page(current, raw, content_type, self.max_content_chars)
                except (aiohttp.ClientError, asyncio.TimeoutError, WebSecurityError) as exc:
                    raise FetchError(f"Safe fetch failed: {exc}") from exc
            raise FetchError("Redirect processing failed.")
