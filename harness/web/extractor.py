from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import trafilatura

from harness.web.models import WebPage


def extract_page(url: str, body: bytes, content_type: str, max_chars: int) -> WebPage:
    html = body.decode("utf-8", errors="replace")
    extracted = trafilatura.extract(
        html, output_format="txt", include_comments=False,
        include_tables=True, favor_recall=False,
    ) or ""
    metadata = trafilatura.extract_metadata(html)
    title = (metadata.title if metadata and metadata.title else "").strip()[:500]
    canonical = url
    if metadata and metadata.url:
        candidate = urljoin(url, metadata.url)
        original_parts = urlsplit(url)
        candidate_parts = urlsplit(candidate)
        if (
            candidate_parts.scheme in {"http", "https"}
            and candidate_parts.hostname
            and candidate_parts.hostname.lower() == (original_parts.hostname or "").lower()
            and not candidate_parts.username
            and not candidate_parts.password
        ):
            canonical = candidate
    text = extracted[:max_chars]
    return WebPage(
        url=url, canonical_url=canonical, title=title, text=text,
        content_type=content_type,
        fetched_at=datetime.now(timezone.utc).isoformat(),
        content_hash=hashlib.sha256(body).hexdigest(),
    )
