from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


class CitationStore:
    """Persist source metadata only; page bodies are deliberately not stored."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS web_sources (
                    source_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    title TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_web_sources_session ON web_sources(session_id)")

    def record(self, session_id: str, page, status: str = "fetched") -> str:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT source_id FROM web_sources WHERE session_id=?",
                (session_id,),
            ).fetchall()
            ordinal = max(
                (int(row["source_id"].rsplit(":", 1)[-1][1:])
                 for row in rows
                 if row["source_id"].rsplit(":", 1)[-1].startswith("W")
                 and row["source_id"].rsplit(":", 1)[-1][1:].isdigit()),
                default=0,
            ) + 1
            source_id = f"W{ordinal}"
            canonical_url = page.get("canonical_url") if isinstance(page, dict) else page.canonical_url
            title = page.get("title", "") if isinstance(page, dict) else page.title
            fetched_at = page.get("fetched_at", "") if isinstance(page, dict) else page.fetched_at
            content_hash = page.get("content_hash", "") if isinstance(page, dict) else page.content_hash
            domain = (urlsplit(canonical_url).hostname or "")[:255]
            conn.execute("""
                INSERT INTO web_sources
                (source_id, session_id, url, title, domain, fetched_at, content_hash, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f"{session_id}:{source_id}", session_id, canonical_url[:4096],
                title[:500], domain, fetched_at, content_hash, status[:40],
            ))
        return source_id

    def list_sources(self, session_id: str):
        with self._connect() as conn:
            rows = [dict(row) for row in conn.execute(
                "SELECT source_id, session_id, url, title, domain, fetched_at, content_hash, status "
                "FROM web_sources WHERE session_id=? ORDER BY rowid",
                (session_id,),
            ).fetchall()]
        for row in rows:
            row["source_id"] = row["source_id"].split(":", 1)[-1]
        return rows
