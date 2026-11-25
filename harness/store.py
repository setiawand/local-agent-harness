from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


class Store:
    """SQLite storage for sessions, memories, tool journal, and security audit."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    project_path TEXT NOT NULL,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(session_id, ordinal),
                    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_path TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tags TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tool_runs (
                    tool_call_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    tool_args TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result TEXT,
                    error TEXT,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    tool_call_id TEXT,
                    tool_name TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, ordinal);
                CREATE INDEX IF NOT EXISTS idx_memories_project ON memories(project_path, created_at);
                CREATE INDEX IF NOT EXISTS idx_tool_runs_session ON tool_runs(session_id, started_at);
                CREATE INDEX IF NOT EXISTS idx_security_events_session ON security_events(session_id, created_at);
            """)

    def backup_to(self, destination: Path) -> Path:
        """Create a consistent SQLite backup, including committed WAL content."""
        target = Path(destination).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.resolve() == self.db_path.resolve():
            raise ValueError("Backup destination must differ from the active database.")
        temporary = target.with_name(target.name + ".tmp")
        if temporary.exists():
            temporary.unlink()
        source = self._connect()
        backup = sqlite3.connect(temporary)
        try:
            source.backup(backup)
            result = backup.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise RuntimeError(f"Backup integrity check failed: {result}")
        finally:
            backup.close()
            source.close()
        os.replace(temporary, target)
        return target

    def restore_from(self, source_path: Path) -> Path:
        """Restore from a verified backup after preserving the current database."""
        source_path = Path(source_path).expanduser().resolve(strict=True)
        if source_path == self.db_path.resolve():
            raise ValueError("Cannot restore the active database from itself.")
        temporary = self.db_path.with_name(self.db_path.name + ".restore.tmp")
        if temporary.exists():
            temporary.unlink()
        source = sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)
        destination = sqlite3.connect(temporary)
        try:
            check = source.execute("PRAGMA integrity_check").fetchone()[0]
            if check != "ok":
                raise RuntimeError(f"Backup integrity check failed: {check}")
            tables = {
                row[0] for row in source.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            required = {"sessions", "messages", "memories", "tool_runs", "security_events"}
            if not required.issubset(tables):
                raise RuntimeError("Backup is missing required Local Agent Harness tables.")
            source.backup(destination)
            restored_check = destination.execute("PRAGMA integrity_check").fetchone()[0]
            if restored_check != "ok":
                raise RuntimeError(f"Restored database integrity check failed: {restored_check}")
        finally:
            destination.close()
            source.close()

        # Preserve the current DB before replacement; WAL must be checkpointed.
        current = self._connect()
        try:
            current.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            current.close()
        backup_path = self.db_path.with_name(
            self.db_path.name + ".pre-restore-" + uuid.uuid4().hex[:8]
        )
        if self.db_path.exists():
            os.replace(self.db_path, backup_path)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(self.db_path) + suffix)
            if sidecar.exists():
                sidecar.unlink()
        os.replace(temporary, self.db_path)
        return backup_path

    # Sessions
    def create_session(self, project_path: str, title: str = "New session") -> str:
        session_id = uuid.uuid4().hex[:12]
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO sessions(id, project_path, title, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (session_id, project_path, title, now, now),
            )
        return session_id

    def get_session(self, session_id: str):
        with self._connect() as conn:
            return conn.execute(
                """SELECT id, project_path, title, created_at, updated_at
                   FROM sessions WHERE id=?""",
                (session_id,),
            ).fetchone()

    def list_sessions(self, project_path: str, limit: int = 10):
        with self._connect() as conn:
            return conn.execute(
                """SELECT id, title, created_at, updated_at FROM sessions
                   WHERE project_path=? ORDER BY updated_at DESC LIMIT ?""",
                (project_path, limit),
            ).fetchall()

    # Messages
    def save_messages(self, session_id: str, messages: list[dict[str, Any]]):
        payloads = []
        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                raise TypeError(f"Message at index {index} must be a dictionary")
            payloads.append(_json_dump(message))
        now = utc_now()
        with self._connect() as conn:
            if not conn.execute("SELECT 1 FROM sessions WHERE id=?", (session_id,)).fetchone():
                raise ValueError(f"Session not found: {session_id}")
            conn.execute("DELETE FROM messages WHERE session_id=?", (session_id,))
            conn.executemany(
                """INSERT INTO messages(session_id, ordinal, payload, created_at)
                   VALUES (?, ?, ?, ?)""",
                [(session_id, i, payload, now) for i, payload in enumerate(payloads)],
            )
            conn.execute("UPDATE sessions SET updated_at=? WHERE id=?", (now, session_id))

    def load_messages(self, session_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ordinal, payload FROM messages WHERE session_id=? ORDER BY ordinal",
                (session_id,),
            ).fetchall()
        result = []
        for row in rows:
            try:
                message = json.loads(row["payload"])
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Corrupt JSON in session {session_id}, message ordinal {row['ordinal']}"
                ) from exc
            if not isinstance(message, dict):
                raise RuntimeError(
                    f"Invalid message structure in session {session_id}, message ordinal {row['ordinal']}"
                )
            result.append(message)
        return result

    # Tool journal
    def start_tool_run(self, session_id: str, call: dict[str, Any]):
        call_id, name, args = call.get("id"), call.get("name"), call.get("arguments")
        if not call_id or not name or not isinstance(args, dict):
            raise ValueError(f"Invalid tool call for journal: {call!r}")
        now = utc_now()
        with self._connect() as conn:
            # Tool-call IDs are immutable journal identities. Reusing one must
            # fail closed rather than resetting a completed/failed operation.
            conn.execute(
                """INSERT INTO tool_runs
                   (tool_call_id, session_id, tool_name, tool_args, status, result,
                    error, started_at, updated_at)
                   VALUES (?, ?, ?, ?, 'running', NULL, NULL, ?, ?)""",
                (call_id, session_id, name, _json_dump(args), now, now),
            )

    def complete_tool_run(self, session_id: str, call_id: str, result: dict[str, Any]):
        with self._connect() as conn:
            cursor = conn.execute(
                """UPDATE tool_runs SET status='completed', result=?, error=NULL, updated_at=?
                   WHERE session_id=? AND tool_call_id=? AND status='running'""",
                (_json_dump(result), utc_now(), session_id, call_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError(f"Tool journal entry not found: {call_id}")

    def fail_tool_run(self, session_id: str, call_id: str, error: str):
        with self._connect() as conn:
            cursor = conn.execute(
                """UPDATE tool_runs SET status='failed', error=?, updated_at=?
                   WHERE session_id=? AND tool_call_id=? AND status='running'""",
                (error[:4000], utc_now(), session_id, call_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError(f"Tool journal entry is not running: {call_id}")

    def deny_tool_run(self, session_id: str, call: dict[str, Any], reason: str):
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO tool_runs
                   (tool_call_id, session_id, tool_name, tool_args, status,
                    result, error, started_at, updated_at)
                   VALUES (?, ?, ?, ?, 'denied', NULL, ?, ?, ?)""",
                (call["id"], session_id, call["name"], _json_dump(call.get("arguments", {})),
                 reason[:4000], now, now),
            )

    def list_tool_runs(self, session_id: str):
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT tool_call_id, tool_name, tool_args, status, result, error,
                          started_at, updated_at
                   FROM tool_runs WHERE session_id=? ORDER BY started_at""",
                (session_id,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["tool_args"] = json.loads(item["tool_args"])
            item["result"] = json.loads(item["result"]) if item["result"] else None
            result.append(item)
        return result

    def mark_tool_interrupted(self, session_id: str, call_id: str):
        with self._connect() as conn:
            conn.execute(
                """UPDATE tool_runs SET status='interrupted', updated_at=?
                   WHERE session_id=? AND tool_call_id=? AND status='running'""",
                (utc_now(), session_id, call_id),
            )

    # Security audit
    def record_security_event(
        self, session_id: str, tool_call_id: str | None, tool_name: str,
        action: str, target: str, decision: str, reason: str,
    ):
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO security_events
                   (session_id, tool_call_id, tool_name, action, target,
                    decision, reason, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, tool_call_id, tool_name, action, target[:2000],
                 decision, reason[:2000], utc_now()),
            )

    def list_security_events(self, session_id: str, limit: int = 30):
        with self._connect() as conn:
            return conn.execute(
                """SELECT id, tool_call_id, tool_name, action, target,
                          decision, reason, created_at
                   FROM security_events WHERE session_id=?
                   ORDER BY id DESC LIMIT ?""",
                (session_id, limit),
            ).fetchall()

    # Memories
    def add_memory(self, project_path: str, content: str, tags: str = ""):
        content = content.strip()
        if not content:
            raise ValueError("Memory content cannot be empty")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO memories(project_path, content, tags, created_at)
                   VALUES (?, ?, ?, ?)""",
                (project_path, content, tags.strip(), utc_now()),
            )

    def list_memories(self, project_path: str, limit: int = 30):
        with self._connect() as conn:
            return conn.execute(
                """SELECT id, content, tags, created_at FROM memories
                   WHERE project_path=? ORDER BY id DESC LIMIT ?""",
                (project_path, limit),
            ).fetchall()

    def search_memories(self, project_path: str, query: str, limit: int = 8):
        terms = [term for term in query.lower().split() if len(term) > 2]
        if not terms:
            return []
        where = " OR ".join(["lower(content) LIKE ?" for _ in terms])
        params = [project_path] + [f"%{term}%" for term in terms] + [limit]
        with self._connect() as conn:
            return conn.execute(
                f"""SELECT id, content, tags FROM memories
                    WHERE project_path=? AND ({where})
                    ORDER BY id DESC LIMIT ?""",
                params,
            ).fetchall()
