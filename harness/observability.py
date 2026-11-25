from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        event = getattr(record, "event_data", None)
        if isinstance(event, dict):
            payload["event"] = event
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(project_root: Path) -> logging.Logger:
    key_dir = Path.home() / "Library" / "Application Support" / "LocalAgentHarness"
    # Project-specific logs are outside the repository and never enter Docker snapshots.
    import hashlib
    project_key = hashlib.sha256(
        str(project_root.resolve()).encode("utf-8")
    ).hexdigest()[:16]
    log_dir = key_dir / project_key / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("local_agent_harness")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = RotatingFileHandler(
            log_dir / "harness.jsonl",
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    return logger
