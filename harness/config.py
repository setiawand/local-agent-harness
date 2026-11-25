from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.docker_sandbox import DEFAULT_IMAGE


@dataclass(frozen=True)
class HarnessConfig:
    endpoint: str = "http://127.0.0.1:8001"
    docker_image: str = DEFAULT_IMAGE
    sandbox_timeout: int = 60
    docker_memory: str = "512m"
    docker_cpus: str = "1"
    docker_pids_limit: int = 64
    max_output_bytes: int = 1_048_576
    max_snapshot_files: int = 10_000
    max_snapshot_bytes: int = 524_288_000
    max_snapshot_file_bytes: int = 26_214_400


_ALLOWED = {
    "endpoint", "docker_image", "sandbox_timeout", "docker_memory",
    "docker_cpus", "docker_pids_limit", "max_output_bytes",
    "max_snapshot_files", "max_snapshot_bytes", "max_snapshot_file_bytes",
}
_ENV = {
    "endpoint": "LAH_ENDPOINT",
    "docker_image": "LAH_DOCKER_IMAGE",
    "sandbox_timeout": "LAH_SANDBOX_TIMEOUT",
    "docker_memory": "LAH_DOCKER_MEMORY",
    "docker_cpus": "LAH_DOCKER_CPUS",
    "docker_pids_limit": "LAH_DOCKER_PIDS_LIMIT",
    "max_output_bytes": "LAH_MAX_OUTPUT_BYTES",
    "max_snapshot_files": "LAH_MAX_SNAPSHOT_FILES",
    "max_snapshot_bytes": "LAH_MAX_SNAPSHOT_BYTES",
    "max_snapshot_file_bytes": "LAH_MAX_SNAPSHOT_FILE_BYTES",
}


def default_config_path() -> Path:
    return Path.home() / ".config" / "local-agent-harness" / "config.toml"


def load_config(config_path: str | Path | None = None) -> HarnessConfig:
    path = Path(config_path).expanduser() if config_path else default_config_path()
    values: dict[str, Any] = {}
    if path.exists():
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ValueError(f"Cannot read configuration {path}: {exc}") from exc
        section = raw.get("harness", raw)
        if not isinstance(section, dict):
            raise ValueError("Configuration must contain a [harness] table or root keys.")
        unknown = set(section) - _ALLOWED
        if unknown:
            raise ValueError("Unknown configuration key(s): " + ", ".join(sorted(unknown)))
        values.update(section)
    elif config_path is not None:
        raise FileNotFoundError(f"Configuration file not found: {path}")

    for key, env_name in _ENV.items():
        if env_name in os.environ:
            values[key] = os.environ[env_name]

    defaults = HarnessConfig()
    converted: dict[str, Any] = {}
    integer_fields = {
        "sandbox_timeout", "docker_pids_limit", "max_output_bytes",
        "max_snapshot_files", "max_snapshot_bytes", "max_snapshot_file_bytes",
    }
    for key, value in values.items():
        try:
            converted[key] = int(value) if key in integer_fields else str(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid value for configuration key '{key}': {value!r}") from exc

    config = HarnessConfig(**{
        field: converted.get(field, getattr(defaults, field))
        for field in _ALLOWED
    })
    if not config.endpoint.startswith(("http://", "https://")):
        raise ValueError("endpoint must start with http:// or https://")
    if config.sandbox_timeout < 1 or config.sandbox_timeout > 3600:
        raise ValueError("sandbox_timeout must be between 1 and 3600 seconds")
    if config.docker_pids_limit < 16 or config.docker_pids_limit > 4096:
        raise ValueError("docker_pids_limit must be between 16 and 4096")
    if config.max_output_bytes < 4096 or config.max_output_bytes > 50_000_000:
        raise ValueError("max_output_bytes must be between 4096 and 50000000")
    if min(config.max_snapshot_files, config.max_snapshot_bytes,
           config.max_snapshot_file_bytes) <= 0:
        raise ValueError("Snapshot limits must be positive")
    if not config.docker_image.strip():
        raise ValueError("docker_image must not be empty")
    if not re.fullmatch(r"[1-9][0-9]*(?:[bkmg])?", config.docker_memory.lower()):
        raise ValueError("docker_memory must be a positive Docker memory quantity, e.g. 512m")
    try:
        cpu_value = float(config.docker_cpus)
    except ValueError as exc:
        raise ValueError("docker_cpus must be a positive number") from exc
    if not (0 < cpu_value <= 64):
        raise ValueError("docker_cpus must be greater than 0 and at most 64")
    return config
