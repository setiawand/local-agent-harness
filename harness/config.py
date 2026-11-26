from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from harness.docker_sandbox import DEFAULT_IMAGE


@dataclass(frozen=True)
class WebConfig:
    enabled: bool = False
    provider: str = "searxng"
    base_url: str = "http://127.0.0.1:8888"
    search_timeout_seconds: int = 8
    default_language: str = "auto"
    safe_search: int = 1
    max_results: int = 5
    max_query_length: int = 500
    search_cache_ttl_seconds: int = 300
    fetch_enabled: bool = True
    fetch_timeout_seconds: int = 10
    max_redirects: int = 3
    max_response_bytes: int = 2_097_152
    max_content_chars: int = 12_000
    max_concurrent: int = 2
    fetch_cache_ttl_seconds: int = 3600
    allow_http: bool = True
    allow_https: bool = True
    block_private_ips: bool = True
    block_localhost: bool = True
    validate_redirects: bool = True
    reject_ip_literals: bool = True
    audit_enabled: bool = True
    store_page_content: bool = False
    store_source_metadata: bool = True


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
    web: WebConfig = field(default_factory=WebConfig)


_ALLOWED = {
    "endpoint", "docker_image", "sandbox_timeout", "docker_memory",
    "docker_cpus", "docker_pids_limit", "max_output_bytes",
    "max_snapshot_files", "max_snapshot_bytes", "max_snapshot_file_bytes",
}
_WEB_ALLOWED = set(WebConfig.__dataclass_fields__)
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


def _flatten_web(raw: dict[str, Any]) -> dict[str, Any]:
    allowed_sections = {"searxng", "search", "fetch", "security", "audit"}
    unknown_sections = set(raw) - ({"enabled", "provider"} | allowed_sections)
    if unknown_sections:
        raise ValueError("Unknown [web] section(s): " + ", ".join(sorted(unknown_sections)))
    result = {"enabled": raw.get("enabled", False), "provider": raw.get("provider", "searxng")}
    mapping = {
        "searxng": {"base_url": "base_url", "timeout_seconds": "search_timeout_seconds",
                    "default_language": "default_language", "safe_search": "safe_search"},
        "search": {"max_results": "max_results", "max_query_length": "max_query_length",
                   "cache_ttl_seconds": "search_cache_ttl_seconds"},
        "fetch": {"enabled": "fetch_enabled", "timeout_seconds": "fetch_timeout_seconds",
                  "max_redirects": "max_redirects", "max_response_bytes": "max_response_bytes",
                  "max_content_chars": "max_content_chars", "max_concurrent": "max_concurrent",
                  "cache_ttl_seconds": "fetch_cache_ttl_seconds"},
        "security": {"allow_http": "allow_http", "allow_https": "allow_https",
                     "block_private_ips": "block_private_ips", "block_localhost": "block_localhost",
                     "validate_redirects": "validate_redirects", "reject_ip_literals": "reject_ip_literals"},
        "audit": {"enabled": "audit_enabled", "store_page_content": "store_page_content",
                  "store_source_metadata": "store_source_metadata"},
    }
    for section, keys in mapping.items():
        values = raw.get(section, {})
        if not isinstance(values, dict):
            raise ValueError(f"[web.{section}] must be a table.")
        unknown = set(values) - set(keys)
        if unknown:
            raise ValueError(f"Unknown [web.{section}] key(s): " + ", ".join(sorted(unknown)))
        for source, target in keys.items():
            if source in values:
                result[target] = values[source]
    return result


def load_config(config_path: str | Path | None = None) -> HarnessConfig:
    path = Path(config_path).expanduser() if config_path else default_config_path()
    values: dict[str, Any] = {}
    web_values: dict[str, Any] = {}
    if path.exists():
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ValueError(f"Cannot read configuration {path}: {exc}") from exc
        if "harness" in raw:
            section = raw["harness"]
            if not isinstance(section, dict):
                raise ValueError("[harness] must be a table.")
            unknown = set(section) - _ALLOWED
            if unknown:
                raise ValueError("Unknown configuration key(s): " + ", ".join(sorted(unknown)))
            values.update(section)
            if "web" in raw:
                if not isinstance(raw["web"], dict):
                    raise ValueError("[web] must be a table.")
                web_values.update(_flatten_web(raw["web"]))
            unknown_top = set(raw) - {"harness", "web"}
            if unknown_top:
                raise ValueError("Unknown top-level configuration table(s): " + ", ".join(sorted(unknown_top)))
        else:
            unknown = set(raw) - _ALLOWED
            if unknown:
                raise ValueError("Unknown configuration key(s): " + ", ".join(sorted(unknown)))
            values.update(raw)
    elif config_path is not None:
        raise FileNotFoundError(f"Configuration file not found: {path}")

    for key, env_name in _ENV.items():
        if env_name in os.environ:
            values[key] = os.environ[env_name]

    integer_fields = {
        "sandbox_timeout", "docker_pids_limit", "max_output_bytes",
        "max_snapshot_files", "max_snapshot_bytes", "max_snapshot_file_bytes",
    }
    converted = {}
    for key, value in values.items():
        try:
            converted[key] = int(value) if key in integer_fields else str(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid value for configuration key '{key}': {value!r}") from exc

    defaults = HarnessConfig()
    config = HarnessConfig(**{
        field: converted.get(field, getattr(defaults, field))
        for field in _ALLOWED
    })
    web_defaults = WebConfig()
    web_ints = {
        "search_timeout_seconds", "safe_search", "max_results", "max_query_length",
        "search_cache_ttl_seconds", "fetch_timeout_seconds", "max_redirects",
        "max_response_bytes", "max_content_chars", "max_concurrent",
        "fetch_cache_ttl_seconds",
    }
    web_bools = {
        "enabled", "fetch_enabled", "allow_http", "allow_https",
        "block_private_ips", "block_localhost", "validate_redirects",
        "reject_ip_literals", "audit_enabled", "store_page_content",
        "store_source_metadata",
    }
    web_converted = {}
    for key, value in web_values.items():
        if key not in _WEB_ALLOWED:
            raise ValueError(f"Unknown web configuration key: {key}")
        try:
            if key in web_ints:
                web_converted[key] = int(value)
            elif key in web_bools:
                if not isinstance(value, bool):
                    raise ValueError("must be true or false")
                web_converted[key] = value
            else:
                web_converted[key] = str(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid web configuration '{key}': {value!r}") from exc
    web = WebConfig(**{
        field: web_converted.get(field, getattr(web_defaults, field))
        for field in _WEB_ALLOWED
    })
    config = HarnessConfig(**{
        **{field: getattr(config, field) for field in _ALLOWED},
        "web": web,
    })

    if not config.endpoint.startswith(("http://", "https://")):
        raise ValueError("endpoint must start with http:// or https://")
    if not 1 <= config.sandbox_timeout <= 3600:
        raise ValueError("sandbox_timeout must be between 1 and 3600 seconds")
    if not 16 <= config.docker_pids_limit <= 4096:
        raise ValueError("docker_pids_limit must be between 16 and 4096")
    if not 4096 <= config.max_output_bytes <= 50_000_000:
        raise ValueError("max_output_bytes must be between 4096 and 50000000")
    if min(config.max_snapshot_files, config.max_snapshot_bytes, config.max_snapshot_file_bytes) <= 0:
        raise ValueError("Snapshot limits must be positive")
    if not config.docker_image.strip():
        raise ValueError("docker_image must not be empty")
    if not re.fullmatch(r"[1-9][0-9]*(?:[bkmg])?", config.docker_memory.lower()):
        raise ValueError("docker_memory must be a positive Docker memory quantity, e.g. 512m")
    try:
        cpu_value = float(config.docker_cpus)
    except ValueError as exc:
        raise ValueError("docker_cpus must be a positive number") from exc
    if not 0 < cpu_value <= 64:
        raise ValueError("docker_cpus must be greater than 0 and at most 64")

    if web.provider != "searxng":
        raise ValueError("Only provider='searxng' is supported.")
    parsed = urlsplit(web.base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("web.searxng.base_url must use a loopback host.")
    try:
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("web.searxng.base_url port must be between 1 and 65535.")
    except ValueError as exc:
        raise ValueError(f"Invalid web.searxng.base_url: {exc}") from exc
    if len(web.default_language) > 32 or any(ord(ch) < 32 for ch in web.default_language):
        raise ValueError("web.searxng.default_language must be at most 32 printable characters.")
    if not 0 <= web.search_cache_ttl_seconds <= 86400:
        raise ValueError("web.search.cache_ttl_seconds must be between 0 and 86400.")
    if not 0 <= web.fetch_cache_ttl_seconds <= 604800:
        raise ValueError("web.fetch.cache_ttl_seconds must be between 0 and 604800.")
    if web.safe_search not in {0, 1, 2}:
        raise ValueError("web.searxng.safe_search must be 0, 1, or 2.")
    if not 1 <= web.max_results <= 10 or not 1 <= web.max_query_length <= 500:
        raise ValueError("Web search limits are outside allowed bounds.")
    if not 1 <= web.search_timeout_seconds <= 60 or not 1 <= web.fetch_timeout_seconds <= 60:
        raise ValueError("Web timeouts must be between 1 and 60 seconds.")
    if not 0 <= web.max_redirects <= 3 or not 1024 <= web.max_response_bytes <= 10_485_760:
        raise ValueError("Web redirect or response size limit is outside allowed bounds.")
    if not 256 <= web.max_content_chars <= 100_000 or not 1 <= web.max_concurrent <= 2:
        raise ValueError("Web content or concurrency limit is outside allowed bounds.")
    if web.enabled and not web.store_source_metadata:
        raise ValueError("Web source metadata must remain enabled so fetched pages can be cited.")
    if web.enabled and not web.audit_enabled:
        raise ValueError("Web audit logging cannot be disabled in this release.")
    if web.store_page_content:
        raise ValueError("Storing fetched page content is not supported; keep store_page_content=false.")
    if web.enabled and not (web.allow_http or web.allow_https):
        raise ValueError("At least one of web.security.allow_http / allow_https must be enabled.")
    if web.enabled and (not web.block_private_ips or not web.block_localhost or not web.validate_redirects or not web.reject_ip_literals):
        raise ValueError("Web SSRF protections cannot be disabled in this release.")
    return config
