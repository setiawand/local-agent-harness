from __future__ import annotations

import shutil
import socket
import subprocess
import sys
from urllib.parse import urlparse
from pathlib import Path

from harness.config import HarnessConfig


def doctor(config: HarnessConfig, project_root: Path) -> tuple[bool, list[tuple[str, str, str]]]:
    """Return (required_checks_ok, [(name, status, detail), ...])."""
    checks: list[tuple[str, str, str]] = []
    required_ok = True

    def add(name: str, status: str, detail: str, required: bool = True):
        nonlocal required_ok
        checks.append((name, status, detail))
        if required and status != "PASS":
            required_ok = False

    add(
        "Python",
        "PASS" if sys.version_info >= (3, 12, 8) else "FAIL",
        sys.version.split()[0],
    )

    docker = shutil.which("docker")
    if not docker:
        add("Docker CLI", "FAIL", "docker executable not found")
        return required_ok, checks
    add("Docker CLI", "PASS", docker)

    try:
        result = subprocess.run(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0:
            add("Docker daemon", "PASS", result.stdout.strip() or "available")
        else:
            add("Docker daemon", "FAIL", result.stderr.strip()[-500:] or "not available")
            return required_ok, checks
    except (OSError, subprocess.TimeoutExpired) as exc:
        add("Docker daemon", "FAIL", str(exc))
        return required_ok, checks

    try:
        result = subprocess.run(
            [docker, "image", "inspect", config.docker_image, "--format", "{{.Id}}"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0:
            add("Sandbox image", "PASS", result.stdout.strip())
        else:
            add("Sandbox image", "FAIL", "Image not present locally; pull the configured image before use")
    except (OSError, subprocess.TimeoutExpired) as exc:
        add("Sandbox image", "FAIL", str(exc))

    if config.web.enabled:
        web_parsed = urlparse(config.web.base_url)
        try:
            with socket.create_connection(
                (web_parsed.hostname, web_parsed.port or (443 if web_parsed.scheme == "https" else 80)),
                timeout=2,
            ):
                add("SearXNG", "PASS", config.web.base_url, required=False)
        except OSError as exc:
            add("SearXNG", "WARN", f"{config.web.base_url} not reachable ({exc})", required=False)

    parsed = urlparse(config.endpoint)
    try:
        with socket.create_connection((parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)), timeout=2):
            add("Inference endpoint", "PASS", config.endpoint, required=False)
    except OSError as exc:
        add("Inference endpoint", "WARN", f"{config.endpoint} not reachable ({exc})", required=False)

    try:
        project_root = project_root.resolve(strict=True)
        if not project_root.is_dir():
            raise NotADirectoryError(project_root)
        add("Project root", "PASS", str(project_root))
    except OSError as exc:
        add("Project root", "FAIL", str(exc))

    return required_ok, checks
