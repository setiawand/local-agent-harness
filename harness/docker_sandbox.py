from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import stat
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any


DEFAULT_IMAGE = (
    "python@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b"
)

SENSITIVE_NAMES = {
    ".env", ".netrc", ".npmrc", ".pypirc", ".git-credentials",
    "id_rsa", "id_ed25519", "id_ecdsa", "known_hosts", "credentials",
    "secrets.json", "secrets.yaml", "secrets.yml",
}
SENSITIVE_DIRS = {
    ".git", ".ssh", ".aws", ".gnupg", ".azure", ".kube",
    "private", "credentials",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"}
IGNORED_BUILD_DIRS = {
    ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".next", ".cache",
}


class DockerSandboxError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sensitive_relative(relative: PurePosixPath) -> bool:
    for part in relative.parts:
        lower = part.lower()
        if lower in SENSITIVE_NAMES or lower in SENSITIVE_DIRS:
            return True
        if lower.startswith(".env."):
            return True
        if any(lower.endswith(suffix) for suffix in SENSITIVE_SUFFIXES):
            return True
    return False


class DockerSandbox:
    """Run Bash in a restricted Docker container using a secret-filtered snapshot.

    The container never receives the live project directory. It receives a temporary
    copy with sensitive paths, symlinks, VCS metadata, and local build environments
    omitted. Regular-file changes are copied back conservatively after execution.
    """

    def __init__(
        self,
        project_root: Path,
        *,
        image: str = DEFAULT_IMAGE,
        max_timeout: int = 60,
        memory: str = "512m",
        cpus: str = "1",
        pids_limit: int = 64,
        max_files: int = 10000,
        max_total_bytes: int = 500 * 1024 * 1024,
        max_file_bytes: int = 25 * 1024 * 1024,
        max_output_bytes: int = 1 * 1024 * 1024,
    ):
        self.root = Path(project_root).expanduser().resolve(strict=True)
        if not self.root.is_dir():
            raise DockerSandboxError(f"Project root is not a directory: {self.root}")
        self.image = image
        self.max_timeout = max_timeout
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_file_bytes = max_file_bytes
        self.max_output_bytes = max(4096, int(max_output_bytes))
        if shutil.which("docker") is None:
            raise DockerSandboxError("Docker CLI was not found in PATH.")

    def _copy_snapshot(self, destination: Path) -> dict[str, str]:
        baseline: dict[str, str] = {}
        total_bytes = 0
        file_count = 0

        for current, dirnames, filenames in os.walk(self.root, topdown=True, followlinks=False):
            current_path = Path(current)
            relative_dir = current_path.relative_to(self.root)
            kept_dirs = []
            for dirname in dirnames:
                child = current_path / dirname
                relative = PurePosixPath((relative_dir / dirname).as_posix())
                if dirname.lower() in SENSITIVE_DIRS or dirname.lower() in IGNORED_BUILD_DIRS:
                    continue
                if child.is_symlink():
                    continue
                kept_dirs.append(dirname)
            dirnames[:] = kept_dirs

            target_dir = destination / relative_dir
            target_dir.mkdir(parents=True, exist_ok=True)

            for filename in filenames:
                source = current_path / filename
                relative_path = relative_dir / filename
                relative_posix = PurePosixPath(relative_path.as_posix())
                if _sensitive_relative(relative_posix) or source.is_symlink():
                    continue
                try:
                    info = source.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_size > self.max_file_bytes:
                    continue
                file_count += 1
                total_bytes += info.st_size
                if file_count > self.max_files:
                    raise DockerSandboxError(
                        f"Workspace snapshot exceeds file limit ({self.max_files})."
                    )
                if total_bytes > self.max_total_bytes:
                    raise DockerSandboxError(
                        f"Workspace snapshot exceeds size limit ({self.max_total_bytes} bytes)."
                    )
                target = destination / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target, follow_symlinks=False)
                baseline[relative_posix.as_posix()] = _sha256(target)

        return baseline

    def _sync_snapshot(self, snapshot: Path, baseline: dict[str, str]) -> tuple[int, int, int]:
        updated = 0
        conflicts = 0
        skipped = 0
        snapshot_files: set[str] = set()
        file_count = 0
        total_bytes = 0

        for current, dirnames, filenames in os.walk(snapshot, topdown=True, followlinks=False):
            current_path = Path(current)
            relative_dir = current_path.relative_to(snapshot)
            dirnames[:] = [
                name for name in dirnames
                if not (current_path / name).is_symlink()
                and name.lower() not in SENSITIVE_DIRS
                and name.lower() not in IGNORED_BUILD_DIRS
            ]
            for filename in filenames:
                source = current_path / filename
                relative = PurePosixPath((relative_dir / filename).as_posix())
                key = relative.as_posix()
                snapshot_files.add(key)
                if _sensitive_relative(relative) or source.is_symlink():
                    skipped += 1
                    continue
                try:
                    info = source.stat(follow_symlinks=False)
                except OSError:
                    skipped += 1
                    continue
                if not stat.S_ISREG(info.st_mode):
                    skipped += 1
                    continue
                file_count += 1
                total_bytes += info.st_size
                if (
                    file_count > self.max_files
                    or info.st_size > self.max_file_bytes
                    or total_bytes > self.max_total_bytes
                ):
                    skipped += 1
                    continue

                new_hash = _sha256(source)
                old_hash = baseline.get(key)
                if old_hash == new_hash:
                    continue

                destination = self.root / Path(*relative.parts)
                if not self._safe_destination(destination):
                    skipped += 1
                    continue

                if destination.exists():
                    if not destination.is_file() or destination.is_symlink():
                        conflicts += 1
                        continue
                    current_hash = _sha256(destination)
                    if old_hash is None or current_hash != old_hash:
                        conflicts += 1
                        continue
                elif old_hash is not None:
                    # The original file was removed or moved while the sandbox ran.
                    conflicts += 1
                    continue

                destination.parent.mkdir(parents=True, exist_ok=True)
                if not self._safe_destination(destination):
                    skipped += 1
                    continue
                temp_path = destination.with_name(
                    f".{destination.name}.lah-{uuid.uuid4().hex}.tmp"
                )
                try:
                    shutil.copyfile(source, temp_path)
                    os.chmod(temp_path, stat.S_IMODE(info.st_mode) & 0o777)
                    os.replace(temp_path, destination)
                    updated += 1
                finally:
                    if temp_path.exists():
                        temp_path.unlink()

        # Deletions in the container are intentionally not propagated to the host.
        return updated, conflicts, skipped

    def _safe_destination(self, destination: Path) -> bool:
        try:
            relative = destination.relative_to(self.root)
        except ValueError:
            return False
        if _sensitive_relative(PurePosixPath(relative.as_posix())):
            return False
        if any(part.lower() in IGNORED_BUILD_DIRS for part in relative.parts):
            return False
        cursor = self.root
        for part in relative.parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                return False
            if cursor.exists() and not cursor.is_dir():
                return False
        if destination.is_symlink():
            return False
        return True

    async def _read_output_limited(self, stream) -> tuple[bytes, bool]:
        """Drain stdout completely while retaining at most max_output_bytes."""
        chunks: list[bytes] = []
        retained = 0
        truncated = False
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            remaining = self.max_output_bytes - retained
            if remaining > 0:
                kept = chunk[:remaining]
                chunks.append(kept)
                retained += len(kept)
            if len(chunk) > max(0, remaining):
                truncated = True
        return b"".join(chunks), truncated

    async def _remove_container(self, name: str) -> None:
        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", name,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(process.wait(), timeout=5)
        except (OSError, asyncio.TimeoutError):
            pass

    async def execute(
        self,
        command: str,
        *,
        timeout: float | int | None = None,
        signal: Any = None,
    ) -> dict[str, Any]:
        if not isinstance(command, str) or not command.strip():
            raise DockerSandboxError("Empty command is not allowed.")
        requested_timeout = self.max_timeout if timeout is None else float(timeout)
        effective_timeout = max(1.0, min(requested_timeout, float(self.max_timeout)))
        container_name = f"lah-sandbox-{uuid.uuid4().hex[:16]}"

        with tempfile.TemporaryDirectory(prefix="lah-sandbox-") as temp_dir:
            snapshot = Path(temp_dir) / "workspace"
            snapshot.mkdir(mode=0o700)
            baseline = self._copy_snapshot(snapshot)
            if "," in str(snapshot):
                raise DockerSandboxError("Temporary workspace path contains an unsupported comma.")

            uid = os.getuid() if hasattr(os, "getuid") else 1000
            gid = os.getgid() if hasattr(os, "getgid") else 1000
            argv = [
                "docker", "run", "--rm", "--init", "--name", container_name,
                "--label", "app=local-agent-harness",
                "--network", "none",
                "--read-only",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", str(self.pids_limit),
                "--memory", self.memory,
                "--memory-swap", self.memory,
                "--cpus", self.cpus,
                "--ulimit", "nofile=256:256",
                "--ulimit", "core=0:0",
                "--ulimit", "fsize=52428800:52428800",
                "--user", f"{uid}:{gid}",
                "--env", "HOME=/tmp",
                "--env", "TMPDIR=/tmp",
                "--env", "PYTHONDONTWRITEBYTECODE=1",
                "--mount", f"type=bind,src={snapshot},dst=/workspace",
                "--workdir", "/workspace",
                "--entrypoint", "/bin/sh",
                self.image,
                "-c", command,
            ]

            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            output_task = asyncio.create_task(self._read_output_limited(process.stdout))
            signal_task = None
            if signal is not None and hasattr(signal, "wait"):
                signal_task = asyncio.create_task(signal.wait())

            timed_out = False
            aborted = False
            output = b""
            output_truncated = False
            return_code: int | None = None
            try:
                wait_set = {output_task}
                if signal_task is not None:
                    wait_set.add(signal_task)
                done, _ = await asyncio.wait(
                    wait_set,
                    timeout=effective_timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if output_task in done:
                    output, output_truncated = output_task.result()
                    return_code = await process.wait()
                else:
                    timed_out = signal_task not in done if signal_task else True
                    aborted = signal_task in done if signal_task else False
                    await self._remove_container(container_name)
                    if process.returncode is None:
                        process.kill()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        pass
                    try:
                        output, output_truncated = await asyncio.wait_for(output_task, timeout=5)
                    except asyncio.TimeoutError:
                        output_task.cancel()
                        try:
                            await output_task
                        except asyncio.CancelledError:
                            pass
            except BaseException:
                await self._remove_container(container_name)
                if process.returncode is None:
                    process.kill()
                try:
                    await process.wait()
                except Exception:
                    pass
                if not output_task.done():
                    output_task.cancel()
                    try:
                        await output_task
                    except asyncio.CancelledError:
                        pass
                raise
            finally:
                if signal_task is not None and not signal_task.done():
                    signal_task.cancel()
                    try:
                        await signal_task
                    except asyncio.CancelledError:
                        pass

            updated, conflicts, skipped = self._sync_snapshot(snapshot, baseline)
            sync_note = (
                f"\n[workspace sync: {updated} file(s) updated, "
                f"{conflicts} conflict(s), {skipped} skipped; deletions are not propagated]"
            )
            text = output.decode(errors="replace")
            if output_truncated:
                text += f"\\n[output truncated; retained at most {self.max_output_bytes} bytes]"
            if timed_out:
                raise ValueError(
                    f"Command timed out after {effective_timeout:g}s.\n{text}{sync_note}"
                )
            if aborted:
                raise ValueError(f"Command aborted.\n{text}{sync_note}")

            code = int(return_code or 0)
            if code != 0:
                text += f"\n[exit code {code}]"
            text += sync_note
            if len(text) > 30000:
                text = text[:12000] + "\n...[output truncated]...\n" + text[-16000:]
            return {
                "content": [{"type": "text", "text": text}],
                "is_error": code != 0,
            }
