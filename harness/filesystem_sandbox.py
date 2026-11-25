from __future__ import annotations

import base64
import json
import os
from pathlib import Path, PurePosixPath
from types import MethodType
from typing import Any

from harness.docker_sandbox import DockerSandbox, DockerSandboxError


# This program is executed inside the filtered /workspace snapshot. It receives
# only JSON-serialized tool arguments and never executes user-supplied Python.
_WORKER = r'''import fnmatch
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath

args = json.loads(__PAYLOAD__)
operation = args.pop("_operation")
root = Path.cwd().resolve()
SENSITIVE_NAMES = {".env", ".netrc", ".npmrc", ".pypirc", ".git-credentials", "id_rsa", "id_ed25519", "id_ecdsa", "known_hosts", "credentials", "secrets.json", "secrets.yaml", "secrets.yml"}
SENSITIVE_DIRS = {".git", ".ssh", ".aws", ".gnupg", ".azure", ".kube", "private", "credentials"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"}
IGNORED_DIRS = {".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".next", ".cache"}

def sensitive(rel):
    for part in PurePosixPath(rel).parts:
        low = part.lower()
        if low in SENSITIVE_NAMES or low in SENSITIVE_DIRS or low.startswith(".env."):
            return True
        if any(low.endswith(s) for s in SENSITIVE_SUFFIXES):
            return True
    return False

def safe_path(raw, allow_root=True):
    value = str(raw or ".")
    candidate = Path(value)
    if candidate.is_absolute():
        # Absolute host paths must have been normalized by the host adapter.
        if str(candidate).startswith("/workspace/"):
            candidate = Path(str(candidate)[len("/workspace/"):])
        elif str(candidate) == "/workspace":
            candidate = Path(".")
        else:
            raise ValueError("Absolute paths are not permitted inside filesystem sandbox")
    if ".." in candidate.parts:
        raise ValueError("Path traversal is not permitted")
    target = (root / candidate).resolve(strict=False)
    try:
        rel = target.relative_to(root).as_posix()
    except ValueError:
        raise ValueError("Path escapes the isolated workspace")
    if not allow_root and target == root:
        raise ValueError("Workspace root is not a valid file target")
    if rel != "." and sensitive(rel):
        raise ValueError("Access to a protected path is blocked")
    # The snapshot contains no symlinks; still reject any encountered symlink.
    cursor = root
    for part in PurePosixPath(rel).parts if rel != "." else ():
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("Symlink paths are not permitted")
    return target, rel

def emit(text):
    sys.stdout.write(str(text))

try:
    if operation == "Read":
        path, rel = safe_path(args.get("path"), allow_root=False)
        if path.is_dir():
            raise ValueError(f"Path is a directory: {args.get('path')}")
        if not path.is_file():
            raise ValueError(f"File not found: {args.get('path')}")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        offset = max(0, int(args.get("offset") or 1) - 1)
        limit = args.get("limit")
        end = offset + int(limit) if limit else len(lines)
        emit(f"# {args.get('path')} (lines {offset+1}–{min(end, len(lines))} of {len(lines)})\n")
        emit("".join(lines[offset:end]))

    elif operation == "Write":
        path, rel = safe_path(args.get("path"), allow_root=False)
        if path.exists() and not path.is_file():
            raise ValueError("Write target is not a regular file")
        path.parent.mkdir(parents=True, exist_ok=True)
        existed = path.exists()
        content = str(args.get("content") or "")
        path.write_text(content, encoding="utf-8")
        emit(f"{'overwrote' if existed else 'created'} {args.get('path')} ({content.count(chr(10))+1} lines)")

    elif operation == "Edit":
        path, rel = safe_path(args.get("path"), allow_root=False)
        if not path.is_file():
            raise ValueError(f"File not found: {args.get('path')}")
        old = str(args.get("old_text") or "")
        new = str(args.get("new_text") or "")
        if not old:
            raise ValueError("old_text cannot be empty")
        original = path.read_text(encoding="utf-8")
        count = original.count(old)
        if count == 0:
            raise ValueError(f"old_text not found in {args.get('path')}")
        if count > 1:
            raise ValueError(f"old_text appears {count} times in {args.get('path')}; make it more specific")
        changed = original.replace(old, new, 1)
        path.write_text(changed, encoding="utf-8")
        import difflib
        diff = "".join(difflib.unified_diff(original.splitlines(keepends=True), changed.splitlines(keepends=True), fromfile=f"a/{args.get('path')}", tofile=f"b/{args.get('path')}"))
        emit(diff or f"No visible changes made to {args.get('path')}")

    elif operation == "Grep":
        path, rel = safe_path(args.get("path") or ".")
        if path.is_dir():
            raise ValueError("Recursive Grep is disabled. Specify one file path.")
        if not path.is_file():
            raise ValueError(f"File not found: {args.get('path')}")
        pattern = str(args.get("pattern") or "")
        flags = re.IGNORECASE if args.get("ignore_case") else 0
        regex = re.compile(re.escape(pattern) if args.get("literal") else pattern, flags)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        context = max(0, int(args.get("context") or 0))
        limit = max(1, int(args.get("limit") or 100))
        output, matched, emitted = [], 0, set()
        for index, line in enumerate(lines):
            if regex.search(line):
                matched += 1
                if matched > limit:
                    break
                for pos in range(max(0, index-context), min(len(lines), index+context+1)):
                    if pos not in emitted:
                        output.append(f"{rel}:{pos+1}{':' if pos == index else '-'}{lines[pos]}")
                        emitted.add(pos)
                if context:
                    output.append("--")
        text = "\n".join(output) if output else f"No matches for '{pattern}'"
        if matched > limit:
            text += f"\n[truncated at {limit} matches]"
        emit(text)

    elif operation == "Find":
        path, rel = safe_path(args.get("path") or ".")
        if not path.is_dir():
            raise ValueError("Find requires a directory")
        pattern = str(args.get("pattern") or "")
        kind = args.get("type") or "both"
        limit = max(1, int(args.get("limit") or 100))
        results = []
        for current, dirs, files in os.walk(path, topdown=True, followlinks=False):
            current_path = Path(current)
            dirs[:] = [d for d in dirs if not d.startswith(".") and d.lower() not in IGNORED_DIRS and not (current_path/d).is_symlink() and not sensitive((current_path/d).relative_to(root).as_posix())]
            if kind in ("dir", "both"):
                for name in dirs:
                    if not pattern or fnmatch.fnmatch(name, pattern):
                        results.append((current_path/name).relative_to(root).as_posix()+"/")
            if kind in ("file", "both"):
                for name in files:
                    candidate = current_path/name
                    relname = candidate.relative_to(root).as_posix()
                    if not candidate.is_symlink() and not sensitive(relname) and (not pattern or fnmatch.fnmatch(name, pattern)):
                        results.append(relname)
            if len(results) >= limit:
                results = results[:limit] + [f"[truncated at {limit} results]"]
                break
        emit("\n".join(results) if results else "No results")

    elif operation == "Ls":
        path, rel = safe_path(args.get("path") or ".")
        if not path.is_dir():
            raise ValueError(f"Not a directory: {args.get('path') or '.'}")
        entries = []
        for item in sorted(path.iterdir(), key=lambda p: p.name):
            if item.name.startswith(".") or item.name.lower() in IGNORED_DIRS or sensitive(item.relative_to(root).as_posix()) or item.is_symlink():
                continue
            if item.is_dir():
                entries.append(item.name + "/")
            else:
                entries.append(item.name)
        emit("\n".join(entries) if entries else "(empty)")
    else:
        raise ValueError("Unsupported filesystem operation")
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(2)
'''


def _params_to_dict(params: Any) -> dict[str, Any]:
    if hasattr(params, "model_dump"):
        return params.model_dump(exclude_none=False)
    if hasattr(params, "dict"):
        return params.dict(exclude_none=False)
    if isinstance(params, dict):
        return dict(params)
    raise TypeError(f"Unsupported tool parameter object: {type(params)!r}")


def _normalize_path(value: Any, root: Path) -> str:
    if value is None or str(value).strip() == "":
        return "."
    path = Path(str(value)).expanduser()
    if path.is_absolute():
        resolved = path.resolve(strict=False)
        try:
            return resolved.relative_to(root).as_posix() or "."
        except ValueError as exc:
            raise DockerSandboxError("Filesystem tool path is outside the project root") from exc
    # Keep relative path lexical; SecurityPolicy has already rejected traversal.
    return PurePosixPath(str(value)).as_posix()


def build_worker_source(operation: str, params: dict[str, Any]) -> str:
    payload = dict(params)
    payload["_operation"] = operation
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return _WORKER.replace("__PAYLOAD__", repr(payload_json))


def build_worker_command(operation: str, params: dict[str, Any]) -> str:
    source = build_worker_source(operation, params)
    encoded = base64.b64encode(source.encode("utf-8")).decode("ascii")
    # Only base64 characters enter the shell command; tool arguments never do.
    return f'python -c "import base64;exec(base64.b64decode(\'{encoded}\'))"'


class FilesystemSandbox:
    def __init__(self, sandbox: DockerSandbox):
        self.sandbox = sandbox
        self.root = sandbox.root

    async def execute(self, operation: str, params: Any, signal=None) -> dict[str, Any]:
        values = _params_to_dict(params)
        if "path" in values:
            values["path"] = _normalize_path(values.get("path"), self.root)
        command = build_worker_command(operation, values)
        timeout = getattr(params, "timeout", None)
        return await self.sandbox.execute(command, timeout=timeout, signal=signal)


def install_filesystem_sandbox(agent, sandbox: DockerSandbox) -> FilesystemSandbox:
    """Replace all six native filesystem tool executors with Docker-backed ones."""
    gateway = FilesystemSandbox(sandbox)
    operation_by_name = {
        "Read": "Read",
        "Write": "Write",
        "Edit": "Edit",
        "EditTool": "Edit",
        "Grep": "Grep",
        "GrepTool": "Grep",
        "Find": "Find",
        "FindTool": "Find",
        "Ls": "Ls",
        "LsTool": "Ls",
    }
    installed = []
    for tool in agent.tools:
        operation = operation_by_name.get(getattr(tool, "name", ""))
        if operation is None:
            continue
        async def isolated_execute(self, params, signal=None, _operation=operation):
            return await gateway.execute(_operation, params, signal)
        tool.execute = MethodType(isolated_execute, tool)
        tool._lah_filesystem_sandbox = True
        installed.append(operation)
    installed_set = set(installed)
    required = {"Read", "Grep", "Find", "Ls"}
    if "Write" in installed_set or "Edit" in installed_set:
        required.update({"Write", "Edit"})
    missing = required - installed_set
    if missing:
        raise DockerSandboxError(
            "Filesystem sandbox installation incomplete; missing tool(s): "
            + ", ".join(sorted(missing))
        )
    agent._lah_filesystem_sandbox = gateway
    agent._lah_filesystem_tools = tuple(installed)
    return gateway
