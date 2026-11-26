from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class SecurityViolation(ValueError):
    pass


class SecurityPolicy:
    """
    Application-level tool policy.

    Native file tools are constrained to project_root. Bash is approval-gated
    and rejects shell syntax / dangerous executables, but is NOT an OS sandbox.
    """

    SENSITIVE_NAMES = {
        ".env",
        ".env.local",
        ".env.production",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "known_hosts",
        "credentials",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
    }
    SENSITIVE_DIRS = {
        ".git",
        ".ssh",
        ".aws",
        ".gnupg",
        ".azure",
        ".kube",
        "private",
        "credentials",
    }
    SENSITIVE_SUFFIXES = {
        ".pem", ".key", ".p12", ".pfx", ".keystore", ".jks",
    }
    ALLOWED_EXECUTABLES = {
        "pwd", "ls", "cat", "head", "tail", "grep", "rg", "find", "touch",
        "wc", "sort", "uniq", "git", "python", "python3", "uv",
        "pytest", "npm", "npx", "node", "make", "cmake",
        "go", "cargo", "rustc", "java", "javac", "dotnet",
    }
    BLOCKED_EXECUTABLES = {
        "sudo", "su", "doas",
        "rm", "rmdir", "unlink", "shred",
        "dd", "mkfs", "fdisk", "diskutil",
        "chmod", "chown", "chgrp",
        "kill", "pkill", "killall",
        "curl", "wget", "nc", "ncat", "netcat", "socat",
        "ssh", "scp", "sftp", "telnet",
        "osascript", "launchctl", "security",
    }
    # Shell operators, expansions, redirections, globbing and substitutions.
    SHELL_META = set(";|&><`$(){}*?")

    def __init__(self, project_root: Path):
        self.root = Path(project_root).expanduser().resolve(strict=True)

    def _is_sensitive(self, path: Path) -> bool:
        try:
            rel = path.relative_to(self.root)
        except ValueError:
            return True

        for part in rel.parts:
            lower = part.lower()
            if lower in self.SENSITIVE_NAMES or lower in self.SENSITIVE_DIRS:
                return True
            if any(lower.endswith(suffix) for suffix in self.SENSITIVE_SUFFIXES):
                return True
            if lower.startswith(".env."):
                return True
        return False

    def resolve_project_path(self, raw_path: str | None, *, allow_root: bool = True) -> Path:
        if raw_path is None or not str(raw_path).strip():
            candidate = self.root
        else:
            value = Path(str(raw_path)).expanduser()
            candidate = value if value.is_absolute() else self.root / value

        # Reject symlink components, including an existing final symlink. This
        # prevents ordinary symlink escapes and reduces path substitution risk.
        lexical = Path(os.path.abspath(candidate))
        try:
            lexical_rel = lexical.relative_to(self.root)
        except ValueError as exc:
            raise SecurityViolation(
                f"Path is outside project root: {raw_path}"
            ) from exc

        cursor = self.root
        for part in lexical_rel.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise SecurityViolation(
                    f"Symlink paths are not permitted by policy: {raw_path}"
                )

        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise SecurityViolation(
                f"Resolved path is outside project root: {raw_path}"
            ) from exc

        if not allow_root and resolved == self.root:
            raise SecurityViolation("The project root itself is not a valid file target.")

        if self._is_sensitive(resolved):
            raise SecurityViolation(
                f"Access to a protected path is blocked: {raw_path}"
            )
        return resolved

    def validate_tool_call(self, name: str, args: dict[str, Any]) -> tuple[str, str]:
        """Return (target_summary, approval_reason). Raise on policy violation."""
        if name in {"Read", "Write", "EditTool", "Edit"}:
            path = self.resolve_project_path(args.get("path"), allow_root=False)
            if name == "Read" and path.is_dir():
                raise SecurityViolation("Read only accepts a file path.")
            if name in {"Write", "EditTool", "Edit"} and path == self.root:
                raise SecurityViolation("Cannot modify the project root directory.")
            if name in {"EditTool", "Edit"}:
                return str(path), "Edit modifies an existing file"
            if name == "Write" and path.exists():
                return str(path), "Write would overwrite an existing file"
            return str(path), ""

        if name in {"GrepTool", "Grep"}:
            raw = args.get("path") or "."
            path = self.resolve_project_path(raw)
            # The upstream GrepTool recursively walks directories and does not
            # expose a reliable exclusion hook for protected files. Restrict it
            # to a single file; use Find + Read for repository-wide inspection.
            if path.is_dir():
                raise SecurityViolation(
                    "Recursive Grep is disabled by security policy. "
                    "Use Find to locate files, then Grep a specific file."
                )
            return str(path), ""

        if name in {"FindTool", "Find", "LsTool", "LS", "Ls"}:
            path = self.resolve_project_path(args.get("path") or ".")
            if not path.is_dir():
                raise SecurityViolation(f"{name} requires a directory inside the project.")
            return str(path), ""

        if name == "WebSearch":
            query = str(args.get("query") or "").strip()
            if not query or len(query) > 500:
                raise SecurityViolation("WebSearch query must contain 1–500 characters.")
            if any(ord(ch) < 32 for ch in query):
                raise SecurityViolation("WebSearch query contains control characters.")
            return query, "Outbound web search sends this query to configured search engines"

        if name == "WebFetch":
            raw_url = str(args.get("url") or "").strip()
            if len(raw_url) > 4096:
                raise SecurityViolation("WebFetch URL exceeds 4096 characters.")
            try:
                parsed = urlsplit(raw_url)
                host = (parsed.hostname or "").rstrip(".").lower()
                _ = parsed.port
            except ValueError as exc:
                raise SecurityViolation(f"Malformed WebFetch URL: {exc}") from exc
            if parsed.scheme.lower() not in {"http", "https"} or not host:
                raise SecurityViolation("WebFetch requires a valid HTTP(S) URL.")
            if parsed.username or parsed.password:
                raise SecurityViolation("WebFetch URLs containing credentials are blocked.")
            if host in {"localhost", "localhost.localdomain"} or host.endswith(
                (".localhost", ".local", ".internal", ".test")
            ):
                raise SecurityViolation("WebFetch local and internal hostnames are blocked.")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise SecurityViolation("WebFetch IP-literal URLs are blocked.")
            return raw_url, "Outbound HTTP request to a public web page requires one-time approval"

        if name == "Bash":
            command = str(args.get("command") or "").strip()
            self.validate_bash(command)
            return command, "Bash command requires explicit approval"

        # Unknown tools are denied by default. Add a policy explicitly before
        # exposing any additional tool to the agent.
        raise SecurityViolation(f"Tool is not permitted by Stage 4 policy: {name}")

    def validate_bash(self, command: str) -> list[str]:
        if not command:
            raise SecurityViolation("Empty Bash command is not allowed.")
        if len(command) > 2000:
            raise SecurityViolation("Bash command exceeds the 2000-character policy limit.")
        if any(ch in self.SHELL_META for ch in command) or "\n" in command or "\r" in command:
            raise SecurityViolation(
                "Shell operators, substitutions, redirections, globbing, and "
                "multi-command strings are blocked. Submit one simple command."
            )

        try:
            argv = shlex.split(command, posix=True)
        except ValueError as exc:
            raise SecurityViolation(f"Invalid shell quoting: {exc}") from exc

        if not argv:
            raise SecurityViolation("Empty Bash command is not allowed.")

        executable = Path(argv[0]).name.lower()
        if executable in self.BLOCKED_EXECUTABLES:
            raise SecurityViolation(f"Executable is blocked by policy: {executable}")
        if executable not in self.ALLOWED_EXECUTABLES:
            raise SecurityViolation(
                f"Executable is not on the Bash allowlist: {executable}"
            )

        lowered_args = [token.lower() for token in argv[1:]]
        if executable == "find" and any(
            token in {"-exec", "-execdir", "-delete", "-ok", "-okdir"}
            for token in lowered_args
        ):
            raise SecurityViolation(
                "find execution/deletion predicates are blocked by policy."
            )
        if executable == "git" and (
            lowered_args[:1] == ["clean"]
            or lowered_args[:2] == ["reset", "--hard"]
            or lowered_args[:1] == ["push"]
        ):
            raise SecurityViolation(
                "This Git operation is blocked by policy."
            )

        # Check explicit path-like arguments. This is defense-in-depth, not a
        # substitute for an OS sandbox: interpreters can still access arbitrary
        # paths through code, so every Bash invocation also requires approval.
        for token in argv[1:]:
            if token.startswith("-"):
                continue
            token_path = self.root / token
            lower = Path(token).name.lower()
            looks_sensitive = (
                lower in self.SENSITIVE_NAMES
                or lower in self.SENSITIVE_DIRS
                or lower.startswith(".env.")
                or any(lower.endswith(suffix) for suffix in self.SENSITIVE_SUFFIXES)
            )
            path_like = (
                token.startswith("/")
                or token.startswith("~")
                or token.startswith(".")
                or "/" in token
                or "\\\\" in token
                or ".." in Path(token).parts
                or token_path.exists()
                or looks_sensitive
            )
            if path_like:
                self.resolve_project_path(token)

        return argv


class ApprovalGate:
    def __init__(self):
        self._lock = asyncio.Lock()

    async def approve(self, tool_name: str, target: str, reason: str, cwd: Path) -> bool:
        async with self._lock:
            print("\n" + "=" * 68)
            print("SECURITY APPROVAL REQUIRED")
            print(f"Tool: {tool_name}")
            print(f"Working directory: {cwd}")
            print(f"Target / command: {target}")
            print(f"Reason: {reason}")
            print("Type APPROVE to allow this one operation. Anything else denies.")
            print("=" * 68)
            try:
                answer = input("Approval> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nApproval denied.")
                return False
            approved = answer == "APPROVE"
            print("Approved for this operation." if approved else "Operation denied.")
            return approved


def redact_audit_target(tool_name: str, target: str) -> str:
    """Keep useful audit context while masking common inline credentials."""
    value = target[:2000]
    value = re.sub(
        r"(?i)(--password|--token|--secret|--api-key)(\s+)(\S+)",
        r"\1\2[REDACTED]",
        value,
    )
    value = re.sub(
        r"(?i)\b(password|token|secret|api_key)=([^\s]+)",
        r"\1=[REDACTED]",
        value,
    )
    if tool_name in {"Write", "EditTool"}:
        return value
    return value
