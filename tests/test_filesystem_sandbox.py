from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from harness.filesystem_sandbox import build_worker_source


def run_worker(root: Path, operation: str, **params):
    source = build_worker_source(operation, params)
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=20,
    )


def test_read_and_grep_run_inside_workspace_snapshot(tmp_path):
    (tmp_path / "README.md").write_text("alpha\nbeta target\ngamma\n", encoding="utf-8")

    read = run_worker(tmp_path, "Read", path="README.md", offset=2, limit=1)
    grep = run_worker(tmp_path, "Grep", path="README.md", pattern="target", literal=True, limit=10)

    assert read.returncode == 0
    assert "beta target" in read.stdout
    assert grep.returncode == 0
    assert "README.md:2:beta target" in grep.stdout


def test_write_and_edit_modify_only_snapshot(tmp_path):
    (tmp_path / "README.md").write_text("before\n", encoding="utf-8")

    write = run_worker(tmp_path, "Write", path="created.txt", content="new file\n")
    edit = run_worker(tmp_path, "Edit", path="README.md", old_text="before", new_text="after")

    assert write.returncode == 0
    assert (tmp_path / "created.txt").read_text(encoding="utf-8") == "new file\n"
    assert edit.returncode == 0
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == "after\n"


def test_find_and_ls_list_workspace_contents_without_hidden_or_sensitive_paths(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('ok')", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=x", encoding="utf-8")
    (tmp_path / ".hidden").mkdir()
    (tmp_path / ".hidden" / "secret.txt").write_text("secret", encoding="utf-8")

    find = run_worker(tmp_path, "Find", path=".", pattern="*.py", type="file", limit=100)
    ls = run_worker(tmp_path, "Ls", path=".")

    assert find.returncode == 0
    assert "src/main.py" in find.stdout
    assert ".env" not in find.stdout
    assert ls.returncode == 0
    assert "src/" in ls.stdout
    assert ".env" not in ls.stdout
    assert ".hidden" not in ls.stdout


def test_path_traversal_and_sensitive_file_access_are_denied(tmp_path):
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("outside", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=x", encoding="utf-8")

    traversal = run_worker(tmp_path, "Read", path="../outside-secret.txt")
    secret = run_worker(tmp_path, "Read", path=".env")

    assert traversal.returncode != 0
    assert "traversal" in traversal.stderr.lower() or "escapes" in traversal.stderr.lower()
    assert secret.returncode != 0
    assert "protected" in secret.stderr.lower()


def test_symlink_escape_is_denied(tmp_path):
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (tmp_path / "escape").symlink_to(outside)
    except OSError:
        return

    result = run_worker(tmp_path, "Read", path="escape")
    assert result.returncode != 0
    assert "escapes" in result.stderr.lower() or "symlink" in result.stderr.lower()


def test_gateway_replaces_tool_executor_and_encodes_arguments(tmp_path):
    import asyncio
    import base64
    import re
    from pathlib import Path

    from harness.filesystem_sandbox import install_filesystem_sandbox

    class FakeSandbox:
        root = tmp_path

        async def execute(self, command, timeout=None, signal=None):
            self.command = command
            return {"content": [{"type": "text", "text": "isolated"}], "is_error": False}

    class FakeTool:
        def __init__(self, name):
            self.name = name
            self.called_original = False

        async def execute(self, params, signal=None):
            self.called_original = True
            raise AssertionError("native filesystem executor must not run")

    class FakeAgent:
        def __init__(self):
            self.tools = [FakeTool(name) for name in ("Read", "Write", "Edit", "Grep", "Find", "Ls")]

    agent = FakeAgent()
    sandbox = FakeSandbox()
    install_filesystem_sandbox(agent, sandbox)

    result = asyncio.run(agent.tools[0].execute({"path": "README.md", "offset": 1}))
    assert result["content"][0]["text"] == "isolated"
    assert not agent.tools[0].called_original

    match = re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", sandbox.command)
    assert match
    import ast
    encoded_source = base64.b64decode(match.group(1)).decode("utf-8")
    # The tool arguments are embedded as a Python string literal, not shell syntax.
    assert "README.md" in encoded_source
    assert "_operation" in encoded_source
