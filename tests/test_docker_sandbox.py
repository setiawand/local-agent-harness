from __future__ import annotations

from pathlib import Path

from harness.docker_sandbox import DockerSandbox


def make_sandbox(root: Path) -> DockerSandbox:
    sandbox = object.__new__(DockerSandbox)
    sandbox.root = root.resolve()
    sandbox.max_files = 1000
    sandbox.max_total_bytes = 10 * 1024 * 1024
    sandbox.max_file_bytes = 1024 * 1024
    return sandbox


def test_snapshot_excludes_secrets_build_dirs_and_symlinks(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("safe", encoding="utf-8")
    (root / ".env").write_text("SECRET=do-not-copy", encoding="utf-8")
    (root / "config.pem").write_text("private-key", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("remote credentials", encoding="utf-8")
    (root / ".venv").mkdir()
    (root / ".venv" / "python").write_text("binary placeholder", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (root / "outside-link").symlink_to(outside)
    except OSError:
        pass

    sandbox = make_sandbox(root)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    baseline = sandbox._copy_snapshot(snapshot)

    assert (snapshot / "README.md").read_text(encoding="utf-8") == "safe"
    assert not (snapshot / ".env").exists()
    assert not (snapshot / "config.pem").exists()
    assert not (snapshot / ".git").exists()
    assert not (snapshot / ".venv").exists()
    assert "README.md" in baseline
    assert ".env" not in baseline
    assert not (snapshot / "outside-link").exists()


def test_sync_applies_regular_file_changes_and_new_files(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("before", encoding="utf-8")
    sandbox = make_sandbox(root)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    baseline = sandbox._copy_snapshot(snapshot)

    (snapshot / "README.md").write_text("after", encoding="utf-8")
    (snapshot / "created.txt").write_text("new", encoding="utf-8")
    updated, conflicts, skipped = sandbox._sync_snapshot(snapshot, baseline)

    assert updated == 2
    assert conflicts == 0
    assert skipped == 0
    assert (root / "README.md").read_text(encoding="utf-8") == "after"
    assert (root / "created.txt").read_text(encoding="utf-8") == "new"


def test_sync_does_not_overwrite_concurrent_host_changes(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("original", encoding="utf-8")
    sandbox = make_sandbox(root)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    baseline = sandbox._copy_snapshot(snapshot)

    (snapshot / "README.md").write_text("container version", encoding="utf-8")
    (root / "README.md").write_text("host concurrent version", encoding="utf-8")
    updated, conflicts, skipped = sandbox._sync_snapshot(snapshot, baseline)

    assert updated == 0
    assert conflicts == 1
    assert (root / "README.md").read_text(encoding="utf-8") == "host concurrent version"


def test_sync_never_propagates_sensitive_paths_or_deletions(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("keep", encoding="utf-8")
    (root / ".env").write_text("SECRET=host", encoding="utf-8")
    sandbox = make_sandbox(root)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    baseline = sandbox._copy_snapshot(snapshot)

    (snapshot / "README.md").unlink()
    (snapshot / ".env").write_text("SECRET=container", encoding="utf-8")
    (snapshot / "new.txt").write_text("new", encoding="utf-8")
    updated, conflicts, skipped = sandbox._sync_snapshot(snapshot, baseline)

    assert updated == 1
    assert (root / "README.md").read_text(encoding="utf-8") == "keep"
    assert (root / ".env").read_text(encoding="utf-8") == "SECRET=host"
    assert (root / "new.txt").read_text(encoding="utf-8") == "new"


def test_sync_enforces_file_and_total_size_limits(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    sandbox = make_sandbox(root)
    sandbox.max_file_bytes = 4
    sandbox.max_total_bytes = 6
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    baseline = sandbox._copy_snapshot(snapshot)

    (snapshot / "too-large.txt").write_text("12345", encoding="utf-8")
    (snapshot / "small.txt").write_text("1234", encoding="utf-8")
    (snapshot / "second-small.txt").write_text("5678", encoding="utf-8")

    updated, conflicts, skipped = sandbox._sync_snapshot(snapshot, baseline)

    assert updated <= 1
    assert conflicts == 0
    assert skipped >= 1
    assert not (root / "too-large.txt").exists()
