from __future__ import annotations

import argparse
import asyncio
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from types import MethodType

from harness.runtime import create_agent
from harness.store import Store
from harness.streaming import TerminalStream
from harness.docker_sandbox import DockerSandbox
from harness.filesystem_sandbox import install_filesystem_sandbox
from harness.config import HarnessConfig, load_config
from harness.web.citations import CitationStore
from harness.web.gateway import WebGateway
from harness.web.tools import build_web_tool_classes
from harness.diagnostics import doctor
from harness.observability import configure_logging
from harness.security import (
    ApprovalGate,
    SecurityPolicy,
    SecurityViolation,
    redact_audit_target,
)
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings


def find_project_root(start: Path) -> Path:
    current = start.expanduser().resolve()
    if current.is_file():
        current = current.parent
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists() or (candidate / "AGENTS.md").exists():
            return candidate
    return current


def default_db_path(project_root: Path) -> Path:
    project_key = hashlib.sha256(
        str(project_root).encode("utf-8")
    ).hexdigest()[:16]
    return (
        Path.home() / "Library" / "Application Support"
        / "LocalAgentHarness" / project_key / "state.sqlite3"
    )


def print_help():
    print("""
Available commands:

  /help              Show commands
  /new               Create a new session
  /sessions          List project sessions
  /resume ID         Resume a session
  /memory            List saved memories
  /remember TEXT     Save a persistent memory
  /search TEXT       Search persistent memories
  /audit             Show security audit events
  /sources           List fetched web sources for this session
  /backup            Create a consistent SQLite backup
  /restore PATH      Restore a database backup (explicit confirmation required)
  /write on          Enable write tools
  /write off         Disable write tools
  /quit              Save and exit

Input:
  Enter              Submit prompt
  Ctrl+J             Insert a new line

Security:
  Bash requires one-time approval and runs in an isolated Docker container.
  Edit and overwriting an existing file require one-time approval.
  New file creation requires /write on.
""")


def build_prompt_session():
    kb = KeyBindings()

    @kb.add("enter", eager=True)
    def submit_prompt(event):
        event.current_buffer.validate_and_handle()

    @kb.add("c-j", eager=True)
    def insert_newline(event):
        event.current_buffer.insert_text("\n")

    return PromptSession(
        multiline=True,
        key_bindings=kb,
        prompt_continuation=lambda width, line_number, is_soft_wrap: " " * 4,
    )


def build_agent(
    project_root: Path, db: Store, write_enabled: bool, config: HarnessConfig,
    session_id: str,
):
    memories = db.list_memories(str(project_root))
    memory_lines = [row["content"] for row in memories[:12]]
    extra_tool_classes = []
    if config.web.enabled:
        web = config.web
        gateway = WebGateway(
            base_url=web.base_url,
            search_timeout=web.search_timeout_seconds,
            fetch_timeout=web.fetch_timeout_seconds,
            max_results=web.max_results,
            max_query_length=web.max_query_length,
            max_content_chars=web.max_content_chars,
            max_response_bytes=web.max_response_bytes,
            max_redirects=web.max_redirects,
            max_concurrent=web.max_concurrent,
            allowed_schemes={
                scheme for scheme, enabled in
                (("http", web.allow_http), ("https", web.allow_https)) if enabled
            },
            default_language=web.default_language,
            safe_search=web.safe_search,
            search_cache_ttl=web.search_cache_ttl_seconds,
            fetch_cache_ttl=web.fetch_cache_ttl_seconds,
        )
        citations = CitationStore(db.db_path)
        citations.initialize()
        extra_tool_classes = build_web_tool_classes(gateway, citations, session_id)
        if not web.fetch_enabled:
            extra_tool_classes = extra_tool_classes[:1]
    return create_agent(
        project_root, memory_lines, write_enabled, endpoint=config.endpoint,
        extra_tool_classes=extra_tool_classes, web_enabled=config.web.enabled,
    )


def validate_session(db: Store, session_id: str, project_key: str):
    session = db.get_session(session_id)
    if not session:
        print(f"Session not found: {session_id}")
        return False
    if session["project_path"] != project_key:
        print("Session belongs to a different project. Resume rejected.")
        return False
    return True


def save_session(db: Store, session_id: str, agent):
    try:
        db.save_messages(session_id, agent.messages)
        return True
    except Exception as exc:
        print(f"Failed to save session: {exc}")
        return False


def _tool_calls_in_messages(messages):
    calls = []
    for message in messages:
        if message.get("role") != "assistant":
            continue
        content = message.get("content")
        if isinstance(content, list):
            calls.extend(
                item for item in content
                if isinstance(item, dict) and item.get("type") == "toolCall"
            )
    return calls


def recover_interrupted_tools(db: Store, session_id: str, messages):
    runs = {row["tool_call_id"]: row for row in db.list_tool_runs(session_id)}
    existing = {
        message.get("tool_call_id")
        for message in messages if message.get("role") == "toolResult"
    }
    recovered = []
    for call in _tool_calls_in_messages(messages):
        call_id = call.get("id")
        if not call_id or call_id in existing:
            continue
        run = runs.get(call_id)
        if run and run["status"] == "completed" and run["result"]:
            recovered.append(run["result"])
            continue
        if run and run["status"] == "running":
            db.mark_tool_interrupted(session_id, call_id)
        status = run["status"] if run else "no journal record"
        recovered.append({
            "role": "toolResult",
            "tool_call_id": call_id,
            "tool_name": call.get("name", run["tool_name"] if run else "unknown"),
            "tool_args": call.get("arguments", run["tool_args"] if run else {}),
            "content": [{
                "type": "text",
                "text": (
                    "Execution was interrupted or completion could not be confirmed "
                    f"(journal status: {status}). It was NOT automatically retried. "
                    "Inspect actual state before deciding whether to retry."
                ),
            }],
            "is_error": True,
        })
    if recovered:
        messages.extend(recovered)
        db.save_messages(session_id, messages)
        print(
            f"Recovery: reconciled {len(recovered)} incomplete tool result(s). "
            "No tool was automatically re-executed."
        )
    return messages


class CheckpointListener:
    def __init__(self, db: Store, session_id: str, agent):
        self.db, self.session_id, self.agent = db, session_id, agent

    async def on_event(self, event: dict):
        if event.get("type") in {"turn_end", "tool_results_ready"}:
            self.db.save_messages(self.session_id, self.agent.messages)


def install_security_and_journal(
    agent, db: Store, session_id: str, project_root: Path,
    config: HarnessConfig,
):
    if getattr(agent, "_lah_policy_session_id", None) == session_id:
        return agent

    original_execute_one = agent._execute_one
    policy = SecurityPolicy(project_root)
    approval = ApprovalGate()

    # All filesystem tools and Bash share one filtered Docker snapshot backend.
    # Agent._execute_one and its event lifecycle remain upstream, preserving
    # tool_start/tool_result/tool_end behavior and Stage 3 journal semantics.
    sandbox = getattr(agent, "_lah_docker_sandbox", None)
    if sandbox is None:
        sandbox = DockerSandbox(
            project_root,
            image=config.docker_image,
            max_timeout=config.sandbox_timeout,
            memory=config.docker_memory,
            cpus=config.docker_cpus,
            pids_limit=config.docker_pids_limit,
            max_files=config.max_snapshot_files,
            max_total_bytes=config.max_snapshot_bytes,
            max_file_bytes=config.max_snapshot_file_bytes,
            max_output_bytes=config.max_output_bytes,
        )
        agent._lah_docker_sandbox = sandbox

    if not getattr(agent, "_lah_filesystem_sandbox", None):
        install_filesystem_sandbox(agent, sandbox)

    bash_tool = next((tool for tool in agent.tools if tool.name == "Bash"), None)
    if bash_tool is not None and not getattr(bash_tool, "_lah_docker_sandbox", False):
        async def docker_sandboxed_bash(self, params, signal=None):
            return await sandbox.execute(
                params.command,
                timeout=getattr(params, "timeout", None),
                signal=signal,
            )

        bash_tool.execute = MethodType(docker_sandboxed_bash, bash_tool)
        bash_tool._lah_docker_sandbox = True

    async def secure_journalled_execute_one(self, call):
        name = call.get("name", "unknown")
        args = call.get("arguments") or {}
        call_id = call.get("id", "")
        target = ""
        reason = ""

        try:
            target, reason = policy.validate_tool_call(name, args)
        except SecurityViolation as exc:
            reason = str(exc)
            target = str(args.get("path") or args.get("command") or "")
            db.record_security_event(
                session_id, call_id, name, "tool_call",
                redact_audit_target(name, target), "denied", reason,
            )
            db.deny_tool_run(session_id, call, reason)
            result = {
                "role": "toolResult",
                "tool_call_id": call_id,
                "tool_name": name,
                "tool_args": args,
                "content": [{"type": "text", "text": f"Security policy denied this tool call: {reason}"}],
                "is_error": True,
            }
            await self._emit({
                "type": "tool_start",
                "payload": {"name": name, "args": args},
            })
            await self._emit({
                "type": "tool_result",
                "payload": {"result": result},
            })
            await self._emit({
                "type": "tool_end",
                "payload": {"name": name, "is_error": True, "result": result},
            })
            return result

        requires_approval = bool(reason)
        if requires_approval:
            approved = await approval.approve(name, target, reason, project_root)
            decision = "approved" if approved else "denied"
            db.record_security_event(
                session_id, call_id, name, "tool_call",
                redact_audit_target(name, target), decision, reason,
            )
            if not approved:
                denial_reason = "User denied this one-time operation."
                db.deny_tool_run(session_id, call, denial_reason)
                result = {
                    "role": "toolResult",
                    "tool_call_id": call_id,
                    "tool_name": name,
                    "tool_args": args,
                    "content": [{"type": "text", "text": denial_reason}],
                    "is_error": True,
                }
                await self._emit({
                    "type": "tool_start",
                    "payload": {"name": name, "args": args},
                })
                await self._emit({
                    "type": "tool_result",
                    "payload": {"result": result},
                })
                await self._emit({
                    "type": "tool_end",
                    "payload": {"name": name, "is_error": True, "result": result},
                })
                return result
        else:
            db.record_security_event(
                session_id, call_id, name, "tool_call",
                redact_audit_target(name, target), "allowed",
                "Within project-root policy; Write creation authorized by /write on.",
            )

        # Fail closed: journal start must commit before tool execution.
        db.start_tool_run(session_id, call)
        try:
            result = await original_execute_one(call)
        except BaseException as exc:
            try:
                db.fail_tool_run(session_id, call_id, repr(exc))
            except Exception as journal_exc:
                print(f"\nTool journal failure: {journal_exc}")
            raise
        db.complete_tool_run(session_id, call_id, result)
        return result

    agent._execute_one = MethodType(secure_journalled_execute_one, agent)
    agent._lah_policy_session_id = session_id
    return agent


async def run(args):
    project_root = find_project_root(Path(args.project))
    config = load_config(args.config)
    logger = configure_logging(project_root)
    project_key = str(project_root)
    db = Store(default_db_path(project_root))
    write_enabled = args.write

    if args.session:
        session_id = args.session
        if not validate_session(db, session_id, project_key):
            return
        messages = db.load_messages(session_id)
        if not messages:
            print(f"Session is empty: {session_id}")
            return
        messages = recover_interrupted_tools(db, session_id, messages)
        agent = build_agent(project_root, db, write_enabled, config, session_id)
        agent.messages = messages
        print(f"Resumed session: {session_id}")
    else:
        session_id = db.create_session(project_key)
        agent = build_agent(project_root, db, write_enabled, config, session_id)
        print(f"New session: {session_id}")

    print(f"Project: {project_root}")
    print(f"Write tools: {'ON' if write_enabled else 'OFF (read-only)'}")
    if write_enabled:
        print("Execution: Docker sandbox (filesystem tools + Bash; network disabled)")
    print(f"Web tools: {'ON' if config.web.enabled else 'OFF'}")
    print("Type /help for commands. Ctrl-D or /quit to exit.")
    prompt_session = build_prompt_session()

    while True:
        try:
            user_text = (await prompt_session.prompt_async("You> ")).strip()
        except (EOFError, KeyboardInterrupt):
            save_session(db, session_id, agent)
            print("Exiting.")
            break

        if not user_text:
            continue
        if user_text == "/quit":
            save_session(db, session_id, agent)
            break
        if user_text == "/help":
            print_help()
            continue
        if user_text == "/new":
            if not save_session(db, session_id, agent):
                print("New session not created because save failed.")
                continue
            session_id = db.create_session(project_key)
            agent = build_agent(project_root, db, write_enabled, config, session_id)
            print(f"New session: {session_id}")
            continue
        if user_text == "/sessions":
            for row in db.list_sessions(project_key):
                print(f"{row['id']}  {row['updated_at']}  {row['title']}")
            continue
        if user_text == "/memory":
            memories = db.list_memories(project_key)
            if not memories:
                print("No saved memories.")
            else:
                for row in memories:
                    print(f"[{row['id']}] {row['content']}")
            continue
        if user_text.startswith("/remember "):
            content = user_text[len("/remember "):].strip()
            if not content:
                print("Memory content cannot be empty.")
                continue
            try:
                db.add_memory(project_key, content)
                print("Memory saved.")
            except Exception as exc:
                print(f"Failed to save memory: {exc}")
            continue
        if user_text.startswith("/search "):
            query = user_text[len("/search "):].strip()
            results = db.search_memories(project_key, query)
            if not results:
                print("No matching memories.")
            else:
                for row in results:
                    print(f"[{row['id']}] {row['content']}")
            continue
        if user_text == "/backup":
            backup_dir = db.db_path.parent / "backups"
            backup_name = "state-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".sqlite3"
            try:
                destination = db.backup_to(backup_dir / backup_name)
                print(f"Database backup created: {destination}")
                logger.info("Database backup created", extra={"event_data": {
                    "session_id": session_id, "backup_name": backup_name
                }})
            except Exception as exc:
                print(f"Database backup failed: {exc}")
                logger.exception("Database backup failed")
            continue
        if user_text.startswith("/restore "):
            backup_source = Path(user_text[len("/restore "):].strip()).expanduser()
            print("This replaces the active session database. A pre-restore backup will be kept.")
            try:
                confirmation = input(f"Type RESTORE to restore from {backup_source}: ").strip()
                if confirmation != "RESTORE":
                    print("Restore cancelled.")
                    continue
                preserved = db.restore_from(backup_source)
                print(f"Database restored. Previous database preserved at: {preserved}")
                logger.warning("Database restored", extra={"event_data": {
                    "session_id": session_id, "source": str(backup_source),
                    "preserved_database": str(preserved)
                }})
                print("Restart lah before continuing to avoid stale in-memory session state.")
                break
            except Exception as exc:
                print(f"Database restore failed: {exc}")
                logger.exception("Database restore failed")
            continue
        if user_text == "/sources":
            if not config.web.enabled:
                print("Web tools are disabled in configuration.")
                continue
            citations = CitationStore(db.db_path)
            sources = citations.list_sources(session_id)
            if not sources:
                print("No fetched web sources in this session.")
            else:
                for source in sources:
                    print("[{}] {} — {}\n    {}".format(source["source_id"], source["title"], source["domain"], source["url"]))
            continue
        if user_text == "/audit":
            events = db.list_security_events(session_id, 30)
            if not events:
                print("No security events for this session.")
            else:
                for row in events:
                    print(
                        f"[{row['id']}] {row['created_at']} | {row['tool_name']} | "
                        f"{row['decision']} | {row['target']} | {row['reason']}"
                    )
            continue
        if user_text.startswith("/resume "):
            target = user_text[len("/resume "):].strip()
            if not validate_session(db, target, project_key):
                continue
            try:
                messages = db.load_messages(target)
                if not messages:
                    print(f"Session is empty: {target}")
                    continue
                if not save_session(db, session_id, agent):
                    print("Current session was not switched because save failed.")
                    continue
                messages = recover_interrupted_tools(db, target, messages)
                session_id = target
                agent = build_agent(project_root, db, write_enabled, config, session_id)
                agent.messages = messages
                print(f"Resumed session: {session_id}")
            except Exception as exc:
                print(f"Failed to resume session: {exc}")
            continue
        if user_text.startswith("/write "):
            value = user_text.split(maxsplit=1)[1].lower()
            if value not in {"on", "off"}:
                print("Use /write on or /write off")
                continue
            new_write_enabled = value == "on"
            if new_write_enabled == write_enabled:
                print(f"Write tools already {'ON' if write_enabled else 'OFF'}")
                continue
            if not save_session(db, session_id, agent):
                print("Write mode unchanged because save failed.")
                continue
            saved_messages = list(agent.messages)
            agent = build_agent(project_root, db, new_write_enabled, config, session_id)
            agent.messages = saved_messages
            write_enabled = new_write_enabled
            print(f"Write tools: {'ON' if write_enabled else 'OFF'}")
            continue

        install_security_and_journal(agent, db, session_id, project_root, config)
        checkpoint = CheckpointListener(db, session_id, agent)
        stream = TerminalStream()
        agent._listeners.add(checkpoint.on_event)
        agent._listeners.add(stream.on_event)
        result = None
        try:
            result = await agent.run(user_text)
        except Exception as exc:
            print(f"\nAgent exception: {exc}")
        finally:
            agent._listeners.discard(checkpoint.on_event)
            agent._listeners.discard(stream.on_event)
            save_session(db, session_id, agent)
        if result and result.get("stop_reason") == "error":
            print(f"\nAgent error: {result.get('error_message')}")


def main():
    parser = argparse.ArgumentParser(description="Local Agent Harness v1.0")
    parser.add_argument("--project", default=".", help="Project directory")
    parser.add_argument("--session", help="Resume an existing harness session")
    parser.add_argument("--write", action="store_true", help="Enable Write/Edit/Bash tools")
    parser.add_argument("--config", help="Path to TOML configuration file")
    parser.add_argument("--doctor", action="store_true", help="Run environment diagnostics and exit")
    parser.add_argument("--version", action="version", version="Local Agent Harness 1.0.0")
    args = parser.parse_args()
    if args.doctor:
        project_root = find_project_root(Path(args.project))
        try:
            config = load_config(args.config)
            ok, checks = doctor(config, project_root)
        except Exception as exc:
            print(f"Configuration: FAIL — {exc}")
            raise SystemExit(1)
        for name, status, detail in checks:
            print(f"{status:4}  {name}: {detail}")
        raise SystemExit(0 if ok else 1)
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
