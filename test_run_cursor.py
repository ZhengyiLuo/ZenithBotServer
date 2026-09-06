"""Subprocess-level lifecycle regressions for the production Cursor runner.

The fake CLIs emit captured Cursor stream-json shapes through real OS pipes,
so these tests exercise spawn, concurrent stderr drain, protocol validation,
timeouts, stop/teardown, provider persistence, and terminal projection rather
than mocking the runner's internals.
"""

import asyncio
import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_server

FAKE_AGENT_CLI = """#!/usr/bin/env python3
import json, os, sys

cwd = os.getcwd()
session_id = "cursor-sess-abc123"
hello_path = os.path.join(cwd, "hello.py")
events = [
    {"type": "system", "subtype": "init", "apiKeySource": "login", "cwd": cwd,
     "session_id": session_id, "model": "Auto", "permissionMode": "default"},
    {"type": "tool_call", "subtype": "started", "call_id": "call-edit-1",
     "tool_call": {"editToolCall": {"args": {"path": hello_path, "streamContent": "print(1)"}}},
     "session_id": session_id},
    {"type": "tool_call", "subtype": "completed", "call_id": "call-edit-1",
     "tool_call": {"editToolCall": {"args": {"path": hello_path},
                                     "result": {"success": {"path": hello_path,
                                                             "linesAdded": 1,
                                                             "linesRemoved": 0}}}},
     "session_id": session_id},
    {"type": "assistant",
     "message": {"role": "assistant", "content": [{"type": "text", "text": "Done."}]},
     "session_id": session_id},
    {"type": "result", "subtype": "success", "duration_ms": 123, "is_error": False,
     "result": "Done.", "session_id": session_id,
     "usage": {"inputTokens": 10, "outputTokens": 2}},
]
for event in events:
    print(json.dumps(event), flush=True)
sys.exit(0)
"""

FAKE_AGENT_CLI_REJECTED_SHELL = """#!/usr/bin/env python3
import json, sys

session_id = "cursor-sess-rejected"
events = [
    {"type": "system", "subtype": "init", "cwd": ".", "session_id": session_id, "model": "Auto"},
    {"type": "tool_call", "subtype": "completed", "call_id": "call-shell-1",
     "tool_call": {"shellToolCall": {"result": {"rejected": {"command": "rm -rf /",
                                                              "reason": "not trusted"}}}},
     "session_id": session_id},
    {"type": "result", "subtype": "success", "duration_ms": 5, "is_error": False,
     "result": "I can't run that without permission.", "session_id": session_id},
]
for event in events:
    print(json.dumps(event), flush=True)
sys.exit(0)
"""


def _write_fake_cli(directory: Path, body: str) -> Path:
    script = directory / "fake_agent_cli.py"
    script.write_text(body, encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def _event_script(
    events: list[dict],
    *,
    exit_code: int = 0,
    stderr_bytes: int = 0,
    hang_after: float = 0,
) -> str:
    payload = json.dumps(events)
    return f'''#!/usr/bin/env python3
import json, sys, time
events = json.loads({payload!r})
if {stderr_bytes}:
    sys.stderr.write("x" * {stderr_bytes})
    sys.stderr.flush()
for event in events:
    print(json.dumps(event), flush=True)
if {hang_after!r}:
    time.sleep({hang_after!r})
sys.exit({exit_code})
'''


def _init_event(session_id: str = "cursor-sess-test") -> dict:
    return {
        "type": "system",
        "subtype": "init",
        "cwd": ".",
        "session_id": session_id,
        "model": "Auto",
    }


def _result_event(
    text: str = "Done.",
    *,
    session_id: str = "cursor-sess-test",
    is_error: bool = False,
) -> dict:
    return {
        "type": "result",
        "subtype": "error" if is_error else "success",
        "duration_ms": 5,
        "is_error": is_error,
        "result": text,
        "session_id": session_id,
    }


class RunCursorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.previous_sessions = agent_server.STORE.sessions
        self.previous_active = agent_server.ACTIVE
        self.previous_busy = agent_server.BUSY_SESSIONS
        self.previous_current = agent_server.CURRENT_TURNS
        self.previous_stop_requests = agent_server.STOP_REQUESTS
        self.previous_stopped_runs = agent_server.STOPPED_RUNS
        self.previous_queued = agent_server.QUEUED_TURNS
        self.previous_run_now = agent_server.RUN_NOW_TURNS
        self.previous_run_metadata = agent_server.RUN_METADATA
        self.previous_runtime_diagnostics = dict(
            agent_server.RUNTIME_DIAGNOSTICS
        )
        self.previous_runtime_diagnostic_generations = dict(
            agent_server.RUNTIME_DIAGNOSTIC_GENERATIONS
        )
        self.previous_state_dir = agent_server.STATE_DIR
        self.previous_sessions_file = agent_server.SESSIONS_FILE
        self.previous_cursor_bin = agent_server.CURSOR_BIN
        self.previous_startup_timeout = agent_server.CURSOR_STARTUP_TIMEOUT_SECONDS
        self.previous_turn_timeout = agent_server.CURSOR_TURN_TIMEOUT_SECONDS
        self.previous_idle_timeout = agent_server.CURSOR_IDLE_TIMEOUT_SECONDS
        self.previous_idle_warn = agent_server.CURSOR_IDLE_WARN_SECONDS
        self.previous_post_terminal = agent_server.CURSOR_POST_TERMINAL_EXIT_SECONDS
        self.previous_accumulated_text = agent_server.CURSOR_ACCUMULATED_TEXT_MAX_CHARS
        self.previous_max_tool_calls = agent_server.CURSOR_MAX_TOOL_CALLS
        self.previous_max_stream_events = agent_server.CURSOR_MAX_STREAM_EVENTS
        self.previous_max_stream_bytes = agent_server.CURSOR_MAX_STREAM_BYTES

        self.tempdir = tempfile.TemporaryDirectory()
        self.cwd = str(Path(self.tempdir.name) / "workspace")
        os.makedirs(self.cwd, exist_ok=True)
        agent_server.STATE_DIR = Path(self.tempdir.name) / "state"
        agent_server.SESSIONS_FILE = agent_server.STATE_DIR / "sessions.json"

        self.session_id = "chat-cursor-test"
        self.session = {
            "id": self.session_id,
            "backend": agent_server.BACKEND_CURSOR,
            "cwd": self.cwd,
        }
        agent_server.STORE.sessions = {self.session_id: self.session}
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = {self.session_id}
        agent_server.CURRENT_TURNS = {
            self.session_id: {
                "run_id": "run-cursor-1",
                "prompt": "hello",
                "file_ids": [],
                "backend": agent_server.BACKEND_CURSOR,
            }
        }
        agent_server.STOP_REQUESTS = set()
        agent_server.STOPPED_RUNS = set()
        agent_server.QUEUED_TURNS = {}
        agent_server.RUN_NOW_TURNS = {}
        agent_server.RUN_METADATA = {}

    async def asyncTearDown(self) -> None:
        agent_server.STORE.sessions = self.previous_sessions
        agent_server.ACTIVE = self.previous_active
        agent_server.BUSY_SESSIONS = self.previous_busy
        agent_server.CURRENT_TURNS = self.previous_current
        agent_server.STOP_REQUESTS = self.previous_stop_requests
        agent_server.STOPPED_RUNS = self.previous_stopped_runs
        agent_server.QUEUED_TURNS = self.previous_queued
        agent_server.RUN_NOW_TURNS = self.previous_run_now
        agent_server.RUN_METADATA = self.previous_run_metadata
        agent_server.RUNTIME_DIAGNOSTICS.clear()
        agent_server.RUNTIME_DIAGNOSTICS.update(
            self.previous_runtime_diagnostics
        )
        agent_server.RUNTIME_DIAGNOSTIC_GENERATIONS.clear()
        agent_server.RUNTIME_DIAGNOSTIC_GENERATIONS.update(
            self.previous_runtime_diagnostic_generations
        )
        agent_server.STATE_DIR = self.previous_state_dir
        agent_server.SESSIONS_FILE = self.previous_sessions_file
        agent_server.CURSOR_BIN = self.previous_cursor_bin
        agent_server.CURSOR_STARTUP_TIMEOUT_SECONDS = self.previous_startup_timeout
        agent_server.CURSOR_TURN_TIMEOUT_SECONDS = self.previous_turn_timeout
        agent_server.CURSOR_IDLE_TIMEOUT_SECONDS = self.previous_idle_timeout
        agent_server.CURSOR_IDLE_WARN_SECONDS = self.previous_idle_warn
        agent_server.CURSOR_POST_TERMINAL_EXIT_SECONDS = self.previous_post_terminal
        agent_server.CURSOR_ACCUMULATED_TEXT_MAX_CHARS = self.previous_accumulated_text
        agent_server.CURSOR_MAX_TOOL_CALLS = self.previous_max_tool_calls
        agent_server.CURSOR_MAX_STREAM_EVENTS = self.previous_max_stream_events
        agent_server.CURSOR_MAX_STREAM_BYTES = self.previous_max_stream_bytes
        self.tempdir.cleanup()

    def _read_events(self) -> list[dict]:
        path = agent_server.events_path(self.session_id)
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def _arm_run(self, run_id: str, prompt: str = "hello") -> None:
        agent_server.BUSY_SESSIONS.add(self.session_id)
        agent_server.CURRENT_TURNS[self.session_id] = {
            "run_id": run_id,
            "prompt": prompt,
            "file_ids": [],
            "backend": agent_server.BACKEND_CURSOR,
        }

    def test_cursor_mutation_tool_aliases_are_attributed(self) -> None:
        self.assertEqual(
            agent_server.tool_changed_paths({
                "name": "deleteFile",
                "input": {"path": "gone.py"},
            }),
            {"gone.py"},
        )
        self.assertEqual(
            agent_server.tool_changed_paths({
                "name": "renameFile",
                "input": {"old_path": "old.py", "new_path": "new.py"},
            }),
            {"old.py", "new.py"},
        )
        self.assertEqual(
            agent_server.tool_changed_paths({
                "name": "shell",
                "input": {"command": "apply_patch <<'PATCH'\n*** Update File: app.py\nPATCH"},
            }),
            {"app.py"},
        )

    async def _run_script(
        self,
        body: str,
        *,
        run_id: str = "run-cursor-1",
        prompt: str = "hello",
        session_patch: dict | None = None,
        standalone: bool = False,
    ) -> list[dict]:
        script = _write_fake_cli(Path(self.tempdir.name), body)
        runner_session = {**self.session, **(session_patch or {})}
        runner_session["_cursor_executable"] = str(script)
        self._arm_run(run_id, prompt)
        await agent_server.run_cursor(
            self.session_id,
            run_id,
            prompt,
            runner_session,
            Path(self.tempdir.name) / "manifest.json",
            standalone_provider_context=standalone,
        )
        return [
            event
            for event in self._read_events()
            if event.get("run_id") == run_id
        ]

    async def test_full_turn_emits_tool_and_assistant_and_terminal_events(self) -> None:
        script = _write_fake_cli(Path(self.tempdir.name), FAKE_AGENT_CLI)
        self.session["_cursor_executable"] = str(script)

        await agent_server.run_cursor(
            self.session_id,
            "run-cursor-1",
            "hello",
            dict(self.session),
            Path(self.tempdir.name) / "manifest.json",
        )

        events = self._read_events()
        types = [e["type"] for e in events]

        self.assertIn("process_started", types)
        self.assertIn("tool_started", types)
        self.assertIn("tool_finished", types)
        self.assertIn("assistant_text", types)
        self.assertIn("turn_finished", types)

        assistant_events = [e for e in events if e["type"] == "assistant_text"]
        self.assertEqual(assistant_events[0]["text"], "Done.")

        tool_started = next(e for e in events if e["type"] == "tool_started")
        self.assertEqual(tool_started["tool"]["name"], "edit")

        tool_finished = next(e for e in events if e["type"] == "tool_finished")
        self.assertEqual(tool_finished["tool"]["name"], "edit")
        self.assertIn("linesAdded", str(tool_finished["output"]))

        turn_finished = next(e for e in events if e["type"] == "turn_finished")
        self.assertEqual(turn_finished["backend"], agent_server.BACKEND_CURSOR)
        self.assertEqual(turn_finished["exit_code"], 0)
        self.assertEqual(turn_finished["input_tokens"], 10)
        self.assertEqual(turn_finished["output_tokens"], 2)
        self.assertEqual(turn_finished["total_tokens"], 12)

        # persist_run_provider_session should have bound the resumed id.
        self.assertEqual(
            agent_server.STORE.sessions[self.session_id].get("cursor_session_id"),
            "cursor-sess-abc123",
        )
        self.assertEqual(
            len([event for event in events if event["type"] == "provider_session"]),
            1,
        )

        # A successful turn must release the slot it was holding.
        self.assertNotIn(self.session_id, agent_server.BUSY_SESSIONS)
        self.assertNotIn(self.session_id, agent_server.CURRENT_TURNS)

    async def test_composed_prompt_is_delivered_only_over_stdin(self) -> None:
        secret = "AUTHORITY-SENTINEL-STDIN-CURSOR"
        captured = Path(self.tempdir.name) / "captured-prompt.txt"
        script = f'''#!/usr/bin/env python3
import json, pathlib, sys
prompt = sys.stdin.read()
pathlib.Path({str(captured)!r}).write_text(prompt, encoding="utf-8")
session_id = "cursor-sess-test"
print(json.dumps({{"type":"system","subtype":"init","session_id":session_id,"cwd":".","model":"Auto"}}), flush=True)
print(json.dumps({{"type":"result","subtype":"success","is_error":False,"result":"received","session_id":session_id}}), flush=True)
'''
        events = await self._run_script(
            script,
            prompt=f"--model fake\nUnicode ✓\n{secret}",
        )
        started = next(event for event in events if event["type"] == "process_started")
        self.assertNotIn(secret, json.dumps(started["argv"]))
        self.assertNotIn("--model fake", started["argv"])
        written = captured.read_text(encoding="utf-8")
        self.assertIn(secret, written)
        self.assertIn("--model fake", written)
        self.assertIn("Unicode ✓", written)

    async def test_current_lifecycle_events_do_not_abort_or_leak_payloads(self) -> None:
        secret = "LIFECYCLE-SECRET"
        events = await self._run_script(_event_script([
            _init_event(),
            {"type": "retry", "subtype": "starting", "session_id": "cursor-sess-test", "attempt": 1},
            {"type": "connection", "subtype": "reconnecting", "session_id": "cursor-sess-test", "attempt": 2, "endpoint_url": secret},
            {"type": "connection", "subtype": "reconnected", "session_id": "cursor-sess-test"},
            {"type": "interaction_query", "subtype": "request", "session_id": "cursor-sess-test", "query_type": "permission", "query": {"prompt": secret}},
            {"type": "interaction_query", "subtype": "response", "session_id": "cursor-sess-test", "query_type": "permission", "response": {"answer": secret}},
            {"type": "system", "subtype": "task_notification", "session_id": "cursor-sess-test", "title": secret},
            {"type": "system", "subtype": "background_shell_timeout", "session_id": "cursor-sess-test", "aborted_count": 1, "timeout_ms": 1_000},
            _result_event("lifecycle complete"),
        ]))
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertFalse(terminal["is_error"])
        self.assertFalse(any(event["type"] == "raw_event" for event in events))
        self.assertNotIn(secret, json.dumps(events))

    async def test_nonzero_shell_tool_exit_is_preserved(self) -> None:
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "tool_call",
                "subtype": "completed",
                "call_id": "failed-shell",
                "tool_call": {"shellToolCall": {
                    "args": {"command": "false"},
                    "result": {"failure": {"exitCode": 7, "stderr": "failed"}},
                }},
                "session_id": "cursor-sess-test",
            },
            _result_event("handled failure"),
        ]))
        finished = next(event for event in events if event["type"] == "tool_finished")
        self.assertEqual(finished["exit_code"], 7)
        self.assertEqual(finished["tool"]["input"], {"command": "false"})

    async def test_current_tool_timeout_is_not_projected_as_success(self) -> None:
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "tool_call",
                "subtype": "completed",
                "call_id": "timed-out-shell",
                "tool_call": {"shellToolCall": {
                    "args": {"command": "sleep 10"},
                    "result": {"timeout": {
                        "command": "sleep 10",
                        "timeoutMs": 1000,
                    }},
                }},
                "session_id": "cursor-sess-test",
            },
            _result_event("handled timeout"),
        ]))
        finished = next(event for event in events if event["type"] == "tool_finished")
        self.assertEqual(finished["exit_code"], 1)
        self.assertIn("timeoutMs", finished["output"])

    async def test_cache_usage_buckets_count_toward_total_tokens(self) -> None:
        result = _result_event("cached")
        result["usage"] = {
            "inputTokens": 5,
            "outputTokens": 2,
            "cacheReadTokens": 10,
            "cacheWriteTokens": 3,
        }
        events = await self._run_script(_event_script([
            _init_event(),
            result,
        ]))
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertEqual(terminal["input_tokens"], 5)
        self.assertEqual(terminal["cached_input_tokens"], 10)
        self.assertEqual(terminal["cache_write_input_tokens"], 3)
        self.assertEqual(terminal["output_tokens"], 2)
        self.assertEqual(terminal["total_tokens"], 20)

    async def test_unfinished_tool_is_closed_and_turn_fails_protocol(self) -> None:
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "tool_call",
                "subtype": "started",
                "call_id": "open-edit",
                "tool_call": {"writeToolCall": {"args": {"path": "hello.py"}}},
                "session_id": "cursor-sess-test",
            },
            _result_event("premature result"),
        ]))
        finished = next(event for event in events if event["type"] == "tool_finished")
        self.assertEqual(finished["tool_id"], "open-edit")
        self.assertEqual(finished["exit_code"], 1)
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "")

    async def test_write_tool_projects_an_actual_code_diff(self) -> None:
        target = Path(self.cwd) / "hello.py"
        target.write_text("print('before')\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=self.cwd, check=True)
        subprocess.run(["git", "add", "hello.py"], cwd=self.cwd, check=True)
        subprocess.run(
            ["git", "-c", "user.name=AgentsDock Test", "-c",
             "user.email=test@agentsdock.invalid", "commit", "-qm", "baseline"],
            cwd=self.cwd,
            check=True,
        )
        script = f'''#!/usr/bin/env python3
import json, pathlib, sys
sys.stdin.read()
path = {str(target)!r}
pathlib.Path(path).write_text("print('after')\\n", encoding="utf-8")
session_id = "cursor-sess-test"
events = [
  {{"type":"system","subtype":"init","session_id":session_id,"cwd":{self.cwd!r},"model":"Auto"}},
  {{"type":"tool_call","subtype":"started","call_id":"write-1","tool_call":{{"writeToolCall":{{"args":{{"path":path}}}}}},"session_id":session_id}},
  {{"type":"tool_call","subtype":"completed","call_id":"write-1","tool_call":{{"writeToolCall":{{"args":{{"path":path}},"result":{{"success":{{"path":path}}}}}}}},"session_id":session_id}},
  {{"type":"result","subtype":"success","is_error":False,"result":"updated","session_id":session_id}},
]
for event in events:
    print(json.dumps(event), flush=True)
'''
        events = await self._run_script(script, run_id="run-cursor-code-diff")
        diff = next(event for event in events if event["type"] == "code_diff")
        self.assertEqual(diff["attributed_paths"], ["hello.py"])
        self.assertEqual(diff["files_changed"], 1)
        self.assertEqual(diff["diff_files"][0]["path"], "hello.py")

    async def test_rejected_shell_call_is_reported_as_tool_finished_not_dropped(
        self,
    ) -> None:
        script = _write_fake_cli(Path(self.tempdir.name), FAKE_AGENT_CLI_REJECTED_SHELL)
        self.session["_cursor_executable"] = str(script)

        await agent_server.run_cursor(
            self.session_id,
            "run-cursor-1",
            "run rm -rf /",
            dict(self.session),
            Path(self.tempdir.name) / "manifest.json",
        )

        events = self._read_events()
        tool_finished = next(e for e in events if e["type"] == "tool_finished")
        self.assertEqual(tool_finished["tool"]["name"], "shell")
        self.assertEqual(tool_finished["exit_code"], 1)
        self.assertIn("not trusted", tool_finished["output"])

    async def test_cursor_tool_status_is_neutral_not_successful(self) -> None:
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "tool_call",
                "subtype": "started",
                "call_id": "await-1",
                "tool_call": {"awaitToolCall": {"args": {"task": "job-1"}}},
                "session_id": "cursor-sess-test",
            },
            {
                "type": "tool_call",
                "subtype": "completed",
                "call_id": "await-1",
                "tool_call": {"awaitToolCall": {
                    "args": {"task": "job-1"},
                    "result": {"stillRunning": {}},
                }},
                "session_id": "cursor-sess-test",
            },
            _result_event("The task is still running."),
        ]), run_id="run-cursor-neutral-tool-status")

        finished = next(event for event in events if event["type"] == "tool_finished")
        self.assertIsNone(finished["exit_code"])
        self.assertIn("still running", finished["output"].lower())

    async def test_confirmation_required_fails_closed_without_bridge(self) -> None:
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "tool_call",
                "subtype": "started",
                "call_id": "pr-1",
                "tool_call": {"prManagementToolCall": {"args": {}}},
                "session_id": "cursor-sess-test",
            },
            {
                "type": "tool_call",
                "subtype": "completed",
                "call_id": "pr-1",
                "tool_call": {"prManagementToolCall": {
                    "args": {},
                    "result": {"needsConfirmation": {}},
                }},
                "session_id": "cursor-sess-test",
            },
            _result_event("Done."),
        ]), run_id="run-cursor-confirmation-required")

        finished = next(event for event in events if event["type"] == "tool_finished")
        self.assertEqual(finished["exit_code"], 1)
        self.assertIn("requires confirmation", finished["output"].lower())
        error = next(event for event in events if event["type"] == "error")
        self.assertIn("not supported", error["message"].lower())
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])

    async def test_logical_error_exit_zero_is_failed_with_empty_result(self) -> None:
        agent_server.RUN_METADATA["run-cursor-1"] = {
            "purpose": "scheduled_job",
            "job_id": "job-cursor-failure",
        }
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "partial secret"}],
                },
                "session_id": "cursor-sess-test",
            },
            _result_event("provider rejected request", is_error=True),
        ]))

        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "")
        self.assertEqual(
            agent_server.scheduled_job_run_status(terminal),
            "failed",
        )
        self.assertTrue(any(event["type"] == "error" for event in events))

    async def test_logical_auth_failure_marks_runtime_unauthenticated(self) -> None:
        secret = "private-account-identity"
        with patch.object(
            agent_server,
            "cursor_auth_probe_state",
            return_value="unauthenticated",
        ) as confirm:
            events = await self._run_script(_event_script([
                _init_event(),
                _result_event(
                    f"Authentication failed. Please sign in. {secret}",
                    is_error=True,
                ),
            ]), run_id="run-cursor-logical-auth")

        diagnostic = agent_server.RUNTIME_DIAGNOSTICS[
            agent_server.BACKEND_CURSOR
        ]
        self.assertEqual(diagnostic["status"], "unauthenticated")
        self.assertFalse(diagnostic["authenticated"])
        self.assertNotIn(secret, json.dumps(events))
        self.assertNotIn(secret, json.dumps(diagnostic))
        error = next(event for event in events if event["type"] == "error")
        self.assertIn("authentication failed", error["message"].lower())
        confirm.assert_called_once()

    async def test_stderr_auth_failure_marks_runtime_unauthenticated(self) -> None:
        secret = "private-auth-stderr"
        with patch.object(
            agent_server,
            "cursor_auth_probe_state",
            return_value="unauthenticated",
        ) as confirm:
            events = await self._run_script(
                f'''#!/usr/bin/env python3
import json, sys
sys.stdin.read()
print(json.dumps({{"type":"system","subtype":"init","session_id":"cursor-sess-test","cwd":".","model":"Auto"}}), flush=True)
sys.stderr.write("Authentication required. Please sign in. {secret}")
sys.stderr.flush()
sys.exit(7)
''',
                run_id="run-cursor-stderr-auth",
            )

        diagnostic = agent_server.RUNTIME_DIAGNOSTICS[
            agent_server.BACKEND_CURSOR
        ]
        self.assertEqual(diagnostic["status"], "unauthenticated")
        self.assertFalse(diagnostic["authenticated"])
        self.assertNotIn(secret, json.dumps(events))
        self.assertNotIn(secret, json.dumps(diagnostic))
        confirm.assert_called_once()

    async def test_project_auth_text_does_not_disable_cursor_without_confirmation(
        self,
    ) -> None:
        agent_server.store_runtime_diagnostic(
            agent_server.runtime_diagnostic_payload(
                agent_server.BACKEND_CURSOR,
                "ready",
                installed=True,
                authenticated=True,
                executable="/bin/agent",
            )
        )
        script = '''#!/usr/bin/env python3
import json, sys
sys.stdin.read()
print(json.dumps({"type":"system","subtype":"init","session_id":"cursor-sess-test","cwd":".","model":"Auto"}), flush=True)
sys.stderr.write("project says 401 Unauthorized")
sys.stderr.flush()
sys.exit(7)
'''
        with patch.object(
            agent_server,
            "cursor_auth_probe_state",
            return_value="ready",
        ) as confirm:
            events = await self._run_script(
                script,
                run_id="run-cursor-project-401",
            )

        diagnostic = agent_server.RUNTIME_DIAGNOSTICS[
            agent_server.BACKEND_CURSOR
        ]
        self.assertEqual(diagnostic["status"], "ready")
        self.assertTrue(diagnostic["authenticated"])
        error = next(event for event in events if event["type"] == "error")
        self.assertNotIn("authentication failed", error["message"].lower())
        confirm.assert_called_once()

    async def test_project_auth_result_uses_generic_error_when_login_is_ready(
        self,
    ) -> None:
        with patch.object(
            agent_server,
            "cursor_auth_probe_state",
            return_value="ready",
        ) as confirm:
            events = await self._run_script(_event_script([
                _init_event(),
                _result_event(
                    "Project endpoint returned 401 Unauthorized",
                    is_error=True,
                ),
            ]), run_id="run-cursor-project-result-401")

        error = next(event for event in events if event["type"] == "error")
        self.assertEqual(
            error["message"],
            "Cursor reported a logical provider error.",
        )
        confirm.assert_called_once()

    async def test_ambiguous_api_key_failure_is_runtime_error_not_auth_failure(
        self,
    ) -> None:
        with patch.object(
            agent_server,
            "cursor_auth_probe_state",
            return_value="error",
        ) as confirm:
            events = await self._run_script(_event_script([
                _init_event(),
                _result_event("Invalid API key", is_error=True),
            ]), run_id="run-cursor-ambiguous-api-key")

        diagnostic = agent_server.RUNTIME_DIAGNOSTICS[
            agent_server.BACKEND_CURSOR
        ]
        self.assertEqual(diagnostic["status"], "error")
        self.assertIsNone(diagnostic["authenticated"])
        error = next(event for event in events if event["type"] == "error")
        self.assertIn("could not validate", error["message"].lower())
        self.assertNotIn("authentication failed", error["message"].lower())
        confirm.assert_called_once()

    async def test_admitted_executable_is_spawned_without_reresolution(self) -> None:
        with patch.object(
            agent_server,
            "resolve_cursor_executable",
            side_effect=AssertionError("admitted executable must be fenced"),
        ):
            events = await self._run_script(
                _event_script([_init_event(), _result_event("fenced")])
            )

        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertFalse(terminal["is_error"])
        started = next(event for event in events if event["type"] == "process_started")
        self.assertEqual(started["argv"][0], str(Path(self.tempdir.name) / "fake_agent_cli.py"))

    async def test_exit_zero_without_terminal_after_partial_text_fails(self) -> None:
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "partial"}],
                },
                "session_id": "cursor-sess-test",
            },
        ]))

        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "")
        error = next(event for event in events if event["type"] == "error")
        self.assertIn("without a terminal result", error["message"])

    async def test_unknown_schema_after_partial_text_fails_closed(self) -> None:
        sensitive_unknown_payload = "AUTHORITY-SENTINEL-DO-NOT-PERSIST"
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "partial"}],
                },
                "session_id": "cursor-sess-test",
            },
            {
                "type": sensitive_unknown_payload,
                "subtype": sensitive_unknown_payload,
                "session_id": "cursor-sess-test",
                sensitive_unknown_payload: sensitive_unknown_payload,
            },
        ]))

        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "")
        raw_event = next(event for event in events if event["type"] == "raw_event")
        self.assertNotIn(sensitive_unknown_payload, json.dumps(raw_event))
        self.assertNotIn("raw", raw_event)
        self.assertEqual(raw_event["diagnostic"]["json_type"], "dict")
        self.assertTrue(raw_event["diagnostic"]["has_type_field"])
        self.assertTrue(raw_event["diagnostic"]["has_subtype_field"])
        error = next(event for event in events if event["type"] == "error")
        self.assertIn("unsupported stream-json", error["message"])
        self.assertNotIn(sensitive_unknown_payload, json.dumps(error))

    async def test_malformed_stream_and_stderr_cannot_leak_prompt_material(
        self,
    ) -> None:
        secret = "AUTHORITY-SENTINEL-MALFORMED-CURSOR"
        malformed_script = f'''#!/usr/bin/env python3
import json
print(json.dumps({{"type":"system","subtype":"init","session_id":"cursor-sess-test","cwd":".","model":"Auto"}}), flush=True)
print('{{"type":"future_schema","payload":"{secret}"', flush=True)
'''
        with self.assertLogs(agent_server.logger, level="WARNING") as captured:
            events = await self._run_script(
                malformed_script,
                run_id="run-malformed-private",
            )

        raw_event = next(event for event in events if event["type"] == "raw_event")
        terminal = next(event for event in events if event["type"] == "turn_finished")
        error = next(event for event in events if event["type"] == "error")
        self.assertTrue(terminal["is_error"])
        self.assertNotIn(secret, json.dumps(events))
        self.assertNotIn(secret, "\n".join(captured.output))
        self.assertNotIn(secret, json.dumps(raw_event))
        self.assertNotIn(secret, json.dumps(error))
        self.assertNotIn(
            secret,
            json.dumps(
                agent_server.RUNTIME_DIAGNOSTICS.get(
                    agent_server.BACKEND_CURSOR,
                    {},
                )
            ),
        )

        stderr_events = await self._run_script(
            f'''#!/usr/bin/env python3
import json, sys
print(json.dumps({{"type":"system","subtype":"init","session_id":"cursor-sess-test","cwd":".","model":"Auto"}}), flush=True)
sys.stderr.write("{secret}")
sys.stderr.flush()
sys.exit(7)
''',
            run_id="run-stderr-private",
        )
        self.assertNotIn(secret, json.dumps(stderr_events))
        stderr_error = next(
            event for event in stderr_events if event["type"] == "error"
        )
        self.assertIn("stderr was omitted", stderr_error["message"])

    async def test_session_id_is_pinned_across_every_projected_event(self) -> None:
        for event in (
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "wrong"}],
                },
                "session_id": "different-session",
            },
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "missing"}],
                },
            },
        ):
            run_id = "run-" + (event.get("session_id") or "missing")
            events = await self._run_script(
                _event_script([_init_event(), event, _result_event()]),
                run_id=run_id,
            )
            terminal = next(
                item for item in events if item["type"] == "turn_finished"
            )
            self.assertTrue(terminal["is_error"])
            self.assertEqual(terminal["result_text"], "")
            self.assertTrue(any(item["type"] == "error" for item in events))

    async def test_concurrent_stderr_drain_prevents_pipe_deadlock(self) -> None:
        events = await asyncio.wait_for(
            self._run_script(
                _event_script(
                    [_init_event(), _result_event("drained")],
                    stderr_bytes=2 * 1024 * 1024,
                )
            ),
            timeout=5,
        )
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertFalse(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "drained")

    async def test_terminal_event_with_hung_process_is_not_committed_as_resumable(self) -> None:
        agent_server.CURSOR_POST_TERMINAL_EXIT_SECONDS = 0.05
        self.session["backend_locked"] = True
        started = time.monotonic()
        events = await self._run_script(
            _event_script(
                [_init_event(), _result_event("complete before hang")],
                hang_after=10,
            )
        )
        self.assertLess(time.monotonic() - started, 2)
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "")
        self.assertNotIn("cursor_session_id", self.session)
        self.assertTrue(self.session["backend_locked"])
        error = next(event for event in events if event["type"] == "error")
        self.assertIn("did not exit cleanly", error["message"])

    async def test_failed_first_turn_never_commits_a_provisional_cursor_session(self) -> None:
        self.session["backend_locked"] = True
        events = await self._run_script(_event_script([
            _init_event("provisional-cursor-id"),
            _result_event(
                "provider failure",
                session_id="provisional-cursor-id",
                is_error=True,
            ),
        ]))

        self.assertTrue(next(
            event for event in events if event["type"] == "turn_finished"
        )["is_error"])
        self.assertNotIn("cursor_session_id", self.session)
        self.assertNotIn("session_id", self.session)
        self.assertTrue(self.session["backend_locked"])
        self.assertFalse(any(
            event["type"] == "provider_session" for event in events
        ))

    async def test_failed_resumed_turn_preserves_original_cursor_binding(self) -> None:
        self.session.update({
            "backend_locked": True,
            "cursor_session_id": "existing-cursor-id",
            "session_id": "existing-cursor-id",
            "cursor_instruction_hash": "existing-hash",
            "cursor_instruction_version": "existing-version",
        })
        before = dict(self.session)
        events = await self._run_script(_event_script([
            _init_event("existing-cursor-id"),
            _result_event(
                "provider failure",
                session_id="existing-cursor-id",
                is_error=True,
            ),
        ]), session_patch=self.session)

        self.assertTrue(next(
            event for event in events if event["type"] == "turn_finished"
        )["is_error"])
        for key in (
            "backend_locked",
            "cursor_session_id",
            "session_id",
            "cursor_instruction_hash",
            "cursor_instruction_version",
        ):
            self.assertEqual(self.session.get(key), before.get(key))

    async def test_active_cursor_turn_stops_and_releases_process(self) -> None:
        script = _write_fake_cli(
            Path(self.tempdir.name),
            """#!/usr/bin/env python3
import json, time
print(json.dumps({"type":"system","subtype":"init","session_id":"cursor-sess-test","cwd":".","model":"Auto"}), flush=True)
while True:
    print("heartbeat", flush=True)
    time.sleep(0.01)
""",
        )
        runner_session = {**self.session, "_cursor_executable": str(script)}
        self._arm_run("run-cursor-stop")
        task = asyncio.create_task(
            agent_server.run_cursor(
                self.session_id,
                "run-cursor-stop",
                "hello",
                runner_session,
                Path(self.tempdir.name) / "manifest.json",
            )
        )
        try:
            for _ in range(200):
                active = agent_server.ACTIVE.get(self.session_id)
                if active and active.get("provider_turn_ready"):
                    break
                await asyncio.sleep(0.01)
            else:
                self.fail("Cursor runner never reached its active ready state")

            result = await asyncio.wait_for(
                agent_server.stop_turn(
                    self.session_id,
                    schedule_queue=False,
                    cascade_codex_subagents=False,
                    cascade_claude_subagents=False,
                ),
                timeout=3,
            )
            await asyncio.wait_for(task, timeout=3)
        finally:
            if not task.done():
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task

        self.assertTrue(result["stopped"])
        self.assertNotIn(self.session_id, agent_server.ACTIVE)
        self.assertNotIn(self.session_id, agent_server.BUSY_SESSIONS)
        terminal = next(
            event
            for event in self._read_events()
            if event.get("run_id") == "run-cursor-stop"
            and event["type"] == "turn_finished"
        )
        self.assertTrue(terminal["stopped"])
        self.assertFalse(terminal["is_error"])

    async def test_process_endpoint_never_exposes_cursor_prompt_or_user_echo(
        self,
    ) -> None:
        secret = "AUTHORITY-SENTINEL-CURSOR-PROCESS-LEAK"
        script = _write_fake_cli(
            Path(self.tempdir.name),
            """#!/usr/bin/env python3
import json, sys, time
prompt = sys.stdin.read()
session_id = "cursor-sess-test"
print(json.dumps({"type":"system","subtype":"init","session_id":session_id,"cwd":".","model":"Auto"}), flush=True)
print(json.dumps({"type":"user","message":{"role":"user","content":prompt},"session_id":session_id}), flush=True)
while True:
    time.sleep(0.01)
""",
        )
        runner_session = {
            **self.session,
            "system_prompt": f"System {secret}",
            "_cursor_executable": str(script),
        }
        self._arm_run("run-cursor-private")
        task = asyncio.create_task(
            agent_server.run_cursor(
                self.session_id,
                "run-cursor-private",
                f"User {secret}",
                runner_session,
                Path(self.tempdir.name) / "manifest.json",
            )
        )
        try:
            for _ in range(200):
                active = agent_server.ACTIVE.get(self.session_id)
                if active and active.get("provider_turn_ready"):
                    break
                await asyncio.sleep(0.01)
            else:
                self.fail("Cursor runner never reached its active ready state")

            pid = int(active["pid"])
            pgid = int(active["pgid"])
            leaked_args = f"{script} -p --output-format stream-json --trust"
            process_row = {
                "pid": pid,
                "ppid": 1,
                "pgid": pgid,
                "sid": pgid,
                "stat": "S",
                "elapsed_seconds": 1,
                "cpu_percent": 0.0,
                "mem_percent": 0.0,
                "rss_kb": 1024,
                "command": str(script),
                "args": leaked_args,
            }
            with patch.object(
                agent_server,
                "ps_process_rows",
                return_value=[process_row],
            ), patch.object(
                agent_server,
                "proc_cwd",
                return_value=self.cwd,
            ), patch.object(
                agent_server,
                "fd_log_hints",
                return_value=[],
            ):
                snapshot = await agent_server.get_session_processes(
                    self.session_id
                )
        finally:
            await agent_server.stop_turn(
                self.session_id,
                emit_event=False,
                schedule_queue=False,
                cascade_codex_subagents=False,
                cascade_claude_subagents=False,
            )
            await asyncio.wait_for(task, timeout=3)

        serialized = json.dumps(snapshot)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("AgentsDock provider instructions", serialized)
        self.assertNotIn("<prompt>", serialized)
        self.assertTrue(snapshot["processes"][0]["args_redacted"])
        self.assertNotIn(secret, snapshot["stdout_tail"]["text"])
        self.assertNotIn("Current user prompt", snapshot["stdout_tail"]["text"])

    async def test_cursor_prebind_stop_hard_terminalizes_stale_runner(self) -> None:
        self._arm_run("run-cursor-prebind")

        async def never_binds() -> None:
            await asyncio.Future()

        stale_runner = asyncio.create_task(never_binds())
        turn_tasks = {self.session_id: {stale_runner}}
        try:
            with patch.object(agent_server, "SESSION_TURN_TASKS", turn_tasks), patch.object(
                agent_server,
                "STOP_CONFIRM_TIMEOUT_SECONDS",
                0.02,
            ):
                result = await agent_server.stop_turn(
                    self.session_id,
                    schedule_queue=False,
                    cascade_codex_subagents=False,
                    cascade_claude_subagents=False,
                )
        finally:
            if not stale_runner.done():
                stale_runner.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await stale_runner

        self.assertTrue(result["stopped"])
        self.assertTrue(result["hard_stop"])
        self.assertNotIn(self.session_id, agent_server.BUSY_SESSIONS)
        stopped = next(
            event
            for event in self._read_events()
            if event.get("run_id") == "run-cursor-prebind"
            and event["type"] == "turn_stopped"
        )
        self.assertEqual(stopped["backend"], agent_server.BACKEND_CURSOR)

    async def test_cursor_does_not_deliver_prompt_when_binding_is_stale(self) -> None:
        script = _write_fake_cli(
            Path(self.tempdir.name),
            "#!/usr/bin/env python3\nimport sys, time\nsys.stdin.read()\ntime.sleep(60)\n",
        )
        runner_session = {**self.session, "_cursor_executable": str(script)}
        self._arm_run("run-cursor-stale-bind", "do not deliver")

        with patch.object(
            agent_server,
            "bind_active_turn",
            return_value=(False, False),
        ), patch.object(
            agent_server,
            "write_cursor_process_stdin",
        ) as write_stdin:
            await asyncio.wait_for(
                agent_server.run_cursor(
                    self.session_id,
                    "run-cursor-stale-bind",
                    "do not deliver",
                    runner_session,
                    Path(self.tempdir.name) / "manifest.json",
                ),
                timeout=3,
            )

        write_stdin.assert_not_awaited()

    async def test_cursor_cancelled_during_binding_cleans_up_without_prompt(self) -> None:
        child_pid_file = Path(self.tempdir.name) / "prebind-child.pid"
        script = _write_fake_cli(
            Path(self.tempdir.name),
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys, time\n"
            f"pathlib.Path({str(child_pid_file)!r}).write_text(str(os.getpid()))\n"
            "sys.stdin.read()\n"
            "time.sleep(60)\n",
        )
        runner_session = {**self.session, "_cursor_executable": str(script)}
        self._arm_run("run-cursor-cancelled-bind", "do not deliver")
        bind_entered = asyncio.Event()

        async def blocked_bind(*_args: object, **_kwargs: object) -> tuple[bool, bool]:
            bind_entered.set()
            await asyncio.Future()

        with patch.object(
            agent_server,
            "bind_active_turn",
            side_effect=blocked_bind,
        ), patch.object(
            agent_server,
            "write_cursor_process_stdin",
        ) as write_stdin:
            task = asyncio.create_task(agent_server.run_cursor(
                self.session_id,
                "run-cursor-cancelled-bind",
                "do not deliver",
                runner_session,
                Path(self.tempdir.name) / "manifest.json",
            ))
            await asyncio.wait_for(bind_entered.wait(), timeout=2)
            deadline = time.monotonic() + 2
            while not child_pid_file.exists() and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            self.assertTrue(child_pid_file.exists())
            child_pid = int(child_pid_file.read_text())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=3)

        write_stdin.assert_not_awaited()
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            await asyncio.sleep(0.02)
        else:
            try:
                os.kill(child_pid, 9)
            except ProcessLookupError:
                pass
            self.fail("Cursor child survived cancellation during bind")

    async def test_cursor_does_not_deliver_prompt_for_a_preexisting_stop(self) -> None:
        script = _write_fake_cli(
            Path(self.tempdir.name),
            "#!/usr/bin/env python3\nimport sys, time\nsys.stdin.read()\ntime.sleep(60)\n",
        )
        runner_session = {**self.session, "_cursor_executable": str(script)}
        self._arm_run("run-cursor-prestopped", "do not deliver")
        agent_server.STOP_REQUESTS.add(self.session_id)

        with patch.object(
            agent_server,
            "write_cursor_process_stdin",
        ) as write_stdin:
            await asyncio.wait_for(
                agent_server.run_cursor(
                    self.session_id,
                    "run-cursor-prestopped",
                    "do not deliver",
                    runner_session,
                    Path(self.tempdir.name) / "manifest.json",
                ),
                timeout=3,
            )

        write_stdin.assert_not_awaited()

    async def test_startup_timeout_fails_and_releases_turn(self) -> None:
        agent_server.CURSOR_STARTUP_TIMEOUT_SECONDS = 0.05
        agent_server.CURSOR_TURN_TIMEOUT_SECONDS = 1
        events = await self._run_script(
            """#!/usr/bin/env python3
import time
time.sleep(10)
"""
        )
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "")
        self.assertNotIn(self.session_id, agent_server.BUSY_SESSIONS)

    async def test_absolute_timeout_applies_despite_continuous_output(self) -> None:
        agent_server.CURSOR_STARTUP_TIMEOUT_SECONDS = 0.2
        agent_server.CURSOR_TURN_TIMEOUT_SECONDS = 0.15
        events = await self._run_script(
            """#!/usr/bin/env python3
import json, time
print(json.dumps({"type":"system","subtype":"init","session_id":"cursor-sess-test","cwd":".","model":"Auto"}), flush=True)
while True:
    print("heartbeat", flush=True)
    time.sleep(0.01)
"""
        )
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        error = next(event for event in events if event["type"] == "error")
        self.assertIn("absolute turn timeout", error["message"])

    async def test_pending_live_cross_chat_wait_pauses_cursor_watchdogs(self) -> None:
        agent_server.CURSOR_STARTUP_TIMEOUT_SECONDS = 0.05
        agent_server.CURSOR_TURN_TIMEOUT_SECONDS = 0.05
        agent_server.CURSOR_IDLE_WARN_SECONDS = 0.01
        agent_server.CURSOR_IDLE_TIMEOUT_SECONDS = 0.03
        with patch.object(
            agent_server,
            "provider_run_owns_pending_cross_chat_live_wait",
            return_value=True,
        ):
            events = await self._run_script(
                """#!/usr/bin/env python3
import json, sys, time
sys.stdin.read()
session_id = "cursor-sess-test"
print(json.dumps({"type":"system","subtype":"init","session_id":session_id,"cwd":".","model":"Auto"}), flush=True)
time.sleep(0.12)
print(json.dumps({"type":"result","subtype":"success","is_error":False,"result":"peer answered","session_id":session_id}), flush=True)
"""
            )

        terminal = next(
            event for event in events if event["type"] == "turn_finished"
        )
        self.assertFalse(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "peer answered")
        self.assertFalse(any(
            event["type"] in {"error", "idle_warning"}
            for event in events
        ))

    async def test_idle_warning_is_emitted_once_per_idle_period(self) -> None:
        agent_server.CURSOR_IDLE_WARN_SECONDS = 0.02
        agent_server.CURSOR_IDLE_TIMEOUT_SECONDS = 0.12
        events = await self._run_script(
            """#!/usr/bin/env python3
import json, sys, time
sys.stdin.read()
print(json.dumps({"type":"system","subtype":"init","session_id":"cursor-sess-test","cwd":".","model":"Auto"}), flush=True)
time.sleep(5)
"""
        )
        warnings = [event for event in events if event["type"] == "idle_warning"]
        self.assertEqual(len(warnings), 1)
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])

    async def test_missing_runtime_is_a_failed_terminal(self) -> None:
        self._arm_run("run-cursor-1")
        with patch.object(agent_server, "resolve_cursor_executable", return_value=None):
            await agent_server.run_cursor(
                self.session_id,
                "run-cursor-1",
                "hello",
                dict(self.session),
                Path(self.tempdir.name) / "manifest.json",
            )
        events = self._read_events()
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "")

    async def test_spawn_failure_is_a_failed_terminal(self) -> None:
        runner = {
            **self.session,
            "_cursor_executable": str(Path(self.tempdir.name) / "missing-agent"),
        }
        self._arm_run("run-cursor-1")
        await agent_server.run_cursor(
            self.session_id,
            "run-cursor-1",
            "hello",
            runner,
            Path(self.tempdir.name) / "manifest.json",
        )
        terminal = next(
            event
            for event in self._read_events()
            if event["type"] == "turn_finished"
        )
        self.assertTrue(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "")

    async def test_tool_state_and_payloads_are_bounded(self) -> None:
        huge_id = "call-" + ("z" * 235)
        huge_args = {"nested": {"value": "a" * 100_000}}
        huge_reason = "r" * 100_000
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "tool_call",
                "subtype": "started",
                "call_id": huge_id,
                "tool_call": {"shellToolCall": {"args": huge_args}},
                "session_id": "cursor-sess-test",
            },
            {
                "type": "tool_call",
                "subtype": "completed",
                "call_id": huge_id,
                "tool_call": {
                    "shellToolCall": {
                        "result": {"rejected": {"reason": huge_reason}}
                    }
                },
                "session_id": "cursor-sess-test",
            },
            {
                "type": "tool_call",
                "subtype": "completed",
                "call_id": "without-start",
                "tool_call": {
                    (("n" * 1000) + "ToolCall"): {
                        "result": {"success": {"output": "o" * 100_000}}
                    }
                },
                "session_id": "cursor-sess-test",
            },
            _result_event(),
        ]))
        started = next(event for event in events if event["type"] == "tool_started")
        self.assertLessEqual(len(started["tool"]["id"]), 240)
        self.assertLess(len(json.dumps(started["tool"]["input"])), 20_000)
        completed = [event for event in events if event["type"] == "tool_finished"]
        self.assertTrue(completed)
        self.assertTrue(all(len(event["tool_id"]) <= 240 for event in completed))
        self.assertTrue(all(len(event["tool"]["name"]) <= 240 for event in completed))
        self.assertTrue(all(len(str(event["output"])) < 150_000 for event in completed))

    async def test_invalid_tool_call_id_fails_closed_without_projection(self) -> None:
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "tool_call",
                "subtype": "started",
                "tool_call": {"readToolCall": {"args": {"path": "a"}}},
                "session_id": "cursor-sess-test",
            },
            _result_event(),
        ]))
        self.assertFalse(any(event["type"] == "tool_started" for event in events))
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "")

    async def test_tool_cardinality_ceiling_fails_visibly(self) -> None:
        agent_server.CURSOR_MAX_TOOL_CALLS = 2
        tool_events = []
        for index in range(3):
            tool_events.append({
                "type": "tool_call",
                "subtype": "started",
                "call_id": f"call-{index}",
                "tool_call": {"readToolCall": {"args": {"path": str(index)}}},
                "session_id": "cursor-sess-test",
            })
        events = await self._run_script(
            _event_script([_init_event(), *tool_events, _result_event()])
        )
        self.assertEqual(
            len([event for event in events if event["type"] == "tool_started"]),
            2,
        )
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        self.assertEqual(terminal["result_text"], "")

    async def test_stream_event_ceiling_bounds_durable_output(self) -> None:
        agent_server.CURSOR_MAX_STREAM_EVENTS = 3
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "thinking",
                "subtype": "delta",
                "text": "one",
                "session_id": "cursor-sess-test",
            },
            {
                "type": "thinking",
                "subtype": "delta",
                "text": "two",
                "session_id": "cursor-sess-test",
            },
            {
                "type": "thinking",
                "subtype": "delta",
                "text": "three",
                "session_id": "cursor-sess-test",
            },
            _result_event(),
        ]))
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertTrue(terminal["is_error"])
        # Deltas are buffered into one reasoning block, so the ceiling is
        # asserted on retained content rather than event count: the two
        # deltas admitted before the ceiling are published, and the third
        # one never reaches durable output.
        reasoning = [
            event for event in events if event["type"] == "reasoning_summary"
        ]
        self.assertEqual(len(reasoning), 1)
        self.assertEqual(reasoning[0]["text"], "onetwo")
        self.assertNotIn("three", reasoning[0]["text"])

    async def test_thinking_deltas_publish_one_block_per_completed_thought(
        self,
    ) -> None:
        # Cursor streams reasoning token-by-token. Publishing each delta as
        # its own durable event made one thought render as a burst of
        # answer-looking blocks that the timeline then reconciled away
        # (the "reasoning flashes then disappears" report).
        def delta(text: str) -> dict:
            return {
                "type": "thinking",
                "subtype": "delta",
                "text": text,
                "session_id": "cursor-sess-test",
            }

        events = await self._run_script(_event_script([
            _init_event(),
            delta("The user wants "),
            delta("a logo, so I "),
            delta("will draft one."),
            {
                "type": "thinking",
                "subtype": "completed",
                "session_id": "cursor-sess-test",
            },
            delta("Second thought."),
            {
                "type": "thinking",
                "subtype": "completed",
                "session_id": "cursor-sess-test",
            },
            _result_event(),
        ]))

        reasoning = [
            event for event in events if event["type"] == "reasoning_summary"
        ]
        self.assertEqual(len(reasoning), 2)
        self.assertEqual(
            reasoning[0]["text"],
            "The user wants a logo, so I will draft one.",
        )
        self.assertEqual(reasoning[1]["text"], "Second thought.")

    async def test_buffered_reasoning_is_published_before_the_answer(
        self,
    ) -> None:
        # Cursor does not always send `thinking/completed`; the pending
        # thought must still reach the timeline, and must stay ordered
        # before the answer it produced.
        events = await self._run_script(_event_script([
            _init_event(),
            {
                "type": "thinking",
                "subtype": "delta",
                "text": "Working it out.",
                "session_id": "cursor-sess-test",
            },
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Here it is."}],
                },
                "session_id": "cursor-sess-test",
            },
            _result_event("Here it is."),
        ]))

        ordered = [
            event["type"] for event in events
            if event["type"] in {"reasoning_summary", "assistant_text"}
        ]
        self.assertEqual(ordered, ["reasoning_summary", "assistant_text"])
        reasoning = next(
            event for event in events if event["type"] == "reasoning_summary"
        )
        self.assertEqual(reasoning["text"], "Working it out.")

    async def test_accumulated_assistant_fallback_is_bounded(self) -> None:
        agent_server.CURSOR_ACCUMULATED_TEXT_MAX_CHARS = 10
        assistant = lambda text: {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": text}],
            },
            "session_id": "cursor-sess-test",
        }
        events = await self._run_script(
            _event_script([
                _init_event(),
                assistant("abcdefgh"),
                assistant("ijklmnop"),
                _result_event(""),
            ])
        )
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertFalse(terminal["is_error"])
        self.assertLessEqual(len(terminal["result_text"]), 10)

    async def test_standalone_turn_does_not_mutate_parent_provider_state(self) -> None:
        parent = agent_server.STORE.sessions[self.session_id]
        parent.update({
            "cursor_session_id": "parent-cursor-id",
            "session_id": "parent-cursor-id",
            "cursor_instruction_hash": "parent-hash",
            "cursor_instruction_version": "old-version",
            "memory_seed": "parent memory",
            "memory_seed_used": False,
        })
        before = dict(parent)
        events = await self._run_script(
            _event_script([_init_event("standalone-id"), _result_event(
                "standalone",
                session_id="standalone-id",
            )]),
            session_patch=before,
            standalone=True,
        )
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertFalse(terminal["is_error"])
        for key in (
            "session_id",
            "cursor_session_id",
            "cursor_instruction_hash",
            "cursor_instruction_version",
            "memory_seed_used",
        ):
            self.assertEqual(parent.get(key), before.get(key))

    async def test_start_turn_pins_the_compatibility_probed_cursor_executable(self) -> None:
        pinned = str(Path(self.tempdir.name) / "verified-cursor-agent")
        captured_session: dict = {}

        async def capture_cursor(
            _session_id: str,
            _run_id: str,
            _prompt: str,
            runner_session: dict,
            _manifest_path: Path,
            **_kwargs: object,
        ) -> None:
            captured_session.update(runner_session)

        agent_server.BUSY_SESSIONS.clear()
        agent_server.CURRENT_TURNS.clear()
        with patch.object(
            agent_server,
            "ensure_runtime_available",
            return_value={"status": "ready", "_executable": pinned},
        ), patch.object(
            agent_server,
            "run_cursor",
            side_effect=capture_cursor,
        ), patch.object(
            agent_server,
            "resolve_cursor_executable",
        ) as resolve_cursor, patch.object(
            agent_server,
            "scrub_tmux_global_secret_environment",
        ):
            await agent_server.start_turn(
                self.session_id,
                agent_server.TurnRequest(
                    prompt="Use the admitted Cursor executable",
                    backend=agent_server.BACKEND_CURSOR,
                ),
            )
            for _ in range(300):
                if captured_session:
                    break
                await asyncio.sleep(0.01)
            else:
                self.fail("Cursor runner was not scheduled")
            for _ in range(300):
                if self.session_id not in agent_server.BUSY_SESSIONS:
                    break
                await asyncio.sleep(0.01)

        self.assertEqual(captured_session.get("_cursor_executable"), pinned)
        resolve_cursor.assert_not_called()

    async def test_start_turn_scheduled_standalone_cursor_override_isolated_from_parent(
        self,
    ) -> None:
        script = _write_fake_cli(
            Path(self.tempdir.name),
            _event_script([
                _init_event("standalone-cursor-job"),
                _result_event(
                    "scheduled standalone complete",
                    session_id="standalone-cursor-job",
                ),
            ]),
        )
        parent = agent_server.STORE.sessions[self.session_id]
        parent.update({
            "title": "Claude parent",
            "backend": agent_server.BACKEND_CLAUDE,
            "backend_locked": True,
            "session_id": "claude-parent-provider",
            "claude_session_id": "claude-parent-provider",
            "cursor_session_id": None,
            "cursor_instruction_hash": "parked-cursor-hash",
            "cursor_instruction_version": "parked-version",
            "memory_seed": "parent memory remains untouched",
            "memory_seed_used": False,
        })
        before = dict(parent)
        agent_server.BUSY_SESSIONS.clear()
        agent_server.CURRENT_TURNS.clear()

        with patch.object(
            agent_server,
            "ensure_runtime_available",
            return_value={
                "status": "ready",
                "_executable": str(script),
            },
        ), patch.object(
            agent_server,
            "scrub_tmux_global_secret_environment",
        ):
            admitted = await agent_server.start_turn(
                self.session_id,
                agent_server.TurnRequest(
                    prompt="Run scheduled Cursor work",
                    backend=agent_server.BACKEND_CURSOR,
                    purpose="scheduled_job",
                    job_id="job-cursor-standalone",
                ),
                provider_context_mode="standalone",
            )
            for _ in range(500):
                if self.session_id not in agent_server.BUSY_SESSIONS:
                    break
                await asyncio.sleep(0.01)
            else:
                self.fail("standalone Cursor job did not reach terminal state")

        self.assertFalse(admitted["queued"])
        events = [
            event
            for event in self._read_events()
            if event.get("run_id") == admitted["run_id"]
        ]
        terminal = next(event for event in events if event["type"] == "turn_finished")
        self.assertFalse(terminal["is_error"])
        self.assertEqual(terminal["backend"], agent_server.BACKEND_CURSOR)
        self.assertEqual(terminal["job_context_mode"], "standalone")
        for key in (
            "backend",
            "backend_locked",
            "session_id",
            "claude_session_id",
            "cursor_session_id",
            "cursor_instruction_hash",
            "cursor_instruction_version",
            "memory_seed_used",
        ):
            self.assertEqual(parent.get(key), before.get(key))

    async def test_failed_policy_and_fork_memory_are_reinjected_until_success(
        self,
    ) -> None:
        session = agent_server.STORE.sessions[self.session_id]
        session.update({
            "system_prompt": "Always preserve the test contract.",
            "memory_seed": "bounded fork memory sentinel",
            "memory_seed_used": False,
        })
        captured_prompts: list[str] = []
        real_write_cursor_stdin = agent_server.write_cursor_process_stdin

        async def capture_stdin(proc: object, provider_prompt: str) -> None:
            captured_prompts.append(provider_prompt)
            await real_write_cursor_stdin(proc, provider_prompt)

        with patch.object(
            agent_server,
            "write_cursor_process_stdin",
            side_effect=capture_stdin,
        ):
            failed = await self._run_script(
                _event_script([
                    _init_event(),
                    _result_event("provider failure", is_error=True),
                ]),
                run_id="run-policy-failed",
                session_patch=session,
            )
            self.assertTrue(next(
                event for event in failed if event["type"] == "turn_finished"
            )["is_error"])
            self.assertFalse(session["memory_seed_used"])
            self.assertNotIn("cursor_instruction_hash", session)

            succeeded = await self._run_script(
                _event_script([_init_event(), _result_event("success")]),
                run_id="run-policy-success",
                session_patch=session,
            )
            self.assertFalse(next(
                event for event in succeeded if event["type"] == "turn_finished"
            )["is_error"])
            self.assertTrue(session["memory_seed_used"])
            self.assertIn("cursor_instruction_hash", session)

            resumed = await self._run_script(
                _event_script([_init_event(), _result_event("resumed")]),
                run_id="run-policy-resumed",
                session_patch=session,
            )
            self.assertFalse(next(
                event for event in resumed if event["type"] == "turn_finished"
            )["is_error"])

        self.assertEqual(len(captured_prompts), 3)
        self.assertIn("Always preserve the test contract.", captured_prompts[0])
        self.assertIn("bounded fork memory sentinel", captured_prompts[0])
        self.assertIn("Always preserve the test contract.", captured_prompts[1])
        self.assertIn("bounded fork memory sentinel", captured_prompts[1])
        self.assertNotIn("[AgentsDock provider instructions]", captured_prompts[2])
        self.assertNotIn("bounded fork memory sentinel", captured_prompts[2])


class CursorFileDeliveryInstructionTests(unittest.TestCase):
    def test_instructions_route_file_delivery_around_blocked_shell(self) -> None:
        # Real failure this guards (observed in a live chat): Cursor
        # generated an image, its publish command was rejected four times by
        # the permission policy, and it told the user to open the file from
        # disk instead - the image never reached the chat. Writing the
        # manifest needs no shell, so it must be named as the route to use
        # when the publish command cannot run.
        manifest = Path("/tmp/agentsdock-state/sessions/chat-x/manifest.json")
        instructions = agent_server.cursor_provider_instructions(
            "chat-x", {}, manifest
        )

        self.assertIn(str(manifest), instructions)
        self.assertIn('{"files":["/absolute/path.ext"]}', instructions)
        self.assertIn("needs no shell", instructions)
        self.assertIn("generated images", instructions)

    def test_instruction_hash_changes_so_live_sessions_reinject(self) -> None:
        # Instructions are only re-sent when their hash changes, so a policy
        # text change has to move the hash or existing chats keep running on
        # the old guidance forever.
        manifest = Path("/tmp/agentsdock-state/sessions/chat-x/manifest.json")
        with patch.object(
            agent_server,
            "CURSOR_FILE_DELIVERY_ADDENDUM",
            "Delivering files: old guidance.\n",
        ):
            previous = agent_server.cursor_instruction_hash(
                "chat-x", {}, manifest
            )
        current = agent_server.cursor_instruction_hash("chat-x", {}, manifest)
        self.assertNotEqual(previous, current)


if __name__ == "__main__":
    unittest.main()
