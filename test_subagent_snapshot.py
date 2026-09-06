import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

import agent_server


class ClaudeSubagentSnapshotTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.previous_state_dir = agent_server.STATE_DIR
        agent_server.STATE_DIR = Path(self.temporary.name)
        self.session_id = "claude-chat"

    def tearDown(self) -> None:
        agent_server.STATE_DIR = self.previous_state_dir
        self.temporary.cleanup()

    def write_events(self, events: list[dict[str, object]]) -> None:
        path = agent_server.events_path(self.session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")

    def event(self, seq: int, event_type: str, *, run_id: str = "run-1", **fields: object) -> dict[str, object]:
        return {
            "seq": seq,
            "id": f"event-{seq}",
            "session_id": self.session_id,
            "run_id": run_id,
            "type": event_type,
            "ts": f"2026-07-21T00:00:00.{seq:06d}Z",
            **fields,
        }

    def raw(self, seq: int, payload: dict[str, object], *, run_id: str = "run-1") -> dict[str, object]:
        return self.event(
            seq,
            "raw_event",
            run_id=run_id,
            backend="claude",
            raw=json.dumps(payload),
        )

    def test_projects_background_agent_lifecycle_without_raw_prompt_or_output(self) -> None:
        prompt_secret = "PROMPT_SECRET_DO_NOT_EXPOSE"
        command_secret = "COMMAND_SECRET_DO_NOT_EXPOSE"
        output_secret = "OUTPUT_SECRET_DO_NOT_EXPOSE"
        events = [
            self.event(1, "tool_started", tool={
                "id": "tool-agent",
                "name": "Agent",
                "input": {
                    "description": "Audit the renderer",
                    "subagent_type": "code-explorer",
                    "run_in_background": True,
                    "prompt": prompt_secret,
                },
            }),
            self.raw(2, {
                "type": "system",
                "subtype": "background_tasks_changed",
                "tasks": [{
                    "task_id": "task-1",
                    "task_type": "local_agent",
                    "description": "Audit the renderer",
                }],
            }),
            self.raw(3, {
                "type": "system",
                "subtype": "task_started",
                "task_id": "task-1",
                "tool_use_id": "tool-agent",
                "task_type": "local_agent",
                "subagent_type": "code-explorer",
                "description": "Audit the renderer",
                "prompt": prompt_secret,
            }),
            self.event(4, "tool_finished", tool_id="tool-agent", tool={
                "id": "tool-agent",
                "name": "Agent",
                "input": {"run_in_background": True},
            }, output=output_secret, is_error=False),
            self.raw(5, {
                "type": "assistant",
                "parent_tool_use_id": "tool-agent",
                "message": {"content": [{
                    "type": "tool_use",
                    "name": "Bash",
                    "input": {"description": "Run timeline tests", "command": command_secret},
                }]},
            }),
            self.raw(6, {
                "type": "assistant",
                "parent_tool_use_id": "tool-agent",
                "message": {"content": [{"type": "text", "text": output_secret}]},
            }),
            self.raw(7, {
                "type": "system",
                "subtype": "task_progress",
                "task_id": "task-1",
                "tool_use_id": "tool-agent",
                "subagent_type": "code-explorer",
                "description": "Reading the inspector",
            }),
            self.raw(8, {
                "type": "system",
                "subtype": "task_notification",
                "task_id": "task-1",
                "tool_use_id": "tool-agent",
                "status": "completed",
                "summary": "Found the state race",
                "output_file": f"/tmp/{output_secret}",
                "output": output_secret,
            }),
            self.event(9, "turn_finished", exit_code=0),
        ]
        self.write_events(events)

        snapshot = agent_server.build_claude_subagent_snapshot(self.session_id)

        self.assertEqual(snapshot["count"], 1)
        self.assertEqual(snapshot["active_count"], 0)
        self.assertEqual(snapshot["latest_seq"], 9)
        subagent = snapshot["subagents"][0]
        self.assertEqual(subagent["subagent_id"], "task-1")
        self.assertEqual(subagent["subagent_tool_id"], "tool-agent")
        self.assertEqual(subagent["subagent_name"], "Audit the renderer")
        self.assertEqual(subagent["subagent_kind"], "code-explorer")
        self.assertEqual(subagent["subagent_status"], "completed")
        self.assertEqual(subagent["subagent_summary"], "Found the state race")
        log = [entry["text"] for entry in subagent["subagent_log"]]
        self.assertIn("Run timeline tests", log)
        self.assertIn("Reading the inspector", log)
        self.assertIn("Found the state race", log)
        serialized = json.dumps(snapshot)
        self.assertNotIn("raw_event", serialized)
        self.assertNotIn(prompt_secret, serialized)
        self.assertNotIn(command_secret, serialized)
        self.assertNotIn(output_secret, serialized)

    def test_recovers_orphan_progress_and_notification_but_ignores_local_bash(self) -> None:
        events = [
            self.raw(1, {
                "type": "system",
                "subtype": "task_progress",
                "task_id": "orphan-progress",
                "tool_use_id": "orphan-tool",
                "subagent_type": "general-purpose",
                "description": "Inspecting files",
            }),
            self.raw(2, {
                "type": "system",
                "subtype": "task_notification",
                "task_id": "orphan-progress",
                "tool_use_id": "orphan-tool",
                "status": "completed",
                "summary": "Inspection complete",
            }),
            self.event(3, "tool_started", tool={
                "id": "known-agent-tool",
                "name": "Agent",
                "input": {"description": "Recover notification", "run_in_background": True},
            }),
            self.raw(4, {
                "type": "system",
                "subtype": "task_notification",
                "task_id": "notification-only",
                "tool_use_id": "known-agent-tool",
                "status": "failed",
                "summary": "Agent failed safely",
            }),
            self.raw(5, {
                "type": "system",
                "subtype": "task_started",
                "task_id": "bash-task",
                "tool_use_id": "bash-tool",
                "task_type": "local_bash",
                "description": "Background shell",
            }),
            self.raw(6, {
                "type": "system",
                "subtype": "task_progress",
                "task_id": "bash-task",
                "tool_use_id": "bash-tool",
                "description": "Still running shell",
            }),
            self.raw(7, {
                "type": "system",
                "subtype": "task_notification",
                "task_id": "bash-task",
                "tool_use_id": "bash-tool",
                "status": "completed",
                "summary": "Shell complete",
            }),
        ]
        self.write_events(events)

        snapshot = agent_server.build_claude_subagent_snapshot(self.session_id)
        by_id = {item["subagent_id"]: item for item in snapshot["subagents"]}

        self.assertEqual(set(by_id), {"orphan-progress", "notification-only"})
        self.assertEqual(by_id["orphan-progress"]["subagent_status"], "completed")
        self.assertEqual(by_id["notification-only"]["subagent_status"], "failed")
        self.assertEqual(by_id["notification-only"]["subagent_tool_id"], "known-agent-tool")

    def test_native_async_ack_and_task_updates_drive_status_without_exposing_ack_output(self) -> None:
        ack_secret = "NATIVE_ASYNC_ACK_OUTPUT_SECRET"
        events = [
            self.event(1, "tool_started", tool={
                "id": "native-tool",
                "name": "Agent",
                "input": {"description": "Native async agent", "subagent_type": "Explore"},
            }),
            self.raw(2, {
                "type": "system",
                "subtype": "task_started",
                "task_id": "native-task",
                "tool_use_id": "native-tool",
                "task_type": "local_agent",
                "subagent_type": "Explore",
                "description": "Native async agent",
            }),
            self.event(3, "tool_finished", tool_id="native-tool", tool={
                "id": "native-tool", "name": "Agent", "input": {"description": "Native async agent"},
            }, output=ack_secret, is_error=False),
        ]
        self.write_events(events)

        running = agent_server.build_claude_subagent_snapshot(self.session_id)["subagents"][0]
        self.assertEqual(running["subagent_status"], "running")
        self.assertNotIn(ack_secret, json.dumps(running))

        events.append(self.raw(4, {
            "type": "system",
            "subtype": "task_updated",
            "task_id": "native-task",
            "patch": {"status": "pending"},
        }))
        self.write_events(events)
        pending = agent_server.build_claude_subagent_snapshot(self.session_id)["subagents"][0]
        self.assertEqual(pending["subagent_status"], "starting")

        events.append(self.raw(5, {
            "type": "system",
            "subtype": "task_updated",
            "task_id": "native-task",
            "patch": {
                "status": "in_progress",
                "progress": {"summary": "Scanning the repository"},
                "last_tool_name": "Read",
            },
        }))
        self.write_events(events)
        progressing = agent_server.build_claude_subagent_snapshot(self.session_id)["subagents"][0]
        self.assertEqual(progressing["subagent_status"], "running")
        self.assertEqual(progressing["subagent_activity"], "Scanning the repository")

        events.append(self.raw(6, {
            "type": "system",
            "subtype": "task_updated",
            "task_id": "native-task",
            "patch": {"last_tool_name": "Grep"},
        }))
        self.write_events(events)
        using_tool = agent_server.build_claude_subagent_snapshot(self.session_id)["subagents"][0]
        self.assertEqual(using_tool["subagent_activity"], "Using Grep")

        events.append(self.raw(7, {
            "type": "system",
            "subtype": "task_updated",
            "task_id": "native-task",
            "patch": {"status": "killed", "end_time": 1784592454084},
        }))
        self.write_events(events)
        stopped = agent_server.build_claude_subagent_snapshot(self.session_id)["subagents"][0]
        self.assertEqual(stopped["subagent_status"], "stopped")

    def test_parent_terminal_events_preserve_background_agents_after_success(self) -> None:
        events = [
            self.event(1, "tool_started", run_id="run-ok", tool={
                "id": "ok-tool", "name": "Agent", "input": {"description": "Okay agent", "run_in_background": True},
            }),
            self.event(2, "turn_finished", run_id="run-ok", exit_code=0),
            self.raw(3, {
                "type": "system", "subtype": "task_progress", "task_id": "failed-task",
                "subagent_type": "Explore", "description": "Working",
            }, run_id="run-failed"),
            self.event(4, "error", run_id="run-failed", message="parent failed"),
            self.raw(5, {
                "type": "system", "subtype": "background_tasks_changed",
                "tasks": [{"task_id": "stopped-task", "task_type": "local_agent", "description": "Stop me"}],
            }, run_id="run-stopped"),
            self.event(6, "turn_stopped", run_id="run-stopped"),
        ]
        self.write_events(events)

        snapshot = agent_server.build_claude_subagent_snapshot(self.session_id)
        by_run = {item["run_id"]: item for item in snapshot["subagents"]}

        self.assertEqual(by_run["run-ok"]["subagent_status"], "starting")
        self.assertEqual(by_run["run-failed"]["subagent_status"], "failed")
        self.assertEqual(by_run["run-stopped"]["subagent_status"], "stopped")
        self.assertEqual(snapshot["active_count"], 1)

    def test_idle_stop_marker_terminalizes_prior_background_agents(self) -> None:
        events = [
            self.event(1, "tool_started", run_id="run-parent", tool={
                "id": "agent-tool",
                "name": "Agent",
                "input": {
                    "description": "Background worker",
                    "run_in_background": True,
                },
            }),
            self.event(2, "turn_finished", run_id="run-parent", exit_code=0),
            self.event(
                3,
                "claude_subagents_stopped",
                run_ids=["run-parent"],
                subagent_ids=["agent-tool"],
                **{"all": True},
            ),
        ]
        self.write_events(events)

        snapshot = agent_server.build_claude_subagent_snapshot(self.session_id)

        self.assertEqual(snapshot["active_count"], 0)
        self.assertEqual(
            snapshot["subagents"][0]["subagent_status"],
            "stopped",
        )

    def test_snapshot_bounds_states_logs_and_endpoint_limit(self) -> None:
        events: list[dict[str, object]] = []
        seq = 0
        for index in range(agent_server.SUBAGENT_SNAPSHOT_STATE_LIMIT + 14):
            seq += 1
            events.append(self.event(seq, "tool_started", run_id=f"run-{index}", tool={
                "id": f"tool-{index}",
                "name": "Agent",
                "input": {"description": f"Agent {index}", "run_in_background": True},
            }))
        for index in range(agent_server.SUBAGENT_SNAPSHOT_LOG_LIMIT + 25):
            seq += 1
            events.append(self.raw(seq, {
                "type": "system",
                "subtype": "task_progress",
                "task_id": "latest-task",
                "tool_use_id": f"tool-{agent_server.SUBAGENT_SNAPSHOT_STATE_LIMIT + 13}",
                "subagent_type": "Explore",
                "description": f"Step {index}",
            }, run_id=f"run-{agent_server.SUBAGENT_SNAPSHOT_STATE_LIMIT + 13}"))
        self.write_events(events)

        snapshot = agent_server.build_claude_subagent_snapshot(self.session_id, limit=5)

        self.assertEqual(snapshot["count"], agent_server.SUBAGENT_SNAPSHOT_STATE_LIMIT)
        self.assertEqual(len(snapshot["subagents"]), 5)
        latest = next(item for item in snapshot["subagents"] if item["subagent_id"] == "latest-task")
        self.assertEqual(len(latest["subagent_log"]), agent_server.SUBAGENT_SNAPSHOT_LOG_LIMIT)
        self.assertEqual(latest["subagent_log"][-1]["text"], f"Step {agent_server.SUBAGENT_SNAPSHOT_LOG_LIMIT + 24}")

    async def test_snapshot_omits_silently_learned_state_without_event_identity(self) -> None:
        session_id = "codex-chat"
        with patch.dict(agent_server.STORE.sessions, {
            session_id: {"id": session_id, "backend": agent_server.BACKEND_CODEX},
        }, clear=True), patch.dict(
            agent_server.CODEX_SUBAGENT_STATE, {}, clear=True
        ), patch.dict(
            agent_server.CODEX_SUBAGENT_SESSION_INDEX, {}, clear=True
        ):
            learned = await agent_server.emit_codex_subagent_state(
                session_id,
                "terminal-child",
                "completed",
                activity="Subagent completed",
                persist_event=False,
            )

            self.assertNotIn("seq", learned or {})
            self.assertNotIn("id", learned or {})
            snapshot = agent_server.build_subagent_snapshot(session_id)

        self.assertEqual(snapshot["count"], 1)
        self.assertEqual(snapshot["active_count"], 0)
        self.assertEqual(snapshot["latest_seq"], 0)
        self.assertEqual(snapshot["subagents"], [])

    def test_sanitized_sdk_lifecycle_completes_background_agent(self) -> None:
        self.write_events([
            self.event(1, "tool_started", tool={
                "id": "agent-tool",
                "name": "Agent",
                "input": {"description": "Review the server", "run_in_background": True},
            }),
            self.event(2, "raw_event", backend=agent_server.BACKEND_CLAUDE, raw=json.dumps({
                "type": "user",
                "tool_use_result": {
                    "status": "async_launched",
                    "isAsync": True,
                    "agentId": "task-1",
                    "task_id": "",
                },
                "message": {"content": [{
                    "type": "tool_result",
                    "tool_use_id": "agent-tool",
                }]},
            })),
            self.event(3, "raw_event", backend=agent_server.BACKEND_CLAUDE, raw=json.dumps({
                "type": "system",
                "subtype": "task_started",
                "task_id": "task-1",
                "tool_use_id": "agent-tool",
                "task_type": "local_agent",
                "description": "Review the server",
            })),
            self.event(4, "raw_event", backend=agent_server.BACKEND_CLAUDE, raw=json.dumps({
                "type": "system",
                "subtype": "task_progress",
                "task_id": "task-1",
                "description": "Running tests",
                "last_tool_name": "Bash",
            })),
            self.event(5, "raw_event", backend=agent_server.BACKEND_CLAUDE, raw=json.dumps({
                "type": "system",
                "subtype": "task_updated",
                "task_id": "task-1",
                "patch": {"status": "completed", "summary": "Review complete"},
            })),
        ])

        snapshot = agent_server.build_claude_subagent_snapshot(self.session_id)

        self.assertEqual(snapshot["active_count"], 0)
        self.assertEqual(len(snapshot["subagents"]), 1)
        self.assertEqual(snapshot["subagents"][0]["subagent_status"], "completed")
        self.assertEqual(
            snapshot["subagents"][0]["subagent_summary"],
            "Review complete",
        )

    async def test_endpoint_offloads_snapshot_and_rejects_unknown_sessions(self) -> None:
        self.write_events([])
        original_to_thread = asyncio.to_thread
        offload = AsyncMock(side_effect=original_to_thread)
        with patch.dict(agent_server.STORE.sessions, {self.session_id: {"id": self.session_id}}, clear=True), patch.object(
            agent_server.asyncio,
            "to_thread",
            new=offload,
        ):
            response = await agent_server.get_session_subagents(self.session_id, limit=12)
            with self.assertRaises(HTTPException) as raised:
                await agent_server.get_session_subagents("missing", limit=12)

        self.assertEqual(response["subagents"], [])
        self.assertEqual(offload.await_count, 1)
        self.assertIs(offload.await_args.args[0], agent_server.build_subagent_snapshot)
        self.assertEqual(offload.await_args.args[1:], (self.session_id, 12))
        self.assertEqual(raised.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
