import asyncio
import json
import tempfile
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

import agent_server


class CodexGoalsAdminTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.previous_enabled = agent_server.CODEX_GOALS_ENABLED
        self.previous_reconfiguring = agent_server.CODEX_GOALS_RECONFIGURING
        self.previous_manager = agent_server.CODEX_APP_SERVER_MANAGER
        self.previous_sessions = agent_server.STORE.sessions
        self.previous_busy = agent_server.BUSY_SESSIONS
        self.previous_active = agent_server.ACTIVE
        self.previous_current = agent_server.CURRENT_TURNS
        self.previous_maintenance = agent_server.SERVER_MAINTENANCE_SESSIONS
        self.previous_queued = agent_server.QUEUED_TURNS
        self.previous_run_now = agent_server.RUN_NOW_TURNS
        self.previous_pending = agent_server.CODEX_PENDING_INTERACTIONS
        self.previous_actions = agent_server.CODEX_NATIVE_ACTION_TASKS
        self.previous_subagents = agent_server.CODEX_SUBAGENT_STATE
        self.previous_subagent_index = agent_server.CODEX_SUBAGENT_SESSION_INDEX
        self.previous_live_generations = (
            agent_server.CODEX_SUBAGENT_LIVE_GENERATIONS
        )

        agent_server.CODEX_GOALS_ENABLED = True
        agent_server.CODEX_GOALS_RECONFIGURING = False
        agent_server.CODEX_APP_SERVER_MANAGER = None
        agent_server.STORE.sessions = {
            "chat": {
                "id": "chat",
                "backend": agent_server.BACKEND_CODEX,
                "codex_thread_id": "thread",
                "codex_goal": {
                    "objective": "Finish the work",
                    "status": "active",
                },
            }
        }
        agent_server.BUSY_SESSIONS = set()
        agent_server.ACTIVE = {}
        agent_server.CURRENT_TURNS = {}
        agent_server.SERVER_MAINTENANCE_SESSIONS = set()
        agent_server.QUEUED_TURNS = {}
        agent_server.RUN_NOW_TURNS = {}
        agent_server.CODEX_PENDING_INTERACTIONS = {}
        agent_server.CODEX_NATIVE_ACTION_TASKS = {}
        agent_server.CODEX_SUBAGENT_STATE = {}
        agent_server.CODEX_SUBAGENT_SESSION_INDEX = {}
        agent_server.CODEX_SUBAGENT_LIVE_GENERATIONS = {}

    async def asyncTearDown(self) -> None:
        agent_server.CODEX_GOALS_ENABLED = self.previous_enabled
        agent_server.CODEX_GOALS_RECONFIGURING = self.previous_reconfiguring
        agent_server.CODEX_APP_SERVER_MANAGER = self.previous_manager
        agent_server.STORE.sessions = self.previous_sessions
        agent_server.BUSY_SESSIONS = self.previous_busy
        agent_server.ACTIVE = self.previous_active
        agent_server.CURRENT_TURNS = self.previous_current
        agent_server.SERVER_MAINTENANCE_SESSIONS = self.previous_maintenance
        agent_server.QUEUED_TURNS = self.previous_queued
        agent_server.RUN_NOW_TURNS = self.previous_run_now
        agent_server.CODEX_PENDING_INTERACTIONS = self.previous_pending
        agent_server.CODEX_NATIVE_ACTION_TASKS = self.previous_actions
        agent_server.CODEX_SUBAGENT_STATE = self.previous_subagents
        agent_server.CODEX_SUBAGENT_SESSION_INDEX = self.previous_subagent_index
        agent_server.CODEX_SUBAGENT_LIVE_GENERATIONS = (
            self.previous_live_generations
        )

    async def test_admin_endpoint_direct_invocation_repeats_native_auth(self) -> None:
        request = Request({
            "type": "http",
            "method": "PUT",
            "path": "/api/admin/codex/goals",
            "headers": [
                (b"x-agentsdock-token", b"test-secret"),
                (b"x-zenithdock-token", b"test-secret"),
            ],
            "query_string": b"",
            "scheme": "http",
            "server": ("127.0.0.1", 7850),
            "client": ("127.0.0.1", 41000),
        })
        with patch.object(agent_server, "AGENT_TOKEN", "test-secret"):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.put_codex_goals_admin_endpoint(
                    agent_server.CodexGoalsAdminRequest(enabled=False),
                    request,
                )

        self.assertEqual(raised.exception.status_code, 401)

    def test_admin_routes_reject_query_and_browser_credentials_before_parsing(self) -> None:
        with patch.object(agent_server, "AGENT_TOKEN", "test-secret"):
            client = TestClient(agent_server.app)
            cases = (
                ("GET", "/api/admin/codex/goals?token=test-secret", {}, None, 401),
                (
                    "PUT",
                    "/api/admin/codex/goals?token=test-secret",
                    {"Content-Type": "application/json"},
                    b"{",
                    401,
                ),
                (
                    "GET",
                    "/api/admin/codex/goals",
                    {
                        "Origin": "https://attacker.example",
                        "X-AgentsDock-Token": "test-secret",
                    },
                    None,
                    403,
                ),
                (
                    "PUT",
                    "/api/admin/codex/goals",
                    {
                        "Origin": "https://attacker.example",
                        "X-AgentsDock-Token": "test-secret",
                        "Content-Type": "application/json",
                    },
                    b"{",
                    403,
                ),
            )
            for method, path, headers, body, expected in cases:
                with self.subTest(method=method, path=path, expected=expected):
                    response = client.request(
                        method,
                        path,
                        headers=headers,
                        content=body,
                    )

                    self.assertEqual(response.status_code, expected)

    def test_admin_routes_require_exactly_one_supported_token_header(self) -> None:
        cases = (
            [("Authorization", "Bearer test-secret")],
            [
                ("X-AgentsDock-Token", "test-secret"),
                ("X-AgentsDock-Token", "test-secret"),
            ],
            [
                ("X-AgentsDock-Token", "test-secret"),
                ("X-ZenithDock-Token", "test-secret"),
            ],
        )
        with patch.object(agent_server, "AGENT_TOKEN", "test-secret"):
            client = TestClient(agent_server.app)
            for headers in cases:
                with self.subTest(headers=headers):
                    response = client.get(
                        "/api/admin/codex/goals",
                        headers=headers,
                    )

                    self.assertEqual(response.status_code, 401)

    def test_admin_put_has_exact_small_json_transport_contract(self) -> None:
        cases = (
            (
                {
                    "X-AgentsDock-Token": "test-secret",
                    "Content-Type": "text/plain",
                },
                b'{"enabled":true}',
                415,
            ),
            (
                {
                    "X-AgentsDock-Token": "test-secret",
                    "Content-Type": "application/json",
                    "Transfer-Encoding": "chunked",
                },
                b'{"enabled":true}',
                400,
            ),
            (
                {
                    "X-AgentsDock-Token": "test-secret",
                    "Content-Type": "application/json",
                    # This endpoint has one boolean field; 256 bytes leaves
                    # ample wire-format headroom without permitting an
                    # attacker-controlled generic JSON allocation.
                    "Content-Length": "257",
                },
                b'{"enabled":true}',
                413,
            ),
        )
        with patch.object(agent_server, "AGENT_TOKEN", "test-secret"):
            client = TestClient(agent_server.app)
            for headers, body, expected in cases:
                with self.subTest(headers=headers, expected=expected):
                    response = client.put(
                        "/api/admin/codex/goals",
                        headers=headers,
                        content=body,
                    )

                    self.assertEqual(response.status_code, expected)

    def test_admin_routes_keep_both_current_native_client_headers(self) -> None:
        with patch.object(agent_server, "AGENT_TOKEN", "test-secret"):
            client = TestClient(agent_server.app)
            for name in ("X-AgentsDock-Token", "X-ZenithDock-Token"):
                with self.subTest(header=name):
                    response = client.get(
                        "/api/admin/codex/goals",
                        headers={name: "test-secret"},
                    )

                    self.assertEqual(response.status_code, 200)

    def test_setting_defaults_enabled_and_reads_persisted_choice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "codex-settings.json"
            self.assertEqual(
                agent_server.read_codex_goals_enabled(path),
                agent_server.CODEX_GOALS_DEFAULT_ENABLED,
            )
            path.write_text(json.dumps({"goals_enabled": False}))
            self.assertFalse(agent_server.read_codex_goals_enabled(path))

    async def test_disabling_pauses_goals_restarts_manager_and_persists(self) -> None:
        async def pause_goal(_session_id: str) -> dict[str, bool]:
            agent_server.STORE.sessions["chat"]["codex_goal"]["status"] = "paused"
            return {"goal_paused": True}

        with tempfile.TemporaryDirectory() as temporary:
            settings_file = Path(temporary) / "admin" / "codex-settings.json"
            with (
                patch.object(agent_server, "CODEX_SETTINGS_FILE", settings_file),
                patch.object(
                    agent_server,
                    "settle_idle_codex_goal_for_stop",
                    AsyncMock(side_effect=pause_goal),
                ) as settle,
                patch.object(
                    agent_server,
                    "close_codex_app_server_manager",
                    AsyncMock(),
                ) as close_manager,
            ):
                result = await agent_server.put_codex_goals_admin(
                    agent_server.CodexGoalsAdminRequest(enabled=False)
                )

            self.assertFalse(result["enabled"])
            self.assertTrue(result["configurable"])
            self.assertFalse(result["reconfiguring"])
            self.assertEqual(result["paused_goal_count"], 1)
            self.assertFalse(json.loads(settings_file.read_text())["goals_enabled"])
            settle.assert_awaited_once_with("chat")
            close_manager.assert_awaited_once()

    async def test_disabling_does_not_load_ordinary_codex_threads(self) -> None:
        for index in range(500):
            agent_server.STORE.sessions[f"ordinary-{index}"] = {
                "id": f"ordinary-{index}",
                "backend": agent_server.BACKEND_CODEX,
                "codex_thread_id": f"thread-{index}",
                "codex_goal": None,
            }
        agent_server.STORE.sessions["chat"]["codex_goal"]["status"] = "paused"
        settle = AsyncMock(return_value={})

        with patch.object(
            agent_server,
            "settle_idle_codex_goal_for_stop",
            settle,
        ):
            result = await agent_server.pause_idle_codex_goals_before_disable()

        self.assertEqual(result, {
            "paused_goal_count": 0,
            "fenced_goal_count": 0,
        })
        settle.assert_awaited_once_with("chat")

    async def test_disabling_checks_only_loaded_uncached_provider_threads(self) -> None:
        agent_server.STORE.sessions["chat"]["codex_goal"] = None
        agent_server.STORE.sessions["ordinary"] = {
            "id": "ordinary",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "unloaded-thread",
            "codex_goal": None,
        }
        manager = Mock()
        manager.is_thread_loaded.side_effect = (
            lambda thread_id: thread_id == "thread"
        )
        agent_server.CODEX_APP_SERVER_MANAGER = manager
        settle = AsyncMock(return_value={})

        with patch.object(
            agent_server,
            "settle_idle_codex_goal_for_stop",
            settle,
        ):
            await agent_server.pause_idle_codex_goals_before_disable()

        settle.assert_awaited_once_with("chat")

    async def test_change_is_rejected_while_codex_work_is_active(self) -> None:
        agent_server.BUSY_SESSIONS.add("chat")
        agent_server.CURRENT_TURNS["chat"] = {
            "backend": agent_server.BACKEND_CODEX,
        }

        with self.assertRaises(HTTPException) as raised:
            await agent_server.put_codex_goals_admin(
                agent_server.CodexGoalsAdminRequest(enabled=False)
            )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("active or queued", str(raised.exception.detail))
        self.assertFalse(agent_server.CODEX_GOALS_RECONFIGURING)
        self.assertTrue(agent_server.CODEX_GOALS_ENABLED)

    async def test_change_is_rejected_while_codex_work_is_queued(self) -> None:
        agent_server.QUEUED_TURNS["chat"] = deque([
            {
                "queued_id": "queued-1",
                "backend": agent_server.BACKEND_CODEX,
            }
        ])

        with self.assertRaises(HTTPException) as raised:
            await agent_server.put_codex_goals_admin(
                agent_server.CodexGoalsAdminRequest(enabled=False)
            )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("queued Codex turn", str(raised.exception.detail))
        self.assertFalse(agent_server.CODEX_GOALS_RECONFIGURING)

    async def test_live_subagent_blocks_change_but_completed_history_does_not(
        self,
    ) -> None:
        agent_server.CODEX_SUBAGENT_STATE = {
            "running-child": {
                "session_id": "chat",
                "subagent_status": "running",
            },
            "finished-child": {"subagent_status": "done"},
        }
        manager = Mock(ready=True, generation=7)
        manager.active_turn.return_value = None
        agent_server.CODEX_APP_SERVER_MANAGER = manager
        agent_server.CODEX_SUBAGENT_LIVE_GENERATIONS = {
            "running-child": 7,
        }
        with self.assertRaises(HTTPException) as raised:
            await agent_server.reserve_codex_goals_reconfiguration()
        self.assertIn("running-child", str(raised.exception.detail))
        self.assertNotIn("finished-child", str(raised.exception.detail))

    async def test_stale_running_subagent_does_not_block_change(self) -> None:
        agent_server.CODEX_SUBAGENT_STATE = {
            "stale-child": {
                "session_id": "chat",
                "subagent_status": "running",
            },
        }

        await agent_server.reserve_codex_goals_reconfiguration()

        self.assertTrue(agent_server.CODEX_GOALS_RECONFIGURING)
        await agent_server.release_codex_goals_reconfiguration()

    async def test_goal_mutation_is_rejected_when_disabled(self) -> None:
        agent_server.CODEX_GOALS_ENABLED = False
        acquire = AsyncMock()
        with patch.object(
            agent_server,
            "acquire_codex_control_thread",
            acquire,
        ):
            with self.assertRaises(HTTPException) as raised:
                await agent_server._put_codex_goal_locked(
                    "chat",
                    agent_server.CodexGoalRequest(
                        objective="A new objective",
                    ),
                )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("disabled", str(raised.exception.detail))
        acquire.assert_not_awaited()

    async def test_goal_budget_does_not_block_turns_when_goals_are_disabled(
        self,
    ) -> None:
        session = agent_server.STORE.sessions["chat"]
        session["codex_goal_time_budget_seconds"] = 1
        session["codex_goal_time_budget_exhausted"] = True
        agent_server.CODEX_GOALS_ENABLED = False

        self.assertFalse(
            agent_server.provider_context_goal_is_exhausted(session, "chat")
        )

    async def test_health_advertises_the_effective_goal_capability(self) -> None:
        agent_server.CODEX_GOALS_ENABLED = False
        with (
            patch.object(agent_server, "host_pressure_snapshot", return_value={}),
            patch.object(
                agent_server,
                "tmux_capability",
                return_value={"available": False},
            ),
            patch.object(agent_server, "runtime_diagnostics_snapshot", return_value={}),
        ):
            response = await agent_server.health()

        self.assertFalse(
            response["capabilities"]["codex_controls"]["features"]["goals"]
        )

    async def test_disabled_manager_launches_with_native_goal_feature_off(self) -> None:
        agent_server.CODEX_GOALS_ENABLED = False
        manager = Mock()
        manager.add_notification_handler = Mock()
        with patch.object(
            agent_server,
            "CodexAppServerManager",
            return_value=manager,
        ) as manager_type:
            created = await agent_server.codex_app_server_manager()

        self.assertIs(created, manager)
        self.assertEqual(
            manager_type.call_args.kwargs["app_server_args"],
            ("--disable", "goals"),
        )

    def test_exec_command_applies_native_goal_feature_off(self) -> None:
        agent_server.CODEX_GOALS_ENABLED = False

        command = agent_server.build_codex_cmd(
            "chat",
            agent_server.STORE.sessions["chat"],
            "Do the work",
            Path("/tmp/current.json"),
        )

        self.assertEqual(command[:4], [
            agent_server.CODEX_BIN,
            "exec",
            "--disable",
            "goals",
        ])

    def test_exec_command_omits_goal_override_when_enabled(self) -> None:
        command = agent_server.build_codex_cmd(
            "chat",
            agent_server.STORE.sessions["chat"],
            "Do the work",
            Path("/tmp/current.json"),
        )

        self.assertNotIn("goals", command)

    async def test_handoff_summarizer_applies_native_goal_feature_off(self) -> None:
        agent_server.CODEX_GOALS_ENABLED = False
        process = Mock(returncode=0)
        process.communicate = AsyncMock(return_value=(
            b'{"type":"item.completed","item":{"type":"agent_message","text":"Summary"}}\n',
            b"",
        ))
        with patch.object(
            agent_server.asyncio,
            "create_subprocess_exec",
            AsyncMock(return_value=process),
        ) as create_process:
            result = await agent_server.run_codex_handoff_summarizer(
                "Summarize",
                model=None,
                effort=None,
            )

        self.assertEqual(result, "Summary")
        self.assertEqual(
            create_process.await_args.args[:4],
            (agent_server.CODEX_BIN, "exec", "--disable", "goals"),
        )

    async def test_manager_creation_waits_for_goal_reconfiguration(self) -> None:
        entered_close = asyncio.Event()
        release_close = asyncio.Event()

        async def delayed_close() -> None:
            entered_close.set()
            await release_close.wait()

        manager = Mock()
        manager.add_notification_handler = Mock()
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(
                    agent_server,
                    "CODEX_SETTINGS_FILE",
                    Path(temporary) / "codex-settings.json",
                ),
                patch.object(
                    agent_server,
                    "pause_idle_codex_goals_before_disable",
                    AsyncMock(return_value={
                        "paused_goal_count": 0,
                        "fenced_goal_count": 0,
                    }),
                ),
                patch.object(
                    agent_server,
                    "close_codex_app_server_manager",
                    AsyncMock(side_effect=delayed_close),
                ),
                patch.object(
                    agent_server,
                    "CodexAppServerManager",
                    return_value=manager,
                ) as manager_type,
            ):
                reconfigure = asyncio.create_task(
                    agent_server.put_codex_goals_admin(
                        agent_server.CodexGoalsAdminRequest(enabled=False)
                    )
                )
                await entered_close.wait()
                create_manager = asyncio.create_task(
                    agent_server.codex_app_server_manager()
                )
                await asyncio.sleep(0)
                self.assertFalse(create_manager.done())
                release_close.set()
                await reconfigure
                self.assertIs(await create_manager, manager)

        self.assertEqual(
            manager_type.call_args.kwargs["app_server_args"],
            ("--disable", "goals"),
        )

    async def test_compaction_metadata_closes_and_rejects_late_duplicate_start(
        self,
    ) -> None:
        start = {
            "seq": 10,
            "type": "codex_compaction_started",
            "ts": "2026-08-02T12:00:00Z",
            "operation_id": "compact-1",
            "thread_id": "thread",
            "run_id": "compact-1",
        }
        completed = {
            **start,
            "seq": 11,
            "type": "codex_compaction_completed",
            "ts": "2026-08-02T12:00:01Z",
            "status": "completed",
        }
        late_duplicate = {
            **start,
            "seq": 12,
            "ts": "2026-08-02T12:00:02Z",
        }
        with patch.object(agent_server.STORE, "save", AsyncMock()):
            await agent_server.update_session_event_metadata("chat", start)
            self.assertIn(
                "codex:compaction:compact-1",
                agent_server.STORE.sessions["chat"][
                    "_active_codex_compactions"
                ],
            )
            await agent_server.update_session_event_metadata("chat", completed)
            await agent_server.update_session_event_metadata(
                "chat",
                late_duplicate,
            )

        session = agent_server.STORE.sessions["chat"]
        self.assertNotIn("_active_codex_compactions", session)
        self.assertIn(
            "codex:compaction:compact-1",
            session["_codex_compaction_terminal_keys"],
        )

    async def test_start_only_compaction_is_recovered_after_restart(self) -> None:
        agent_server.STORE.sessions["chat"]["_active_codex_compactions"] = {
            "codex:compaction:compact-1": {
                "lifecycle_key": "codex:compaction:compact-1",
                "operation_id": "compact-1",
                "thread_id": "thread",
                "run_id": "compact-1",
                "started_seq": 10,
                "started_at": "2026-08-02T12:00:00Z",
            },
        }
        recorded: list[dict[str, object]] = []

        async def append_recovery(
            session_id: str,
            event_type: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            event = {
                "seq": 11,
                "type": event_type,
                "ts": "2026-08-02T12:00:01Z",
                **payload,
            }
            recorded.append(event)
            await agent_server.update_session_event_metadata(session_id, event)
            return event

        with (
            patch.object(agent_server, "append_event", side_effect=append_recovery),
            patch.object(agent_server.STORE, "save", AsyncMock()),
        ):
            recovered = (
                await agent_server.recover_abandoned_codex_compactions_after_start()
            )

        self.assertEqual(recovered, 1)
        self.assertEqual(recorded[0]["type"], "codex_compaction_completed")
        self.assertEqual(recorded[0]["status"], "interrupted")
        self.assertTrue(recorded[0]["recovered_after_restart"])
        self.assertNotIn(
            "_active_codex_compactions",
            agent_server.STORE.sessions["chat"],
        )


if __name__ == "__main__":
    unittest.main()
