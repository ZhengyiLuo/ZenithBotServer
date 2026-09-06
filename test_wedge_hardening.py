"""Regression tests for the 2026-09-04 wedge: fenced queues, hung Stop, retry
storms, health-poll reconcile spam, and update-when-idle lockout."""

import asyncio
import json
import os
import tempfile
import tracemalloc
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import BackgroundTasks, HTTPException

import agent_server
from test_server_restart_endpoints import (
    http_request,
    restart_body,
    restart_environment,
)


def utc(offset_seconds: float = 0.0) -> str:
    moment = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class QueueFenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_reconcile_skips_and_names_explicit_stop_fence(self):
        never = asyncio.get_running_loop().create_future()
        stop_operation = asyncio.ensure_future(never)
        try:
            with patch.object(
                agent_server,
                "EXPLICIT_STOP_OPERATIONS",
                {"chat": stop_operation},
            ), patch.object(
                agent_server,
                "QUEUED_TURNS",
                {"chat": agent_server.deque([{"queued_id": "q1", "_durable": True}])},
            ), patch.object(agent_server, "QUEUE_FENCE_LOGGED_AT", {}), \
                 patch.object(
                     agent_server,
                     "schedule_next_queued_turn",
                 ) as schedule, \
                 self.assertLogs(agent_server.logger, level="WARNING") as logs:
                repaired = await agent_server.reconcile_idle_queue_session(
                    "chat",
                    schedule=True,
                    reason="health_poll",
                )
                # A second reconcile within the log interval stays quiet.
                await agent_server.reconcile_idle_queue_session(
                    "chat",
                    schedule=True,
                    reason="health_poll",
                )
        finally:
            never.cancel()
        self.assertFalse(repaired)
        schedule.assert_not_called()
        fence_lines = [
            line for line in logs.output if "queue promotion fenced" in line
        ]
        self.assertEqual(len(fence_lines), 1)
        self.assertIn("fence=explicit_stop", fence_lines[0])
        self.assertIn("session=chat", fence_lines[0])

    async def test_reconcile_names_server_restart_fence(self):
        with patch.object(
            agent_server,
            "managed_server_update_blocker",
            return_value=agent_server.MANAGED_SERVER_RESTART_ACTIVE_DETAIL,
        ), patch.object(agent_server, "EXPLICIT_STOP_OPERATIONS", {}):
            self.assertEqual(
                agent_server.queue_promotion_fence("chat"),
                "server_restart",
            )
        with patch.object(
            agent_server,
            "managed_server_update_blocker",
            return_value=agent_server.MANAGED_SERVER_UPDATE_ACTIVE_DETAIL,
        ), patch.object(agent_server, "EXPLICIT_STOP_OPERATIONS", {}):
            self.assertEqual(
                agent_server.queue_promotion_fence("chat"),
                "server_update",
            )
        with patch.object(
            agent_server,
            "managed_server_update_blocker",
            return_value=None,
        ), patch.object(agent_server, "EXPLICIT_STOP_OPERATIONS", {}):
            self.assertIsNone(agent_server.queue_promotion_fence("chat"))

    async def test_routine_idle_reconcile_logs_at_debug_only(self):
        with patch.object(
            agent_server,
            "QUEUED_TURNS",
            {"chat": agent_server.deque([{"queued_id": "q1", "_durable": True}])},
        ), patch.object(agent_server, "EXPLICIT_STOP_OPERATIONS", {}), \
             patch.object(agent_server, "RUN_NOW_REQUESTS", {}), \
             patch.object(agent_server, "QUEUE_START_TASKS", {}), \
             patch.object(agent_server, "STEERING_WAIT_TASKS", {}), \
             patch.object(agent_server, "STEERING_SESSIONS", set()), \
             patch.object(agent_server, "RUN_NOW_TURNS", {}), \
             patch.object(agent_server, "ACTIVE", {}), \
             patch.object(agent_server, "BUSY_SESSIONS", set()), \
             patch.object(agent_server, "CURRENT_TURNS", {}), \
             patch.object(
                 agent_server,
                 "managed_server_update_blocker",
                 return_value=None,
             ), \
             patch.object(agent_server, "schedule_next_queued_turn") as schedule, \
             self.assertNoLogs(agent_server.logger, level="INFO"):
            repaired = await agent_server.reconcile_idle_queue_session(
                "chat",
                schedule=True,
                reason="health_poll",
            )
        self.assertTrue(repaired)
        schedule.assert_called_once_with("chat")


class RetryTimerTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_one_retry_timer_is_armed_per_chat(self):
        with patch.object(agent_server, "QUEUE_RETRY_TASKS", {}) as timers, \
             patch.object(
                 agent_server,
                 "start_next_queued_turn",
                 new=AsyncMock(),
             ) as start:
            self.assertTrue(agent_server.schedule_queued_turn_retry("chat", 5))
            self.assertFalse(agent_server.schedule_queued_turn_retry("chat", 5))
            self.assertFalse(agent_server.schedule_queued_turn_retry("chat", 5))
            self.assertEqual(len(timers), 1)
            timers["chat"].cancel()
            await asyncio.gather(timers["chat"], return_exceptions=True)
            await asyncio.sleep(0)
            self.assertNotIn("chat", timers)
            start.assert_not_called()
            # Once the previous timer settled a new one may be armed.
            self.assertTrue(agent_server.schedule_queued_turn_retry("chat", 5))
            timers["chat"].cancel()
            await asyncio.gather(timers["chat"], return_exceptions=True)


class HealthReconcileTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_poll_reconcile_is_rate_limited(self):
        with patch.object(
            agent_server,
            "HEALTH_QUEUE_RECONCILE_STATE",
            {"last_at": float("-inf"), "task": None},
        ) as state, patch.object(
            agent_server,
            "reconcile_idle_queued_turns",
            new=AsyncMock(return_value=0),
        ) as reconcile, patch.object(
            agent_server,
            "HEALTH_QUEUE_RECONCILE_INTERVAL_SECONDS",
            3600.0,
        ):
            self.assertTrue(
                await agent_server.reconcile_idle_queued_turns_from_health_poll()
            )
            self.assertFalse(
                await agent_server.reconcile_idle_queued_turns_from_health_poll()
            )
            self.assertFalse(
                await agent_server.reconcile_idle_queued_turns_from_health_poll()
            )
            await state["task"]
            reconcile.assert_awaited_once_with(reason="health_poll")
            state["last_at"] = float("-inf")
            self.assertTrue(
                await agent_server.reconcile_idle_queued_turns_from_health_poll()
            )
            await state["task"]
            self.assertEqual(reconcile.await_count, 2)

    async def test_health_poll_does_not_wait_for_a_blocked_reconcile(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def blocked_reconcile(*, reason):
            self.assertEqual(reason, "health_poll")
            started.set()
            await release.wait()
            return 0

        state = {"last_at": float("-inf"), "task": None}
        with patch.object(
            agent_server,
            "HEALTH_QUEUE_RECONCILE_STATE",
            state,
        ), patch.object(
            agent_server,
            "reconcile_idle_queued_turns",
            side_effect=blocked_reconcile,
        ):
            scheduled = await asyncio.wait_for(
                agent_server.reconcile_idle_queued_turns_from_health_poll(),
                timeout=0.1,
            )
            self.assertTrue(scheduled)
            await asyncio.wait_for(started.wait(), timeout=0.1)
            self.assertFalse(
                await agent_server.reconcile_idle_queued_turns_from_health_poll()
            )
            release.set()
            await asyncio.wait_for(state["task"], timeout=0.1)

    async def test_shutdown_fence_prevents_new_reconcile_and_queue_tasks(self):
        with patch.object(agent_server, "SERVER_SHUTTING_DOWN", True), \
             patch.object(agent_server.asyncio, "create_task") as create_task:
            self.assertFalse(
                await agent_server.reconcile_idle_queued_turns_from_health_poll()
            )
            agent_server.schedule_next_queued_turn("chat")
            agent_server.schedule_claude_stop_fence_retry("chat")
        create_task.assert_not_called()


class ExplicitStopDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_hung_stop_releases_fence_and_reports_timeout(self):
        release = asyncio.Event()

        async def hung_stop(
            session_id,
            *,
            schedule_queue=True,
            _admission_ready=None,
        ):
            self.assertFalse(schedule_queue)
            if _admission_ready is not None:
                _admission_ready.set()
            await release.wait()
            return {"ok": True, "stopped": True, "late": True}

        events: list[tuple[str, dict]] = []

        async def record_event(session_id, event_type, payload):
            events.append((event_type, payload))

        with patch.object(agent_server, "stop_turn", new=hung_stop), \
             patch.object(agent_server, "EXPLICIT_STOP_OPERATIONS", {}) as fences, \
             patch.object(agent_server, "EXPLICIT_STOP_OPERATION_TIMEOUT_SECONDS", 1.0), \
             patch.object(agent_server, "DETACHED_STOP_TASKS", set()) as detached, \
             patch.object(agent_server, "DETACHED_STOP_TASKS_BY_SESSION", {}), \
             patch.object(agent_server, "SESSION_LIFECYCLE_LOCKS", {}), \
             patch.object(agent_server, "append_event", new=record_event), \
             patch.object(agent_server, "schedule_next_queued_turn") as schedule, \
             patch.object(
                 agent_server,
                 "managed_server_update_blocker",
                 return_value=None,
             ), \
             self.assertLogs(agent_server.logger, level="ERROR") as logs:
            result = await asyncio.wait_for(
                agent_server.stop_turn_endpoint("chat"),
                timeout=5,
            )
            self.assertFalse(agent_server.explicit_stop_in_progress("chat"))
            self.assertNotIn("chat", fences)
            # Teardown keeps running detached until the provider settles.
            self.assertEqual(len(detached), 1)
            self.assertTrue(agent_server.detached_stop_in_progress("chat"))
            self.assertTrue(agent_server.stop_cleanup_in_progress("chat"))
            self.assertEqual(
                agent_server.queue_promotion_fence("chat"),
                "explicit_stop",
            )
            self.assertEqual(agent_server.explicit_stop_session_ids(), {"chat"})
            self.assertEqual(
                await agent_server.scheduled_job_blocker("chat"),
                "chat is finishing an explicit Stop",
            )
            with self.assertRaises(HTTPException) as repeat_stop:
                await agent_server.stop_turn_endpoint("chat")
            self.assertEqual(repeat_stop.exception.status_code, 409)
            with self.assertRaises(HTTPException) as delete_raised:
                await agent_server.delete_session("chat")
            self.assertEqual(delete_raised.exception.status_code, 409)
            self.assertIn("Stop cleanup", str(delete_raised.exception.detail))
            release.set()
            await asyncio.gather(*detached, return_exceptions=True)
            await asyncio.sleep(0)
            self.assertFalse(agent_server.detached_stop_in_progress("chat"))
            self.assertFalse(agent_server.stop_cleanup_in_progress("chat"))
            self.assertEqual(agent_server.explicit_stop_session_ids(), set())
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["stopped"])
        self.assertTrue(result["pending"])
        self.assertIn("remain queued", result["message"])
        self.assertEqual([kind for kind, _ in events], ["error"])
        self.assertTrue(events[0][1]["stop_timeout"])
        schedule.assert_called_once_with("chat")
        self.assertTrue(any("did not finish" in line for line in logs.output))

    async def test_prompt_stop_returns_its_result_and_clears_fence(self):
        async def quick_stop(
            session_id,
            *,
            schedule_queue=True,
            _admission_ready=None,
        ):
            self.assertFalse(schedule_queue)
            if _admission_ready is not None:
                _admission_ready.set()
            return {"ok": True, "stopped": True}

        with patch.object(agent_server, "stop_turn", new=quick_stop), \
             patch.object(agent_server, "EXPLICIT_STOP_OPERATIONS", {}) as fences, \
             patch.object(agent_server, "SESSION_LIFECYCLE_LOCKS", {}), \
             patch.object(
                 agent_server,
                 "schedule_next_queued_turn",
             ) as schedule, \
             patch.object(
                 agent_server,
                 "managed_server_update_blocker",
                 return_value=None,
             ):
            result = await agent_server.stop_turn_endpoint("chat")
        self.assertEqual(result, {"ok": True, "stopped": True})
        self.assertEqual(fences, {})
        schedule.assert_called_once_with("chat")


class PendingUpdateSelectiveDrainTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_reservation_defers_only_automatic_jobs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                agent_server,
                "SERVER_UPDATE_STATUS_FILE",
                root / "status.json",
            ), patch.object(agent_server, "BUSY_SESSIONS", {"busy-chat"}), \
                 patch.object(agent_server, "MAX_ACTIVE_AGENT_RUNS", 0), \
                 patch.object(agent_server, "JOB_MAX_ACTIVE_RUNS", 0), \
                 patch.object(
                     agent_server,
                     "host_pressure_snapshot",
                     return_value={"available_mem_mb": 1_000_000},
                 ):
                agent_server.write_fresh_server_update_status(
                    phase="pending",
                    schedule_id="e" * 32,
                    target_version="1.1.0",
                    track="stable",
                    when_idle=True,
                    pending_at=utc(3600),
                )
                self.assertTrue(agent_server.managed_server_update_is_pending())
                self.assertIsNone(agent_server.managed_server_update_admission_blocker())
                self.assertIsNone(await agent_server.turn_start_blocker())
                self.assertEqual(
                    await agent_server.scheduled_job_blocker("other-chat"),
                    agent_server.MANAGED_SERVER_UPDATE_PENDING_DETAIL,
                )
                self.assertIsNone(
                    await agent_server.scheduled_job_blocker(
                        "other-chat",
                        manual=True,
                    )
                )

    async def test_active_update_still_fences(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                agent_server,
                "SERVER_UPDATE_STATUS_FILE",
                root / "status.json",
            ):
                agent_server.write_fresh_server_update_status(
                    phase="installing",
                    update_id="update-1",
                    track="stable",
                )
                self.assertEqual(
                    agent_server.managed_server_update_admission_blocker(),
                    agent_server.MANAGED_SERVER_UPDATE_ACTIVE_DETAIL,
                )
                self.assertEqual(
                    await agent_server.scheduled_job_blocker(
                        "other-chat",
                        manual=True,
                    ),
                    agent_server.MANAGED_SERVER_UPDATE_ACTIVE_DETAIL,
                )

    async def test_active_restart_still_fences_manual_jobs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                agent_server,
                "SERVER_RESTART_STATUS_FILE",
                root / "restart.json",
            ), patch.object(
                agent_server,
                "SERVER_UPDATE_STATUS_FILE",
                root / "update.json",
            ):
                agent_server.write_server_restart_status(
                    phase="signaling",
                    request_id="restart-1",
                )
                self.assertEqual(
                    await agent_server.scheduled_job_blocker(
                        "other-chat",
                        manual=True,
                    ),
                    agent_server.MANAGED_SERVER_RESTART_ACTIVE_DETAIL,
                )


class RestartDenialLoggingTests(unittest.IsolatedAsyncioTestCase):
    async def test_denied_restart_logs_code_and_blockers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with restart_environment(root), \
                 patch.object(agent_server, "BUSY_SESSIONS", {"chat"}), \
                 self.assertLogs(agent_server.logger, level="WARNING") as logs:
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.restart_server_endpoint(
                        restart_body(),
                        http_request(method="POST"),
                        BackgroundTasks(),
                    )
        self.assertEqual(raised.exception.detail["code"], "server_restart_busy")
        denial = [line for line in logs.output if "server restart denied" in line]
        self.assertEqual(len(denial), 1)
        self.assertIn("code=server_restart_busy", denial[0])
        self.assertIn("forced=False", denial[0])
        self.assertIn('"active_count": 1', denial[0])

    async def test_snapshot_advertises_force_availability(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with restart_environment(root), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", {"chat"}):
                snapshot = agent_server.server_restart_blocker_snapshot_locked()
        self.assertTrue(snapshot["has_safety_blockers"])
        self.assertTrue(snapshot["force_restart_available"])


class HistoryImportAnchorTests(unittest.TestCase):
    def select(self, events, items):
        message_keys = []
        for index, event in enumerate(events, 1):
            if event.get("type") == "turn_started":
                key = agent_server.history_dedup_key("user", event.get("prompt"))
            elif event.get("type") == "assistant_text":
                key = agent_server.history_dedup_key(
                    "assistant", event.get("text")
                )
            else:
                continue
            message_keys.append((index, key))
        with patch.object(
            agent_server,
            "history_timeline_message_keys",
            return_value=(message_keys, bool(message_keys), False),
        ) as scan:
            fresh = agent_server.unsynced_history_items(
                "chat-x",
                items,
                timeline_through_seq=len(events),
            )
        return fresh, scan

    def test_dedup_scans_the_timeline_tail(self):
        events = [{"type": "turn_started", "prompt": "hello"}]
        _fresh, scan = self.select(events, [{"kind": "user", "text": "hello"}])
        self.assertTrue(scan.call_args.kwargs.get("tail"))

    def test_no_anchor_on_a_populated_timeline_imports_nothing(self):
        # Every transcript item failed to match an existing conversation:
        # importing them would duplicate the whole chat (12k duplicate events
        # on 2026-09-04). Nothing is the only safe answer.
        events = [
            {"type": "turn_started", "prompt": "timeline only"},
            {"type": "assistant_text", "text": "timeline reply"},
        ]
        with self.assertLogs(agent_server.logger, level="WARNING"):
            fresh, _read = self.select(
                events,
                [
                    {"kind": "user", "text": "transcript A"},
                    {"kind": "assistant", "text": "transcript B"},
                ],
            )
        self.assertEqual(fresh, [])

    def test_empty_timeline_still_imports_everything(self):
        items = [{"kind": "user", "text": "hello"}, {"kind": "assistant", "text": "hi"}]
        fresh, _read = self.select([], items)
        self.assertEqual(fresh, items)


class SubagentReconcileBurstTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.previous_sessions = agent_server.STORE.sessions
        self.previous_index = agent_server.CODEX_SUBAGENT_SESSION_INDEX
        self.previous_states = agent_server.CODEX_SUBAGENT_STATE
        self.session = {
            "id": "chat",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "parent-thread",
            "session_id": "parent-thread",
        }
        agent_server.STORE.sessions = {"chat": self.session}
        agent_server.CODEX_SUBAGENT_SESSION_INDEX = {}
        agent_server.CODEX_SUBAGENT_STATE = {}
        self.events: list[tuple[str, dict]] = []

    async def asyncTearDown(self) -> None:
        agent_server.STORE.sessions = self.previous_sessions
        agent_server.CODEX_SUBAGENT_SESSION_INDEX = self.previous_index
        agent_server.CODEX_SUBAGENT_STATE = self.previous_states

    async def append(self, session_id, event_type, payload):
        self.events.append((event_type, payload))
        return {"seq": len(self.events), **payload}

    class Manager:
        def __init__(self, descendants):
            self.descendants = descendants

        async def list_descendant_threads(self, thread_id):
            return list(self.descendants)

    async def test_terminal_children_unknown_to_this_process_are_learned_silently(self):
        manager = self.Manager([
            {"id": f"child-{index}", "parentThreadId": "parent-thread",
             "preview": f"Audit {index}", "status": {"type": "notLoaded"},
             "updatedAt": f"2026-09-04T10:00:{index:02d}Z"}
            for index in range(5)
        ])
        with patch.object(agent_server, "append_event", AsyncMock(side_effect=self.append)), \
             patch.object(agent_server.STORE, "save", AsyncMock()):
            result = await agent_server.reconcile_codex_subagents("chat", manager)
        self.assertEqual(result["reconciled"], 5)
        self.assertEqual(result["silent"], 5)
        self.assertEqual(self.events, [])
        self.assertEqual(
            agent_server.CODEX_SUBAGENT_STATE["child-3"]["subagent_status"],
            "completed",
        )
        self.assertEqual(agent_server.CODEX_SUBAGENT_SESSION_INDEX["child-3"], "chat")

    async def test_running_children_and_known_transitions_still_emit(self):
        manager = self.Manager([
            {"id": "child-run", "parentThreadId": "parent-thread",
             "preview": "Live", "status": {"type": "active", "activeFlags": []}},
        ])
        with patch.object(agent_server, "append_event", AsyncMock(side_effect=self.append)), \
             patch.object(agent_server.STORE, "save", AsyncMock()):
            await agent_server.reconcile_codex_subagents("chat", manager)
            self.assertEqual([kind for kind, _ in self.events], ["subagent_state"])
            self.assertEqual(self.events[0][1]["subagent_status"], "running")
            manager.descendants[0]["status"] = {"type": "notLoaded"}
            await agent_server.reconcile_codex_subagents("chat", manager)
        self.assertEqual(len(self.events), 2)
        self.assertEqual(self.events[1][1]["subagent_status"], "completed")

    async def test_durable_snapshot_rehydrates_known_children_after_restart(self):
        self.session["codex_subagents"] = {
            "child-a": {
                "session_id": "chat",
                "subagent_id": "child-a",
                "subagent_status": "completed",
                "subagent_name": "Leibniz",
            },
        }
        manager = self.Manager([
            {"id": "child-a", "parentThreadId": "parent-thread",
             "preview": "Audit A", "status": {"type": "notLoaded"}},
        ])
        with patch.object(agent_server, "append_event", AsyncMock(side_effect=self.append)), \
             patch.object(agent_server.STORE, "save", AsyncMock()):
            await agent_server.reconcile_codex_subagents("chat", manager)
        self.assertEqual(self.events, [])
        self.assertEqual(
            agent_server.CODEX_SUBAGENT_STATE["child-a"]["subagent_name"],
            "Leibniz",
        )

    async def test_descendant_reconciliation_is_capped_to_most_recent(self):
        manager = self.Manager([
            {"id": f"child-{index}", "parentThreadId": "parent-thread",
             "preview": f"Audit {index}", "status": {"type": "notLoaded"},
             "updatedAt": f"2026-09-04T10:{index // 60:02d}:{index % 60:02d}Z"}
            for index in range(10)
        ])
        with patch.object(agent_server, "CODEX_SUBAGENT_RECONCILE_LIMIT", 3), \
             patch.object(agent_server, "append_event", AsyncMock(side_effect=self.append)), \
             patch.object(agent_server.STORE, "save", AsyncMock()):
            result = await agent_server.reconcile_codex_subagents("chat", manager)
        self.assertEqual(result["reconciled"], 3)
        self.assertEqual(result["skipped"], 7)
        self.assertEqual(result["descendants"], 10)
        self.assertIn("child-9", agent_server.CODEX_SUBAGENT_STATE)
        self.assertNotIn("child-0", agent_server.CODEX_SUBAGENT_STATE)


class SessionsWriterFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_encode_failure_reaches_the_awaiter_and_does_not_strand_later_saves(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(agent_server, "SESSIONS_FILE", root / "sessions.json"):
                store = agent_server.SessionStore()
                store.sessions = {"chat": {"id": "chat", "bad": {1, 2}}}
                with self.assertRaises(TypeError):
                    await asyncio.wait_for(store.save(), timeout=5)
                store.sessions = {"chat": {"id": "chat"}}
                await asyncio.wait_for(store.save(), timeout=5)
                await asyncio.wait_for(store.flush_pending_save(), timeout=5)
            self.assertEqual(
                json.loads((root / "sessions.json").read_text())["chat"]["id"],
                "chat",
            )

    def test_bounded_writer_lock_refuses_instead_of_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sessions.json"
            agent_server.SESSIONS_WRITE_LOCK.acquire()
            try:
                with self.assertRaises(RuntimeError):
                    agent_server.write_sessions_json_text(
                        path,
                        "{}",
                        durable=False,
                        lock_timeout=0.05,
                    )
            finally:
                agent_server.SESSIONS_WRITE_LOCK.release()
            agent_server.write_sessions_json_text(path, "{}", durable=False, lock_timeout=0.05)
            self.assertEqual(path.read_text(), "{}")


class ManagedServiceProofTests(unittest.TestCase):
    def test_probe_timeout_keeps_prior_positive_proof(self):
        with patch.object(agent_server.sys, "platform", "darwin"), \
             patch.object(agent_server, "official_server_release_tree", return_value=True), \
             patch.object(agent_server, "MANAGED_SERVER_SERVICE_KIND_CACHE", "launch-agent"), \
             patch.object(
                 agent_server,
                 "macos_launchd_owns_current_process",
                 return_value=None,
             ):
            self.assertEqual(
                agent_server.detect_managed_server_service_kind(),
                "launch-agent",
            )
            self.assertEqual(agent_server.managed_server_service_kind(), "launch-agent")

    def test_probe_timeout_without_prior_proof_fails_closed(self):
        with patch.object(agent_server.sys, "platform", "darwin"), \
             patch.object(agent_server, "official_server_release_tree", return_value=True), \
             patch.object(agent_server, "MANAGED_SERVER_SERVICE_KIND_CACHE", None), \
             patch.object(
                 agent_server,
                 "macos_launchd_owns_current_process",
                 return_value=None,
             ):
            self.assertIsNone(agent_server.detect_managed_server_service_kind())

    def test_launchctl_timeout_reports_unknown(self):
        with patch.object(agent_server.sys, "platform", "darwin"), \
             patch.object(agent_server.Path, "is_file", return_value=True), \
             patch.object(
                 agent_server.subprocess,
                 "run",
                 side_effect=agent_server.subprocess.TimeoutExpired(cmd="launchctl", timeout=3),
             ):
            self.assertIsNone(agent_server.macos_launchd_owns_current_process())

    def test_cooperative_kill_delay_covers_every_shutdown_phase(self):
        self.assertGreaterEqual(
            agent_server.SERVER_RESTART_GRACEFUL_KILL_DELAY_SECONDS,
            agent_server.configured_uvicorn_graceful_shutdown_seconds()
            + agent_server.SERVER_SHUTDOWN_PHASE_COUNT
            * agent_server.SERVER_SHUTDOWN_PHASE_TIMEOUT_SECONDS,
        )
        source = Path(agent_server.__file__).read_text()
        self.assertEqual(
            source.count("await bounded_shutdown_phase("),
            agent_server.SERVER_SHUTDOWN_PHASE_COUNT,
        )


class ExchangeReplayAfterThreadRotationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_sessions = agent_server.STORE.sessions
        self.marker = "ZZ-END-OF-INSTRUCTION-MARKER"
        self.exchange = {
            "id": "exchange-1",
            "requester_session_id": "requester",
            "responder_session_id": "target",
            "authorization_source_run_id": "run-1",
            "initial_action": "request_reply",
            "max_legs": 6,
            "used_legs": 2,
            "created_at": "2026-09-04T10:00:00Z",
            "source_user_instruction": ("please audit the release " * 30) + self.marker,
        }
        self.leg = {
            "id": "leg-3",
            "ordinal": 3,
            "kind": "message",
            "target_session_id": "target",
            "source_session_id": "requester",
            "body": "third leg body",
        }

    def tearDown(self) -> None:
        agent_server.STORE.sessions = self.previous_sessions

    def prompt_for(self, target: dict) -> str:
        agent_server.STORE.sessions = {
            "target": target,
            "requester": {"id": "requester", "title": "Requester chat"},
        }
        return agent_server.cross_chat_exchange_delivery_prompt(self.exchange, self.leg)

    def test_later_leg_to_an_unchanged_thread_carries_only_an_excerpt(self):
        prompt = self.prompt_for({
            "id": "target",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "thread-1",
            "codex_thread_started_at": "2026-09-04T09:00:00Z",
        })
        self.assertNotIn(self.marker, prompt)

    def test_later_leg_replays_in_full_when_the_thread_was_rotated(self):
        rotated = self.prompt_for({
            "id": "target",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "thread-2",
            "codex_thread_started_at": "2026-09-04T11:00:00Z",
        })
        self.assertIn(self.marker, rotated)
        # Unbound after a rotation: the rotation record is the evidence.
        unbound = self.prompt_for({
            "id": "target",
            "backend": agent_server.BACKEND_CODEX,
            "codex_rotated_threads": [{"thread_id": "thread-1"}],
        })
        self.assertIn(self.marker, unbound)
        # A chat that never had a thread keeps the ordinary first-leg rule.
        fresh = self.prompt_for({
            "id": "target",
            "backend": agent_server.BACKEND_CODEX,
        })
        self.assertNotIn(self.marker, fresh)


class ImportedHistoryLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_imported_turns_never_set_active_run(self):
        sessions = {"chat": {"id": "chat", "backend": agent_server.BACKEND_CODEX}}
        with patch.object(agent_server.STORE, "sessions", sessions), \
             patch.object(agent_server.STORE, "save", AsyncMock()):
            await agent_server.update_session_event_metadata("chat", {
                "type": "turn_started",
                "run_id": "import_abc123",
                "imported": True,
                "prompt": "old message",
                "ts": "2026-09-04T10:00:00Z",
            })
            self.assertNotIn("active_run", sessions["chat"])
            await agent_server.update_session_event_metadata("chat", {
                "type": "turn_started",
                "run_id": "run_live",
                "prompt": "new message",
                "ts": "2026-09-04T10:00:01Z",
            })
            self.assertEqual(sessions["chat"]["active_run"]["run_id"], "run_live")

    def test_stale_imported_active_run_is_cleared_at_startup(self):
        sessions = {
            "a": {"id": "a", "active_run": {"run_id": "import_dead"}},
            "b": {"id": "b", "active_run": {"run_id": "run_live"}},
        }
        with patch.object(agent_server.STORE, "sessions", sessions):
            self.assertEqual(agent_server.clear_imported_active_runs(), 1)
        self.assertNotIn("active_run", sessions["a"])
        self.assertEqual(sessions["b"]["active_run"]["run_id"], "run_live")

    async def test_import_batch_ends_with_a_terminal_event(self):
        appended: list[tuple[str, dict]] = []

        async def record(session_id, event_specs):
            appended.extend(event_specs)
            return [
                {"seq": index, "type": event_type, **payload}
                for index, (event_type, payload) in enumerate(event_specs, 1)
            ]

        sess = {"id": "chat", "backend": agent_server.BACKEND_CODEX, "codex_thread_id": "t1"}
        with patch.object(agent_server, "append_durable_event_batch", new=record):
            await agent_server.append_imported_history(
                sess, Path("/tmp/rollout.jsonl"), [{"kind": "user", "text": "hello"}],
            )
        self.assertEqual([kind for kind, _ in appended], ["history_imported", "turn_started", "turn_finished"])
        self.assertTrue(appended[-1][1]["imported"])
        self.assertEqual(appended[-1][1]["run_id"], appended[1][1]["run_id"])

    async def test_sync_skips_unchanged_transcripts(self):
        sess = {"id": "chat", "backend": agent_server.BACKEND_CODEX, "codex_thread_id": "t1"}
        live = {"chat": dict(sess)}
        stamp = ["/tmp/rollout.jsonl", 10, 20, 30, 40]
        cursor = {
            "version": agent_server.HISTORY_SYNC_CURSOR_VERSION,
            "backend": agent_server.BACKEND_CODEX,
            "provider_session_id": "t1",
            "source_path": stamp[0],
            "source_size": stamp[1],
            "source_mtime_ns": stamp[2],
            "source_dev": stamp[3],
            "source_ino": stamp[4],
            "source_offset": stamp[1],
            "source_digest": "a" * 64,
            "last_item_digest": "",
            "timeline_seq": 0,
        }
        with patch.object(agent_server.STORE, "sessions", live), \
             patch.object(agent_server, "provider_history_source_stamp", return_value=stamp), \
             patch.object(
                 agent_server,
                 "load_provider_history_with_cursor",
                 return_value=(
                     Path("/tmp/rollout.jsonl"),
                     [{"kind": "user", "text": "x"}],
                     cursor,
                     False,
                 ),
             ) as parse, \
             patch.object(agent_server, "unsynced_history_items", return_value=[]), \
             patch.object(agent_server, "last_event_seq_from_file", return_value=0), \
             patch.object(agent_server.STORE, "save", new=AsyncMock()) as save:
            first = await agent_server.sync_provider_history(dict(sess))
            second = await agent_server.sync_provider_history(dict(sess))
        self.assertEqual(parse.call_count, 1)
        save.assert_awaited_once_with(durable=True)
        self.assertIn("Already up to date", first["message"])
        self.assertIn("unchanged", second["message"])

    async def test_failed_sync_does_not_cache_source_stamp(self):
        sess = {
            "id": "chat",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "t1",
        }
        live = {"chat": dict(sess)}
        cursor = {
            "version": agent_server.HISTORY_SYNC_CURSOR_VERSION,
            "backend": agent_server.BACKEND_CODEX,
            "provider_session_id": "t1",
            "source_path": "/tmp/rollout.jsonl",
            "source_size": 10,
            "source_mtime_ns": 20,
            "source_dev": 30,
            "source_ino": 40,
            "source_offset": 10,
            "source_digest": "a" * 64,
            "last_item_digest": "",
            "timeline_seq": 0,
        }
        with patch.object(agent_server.STORE, "sessions", live), \
             patch.object(
                 agent_server,
                 "load_provider_history_with_cursor",
                 return_value=(
                     Path("/tmp/rollout.jsonl"),
                     [{"kind": "user", "text": "new"}],
                     cursor,
                     False,
                 ),
             ), patch.object(
                 agent_server,
                 "unsynced_history_items",
                 return_value=[{"kind": "user", "text": "new"}],
             ), patch.object(
                 agent_server,
                 "append_imported_history",
                 new=AsyncMock(side_effect=OSError("disk full")),
             ), patch.object(
                 agent_server.STORE,
                 "save",
                 new=AsyncMock(),
             ) as save:
            with self.assertRaises(OSError):
                await agent_server.sync_provider_history(dict(sess))
        self.assertNotIn("_history_sync_cursor", live["chat"])
        save.assert_not_awaited()

    async def test_forced_import_only_appends_unsynced_suffix(self):
        sess = {
            "id": "chat",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "t1",
        }
        transcript = [
            {"kind": "user", "text": "already present"},
            {"kind": "assistant", "text": "also present"},
        ]
        with patch.object(
            agent_server,
            "load_provider_history_with_cursor",
            return_value=(Path("/tmp/rollout.jsonl"), transcript, None, False),
        ), patch.object(
            agent_server,
            "unsynced_history_items",
            return_value=[],
        ) as unsynced, patch.object(
            agent_server,
            "append_imported_history",
            new=AsyncMock(),
        ) as append, patch.object(
            agent_server,
            "last_event_seq_from_file",
            return_value=0,
        ):
            result = await agent_server.import_session_history(sess, force=True)

        unsynced.assert_called_once_with(
            "chat",
            transcript,
            timeline_through_seq=0,
        )
        append.assert_not_awaited()
        self.assertEqual(result["imported"], 0)
        self.assertIn("Already up to date", result["message"])

    def test_sync_matches_repeated_text_to_newest_transcript_occurrence(self):
        transcript = [
            {"kind": "assistant", "text": "same answer"},
            {"kind": "user", "text": "latest question"},
            {"kind": "assistant", "text": "same answer"},
        ]
        timeline_keys = [
            (
                1,
                agent_server.history_dedup_key("user", "latest question"),
            ),
            (
                2,
                agent_server.history_dedup_key("assistant", "same answer"),
            ),
        ]
        with patch.object(
            agent_server,
            "history_timeline_message_keys",
            return_value=(timeline_keys, True, False),
        ):
            fresh = agent_server.unsynced_history_items("chat", transcript)

        self.assertEqual(fresh, [])

    async def test_manual_import_rejects_busy_chat_before_reading_provider(self):
        sess = {
            "id": "chat",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "t1",
        }
        with patch.dict(agent_server.STORE.sessions, {"chat": sess}, clear=True), \
             patch.object(agent_server, "SESSION_LIFECYCLE_LOCKS", {}), \
             patch.object(agent_server, "ACTIVE_LOCK", asyncio.Lock()), \
             patch.object(agent_server, "BUSY_SESSIONS", {"chat"}), \
             patch.object(agent_server, "provider_history") as provider:
            with self.assertRaises(HTTPException) as raised:
                await agent_server.import_history(
                    "chat",
                    agent_server.ImportHistoryRequest(force=True),
                )

        self.assertEqual(raised.exception.status_code, 409)
        provider.assert_not_called()

    async def test_prune_revalidates_busy_state_after_lifecycle_wait(self):
        lifecycle = asyncio.Lock()
        await lifecycle.acquire()
        sync = MagicMock(return_value={
            "dry_run": True,
            "events_before": 0,
            "removed_events": 0,
            "removed_runs": 0,
            "bytes_before": 0,
            "bytes_after": 0,
            "_max_seq_before": 0,
        })
        with patch.dict(
            agent_server.STORE.sessions,
            {"chat": {"id": "chat"}},
            clear=True,
        ), patch.object(
            agent_server,
            "SESSION_LIFECYCLE_LOCKS",
            {"chat": lifecycle},
        ), patch.object(agent_server, "ACTIVE_LOCK", asyncio.Lock()), \
             patch.object(agent_server, "BUSY_SESSIONS", set()), \
             patch.object(
                 agent_server,
                 "prune_duplicate_imported_history_sync",
                 sync,
             ):
            operation = asyncio.create_task(
                agent_server.prune_imported_history(
                    "chat",
                    agent_server.PruneImportedHistoryRequest(dry_run=True),
                )
            )
            await asyncio.sleep(0)
            sync.assert_not_called()
            agent_server.BUSY_SESSIONS.add("chat")
            lifecycle.release()
            with self.assertRaises(HTTPException) as raised:
                await operation

        self.assertEqual(raised.exception.status_code, 409)
        sync.assert_not_called()


class PruneImportedHistoryTests(unittest.TestCase):
    def write_log(self, path: Path, events: list[dict]) -> None:
        path.write_text("".join(json.dumps(e) + "\n" for e in events))

    def test_duplicate_imported_rows_are_removed_and_first_copies_kept(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "events.jsonl"
            events = [
                {"seq": 1, "type": "turn_started", "run_id": "run_a", "prompt": "hello"},
                {"seq": 2, "type": "assistant_text", "run_id": "run_a", "text": "hi there"},
                {"seq": 3, "type": "turn_finished", "run_id": "run_a"},
                {"seq": 4, "type": "history_imported", "run_id": "import_1"},
                {"seq": 5, "type": "turn_started", "run_id": "import_1", "imported": True, "prompt": "hello"},
                {"seq": 6, "type": "assistant_text", "run_id": "import_1", "imported": True, "text": "hi  there"},
                {"seq": 7, "type": "history_imported", "run_id": "import_2"},
                {"seq": 8, "type": "turn_started", "run_id": "import_2", "imported": True, "prompt": "hello"},
                {"seq": 9, "type": "assistant_text", "run_id": "import_2", "imported": True, "text": "brand new reply"},
                {"seq": 10, "type": "turn_finished", "run_id": "import_2", "imported": True},
            ]
            self.write_log(log, events)
            with patch.object(agent_server, "events_path", return_value=log):
                dry = agent_server.prune_duplicate_imported_history_sync("chat", dry_run=True)
                self.assertEqual(dry["removed_events"], 4)
                self.assertEqual(dry["removed_runs"], 1)
                self.assertEqual(len(log.read_text().splitlines()), 10)
                real = agent_server.prune_duplicate_imported_history_sync("chat", dry_run=False)
            remaining = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
        self.assertEqual(real["removed_events"], 4)
        self.assertEqual([e["seq"] for e in remaining], [1, 2, 3, 7, 9, 10])

    def test_prune_without_duplicates_leaves_the_file_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "events.jsonl"
            self.write_log(log, [
                {"seq": 1, "type": "turn_started", "run_id": "run_a", "prompt": "hello"},
            ])
            before = log.read_bytes()
            with patch.object(agent_server, "events_path", return_value=log):
                summary = agent_server.prune_duplicate_imported_history_sync("chat", dry_run=False)
            self.assertEqual(summary["removed_events"], 0)
            self.assertEqual(log.read_bytes(), before)

    def test_prune_preserves_malformed_bytes_and_unframed_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "events.jsonl"
            native = json.dumps({
                "seq": 1,
                "type": "turn_started",
                "run_id": "native",
                "prompt": "same",
            }, separators=(",", ":")).encode() + b"\n"
            marker = json.dumps({
                "seq": 2,
                "type": "history_imported",
                "run_id": "import_tail",
                "imported": True,
            }, separators=(",", ":")).encode() + b"\n"
            duplicate = json.dumps({
                "seq": 3,
                "type": "turn_started",
                "run_id": "import_tail",
                "imported": True,
                "prompt": "same",
            }, separators=(",", ":")).encode() + b"\n"
            terminal = json.dumps({
                "seq": 4,
                "type": "turn_finished",
                "run_id": "import_tail",
                "imported": True,
            }, separators=(",", ":")).encode() + b"\n"
            malformed = b"not-json-\xff-without-final-newline"
            original = native + marker + duplicate + terminal + malformed
            log.write_bytes(original)
            with patch.object(agent_server, "events_path", return_value=log), patch.object(
                agent_server,
                "fsync_parent_directory",
                wraps=agent_server.fsync_parent_directory,
            ) as directory_fsync:
                dry = agent_server.prune_duplicate_imported_history_sync(
                    "chat",
                    dry_run=True,
                )
                real = agent_server.prune_duplicate_imported_history_sync(
                    "chat",
                    dry_run=False,
                )

            expected_without_checkpoint = native + malformed
            self.assertEqual(dry["bytes_after"], len(expected_without_checkpoint))
            self.assertEqual(real["removed_events"], 3)
            self.assertEqual(real["removed_runs"], 1)
            rewritten = log.read_bytes()
            self.assertTrue(rewritten.startswith(expected_without_checkpoint + b"\n"))
            self.assertIn(b'"type":"_event_sequence_checkpoint"', rewritten)
            self.assertEqual(real["bytes_after"], len(rewritten))
            directory_fsync.assert_called_once_with(log)
            self.assertEqual(
                list(log.parent.glob(".*prune*")),
                [],
            )

    def test_prune_uses_bounded_python_memory_for_large_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "events.jsonl"
            with log.open("wb") as output:
                seq = 0
                # Roughly eight MiB and tens of thousands of unique keys. The
                # old read/split/parse/list/set implementation peaked around
                # one hundred MiB for this shape.
                while output.tell() < 8 * 1024 * 1024:
                    seq += 1
                    output.write(json.dumps({
                        "seq": seq,
                        "type": "assistant_text",
                        "run_id": f"native_{seq}",
                        "text": f"unique history message {seq:08d} " + ("x" * 96),
                    }, separators=(",", ":")).encode() + b"\n")
            with patch.object(agent_server, "events_path", return_value=log):
                tracemalloc.start()
                tracemalloc.reset_peak()
                try:
                    summary = agent_server.prune_duplicate_imported_history_sync(
                        "chat",
                        dry_run=True,
                    )
                    _current, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()

            self.assertEqual(summary["removed_events"], 0)
            self.assertGreaterEqual(summary["bytes_before"], 8 * 1024 * 1024)
            self.assertLess(
                peak,
                12 * 1024 * 1024,
                f"streaming prune allocated {peak / (1024 * 1024):.1f} MiB",
            )

    def test_prune_refuses_to_replace_a_concurrently_changed_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "events.jsonl"
            events = [
                {"seq": 1, "type": "turn_started", "run_id": "native", "prompt": "same"},
                {"seq": 2, "type": "history_imported", "run_id": "import_1", "imported": True},
                {"seq": 3, "type": "turn_started", "run_id": "import_1", "imported": True, "prompt": "same"},
                {"seq": 4, "type": "turn_finished", "run_id": "import_1", "imported": True},
            ]
            self.write_log(log, events)
            before = log.read_bytes()
            # Exercise the generation fence directly by changing the file
            # after the replacement stream has been fsynced.
            real_stat = agent_server.Path.stat
            calls = 0

            def changing_stat(target, *args, **kwargs):
                nonlocal calls
                result = real_stat(target, *args, **kwargs)
                if target == log:
                    calls += 1
                    if calls == 3:
                        with log.open("ab") as output:
                            output.write(b'{"seq":5,"type":"assistant_text","text":"late"}\n')
                        result = real_stat(target, *args, **kwargs)
                return result

            with patch.object(agent_server, "events_path", return_value=log), patch.object(
                agent_server.Path,
                "stat",
                changing_stat,
            ):
                with self.assertRaises(RuntimeError):
                    agent_server.prune_duplicate_imported_history_sync(
                        "chat",
                        dry_run=False,
                    )
            self.assertTrue(log.read_bytes().startswith(before))
            self.assertIn(b'"text":"late"', log.read_bytes())

    def test_prune_detects_same_size_rewrite_with_restored_mtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "events.jsonl"
            events = [
                {
                    "seq": 1,
                    "type": "turn_started",
                    "run_id": "native",
                    "prompt": "same",
                },
                {
                    "seq": 2,
                    "type": "history_imported",
                    "run_id": "import_1",
                    "imported": True,
                },
                {
                    "seq": 3,
                    "type": "turn_started",
                    "run_id": "import_1",
                    "imported": True,
                    "prompt": "same",
                },
                {
                    "seq": 4,
                    "type": "turn_finished",
                    "run_id": "import_1",
                    "imported": True,
                },
            ]
            self.write_log(log, events)
            original = log.read_bytes()
            rewritten_by_racer = original.replace(b'"prompt": "same"', b'"prompt": "tame"', 1)
            self.assertEqual(len(rewritten_by_racer), len(original))
            initial = log.stat()
            real_stat = agent_server.Path.stat
            calls = 0

            def changing_stat(target, *args, **kwargs):
                nonlocal calls
                result = real_stat(target, *args, **kwargs)
                if target == log:
                    calls += 1
                    if calls == 3:
                        log.write_bytes(rewritten_by_racer)
                        os.utime(
                            log,
                            ns=(initial.st_atime_ns, initial.st_mtime_ns),
                        )
                        result = real_stat(target, *args, **kwargs)
                        self.assertEqual(result.st_size, initial.st_size)
                        self.assertEqual(result.st_mtime_ns, initial.st_mtime_ns)
                        self.assertNotEqual(result.st_ctime_ns, initial.st_ctime_ns)
                return result

            with patch.object(
                agent_server,
                "events_path",
                return_value=log,
            ), patch.object(agent_server.Path, "stat", changing_stat):
                with self.assertRaises(RuntimeError):
                    agent_server.prune_duplicate_imported_history_sync(
                        "chat",
                        dry_run=False,
                    )

            self.assertEqual(log.read_bytes(), rewritten_by_racer)

    def test_prune_handles_unpaired_surrogate_keys_losslessly(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "events.jsonl"
            events = [
                {
                    "seq": 1,
                    "type": "assistant_text",
                    "run_id": "native",
                    "text": "\ud800",
                },
                {
                    "seq": 2,
                    "type": "history_imported",
                    "run_id": "import_\ud800_drop",
                    "imported": True,
                },
                {
                    "seq": 3,
                    "type": "assistant_text",
                    "run_id": "import_\ud800_drop",
                    "imported": True,
                    "text": "\ud800",
                },
                {
                    "seq": 4,
                    "type": "turn_finished",
                    "run_id": "import_\ud800_drop",
                    "imported": True,
                },
                {
                    "seq": 5,
                    "type": "history_imported",
                    "run_id": "import_\ud800_keep",
                    "imported": True,
                },
                {
                    "seq": 6,
                    "type": "assistant_text",
                    "run_id": "import_\ud800_keep",
                    "imported": True,
                    "text": "unique",
                },
                {
                    "seq": 7,
                    "type": "turn_finished",
                    "run_id": "import_\ud800_keep",
                    "imported": True,
                },
            ]
            self.write_log(log, events)
            before = log.read_bytes()
            with patch.object(
                agent_server,
                "events_path",
                return_value=log,
            ), patch.object(agent_server.hashlib, "sha256") as sha256:
                # Every normalized key shares one digest. Full BLOB key
                # equality must still distinguish the unique imported text.
                sha256.return_value.digest.return_value = b"x" * 32
                dry = agent_server.prune_duplicate_imported_history_sync(
                    "chat",
                    dry_run=True,
                )
                self.assertEqual(log.read_bytes(), before)
                real = agent_server.prune_duplicate_imported_history_sync(
                    "chat",
                    dry_run=False,
                )

            self.assertEqual(dry["removed_events"], 3)
            self.assertEqual(dry["removed_runs"], 1)
            self.assertEqual(real["removed_events"], 3)
            self.assertEqual(real["removed_runs"], 1)
            rewritten = log.read_bytes()
            self.assertIn(b'"text": "\\ud800"', rewritten)
            self.assertIn(b'"run_id": "import_\\ud800_keep"', rewritten)
            self.assertNotIn(b'"run_id": "import_\\ud800_drop"', rewritten)
            self.assertEqual(real["bytes_after"], len(rewritten))


class DarwinMetricsTests(unittest.TestCase):
    def test_elapsed_time_parsing(self):
        self.assertEqual(agent_server.parse_elapsed_seconds("05:33"), 333)
        self.assertEqual(agent_server.parse_elapsed_seconds("01:02:03"), 3723)
        self.assertEqual(agent_server.parse_elapsed_seconds("10-17:57:40"), 928660)
        with self.assertRaises(ValueError):
            agent_server.parse_elapsed_seconds("")

    def test_darwin_ps_rows_parse_bsd_output(self):
        stdout = (
            "52965 52964 52924 S    03:58 14.6  4.4 1641904 /Users/zen/.nvm/bin/codex app-server --listen stdio://\n"
            "  791     1   791 Ss 10-18:28:56 40.6  0.1 23056 /System/Library/CoreServices/TimeMachine/backupd\n"
            "  900     1   900 S  01:02:03  1.0  0.2 4096 /Applications/Activity Monitor.app/Contents/MacOS/Activity Monitor\n"
            "garbage line\n"
        )
        rows = agent_server.parse_darwin_ps_rows(stdout)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["pid"], 52965)
        self.assertEqual(rows[0]["sid"], 52924)
        self.assertEqual(rows[0]["elapsed_seconds"], 238)
        self.assertEqual(rows[0]["rss_kb"], 1641904)
        self.assertEqual(rows[0]["command"], "codex")
        self.assertEqual(rows[0]["args"], "/Users/zen/.nvm/bin/codex app-server --listen stdio://")
        self.assertEqual(rows[1]["elapsed_seconds"], 10 * 86400 + 18 * 3600 + 28 * 60 + 56)
        self.assertEqual(rows[1]["command"], "backupd")
        # Command names with spaces must not shift the numeric columns.
        self.assertEqual(rows[2]["rss_kb"], 4096)
        self.assertIn("Activity Monitor", rows[2]["args"])

    def test_vm_stat_available_memory(self):
        stdout = (
            "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
            "Pages free:                               100000.\n"
            "Pages active:                            2000000.\n"
            "Pages inactive:                           200000.\n"
            "Pages speculative:                         50000.\n"
            "Pages purgeable:                           10000.\n"
            "Pages wired down:                         900000.\n"
        )
        expected = int((100000 + 200000 + 50000 + 10000) * 16384 / (1024 * 1024))
        self.assertEqual(agent_server.parse_vm_stat_available_mb(stdout), expected)
        self.assertIsNone(agent_server.parse_vm_stat_available_mb("no pages here"))

    def test_darwin_memory_probe_is_cached(self):
        completed = MagicMock(returncode=0, stdout=(
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
            "Pages free: 1024.\n"
        ))
        with patch.object(
            agent_server,
            "DARWIN_MEMORY_CACHE",
            {"at": float("-inf"), "mb": None},
        ), patch.object(agent_server.subprocess, "run", return_value=completed) as run:
            first = agent_server.darwin_available_memory_mb()
            second = agent_server.darwin_available_memory_mb()
        self.assertEqual(first, 4)
        self.assertEqual(second, 4)
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
