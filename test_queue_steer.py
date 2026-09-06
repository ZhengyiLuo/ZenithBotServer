import asyncio
import json
import tempfile
import time
import unittest
from collections import OrderedDict, deque
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

import agent_server
from agent_server import (
    build_turn_provider_prompt,
    claude_result_error,
    is_expected_claude_interruption_result,
    prepare_steered_turn,
    queued_turn_from_event,
    rebuild_queued_turns_from_events,
    run_queued_turn_now,
    should_schedule_queue_after_finish,
    start_next_queued_turn,
)


class PrepareSteeredTurnTests(unittest.TestCase):
    def test_persists_raw_messages_and_generates_scoped_provider_prompt_at_launch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            files_root = Path(tmp)
            for file_id in ("original", "shared", "new"):
                file_dir = files_root / file_id
                file_dir.mkdir()
                (file_dir / "meta.json").write_text(json.dumps({
                    "session_id": "session-steer",
                    "path": f"/uploads/{file_id}.png",
                    "filename": f"{file_id}.png",
                    "content_type": "image/png",
                }))
            with patch.object(agent_server, "FILES_ROOT", files_root):
                turn = prepare_steered_turn(
                    {
                        "queued_id": "queued-steer",
                        "prompt": "Use the smaller batch instead.",
                        "file_ids": ["new", "shared"],
                    },
                    {
                        "run_id": "run-original",
                        "prompt": "Launch the complete training sweep.",
                        "file_ids": ["original", "shared"],
                    },
                )
                provider_prompt = build_turn_provider_prompt(
                    "session-steer",
                    turn["prompt"],
                    turn["file_ids"],
                    turn["steering_lineage"],
                )

        self.assertEqual(turn["prompt"], "Use the smaller batch instead.")
        self.assertEqual(turn["steering_lineage"], [
            {
                "prompt": "Launch the complete training sweep.",
                "file_ids": ["original", "shared"],
            },
            {
                "prompt": "Use the smaller batch instead.",
                "file_ids": ["new", "shared"],
            },
        ])
        self.assertNotIn("[Interrupted message]", json.dumps(turn))
        self.assertNotIn("/uploads/", json.dumps(turn))
        self.assertNotIn("Launch the complete training sweep.", provider_prompt)
        self.assertNotIn("[Interrupted message]", provider_prompt)
        self.assertNotIn("/uploads/original.png", provider_prompt)
        self.assertIn("Use the smaller batch instead.", provider_prompt)
        self.assertIn("/uploads/new.png", provider_prompt)
        self.assertEqual(turn["display_prompt"], "Use the smaller batch instead.")
        self.assertEqual(turn["file_ids"], ["new", "shared"])
        self.assertEqual(turn["display_file_ids"], ["new", "shared"])
        self.assertEqual(turn["steer_interrupted_run_id"], "run-original")
        self.assertFalse(turn["replays_interrupted_message"])

    def test_text_only_steer_keeps_the_interrupted_image_scoped_to_old_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            files_root = Path(tmp)
            file_dir = files_root / "original-image"
            file_dir.mkdir()
            (file_dir / "meta.json").write_text(json.dumps({
                "session_id": "session-steer",
                "path": "/uploads/original.png",
                "filename": "original.png",
                "content_type": "image/png",
            }))
            with patch.object(agent_server, "FILES_ROOT", files_root):
                turn = prepare_steered_turn(
                    {"queued_id": "queued-steer", "prompt": "Look at the warning instead.", "file_ids": []},
                    {"run_id": "run-original", "prompt": "What is this?", "file_ids": ["original-image"]},
                )
                provider_prompt = build_turn_provider_prompt(
                    "session-steer",
                    turn["prompt"],
                    turn["file_ids"],
                    turn["steering_lineage"],
                )

        self.assertNotIn("/uploads/original.png", provider_prompt)
        self.assertEqual(provider_prompt, "Look at the warning instead.")
        self.assertEqual(turn["prompt"], "Look at the warning instead.")
        self.assertEqual(turn["file_ids"], [])
        self.assertEqual(turn["display_file_ids"], [])

    def test_image_only_messages_remain_distinct_during_steering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            files_root = Path(tmp)
            for file_id in ("original-image", "new-image"):
                file_dir = files_root / file_id
                file_dir.mkdir()
                filename = "original.png" if file_id == "original-image" else "new.png"
                (file_dir / "meta.json").write_text(json.dumps({
                    "session_id": "session-steer",
                    "path": f"/uploads/{filename}",
                    "filename": filename,
                    "content_type": "image/png",
                }))
            with patch.object(agent_server, "FILES_ROOT", files_root):
                turn = prepare_steered_turn(
                    {"queued_id": "queued-steer", "prompt": "", "file_ids": ["new-image"]},
                    {"run_id": "run-original", "prompt": "", "file_ids": ["original-image"]},
                )
                provider_prompt = build_turn_provider_prompt(
                    "session-steer",
                    turn["prompt"],
                    turn["file_ids"],
                    turn["steering_lineage"],
                )

        self.assertEqual(turn["prompt"], "")
        self.assertIn("/uploads/new.png", provider_prompt)
        self.assertNotIn("/uploads/original.png", provider_prompt)
        self.assertEqual(turn["display_prompt"], "")
        self.assertEqual(turn["file_ids"], ["new-image"])
        self.assertEqual(turn["display_file_ids"], ["new-image"])

    def test_plain_promotion_stays_unchanged_without_an_interrupted_turn(self) -> None:
        selected = {"queued_id": "queued-steer", "prompt": "Run this now.", "file_ids": []}
        self.assertEqual(prepare_steered_turn(selected, None), selected)

    def test_repeated_steering_stays_flat_instead_of_nesting_generated_wrappers(self) -> None:
        first = prepare_steered_turn(
            {"prompt": "First steering instruction.", "file_ids": []},
            {"run_id": "run-original", "prompt": "Original request.", "file_ids": []},
        )
        second = prepare_steered_turn(
            {"prompt": "Second steering instruction.", "file_ids": []},
            {
                "run_id": "run-first-steer",
                "prompt": first["prompt"],
                "file_ids": first["file_ids"],
                "steering_lineage": first["steering_lineage"],
            },
        )
        provider_prompt = build_turn_provider_prompt(
            "session-steer",
            second["prompt"],
            second["file_ids"],
            second["steering_lineage"],
        )

        self.assertEqual(second["prompt"], "Second steering instruction.")
        self.assertEqual(
            [item["prompt"] for item in second["steering_lineage"]],
            ["Original request.", "First steering instruction.", "Second steering instruction."],
        )
        self.assertEqual(provider_prompt, "Second steering instruction.")
        self.assertNotIn("[AgentsDock steering context]", provider_prompt)
        self.assertNotIn("[Interrupted user message]", provider_prompt)
        self.assertNotIn("Original request.", provider_prompt)
        self.assertNotIn("First steering instruction.", provider_prompt)

    def test_nested_legacy_steering_envelopes_restore_flat_lineage(self) -> None:
        first = (
            agent_server.LEGACY_STEERING_PREFIX
            + "[Interrupted message]\nOriginal request.\n"
            "[End interrupted message]\n\n"
            "[Steering message]\nFirst steering instruction.\n"
            "[End steering message]"
        )
        second = (
            agent_server.LEGACY_STEERING_PREFIX
            + f"[Interrupted message]\n{first}\n"
            "[End interrupted message]\n\n"
            "[Steering message]\nSecond steering instruction.\n"
            "[End steering message]"
        )

        lineage = agent_server.parse_legacy_steering_lineage(second)

        self.assertEqual(
            [message["prompt"] for message in lineage],
            [
                "Original request.",
                "First steering instruction.",
                "Second steering instruction.",
            ],
        )


class StopTurnProviderReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def test_queue_append_failure_removes_only_provisional_item(self) -> None:
        existing = {
            "queued_id": "existing",
            "prompt": "Keep me.",
            "_durable": True,
        }
        queued = {"chat-1": deque([existing])}
        request = agent_server.TurnRequest(prompt="New message")
        session = {"id": "chat-1", "backend": "codex"}
        with patch.object(agent_server.STORE, "sessions", {"chat-1": session}), \
             patch.object(agent_server, "QUEUED_TURNS", queued), \
             patch.object(agent_server, "append_durable_event", new_callable=AsyncMock, side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                await agent_server.enqueue_turn("chat-1", request, session)

        self.assertEqual(list(queued["chat-1"]), [existing])

    async def test_queue_append_cancellation_cannot_leave_provisional_blocker(self) -> None:
        queued: dict[str, deque[dict[str, object]]] = {}
        request = agent_server.TurnRequest(prompt="Do not strand this admission")
        session = {"id": "chat-1", "backend": "codex"}
        append_entered = asyncio.Event()

        async def blocked_append(*_args, **_kwargs):
            append_entered.set()
            await asyncio.Event().wait()

        with patch.object(agent_server.STORE, "sessions", {"chat-1": session}), \
             patch.object(agent_server, "QUEUED_TURNS", queued), \
             patch.object(agent_server, "BUSY_SESSIONS", {"chat-1"}), \
             patch.object(agent_server, "append_durable_event", side_effect=blocked_append), \
             patch.object(agent_server, "schedule_next_queued_turn") as schedule:
            admission = asyncio.create_task(
                agent_server.enqueue_turn("chat-1", request, session)
            )
            await asyncio.wait_for(append_entered.wait(), timeout=1)
            self.assertEqual(agent_server.update_blocking_queued_turn_count_locked(), 1)

            admission.cancel()
            admission.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await admission

            self.assertNotIn("chat-1", queued)
            self.assertEqual(agent_server.update_blocking_queued_turn_count_locked(), 0)
            schedule.assert_not_called()

    async def test_successful_queue_append_becomes_restart_durable(self) -> None:
        queued: dict[str, deque[dict[str, object]]] = {}
        request = agent_server.TurnRequest(prompt="New message")
        session = {"id": "chat-1", "backend": "codex"}
        with patch.object(agent_server.STORE, "sessions", {"chat-1": session}), \
             patch.object(agent_server, "QUEUED_TURNS", queued), \
             patch.object(agent_server, "BUSY_SESSIONS", {"chat-1"}), \
             patch.object(agent_server, "append_durable_event", new_callable=AsyncMock, return_value={}), \
             patch.object(agent_server, "schedule_next_queued_turn") as schedule:
            await agent_server.enqueue_turn("chat-1", request, session)

        self.assertTrue(queued["chat-1"][0]["_durable"])
        schedule.assert_not_called()

    async def test_cancellation_after_queue_fsync_keeps_live_durable_row(self) -> None:
        queued: dict[str, deque[dict[str, object]]] = {}
        request = agent_server.TurnRequest(prompt="Keep this even if I disconnect")
        session = {"id": "chat-1", "backend": "codex"}
        with patch.object(agent_server.STORE, "sessions", {"chat-1": session}), \
             patch.object(agent_server, "QUEUED_TURNS", queued), \
             patch.object(agent_server, "BUSY_SESSIONS", {"chat-1"}), \
             patch.object(agent_server, "managed_server_update_blocker", return_value=None), \
             patch.object(
                 agent_server,
                 "append_durable_event",
                 new_callable=AsyncMock,
                 return_value={"type": "turn_queued"},
             ), \
             patch.object(
                 agent_server,
                 "commit_durable_provider_cross_chat_reference_grants",
                 new_callable=AsyncMock,
                 side_effect=asyncio.CancelledError,
             ), \
             patch.object(agent_server, "schedule_next_queued_turn") as schedule:
            with self.assertRaises(asyncio.CancelledError):
                await agent_server.enqueue_turn("chat-1", request, session)

            self.assertEqual(len(queued["chat-1"]), 1)
            self.assertTrue(queued["chat-1"][0]["_durable"])
            self.assertEqual(agent_server.update_blocking_queued_turn_count_locked(), 0)
            schedule.assert_called_once_with("chat-1")

    async def test_pre_spawn_force_send_defers_without_cancelling_the_original_turn(self) -> None:
        stop_requests: set[str] = set()
        with patch.object(agent_server, "ACTIVE", {}), \
                patch.object(agent_server, "BUSY_SESSIONS", {"chat-1"}), \
                patch.object(agent_server, "STOP_REQUESTS", stop_requests), \
                patch.object(agent_server, "STOPPED_RUNS", set()):
            result = await agent_server.stop_turn(
                "chat-1",
                emit_event=False,
                schedule_queue=False,
                require_provider_turn_ready=True,
            )

        self.assertFalse(result["stopped"])
        self.assertTrue(result["deferred"])
        self.assertNotIn("chat-1", stop_requests)

    async def test_explicit_idle_stop_keeps_queue_paused_without_scheduling(self) -> None:
        queued = {
            "chat-1": deque([{
                "queued_id": "queued-kept",
                "prompt": "Keep this message.",
                "_durable": True,
            }]),
        }
        append_durable_event = AsyncMock(return_value={})
        with patch.object(agent_server.STORE, "sessions", {
                "chat-1": {"id": "chat-1", "backend": "claude"},
            }), patch.object(agent_server, "ACTIVE", {}), \
                patch.object(agent_server, "BUSY_SESSIONS", set()), \
                patch.object(agent_server, "QUEUED_TURNS", queued), \
                patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                patch.object(agent_server, "CLAUDE_SDK_MANAGER", None), \
                patch.object(agent_server, "append_durable_event", append_durable_event), \
                patch.object(agent_server, "cancel_codex_interactions", AsyncMock()), \
                patch.object(agent_server, "cancel_claude_interactions", AsyncMock()), \
                patch.object(agent_server, "schedule_next_queued_turn") as schedule:
            result = await agent_server.stop_turn("chat-1")

        self.assertTrue(result["stopped"])
        self.assertTrue(queued["chat-1"][0]["_paused_after_stop"])
        self.assertEqual(
            append_durable_event.await_args.args[1],
            "turn_queue_paused",
        )
        schedule.assert_not_called()

    async def test_idle_stop_pauses_promotion_waiting_for_lifecycle(self) -> None:
        queued_item = {
            "queued_id": "queued-in-flight",
            "prompt": "Do not start after Stop wins.",
            "_durable": True,
            "_paused_after_stop": False,
        }
        queued = {"chat-1": deque([queued_item])}
        queue_start_tasks: dict[str, asyncio.Task[object]] = {}
        descendant_cleanup_started = asyncio.Event()
        finish_descendant_cleanup = asyncio.Event()

        async def gated_descendant_cleanup(
            *_args: object,
            **_kwargs: object,
        ) -> dict[str, object]:
            descendant_cleanup_started.set()
            await finish_descendant_cleanup.wait()
            return agent_server.empty_subagent_stop_result()

        manager = object()
        append_durable_event = AsyncMock(return_value={})
        start_locked = AsyncMock(return_value={"run_id": "unexpected"})
        with (
            patch.object(agent_server.STORE, "sessions", {
                "chat-1": {
                    "id": "chat-1",
                    "backend": agent_server.BACKEND_CODEX,
                    "session_id": "thread-root",
                },
            }),
            patch.multiple(
                agent_server,
                ACTIVE={},
                BUSY_SESSIONS=set(),
                CURRENT_TURNS={},
                STOP_REQUESTS=set(),
                STOPPED_RUNS=set(),
                EXPLICIT_STOP_OPERATIONS={},
                RUN_METADATA={},
                SESSION_TURN_TASKS={},
                CODEX_NATIVE_ACTION_TASKS={},
                QUEUED_TURNS=queued,
                RUN_NOW_TURNS={},
                STEERING_SESSIONS=set(),
                QUEUE_START_TASKS=queue_start_tasks,
                CODEX_APP_SERVER_MANAGER=manager,
                append_durable_event=append_durable_event,
                cancel_codex_interactions=AsyncMock(),
                cancel_claude_interactions=AsyncMock(),
                stop_codex_descendant_subagents=AsyncMock(
                    side_effect=gated_descendant_cleanup
                ),
                settle_idle_codex_goal_for_stop=AsyncMock(return_value={}),
                managed_server_update_blocker=lambda: None,
            ),
            patch.object(agent_server, "_start_turn_locked", start_locked),
        ):
            stop_task = asyncio.create_task(
                agent_server.stop_turn_endpoint("chat-1")
            )
            await asyncio.wait_for(
                descendant_cleanup_started.wait(),
                timeout=0.5,
            )
            promotion_task = asyncio.create_task(
                agent_server.start_next_queued_turn("chat-1")
            )
            try:
                for _ in range(100):
                    if queue_start_tasks.get("chat-1") is promotion_task:
                        break
                    await asyncio.sleep(0)
                else:
                    self.fail("queue promotion did not register its owner")
                self.assertIs(queued["chat-1"][0], queued_item)
                finish_descendant_cleanup.set()
                result, _ = await asyncio.gather(stop_task, promotion_task)
            finally:
                finish_descendant_cleanup.set()
                if not stop_task.done():
                    stop_task.cancel()
                if not promotion_task.done():
                    promotion_task.cancel()
                await asyncio.gather(
                    stop_task,
                    promotion_task,
                    return_exceptions=True,
                )

        self.assertTrue(result["stopped"])
        self.assertTrue(queued_item["_paused_after_stop"])
        self.assertIs(queued["chat-1"][0], queued_item)
        start_locked.assert_not_awaited()
        append_durable_event.assert_awaited_once()
        self.assertFalse(queue_start_tasks)

    async def test_stalled_explicit_stop_cleanup_does_not_block_chat_access(
        self,
    ) -> None:
        cleanup_started = asyncio.Event()
        finish_cleanup = asyncio.Event()
        lifecycle_locks: dict[str, asyncio.Lock] = {}

        async def stalled_queue_pause(
            *_args: object,
            **_kwargs: object,
        ) -> int:
            cleanup_started.set()
            await finish_cleanup.wait()
            return 0

        session = {
            "id": "chat-1",
            "backend": agent_server.BACKEND_CODEX,
            "provider_cross_chat_routes": [],
        }
        mark_read = AsyncMock(return_value=session)
        enqueue = AsyncMock(return_value={
            "queued": True,
            "queued_id": "queued-during-stop",
        })
        with (
            patch.object(agent_server.STORE, "sessions", {"chat-1": session}),
            patch.object(agent_server.STORE, "mark_read", mark_read),
            patch.multiple(
                agent_server,
                ACTIVE={},
                BUSY_SESSIONS=set(),
                CURRENT_TURNS={},
                STOP_REQUESTS=set(),
                STOPPED_RUNS=set(),
                EXPLICIT_STOP_OPERATIONS={},
                SESSION_TURN_TASKS={},
                CODEX_NATIVE_ACTION_TASKS={},
                QUEUED_TURNS={},
                RUN_NOW_TURNS={},
                STEERING_SESSIONS=set(),
                QUEUE_START_TASKS={},
                SESSION_LIFECYCLE_LOCKS=lifecycle_locks,
                CODEX_APP_SERVER_MANAGER=None,
                append_durable_event=AsyncMock(return_value={}),
                cancel_codex_interactions=AsyncMock(),
                cancel_claude_interactions=AsyncMock(),
                pause_queued_turns_after_explicit_stop=AsyncMock(
                    side_effect=stalled_queue_pause
                ),
                settle_idle_codex_goal_for_stop=AsyncMock(return_value={}),
                enqueue_turn=enqueue,
                managed_server_update_blocker=lambda: None,
            ),
            patch.object(agent_server, "schedule_next_queued_turn") as schedule,
        ):
            stop_task = asyncio.create_task(
                agent_server.stop_turn_endpoint("chat-1")
            )
            await asyncio.wait_for(cleanup_started.wait(), timeout=0.5)
            try:
                self.assertTrue(agent_server.explicit_stop_in_progress("chat-1"))
                self.assertFalse(
                    agent_server.session_lifecycle_lock("chat-1").locked()
                )

                routes, read, queued = await asyncio.wait_for(
                    asyncio.gather(
                        agent_server.list_agent_handoff_routes("chat-1"),
                        agent_server.mark_session_read(
                            "chat-1",
                            agent_server.ReadSessionRequest(
                                last_read_agent_event_seq=42
                            ),
                        ),
                        agent_server.post_turn(
                            "chat-1",
                            agent_server.TurnRequest(
                                prompt="Queue while Stop cleanup is stalled."
                            ),
                        ),
                    ),
                    timeout=0.5,
                )

                self.assertEqual(routes, {
                    "routes": [],
                    "max_routes": agent_server.PROVIDER_CROSS_CHAT_ROUTE_LIMIT,
                })
                self.assertEqual(read["session"], agent_server.public_session(session))
                self.assertTrue(queued["queued"])
                mark_read.assert_awaited_once_with("chat-1", 42)
                enqueue.assert_awaited_once()
                self.assertFalse(stop_task.done())
            finally:
                finish_cleanup.set()
                result = await asyncio.wait_for(stop_task, timeout=0.5)

        self.assertTrue(result["stopped"])
        self.assertFalse(agent_server.explicit_stop_in_progress("chat-1"))
        schedule.assert_called_once_with("chat-1")

    async def test_cancelled_stop_waiter_does_not_cancel_admitted_cleanup(
        self,
    ) -> None:
        cleanup_started = asyncio.Event()
        finish_cleanup = asyncio.Event()
        operations: dict[str, asyncio.Task[dict[str, object]]] = {}

        async def stalled_queue_pause(_session_id: str) -> int:
            cleanup_started.set()
            await finish_cleanup.wait()
            return 0

        session = {"id": "chat-1", "backend": agent_server.BACKEND_CODEX}
        with (
            patch.object(agent_server.STORE, "sessions", {"chat-1": session}),
            patch.multiple(
                agent_server,
                ACTIVE={},
                BUSY_SESSIONS=set(),
                CURRENT_TURNS={},
                STOP_REQUESTS=set(),
                STOPPED_RUNS=set(),
                EXPLICIT_STOP_OPERATIONS=operations,
                SESSION_TURN_TASKS={},
                CODEX_NATIVE_ACTION_TASKS={},
                QUEUED_TURNS={},
                RUN_NOW_TURNS={},
                STEERING_SESSIONS=set(),
                QUEUE_START_TASKS={},
                SESSION_LIFECYCLE_LOCKS={},
                CODEX_APP_SERVER_MANAGER=None,
                pause_queued_turns_after_explicit_stop=AsyncMock(
                    side_effect=stalled_queue_pause
                ),
                cancel_codex_interactions=AsyncMock(),
                cancel_claude_interactions=AsyncMock(),
                settle_idle_codex_goal_for_stop=AsyncMock(return_value={}),
                managed_server_update_blocker=lambda: None,
            ),
            patch.object(agent_server, "schedule_next_queued_turn"),
        ):
            waiter = asyncio.create_task(
                agent_server.stop_turn_endpoint("chat-1")
            )
            await asyncio.wait_for(cleanup_started.wait(), timeout=0.5)
            operation = operations["chat-1"]
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter

            self.assertFalse(operation.cancelled())
            self.assertFalse(operation.done())
            self.assertTrue(agent_server.explicit_stop_in_progress("chat-1"))

            finish_cleanup.set()
            result = await asyncio.wait_for(operation, timeout=0.5)

        self.assertTrue(result["stopped"])
        self.assertFalse(operations)

    async def test_detached_stop_cleanup_blocks_update_and_forced_restart(
        self,
    ) -> None:
        finish_cleanup = asyncio.Event()
        operation = asyncio.create_task(finish_cleanup.wait())
        try:
            with patch.multiple(
                agent_server,
                ACTIVE={},
                BUSY_SESSIONS=set(),
                CURRENT_TURNS={},
                SERVER_MAINTENANCE_SESSIONS=set(),
                EXPLICIT_STOP_OPERATIONS={"chat-1": operation},
                QUEUED_TURNS={},
                RUN_NOW_TURNS={},
                DELETING_SESSIONS=set(),
                CODEX_GOALS_RECONFIGURING=False,
                UNSAFE_HTTP_MUTATION_TASKS={},
                CODEX_APP_SERVER_MANAGER=None,
                CLAUDE_SDK_MANAGER=None,
                CODEX_NATIVE_ACTION_TASKS={},
                CODEX_PENDING_INTERACTIONS={},
            ):
                self.assertEqual(
                    agent_server.server_update_active_session_ids_locked(),
                    ["chat-1"],
                )
                snapshot = agent_server.server_restart_blocker_snapshot_locked(
                    tmux_cgroup_state={}
                )

            self.assertEqual(snapshot["server_maintenance_count"], 1)
            self.assertTrue(snapshot["has_safety_blockers"])
        finally:
            finish_cleanup.set()
            await operation

    async def test_cross_chat_queue_failures_deliver_after_both_lifecycle_locks_release(
        self,
    ) -> None:
        sessions = {
            chat_id: {
                "id": chat_id,
                "backend": agent_server.BACKEND_CODEX,
            }
            for chat_id in ("chat-a", "chat-b")
        }
        queued = {
            chat_id: deque([{
                "queued_id": f"queued-{chat_id}",
                "prompt": "invalid exchange delivery",
                "purpose": "cross_chat_handoff_delivery",
                "cross_chat_exchange_id": f"exchange-{chat_id}",
                "cross_chat_exchange_leg_id": f"leg-{chat_id}",
                "source_session_id": other_id,
                "target_session_id": chat_id,
                "_durable": True,
                "_paused_after_stop": False,
            }])
            for chat_id, other_id in (
                ("chat-a", "chat-b"),
                ("chat-b", "chat-a"),
            )
        }
        both_discards_entered = asyncio.Event()
        discard_count = 0
        wake_count = 0
        both_wakes_finished = asyncio.Event()

        async def reject_turn(*_args: object, **_kwargs: object) -> None:
            raise agent_server.HTTPException(
                status_code=400,
                detail="invalid exchange delivery",
            )

        async def finish_exchange_leg(
            leg_id: str,
            **_kwargs: object,
        ) -> tuple[dict[str, object], dict[str, object]]:
            nonlocal discard_count
            target_id = "chat-a" if leg_id == "leg-chat-a" else "chat-b"
            source_id = "chat-b" if target_id == "chat-a" else "chat-a"
            discard_count += 1
            if discard_count == 2:
                both_discards_entered.set()
            await both_discards_entered.wait()
            return (
                {"id": f"exchange-{target_id}", "status": "failed"},
                {
                    "id": leg_id,
                    "status": "failed",
                    "source_session_id": source_id,
                    "target_session_id": target_id,
                },
            )

        async def deliver_failure_status(
            _exchange: dict[str, object],
            *,
            failed_session_id: str,
            failed_leg: dict[str, object],
        ) -> None:
            nonlocal wake_count
            # The deferred wake first waits for this failed target's lock. It
            # must not retain that lock while starting the opposite chat.
            self.assertFalse(
                agent_server.session_lifecycle_lock(
                    failed_session_id
                ).locked()
            )
            source_id = str(failed_leg.get("source_session_id") or "")
            async with agent_server.session_lifecycle_lock(source_id):
                wake_count += 1
                if wake_count == 2:
                    both_wakes_finished.set()

        with (
            patch.object(agent_server.STORE, "sessions", sessions),
            patch.multiple(
                agent_server,
                ACTIVE={},
                BUSY_SESSIONS=set(),
                CURRENT_TURNS={},
                QUEUED_TURNS=queued,
                RUN_NOW_TURNS={},
                STEERING_SESSIONS=set(),
                QUEUE_START_TASKS={},
                SESSION_TURN_TASKS={},
                SESSION_LIFECYCLE_LOCKS={},
                CROSS_CHAT_STATUS_WAKE_TASKS=set(),
                append_durable_event=AsyncMock(return_value={}),
                append_event=AsyncMock(return_value={}),
                append_cross_chat_exchange_leg_terminal_lifecycle=AsyncMock(),
                append_cross_chat_exchange_terminal_lifecycle=AsyncMock(),
            ),
            patch.object(
                agent_server,
                "_start_turn_locked",
                side_effect=reject_turn,
            ),
            patch.object(
                agent_server.CROSS_CHAT,
                "finish_exchange_leg",
                side_effect=finish_exchange_leg,
            ),
            patch.object(
                agent_server,
                "maybe_deliver_cross_chat_exchange_failure_status",
                side_effect=deliver_failure_status,
            ),
        ):
            await asyncio.wait_for(
                asyncio.gather(
                    agent_server.start_next_queued_turn("chat-a"),
                    agent_server.start_next_queued_turn("chat-b"),
                ),
                timeout=0.5,
            )
            await asyncio.wait_for(
                both_wakes_finished.wait(),
                timeout=0.5,
            )

        self.assertEqual(discard_count, 2)
        self.assertEqual(wake_count, 2)
        self.assertFalse(queued)

    async def test_stopping_scheduled_job_releases_human_queue_without_pausing(self) -> None:
        human_turn = {
            "queued_id": "queued-human",
            "prompt": "Run this after the scheduled report.",
            "_durable": True,
        }
        queued = {
            "chat-1": deque([human_turn]),
        }
        sessions = {
            "chat-1": {"id": "chat-1", "backend": "claude"},
        }
        current_turns = {
            "chat-1": {
                "run_id": "run-job",
                "backend": "claude",
                "purpose": "scheduled_job",
            },
        }
        busy = {"chat-1"}
        queue_start_tasks: dict[str, asyncio.Task[object]] = {}
        launch_started = asyncio.Event()
        finish_launch = asyncio.Event()
        launch_calls: list[tuple[str, agent_server.TurnRequest, dict[str, object]]] = []

        async def gated_start_turn(
            session_id: str,
            request: agent_server.TurnRequest,
            **kwargs: object,
        ) -> dict[str, object]:
            launch_calls.append((session_id, request, kwargs))
            launch_started.set()
            await finish_launch.wait()
            return {"run_id": "run-human", "queued": False}

        append_durable_event = AsyncMock(return_value={})
        with patch.object(agent_server.STORE, "sessions", sessions), \
                patch.multiple(
                    agent_server,
                    ACTIVE={},
                    BUSY_SESSIONS=busy,
                    CURRENT_TURNS=current_turns,
                    STOP_REQUESTS=set(),
                    STOPPED_RUNS=set(),
                    RUN_METADATA={
                        "run-job": {"purpose": "scheduled_job"},
                    },
                    SESSION_TURN_TASKS={},
                    CODEX_NATIVE_ACTION_TASKS={},
                    QUEUED_TURNS=queued,
                    RUN_NOW_TURNS={},
                    STEERING_SESSIONS=set(),
                    QUEUE_START_TASKS=queue_start_tasks,
                    STOP_CONFIRM_TIMEOUT_SECONDS=0,
                    append_durable_event=append_durable_event,
                    append_event=AsyncMock(return_value={}),
                    revoke_cross_chat_capability=AsyncMock(),
                    cancel_codex_interactions=AsyncMock(),
                    cancel_claude_interactions=AsyncMock(),
                ), \
                patch.object(agent_server, "_start_turn_locked", side_effect=gated_start_turn):
            result = await agent_server.stop_turn(
                "chat-1",
                cascade_claude_subagents=False,
            )
            promotion_task: asyncio.Task[object] | None = None
            try:
                await asyncio.wait_for(launch_started.wait(), timeout=0.5)
                promotion_task = queue_start_tasks.get("chat-1")
                self.assertIsNotNone(promotion_task)
                await asyncio.sleep(0)

                self.assertTrue(result["stopped"])
                self.assertNotIn("_paused_after_stop", human_turn)
                append_durable_event.assert_not_awaited()
                self.assertNotIn("chat-1", busy)
                self.assertNotIn("chat-1", current_turns)
                self.assertNotIn("chat-1", queued)
                self.assertEqual(len(launch_calls), 1)
                launched_session, launched_request, launched_kwargs = launch_calls[0]
                self.assertEqual(launched_session, "chat-1")
                self.assertEqual(
                    launched_request.prompt,
                    "Run this after the scheduled report.",
                )
                self.assertEqual(launched_kwargs["queued_id"], "queued-human")
            finally:
                finish_launch.set()
                if promotion_task is not None:
                    await asyncio.gather(promotion_task, return_exceptions=True)

        self.assertFalse(queue_start_tasks)

    async def test_hung_codex_exec_hard_stop_drains_without_goal_fence(self) -> None:
        human_turn = {
            "queued_id": "queued-human",
            "prompt": "Continue after Codex exec is stopped.",
            "_durable": True,
        }
        sessions = {
            "chat-1": {
                "id": "chat-1",
                "backend": agent_server.BACKEND_CODEX,
                "active_run": {"run_id": "run-job"},
            },
        }
        active = {"chat-1": {
            "proc": object(),
            "run_id": "run-job",
            "backend": agent_server.BACKEND_CODEX,
            "transport": agent_server.CODEX_TRANSPORT_EXEC,
            "provider_turn_ready": True,
            "stop_requested": False,
        }}
        busy = {"chat-1"}
        current = {"chat-1": {
            "run_id": "run-job",
            "backend": agent_server.BACKEND_CODEX,
            "purpose": "scheduled_job",
        }}
        queued = {"chat-1": deque([human_turn])}
        queue_start_tasks: dict[str, asyncio.Task[object]] = {}
        launch_started = asyncio.Event()
        finish_launch = asyncio.Event()
        release_old = asyncio.Event()
        launch_calls: list[tuple[str, agent_server.TurnRequest]] = []

        async def cancellation_hostile_owner() -> None:
            while not release_old.is_set():
                try:
                    await release_old.wait()
                except asyncio.CancelledError:
                    continue

        async def gated_start_turn(
            session_id: str,
            request: agent_server.TurnRequest,
            **_kwargs: object,
        ) -> dict[str, object]:
            launch_calls.append((session_id, request))
            launch_started.set()
            await finish_launch.wait()
            return {"run_id": "run-human", "queued": False}

        owner_task = asyncio.create_task(cancellation_hostile_owner())
        quarantine = AsyncMock(return_value=True)
        append_event = AsyncMock(return_value={})
        with patch.object(agent_server.STORE, "sessions", sessions), \
                patch.multiple(
                    agent_server,
                    ACTIVE=active,
                    BUSY_SESSIONS=busy,
                    CURRENT_TURNS=current,
                    STOP_REQUESTS=set(),
                    STOPPED_RUNS=set(),
                    RUN_METADATA={"run-job": {"purpose": "scheduled_job"}},
                    QUEUED_TURNS=queued,
                    RUN_NOW_TURNS={},
                    STEERING_SESSIONS=set(),
                    QUEUE_START_TASKS=queue_start_tasks,
                    SESSION_TURN_TASKS={"chat-1": {owner_task}},
                    CODEX_NATIVE_ACTION_TASKS={},
                    STOP_CONFIRM_TIMEOUT_SECONDS=0.01,
                    append_event=append_event,
                    revoke_cross_chat_capability=AsyncMock(),
                    cancel_codex_interactions=AsyncMock(),
                    cancel_claude_interactions=AsyncMock(),
                    terminate_process_tree=AsyncMock(return_value=True),
                    quarantine_codex_goal_thread=quarantine,
                ), patch.object(
                    agent_server,
                    "_start_turn_locked",
                    side_effect=gated_start_turn,
                ):
            promotion_task: asyncio.Task[object] | None = None
            try:
                result = await asyncio.wait_for(
                    agent_server.stop_turn("chat-1"),
                    timeout=0.5,
                )
                await asyncio.wait_for(launch_started.wait(), 0.5)
                promotion_task = queue_start_tasks.get("chat-1")

                self.assertTrue(result["stopped"])
                self.assertTrue(result["hard_stop"])
                self.assertEqual(len(launch_calls), 1)
                self.assertEqual(
                    launch_calls[0][1].prompt,
                    "Continue after Codex exec is stopped.",
                )
                quarantine.assert_not_awaited()
                terminal_calls = [
                    call
                    for call in append_event.await_args_list
                    if call.args[1] == "turn_stopped"
                ]
                self.assertEqual(len(terminal_calls), 1)
            finally:
                release_old.set()
                finish_launch.set()
                await asyncio.gather(owner_task, return_exceptions=True)
                if promotion_task is not None:
                    await asyncio.gather(
                        promotion_task,
                        return_exceptions=True,
                    )

        self.assertFalse(queue_start_tasks)


class QueuedTurnPresentationTests(unittest.TestCase):
    def test_public_queue_reports_stop_and_delivery_uncertainty_holds(self) -> None:
        ordinary = agent_server.public_queued_turn(
            "chat-1",
            {"queued_id": "ordinary", "prompt": "Next"},
            1,
        )
        stopped = agent_server.public_queued_turn(
            "chat-1",
            {
                "queued_id": "stopped",
                "prompt": "Held after Stop",
                "_paused_after_stop": True,
            },
            2,
        )
        uncertain = agent_server.public_queued_turn(
            "chat-1",
            {
                "queued_id": "uncertain",
                "prompt": "Delivery may have happened",
                "_paused_after_stop": True,
                "_native_delivery_fenced": True,
            },
            3,
        )
        promoted = agent_server.public_queued_turn(
            "chat-1",
            {"queued_id": "promoted", "prompt": "In handoff"},
            1,
            promoted=True,
        )

        self.assertFalse(ordinary["promoted"])
        self.assertTrue(promoted["promoted"])
        self.assertFalse(ordinary["paused"])
        self.assertIsNone(ordinary["pause_reason"])
        self.assertTrue(stopped["paused"])
        self.assertEqual(stopped["pause_reason"], "stopped")
        self.assertTrue(uncertain["paused"])
        self.assertEqual(uncertain["pause_reason"], "delivery_uncertain")


class QueuedTurnEditTests(unittest.IsolatedAsyncioTestCase):
    async def test_visible_promoted_turn_rejects_every_queue_mutation_truthfully(
        self,
    ) -> None:
        original_sessions = agent_server.STORE.sessions
        original_queue = agent_server.QUEUED_TURNS
        original_run_now = agent_server.RUN_NOW_TURNS
        promoted = {
            "queued_id": "queued-promoted",
            "prompt": "Already handed off",
            "file_ids": [],
            "backend": "codex",
            "_durable": True,
        }
        try:
            agent_server.STORE.sessions = {
                "chat-edit": {"id": "chat-edit", "backend": "codex"}
            }
            agent_server.QUEUED_TURNS = {"chat-edit": deque()}
            agent_server.RUN_NOW_TURNS = {"chat-edit": promoted}
            with patch.object(
                agent_server, "managed_server_update_blocker", return_value=None
            ):
                snapshot = await agent_server.queued_turns_snapshot("chat-edit")
                self.assertEqual(snapshot[0]["queued_id"], "queued-promoted")
                self.assertTrue(snapshot[0]["promoted"])

                mutations = (
                    agent_server.unqueue_turn(
                        "chat-edit", "queued-promoted"
                    ),
                    agent_server.update_queued_turn(
                        "chat-edit",
                        "queued-promoted",
                        agent_server.UpdateQueuedTurnRequest(
                            prompt="Too late"
                        ),
                    ),
                    agent_server.move_queued_turn(
                        "chat-edit",
                        "queued-promoted",
                        agent_server.MoveQueuedTurnRequest(direction="down"),
                    ),
                )
                for mutation in mutations:
                    with self.assertRaises(HTTPException) as raised:
                        await mutation
                    self.assertEqual(raised.exception.status_code, 409)
                    self.assertEqual(
                        raised.exception.detail["code"],
                        "queued_turn_already_promoted",
                    )

            self.assertIs(agent_server.RUN_NOW_TURNS["chat-edit"], promoted)
        finally:
            agent_server.STORE.sessions = original_sessions
            agent_server.QUEUED_TURNS = original_queue
            agent_server.RUN_NOW_TURNS = original_run_now

    async def test_edit_rejects_legacy_hidden_display_reference(self) -> None:
        original_sessions = agent_server.STORE.sessions
        original_queue = agent_server.QUEUED_TURNS
        item = {
            "queued_id": "queued-hidden-display-edit",
            "prompt": "Tell @@SONIC now",
            "display_prompt": "Tell the team now",
            "file_ids": [],
            "chat_references": [],
            "team_references": [
                {
                    "kind": "recipient",
                    "recipient_kind": "server",
                    "team_id": "team_alpha",
                    "target_id": "node_sonic",
                    "display_name_snapshot": "SONIC",
                    "source_text_start": 5,
                    "source_text_end": 12,
                    "grant_intent": True,
                }
            ],
            "client_capabilities": [],
            "provider_cross_chat_route_snapshot": [],
            "secure_peer_route_snapshots": [],
            "cross_chat_obligation_ids": [],
            "cross_chat_exchange_ids": [],
            "backend": "codex",
        }
        original_item = {
            **item,
            "team_references": [dict(item["team_references"][0])],
        }
        try:
            agent_server.STORE.sessions = {
                "chat-edit": {"id": "chat-edit", "backend": "codex"}
            }
            agent_server.QUEUED_TURNS = {"chat-edit": deque([item])}
            with patch.object(
                agent_server, "managed_server_update_blocker", return_value=None
            ):
                with self.assertRaisesRegex(HTTPException, "display_prompt"):
                    await agent_server.update_queued_turn(
                        "chat-edit",
                        "queued-hidden-display-edit",
                        agent_server.UpdateQueuedTurnRequest(file_ids=[]),
                    )
            self.assertEqual(item, original_item)
        finally:
            agent_server.STORE.sessions = original_sessions
            agent_server.QUEUED_TURNS = original_queue

    async def test_edit_preserves_exact_prompt_for_team_reference_offsets(self) -> None:
        original_sessions = agent_server.STORE.sessions
        original_queue = agent_server.QUEUED_TURNS
        prompt = "  😀 Tell @@DPark  "
        mention = "@@DPark"
        start = len("  😀 Tell ".encode("utf-16-le")) // 2
        reference = agent_server.TeamReference(
            kind="recipient",
            recipient_kind="human",
            team_id="team_alpha",
            target_id="member_dpark",
            display_name_snapshot="DPark",
            source_text_start=start,
            source_text_end=start + len(mention),
            grant_intent=True,
        )
        item = {
            "queued_id": "queued-team-edit",
            "prompt": "old",
            "display_prompt": "old",
            "file_ids": [],
            "chat_references": [],
            "team_references": [],
            "client_capabilities": [],
            "provider_cross_chat_route_snapshot": [],
            "secure_peer_route_snapshots": [],
            "cross_chat_obligation_ids": [],
            "cross_chat_exchange_ids": [],
            "backend": "codex",
            "position": 1,
        }
        append = AsyncMock()
        try:
            agent_server.STORE.sessions = {
                "chat-edit": {
                    "id": "chat-edit",
                    "title": "Edit",
                    "backend": "codex",
                }
            }
            agent_server.QUEUED_TURNS = {
                "chat-edit": deque([item])
            }
            with (
                patch.object(
                    agent_server,
                    "managed_server_update_blocker",
                    return_value=None,
                ),
                patch.object(
                    agent_server,
                    "append_durable_event",
                    append,
                ),
            ):
                response = await agent_server.update_queued_turn(
                    "chat-edit",
                    "queued-team-edit",
                    agent_server.UpdateQueuedTurnRequest(
                        prompt=prompt,
                        team_references=[reference],
                    ),
                )

            updated = response["item"]
            self.assertEqual(updated["prompt"], prompt)
            self.assertEqual(updated["display_prompt"], prompt)
            self.assertEqual(
                updated["team_references"][0]["source_text_start"],
                start,
            )
            self.assertEqual(
                updated["team_references"][0]["source_text_end"],
                start + len(mention),
            )
            update_payload = append.await_args.args[2]
            self.assertEqual(update_payload["request_prompt"], prompt)
            self.assertEqual(update_payload["display_prompt"], prompt)
            self.assertEqual(
                update_payload["team_references"],
                updated["team_references"],
            )
        finally:
            agent_server.STORE.sessions = original_sessions
            agent_server.QUEUED_TURNS = original_queue

    async def test_edit_rejects_hidden_team_reference_without_mutating_queue(self) -> None:
        original_sessions = agent_server.STORE.sessions
        original_queue = agent_server.QUEUED_TURNS
        item = {
            "queued_id": "queued-hidden-team-reference",
            "prompt": "No team mention here",
            "file_ids": [],
            "chat_references": [],
            "team_references": [],
            "client_capabilities": [],
            "provider_cross_chat_route_snapshot": [],
            "secure_peer_route_snapshots": [],
            "cross_chat_obligation_ids": [],
            "cross_chat_exchange_ids": [],
            "backend": "codex",
        }
        original_item = dict(item)
        append = AsyncMock()
        try:
            agent_server.STORE.sessions = {
                "chat-edit": {
                    "id": "chat-edit",
                    "title": "Edit",
                    "backend": "codex",
                }
            }
            agent_server.QUEUED_TURNS = {
                "chat-edit": deque([item])
            }
            with (
                patch.object(
                    agent_server,
                    "managed_server_update_blocker",
                    return_value=None,
                ),
                patch.object(
                    agent_server,
                    "append_durable_event",
                    append,
                ),
            ):
                with self.assertRaisesRegex(HTTPException, "visible @@"):
                    await agent_server.update_queued_turn(
                        "chat-edit",
                        "queued-hidden-team-reference",
                        agent_server.UpdateQueuedTurnRequest(
                            team_references=[
                                agent_server.TeamReference(
                                    kind="recipient",
                                    recipient_kind="server",
                                    team_id="team_alpha",
                                    target_id="node_sonic",
                                    display_name_snapshot="SONIC",
                                    source_text_start=0,
                                    source_text_end=7,
                                )
                            ],
                        ),
                    )

            self.assertEqual(item, original_item)
            append.assert_not_awaited()
        finally:
            agent_server.STORE.sessions = original_sessions
            agent_server.QUEUED_TURNS = original_queue

    async def test_edit_updates_visible_prompt_lineage_and_recovery(self) -> None:
        original_sessions = agent_server.STORE.sessions
        original_queue = agent_server.QUEUED_TURNS
        item = {
            "queued_id": "queued-edit",
            "prompt": "Old raw prompt",
            "display_prompt": "Old visible prompt",
            "steering_prompt": "Old visible prompt",
            "steering_lineage": [
                {"prompt": "Original interrupted prompt", "file_ids": []},
                {"prompt": "Old visible prompt", "file_ids": []},
            ],
            "file_ids": [],
            "backend": "codex",
            "position": 1,
        }
        original_event = {
            "type": "turn_queued",
            "queued_id": "queued-edit",
            "prompt": "Old raw prompt",
            "request_prompt": "Old raw prompt",
            "display_prompt": "Old visible prompt",
            "steering_lineage": list(item["steering_lineage"]),
            "file_ids": [],
            "backend": "codex",
            "position": 1,
            "ts": "2026-08-26T00:00:00Z",
        }
        append = AsyncMock()
        try:
            agent_server.STORE.sessions = {
                "chat-edit": {"id": "chat-edit", "title": "Edit", "backend": "codex"}
            }
            agent_server.QUEUED_TURNS = {"chat-edit": deque([item])}
            with (
                patch.object(agent_server, "managed_server_update_blocker", return_value=None),
                patch.object(agent_server, "append_durable_event", append),
            ):
                response = await agent_server.update_queued_turn(
                    "chat-edit",
                    "queued-edit",
                    agent_server.UpdateQueuedTurnRequest(prompt="New visible prompt"),
                )
                snapshot = await agent_server.queued_turns_snapshot("chat-edit")

            updated = response["item"]
            self.assertEqual(updated["prompt"], "New visible prompt")
            self.assertEqual(updated["display_prompt"], "New visible prompt")
            self.assertEqual(updated["steering_prompt"], "New visible prompt")
            self.assertEqual(
                updated["steering_lineage"][-1]["prompt"],
                "New visible prompt",
            )
            self.assertEqual(snapshot[0]["prompt"], "New visible prompt")
            self.assertEqual(snapshot[0]["display_prompt"], "New visible prompt")
            provider_prompt = agent_server.build_turn_provider_prompt(
                "chat-edit",
                updated["prompt"],
                updated["file_ids"],
                updated["steering_lineage"],
            )
            self.assertIn("New visible prompt", provider_prompt)
            self.assertNotIn("Old visible prompt", provider_prompt)

            update_payload = append.await_args.args[2]
            self.assertEqual(update_payload["request_prompt"], "New visible prompt")
            self.assertEqual(update_payload["display_prompt"], "New visible prompt")
            self.assertEqual(
                update_payload["steering_lineage"][-1]["prompt"],
                "New visible prompt",
            )
            with tempfile.TemporaryDirectory() as tmp:
                event_file = Path(tmp) / "events.jsonl"
                event_file.write_text(
                    json.dumps(original_event) + "\n"
                    + json.dumps({"type": "turn_queue_updated", **update_payload}) + "\n"
                )
                with patch.object(agent_server, "events_path", return_value=event_file):
                    recovered = agent_server.scan_queued_turns_from_events([
                        ("chat-edit", agent_server.STORE.sessions["chat-edit"]),
                    ])["chat-edit"][0]
            self.assertEqual(recovered["prompt"], "New visible prompt")
            self.assertEqual(recovered["display_prompt"], "New visible prompt")
            self.assertEqual(
                recovered["steering_lineage"][-1]["prompt"],
                "New visible prompt",
            )
        finally:
            agent_server.STORE.sessions = original_sessions
            agent_server.QUEUED_TURNS = original_queue


class ProviderTurnTaskRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_delayed_provider_bind_cannot_replace_successor_for_any_transport(
        self,
    ) -> None:
        transports = (
            (agent_server.BACKEND_CLAUDE, agent_server.CLAUDE_TRANSPORT_PRINT),
            (agent_server.BACKEND_CODEX, agent_server.CODEX_TRANSPORT_EXEC),
            (agent_server.BACKEND_CODEX, agent_server.CODEX_TRANSPORT_APP_SERVER),
            (agent_server.BACKEND_CLAUDE, agent_server.CLAUDE_TRANSPORT_AGENT_SDK),
        )
        for backend, transport in transports:
            with self.subTest(transport=transport):
                replacement = {
                    "run_id": "run-new",
                    "backend": backend,
                    "transport": transport,
                }
                active = {"chat-1": replacement}
                busy = {"chat-1"}
                current = {"chat-1": {"run_id": "run-new"}}
                with patch.object(agent_server, "ACTIVE", active), \
                        patch.object(agent_server, "BUSY_SESSIONS", busy), \
                        patch.object(agent_server, "CURRENT_TURNS", current), \
                        patch.object(agent_server, "STOP_REQUESTS", set()), \
                        patch.object(agent_server, "STOPPED_RUNS", {"run-old"}):
                    bound, stop_requested = await agent_server.bind_active_turn(
                        "chat-1",
                        "run-old",
                        {
                            "run_id": "run-old",
                            "backend": backend,
                            "transport": transport,
                        },
                    )
                    cleared = await agent_server.clear_active_process(
                        "chat-1",
                        expected_run_id="run-old",
                    )

                self.assertFalse(bound)
                self.assertFalse(stop_requested)
                self.assertFalse(cleared)
                self.assertIs(active["chat-1"], replacement)
                self.assertIn("chat-1", busy)
                self.assertEqual(current["chat-1"]["run_id"], "run-new")

    async def test_stale_provider_identity_cannot_overwrite_successor(self) -> None:
        active = {"chat-1": {"run_id": "run-new"}}
        busy = {"chat-1"}
        current = {"chat-1": {"run_id": "run-new"}}
        save_provider = AsyncMock()
        append_event = AsyncMock()
        with patch.object(agent_server, "ACTIVE", active), \
                patch.object(agent_server, "BUSY_SESSIONS", busy), \
                patch.object(agent_server, "CURRENT_TURNS", current), \
                patch.object(
                    agent_server.STORE,
                    "save_provider_session",
                    save_provider,
                ), patch.object(agent_server, "append_event", append_event):
            persisted = await agent_server.persist_run_provider_session(
                "chat-1",
                "run-old",
                agent_server.BACKEND_CLAUDE,
                "provider-old",
            )

        self.assertFalse(persisted)
        save_provider.assert_not_awaited()
        append_event.assert_not_awaited()

    async def test_provider_runtime_broadcast_happens_after_active_lock_release(
        self,
    ) -> None:
        active = {"chat-1": {"run_id": "run-old"}}
        busy = {"chat-1"}
        current = {"chat-1": {"run_id": "run-old"}}
        lock_states: list[bool] = []

        async def observe_broadcast(*_args: object) -> None:
            lock_states.append(agent_server.ACTIVE_LOCK.locked())

        with patch.object(agent_server, "ACTIVE", active), \
                patch.object(agent_server, "BUSY_SESSIONS", busy), \
                patch.object(agent_server, "CURRENT_TURNS", current), \
                patch.object(
                    agent_server.STORE,
                    "save_provider_session",
                    AsyncMock(return_value={"state": "cleared"}),
                ), patch.object(
                    agent_server,
                    "broadcast_provider_runtime_changed",
                    side_effect=observe_broadcast,
                ), patch.object(
                    agent_server,
                    "append_event",
                    AsyncMock(return_value={}),
                ):
            persisted = await agent_server.persist_run_provider_session(
                "chat-1",
                "run-old",
                agent_server.BACKEND_CLAUDE,
                "provider-old",
            )

        self.assertTrue(persisted)
        self.assertEqual(lock_states, [False])

    async def test_cancel_after_terminal_marker_releases_slot_and_drains_queue(self) -> None:
        sessions = {
            "chat-1": {"id": "chat-1", "backend": "claude"},
        }
        active = {"chat-1": {"run_id": "run-old", "backend": "claude"}}
        busy = {"chat-1"}
        current = {"chat-1": {"run_id": "run-old", "backend": "claude"}}
        metadata = {"run-old": {"purpose": "scheduled_job"}}

        async def cancelled_runner() -> None:
            # The durable terminal marker already cleared sessions.active_run,
            # then cancellation landed before the legacy runner released BUSY.
            raise asyncio.CancelledError

        append_event = AsyncMock(return_value={})
        with patch.object(agent_server.STORE, "sessions", sessions), \
                patch.object(agent_server, "ACTIVE", active), \
                patch.object(agent_server, "BUSY_SESSIONS", busy), \
                patch.object(agent_server, "CURRENT_TURNS", current), \
                patch.object(agent_server, "STOP_REQUESTS", set()), \
                patch.object(agent_server, "STOPPED_RUNS", {"run-old"}), \
                patch.object(agent_server, "RUN_METADATA", metadata), \
                patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                patch.object(agent_server, "STEERING_SESSIONS", set()), \
                patch.object(agent_server, "append_event", append_event), \
                patch.object(agent_server, "schedule_next_queued_turn") as schedule:
            task = asyncio.create_task(agent_server.supervise_provider_turn_task(
                "chat-1",
                "run-old",
                "claude",
                cancelled_runner(),
            ))
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertNotIn("chat-1", active)
        self.assertNotIn("chat-1", busy)
        self.assertNotIn("chat-1", current)
        self.assertNotIn("run-old", metadata)
        append_event.assert_not_awaited()
        schedule.assert_called_once_with("chat-1")

    async def test_finalizer_and_stop_duplicate_drains_launch_queue_once(self) -> None:
        human_turn = {
            "queued_id": "queued-human",
            "prompt": "Continue after cancellation.",
            "_durable": True,
        }
        sessions = {
            "chat-1": {"id": "chat-1", "backend": "claude"},
        }
        active = {"chat-1": {"run_id": "run-job", "backend": "claude"}}
        busy = {"chat-1"}
        current = {
            "chat-1": {
                "run_id": "run-job",
                "backend": "claude",
                "purpose": "scheduled_job",
            },
        }
        queued = {"chat-1": deque([human_turn])}
        queue_start_tasks: dict[str, asyncio.Task[object]] = {}
        launch_started = asyncio.Event()
        finish_launch = asyncio.Event()
        launch_calls: list[tuple[str, agent_server.TurnRequest, dict[str, object]]] = []

        async def gated_start_turn(
            session_id: str,
            request: agent_server.TurnRequest,
            **kwargs: object,
        ) -> dict[str, object]:
            launch_calls.append((session_id, request, kwargs))
            launch_started.set()
            await finish_launch.wait()
            return {"run_id": "run-human", "queued": False}

        with patch.object(agent_server.STORE, "sessions", sessions), \
                patch.multiple(
                    agent_server,
                    ACTIVE=active,
                    BUSY_SESSIONS=busy,
                    CURRENT_TURNS=current,
                    STOP_REQUESTS=set(),
                    STOPPED_RUNS={"run-job"},
                    RUN_METADATA={
                        "run-job": {"purpose": "scheduled_job"},
                    },
                    QUEUED_TURNS=queued,
                    RUN_NOW_TURNS={},
                    STEERING_SESSIONS=set(),
                    QUEUE_START_TASKS=queue_start_tasks,
                    SESSION_TURN_TASKS={},
                    CODEX_NATIVE_ACTION_TASKS={},
                    append_event=AsyncMock(return_value={}),
                    cancel_codex_interactions=AsyncMock(),
                    cancel_claude_interactions=AsyncMock(),
                ), \
                patch.object(agent_server, "_start_turn_locked", side_effect=gated_start_turn):
            released = await agent_server.reconcile_provider_task_exit(
                "chat-1",
                "run-job",
                "claude",
            )
            promotion_task: asyncio.Task[object] | None = None
            try:
                self.assertTrue(released)
                await asyncio.wait_for(launch_started.wait(), timeout=0.5)
                promotion_task = queue_start_tasks.get("chat-1")
                self.assertIsNotNone(promotion_task)

                # The fallback already scheduled this queue. An overlapping
                # Stop drain must join the same queue-start owner, not pop or
                # launch the human message a second time.
                result = await agent_server.stop_turn(
                    "chat-1",
                    pause_queued_turns_on_stop=False,
                    cascade_claude_subagents=False,
                )
                await asyncio.sleep(0)
                await asyncio.sleep(0)

                self.assertTrue(result["stopped"])
                self.assertEqual(len(launch_calls), 1)
                self.assertNotIn("chat-1", queued)
                self.assertIs(queue_start_tasks.get("chat-1"), promotion_task)
                launched_session, launched_request, launched_kwargs = launch_calls[0]
                self.assertEqual(launched_session, "chat-1")
                self.assertEqual(
                    launched_request.prompt,
                    "Continue after cancellation.",
                )
                self.assertEqual(launched_kwargs["queued_id"], "queued-human")
            finally:
                finish_launch.set()
                if promotion_task is not None:
                    await asyncio.gather(promotion_task, return_exceptions=True)

        self.assertFalse(queue_start_tasks)

    async def test_task_failure_before_terminal_marker_is_closed_as_stopped(self) -> None:
        sessions = {
            "chat-1": {
                "id": "chat-1",
                "backend": "claude",
                "active_run": {"run_id": "run-old"},
            },
        }
        active = {"chat-1": {"run_id": "run-old", "backend": "claude"}}
        busy = {"chat-1"}
        current = {"chat-1": {"run_id": "run-old", "backend": "claude"}}

        async def failed_runner() -> None:
            raise RuntimeError("runner cleanup failed")

        append_event = AsyncMock(return_value={})
        with patch.object(agent_server.STORE, "sessions", sessions), \
                patch.object(agent_server, "ACTIVE", active), \
                patch.object(agent_server, "BUSY_SESSIONS", busy), \
                patch.object(agent_server, "CURRENT_TURNS", current), \
                patch.object(agent_server, "STOP_REQUESTS", set()), \
                patch.object(agent_server, "STOPPED_RUNS", set()), \
                patch.object(agent_server, "RUN_METADATA", {}), \
                patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                patch.object(agent_server, "STEERING_SESSIONS", set()), \
                patch.object(agent_server, "append_event", append_event), \
                patch.object(agent_server, "schedule_next_queued_turn") as schedule:
            with self.assertRaisesRegex(RuntimeError, "runner cleanup failed"):
                await agent_server.supervise_provider_turn_task(
                    "chat-1",
                    "run-old",
                    "claude",
                    failed_runner(),
                )

        self.assertNotIn("chat-1", active)
        self.assertNotIn("chat-1", busy)
        self.assertNotIn("chat-1", current)
        append_event.assert_awaited_once()
        self.assertEqual(append_event.await_args.args[1], "turn_stopped")
        self.assertTrue(append_event.await_args.args[2]["stopped"])
        schedule.assert_called_once_with("chat-1")

    async def test_delayed_old_task_exit_cannot_release_replacement_turn(self) -> None:
        sessions = {
            "chat-1": {
                "id": "chat-1",
                "backend": "claude",
                "active_run": {"run_id": "run-new"},
            },
        }
        active = {"chat-1": {"run_id": "run-new", "backend": "claude"}}
        busy = {"chat-1"}
        current = {"chat-1": {"run_id": "run-new", "backend": "claude"}}

        async def cancelled_runner() -> None:
            raise asyncio.CancelledError

        with patch.object(agent_server.STORE, "sessions", sessions), \
                patch.object(agent_server, "ACTIVE", active), \
                patch.object(agent_server, "BUSY_SESSIONS", busy), \
                patch.object(agent_server, "CURRENT_TURNS", current), \
                patch.object(agent_server, "STOP_REQUESTS", set()), \
                patch.object(agent_server, "STOPPED_RUNS", {"run-old"}), \
                patch.object(agent_server, "RUN_METADATA", {}), \
                patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                patch.object(agent_server, "STEERING_SESSIONS", set()), \
                patch.object(agent_server, "append_event", AsyncMock(return_value={})), \
                patch.object(agent_server, "schedule_next_queued_turn") as schedule:
            task = asyncio.create_task(agent_server.supervise_provider_turn_task(
                "chat-1",
                "run-old",
                "claude",
                cancelled_runner(),
            ))
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertEqual(active["chat-1"]["run_id"], "run-new")
        self.assertIn("chat-1", busy)
        self.assertEqual(current["chat-1"]["run_id"], "run-new")
        schedule.assert_not_called()


class RunQueuedTurnNowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.previous_sessions = agent_server.STORE.sessions
        self.previous_queued = agent_server.QUEUED_TURNS
        self.previous_run_now = agent_server.RUN_NOW_TURNS
        self.previous_steering = agent_server.STEERING_SESSIONS
        self.previous_steering_wait_tasks = agent_server.STEERING_WAIT_TASKS
        self.previous_run_now_requests = agent_server.RUN_NOW_REQUESTS
        self.previous_run_now_completed = agent_server.RUN_NOW_COMPLETED_RESULTS
        self.previous_current = agent_server.CURRENT_TURNS
        self.previous_active = agent_server.ACTIVE
        self.previous_busy = agent_server.BUSY_SESSIONS
        self.previous_queue_start_tasks = agent_server.QUEUE_START_TASKS
        agent_server.STORE.sessions = {
            "chat-1": {"id": "chat-1", "title": "Chat", "backend": "codex"},
        }
        agent_server.QUEUED_TURNS = {
            "chat-1": deque([{
                "queued_id": "queued-steer",
                "prompt": "Change course now.",
                "file_ids": ["new-file"],
                "backend": "codex",
            }]),
        }
        agent_server.RUN_NOW_TURNS = {}
        agent_server.STEERING_SESSIONS = set()
        agent_server.STEERING_WAIT_TASKS = {}
        agent_server.RUN_NOW_REQUESTS = {}
        agent_server.RUN_NOW_COMPLETED_RESULTS = OrderedDict()
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.QUEUE_START_TASKS = {}
        agent_server.CURRENT_TURNS = {
            "chat-1": {
                "run_id": "run-original",
                "prompt": "Finish the original investigation.",
                "file_ids": ["original-file"],
                "backend": "codex",
            },
        }

    async def asyncTearDown(self) -> None:
        live_waiters = [
            owner[2]
            for owner in agent_server.STEERING_WAIT_TASKS.values()
            if not owner[2].done()
        ]
        for task in live_waiters:
            task.cancel()
        if live_waiters:
            await asyncio.gather(*live_waiters, return_exceptions=True)
        agent_server.STORE.sessions = self.previous_sessions
        agent_server.QUEUED_TURNS = self.previous_queued
        agent_server.RUN_NOW_TURNS = self.previous_run_now
        agent_server.STEERING_SESSIONS = self.previous_steering
        agent_server.STEERING_WAIT_TASKS = self.previous_steering_wait_tasks
        agent_server.RUN_NOW_REQUESTS = self.previous_run_now_requests
        agent_server.RUN_NOW_COMPLETED_RESULTS = self.previous_run_now_completed
        agent_server.CURRENT_TURNS = self.previous_current
        agent_server.ACTIVE = self.previous_active
        agent_server.BUSY_SESSIONS = self.previous_busy
        agent_server.QUEUE_START_TASKS = self.previous_queue_start_tasks

    async def test_idle_orphaned_steering_fence_self_heals_before_force_send(
        self,
    ) -> None:
        agent_server.CURRENT_TURNS.clear()
        agent_server.STEERING_SESSIONS.add("chat-1")

        with patch.object(
            agent_server,
            "_run_queued_turn_now_once",
            new_callable=AsyncMock,
            return_value={"ok": True, "queued_id": "queued-steer"},
        ) as handoff:
            result = await agent_server.run_queued_turn_now(
                "chat-1",
                "queued-steer",
            )

        self.assertTrue(result["ok"])
        self.assertNotIn("chat-1", agent_server.STEERING_SESSIONS)
        handoff.assert_awaited_once()

    async def test_idle_reconciliation_keeps_live_owner_but_prunes_done_owner(
        self,
    ) -> None:
        agent_server.CURRENT_TURNS.clear()
        agent_server.STEERING_SESSIONS.add("chat-1")
        release = asyncio.Event()

        async def live_operation() -> dict[str, object]:
            await release.wait()
            return {"ok": True}

        live_task = asyncio.create_task(live_operation())
        setattr(live_task, "_agentsdock_force_send_queued_id", "queued-old")
        setattr(live_task, "_agentsdock_force_send_started_at", time.monotonic())
        agent_server.RUN_NOW_REQUESTS["chat-1"] = ("queued-old", live_task)
        try:
            repaired = await agent_server.reconcile_idle_queue_session(
                "chat-1",
                schedule=False,
                reason="test_live_owner",
            )
            self.assertFalse(repaired)
            self.assertIn("chat-1", agent_server.STEERING_SESSIONS)

            release.set()
            await live_task
            repaired = await agent_server.reconcile_idle_queue_session(
                "chat-1",
                schedule=False,
                reason="test_done_owner",
            )
        finally:
            if not live_task.done():
                live_task.cancel()
                await asyncio.gather(live_task, return_exceptions=True)

        self.assertTrue(repaired)
        self.assertNotIn("chat-1", agent_server.RUN_NOW_REQUESTS)
        self.assertNotIn("chat-1", agent_server.STEERING_SESSIONS)

    async def test_idle_reconciliation_expires_stale_owner_and_restores_fenced_row(
        self,
    ) -> None:
        agent_server.CURRENT_TURNS.clear()
        agent_server.QUEUED_TURNS.clear()
        agent_server.STEERING_SESSIONS.add("chat-1")

        async def stuck_operation() -> dict[str, object]:
            await asyncio.Event().wait()
            return {"ok": True}

        stale_task = asyncio.create_task(stuck_operation())
        setattr(
            stale_task,
            "_agentsdock_force_send_started_at",
            time.monotonic() - 60,
        )
        setattr(
            stale_task,
            "_agentsdock_force_send_queued_id",
            "queued-steer",
        )
        agent_server.RUN_NOW_REQUESTS["chat-1"] = (
            "queued-steer",
            stale_task,
        )
        fenced = {
            "queued_id": "queued-steer",
            "prompt": "Change course now.",
            "file_ids": [],
            "_durable": True,
            "_paused_after_stop": True,
            "_native_delivery_fenced": True,
        }

        with patch.object(
            agent_server,
            "RUN_NOW_IDLE_OWNER_TIMEOUT_SECONDS",
            0.01,
        ), patch.object(
            agent_server,
            "scan_queued_turns_from_events",
            return_value={"chat-1": [fenced]},
        ), patch.object(
            agent_server,
            "schedule_next_queued_turn",
        ) as schedule_next:
            repaired = await agent_server.reconcile_idle_queue_session(
                "chat-1",
                schedule=True,
                reason="test_stale_owner",
            )

        self.assertTrue(repaired)
        self.assertTrue(stale_task.cancelled())
        self.assertNotIn("chat-1", agent_server.RUN_NOW_REQUESTS)
        self.assertNotIn("chat-1", agent_server.STEERING_SESSIONS)
        restored = agent_server.QUEUED_TURNS["chat-1"][0]
        self.assertIs(restored, fenced)
        self.assertTrue(restored["_paused_after_stop"])
        self.assertTrue(restored["_native_delivery_fenced"])
        schedule_next.assert_not_called()

    async def test_ownerless_transitioning_promotion_is_released_when_idle(
        self,
    ) -> None:
        agent_server.CURRENT_TURNS.clear()
        agent_server.QUEUED_TURNS.clear()
        agent_server.RUN_NOW_TURNS["chat-1"] = {
            "queued_id": "queued-steer",
            "prompt": "Change course now.",
            "file_ids": [],
            "_durable": True,
            "_paused_after_stop": False,
            "_update_transitioning": True,
        }
        agent_server.STEERING_SESSIONS.add("chat-1")

        with patch.object(
            agent_server,
            "schedule_next_queued_turn",
        ) as schedule_next:
            repaired = await agent_server.reconcile_idle_queue_session(
                "chat-1",
                schedule=True,
                reason="test_transitioning_owner",
            )

        self.assertTrue(repaired)
        self.assertNotIn("chat-1", agent_server.STEERING_SESSIONS)
        self.assertNotIn(
            "_update_transitioning",
            agent_server.RUN_NOW_TURNS["chat-1"],
        )
        schedule_next.assert_called_once_with("chat-1")

    async def test_stale_owner_restores_unfenced_row_for_normal_delivery(
        self,
    ) -> None:
        agent_server.CURRENT_TURNS.clear()
        agent_server.QUEUED_TURNS.clear()
        agent_server.STEERING_SESSIONS.add("chat-1")

        async def stuck_operation() -> dict[str, object]:
            await asyncio.Event().wait()
            return {"ok": True}

        stale_task = asyncio.create_task(stuck_operation())
        setattr(
            stale_task,
            "_agentsdock_force_send_started_at",
            time.monotonic() - 60,
        )
        agent_server.RUN_NOW_REQUESTS["chat-1"] = (
            "queued-steer",
            stale_task,
        )
        recovered = {
            "queued_id": "queued-steer",
            "prompt": "Change course now.",
            "file_ids": [],
            "_durable": True,
            "_paused_after_stop": False,
        }

        with patch.object(
            agent_server,
            "RUN_NOW_IDLE_OWNER_TIMEOUT_SECONDS",
            0.01,
        ), patch.object(
            agent_server,
            "scan_queued_turns_from_events",
            return_value={"chat-1": [recovered]},
        ), patch.object(
            agent_server,
            "schedule_next_queued_turn",
        ) as schedule_next:
            repaired = await agent_server.reconcile_idle_queue_session(
                "chat-1",
                schedule=True,
                reason="test_stale_unfenced_owner",
            )

        self.assertTrue(repaired)
        self.assertTrue(stale_task.cancelled())
        self.assertIs(agent_server.QUEUED_TURNS["chat-1"][0], recovered)
        schedule_next.assert_called_once_with("chat-1")

    async def test_delivery_fenced_row_cannot_be_force_sent_again(self) -> None:
        fenced = agent_server.QUEUED_TURNS["chat-1"][0]
        fenced["_paused_after_stop"] = True
        fenced["_native_delivery_fenced"] = True

        with self.assertRaises(agent_server.HTTPException) as raised:
            await agent_server.run_queued_turn_now(
                "chat-1",
                "queued-steer",
            )

        detail = raised.exception.detail
        self.assertEqual(detail["guard"], "delivery_uncertain")
        self.assertFalse(detail["retryable"])
        self.assertIs(agent_server.QUEUED_TURNS["chat-1"][0], fenced)
        self.assertNotIn("chat-1", agent_server.STEERING_SESSIONS)
        self.assertNotIn("chat-1", agent_server.RUN_NOW_REQUESTS)

    async def test_native_provider_handoff_deadline_only_expires_before_accept(
        self,
    ) -> None:
        selected = agent_server.QUEUED_TURNS["chat-1"][0]

        async def exercise_pre_accept() -> agent_server.NativeSteerHandoffError:
            provider_queue: asyncio.Queue[dict[str, object]] = asyncio.Queue(
                maxsize=1
            )
            future: asyncio.Future[dict[str, object]] = (
                asyncio.get_running_loop().create_future()
            )
            request: dict[str, object] = {
                "selected": selected,
                "future": future,
                "phase": "queued",
                "accepted_event": asyncio.Event(),
            }
            provider_queue.put_nowait(request)
            try:
                with patch.object(
                    agent_server,
                    "RUN_NOW_PROVIDER_HANDOFF_TIMEOUT_SECONDS",
                    0.01,
                ):
                    await agent_server.await_native_steer_result(
                        "chat-1",
                        selected,
                        backend="codex",
                        native_steer_queue=provider_queue,
                        request=request,
                        future=future,
                    )
            except agent_server.NativeSteerHandoffError as exc:
                return exc
            finally:
                if not future.done():
                    future.cancel()
            self.fail("handoff deadline did not raise")

        pre_accept = await exercise_pre_accept()
        self.assertTrue(pre_accept.safe_to_requeue)
        self.assertFalse(pre_accept.delivery_uncertain)
        self.assertNotIn("_native_delivery_fenced", selected)

        provider_queue = asyncio.Queue(maxsize=1)
        future = asyncio.get_running_loop().create_future()
        accepted_event = asyncio.Event()
        request = {
            "selected": selected,
            "future": future,
            "phase": "accepted",
            "accepted_event": accepted_event,
        }
        accepted_event.set()
        with patch.object(
            agent_server,
            "RUN_NOW_PROVIDER_HANDOFF_TIMEOUT_SECONDS",
            0.01,
        ):
            owner = asyncio.create_task(agent_server.await_native_steer_result(
                "chat-1",
                selected,
                backend="codex",
                native_steer_queue=provider_queue,
                request=request,
                future=future,
            ))
            await asyncio.sleep(0.02)
            self.assertFalse(owner.done())
            future.set_result({"ok": True, "queued_id": "queued-steer"})
            result = await owner
        self.assertTrue(result["ok"])
        self.assertNotIn("_native_delivery_fenced", selected)

    async def test_cancelled_steering_waiter_always_releases_its_exact_fence(
        self,
    ) -> None:
        agent_server.CURRENT_TURNS.clear()
        agent_server.QUEUED_TURNS.clear()
        agent_server.BUSY_SESSIONS.add("chat-1")
        agent_server.STEERING_SESSIONS.add("chat-1")
        waiter = agent_server.schedule_steered_turn_slot_waiter(
            "chat-1",
            "queued-steer",
        )
        await asyncio.sleep(0)

        waiter.cancel()
        agent_server.BUSY_SESSIONS.discard("chat-1")
        await asyncio.gather(waiter, return_exceptions=True)
        await asyncio.sleep(0)

        self.assertNotIn("chat-1", agent_server.STEERING_SESSIONS)
        self.assertNotIn("chat-1", agent_server.STEERING_WAIT_TASKS)

    async def test_duplicate_force_send_requests_join_one_handoff(self) -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        async def gated_handoff(
            _session_id: str,
            _queued_id: str,
            **_kwargs: object,
        ) -> dict[str, object]:
            started.set()
            await release.wait()
            return {"ok": True, "queued_id": "queued-steer"}

        with patch.object(
            agent_server,
            "_run_queued_turn_now_once",
            side_effect=gated_handoff,
        ) as handoff:
            first = asyncio.create_task(
                run_queued_turn_now("chat-1", "queued-steer")
            )
            await started.wait()
            second = asyncio.create_task(
                run_queued_turn_now("chat-1", "queued-steer")
            )
            await asyncio.sleep(0)
            self.assertEqual(handoff.call_count, 1)
            release.set()
            first_result, second_result = await asyncio.gather(first, second)

        self.assertEqual(first_result, second_result)
        self.assertNotIn("chat-1", agent_server.RUN_NOW_REQUESTS)

    async def test_retry_after_dropped_completed_response_reuses_result(self) -> None:
        started = asyncio.Event()
        release = asyncio.Event()
        completed = asyncio.Event()

        async def gated_handoff(
            _session_id: str,
            _queued_id: str,
            **_kwargs: object,
        ) -> dict[str, object]:
            started.set()
            await release.wait()
            completed.set()
            return {
                "ok": True,
                "queued_id": "queued-steer",
                "run_id": "run-steered",
            }

        with patch.object(
            agent_server,
            "_run_queued_turn_now_once",
            side_effect=gated_handoff,
        ) as handoff:
            dropped_waiter = asyncio.create_task(
                run_queued_turn_now("chat-1", "queued-steer")
            )
            await started.wait()
            dropped_waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await dropped_waiter
            release.set()
            await completed.wait()
            for _ in range(100):
                if "chat-1" not in agent_server.RUN_NOW_REQUESTS:
                    break
                await asyncio.sleep(0)
            retried = await run_queued_turn_now("chat-1", "queued-steer")

        self.assertEqual(retried["run_id"], "run-steered")
        self.assertEqual(handoff.call_count, 1)

    async def test_deferred_force_send_is_not_cached(self) -> None:
        outcomes = [
            {
                "ok": False,
                "queued_id": "queued-steer",
                "deferred": True,
            },
            {
                "ok": True,
                "queued_id": "queued-steer",
                "run_id": "run-steered",
            },
        ]

        with patch.object(
            agent_server,
            "_run_queued_turn_now_once",
            side_effect=outcomes,
        ) as handoff:
            first = await run_queued_turn_now("chat-1", "queued-steer")
            second = await run_queued_turn_now("chat-1", "queued-steer")

        self.assertTrue(first["deferred"])
        self.assertEqual(second["run_id"], "run-steered")
        self.assertEqual(handoff.call_count, 2)

    async def test_retry_safe_handoff_returns_deferred_queue_outcome(self) -> None:
        retry_safe = agent_server.NativeSteerHandoffError(
            "the active Codex turn has already completed",
            safe_to_requeue=True,
        )
        with patch.object(
            agent_server,
            "_run_queued_turn_now_once",
            side_effect=retry_safe,
        ):
            result = await run_queued_turn_now("chat-1", "queued-steer")

        self.assertFalse(result["ok"])
        self.assertTrue(result["deferred"])
        self.assertTrue(result["retryable"])
        self.assertFalse(result["delivery_uncertain"])
        self.assertEqual(result["remaining"], 1)
        self.assertIn("kept for normal queue delivery", result["message"])
        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-steer"],
        )
        self.assertNotIn("chat-1", agent_server.RUN_NOW_REQUESTS)
        self.assertFalse(agent_server.RUN_NOW_COMPLETED_RESULTS)

    async def test_safe_native_prefence_rejection_durably_requeues_in_order(
        self,
    ) -> None:
        before = {
            "queued_id": "queued-before",
            "prompt": "Before",
            "file_ids": [],
            "backend": "codex",
            "_durable": True,
        }
        selected = {
            "queued_id": "queued-steer",
            "prompt": "Retry normally",
            "file_ids": [],
            "backend": "codex",
            "_durable": True,
            # _run_queued_turn_now_once clears an explicit Stop hold before its
            # final ACTIVE/QueueFull recheck, even though provider fencing has
            # not begun. This branch still needs a durable compensation.
            "_paused_after_stop": False,
            "_native_delivery_queue_position": 2,
        }
        after = {
            "queued_id": "queued-after",
            "prompt": "After",
            "file_ids": [],
            "backend": "codex",
            "_durable": True,
        }
        agent_server.QUEUED_TURNS["chat-1"] = deque([before, after])
        append_batch = AsyncMock(return_value=[])

        with patch.object(
            agent_server,
            "append_durable_event_batch",
            append_batch,
        ):
            await agent_server.requeue_native_steer_after_safe_rejection(
                "chat-1",
                selected,
                selected_index=1,
                selected_predecessor_id="queued-before",
                selected_successor_id="queued-after",
            )
            public = await agent_server.queued_turns_snapshot("chat-1")

        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-before", "queued-steer", "queued-after"],
        )
        self.assertNotIn("_native_delivery_fenced", selected)
        self.assertFalse(selected["_paused_after_stop"])
        self.assertNotIn("_native_delivery_queue_position", selected)
        self.assertFalse(public[1]["paused"])
        self.assertIsNone(public[1]["pause_reason"])
        event_specs = append_batch.await_args.args[1]
        self.assertEqual(
            [event_type for event_type, _payload in event_specs],
            ["turn_queued", "turn_queue_reordered"],
        )
        self.assertEqual(event_specs[0][1]["position"], 2)
        self.assertEqual(
            event_specs[1][1]["positions"],
            [
                {"queued_id": "queued-before", "position": 1},
                {"queued_id": "queued-steer", "position": 2},
                {"queued_id": "queued-after", "position": 3},
            ],
        )

    async def test_safe_native_rejection_compensation_failure_stays_fenced(
        self,
    ) -> None:
        selected = {
            "queued_id": "queued-steer",
            "prompt": "Do not claim a safe rollback",
            "file_ids": [],
            "backend": "codex",
            "_durable": True,
            "_paused_after_stop": True,
            "_native_delivery_fenced": True,
        }
        agent_server.QUEUED_TURNS.pop("chat-1", None)

        with patch.object(
            agent_server,
            "append_durable_event_batch",
            new_callable=AsyncMock,
            side_effect=OSError("rollback fsync failed"),
        ):
            with self.assertRaises(
                agent_server.NativeSteerHandoffError
            ) as raised:
                await agent_server.requeue_native_steer_after_safe_rejection(
                    "chat-1",
                    selected,
                    selected_index=0,
                    selected_predecessor_id=None,
                    selected_successor_id=None,
                )
            public = await agent_server.queued_turns_snapshot("chat-1")

        self.assertFalse(raised.exception.safe_to_requeue)
        self.assertFalse(raised.exception.delivery_uncertain)
        self.assertIs(agent_server.QUEUED_TURNS["chat-1"][0], selected)
        self.assertTrue(selected["_paused_after_stop"])
        self.assertTrue(selected["_native_delivery_fenced"])
        self.assertTrue(public[0]["paused"])
        self.assertEqual(public[0]["pause_reason"], "delivery_uncertain")

    async def test_deferred_response_requires_explicit_client_capability(self) -> None:
        deferred = {
            "ok": False,
            "queued_id": "queued-steer",
            "deferred": True,
            "retryable": True,
            "delivery_uncertain": False,
            "message": "The message remains queued.",
            "remaining": 1,
        }
        with patch.object(
            agent_server,
            "run_queued_turn_now",
            new_callable=AsyncMock,
            return_value=deferred,
        ):
            with self.assertRaises(agent_server.HTTPException) as legacy:
                await agent_server.post_run_queued_turn_now(
                    "chat-1",
                    "queued-steer",
                )
            capable = await agent_server.post_run_queued_turn_now(
                "chat-1",
                "queued-steer",
                agent_server.RunQueuedTurnNowRequest(
                    accept_deferred_queue_response=True,
                ),
            )

        self.assertEqual(legacy.exception.status_code, 409)
        self.assertEqual(legacy.exception.detail["code"], "force_send_deferred")
        self.assertTrue(legacy.exception.detail["retryable"])
        self.assertFalse(legacy.exception.detail["delivery_uncertain"])
        self.assertEqual(capable, deferred)

    async def test_delivery_uncertain_handoff_is_explicit_non_retryable_conflict(self) -> None:
        uncertain = agent_server.NativeSteerHandoffError(
            "the provider turn completed at the Force Send boundary",
            safe_to_requeue=False,
            delivery_uncertain=True,
        )
        with patch.object(
            agent_server,
            "run_queued_turn_now",
            new_callable=AsyncMock,
            side_effect=uncertain,
        ):
            with self.assertRaises(agent_server.HTTPException) as raised:
                await agent_server.post_run_queued_turn_now(
                    "chat-1",
                    "queued-steer",
                )

        self.assertEqual(raised.exception.status_code, 409)
        detail = raised.exception.detail
        self.assertEqual(detail["code"], "force_send_delivery_uncertain")
        self.assertFalse(detail["retryable"])
        self.assertTrue(detail["delivery_uncertain"])
        self.assertEqual(detail["queued_id"], "queued-steer")
        self.assertIn("Do not retry automatically", detail["action"])

    async def test_different_force_send_is_rejected_with_friendly_state(
        self,
    ) -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        async def gated_handoff(
            _session_id: str,
            _queued_id: str,
            **_kwargs: object,
        ) -> dict[str, object]:
            started.set()
            await release.wait()
            return {"ok": True, "queued_id": "queued-steer"}

        with patch.object(
            agent_server,
            "_run_queued_turn_now_once",
            side_effect=gated_handoff,
        ):
            first = asyncio.create_task(
                run_queued_turn_now("chat-1", "queued-steer")
            )
            await started.wait()
            with self.assertRaises(agent_server.HTTPException) as raised:
                await run_queued_turn_now("chat-1", "queued-other")
            detail = raised.exception.detail
            self.assertIn(
                "Another Force Send is already being applied",
                detail["message"],
            )
            self.assertEqual(detail["guard"], "run_now_request")
            self.assertEqual(detail["owner"]["queued_id"], "queued-steer")
            self.assertTrue(detail["owner"]["operation_id"].startswith("force_send_"))
            self.assertIsNotNone(detail["owner"]["age_seconds"])
            self.assertEqual(detail["owner"]["phase"], "admission")
            release.set()
            await first

    async def test_explicit_stop_waits_for_non_native_force_send_transition(
        self,
    ) -> None:
        transition_started = asyncio.Event()
        release_transition = asyncio.Event()
        lifecycle_locks: dict[str, asyncio.Lock] = {}

        async def gated_handoff(
            _session_id: str,
            _queued_id: str,
            *,
            require_native: bool = False,
        ) -> dict[str, object]:
            if require_native:
                raise agent_server.NonNativeForceSendRequiresLifecycleLock
            transition_started.set()
            await release_transition.wait()
            return {"ok": True, "queued_id": "queued-steer"}

        stop_turn = AsyncMock(return_value={"ok": True, "stopped": True})
        with patch.object(
            agent_server,
            "_run_queued_turn_now_once",
            side_effect=gated_handoff,
        ), patch.object(
            agent_server,
            "SESSION_LIFECYCLE_LOCKS",
            lifecycle_locks,
        ), patch.object(
            agent_server,
            "managed_server_update_blocker",
            return_value=None,
        ), patch.object(
            agent_server,
            "stop_turn",
            stop_turn,
        ), patch.object(
            agent_server,
            "schedule_next_queued_turn",
        ) as schedule_next:
            force_send = asyncio.create_task(
                run_queued_turn_now("chat-1", "queued-steer")
            )
            await asyncio.wait_for(transition_started.wait(), 0.5)
            explicit_stop = asyncio.create_task(
                agent_server.stop_turn_endpoint("chat-1")
            )
            await asyncio.sleep(0)
            stop_turn.assert_not_awaited()

            release_transition.set()
            await force_send
            await explicit_stop

        stop_turn.assert_awaited_once()
        self.assertEqual(stop_turn.await_args.args, ("chat-1",))
        self.assertTrue(
            stop_turn.await_args.kwargs["_admission_ready"].is_set()
        )
        self.assertFalse(stop_turn.await_args.kwargs["schedule_queue"])
        schedule_next.assert_called_once_with("chat-1")

    async def test_stop_after_promotion_holds_run_now_and_clears_cached_success(
        self,
    ) -> None:
        promoted = agent_server.QUEUED_TURNS.pop("chat-1")[0]
        promoted["_durable"] = True
        promoted["_paused_after_stop"] = False
        agent_server.RUN_NOW_TURNS["chat-1"] = promoted
        agent_server.RUN_NOW_COMPLETED_RESULTS[("chat-1", "queued-steer")] = {
            "expires_at": time.monotonic() + 30,
            "result": {"ok": True, "queued_id": "queued-steer"},
        }

        with patch.object(
            agent_server,
            "append_durable_event",
            new_callable=AsyncMock,
            return_value={},
        ), patch.object(
            agent_server,
            "_start_turn_locked",
            new_callable=AsyncMock,
        ) as start:
            paused = await agent_server.pause_queued_turns_after_explicit_stop(
                "chat-1"
            )
            await agent_server.start_next_queued_turn("chat-1")

        self.assertEqual(paused, 1)
        self.assertNotIn("chat-1", agent_server.RUN_NOW_TURNS)
        self.assertTrue(
            agent_server.QUEUED_TURNS["chat-1"][0]["_paused_after_stop"]
        )
        self.assertNotIn(
            ("chat-1", "queued-steer"),
            agent_server.RUN_NOW_COMPLETED_RESULTS,
        )
        start.assert_not_awaited()

    async def test_force_send_does_not_cache_success_after_stop_pauses_item(
        self,
    ) -> None:
        async def paused_handoff(
            _session_id: str,
            _queued_id: str,
            **_kwargs: object,
        ) -> dict[str, object]:
            promoted = agent_server.QUEUED_TURNS.pop("chat-1")[0]
            promoted["_paused_after_stop"] = True
            agent_server.RUN_NOW_TURNS["chat-1"] = promoted
            return {"ok": True, "queued_id": "queued-steer"}

        with patch.object(
            agent_server,
            "_run_queued_turn_now_once",
            side_effect=paused_handoff,
        ):
            result = await run_queued_turn_now("chat-1", "queued-steer")

        self.assertTrue(result["ok"])
        self.assertFalse(agent_server.RUN_NOW_COMPLETED_RESULTS)

    async def test_interrupted_turn_promotes_only_the_exact_steering_message(self) -> None:
        append_durable_event = AsyncMock(return_value={})

        async def completed_wait(_session_id: str) -> None:
            return None

        with patch.object(
                agent_server,
                "stop_turn",
                new_callable=AsyncMock,
                return_value={"stopped": True},
        ) as stop_turn, \
                patch.object(agent_server, "append_durable_event", append_durable_event), \
                patch.object(agent_server, "wait_for_steered_turn_slot", completed_wait):
            result = await run_queued_turn_now("chat-1", "queued-steer")
            await asyncio.sleep(0)

        self.assertTrue(stop_turn.await_args.kwargs["require_provider_turn_ready"])
        self.assertFalse(stop_turn.await_args.kwargs["cascade_codex_subagents"])
        self.assertFalse(stop_turn.await_args.kwargs["cascade_claude_subagents"])
        self.assertFalse(stop_turn.await_args.kwargs["hard_terminalize_on_timeout"])
        promoted = agent_server.RUN_NOW_TURNS["chat-1"]
        self.assertFalse(result["replays_interrupted_message"])
        self.assertEqual(promoted["prompt"], "Change course now.")
        self.assertEqual(
            [item["prompt"] for item in promoted["steering_lineage"]],
            ["Finish the original investigation.", "Change course now."],
        )
        self.assertEqual(promoted["display_prompt"], "Change course now.")
        self.assertEqual(promoted["file_ids"], ["new-file"])
        self.assertEqual(promoted["display_file_ids"], ["new-file"])
        event_payload = append_durable_event.await_args.args[2]
        self.assertEqual(event_payload["prompt"], "Change course now.")
        self.assertEqual(event_payload["request_prompt"], "Change course now.")
        self.assertNotIn("[Interrupted message]", event_payload["request_prompt"])
        self.assertEqual(event_payload["steering_lineage"], promoted["steering_lineage"])
        self.assertEqual(event_payload["file_ids"], ["new-file"])
        self.assertEqual(event_payload["display_file_ids"], ["new-file"])
        self.assertFalse(event_payload["replays_interrupted_message"])

    async def test_background_recovery_preserves_messages_queued_after_startup(self) -> None:
        agent_server.QUEUED_TURNS["chat-1"] = deque([{
            "queued_id": "queued-new",
            "prompt": "Queued while recovery was scanning.",
            "file_ids": [],
        }])
        recovered = {
            "chat-1": [{
                "queued_id": "queued-restored",
                "prompt": "Restored after restart.",
                "file_ids": [],
            }]
        }

        with patch.object(agent_server, "scan_queued_turns_from_events", return_value=recovered), \
             patch.object(agent_server, "schedule_next_queued_turn") as schedule:
            rebuilt, scheduled = await agent_server.recover_queued_turns_after_start()

        self.assertEqual(rebuilt, 1)
        self.assertEqual(scheduled, 1)
        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-restored", "queued-new"],
        )
        schedule.assert_called_once_with("chat-1")

    async def test_recovery_preserves_stopped_queue_without_auto_running(self) -> None:
        recovered = {
            "chat-1": [{
                "queued_id": "queued-paused",
                "prompt": "Wait for me to run this.",
                "file_ids": [],
                "_durable": True,
                "_paused_after_stop": True,
            }],
        }
        agent_server.QUEUED_TURNS.clear()

        with patch.object(agent_server, "scan_queued_turns_from_events", return_value=recovered), \
             patch.object(agent_server, "schedule_next_queued_turn") as schedule:
            rebuilt, scheduled = await agent_server.recover_queued_turns_after_start()

        self.assertEqual((rebuilt, scheduled), (1, 0))
        self.assertEqual(
            agent_server.QUEUED_TURNS["chat-1"][0]["queued_id"],
            "queued-paused",
        )
        schedule.assert_not_called()

    async def test_scheduler_does_not_pop_stopped_queue_without_run_now(self) -> None:
        agent_server.QUEUED_TURNS["chat-1"][0]["_paused_after_stop"] = True
        with patch.object(agent_server, "_start_turn_locked", new_callable=AsyncMock) as start:
            await agent_server.start_next_queued_turn("chat-1")

        self.assertEqual(len(agent_server.QUEUED_TURNS["chat-1"]), 1)
        start.assert_not_awaited()

    async def test_busy_turn_rejects_invalid_backend_before_queueing(self) -> None:
        agent_server.BUSY_SESSIONS = {"chat-1"}
        enqueue = AsyncMock()
        with patch.object(agent_server, "enqueue_turn", enqueue):
            with self.assertRaises(HTTPException) as raised:
                await agent_server._start_turn_locked(
                    "chat-1",
                    agent_server.TurnRequest(
                        prompt="Do not queue an invalid runtime",
                        backend="not-a-provider",
                    ),
                    queue_if_busy=True,
                    admission_backend="codex",
                )
        self.assertEqual(raised.exception.status_code, 400)
        enqueue.assert_not_awaited()

    async def test_permanent_promotion_rejection_durably_unqueues_user_turn(self) -> None:
        agent_server.CURRENT_TURNS.clear()
        durable = AsyncMock(return_value={})
        with (
            patch.object(
                agent_server,
                "_start_turn_locked",
                AsyncMock(side_effect=HTTPException(status_code=400, detail="invalid runtime")),
            ),
            patch.object(agent_server, "append_durable_event", durable),
            patch.object(agent_server, "append_event", AsyncMock()),
        ):
            await agent_server._start_next_queued_turn_locked(
                "chat-1",
                admission_backend="codex",
            )
        self.assertNotIn("chat-1", agent_server.QUEUED_TURNS)
        self.assertTrue(any(
            call.args[1] == "turn_unqueued"
            and call.args[2]["queued_id"] == "queued-steer"
            for call in durable.await_args_list
        ))

    async def test_terminally_discarded_head_immediately_promotes_next_row(self) -> None:
        agent_server.CURRENT_TURNS.clear()
        invalid = {
            "queued_id": "queued-invalid-head",
            "prompt": "Invalid saved reference",
            "file_ids": [],
            "backend": "codex",
            "chat_references": [{}],
            "team_references": [],
        }
        valid = {
            "queued_id": "queued-valid-second",
            "prompt": "Run the valid second row",
            "file_ids": [],
            "backend": "codex",
            "chat_references": [],
            "team_references": [],
        }
        agent_server.QUEUED_TURNS["chat-1"] = deque([invalid, valid])
        second_started = asyncio.Event()

        async def start_second(
            _session_id: str,
            request: agent_server.TurnRequest,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.assertEqual(request.prompt, valid["prompt"])
            second_started.set()
            return {"queued": False}

        with (
            patch.object(
                agent_server,
                "wait_for_queue_recovery_admission",
                new_callable=AsyncMock,
            ),
            patch.object(
                agent_server,
                "reconcile_idle_queue_session",
                new_callable=AsyncMock,
            ),
            patch.object(agent_server, "append_durable_event", AsyncMock(return_value={})),
            patch.object(agent_server, "append_event", AsyncMock(return_value={})),
            patch.object(agent_server, "_start_turn_locked", side_effect=start_second) as start,
        ):
            await agent_server.start_next_queued_turn("chat-1")
            await asyncio.wait_for(second_started.wait(), timeout=1)
            for _ in range(20):
                owner = agent_server.QUEUE_START_TASKS.get("chat-1")
                if owner is None or owner.done():
                    break
                await asyncio.sleep(0)

        start.assert_awaited_once()
        self.assertNotIn("chat-1", agent_server.QUEUED_TURNS)

    async def test_ambiguous_promotion_failure_requeues_user_turn(self) -> None:
        agent_server.CURRENT_TURNS.clear()
        schedule = patch.object(agent_server, "schedule_queued_turn_retry")
        with (
            patch.object(
                agent_server,
                "_start_turn_locked",
                AsyncMock(side_effect=RuntimeError("temporary provider fault")),
            ),
            patch.object(agent_server, "append_event", AsyncMock()) as event,
            schedule as retry,
        ):
            await agent_server._start_next_queued_turn_locked(
                "chat-1",
                admission_backend="codex",
            )
        self.assertEqual(
            agent_server.QUEUED_TURNS["chat-1"][0]["queued_id"],
            "queued-steer",
        )
        self.assertEqual(event.await_args.args[1], "turn_deferred")
        retry.assert_called_once_with("chat-1")

    async def test_scheduler_terminally_discards_stale_team_reference(self) -> None:
        agent_server.CURRENT_TURNS.clear()
        stale = {
            "queued_id": "queued-stale-team-reference",
            "prompt": "This prompt no longer names a team recipient.",
            "file_ids": [],
            "backend": "codex",
            "chat_references": [],
            "team_references": [
                {
                    "kind": "recipient",
                    "recipient_kind": "server",
                    "team_id": "team_alpha",
                    "target_id": "node_sonic",
                    "display_name_snapshot": "SONIC",
                    "source_text_start": 0,
                    "source_text_end": 7,
                    "grant_intent": True,
                }
            ],
        }
        agent_server.QUEUED_TURNS["chat-1"] = deque([stale])
        discard = AsyncMock()

        with (
            patch.object(
                agent_server,
                "terminally_discard_queued_turn",
                discard,
            ),
            patch.object(
                agent_server,
                "_start_turn_locked",
                new_callable=AsyncMock,
            ) as start,
        ):
            await agent_server._start_next_queued_turn_locked(
                "chat-1",
                admission_backend="codex",
            )

        start.assert_not_awaited()
        discard.assert_awaited_once_with(
            "chat-1",
            stale,
            "saved Team target configuration is invalid",
        )
        self.assertNotIn("chat-1", agent_server.QUEUED_TURNS)

    async def test_scheduler_discards_routed_turn_with_hidden_display_prompt(self) -> None:
        agent_server.CURRENT_TURNS.clear()
        hidden = {
            "queued_id": "queued-hidden-display-reference",
            "prompt": "Tell @@SONIC now",
            "display_prompt": "Tell the team now",
            "file_ids": [],
            "backend": "codex",
            "chat_references": [],
            "team_references": [
                {
                    "kind": "recipient",
                    "recipient_kind": "server",
                    "team_id": "team_alpha",
                    "target_id": "node_sonic",
                    "display_name_snapshot": "SONIC",
                    "source_text_start": 5,
                    "source_text_end": 12,
                    "grant_intent": True,
                }
            ],
        }
        agent_server.QUEUED_TURNS["chat-1"] = deque([hidden])
        discard = AsyncMock()
        with (
            patch.object(agent_server, "terminally_discard_queued_turn", discard),
            patch.object(
                agent_server, "_start_turn_locked", new_callable=AsyncMock
            ) as start,
        ):
            await agent_server._start_next_queued_turn_locked(
                "chat-1", admission_backend="codex"
            )

        start.assert_not_awaited()
        discard.assert_awaited_once_with(
            "chat-1",
            hidden,
            "saved Team target configuration is invalid",
        )

    async def test_scheduler_does_not_retry_a_permanently_changed_team_target(self) -> None:
        agent_server.CURRENT_TURNS.clear()
        item = {
            "queued_id": "queued-renamed-team-target",
            "prompt": "Tell @@SONIC now",
            "file_ids": [],
            "backend": "codex",
            "chat_references": [],
            "team_references": [
                {
                    "kind": "recipient",
                    "recipient_kind": "server",
                    "team_id": "team_alpha",
                    "target_id": "node_sonic",
                    "display_name_snapshot": "SONIC",
                    "source_text_start": 5,
                    "source_text_end": 12,
                    "grant_intent": True,
                }
            ],
        }
        agent_server.QUEUED_TURNS["chat-1"] = deque([item])
        discard = AsyncMock()
        with (
            patch.object(agent_server, "terminally_discard_queued_turn", discard),
            patch.object(
                agent_server,
                "_start_turn_locked",
                new_callable=AsyncMock,
                side_effect=agent_server.TeamReferenceTargetRepairRequired(
                    status_code=409,
                    detail="Team Network reference is unavailable or changed",
                ),
            ),
            patch.object(agent_server, "retry_next_queued_turn_later") as retry,
        ):
            await agent_server._start_next_queued_turn_locked(
                "chat-1", admission_backend="codex"
            )

        discard.assert_awaited_once_with(
            "chat-1",
            item,
            "saved Team target configuration is invalid",
        )
        retry.assert_not_called()

    async def test_no_active_turn_promotes_without_replaying_old_text(self) -> None:
        append_durable_event = AsyncMock(return_value={})

        async def completed_wait(_session_id: str) -> None:
            return None

        with patch.object(agent_server, "stop_turn", new_callable=AsyncMock, return_value={"stopped": False}), \
                patch.object(agent_server, "append_durable_event", append_durable_event), \
                patch.object(agent_server, "wait_for_steered_turn_slot", completed_wait):
            result = await run_queued_turn_now("chat-1", "queued-steer")
            await asyncio.sleep(0)

        promoted = agent_server.RUN_NOW_TURNS["chat-1"]
        self.assertFalse(result["replays_interrupted_message"])
        self.assertEqual(promoted["prompt"], "Change course now.")

    async def test_unready_provider_leaves_force_send_message_in_the_queue(self) -> None:
        append_event = AsyncMock(return_value={})
        with patch.object(
                agent_server,
                "stop_turn",
                new_callable=AsyncMock,
                return_value={"stopped": False, "deferred": True},
        ) as stop_turn, \
                patch.object(agent_server, "append_event", append_event), \
                patch.object(agent_server, "BUSY_SESSIONS", {"chat-1"}), \
                patch.object(agent_server, "schedule_next_queued_turn") as schedule_next:
            result = await run_queued_turn_now("chat-1", "queued-steer")

        self.assertFalse(result["ok"])
        self.assertTrue(result["deferred"])
        self.assertFalse(result["interrupted"])
        self.assertTrue(stop_turn.await_args.kwargs["require_provider_turn_ready"])
        self.assertFalse(stop_turn.await_args.kwargs["hard_terminalize_on_timeout"])
        self.assertNotIn("chat-1", agent_server.RUN_NOW_TURNS)
        self.assertNotIn("chat-1", agent_server.STEERING_SESSIONS)
        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-steer"],
        )
        self.assertEqual(append_event.await_args.args[1], "turn_deferred")
        schedule_next.assert_not_called()

    async def test_repeated_force_send_emits_one_deferred_notice_for_the_queue_item(self) -> None:
        append_event = AsyncMock(return_value={})
        with patch.object(
                agent_server,
                "stop_turn",
                new_callable=AsyncMock,
                return_value={"stopped": False, "deferred": True},
        ), \
                patch.object(agent_server, "append_event", append_event), \
                patch.object(agent_server, "BUSY_SESSIONS", {"chat-1"}):
            first = await run_queued_turn_now("chat-1", "queued-steer")
            second = await run_queued_turn_now("chat-1", "queued-steer")

        self.assertTrue(first["deferred"])
        self.assertTrue(second["deferred"])
        self.assertEqual(append_event.await_count, 1)
        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-steer"],
        )

    async def test_background_retry_emits_one_deferred_notice_for_the_queue_item(self) -> None:
        append_event = AsyncMock(return_value={})

        async def completed_retry(_session_id: str, _delay_seconds: int | None = None) -> None:
            return None

        with patch.object(
                agent_server,
                "_start_turn_locked",
                new_callable=AsyncMock,
                side_effect=agent_server.HTTPException(status_code=409, detail="turn already active"),
        ), \
                patch.object(agent_server, "append_event", append_event), \
                patch.object(agent_server, "retry_next_queued_turn_later", completed_retry):
            await start_next_queued_turn("chat-1")
            await asyncio.sleep(0)
            await start_next_queued_turn("chat-1")
            await asyncio.sleep(0)

        self.assertEqual(append_event.await_count, 1)
        self.assertEqual(append_event.await_args.args[1], "turn_deferred")
        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-steer"],
        )

    async def test_repeated_cancelled_promotion_restores_item_before_owner_clears(
        self,
    ) -> None:
        selected = agent_server.QUEUED_TURNS["chat-1"][0]
        start_entered = asyncio.Event()
        requeue_entered = asyncio.Event()
        join_entered = asyncio.Event()
        owner_at_restore: list[asyncio.Task[object] | None] = []
        original_requeue = agent_server.requeue_turn_front
        original_join = agent_server.join_task_despite_caller_cancellation
        queue_lock = asyncio.Lock()

        async def blocked_start(*_args: object, **_kwargs: object) -> None:
            start_entered.set()
            await asyncio.Event().wait()

        async def tracked_requeue(
            session_id: str,
            item: dict[str, object],
        ) -> None:
            requeue_entered.set()
            await original_requeue(session_id, item)
            owner_at_restore.append(
                agent_server.QUEUE_START_TASKS.get(session_id)
            )

        async def tracked_join(task: asyncio.Task[object]) -> object:
            join_entered.set()
            return await original_join(task)

        with (
            patch.object(
                agent_server,
                "reconcile_idle_queue_session",
                new_callable=AsyncMock,
            ),
            patch.object(agent_server, "_start_turn_locked", blocked_start),
            patch.object(agent_server, "requeue_turn_front", tracked_requeue),
            patch.object(
                agent_server,
                "join_task_despite_caller_cancellation",
                tracked_join,
            ),
            patch.object(agent_server, "QUEUE_LOCK", queue_lock),
        ):
            promotion = asyncio.create_task(
                agent_server.start_next_queued_turn("chat-1")
            )
            await asyncio.wait_for(start_entered.wait(), 0.5)
            await queue_lock.acquire()
            try:
                promotion.cancel()
                await asyncio.wait_for(requeue_entered.wait(), 0.5)
                promotion.cancel()
                await asyncio.wait_for(join_entered.wait(), 0.5)
                promotion.cancel()
                await asyncio.sleep(0)

                self.assertFalse(promotion.done())
                self.assertNotIn("chat-1", agent_server.QUEUED_TURNS)
                self.assertIs(
                    agent_server.QUEUE_START_TASKS.get("chat-1"),
                    promotion,
                )
            finally:
                queue_lock.release()

            with self.assertRaises(asyncio.CancelledError):
                await promotion

        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-steer"],
        )
        self.assertIs(agent_server.QUEUED_TURNS["chat-1"][0], selected)
        self.assertEqual(owner_at_restore, [promotion])
        await asyncio.sleep(0)
        self.assertNotIn("chat-1", agent_server.QUEUE_START_TASKS)

    async def test_terminal_session_queue_items_are_never_requeued(self) -> None:
        cases = ("tombstoned", "deleting", "deleting_race", "not_found")
        for case in cases:
            with self.subTest(case=case):
                agent_server.QUEUED_TURNS["chat-1"] = deque(
                    [
                        {
                            "queued_id": "queued-terminal",
                            "prompt": "Do not retry this.",
                            "file_ids": [],
                            "backend": "codex",
                        }
                    ]
                )
                agent_server.STORE.sessions["chat-1"] = {
                    "id": "chat-1",
                    "backend": "codex",
                }
                if case == "tombstoned":
                    agent_server.STORE.sessions.pop("chat-1", None)
                    agent_server.DELETED_SESSION_TOMBSTONES.add("chat-1")
                elif case == "deleting":
                    agent_server.DELETING_SESSIONS.add("chat-1")

                async def start_turn(
                    *_args: object,
                    **_kwargs: object,
                ) -> dict[str, object]:
                    if case == "not_found":
                        agent_server.STORE.sessions.pop("chat-1", None)
                        raise agent_server.HTTPException(
                            status_code=404,
                            detail="session not found",
                        )
                    if case == "deleting_race":
                        agent_server.DELETING_SESSIONS.add("chat-1")
                        raise agent_server.HTTPException(
                            status_code=409,
                            detail="session is being deleted",
                        )
                    raise AssertionError("terminal state must be checked first")

                try:
                    with (
                        patch.object(
                            agent_server,
                            "_start_turn_locked",
                            side_effect=start_turn,
                        ) as launch,
                        patch.object(
                            agent_server,
                            "requeue_turn_front",
                            wraps=agent_server.requeue_turn_front,
                        ) as requeue,
                        patch.object(
                            agent_server,
                            "retry_next_queued_turn_later",
                            new_callable=AsyncMock,
                        ) as retry,
                        patch.object(
                            agent_server,
                            "append_event",
                            new_callable=AsyncMock,
                        ) as append_event,
                    ):
                        await start_next_queued_turn("chat-1")
                        await asyncio.sleep(0)

                    if case in {"deleting", "deleting_race"}:
                        self.assertEqual(
                            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
                            ["queued-terminal"],
                        )
                        requeue.assert_awaited_once()
                    else:
                        self.assertNotIn("chat-1", agent_server.QUEUED_TURNS)
                        requeue.assert_not_awaited()
                    retry.assert_not_awaited()
                    append_event.assert_not_awaited()
                    if case in {"not_found", "deleting_race"}:
                        launch.assert_awaited_once()
                    else:
                        launch.assert_not_awaited()
                finally:
                    agent_server.DELETING_SESSIONS.discard("chat-1")
                    agent_server.DELETED_SESSION_TOMBSTONES.discard("chat-1")

    async def test_later_steer_runs_first_then_keeps_other_messages_in_original_order(self) -> None:
        agent_server.QUEUED_TURNS["chat-1"] = deque([
            {
                "queued_id": "queued-first",
                "prompt": "First queued message.",
                "file_ids": [],
                "backend": "codex",
            },
            {
                "queued_id": "queued-steer",
                "prompt": "Change course now.",
                "file_ids": ["new-file"],
                "backend": "codex",
            },
            {
                "queued_id": "queued-later",
                "prompt": "Keep this for afterward.",
                "file_ids": [],
                "backend": "codex",
            },
        ])
        append_durable_event = AsyncMock(return_value={})

        async def completed_wait(_session_id: str) -> None:
            return None

        with patch.object(agent_server, "stop_turn", new_callable=AsyncMock, return_value={"stopped": True}), \
                patch.object(
                    agent_server,
                    "append_durable_event",
                    append_durable_event,
                ), \
                patch.object(agent_server, "wait_for_steered_turn_slot", completed_wait):
            result = await run_queued_turn_now("chat-1", "queued-steer")
            await asyncio.sleep(0)

        self.assertEqual(result["superseded_queued_ids"], [])
        self.assertEqual(agent_server.RUN_NOW_TURNS["chat-1"]["queued_id"], "queued-steer")
        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-first", "queued-later"],
        )
        event_types = [
            call.args[1]
            for call in append_durable_event.await_args_list
        ]
        self.assertEqual(event_types, ["turn_queue_run_now"])
        run_now_payload = append_durable_event.await_args_list[0].args[2]
        self.assertEqual(run_now_payload["remaining"], 2)
        self.assertEqual(run_now_payload["superseded_queued_ids"], [])

        agent_server.STEERING_SESSIONS.discard("chat-1")
        with patch.object(agent_server, "_start_turn_locked", new_callable=AsyncMock) as start_turn:
            await start_next_queued_turn("chat-1")
            await start_next_queued_turn("chat-1")
            await start_next_queued_turn("chat-1")

        self.assertEqual(
            [call.kwargs["queued_id"] for call in start_turn.await_args_list],
            ["queued-steer", "queued-first", "queued-later"],
        )

    async def test_later_steer_preserves_user_and_internal_work_in_original_order(self) -> None:
        agent_server.QUEUED_TURNS["chat-1"] = deque([
            {
                "queued_id": "queued-first",
                "prompt": "Stale first message.",
                "file_ids": [],
                "backend": "codex",
            },
            {
                "queued_id": "queued-digest",
                "prompt": "Internal digest.",
                "file_ids": [],
                "backend": "codex",
                "purpose": "handoff_digest",
            },
            {
                "queued_id": "queued-steer",
                "prompt": "Change course now.",
                "file_ids": [],
                "backend": "codex",
            },
        ])

        async def completed_wait(_session_id: str) -> None:
            return None

        with patch.object(agent_server, "stop_turn", new_callable=AsyncMock, return_value={"stopped": True}), \
                patch.object(agent_server, "append_durable_event", new_callable=AsyncMock), \
                patch.object(agent_server, "wait_for_steered_turn_slot", completed_wait):
            await run_queued_turn_now("chat-1", "queued-steer")
            await asyncio.sleep(0)

        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-first", "queued-digest"],
        )

    async def test_second_steer_cannot_overwrite_the_first_handoff(self) -> None:
        agent_server.RUN_NOW_TURNS["chat-1"] = {
            "queued_id": "already-steering",
            "prompt": "First steer",
        }
        with self.assertRaises(agent_server.HTTPException) as raised:
            await run_queued_turn_now("chat-1", "queued-steer")
        detail = raised.exception.detail
        self.assertEqual(detail["guard"], "run_now_promotion")
        self.assertEqual(detail["owner"]["queued_id"], "already-steering")
        # The newly admitted request is the observer, not the stale owner.
        self.assertIsNone(detail["owner"]["operation_id"])
        self.assertIsNone(detail["owner"]["age_seconds"])
        self.assertEqual(agent_server.RUN_NOW_TURNS["chat-1"]["queued_id"], "already-steering")
        self.assertEqual(len(agent_server.QUEUED_TURNS["chat-1"]), 1)

    async def test_handoff_barrier_keeps_the_promoted_turn_reserved(self) -> None:
        lineage = [
            {"prompt": "Continue the original request.", "file_ids": []},
            {"prompt": "Use the smaller batch.", "file_ids": []},
        ]
        promoted = {
            "queued_id": "queued-steer",
            "prompt": "Use the smaller batch.",
            "display_prompt": "Use the smaller batch.",
            "file_ids": [],
            "display_file_ids": [],
            "backend": "codex",
            "steering_lineage": lineage,
        }
        agent_server.RUN_NOW_TURNS["chat-1"] = promoted
        agent_server.STEERING_SESSIONS.add("chat-1")

        with patch.object(agent_server, "_start_turn_locked", new_callable=AsyncMock) as start_turn:
            await start_next_queued_turn("chat-1")
            start_turn.assert_not_awaited()
            self.assertIs(agent_server.RUN_NOW_TURNS["chat-1"], promoted)

            agent_server.STEERING_SESSIONS.discard("chat-1")
            await start_next_queued_turn("chat-1")

        start_turn.assert_awaited_once()
        request = start_turn.await_args.args[1]
        self.assertEqual(request.prompt, promoted["prompt"])
        self.assertEqual(request.display_prompt, promoted["display_prompt"])
        self.assertEqual(start_turn.await_args.kwargs["display_file_ids"], [])
        self.assertEqual(start_turn.await_args.kwargs["steering_lineage"], lineage)
        self.assertNotIn("chat-1", agent_server.RUN_NOW_TURNS)

    def test_recovered_legacy_run_now_turn_restores_raw_lineage(self) -> None:
        item = queued_turn_from_event(
            {
                "type": "turn_queue_run_now",
                "queued_id": "queued-steer",
                "request_prompt": (
                    agent_server.LEGACY_STEERING_PREFIX
                    + "[Interrupted message]\nOld request\n\n"
                    "[Interrupted message attachments]\n"
                    "- /uploads/old.png (old.png, image/png)\n"
                    "[End interrupted message attachments]\n"
                    "[End interrupted message]\n\n"
                    "[Steering message]\nNew steering text\n[End steering message]"
                ),
                "prompt": "New steering text",
                "file_ids": ["new-image"],
                "display_file_ids": ["new-image"],
                "replays_interrupted_message": True,
            },
            agent_server.STORE.sessions["chat-1"],
            1,
        )

        self.assertEqual(item["prompt"], "New steering text")
        self.assertNotIn("/uploads/old.png", item["prompt"])
        self.assertEqual(
            [message["prompt"] for message in item["steering_lineage"]],
            ["Old request", "New steering text"],
        )
        self.assertEqual(item["file_ids"], ["new-image"])
        self.assertEqual(item["display_file_ids"], ["new-image"])

    def test_recovered_run_now_turn_keeps_structured_lineage(self) -> None:
        lineage = [
            {"prompt": "Old request", "file_ids": ["old-image"]},
            {"prompt": "New steering text", "file_ids": ["new-image"]},
        ]
        item = queued_turn_from_event(
            {
                "type": "turn_queue_run_now",
                "queued_id": "queued-steer",
                "request_prompt": "New steering text",
                "prompt": "New steering text",
                "file_ids": ["new-image"],
                "display_file_ids": ["new-image"],
                "replays_interrupted_message": True,
                "steering_lineage": lineage,
            },
            agent_server.STORE.sessions["chat-1"],
            1,
        )

        self.assertEqual(item["prompt"], "New steering text")
        self.assertEqual(item["steering_lineage"], lineage)

    def test_recovery_keeps_an_image_only_queued_turn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text(json.dumps({
                "id": "event-1",
                "seq": 1,
                "session_id": "chat-1",
                "type": "turn_queued",
                "ts": "2026-07-20T23:00:00Z",
                "queued_id": "queued-image",
                "prompt": "",
                "request_prompt": "",
                "file_ids": ["image-only"],
            }) + "\n")
            with patch.object(agent_server, "events_path", return_value=path):
                rebuilt = rebuild_queued_turns_from_events()

        self.assertEqual(rebuilt, 1)
        self.assertEqual(agent_server.QUEUED_TURNS["chat-1"][0]["prompt"], "")
        self.assertEqual(agent_server.QUEUED_TURNS["chat-1"][0]["file_ids"], ["image-only"])

    def test_recovery_rebuilds_durable_queue_hold_after_explicit_stop(self) -> None:
        agent_server.QUEUED_TURNS.pop("chat-1", None)
        events = [
            {
                "seq": 1,
                "type": "turn_queued",
                "queued_id": "queued-paused",
                "prompt": "Keep this queued.",
                "request_prompt": "Keep this queued.",
                "file_ids": [],
            },
            {
                "seq": 2,
                "type": "turn_queue_paused",
                "queued_ids": ["queued-paused"],
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text("".join(json.dumps({
                "id": f"event-{event['seq']}",
                "session_id": "chat-1",
                "ts": "2026-08-06T00:00:00Z",
                **event,
            }) + "\n" for event in events))
            with patch.object(agent_server, "events_path", return_value=path):
                rebuilt = rebuild_queued_turns_from_events()

        self.assertEqual(rebuilt, 1)
        item = agent_server.QUEUED_TURNS["chat-1"][0]
        self.assertTrue(item["_durable"])
        self.assertTrue(item["_paused_after_stop"])
        self.assertEqual(agent_server.update_blocking_queued_turn_count_locked(), 0)

    def test_recovery_holds_native_delivery_fence_without_replaying(self) -> None:
        agent_server.QUEUED_TURNS.pop("chat-1", None)
        events = [
            {
                "seq": 1,
                "type": "turn_queued",
                "queued_id": "queued-native",
                "prompt": "Steer exactly once.",
                "request_prompt": "Steer exactly once.",
                "file_ids": [],
            },
            {
                "seq": 2,
                "type": "turn_unqueued",
                "queued_id": "queued-native",
                "reason": "native_delivery_fence",
            },
            {
                "seq": 3,
                "type": "turn_queue_delivery_fenced",
                "queued_id": "queued-native",
                "backend": "codex",
                "prompt": "Steer exactly once.",
                "request_prompt": "Steer exactly once.",
                "file_ids": ["file-one"],
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text("".join(json.dumps({
                "id": f"event-{event['seq']}",
                "session_id": "chat-1",
                "ts": "2026-08-06T00:00:00Z",
                **event,
            }) + "\n" for event in events))
            with patch.object(agent_server, "events_path", return_value=path):
                rebuilt = rebuild_queued_turns_from_events()

        self.assertEqual(rebuilt, 1)
        item = agent_server.QUEUED_TURNS["chat-1"][0]
        self.assertTrue(item["_paused_after_stop"])
        self.assertTrue(item["_native_delivery_fenced"])
        self.assertEqual(item["prompt"], "Steer exactly once.")
        self.assertEqual(item["file_ids"], ["file-one"])
        self.assertEqual(item["backend"], "codex")

    async def test_recovery_replays_safe_rejection_compensation_as_runnable_in_order(
        self,
    ) -> None:
        agent_server.QUEUED_TURNS.pop("chat-1", None)
        events = [
            {
                "seq": 1,
                "type": "turn_queued",
                "queued_id": "queued-before",
                "prompt": "Before",
                "request_prompt": "Before",
                "file_ids": [],
                "position": 1,
            },
            {
                "seq": 2,
                "type": "turn_queued",
                "queued_id": "queued-native",
                "prompt": "Retry normally",
                "request_prompt": "Retry normally",
                "file_ids": [],
                "position": 2,
            },
            {
                "seq": 3,
                "type": "turn_queued",
                "queued_id": "queued-after",
                "prompt": "After",
                "request_prompt": "After",
                "file_ids": [],
                "position": 3,
            },
            {
                "seq": 4,
                "type": "turn_unqueued",
                "queued_id": "queued-native",
                "reason": "native_delivery_fence",
            },
            {
                "seq": 5,
                "type": "turn_queue_delivery_fenced",
                "queued_id": "queued-native",
                "backend": "codex",
                "prompt": "Retry normally",
                "request_prompt": "Retry normally",
                "file_ids": [],
                "position": 2,
            },
            {
                "seq": 6,
                "type": "turn_queued",
                "queued_id": "queued-native",
                "backend": "codex",
                "prompt": "Retry normally",
                "request_prompt": "Retry normally",
                "file_ids": [],
                "position": 2,
            },
            {
                "seq": 7,
                "type": "turn_queue_reordered",
                "positions": [
                    {"queued_id": "queued-before", "position": 1},
                    {"queued_id": "queued-native", "position": 2},
                    {"queued_id": "queued-after", "position": 3},
                ],
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text("".join(json.dumps({
                "id": f"event-{event['seq']}",
                "session_id": "chat-1",
                "ts": "2026-08-21T00:00:00Z",
                **event,
            }) + "\n" for event in events))
            with patch.object(agent_server, "events_path", return_value=path):
                rebuilt = rebuild_queued_turns_from_events()

        self.assertEqual(rebuilt, 3)
        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-before", "queued-native", "queued-after"],
        )
        restored = agent_server.QUEUED_TURNS["chat-1"][1]
        self.assertFalse(restored["_paused_after_stop"])
        self.assertNotIn("_native_delivery_fenced", restored)
        public = await agent_server.queued_turns_snapshot("chat-1")
        self.assertFalse(public[1]["paused"])

        start = AsyncMock(return_value={"run_id": "run-next"})
        with patch.object(agent_server, "_start_turn_locked", start):
            for _ in range(3):
                await agent_server._start_next_queued_turn_locked(
                    "chat-1",
                    admission_backend="codex",
                )

        self.assertEqual(
            [call.args[1].prompt for call in start.await_args_list],
            ["Before", "Retry normally", "After"],
        )
        self.assertNotIn("chat-1", agent_server.QUEUED_TURNS)

    def test_recovery_standard_compensation_releases_prefence_stop_hold(
        self,
    ) -> None:
        agent_server.QUEUED_TURNS.pop("chat-1", None)
        events = [
            {
                "seq": 1,
                "type": "turn_queued",
                "queued_id": "queued-native",
                "prompt": "Retry after pre-fence rejection",
                "request_prompt": "Retry after pre-fence rejection",
                "file_ids": [],
                "position": 1,
            },
            {
                "seq": 2,
                "type": "turn_queue_paused",
                "queued_ids": ["queued-native"],
            },
            {
                "seq": 3,
                "type": "turn_queued",
                "queued_id": "queued-native",
                "backend": "claude",
                "prompt": "Retry after pre-fence rejection",
                "request_prompt": "Retry after pre-fence rejection",
                "file_ids": [],
                "position": 1,
            },
            {
                "seq": 4,
                "type": "turn_queue_reordered",
                "positions": [
                    {"queued_id": "queued-native", "position": 1},
                ],
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text("".join(json.dumps({
                "id": f"event-{event['seq']}",
                "session_id": "chat-1",
                "ts": "2026-08-21T00:00:00Z",
                **event,
            }) + "\n" for event in events))
            with patch.object(agent_server, "events_path", return_value=path):
                rebuilt = rebuild_queued_turns_from_events()

        self.assertEqual(rebuilt, 1)
        restored = agent_server.QUEUED_TURNS["chat-1"][0]
        self.assertFalse(restored["_paused_after_stop"])
        self.assertNotIn("_native_delivery_fenced", restored)

    def test_recovery_keeps_unselected_turns_in_original_order_after_run_now_starts(self) -> None:
        events = [
            {
                "seq": 1,
                "type": "turn_queued",
                "queued_id": "queued-first",
                "prompt": "First queued message.",
                "file_ids": [],
            },
            {
                "seq": 2,
                "type": "turn_queued",
                "queued_id": "queued-steer",
                "prompt": "Run this now.",
                "file_ids": [],
            },
            {
                "seq": 3,
                "type": "turn_queued",
                "queued_id": "queued-later",
                "prompt": "Keep this for afterward.",
                "file_ids": [],
            },
            {
                "seq": 4,
                "type": "turn_queue_run_now",
                "queued_id": "queued-steer",
                "superseded_queued_ids": [],
            },
            {
                "seq": 5,
                "type": "turn_started",
                "queued_id": "queued-steer",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text("".join(json.dumps({
                "id": f"event-{event['seq']}",
                "session_id": "chat-1",
                "ts": "2026-07-21T00:00:00Z",
                **event,
            }) + "\n" for event in events))
            with patch.object(agent_server, "events_path", return_value=path):
                rebuilt = rebuild_queued_turns_from_events()

        self.assertEqual(rebuilt, 2)
        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-first", "queued-later"],
        )

    def test_recovery_honors_legacy_run_now_supersession_records(self) -> None:
        agent_server.QUEUED_TURNS.pop("chat-1", None)
        events = [
            {
                "seq": 1,
                "type": "turn_queued",
                "queued_id": "queued-first",
                "prompt": "Legacy superseded message.",
                "file_ids": [],
            },
            {
                "seq": 2,
                "type": "turn_queued",
                "queued_id": "queued-steer",
                "prompt": "Run this now.",
                "file_ids": [],
            },
            {
                "seq": 3,
                "type": "turn_queue_run_now",
                "queued_id": "queued-steer",
                "superseded_queued_ids": ["queued-first"],
            },
            {
                "seq": 4,
                "type": "turn_started",
                "queued_id": "queued-steer",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text("".join(json.dumps({
                "id": f"event-{event['seq']}",
                "session_id": "chat-1",
                "ts": "2026-07-21T00:00:00Z",
                **event,
            }) + "\n" for event in events))
            with patch.object(agent_server, "events_path", return_value=path):
                rebuilt = rebuild_queued_turns_from_events()

        self.assertEqual(rebuilt, 0)
        self.assertNotIn("chat-1", agent_server.QUEUED_TURNS)

    def test_finished_runner_schedules_owner_fenced_queue_reconciliation(self) -> None:
        agent_server.RUN_NOW_TURNS["chat-1"] = {
            "queued_id": "queued-steer",
            "prompt": "Run this next.",
        }

        self.assertTrue(should_schedule_queue_after_finish("chat-1", stopped=True))
        self.assertTrue(should_schedule_queue_after_finish("chat-1", stopped=False))
        agent_server.RUN_NOW_TURNS.clear()
        agent_server.STEERING_SESSIONS.add("chat-1")
        self.assertTrue(should_schedule_queue_after_finish("chat-1", stopped=False))
        agent_server.STEERING_SESSIONS.clear()
        self.assertTrue(should_schedule_queue_after_finish("chat-1", stopped=False))
        self.assertTrue(should_schedule_queue_after_finish("chat-1", stopped=True))

    async def test_append_failure_restores_selected_message_in_original_order(self) -> None:
        agent_server.QUEUED_TURNS["chat-1"] = deque([
            {
                "queued_id": "queued-first",
                "prompt": "Do not lose this message.",
                "file_ids": [],
                "backend": "codex",
            },
            {
                "queued_id": "queued-internal",
                "prompt": "Internal work.",
                "file_ids": [],
                "backend": "codex",
                "purpose": "scheduled_job",
            },
            {
                "queued_id": "queued-second",
                "prompt": "Do not lose this one either.",
                "file_ids": [],
                "backend": "codex",
            },
            {
                "queued_id": "queued-steer",
                "prompt": "Run this now.",
                "file_ids": [],
                "backend": "codex",
            },
        ])

        with patch.object(agent_server, "stop_turn", new_callable=AsyncMock, return_value={"stopped": True}), \
                patch.object(agent_server, "append_durable_event", new_callable=AsyncMock, side_effect=OSError("disk full")), \
                patch.object(agent_server, "schedule_next_queued_turn") as schedule_next:
            with self.assertRaisesRegex(OSError, "disk full"):
                await run_queued_turn_now("chat-1", "queued-steer")

        self.assertEqual(
            [item["queued_id"] for item in agent_server.QUEUED_TURNS["chat-1"]],
            ["queued-first", "queued-internal", "queued-second", "queued-steer"],
        )
        self.assertNotIn("chat-1", agent_server.RUN_NOW_TURNS)
        self.assertNotIn(
            "_update_transitioning",
            agent_server.QUEUED_TURNS["chat-1"][-1],
        )
        self.assertNotIn("chat-1", agent_server.STEERING_SESSIONS)
        schedule_next.assert_called_once_with("chat-1")

    async def test_precommit_cancellation_restores_force_send_without_leaking_markers(self) -> None:
        selected = agent_server.QUEUED_TURNS["chat-1"][0]
        selected["_paused_after_stop"] = True
        write_started = asyncio.Event()

        async def cancelled_before_commit(*_args: object) -> dict[str, object]:
            write_started.set()
            await asyncio.Event().wait()
            return {}

        with patch.object(
            agent_server,
            "stop_turn",
            new_callable=AsyncMock,
            return_value={"stopped": True},
        ), patch.object(
            agent_server,
            "append_durable_event",
            side_effect=cancelled_before_commit,
        ), patch.object(
            agent_server,
            "schedule_next_queued_turn",
        ) as schedule_next:
            task = asyncio.create_task(
                agent_server._run_queued_turn_now_once(
                    "chat-1",
                    "queued-steer",
                )
            )
            await asyncio.wait_for(write_started.wait(), 0.5)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        restored = agent_server.QUEUED_TURNS["chat-1"][0]
        self.assertEqual(restored["queued_id"], "queued-steer")
        self.assertTrue(restored["_paused_after_stop"])
        self.assertNotIn("_update_transitioning", restored)
        self.assertNotIn("chat-1", agent_server.RUN_NOW_TURNS)
        self.assertNotIn("chat-1", agent_server.STEERING_SESSIONS)
        schedule_next.assert_called_once_with("chat-1")

    async def test_repeated_precommit_cancellation_cannot_cancel_force_send_rollback(
        self,
    ) -> None:
        selected = agent_server.QUEUED_TURNS["chat-1"][0]
        selected["_durable"] = True
        selected["_paused_after_stop"] = True
        write_started = asyncio.Event()

        async def cancelled_before_commit(*_args: object) -> dict[str, object]:
            write_started.set()
            await asyncio.Event().wait()
            return {}

        with patch.object(
            agent_server,
            "stop_turn",
            new_callable=AsyncMock,
            return_value={"stopped": True},
        ), patch.object(
            agent_server,
            "append_durable_event",
            side_effect=cancelled_before_commit,
        ), patch.object(
            agent_server,
            "schedule_next_queued_turn",
        ) as schedule_next, patch.object(
            agent_server,
            "QUEUE_LOCK",
            asyncio.Lock(),
        ):
            task = asyncio.create_task(
                agent_server._run_queued_turn_now_once(
                    "chat-1",
                    "queued-steer",
                )
            )
            await asyncio.wait_for(write_started.wait(), 0.5)
            await agent_server.QUEUE_LOCK.acquire()
            try:
                task.cancel()
                for _ in range(100):
                    waiters = getattr(agent_server.QUEUE_LOCK, "_waiters", ())
                    if waiters and any(not waiter.done() for waiter in waiters):
                        break
                    await asyncio.sleep(0)
                else:
                    self.fail("force-send rollback did not wait for QUEUE_LOCK")
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                self.assertTrue(
                    agent_server.RUN_NOW_TURNS["chat-1"][
                        "_update_transitioning"
                    ]
                )
            finally:
                agent_server.QUEUE_LOCK.release()
            with self.assertRaises(asyncio.CancelledError):
                await task

        restored = agent_server.QUEUED_TURNS["chat-1"][0]
        self.assertIs(restored, selected)
        self.assertTrue(restored["_durable"])
        self.assertTrue(restored["_paused_after_stop"])
        self.assertNotIn("_update_transitioning", restored)
        self.assertNotIn("chat-1", agent_server.RUN_NOW_TURNS)
        self.assertNotIn("chat-1", agent_server.STEERING_SESSIONS)
        self.assertEqual(agent_server.update_blocking_queued_turn_count_locked(), 0)
        schedule_next.assert_called_once_with("chat-1")


class StartupQueueRecoveryAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_new_submission_cannot_leapfrog_undiscovered_durable_row(
        self,
    ) -> None:
        original_sessions = agent_server.STORE.sessions
        original_queue = agent_server.QUEUED_TURNS
        original_recovery = agent_server.QUEUE_RECOVERY_TASK
        release_recovery = asyncio.Event()
        recovery_started = asyncio.Event()
        old = {
            "queued_id": "queued-before-restart",
            "prompt": "Older durable prompt",
            "file_ids": [],
            "backend": "codex",
            "_durable": True,
        }

        async def delayed_recovery() -> tuple[int, int]:
            recovery_started.set()
            await release_recovery.wait()
            async with agent_server.QUEUE_LOCK:
                agent_server.QUEUED_TURNS["chat-recovery"] = deque([old])
            return 1, 1

        recovery = asyncio.create_task(delayed_recovery())
        try:
            agent_server.STORE.sessions = {
                "chat-recovery": {
                    "id": "chat-recovery",
                    "backend": "codex",
                }
            }
            agent_server.QUEUED_TURNS = {}
            agent_server.QUEUE_RECOVERY_TASK = recovery
            await recovery_started.wait()
            request = agent_server.TurnRequest(prompt="New prompt")
            with patch.object(
                agent_server,
                "QUEUE_RECOVERY_ADMISSION_WAIT_SECONDS",
                0.01,
            ):
                with self.assertRaises(agent_server.TransientAdmissionWait) as raised:
                    await agent_server.start_turn("chat-recovery", request)
            self.assertEqual(raised.exception.status_code, 503)
            self.assertNotIn("chat-recovery", agent_server.QUEUED_TURNS)

            release_recovery.set()
            await recovery
            with patch.object(
                agent_server,
                "append_durable_event",
                new_callable=AsyncMock,
                return_value={"type": "turn_queued"},
            ), patch.object(agent_server, "schedule_next_queued_turn"):
                await agent_server.enqueue_turn(
                    "chat-recovery",
                    request,
                    agent_server.STORE.sessions["chat-recovery"],
                )

            prompts = [
                item["prompt"]
                for item in agent_server.QUEUED_TURNS["chat-recovery"]
            ]
            self.assertEqual(prompts, ["Older durable prompt", "New prompt"])
        finally:
            release_recovery.set()
            await asyncio.gather(recovery, return_exceptions=True)
            agent_server.STORE.sessions = original_sessions
            agent_server.QUEUED_TURNS = original_queue
            agent_server.QUEUE_RECOVERY_TASK = original_recovery

    async def test_failed_recovery_keeps_internal_start_admission_fail_closed(
        self,
    ) -> None:
        original_recovery = agent_server.QUEUE_RECOVERY_TASK

        async def failed_recovery() -> tuple[int, int]:
            raise OSError("timeline unreadable")

        recovery = asyncio.create_task(failed_recovery())
        await asyncio.gather(recovery, return_exceptions=True)
        try:
            agent_server.QUEUE_RECOVERY_TASK = recovery
            with self.assertRaises(agent_server.TransientAdmissionWait) as raised:
                await agent_server._start_turn_locked(
                    "chat-recovery",
                    agent_server.TurnRequest(prompt="Must not start"),
                )
            self.assertEqual(raised.exception.status_code, 503)
            self.assertIn("did not complete", str(raised.exception.detail))
        finally:
            agent_server.QUEUE_RECOVERY_TASK = original_recovery


class ClaudeResultDiagnosticTests(unittest.TestCase):
    def diagnostic_event(self, errors: list[str] | None = None) -> dict[str, object]:
        return {
            "type": "result",
            "subtype": "error_during_execution",
            "terminal_reason": "aborted_tools",
            "stop_reason": "tool_use",
            "errors": errors or ["[ede_diagnostic] result_type=user last_content_type=n/a stop_reason=tool_use"],
        }

    def test_expected_interruption_is_recognized_and_sanitized(self) -> None:
        event = self.diagnostic_event()
        self.assertTrue(is_expected_claude_interruption_result(event))
        self.assertEqual(claude_result_error(event), "Claude stopped before completing the turn.")

    def test_aborted_streaming_interruption_with_null_stop_reason_is_recognized(self) -> None:
        event = self.diagnostic_event([
            "[ede_diagnostic] result_type=user last_content_type=n/a stop_reason=null",
        ])
        event["terminal_reason"] = "aborted_streaming"
        event["stop_reason"] = None

        self.assertTrue(is_expected_claude_interruption_result(event))
        self.assertEqual(claude_result_error(event), "Claude stopped before completing the turn.")

    def test_real_error_survives_alongside_internal_diagnostic(self) -> None:
        event = self.diagnostic_event([
            "[ede_diagnostic] result_type=user last_content_type=n/a stop_reason=null",
            "Provider connection failed",
        ])
        event["terminal_reason"] = "aborted_streaming"
        event["stop_reason"] = None
        self.assertFalse(is_expected_claude_interruption_result(event))
        self.assertEqual(claude_result_error(event), "Provider connection failed")

    def test_ordinary_claude_error_is_unchanged(self) -> None:
        event = {"type": "result", "subtype": "error_during_execution", "errors": ["Authentication failed"]}
        self.assertEqual(claude_result_error(event), "Authentication failed")


if __name__ == "__main__":
    unittest.main()
