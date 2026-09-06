"""Regression tests for the 2026-09-04 cross-chat queue wedge: restart-rebuilt
delivery rows that could never pass the immutability check, silent retry
loops that appended a turn_deferred event on every attempt, and unbounded
retries for hidden delivery rows."""

import unittest
from collections import deque
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException

import agent_server


class AdmissionReached(Exception):
    """Raised by the first call after the delivery immutability checks."""


TARGET_SESSION = {
    "id": "target",
    "title": "Target",
    "backend": "claude",
    "model": "opus",
    "effort": "high",
}
CLAUDE_CAPS = [agent_server.CLAUDE_SDK_INTERACTIVE_CLIENT_CAPABILITY]
CODEX_CAPS = [agent_server.CODEX_INTERACTIVE_CLIENT_CAPABILITY]


def delivery_event(**overrides):
    event = {
        "type": "turn_queued",
        "queued_id": "queued_delivery",
        "prompt": "Incoming cross-chat message",
        "request_prompt": "relay prompt",
        "display_prompt": "Incoming cross-chat message",
        # enqueue_turn persists the target's concrete backend for display even
        # though the in-memory delivery item carried backend=None.
        "backend": "claude",
        "model": None,
        "effort": None,
        "purpose": agent_server.LOCAL_CROSS_CHAT_DELIVERY_PURPOSE,
        "source_session_id": "source",
        "target_session_id": "target",
        "cross_chat_envelope_id": "handoff_rebuilt",
        "client_capabilities": list(CLAUDE_CAPS),
        "ts": "2026-09-04T00:00:00Z",
    }
    event.update(overrides)
    return event


def delivery_request(item: dict, **overrides) -> agent_server.TurnRequest:
    fields = {
        "prompt": str(item.get("prompt") or ""),
        "backend": item.get("backend"),
        "model": item.get("model"),
        "effort": item.get("effort"),
        "display_prompt": item.get("display_prompt"),
        "purpose": item.get("purpose"),
        "source_session_id": item.get("source_session_id"),
        "target_session_id": item.get("target_session_id"),
        "cross_chat_envelope_id": item.get("cross_chat_envelope_id"),
        "client_capabilities": list(item.get("client_capabilities") or []),
    }
    fields.update(overrides)
    return agent_server.TurnRequest(**fields)


def delivery_record(queued_id: str = "queued_delivery") -> dict:
    return {
        "id": "handoff_rebuilt",
        "source_session_id": "source",
        "target_session_id": "target",
        "status": "queued",
        "queued_id": queued_id,
    }


class RebuiltDeliveryRowTests(unittest.IsolatedAsyncioTestCase):
    def test_rebuilt_delivery_row_carries_no_runtime(self) -> None:
        sess = {"backend": "claude", "model": "opus", "effort": "high"}
        item = agent_server.queued_turn_from_event(delivery_event(), sess, 1)
        self.assertIsNone(item["backend"])
        self.assertIsNone(item["model"])
        self.assertIsNone(item["effort"])
        secure = agent_server.queued_turn_from_event(
            delivery_event(
                purpose=agent_server.SECURE_PEER_DELIVERY_PURPOSE,
                cross_chat_envelope_id=None,
                secure_peer_envelope_id="secure_rebuilt",
                backend="codex",
                model="gpt-5",
                effort="low",
            ),
            sess,
            1,
        )
        self.assertIsNone(secure["backend"])
        self.assertIsNone(secure["model"])
        self.assertIsNone(secure["effort"])

    def test_user_rows_still_inherit_the_session_runtime(self) -> None:
        item = agent_server.queued_turn_from_event(
            {"type": "turn_queued", "queued_id": "queued_user", "prompt": "hi"},
            {"backend": "codex", "model": "gpt-5", "effort": "medium"},
            1,
        )
        self.assertEqual(item["backend"], "codex")
        self.assertEqual(item["model"], "gpt-5")
        self.assertEqual(item["effort"], "medium")

    async def start_delivery(self, req: agent_server.TurnRequest) -> None:
        with (
            patch.object(
                agent_server.STORE,
                "sessions",
                {
                    "source": {"id": "source", "title": "Source", "backend": "codex"},
                    "target": dict(TARGET_SESSION),
                },
            ),
            patch.object(agent_server, "DELETING_SESSIONS", set()),
            patch.object(agent_server, "DELETED_SESSION_TOMBSTONES", set()),
            patch.object(
                agent_server,
                "cross_chat_delivery_client_capabilities",
                return_value=list(CLAUDE_CAPS),
            ),
            patch.object(
                agent_server,
                "get_cross_chat_delivery_record",
                AsyncMock(return_value=delivery_record()),
            ),
            patch.object(
                agent_server,
                "validate_session_file_ids",
                side_effect=AdmissionReached,
            ),
        ):
            await agent_server._start_turn_locked(
                "target",
                req,
                queue_if_busy=False,
                queued_id="queued_delivery",
                accepted_provider_route_snapshot=[],
            )

    async def test_rebuilt_delivery_row_passes_the_immutability_check(self) -> None:
        item = agent_server.queued_turn_from_event(
            delivery_event(), dict(TARGET_SESSION), 1
        )
        with self.assertRaises(AdmissionReached):
            await self.start_delivery(delivery_request(item))

    async def test_runtime_equal_to_the_target_is_not_a_mutation(self) -> None:
        # Rows persisted by older builds echo the target chat's own runtime.
        item = agent_server.queued_turn_from_event(
            delivery_event(), dict(TARGET_SESSION), 1
        )
        with self.assertRaises(AdmissionReached):
            await self.start_delivery(
                delivery_request(
                    item, backend="claude", model="opus", effort="high"
                )
            )

    async def test_user_selected_backend_mismatch_still_rejects(self) -> None:
        item = agent_server.queued_turn_from_event(
            delivery_event(), dict(TARGET_SESSION), 1
        )
        for overrides in (
            {"backend": "codex"},
            {"model": "sonnet"},
            {"effort": "low"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(HTTPException) as raised:
                    await self.start_delivery(delivery_request(item, **overrides))
                self.assertEqual(raised.exception.status_code, 400)
                self.assertEqual(
                    raised.exception.detail,
                    "cross-chat delivery runtime is immutable",
                )

    async def test_capability_set_of_another_backend_is_a_target_change(self) -> None:
        item = agent_server.queued_turn_from_event(
            delivery_event(client_capabilities=list(CODEX_CAPS)),
            dict(TARGET_SESSION),
            1,
        )
        with self.assertRaises(HTTPException) as raised:
            await self.start_delivery(delivery_request(item))
        self.assertEqual(raised.exception.status_code, 410)
        self.assertEqual(
            raised.exception.detail,
            "cross-chat delivery target runtime changed",
        )

    async def test_unknown_capability_set_is_still_immutable_violation(self) -> None:
        item = agent_server.queued_turn_from_event(
            delivery_event(client_capabilities=["forged_capability"]),
            dict(TARGET_SESSION),
            1,
        )
        with self.assertRaises(HTTPException) as raised:
            await self.start_delivery(delivery_request(item))
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(
            raised.exception.detail,
            "cross-chat delivery runtime is immutable",
        )


def queued_delivery_item(**overrides) -> dict:
    item = {
        "queued_id": "queued_delivery",
        "prompt": "relay prompt",
        "file_ids": [],
        "backend": None,
        "model": None,
        "effort": None,
        "display_prompt": "Incoming cross-chat message",
        "purpose": agent_server.LOCAL_CROSS_CHAT_DELIVERY_PURPOSE,
        "source_session_id": "source",
        "target_session_id": "target",
        "chat_references": [],
        "team_references": [],
        "cross_chat_envelope_id": "handoff_retry",
        "client_capabilities": list(CLAUDE_CAPS),
        "_durable": True,
    }
    item.update(overrides)
    return item


def queued_user_item(**overrides) -> dict:
    item = {
        "queued_id": "queued_user",
        "prompt": "hello",
        "file_ids": [],
        "backend": None,
        "model": None,
        "effort": None,
        "display_prompt": None,
        "purpose": None,
        "chat_references": [],
        "team_references": [],
        "_durable": True,
    }
    item.update(overrides)
    return item


class DeferredDeliveryRetryTests(unittest.IsolatedAsyncioTestCase):
    async def promote(self, item: dict, failure: BaseException):
        """Run one promotion whose admission fails with ``failure``."""
        queue = {"target": deque([item])}
        append_event = AsyncMock()
        discard = AsyncMock()
        with (
            patch.object(
                agent_server.STORE,
                "sessions",
                {
                    "source": {"id": "source", "title": "Source", "backend": "codex"},
                    "target": dict(TARGET_SESSION),
                },
            ),
            patch.object(agent_server, "QUEUED_TURNS", queue),
            patch.object(agent_server, "RUN_NOW_TURNS", {}),
            patch.object(agent_server, "STEERING_SESSIONS", set()),
            patch.object(agent_server, "EXPLICIT_STOP_OPERATIONS", {}),
            patch.object(agent_server, "DELETING_SESSIONS", set()),
            patch.object(agent_server, "DELETED_SESSION_TOMBSTONES", set()),
            patch.object(agent_server, "BUSY_SESSIONS", set()),
            patch.object(
                agent_server,
                "managed_server_update_admission_blocker",
                return_value=None,
            ),
            patch.object(
                agent_server,
                "_start_turn_locked",
                AsyncMock(side_effect=failure),
            ),
            patch.object(agent_server, "append_event", append_event),
            patch.object(agent_server, "terminally_discard_queued_turn", discard),
            patch.object(agent_server, "schedule_queued_turn_retry", MagicMock()),
        ):
            await agent_server._start_next_queued_turn_locked(
                "target", admission_backend=None
            )
        return queue, append_event, discard

    @staticmethod
    def deferred_events(append_event: AsyncMock) -> list[dict]:
        return [
            call.args[2]
            for call in append_event.await_args_list
            if call.args[1] == "turn_deferred"
        ]

    async def test_generic_failure_announces_deferral_once(self) -> None:
        item = queued_delivery_item()
        queue, append_event, discard = await self.promote(
            item, RuntimeError("provider bridge unavailable")
        )
        self.assertEqual(len(self.deferred_events(append_event)), 1)
        self.assertIn(
            "provider bridge unavailable",
            self.deferred_events(append_event)[0]["message"],
        )
        self.assertTrue(item["_turn_deferred_notified"])
        self.assertEqual(item["_last_deferred_detail"], "provider bridge unavailable")
        self.assertEqual(item["_admission_failures"], 1)
        self.assertEqual(list(queue["target"]), [item])
        discard.assert_not_awaited()

        # The same failure again: requeued, counted, but not announced again.
        queue, append_event, discard = await self.promote(
            item, RuntimeError("provider bridge unavailable")
        )
        self.assertEqual(self.deferred_events(append_event), [])
        self.assertEqual(item["_admission_failures"], 2)
        self.assertEqual(list(queue["target"]), [item])
        discard.assert_not_awaited()

        # A different concise error is announced once more.
        queue, append_event, discard = await self.promote(
            item, RuntimeError("target transport restarting")
        )
        self.assertEqual(len(self.deferred_events(append_event)), 1)
        self.assertEqual(item["_last_deferred_detail"], "target transport restarting")
        self.assertEqual(item["_admission_failures"], 3)

    async def test_http_deferral_counts_admission_failures(self) -> None:
        item = queued_delivery_item()
        queue, append_event, discard = await self.promote(
            item, HTTPException(status_code=409, detail="wait for Codex goals")
        )
        self.assertEqual(item["_admission_failures"], 1)
        self.assertEqual(item["_last_deferred_detail"], "wait for Codex goals")
        self.assertEqual(len(self.deferred_events(append_event)), 1)
        self.assertEqual(list(queue["target"]), [item])
        discard.assert_not_awaited()

    async def test_thirty_first_failure_discards_a_delivery_row(self) -> None:
        self.assertEqual(agent_server.QUEUE_DELIVERY_ADMISSION_FAILURE_LIMIT, 30)
        for failure in (
            RuntimeError("provider bridge unavailable"),
            HTTPException(status_code=503, detail="runtime unavailable"),
        ):
            with self.subTest(failure=type(failure).__name__):
                item = queued_delivery_item(_admission_failures=30)
                queue, _append_event, discard = await self.promote(item, failure)
                discard.assert_awaited_once()
                discarded_item = discard.await_args.args[1]
                reason = discard.await_args.args[2]
                self.assertIs(discarded_item, item)
                self.assertIn(
                    "cross-chat delivery could not be admitted after 31 attempts",
                    reason,
                )
                self.assertTrue(
                    reason.endswith("provider bridge unavailable")
                    or reason.endswith("runtime unavailable"),
                    reason,
                )
                self.assertEqual(item["_admission_failures"], 31)
                # The discarded row was not requeued.
                self.assertNotIn("target", queue)

    async def test_thirtieth_failure_still_requeues(self) -> None:
        item = queued_delivery_item(_admission_failures=29)
        queue, _append_event, discard = await self.promote(
            item, RuntimeError("provider bridge unavailable")
        )
        discard.assert_not_awaited()
        self.assertEqual(item["_admission_failures"], 30)
        self.assertEqual(list(queue["target"]), [item])

    async def test_user_rows_are_never_discarded_by_the_bound(self) -> None:
        item = queued_user_item(_admission_failures=30)
        queue, append_event, discard = await self.promote(
            item, HTTPException(status_code=409, detail="session already has a running turn")
        )
        discard.assert_not_awaited()
        self.assertEqual(item["_admission_failures"], 31)
        self.assertEqual(list(queue["target"]), [item])
        self.assertEqual(len(self.deferred_events(append_event)), 1)

        # Far beyond the delivery bound the user's message is still preserved.
        item = queued_user_item(_admission_failures=500)
        queue, _append_event, discard = await self.promote(
            item, HTTPException(status_code=503, detail="server update in progress")
        )
        discard.assert_not_awaited()
        self.assertEqual(list(queue["target"]), [item])

    async def test_waiting_on_a_busy_target_is_not_an_admission_failure(self) -> None:
        item = queued_delivery_item(_admission_failures=30)
        queue = {"target": deque([item])}
        with (
            patch.object(
                agent_server.STORE,
                "sessions",
                {
                    "source": {"id": "source", "title": "Source", "backend": "codex"},
                    "target": dict(TARGET_SESSION),
                },
            ),
            patch.object(agent_server, "QUEUED_TURNS", queue),
            patch.object(agent_server, "RUN_NOW_TURNS", {}),
            patch.object(agent_server, "STEERING_SESSIONS", set()),
            patch.object(agent_server, "EXPLICIT_STOP_OPERATIONS", {}),
            patch.object(agent_server, "DELETING_SESSIONS", set()),
            patch.object(agent_server, "DELETED_SESSION_TOMBSTONES", set()),
            patch.object(agent_server, "BUSY_SESSIONS", {"target"}),
            patch.object(
                agent_server,
                "_start_turn_locked",
                AsyncMock(
                    side_effect=HTTPException(
                        status_code=409,
                        detail="session already has a running turn",
                    )
                ),
            ),
            patch.object(agent_server, "append_event", AsyncMock()),
            patch.object(
                agent_server, "terminally_discard_queued_turn", AsyncMock()
            ) as discard,
            patch.object(agent_server, "schedule_queued_turn_retry", MagicMock()),
        ):
            await agent_server._start_next_queued_turn_locked(
                "target", admission_backend=None
            )
        discard.assert_not_awaited()
        self.assertEqual(item["_admission_failures"], 30)
        self.assertEqual(list(queue["target"]), [item])


if __name__ == "__main__":
    unittest.main()
