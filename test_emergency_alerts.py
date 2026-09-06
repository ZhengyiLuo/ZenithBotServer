import asyncio
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from starlette.requests import Request

import agent_server


def provider_request(
    token: str,
    *,
    session_id: str = "source",
    host: str = "127.0.0.1",
) -> Request:
    return Request({
        "type": "http",
        "method": "POST",
        "path": f"/api/agent/sessions/{session_id}/emergency-alerts",
        "headers": [
            (
                b"x-agentsdock-provider-capability",
                token.encode("utf-8"),
            ),
        ],
        "query_string": b"",
        "scheme": "http",
        "server": ("127.0.0.1", 7850),
        "client": (host, 43100),
    })


class EmergencyAlertServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(agent_server, "STATE_DIR", self.root / "state"))
        self.stack.enter_context(patch.object(
            agent_server,
            "SESSIONS_FILE",
            self.root / "state" / "sessions.json",
        ))
        self.stack.enter_context(patch.object(agent_server, "FILES_ROOT", self.root / "state" / "files"))
        self.stack.enter_context(patch.object(
            agent_server,
            "CODE_DIFFS_ROOT",
            self.root / "state" / "code_diffs",
        ))
        self.stack.enter_context(patch.object(
            agent_server,
            "CROSS_CHAT_AUTHORITY_ROOT",
            self.root / "state" / "cross_chat_authority",
        ))
        self.stack.enter_context(patch.object(agent_server, "AGENT_TOKEN", "server-token"))
        self.stack.enter_context(patch.object(agent_server, "EVENT_SEQ_CACHE", {}))
        self.stack.enter_context(patch.object(agent_server, "EVENT_SEQ_LOCK", asyncio.Lock()))
        self.stack.enter_context(patch.object(agent_server, "EVENT_DELIVERY_LOCKS", {}))
        self.stack.enter_context(patch.object(agent_server, "SESSION_LIFECYCLE_LOCKS", {}))
        self.stack.enter_context(patch.object(agent_server, "HISTORY_SEARCH_DIRTY", set()))
        self.stack.enter_context(patch.object(agent_server, "DELETING_SESSIONS", set()))
        self.stack.enter_context(patch.object(agent_server, "DELETED_SESSION_TOMBSTONES", set()))
        self.stack.enter_context(patch.object(agent_server, "CROSS_CHAT_CAPABILITIES", {}))
        self.stack.enter_context(patch.object(
            agent_server,
            "CROSS_CHAT_CAPABILITY_LOCK",
            asyncio.Lock(),
        ))
        self.stack.enter_context(patch.object(agent_server, "STOPPED_RUNS", set()))
        self.stack.enter_context(patch.object(agent_server.HUB, "broadcast", AsyncMock()))

        self.base_source = {
            "id": "source",
            "title": "Source chat",
            "folder": "General",
            "cwd": str(self.root),
            "backend": agent_server.BACKEND_CODEX,
            "provider_jobs_access": "full",
            "created_at": "2026-08-25T00:00:00Z",
            "updated_at": "2026-08-25T00:00:00Z",
        }
        self.other = {
            **self.base_source,
            "id": "other",
            "title": "Other chat",
        }
        self.stack.enter_context(patch.object(
            agent_server.STORE,
            "sessions",
            {"source": dict(self.base_source), "other": dict(self.other)},
        ))
        self.stack.enter_context(patch.object(agent_server.STORE, "_lock", asyncio.Lock()))
        self.stack.enter_context(patch.object(
            agent_server,
            "CURRENT_TURNS",
            {"source": {"run_id": "run_active"}},
        ))
        self.stack.enter_context(patch.object(
            agent_server,
            "ACTIVE",
            {
                "source": {
                    "run_id": "run_active",
                    "stop_requested": False,
                }
            },
        ))
        self.stack.enter_context(patch.object(agent_server, "BUSY_SESSIONS", {"source"}))
        agent_server.ensure_dirs("source")
        agent_server.ensure_dirs("other")
        await agent_server.STORE.save()
        self.authority_path, self.token = await self.issue_authority(
            "source",
            "run_active",
            actions={"emergency"},
        )

    async def asyncTearDown(self) -> None:
        self.stack.close()
        self.temporary.cleanup()

    async def issue_authority(
        self,
        session_id: str,
        run_id: str,
        *,
        actions: set[str],
    ) -> tuple[Path, str]:
        path = await agent_server.issue_cross_chat_capability(
            session_id,
            run_id,
            [],
            actions=actions,
        )
        self.assertIsNotNone(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        return path, str(payload["provider_capability"])

    async def raise_alert(
        self,
        request_id: str,
        message: str,
        *,
        token: str | None = None,
        session_id: str = "source",
    ) -> dict:
        return await agent_server.raise_agent_emergency_alert(
            provider_request(token or self.token, session_id=session_id),
            session_id,
            agent_server.EmergencyAlertRequest(
                request_id=request_id,
                message=message,
            ),
        )

    def event_records(self, session_id: str = "source") -> list[dict]:
        path = agent_server.events_path(session_id)
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    async def test_raise_is_durable_idempotent_and_binds_request_content(self) -> None:
        first = await self.raise_alert(
            "request.raise.0001",
            "Database replicas are losing committed writes.",
        )
        second = await self.raise_alert(
            "request.raise.0001",
            "Database replicas are losing committed writes.",
        )

        self.assertTrue(first["ok"])
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["event_id"], second["event_id"])
        self.assertEqual(first["event_seq"], second["event_seq"])
        self.assertEqual(first["alert"], second["alert"])
        self.assertEqual(first["alert"]["severity"], "critical")
        self.assertEqual(first["alert"]["source_run_id"], "run_active")
        self.assertEqual(first["unacknowledged_emergency_count"], 1)

        events = self.event_records()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "emergency_alert_raised")
        self.assertEqual(events[0]["emergency_request_id"], "request.raise.0001")
        self.assertEqual(events[0]["run_id"], "run_active")
        self.assertGreater(int(events[0]["seq"]), 0)
        self.assertTrue(agent_server.events_path("source").is_file())

        safe = agent_server.client_safe_event(events[0])
        self.assertNotIn("emergency_request_id", safe)
        self.assertNotIn("emergency_request_digest", safe)
        emergency_broadcast = agent_server.HUB.broadcast.await_args_list[-1].args
        self.assertEqual(emergency_broadcast[0], agent_server.EMERGENCY_HUB_KEY)
        self.assertEqual(
            emergency_broadcast[1]["server_identity"],
            agent_server.server_identity(),
        )

        with self.assertRaises(HTTPException) as changed:
            await self.raise_alert(
                "request.raise.0001",
                "A different emergency must not reuse the receipt.",
            )
        self.assertEqual(changed.exception.status_code, 409)
        self.assertEqual(len(self.event_records()), 1)

    async def test_request_receipt_is_run_scoped_and_foreign_capability_is_rejected(self) -> None:
        first = await self.raise_alert(
            "request.bound.0001",
            "Production state is at immediate risk.",
        )

        agent_server.CURRENT_TURNS["source"] = {"run_id": "run_replacement"}
        agent_server.ACTIVE["source"] = {
            "run_id": "run_replacement",
            "stop_requested": False,
        }
        _replacement_path, replacement_token = await self.issue_authority(
            "source",
            "run_replacement",
            actions={"emergency"},
        )
        replacement = await self.raise_alert(
            "request.bound.0001",
            "Production state is at immediate risk.",
            token=replacement_token,
        )
        self.assertFalse(replacement["duplicate"])
        self.assertNotEqual(replacement["alert"]["id"], first["alert"]["id"])

        agent_server.CURRENT_TURNS["other"] = {"run_id": "run_other"}
        agent_server.ACTIVE["other"] = {
            "run_id": "run_other",
            "stop_requested": False,
        }
        agent_server.BUSY_SESSIONS.add("other")
        _other_path, other_token = await self.issue_authority(
            "other",
            "run_other",
            actions={"emergency"},
        )
        with self.assertRaises(HTTPException) as foreign:
            await self.raise_alert(
                "request.foreign.0001",
                "Must remain in the owning chat.",
                token=other_token,
            )
        self.assertEqual(foreign.exception.status_code, 403)
        self.assertEqual(len(self.event_records()), 2)

    async def test_per_run_request_cap_allows_safe_retries_but_rejects_a_fourth_alert(self) -> None:
        receipts = []
        for index in range(agent_server.EMERGENCY_REQUESTS_PER_RUN):
            receipts.append(await self.raise_alert(
                f"request.limit.{index:04d}",
                f"Distinct emergency number {index + 1}.",
            ))

        duplicate = await self.raise_alert(
            "request.limit.0000",
            "Distinct emergency number 1.",
        )
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(duplicate["event_id"], receipts[0]["event_id"])

        with self.assertRaises(HTTPException) as over_limit:
            await self.raise_alert(
                "request.limit.9999",
                "A fourth distinct request must be rejected.",
            )
        self.assertEqual(over_limit.exception.status_code, 429)
        self.assertEqual(
            len(self.event_records()),
            agent_server.EMERGENCY_REQUESTS_PER_RUN,
        )

    async def test_active_alert_ceiling_rejects_instead_of_silently_dropping_an_alert(self) -> None:
        agent_server.STORE.sessions["source"]["_emergency_alerts"] = [
            {
                "id": f"emergency_{index:032x}",
                "status": "active",
                "severity": "critical",
                "message": f"Existing emergency {index}",
                "raised_at": "2026-08-25T00:00:00Z",
                "source_run_id": "older-run",
            }
            for index in range(agent_server.EMERGENCY_ACTIVE_ALERT_LIMIT)
        ]

        with self.assertRaises(HTTPException) as full:
            await self.raise_alert(
                "request.capacity.0001",
                "This must wait for an explicit acknowledgement.",
            )

        self.assertEqual(full.exception.status_code, 429)
        self.assertEqual(
            len(agent_server.active_emergency_alerts(
                agent_server.STORE.sessions["source"],
            )),
            agent_server.EMERGENCY_ACTIVE_ALERT_LIMIT,
        )
        self.assertFalse(self.event_records())

    async def test_request_and_ack_recovery_is_not_lost_after_two_hundred_later_events(self) -> None:
        raised = await self.raise_alert(
            "request.deep-history.0001",
            "This receipt must remain exact in a long-running turn.",
        )
        await agent_server.acknowledge_session_emergency(
            "source",
            agent_server.AcknowledgeEmergencyRequest(
                expected_alert_id=raised["alert"]["id"],
            ),
        )
        await agent_server.append_durable_event_batch(
            "source",
            [
                ("reasoning_summary", {
                    "run_id": "run_active",
                    "text": f"ordinary event {index}",
                })
                for index in range(250)
            ],
        )

        duplicate = await self.raise_alert(
            "request.deep-history.0001",
            "This receipt must remain exact in a long-running turn.",
        )

        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(duplicate["event_id"], raised["event_id"])
        self.assertEqual(duplicate["unacknowledged_emergency_count"], 0)
        self.assertEqual(
            agent_server.public_session(agent_server.STORE.sessions["source"])[
                "unacknowledged_emergency_count"
            ],
            0,
        )

    async def test_later_projection_recovers_every_prior_committed_lifecycle_event(self) -> None:
        def alert(identifier: str, message: str) -> dict:
            return {
                "id": identifier,
                "status": "active",
                "severity": "critical",
                "message": message,
                "raised_at": "2026-08-25T12:00:00Z",
                "source_run_id": "run_active",
            }

        first_alert = alert(
            "emergency_" + "a" * 32,
            "The first durable projection failed.",
        )
        first = await agent_server.append_durable_event(
            "source",
            "emergency_alert_raised",
            {"run_id": "run_active", "emergency_alert": first_alert},
        )
        with patch.object(
            agent_server.STORE,
            "save",
            AsyncMock(side_effect=OSError("projection disk failure")),
        ):
            with self.assertRaises(OSError):
                await agent_server.STORE.apply_emergency_event("source", first)

        second_alert = alert(
            "emergency_" + "b" * 32,
            "The later alert must recover the first one too.",
        )
        second = await agent_server.append_durable_event(
            "source",
            "emergency_alert_raised",
            {"run_id": "run_active", "emergency_alert": second_alert},
        )
        await agent_server.STORE.apply_emergency_event("source", second)

        active_ids = {
            value["id"]
            for value in agent_server.active_emergency_alerts(
                agent_server.STORE.sessions["source"],
            )
        }
        self.assertEqual(active_ids, {first_alert["id"], second_alert["id"]})
        self.assertGreaterEqual(
            int(agent_server.STORE.sessions["source"]["_emergency_reconciled_through_seq"]),
            int(second["seq"]),
        )

    async def test_post_fsync_projection_finishes_when_the_request_is_cancelled(self) -> None:
        projection_started = asyncio.Event()
        release_projection = asyncio.Event()
        original_apply = agent_server.STORE.apply_emergency_event

        async def delayed_apply(session_id: str, event: dict) -> dict:
            projection_started.set()
            await release_projection.wait()
            return await original_apply(session_id, event)

        with patch.object(
            agent_server.STORE,
            "apply_emergency_event",
            side_effect=delayed_apply,
        ):
            task = asyncio.create_task(self.raise_alert(
                "request.cancel.0001",
                "The durable red state must survive caller cancellation.",
            ))
            await projection_started.wait()
            task.cancel()
            release_projection.set()
            receipt = await task

        self.assertFalse(receipt["duplicate"])
        self.assertEqual(len(self.event_records()), 1)
        self.assertEqual(
            agent_server.public_session(agent_server.STORE.sessions["source"])[
                "emergency_alert"
            ]["id"],
            receipt["alert"]["id"],
        )

    async def test_unauthorized_call_cannot_probe_hidden_session_state(self) -> None:
        agent_server.STORE.sessions["source"]["archived"] = True
        cases = (
            ("source", "Visible text"),
            ("missing-chat", "Visible text"),
            ("source", "\x00"),
        )
        for session_id, message in cases:
            with self.subTest(session_id=session_id, message=repr(message)):
                with self.assertRaises(HTTPException) as denied:
                    await self.raise_alert(
                        "request.oracle.0001",
                        message,
                        token="invalid-provider-capability",
                        session_id=session_id,
                    )
                self.assertEqual(denied.exception.status_code, 403)

    async def test_websocket_subprotocol_auth_keeps_the_access_token_out_of_the_url(self) -> None:
        encoded = agent_server.base64.urlsafe_b64encode(
            b"server-token",
        ).decode("ascii").rstrip("=")
        socket = type("Socket", (), {
            "headers": {"sec-websocket-protocol": f"agentsdock-token.{encoded}"},
            "query_params": {},
        })()
        self.assertTrue(agent_server.websocket_authorized(socket))
        self.assertEqual(
            agent_server.websocket_token_subprotocol(socket),
            f"agentsdock-token.{encoded}",
        )
        socket.headers = {"sec-websocket-protocol": "agentsdock-token.invalid"}
        self.assertFalse(agent_server.websocket_authorized(socket))
        self.assertIsNone(agent_server.websocket_token_subprotocol(socket))

    async def test_emergency_websocket_selects_fixed_protocol_and_binds_snapshot_identity(self) -> None:
        encoded = agent_server.base64.urlsafe_b64encode(
            b"server-token",
        ).decode("ascii").rstrip("=")

        class Socket:
            headers = {
                "sec-websocket-protocol": (
                    f"{agent_server.EMERGENCY_WEBSOCKET_PROTOCOL}, "
                    f"agentsdock-token.{encoded}"
                ),
            }
            query_params = {}

            def __init__(self) -> None:
                self.accepted_protocol = None
                self.packet = None

            async def close(self, code: int) -> None:
                raise AssertionError(f"socket unexpectedly closed with {code}")

            async def accept(self, *, subprotocol: str) -> None:
                self.accepted_protocol = subprotocol

            async def send_json(self, packet: dict) -> None:
                self.packet = packet

            async def receive_text(self) -> str:
                raise agent_server.WebSocketDisconnect()

        socket = Socket()
        await agent_server.emergency_alert_events(socket)

        self.assertEqual(
            socket.accepted_protocol,
            agent_server.EMERGENCY_WEBSOCKET_PROTOCOL,
        )
        self.assertEqual(socket.packet["type"], "emergency_snapshot")
        self.assertEqual(socket.packet["server_identity"], agent_server.server_identity())
        self.assertEqual(socket.packet["sessions"], [])

    async def test_mark_read_never_acknowledges_an_emergency(self) -> None:
        raised = await self.raise_alert(
            "request.read.0001",
            "A human decision is urgently required.",
        )
        marked = await agent_server.mark_session_read(
            "source",
            agent_server.ReadSessionRequest(
                last_read_agent_event_seq=int(raised["event_seq"]),
            ),
        )

        self.assertFalse(marked["session"]["manual_unread"])
        self.assertEqual(marked["session"]["unacknowledged_emergency_count"], 1)
        self.assertEqual(
            marked["session"]["emergency_alert"]["id"],
            raised["alert"]["id"],
        )
        self.assertEqual(
            [event["type"] for event in self.event_records()],
            ["emergency_alert_raised"],
        )

    async def test_dedicated_stream_projection_keeps_explicit_clear_fields(self) -> None:
        ordinary_summary = agent_server.public_session(
            agent_server.STORE.sessions["source"],
            summary=True,
        )
        stream_summary = agent_server.public_emergency_session(
            agent_server.STORE.sessions["source"],
        )

        self.assertNotIn("emergency_alert", ordinary_summary)
        self.assertNotIn("unacknowledged_emergency_count", ordinary_summary)
        self.assertIsNone(stream_summary["emergency_alert"])
        self.assertEqual(stream_summary["unacknowledged_emergency_count"], 0)

    async def test_acknowledgement_is_exact_and_preserves_other_active_alerts(self) -> None:
        first = await self.raise_alert(
            "request.multi.0001",
            "Primary storage is corrupting new objects.",
        )
        second = await self.raise_alert(
            "request.multi.0002",
            "The failover path is also unavailable.",
        )
        self.assertNotEqual(first["alert"]["id"], second["alert"]["id"])
        self.assertEqual(second["unacknowledged_emergency_count"], 2)

        acknowledged_first = await agent_server.acknowledge_session_emergency(
            "source",
            agent_server.AcknowledgeEmergencyRequest(
                expected_alert_id=first["alert"]["id"],
            ),
        )
        self.assertTrue(acknowledged_first["acknowledged"])
        self.assertEqual(
            acknowledged_first["session"]["unacknowledged_emergency_count"],
            1,
        )
        self.assertEqual(
            acknowledged_first["session"]["emergency_alert"]["id"],
            second["alert"]["id"],
        )

        duplicate_ack = await agent_server.acknowledge_session_emergency(
            "source",
            agent_server.AcknowledgeEmergencyRequest(
                expected_alert_id=first["alert"]["id"],
            ),
        )
        self.assertFalse(duplicate_ack["acknowledged"])
        self.assertEqual(
            duplicate_ack["session"]["emergency_alert"]["id"],
            second["alert"]["id"],
        )

        with self.assertRaises(HTTPException) as wrong_id:
            await agent_server.acknowledge_session_emergency(
                "source",
                agent_server.AcknowledgeEmergencyRequest(
                    expected_alert_id="emergency_" + "0" * 32,
                ),
            )
        self.assertEqual(wrong_id.exception.status_code, 409)
        self.assertEqual(
            agent_server.public_session(agent_server.STORE.sessions["source"])[
                "unacknowledged_emergency_count"
            ],
            1,
        )

        acknowledged_second = await agent_server.acknowledge_session_emergency(
            "source",
            agent_server.AcknowledgeEmergencyRequest(
                expected_alert_id=second["alert"]["id"],
            ),
        )
        self.assertTrue(acknowledged_second["acknowledged"])
        self.assertEqual(
            acknowledged_second["session"]["unacknowledged_emergency_count"],
            0,
        )
        self.assertIsNone(acknowledged_second["session"]["emergency_alert"])
        self.assertEqual(
            [event["type"] for event in self.event_records()],
            [
                "emergency_alert_raised",
                "emergency_alert_raised",
                "emergency_alert_acknowledged",
                "emergency_alert_acknowledged",
            ],
        )

    async def test_internal_purpose_authority_cannot_raise_an_alert(self) -> None:
        for purpose in agent_server.EMERGENCY_AUTHORITY_DENIED_PURPOSES:
            with self.subTest(purpose=purpose):
                self.assertFalse(agent_server.provider_turn_may_raise_emergency(purpose))

        actions, _jobs_access = agent_server.native_steer_provider_actions(
            "source",
            {"purpose": "handoff_digest"},
        )
        self.assertNotIn("emergency", actions)

        _path, restricted_token = await self.issue_authority(
            "source",
            "run_active",
            actions={"publish"},
        )
        with self.assertRaises(HTTPException) as denied:
            await self.raise_alert(
                "request.internal.0001",
                "An internal delivery must not page the user.",
                token=restricted_token,
            )
        self.assertEqual(denied.exception.status_code, 403)
        self.assertFalse(self.event_records())

    async def test_restart_reconciles_raise_and_ack_from_durable_events(self) -> None:
        raised = await self.raise_alert(
            "request.restart.0001",
            "The server must remember this after restart.",
        )

        stale_without_alert = {
            "source": dict(self.base_source),
            "other": dict(self.other),
        }
        agent_server.SESSIONS_FILE.write_text(
            json.dumps(stale_without_alert),
            encoding="utf-8",
        )
        restored = agent_server.SessionStore()
        with patch.object(agent_server, "STORE", restored):
            await restored.load()
        summary = agent_server.public_session(restored.sessions["source"])
        self.assertEqual(summary["unacknowledged_emergency_count"], 1)
        self.assertEqual(summary["emergency_alert"]["id"], raised["alert"]["id"])

        await agent_server.acknowledge_session_emergency(
            "source",
            agent_server.AcknowledgeEmergencyRequest(
                expected_alert_id=raised["alert"]["id"],
            ),
        )
        await agent_server.append_durable_event_batch(
            "source",
            [
                ("reasoning_summary", {
                    "run_id": "run_active",
                    "text": f"post-ack restart event {index}",
                })
                for index in range(250)
            ],
        )
        stale_with_alert = dict(self.base_source)
        stale_with_alert["_emergency_alerts"] = [raised["alert"]]
        agent_server.SESSIONS_FILE.write_text(
            json.dumps({"source": stale_with_alert, "other": dict(self.other)}),
            encoding="utf-8",
        )
        restored_after_ack = agent_server.SessionStore()
        with patch.object(agent_server, "STORE", restored_after_ack):
            await restored_after_ack.load()
        acknowledged_summary = agent_server.public_session(
            restored_after_ack.sessions["source"]
        )
        self.assertEqual(acknowledged_summary["unacknowledged_emergency_count"], 0)
        self.assertIsNone(acknowledged_summary["emergency_alert"])

    async def test_ordinary_error_does_not_create_emergency_state(self) -> None:
        await agent_server.append_event(
            "source",
            "error",
            {"run_id": "run_active", "message": "ordinary provider failure"},
        )

        summary = agent_server.public_session(agent_server.STORE.sessions["source"])
        self.assertEqual(summary["unacknowledged_emergency_count"], 0)
        self.assertIsNone(summary["emergency_alert"])


if __name__ == "__main__":
    unittest.main()
