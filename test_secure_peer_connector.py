import asyncio
import json
import tempfile
import threading
import time
import unittest
import uuid
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

from fastapi import HTTPException

import agent_server
from agentsdock_team_hub.secure_peer import ProxyResponse, SecurePeerError
from secure_peer_delivery import SecurePeerDeliveryLedger
from secure_peer_runtime import SecurePeerRuntime


def uuid4_text() -> str:
    return str(uuid.uuid4())


class LedgerBackedPeerRuntime:
    """Mock only the remote wire while retaining the real owner ledger."""

    def __init__(self, root: Path) -> None:
        self.delivery_ledger = SecurePeerDeliveryLedger(root / "deliveries.sqlite3")
        self.validations: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.submissions: list[dict[str, Any]] = []
        self.source_route_active = True

    def remote_route_delivery_available(self) -> bool:
        return True

    def validate_remote_reference(
        self,
        source_session_id: str,
        reference: dict[str, Any],
        *,
        expected_snapshot: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        key = (
            source_session_id,
            str(reference.get("target_route_id") or ""),
            str(reference.get("action") or ""),
        )
        snapshot = self.validations.get(key)
        if snapshot is None or not self.source_route_active:
            raise SecurePeerError(
                "route_changed",
                "Secure peer route is unavailable or changed",
                409,
            )
        if expected_snapshot is not None and dict(expected_snapshot) != snapshot:
            raise SecurePeerError(
                "route_changed",
                "Secure peer route changed while the turn was queued",
                409,
            )
        return dict(snapshot)

    def submit_remote_handoff(
        self,
        snapshot: dict[str, Any],
        *,
        body: str,
        action: str,
        request_id: str,
        exchange_id: str | None = None,
        parent_envelope_id: str | None = None,
        expires_at: int | None = None,
        request_response: bool | None = None,
        expected_used_legs: int | None = None,
    ) -> dict[str, Any]:
        attempt = {
            "snapshot": dict(snapshot),
            "body": body,
            "action": action,
            "request_id": request_id,
            "exchange_id": exchange_id,
            "parent_envelope_id": parent_envelope_id,
            "expires_at": expires_at,
            "request_response": request_response,
            "expected_used_legs": expected_used_legs,
        }
        self.submissions.append(attempt)
        if not self.source_route_active:
            raise SecurePeerError(
                "route_changed",
                "Secure peer source route was revoked",
                409,
            )
        if parent_envelope_id is None:
            return {
                "envelope_id": request_id,
                "exchange_id": exchange_id or uuid4_text(),
                "status": "accepted",
                "used_legs": 1,
                "max_legs": 6,
                "expires_at": expires_at or int(time.time()) + 3600,
            }
        parent = self.delivery(parent_envelope_id)
        if parent is None:
            raise SecurePeerError("parent_missing", "Parent leg is unavailable", 410)
        used_legs = int(parent["used_legs"])
        if request_response and used_legs >= int(parent["max_legs"]) - 1:
            raise SecurePeerError(
                "budget_exhausted",
                "No leg remains after the requested follow-up",
                409,
            )
        return {
            "envelope_id": request_id,
            "exchange_id": exchange_id or str(parent["exchange_id"]),
            "status": "active" if request_response else "completed",
            "used_legs": used_legs + 1,
            "max_legs": int(parent["max_legs"]),
            "expires_at": expires_at or int(parent["expires_at"]),
        }

    def delivery(self, envelope_id: str) -> dict[str, Any] | None:
        return self.delivery_ledger.get(envelope_id)

    def delivery_for_run(self, run_id: str) -> dict[str, Any] | None:
        return self.delivery_ledger.for_run(run_id)

    def recoverable_deliveries(self) -> list[dict[str, Any]]:
        return self.delivery_ledger.recoverable()

    def recover_prepared_deliveries(self) -> list[dict[str, Any]]:
        return []

    def claim_deliveries_once(self, *, limit: int = 20) -> list[dict[str, Any]]:
        del limit
        return []

    def prepare_outbound_handoff(self, **kwargs: Any) -> tuple[dict[str, Any], bool]:
        return self.delivery_ledger.prepare_outbound(**kwargs)

    def commit_outbound_handoff(
        self, request_id: str, response: dict[str, Any]
    ) -> dict[str, Any] | None:
        return self.delivery_ledger.commit_outbound(request_id, response)

    def defer_outbound_handoff(
        self, request_id: str, *, error: str
    ) -> dict[str, Any] | None:
        return self.delivery_ledger.defer_outbound(request_id, error)

    def fail_outbound_handoff(
        self, request_id: str, *, error: str
    ) -> dict[str, Any] | None:
        return self.delivery_ledger.fail_outbound(request_id, error)

    def pending_outbound_handoffs(self, *, limit: int = 8) -> list[dict[str, Any]]:
        return self.delivery_ledger.pending_outbound(limit=limit)

    def recoverable_outbound_handoffs(
        self,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        return self.delivery_ledger.recoverable_outbound(limit=limit)

    def retire_agent_routes_locally(self) -> int:
        return 0

    def bind_delivery_owner(
        self,
        envelope_id: str,
        *,
        queued_id: str | None,
        run_id: str | None,
    ) -> dict[str, Any] | None:
        return self.delivery_ledger.bind_owner(
            envelope_id,
            queued_id=queued_id,
            run_id=run_id,
        )

    def prepare_delivery_response(
        self,
        envelope_id: str,
        *,
        request_id: str,
        body: str,
        request_response: bool,
    ) -> dict[str, Any] | None:
        return self.delivery_ledger.prepare_response(
            envelope_id,
            request_id=request_id,
            body=body,
            request_response=request_response,
        )

    def mark_delivery_response(
        self,
        envelope_id: str,
        *,
        request_id: str | None = None,
    ) -> dict[str, Any] | None:
        return self.delivery_ledger.mark_response_committed(
            envelope_id,
            request_id=request_id,
        )

    def clear_delivery_response(
        self,
        envelope_id: str,
        *,
        request_id: str,
    ) -> dict[str, Any] | None:
        return self.delivery_ledger.clear_response_intent(
            envelope_id,
            request_id=request_id,
        )

    def defer_delivery_response(
        self,
        envelope_id: str,
        *,
        request_id: str,
        error: str,
    ) -> dict[str, Any] | None:
        return self.delivery_ledger.defer_response(
            envelope_id,
            request_id=request_id,
            error=error,
        )

    def pending_delivery_responses(
        self,
        *,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        return self.delivery_ledger.pending_responses(limit=limit)

    def finish_delivery(
        self,
        envelope_id: str,
        *,
        succeeded: bool,
        result_text: str = "",
        error: str | None = None,
    ) -> dict[str, Any] | None:
        return self.delivery_ledger.finish(
            envelope_id,
            succeeded=succeeded,
            result_text=result_text,
            error=error,
        )


class SecurePeerConnectorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.original = {
            "runtime": agent_server.SECURE_PEER_RUNTIME,
            "cross_chat": agent_server.CROSS_CHAT,
            "authority_root": agent_server.CROSS_CHAT_AUTHORITY_ROOT,
            "sessions": agent_server.STORE.sessions,
            "current_turns": agent_server.CURRENT_TURNS,
            "queued_turns": agent_server.QUEUED_TURNS,
            "run_now_turns": agent_server.RUN_NOW_TURNS,
            "queue_start_tasks": agent_server.QUEUE_START_TASKS,
            "active": agent_server.ACTIVE,
            "lifecycle_locks": agent_server.SESSION_LIFECYCLE_LOCKS,
            "event_cache": agent_server.CROSS_CHAT_EVENT_TYPE_CACHE,
            "agent_token": agent_server.AGENT_TOKEN,
            "agent_relay_enabled": agent_server.SECURE_PEER_AGENT_RELAY_ENABLED,
            "busy": set(agent_server.BUSY_SESSIONS),
            "stopped": set(agent_server.STOPPED_RUNS),
            "deleting": set(agent_server.DELETING_SESSIONS),
            "deleted": set(agent_server.DELETED_SESSION_TOMBSTONES),
        }
        self.runtime = LedgerBackedPeerRuntime(self.root / "runtime")
        agent_server.SECURE_PEER_RUNTIME = self.runtime
        agent_server.AGENT_TOKEN = "test-admin-token"
        # This suite exercises the retired relay protocol in isolation. The
        # production server hard-disables it and has separate boundary tests.
        agent_server.SECURE_PEER_AGENT_RELAY_ENABLED = True
        agent_server.CROSS_CHAT = agent_server.CrossChatStore(
            self.root / "cross-chat.sqlite3"
        )
        await agent_server.CROSS_CHAT.initialize()
        agent_server.CROSS_CHAT_AUTHORITY_ROOT = self.root / "authority"
        agent_server.STORE.sessions = {
            "source": {
                "id": "source",
                "title": "Source",
                "folder": "/source-private",
                "backend": "codex",
            },
            "target": {
                "id": "target",
                "title": "Target",
                "folder": "/target-private",
                "backend": "codex",
            },
        }
        agent_server.CURRENT_TURNS = {}
        agent_server.QUEUED_TURNS = {}
        agent_server.RUN_NOW_TURNS = {}
        agent_server.QUEUE_START_TASKS = {}
        agent_server.ACTIVE = {}
        agent_server.SESSION_LIFECYCLE_LOCKS = {}
        agent_server.CROSS_CHAT_EVENT_TYPE_CACHE = OrderedDict()
        agent_server.BUSY_SESSIONS.clear()
        agent_server.STOPPED_RUNS.clear()
        agent_server.DELETING_SESSIONS.clear()
        agent_server.DELETED_SESSION_TOMBSTONES.clear()
        agent_server.CROSS_CHAT_CAPABILITIES.clear()

        self.connection_id = uuid4_text()
        self.team_id = uuid4_text()
        self.source_route_id = uuid4_text()
        self.target_route_id = uuid4_text()
        self.source_revision = "rev_" + "a" * 32
        self.target_revision = "rev_" + "b" * 32
        self.local_identity = "local_server_identity"
        self.remote_identity = "remote_server_identity"

    async def asyncTearDown(self) -> None:
        agent_server.CROSS_CHAT_CAPABILITIES.clear()
        agent_server.SECURE_PEER_RUNTIME = self.original["runtime"]
        agent_server.CROSS_CHAT = self.original["cross_chat"]
        agent_server.CROSS_CHAT_AUTHORITY_ROOT = self.original["authority_root"]
        agent_server.STORE.sessions = self.original["sessions"]
        agent_server.CURRENT_TURNS = self.original["current_turns"]
        agent_server.QUEUED_TURNS = self.original["queued_turns"]
        agent_server.RUN_NOW_TURNS = self.original["run_now_turns"]
        agent_server.QUEUE_START_TASKS = self.original["queue_start_tasks"]
        agent_server.ACTIVE = self.original["active"]
        agent_server.SESSION_LIFECYCLE_LOCKS = self.original["lifecycle_locks"]
        agent_server.CROSS_CHAT_EVENT_TYPE_CACHE = self.original["event_cache"]
        agent_server.AGENT_TOKEN = self.original["agent_token"]
        agent_server.SECURE_PEER_AGENT_RELAY_ENABLED = self.original[
            "agent_relay_enabled"
        ]
        agent_server.BUSY_SESSIONS.clear()
        agent_server.BUSY_SESSIONS.update(self.original["busy"])
        agent_server.STOPPED_RUNS.clear()
        agent_server.STOPPED_RUNS.update(self.original["stopped"])
        agent_server.DELETING_SESSIONS.clear()
        agent_server.DELETING_SESSIONS.update(self.original["deleting"])
        agent_server.DELETED_SESSION_TOMBSTONES.clear()
        agent_server.DELETED_SESSION_TOMBSTONES.update(self.original["deleted"])
        self.temporary.cleanup()

    def native_transport(self):
        return patch.object(
            agent_server,
            "CODEX_TRANSPORT",
            agent_server.CODEX_TRANSPORT_APP_SERVER,
        )

    async def test_local_secure_proxy_forces_private_cache_policy(self) -> None:
        runtime = Mock()
        runtime.proxy.return_value = ProxyResponse(
            200,
            (
                ("content-type", "application/json"),
                ("cache-control", "public, max-age=86400"),
                ("etag", '"peer-value"'),
            ),
            b'{"ok":true}',
        )
        request = Mock()
        request.method = "GET"
        request.scope = {"headers": []}
        request.headers = {}
        request.url.query = ""
        agent_server.SECURE_PEER_RUNTIME = runtime
        try:
            with patch.object(agent_server, "require_secure_peer_control"):
                response = await agent_server.secure_peer_hub_proxy_endpoint(
                    self.connection_id,
                    "v1/health",
                    request,
                )
        finally:
            agent_server.SECURE_PEER_RUNTIME = self.runtime

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b'{"ok":true}')
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["pragma"], "no-cache")
        self.assertEqual(response.headers["etag"], '"peer-value"')
        self.assertEqual(
            sum(
                1
                for name, _value in response.raw_headers
                if name.lower() == b"cache-control"
            ),
            1,
        )

    async def test_local_secure_proxy_forwards_delete_json_without_core_credentials(self) -> None:
        runtime = Mock()
        runtime.proxy.return_value = ProxyResponse(
            200,
            (("content-type", "application/json"),),
            b'{"deleted":true,"message_id":"tmsg_gateway_delete_001"}',
        )
        payload = b'{"idempotency_key":"local-gateway-delete-001"}'
        request = Mock()
        request.method = "DELETE"
        request.scope = {
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
                (b"x-agentsdock-token", b"local-secret"),
            ]
        }
        request.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer must-not-cross",
            "X-AgentsDock-Token": "local-secret",
        }
        request.url.query = ""
        request.url.path = (
            f"/api/team-hub-secure/{self.connection_id}/v1/teams/{self.team_id}/"
            "network/messages/tmsg_gateway_delete_001"
        )
        request.body = AsyncMock(return_value=payload)
        agent_server.SECURE_PEER_RUNTIME = runtime
        try:
            with patch.object(agent_server, "require_secure_peer_control"):
                response = await agent_server.secure_peer_hub_proxy_endpoint(
                    self.connection_id,
                    f"v1/teams/{self.team_id}/network/messages/tmsg_gateway_delete_001",
                    request,
                )
        finally:
            agent_server.SECURE_PEER_RUNTIME = self.runtime

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.body,
            b'{"deleted":true,"message_id":"tmsg_gateway_delete_001"}',
        )
        self.assertEqual(response.headers["cache-control"], "no-store")
        runtime.proxy.assert_called_once_with(
            self.connection_id,
            "DELETE",
            f"/v1/teams/{self.team_id}/network/messages/tmsg_gateway_delete_001",
            query="",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body=payload,
        )

    def snapshot(
        self,
        *,
        source_chat_id: str = "source",
        action: str = "instruction",
    ) -> dict[str, Any]:
        return {
            "version": 1,
            "role": "client",
            "connection_id": self.connection_id,
            "team_id": self.team_id,
            "hub_id": uuid4_text(),
            "source_server_identity": self.local_identity,
            "source_chat_id": source_chat_id,
            "source_route_id": self.source_route_id,
            "source_route_revision": self.source_revision,
            "target_server_identity": self.remote_identity,
            "target_route_id": self.target_route_id,
            "target_route_revision": self.target_revision,
            "action": action,
        }

    def response_snapshot(self, *, target_chat_id: str = "target") -> dict[str, Any]:
        return {
            "version": 1,
            "role": "client",
            "connection_id": self.connection_id,
            "team_id": self.team_id,
            "hub_id": uuid4_text(),
            "source_server_identity": self.local_identity,
            "source_chat_id": target_chat_id,
            "source_route_id": self.target_route_id,
            "source_route_revision": self.target_revision,
            "target_server_identity": self.remote_identity,
            "target_route_id": self.source_route_id,
            "target_route_revision": self.source_revision,
            "action": "request_reply",
        }

    def envelope(
        self,
        *,
        envelope_id: str | None = None,
        kind: str = "request_reply",
        used_legs: int = 1,
        body: str = "Please investigate",
        expires_at: int | None = None,
    ) -> dict[str, Any]:
        return {
            "envelope_id": envelope_id or uuid4_text(),
            "request_id": uuid4_text(),
            "team_id": self.team_id,
            "source_peer_id": uuid4_text(),
            "source_server_identity": self.remote_identity,
            "source_route_id": self.source_route_id,
            "source_route_revision": self.source_revision,
            "target_peer_id": None,
            "target_server_identity": self.local_identity,
            "target_route_id": self.target_route_id,
            "target_route_revision": self.target_revision,
            "action": "instruction" if kind == "instruction" else "request_reply",
            "kind": kind,
            "exchange_id": uuid4_text(),
            "parent_envelope_id": None,
            "parent_leg": None,
            "used_legs": used_legs,
            "max_legs": 6,
            "expires_at": expires_at or int(time.time()) + 3600,
            "body": {"message": body},
        }

    def prepare_running(
        self,
        *,
        kind: str = "request_reply",
        used_legs: int = 1,
        expires_at: int | None = None,
        run_id: str = "run_target",
    ) -> dict[str, Any]:
        envelope = self.envelope(
            kind=kind,
            used_legs=used_legs,
            expires_at=expires_at,
        )
        record, created = self.runtime.delivery_ledger.prepare(
            envelope,
            transport_role="client",
            connection_id=self.connection_id,
            lease_token="lease-token",
            target_chat_id="target",
        )
        self.assertTrue(created)
        record = self.runtime.delivery_ledger.authorize(envelope["envelope_id"])
        self.assertIsNotNone(record)
        record = self.runtime.bind_delivery_owner(
            envelope["envelope_id"],
            queued_id=None,
            run_id=run_id,
        )
        self.assertIsNotNone(record)
        return record

    async def issue_secure_send(
        self,
        run_id: str,
        snapshot: dict[str, Any],
    ) -> str:
        agent_server.CURRENT_TURNS["source"] = {"run_id": run_id}
        authority = await agent_server.issue_cross_chat_capability(
            "source",
            run_id,
            [],
            actions={
                "secure_peer_request_reply"
                if snapshot["action"] == "request_reply"
                else "secure_peer_instruction"
            },
            secure_peer_route_snapshots=[snapshot],
        )
        self.assertIsNotNone(authority)
        return json.loads(authority.read_text())["provider_capability"]

    async def issue_secure_response(
        self,
        record: dict[str, Any],
        snapshot: dict[str, Any],
        *,
        run_id: str = "run_target",
    ) -> str:
        agent_server.CURRENT_TURNS["target"] = {"run_id": run_id}
        grant = (str(record["exchange_id"]), str(record["envelope_id"]))
        authority = await agent_server.issue_cross_chat_capability(
            "target",
            run_id,
            [],
            actions={"secure_peer_response"},
            secure_peer_response_grants={
                grant: {**snapshot, "expires_at": int(record["expires_at"])}
            },
        )
        self.assertIsNotNone(authority)
        return json.loads(authority.read_text())["provider_capability"]

    async def test_local_and_secure_destination_namespace_collision_is_rejected(self) -> None:
        # A renderer must not be able to make a local chat ID and an opaque
        # remote route ID share a capability key.
        agent_server.STORE.sessions[self.target_route_id] = {
            "id": self.target_route_id,
            "title": "Local",
            "backend": "codex",
        }
        snapshot = self.snapshot(action="instruction")
        self.runtime.validations[
            ("source", self.target_route_id, "instruction")
        ] = snapshot
        references = [
            agent_server.ChatReference(
                session_id=self.target_route_id,
                display_title_snapshot="Local",
                source_text_start=0,
                source_text_end=6,
                action="instruction",
            ),
            agent_server.ChatReference(
                session_id=self.target_route_id,
                display_title_snapshot="Remote",
                source_text_start=7,
                source_text_end=14,
                action="instruction",
                target_kind="secure_peer",
                target_server_identity=self.remote_identity,
                target_connection_id=self.connection_id,
                target_route_id=self.target_route_id,
                target_route_revision=self.target_revision,
            ),
        ]
        with self.native_transport(), self.assertRaises(HTTPException) as raised:
            agent_server.validate_chat_references(
                "source",
                "@Local @Remote",
                references,
                [],
            )
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("ambiguous", str(raised.exception.detail))

    async def test_provider_idempotency_key_is_namespaced_by_exact_route(self) -> None:
        raw = "provider-may-reuse-this-key"
        first = agent_server.secure_peer_request_uuid(
            raw,
            namespace="initial\0server-a\0route-a\0server-b\0route-b",
        )
        repeated = agent_server.secure_peer_request_uuid(
            raw,
            namespace="initial\0server-a\0route-a\0server-b\0route-b",
        )
        second_route = agent_server.secure_peer_request_uuid(
            raw,
            namespace="initial\0server-a\0route-c\0server-b\0route-b",
        )
        self.assertEqual(first, repeated)
        self.assertNotEqual(first, second_route)
        self.assertEqual(uuid.UUID(first).version, 4)

    async def test_secure_source_grant_is_one_use_and_revoke_before_submit_fails(self) -> None:
        snapshot = self.snapshot(action="instruction")
        token = await self.issue_secure_send("run_source", snapshot)
        request = agent_server.CrossChatHandoffRequest(
            target_session_id=self.target_route_id,
            action="instruction",
            body="Do the check",
            idempotency_key="stable-send-key",
        )
        first, created = await agent_server.create_authorized_cross_chat_instruction(
            token,
            request,
        )
        replay, replay_created = (
            await agent_server.create_authorized_cross_chat_instruction(token, request)
        )
        self.assertTrue(first["_secure_peer"])
        self.assertTrue(created)
        self.assertFalse(replay_created)
        self.assertEqual(first["envelope_id"], replay["envelope_id"])
        self.assertEqual(len(self.runtime.submissions), 1)
        with self.assertRaises(HTTPException) as reused:
            await agent_server.create_authorized_cross_chat_instruction(
                token,
                request.model_copy(update={
                    "body": "Different payload",
                    "idempotency_key": "different-send-key",
                }),
            )
        self.assertEqual(reused.exception.status_code, 403)

        revoked_snapshot = self.snapshot(action="instruction")
        revoked_token = await self.issue_secure_send("run_revoked", revoked_snapshot)
        self.runtime.source_route_active = False
        with self.assertRaises(HTTPException) as revoked:
            await agent_server.create_authorized_cross_chat_instruction(
                revoked_token,
                request.model_copy(update={"idempotency_key": "revoked-send-key"}),
            )
        self.assertEqual(revoked.exception.status_code, 409)
        self.assertIn("revoked", str(revoked.exception.detail))

    async def test_prepared_receipt_queue_and_start_crash_recovery_is_single_owner(self) -> None:
        # Use the real runtime recovery method for the ambiguous
        # prepare->remote-receipt boundary, then the real AgentServer queue
        # admission and durable ledger owner transitions.
        actual = SecurePeerRuntime(
            self.root / "actual-runtime",
            server_identity=self.local_identity,
            server_instance_id="test-instance",
            display_name="Test server",
        )
        agent_server.SECURE_PEER_RUNTIME = actual
        actual.set_delivery_target_validator(
            agent_server.secure_peer_delivery_target_available
        )
        envelope = self.envelope()
        record, created = actual.delivery_ledger.prepare(
            envelope,
            transport_role="client",
            connection_id=self.connection_id,
            lease_token="lease-token",
            target_chat_id="target",
        )
        self.assertTrue(created)
        self.assertEqual(record["state"], "prepared")
        receipts: list[str] = []

        def ambiguous_receipt(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            receipts.append("committed-before-crash")
            raise RuntimeError("connection dropped after receipt commit")

        try:
            recovered = actual.recover_prepared_deliveries()
            self.assertEqual(
                [item["envelope_id"] for item in recovered],
                [envelope["envelope_id"]],
            )
            with patch.object(actual, "_receipt_claim", side_effect=ambiguous_receipt):
                with self.assertRaises(RuntimeError):
                    actual.accept_prepared_delivery(envelope["envelope_id"])
            self.assertEqual(actual.delivery(envelope["envelope_id"])["state"], "prepared")
            with patch.object(
                actual,
                "_receipt_claim",
                side_effect=lambda *_args, **_kwargs: receipts.append("idempotent-retry") or {},
            ):
                accepted = actual.accept_prepared_delivery(envelope["envelope_id"])
            self.assertIsNotNone(accepted)
            ready = [accepted]
            self.assertEqual(actual.delivery(envelope["envelope_id"])["state"], "authorized")

            agent_server.BUSY_SESSIONS.add("target")
            with (
                self.native_transport(),
                patch.object(
                    agent_server,
                    "append_durable_event",
                    AsyncMock(return_value={"type": "turn_queued", "seq": 1}),
                ),
            ):
                queued = await agent_server.submit_secure_peer_delivery(ready[0])
            self.assertEqual(queued["state"], "queued")
            queued_id = str(queued["queued_id"])
            self.assertEqual(len(agent_server.QUEUED_TURNS["target"]), 1)

            # Crash after turn_started became durable but before the queue->run
            # owner CAS. Recovery binds that exact run, terminalizes it, and
            # never launches a replacement with possibly duplicated effects.
            agent_server.QUEUED_TURNS.clear()
            agent_server.BUSY_SESSIONS.clear()
            started_event = {
                "type": "turn_started",
                "run_id": "run_crashed_after_start",
                "queued_id": queued_id,
                "secure_peer_envelope_id": envelope["envelope_id"],
                "purpose": "secure_peer_handoff_delivery",
            }
            with (
                patch.object(
                    agent_server,
                    "secure_peer_delivery_history",
                    return_value=[started_event],
                ),
                patch.object(
                    agent_server,
                    "submit_secure_peer_delivery",
                    AsyncMock(),
                ) as duplicate_submit,
            ):
                recovered = await agent_server.reconcile_secure_peer_deliveries()
            self.assertEqual(recovered, 1)
            duplicate_submit.assert_not_awaited()
            terminal = actual.delivery(envelope["envelope_id"])
            self.assertEqual(terminal["state"], "failed")
            self.assertEqual(terminal["run_id"], "run_crashed_after_start")
            self.assertIn("interrupted", terminal["error"])
            self.assertEqual(receipts, ["committed-before-crash", "idempotent-retry"])
        finally:
            actual.shutdown()

    async def test_response_requires_the_exact_reverse_route_revisions(self) -> None:
        record = self.prepare_running()
        exact = self.response_snapshot()
        key = ("target", self.source_route_id, "request_reply")
        self.runtime.validations[key] = exact
        self.assertEqual(
            agent_server.secure_peer_response_snapshot_for_delivery("target", record),
            exact,
        )

        self.runtime.validations[key] = {
            **exact,
            "target_route_revision": "rev_" + "c" * 32,
        }
        with self.assertRaises(SecurePeerError) as changed:
            agent_server.secure_peer_response_snapshot_for_delivery("target", record)
        self.assertEqual(changed.exception.code, "route_changed")

    async def test_explicit_terminal_reply_completes_after_two_of_six_legs(self) -> None:
        record = self.prepare_running(used_legs=1)
        response_snapshot = self.response_snapshot()
        token = await self.issue_secure_response(record, response_snapshot)
        exchange, leg, created = (
            await agent_server.create_authorized_cross_chat_exchange_response(
                token,
                str(record["exchange_id"]),
                agent_server.CrossChatExchangeResponseRequest(
                    inbound_leg_id=str(record["envelope_id"]),
                    body="Done",
                    request_response=False,
                    idempotency_key="explicit-response-key",
                ),
            )
        )
        self.assertTrue(created)
        self.assertTrue(exchange["_secure_peer"])
        self.assertEqual(exchange["status"], "completed")
        self.assertEqual(leg["used_legs"], 2)
        self.assertEqual(leg["max_legs"], 6)
        self.assertFalse(self.runtime.submissions[-1]["request_response"])
        self.assertEqual(
            self.runtime.delivery(str(record["envelope_id"]))["response_committed"],
            1,
        )

        # Terminal bookkeeping closes the local owner; it does not require or
        # synthesize four more legs merely because the maximum is six.
        before = len(self.runtime.submissions)
        await agent_server.finalize_secure_peer_delivery_run({
            "type": "turn_finished",
            "run_id": "run_target",
            "secure_peer_envelope_id": record["envelope_id"],
            "result_text": "Done",
            "exit_code": 0,
        })
        closed = self.runtime.delivery(str(record["envelope_id"]))
        self.assertEqual(closed["state"], "completed")
        self.assertEqual(len(self.runtime.submissions), before)

    async def test_explicit_async_followup_preserves_secure_peer_multi_leg_exchange(self) -> None:
        record = self.prepare_running(used_legs=1)
        self.assertIn(
            "--request-response --async-response",
            agent_server.secure_peer_delivery_prompt(record),
        )
        token = await self.issue_secure_response(record, self.response_snapshot())
        authority_copy = agent_server.cross_chat_provider_authority_block(
            [],
            self.root / "secure-response-authority.json",
            "target",
            {"secure_peer_response"},
            exchange_response_grant=(
                str(record["exchange_id"]),
                str(record["envelope_id"]),
            ),
            exchange_response_followup_allowed=True,
        )
        self.assertIn(
            "`--request-response --async-response`",
            authority_copy,
        )
        request = Mock(headers={
            "x-agentsdock-provider-capability": token,
        })
        receipt = await agent_server.submit_authorized_cross_chat_exchange_response(
            str(record["exchange_id"]),
            agent_server.CrossChatExchangeResponseRequest(
                inbound_leg_id=str(record["envelope_id"]),
                body="Question back to the peer",
                request_response=True,
                idempotency_key="secure-async-followup",
            ),
            request,
        )
        self.assertEqual(
            receipt,
            {"ok": True, "action": "response", "accepted": True},
        )
        self.assertTrue(self.runtime.submissions[-1]["request_response"])
        self.assertEqual(self.runtime.submissions[-1]["expected_used_legs"], 2)

    async def test_automatic_terminal_reply_is_early_and_closes_ledger(self) -> None:
        record = self.prepare_running(used_legs=1)
        exact = self.response_snapshot()
        self.runtime.validations[
            ("target", self.source_route_id, "request_reply")
        ] = exact
        await agent_server.finalize_secure_peer_delivery_run({
            "type": "turn_finished",
            "run_id": "run_target",
            "secure_peer_envelope_id": record["envelope_id"],
            "result_text": "Automatic answer",
            "exit_code": 0,
        })
        self.assertEqual(len(self.runtime.submissions), 1)
        submission = self.runtime.submissions[0]
        self.assertEqual(submission["parent_envelope_id"], record["envelope_id"])
        self.assertFalse(submission["request_response"])
        closed = self.runtime.delivery(str(record["envelope_id"]))
        self.assertEqual(closed["state"], "completed")
        self.assertEqual(closed["response_committed"], 1)

    async def test_incoming_terminal_response_does_not_create_a_response_to_response(
        self,
    ) -> None:
        record = self.prepare_running(kind="response", used_legs=2)
        await agent_server.finalize_secure_peer_delivery_run({
            "type": "turn_finished",
            "run_id": "run_target",
            "secure_peer_envelope_id": record["envelope_id"],
            "result_text": "Response received successfully",
            "exit_code": 0,
        })

        closed = self.runtime.delivery(str(record["envelope_id"]))
        self.assertEqual(closed["state"], "completed")
        self.assertEqual(self.runtime.submissions, [])

    async def test_exact_secure_send_retry_freezes_expiry_in_idempotency_digest(
        self,
    ) -> None:
        snapshot = self.snapshot(action="instruction")
        token = await self.issue_secure_send("run_expiry_retry", snapshot)
        request = agent_server.CrossChatHandoffRequest(
            target_session_id=self.target_route_id,
            action="instruction",
            body="Deliver exactly once",
            idempotency_key="expiry-retry-key",
        )

        with patch.object(agent_server.time, "time", return_value=1_000_000):
            first, first_created = (
                await agent_server.create_authorized_cross_chat_instruction(
                    token,
                    request,
                )
            )
        with patch.object(agent_server.time, "time", return_value=1_000_001):
            replay, replay_created = (
                await agent_server.create_authorized_cross_chat_instruction(
                    token,
                    request,
                )
            )

        self.assertTrue(first_created)
        self.assertFalse(replay_created)
        self.assertEqual(first["envelope_id"], replay["envelope_id"])
        self.assertEqual(first["expires_at"], replay["expires_at"])

    async def test_corrected_send_after_definite_rejection_gets_fresh_expiry(
        self,
    ) -> None:
        snapshot = self.snapshot(action="instruction")
        token = await self.issue_secure_send("run_expiry_reopen", snapshot)
        original_prepare = self.runtime.prepare_outbound_handoff
        attempts = 0

        def reject_once(**kwargs: Any):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise SecurePeerError(
                    "route_changed",
                    "Correct the stale route",
                    409,
                )
            return original_prepare(**kwargs)

        first_request = agent_server.CrossChatHandoffRequest(
            target_session_id=self.target_route_id,
            action="instruction",
            body="First shape",
            idempotency_key="expiry-rejected-key",
        )
        with patch.object(
            self.runtime,
            "prepare_outbound_handoff",
            side_effect=reject_once,
        ), patch.object(agent_server.time, "time", return_value=1_000_000):
            with self.assertRaises(HTTPException) as rejected:
                await agent_server.create_authorized_cross_chat_instruction(
                    token,
                    first_request,
                )
        self.assertEqual(rejected.exception.status_code, 409)

        corrected = first_request.model_copy(update={
            "body": "Corrected shape",
            "idempotency_key": "expiry-corrected-key",
        })
        with patch.object(
            self.runtime,
            "prepare_outbound_handoff",
            side_effect=reject_once,
        ), patch.object(agent_server.time, "time", return_value=1_000_100):
            accepted, created = (
                await agent_server.create_authorized_cross_chat_instruction(
                    token,
                    corrected,
                )
            )

        self.assertTrue(created)
        self.assertEqual(accepted["expires_at"], 1_000_100 + (72 * 60 * 60))

    async def test_live_response_intent_does_not_block_newer_same_peer_work(self) -> None:
        base = int(time.time())
        with patch("secure_peer_delivery.time.time", return_value=base - 30):
            live = self.prepare_running(run_id="run_live")
            self.runtime.prepare_delivery_response(
                str(live["envelope_id"]),
                request_id=uuid4_text(),
                body="Still being composed",
                request_response=False,
            )
        with patch("secure_peer_delivery.time.time", return_value=base - 20):
            terminal = self.prepare_running(run_id="run_terminal")
            self.runtime.prepare_delivery_response(
                str(terminal["envelope_id"]),
                request_id=uuid4_text(),
                body="Terminal answer",
                request_response=False,
            )
        outbound_request_id = uuid4_text()
        with patch("secure_peer_delivery.time.time", return_value=base - 10):
            self.runtime.prepare_outbound_handoff(
                request_id=outbound_request_id,
                source_session_id="source",
                source_run_id="run_source",
                snapshot=self.snapshot(action="instruction"),
                body="New outbound work",
                action="instruction",
                expires_at=base + 3600,
            )

        self.runtime.validations[
            ("target", self.source_route_id, "request_reply")
        ] = self.response_snapshot()

        def history(_session_id: str, envelope_id: str) -> list[dict[str, Any]]:
            if envelope_id != terminal["envelope_id"]:
                return []
            return [{
                "type": "turn_finished",
                "run_id": "run_terminal",
                "secure_peer_envelope_id": terminal["envelope_id"],
                "result_text": "Terminal answer",
                "exit_code": 0,
            }]

        with patch.object(
            agent_server,
            "secure_peer_delivery_history",
            side_effect=history,
        ):
            self.assertEqual(
                await agent_server.reconcile_secure_peer_response_outbox(),
                1,
            )
            self.assertEqual(
                self.runtime.delivery(str(terminal["envelope_id"]))["state"],
                "completed",
            )
            self.assertEqual(
                self.runtime.delivery(str(live["envelope_id"]))["state"],
                "running",
            )
            self.assertEqual(
                await agent_server.reconcile_secure_peer_response_outbox(),
                1,
            )

        outbound = self.runtime.delivery_ledger.outbound(outbound_request_id)
        self.assertIsNotNone(outbound)
        self.assertEqual(outbound["state"], "committed")
        self.assertEqual(len(self.runtime.submissions), 2)
        self.assertEqual(
            self.runtime.submissions[0]["parent_envelope_id"],
            terminal["envelope_id"],
        )
        self.assertIsNone(self.runtime.submissions[1]["parent_envelope_id"])

    async def test_sixteen_live_response_intents_do_not_hide_terminal_seventeenth(self) -> None:
        base = int(time.time())
        live: list[dict[str, Any]] = []
        with patch("secure_peer_delivery.time.time", return_value=base - 20):
            for index in range(16):
                record = self.prepare_running(run_id=f"run_live_response_{index}")
                self.runtime.prepare_delivery_response(
                    str(record["envelope_id"]),
                    request_id=uuid4_text(),
                    body=f"Live response {index}",
                    request_response=False,
                )
                live.append(record)
        with patch("secure_peer_delivery.time.time", return_value=base - 10):
            terminal = self.prepare_running(run_id="run_terminal_response_17")
            self.runtime.prepare_delivery_response(
                str(terminal["envelope_id"]),
                request_id=uuid4_text(),
                body="Terminal response",
                request_response=False,
            )
        self.runtime.validations[
            ("target", self.source_route_id, "request_reply")
        ] = self.response_snapshot()
        terminal_event = {
            "type": "turn_finished",
            "run_id": "run_terminal_response_17",
            "secure_peer_envelope_id": terminal["envelope_id"],
            "result_text": "Terminal response",
            "exit_code": 0,
        }

        def history(_session_id: str, envelope_id: str) -> list[dict[str, Any]]:
            return [terminal_event] if envelope_id == terminal["envelope_id"] else []

        with patch.object(
            agent_server,
            "secure_peer_delivery_history",
            side_effect=history,
        ):
            self.assertEqual(
                await agent_server.reconcile_secure_peer_response_outbox(),
                1,
            )
        self.assertEqual(
            self.runtime.delivery(str(terminal["envelope_id"]))["state"],
            "completed",
        )
        self.assertTrue(all(
            self.runtime.delivery(str(record["envelope_id"]))["state"] == "running"
            for record in live
        ))

    async def test_live_response_intent_is_terminalized_when_exchange_expires(self) -> None:
        base = int(time.time())
        record = self.prepare_running(
            expires_at=base - 1,
            run_id="run_expired_live",
        )
        self.runtime.prepare_delivery_response(
            str(record["envelope_id"]),
            request_id=uuid4_text(),
            body="Too late",
            request_response=False,
        )
        with patch.object(
            agent_server,
            "secure_peer_delivery_history",
            return_value=[],
        ):
            self.assertEqual(
                await agent_server.reconcile_secure_peer_response_outbox(),
                1,
            )
        closed = self.runtime.delivery(str(record["envelope_id"]))
        self.assertEqual(closed["state"], "failed")
        self.assertIn("expired", str(closed["error"]))
        self.assertEqual(self.runtime.submissions, [])

    async def test_expired_offline_response_terminalizes_and_unblocks_retirement(self) -> None:
        record = self.prepare_running(
            used_legs=1,
            expires_at=int(time.time()) - 1,
        )
        await agent_server.finalize_secure_peer_delivery_run({
            "type": "turn_finished",
            "run_id": "run_target",
            "secure_peer_envelope_id": record["envelope_id"],
            "result_text": "Too late",
            "exit_code": 0,
        })
        closed = self.runtime.delivery(str(record["envelope_id"]))
        self.assertEqual(closed["state"], "failed")
        self.assertIn("expired", str(closed["error"]))
        self.assertEqual(
            self.runtime.delivery_ledger.nonterminal_for_chat("target"),
            [],
        )

    async def test_committed_response_remains_successful_when_recovered_after_expiry(self) -> None:
        record = self.prepare_running(
            used_legs=1,
            expires_at=int(time.time()) - 1,
        )
        request_id = uuid4_text()
        self.runtime.prepare_delivery_response(
            str(record["envelope_id"]),
            request_id=request_id,
            body="Already delivered",
            request_response=False,
        )
        self.runtime.mark_delivery_response(
            str(record["envelope_id"]),
            request_id=request_id,
        )
        await agent_server.finalize_secure_peer_delivery_run({
            "type": "turn_finished",
            "run_id": "run_target",
            "secure_peer_envelope_id": record["envelope_id"],
            "result_text": "Already delivered",
            "exit_code": 0,
        })
        closed = self.runtime.delivery(str(record["envelope_id"]))
        self.assertEqual(closed["state"], "completed")
        self.assertEqual(closed["response_committed"], 1)

    async def test_terminal_orphan_is_not_hidden_by_sixteen_live_owners(self) -> None:
        base = int(time.time())
        live: list[dict[str, Any]] = []
        with patch("secure_peer_delivery.time.time", return_value=base - 20):
            for index in range(16):
                live.append(self.prepare_running(run_id=f"run_live_{index}"))
        agent_server.QUEUED_TURNS["target"] = deque(
            {"secure_peer_envelope_id": row["envelope_id"]} for row in live
        )
        with patch("secure_peer_delivery.time.time", return_value=base - 10):
            orphan = self.prepare_running(run_id="run_terminal_orphan")
        terminal = {
            "type": "turn_finished",
            "run_id": "run_terminal_orphan",
            "secure_peer_envelope_id": orphan["envelope_id"],
            "result_text": "Finished",
            "exit_code": 0,
        }

        def history(_session_id: str, envelope_id: str) -> list[dict[str, Any]]:
            return [terminal] if envelope_id == orphan["envelope_id"] else []

        with (
            patch.object(
                agent_server,
                "secure_peer_delivery_history",
                side_effect=history,
            ),
            patch.object(
                agent_server,
                "finalize_secure_peer_delivery_run",
                new=AsyncMock(),
            ) as finalize,
        ):
            self.assertEqual(
                await agent_server.reconcile_secure_peer_terminal_orphans(limit=1),
                1,
            )
        finalize.assert_awaited_once_with(terminal)

    async def test_inbox_only_migration_terminalizes_all_relay_state_offline(
        self,
    ) -> None:
        envelope = self.envelope(kind="request_reply")
        record, created = self.runtime.delivery_ledger.prepare(
            envelope,
            transport_role="client",
            connection_id=self.connection_id,
            lease_token="lease-token",
            target_chat_id="target",
        )
        self.assertTrue(created)
        record = self.runtime.delivery_ledger.authorize(envelope["envelope_id"])
        self.assertIsNotNone(record)
        record = self.runtime.bind_delivery_owner(
            envelope["envelope_id"],
            queued_id="legacy-queued-delivery",
            run_id=None,
        )
        self.assertIsNotNone(record)
        self.runtime.prepare_delivery_response(
            envelope["envelope_id"],
            request_id=uuid4_text(),
            body="legacy response",
            request_response=False,
        )
        outbound_request_id = uuid4_text()
        self.runtime.prepare_outbound_handoff(
            request_id=outbound_request_id,
            source_session_id="source",
            source_run_id="run-source",
            snapshot=self.snapshot(action="instruction"),
            body="legacy outbound",
            action="instruction",
            expires_at=int(time.time()) + 3600,
        )
        self.runtime.defer_outbound_handoff(
            outbound_request_id,
            error="peer offline",
        )

        with patch.object(
            agent_server,
            "SECURE_PEER_AGENT_RELAY_ENABLED",
            False,
        ):
            retired = await agent_server.retire_secure_peer_agent_relay_state()

        self.assertEqual(retired, 2)
        delivery = self.runtime.delivery(envelope["envelope_id"])
        self.assertEqual(delivery["state"], "failed")
        self.assertIn("retired", str(delivery["error"]))
        outbound = self.runtime.delivery_ledger.outbound(outbound_request_id)
        self.assertEqual(outbound["state"], "failed")
        self.assertIn("retired", str(outbound["last_error"]))
        self.assertEqual(self.runtime.delivery_ledger.recoverable(), [])
        self.assertEqual(
            self.runtime.delivery_ledger.recoverable_outbound(),
            [],
        )
        self.assertEqual(self.runtime.submissions, [])

    async def test_inbox_only_retirement_is_one_shot_across_background_loops(
        self,
    ) -> None:
        runtime = Mock()
        entered = threading.Event()
        release = threading.Event()

        def recoverable_deliveries() -> list[dict[str, Any]]:
            entered.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test retirement release timed out")
            return []

        runtime.recoverable_deliveries.side_effect = recoverable_deliveries
        runtime.recoverable_outbound_handoffs.return_value = []
        runtime.retire_agent_routes_locally.return_value = 0
        with (
            patch.object(agent_server, "SECURE_PEER_RUNTIME", runtime),
            patch.object(
                agent_server,
                "SECURE_PEER_AGENT_RELAY_ENABLED",
                False,
            ),
        ):
            connector = asyncio.create_task(
                agent_server.secure_peer_connector_once()
            )
            self.assertTrue(await asyncio.to_thread(entered.wait, 5))
            outbox = asyncio.create_task(
                agent_server.reconcile_secure_peer_response_outbox()
            )
            await asyncio.sleep(0)
            release.set()
            self.assertEqual(
                await asyncio.gather(connector, outbox),
                [0, 0],
            )
            self.assertEqual(await agent_server.secure_peer_connector_once(), 0)
            self.assertEqual(
                await agent_server.reconcile_secure_peer_response_outbox(),
                0,
            )

        runtime.recoverable_deliveries.assert_called_once_with()
        runtime.recoverable_outbound_handoffs.assert_called_once_with(limit=50)
        runtime.retire_agent_routes_locally.assert_called_once_with()
        runtime.fail_outbound_handoff.assert_not_called()
        runtime.finish_delivery.assert_not_called()
        runtime.proxy.assert_not_called()

    async def test_inbox_only_retirement_retries_after_failed_attempt(self) -> None:
        runtime = Mock()
        runtime.recoverable_deliveries.side_effect = [
            RuntimeError("retirement failed"),
            [],
        ]
        runtime.recoverable_outbound_handoffs.return_value = []
        runtime.retire_agent_routes_locally.return_value = 0
        with (
            patch.object(agent_server, "SECURE_PEER_RUNTIME", runtime),
            patch.object(
                agent_server,
                "SECURE_PEER_AGENT_RELAY_ENABLED",
                False,
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "retirement failed"):
                await agent_server.secure_peer_connector_once()
            self.assertEqual(
                await agent_server.reconcile_secure_peer_response_outbox(),
                0,
            )
            self.assertEqual(await agent_server.secure_peer_connector_once(), 0)

        self.assertEqual(runtime.recoverable_deliveries.call_count, 2)
        runtime.recoverable_outbound_handoffs.assert_called_once_with(limit=50)
        runtime.retire_agent_routes_locally.assert_called_once_with()

    async def test_unsupported_target_is_rejected_before_delivered_receipt(self) -> None:
        actual = SecurePeerRuntime(
            self.root / "unsupported-runtime",
            server_identity=self.local_identity,
            server_instance_id="test-instance",
            display_name="Test server",
        )
        agent_server.SECURE_PEER_RUNTIME = actual
        envelope = self.envelope()
        record, _created = actual.delivery_ledger.prepare(
            envelope,
            transport_role="client",
            connection_id=self.connection_id,
            lease_token="lease-token",
            target_chat_id="target",
        )
        agent_server.STORE.sessions["target"]["backend"] = "unsupported"
        outcomes: list[str] = []

        def receipt(*_args: Any, **kwargs: Any) -> dict[str, Any]:
            outcomes.append(str(kwargs.get("outcome") or ""))
            return {"status": kwargs.get("outcome")}

        try:
            with patch.object(actual, "_receipt_claim", side_effect=receipt):
                admitted = await agent_server.admit_prepared_secure_peer_delivery(
                    record
                )
            self.assertIsNone(admitted)
            self.assertEqual(outcomes, ["failed"])
            self.assertEqual(actual.delivery(envelope["envelope_id"])["state"], "failed")
        finally:
            actual.shutdown()

    async def test_unsupported_target_terminalizes_accepted_ownerless_delivery(
        self,
    ) -> None:
        actual = SecurePeerRuntime(
            self.root / "accepted-unsupported-runtime",
            server_identity=self.local_identity,
            server_instance_id="test-instance",
            display_name="Test server",
        )
        agent_server.SECURE_PEER_RUNTIME = actual
        envelope = self.envelope()
        record, _created = actual.delivery_ledger.prepare(
            envelope,
            transport_role="client",
            connection_id=self.connection_id,
            lease_token="lease-token",
            target_chat_id="target",
        )
        record = actual.delivery_ledger.authorize(envelope["envelope_id"])
        self.assertIsNotNone(record)
        agent_server.STORE.sessions["target"]["backend"] = "unsupported"

        try:
            admitted = await agent_server.admit_prepared_secure_peer_delivery(
                record,  # type: ignore[arg-type]
            )
            self.assertIsNone(admitted)
            self.assertEqual(
                actual.delivery(envelope["envelope_id"])["state"],
                "failed",
            )
            self.assertEqual(actual.delivery_ledger.pending_admissions(), [])
            self.assertEqual(
                actual.delivery_ledger.nonterminal_for_chat("target"),
                [],
            )
        finally:
            actual.shutdown()

    async def test_followup_budget_rejection_can_fall_back_to_terminal_sixth_leg(self) -> None:
        record = self.prepare_running(used_legs=5)
        token = await self.issue_secure_response(record, self.response_snapshot())
        followup = agent_server.CrossChatExchangeResponseRequest(
            inbound_leg_id=str(record["envelope_id"]),
            body="One more question",
            request_response=True,
            idempotency_key="followup-response-key",
        )
        with self.assertRaises(HTTPException) as exhausted:
            await agent_server.create_authorized_cross_chat_exchange_response(
                token,
                str(record["exchange_id"]),
                followup,
            )
        self.assertEqual(exhausted.exception.status_code, 409)
        self.assertIn("No leg remains", str(exhausted.exception.detail))

        # A definite budget rejection creates no leg and re-opens this exact
        # live response slot, permitting a terminal answer instead.
        exchange, leg, created = (
            await agent_server.create_authorized_cross_chat_exchange_response(
                token,
                str(record["exchange_id"]),
                followup.model_copy(update={
                    "body": "Final answer",
                    "request_response": False,
                    "idempotency_key": "terminal-response-key",
                }),
            )
        )
        self.assertTrue(created)
        self.assertEqual(exchange["status"], "completed")
        self.assertEqual(leg["used_legs"], 6)
        self.assertFalse(self.runtime.submissions[-1]["request_response"])


if __name__ == "__main__":
    unittest.main()
