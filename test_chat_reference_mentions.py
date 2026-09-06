import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from fastapi import HTTPException

import agent_server


class ChatReferenceMentionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.sessions = {
            "source-private-id": {
                "id": "source-private-id",
                "title": "Source",
                "backend": agent_server.BACKEND_CODEX,
            },
            "target-private-id": {
                "id": "target-private-id",
                "title": "Target",
                "backend": agent_server.BACKEND_CODEX,
            },
        }

    def reference(
        self,
        action: str = "route",
        *,
        marker: str = "@Target",
        route_action: str | None = None,
        grant_intent: bool | None = None,
        start: int = 0,
    ) -> agent_server.ChatReference:
        return agent_server.ChatReference(
            session_id="target-private-id",
            display_title_snapshot="Target",
            source_text_start=start,
            source_text_end=start + len(marker),
            action=action,
            route_action=route_action,
            grant_intent=grant_intent,
        )

    def test_single_at_is_current_route_and_legacy_values_normalize_safely(self) -> None:
        with (
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(agent_server.STORE, "sessions", self.sessions),
            patch.object(
                agent_server,
                "cross_chat_delivery_client_capabilities",
                return_value=[agent_server.CODEX_INTERACTIVE_CLIENT_CAPABILITY],
            ),
        ):
            current = agent_server.validate_chat_references(
                "source-private-id", "@Target do it", [self.reference()]
            )
            legacy_direct = agent_server.validate_chat_references(
                "source-private-id",
                "@Target do it",
                [self.reference("direct_message")],
            )
            legacy_route = agent_server.validate_chat_references(
                "source-private-id",
                "@@Target ask it",
                [self.reference("route", marker="@@Target")],
            )
        self.assertEqual(current[0].action, "route")
        self.assertEqual(legacy_direct[0].action, "route")
        self.assertEqual(legacy_route[0].action, "route")
        self.assertEqual(agent_server.chat_reference_marker(legacy_route[0]), "@Target")

    def test_cross_server_agent_reference_is_rejected_before_runtime_lookup(
        self,
    ) -> None:
        reference = agent_server.ChatReference(
            session_id="22222222-2222-4222-8222-222222222222",
            display_title_snapshot="Remote",
            source_text_start=0,
            source_text_end=7,
            action="instruction",
            target_kind="secure_peer",
            target_server_identity="peer_" + "a" * 64,
            target_connection_id="11111111-1111-4111-8111-111111111111",
            target_route_id="22222222-2222-4222-8222-222222222222",
            target_route_revision="rev_" + "d" * 32,
        )
        with (
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(agent_server, "SECURE_PEER_AGENT_RELAY_ENABLED", False),
            patch.object(agent_server.STORE, "sessions", self.sessions),
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "remote_route_delivery_available",
                side_effect=AssertionError("remote relay must not be consulted"),
            ) as runtime_lookup,
            self.assertRaises(HTTPException) as raised,
        ):
            agent_server.validate_chat_references(
                "source-private-id",
                "@Remote",
                [reference],
            )
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("Team Network Inbox", str(raised.exception.detail))
        runtime_lookup.assert_not_called()

    async def test_inbox_only_capability_strips_legacy_secure_relay_grants(
        self,
    ) -> None:
        snapshot = {
            "version": 1,
            "role": "client",
            "connection_id": "11111111-1111-4111-8111-111111111111",
            "team_id": "team-current",
            "hub_id": "hub-current",
            "source_server_identity": "server-local",
            "source_chat_id": "source-private-id",
            "source_route_id": "33333333-3333-4333-8333-333333333333",
            "source_route_revision": "rev_" + "c" * 32,
            "target_server_identity": "server-remote",
            "target_route_id": "22222222-2222-4222-8222-222222222222",
            "target_route_revision": "rev_" + "d" * 32,
            "action": "instruction",
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(agent_server, "SECURE_PEER_AGENT_RELAY_ENABLED", False),
            patch.object(
                agent_server,
                "CROSS_CHAT_AUTHORITY_ROOT",
                Path(temporary) / "authority",
            ),
            patch.object(agent_server.STORE, "sessions", self.sessions),
        ):
            authority = await agent_server.issue_cross_chat_capability(
                "source-private-id",
                "run_inbox_only",
                [],
                actions={"publish", "secure_peer_instruction"},
                secure_peer_route_snapshots=[snapshot],
            )
            token = agent_server.json.loads(authority.read_text())[
                "provider_capability"
            ]
            token_hash = agent_server.hashlib.sha256(token.encode()).hexdigest()
            capability = agent_server.CROSS_CHAT_CAPABILITIES.pop(token_hash)
        self.assertEqual(capability["secure_peer_grants"], {})
        self.assertNotIn("secure_peer_instruction", capability["actions"])

    async def test_forged_legacy_secure_capability_cannot_submit(self) -> None:
        token = "legacy-secure-capability"
        token_hash = agent_server.hashlib.sha256(token.encode()).hexdigest()
        handle = "legacy-remote-route"
        capability = {
            "server_identity": agent_server.server_identity(),
            "source_session_id": "source-private-id",
            "source_run_id": "run-legacy-secure",
            "source_user_instruction": "Contact the remote agent",
            "native_transition_nonce": "",
            "actions": {"secure_peer_instruction"},
            "secure_peer_grants": {
                (handle, "instruction"): {"opaque": "legacy-snapshot"},
            },
            "consumed": {},
        }
        submit = Mock()
        with (
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(agent_server, "SECURE_PEER_AGENT_RELAY_ENABLED", False),
            patch.object(
                agent_server,
                "CURRENT_TURNS",
                {"source-private-id": {"run_id": "run-legacy-secure"}},
            ),
            patch.dict(
                agent_server.CROSS_CHAT_CAPABILITIES,
                {token_hash: capability},
                clear=True,
            ),
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "submit_remote_handoff",
                submit,
            ),
            self.assertRaises(HTTPException) as raised,
        ):
            await agent_server.create_authorized_cross_chat_instruction(
                token,
                agent_server.CrossChatHandoffRequest(
                    target_session_id=handle,
                    action="instruction",
                    body="Do not send this",
                    idempotency_key="legacy-secure-send",
                ),
            )
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("Team Network Inbox", str(raised.exception.detail))
        self.assertEqual(capability["consumed"], {})
        submit.assert_not_called()

    async def test_v2_grant_intent_requires_exact_single_at_and_fences_v1(self) -> None:
        durable = self.reference("route", grant_intent=True)
        with (
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(agent_server.STORE, "sessions", self.sessions),
            patch.object(
                agent_server,
                "cross_chat_delivery_client_capabilities",
                return_value=[agent_server.CODEX_INTERACTIVE_CLIENT_CAPABILITY],
            ),
        ):
            with self.assertRaisesRegex(HTTPException, "updated client"):
                agent_server.validate_chat_references(
                    "source-private-id",
                    "@Target do it",
                    [durable],
                    ["agent_cross_chat_routes_v1"],
                )
            accepted = agent_server.validate_chat_references(
                "source-private-id",
                "@Target do it",
                [durable],
                [agent_server.AGENT_CROSS_CHAT_ROUTES_CLIENT_CAPABILITY],
            )
            self.assertTrue(accepted[0].grant_intent)
            with self.assertRaisesRegex(HTTPException, "exact canonical"):
                agent_server.validate_chat_references(
                    "source-private-id",
                    "@@Target do it",
                    [
                        self.reference(
                            "route",
                            marker="@@Target",
                            grant_intent=True,
                        )
                    ],
                    [agent_server.AGENT_CROSS_CHAT_ROUTES_CLIENT_CAPABILITY],
                )

            legacy_request = agent_server.TurnRequest(
                prompt="@Target old client",
                chat_references=[self.reference("route")],
                client_capabilities=["agent_cross_chat_routes_v1"],
            )
            with self.assertRaisesRegex(HTTPException, "legacy cross-chat"):
                await agent_server._start_turn_locked(
                    "source-private-id",
                    legacy_request,
                    queue_if_busy=False,
                    provider_context_mode="chat",
                    admission_backend=agent_server.BACKEND_CODEX,
                )
        self.assertEqual(
            self.sessions["source-private-id"].get(
                "provider_cross_chat_routes", []
            ),
            [],
        )

    def test_legacy_direct_large_prompt_is_only_a_route_hint(self) -> None:
        prompt = "@Target " + (
            "x" * agent_server.CROSS_CHAT_HANDOFF_BODY_MAX_CHARS
        )
        with (
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(agent_server.STORE, "sessions", self.sessions),
            patch.object(
                agent_server,
                "cross_chat_delivery_client_capabilities",
                return_value=[agent_server.CODEX_INTERACTIVE_CLIENT_CAPABILITY],
            ),
        ):
            normalized = agent_server.validate_chat_references(
                "source-private-id",
                prompt,
                [self.reference("direct_message")],
            )
        self.assertEqual(normalized[0].action, "route")

    def test_scheduled_route_reference_becomes_a_fresh_opaque_run_route(self) -> None:
        route_reference = self.reference("route")
        with (
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(agent_server.STORE, "sessions", self.sessions),
            patch.object(
                agent_server,
                "cross_chat_target_backend_supported",
                return_value=True,
            ),
        ):
            first = agent_server.provider_cross_chat_route_snapshot_for_authority(
                [],
                [route_reference],
                source_session_id="source-private-id",
                per_job_reference_routes=True,
            )
            second = agent_server.provider_cross_chat_route_snapshot_for_authority(
                [],
                [route_reference],
                source_session_id="source-private-id",
                per_job_reference_routes=True,
            )
            self.assertEqual(len(first), 1)
            self.assertEqual(
                first[0]["route_kind"],
                agent_server.PROVIDER_CROSS_CHAT_ROUTE_KIND_REFERENCE,
            )
            self.assertEqual(first[0]["target_session_id"], "target-private-id")
            self.assertEqual(first[0]["actions"], ["instruction", "request_reply"])
            self.assertNotEqual(first[0]["route_id"], second[0]["route_id"])
            block = agent_server.cross_chat_provider_authority_block(
                [route_reference],
                Path("/tmp/run_example-0123456789abcdef0123456789abcdef.json"),
                "source-private-id",
                {"agent_cross_chat_routes"},
                provider_route_snapshot=first,
            )
        self.assertIn("@ route hint 1", block)
        self.assertIn(first[0]["route_id"], block)
        self.assertNotIn("target-private-id", block)
        self.assertIn("never forwards the raw source prompt", block)
        self.assertIn("send a prepared message", block)
        self.assertIn("make no contact", block)

    def test_legacy_ambient_and_route_hints_are_quarantined_for_ordinary_turns(self) -> None:
        ambient = {
            "route_id": "route_" + ("1" * 32),
            "revision": "rev_" + ("2" * 32),
            "alias": "chat1",
            "target_session_id": "target-private-id",
            "actions": ["instruction", "request_reply"],
            "route_kind": agent_server.PROVIDER_CROSS_CHAT_ROUTE_KIND_AMBIENT,
        }
        with (
            patch.object(agent_server.STORE, "sessions", self.sessions),
            patch.object(
                agent_server,
                "cross_chat_target_backend_supported",
                return_value=True,
            ),
        ):
            direct_routes = (
                agent_server.provider_cross_chat_route_snapshot_for_authority(
                    [ambient],
                    [self.reference("direct_message")],
                    source_session_id="source-private-id",
                )
            )
            explicit_routes = (
                agent_server.provider_cross_chat_route_snapshot_for_authority(
                    [ambient],
                    [self.reference("route")],
                    source_session_id="source-private-id",
                )
            )
        self.assertEqual(direct_routes, [])
        self.assertEqual(explicit_routes, [])

    def test_provider_job_route_conversion_requires_and_persists_single_at(self) -> None:
        issued = {
            "route_id": "route_" + ("1" * 32),
            "revision": "rev_" + ("2" * 32),
            "alias": "chat1",
            "target_session_id": "target-private-id",
            "actions": ["instruction", "request_reply"],
            "created_at": "2026-08-27T00:00:00Z",
            "updated_at": "2026-08-27T00:00:00Z",
        }
        capability = {"provider_route_grants": {issued["route_id"]: issued}}
        selection = agent_server.AgentJobChatRouteSelection(
            route_id=issued["route_id"],
            action="instruction",
        )
        with (
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(agent_server.STORE, "sessions", self.sessions),
            patch.object(
                agent_server,
                "cross_chat_target_backend_supported",
                return_value=True,
            ),
            patch.object(
                agent_server,
                "cross_chat_delivery_client_capabilities",
                return_value=[agent_server.CODEX_INTERACTIVE_CLIENT_CAPABILITY],
            ),
        ):
            self.sessions["source-private-id"][
                "provider_cross_chat_routes"
            ] = [dict(issued)]
            references = agent_server.provider_job_chat_references(
                capability,
                "source-private-id",
                "@Target check later",
                [selection],
            )
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0].action, "route")
        self.assertEqual(
            agent_server.chat_reference_marker(references[0]), "@Target"
        )
        with (
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(agent_server.STORE, "sessions", self.sessions),
            patch.object(
                agent_server,
                "cross_chat_target_backend_supported",
                return_value=True,
            ),
        ):
            with self.assertRaisesRegex(HTTPException, "must include"):
                agent_server.provider_job_chat_references(
                    capability,
                    "source-private-id",
                    "@@Target check later",
                    [selection],
                )

    async def test_legacy_direct_registration_is_a_noop(self) -> None:
        original_cross_chat = agent_server.CROSS_CHAT
        original_cache = agent_server.CROSS_CHAT_EVENT_TYPE_CACHE
        with tempfile.TemporaryDirectory() as temporary:
            agent_server.CROSS_CHAT = agent_server.CrossChatStore(
                Path(temporary) / "cross-chat.sqlite3"
            )
            agent_server.CROSS_CHAT_EVENT_TYPE_CACHE = agent_server.OrderedDict()
            await agent_server.CROSS_CHAT.initialize()
            try:
                direct_ids = await agent_server.register_direct_message_handoffs(
                    "source-private-id",
                    "run_direct",
                    "@Target please handle this",
                    [self.reference("direct_message"), self.reference("route")],
                )
                self.assertEqual(direct_ids, [])
                self.assertEqual(await agent_server.CROSS_CHAT.recoverable(), [])
            finally:
                agent_server.CROSS_CHAT = original_cross_chat
                agent_server.CROSS_CHAT_EVENT_TYPE_CACHE = original_cache

    def test_dual_beta_mentions_collapse_but_current_duplicates_fail(self) -> None:
        prompt = "@Target then @@Target"
        legacy_direct = self.reference("direct_message")
        legacy_route = self.reference("route", marker="@@Target", start=13)
        with (
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(agent_server.STORE, "sessions", self.sessions),
            patch.object(
                agent_server,
                "cross_chat_delivery_client_capabilities",
                return_value=[agent_server.CODEX_INTERACTIVE_CLIENT_CAPABILITY],
            ),
        ):
            collapsed = agent_server.validate_chat_references(
                "source-private-id", prompt, [legacy_direct, legacy_route]
            )
            self.assertEqual(len(collapsed), 1)
            self.assertEqual(collapsed[0].action, "route")
            self.assertEqual(collapsed[0].source_text_start, 0)

            with self.assertRaisesRegex(HTTPException, "duplicate"):
                agent_server.validate_chat_references(
                    "source-private-id",
                    "@Target then @Target",
                    [self.reference(), self.reference(start=13)],
                )

    async def test_job_store_load_collapses_dual_legacy_target(self) -> None:
        prompt = "@Target then @@Target"
        raw_direct = agent_server.chat_reference_dict(
            self.reference("direct_message")
        )
        raw_route = agent_server.chat_reference_dict(
            self.reference(
                "route",
                marker="@@Target",
                route_action="instruction",
                start=13,
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            jobs_file = Path(temporary) / "jobs.json"
            jobs_file.write_text(
                agent_server.json.dumps({
                    "job_legacy": {
                        "id": "job_legacy",
                        "session_id": "source-private-id",
                        "title": "Legacy",
                        "prompt": prompt,
                        "chat_references": [raw_direct, raw_route],
                        "enabled": False,
                        "next_run_at": None,
                    }
                }),
                encoding="utf-8",
            )
            store = agent_server.JobStore()
            with patch.object(agent_server, "JOBS_FILE", jobs_file):
                await store.load()
            references = store.jobs["job_legacy"]["chat_references"]
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0]["action"], "route")
        self.assertEqual(references[0]["route_action"], "instruction")
        self.assertEqual(references[0]["source_text_start"], 13)

    async def test_store_initialize_quarantines_only_legacy_raw_direct_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cross-chat.sqlite3"
            store = agent_server.CrossChatStore(path)
            await store.initialize()
            legacy, _ = await store.create_instruction(
                envelope_id="handoff_legacy",
                source_session_id="source-private-id",
                source_run_id="run_legacy",
                target_session_id="target-private-id",
                body="raw source prompt",
                idempotency_key="direct:0:target-private-id",
            )
            configured, _ = await store.create_instruction(
                envelope_id="handoff_configured",
                source_session_id="source-private-id",
                source_run_id="run_configured",
                target_session_id="target-private-id",
                body="agent prepared message",
                idempotency_key="configured-send-key",
                authorization_kind="configured_route",
                authorization_route_id="route_" + ("1" * 32),
            )
            self.assertEqual(legacy["status"], "ready")
            self.assertEqual(configured["status"], "ready")
            restarted = agent_server.CrossChatStore(path)
            await restarted.initialize()
            self.assertEqual(
                (await restarted.get("handoff_legacy"))["status"], "failed"
            )
            self.assertEqual(
                (await restarted.get("handoff_configured"))["status"], "ready"
            )

    async def test_legacy_reconcile_cancels_queue_and_fails_ownerless_submit(self) -> None:
        base = {
            "kind": "instruction",
            "authorization_kind": "explicit_prompt",
            "idempotency_key": "direct:0:target-private-id",
            "target_session_id": "target-private-id",
        }
        queued = {**base, "id": "handoff_queued", "status": "queued"}
        cancel = AsyncMock(return_value={**queued, "status": "cancelled"})
        with patch.object(
            agent_server,
            "cancel_queued_cross_chat_handoff",
            cancel,
        ):
            await agent_server.reconcile_legacy_raw_direct_message_envelope(
                queued
            )
        cancel.assert_awaited_once_with("handoff_queued")

        submitting = {
            **base,
            "id": "handoff_submitting",
            "status": "submitting",
        }
        failed = {**submitting, "status": "failed"}
        update = AsyncMock(return_value=failed)
        with (
            patch.object(agent_server.CROSS_CHAT, "update", update),
            patch.object(
                agent_server,
                "live_cross_chat_delivery_state",
                AsyncMock(return_value=None),
            ),
            patch.object(
                agent_server,
                "cross_chat_delivery_state",
                Mock(return_value=None),
            ),
            patch.object(
                agent_server,
                "append_cross_chat_terminal_lifecycle",
                AsyncMock(),
            ),
        ):
            await agent_server.reconcile_legacy_raw_direct_message_envelope(
                submitting
            )
        self.assertEqual(update.await_args.kwargs["status"], "failed")

    async def test_legacy_reconcile_never_submits_and_preserves_live_owner(self) -> None:
        ready = {
            "id": "handoff_ready",
            "kind": "instruction",
            "authorization_kind": "explicit_prompt",
            "idempotency_key": "direct:0:target-private-id",
            "status": "ready",
            "target_session_id": "target-private-id",
        }
        running = {**ready, "id": "handoff_running", "status": "running"}
        failed = {**ready, "status": "failed"}
        submit = AsyncMock()
        update = AsyncMock(side_effect=[failed, running])
        with (
            patch.object(agent_server.CROSS_CHAT, "pending_terminal_lifecycle", AsyncMock(return_value=[])),
            patch.object(agent_server.CROSS_CHAT, "recoverable", AsyncMock(return_value=[ready, running])),
            patch.object(agent_server.CROSS_CHAT, "update", update),
            patch.object(agent_server.CROSS_CHAT, "get", AsyncMock(return_value=running)),
            patch.object(agent_server, "append_cross_chat_terminal_lifecycle", AsyncMock()),
            patch.object(
                agent_server,
                "live_cross_chat_delivery_state",
                AsyncMock(return_value={"status": "running", "target_run_id": "run_target"}),
            ),
            patch.object(agent_server, "submit_cross_chat_delivery", submit),
        ):
            recovered = await agent_server.reconcile_cross_chat_handoffs()
        self.assertEqual(recovered, 2)
        submit.assert_not_awaited()
        self.assertEqual(update.await_args_list[0].kwargs["status"], "failed")
        self.assertEqual(update.await_args_list[1].kwargs["status"], "running")

    async def test_direct_dispatch_waits_until_source_lock_is_released(self) -> None:
        source_id = "source-private-id"
        original_locks = agent_server.SESSION_LIFECYCLE_LOCKS
        original_tasks = agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS
        original_tasks_by_envelope = (
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE
        )
        agent_server.SESSION_LIFECYCLE_LOCKS = {}
        agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS = set()
        agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE = {}
        record = {"id": "handoff_direct", "status": "ready"}
        submit = AsyncMock(
            return_value={"id": "handoff_direct", "status": "running"}
        )
        try:
            with (
                patch.object(agent_server.CROSS_CHAT, "get", AsyncMock(return_value=record)),
                patch.object(agent_server, "submit_cross_chat_delivery", submit),
            ):
                async with agent_server.session_lifecycle_lock(source_id):
                    agent_server.schedule_direct_message_handoffs_after_unlock(
                        source_id, ["handoff_direct"]
                    )
                    await asyncio.sleep(0)
                    submit.assert_not_awaited()
                await asyncio.gather(
                    *tuple(agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS)
                )
                submit.assert_awaited_once_with(record)
        finally:
            agent_server.SESSION_LIFECYCLE_LOCKS = original_locks
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS = original_tasks
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE = (
                original_tasks_by_envelope
            )

    async def test_direct_dispatch_retries_transient_failure_without_restart(self) -> None:
        source_id = "source-private-id"
        original_locks = agent_server.SESSION_LIFECYCLE_LOCKS
        original_tasks = agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS
        original_tasks_by_envelope = (
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE
        )
        agent_server.SESSION_LIFECYCLE_LOCKS = {}
        agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS = set()
        agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE = {}
        record = {"id": "handoff_retry", "status": "ready"}
        submitted = {"id": "handoff_retry", "status": "running"}
        submit = AsyncMock(
            side_effect=[RuntimeError("target temporarily busy"), submitted]
        )
        archived_source_sessions = {
            session_id: dict(session)
            for session_id, session in self.sessions.items()
        }
        archived_source_sessions[source_id]["archived"] = True
        try:
            with (
                # Source archive does not revoke a direct-message effect after
                # the source turn's durable admission boundary.
                patch.object(
                    agent_server.STORE,
                    "sessions",
                    archived_source_sessions,
                ),
                patch.object(
                    agent_server.CROSS_CHAT,
                    "get",
                    AsyncMock(return_value=record),
                ),
                patch.object(
                    agent_server,
                    "submit_cross_chat_delivery",
                    submit,
                ),
                patch.object(
                    agent_server,
                    "CROSS_CHAT_DIRECT_RETRY_DELAYS_SECONDS",
                    (0.0,),
                ),
            ):
                agent_server.schedule_direct_message_handoffs_after_unlock(
                    source_id, ["handoff_retry"]
                )
                # Reconciliation/admission can race to schedule the same
                # durable row. It must still have exactly one retry owner.
                agent_server.schedule_direct_message_handoffs_after_unlock(
                    source_id, ["handoff_retry"]
                )
                self.assertEqual(
                    len(agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE),
                    1,
                )
                await asyncio.gather(
                    *tuple(agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS)
                )
            self.assertEqual(submit.await_count, 2)
        finally:
            agent_server.SESSION_LIFECYCLE_LOCKS = original_locks
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS = original_tasks
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE = (
                original_tasks_by_envelope
            )

    async def test_direct_retry_stops_when_terminal_cas_wins(self) -> None:
        source_id = "source-private-id"
        original_locks = agent_server.SESSION_LIFECYCLE_LOCKS
        original_tasks = agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS
        original_tasks_by_envelope = (
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE
        )
        agent_server.SESSION_LIFECYCLE_LOCKS = {}
        agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS = set()
        agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE = {}
        ready = {"id": "handoff_cancelled", "status": "ready"}
        cancelled = {"id": "handoff_cancelled", "status": "cancelled"}
        submit = AsyncMock(side_effect=RuntimeError("target temporarily busy"))
        terminal = AsyncMock()
        try:
            with (
                patch.object(
                    agent_server.CROSS_CHAT,
                    "get",
                    AsyncMock(side_effect=[ready, cancelled]),
                ),
                patch.object(
                    agent_server,
                    "submit_cross_chat_delivery",
                    submit,
                ),
                patch.object(
                    agent_server,
                    "append_cross_chat_terminal_lifecycle",
                    terminal,
                ),
                patch.object(
                    agent_server,
                    "CROSS_CHAT_DIRECT_RETRY_DELAYS_SECONDS",
                    (0.0,),
                ),
            ):
                agent_server.schedule_direct_message_handoffs_after_unlock(
                    source_id, ["handoff_cancelled"]
                )
                await asyncio.gather(
                    *tuple(agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS)
                )
            submit.assert_awaited_once_with(ready)
            terminal.assert_awaited_once_with(
                cancelled,
                "Direct @chat delivery was cancelled.",
            )
        finally:
            agent_server.SESSION_LIFECYCLE_LOCKS = original_locks
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS = original_tasks
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE = (
                original_tasks_by_envelope
            )

    async def test_direct_retry_exhaustion_terminalizes_visibly(self) -> None:
        source_id = "source-private-id"
        original_locks = agent_server.SESSION_LIFECYCLE_LOCKS
        original_tasks = agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS
        original_tasks_by_envelope = (
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE
        )
        agent_server.SESSION_LIFECYCLE_LOCKS = {}
        agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS = set()
        agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE = {}
        ready = {"id": "handoff_exhausted", "status": "ready"}
        failed = {"id": "handoff_exhausted", "status": "failed"}
        submit = AsyncMock(side_effect=RuntimeError("target temporarily busy"))
        update = AsyncMock(return_value=failed)
        terminal = AsyncMock()
        try:
            with (
                patch.object(
                    agent_server.CROSS_CHAT,
                    "get",
                    AsyncMock(return_value=ready),
                ),
                patch.object(agent_server.CROSS_CHAT, "update", update),
                patch.object(
                    agent_server,
                    "submit_cross_chat_delivery",
                    submit,
                ),
                patch.object(
                    agent_server,
                    "append_cross_chat_terminal_lifecycle",
                    terminal,
                ),
                patch.object(
                    agent_server,
                    "CROSS_CHAT_DIRECT_RETRY_DELAYS_SECONDS",
                    (0.0,),
                ),
            ):
                agent_server.schedule_direct_message_handoffs_after_unlock(
                    source_id, ["handoff_exhausted"]
                )
                await asyncio.gather(
                    *tuple(agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS)
                )
            self.assertEqual(submit.await_count, 2)
            update.assert_awaited_once_with(
                "handoff_exhausted",
                expected={"ready"},
                status="failed",
                error=(
                    "direct message delivery remained unavailable after "
                    "bounded retries"
                ),
            )
            terminal.assert_awaited_once_with(
                failed,
                "Direct @chat delivery failed after repeated transient "
                "submission errors.",
            )
        finally:
            agent_server.SESSION_LIFECYCLE_LOCKS = original_locks
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS = original_tasks
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE = (
                original_tasks_by_envelope
            )

    async def test_direct_retry_cancellation_leaves_ready_row_recoverable(self) -> None:
        source_id = "source-private-id"
        original_locks = agent_server.SESSION_LIFECYCLE_LOCKS
        original_tasks = agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS
        original_tasks_by_envelope = (
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE
        )
        agent_server.SESSION_LIFECYCLE_LOCKS = {}
        agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS = set()
        agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE = {}
        ready = {"id": "handoff_shutdown", "status": "ready"}
        attempted = asyncio.Event()

        async def transient_failure(_record: dict) -> dict:
            attempted.set()
            raise RuntimeError("target temporarily busy")

        update = AsyncMock()
        try:
            with (
                patch.object(
                    agent_server.CROSS_CHAT,
                    "get",
                    AsyncMock(return_value=ready),
                ),
                patch.object(agent_server.CROSS_CHAT, "update", update),
                patch.object(
                    agent_server,
                    "submit_cross_chat_delivery",
                    side_effect=transient_failure,
                ),
                patch.object(
                    agent_server,
                    "CROSS_CHAT_DIRECT_RETRY_DELAYS_SECONDS",
                    (60.0,),
                ),
            ):
                agent_server.schedule_direct_message_handoffs_after_unlock(
                    source_id, ["handoff_shutdown"]
                )
                await asyncio.wait_for(attempted.wait(), timeout=1)
                await asyncio.sleep(0)
                task = (
                    agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE[
                        "handoff_shutdown"
                    ]
                )
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                await asyncio.sleep(0)
            update.assert_not_awaited()
            self.assertNotIn(
                "handoff_shutdown",
                agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE,
            )
        finally:
            agent_server.SESSION_LIFECYCLE_LOCKS = original_locks
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS = original_tasks
            agent_server.CROSS_CHAT_DIRECT_DELIVERY_TASKS_BY_ENVELOPE = (
                original_tasks_by_envelope
            )

    async def test_unavailable_endpoint_check_cannot_overwrite_terminal_cas(self) -> None:
        original_cross_chat = agent_server.CROSS_CHAT
        original_cache = agent_server.CROSS_CHAT_EVENT_TYPE_CACHE
        with tempfile.TemporaryDirectory() as temporary:
            agent_server.CROSS_CHAT = agent_server.CrossChatStore(
                Path(temporary) / "cross-chat.sqlite3"
            )
            agent_server.CROSS_CHAT_EVENT_TYPE_CACHE = agent_server.OrderedDict()
            await agent_server.CROSS_CHAT.initialize()
            try:
                stale, _created = await agent_server.CROSS_CHAT.create_instruction(
                    envelope_id="handoff_terminal_race",
                    source_session_id="source-private-id",
                    source_run_id="run_source",
                    target_session_id="target-private-id",
                    body="already cancelled",
                    idempotency_key="terminal-race-key",
                )
                await agent_server.CROSS_CHAT.update(
                    str(stale["id"]),
                    expected={"ready"},
                    status="cancelled",
                )
                with (
                    patch.object(
                        agent_server.STORE,
                        "sessions",
                        {"target-private-id": self.sessions["target-private-id"]},
                    ),
                    self.assertRaises(HTTPException),
                ):
                    await agent_server.submit_cross_chat_delivery(stale)
                refreshed = await agent_server.CROSS_CHAT.get(str(stale["id"]))
                self.assertEqual(refreshed["status"], "cancelled")
            finally:
                agent_server.CROSS_CHAT = original_cross_chat
                agent_server.CROSS_CHAT_EVENT_TYPE_CACHE = original_cache

    def test_capability_advertises_new_mention_contract(self) -> None:
        with (
            patch.object(agent_server, "AGENT_TOKEN", "token"),
            patch.object(
                agent_server,
                "cross_chat_supported_target_backends",
                return_value=[agent_server.BACKEND_CODEX],
            ),
        ):
            capability = agent_server.cross_chat_handoffs_capability()
        self.assertEqual(capability["version"], 12)
        self.assertEqual(capability["default_action"], "route")
        self.assertNotIn("direct_message", capability["actions"])
        self.assertIn("route", capability["actions"])
        self.assertTrue(capability["features"]["route_hint_mentions"])
        self.assertFalse(capability["features"]["direct_message_mentions"])
        self.assertTrue(capability["features"]["durable_route_grants"])
        self.assertTrue(capability["features"]["agent_cross_chat_routes"])
        self.assertTrue(
            capability["features"]["configured_route_async_request_reply"]
        )
        self.assertTrue(
            capability["features"]["live_same_server_request_reply"]
        )
        self.assertFalse(
            capability["features"]["agent_ambient_local_handoffs"]
        )
        self.assertEqual(capability["agent_routes"]["policy"], "default_deny")
        self.assertTrue(capability["agent_routes"]["same_server_only"])
        self.assertEqual(
            capability["agent_routes"]["client_capability"],
            "agent_cross_chat_routes_v2",
        )


if __name__ == "__main__":
    unittest.main()
