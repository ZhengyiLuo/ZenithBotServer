import asyncio
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from starlette.requests import Request

import agent_server


class ProviderJobsAccessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.original_sessions = agent_server.STORE.sessions
        self.original_current_turns = agent_server.CURRENT_TURNS
        self.original_authority_root = agent_server.CROSS_CHAT_AUTHORITY_ROOT
        self.original_agent_token = agent_server.AGENT_TOKEN
        self.original_jobs = agent_server.JOBS.jobs
        self.original_lifecycle_locks = agent_server.SESSION_LIFECYCLE_LOCKS
        agent_server.STORE.sessions = {
            "source": {
                "id": "source",
                "title": "Source",
                "backend": "codex",
                "provider_jobs_access": "full",
            },
        }
        agent_server.CURRENT_TURNS = {}
        agent_server.CROSS_CHAT_AUTHORITY_ROOT = self.root / "authority"
        agent_server.CROSS_CHAT_CAPABILITIES.clear()
        agent_server.AGENT_TOKEN = "test-admin-token"
        agent_server.JOBS.jobs = {}
        agent_server.SESSION_LIFECYCLE_LOCKS = {}

    async def asyncTearDown(self) -> None:
        agent_server.CROSS_CHAT_CAPABILITIES.clear()
        agent_server.STORE.sessions = self.original_sessions
        agent_server.CURRENT_TURNS = self.original_current_turns
        agent_server.CROSS_CHAT_AUTHORITY_ROOT = self.original_authority_root
        agent_server.AGENT_TOKEN = self.original_agent_token
        agent_server.JOBS.jobs = self.original_jobs
        agent_server.SESSION_LIFECYCLE_LOCKS = self.original_lifecycle_locks
        self.temporary.cleanup()

    @staticmethod
    def provider_request(token: str, method: str = "GET") -> Request:
        return Request({
            "type": "http",
            "method": method,
            "path": "/api/agent/sessions/source/jobs",
            "headers": [
                (b"x-agentsdock-provider-capability", token.encode("utf-8")),
            ],
            "query_string": b"",
            "scheme": "http",
            "server": ("127.0.0.1", 7850),
            "client": ("127.0.0.1", 41000),
        })

    async def issue(
        self,
        mode: str,
        run_id: str,
        *,
        provider_route_snapshot: list[dict] | None = None,
    ) -> tuple[str, dict]:
        agent_server.STORE.sessions["source"]["provider_jobs_access"] = mode
        authority_path = await agent_server.issue_cross_chat_capability(
            "source",
            run_id,
            [],
            actions=(
                {
                    "jobs",
                    "publish",
                    "emergency",
                    "cross_chat_instruction",
                    "cross_chat_request_reply",
                    "agent_cross_chat_routes",
                }
                if provider_route_snapshot
                else None
            ),
            provider_route_snapshot=provider_route_snapshot,
        )
        payload = json.loads(authority_path.read_text(encoding="utf-8"))
        token = payload["provider_capability"]
        token_hash = agent_server.hashlib.sha256(token.encode("utf-8")).hexdigest()
        return token, agent_server.CROSS_CHAT_CAPABILITIES[token_hash]

    async def issue_with_target(
        self,
        run_id: str,
        *,
        target_id: str = "target",
        target_title: str = "Target",
        route_actions: list[str] | None = None,
    ) -> tuple[str, dict, dict]:
        agent_server.STORE.sessions[target_id] = {
            "id": target_id,
            "title": target_title,
            "backend": agent_server.BACKEND_CODEX,
        }
        timestamp = agent_server.now_iso()
        route = {
            "route_id": "route_" + "a" * 32,
            "revision": "rev_" + "b" * 32,
            "alias": "target",
            "target_session_id": target_id,
            "actions": list(route_actions or ["instruction", "request_reply"]),
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        agent_server.STORE.sessions["source"][
            "provider_cross_chat_routes"
        ] = [dict(route)]
        routes = agent_server.provider_cross_chat_routes(
            agent_server.STORE.sessions["source"]
        )
        token, capability = await self.issue(
            "full",
            run_id,
            provider_route_snapshot=routes,
        )
        agent_server.CURRENT_TURNS = {
            "source": {"run_id": run_id},
        }
        return token, capability, route

    async def test_session_policy_defaults_persists_updates_and_validates(self) -> None:
        store = agent_server.SessionStore()
        sessions_path = self.root / "sessions.json"
        with (
            patch.object(agent_server, "SESSIONS_FILE", sessions_path),
            patch.object(agent_server, "ensure_dirs"),
            patch.object(agent_server, "append_event", new_callable=AsyncMock),
        ):
            created = await store.create(
                agent_server.CreateSessionRequest(title="Policy chat"),
            )
            self.assertEqual(created["provider_jobs_access"], "full")
            persisted = json.loads(sessions_path.read_text(encoding="utf-8"))
            self.assertEqual(
                persisted[created["id"]]["provider_jobs_access"],
                "full",
            )

            updated = await store.update(
                created["id"],
                {"provider_jobs_access": "read_only"},
            )
            self.assertEqual(updated["provider_jobs_access"], "read_only")
            persisted = json.loads(sessions_path.read_text(encoding="utf-8"))
            self.assertEqual(
                persisted[created["id"]]["provider_jobs_access"],
                "read_only",
            )

            with self.assertRaises(HTTPException) as raised:
                await store.update(
                    created["id"],
                    {"provider_jobs_access": "unexpected"},
                )
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(
            agent_server.effective_provider_jobs_access({}),
            "full",
        )
        self.assertEqual(
            agent_server.public_session({"id": "legacy"})["provider_jobs_access"],
            "full",
        )
        with self.assertRaises(ValueError):
            agent_server.UpdateSessionRequest(provider_jobs_access="unexpected")

    async def test_legacy_session_load_migrates_default_policy_durably(self) -> None:
        sessions_path = self.root / "legacy-sessions.json"
        sessions_path.write_text(json.dumps({
            "legacy": {
                "id": "legacy",
                "title": "Legacy",
                "backend": "claude",
                "cwd": "/tmp",
            },
        }), encoding="utf-8")
        store = agent_server.SessionStore()
        with (
            patch.object(agent_server, "SESSIONS_FILE", sessions_path),
            patch.object(agent_server, "ensure_dirs"),
            patch.object(
                agent_server,
                "read_abandoned_fork_thread_ids",
                return_value=set(),
            ),
            patch.object(agent_server, "rebuild_codex_subagent_indexes"),
        ):
            await store.load()

        self.assertEqual(
            store.sessions["legacy"]["provider_jobs_access"],
            "full",
        )
        persisted = json.loads(sessions_path.read_text(encoding="utf-8"))
        self.assertEqual(
            persisted["legacy"]["provider_jobs_access"],
            "full",
        )

    async def test_failed_policy_save_restores_previous_authorization(self) -> None:
        store = agent_server.SessionStore()
        store.sessions = {
            "source": {
                "id": "source",
                "backend": "codex",
                "provider_jobs_access": "blocked",
            },
        }
        with patch.object(
            store,
            "save",
            AsyncMock(side_effect=OSError("disk unavailable")),
        ):
            with self.assertRaises(OSError):
                await store.update(
                    "source",
                    {"provider_jobs_access": "full"},
                )
        self.assertEqual(
            store.sessions["source"]["provider_jobs_access"],
            "blocked",
        )

    async def test_cancelled_policy_expansion_is_rolled_back_on_disk(self) -> None:
        store = agent_server.SessionStore()
        store.sessions = {
            "source": {
                "id": "source",
                "backend": "codex",
                "provider_jobs_access": "blocked",
            },
        }
        sessions_path = self.root / "cancelled-policy-sessions.json"
        first_write_started = threading.Event()
        release_first_write = threading.Event()
        written_policies: list[str] = []
        real_write = agent_server.write_sessions_json_text

        def blocked_write(
            path: Path,
            text: str,
            *,
            durable: bool,
        ) -> None:
            policy = json.loads(text)["source"]["provider_jobs_access"]
            written_policies.append(policy)
            if len(written_policies) == 1:
                first_write_started.set()
                self.assertTrue(release_first_write.wait(timeout=2))
            real_write(path, text, durable=durable)

        with (
            patch.object(agent_server, "SESSIONS_FILE", sessions_path),
            patch.object(agent_server, "ensure_dirs"),
            patch.object(
                agent_server,
                "write_sessions_json_text",
                side_effect=blocked_write,
            ),
        ):
            update_task = asyncio.create_task(store.update(
                "source",
                {"provider_jobs_access": "full"},
            ))
            try:
                self.assertTrue(
                    await asyncio.to_thread(first_write_started.wait, 1)
                )
                update_task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(update_task.done())
                # A second cancellation must not interrupt the rollback join.
                update_task.cancel()
            finally:
                release_first_write.set()
            with self.assertRaises(asyncio.CancelledError):
                await update_task
            await store.flush_pending_save()

        self.assertEqual(written_policies, ["full", "blocked"])
        self.assertEqual(
            store.sessions["source"]["provider_jobs_access"],
            "blocked",
        )
        persisted = json.loads(sessions_path.read_text(encoding="utf-8"))
        self.assertEqual(
            persisted["source"]["provider_jobs_access"],
            "blocked",
        )

    def test_standalone_scheduled_context_inherits_provider_jobs_policy(self) -> None:
        isolated = agent_server.standalone_provider_session({
            "id": "source",
            "backend": "codex",
            "provider_jobs_access": "read_only",
            "codex_thread_id": "thread-parent",
        })
        self.assertEqual(isolated["provider_jobs_access"], "read_only")
        self.assertIsNone(isolated["codex_thread_id"])

    async def test_health_advertises_versioned_policy_contract(self) -> None:
        with patch.object(
            agent_server,
            "tmux_capability",
            return_value={
                "available": False,
                "required": False,
                "message": "tmux unavailable",
                "action": None,
            },
        ):
            response = await agent_server.health()
        self.assertEqual(response["api_contract_version"], 27)
        self.assertEqual(
            response["capabilities"]["provider_jobs_access_control_v1"],
            {
                "available": True,
                "required": False,
                "message": "Per-chat provider scheduled-jobs access control is available.",
                "action": None,
                "version": 1,
                "modes": ["full", "read_only", "blocked"],
                "default": "full",
            },
        )

    async def test_capability_issuance_is_bounded_by_policy(self) -> None:
        _full_token, full = await self.issue("full", "run_full")
        self.assertIn("jobs", full["actions"])
        self.assertEqual(full["provider_jobs_access"], "full")

        _read_token, read_only = await self.issue("read_only", "run_read")
        self.assertIn("jobs", read_only["actions"])
        self.assertEqual(read_only["provider_jobs_access"], "read_only")

        _blocked_token, blocked = await self.issue("blocked", "run_blocked")
        self.assertNotIn("jobs", blocked["actions"])
        self.assertEqual(blocked["provider_jobs_access"], "blocked")

    def test_internal_handoff_jobs_follow_target_policy_not_route_authority(self) -> None:
        self.assertTrue(
            agent_server.provider_turn_may_manage_jobs(
                "cross_chat_handoff_delivery",
                cross_chat_delivery_kind="instruction",
            )
        )
        self.assertTrue(
            agent_server.provider_turn_may_manage_jobs(
                "cross_chat_handoff_delivery",
                cross_chat_delivery_kind="request",
            )
        )
        for kind in ("reply", "final_result", "status", None):
            with self.subTest(kind=kind):
                self.assertFalse(
                    agent_server.provider_turn_may_manage_jobs(
                        "cross_chat_handoff_delivery",
                        cross_chat_delivery_kind=kind,
                    )
                )
        self.assertTrue(agent_server.provider_turn_may_manage_jobs(None))
        self.assertFalse(
            agent_server.provider_turn_may_manage_jobs(
                "secure_peer_handoff_delivery"
            )
        )

        relay = agent_server.cross_chat_delivery_prompt(
            {
                "id": "handoff_policy",
                "source_session_id": "source",
                "source_run_id": "run_source",
                "target_session_id": "target",
                "authorization_route_id": "route_source",
                "authorization_kind": "configured_route",
                "kind": "instruction",
                "body": "Create the requested local cron.",
            },
            "Source",
        )
        # Context diet: the jobs guidance is static and now lives once in the
        # thread-level delivery instructions instead of every relay prompt.
        self.assertIn("kind=instruction leg=1/1 origin=route", relay)
        self.assertIn(
            "Handoff or reply authorization governs cross-chat contact only",
            agent_server.CROSS_CHAT_DELIVERY_INSTRUCTIONS,
        )
        self.assertIn(
            "route-free scheduled job",
            agent_server.CROSS_CHAT_DELIVERY_INSTRUCTIONS,
        )
        self.assertIn(
            "user or an authorized same-server handoff explicitly asks",
            agent_server.SCHEDULED_JOBS_PROMPT,
        )

        final_result = agent_server.cross_chat_delivery_prompt(
            {
                "id": "handoff_result",
                "source_session_id": "source",
                "source_run_id": "run_source",
                "target_session_id": "target",
                "authorization_route_id": None,
                "authorization_kind": "explicit_prompt",
                "kind": "final_result",
                "body": "Finished.",
            },
            "Source",
        )
        self.assertNotIn("route-free scheduled job", final_result)

    async def test_provider_capability_cannot_authorize_human_jobs_or_run_now(self) -> None:
        token, _capability = await self.issue("full", "run_human_bypass")
        for method, path in (
            ("GET", "/api/jobs"),
            ("POST", "/api/jobs/job_one/run"),
        ):
            request = Request({
                "type": "http",
                "method": method,
                "path": path,
                "headers": [
                    (b"x-agentsdock-provider-capability", token.encode("utf-8")),
                ],
                "query_string": b"",
                "scheme": "http",
                "server": ("127.0.0.1", 7850),
                "client": ("127.0.0.1", 41000),
            })
            call_next = AsyncMock()
            response = await agent_server.require_agent_token(request, call_next)
            self.assertEqual(response.status_code, 401)
            call_next.assert_not_awaited()

    async def test_no_auth_mode_advertises_policy_unavailable_and_omits_jobs_authority(self) -> None:
        agent_server.AGENT_TOKEN = ""
        with patch.object(
            agent_server,
            "tmux_capability",
            return_value={
                "available": False,
                "required": False,
                "message": "tmux unavailable",
                "action": None,
            },
        ):
            response = await agent_server.health()
        capability = response["capabilities"]["provider_jobs_access_control_v1"]
        self.assertFalse(capability["available"])
        self.assertIn("authenticated", capability["message"])
        authority_path = await agent_server.issue_cross_chat_capability(
            "source", "run_no_auth", []
        )
        payload = json.loads(authority_path.read_text(encoding="utf-8"))
        token_hash = agent_server.hashlib.sha256(
            payload["provider_capability"].encode("utf-8")
        ).hexdigest()
        self.assertNotIn("jobs", agent_server.CROSS_CHAT_CAPABILITIES[token_hash]["actions"])

    async def test_policy_tightening_is_immediate_during_live_turn(self) -> None:
        token, _capability = await self.issue("full", "run_live")
        agent_server.CURRENT_TURNS = {"source": {"run_id": "run_live"}}
        request = self.provider_request(token)

        await agent_server.authorize_provider_jobs_operation(
            request,
            session_id="source",
            operation="write",
        )

        async def update(_session_id: str, policy_patch: dict) -> dict:
            agent_server.STORE.sessions["source"].update(policy_patch)
            return agent_server.STORE.sessions["source"]

        with patch.object(
            agent_server.STORE,
            "update",
            AsyncMock(side_effect=update),
        ):
            response = await agent_server.update_session(
                "source",
                agent_server.UpdateSessionRequest(
                    provider_jobs_access="read_only",
                ),
            )
            self.assertEqual(
                response["session"]["provider_jobs_access"],
                "read_only",
            )
            await agent_server.authorize_provider_jobs_operation(
                request,
                session_id="source",
                operation="read",
            )
            with self.assertRaises(HTTPException) as raised:
                await agent_server.authorize_provider_jobs_operation(
                    request,
                    session_id="source",
                    operation="write",
                )
            self.assertEqual(raised.exception.status_code, 403)
            self.assertIn("read-only", str(raised.exception.detail))

            await agent_server.update_session(
                "source",
                agent_server.UpdateSessionRequest(
                    provider_jobs_access="blocked",
                ),
            )
            with self.assertRaises(HTTPException) as raised:
                await agent_server.authorize_provider_jobs_operation(
                    request,
                    session_id="source",
                    operation="read",
                )
            self.assertEqual(raised.exception.status_code, 403)
            self.assertIn("blocked", str(raised.exception.detail))

    async def test_issue_time_read_only_ceiling_cannot_be_loosened_mid_turn(self) -> None:
        token, _capability = await self.issue("read_only", "run_read_live")
        agent_server.CURRENT_TURNS = {
            "source": {"run_id": "run_read_live"},
        }
        agent_server.STORE.sessions["source"]["provider_jobs_access"] = "full"
        request = self.provider_request(token)
        await agent_server.authorize_provider_jobs_operation(
            request,
            session_id="source",
            operation="read",
        )
        with self.assertRaises(HTTPException) as raised:
            await agent_server.authorize_provider_jobs_operation(
                request,
                session_id="source",
                operation="write",
            )
        self.assertEqual(raised.exception.status_code, 403)

    async def test_policy_patch_serializes_with_live_agent_job_mutation(self) -> None:
        token, _capability = await self.issue("full", "run_policy_race")
        agent_server.CURRENT_TURNS = {
            "source": {"run_id": "run_policy_race"},
        }
        request = self.provider_request(token, method="POST")
        update_entered = agent_server.asyncio.Event()
        allow_update = agent_server.asyncio.Event()

        async def gated_update(_session_id: str, policy_patch: dict) -> dict:
            update_entered.set()
            await allow_update.wait()
            agent_server.STORE.sessions["source"].update(policy_patch)
            return agent_server.STORE.sessions["source"]

        create = AsyncMock(return_value={})
        with (
            patch.object(
                agent_server.STORE,
                "update",
                AsyncMock(side_effect=gated_update),
            ),
            patch.object(agent_server.JOBS, "create", create),
        ):
            update_task = agent_server.asyncio.create_task(
                agent_server.update_session(
                    "source",
                    agent_server.UpdateSessionRequest(
                        provider_jobs_access="blocked",
                    ),
                )
            )
            await update_entered.wait()
            create_task = agent_server.asyncio.create_task(
                agent_server.create_agent_session_job(
                    request,
                    "source",
                    agent_server.AgentCreateScopedJobRequest(
                        title="Must not race",
                        prompt="Run",
                        interval_seconds=60,
                    ),
                )
            )
            await agent_server.asyncio.sleep(0)
            self.assertFalse(create_task.done())
            allow_update.set()
            await update_task
            with self.assertRaises(HTTPException) as raised:
                await create_task

        self.assertEqual(raised.exception.status_code, 403)
        create.assert_not_awaited()

    async def test_every_agent_jobs_route_declares_read_or_write_policy(self) -> None:
        request = self.provider_request("unused")
        authorize = AsyncMock(return_value={})
        with (
            patch.object(
                agent_server,
                "authorize_provider_jobs_operation",
                authorize,
            ),
            patch.object(
                agent_server,
                "list_session_jobs",
                AsyncMock(return_value={"jobs": []}),
            ),
            patch.object(
                agent_server,
                "get_session_job_runs",
                AsyncMock(return_value={"runs": []}),
            ),
            patch.object(agent_server.JOBS, "create", AsyncMock(return_value={})),
            patch.object(agent_server.JOBS, "update", AsyncMock(return_value={})),
            patch.object(agent_server.JOBS, "delete", AsyncMock(return_value=True)),
        ):
            await agent_server.list_agent_session_jobs(request, "source")
            await agent_server.get_agent_session_job_runs(
                request,
                "source",
                "job_1",
                before_seq=None,
                limit=20,
            )
            await agent_server.create_agent_session_job(
                request,
                "source",
                agent_server.AgentCreateScopedJobRequest(
                    title="Create",
                    prompt="Run",
                    interval_seconds=60,
                ),
            )
            await agent_server.update_agent_session_job(
                request,
                "source",
                "job_1",
                agent_server.AgentUpdateJobRequest(enabled=False),
            )
            await agent_server.delete_agent_session_job(
                request,
                "source",
                "job_1",
            )

        self.assertEqual(
            [call.kwargs["operation"] for call in authorize.await_args_list],
            ["read", "read", "write", "write", "write"],
        )

    async def test_agent_job_projections_hide_internal_chat_reference_ids(self) -> None:
        secret_target_id = "internal-target-session-secret"
        token, _capability = await self.issue("full", "run_projection")
        agent_server.CURRENT_TURNS = {
            "source": {"run_id": "run_projection"},
        }
        direct_reference = agent_server.ChatReference(
            session_id=secret_target_id,
            display_title_snapshot=f"Mobile {secret_target_id}",
            source_text_start=0,
            source_text_end=len(f"@Mobile {secret_target_id}"),
            action="direct_message",
        )
        route_reference = agent_server.ChatReference(
            session_id="second-internal-target-session-secret",
            display_title_snapshot="Ops",
            source_text_start=18,
            source_text_end=23,
            action="route",
        )
        raw_job = {
            "id": "job_secret_target",
            "session_id": "source",
            "title": "Routed job",
            "prompt": f"@Mobile {secret_target_id} check now",
            "chat_references": [
                direct_reference.model_dump(),
                route_reference.model_dump(),
            ],
            "schedule_kind": "interval",
            "interval_seconds": 300,
            "timezone": "UTC",
            "loop": True,
            "enabled": True,
            "updated_at": "2026-08-26T00:00:00Z",
        }
        agent_server.JOBS.jobs[raw_job["id"]] = raw_job

        listed = await agent_server.list_agent_session_jobs(
            self.provider_request(token),
            "source",
        )
        with (
            patch.object(
                agent_server.JOBS,
                "create",
                AsyncMock(return_value=raw_job),
            ),
            patch.object(
                agent_server.JOBS,
                "update",
                AsyncMock(return_value=raw_job),
            ),
            patch.object(
                agent_server,
                "append_provider_job_mutation_event",
                new_callable=AsyncMock,
            ),
        ):
            created = await agent_server.create_agent_session_job(
                self.provider_request(token, method="POST"),
                "source",
                agent_server.AgentCreateScopedJobRequest(
                    title="Routed job",
                    prompt="Run",
                    interval_seconds=300,
                ),
            )
            updated = await agent_server.update_agent_session_job(
                self.provider_request(token, method="PATCH"),
                "source",
                raw_job["id"],
                agent_server.AgentUpdateJobRequest(title="Renamed"),
            )

        projections = [listed["jobs"][0], created["job"], updated["job"]]
        for projection in projections:
            with self.subTest(projection=projection):
                self.assertNotIn("chat_references", projection)
                self.assertNotIn(secret_target_id, json.dumps(projection))
                self.assertEqual(projection["chat_target_count"], 2)
                self.assertEqual(projection["chat_targets"], [
                    {
                        "display_title_snapshot": "Saved chat target",
                        "action": "direct_message",
                    },
                    {
                        "display_title_snapshot": "Ops",
                        "action": "route",
                    },
                ])

    async def test_agent_job_runs_hide_target_ids_in_running_and_error_events(self) -> None:
        secret_target_id = "internal-target-session-secret"
        field_only_target_id = "field-only-target-session-secret"
        envelope_id = "handoff_private_scheduled_delivery"
        exchange_id = "exchange_private_scheduled_delivery"
        leg_id = "leg_private_scheduled_delivery"
        token, _capability = await self.issue("read_only", "run_history_projection")
        agent_server.CURRENT_TURNS = {
            "source": {"run_id": "run_history_projection"},
        }
        reference = agent_server.ChatReference(
            session_id=secret_target_id,
            display_title_snapshot="Mobile",
            source_text_start=0,
            source_text_end=7,
            action="direct_message",
        ).model_dump()
        raw_job = {
            "id": "job_secret_target",
            "session_id": "source",
            "title": "Routed job",
            "prompt": "@Mobile check now",
            "chat_references": [reference],
            "schedule_kind": "interval",
            "interval_seconds": 300,
            "timezone": "UTC",
        }
        raw_response = {
            "session_id": "source",
            "job_id": raw_job["id"],
            "runs": [
                {
                    "type": "turn_started",
                    "job_id": raw_job["id"],
                    "chat_references": [reference],
                    "target_session_id": secret_target_id,
                    "cross_chat_envelope_id": envelope_id,
                    "cross_chat_exchange_ids": [exchange_id],
                    "cross_chat_direct_message_ids": [envelope_id],
                    "delivery": {
                        "id": leg_id,
                        "parent_leg_id": leg_id,
                    },
                    "message": (
                        f"Started {envelope_id} / {exchange_id} / {leg_id}"
                    ),
                    "job_status": "running",
                },
                {
                    "type": "job_deferred",
                    "job_id": raw_job["id"],
                    "job": raw_job,
                    "message": f"Deferred target {secret_target_id}",
                    "job_status": "deferred",
                },
                {
                    "type": "job_error",
                    "job_id": raw_job["id"],
                    "target_session_id": field_only_target_id,
                    "error": f"Could not reach {field_only_target_id}",
                    "job_status": "failed",
                },
            ],
            "total": 3,
        }

        with patch.object(
            agent_server,
            "get_session_job_runs",
            AsyncMock(return_value=raw_response),
        ):
            response = await agent_server.get_agent_session_job_runs(
                self.provider_request(token),
                "source",
                raw_job["id"],
                before_seq=None,
                limit=20,
            )

        self.assertEqual(response["total"], 3)
        self.assertNotIn(secret_target_id, json.dumps(response))
        self.assertNotIn(field_only_target_id, json.dumps(response))
        for private_id in (envelope_id, exchange_id, leg_id):
            self.assertNotIn(private_id, json.dumps(response))
        for run in response["runs"]:
            with self.subTest(run=run):
                self.assertNotIn("chat_references", run)
                self.assertNotIn("target_session_id", run)
                self.assertNotIn("cross_chat_envelope_id", run)
                self.assertNotIn("cross_chat_exchange_ids", run)
                self.assertNotIn("cross_chat_direct_message_ids", run)
        self.assertEqual(response["runs"][0]["chat_target_count"], 1)
        self.assertEqual(response["runs"][0]["chat_targets"], [{
            "display_title_snapshot": "Mobile",
            "action": "direct_message",
        }])
        for run in response["runs"][1:2]:
            self.assertNotIn("chat_references", run["job"])
            self.assertEqual(run["job"]["chat_target_count"], 1)
            self.assertEqual(run["job"]["chat_targets"], [{
                "display_title_snapshot": "Mobile",
                "action": "direct_message",
            }])

    def test_agent_job_models_accept_opaque_chat_route_selections(self) -> None:
        route_id = "route_" + "a" * 32
        create = agent_server.AgentCreateScopedJobRequest(
            title="Escalate",
            prompt="@Target do work",
            interval_seconds=300,
            chat_routes=[{
                "route_id": route_id,
                "action": "request_reply",
            }],
        )
        update = agent_server.AgentUpdateJobRequest(
            chat_routes=[{
                "route_id": route_id,
                "action": "instruction",
            }],
        )

        self.assertEqual(create.chat_routes[0].route_id, route_id)
        self.assertEqual(create.chat_routes[0].action, "request_reply")
        self.assertEqual(update.chat_routes[0].route_id, route_id)
        self.assertEqual(update.chat_routes[0].action, "instruction")

    async def test_provider_create_resolves_current_durable_route_to_exact_reference(self) -> None:
        token, _capability, route = await self.issue_with_target(
            "run_job_route_create",
            target_title="Mobile 📱",
        )
        request = self.provider_request(token, method="POST")
        prompt = "Before 🧪 @Mobile 📱 investigate"
        marker = "@Mobile 📱"
        marker_start = prompt.index(marker)
        create = AsyncMock(return_value={
            "id": "job_routed",
            "session_id": "source",
        })

        with (
            patch.object(agent_server.JOBS, "create", create),
            patch.object(
                agent_server,
                "append_provider_job_route_conversion_event",
                new_callable=AsyncMock,
            ),
        ):
            response = await agent_server.create_agent_session_job(
                request,
                "source",
                agent_server.AgentCreateScopedJobRequest(
                    title="Escalate",
                    prompt=prompt,
                    interval_seconds=300,
                    chat_routes=[{
                        "route_id": route["route_id"],
                        "action": "instruction",
                    }],
                ),
            )

        self.assertEqual(response["job"]["id"], "job_routed")
        create.assert_awaited_once()
        forwarded = create.await_args.args[0]
        self.assertIsInstance(forwarded, agent_server.CreateJobRequest)
        self.assertNotIn("chat_routes", forwarded.model_dump())
        self.assertEqual(len(forwarded.chat_references), 1)
        reference = forwarded.chat_references[0]
        self.assertEqual(reference.session_id, "target")
        self.assertEqual(reference.display_title_snapshot, "Mobile 📱")
        self.assertEqual(reference.action, "route")
        self.assertEqual(reference.route_action, "instruction")
        self.assertEqual(
            reference.source_text_start,
            agent_server.utf16_length(prompt[:marker_start]),
        )
        self.assertEqual(
            reference.source_text_end,
            agent_server.utf16_length(prompt[:marker_start + len(marker)]),
        )
        # Saving a route is an action-preserving conversion, not a future
        # authorization upgrade. Even if the source's durable grant offers
        # Ask, this exact per-job target remains instruction-only.
        snapshot = agent_server.provider_cross_chat_route_snapshot_for_authority(
            agent_server.provider_cross_chat_routes(
                agent_server.STORE.sessions["source"]
            ),
            [reference],
            source_session_id="source",
            per_job_reference_routes=True,
        )
        target_routes = [
            item
            for item in snapshot
            if item.get("target_session_id") == "target"
        ]
        self.assertEqual(len(target_routes), 1)
        self.assertEqual(
            target_routes[0]["route_kind"],
            agent_server.PROVIDER_CROSS_CHAT_ROUTE_KIND_REFERENCE,
        )
        self.assertEqual(target_routes[0]["actions"], ["instruction"])

    async def test_provider_job_routes_reject_raw_references(self) -> None:
        token, _capability, _route = await self.issue_with_target(
            "run_job_route_raw",
        )
        request = self.provider_request(token, method="POST")
        reference = agent_server.ChatReference(
            session_id="target",
            display_title_snapshot="Target",
            source_text_start=0,
            source_text_end=7,
            action="instruction",
        )
        agent_server.JOBS.jobs["job_existing"] = self.routed_job(reference)
        create = AsyncMock(return_value={})
        update = AsyncMock(return_value={})

        with (
            patch.object(agent_server.JOBS, "create", create),
            patch.object(agent_server.JOBS, "update", update),
        ):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.create_agent_session_job(
                    request,
                    "source",
                    agent_server.AgentCreateScopedJobRequest(
                        title="Escalate",
                        prompt="@Target do work",
                        chat_references=[reference],
                    ),
                )
            self.assertEqual(raised.exception.status_code, 403)

            # Even an explicitly empty raw list is not the provider revocation
            # contract; providers must use chat_routes=[] so the server can
            # distinguish a deliberate revoke from a forged durable reference.
            with self.assertRaises(HTTPException) as raised:
                await agent_server.update_agent_session_job(
                    request,
                    "source",
                    "job_existing",
                    agent_server.AgentUpdateJobRequest(chat_references=[]),
                )
            self.assertEqual(raised.exception.status_code, 403)

        create.assert_not_awaited()
        update.assert_not_awaited()

    async def test_provider_job_route_must_be_current_live_and_authorized(self) -> None:
        create = AsyncMock(return_value={})

        token, _capability, route = await self.issue_with_target(
            "run_job_route_unknown",
        )
        with (
            patch.object(agent_server.JOBS, "create", create),
            self.assertRaises(HTTPException) as raised,
        ):
            await agent_server.create_agent_session_job(
                self.provider_request(token, method="POST"),
                "source",
                agent_server.AgentCreateScopedJobRequest(
                    title="Unknown",
                    prompt="@Target do work",
                    chat_routes=[{
                        "route_id": "route_" + "f" * 32,
                        "action": "instruction",
                    }],
                ),
            )
        self.assertEqual(raised.exception.status_code, 409)

        token, _capability, route = await self.issue_with_target(
            "run_job_route_stale",
        )
        agent_server.STORE.sessions["target"]["archived"] = True
        with (
            patch.object(agent_server.JOBS, "create", create),
            self.assertRaises(HTTPException) as raised,
        ):
            await agent_server.create_agent_session_job(
                self.provider_request(token, method="POST"),
                "source",
                agent_server.AgentCreateScopedJobRequest(
                    title="Stale",
                    prompt="@Target do work",
                    chat_routes=[{
                        "route_id": route["route_id"],
                        "action": "instruction",
                    }],
                ),
            )
        self.assertEqual(raised.exception.status_code, 409)

        token, _capability, route = await self.issue_with_target(
            "run_job_route_action",
            route_actions=["instruction"],
        )
        with (
            patch.object(agent_server.JOBS, "create", create),
            self.assertRaises(HTTPException) as raised,
        ):
            await agent_server.create_agent_session_job(
                self.provider_request(token, method="POST"),
                "source",
                agent_server.AgentCreateScopedJobRequest(
                    title="Wrong action",
                    prompt="@Target do work",
                    chat_routes=[{
                        "route_id": route["route_id"],
                        "action": "request_reply",
                    }],
                ),
            )
        self.assertEqual(raised.exception.status_code, 403)
        create.assert_not_awaited()

    async def test_provider_job_route_requires_exact_prompt_mention(self) -> None:
        token, _capability, route = await self.issue_with_target(
            "run_job_route_missing_mention",
        )
        create = AsyncMock(return_value={})
        with (
            patch.object(agent_server.JOBS, "create", create),
            self.assertRaises(HTTPException) as raised,
        ):
            await agent_server.create_agent_session_job(
                self.provider_request(token, method="POST"),
                "source",
                agent_server.AgentCreateScopedJobRequest(
                    title="Missing mention",
                    prompt="Ask the target to investigate",
                    chat_routes=[{
                        "route_id": route["route_id"],
                        "action": "instruction",
                    }],
                ),
            )
        self.assertEqual(raised.exception.status_code, 400)
        create.assert_not_awaited()

    async def test_provider_job_route_accepts_configured_durable_grant(self) -> None:
        agent_server.STORE.sessions["target"] = {
            "id": "target",
            "title": "Target",
            "backend": agent_server.BACKEND_CODEX,
        }
        route = {
            "route_id": "route_" + "b" * 32,
            "revision": "rev_" + "c" * 32,
            "alias": "target",
            "target_session_id": "target",
            "actions": ["instruction"],
        }
        agent_server.STORE.sessions["source"]["provider_cross_chat_routes"] = [route]
        token, _capability = await self.issue(
            "full",
            "run_job_configured_route",
            provider_route_snapshot=[route],
        )
        agent_server.CURRENT_TURNS = {
            "source": {"run_id": "run_job_configured_route"},
        }
        create = AsyncMock(return_value={
            "id": "job_configured_route",
            "session_id": "source",
        })
        with patch.object(agent_server.JOBS, "create", create):
            response = await agent_server.create_agent_session_job(
                self.provider_request(token, method="POST"),
                "source",
                agent_server.AgentCreateScopedJobRequest(
                    title="Configured route",
                    prompt="@Target do work",
                    chat_routes=[{
                        "route_id": route["route_id"],
                        "action": "instruction",
                    }],
                ),
            )
        self.assertEqual(response["job"]["id"], "job_configured_route")
        create.assert_awaited_once()
        reference = create.await_args.args[0].chat_references[0]
        self.assertEqual(reference.session_id, "target")
        self.assertEqual(reference.route_action, "instruction")

    async def test_provider_job_route_can_be_converted_only_once(self) -> None:
        token, _capability, route = await self.issue_with_target(
            "run_job_route_once",
        )
        request = self.provider_request(token, method="POST")
        create = AsyncMock(return_value={
            "id": "job_routed",
            "session_id": "source",
        })
        req = agent_server.AgentCreateScopedJobRequest(
            title="Escalate",
            prompt="@Target do work",
            interval_seconds=300,
            chat_routes=[{
                "route_id": route["route_id"],
                "action": "instruction",
            }],
        )
        with (
            patch.object(agent_server.JOBS, "create", create),
            patch.object(
                agent_server,
                "append_provider_job_route_conversion_event",
                new_callable=AsyncMock,
            ),
        ):
            await agent_server.create_agent_session_job(request, "source", req)
            with self.assertRaises(HTTPException) as raised:
                await agent_server.create_agent_session_job(request, "source", req)

        self.assertEqual(raised.exception.status_code, 403)
        create.assert_awaited_once()

    async def test_failed_create_removes_job_before_refunding_route(self) -> None:
        token, capability, route = await self.issue_with_target(
            "run_job_route_create_failure",
        )
        request = self.provider_request(token, method="POST")
        req = agent_server.AgentCreateScopedJobRequest(
            title="Retry safe route",
            prompt="@Target do work",
            interval_seconds=300,
            chat_routes=[{
                "route_id": route["route_id"],
                "action": "instruction",
            }],
        )

        with (
            patch.object(
                agent_server.JOBS,
                "save",
                AsyncMock(side_effect=[OSError("disk full"), None]),
            ),
            patch.object(
                agent_server,
                "append_provider_job_mutation_event",
                new_callable=AsyncMock,
            ),
            patch.object(
                agent_server,
                "append_provider_job_route_conversion_event",
                new_callable=AsyncMock,
            ),
        ):
            with self.assertRaisesRegex(OSError, "disk full"):
                await agent_server.create_agent_session_job(
                    request,
                    "source",
                    req,
                )

            self.assertEqual(agent_server.JOBS.jobs, {})
            self.assertEqual(capability["provider_route_handoff_count"], 0)
            self.assertNotIn(
                route["route_id"],
                capability["provider_job_route_conversions"],
            )

            response = await agent_server.create_agent_session_job(
                request,
                "source",
                req,
            )

        self.assertEqual(len(agent_server.JOBS.jobs), 1)
        self.assertEqual(response["job"]["chat_target_count"], 1)
        self.assertEqual(capability["provider_route_handoff_count"], 1)
        self.assertIn(
            route["route_id"],
            capability["provider_job_route_conversions"],
        )

    async def test_committed_route_conversion_survives_event_failure(self) -> None:
        token, capability, route = await self.issue_with_target(
            "run_job_route_event_failure",
        )
        request = self.provider_request(token, method="POST")
        reference = agent_server.ChatReference(
            session_id="target",
            display_title_snapshot="Target",
            source_text_start=0,
            source_text_end=7,
            action="instruction",
        )
        committed_job = self.routed_job(reference)
        committed_job["id"] = "job_committed"
        create = AsyncMock(return_value=committed_job)
        req = agent_server.AgentCreateScopedJobRequest(
            title="Committed route",
            prompt="@Target do work",
            interval_seconds=300,
            chat_routes=[{
                "route_id": route["route_id"],
                "action": "instruction",
            }],
        )

        with (
            patch.object(agent_server.JOBS, "create", create),
            patch.object(
                agent_server,
                "append_event",
                AsyncMock(side_effect=OSError("timeline unavailable")),
            ),
        ):
            response = await agent_server.create_agent_session_job(
                request,
                "source",
                req,
            )
            with self.assertRaises(HTTPException) as raised:
                await agent_server.create_agent_session_job(
                    request,
                    "source",
                    req,
                )

        self.assertEqual(response["job"]["id"], "job_committed")
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(capability["provider_route_handoff_count"], 1)
        self.assertIn(
            route["route_id"],
            capability["provider_job_route_conversions"],
        )
        create.assert_awaited_once()
        self.assertFalse(create.await_args.kwargs["emit_event"])
        self.assertTrue(
            create.await_args.kwargs["redact_chat_reference_errors"],
        )

    async def test_committed_route_conversion_cancellation_is_not_refunded(self) -> None:
        token, capability, route = await self.issue_with_target(
            "run_job_route_event_cancel",
        )
        request = self.provider_request(token, method="POST")
        reference = agent_server.ChatReference(
            session_id="target",
            display_title_snapshot="Target",
            source_text_start=0,
            source_text_end=7,
            action="instruction",
        )
        create = AsyncMock(return_value=self.routed_job(reference))
        req = agent_server.AgentCreateScopedJobRequest(
            title="Committed route",
            prompt="@Target do work",
            interval_seconds=300,
            chat_routes=[{
                "route_id": route["route_id"],
                "action": "instruction",
            }],
        )

        with (
            patch.object(agent_server.JOBS, "create", create),
            patch.object(
                agent_server,
                "append_provider_job_mutation_event",
                AsyncMock(side_effect=agent_server.asyncio.CancelledError),
            ),
        ):
            with self.assertRaises(agent_server.asyncio.CancelledError):
                await agent_server.create_agent_session_job(
                    request,
                    "source",
                    req,
                )
            with self.assertRaises(HTTPException) as raised:
                await agent_server.create_agent_session_job(
                    request,
                    "source",
                    req,
                )

        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(capability["provider_route_handoff_count"], 1)
        self.assertIn(
            route["route_id"],
            capability["provider_job_route_conversions"],
        )
        create.assert_awaited_once()

    async def test_committed_route_update_survives_event_failure(self) -> None:
        token, capability, route = await self.issue_with_target(
            "run_job_route_update_event_failure",
            target_id="replacement",
            target_title="Replacement",
        )
        old_reference = agent_server.ChatReference(
            session_id="old-target",
            display_title_snapshot="Old target",
            source_text_start=0,
            source_text_end=11,
            action="instruction",
        )
        job = self.routed_job(old_reference)
        agent_server.JOBS.jobs[job["id"]] = job
        request = self.provider_request(token, method="PATCH")
        req = agent_server.AgentUpdateJobRequest(
            prompt="@Replacement take over",
            chat_routes=[{
                "route_id": route["route_id"],
                "action": "instruction",
            }],
        )

        with (
            patch.object(agent_server.JOBS, "save", new_callable=AsyncMock),
            patch.object(
                agent_server,
                "append_event",
                AsyncMock(side_effect=OSError("timeline unavailable")),
            ),
        ):
            response = await agent_server.update_agent_session_job(
                request,
                "source",
                job["id"],
                req,
            )
            with self.assertRaises(HTTPException) as raised:
                await agent_server.update_agent_session_job(
                    request,
                    "source",
                    job["id"],
                    req,
                )

        self.assertEqual(response["job"]["id"], job["id"])
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(capability["provider_route_handoff_count"], 1)
        self.assertIn(
            route["route_id"],
            capability["provider_job_route_conversions"],
        )
        self.assertNotIn("chat_references", response["job"])
        self.assertNotIn("replacement", json.dumps(response["job"]))

    @staticmethod
    def routed_job(reference: agent_server.ChatReference) -> dict:
        return {
            "id": "job_existing",
            "session_id": "source",
            "title": "Routed job",
            "prompt": "@Target do work",
            "chat_references": [reference.model_dump()],
            "schedule_kind": "interval",
            "interval_seconds": 600,
            "cron_expression": None,
            "rrule": None,
            "timezone": "UTC",
            "loop": True,
            "max_runs": None,
            "enabled": True,
            "backend": agent_server.BACKEND_CODEX,
            "context_mode": "chat",
            "schedule_start_at": 4_102_444_800.0,
            "scheduled_run_at": 4_102_444_800.0,
            "next_run_at": 4_102_444_800.0,
            "run_count": 0,
            "updated_at": "2026-08-26T00:00:00Z",
            "_revision": "revision-before-update",
        }

    async def test_routed_job_omitting_routes_cannot_rewrite_or_accelerate(self) -> None:
        token, _capability, _route = await self.issue_with_target(
            "run_job_route_fence",
        )
        reference = agent_server.ChatReference(
            session_id="target",
            display_title_snapshot="Target",
            source_text_start=0,
            source_text_end=7,
            action="instruction",
        )
        job = self.routed_job(reference)
        agent_server.JOBS.jobs[job["id"]] = job
        forbidden = (
            agent_server.AgentUpdateJobRequest(prompt="@Target changed"),
            agent_server.AgentUpdateJobRequest(interval_seconds=60),
            agent_server.AgentUpdateJobRequest(
                next_run_at="2000-01-01T00:00:00Z",
            ),
        )

        with (
            patch.object(agent_server.JOBS, "save", new_callable=AsyncMock),
            patch.object(agent_server, "append_event", new_callable=AsyncMock),
        ):
            for req in forbidden:
                with self.subTest(patch=req.model_dump(exclude_unset=True)):
                    with self.assertRaises(HTTPException) as raised:
                        await agent_server.update_agent_session_job(
                            self.provider_request(token, method="PATCH"),
                            "source",
                            job["id"],
                            req,
                        )
                    self.assertEqual(raised.exception.status_code, 403)

            job["enabled"] = False
            with self.assertRaises(HTTPException) as raised:
                await agent_server.update_agent_session_job(
                    self.provider_request(token, method="PATCH"),
                    "source",
                    job["id"],
                    agent_server.AgentUpdateJobRequest(enabled=True),
                )
            self.assertEqual(raised.exception.status_code, 403)

    async def test_routed_job_omitting_routes_may_only_disable_or_rename(self) -> None:
        token, _capability, _route = await self.issue_with_target(
            "run_job_route_safe_update",
        )
        reference = agent_server.ChatReference(
            session_id="target",
            display_title_snapshot="Target",
            source_text_start=0,
            source_text_end=7,
            action="instruction",
        )
        job = self.routed_job(reference)
        agent_server.JOBS.jobs[job["id"]] = job

        with (
            patch.object(agent_server.JOBS, "save", new_callable=AsyncMock),
            patch.object(agent_server, "append_event", new_callable=AsyncMock),
        ):
            await agent_server.update_agent_session_job(
                self.provider_request(token, method="PATCH"),
                "source",
                job["id"],
                agent_server.AgentUpdateJobRequest(
                    title="Renamed safely",
                    enabled=False,
                ),
            )

        updated = agent_server.JOBS.jobs[job["id"]]
        self.assertEqual(updated["title"], "Renamed safely")
        self.assertFalse(updated["enabled"])
        self.assertEqual(
            updated["chat_references"],
            agent_server.chat_reference_dicts([reference]),
        )

    async def test_routed_job_can_revoke_routes_and_edit_atomically(self) -> None:
        token, _capability, _route = await self.issue_with_target(
            "run_job_route_revoke",
        )
        reference = agent_server.ChatReference(
            session_id="target",
            display_title_snapshot="Target",
            source_text_start=0,
            source_text_end=7,
            action="instruction",
        )
        job = self.routed_job(reference)
        agent_server.JOBS.jobs[job["id"]] = job

        with (
            patch.object(agent_server.JOBS, "save", new_callable=AsyncMock),
            patch.object(agent_server, "append_event", new_callable=AsyncMock),
        ):
            await agent_server.update_agent_session_job(
                self.provider_request(token, method="PATCH"),
                "source",
                job["id"],
                agent_server.AgentUpdateJobRequest(
                    prompt="No cross-chat target",
                    interval_seconds=60,
                    chat_routes=[],
                ),
            )

        updated = agent_server.JOBS.jobs[job["id"]]
        self.assertEqual(updated["chat_references"], [])
        self.assertEqual(updated["prompt"], "No cross-chat target")
        self.assertEqual(updated["interval_seconds"], 60)

    async def test_current_route_can_replace_existing_job_references(self) -> None:
        token, _capability, route = await self.issue_with_target(
            "run_job_route_replace",
            target_id="replacement",
            target_title="Replacement",
        )
        old_reference = agent_server.ChatReference(
            session_id="old_target",
            display_title_snapshot="Old target",
            source_text_start=0,
            source_text_end=11,
            action="instruction",
        )
        job = self.routed_job(old_reference)
        job["prompt"] = "@Old target do work"
        agent_server.JOBS.jobs[job["id"]] = job

        with (
            patch.object(agent_server.JOBS, "save", new_callable=AsyncMock),
            patch.object(agent_server, "append_event", new_callable=AsyncMock),
        ):
            await agent_server.update_agent_session_job(
                self.provider_request(token, method="PATCH"),
                "source",
                job["id"],
                agent_server.AgentUpdateJobRequest(
                    prompt="@Replacement take over",
                    chat_routes=[{
                        "route_id": route["route_id"],
                        "action": "request_reply",
                    }],
                ),
            )

        references = agent_server.JOBS.jobs[job["id"]]["chat_references"]
        self.assertEqual(len(references), 1)
        replacement = references[0]
        self.assertEqual(replacement["session_id"], "replacement")
        self.assertEqual(replacement["display_title_snapshot"], "Replacement")
        self.assertEqual(replacement["action"], "route")
        self.assertEqual(replacement["route_action"], "request_reply")

    async def test_human_jobs_routes_ignore_provider_policy(self) -> None:
        agent_server.STORE.sessions["source"]["provider_jobs_access"] = "blocked"
        job = {
            "id": "job_human",
            "session_id": "source",
            "title": "Human-created",
        }
        with patch.object(
            agent_server.JOBS,
            "create",
            AsyncMock(return_value=job),
        ) as create:
            response = await agent_server.create_session_job(
                "source",
                agent_server.CreateScopedJobRequest(
                    title="Human-created",
                    prompt="Run",
                    interval_seconds=60,
                ),
            )
        self.assertEqual(response["job"]["id"], "job_human")
        create.assert_awaited_once()

    def test_provider_prompt_cannot_overstate_read_only_or_blocked_access(self) -> None:
        authority = self.root / "authority.json"
        read_only = agent_server.cross_chat_provider_authority_block(
            [],
            authority,
            "source",
            {"jobs", "publish"},
            "read_only",
        )
        self.assertIn("Jobs access is read-only", read_only)
        self.assertIn("Jobs list", read_only)
        self.assertIn("Jobs detail", read_only)
        self.assertIn("Jobs run status", read_only)
        self.assertNotIn("Jobs (full access)", read_only)
        self.assertNotIn(" COMMAND`", read_only)

        blocked = agent_server.cross_chat_provider_authority_block(
            [],
            authority,
            "source",
            {"publish"},
            "blocked",
        )
        self.assertIn("Jobs access is blocked", blocked)
        self.assertNotIn("$AGENTSDOCK_JOBS_CLI", blocked)

    def test_full_jobs_authority_explains_future_chat_route_storage(self) -> None:
        authority = self.root / "authority.json"
        durable_route = {
            "route_id": "route_" + "d" * 32,
            "revision": "rev_" + "e" * 32,
            "alias": "chat1",
            "target_session_id": "target",
            "actions": ["instruction", "request_reply"],
            "created_at": "2026-08-27T00:00:00Z",
            "updated_at": "2026-08-27T00:00:00Z",
        }
        block = agent_server.cross_chat_provider_authority_block(
            [],
            authority,
            "source",
            {"jobs", "agent_cross_chat_routes"},
            "full",
            provider_route_snapshot=[durable_route],
        )

        self.assertIn("include the exact single-@ `@Chat`", block)
        self.assertIn(
            "--chat-route ROUTE_ID",
            block,
        )
        self.assertIn("without contacting the target now", block)
        self.assertIn("--clear-chat-routes", block)


if __name__ == "__main__":
    unittest.main()
