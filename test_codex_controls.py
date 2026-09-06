import asyncio
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from fastapi import HTTPException

import agent_server


class CodexControlValidationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.previous_pending = agent_server.CODEX_PENDING_INTERACTIONS
        self.previous_approval_items = agent_server.CODEX_APPROVAL_ITEM_CACHE
        self.previous_sessions = agent_server.STORE.sessions
        self.previous_thread_index = agent_server.CODEX_THREAD_SESSION_INDEX
        agent_server.CODEX_PENDING_INTERACTIONS = {}
        agent_server.CODEX_APPROVAL_ITEM_CACHE = agent_server.OrderedDict()
        agent_server.CODEX_THREAD_SESSION_INDEX = {}
        agent_server.STORE.sessions = {
            "chat": {
                "id": "chat",
                "backend": agent_server.BACKEND_CODEX,
                "codex_thread_id": "thread",
            }
        }

    async def asyncTearDown(self) -> None:
        agent_server.CODEX_PENDING_INTERACTIONS = self.previous_pending
        agent_server.CODEX_APPROVAL_ITEM_CACHE = self.previous_approval_items
        agent_server.CODEX_THREAD_SESSION_INDEX = self.previous_thread_index
        agent_server.STORE.sessions = self.previous_sessions

    def test_command_approval_is_fail_closed(self) -> None:
        pending = {
            "method": "item/commandExecution/requestApproval",
            "params": {"availableDecisions": ["accept", "decline"]},
        }
        self.assertEqual(
            agent_server.validate_codex_interaction_response(
                pending,
                {"decision": "decline"},
            ),
            {"decision": "decline"},
        )
        with self.assertRaises(HTTPException):
            agent_server.validate_codex_interaction_response(
                pending,
                {"decision": "acceptForSession"},
            )
        with self.assertRaises(HTTPException):
            agent_server.validate_codex_interaction_response(
                pending,
                {
                    "decision": {
                        "applyNetworkPolicyAmendment": {
                            "network_policy_amendment": {"host": "example.com"}
                        }
                    }
                },
            )

    def test_command_approval_accepts_only_exact_proposed_amendments(self) -> None:
        exec_decision = {
            "acceptWithExecpolicyAmendment": {
                "execpolicy_amendment": ["git", "status"],
            }
        }
        network_decision = {
            "applyNetworkPolicyAmendment": {
                "network_policy_amendment": {
                    "action": "allow",
                    "host": "example.com",
                }
            }
        }
        pending = {
            "method": "item/commandExecution/requestApproval",
            "params": {
                "availableDecisions": [exec_decision, network_decision, "decline"],
                "proposedExecpolicyAmendment": ["git", "status"],
                "proposedNetworkPolicyAmendments": [
                    {"action": "allow", "host": "example.com"}
                ],
            },
        }
        self.assertEqual(
            agent_server.validate_codex_interaction_response(
                pending,
                {"decision": exec_decision},
            ),
            {"decision": exec_decision},
        )
        self.assertEqual(
            agent_server.validate_codex_interaction_response(
                pending,
                {"decision": network_decision},
            ),
            {"decision": network_decision},
        )

        invalid_decisions = [
            {
                "acceptWithExecpolicyAmendment": {
                    "execpolicy_amendment": ["rm", "-rf"],
                }
            },
            {
                "applyNetworkPolicyAmendment": {
                    "network_policy_amendment": {
                        "action": "allow",
                        "host": "other.example",
                    }
                }
            },
            {
                "applyNetworkPolicyAmendment": {
                    "network_policy_amendment": {
                        "action": "sometimes",
                        "host": "example.com",
                    }
                }
            },
        ]
        for decision in invalid_decisions:
            with self.subTest(decision=decision), self.assertRaises(HTTPException):
                agent_server.validate_codex_interaction_response(
                    pending,
                    {"decision": decision},
                )
        for available in (None, []):
            with self.subTest(available=available), self.assertRaises(
                HTTPException
            ):
                agent_server.validate_codex_interaction_response(
                    {
                        "method": pending["method"],
                        "params": {
                            **pending["params"],
                            "availableDecisions": available,
                        },
                    },
                    {"decision": exec_decision},
                )

    async def test_file_approval_includes_cached_proposed_changes(self) -> None:
        agent_server.cache_codex_approval_item({
            "method": "item/started",
            "params": {
                "threadId": "thread",
                "item": {
                    "id": "change-1",
                    "type": "fileChange",
                    "changes": [{
                        "path": "/work/app.py",
                        "kind": "update",
                        "diff": "+print('safe')",
                    }],
                },
            },
        })
        with (
            patch.object(
                agent_server,
                "codex_session_id_for_thread",
                return_value="chat",
            ),
            patch.object(
                agent_server,
                "codex_request_is_interactive",
                return_value=True,
            ),
            patch.object(agent_server, "append_event", AsyncMock()),
            patch.object(
                agent_server,
                "update_codex_pending_session_metadata",
                AsyncMock(),
            ),
        ):
            request_task = asyncio.create_task(
                agent_server.handle_codex_server_request(
                    7,
                    "item/fileChange/requestApproval",
                    {
                        "threadId": "thread",
                        "turnId": "turn",
                        "itemId": "change-1",
                    },
                )
            )
            await asyncio.sleep(0)
            interaction_id, pending = next(
                iter(agent_server.CODEX_PENDING_INTERACTIONS.items())
            )
            self.assertEqual(
                pending["params"]["changes"][0]["path"],
                "/work/app.py",
            )
            await agent_server.resolve_codex_interaction(
                "chat",
                interaction_id,
                {"decision": "decline"},
            )
            self.assertEqual(
                await request_task,
                {"decision": "decline"},
            )

    async def test_interaction_registration_is_atomic_and_does_not_hold_lifecycle_lock(
        self,
    ) -> None:
        handler_tasks: dict[str, set[asyncio.Task[object]]] = {}
        lifecycle_locks: dict[str, asyncio.Lock] = {}
        with (
            patch.object(
                agent_server,
                "CODEX_INTERACTION_HANDLER_TASKS",
                handler_tasks,
            ),
            patch.object(agent_server, "SESSION_LIFECYCLE_LOCKS", lifecycle_locks),
            patch.object(agent_server, "DELETING_SESSIONS", set()),
            patch.object(agent_server, "DELETED_SESSION_TOMBSTONES", set()),
            patch.object(
                agent_server,
                "codex_session_id_for_thread",
                return_value="chat",
            ),
            patch.object(
                agent_server,
                "codex_request_is_interactive",
                return_value=True,
            ),
            patch.object(agent_server, "append_event", AsyncMock()),
            patch.object(
                agent_server,
                "update_codex_pending_session_metadata",
                AsyncMock(),
            ),
        ):
            request_task = asyncio.create_task(
                agent_server.handle_codex_server_request(
                    9,
                    "item/commandExecution/requestApproval",
                    {
                        "threadId": "thread",
                        "availableDecisions": ["accept", "decline"],
                    },
                )
            )
            for _attempt in range(20):
                if agent_server.CODEX_PENDING_INTERACTIONS:
                    break
                await asyncio.sleep(0)

            self.assertTrue(agent_server.CODEX_PENDING_INTERACTIONS)
            self.assertIn(request_task, handler_tasks["chat"])
            lifecycle_lock = agent_server.session_lifecycle_lock("chat")
            await asyncio.wait_for(lifecycle_lock.acquire(), timeout=0.1)
            lifecycle_lock.release()

            interaction_id = next(iter(agent_server.CODEX_PENDING_INTERACTIONS))
            await agent_server.resolve_codex_interaction(
                "chat",
                interaction_id,
                {"decision": "decline"},
            )
            self.assertEqual(await request_task, {"decision": "decline"})

    async def test_delete_marker_wins_before_interaction_registration(self) -> None:
        handler_tasks: dict[str, set[asyncio.Task[object]]] = {}
        lifecycle_locks: dict[str, asyncio.Lock] = {}
        deleting: set[str] = set()
        with (
            patch.object(
                agent_server,
                "CODEX_INTERACTION_HANDLER_TASKS",
                handler_tasks,
            ),
            patch.object(agent_server, "SESSION_LIFECYCLE_LOCKS", lifecycle_locks),
            patch.object(agent_server, "DELETING_SESSIONS", deleting),
            patch.object(agent_server, "DELETED_SESSION_TOMBSTONES", set()),
            patch.object(
                agent_server,
                "codex_session_id_for_thread",
                return_value="chat",
            ),
            patch.object(
                agent_server,
                "codex_request_is_interactive",
                return_value=True,
            ),
            patch.object(
                agent_server,
                "decline_server_request",
                AsyncMock(return_value={"decision": "decline"}),
            ) as decline,
        ):
            lifecycle_lock = agent_server.session_lifecycle_lock("chat")
            await lifecycle_lock.acquire()
            request_task = asyncio.create_task(
                agent_server.handle_codex_server_request(
                    10,
                    "item/commandExecution/requestApproval",
                    {
                        "threadId": "thread",
                        "availableDecisions": ["accept", "decline"],
                    },
                )
            )
            await asyncio.sleep(0)
            deleting.add("chat")
            lifecycle_lock.release()
            try:
                self.assertEqual(
                    await request_task,
                    {"decision": "decline"},
                )
            finally:
                deleting.discard("chat")

            decline.assert_awaited_once()
            self.assertFalse(agent_server.CODEX_PENDING_INTERACTIONS)
            self.assertNotIn("chat", handler_tasks)

    async def test_stop_all_terminals_requires_confirmation(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            await agent_server.post_codex_background_terminals_clean(
                "chat",
                agent_server.CodexBackgroundTerminalsCleanRequest(
                    confirmed=False
                ),
            )
        self.assertEqual(raised.exception.status_code, 400)

        manager = AsyncMock()
        with (
            patch.object(
                agent_server,
                "acquire_codex_control_thread",
                AsyncMock(return_value=(manager, "thread", {})),
            ),
            patch.object(
                agent_server,
                "release_codex_control_thread",
                AsyncMock(),
            ) as release,
        ):
            result = await agent_server.post_codex_background_terminals_clean(
                "chat",
                agent_server.CodexBackgroundTerminalsCleanRequest(
                    confirmed=True
                ),
            )
        self.assertEqual(result, {"cleaned": True})
        manager.clean_background_terminals.assert_awaited_once_with("thread")
        release.assert_awaited_once_with("chat", manager, "thread")

    async def test_terminate_terminal_requires_confirmation(self) -> None:
        with patch.object(
            agent_server,
            "acquire_codex_control_thread",
            AsyncMock(),
        ) as acquire:
            with self.assertRaises(HTTPException) as raised:
                await agent_server.post_codex_background_terminal_terminate(
                    "chat",
                    agent_server.CodexBackgroundTerminalRequest(
                        process_id="process-1",
                        confirmed=False,
                    ),
                )
        self.assertEqual(raised.exception.status_code, 400)
        acquire.assert_not_awaited()

    def test_permission_grant_cannot_exceed_requested_subset(self) -> None:
        pending = {
            "method": "item/permissions/requestApproval",
            "params": {
                "permissions": {
                    "network": False,
                    "filesystem": {"read": True, "write": False},
                }
            },
        }
        accepted = agent_server.validate_codex_interaction_response(
            pending,
            {
                "permissions": {
                    "filesystem": {"read": True},
                },
                "scope": "turn",
            },
        )
        self.assertEqual(accepted["scope"], "turn")
        with self.assertRaises(HTTPException):
            agent_server.validate_codex_interaction_response(
                pending,
                {
                    "permissions": {
                        "filesystem": {"write": True},
                    },
                    "scope": "session",
                },
            )

    def test_question_answers_are_bounded_and_keyed_by_known_ids(self) -> None:
        pending = {
            "method": "item/tool/requestUserInput",
            "params": {"questions": [{"id": "choice"}]},
        }
        self.assertEqual(
            agent_server.validate_codex_interaction_response(
                pending,
                {"answers": {"choice": {"answers": ["A"]}}},
            ),
            {"answers": {"choice": {"answers": ["A"]}}},
        )
        with self.assertRaises(HTTPException):
            agent_server.validate_codex_interaction_response(
                pending,
                {"answers": {"unknown": {"answers": ["A"]}}},
            )

    async def test_cancel_pending_interaction_returns_least_privilege(self) -> None:
        future: asyncio.Future[dict[str, object]] = (
            asyncio.get_running_loop().create_future()
        )
        agent_server.CODEX_PENDING_INTERACTIONS["pending"] = {
            "id": "pending",
            "native_request_id": 1,
            "session_id": "chat",
            "thread_id": "thread",
            "method": "item/fileChange/requestApproval",
            "params": {},
            "future": future,
            "responded": False,
        }
        with patch.object(agent_server.STORE, "save", AsyncMock()):
            await agent_server.cancel_codex_interactions(
                "chat",
                resolution="turn_stopped",
            )
        self.assertEqual(await future, {"decision": "decline"})
        self.assertEqual(
            agent_server.CODEX_PENDING_INTERACTIONS["pending"]["resolution"],
            "turn_stopped",
        )
        with self.assertRaises(HTTPException) as raised:
            await agent_server.resolve_codex_interaction(
                "chat",
                "pending",
                {"decision": "accept"},
            )
        self.assertEqual(raised.exception.status_code, 409)

    async def test_user_response_wins_race_with_interaction_cancellation(self) -> None:
        future: asyncio.Future[dict[str, object]] = (
            asyncio.get_running_loop().create_future()
        )
        pending = {
            "id": "pending",
            "native_request_id": 1,
            "session_id": "chat",
            "thread_id": "thread",
            "method": "item/fileChange/requestApproval",
            "params": {"availableDecisions": ["accept", "decline"]},
            "created_at": agent_server.now_iso(),
            "future": future,
            "responded": False,
        }
        agent_server.CODEX_PENDING_INTERACTIONS["pending"] = pending
        decline_started = asyncio.Event()
        release_decline = asyncio.Event()

        async def delayed_decline(*_args: object, **_kwargs: object) -> dict[str, str]:
            decline_started.set()
            await release_decline.wait()
            return {"decision": "decline"}

        with (
            patch.object(
                agent_server,
                "decline_server_request",
                side_effect=delayed_decline,
            ),
            patch.object(agent_server.STORE, "save", AsyncMock()),
        ):
            cancel_task = asyncio.create_task(
                agent_server.cancel_codex_interactions(
                    "chat",
                    resolution="turn_stopped",
                )
            )
            await decline_started.wait()
            interaction = await agent_server.resolve_codex_interaction(
                "chat",
                "pending",
                {"decision": "accept"},
            )
            release_decline.set()
            await cancel_task

        self.assertEqual(interaction["id"], "pending")
        self.assertEqual(await future, {"decision": "accept"})
        self.assertEqual(pending["resolution"], "answered")

    async def test_user_response_wins_race_with_auto_resolution(self) -> None:
        decline_started = asyncio.Event()
        release_decline = asyncio.Event()

        async def delayed_decline(*_args: object, **_kwargs: object) -> dict[str, object]:
            decline_started.set()
            await release_decline.wait()
            return {"answers": {}}

        with (
            patch.object(
                agent_server,
                "codex_session_id_for_thread",
                return_value="chat",
            ),
            patch.object(
                agent_server,
                "codex_request_is_interactive",
                return_value=True,
            ),
            patch.object(
                agent_server,
                "decline_server_request",
                side_effect=delayed_decline,
            ),
            patch.object(agent_server, "append_event", AsyncMock()),
            patch.object(
                agent_server,
                "update_codex_pending_session_metadata",
                AsyncMock(),
            ),
        ):
            request_task = asyncio.create_task(
                agent_server.handle_codex_server_request(
                    1,
                    "item/tool/requestUserInput",
                    {
                        "threadId": "thread",
                        "autoResolutionMs": 1,
                        "questions": [{"id": "choice"}],
                    },
                )
            )
            await decline_started.wait()
            interaction_id, pending = next(
                iter(agent_server.CODEX_PENDING_INTERACTIONS.items())
            )
            await agent_server.resolve_codex_interaction(
                "chat",
                interaction_id,
                {"answers": {"choice": {"answers": ["A"]}}},
            )
            release_decline.set()
            result = await request_task

        self.assertEqual(
            result,
            {"answers": {"choice": {"answers": ["A"]}}},
        )
        self.assertEqual(pending["resolution"], "answered")

    async def test_secret_response_is_not_copied_into_pending_metadata(self) -> None:
        future: asyncio.Future[dict[str, object]] = (
            asyncio.get_running_loop().create_future()
        )
        pending = {
            "id": "secret",
            "native_request_id": 1,
            "session_id": "chat",
            "thread_id": "thread",
            "method": "mcpServer/elicitation/request",
            "params": {},
            "created_at": agent_server.now_iso(),
            "future": future,
            "responded": False,
        }
        agent_server.CODEX_PENDING_INTERACTIONS["secret"] = pending

        interaction = await agent_server.resolve_codex_interaction(
            "chat",
            "secret",
            {"action": "accept", "content": {"password": "top-secret"}},
        )

        self.assertEqual(
            await future,
            {"action": "accept", "content": {"password": "top-secret"}},
        )
        self.assertNotIn("response", pending)
        self.assertNotIn("top-secret", repr(interaction))

    def test_goal_time_budget_uses_native_elapsed_time(self) -> None:
        session = {
            "codex_goal": {
                "status": "active",
                "timeUsedSeconds": 12,
            },
            "codex_goal_time_budget_seconds": 20,
        }
        self.assertEqual(
            agent_server.codex_goal_time_budget_remaining(session),
            8,
        )
        session["codex_goal"]["status"] = "paused"
        self.assertIsNone(agent_server.codex_goal_time_budget_remaining(session))

    def test_goal_time_budget_stays_exhausted_after_native_status_change(
        self,
    ) -> None:
        session = {
            "codex_goal": {
                "status": "budgetLimited",
                "timeUsedSeconds": 12,
            },
            "codex_goal_time_budget_seconds": 20,
            "codex_goal_time_budget_exhausted": True,
        }
        self.assertEqual(
            agent_server.codex_goal_time_budget_remaining(session),
            0,
        )

    async def test_native_elapsed_budget_is_exposed_as_exhausted(self) -> None:
        session = agent_server.STORE.sessions["chat"]
        session.update(
            {
                "codex_goal": {
                    "status": "budgetLimited",
                    "timeUsedSeconds": 20,
                },
                "codex_goal_time_budget_seconds": 20,
                "codex_goal_time_budget_exhausted": False,
            }
        )
        self.assertTrue(
            agent_server.public_session(session)[
                "codex_goal_time_budget_exhausted"
            ]
        )
        goal = await agent_server.get_codex_goal("chat")
        self.assertTrue(goal["time_budget_exhausted"])
        runtime = await agent_server.get_codex_runtime("chat")
        self.assertTrue(runtime["time_budget_exhausted"])

    async def test_exhausted_time_budget_blocks_a_new_turn(self) -> None:
        agent_server.STORE.sessions["chat"].update(
            {
                "codex_goal": {
                    "status": "budgetLimited",
                    "timeUsedSeconds": 12,
                },
                "codex_goal_time_budget_seconds": 20,
                "codex_goal_time_budget_exhausted": True,
            }
        )
        with self.assertRaises(HTTPException) as raised:
            await agent_server.start_turn(
                "chat",
                agent_server.TurnRequest(prompt="continue"),
            )
        self.assertEqual(raised.exception.status_code, 409)

    def test_permission_profile_cache_is_ttl_and_generation_scoped(self) -> None:
        class Manager:
            ready = True
            generation = 4

        manager = Manager()
        agent_server.CODEX_PERMISSION_PROFILES_CACHE["/work"] = (
            4,
            agent_server.time.monotonic(),
            [{"id": "default", "allowed": True}],
        )
        self.assertEqual(
            agent_server.cached_codex_permission_profiles("/work", manager),
            [{"id": "default", "allowed": True}],
        )
        manager.generation = 5
        self.assertIsNone(
            agent_server.cached_codex_permission_profiles("/work", manager)
        )
        agent_server.CODEX_PERMISSION_PROFILES_CACHE["/work"] = (
            5,
            agent_server.time.monotonic()
            - agent_server.CODEX_PERMISSION_PROFILES_CACHE_SECONDS
            - 1,
            [{"id": "stale", "allowed": True}],
        )
        self.assertIsNone(
            agent_server.cached_codex_permission_profiles("/work", manager)
        )

    async def test_new_sessions_and_null_resets_use_canonical_permission_defaults(
        self,
    ) -> None:
        store = agent_server.SessionStore()
        with (
            patch.object(agent_server, "ensure_dirs"),
            patch.object(agent_server, "append_event", AsyncMock()),
            patch.object(store, "save", AsyncMock()),
        ):
            created = await store.create(
                agent_server.CreateSessionRequest(
                    backend=agent_server.BACKEND_CODEX,
                )
            )
            explicit = await store.create(
                agent_server.CreateSessionRequest(
                    backend=agent_server.BACKEND_CODEX,
                    codex_approval_policy="never",
                    codex_sandbox_mode="read-only",
                    codex_permission_profile=":read-only",
                    codex_approvals_reviewer="user",
                )
            )
            reset = await store.update(
                explicit["id"],
                {
                    "codex_approval_policy": None,
                    "codex_sandbox_mode": None,
                    "codex_permission_profile": None,
                    "codex_approvals_reviewer": None,
                },
            )

        self.assertEqual(
            created["codex_approval_policy"],
            agent_server.CODEX_DEFAULT_APPROVAL_POLICY,
        )
        self.assertEqual(
            created["codex_sandbox_mode"],
            agent_server.CODEX_DEFAULT_SANDBOX_MODE,
        )
        self.assertIs(
            created["codex_permission_profile"],
            agent_server.CODEX_DEFAULT_PERMISSION_PROFILE,
        )
        self.assertEqual(
            created["codex_approvals_reviewer"],
            agent_server.CODEX_DEFAULT_APPROVALS_REVIEWER,
        )
        self.assertEqual(
            reset["codex_approval_policy"],
            agent_server.CODEX_DEFAULT_APPROVAL_POLICY,
        )
        self.assertEqual(
            reset["codex_sandbox_mode"],
            agent_server.CODEX_DEFAULT_SANDBOX_MODE,
        )
        self.assertIsNone(reset["codex_permission_profile"])
        self.assertEqual(
            reset["codex_approvals_reviewer"],
            agent_server.CODEX_DEFAULT_APPROVALS_REVIEWER,
        )

    async def test_session_load_defaults_missing_permissions_without_overwriting_choices(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sessions_file = Path(temp_dir) / "sessions.json"
            sessions_file.write_text(
                json.dumps(
                    {
                        "missing": {
                            "id": "missing",
                            "backend": agent_server.BACKEND_CODEX,
                        },
                        "explicit": {
                            "id": "explicit",
                            "backend": agent_server.BACKEND_CODEX,
                            "codex_approval_policy": "never",
                            "codex_sandbox_mode": "read-only",
                            "codex_permission_profile": ":read-only",
                            "codex_approvals_reviewer": "user",
                        },
                    }
                )
            )
            store = agent_server.SessionStore()
            with (
                patch.object(agent_server, "SESSIONS_FILE", sessions_file),
                patch.object(agent_server, "ensure_dirs"),
                patch.object(store, "save", AsyncMock()),
            ):
                await store.load()

        missing = store.sessions["missing"]
        self.assertEqual(
            missing["codex_approval_policy"],
            agent_server.CODEX_DEFAULT_APPROVAL_POLICY,
        )
        self.assertEqual(
            missing["codex_sandbox_mode"],
            agent_server.CODEX_DEFAULT_SANDBOX_MODE,
        )
        self.assertIsNone(missing["codex_permission_profile"])
        self.assertEqual(
            missing["codex_approvals_reviewer"],
            agent_server.CODEX_DEFAULT_APPROVALS_REVIEWER,
        )
        explicit = store.sessions["explicit"]
        self.assertEqual(explicit["codex_approval_policy"], "never")
        self.assertEqual(explicit["codex_sandbox_mode"], "read-only")
        self.assertEqual(explicit["codex_permission_profile"], ":read-only")
        self.assertEqual(explicit["codex_approvals_reviewer"], "user")

    async def test_runtime_policy_reports_canonical_defaults_for_legacy_session(
        self,
    ) -> None:
        with (
            patch.object(agent_server, "CODEX_APP_SERVER_MANAGER", None),
            patch.object(agent_server, "CODEX_GOALS_ENABLED", False),
        ):
            runtime = await agent_server.codex_runtime_snapshot("chat")

        self.assertFalse(runtime["goals_enabled"])
        self.assertEqual(
            runtime["policy"],
            {
                "approval_policy": agent_server.CODEX_DEFAULT_APPROVAL_POLICY,
                "sandbox_mode": agent_server.CODEX_DEFAULT_SANDBOX_MODE,
                "permission_profile": agent_server.CODEX_DEFAULT_PERMISSION_PROFILE,
                "approvals_reviewer": agent_server.CODEX_DEFAULT_APPROVALS_REVIEWER,
            },
        )

    async def test_native_status_and_automatic_compaction_events_are_readable(
        self,
    ) -> None:
        self.assertEqual(
            agent_server.codex_thread_status_message(
                {
                    "type": "active",
                    "activeFlags": ["waitingOnApproval"],
                }
            ),
            "Codex is waiting for approval.",
        )
        with (
            patch.object(agent_server, "ACTIVE", {}),
            patch.object(
                agent_server,
                "append_event",
                AsyncMock(),
            ) as append_event,
        ):
            await agent_server.project_codex_notification(
                {
                    "method": "item/completed",
                    "params": {
                        "threadId": "thread",
                        "turnId": "turn-1",
                        "item": {
                            "id": "compact-1",
                            "type": "contextCompaction",
                        },
                    },
                }
            )
        payload = append_event.await_args.args[2]
        self.assertEqual(
            payload["message"],
            "Codex completed automatic context compaction.",
        )

    async def test_token_usage_is_run_scoped_coalesced_and_finalized(self) -> None:
        usage = {
            "last": {
                "inputTokens": 23_000,
                "cachedInputTokens": 20_000,
                "cacheWriteInputTokens": 100,
                "outputTokens": 1_000,
                "reasoningOutputTokens": 500,
                "totalTokens": 25_000,
            },
            "total": {
                "inputTokens": 7_000_000,
                "cachedInputTokens": 6_000_000,
                "outputTokens": 200_000,
                "reasoningOutputTokens": 100_000,
                "totalTokens": 7_300_000,
            },
            "modelContextWindow": 100_000,
        }
        active = {
            "chat": {
                "run_id": "run-1",
                "backend": agent_server.BACKEND_CODEX,
                "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
                "provider_thread_id": "thread",
                "provider_turn_id": "turn-1",
            }
        }
        save = AsyncMock()
        append_event = AsyncMock()
        broadcast = AsyncMock()
        with (
            patch.object(agent_server, "ACTIVE", active),
            patch.object(
                agent_server,
                "codex_session_id_for_thread",
                return_value="chat",
            ),
            patch.object(agent_server.STORE, "save", save),
            patch.object(agent_server, "append_event", append_event),
            patch.object(agent_server.HUB, "broadcast", broadcast),
            patch.object(
                agent_server.time,
                "time",
                side_effect=[1_000, 1_001, 1_002, 1_003],
            ),
        ):
            await agent_server.project_codex_notification(
                {
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread",
                        "turnId": "turn-1",
                        "tokenUsage": usage,
                    },
                }
            )
            first_payload = agent_server.STORE.sessions["chat"][
                "codex_token_usage_snapshot"
            ]
            self.assertEqual(first_payload["run_id"], "run-1")
            self.assertEqual(first_payload["turn_id"], "turn-1")
            self.assertEqual(first_payload["raw_context_tokens"], 25_000)
            self.assertEqual(first_payload["context_tokens"], 25_000)
            self.assertEqual(first_payload["context_percent"], 14.77)
            self.assertEqual(first_payload["context_window"], 100_000)
            self.assertEqual(first_payload["baseline_tokens"], 12_000)
            self.assertEqual(
                first_payload["effective_context_window"],
                88_000,
            )
            self.assertEqual(first_payload["raw_context_window"], 100_000)
            self.assertEqual(first_payload["provider_session_id"], "thread")
            self.assertEqual(first_payload["usage_generation"], 1)
            self.assertEqual(first_payload["cache_write_input_tokens"], 100)
            self.assertTrue(first_payload["snapshot_at"])
            self.assertEqual(
                first_payload["cumulative_total_tokens"],
                7_300_000,
            )
            self.assertEqual(save.await_count, 1)
            self.assertEqual(append_event.await_count, 0)
            first_signal = broadcast.await_args_list[0].args[1]
            self.assertEqual(first_signal["type"], "provider_runtime_changed")
            self.assertEqual(first_signal["session_id"], "chat")
            self.assertEqual(first_signal["context_usage_state"], "available")
            self.assertNotIn("seq", first_signal)

            updated_usage = json.loads(json.dumps(usage))
            updated_usage["last"]["totalTokens"] = 25_500
            await agent_server.project_codex_notification(
                {
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread",
                        "turnId": "turn-1",
                        "tokenUsage": updated_usage,
                    },
                }
            )
            self.assertEqual(save.await_count, 1)
            self.assertEqual(append_event.await_count, 0)

            await agent_server.project_codex_notification(
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread",
                        "turn": {"id": "turn-1", "status": "completed"},
                    },
                }
            )

            # Global notification handlers are asynchronous. A final usage
            # sample may complete after the ordinary turn consumer has already
            # released ACTIVE; it must still be durable and keep attribution.
            active.clear()
            final_usage = json.loads(json.dumps(updated_usage))
            final_usage["last"]["totalTokens"] = 26_000
            await agent_server.project_codex_notification(
                {
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread",
                        "turnId": "turn-1",
                        "tokenUsage": final_usage,
                    },
                }
            )

        self.assertEqual(save.await_count, 3)
        self.assertEqual(append_event.await_count, 0)
        final_payload = agent_server.STORE.sessions["chat"][
            "codex_token_usage_snapshot"
        ]
        self.assertEqual(final_payload["raw_context_tokens"], 26_000)
        self.assertEqual(final_payload["context_tokens"], 26_000)
        self.assertEqual(final_payload["run_id"], "run-1")
        self.assertEqual(
            agent_server.STORE.sessions["chat"]["codex_token_usage"],
            final_usage,
        )

    async def test_turn_completion_does_not_relabel_stale_usage(self) -> None:
        stale = {
            "thread_id": "thread",
            "turn_id": "turn-old",
            "run_id": "run-old",
            "snapshot_at": agent_server.now_iso(),
            "token_usage": {"last": {"totalTokens": 10}},
            "context_tokens": 10,
        }
        agent_server.STORE.sessions["chat"]["codex_token_usage_snapshot"] = stale
        save = AsyncMock()
        active = {
            "chat": {
                "run_id": "run-new",
                "backend": agent_server.BACKEND_CODEX,
                "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
                "provider_thread_id": "thread",
                "provider_turn_id": "turn-new",
            }
        }
        with (
            patch.object(agent_server, "ACTIVE", active),
            patch.object(
                agent_server,
                "codex_session_id_for_thread",
                return_value="chat",
            ),
            patch.object(agent_server.STORE, "save", save),
        ):
            await agent_server.project_codex_notification(
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread",
                        "turn": {"id": "turn-new", "status": "completed"},
                    },
                }
            )

            self.assertEqual(save.await_count, 0)
            self.assertEqual(
                agent_server.STORE.sessions["chat"]["codex_token_usage_snapshot"],
                stale,
            )

            active.clear()
            late_usage = {
                "last": {"totalTokens": 25},
                "total": {"totalTokens": 100},
                "modelContextWindow": 100,
            }
            await agent_server.project_codex_notification(
                {
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread",
                        "turnId": "turn-new",
                        "tokenUsage": late_usage,
                    },
                }
            )

        self.assertEqual(save.await_count, 1)
        final_snapshot = agent_server.STORE.sessions["chat"][
            "codex_token_usage_snapshot"
        ]
        self.assertEqual(final_snapshot["turn_id"], "turn-new")
        self.assertEqual(final_snapshot["run_id"], "run-new")

    async def test_token_usage_cannot_repopulate_a_replaced_thread(self) -> None:
        snapshot = agent_server.codex_token_usage_snapshot(
            {
                "last": {"totalTokens": 25_000},
                "total": {"totalTokens": 25_000},
                "modelContextWindow": 100_000,
            },
            thread_id="thread",
            turn_id="turn-old",
            run_id="run-old",
        )
        self.assertIsNotNone(snapshot)
        agent_server.STORE.sessions["chat"]["codex_thread_id"] = "thread-new"
        agent_server.STORE.sessions["chat"]["session_id"] = "thread-new"
        save = AsyncMock()
        with patch.object(agent_server.STORE, "save", save):
            recorded = await agent_server.record_codex_token_usage(
                "chat",
                snapshot,
                force_checkpoint=True,
            )

        self.assertFalse(recorded)
        self.assertNotIn(
            "codex_token_usage_snapshot",
            agent_server.STORE.sessions["chat"],
        )
        self.assertEqual(save.await_count, 0)

    async def test_exec_invalidates_native_usage_and_rejects_late_samples(self) -> None:
        session = agent_server.STORE.sessions["chat"]
        session.update(
            {
                "context_usage_state": "available",
                "context_usage_snapshot": {"context_tokens": 55_000},
                "codex_token_usage": {"last": {"totalTokens": 55_000}},
                "codex_token_usage_snapshot": {
                    "thread_id": "thread",
                    "turn_id": "turn-native",
                    "run_id": "run-native",
                    "context_tokens": 55_000,
                },
                "_codex_token_usage_checkpoint": {"run_id": "run-native"},
                "_codex_token_usage_terminal": {
                    "thread_id": "thread",
                    "turn_id": "turn-native",
                    "run_id": "run-native",
                },
            }
        )
        save = AsyncMock()
        broadcast = AsyncMock()
        active = {
            "chat": {
                "run_id": "run-exec",
                "backend": agent_server.BACKEND_CODEX,
                "transport": agent_server.CODEX_TRANSPORT_EXEC,
            }
        }
        with (
            patch.object(agent_server.STORE, "save", save),
            patch.object(agent_server.HUB, "broadcast", broadcast),
            patch.object(agent_server, "ACTIVE", active),
            patch.object(
                agent_server,
                "codex_session_id_for_thread",
                return_value="chat",
            ),
        ):
            await agent_server.mark_codex_exec_context_usage_unavailable("chat")
            for key in (
                "context_usage_snapshot",
                "codex_token_usage",
                "codex_token_usage_snapshot",
                "_codex_token_usage_checkpoint",
                "_codex_token_usage_terminal",
            ):
                self.assertNotIn(key, session)
            self.assertEqual(session["context_usage_state"], "unavailable")

            save.reset_mock()
            await agent_server.project_codex_notification(
                {
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread",
                        "turnId": "turn-native",
                        "tokenUsage": {
                            "last": {"totalTokens": 60_000},
                            "total": {"totalTokens": 60_000},
                            "modelContextWindow": 100_000,
                        },
                    },
                }
            )

        self.assertNotIn("codex_token_usage_snapshot", session)
        save.assert_not_awaited()

    async def test_automatic_compaction_preserves_before_and_after_usage(self) -> None:
        before_usage = {
            "last": {
                "inputTokens": 85_000,
                "cachedInputTokens": 80_000,
                "outputTokens": 3_000,
                "reasoningOutputTokens": 2_000,
                "totalTokens": 90_000,
            },
            "total": {
                "inputTokens": 85_000,
                "cachedInputTokens": 80_000,
                "outputTokens": 3_000,
                "reasoningOutputTokens": 2_000,
                "totalTokens": 90_000,
            },
            "modelContextWindow": 100_000,
        }
        after_usage = json.loads(json.dumps(before_usage))
        after_usage["last"]["inputTokens"] = 8_000
        after_usage["last"]["totalTokens"] = 10_000
        after_usage["total"]["totalTokens"] = 100_000
        active = {
            "chat": {
                "run_id": "run-compact",
                "backend": agent_server.BACKEND_CODEX,
                "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
                "provider_thread_id": "thread",
                "provider_turn_id": "turn-1",
            }
        }
        events: list[tuple[str, dict[str, object]]] = []

        async def record_event(
            _session_id: str,
            event_type: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            events.append((event_type, payload))
            return {}

        with (
            patch.object(agent_server, "ACTIVE", active),
            patch.object(
                agent_server,
                "codex_session_id_for_thread",
                return_value="chat",
            ),
            patch.object(agent_server.STORE, "save", AsyncMock()),
            patch.object(agent_server, "append_event", side_effect=record_event),
        ):
            for usage in (before_usage,):
                await agent_server.project_codex_notification(
                    {
                        "method": "thread/tokenUsage/updated",
                        "params": {
                            "threadId": "thread",
                            "turnId": "turn-1",
                            "tokenUsage": usage,
                        },
                    }
                )
            await agent_server.project_codex_notification(
                {
                    "method": "item/started",
                    "params": {
                        "threadId": "thread",
                        "turnId": "turn-1",
                        "item": {"id": "compact-1", "type": "contextCompaction"},
                    },
                }
            )
            await agent_server.project_codex_notification(
                {
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "threadId": "thread",
                        "turnId": "turn-1",
                        "tokenUsage": after_usage,
                    },
                }
            )
            await agent_server.project_codex_notification(
                {
                    "method": "item/completed",
                    "params": {
                        "threadId": "thread",
                        "turnId": "turn-1",
                        "item": {"id": "compact-1", "type": "contextCompaction"},
                    },
                }
            )

        compaction = next(
            payload
            for event_type, payload in events
            if event_type == "codex_compaction_completed"
        )
        compaction_started = next(
            payload
            for event_type, payload in events
            if event_type == "codex_compaction_started"
        )
        self.assertEqual(
            compaction_started["compaction_id"],
            compaction["compaction_id"],
        )
        self.assertEqual(compaction_started["run_id"], "run-compact")
        self.assertEqual(compaction_started["thread_id"], "thread")
        self.assertEqual(compaction_started["turn_id"], "turn-1")
        self.assertEqual(compaction_started["item_id"], "compact-1")
        self.assertEqual(
            compaction["token_usage_before"]["context_tokens"],
            90_000,
        )
        self.assertEqual(
            compaction["token_usage_before"]["raw_context_tokens"],
            90_000,
        )
        self.assertEqual(
            compaction["token_usage_after"]["context_tokens"],
            10_000,
        )

    async def test_automatic_compaction_reuses_start_identity_when_completion_is_sparse(
        self,
    ) -> None:
        active = {
            "chat": {
                "run_id": "run-compact",
                "backend": agent_server.BACKEND_CODEX,
                "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
                "provider_thread_id": "thread",
                "provider_turn_id": "turn-1",
            }
        }
        events: list[tuple[str, dict[str, object]]] = []

        async def record_event(
            _session_id: str,
            event_type: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            events.append((event_type, payload))
            return {}

        with (
            patch.object(agent_server, "ACTIVE", active),
            patch.object(
                agent_server,
                "codex_session_id_for_thread",
                return_value="chat",
            ),
            patch.object(agent_server, "append_event", side_effect=record_event),
        ):
            await agent_server.project_codex_notification({
                "method": "item/started",
                "params": {
                    "threadId": "thread",
                    "turnId": "turn-1",
                    "item": {"id": "compact-1", "type": "contextCompaction"},
                },
            })
            await agent_server.project_codex_notification({
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "item": {"type": "contextCompaction"},
                },
            })

        compactions = [
            payload
            for event_type, payload in events
            if event_type in {
                "codex_compaction_started",
                "codex_compaction_completed",
            }
        ]
        self.assertEqual(len(compactions), 2)
        self.assertEqual(compactions[0]["compaction_id"], compactions[1]["compaction_id"])
        self.assertEqual(compactions[1]["turn_id"], "turn-1")
        self.assertEqual(compactions[1]["item_id"], "compact-1")

    async def test_automatic_compaction_does_not_invent_before_usage(self) -> None:
        after_usage = {
            "last": {"totalTokens": 10_000},
            "total": {"totalTokens": 100_000},
            "modelContextWindow": 100_000,
        }
        active = {
            "chat": {
                "run_id": "run-compact",
                "backend": agent_server.BACKEND_CODEX,
                "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
                "provider_thread_id": "thread",
                "provider_turn_id": "turn-1",
            }
        }
        events: list[tuple[str, dict[str, object]]] = []

        async def record_event(
            _session_id: str,
            event_type: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            events.append((event_type, payload))
            return {}

        with (
            patch.object(agent_server, "ACTIVE", active),
            patch.object(
                agent_server,
                "codex_session_id_for_thread",
                return_value="chat",
            ),
            patch.object(agent_server.STORE, "save", AsyncMock()),
            patch.object(agent_server, "append_event", side_effect=record_event),
        ):
            await agent_server.project_codex_notification({
                "method": "item/started",
                "params": {
                    "threadId": "thread",
                    "turnId": "turn-1",
                    "item": {"id": "compact-1", "type": "contextCompaction"},
                },
            })
            await agent_server.project_codex_notification({
                "method": "thread/tokenUsage/updated",
                "params": {
                    "threadId": "thread",
                    "turnId": "turn-1",
                    "tokenUsage": after_usage,
                },
            })
            await agent_server.project_codex_notification({
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "turnId": "turn-1",
                    "item": {"id": "compact-1", "type": "contextCompaction"},
                },
            })

        compaction = next(
            payload
            for event_type, payload in events
            if event_type == "codex_compaction_completed"
        )
        self.assertIsNone(compaction["token_usage_before"])
        self.assertEqual(
            compaction["token_usage_after"]["context_tokens"],
            10_000,
        )

    def test_goal_budget_and_native_completion_events_bump_timeline(self) -> None:
        for event_type in (
            "codex_goal_budget_limited",
            "codex_compaction_started",
            "codex_compaction_completed",
            "codex_review_finished",
            "codex_shell_finished",
        ):
            with self.subTest(event_type=event_type):
                self.assertTrue(
                    agent_server.should_bump_session_updated_at(
                        event_type,
                        {"type": event_type},
                    )
                )

    def test_routine_status_and_goal_state_do_not_bump_timeline(self) -> None:
        for event_type in (
            "codex_thread_status",
            "codex_goal_updated",
            "codex_goal_cleared",
        ):
            with self.subTest(event_type=event_type):
                self.assertFalse(
                    agent_server.should_bump_session_updated_at(
                        event_type,
                        {"type": event_type},
                    )
                )

    async def test_native_goal_state_persists_without_reordering_session(
        self,
    ) -> None:
        original_updated_at = "2026-07-28T10:00:00Z"
        agent_server.STORE.sessions["chat"].update(
            {
                "updated_at": original_updated_at,
                "codex_goal_time_budget_seconds": 30,
                "codex_goal_time_budget_exhausted": False,
            }
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            sessions_file = Path(temp_dir) / "sessions.json"
            with (
                patch.object(agent_server, "SESSIONS_FILE", sessions_file),
                patch.object(
                    agent_server,
                    "codex_session_id_for_thread",
                    return_value="chat",
                ),
                patch.object(agent_server, "append_event", AsyncMock()),
            ):
                await agent_server.project_codex_notification(
                    {
                        "method": "thread/goal/updated",
                        "params": {
                            "threadId": "thread",
                            "goal": {
                                "objective": "Keep the projection compact",
                                "status": "active",
                                "timeUsedSeconds": 12,
                            },
                        },
                    }
                )
                stored = json.loads(sessions_file.read_text())["chat"]
                self.assertEqual(
                    stored["codex_goal"]["objective"],
                    "Keep the projection compact",
                )
                self.assertEqual(stored["updated_at"], original_updated_at)

                await agent_server.project_codex_notification(
                    {
                        "method": "thread/goal/cleared",
                        "params": {"threadId": "thread"},
                    }
                )
                stored = json.loads(sessions_file.read_text())["chat"]

        self.assertIsNone(stored["codex_goal"])
        self.assertIsNone(stored["codex_goal_time_budget_seconds"])
        self.assertFalse(stored["codex_goal_time_budget_exhausted"])
        self.assertEqual(stored["updated_at"], original_updated_at)

    async def test_session_load_keeps_durable_token_usage_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sessions_file = Path(temp_dir) / "sessions.json"
            sessions_file.write_text(json.dumps({
                "stale": {
                    "id": "stale",
                    "backend": agent_server.BACKEND_CODEX,
                    "codex_thread_id": "thread-stale",
                    "codex_thread_status": {
                        "type": "active",
                        "activeFlags": ["waitingOnApproval"],
                    },
                    "codex_pending_interaction_count": 2,
                    "codex_needs_user_action": True,
                    "codex_token_usage": {"totalTokens": 100},
                }
            }))
            store = agent_server.SessionStore()
            with patch.object(agent_server, "SESSIONS_FILE", sessions_file):
                await store.load()

        session = store.sessions["stale"]
        self.assertEqual(session["codex_thread_status"], {"type": "notLoaded"})
        self.assertEqual(session["codex_pending_interaction_count"], 0)
        self.assertFalse(session["codex_needs_user_action"])
        self.assertEqual(session["codex_token_usage"], {"totalTokens": 100})
        self.assertEqual(
            agent_server.CODEX_THREAD_SESSION_INDEX["thread-stale"],
            "stale",
        )

    async def test_runtime_never_trusts_stale_active_status_when_thread_is_unloaded(
        self,
    ) -> None:
        agent_server.STORE.sessions["chat"]["codex_thread_status"] = {
            "type": "active",
            "activeFlags": ["waitingOnApproval"],
        }
        previous_manager = agent_server.CODEX_APP_SERVER_MANAGER
        agent_server.CODEX_APP_SERVER_MANAGER = None
        try:
            runtime = await agent_server.get_codex_runtime("chat")
        finally:
            agent_server.CODEX_APP_SERVER_MANAGER = previous_manager
        self.assertEqual(runtime["status"], {"type": "notLoaded"})

    async def test_load_runtime_resumes_only_a_persisted_idle_thread(self) -> None:
        manager = AsyncMock()
        manager.is_thread_loaded = Mock(return_value=True)
        ensure_thread = AsyncMock(return_value=("thread", "instruction-hash"))
        previous_manager = agent_server.CODEX_APP_SERVER_MANAGER
        previous_busy = agent_server.BUSY_SESSIONS
        previous_current = agent_server.CURRENT_TURNS
        previous_maintenance = agent_server.SERVER_MAINTENANCE_SESSIONS
        agent_server.CODEX_APP_SERVER_MANAGER = manager
        agent_server.BUSY_SESSIONS = set()
        agent_server.CURRENT_TURNS = {}
        agent_server.SERVER_MAINTENANCE_SESSIONS = set()
        unpin_thread = AsyncMock()
        try:
            with patch.object(
                agent_server,
                "ensure_codex_app_server_thread",
                ensure_thread,
            ), patch.object(
                agent_server,
                "unpin_codex_app_server_thread",
                unpin_thread,
            ), patch.object(
                agent_server,
                "managed_server_update_blocker",
                return_value=None,
            ):
                runtime = await agent_server.load_codex_runtime("chat")
                released = "chat" not in agent_server.BUSY_SESSIONS
                maintenance_released = (
                    "chat" not in agent_server.SERVER_MAINTENANCE_SESSIONS
                )
        finally:
            agent_server.CODEX_APP_SERVER_MANAGER = previous_manager
            agent_server.BUSY_SESSIONS = previous_busy
            agent_server.CURRENT_TURNS = previous_current
            agent_server.SERVER_MAINTENANCE_SESSIONS = previous_maintenance

        self.assertTrue(runtime["persisted_thread"])
        self.assertTrue(runtime["thread_loaded"])
        self.assertEqual(runtime["status"], {"type": "idle"})
        ensure_thread.assert_awaited_once()
        unpin_thread.assert_awaited_once_with(manager, "thread")
        self.assertTrue(released)
        self.assertTrue(maintenance_released)

    async def test_load_runtime_does_not_create_a_thread_for_a_new_chat(
        self,
    ) -> None:
        agent_server.STORE.sessions["chat"].pop("codex_thread_id", None)
        agent_server.STORE.sessions["chat"].pop("session_id", None)
        manager_factory = AsyncMock(
            side_effect=AssertionError("new chats must not start app-server")
        )
        previous_manager = agent_server.CODEX_APP_SERVER_MANAGER
        previous_busy = agent_server.BUSY_SESSIONS
        agent_server.CODEX_APP_SERVER_MANAGER = None
        agent_server.BUSY_SESSIONS = set()
        try:
            with patch.object(
                agent_server,
                "codex_app_server_manager",
                manager_factory,
            ), patch.object(
                agent_server,
                "managed_server_update_blocker",
                return_value=None,
            ):
                runtime = await agent_server.load_codex_runtime("chat")
        finally:
            agent_server.CODEX_APP_SERVER_MANAGER = previous_manager
            agent_server.BUSY_SESSIONS = previous_busy

        self.assertFalse(runtime["thread_loaded"])
        self.assertFalse(runtime["persisted_thread"])
        self.assertEqual(runtime["status"], {"type": "notLoaded"})
        manager_factory.assert_not_awaited()

    async def test_load_runtime_rejects_while_chat_is_busy(self) -> None:
        previous_busy = agent_server.BUSY_SESSIONS
        agent_server.BUSY_SESSIONS = {"chat"}
        try:
            with patch.object(
                agent_server,
                "managed_server_update_blocker",
                return_value=None,
            ):
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.load_codex_runtime("chat")
        finally:
            agent_server.BUSY_SESSIONS = previous_busy

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("active Codex turn", str(raised.exception.detail))

    async def test_all_codex_control_acquisition_is_blocked_during_update(
        self,
    ) -> None:
        manager_factory = AsyncMock(
            side_effect=AssertionError("app-server must not start during update")
        )
        with patch.object(
            agent_server,
            "managed_server_update_blocker",
            return_value="AgentsServer is preparing a managed update",
        ), patch.object(
            agent_server,
            "codex_app_server_manager",
            manager_factory,
        ):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.acquire_codex_control_thread(
                    "chat",
                    reserve_session=False,
                )
            with self.assertRaises(HTTPException) as profiles_raised:
                await agent_server.get_codex_permission_profiles("chat")

        self.assertEqual(raised.exception.status_code, 503)
        self.assertIn("managed update", str(raised.exception.detail))
        self.assertEqual(profiles_raised.exception.status_code, 503)
        manager_factory.assert_not_awaited()

    async def test_permission_profile_discovery_uses_maintenance_not_turn_state(
        self,
    ) -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        async def slow_list_permission_profiles(*, cwd: str):
            self.assertEqual(cwd, "/work")
            started.set()
            await release.wait()
            return [{"name": "default"}]

        manager = Mock()
        manager.generation = 7
        manager.start = AsyncMock()
        manager.list_permission_profiles = AsyncMock(
            side_effect=slow_list_permission_profiles
        )
        busy: set[str] = set()
        maintenance: set[str] = set()
        current: dict[str, object] = {}
        queued: dict[str, object] = {}
        with (
            patch.object(agent_server, "BUSY_SESSIONS", busy),
            patch.object(
                agent_server,
                "SERVER_MAINTENANCE_SESSIONS",
                maintenance,
            ),
            patch.object(agent_server, "CURRENT_TURNS", current),
            patch.object(agent_server, "QUEUED_TURNS", queued),
            patch.object(
                agent_server,
                "CODEX_PERMISSION_PROFILES_CACHE",
                {},
            ),
            patch.object(
                agent_server,
                "managed_server_update_blocker",
                return_value=None,
            ),
            patch.object(
                agent_server,
                "existing_cwd",
                return_value="/work",
            ),
            patch.object(
                agent_server,
                "codex_app_server_manager",
                AsyncMock(return_value=manager),
            ),
            patch.object(
                agent_server,
                "cached_codex_permission_profiles",
                return_value=None,
            ),
        ):
            profile_task = asyncio.create_task(
                agent_server._get_codex_permission_profiles_locked("chat")
            )
            await asyncio.wait_for(started.wait(), timeout=1)
            try:
                self.assertEqual(maintenance, {"chat"})
                self.assertEqual(busy, set())
                self.assertEqual(current, {})
                with self.assertRaises(HTTPException) as raised:
                    await agent_server._start_turn_locked(
                        "chat",
                        agent_server.TurnRequest(prompt="do not queue me"),
                    )
                self.assertEqual(raised.exception.status_code, 409)
                self.assertIn("maintenance", str(raised.exception.detail))
                self.assertEqual(queued, {})
            finally:
                release.set()
            result = await profile_task

        self.assertEqual(result, {"profiles": [{"name": "default"}]})
        self.assertEqual(maintenance, set())
        self.assertEqual(busy, set())
        self.assertEqual(current, {})


class GatedNativeSubscription:
    def __init__(self, notifications: list[dict[str, object]], gate_at: int) -> None:
        self.notifications = notifications
        self.gate_at = gate_at
        self.index = 0
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()
        self.closed = False

    async def next_notification(self, *, timeout: float) -> dict[str, object]:
        del timeout
        if self.index == self.gate_at:
            self.waiting.set()
            await self.release.wait()
        notification = self.notifications[self.index]
        self.index += 1
        return notification

    def close(self) -> None:
        self.closed = True


class CodexNativeLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.previous_sessions = agent_server.STORE.sessions
        self.previous_active = agent_server.ACTIVE
        self.previous_busy = agent_server.BUSY_SESSIONS
        self.previous_current = agent_server.CURRENT_TURNS
        self.previous_tasks = agent_server.CODEX_NATIVE_ACTION_TASKS
        self.previous_terminal_fences = (
            agent_server.CODEX_CONTROL_TERMINAL_FENCES
        )
        self.previous_maintenance = (
            agent_server.SERVER_MAINTENANCE_SESSIONS
        )
        self.previous_pins = agent_server.CODEX_APP_SERVER_PINNED_THREADS
        self.previous_pin_counts = (
            agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS
        )
        self.previous_interactive_threads = (
            agent_server.CODEX_INTERACTIVE_CONTROL_THREADS
        )
        self.previous_interactive_counts = (
            agent_server.CODEX_INTERACTIVE_CONTROL_THREAD_COUNTS
        )
        self.previous_turn_tasks = agent_server.SESSION_TURN_TASKS
        self.previous_interaction_tasks = (
            agent_server.CODEX_INTERACTION_HANDLER_TASKS
        )
        agent_server.STORE.sessions = {
            "chat": {
                "id": "chat",
                "backend": agent_server.BACKEND_CODEX,
                "codex_thread_id": "thread",
            }
        }
        agent_server.ACTIVE = {
            "chat": {
                "run_id": "operation",
                "provider_thread_id": "thread",
                "provider_turn_id": None,
                "provider_turn_ready": False,
                "codex_native_operation": True,
                "codex_control_reservation_id": "control-operation",
            }
        }
        agent_server.BUSY_SESSIONS = {"chat"}
        agent_server.CURRENT_TURNS = {
            "chat": {
                "run_id": None,
                "backend": agent_server.BACKEND_CODEX,
                "purpose": "codex_native_control",
                "codex_control_reservation_id": "control-operation",
            }
        }
        agent_server.CODEX_NATIVE_ACTION_TASKS = {}
        agent_server.CODEX_CONTROL_TERMINAL_FENCES = {}
        agent_server.SERVER_MAINTENANCE_SESSIONS = set()
        agent_server.CODEX_APP_SERVER_PINNED_THREADS = set()
        agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS = {}
        agent_server.CODEX_INTERACTIVE_CONTROL_THREADS = set()
        agent_server.CODEX_INTERACTIVE_CONTROL_THREAD_COUNTS = {}
        agent_server.SESSION_TURN_TASKS = {}
        agent_server.CODEX_INTERACTION_HANDLER_TASKS = {}

    async def asyncTearDown(self) -> None:
        await agent_server.cancel_codex_native_actions()
        agent_server.STORE.sessions = self.previous_sessions
        agent_server.ACTIVE = self.previous_active
        agent_server.BUSY_SESSIONS = self.previous_busy
        agent_server.CURRENT_TURNS = self.previous_current
        agent_server.CODEX_NATIVE_ACTION_TASKS = self.previous_tasks
        agent_server.CODEX_CONTROL_TERMINAL_FENCES = (
            self.previous_terminal_fences
        )
        agent_server.SERVER_MAINTENANCE_SESSIONS = (
            self.previous_maintenance
        )
        agent_server.CODEX_APP_SERVER_PINNED_THREADS = self.previous_pins
        agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS = (
            self.previous_pin_counts
        )
        agent_server.CODEX_INTERACTIVE_CONTROL_THREADS = (
            self.previous_interactive_threads
        )
        agent_server.CODEX_INTERACTIVE_CONTROL_THREAD_COUNTS = (
            self.previous_interactive_counts
        )
        agent_server.SESSION_TURN_TASKS = self.previous_turn_tasks
        agent_server.CODEX_INTERACTION_HANDLER_TASKS = (
            self.previous_interaction_tasks
        )

    async def test_compaction_captures_turn_and_waits_for_turn_completed(self) -> None:
        agent_server.ACTIVE["chat"].update(
            {
                "codex_native_operation_kind": "compaction",
                "codex_compaction_in_progress": True,
                "codex_compaction_token_usage_before": {
                    "context_tokens": 90_000,
                    "context_window": 100_000,
                },
                "codex_compaction_token_usage_after": {
                    "context_tokens": 10_000,
                    "context_window": 100_000,
                },
            }
        )
        subscription = GatedNativeSubscription(
            [
                {
                    "method": "turn/started",
                    "params": {
                        "threadId": "thread",
                        "turn": {"id": "turn-compact"},
                    },
                },
                {
                    "method": "item/completed",
                    "params": {
                        "threadId": "thread",
                        "turnId": "turn-compact",
                        "item": {
                            "id": "compact-item",
                            "type": "contextCompaction",
                        },
                    },
                },
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread",
                        "turn": {
                            "id": "turn-compact",
                            "status": "completed",
                        },
                    },
                },
            ],
            gate_at=2,
        )
        events: list[tuple[str, dict[str, object]]] = []

        async def record_event(
            _session_id: str,
            event_type: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            events.append((event_type, payload))
            return {}

        manager = AsyncMock()
        with (
            patch.object(agent_server, "append_event", side_effect=record_event),
            patch.object(
                agent_server,
                "release_codex_control_thread",
                AsyncMock(),
            ) as release_thread,
        ):
            task = asyncio.create_task(
                agent_server.consume_codex_native_turn(
                    "chat",
                    "operation",
                    "compaction",
                    manager,
                    "thread",
                    "control-operation",
                    subscription,
                )
            )
            await subscription.waiting.wait()
            self.assertFalse(task.done())
            self.assertEqual(
                agent_server.ACTIVE["chat"]["provider_turn_id"],
                "turn-compact",
            )
            self.assertTrue(agent_server.ACTIVE["chat"]["provider_turn_ready"])
            release_thread.assert_not_awaited()

            subscription.release.set()
            await task

        self.assertTrue(subscription.closed)
        self.assertEqual(
            [event_type for event_type, _payload in events].count(
                "codex_compaction_completed"
            ),
            1,
        )
        self.assertEqual(events[-1][1]["turn_id"], "turn-compact")
        self.assertEqual(events[-1][1]["run_id"], "operation")
        self.assertEqual(
            events[-1][1]["token_usage_before"]["context_tokens"],
            90_000,
        )
        self.assertEqual(
            events[-1][1]["token_usage_after"]["context_tokens"],
            10_000,
        )
        self.assertEqual(
            events[-1][1]["message"],
            "Context compaction completed.",
        )
        manager.wait_for_notification_handler.assert_awaited_once_with(
            agent_server.project_codex_notification,
            "thread",
        )
        release_thread.assert_awaited_once()

    async def test_sparse_late_replayed_compaction_completion_does_not_persist_twice(
        self,
    ) -> None:
        agent_server.ACTIVE["chat"].update(
            {
                "codex_native_operation_kind": "compaction",
                "codex_compaction_in_progress": True,
            }
        )
        completed_notification = {
            "method": "item/completed",
            "params": {
                "threadId": "thread",
                "turnId": "turn-compact",
                "item": {
                    "id": "compact-item",
                    "type": "contextCompaction",
                },
            },
        }
        subscription = GatedNativeSubscription(
            [
                {
                    "method": "turn/started",
                    "params": {
                        "threadId": "thread",
                        "turn": {"id": "turn-compact"},
                    },
                },
                completed_notification,
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread",
                        "turn": {
                            "id": "turn-compact",
                            "status": "completed",
                        },
                    },
                },
            ],
            gate_at=3,
        )
        events: list[tuple[str, dict[str, object]]] = []

        async def record_event(
            _session_id: str,
            event_type: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            events.append((event_type, payload))
            return {}

        async def release_control_thread(
            session_id: str,
            _manager: object,
            thread_id: str,
            *,
            reserved_session: bool = False,
            reservation_id: str = "",
            lease_already_released: bool = False,
            schedule_queue: bool = True,
        ) -> None:
            del schedule_queue
            self.assertTrue(reserved_session)
            self.assertEqual(reservation_id, "control-operation")
            self.assertTrue(lease_already_released)
            released = await agent_server.release_codex_control_slot(
                session_id,
                expected_thread_id=thread_id,
                expected_reservation_id=reservation_id,
            )
            self.assertFalse(released)
            self.assertNotIn(
                session_id,
                agent_server.SERVER_MAINTENANCE_SESSIONS,
            )

        manager = AsyncMock()
        with (
            patch.object(agent_server, "append_event", side_effect=record_event),
            patch.object(
                agent_server,
                "release_codex_control_thread",
                side_effect=release_control_thread,
            ),
        ):
            # The global projector sees the provider completion while the
            # manual operation still owns ACTIVE and correctly suppresses it.
            await agent_server.project_codex_notification(completed_notification)
            await agent_server.consume_codex_native_turn(
                "chat",
                "operation",
                "compaction",
                manager,
                "thread",
                "control-operation",
                subscription,
            )
            self.assertNotIn("chat", agent_server.ACTIVE)

            manual_completions = [
                payload
                for event_type, payload in events
                if event_type == "codex_compaction_completed"
            ]
            self.assertEqual(len(manual_completions), 1)
            self.assertEqual(manual_completions[0]["operation_id"], "operation")

            # Replaying either lifecycle edge after ACTIVE was released must
            # not leave an orphan start or a second automatic completion.
            # Either provider identity is sufficient when the other is sparse.
            agent_server.ACTIVE["chat"] = {
                "run_id": "next-run",
                "provider_thread_id": "thread",
                "provider_turn_id": "turn-next",
            }
            await agent_server.project_codex_notification({
                "method": "item/started",
                "params": {
                    "threadId": "thread",
                    "item": {
                        "id": "compact-item",
                        "type": "contextCompaction",
                    },
                },
            })
            self.assertNotIn(
                "codex_compaction_in_progress",
                agent_server.ACTIVE["chat"],
            )
            self.assertNotIn(
                "codex_compaction_item_id",
                agent_server.ACTIVE["chat"],
            )
            agent_server.ACTIVE.pop("chat")
            await agent_server.project_codex_notification({
                "method": "item/started",
                "params": {
                    "threadId": "thread",
                    "turnId": "turn-compact",
                    "item": {"type": "contextCompaction"},
                },
            })
            await agent_server.project_codex_notification(completed_notification)
            await agent_server.project_codex_notification({
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "item": {
                        "id": "compact-item",
                        "type": "contextCompaction",
                    },
                },
            })
            await agent_server.project_codex_notification({
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "turnId": "turn-compact",
                    "item": {"type": "contextCompaction"},
                },
            })

        lifecycle_keys = [
            agent_server.timeline_index_codex_lifecycle_key(
                {"type": event_type, **payload}
            )
            for event_type, payload in events
            if event_type == "codex_compaction_completed"
        ]
        self.assertFalse(any(
            event_type == "codex_compaction_started"
            for event_type, _payload in events
        ))
        self.assertEqual(
            lifecycle_keys,
            ["codex:compaction:operation"],
            "one provider compaction persisted under distinct lifecycle keys",
        )

    def test_native_compaction_terminal_aliases_never_use_thread_alone(self) -> None:
        self.assertEqual(
            agent_server.native_codex_compaction_terminal_aliases(
                "thread",
                None,
                None,
            ),
            (),
        )

    async def test_pending_stop_interrupts_when_compaction_turn_id_arrives(
        self,
    ) -> None:
        agent_server.ACTIVE["chat"]["stop_requested"] = True
        subscription = GatedNativeSubscription(
            [
                {
                    "method": "turn/started",
                    "params": {
                        "threadId": "thread",
                        "turn": {"id": "turn-compact"},
                    },
                },
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread",
                        "turn": {
                            "id": "turn-compact",
                            "status": "interrupted",
                        },
                    },
                },
            ],
            gate_at=1,
        )
        manager = AsyncMock()
        with (
            patch.object(agent_server, "append_event", AsyncMock()),
            patch.object(
                agent_server,
                "release_codex_control_thread",
                AsyncMock(),
            ),
        ):
            task = asyncio.create_task(
                agent_server.consume_codex_native_turn(
                    "chat",
                    "operation",
                    "compaction",
                    manager,
                    "thread",
                    "control-operation",
                    subscription,
                )
            )
            await subscription.waiting.wait()
            manager.request.assert_awaited_once_with(
                "turn/interrupt",
                {
                    "threadId": "thread",
                    "turnId": "turn-compact",
                },
            )
            subscription.release.set()
            await task

    async def test_delayed_cancelled_native_finalizer_cannot_terminalize_replacement(
        self,
    ) -> None:
        subscription = GatedNativeSubscription(
            [
                {
                    "method": "error",
                    "params": {"message": "old native failure"},
                },
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread",
                        "turn": {
                            "id": "turn-old",
                            "status": "interrupted",
                        },
                    },
                },
            ],
            gate_at=1,
        )
        handler_started = asyncio.Event()
        finish_handler = asyncio.Event()

        async def gated_handler(*_args: object, **_kwargs: object) -> None:
            handler_started.set()
            await finish_handler.wait()

        manager = AsyncMock()
        manager.wait_for_notification_handler.side_effect = gated_handler
        append = AsyncMock(return_value={})
        record_usage = AsyncMock()
        schedule = Mock()
        agent_server.STOPPED_RUNS.add("operation")
        with (
            patch.object(agent_server, "append_event", append),
            patch.object(
                agent_server,
                "record_codex_token_usage",
                record_usage,
            ),
            patch.object(
                agent_server,
                "unpin_codex_app_server_thread",
                AsyncMock(),
            ),
            patch.object(
                agent_server,
                "release_codex_interactive_control_lease",
            ),
            patch.object(
                agent_server,
                "schedule_next_queued_turn",
                schedule,
            ),
        ):
            old_consumer = asyncio.create_task(
                agent_server.consume_codex_native_turn(
                    "chat",
                    "operation",
                    "shell",
                    manager,
                    "thread",
                    "control-operation",
                    subscription,
                )
            )
            await asyncio.wait_for(subscription.waiting.wait(), timeout=1)
            old_consumer.cancel()
            await asyncio.wait_for(handler_started.wait(), timeout=1)

            released = await agent_server.release_codex_control_slot(
                "chat",
                expected_thread_id="thread",
                expected_reservation_id="control-operation",
            )
            self.assertTrue(released)
            agent_server.BUSY_SESSIONS.add("chat")
            agent_server.CURRENT_TURNS["chat"] = {
                "run_id": "run-replacement",
                "backend": agent_server.BACKEND_CODEX,
            }
            agent_server.ACTIVE["chat"] = {
                "run_id": "run-replacement",
                "backend": agent_server.BACKEND_CODEX,
                "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
                "provider_thread_id": "thread-new",
            }
            agent_server.STORE.sessions["chat"]["active_run"] = {
                "run_id": "run-replacement"
            }
            finish_handler.set()
            with self.assertRaises(asyncio.CancelledError):
                await old_consumer

        append.assert_not_awaited()
        record_usage.assert_not_awaited()
        schedule.assert_not_called()
        self.assertEqual(
            agent_server.ACTIVE["chat"]["run_id"],
            "run-replacement",
        )
        self.assertEqual(
            agent_server.CURRENT_TURNS["chat"]["run_id"],
            "run-replacement",
        )
        self.assertIn("chat", agent_server.BUSY_SESSIONS)
        self.assertNotIn("chat", agent_server.SERVER_MAINTENANCE_SESSIONS)
        self.assertNotIn("chat", agent_server.CODEX_CONTROL_TERMINAL_FENCES)
        self.assertNotIn("operation", agent_server.STOPPED_RUNS)

    async def test_native_terminal_fence_releases_before_delayed_unpin(self) -> None:
        subscription = GatedNativeSubscription(
            [{
                "method": "turn/completed",
                "params": {
                    "threadId": "thread",
                    "turn": {
                        "id": "turn-old",
                        "status": "completed",
                    },
                },
            }],
            gate_at=99,
        )
        unpin_started = asyncio.Event()
        finish_unpin = asyncio.Event()

        async def delayed_unpin(*_args: object, **_kwargs: object) -> None:
            unpin_started.set()
            await finish_unpin.wait()

        manager = AsyncMock()
        schedule = Mock()
        with (
            patch.object(
                agent_server,
                "append_event",
                AsyncMock(return_value={}),
            ),
            patch.object(
                agent_server,
                "unpin_codex_app_server_thread",
                side_effect=delayed_unpin,
            ),
            patch.object(
                agent_server,
                "release_codex_interactive_control_lease",
            ),
            patch.object(
                agent_server,
                "schedule_next_queued_turn",
                schedule,
            ),
        ):
            old_consumer = asyncio.create_task(
                agent_server.consume_codex_native_turn(
                    "chat",
                    "operation",
                    "shell",
                    manager,
                    "thread",
                    "control-operation",
                    subscription,
                )
            )
            await asyncio.wait_for(unpin_started.wait(), timeout=1)
            self.assertNotIn(
                "chat",
                agent_server.SERVER_MAINTENANCE_SESSIONS,
            )
            self.assertNotIn(
                "chat",
                agent_server.CODEX_CONTROL_TERMINAL_FENCES,
            )
            schedule.assert_called_once_with("chat")

            agent_server.BUSY_SESSIONS.add("chat")
            agent_server.CURRENT_TURNS["chat"] = {
                "run_id": "run-replacement",
                "backend": agent_server.BACKEND_CODEX,
            }
            agent_server.ACTIVE["chat"] = {
                "run_id": "run-replacement",
                "backend": agent_server.BACKEND_CODEX,
                "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
                "provider_thread_id": "thread-new",
            }
            finish_unpin.set()
            await old_consumer

        self.assertEqual(
            agent_server.ACTIVE["chat"]["run_id"],
            "run-replacement",
        )
        self.assertEqual(
            agent_server.CURRENT_TURNS["chat"]["run_id"],
            "run-replacement",
        )
        self.assertIn("chat", agent_server.BUSY_SESSIONS)

    async def test_native_terminal_publication_fence_blocks_replacement_admission(
        self,
    ) -> None:
        subscription = GatedNativeSubscription(
            [{
                "method": "turn/completed",
                "params": {
                    "threadId": "thread",
                    "turn": {
                        "id": "turn-old",
                        "status": "completed",
                    },
                },
            }],
            gate_at=99,
        )
        terminal_append_started = asyncio.Event()
        finish_terminal_append = asyncio.Event()

        async def gated_append(
            _session_id: str,
            event_type: str,
            _payload: dict[str, object],
        ) -> dict[str, object]:
            if event_type == "codex_shell_finished":
                terminal_append_started.set()
                await finish_terminal_append.wait()
            return {}

        manager = AsyncMock()
        schedule = Mock()
        with (
            patch.object(agent_server, "append_event", side_effect=gated_append),
            patch.object(
                agent_server,
                "unpin_codex_app_server_thread",
                AsyncMock(),
            ),
            patch.object(
                agent_server,
                "release_codex_interactive_control_lease",
            ),
            patch.object(
                agent_server,
                "schedule_next_queued_turn",
                schedule,
            ),
        ):
            old_consumer = asyncio.create_task(
                agent_server.consume_codex_native_turn(
                    "chat",
                    "operation",
                    "shell",
                    manager,
                    "thread",
                    "control-operation",
                    subscription,
                )
            )
            await asyncio.wait_for(terminal_append_started.wait(), timeout=1)
            self.assertNotIn("chat", agent_server.ACTIVE)
            self.assertNotIn("chat", agent_server.BUSY_SESSIONS)
            self.assertNotIn("chat", agent_server.CURRENT_TURNS)
            self.assertIn("chat", agent_server.SERVER_MAINTENANCE_SESSIONS)
            self.assertEqual(
                agent_server.CODEX_CONTROL_TERMINAL_FENCES.get("chat"),
                "control-operation",
            )
            with self.assertRaises(agent_server.HTTPException) as raised:
                await agent_server._start_turn_locked(
                    "chat",
                    agent_server.TurnRequest(prompt="replacement"),
                    queue_if_busy=False,
                    admission_backend=agent_server.BACKEND_CODEX,
                )
            self.assertEqual(raised.exception.status_code, 409)
            self.assertIn("maintenance", str(raised.exception.detail))

            finish_terminal_append.set()
            await old_consumer

        self.assertNotIn("chat", agent_server.SERVER_MAINTENANCE_SESSIONS)
        self.assertNotIn("chat", agent_server.CODEX_CONTROL_TERMINAL_FENCES)
        schedule.assert_called_once_with("chat")

    async def test_shell_retains_native_slot_until_turn_completed(self) -> None:
        subscription = GatedNativeSubscription(
            [
                {
                    "method": "turn/started",
                    "params": {
                        "threadId": "thread",
                        "turn": {"id": "turn-shell"},
                    },
                },
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread",
                        "turn": {
                            "id": "turn-shell",
                            "status": "completed",
                        },
                    },
                },
            ],
            gate_at=1,
        )
        manager = AsyncMock()
        manager.subscribe_thread = lambda _thread_id: subscription
        manager.run_thread_shell_command = AsyncMock()

        async def acquire(
            _session_id: str,
            *,
            reserve_session: bool = False,
        ) -> tuple[object, str, dict[str, object]]:
            self.assertTrue(reserve_session)
            return manager, "thread", agent_server.STORE.sessions["chat"]

        with (
            patch.object(
                agent_server,
                "acquire_codex_control_thread",
                side_effect=acquire,
            ),
            patch.object(agent_server, "append_event", AsyncMock()),
            patch.object(
                agent_server,
                "release_codex_control_thread",
                AsyncMock(),
            ) as release_thread,
        ):
            result = await agent_server.post_codex_shell_command(
                "chat",
                agent_server.CodexShellCommandRequest(
                    command="git status --short",
                    confirmed=True,
                ),
            )
            operation_id = str(result["operation_id"])
            task = agent_server.CODEX_NATIVE_ACTION_TASKS[
                ("chat", operation_id)
            ]
            await subscription.waiting.wait()
            self.assertFalse(task.done())
            release_thread.assert_not_awaited()
            self.assertEqual(
                agent_server.ACTIVE["chat"]["provider_turn_id"],
                "turn-shell",
            )

            subscription.release.set()
            await task

        manager.run_thread_shell_command.assert_awaited_once_with(
            "thread",
            "git status --short",
        )
        release_thread.assert_awaited_once()

    async def test_native_actions_remain_owned_when_start_event_write_fails(
        self,
    ) -> None:
        cases = (
            (
                "compaction",
                "codex_compaction_started",
                lambda: agent_server.post_codex_compact("chat"),
            ),
            (
                "review",
                "codex_review_started",
                lambda: agent_server.post_codex_review(
                    "chat",
                    agent_server.CodexReviewRequest(target={"type": "uncommittedChanges"}),
                ),
            ),
            (
                "shell",
                "codex_shell_started",
                lambda: agent_server.post_codex_shell_command(
                    "chat",
                    agent_server.CodexShellCommandRequest(
                        command="git status --short",
                        confirmed=True,
                    ),
                ),
            ),
        )
        for operation, failing_event, launch in cases:
            with self.subTest(operation=operation):
                agent_server.ACTIVE["chat"].update(
                    {
                        "run_id": None,
                        "provider_turn_id": None,
                        "provider_turn_ready": False,
                        "codex_native_operation_kind": None,
                    }
                )
                turn_id = f"turn-{operation}"
                subscription = GatedNativeSubscription(
                    [
                        {
                            "method": "turn/completed",
                            "params": {
                                "threadId": "thread",
                                "turn": {
                                    "id": turn_id,
                                    "status": "completed",
                                },
                            },
                        }
                    ],
                    gate_at=0,
                )
                manager = AsyncMock()
                manager.subscribe_thread = lambda _thread_id: subscription
                manager.compact_thread = AsyncMock()
                manager.start_review = AsyncMock(
                    return_value={"turn": {"id": turn_id}}
                )
                manager.run_thread_shell_command = AsyncMock()

                async def acquire(
                    _session_id: str,
                    *,
                    reserve_session: bool = False,
                ) -> tuple[object, str, dict[str, object]]:
                    self.assertTrue(reserve_session)
                    return manager, "thread", agent_server.STORE.sessions["chat"]

                async def persist_event(
                    _session_id: str,
                    event_type: str,
                    _payload: dict[str, object],
                ) -> dict[str, object]:
                    if event_type == failing_event:
                        raise OSError("disk full")
                    return {}

                with (
                    patch.object(
                        agent_server,
                        "acquire_codex_control_thread",
                        side_effect=acquire,
                    ),
                    patch.object(
                        agent_server,
                        "append_event",
                        side_effect=persist_event,
                    ),
                    patch.object(
                        agent_server,
                        "release_codex_control_thread",
                        AsyncMock(),
                    ) as release_thread,
                ):
                    result = await launch()
                    operation_id = str(result["operation_id"])
                    task = agent_server.CODEX_NATIVE_ACTION_TASKS[
                        ("chat", operation_id)
                    ]
                    await subscription.waiting.wait()
                    self.assertFalse(task.done())
                    release_thread.assert_not_awaited()
                    subscription.release.set()
                    await task
                    release_thread.assert_awaited_once()

    async def test_budget_interrupt_survives_timeline_write_failure(self) -> None:
        agent_server.STORE.sessions["chat"].update(
            {
                "codex_goal": {
                    "status": "active",
                    "timeUsedSeconds": 10,
                },
                "codex_goal_time_budget_seconds": 10,
            }
        )
        agent_server.ACTIVE["chat"]["run_id"] = "run-budget"
        manager = AsyncMock()
        manager.set_thread_goal = AsyncMock(
            return_value={
                "status": "budgetLimited",
                "timeUsedSeconds": 10,
            }
        )
        turn = AsyncMock()
        turn.turn_id = "turn-budget"
        with (
            patch.object(agent_server.STORE, "save", AsyncMock()),
            patch.object(
                agent_server,
                "append_event",
                AsyncMock(side_effect=OSError("disk full")),
            ),
        ):
            await agent_server.apply_codex_goal_time_budget_limit(
                "chat",
                "run-budget",
                manager,
                "thread",
                turn,
                10,
            )
        turn.interrupt.assert_awaited_once()
        self.assertTrue(agent_server.ACTIVE["chat"]["stop_requested"])
        self.assertTrue(
            agent_server.STORE.sessions["chat"][
                "codex_goal_time_budget_exhausted"
            ]
        )

    async def test_native_tasks_can_be_cancelled_by_session(self) -> None:
        agent_server.ACTIVE.pop("chat", None)
        first = asyncio.create_task(asyncio.Event().wait())
        second = asyncio.create_task(asyncio.Event().wait())
        agent_server.register_codex_native_action("chat", "first", first)
        agent_server.register_codex_native_action("other", "second", second)

        await agent_server.cancel_codex_native_actions("chat")

        self.assertTrue(first.cancelled())
        self.assertFalse(second.done())
        self.assertNotIn(("chat", "first"), agent_server.CODEX_NATIVE_ACTION_TASKS)
        self.assertIn(("other", "second"), agent_server.CODEX_NATIVE_ACTION_TASKS)

    async def test_native_task_without_turn_id_is_not_orphaned_by_cancel(
        self,
    ) -> None:
        task = asyncio.create_task(asyncio.Event().wait())
        agent_server.register_codex_native_action("chat", "operation", task)
        previous_manager = agent_server.CODEX_APP_SERVER_MANAGER
        agent_server.CODEX_APP_SERVER_MANAGER = AsyncMock()
        try:
            with (
                patch.object(
                    agent_server,
                    "CODEX_SESSION_CLEANUP_TIMEOUT_SECONDS",
                    0.01,
                ),
                self.assertRaises(HTTPException) as raised,
            ):
                await agent_server.cancel_codex_native_actions("chat")
            self.assertEqual(raised.exception.status_code, 409)
            self.assertFalse(task.done())
            self.assertTrue(
                agent_server.ACTIVE["chat"]["stop_requested"]
            )
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            agent_server.CODEX_NATIVE_ACTION_TASKS.pop(
                ("chat", "operation"),
                None,
            )
            agent_server.CODEX_APP_SERVER_MANAGER = previous_manager

    async def test_thread_pins_and_interactive_controls_are_reference_counted(
        self,
    ) -> None:
        manager = AsyncMock()
        await agent_server.pin_codex_app_server_thread("thread")
        await agent_server.pin_codex_app_server_thread("thread")
        await agent_server.unpin_codex_app_server_thread(manager, "thread")
        self.assertIn(
            "thread",
            agent_server.CODEX_APP_SERVER_PINNED_THREADS,
        )
        self.assertEqual(
            agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["thread"],
            1,
        )

        agent_server.acquire_codex_interactive_control_lease("thread")
        agent_server.acquire_codex_interactive_control_lease("thread")
        agent_server.release_codex_interactive_control_lease("thread")
        self.assertIn(
            "thread",
            agent_server.CODEX_INTERACTIVE_CONTROL_THREADS,
        )
        self.assertEqual(
            agent_server.CODEX_INTERACTIVE_CONTROL_THREAD_COUNTS["thread"],
            1,
        )

    async def test_noninteractive_active_turn_allows_goal_clear_on_loaded_thread(
        self,
    ) -> None:
        agent_server.STORE.sessions["chat"]["codex_goal"] = {
            "objective": "Finish the active task",
            "status": "active",
        }
        agent_server.ACTIVE["chat"].update({
            "backend": agent_server.BACKEND_CODEX,
            "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
            "provider_thread_id": "thread",
            "interactive_app_server": False,
            "codex_native_operation": False,
        })
        agent_server.CODEX_APP_SERVER_PINNED_THREADS.add("thread")
        agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["thread"] = 1
        manager = AsyncMock()
        manager.is_thread_loaded = Mock(return_value=True)

        async def clear_thread_goal(thread_id: str) -> bool:
            self.assertEqual(thread_id, "thread")
            self.assertIn(
                "chat",
                agent_server.SERVER_MAINTENANCE_SESSIONS,
            )
            return True

        manager.clear_thread_goal.side_effect = clear_thread_goal

        with (
            patch.object(
                agent_server,
                "CODEX_APP_SERVER_MANAGER",
                manager,
            ),
            patch.object(agent_server.STORE, "save", AsyncMock()),
            patch.object(
                agent_server,
                "touch_codex_app_server_thread",
                AsyncMock(),
            ),
            patch.object(
                agent_server,
                "ensure_codex_app_server_thread",
                AsyncMock(),
            ) as ensure_thread,
        ):
            result = await agent_server._delete_codex_goal_locked("chat")

        self.assertEqual(
            result,
            {
                "goal": None,
                "time_budget_seconds": None,
                "time_budget_exhausted": False,
            },
        )
        manager.clear_thread_goal.assert_awaited_once_with("thread")
        ensure_thread.assert_not_awaited()
        self.assertIsNone(
            agent_server.STORE.sessions["chat"]["codex_goal"],
        )
        self.assertIn("chat", agent_server.BUSY_SESSIONS)
        self.assertIn("chat", agent_server.ACTIVE)
        self.assertIn(
            "thread",
            agent_server.CODEX_APP_SERVER_PINNED_THREADS,
        )
        self.assertEqual(
            agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["thread"],
            1,
        )
        self.assertNotIn(
            "thread",
            agent_server.CODEX_INTERACTIVE_CONTROL_THREADS,
        )
        self.assertNotIn(
            "chat",
            agent_server.SERVER_MAINTENANCE_SESSIONS,
        )

    async def test_active_native_operation_allows_goal_clear_on_loaded_thread(
        self,
    ) -> None:
        agent_server.STORE.sessions["chat"]["codex_goal"] = {
            "objective": "Stop this goal",
            "status": "active",
        }
        agent_server.ACTIVE["chat"].update({
            "backend": agent_server.BACKEND_CODEX,
            "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
            "provider_thread_id": "thread",
            "interactive_app_server": True,
            "codex_native_operation": True,
        })
        manager = AsyncMock()
        manager.is_thread_loaded = Mock(return_value=True)
        manager.active_turn = Mock(return_value=None)

        with (
            patch.object(
                agent_server,
                "CODEX_APP_SERVER_MANAGER",
                manager,
            ),
            patch.object(agent_server.STORE, "save", AsyncMock()),
        ):
            result = await agent_server._delete_codex_goal_locked("chat")

        self.assertEqual(
            result,
            {
                "goal": None,
                "time_budget_seconds": None,
                "time_budget_exhausted": False,
            },
        )
        manager.clear_thread_goal.assert_awaited_once_with("thread")
        self.assertNotIn(
            "thread",
            agent_server.CODEX_APP_SERVER_PINNED_THREADS,
        )
        self.assertNotIn(
            "thread",
            agent_server.CODEX_INTERACTIVE_CONTROL_THREADS,
        )

    async def test_noninteractive_active_turn_allows_goal_update_on_loaded_thread(
        self,
    ) -> None:
        agent_server.STORE.sessions["chat"]["codex_goal"] = {
            "objective": "Finish the active task",
            "status": "active",
            "timeUsedSeconds": 31,
        }
        agent_server.ACTIVE["chat"].update({
            "backend": agent_server.BACKEND_CODEX,
            "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
            "provider_thread_id": "thread",
            "interactive_app_server": False,
            "codex_native_operation": False,
        })
        agent_server.CODEX_APP_SERVER_PINNED_THREADS.add("thread")
        agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["thread"] = 1
        manager = AsyncMock()
        manager.is_thread_loaded = Mock(return_value=True)
        manager.set_thread_goal.return_value = {
            "objective": "Finish the active task",
            "status": "paused",
            "timeUsedSeconds": 31,
        }

        with (
            patch.object(
                agent_server,
                "CODEX_APP_SERVER_MANAGER",
                manager,
            ),
            patch.object(agent_server.STORE, "save", AsyncMock()),
            patch.object(
                agent_server,
                "touch_codex_app_server_thread",
                AsyncMock(),
            ),
            patch.object(
                agent_server,
                "ensure_codex_app_server_thread",
                AsyncMock(),
            ) as ensure_thread,
        ):
            result = await agent_server._put_codex_goal_locked(
                "chat",
                agent_server.CodexGoalRequest(status="paused"),
            )

        self.assertEqual(result["goal"]["status"], "paused")
        manager.set_thread_goal.assert_awaited_once_with(
            "thread",
            status="paused",
        )
        ensure_thread.assert_not_awaited()
        self.assertIn("chat", agent_server.BUSY_SESSIONS)
        self.assertIn(
            "thread",
            agent_server.CODEX_APP_SERVER_PINNED_THREADS,
        )
        self.assertEqual(
            agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["thread"],
            1,
        )
        self.assertNotIn(
            "thread",
            agent_server.CODEX_INTERACTIVE_CONTROL_THREADS,
        )

    async def test_manager_shutdown_clears_lru_touched_by_turn_finalizer(
        self,
    ) -> None:
        class Manager:
            generation = 1

            def __init__(self) -> None:
                self.closed = asyncio.Event()

            async def close(self) -> None:
                self.closed.set()

            def is_thread_loaded(self, _thread_id: str) -> bool:
                return True

            def active_turn(self, _thread_id: str) -> None:
                return None

        manager = Manager()

        async def finalize_after_close() -> None:
            await manager.closed.wait()
            await agent_server.unpin_codex_app_server_thread(
                manager,
                "thread",
            )

        task = asyncio.create_task(finalize_after_close())
        agent_server.register_session_task(
            agent_server.SESSION_TURN_TASKS,
            "chat",
            task,
        )
        previous_manager = agent_server.CODEX_APP_SERVER_MANAGER
        agent_server.CODEX_APP_SERVER_MANAGER = manager
        agent_server.CODEX_APP_SERVER_PINNED_THREADS.add("thread")
        agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["thread"] = 1
        try:
            with (
                patch.object(
                    agent_server,
                    "cancel_codex_interactions",
                    AsyncMock(),
                ),
                patch.object(
                    agent_server,
                    "cancel_codex_native_actions",
                    AsyncMock(),
                ),
                patch.object(
                    agent_server,
                    "reset_codex_ephemeral_runtime_metadata",
                    AsyncMock(),
                ),
            ):
                await agent_server.close_codex_app_server_manager()
            self.assertFalse(agent_server.CODEX_APP_SERVER_THREAD_LRU)
            self.assertFalse(agent_server.CODEX_APP_SERVER_PINNED_THREADS)
            self.assertFalse(agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS)
        finally:
            agent_server.CODEX_APP_SERVER_MANAGER = previous_manager

    async def test_deleting_session_discards_append_waiting_on_event_lock(
        self,
    ) -> None:
        lock = agent_server.event_delivery_lock("chat")
        await lock.acquire()
        append_task = asyncio.create_task(
            agent_server.append_event(
                "chat",
                "codex_thread_status",
                {"message": "late"},
            )
        )
        await asyncio.sleep(0)
        agent_server.DELETING_SESSIONS.add("chat")
        try:
            lock.release()
            event = await append_task
        finally:
            agent_server.DELETING_SESSIONS.discard("chat")
        self.assertTrue(event["discarded"])
        self.assertEqual(event["seq"], 0)

    async def test_session_turn_tasks_are_joinable_before_delete(self) -> None:
        release = asyncio.Event()
        task = asyncio.create_task(release.wait())
        agent_server.register_session_task(
            agent_server.SESSION_TURN_TASKS,
            "chat",
            task,
        )
        self.assertFalse(
            await agent_server.wait_for_session_tasks(
                agent_server.SESSION_TURN_TASKS,
                "chat",
                timeout=0.01,
            )
        )
        release.set()
        await task
        self.assertTrue(
            await agent_server.wait_for_session_tasks(
                agent_server.SESSION_TURN_TASKS,
                "chat",
                timeout=0.01,
            )
        )

    async def test_delete_pauses_active_goal_before_interrupting_turn(self) -> None:
        order: list[str] = []
        paused_goal = {
            "id": "goal",
            "threadId": "thread",
            "objective": "Finish the task",
            "status": "paused",
        }
        agent_server.STORE.sessions["chat"]["codex_goal"] = {
            **paused_goal,
            "status": "active",
        }
        interrupted = asyncio.Event()
        native_turn = Mock(turn_id="turn")

        async def interrupt() -> None:
            order.append("interrupt")
            interrupted.set()

        native_turn.interrupt = AsyncMock(side_effect=interrupt)
        agent_server.ACTIVE["chat"] = {
            "run_id": "run",
            "backend": agent_server.BACKEND_CODEX,
            "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
            "provider_thread_id": "thread",
            "provider_session_id": "thread",
            "provider_turn_id": "turn",
            "provider_turn_ready": True,
            "codex_native_operation": False,
            "codex_app_server_turn": native_turn,
        }

        manager = Mock()
        manager.is_thread_loaded = Mock(return_value=True)
        manager.unsubscribe_thread = AsyncMock()

        async def pause_goal(
            thread_id: str,
            *,
            status: str,
        ) -> dict[str, object]:
            self.assertEqual(thread_id, "thread")
            self.assertEqual(status, "paused")
            order.append("pause")
            return paused_goal

        manager.set_thread_goal = AsyncMock(side_effect=pause_goal)
        turn_task = asyncio.create_task(interrupted.wait())
        agent_server.register_session_task(
            agent_server.SESSION_TURN_TASKS,
            "chat",
            turn_task,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir)
            session_path = state_dir / "sessions" / "chat"
            session_path.mkdir(parents=True)
            with (
                patch.object(agent_server, "STATE_DIR", state_dir),
                patch.object(
                    agent_server,
                    "SESSIONS_FILE",
                    state_dir / "sessions.json",
                ),
                patch.object(agent_server, "ensure_dirs"),
                patch.object(
                    agent_server,
                    "CODEX_APP_SERVER_MANAGER",
                    manager,
                ),
                patch.object(
                    agent_server.JOBS,
                    "delete_for_session",
                    AsyncMock(return_value=0),
                ),
                patch.object(agent_server, "kill_terminal_session"),
            ):
                try:
                    result = await agent_server.delete_session("chat")
                finally:
                    agent_server.DELETED_SESSION_TOMBSTONES.discard("chat")

        self.assertEqual(order, ["pause", "interrupt"])
        manager.set_thread_goal.assert_awaited_once_with(
            "thread",
            status="paused",
        )
        native_turn.interrupt.assert_awaited_once()
        self.assertTrue(result["deleted"])
        self.assertNotIn("chat", agent_server.STORE.sessions)

    async def test_delete_preserves_session_when_active_goal_cannot_pause(
        self,
    ) -> None:
        active_goal = {
            "id": "goal",
            "threadId": "thread",
            "objective": "Finish the task",
            "status": "active",
        }
        agent_server.STORE.sessions["chat"]["codex_goal"] = active_goal
        native_turn = Mock(turn_id="turn")
        native_turn.interrupt = AsyncMock()
        agent_server.ACTIVE["chat"] = {
            "run_id": "run",
            "backend": agent_server.BACKEND_CODEX,
            "transport": agent_server.CODEX_TRANSPORT_APP_SERVER,
            "provider_thread_id": "thread",
            "provider_session_id": "thread",
            "provider_turn_id": "turn",
            "provider_turn_ready": True,
            "codex_native_operation": False,
            "codex_app_server_turn": native_turn,
        }
        manager = Mock()
        manager.set_thread_goal = AsyncMock(
            side_effect=RuntimeError("goal control unavailable")
        )

        with (
            patch.object(
                agent_server,
                "CODEX_APP_SERVER_MANAGER",
                manager,
            ),
            self.assertRaises(HTTPException) as raised,
        ):
            await agent_server.delete_session("chat")

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("goal control unavailable", str(raised.exception.detail))
        self.assertIn("chat", agent_server.STORE.sessions)
        self.assertEqual(
            agent_server.STORE.sessions["chat"]["codex_goal"],
            active_goal,
        )
        self.assertNotIn("chat", agent_server.DELETED_SESSION_TOMBSTONES)
        self.assertNotIn("chat", agent_server.DELETING_SESSIONS)
        native_turn.interrupt.assert_not_awaited()

    async def test_delete_drains_late_turn_before_removing_session(self) -> None:
        late_event: dict[str, object] = {}

        async def finish_during_delete() -> None:
            while "chat" not in agent_server.DELETING_SESSIONS:
                await asyncio.sleep(0)
            late_event.update(
                await agent_server.append_event(
                    "chat",
                    "assistant_text",
                    {"text": "too late"},
                )
            )

        task = asyncio.create_task(finish_during_delete())
        agent_server.register_session_task(
            agent_server.SESSION_TURN_TASKS,
            "chat",
            task,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir)
            session_path = state_dir / "sessions" / "chat"
            session_path.mkdir(parents=True)
            (session_path / "events.jsonl").write_text("{}\n")
            with (
                patch.object(agent_server, "STATE_DIR", state_dir),
                patch.object(
                    agent_server,
                    "SESSIONS_FILE",
                    state_dir / "sessions.json",
                ),
                patch.object(agent_server, "ensure_dirs"),
                patch.object(
                    agent_server,
                    "CODEX_APP_SERVER_MANAGER",
                    None,
                ),
                patch.object(
                    agent_server.JOBS,
                    "delete_for_session",
                    AsyncMock(return_value=0),
                ),
                patch.object(agent_server, "kill_terminal_session"),
            ):
                try:
                    result = await agent_server.delete_session("chat")
                    self.assertIn(
                        "chat",
                        agent_server.DELETED_SESSION_TOMBSTONES,
                    )
                finally:
                    agent_server.DELETED_SESSION_TOMBSTONES.discard("chat")

            self.assertTrue(result["deleted"])
            self.assertFalse(session_path.exists())
        self.assertNotIn("chat", agent_server.STORE.sessions)
        self.assertTrue(late_event["discarded"])

    async def test_cancelled_committed_delete_finishes_all_cleanup(self) -> None:
        store = agent_server.SessionStore()
        store.sessions = {
            "chat": {
                "id": "chat",
                "backend": agent_server.BACKEND_CODEX,
                "codex_thread_id": "thread",
            },
        }
        first_write_started = threading.Event()
        release_first_write = threading.Event()
        real_write = agent_server.write_sessions_json_text

        def blocked_write(
            path: Path,
            text: str,
            *,
            durable: bool,
        ) -> None:
            self.assertNotIn("chat", json.loads(text))
            first_write_started.set()
            self.assertTrue(release_first_write.wait(timeout=2))
            real_write(path, text, durable=durable)

        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir)
            session_path = state_dir / "sessions" / "chat"
            session_path.mkdir(parents=True)
            (session_path / "events.jsonl").write_text("{}\n")
            delete_jobs = AsyncMock(return_value=2)
            retire_tunnels = AsyncMock()
            event_seq_cache = {"chat": 41}
            with (
                patch.object(agent_server, "STORE", store),
                patch.object(agent_server, "STATE_DIR", state_dir),
                patch.object(
                    agent_server,
                    "SESSIONS_FILE",
                    state_dir / "sessions.json",
                ),
                patch.object(agent_server, "ensure_dirs"),
                patch.object(
                    agent_server,
                    "EVENT_SEQ_CACHE",
                    event_seq_cache,
                ),
                patch.object(agent_server, "EVENT_SEQ_LOCK", asyncio.Lock()),
                patch.object(
                    agent_server,
                    "write_sessions_json_text",
                    side_effect=blocked_write,
                ),
                patch.object(
                    agent_server,
                    "CODEX_APP_SERVER_MANAGER",
                    None,
                ),
                patch.object(
                    agent_server.JOBS,
                    "delete_for_session",
                    delete_jobs,
                ),
                patch.object(
                    agent_server,
                    "retire_session_port_tunnels",
                    retire_tunnels,
                ),
                patch.object(agent_server, "kill_terminal_session"),
            ):
                delete_task = asyncio.create_task(
                    agent_server.delete_session("chat")
                )
                try:
                    self.assertTrue(
                        await asyncio.to_thread(first_write_started.wait, 1)
                    )
                    delete_task.cancel()
                    await asyncio.sleep(0)
                    self.assertFalse(delete_task.done())
                    # Cleanup remains owned through repeated caller cancels.
                    delete_task.cancel()
                finally:
                    release_first_write.set()
                with self.assertRaises(asyncio.CancelledError):
                    await delete_task

            persisted = json.loads(
                (state_dir / "sessions.json").read_text(encoding="utf-8")
            )
            self.assertNotIn("chat", persisted)
            self.assertFalse(session_path.exists())

        self.assertNotIn("chat", store.sessions)
        self.assertNotIn("chat", event_seq_cache)
        self.assertIn("chat", agent_server.DELETED_SESSION_TOMBSTONES)
        self.assertNotIn("chat", agent_server.DELETING_SESSIONS)
        delete_jobs.assert_awaited_once_with("chat")
        retire_tunnels.assert_awaited_once()
        agent_server.DELETED_SESSION_TOMBSTONES.discard("chat")

    async def test_delete_job_cleanup_failure_is_retryable_without_resurrection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir)
            session_path = state_dir / "sessions" / "chat"
            session_path.mkdir(parents=True)
            (session_path / "events.jsonl").write_text("{}\n")
            delete_jobs = AsyncMock(
                side_effect=[OSError("job store unavailable"), 2]
            )
            with (
                patch.object(agent_server, "STATE_DIR", state_dir),
                patch.object(
                    agent_server,
                    "SESSIONS_FILE",
                    state_dir / "sessions.json",
                ),
                patch.object(agent_server, "ensure_dirs"),
                patch.object(
                    agent_server,
                    "CODEX_APP_SERVER_MANAGER",
                    None,
                ),
                patch.object(
                    agent_server.JOBS,
                    "delete_for_session",
                    delete_jobs,
                ),
                patch.object(agent_server, "kill_terminal_session"),
            ):
                try:
                    with self.assertRaisesRegex(
                        OSError,
                        "job store unavailable",
                    ):
                        await agent_server.delete_session("chat")

                    self.assertNotIn("chat", agent_server.STORE.sessions)
                    self.assertIn(
                        "chat",
                        agent_server.DELETED_SESSION_TOMBSTONES,
                    )
                    self.assertFalse(session_path.exists())
                    late_event = await agent_server.append_event(
                        "chat",
                        "job_error",
                        {"message": "must not resurrect"},
                    )
                    self.assertTrue(late_event["discarded"])
                    self.assertFalse(session_path.exists())

                    retry = await agent_server.delete_session("chat")
                    self.assertFalse(retry["deleted"])
                    self.assertEqual(retry["deleted_jobs"], 2)
                    self.assertEqual(delete_jobs.await_count, 2)
                    self.assertFalse(session_path.exists())
                finally:
                    agent_server.DELETED_SESSION_TOMBSTONES.discard("chat")

    async def test_delete_cleans_provider_thread_bound_while_turn_drains(
        self,
    ) -> None:
        agent_server.STORE.sessions["chat"]["codex_thread_id"] = None

        class LateBindingManager:
            def __init__(self) -> None:
                self.unsubscribe_thread = AsyncMock()

            def is_thread_loaded(self, _thread_id: str) -> bool:
                return True

        manager = LateBindingManager()
        thread_index: dict[str, str] = {}
        thread_lru = agent_server.OrderedDict()
        approval_cache = agent_server.OrderedDict()

        async def bind_before_turn_finishes() -> None:
            while "chat" not in agent_server.DELETING_SESSIONS:
                await asyncio.sleep(0)
            session = agent_server.STORE.sessions["chat"]
            session["session_id"] = "late-thread"
            session["codex_thread_id"] = "late-thread"
            thread_index["late-thread"] = "chat"
            thread_lru["late-thread"] = 1.0
            agent_server.CODEX_APP_SERVER_PINNED_THREADS.add("late-thread")
            agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["late-thread"] = 1
            agent_server.CODEX_INTERACTIVE_CONTROL_THREADS.add("late-thread")
            agent_server.CODEX_INTERACTIVE_CONTROL_THREAD_COUNTS["late-thread"] = 1
            approval_cache[("late-thread", "approval")] = {"id": "approval"}

        turn_task = asyncio.create_task(bind_before_turn_finishes())
        agent_server.register_session_task(
            agent_server.SESSION_TURN_TASKS,
            "chat",
            turn_task,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir)
            session_path = state_dir / "sessions" / "chat"
            session_path.mkdir(parents=True)
            with (
                patch.object(agent_server, "STATE_DIR", state_dir),
                patch.object(
                    agent_server,
                    "SESSIONS_FILE",
                    state_dir / "sessions.json",
                ),
                patch.object(agent_server, "ensure_dirs"),
                patch.object(
                    agent_server,
                    "CODEX_APP_SERVER_MANAGER",
                    manager,
                ),
                patch.object(
                    agent_server,
                    "CODEX_THREAD_SESSION_INDEX",
                    thread_index,
                ),
                patch.object(
                    agent_server,
                    "CODEX_APP_SERVER_THREAD_LRU",
                    thread_lru,
                ),
                patch.object(
                    agent_server,
                    "CODEX_APPROVAL_ITEM_CACHE",
                    approval_cache,
                ),
                patch.object(
                    agent_server.JOBS,
                    "delete_for_session",
                    AsyncMock(return_value=0),
                ),
                patch.object(agent_server, "kill_terminal_session"),
            ):
                try:
                    result = await agent_server.delete_session("chat")
                finally:
                    agent_server.DELETED_SESSION_TOMBSTONES.discard("chat")

        self.assertTrue(result["deleted"])
        manager.unsubscribe_thread.assert_awaited_once_with("late-thread")
        self.assertNotIn("late-thread", thread_index)
        self.assertNotIn("late-thread", thread_lru)
        self.assertNotIn(
            "late-thread",
            agent_server.CODEX_APP_SERVER_PINNED_THREADS,
        )
        self.assertNotIn(
            "late-thread",
            agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS,
        )
        self.assertNotIn(
            "late-thread",
            agent_server.CODEX_INTERACTIVE_CONTROL_THREADS,
        )
        self.assertNotIn(
            "late-thread",
            agent_server.CODEX_INTERACTIVE_CONTROL_THREAD_COUNTS,
        )
        self.assertFalse(approval_cache)

    async def test_delete_timeout_preserves_session_for_retry(self) -> None:
        task = asyncio.create_task(asyncio.Event().wait())
        agent_server.register_session_task(
            agent_server.SESSION_TURN_TASKS,
            "chat",
            task,
        )
        try:
            async def wait_for_tasks(
                registry: dict[str, set[asyncio.Task[object]]],
                _session_id: str,
                **_kwargs: object,
            ) -> bool:
                return registry is not agent_server.SESSION_TURN_TASKS

            with (
                patch.object(
                    agent_server,
                    "wait_for_session_tasks",
                    side_effect=wait_for_tasks,
                ),
                self.assertRaises(HTTPException) as raised,
            ):
                await agent_server.delete_session("chat")
            self.assertEqual(raised.exception.status_code, 409)
            self.assertIn("chat", agent_server.STORE.sessions)
            self.assertNotIn(
                "chat",
                agent_server.DELETED_SESSION_TOMBSTONES,
            )
            self.assertNotIn("chat", agent_server.DELETING_SESSIONS)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_deleted_session_does_not_receive_native_final_events(self) -> None:
        agent_server.STORE.sessions = {}
        subscription = GatedNativeSubscription(
            [
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread",
                        "turn": {"id": "turn", "status": "completed"},
                    },
                }
            ],
            gate_at=1,
        )
        subscription.release.set()
        with (
            patch.object(agent_server, "append_event", AsyncMock()) as append,
            patch.object(
                agent_server,
                "release_codex_control_thread",
                AsyncMock(),
            ),
        ):
            await agent_server.consume_codex_native_turn(
                "chat",
                "operation",
                "shell",
                AsyncMock(),
                "thread",
                "control-operation",
                subscription,
            )
        append.assert_not_awaited()

    async def test_rollback_requires_server_side_confirmation(self) -> None:
        with patch.object(
            agent_server,
            "acquire_codex_control_thread",
            AsyncMock(),
        ) as acquire:
            with self.assertRaises(HTTPException) as raised:
                await agent_server.post_codex_rollback(
                    "chat",
                    agent_server.CodexRollbackRequest(
                        num_turns=1,
                        confirmed=False,
                    ),
                )
        self.assertEqual(raised.exception.status_code, 400)
        acquire.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
