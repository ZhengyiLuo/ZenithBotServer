import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import agent_server


class FakeCodexAppServerManager:
    def __init__(self, *, loaded: set[str] | None = None) -> None:
        self.loaded = set(loaded or set())
        self.active: dict[str, object] = {}
        self.start_calls: list[dict[str, object]] = []
        self.resume_calls: list[tuple[str, dict[str, object]]] = []
        self.inject_calls: list[tuple[str, list[dict[str, object]]]] = []
        self.unsubscribe_calls: list[str] = []

    def is_thread_loaded(self, thread_id: str) -> bool:
        return thread_id in self.loaded

    def active_turn(self, thread_id: str) -> object | None:
        return self.active.get(thread_id)

    async def start_thread(self, params: dict[str, object]) -> str:
        self.start_calls.append(params)
        self.loaded.add("thread-new")
        return "thread-new"

    async def resume_thread(
        self,
        thread_id: str,
        params: dict[str, object] | None = None,
    ) -> str:
        self.resume_calls.append((thread_id, dict(params or {})))
        self.loaded.add(thread_id)
        return thread_id

    async def inject_items(
        self,
        thread_id: str,
        items: list[dict[str, object]],
    ) -> None:
        self.inject_calls.append((thread_id, items))

    async def unsubscribe_thread(self, thread_id: str) -> str:
        self.unsubscribe_calls.append(thread_id)
        self.loaded.discard(thread_id)
        return "unsubscribed"


class CodexThreadPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self) -> None:
        for event in agent_server.CODEX_APP_SERVER_EVICTING_THREADS.values():
            event.set()
        agent_server.CODEX_APP_SERVER_EVICTING_THREADS.clear()
        agent_server.CODEX_APP_SERVER_PINNED_THREADS.clear()
        agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS.clear()
        agent_server.CODEX_APP_SERVER_INVALIDATED_THREADS.clear()
        agent_server.CODEX_APP_SERVER_THREAD_LRU.clear()

    def session(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "id": "chat-1",
            "backend": agent_server.BACKEND_CODEX,
            "cwd": "/repo",
        }
        value.update(overrides)
        return value

    def test_compact_policy_is_thread_context_not_a_user_wrapper(self) -> None:
        session = self.session()
        with patch.object(
            agent_server,
            "codex_user_developer_instructions",
            return_value="",
        ):
            instructions = agent_server.codex_thread_instructions("chat-1", session)

        self.assertNotIn("[AgentsDock context]", instructions)
        self.assertNotIn("User prompt follows", instructions)
        self.assertNotIn("Scheduled jobs", instructions)
        self.assertNotIn("Current jobs for this chat", instructions)
        self.assertIn(str(agent_server.codex_manifest_path("chat-1")), instructions)
        self.assertIn("current turn's provider-authority block", instructions)
        self.assertNotIn("--chat-id chat-1", instructions)
        self.assertIn(agent_server.terminal_session_name("chat-1"), instructions)
        self.assertIn("immediately retry the still-safe requested operation", instructions)
        self.assertIn("delegate bounded noisy exploration", instructions)
        self.assertIn("Never detach required work", instructions)
        self.assertIn("`nohup`, `disown`, `setsid`, or shell `&`", instructions)
        self.assertIn("provider-tracked exec, Agent, or workflow", instructions)
        self.assertIn("observable service manager", instructions)
        self.assertIn("Never rely on provider-local timers, loops, or detached processes", instructions)
        self.assertIn("wake this AgentsDock chat or deliver a later reply", instructions)
        self.assertIn("Manage durable scheduled jobs only when explicitly asked", instructions)
        # Context diet: the static provider-authority usage and delivery
        # provenance rules moved from every per-turn prompt into these thread
        # instructions, so the line budget applies to the core policy and the
        # static addendum is bounded separately (present exactly once).
        core = instructions.split(agent_server.PROVIDER_THREAD_INSTRUCTION_ADDENDUM.strip())[0]
        self.assertLessEqual(len(core.strip().splitlines()), 16)
        self.assertEqual(
            instructions.count(agent_server.PROVIDER_THREAD_INSTRUCTION_ADDENDUM.strip()),
            1,
        )

    def test_codex_policy_version_rotates_existing_thread_hashes(self) -> None:
        session = self.session()
        with patch.object(
            agent_server,
            "codex_user_developer_instructions",
            return_value="",
        ):
            current_hash = agent_server.codex_thread_instruction_hash(
                "chat-1",
                session,
            )
            with patch.object(agent_server, "CODEX_THREAD_POLICY_VERSION", "7"):
                previous_hash = agent_server.codex_thread_instruction_hash(
                    "chat-1",
                    session,
                )

        # v8 migrates resumed threads onto the context-diet instructions.
        self.assertEqual(agent_server.CODEX_THREAD_POLICY_VERSION, "8")
        self.assertNotEqual(current_hash, previous_hash)

    def test_claude_policy_has_the_same_retry_and_context_hygiene_rules(self) -> None:
        instructions = agent_server.CLAUDE_PROMPT_PRELUDE.format()
        self.assertIn("immediately retry the still-safe requested operation", instructions)
        self.assertIn("delegate bounded noisy exploration", instructions)
        self.assertIn("Keep work needed for the current reply in foreground", instructions)
        self.assertIn("tracked Agent/workflow", instructions)
        self.assertIn("does not guarantee a completion wake-up", instructions)
        self.assertIn(
            "Never use Claude's `Monitor`, `ScheduleWakeup`, `/loop`, or `CronCreate`",
            instructions,
        )
        self.assertIn("cannot durably deliver a later chat update", instructions)
        self.assertIn("Jobs `--authority-file` command below", instructions)
        # Context diet: the static addendum is appended once; the core policy
        # keeps its line budget.
        core = instructions.split(agent_server.PROVIDER_THREAD_INSTRUCTION_ADDENDUM.strip())[0]
        self.assertLessEqual(len(core.strip().splitlines()), 16)
        self.assertEqual(
            instructions.count(agent_server.PROVIDER_THREAD_INSTRUCTION_ADDENDUM.strip()),
            1,
        )

    async def test_new_thread_receives_policy_once_at_thread_start(self) -> None:
        manager = FakeCodexAppServerManager()
        session = self.session()
        save_provider_session = AsyncMock()
        with patch.object(
            agent_server,
            "codex_user_developer_instructions",
            return_value="",
        ), patch.object(
            agent_server.STORE,
            "save_provider_session",
            save_provider_session,
        ), patch.object(
            agent_server,
            "touch_codex_app_server_thread",
            AsyncMock(),
        ):
            thread_id, instruction_hash = (
                await agent_server.ensure_codex_app_server_thread(
                    manager,  # type: ignore[arg-type]
                    "chat-1",
                    session,
                    "/repo",
                )
            )

        self.assertEqual(thread_id, "thread-new")
        self.assertEqual(len(manager.start_calls), 1)
        self.assertIn("developerInstructions", manager.start_calls[0])
        self.assertEqual(manager.resume_calls, [])
        self.assertEqual(manager.inject_calls, [])
        save_provider_session.assert_awaited_once_with(
            "chat-1",
            "thread-new",
            agent_server.BACKEND_CODEX,
            codex_instruction_hash=instruction_hash,
        )

    async def test_unchanged_resume_omits_policy_and_injection(self) -> None:
        session = self.session(
            session_id="thread-existing",
            codex_thread_id="thread-existing",
        )
        with patch.object(
            agent_server,
            "codex_user_developer_instructions",
            return_value="",
        ):
            session["codex_instruction_hash"] = (
                agent_server.codex_thread_instruction_hash("chat-1", session)
            )

        manager = FakeCodexAppServerManager()
        save_provider_session = AsyncMock()
        with patch.object(
            agent_server,
            "codex_user_developer_instructions",
            return_value="",
        ), patch.object(
            agent_server.STORE,
            "save_provider_session",
            save_provider_session,
        ), patch.object(
            agent_server,
            "touch_codex_app_server_thread",
            AsyncMock(),
        ):
            await agent_server.ensure_codex_app_server_thread(
                manager,  # type: ignore[arg-type]
                "chat-1",
                session,
                "/repo",
            )

        self.assertEqual(manager.start_calls, [])
        self.assertEqual(len(manager.resume_calls), 1)
        self.assertNotIn("developerInstructions", manager.resume_calls[0][1])
        self.assertTrue(manager.resume_calls[0][1]["excludeTurns"])
        self.assertEqual(manager.inject_calls, [])
        self.assertEqual(manager.unsubscribe_calls, [])
        save_provider_session.assert_not_awaited()

    async def test_changed_resume_uses_resume_policy_and_one_migration_item(self) -> None:
        session = self.session(
            session_id="thread-existing",
            codex_thread_id="thread-existing",
            codex_instruction_hash="stale-hash",
        )
        manager = FakeCodexAppServerManager()
        manager.loaded.add("thread-existing")
        with patch.object(
            agent_server,
            "codex_user_developer_instructions",
            return_value="",
        ), patch.object(
            agent_server.STORE,
            "save_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "touch_codex_app_server_thread",
            AsyncMock(),
        ):
            await agent_server.ensure_codex_app_server_thread(
                manager,  # type: ignore[arg-type]
                "chat-1",
                session,
                "/repo",
            )

        self.assertEqual(len(manager.resume_calls), 1)
        self.assertEqual(manager.unsubscribe_calls, ["thread-existing"])
        self.assertTrue(manager.resume_calls[0][1]["excludeTurns"])
        resume_policy = manager.resume_calls[0][1]["developerInstructions"]
        self.assertEqual(len(manager.inject_calls), 1)
        injected_thread, injected_items = manager.inject_calls[0]
        self.assertEqual(injected_thread, "thread-existing")
        self.assertEqual(injected_items[0]["role"], "developer")
        self.assertEqual(
            injected_items[0]["content"],
            [{"type": "input_text", "text": resume_policy}],
        )

    async def test_native_fork_is_rebound_to_child_chat_policy(self) -> None:
        manager = FakeCodexAppServerManager(loaded={"thread-fork"})
        child = self.session(
            id="chat-child",
            session_id=None,
            codex_thread_id=None,
        )
        save_provider_session = AsyncMock()
        with patch.object(
            agent_server,
            "codex_user_developer_instructions",
            return_value="",
        ), patch.object(
            agent_server,
            "codex_app_server_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "pin_codex_app_server_thread",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "unpin_codex_app_server_thread",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "touch_codex_app_server_thread",
            AsyncMock(),
        ), patch.object(
            agent_server.STORE,
            "save_provider_session",
            save_provider_session,
        ):
            bound, instruction_hash = await agent_server.bind_forked_codex_thread(
                "chat-child",
                "thread-fork",
                child,
            )

        self.assertEqual(bound, "thread-fork")
        self.assertEqual(manager.unsubscribe_calls, ["thread-fork"])
        self.assertEqual(len(manager.resume_calls), 1)
        policy = manager.resume_calls[0][1]["developerInstructions"]
        self.assertIn("sessions/chat-child/manifests/current.json", policy)
        self.assertIn("current turn's provider-authority block", policy)
        self.assertNotIn("--chat-id chat-child", policy)
        self.assertIn("zd_chat_child", policy)
        self.assertTrue(manager.resume_calls[0][1]["excludeTurns"])
        self.assertEqual(manager.inject_calls[0][0], "thread-fork")
        self.assertEqual(
            manager.inject_calls[0][1][0]["content"],
            [{"type": "input_text", "text": policy}],
        )
        save_provider_session.assert_awaited_once_with(
            "chat-child",
            "thread-fork",
            agent_server.BACKEND_CODEX,
            codex_instruction_hash=instruction_hash,
        )

    async def test_slow_lru_eviction_does_not_hold_the_global_lock(self) -> None:
        class SlowManager:
            def __init__(self) -> None:
                self.loaded = {"thread-old", "thread-new"}
                self.started = asyncio.Event()
                self.release = asyncio.Event()

            def active_turn(self, _thread_id: str):
                return None

            def is_thread_loaded(self, thread_id: str) -> bool:
                return thread_id in self.loaded

            async def unsubscribe_thread(self, thread_id: str) -> str:
                self.started.set()
                await self.release.wait()
                self.loaded.discard(thread_id)
                return "unsubscribed"

        manager = SlowManager()
        with patch.object(
            agent_server,
            "CODEX_APP_SERVER_MAX_LOADED_THREADS",
            1,
        ):
            await agent_server.touch_codex_app_server_thread(
                manager,  # type: ignore[arg-type]
                "thread-old",
            )
            eviction = asyncio.create_task(
                agent_server.touch_codex_app_server_thread(
                    manager,  # type: ignore[arg-type]
                    "thread-new",
                )
            )
            await asyncio.wait_for(manager.started.wait(), timeout=1)
            await asyncio.wait_for(
                agent_server.pin_codex_app_server_thread(
                    "thread-unrelated",
                    manager,  # type: ignore[arg-type]
                ),
                timeout=0.1,
            )
            manager.release.set()
            await asyncio.wait_for(eviction, timeout=1)

        self.assertNotIn("thread-old", manager.loaded)
        self.assertNotIn(
            "thread-old",
            agent_server.CODEX_APP_SERVER_EVICTING_THREADS,
        )

    async def test_invalidation_releases_only_callers_pin_and_defers_eviction(
        self,
    ) -> None:
        manager = FakeCodexAppServerManager(loaded={"thread-shared"})
        await agent_server.pin_codex_app_server_thread(
            "thread-shared", manager  # type: ignore[arg-type]
        )
        await agent_server.pin_codex_app_server_thread(
            "thread-shared", manager  # type: ignore[arg-type]
        )

        await agent_server.unpin_codex_app_server_thread(
            manager,  # type: ignore[arg-type]
            "thread-shared",
            invalidate_loaded_thread=True,
        )

        self.assertEqual(
            agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["thread-shared"],
            1,
        )
        self.assertIn("thread-shared", agent_server.CODEX_APP_SERVER_PINNED_THREADS)
        self.assertIn("thread-shared", agent_server.CODEX_APP_SERVER_INVALIDATED_THREADS)
        self.assertEqual(manager.unsubscribe_calls, [])

        await agent_server.unpin_codex_app_server_thread(
            manager,  # type: ignore[arg-type]
            "thread-shared",
        )

        self.assertEqual(manager.unsubscribe_calls, ["thread-shared"])
        self.assertNotIn("thread-shared", agent_server.CODEX_APP_SERVER_INVALIDATED_THREADS)
        self.assertNotIn("thread-shared", agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS)

    async def test_new_pin_fails_closed_while_invalidated_owner_remains(self) -> None:
        manager = FakeCodexAppServerManager(loaded={"thread-shared"})
        await agent_server.pin_codex_app_server_thread(
            "thread-shared", manager  # type: ignore[arg-type]
        )
        await agent_server.pin_codex_app_server_thread(
            "thread-shared", manager  # type: ignore[arg-type]
        )
        await agent_server.unpin_codex_app_server_thread(
            manager,  # type: ignore[arg-type]
            "thread-shared",
            invalidate_loaded_thread=True,
        )

        with self.assertRaises(agent_server.CodexAppServerError) as raised:
            await agent_server.pin_codex_app_server_thread(
                "thread-shared", manager  # type: ignore[arg-type]
            )

        self.assertTrue(raised.exception.safe_to_retry)
        self.assertFalse(raised.exception.request_sent)
        self.assertEqual(
            agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["thread-shared"],
            1,
        )

    async def test_invalidation_retries_after_active_turn_clears(self) -> None:
        manager = FakeCodexAppServerManager(loaded={"thread-stale"})
        manager.active["thread-stale"] = object()
        await agent_server.pin_codex_app_server_thread(
            "thread-stale", manager  # type: ignore[arg-type]
        )
        await agent_server.unpin_codex_app_server_thread(
            manager,  # type: ignore[arg-type]
            "thread-stale",
            invalidate_loaded_thread=True,
        )
        self.assertIn("thread-stale", agent_server.CODEX_APP_SERVER_INVALIDATED_THREADS)
        self.assertEqual(manager.unsubscribe_calls, [])

        with self.assertRaises(agent_server.CodexAppServerError):
            await agent_server.pin_codex_app_server_thread(
                "thread-stale", manager  # type: ignore[arg-type]
            )
        manager.active.clear()
        await agent_server.pin_codex_app_server_thread(
            "thread-stale", manager  # type: ignore[arg-type]
        )

        self.assertEqual(manager.unsubscribe_calls, ["thread-stale"])
        self.assertNotIn("thread-stale", agent_server.CODEX_APP_SERVER_INVALIDATED_THREADS)
        self.assertEqual(
            agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["thread-stale"],
            1,
        )

    async def test_unsubscribe_failure_keeps_invalidation_for_next_pin(self) -> None:
        class FlakyManager(FakeCodexAppServerManager):
            def __init__(self) -> None:
                super().__init__(loaded={"thread-stale"})
                self.failures = 1

            async def unsubscribe_thread(self, thread_id: str) -> str:
                self.unsubscribe_calls.append(thread_id)
                if self.failures:
                    self.failures -= 1
                    raise agent_server.CodexAppServerError("unsubscribe failed")
                self.loaded.discard(thread_id)
                return "unsubscribed"

        manager = FlakyManager()
        await agent_server.pin_codex_app_server_thread(
            "thread-stale", manager  # type: ignore[arg-type]
        )
        await agent_server.unpin_codex_app_server_thread(
            manager,  # type: ignore[arg-type]
            "thread-stale",
            invalidate_loaded_thread=True,
        )
        self.assertIn("thread-stale", agent_server.CODEX_APP_SERVER_INVALIDATED_THREADS)
        self.assertNotIn("thread-stale", agent_server.CODEX_APP_SERVER_THREAD_LRU)

        await agent_server.pin_codex_app_server_thread(
            "thread-stale", manager  # type: ignore[arg-type]
        )

        self.assertEqual(manager.unsubscribe_calls, ["thread-stale", "thread-stale"])
        self.assertNotIn("thread-stale", agent_server.CODEX_APP_SERVER_INVALIDATED_THREADS)
        self.assertEqual(
            agent_server.CODEX_APP_SERVER_THREAD_PIN_COUNTS["thread-stale"],
            1,
        )

    async def test_next_ensure_reloads_an_invalidated_subscription(self) -> None:
        session = self.session(
            session_id="thread-stale",
            codex_thread_id="thread-stale",
        )
        with patch.object(
            agent_server,
            "codex_user_developer_instructions",
            return_value="",
        ):
            session["codex_instruction_hash"] = (
                agent_server.codex_thread_instruction_hash("chat-1", session)
            )

        manager = FakeCodexAppServerManager(loaded={"thread-stale"})
        await agent_server.pin_codex_app_server_thread(
            "thread-stale", manager  # type: ignore[arg-type]
        )
        await agent_server.unpin_codex_app_server_thread(
            manager,  # type: ignore[arg-type]
            "thread-stale",
            invalidate_loaded_thread=True,
        )

        with patch.object(
            agent_server,
            "codex_user_developer_instructions",
            return_value="",
        ), patch.object(
            agent_server.STORE,
            "save_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "touch_codex_app_server_thread",
            AsyncMock(),
        ):
            thread_id, _instruction_hash = (
                await agent_server.ensure_codex_app_server_thread(
                    manager,  # type: ignore[arg-type]
                    "chat-1",
                    session,
                    "/repo",
                )
            )

        self.assertEqual(thread_id, "thread-stale")
        self.assertEqual(manager.unsubscribe_calls, ["thread-stale"])
        self.assertEqual(len(manager.resume_calls), 1)
        self.assertEqual(manager.resume_calls[0][0], "thread-stale")

    async def test_normal_retained_unpin_keeps_loaded_thread_warm(self) -> None:
        manager = FakeCodexAppServerManager(loaded={"thread-retained"})
        await agent_server.pin_codex_app_server_thread(
            "thread-retained", manager  # type: ignore[arg-type]
        )
        with patch.object(
            agent_server.STORE,
            "sessions",
            {
                "chat": {
                    "backend": agent_server.BACKEND_CODEX,
                    "codex_thread_id": "thread-retained",
                }
            },
        ):
            await agent_server.unpin_codex_app_server_thread(
                manager,  # type: ignore[arg-type]
                "thread-retained",
            )

        self.assertEqual(manager.unsubscribe_calls, [])
        self.assertIn("thread-retained", manager.loaded)
        self.assertIn("thread-retained", agent_server.CODEX_APP_SERVER_THREAD_LRU)


if __name__ == "__main__":
    unittest.main()
