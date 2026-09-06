import asyncio
import json
import os
import sys
import tempfile
import types
import unittest
from collections import OrderedDict, deque
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

from fastapi import HTTPException
from starlette.requests import Request

import agent_server
from claude_sdk_client import ClaudeSDKQueryError, ClaudeSDKUnavailable


class FakeClaudeRun:
    def __init__(
        self,
        messages: list[object] | None = None,
        *,
        acknowledged: bool = True,
    ) -> None:
        self.messages: asyncio.Queue[object] = asyncio.Queue()
        for message in messages or []:
            self.messages.put_nowait(message)
        self.interrupt_calls = 0
        self.acknowledged = acknowledged
        self._acknowledged_event = asyncio.Event()
        if acknowledged:
            self._acknowledged_event.set()

    @property
    def done(self) -> bool:
        return False

    async def wait_acknowledged(self) -> None:
        await self._acknowledged_event.wait()

    def acknowledge(self) -> None:
        self.acknowledged = True
        self._acknowledged_event.set()

    async def __anext__(self) -> object:
        return await self.messages.get()

    async def wait_result(self) -> object:
        return {"type": "result", "result": "done", "session_id": "provider"}

    async def interrupt(self) -> bool:
        self.interrupt_calls += 1
        return True


class NoisyClaudeRun(FakeClaudeRun):
    """A provider iterator that is perpetually ready with nonterminal frames."""

    async def __anext__(self) -> object:
        await asyncio.sleep(0)
        return {"type": "SystemMessage"}


class FailingClaudeRun(FakeClaudeRun):
    def __init__(self, error: BaseException) -> None:
        super().__init__(acknowledged=False)
        self.error = error

    async def __anext__(self) -> object:
        raise self.error

    async def wait_result(self) -> object:
        raise self.error


class PrematurelyEndedClaudeRun(FakeClaudeRun):
    def __init__(self) -> None:
        super().__init__()
        self.wait_result_calls = 0

    async def __anext__(self) -> object:
        raise StopAsyncIteration

    async def wait_result(self) -> object:
        self.wait_result_calls += 1
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class FakeClaudePrintStdin:
    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class FakeClaudePrintStream:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = deque(chunks)

    async def readline(self) -> bytes:
        return self.chunks.popleft() if self.chunks else b""

    async def read(self) -> bytes:
        return b"".join(self.chunks)


class FakeClaudePrintProcess:
    def __init__(self, stdout_chunks: list[bytes]) -> None:
        self.pid = 4242
        self.returncode = 0
        self.stdin = FakeClaudePrintStdin()
        self.stdout = FakeClaudePrintStream(stdout_chunks)
        self.stderr = FakeClaudePrintStream([])


class CancellationHostileClaudePrintStream:
    """A transport read that keeps waiting after its wrapper is cancelled."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancellations = 0

    async def readline(self) -> bytes:
        self.started.set()
        while not self.release.is_set():
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                self.cancellations += 1
        return b""

    async def read(self) -> bytes:
        return b""


class CancellationHostileClaudePrintProcess:
    def __init__(self) -> None:
        self.pid = 4243
        self.returncode: int | None = None
        self.stdin = FakeClaudePrintStdin()
        self.stdout = CancellationHostileClaudePrintStream()
        self.stderr = FakeClaudePrintStream([])


class NeverSettlingProcess:
    def __init__(self) -> None:
        self.pid = 4244
        self.returncode: int | None = None
        self.wait_calls = 0
        self.terminate_calls = 0
        self.kill_calls = 0

    async def wait(self) -> int:
        self.wait_calls += 1
        await asyncio.Event().wait()
        return 0

    def terminate(self) -> None:
        self.terminate_calls += 1

    def kill(self) -> None:
        self.kill_calls += 1


class FakeClaudeManager:
    def __init__(self, handle: FakeClaudeRun | None = None) -> None:
        self.handle = handle or FakeClaudeRun()
        self.start_calls: list[tuple[object, ...]] = []
        self.evict_calls: list[tuple[str, bool]] = []
        self.owner_token = "fake-claude-owner"
        self.active_run_id: str | None = None
        self.context_usage_response: tuple[dict[str, Any], int] | None = None
        self.context_usage_calls: list[tuple[str, str | None]] = []
        self.loaded = True

    async def start_run(
        self,
        chat_id: str,
        prompt: str,
        *,
        run_id: str,
        options: object,
        configuration_key: str,
        query_session_id: str | None = None,
        on_supervisor_ready: object | None = None,
    ) -> FakeClaudeRun:
        self.start_calls.append(
            (
                chat_id,
                prompt,
                run_id,
                options,
                configuration_key,
                query_session_id,
            )
        )
        self.active_run_id = run_id
        if on_supervisor_ready is not None:
            await on_supervisor_ready(self.owner_token)  # type: ignore[operator]
        return self.handle

    async def evict(
        self,
        chat_id: str,
        *,
        force: bool = False,
        ownership_token: str | None = None,
    ) -> bool:
        if (
            ownership_token is not None
            and ownership_token != self.owner_token
        ):
            return False
        self.evict_calls.append((chat_id, force))
        self.active_run_id = None
        self.loaded = False
        return True

    def owns_active_run(
        self,
        chat_id: str,
        ownership_token: str,
        run_id: str,
    ) -> bool:
        return (
            chat_id == "chat-claude"
            and ownership_token == self.owner_token
            and run_id == self.active_run_id
        )

    async def get_context_usage(
        self,
        chat_id: str,
        *,
        ownership_token: str | None = None,
    ) -> tuple[dict[str, Any], int] | None:
        self.context_usage_calls.append((chat_id, ownership_token))
        return self.context_usage_response

    def is_loaded(self, chat_id: str) -> bool:
        return self.loaded and chat_id == "chat-claude"


class FakeClaudeManagerFailingAfterOwnership(FakeClaudeManager):
    """A reused supervisor that claims the chat, then fails delivery."""

    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    async def start_run(
        self,
        chat_id: str,
        prompt: str,
        *,
        run_id: str,
        options: object,
        configuration_key: str,
        query_session_id: str | None = None,
        on_supervisor_ready: object | None = None,
    ) -> FakeClaudeRun:
        self.start_calls.append(
            (chat_id, prompt, run_id, options, configuration_key, query_session_id)
        )
        self.active_run_id = run_id
        if on_supervisor_ready is not None:
            await on_supervisor_ready(self.owner_token)  # type: ignore[operator]
        raise self.error


class SequencedClaudeManager(FakeClaudeManager):
    def __init__(self, handles: list[FakeClaudeRun]) -> None:
        super().__init__(handles[0])
        self.handles = deque(handles)

    async def start_run(
        self,
        chat_id: str,
        prompt: str,
        *,
        run_id: str,
        options: object,
        configuration_key: str,
        query_session_id: str | None = None,
        on_supervisor_ready: object | None = None,
    ) -> FakeClaudeRun:
        self.start_calls.append(
            (
                chat_id,
                prompt,
                run_id,
                options,
                configuration_key,
                query_session_id,
            )
        )
        self.active_run_id = run_id
        if on_supervisor_ready is not None:
            await on_supervisor_ready(self.owner_token)  # type: ignore[operator]
        return self.handles.popleft()


class PermissionDuringStartManager(SequencedClaudeManager):
    """Model an SDK query that requests approval before start_run returns."""

    def __init__(
        self,
        handles: list[FakeClaudeRun],
        *,
        permission_on_calls: set[int],
        jobs_authorization_on_calls: set[int] | None = None,
    ) -> None:
        super().__init__(handles)
        self.permission_on_calls = set(permission_on_calls)
        self.jobs_authorization_on_calls = set(
            jobs_authorization_on_calls or set()
        )
        self.permission_results: list[object] = []
        self.permission_requested = asyncio.Event()
        self.jobs_authorization_results: list[dict[str, Any]] = []

    async def start_run(
        self,
        chat_id: str,
        prompt: str,
        *,
        run_id: str,
        options: object,
        configuration_key: str,
        query_session_id: str | None = None,
        on_supervisor_ready: object | None = None,
    ) -> FakeClaudeRun:
        call_number = len(self.start_calls) + 1
        self.start_calls.append(
            (
                chat_id,
                prompt,
                run_id,
                options,
                configuration_key,
                query_session_id,
            )
        )
        self.active_run_id = run_id
        if on_supervisor_ready is not None:
            await on_supervisor_ready(self.owner_token)  # type: ignore[operator]
        # A real supervisor sets _active_run immediately before client.query;
        # can_use_tool can then fire while query/start_run is still awaiting.
        if call_number in self.jobs_authorization_on_calls:
            matching = [
                capability
                for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
                if capability.get("source_run_id") == run_id
            ]
            if len(matching) != 1:
                raise AssertionError("candidate authority was not uniquely issued")
            authority_path = Path(str(matching[0]["authority_path"]))
            token = json.loads(
                authority_path.read_text(encoding="utf-8")
            )["provider_capability"]
            request = Request({
                "type": "http",
                "method": "GET",
                "path": f"/api/agent/sessions/{chat_id}/jobs",
                "headers": [(
                    b"x-agentsdock-provider-capability",
                    token.encode("utf-8"),
                )],
                "query_string": b"",
                "scheme": "http",
                "server": ("127.0.0.1", 7850),
                "client": ("127.0.0.1", 43103),
            })
            self.jobs_authorization_results.append(
                await agent_server.authorize_provider_jobs_operation(
                    request,
                    session_id=chat_id,
                    operation="read",
                )
            )
        if call_number in self.permission_on_calls:
            callback = (
                options.get("can_use_tool")
                if isinstance(options, dict)
                else getattr(options, "can_use_tool")
            )
            permission_task = asyncio.create_task(callback(
                "Bash",
                {"command": "pwd"},
                {"tool_use_id": f"permission-{call_number}"},
            ))
            self.permission_requested.set()
            self.permission_results.append(await permission_task)
        return self.handles.popleft()


class BlockingCandidateStartManager(SequencedClaudeManager):
    """Hold the second query at its delivery-uncertain cancellation boundary."""

    def __init__(self, handles: list[FakeClaudeRun]) -> None:
        super().__init__(handles)
        self.candidate_query_started = asyncio.Event()

    async def start_run(
        self,
        chat_id: str,
        prompt: str,
        *,
        run_id: str,
        options: object,
        configuration_key: str,
        query_session_id: str | None = None,
        on_supervisor_ready: object | None = None,
    ) -> FakeClaudeRun:
        call_number = len(self.start_calls) + 1
        self.start_calls.append(
            (
                chat_id,
                prompt,
                run_id,
                options,
                configuration_key,
                query_session_id,
            )
        )
        self.active_run_id = run_id
        if on_supervisor_ready is not None:
            await on_supervisor_ready(self.owner_token)  # type: ignore[operator]
        if call_number == 2:
            self.candidate_query_started.set()
            await asyncio.Event().wait()
        return self.handles.popleft()


class SafeFailingCandidateStartManager(SequencedClaudeManager):
    """Reject the replacement before query delivery with a retryable result."""

    def __init__(self, handles: list[FakeClaudeRun]) -> None:
        super().__init__(handles)
        self.candidate_authority_path: Path | None = None

    async def start_run(
        self,
        chat_id: str,
        prompt: str,
        *,
        run_id: str,
        options: object,
        configuration_key: str,
        query_session_id: str | None = None,
        on_supervisor_ready: object | None = None,
    ) -> FakeClaudeRun:
        call_number = len(self.start_calls) + 1
        self.start_calls.append((
            chat_id,
            prompt,
            run_id,
            options,
            configuration_key,
            query_session_id,
        ))
        self.active_run_id = run_id
        if on_supervisor_ready is not None:
            await on_supervisor_ready(self.owner_token)  # type: ignore[operator]
        if call_number == 2:
            matching = [
                capability
                for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
                if capability.get("source_run_id") == run_id
            ]
            if len(matching) != 1:
                raise AssertionError("candidate authority was not uniquely issued")
            self.candidate_authority_path = Path(str(
                matching[0]["authority_path"]
            ))
            raise agent_server.NativeSteerHandoffError(
                "candidate query was rejected before delivery",
                safe_to_requeue=True,
            )
        return self.handles.popleft()


class FakePermissionResultAllow:
    def __init__(self, **kwargs: object) -> None:
        self.__dict__.update(kwargs)


class FakePermissionResultDeny:
    def __init__(self, **kwargs: object) -> None:
        self.__dict__.update(kwargs)


def fake_claude_sdk_modules() -> dict[str, types.ModuleType]:
    package = types.ModuleType("claude_agent_sdk")
    package.__path__ = []  # type: ignore[attr-defined]
    sdk_types = types.ModuleType("claude_agent_sdk.types")
    sdk_types.PermissionResultAllow = FakePermissionResultAllow
    sdk_types.PermissionResultDeny = FakePermissionResultDeny
    return {
        "claude_agent_sdk": package,
        "claude_agent_sdk.types": sdk_types,
    }


async def wait_forever(*_args: object, **_kwargs: object) -> None:
    await asyncio.Event().wait()


class ClaudeSDKRunnerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.previous_sessions = agent_server.STORE.sessions
        self.previous_active = agent_server.ACTIVE
        self.previous_busy = agent_server.BUSY_SESSIONS
        self.previous_current = agent_server.CURRENT_TURNS
        self.previous_stop_requests = agent_server.STOP_REQUESTS
        self.previous_stopped_runs = agent_server.STOPPED_RUNS
        self.previous_turn_tasks = agent_server.SESSION_TURN_TASKS
        self.previous_manager = agent_server.CLAUDE_SDK_MANAGER
        self.previous_run_metadata = agent_server.RUN_METADATA
        self.previous_queue = agent_server.QUEUED_TURNS
        self.previous_run_now = agent_server.RUN_NOW_TURNS
        self.previous_run_now_requests = agent_server.RUN_NOW_REQUESTS
        self.previous_run_now_completed = agent_server.RUN_NOW_COMPLETED_RESULTS
        self.previous_steering = agent_server.STEERING_SESSIONS
        self.previous_pending_interactions = agent_server.CLAUDE_PENDING_INTERACTIONS
        self.previous_interaction_tasks = agent_server.CLAUDE_INTERACTION_HANDLER_TASKS
        self.previous_lifecycle_locks = agent_server.SESSION_LIFECYCLE_LOCKS
        self.previous_deleting = agent_server.DELETING_SESSIONS
        self.previous_deleted = agent_server.DELETED_SESSION_TOMBSTONES
        self.previous_maintenance = agent_server.SERVER_MAINTENANCE_SESSIONS
        self.previous_stop_fences = agent_server.CLAUDE_STOP_FENCE_SESSIONS
        self.previous_stop_fence_retries = agent_server.CLAUDE_STOP_FENCE_RETRY_TASKS
        self.previous_stop_fence_locks = agent_server.CLAUDE_STOP_FENCE_ATTEMPT_LOCKS
        self.previous_stop_fence_attempts = agent_server.CLAUDE_STOP_FENCE_ATTEMPT_TASKS
        self.previous_capabilities = agent_server.CROSS_CHAT_CAPABILITIES
        self.previous_authority_root = agent_server.CROSS_CHAT_AUTHORITY_ROOT
        self.previous_agent_token = agent_server.AGENT_TOKEN
        self.authority_temporary = tempfile.TemporaryDirectory()

        self.cwd = str(Path(__file__).resolve().parent.parent)
        self.session = {
            "id": "chat-claude",
            "backend": agent_server.BACKEND_CLAUDE,
            "cwd": self.cwd,
            "model": "claude-opus",
            "effort": "high",
            "provider_jobs_access": "full",
        }
        agent_server.STORE.sessions = {"chat-claude": self.session}
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = {"chat-claude"}
        agent_server.CURRENT_TURNS = {
            "chat-claude": {
                "run_id": "run-claude",
                "prompt": "Prompt",
                "file_ids": [],
                "backend": agent_server.BACKEND_CLAUDE,
            }
        }
        agent_server.STOP_REQUESTS = set()
        agent_server.STOPPED_RUNS = set()
        agent_server.SESSION_TURN_TASKS = {}
        agent_server.CLAUDE_SDK_MANAGER = None
        agent_server.RUN_METADATA = {}
        agent_server.QUEUED_TURNS = {}
        agent_server.RUN_NOW_TURNS = {}
        agent_server.RUN_NOW_REQUESTS = {}
        agent_server.RUN_NOW_COMPLETED_RESULTS = OrderedDict()
        agent_server.STEERING_SESSIONS = set()
        agent_server.CLAUDE_PENDING_INTERACTIONS = {}
        agent_server.CLAUDE_INTERACTION_HANDLER_TASKS = {}
        agent_server.SESSION_LIFECYCLE_LOCKS = {}
        agent_server.DELETING_SESSIONS = set()
        agent_server.DELETED_SESSION_TOMBSTONES = set()
        agent_server.SERVER_MAINTENANCE_SESSIONS = set()
        agent_server.CLAUDE_STOP_FENCE_SESSIONS = set()
        agent_server.CLAUDE_STOP_FENCE_RETRY_TASKS = {}
        agent_server.CLAUDE_STOP_FENCE_ATTEMPT_LOCKS = {}
        agent_server.CLAUDE_STOP_FENCE_ATTEMPT_TASKS = {}
        agent_server.CROSS_CHAT_CAPABILITIES = {}
        agent_server.CROSS_CHAT_AUTHORITY_ROOT = (
            Path(self.authority_temporary.name) / "authority"
        )
        agent_server.AGENT_TOKEN = "test-agent-token"
        self.durable_event_patcher = patch.object(
            agent_server,
            "append_durable_event",
            AsyncMock(return_value={}),
        )
        self.append_durable_event = self.durable_event_patcher.start()
        self.durable_batch_patcher = patch.object(
            agent_server,
            "append_durable_event_batch",
            AsyncMock(return_value=[]),
        )
        self.append_durable_event_batch = self.durable_batch_patcher.start()

    async def asyncTearDown(self) -> None:
        self.durable_batch_patcher.stop()
        self.durable_event_patcher.stop()
        for tasks in agent_server.SESSION_TURN_TASKS.values():
            for task in tasks:
                if not task.done():
                    task.cancel()
        pending = [
            task
            for tasks in agent_server.SESSION_TURN_TASKS.values()
            for task in tasks
            if not task.done()
        ]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        stop_fence_retries = tuple(
            agent_server.CLAUDE_STOP_FENCE_RETRY_TASKS.values()
        )
        stop_fence_attempts = tuple(
            task
            for tasks in agent_server.CLAUDE_STOP_FENCE_ATTEMPT_TASKS.values()
            for task in tasks
        )
        for task in (*stop_fence_retries, *stop_fence_attempts):
            task.cancel()
        if stop_fence_retries or stop_fence_attempts:
            await asyncio.gather(
                *stop_fence_retries,
                *stop_fence_attempts,
                return_exceptions=True,
            )
        agent_server.STORE.sessions = self.previous_sessions
        agent_server.ACTIVE = self.previous_active
        agent_server.BUSY_SESSIONS = self.previous_busy
        agent_server.CURRENT_TURNS = self.previous_current
        agent_server.STOP_REQUESTS = self.previous_stop_requests
        agent_server.STOPPED_RUNS = self.previous_stopped_runs
        agent_server.SESSION_TURN_TASKS = self.previous_turn_tasks
        agent_server.CLAUDE_SDK_MANAGER = self.previous_manager
        agent_server.RUN_METADATA = self.previous_run_metadata
        agent_server.QUEUED_TURNS = self.previous_queue
        agent_server.RUN_NOW_TURNS = self.previous_run_now
        agent_server.RUN_NOW_REQUESTS = self.previous_run_now_requests
        agent_server.RUN_NOW_COMPLETED_RESULTS = self.previous_run_now_completed
        agent_server.STEERING_SESSIONS = self.previous_steering
        agent_server.CLAUDE_PENDING_INTERACTIONS = self.previous_pending_interactions
        agent_server.CLAUDE_INTERACTION_HANDLER_TASKS = self.previous_interaction_tasks
        agent_server.SESSION_LIFECYCLE_LOCKS = self.previous_lifecycle_locks
        agent_server.DELETING_SESSIONS = self.previous_deleting
        agent_server.DELETED_SESSION_TOMBSTONES = self.previous_deleted
        agent_server.SERVER_MAINTENANCE_SESSIONS = self.previous_maintenance
        agent_server.CLAUDE_STOP_FENCE_SESSIONS = self.previous_stop_fences
        agent_server.CLAUDE_STOP_FENCE_RETRY_TASKS = self.previous_stop_fence_retries
        agent_server.CLAUDE_STOP_FENCE_ATTEMPT_LOCKS = self.previous_stop_fence_locks
        agent_server.CLAUDE_STOP_FENCE_ATTEMPT_TASKS = self.previous_stop_fence_attempts
        agent_server.CROSS_CHAT_CAPABILITIES = self.previous_capabilities
        agent_server.CROSS_CHAT_AUTHORITY_ROOT = self.previous_authority_root
        agent_server.AGENT_TOKEN = self.previous_agent_token
        self.authority_temporary.cleanup()

    @staticmethod
    def provider_request(token: str) -> Request:
        return Request({
            "type": "http",
            "method": "GET",
            "path": "/api/agent/sessions/chat-claude/jobs",
            "headers": [
                (
                    b"x-agentsdock-provider-capability",
                    token.encode("utf-8"),
                ),
            ],
            "query_string": b"",
            "scheme": "http",
            "server": ("127.0.0.1", 7850),
            "client": ("127.0.0.1", 43102),
        })

    async def _run_sdk_terminal_case(
        self,
        messages: list[object] | None = None,
        *,
        handle: FakeClaudeRun | None = None,
    ) -> tuple[AsyncMock, AsyncMock, Mock, Mock]:
        manager = FakeClaudeManager(handle or FakeClaudeRun(messages))
        append_event = AsyncMock(return_value={})
        append_finished = AsyncMock(return_value={})
        runtime_success = Mock()
        runtime_failure = Mock()
        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            append_finished,
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "sample_claude_context_usage",
            AsyncMock(return_value=False),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "record_runtime_success",
            runtime_success,
        ), patch.object(
            agent_server,
            "record_runtime_failure",
            runtime_failure,
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            await agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            )
        return append_event, append_finished, runtime_success, runtime_failure

    async def _run_sdk_timeout_case(
        self,
        handle: FakeClaudeRun,
        *,
        pre_ack_timeout: float,
        post_ack_timeout: float,
        turn_timeout: float,
        idle_warn: float,
        idle_timeout: float,
    ) -> tuple[FakeClaudeManager, AsyncMock, AsyncMock, Mock]:
        manager = FakeClaudeManager(handle)
        append_event = AsyncMock(return_value={})
        append_finished = AsyncMock(return_value={})
        runtime_failure = Mock()
        with ExitStack() as stack:
            for name, value in (
                ("CLAUDE_SDK_PRE_ACK_TIMEOUT_SECONDS", pre_ack_timeout),
                (
                    "CLAUDE_SDK_POST_ACK_FIRST_ACTIVITY_TIMEOUT_SECONDS",
                    post_ack_timeout,
                ),
                ("CLAUDE_SDK_TURN_TIMEOUT_SECONDS", turn_timeout),
                ("CLAUDE_SDK_IDLE_WARN_SECONDS", idle_warn),
                ("CLAUDE_SDK_IDLE_TIMEOUT_SECONDS", idle_timeout),
            ):
                stack.enter_context(patch.object(agent_server, name, value))
            stack.enter_context(patch.object(
                agent_server,
                "resolve_claude_resume_provider",
                return_value=(None, None),
            ))
            stack.enter_context(patch.object(
                agent_server,
                "capture_git_baseline",
                AsyncMock(return_value={"head": "base"}),
            ))
            stack.enter_context(patch.object(
                agent_server,
                "build_claude_sdk_options",
                return_value=(object(), "config", "/usr/bin/claude"),
            ))
            stack.enter_context(patch.object(
                agent_server,
                "claude_sdk_manager",
                AsyncMock(return_value=manager),
            ))
            stack.enter_context(patch.object(
                agent_server,
                "watch_manifest_artifacts",
                wait_forever,
            ))
            stack.enter_context(patch.object(
                agent_server,
                "append_event",
                append_event,
            ))
            stack.enter_context(patch.object(
                agent_server,
                "project_claude_sdk_message",
                AsyncMock(return_value=None),
            ))
            for name in (
                "mark_provider_turn_ready",
                "persist_run_provider_session",
                "cancel_claude_interactions",
                "collect_manifest",
                "collect_recent_leftover_manifests",
                "publish_turn_code_diff",
            ):
                stack.enter_context(patch.object(
                    agent_server,
                    name,
                    AsyncMock(),
                ))
            stack.enter_context(patch.object(
                agent_server,
                "append_turn_finished_event",
                append_finished,
            ))
            stack.enter_context(patch.object(
                agent_server,
                "release_turn_slot",
                AsyncMock(return_value=True),
            ))
            stack.enter_context(patch.object(
                agent_server,
                "record_runtime_success",
                Mock(),
            ))
            stack.enter_context(patch.object(
                agent_server,
                "record_runtime_failure",
                runtime_failure,
            ))
            stack.enter_context(patch.object(
                agent_server,
                "should_schedule_queue_after_finish",
                return_value=False,
            ))
            await asyncio.wait_for(
                agent_server.run_claude_sdk(
                    "chat-claude",
                    "run-claude",
                    "Prompt",
                    dict(self.session),
                    Path(self.cwd) / ".manifest.json",
                ),
                timeout=0.5,
            )
        return manager, append_event, append_finished, runtime_failure

    async def test_empty_sdk_result_without_tools_is_visible_failure(self) -> None:
        append_event, append_finished, runtime_success, runtime_failure = (
            await self._run_sdk_terminal_case([{
                "type": "result",
                "result": "",
                "session_id": "provider",
                "terminal_reason": "end_turn",
            }])
        )

        terminal = append_finished.await_args.args[1]
        self.assertEqual(terminal["exit_code"], 1)
        self.assertEqual(terminal["result_text"], "")
        self.assertTrue(any(
            call.args[1] == "error"
            and call.args[2]["message"]
            == agent_server.CLAUDE_EMPTY_TURN_ERROR
            for call in append_event.await_args_list
        ))
        runtime_success.assert_not_called()
        runtime_failure.assert_called_once_with(
            agent_server.BACKEND_CLAUDE,
            agent_server.CLAUDE_EMPTY_TURN_ERROR,
        )

    async def test_tool_only_empty_sdk_result_remains_success(self) -> None:
        append_event, append_finished, runtime_success, runtime_failure = (
            await self._run_sdk_terminal_case([
                {
                    "type": "AssistantMessage",
                    "content": [{
                        "type": "tool_use",
                        "id": "tool-1",
                        "name": "Read",
                        "input": {"file_path": "/tmp/example"},
                    }],
                    "session_id": "provider",
                },
                {
                    "type": "UserMessage",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": "tool-1",
                        "content": "done",
                    }],
                },
                {
                    "type": "result",
                    "result": "",
                    "session_id": "provider",
                    "terminal_reason": "end_turn",
                },
            ])
        )

        terminal = append_finished.await_args.args[1]
        self.assertEqual(terminal["exit_code"], 0)
        self.assertEqual(terminal["result_text"], "")
        self.assertFalse(any(
            call.args[1] == "error"
            and call.args[2].get("message")
            == agent_server.CLAUDE_EMPTY_TURN_ERROR
            for call in append_event.await_args_list
        ))
        runtime_success.assert_called_once_with(agent_server.BACKEND_CLAUDE)
        runtime_failure.assert_not_called()

    async def test_sdk_iterator_end_before_terminal_never_waits_forever(self) -> None:
        handle = PrematurelyEndedClaudeRun()

        append_event, append_finished, runtime_success, runtime_failure = (
            await asyncio.wait_for(
                self._run_sdk_terminal_case(handle=handle),
                0.5,
            )
        )

        self.assertEqual(handle.wait_result_calls, 0)
        terminal = append_finished.await_args.args[1]
        self.assertEqual(terminal["exit_code"], 1)
        self.assertTrue(any(
            call.args[1] == "error"
            and "ended before a terminal result" in call.args[2]["message"]
            for call in append_event.await_args_list
        ))
        runtime_success.assert_not_called()
        runtime_failure.assert_called_once()

    async def test_empty_print_result_without_tools_is_visible_failure(self) -> None:
        process = FakeClaudePrintProcess([
            b'{"type":"result","result":"","session_id":"provider"}\n',
        ])
        append_event = AsyncMock(return_value={})
        append_finished = AsyncMock(return_value={})
        runtime_success = Mock()
        runtime_failure = Mock()
        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_cmd",
            return_value=["claude", "-p"],
        ), patch.object(
            agent_server.asyncio,
            "create_subprocess_exec",
            AsyncMock(return_value=process),
        ), patch.object(
            agent_server,
            "process_group_for_pid",
            return_value=4242,
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            append_finished,
        ), patch.object(
            agent_server,
            "append_active_stdout",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "terminate_process_tree",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "clear_active_process",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "record_runtime_success",
            runtime_success,
        ), patch.object(
            agent_server,
            "record_runtime_failure",
            runtime_failure,
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            await agent_server.run_claude_print(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            )

        terminal = append_finished.await_args.args[1]
        self.assertEqual(terminal["exit_code"], 1)
        self.assertEqual(terminal["result_text"], "")
        self.assertTrue(any(
            call.args[1] == "error"
            and call.args[2].get("message")
            == agent_server.CLAUDE_EMPTY_TURN_ERROR
            for call in append_event.await_args_list
        ))
        runtime_success.assert_not_called()
        runtime_failure.assert_called_once_with(
            agent_server.BACKEND_CLAUDE,
            agent_server.CLAUDE_EMPTY_TURN_ERROR,
        )

    async def test_interactive_auto_never_downgrades_to_unattended_print(self) -> None:
        sdk = AsyncMock(side_effect=ClaudeSDKUnavailable("missing SDK"))
        print_runner = AsyncMock()
        terminal_failure = AsyncMock()
        with patch.object(agent_server, "CLAUDE_TRANSPORT", agent_server.CLAUDE_TRANSPORT_AUTO), patch.object(
            agent_server,
            "run_claude_sdk",
            sdk,
        ), patch.object(
            agent_server,
            "run_claude_print",
            print_runner,
        ), patch.object(
            agent_server,
            "finish_claude_sdk_start_failure",
            terminal_failure,
        ):
            await agent_server.run_claude(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
                interactive_agent_sdk=True,
            )

        sdk.assert_awaited_once()
        print_runner.assert_not_awaited()
        terminal_failure.assert_awaited_once()

    async def test_terminal_context_usage_is_normalized_persisted_and_broadcast(self) -> None:
        manager = FakeClaudeManager()
        manager.context_usage_response = ({
            "totalTokens": 45_000,
            "maxTokens": 188_000,
            "rawMaxTokens": 200_000,
            "percentage": 23.94,
            "model": "claude-opus-4-1",
            "categories": {"ignored": "not persisted"},
        }, 9)
        self.session["claude_session_id"] = "provider-usage"
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "claude_sdk_owner_token": manager.owner_token,
                "stop_requested": False,
            }
        }
        broadcast = AsyncMock()
        with patch.object(
            agent_server.STORE,
            "save",
            AsyncMock(),
        ), patch.object(
            agent_server.HUB,
            "broadcast",
            broadcast,
        ):
            stored = await agent_server.sample_claude_context_usage(
                "chat-claude",
                "run-claude",
                "provider-usage",
                manager,
            )

        self.assertTrue(stored)
        snapshot = self.session["claude_context_usage_snapshot"]
        self.assertEqual(snapshot["context_tokens"], 45_000)
        self.assertEqual(snapshot["totalTokens"], 45_000)
        self.assertEqual(snapshot["maxTokens"], 188_000)
        self.assertEqual(snapshot["rawMaxTokens"], 200_000)
        self.assertEqual(snapshot["effective_context_window"], 188_000)
        self.assertEqual(snapshot["raw_context_window"], 200_000)
        self.assertEqual(snapshot["provider_generation"], 9)
        self.assertEqual(snapshot["usage_generation"], 1)
        self.assertNotIn("categories", snapshot)
        runtime = await agent_server.claude_runtime_snapshot("chat-claude")
        self.assertEqual(runtime["context_usage_state"], "available")
        self.assertEqual(runtime["context_usage_snapshot"], snapshot)
        packet = broadcast.await_args.args[1]
        self.assertEqual(packet["type"], "provider_runtime_changed")
        self.assertEqual(packet["session_id"], "chat-claude")
        self.assertNotIn("seq", packet)

    async def test_manual_context_refresh_samples_loaded_idle_sdk_chat(self) -> None:
        manager = FakeClaudeManager()
        manager.context_usage_response = ({
            "totalTokens": 66_000,
            "maxTokens": 188_000,
            "rawMaxTokens": 200_000,
            "percentage": 35.11,
            "model": "claude-opus-4-1",
        }, 12)
        self.session["claude_session_id"] = "provider-manual"
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.CURRENT_TURNS = {}
        broadcast = AsyncMock()
        with patch.object(
            agent_server,
            "CLAUDE_TRANSPORT",
            agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
        ), patch.object(
            agent_server,
            "claude_sdk_dependency_available",
            return_value=True,
        ), patch.object(
            agent_server.STORE,
            "save",
            AsyncMock(),
        ), patch.object(
            agent_server.HUB,
            "broadcast",
            broadcast,
        ):
            observed = await agent_server.get_claude_runtime("chat-claude")
            self.assertTrue(
                observed["features"]["context_usage_refresh"]
            )
            self.assertEqual(manager.context_usage_calls, [])
            refreshed = await agent_server.post_claude_context_usage_refresh(
                "chat-claude"
            )

        self.assertTrue(refreshed["context_usage_refreshed"])
        self.assertEqual(
            manager.context_usage_calls,
            [("chat-claude", None)],
        )
        snapshot = refreshed["context_usage_snapshot"]
        self.assertEqual(snapshot["context_tokens"], 66_000)
        self.assertEqual(snapshot["provider_generation"], 12)
        self.assertEqual(snapshot["usage_generation"], 1)
        self.assertNotIn("run_id", snapshot)
        self.assertEqual(
            broadcast.await_args.args[1]["context_usage_snapshot"],
            snapshot,
        )

    async def test_manual_context_refresh_rejects_busy_or_unloaded_chat(self) -> None:
        manager = FakeClaudeManager()
        manager.context_usage_response = ({
            "totalTokens": 1,
            "maxTokens": 100,
        }, 1)
        stale_snapshot = {
            "provider_session_id": "provider-manual",
            "context_tokens": 55_000,
            "usage_generation": 4,
        }
        self.session.update({
            "claude_session_id": "provider-manual",
            "_context_usage_generation": 4,
            "context_usage_state": "available",
            "context_usage_snapshot": stale_snapshot,
            "claude_context_usage_snapshot": stale_snapshot,
        })
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {}
        agent_server.CURRENT_TURNS = {}
        with patch.object(
            agent_server,
            "CLAUDE_TRANSPORT",
            agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
        ), patch.object(
            agent_server,
            "claude_sdk_dependency_available",
            return_value=True,
        ):
            agent_server.BUSY_SESSIONS = {"chat-claude"}
            with self.assertRaises(agent_server.HTTPException) as busy:
                await agent_server.post_claude_context_usage_refresh(
                    "chat-claude"
                )
            self.assertEqual(busy.exception.status_code, 409)
            self.assertEqual(manager.context_usage_calls, [])

            agent_server.BUSY_SESSIONS = set()
            manager.loaded = False
            with self.assertRaises(agent_server.HTTPException) as unloaded:
                await agent_server.post_claude_context_usage_refresh(
                    "chat-claude"
                )
            self.assertEqual(unloaded.exception.status_code, 409)

        self.assertIs(self.session["context_usage_snapshot"], stale_snapshot)
        self.assertEqual(self.session["context_usage_state"], "available")

    async def test_manual_context_refresh_cannot_overwrite_newer_generation(self) -> None:
        manager = FakeClaudeManager()
        self.session["claude_session_id"] = "provider-manual"
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.CURRENT_TURNS = {}
        newer_snapshot = {
            "provider_session_id": "provider-manual",
            "context_tokens": 77_000,
            "usage_generation": 5,
        }

        async def sample_after_newer_write(
            *_args: object,
            **_kwargs: object,
        ) -> tuple[dict[str, Any], int]:
            self.session.update({
                "_context_usage_generation": 5,
                "context_usage_state": "available",
                "context_usage_snapshot": newer_snapshot,
                "claude_context_usage_snapshot": newer_snapshot,
            })
            return ({
                "totalTokens": 20_000,
                "maxTokens": 188_000,
            }, 7)

        manager.get_context_usage = AsyncMock(  # type: ignore[method-assign]
            side_effect=sample_after_newer_write
        )
        with patch.object(
            agent_server,
            "CLAUDE_TRANSPORT",
            agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
        ), patch.object(
            agent_server,
            "claude_sdk_dependency_available",
            return_value=True,
        ):
            with self.assertRaises(agent_server.HTTPException) as changed:
                await agent_server.post_claude_context_usage_refresh(
                    "chat-claude"
                )

        self.assertEqual(changed.exception.status_code, 409)
        self.assertIs(self.session["context_usage_snapshot"], newer_snapshot)

    async def test_manual_context_timeout_preserves_snapshot_and_resets_idle_client(self) -> None:
        manager = FakeClaudeManager()
        manager.get_context_usage = AsyncMock(  # type: ignore[method-assign]
            side_effect=wait_forever
        )
        stale_snapshot = {
            "provider_session_id": "provider-manual",
            "context_tokens": 42_000,
            "usage_generation": 3,
        }
        self.session.update({
            "claude_session_id": "provider-manual",
            "_context_usage_generation": 3,
            "context_usage_state": "available",
            "context_usage_snapshot": stale_snapshot,
            "claude_context_usage_snapshot": stale_snapshot,
        })
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.CURRENT_TURNS = {}
        with patch.object(
            agent_server,
            "CLAUDE_TRANSPORT",
            agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
        ), patch.object(
            agent_server,
            "claude_sdk_dependency_available",
            return_value=True,
        ), patch.object(
            agent_server,
            "CLAUDE_CONTEXT_USAGE_TIMEOUT_SECONDS",
            0.01,
        ):
            with self.assertRaises(agent_server.HTTPException) as timed_out:
                await asyncio.wait_for(
                    agent_server.post_claude_context_usage_refresh(
                        "chat-claude"
                    ),
                    0.2,
                )

        self.assertEqual(timed_out.exception.status_code, 504)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        self.assertIs(self.session["context_usage_snapshot"], stale_snapshot)
        self.assertEqual(self.session["context_usage_state"], "available")

    async def test_cancelled_manual_context_refresh_retires_only_idle_client(self) -> None:
        manager = FakeClaudeManager()
        sampling_started = asyncio.Event()

        async def blocked_sample(
            *_args: object,
            **_kwargs: object,
        ) -> None:
            sampling_started.set()
            await asyncio.Event().wait()

        manager.get_context_usage = AsyncMock(  # type: ignore[method-assign]
            side_effect=blocked_sample
        )
        stale_snapshot = {
            "provider_session_id": "provider-manual",
            "context_tokens": 19_000,
            "usage_generation": 2,
        }
        self.session.update({
            "claude_session_id": "provider-manual",
            "_context_usage_generation": 2,
            "context_usage_state": "available",
            "context_usage_snapshot": stale_snapshot,
            "claude_context_usage_snapshot": stale_snapshot,
        })
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.CURRENT_TURNS = {}
        with patch.object(
            agent_server,
            "CLAUDE_TRANSPORT",
            agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
        ), patch.object(
            agent_server,
            "claude_sdk_dependency_available",
            return_value=True,
        ):
            request = asyncio.create_task(
                agent_server.post_claude_context_usage_refresh("chat-claude")
            )
            await asyncio.wait_for(sampling_started.wait(), 0.2)
            request.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await request
            for _ in range(10):
                if manager.evict_calls:
                    break
                await asyncio.sleep(0)

        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        self.assertIs(self.session["context_usage_snapshot"], stale_snapshot)

    async def test_cancelled_context_refresh_cannot_late_evict_replacement_turn(
        self,
    ) -> None:
        manager = FakeClaudeManager()
        sampling_started = asyncio.Event()
        eviction_started = asyncio.Event()
        release_eviction = asyncio.Event()
        replacement_running = asyncio.Event()

        async def blocked_sample(
            *_args: object,
            **_kwargs: object,
        ) -> None:
            sampling_started.set()
            await asyncio.Event().wait()

        async def delayed_evict(
            chat_id: str,
            *,
            force: bool = False,
        ) -> bool:
            manager.evict_calls.append((chat_id, force))
            eviction_started.set()
            await release_eviction.wait()
            manager.active_run_id = None
            manager.loaded = False
            return True

        async def replacement_runner(
            _session_id: str,
            run_id: str,
            *_args: object,
            **_kwargs: object,
        ) -> None:
            manager.active_run_id = run_id
            manager.loaded = True
            replacement_running.set()
            await asyncio.Event().wait()

        manager.get_context_usage = AsyncMock(  # type: ignore[method-assign]
            side_effect=blocked_sample
        )
        manager.evict = AsyncMock(  # type: ignore[method-assign]
            side_effect=delayed_evict
        )
        self.session["claude_session_id"] = "provider-manual"
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.CURRENT_TURNS = {}

        with patch.object(
            agent_server,
            "CLAUDE_TRANSPORT",
            agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
        ), patch.object(
            agent_server,
            "claude_sdk_dependency_available",
            return_value=True,
        ), patch.object(
            agent_server,
            "turn_start_blocker",
            AsyncMock(return_value=None),
        ), patch.object(
            agent_server,
            "ensure_runtime_available",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={"id": "started", "seq": 1}),
        ), patch.object(
            agent_server.STORE,
            "update",
            AsyncMock(return_value=self.session),
        ), patch.object(
            agent_server.STORE,
            "mark_backend_started",
            AsyncMock(return_value=self.session),
        ), patch.object(
            agent_server,
            "run_claude",
            replacement_runner,
        ):
            refresh = asyncio.create_task(
                agent_server.post_claude_context_usage_refresh("chat-claude")
            )
            await asyncio.wait_for(sampling_started.wait(), 0.2)
            refresh.cancel()
            await asyncio.wait_for(eviction_started.wait(), 0.2)

            replacement = asyncio.create_task(
                agent_server.start_turn(
                    "chat-claude",
                    agent_server.TurnRequest(prompt="Replacement turn"),
                )
            )
            await asyncio.sleep(0)
            self.assertFalse(replacement_running.is_set())

            release_eviction.set()
            with self.assertRaises(asyncio.CancelledError):
                await refresh
            # Provider admission now scrubs a pre-existing tmux daemon's
            # global and per-session environments before launch. Keep this
            # lifecycle assertion bounded without assuming that external
            # tmux I/O completes inside 200 ms on a busy host.
            started = await asyncio.wait_for(replacement, 1.0)
            await asyncio.wait_for(replacement_running.wait(), 0.2)

        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        self.assertTrue(manager.loaded)
        self.assertEqual(manager.active_run_id, started["run_id"])

    async def test_context_usage_rejects_stale_provider_and_stop_owner(self) -> None:
        manager = FakeClaudeManager()
        manager.context_usage_response = ({
            "totalTokens": 10,
            "maxTokens": 100,
            "rawMaxTokens": 120,
            "percentage": 10,
            "model": "claude",
        }, 3)
        self.session["claude_session_id"] = "current-provider"
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "claude_sdk_owner_token": manager.owner_token,
                "stop_requested": False,
            }
        }
        self.assertFalse(await agent_server.sample_claude_context_usage(
            "chat-claude",
            "run-claude",
            "stale-provider",
            manager,
        ))
        agent_server.ACTIVE["chat-claude"]["stop_requested"] = True
        self.assertFalse(await agent_server.sample_claude_context_usage(
            "chat-claude",
            "run-claude",
            "current-provider",
            manager,
        ))
        self.assertNotIn("context_usage_snapshot", self.session)

    async def test_context_usage_timeout_does_not_wait_for_slow_eviction(self) -> None:
        manager = FakeClaudeManager()
        manager.get_context_usage = AsyncMock(side_effect=wait_forever)  # type: ignore[method-assign]

        async def slow_evict(*_args: object, **_kwargs: object) -> bool:
            await asyncio.sleep(0.05)
            return True

        manager.evict = AsyncMock(side_effect=slow_evict)  # type: ignore[method-assign]
        self.session["claude_session_id"] = "provider-usage"
        stale_snapshot = {
            "provider_session_id": "provider-usage",
            "context_tokens": 50_000,
            "usage_generation": 4,
        }
        self.session.update({
            "_context_usage_generation": 4,
            "context_usage_state": "available",
            "context_usage_snapshot": stale_snapshot,
            "claude_context_usage_snapshot": stale_snapshot,
        })
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "claude_sdk_owner_token": manager.owner_token,
                "stop_requested": False,
            }
        }
        broadcast = AsyncMock()
        with patch.object(
            agent_server,
            "CLAUDE_CONTEXT_USAGE_TIMEOUT_SECONDS",
            0.01,
        ), patch.object(
            agent_server.STORE,
            "save",
            AsyncMock(),
        ), patch.object(
            agent_server.HUB,
            "broadcast",
            broadcast,
        ):
            self.assertFalse(await asyncio.wait_for(
                agent_server.sample_claude_context_usage(
                    "chat-claude",
                    "run-claude",
                    "provider-usage",
                    manager,
                ),
                0.1,
            ))
        manager.evict.assert_awaited_once_with("chat-claude", force=True)
        self.assertEqual(self.session["context_usage_state"], "unavailable")
        self.assertNotIn("context_usage_snapshot", self.session)
        self.assertNotIn("claude_context_usage_snapshot", self.session)
        self.assertEqual(self.session["_context_usage_generation"], 5)
        packet = broadcast.await_args.args[1]
        self.assertEqual(packet["context_usage_state"], "unavailable")
        await asyncio.sleep(0.06)

    async def test_stop_before_sampling_invalidates_without_rpc(self) -> None:
        manager = FakeClaudeManager()
        manager.get_context_usage = AsyncMock()  # type: ignore[method-assign]
        self.session["claude_session_id"] = "provider-usage"
        stale_snapshot = {
            "provider_session_id": "provider-usage",
            "context_tokens": 22_000,
            "usage_generation": 2,
        }
        self.session.update({
            "_context_usage_generation": 2,
            "context_usage_state": "available",
            "context_usage_snapshot": stale_snapshot,
            "claude_context_usage_snapshot": stale_snapshot,
        })
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "claude_sdk_owner_token": manager.owner_token,
                "stop_requested": True,
            }
        }
        broadcast = AsyncMock()
        with patch.object(
            agent_server.STORE,
            "save",
            AsyncMock(),
        ), patch.object(
            agent_server.HUB,
            "broadcast",
            broadcast,
        ):
            self.assertFalse(await agent_server.sample_claude_context_usage(
                "chat-claude",
                "run-claude",
                "provider-usage",
                manager,
            ))

        manager.get_context_usage.assert_not_awaited()
        self.assertEqual(self.session["context_usage_state"], "unavailable")
        self.assertNotIn("context_usage_snapshot", self.session)
        self.assertEqual(
            broadcast.await_args.args[1]["context_usage_state"],
            "unavailable",
        )

    async def test_stop_during_successful_rpc_invalidates_rejected_sample(self) -> None:
        manager = FakeClaudeManager()
        sampling_started = asyncio.Event()
        release_sampling = asyncio.Event()

        async def valid_after_stop(
            *_args: object,
            **_kwargs: object,
        ) -> tuple[dict[str, Any], int]:
            sampling_started.set()
            await release_sampling.wait()
            return ({
                "totalTokens": 25_000,
                "maxTokens": 188_000,
                "rawMaxTokens": 200_000,
                "percentage": 13.3,
                "model": "claude-opus",
            }, 5)

        manager.get_context_usage = AsyncMock(  # type: ignore[method-assign]
            side_effect=valid_after_stop
        )
        self.session["claude_session_id"] = "provider-usage"
        stale_snapshot = {
            "provider_session_id": "provider-usage",
            "context_tokens": 21_000,
            "usage_generation": 6,
        }
        self.session.update({
            "_context_usage_generation": 6,
            "context_usage_state": "available",
            "context_usage_snapshot": stale_snapshot,
            "claude_context_usage_snapshot": stale_snapshot,
        })
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "claude_sdk_owner_token": manager.owner_token,
                "stop_requested": False,
            }
        }
        broadcast = AsyncMock()
        with patch.object(
            agent_server.STORE,
            "save",
            AsyncMock(),
        ), patch.object(
            agent_server.HUB,
            "broadcast",
            broadcast,
        ):
            sampling = asyncio.create_task(
                agent_server.sample_claude_context_usage(
                    "chat-claude",
                    "run-claude",
                    "provider-usage",
                    manager,
                )
            )
            await asyncio.wait_for(sampling_started.wait(), 0.2)
            agent_server.ACTIVE["chat-claude"]["stop_requested"] = True
            release_sampling.set()
            self.assertFalse(await asyncio.wait_for(sampling, 0.2))

        self.assertEqual(self.session["context_usage_state"], "unavailable")
        self.assertNotIn("context_usage_snapshot", self.session)
        self.assertEqual(
            broadcast.await_args.args[1]["context_usage_state"],
            "unavailable",
        )

    async def test_context_usage_rpc_and_invalid_results_clear_current_snapshot(self) -> None:
        self.session["claude_session_id"] = "provider-usage"
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "claude_sdk_owner_token": "fake-claude-owner",
                "stop_requested": False,
            }
        }
        cases = (
            AsyncMock(side_effect=RuntimeError("usage RPC failed")),
            AsyncMock(return_value=({"unexpected": True}, 7)),
        )
        for index, getter in enumerate(cases, start=1):
            with self.subTest(case=index):
                manager = FakeClaudeManager()
                manager.get_context_usage = getter  # type: ignore[method-assign]
                stale_snapshot = {
                    "provider_session_id": "provider-usage",
                    "context_tokens": 40_000 + index,
                    "usage_generation": index * 10,
                }
                self.session.update({
                    "_context_usage_generation": index * 10,
                    "context_usage_state": "available",
                    "context_usage_snapshot": stale_snapshot,
                    "claude_context_usage_snapshot": stale_snapshot,
                })
                broadcast = AsyncMock()
                with patch.object(
                    agent_server.STORE,
                    "save",
                    AsyncMock(),
                ), patch.object(
                    agent_server.HUB,
                    "broadcast",
                    broadcast,
                ):
                    self.assertFalse(await agent_server.sample_claude_context_usage(
                        "chat-claude",
                        "run-claude",
                        "provider-usage",
                        manager,
                    ))
                self.assertEqual(
                    self.session["context_usage_state"],
                    "unavailable",
                )
                self.assertNotIn("context_usage_snapshot", self.session)
                self.assertEqual(
                    broadcast.await_args.args[1]["context_usage_state"],
                    "unavailable",
                )

    async def test_failed_sample_cannot_clear_newer_generation(self) -> None:
        manager = FakeClaudeManager()
        sampling_started = asyncio.Event()
        release_sampling = asyncio.Event()

        async def invalid_after_race(
            *_args: object,
            **_kwargs: object,
        ) -> tuple[dict[str, Any], int]:
            sampling_started.set()
            await release_sampling.wait()
            return {"invalid": True}, 4

        manager.get_context_usage = AsyncMock(  # type: ignore[method-assign]
            side_effect=invalid_after_race
        )
        self.session["claude_session_id"] = "provider-usage"
        old_snapshot = {
            "provider_session_id": "provider-usage",
            "context_tokens": 20_000,
            "usage_generation": 8,
        }
        self.session.update({
            "_context_usage_generation": 8,
            "context_usage_state": "available",
            "context_usage_snapshot": old_snapshot,
            "claude_context_usage_snapshot": old_snapshot,
        })
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "claude_sdk_owner_token": manager.owner_token,
                "stop_requested": False,
            }
        }
        broadcast = AsyncMock()
        with patch.object(
            agent_server.STORE,
            "save",
            AsyncMock(),
        ), patch.object(
            agent_server.HUB,
            "broadcast",
            broadcast,
        ):
            sampling = asyncio.create_task(
                agent_server.sample_claude_context_usage(
                    "chat-claude",
                    "run-claude",
                    "provider-usage",
                    manager,
                )
            )
            await asyncio.wait_for(sampling_started.wait(), 0.2)
            newer_snapshot = {
                "provider_session_id": "provider-usage",
                "context_tokens": 30_000,
                "usage_generation": 9,
            }
            async with agent_server.STORE._lock:
                self.session.update({
                    "_context_usage_generation": 9,
                    "context_usage_state": "available",
                    "context_usage_snapshot": newer_snapshot,
                    "claude_context_usage_snapshot": newer_snapshot,
                })
            agent_server.ACTIVE["chat-claude"]["stop_requested"] = True
            release_sampling.set()
            self.assertFalse(await asyncio.wait_for(sampling, 0.2))

        self.assertIs(self.session["context_usage_snapshot"], newer_snapshot)
        self.assertEqual(self.session["context_usage_state"], "available")
        broadcast.assert_not_awaited()

    async def test_noninteractive_client_keeps_print_compatibility(self) -> None:
        sdk = AsyncMock()
        print_runner = AsyncMock()
        with patch.object(
            agent_server,
            "run_claude_sdk",
            sdk,
        ), patch.object(
            agent_server,
            "run_claude_print",
            print_runner,
        ):
            await agent_server.run_claude(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
                interactive_agent_sdk=False,
            )

        sdk.assert_not_awaited()
        print_runner.assert_awaited_once()

    async def test_print_fallback_retires_sdk_and_preserves_resume_identity(self) -> None:
        session = {
            **self.session,
            "claude_session_id": "provider-from-print",
            "claude_session_cwd": self.cwd,
        }
        order: list[str] = []

        async def evict(*_args: object, **_kwargs: object) -> bool:
            order.append("evict")
            return True

        async def run_print(
            _session_id: str,
            _run_id: str,
            _prompt: str,
            selected_session: dict[str, object],
            _manifest_path: Path,
            **_kwargs: object,
        ) -> None:
            order.append("print")
            self.assertEqual(
                selected_session.get("claude_session_id"),
                "provider-from-print",
            )

        with patch.object(
            agent_server,
            "evict_claude_sdk_chat",
            side_effect=evict,
        ), patch.object(
            agent_server,
            "run_claude_print",
            side_effect=run_print,
        ):
            await agent_server.run_claude(
                "chat-claude",
                "run-claude",
                "Prompt",
                session,
                Path(self.cwd) / ".manifest.json",
                interactive_agent_sdk=False,
            )

        self.assertEqual(order, ["evict", "print"])

        captured_options: dict[str, object] = {}

        def make_options(**kwargs: object) -> dict[str, object]:
            captured_options.update(kwargs)
            return kwargs

        with patch.object(
            agent_server,
            "claude_sdk_cli_path",
            return_value="/usr/bin/claude",
        ), patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=("provider-from-print", None),
        ), patch.object(
            agent_server,
            "create_claude_agent_options",
            side_effect=make_options,
        ):
            agent_server.build_claude_sdk_options(
                "chat-claude",
                session,
                self.cwd,
                Path(self.cwd) / ".manifest.json",
            )

        self.assertEqual(captured_options["resume"], "provider-from-print")
        self.assertEqual(
            captured_options["extra_args"],
            {
                "replay-user-messages": None,
                "allow-dangerously-skip-permissions": None,
            },
        )

    async def test_sdk_options_explicitly_shadow_server_secrets(self) -> None:
        captured_options: dict[str, object] = {}

        def make_options(**kwargs: object) -> dict[str, object]:
            captured_options.update(kwargs)
            return kwargs

        inherited = {
            name: f"inherited-{index}"
            for index, name in enumerate(agent_server.PROVIDER_SECRET_ENV_NAMES)
        }
        inherited["ANTHROPIC_API_KEY"] = "provider-credential"
        with patch.dict(os.environ, inherited), patch.object(
            agent_server,
            "claude_sdk_cli_path",
            return_value="/usr/bin/claude",
        ), patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "create_claude_agent_options",
            side_effect=make_options,
        ):
            agent_server.build_claude_sdk_options(
                "chat-claude",
                self.session,
                self.cwd,
                Path(self.cwd) / ".manifest.json",
            )

        child_env = captured_options["env"]
        self.assertIsInstance(child_env, dict)
        for secret_name in agent_server.PROVIDER_SECRET_ENV_NAMES:
            with self.subTest(secret_name=secret_name):
                self.assertIn(secret_name, child_env)
                self.assertEqual(child_env[secret_name], "")
                self.assertEqual({**inherited, **child_env}[secret_name], "")
        self.assertEqual(child_env["ANTHROPIC_API_KEY"], "provider-credential")

    async def test_server_secrets_are_removed_from_process_environment(self) -> None:
        inherited = {
            name: f"server-secret-{index}"
            for index, name in enumerate(agent_server.PROVIDER_SECRET_ENV_NAMES)
        }
        inherited["ANTHROPIC_API_KEY"] = "provider-credential"
        with patch.dict(os.environ, inherited, clear=False):
            removed = agent_server.scrub_server_secret_environment()
            self.assertEqual(set(removed), set(agent_server.PROVIDER_SECRET_ENV_NAMES))
            for secret_name in agent_server.PROVIDER_SECRET_ENV_NAMES:
                self.assertNotIn(secret_name, os.environ)
            self.assertEqual(
                os.environ.get("ANTHROPIC_API_KEY"),
                "provider-credential",
            )

    async def test_permission_mode_options_hooks_and_plan_tools_are_wired(self) -> None:
        session = {**self.session, "claude_permission_mode": "plan"}
        captured_options: dict[str, object] = {}
        permission = AsyncMock(return_value={"behavior": "allow"})

        def make_options(**kwargs: object) -> dict[str, object]:
            captured_options.update(kwargs)
            return kwargs

        with patch.object(
            agent_server,
            "claude_sdk_cli_path",
            return_value="/usr/bin/claude",
        ), patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "create_claude_agent_options",
            side_effect=make_options,
        ), patch.object(
            agent_server,
            "handle_claude_tool_permission",
            permission,
        ):
            options, config_key, _ = agent_server.build_claude_sdk_options(
                "chat-claude",
                session,
                self.cwd,
                Path(self.cwd) / ".manifest.json",
            )
            result = await options["can_use_tool"](
                "ExitPlanMode",
                {"plan": "Proceed carefully"},
                {"tool_use_id": "exit-plan"},
            )

        self.assertEqual(captured_options["permission_mode"], "plan")
        self.assertEqual(agent_server.CLAUDE_SDK_CONFIGURATION_VERSION, 7)
        self.assertEqual(
            captured_options["disallowed_tools"],
            ["CronCreate", "Monitor", "ScheduleWakeup"],
        )
        self.assertEqual(
            captured_options["thinking"],
            {"type": "adaptive", "display": "summarized"},
        )
        self.assertEqual(
            captured_options["extra_args"],
            {
                "replay-user-messages": None,
                "allow-dangerously-skip-permissions": None,
            },
        )
        hooks = captured_options["hooks"]
        self.assertEqual(
            [matcher.matcher for matcher in hooks["PreToolUse"]],
            ["Bash", "CronCreate", "Monitor", "ScheduleWakeup"],
        )
        self.assertEqual(result, {"behavior": "allow"})
        permission.assert_awaited_once_with(
            "chat-claude",
            "ExitPlanMode",
            {"plan": "Proceed carefully"},
            {"tool_use_id": "exit-plan"},
            owner_token="",
        )
        default_key = agent_server.claude_sdk_configuration_key(
            {**session, "claude_permission_mode": "default"},
            self.cwd,
            "/usr/bin/claude",
            agent_server.session_system_prompt(
                "chat-claude",
                session,
                Path(self.cwd) / ".manifest.json",
            ),
        )
        self.assertNotEqual(config_key, default_key)
        system_prompt = agent_server.session_system_prompt(
            "chat-claude",
            session,
            Path(self.cwd) / ".manifest.json",
        )
        with patch.object(agent_server, "CLAUDE_SDK_CONFIGURATION_VERSION", 6):
            previous_version_key = agent_server.claude_sdk_configuration_key(
                session,
                self.cwd,
                "/usr/bin/claude",
                system_prompt,
            )
        with patch.object(
            agent_server,
            "CLAUDE_NON_DURABLE_SCHEDULER_TOOLS",
            ("CronCreate",),
        ):
            previous_tools_key = agent_server.claude_sdk_configuration_key(
                session,
                self.cwd,
                "/usr/bin/claude",
                system_prompt,
            )
        self.assertNotEqual(config_key, previous_version_key)
        self.assertNotEqual(config_key, previous_tools_key)

    async def test_nondurable_scheduler_permission_never_creates_interaction(self) -> None:
        append_event = AsyncMock(return_value={})
        update_metadata = AsyncMock()
        with patch.dict(sys.modules, fake_claude_sdk_modules()), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "update_claude_pending_session_metadata",
            update_metadata,
        ):
            for tool_name in ("CronCreate", "Monitor", "ScheduleWakeup"):
                with self.subTest(tool_name=tool_name):
                    result = await agent_server.handle_claude_tool_permission(
                        "chat-claude",
                        tool_name,
                        {},
                        {"tool_use_id": f"tool-{tool_name}"},
                    )
                    self.assertIsInstance(result, FakePermissionResultDeny)
                    self.assertFalse(getattr(result, "interrupt", True))
                    self.assertIn("AgentsDock Jobs CLI", result.message)
                    self.assertIn("provider-authority block", result.message)

        self.assertFalse(agent_server.CLAUDE_PENDING_INTERACTIONS)
        append_event.assert_not_awaited()
        update_metadata.assert_not_awaited()

    async def test_bypass_permission_mode_never_creates_approval_interaction(self) -> None:
        self.session["claude_permission_mode"] = "bypassPermissions"
        manager = FakeClaudeManager()
        manager.active_run_id = "run-claude"
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "interactive_agent_sdk": True,
                "stop_requested": False,
                "claude_sdk_owner_token": manager.owner_token,
                "claude_permission_run_id": "run-claude",
                "claude_permissions_open": True,
                "claude_permission_mode": "bypassPermissions",
            }
        }
        # The persisted setting can change while a turn is active. Permission
        # callbacks must keep using the policy captured when this turn began.
        self.session["claude_permission_mode"] = "default"
        append_event = AsyncMock(return_value={})
        update_metadata = AsyncMock()
        with patch.dict(sys.modules, fake_claude_sdk_modules()), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "update_claude_pending_session_metadata",
            update_metadata,
        ):
            for tool_name, input_data in (
                ("Read", {"file_path": "/tmp/read-only.txt"}),
                ("Bash", {"command": "pwd"}),
            ):
                with self.subTest(tool_name=tool_name):
                    result = await agent_server.handle_claude_tool_permission(
                        "chat-claude",
                        tool_name,
                        input_data,
                        {"tool_use_id": f"tool-{tool_name}"},
                        owner_token=manager.owner_token,
                    )
                    self.assertIsInstance(result, FakePermissionResultAllow)
                    self.assertEqual(result.updated_input, input_data)

        self.assertFalse(agent_server.CLAUDE_PENDING_INTERACTIONS)
        append_event.assert_not_awaited()
        update_metadata.assert_not_awaited()

    async def test_permission_mode_runtime_contract_and_public_session(self) -> None:
        self.session["claude_permission_mode"] = "acceptEdits"
        with patch.object(
            agent_server,
            "claude_sdk_dependency_available",
            return_value=True,
        ), patch.object(
            agent_server,
            "CLAUDE_TRANSPORT",
            agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
        ):
            runtime = await agent_server.claude_runtime_snapshot("chat-claude")

        self.assertEqual(runtime["policy"]["permission_mode"], "acceptEdits")
        self.assertEqual(
            runtime["permission_modes"],
            list(agent_server.CLAUDE_PERMISSION_MODE_OPTIONS),
        )
        self.assertTrue(runtime["features"]["permission_mode_control"])
        with patch.object(
            agent_server,
            "host_pressure_snapshot",
            return_value={},
        ), patch.object(
            agent_server,
            "tmux_capability",
            return_value={"available": False},
        ), patch.object(
            agent_server,
            "runtime_diagnostics_snapshot",
            return_value={},
        ), patch.object(
            agent_server,
            "claude_sdk_dependency_available",
            return_value=True,
        ), patch.object(
            agent_server,
            "CLAUDE_TRANSPORT",
            agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
        ):
            health = await agent_server.health()
        capability = health["capabilities"]["claude_controls"]
        self.assertTrue(capability["features"]["permission_mode_control"])
        self.assertEqual(
            capability["permission_modes"],
            list(agent_server.CLAUDE_PERMISSION_MODE_OPTIONS),
        )
        self.assertEqual(
            agent_server.public_session(self.session)["claude_permission_mode"],
            "acceptEdits",
        )
        legacy = {"id": "legacy", "backend": agent_server.BACKEND_CLAUDE}
        self.assertEqual(
            agent_server.effective_claude_permission_mode(legacy),
            agent_server.CLAUDE_DEFAULT_PERMISSION_MODE,
        )

    async def test_permission_mode_change_is_saved_for_next_turn_while_active(self) -> None:
        self.session["claude_permission_mode"] = "default"
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "claude_permission_mode": "default",
            }
        }

        async def update_session_value(
            _session_id: str,
            values: dict[str, object],
        ) -> dict[str, object]:
            self.session.update(values)
            return self.session

        update = AsyncMock(side_effect=update_session_value)
        with patch.object(agent_server.STORE, "update", update):
            result = await agent_server.update_session(
                "chat-claude",
                agent_server.UpdateSessionRequest(
                    claude_permission_mode="bypassPermissions",
                ),
            )

        self.assertEqual(
            result["session"]["claude_permission_mode"],
            "bypassPermissions",
        )
        update.assert_awaited_once()
        self.assertEqual(
            agent_server.active_claude_permission_mode(
                "chat-claude",
                agent_server.ACTIVE["chat-claude"],
            ),
            "default",
        )

    async def test_permission_mode_store_persists_and_null_resets(self) -> None:
        self.session["claude_permission_mode"] = "default"
        with patch.object(agent_server.STORE, "save", AsyncMock()):
            updated = await agent_server.STORE.update(
                "chat-claude",
                {"claude_permission_mode": "dontAsk"},
            )
            persisted_mode = updated["claude_permission_mode"]
            reset = await agent_server.STORE.update(
                "chat-claude",
                {"claude_permission_mode": None},
            )

        self.assertEqual(persisted_mode, "dontAsk")
        self.assertEqual(reset["claude_permission_mode"], "default")

    async def test_print_fallback_keeps_legacy_permission_behavior(self) -> None:
        session = {**self.session, "claude_permission_mode": "plan"}
        command = agent_server.build_claude_cmd(
            "chat-claude",
            session,
            Path(self.cwd) / ".manifest.json",
        )

        self.assertIn("--dangerously-skip-permissions", command)
        self.assertNotIn("--permission-mode", command)
        disallowed_index = command.index("--disallowedTools")
        self.assertEqual(
            command[disallowed_index + 1:disallowed_index + 7],
            [
                "AskUserQuestion",
                "EnterPlanMode",
                "ExitPlanMode",
                "CronCreate",
                "Monitor",
                "ScheduleWakeup",
            ],
        )
        self.assertNotIn("CronList", command)
        self.assertNotIn("CronDelete", command)

    async def test_process_tree_kill_does_not_wait_forever_after_sigkill(
        self,
    ) -> None:
        process = NeverSettlingProcess()
        with patch.object(
            agent_server.os,
            "getpgid",
            side_effect=ProcessLookupError,
        ):
            result = await asyncio.wait_for(
                agent_server.terminate_process_tree(process, grace=0.01),
                timeout=0.3,
            )

        self.assertTrue(result)
        self.assertEqual(process.wait_calls, 2)
        self.assertEqual(process.terminate_calls, 1)
        self.assertEqual(process.kill_calls, 1)

    async def test_stale_sdk_cleanup_cancels_only_its_owner_generation(
        self,
    ) -> None:
        loop = asyncio.get_running_loop()
        old_future: asyncio.Future[dict[str, object]] = loop.create_future()
        new_future: asyncio.Future[dict[str, object]] = loop.create_future()
        pending = {
            "old": {
                "session_id": "chat-claude",
                "turn_id": "run-old",
                "owner_token": "owner-old",
                "future": old_future,
                "responded": False,
            },
            "new": {
                "session_id": "chat-claude",
                "turn_id": "run-new",
                "owner_token": "owner-new",
                "future": new_future,
                "responded": False,
            },
        }
        with patch.object(
            agent_server,
            "CLAUDE_PENDING_INTERACTIONS",
            pending,
        ), patch.object(
            agent_server,
            "update_claude_pending_session_metadata",
            AsyncMock(),
        ):
            await agent_server.cancel_claude_interactions(
                "chat-claude",
                resolution="turn_stopped",
                expected_run_id="run-old",
                ownership_token="owner-old",
            )

        self.assertTrue(old_future.done())
        self.assertEqual(old_future.result(), {"decision": "cancel"})
        self.assertTrue(pending["old"]["responded"])
        self.assertFalse(new_future.done())
        self.assertFalse(pending["new"]["responded"])

    async def test_hung_print_stop_terminalizes_and_preserves_promoted_turn(
        self,
    ) -> None:
        process = CancellationHostileClaudePrintProcess()
        human_turn = {
            "queued_id": "queued-human",
            "prompt": "Continue after the scheduled print run.",
            "file_ids": [],
            "backend": agent_server.BACKEND_CLAUDE,
            "_durable": True,
        }
        self.session["active_run"] = {"run_id": "run-claude"}
        agent_server.CURRENT_TURNS["chat-claude"]["purpose"] = "scheduled_job"
        agent_server.RUN_METADATA = {
            "run-claude": {"purpose": "scheduled_job"},
        }
        agent_server.QUEUED_TURNS = {
            "chat-claude": deque([human_turn]),
        }
        queue_start_tasks: dict[str, asyncio.Task[object]] = {}
        launch_started = asyncio.Event()
        finish_launch = asyncio.Event()
        launch_calls: list[
            tuple[str, agent_server.TurnRequest, dict[str, object]]
        ] = []

        async def terminate(
            selected: CancellationHostileClaudePrintProcess,
            **_kwargs: object,
        ) -> bool:
            selected.returncode = -15
            return True

        async def gated_start_turn(
            session_id: str,
            request: agent_server.TurnRequest,
            **kwargs: object,
        ) -> dict[str, object]:
            launch_calls.append((session_id, request, kwargs))
            async with agent_server.ACTIVE_LOCK:
                agent_server.ACTIVE[session_id] = {
                    "run_id": "run-human",
                    "backend": agent_server.BACKEND_CLAUDE,
                    "transport": agent_server.CLAUDE_TRANSPORT_PRINT,
                }
                agent_server.BUSY_SESSIONS.add(session_id)
                agent_server.CURRENT_TURNS[session_id] = {
                    "run_id": "run-human",
                    "backend": agent_server.BACKEND_CLAUDE,
                }
                self.session["active_run"] = {"run_id": "run-human"}
            launch_started.set()
            await finish_launch.wait()
            return {"run_id": "run-human", "queued": False}

        append_event = AsyncMock(return_value={})
        append_finished = AsyncMock(return_value={})
        quarantine = AsyncMock(return_value=True)
        with patch.multiple(
            agent_server,
            QUEUE_START_TASKS=queue_start_tasks,
            STOP_CONFIRM_TIMEOUT_SECONDS=0.01,
            resolve_claude_resume_provider=Mock(return_value=(None, None)),
            capture_git_baseline=AsyncMock(return_value={"head": "base"}),
            build_claude_cmd=Mock(return_value=["claude", "-p"]),
            process_group_for_pid=Mock(return_value=4243),
            watch_manifest_artifacts=wait_forever,
            append_event=append_event,
            append_turn_finished_event=append_finished,
            append_active_stdout=AsyncMock(),
            mark_provider_turn_ready=AsyncMock(),
            persist_run_provider_session=AsyncMock(return_value=True),
            collect_manifest=AsyncMock(),
            collect_recent_leftover_manifests=AsyncMock(),
            publish_turn_code_diff=AsyncMock(),
            terminate_process_tree=AsyncMock(side_effect=terminate),
            revoke_cross_chat_capability=AsyncMock(),
            cancel_codex_interactions=AsyncMock(),
            cancel_claude_interactions=AsyncMock(),
            quarantine_codex_goal_thread=quarantine,
            _start_turn_locked=AsyncMock(side_effect=gated_start_turn),
        ), patch.object(
            agent_server.asyncio,
            "create_subprocess_exec",
            AsyncMock(return_value=process),
        ):
            provider_task = asyncio.create_task(
                agent_server.supervise_provider_turn_task(
                    "chat-claude",
                    "run-claude",
                    agent_server.BACKEND_CLAUDE,
                    agent_server.run_claude_print(
                        "chat-claude",
                        "run-claude",
                        "Scheduled prompt",
                        dict(self.session),
                        Path(self.cwd) / ".manifest.json",
                    ),
                )
            )
            agent_server.SESSION_TURN_TASKS = {
                "chat-claude": {provider_task},
            }
            promotion_task: asyncio.Task[object] | None = None
            try:
                await asyncio.wait_for(process.stdout.started.wait(), 0.5)
                result = await asyncio.wait_for(
                    agent_server.stop_turn(
                        "chat-claude",
                        cascade_claude_subagents=False,
                    ),
                    timeout=0.5,
                )
                await asyncio.wait_for(launch_started.wait(), 0.5)
                promotion_task = queue_start_tasks.get("chat-claude")
                self.assertIsNotNone(promotion_task)

                process.stdout.release.set()
                await asyncio.wait_for(
                    asyncio.gather(provider_task, return_exceptions=True),
                    timeout=0.5,
                )

                self.assertTrue(result["stopped"])
                self.assertTrue(result["hard_stop"])
                self.assertEqual(len(launch_calls), 1)
                self.assertEqual(
                    agent_server.ACTIVE["chat-claude"]["run_id"],
                    "run-human",
                )
                self.assertIn("chat-claude", agent_server.BUSY_SESSIONS)
                self.assertEqual(
                    agent_server.CURRENT_TURNS["chat-claude"]["run_id"],
                    "run-human",
                )
                terminal_calls = [
                    call
                    for call in append_event.await_args_list
                    if call.args[1] == "turn_stopped"
                ]
                self.assertEqual(len(terminal_calls), 1)
                append_finished.assert_not_awaited()
                quarantine.assert_not_awaited()
            finally:
                process.stdout.release.set()
                finish_launch.set()
                if not provider_task.done():
                    provider_task.cancel()
                await asyncio.gather(provider_task, return_exceptions=True)
                if promotion_task is not None:
                    await asyncio.gather(
                        promotion_task,
                        return_exceptions=True,
                    )

        self.assertFalse(queue_start_tasks)

    async def test_delayed_sdk_finalizer_cannot_touch_promoted_generation(
        self,
    ) -> None:
        handle = FakeClaudeRun()
        manager = FakeClaudeManager(handle)
        manager.owner_token = "owner-old"
        agent_server.CLAUDE_SDK_MANAGER = manager
        human_turn = {
            "queued_id": "queued-human",
            "prompt": "Continue on the replacement SDK client.",
            "file_ids": [],
            "backend": agent_server.BACKEND_CLAUDE,
            "_durable": True,
        }
        self.session.update({
            "active_run": {"run_id": "run-claude"},
            "session_id": "provider-old",
            "claude_session_id": "provider-old",
            "claude_session_cwd": self.cwd,
        })
        agent_server.CURRENT_TURNS["chat-claude"]["purpose"] = "scheduled_job"
        agent_server.RUN_METADATA = {
            "run-claude": {"purpose": "scheduled_job"},
        }
        agent_server.QUEUED_TURNS = {
            "chat-claude": deque([human_turn]),
        }
        queue_start_tasks: dict[str, asyncio.Task[object]] = {}
        cleanup_started = asyncio.Event()
        release_cleanup = asyncio.Event()
        launch_started = asyncio.Event()
        finish_launch = asyncio.Event()
        new_permission: asyncio.Future[dict[str, object]] | None = None
        real_cancel_interactions = agent_server.cancel_claude_interactions

        async def gated_cancel_interactions(
            session_id: str | None = None,
            **kwargs: object,
        ) -> None:
            if kwargs.get("expected_run_id") == "run-claude":
                cleanup_started.set()
                await release_cleanup.wait()
            await real_cancel_interactions(session_id, **kwargs)

        async def gated_start_turn(
            session_id: str,
            _request: agent_server.TurnRequest,
            **_kwargs: object,
        ) -> dict[str, object]:
            nonlocal new_permission
            manager.owner_token = "owner-new"
            manager.active_run_id = "run-human"
            manager.loaded = True
            new_permission = asyncio.get_running_loop().create_future()
            async with agent_server.CLAUDE_PENDING_INTERACTIONS_LOCK:
                agent_server.CLAUDE_PENDING_INTERACTIONS["new-card"] = {
                    "id": "new-card",
                    "session_id": session_id,
                    "turn_id": "run-human",
                    "owner_token": "owner-new",
                    "future": new_permission,
                    "responded": False,
                }
            async with agent_server.ACTIVE_LOCK:
                agent_server.ACTIVE[session_id] = {
                    "run_id": "run-human",
                    "backend": agent_server.BACKEND_CLAUDE,
                    "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                    "claude_sdk_owner_token": "owner-new",
                }
                agent_server.BUSY_SESSIONS.add(session_id)
                agent_server.CURRENT_TURNS[session_id] = {
                    "run_id": "run-human",
                    "backend": agent_server.BACKEND_CLAUDE,
                }
                self.session.update({
                    "active_run": {"run_id": "run-human"},
                    "session_id": "provider-new",
                    "claude_session_id": "provider-new",
                })
            launch_started.set()
            await finish_launch.wait()
            return {"run_id": "run-human", "queued": False}

        append_event = AsyncMock(return_value={})
        append_finished = AsyncMock(return_value={})
        save_provider = AsyncMock(wraps=agent_server.STORE.save_provider_session)
        with patch.multiple(
            agent_server,
            QUEUE_START_TASKS=queue_start_tasks,
            STOP_CONFIRM_TIMEOUT_SECONDS=0.01,
            resolve_claude_resume_provider=Mock(
                return_value=("provider-old", None)
            ),
            capture_git_baseline=AsyncMock(return_value={"head": "base"}),
            build_claude_sdk_options=Mock(
                return_value=(object(), "config", "/usr/bin/claude")
            ),
            claude_sdk_manager=AsyncMock(return_value=manager),
            watch_manifest_artifacts=wait_forever,
            append_event=append_event,
            append_turn_finished_event=append_finished,
            collect_manifest=AsyncMock(),
            collect_recent_leftover_manifests=AsyncMock(),
            publish_turn_code_diff=AsyncMock(),
            revoke_cross_chat_capability=AsyncMock(),
            cancel_codex_interactions=AsyncMock(),
            cancel_claude_interactions=AsyncMock(
                side_effect=gated_cancel_interactions
            ),
            update_claude_pending_session_metadata=AsyncMock(),
            _start_turn_locked=AsyncMock(side_effect=gated_start_turn),
        ), patch.object(
            agent_server.STORE,
            "save_provider_session",
            save_provider,
        ):
            provider_task = asyncio.create_task(
                agent_server.supervise_provider_turn_task(
                    "chat-claude",
                    "run-claude",
                    agent_server.BACKEND_CLAUDE,
                    agent_server.run_claude_sdk(
                        "chat-claude",
                        "run-claude",
                        "Scheduled prompt",
                        dict(self.session),
                        Path(self.cwd) / ".manifest.json",
                    ),
                )
            )
            agent_server.SESSION_TURN_TASKS = {
                "chat-claude": {provider_task},
            }
            promotion_task: asyncio.Task[object] | None = None
            try:
                for _ in range(100):
                    active = agent_server.ACTIVE.get("chat-claude") or {}
                    if active.get("claude_sdk_run") is handle:
                        break
                    await asyncio.sleep(0)
                else:
                    self.fail("old SDK handle did not attach")

                result = await asyncio.wait_for(
                    agent_server.stop_turn(
                        "chat-claude",
                        cascade_claude_subagents=False,
                    ),
                    timeout=0.5,
                )
                await asyncio.wait_for(cleanup_started.wait(), 0.5)
                await asyncio.wait_for(launch_started.wait(), 0.5)
                promotion_task = queue_start_tasks.get("chat-claude")
                self.assertIsNotNone(promotion_task)

                release_cleanup.set()
                await asyncio.wait_for(
                    asyncio.gather(provider_task, return_exceptions=True),
                    timeout=0.5,
                )

                self.assertTrue(result["hard_stop"])
                self.assertEqual(manager.evict_calls, [("chat-claude", True)])
                self.assertEqual(manager.active_run_id, "run-human")
                self.assertTrue(manager.loaded)
                self.assertIsNotNone(new_permission)
                self.assertFalse(new_permission.done())
                self.assertEqual(self.session["claude_session_id"], "provider-new")
                self.assertEqual(
                    agent_server.ACTIVE["chat-claude"]["run_id"],
                    "run-human",
                )
                self.assertIn("chat-claude", agent_server.BUSY_SESSIONS)
                self.assertEqual(
                    agent_server.CURRENT_TURNS["chat-claude"]["run_id"],
                    "run-human",
                )
                save_provider.assert_not_awaited()
                append_finished.assert_not_awaited()
                terminal_calls = [
                    call
                    for call in append_event.await_args_list
                    if call.args[1] == "turn_stopped"
                ]
                self.assertEqual(len(terminal_calls), 1)
            finally:
                release_cleanup.set()
                finish_launch.set()
                if new_permission is not None and not new_permission.done():
                    new_permission.set_result({"decision": "cancel"})
                if not provider_task.done():
                    provider_task.cancel()
                await asyncio.gather(provider_task, return_exceptions=True)
                if promotion_task is not None:
                    await asyncio.gather(
                        promotion_task,
                        return_exceptions=True,
                    )

        self.assertFalse(queue_start_tasks)

    async def test_sdk_stop_timeout_retires_only_chat_and_terminalizes(self) -> None:
        handle = FakeClaudeRun()
        manager = FakeClaudeManager(handle)
        manager.active_run_id = "run-claude"
        runner = asyncio.create_task(wait_forever())
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {
            "chat-claude": {
                "proc": None,
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "claude_sdk_run": handle,
                "claude_sdk_owner_token": manager.owner_token,
                "provider_turn_ready": True,
                "stop_requested": False,
            }
        }
        agent_server.SESSION_TURN_TASKS = {"chat-claude": {runner}}

        with patch.object(
            agent_server,
            "STOP_CONFIRM_TIMEOUT_SECONDS",
            0.01,
        ), patch.object(
            agent_server,
            "cancel_codex_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ):
            result = await agent_server.stop_turn("chat-claude")

        self.assertTrue(result["stopped"])
        self.assertTrue(result["hard_stop"])
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        self.assertEqual(handle.interrupt_calls, 1)
        self.assertTrue(runner.cancelled() or runner.done())

    async def test_idle_stop_retires_only_chat_with_background_subagents(self) -> None:
        manager = FakeClaudeManager()
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.CURRENT_TURNS = {}
        snapshot = {
            "active_count": 1,
            "subagents": [{
                "run_id": "run-parent",
                "subagent_id": "child-one",
                "subagent_status": "running",
            }],
        }
        append_event = AsyncMock(return_value={})

        with patch.object(
            agent_server,
            "build_claude_subagent_snapshot",
            return_value=snapshot,
        ), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "cancel_codex_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ):
            result = await agent_server.stop_turn("chat-claude")

        self.assertTrue(result["stopped"])
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        self.assertEqual(result["subagents"]["interrupted"], ["child-one"])
        marker = next(
            call
            for call in self.append_durable_event.await_args_list
            if call.args[1] == "claude_subagents_stopped"
        )
        self.assertEqual(marker.args[2]["run_ids"], ["run-parent"])
        self.assertTrue(marker.args[2]["all"])

    async def test_unknown_claude_supervisor_state_keeps_stop_fence_closed(self) -> None:
        manager = FakeClaudeManager()
        manager.is_loaded = Mock(side_effect=RuntimeError("ownership unavailable"))
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()

        result = await agent_server.stop_idle_claude_background_subagents(
            "chat-claude",
            emit_event=False,
        )

        self.assertFalse(result["fence_committed"])
        self.assertEqual(result["pending"], ["claude-background-work"])
        self.assertIn("ownership unavailable", result["errors"])
        self.append_durable_event.assert_not_awaited()

    async def test_unknown_claude_supervisor_state_retries_to_durable_fence(self) -> None:
        manager = FakeClaudeManager()
        manager.is_loaded = Mock(
            side_effect=[RuntimeError("ownership unavailable"), False]
        )
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.CURRENT_TURNS = {}
        snapshot = {
            "active_count": 1,
            "subagents": [{
                "run_id": "run-parent",
                "subagent_id": "child-one",
                "subagent_status": "running",
            }],
        }

        with patch.object(
            agent_server,
            "CLAUDE_STOP_FENCE_RETRY_DELAYS_SECONDS",
            (0.0,),
        ), patch.object(
            agent_server,
            "build_claude_subagent_snapshot",
            return_value=snapshot,
        ), patch.object(
            agent_server,
            "cancel_codex_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "schedule_next_queued_turn",
        ) as schedule:
            result = await agent_server.stop_turn(
                "chat-claude",
                emit_event=False,
                schedule_queue=False,
                pause_queued_turns_on_stop=False,
            )
            for _ in range(100):
                if not agent_server.CLAUDE_STOP_FENCE_RETRY_TASKS:
                    break
                await asyncio.sleep(0)

        self.assertFalse(result["subagents"]["fence_committed"])
        self.assertEqual(manager.is_loaded.call_count, 2)
        self.assertNotIn(
            "chat-claude",
            agent_server.CLAUDE_STOP_FENCE_SESSIONS,
        )
        self.assertEqual(self.append_durable_event.await_count, 1)
        schedule.assert_called_once_with("chat-claude")

    async def test_initial_claude_stop_attempt_error_still_arms_retry(self) -> None:
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.CURRENT_TURNS = {}

        with patch.object(
            agent_server,
            "stop_idle_claude_background_subagents_bounded",
            new=AsyncMock(side_effect=RuntimeError("attempt failed")),
        ), patch.object(
            agent_server,
            "schedule_claude_stop_fence_retry",
        ) as schedule, patch.object(
            agent_server,
            "cancel_codex_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ):
            with self.assertRaisesRegex(RuntimeError, "attempt failed"):
                await agent_server.stop_turn(
                    "chat-claude",
                    emit_event=False,
                    schedule_queue=False,
                    pause_queued_turns_on_stop=False,
                )

        self.assertIn(
            "chat-claude",
            agent_server.CLAUDE_STOP_FENCE_SESSIONS,
        )
        self.assertIn(
            "chat-claude",
            agent_server.SERVER_MAINTENANCE_SESSIONS,
        )
        schedule.assert_called_once_with("chat-claude")

    async def test_failed_claude_stop_fence_retries_and_releases_admission(self) -> None:
        manager = FakeClaudeManager()
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.CURRENT_TURNS = {}
        snapshot = {
            "active_count": 1,
            "subagents": [{
                "run_id": "run-parent",
                "subagent_id": "child-one",
                "subagent_status": "running",
            }],
        }
        self.append_durable_event.side_effect = [
            OSError("event log unavailable"),
            {},
        ]

        with patch.object(
            agent_server,
            "CLAUDE_STOP_FENCE_RETRY_DELAYS_SECONDS",
            (0.0,),
        ), patch.object(
            agent_server,
            "build_claude_subagent_snapshot",
            return_value=snapshot,
        ), patch.object(
            agent_server,
            "cancel_codex_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "schedule_next_queued_turn",
        ) as schedule:
            result = await agent_server.stop_turn(
                "chat-claude",
                emit_event=False,
                schedule_queue=False,
                pause_queued_turns_on_stop=False,
            )
            for _ in range(100):
                if not agent_server.CLAUDE_STOP_FENCE_RETRY_TASKS:
                    break
                await asyncio.sleep(0)

        self.assertFalse(result["subagents"]["fence_committed"])
        self.assertNotIn(
            "chat-claude",
            agent_server.CLAUDE_STOP_FENCE_SESSIONS,
        )
        self.assertNotIn(
            "chat-claude",
            agent_server.SERVER_MAINTENANCE_SESSIONS,
        )
        self.assertNotIn(
            "chat-claude",
            agent_server.CLAUDE_STOP_FENCE_ATTEMPT_LOCKS,
        )
        self.assertEqual(self.append_durable_event.await_count, 2)
        schedule.assert_called_once_with("chat-claude")

    async def test_claude_stop_fence_retry_survives_unexpected_attempt_error(self) -> None:
        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS = set()
        agent_server.CLAUDE_STOP_FENCE_SESSIONS.add("chat-claude")
        agent_server.SERVER_MAINTENANCE_SESSIONS.add("chat-claude")
        attempt = AsyncMock(side_effect=[
            RuntimeError("unexpected persistence error"),
            {"fence_committed": True},
        ])

        with patch.object(
            agent_server,
            "CLAUDE_STOP_FENCE_RETRY_DELAYS_SECONDS",
            (0.0,),
        ), patch.object(
            agent_server,
            "stop_idle_claude_background_subagents_bounded",
            attempt,
        ), patch.object(
            agent_server,
            "schedule_next_queued_turn",
        ) as schedule:
            await agent_server.retry_claude_stop_fence("chat-claude")

        self.assertEqual(attempt.await_count, 2)
        self.assertNotIn(
            "chat-claude",
            agent_server.CLAUDE_STOP_FENCE_SESSIONS,
        )
        self.assertNotIn(
            "chat-claude",
            agent_server.SERVER_MAINTENANCE_SESSIONS,
        )
        schedule.assert_called_once_with("chat-claude")

    async def test_claude_stop_fence_attempt_has_hard_local_deadline(self) -> None:
        release = asyncio.Event()

        async def cancellation_hostile_attempt(
            *_args: object,
            **_kwargs: object,
        ) -> dict[str, object]:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await release.wait()
            return {"fence_committed": True}

        with patch.object(
            agent_server,
            "CLAUDE_STOP_FENCE_ATTEMPT_TIMEOUT_SECONDS",
            0.01,
        ), patch.object(
            agent_server,
            "stop_idle_claude_background_subagents",
            side_effect=cancellation_hostile_attempt,
        ):
            result = await agent_server.stop_idle_claude_background_subagents_bounded(
                "chat-claude",
                emit_event=False,
            )
            self.assertFalse(result["fence_committed"])
            self.assertEqual(result["pending"], ["claude-stop-fence"])
            release.set()
            pending = tuple(
                agent_server.CLAUDE_STOP_FENCE_ATTEMPT_TASKS.get(
                    "chat-claude"
                ) or ()
            )
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

    async def test_cancelled_sdk_start_drains_scheduled_job_successor_once(self) -> None:
        manager = FakeClaudeManager()

        async def cancel_during_start(
            *_args: object,
            **kwargs: object,
        ) -> FakeClaudeRun:
            on_supervisor_ready = kwargs.get("on_supervisor_ready")
            if callable(on_supervisor_ready):
                await on_supervisor_ready(manager.owner_token)
            raise asyncio.CancelledError

        manager.start_run = AsyncMock(side_effect=cancel_during_start)  # type: ignore[method-assign]
        human_turn = {
            "queued_id": "queued-human",
            "prompt": "Run after the cancelled scheduled job.",
            "file_ids": [],
            "backend": agent_server.BACKEND_CLAUDE,
            "_durable": True,
        }
        agent_server.QUEUED_TURNS = {
            "chat-claude": deque([human_turn]),
        }
        agent_server.CURRENT_TURNS["chat-claude"]["purpose"] = "scheduled_job"
        agent_server.RUN_METADATA = {
            "run-claude": {"purpose": "scheduled_job"},
        }
        queue_start_tasks: dict[str, asyncio.Task[object]] = {}
        launch_started = asyncio.Event()
        finish_launch = asyncio.Event()
        launch_calls: list[
            tuple[str, agent_server.TurnRequest, dict[str, object]]
        ] = []

        async def gated_start_turn(
            session_id: str,
            request: agent_server.TurnRequest,
            **kwargs: object,
        ) -> dict[str, object]:
            launch_calls.append((session_id, request, kwargs))
            launch_started.set()
            await finish_launch.wait()
            return {"run_id": "run-human", "queued": False}

        append_event = AsyncMock(return_value={})
        evict = AsyncMock(return_value=True)
        cancel_interactions = AsyncMock()
        with patch.multiple(
            agent_server,
            QUEUE_START_TASKS=queue_start_tasks,
            resolve_claude_resume_provider=Mock(return_value=(None, None)),
            capture_git_baseline=AsyncMock(return_value={"head": "base"}),
            build_claude_sdk_options=Mock(
                return_value=(object(), "config", "/usr/bin/claude")
            ),
            claude_sdk_manager=AsyncMock(return_value=manager),
            append_event=append_event,
            evict_claude_sdk_chat=evict,
            cancel_claude_interactions=cancel_interactions,
            _start_turn_locked=AsyncMock(side_effect=gated_start_turn),
        ):
            runner = asyncio.create_task(agent_server.supervise_provider_turn_task(
                "chat-claude",
                "run-claude",
                agent_server.BACKEND_CLAUDE,
                agent_server.run_claude_sdk(
                    "chat-claude",
                    "run-claude",
                    "Scheduled prompt",
                    dict(self.session),
                    Path(self.cwd) / ".manifest.json",
                ),
            ))
            promotion_task: asyncio.Task[object] | None = None
            try:
                with self.assertRaises(asyncio.CancelledError):
                    await runner
                await asyncio.wait_for(launch_started.wait(), timeout=0.5)
                promotion_task = queue_start_tasks.get("chat-claude")
                self.assertIsNotNone(promotion_task)
                await asyncio.sleep(0)

                self.assertNotIn("chat-claude", agent_server.ACTIVE)
                self.assertNotIn("chat-claude", agent_server.BUSY_SESSIONS)
                self.assertNotIn("chat-claude", agent_server.CURRENT_TURNS)
                self.assertNotIn("chat-claude", agent_server.QUEUED_TURNS)
                self.assertEqual(len(launch_calls), 1)
                launched_session, launched_request, launched_kwargs = launch_calls[0]
                self.assertEqual(launched_session, "chat-claude")
                self.assertEqual(
                    launched_request.prompt,
                    "Run after the cancelled scheduled job.",
                )
                self.assertEqual(launched_kwargs["queued_id"], "queued-human")
                terminal_calls = [
                    call
                    for call in append_event.await_args_list
                    if call.args[1] == "turn_stopped"
                ]
                self.assertEqual(len(terminal_calls), 1)
                evict.assert_awaited_once()
                cancel_interactions.assert_awaited_once_with(
                    "chat-claude",
                    resolution="turn_stopped",
                    expected_run_id="run-claude",
                    ownership_token=manager.owner_token,
                )
            finally:
                finish_launch.set()
                if promotion_task is not None:
                    await asyncio.gather(promotion_task, return_exceptions=True)

        self.assertFalse(queue_start_tasks)

    async def test_startup_query_can_request_permission_before_handle_returns(self) -> None:
        handle = FakeClaudeRun([{
            "type": "result",
            "result": "done",
            "session_id": "provider",
            "terminal_reason": "end_turn",
        }])
        manager = PermissionDuringStartManager(
            [handle],
            permission_on_calls={1},
        )
        agent_server.CLAUDE_SDK_MANAGER = manager

        async def permission_callback(
            tool_name: str,
            input_data: dict[str, Any],
            context: Any,
        ) -> object:
            return await agent_server.handle_claude_tool_permission(
                "chat-claude",
                tool_name,
                input_data,
                context,
                owner_token=manager.owner_token,
            )

        with patch.dict(sys.modules, fake_claude_sdk_modules()), patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(
                {"can_use_tool": permission_callback},
                "config",
                "/usr/bin/claude",
            ),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "update_claude_pending_session_metadata",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "project_claude_sdk_message",
            AsyncMock(return_value={
                "session_id": "provider",
                "result_text": "done",
                "terminal_reason": "end_turn",
                "is_error": False,
                "aborted": False,
                "error": "",
            }),
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "record_runtime_success",
            Mock(),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            await asyncio.wait_for(manager.permission_requested.wait(), 0.5)
            for _ in range(100):
                if agent_server.CLAUDE_PENDING_INTERACTIONS:
                    break
                await asyncio.sleep(0)
            interaction_id, interaction = next(iter(
                agent_server.CLAUDE_PENDING_INTERACTIONS.items()
            ))
            self.assertEqual(interaction["turn_id"], "run-claude")
            self.assertTrue(
                agent_server.ACTIVE["chat-claude"]["claude_permissions_open"]
            )
            await agent_server.resolve_claude_interaction(
                "chat-claude",
                interaction_id,
                {"decision": "accept"},
            )
            await asyncio.wait_for(runner, 0.5)

        self.assertEqual(len(manager.permission_results), 1)
        self.assertIsInstance(
            manager.permission_results[0],
            FakePermissionResultAllow,
        )
        self.assertFalse(agent_server.CLAUDE_PENDING_INTERACTIONS)

    async def test_steered_query_routes_permission_to_candidate_before_handle_returns(self) -> None:
        first = FakeClaudeRun()
        second_terminal = {
            "type": "result",
            "result": "steered done",
            "session_id": "provider",
            "terminal_reason": "end_turn",
        }
        second = FakeClaudeRun()
        manager = PermissionDuringStartManager(
            [first, second],
            permission_on_calls={2},
            jobs_authorization_on_calls={2},
        )
        agent_server.CLAUDE_SDK_MANAGER = manager
        predecessor_run_id = "run_claude"
        predecessor_route = {
            "route_id": "route_" + "5" * 32,
            "revision": "rev_" + "6" * 32,
            "alias": "chat1",
            "target_session_id": "ambient-claude-old",
            "actions": ["instruction"],
            "route_kind": (
                agent_server.PROVIDER_CROSS_CHAT_ROUTE_KIND_AMBIENT
            ),
        }
        candidate_route = {
            "route_id": "route_" + "7" * 32,
            "revision": "rev_" + "8" * 32,
            "alias": "chat1",
            "target_session_id": "ambient-claude-new",
            "actions": ["instruction"],
            "route_kind": (
                agent_server.PROVIDER_CROSS_CHAT_ROUTE_KIND_AMBIENT
            ),
        }
        agent_server.STORE.sessions.update({
            "ambient-claude-old": {
                "id": "ambient-claude-old",
                "title": "Ambient Claude old",
                "backend": agent_server.BACKEND_CLAUDE,
            },
            "ambient-claude-new": {
                "id": "ambient-claude-new",
                "title": "Ambient Claude new",
                "backend": agent_server.BACKEND_CLAUDE,
            },
        })
        agent_server.CURRENT_TURNS["chat-claude"]["run_id"] = predecessor_run_id
        agent_server.CURRENT_TURNS["chat-claude"][
            "provider_cross_chat_route_snapshot"
        ] = [predecessor_route]
        predecessor_path = await agent_server.issue_cross_chat_capability(
            "chat-claude",
            predecessor_run_id,
            [],
            actions={"jobs", "publish"},
        )
        predecessor_token = json.loads(
            predecessor_path.read_text(encoding="utf-8")
        )["provider_capability"]
        real_revoke = agent_server.revoke_cross_chat_capability
        predecessor_revoke_observations: list[tuple[bool, str]] = []

        async def recording_revoke(run_id: str) -> None:
            if run_id == predecessor_run_id:
                candidate_records = [
                    capability
                    for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
                    if capability.get("source_run_id") != predecessor_run_id
                ]
                candidate_path_value = (
                    str(candidate_records[0].get("authority_path") or "")
                    if len(candidate_records) == 1
                    else ""
                )
                predecessor_revoke_observations.append((
                    bool(candidate_path_value)
                    and Path(candidate_path_value).is_file(),
                    str(
                        agent_server.CURRENT_TURNS.get("chat-claude", {}).get(
                            "run_id"
                        )
                        or ""
                    ),
                ))
            await real_revoke(run_id)

        async def permission_callback(
            tool_name: str,
            input_data: dict[str, Any],
            context: Any,
        ) -> object:
            return await agent_server.handle_claude_tool_permission(
                "chat-claude",
                tool_name,
                input_data,
                context,
                owner_token=manager.owner_token,
            )

        async def project_message(
            _session_id: str,
            _run_id: str,
            message: object,
            **_kwargs: object,
        ) -> dict[str, object] | None:
            if isinstance(message, dict) and message.get("type") == "result":
                return {
                    "session_id": str(message.get("session_id") or ""),
                    "result_text": str(message.get("result") or ""),
                    "terminal_reason": str(
                        message.get("terminal_reason") or ""
                    ),
                    "is_error": False,
                    "aborted": (
                        message.get("terminal_reason") == "aborted_streaming"
                    ),
                    "error": "",
                }
            return None

        commit_authority_checks: list[str] = []

        async def inspect_authority_before_commit(
            session_id: str,
            event_specs: list[tuple[str, dict[str, object]]],
        ) -> list[dict[str, object]]:
            if any(
                event_type == "turn_queue_run_now"
                for event_type, _payload in event_specs
            ):
                candidate_records = [
                    capability
                    for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
                    if capability.get("source_run_id") != predecessor_run_id
                ]
                self.assertEqual(len(candidate_records), 1)
                candidate_path = Path(str(
                    candidate_records[0]["authority_path"]
                ))
                candidate_token = json.loads(
                    candidate_path.read_text(encoding="utf-8")
                )["provider_capability"]
                candidate_run_id = str(
                    candidate_records[0]["source_run_id"]
                )
                authorized = await agent_server.authorize_provider_jobs_operation(
                    self.provider_request(candidate_token),
                    session_id="chat-claude",
                    operation="read",
                )
                self.assertEqual(
                    authorized["source_run_id"],
                    candidate_run_id,
                )
                with self.assertRaises(HTTPException) as publish_denied:
                    await agent_server.authorize_provider_action(
                        self.provider_request(candidate_token),
                        action="publish",
                        session_id="chat-claude",
                    )
                self.assertEqual(publish_denied.exception.status_code, 403)
                commit_authority_checks.append(candidate_run_id)
            return []

        self.append_durable_event_batch.side_effect = (
            inspect_authority_before_commit
        )

        revoke_patcher = patch.object(
            agent_server,
            "revoke_cross_chat_capability",
            side_effect=recording_revoke,
        )
        revoke_patcher.start()
        self.addCleanup(revoke_patcher.stop)

        with patch.dict(sys.modules, fake_claude_sdk_modules()), patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(
                {"can_use_tool": permission_callback},
                "config",
                "/usr/bin/claude",
            ),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "update_claude_pending_session_metadata",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "project_claude_sdk_message",
            side_effect=project_message,
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "build_user_provider_prompt",
            return_value="Steered prompt",
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "record_runtime_success",
            Mock(),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                predecessor_run_id,
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            for _ in range(100):
                active = agent_server.ACTIVE.get("chat-claude") or {}
                if active.get("native_steer_queue") is not None:
                    break
                await asyncio.sleep(0)
            steer_future = asyncio.get_running_loop().create_future()
            await agent_server.ACTIVE["chat-claude"]["native_steer_queue"].put({
                "selected": {
                    "queued_id": "queued-next",
                    "prompt": "Steer",
                    "file_ids": [],
                    "provider_cross_chat_route_snapshot": [candidate_route],
                },
                "remaining": 0,
                "future": steer_future,
            })
            for _ in range(100):
                if first.interrupt_calls:
                    break
                await asyncio.sleep(0)
            await first.messages.put({
                "type": "result",
                "result": "interrupted",
                "session_id": "provider",
                "terminal_reason": "aborted_streaming",
            })
            await asyncio.wait_for(manager.permission_requested.wait(), 0.5)
            self.assertEqual(len(manager.jobs_authorization_results), 1)
            self.assertEqual(
                manager.jobs_authorization_results[0]["source_run_id"],
                str(manager.start_calls[1][2]),
            )
            for _ in range(100):
                if agent_server.CLAUDE_PENDING_INTERACTIONS:
                    break
                await asyncio.sleep(0)
            interaction_id, interaction = next(iter(
                agent_server.CLAUDE_PENDING_INTERACTIONS.items()
            ))
            candidate_run_id = str(interaction["turn_id"])
            self.assertNotEqual(candidate_run_id, predecessor_run_id)
            self.assertEqual(
                agent_server.ACTIVE["chat-claude"][
                    "claude_permission_run_id"
                ],
                candidate_run_id,
            )
            await agent_server.resolve_claude_interaction(
                "chat-claude",
                interaction_id,
                {"decision": "accept"},
            )
            steer_result = await asyncio.wait_for(steer_future, 0.5)
            candidate_records = [
                capability
                for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
                if capability.get("source_run_id") == candidate_run_id
            ]
            self.assertEqual(len(candidate_records), 1)
            self.assertEqual(
                list(candidate_records[0]["provider_route_grants"].values()),
                [],
            )
            self.assertEqual(
                agent_server.CURRENT_TURNS["chat-claude"][
                    "provider_cross_chat_route_snapshot"
                ],
                [],
            )
            candidate_path = Path(str(
                candidate_records[0]["authority_path"]
            ))
            candidate_token = json.loads(
                candidate_path.read_text(encoding="utf-8")
            )["provider_capability"]
            authorized = await agent_server.authorize_provider_jobs_operation(
                self.provider_request(candidate_token),
                session_id="chat-claude",
                operation="write",
            )
            self.assertEqual(authorized["source_run_id"], candidate_run_id)
            published = await agent_server.authorize_provider_action(
                self.provider_request(candidate_token),
                action="publish",
                session_id="chat-claude",
            )
            self.assertEqual(published["source_run_id"], candidate_run_id)
            with self.assertRaises(HTTPException) as stale:
                await agent_server.authorize_provider_action(
                    self.provider_request(predecessor_token),
                    action="jobs",
                    session_id="chat-claude",
                )
            self.assertEqual(stale.exception.status_code, 403)
            self.assertFalse(predecessor_path.exists())
            self.assertTrue(
                str(manager.start_calls[1][1]).startswith(
                    "Steered prompt\n\n[AgentsDock provider authority]"
                )
            )
            await second.messages.put(second_terminal)
            await asyncio.wait_for(runner, 0.5)

        self.assertEqual(steer_result["run_id"], candidate_run_id)
        self.assertEqual(len(manager.permission_results), 1)
        self.assertIsInstance(
            manager.permission_results[0],
            FakePermissionResultAllow,
        )
        self.assertEqual(
            predecessor_revoke_observations,
            [(True, candidate_run_id)],
        )
        self.assertEqual(commit_authority_checks, [candidate_run_id])

    async def test_consecutive_native_steers_rotate_to_only_latest_authority(
        self,
    ) -> None:
        first_handle = FakeClaudeRun()
        second_handle = FakeClaudeRun()
        third_handle = FakeClaudeRun()
        manager = SequencedClaudeManager([
            first_handle,
            second_handle,
            third_handle,
        ])
        original_run_id = "run_claude"
        agent_server.CURRENT_TURNS["chat-claude"]["run_id"] = original_run_id
        original_path = await agent_server.issue_cross_chat_capability(
            "chat-claude",
            original_run_id,
            [],
            actions={"jobs", "publish"},
        )
        original_token = json.loads(
            original_path.read_text(encoding="utf-8")
        )["provider_capability"]

        async def project_message(
            _session_id: str,
            _run_id: str,
            message: object,
            **_kwargs: object,
        ) -> dict[str, object] | None:
            if isinstance(message, dict) and message.get("type") == "result":
                return {
                    "session_id": str(message.get("session_id") or ""),
                    "result_text": str(message.get("result") or ""),
                    "terminal_reason": str(
                        message.get("terminal_reason") or ""
                    ),
                    "is_error": False,
                    "aborted": (
                        message.get("terminal_reason") == "aborted_streaming"
                    ),
                    "error": "",
                }
            return None

        stack = ExitStack()
        stack.enter_context(patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ))
        stack.enter_context(patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "append_turn_finished_event",
            AsyncMock(return_value={}),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "project_claude_sdk_message",
            side_effect=project_message,
        ))
        stack.enter_context(patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "build_user_provider_prompt",
            return_value="Steered prompt",
        ))
        stack.enter_context(patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ))

        async def steer_once(
            native_queue: asyncio.Queue[dict[str, object]],
            handle: FakeClaudeRun,
            queued_id: str,
        ) -> dict[str, object]:
            future = asyncio.get_running_loop().create_future()
            native_queue.put_nowait({
                "selected": {
                    "queued_id": queued_id,
                    "prompt": f"Prompt for {queued_id}",
                    "file_ids": [],
                    "backend": agent_server.BACKEND_CLAUDE,
                },
                "remaining": 0,
                "future": future,
            })
            for _ in range(100):
                if handle.interrupt_calls:
                    break
                await asyncio.sleep(0)
            self.assertEqual(handle.interrupt_calls, 1)
            await handle.messages.put({
                "type": "result",
                "result": "interrupted",
                "session_id": "provider",
                "terminal_reason": "aborted_streaming",
            })
            return await asyncio.wait_for(future, 0.5)

        with stack:
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                original_run_id,
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            for _ in range(100):
                active = agent_server.ACTIVE.get("chat-claude") or {}
                if active.get("native_steer_queue") is not None:
                    break
                await asyncio.sleep(0)
            native_queue = agent_server.ACTIVE["chat-claude"][
                "native_steer_queue"
            ]

            first = await steer_once(
                native_queue,
                first_handle,
                "queued-first",
            )
            first_record = next(
                capability
                for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
                if capability.get("source_run_id") == first["run_id"]
            )
            first_path = Path(str(first_record["authority_path"]))
            first_token = json.loads(
                first_path.read_text(encoding="utf-8")
            )["provider_capability"]

            second = await steer_once(
                native_queue,
                second_handle,
                "queued-second",
            )
            second_record = next(
                capability
                for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
                if capability.get("source_run_id") == second["run_id"]
            )
            second_path = Path(str(second_record["authority_path"]))
            second_token = json.loads(
                second_path.read_text(encoding="utf-8")
            )["provider_capability"]

            self.assertNotEqual(first["run_id"], second["run_id"])
            self.assertFalse(original_path.exists())
            self.assertFalse(first_path.exists())
            self.assertTrue(second_path.exists())
            self.assertEqual(
                {
                    str(capability.get("source_run_id") or "")
                    for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
                },
                {second["run_id"]},
            )
            self.assertEqual(
                list(agent_server.CROSS_CHAT_AUTHORITY_ROOT.glob("*.json")),
                [second_path],
            )
            for stale_token in (original_token, first_token):
                with self.assertRaises(HTTPException) as stale:
                    await agent_server.authorize_provider_action(
                        self.provider_request(stale_token),
                        action="jobs",
                        session_id="chat-claude",
                    )
                self.assertEqual(stale.exception.status_code, 403)
            latest = await agent_server.authorize_provider_action(
                self.provider_request(second_token),
                action="publish",
                session_id="chat-claude",
            )
            self.assertEqual(latest["source_run_id"], second["run_id"])

            await third_handle.messages.put({
                "type": "result",
                "result": "done",
                "session_id": "provider",
                "terminal_reason": "end_turn",
            })
            await asyncio.wait_for(runner, 0.5)

        self.assertTrue(second_path.exists())
        self.assertEqual(
            list(agent_server.CROSS_CHAT_AUTHORITY_ROOT.glob("*.json")),
            [second_path],
        )
        await agent_server.revoke_cross_chat_capability(second["run_id"])
        self.assertFalse(second_path.exists())

    async def test_typed_tool_results_finish_from_assistant_and_user_messages(self) -> None:
        from claude_agent_sdk.types import (
            AssistantMessage,
            ServerToolResultBlock,
            ServerToolUseBlock,
            ToolResultBlock,
            ToolUseBlock,
            UserMessage,
        )

        current_tools: dict[str, dict[str, object]] = {}
        append_event = AsyncMock(return_value={})
        mark_ready = AsyncMock()

        assistant_message = AssistantMessage(
            content=[
                ToolUseBlock(
                    id="assistant-local",
                    name="Read",
                    input={"file_path": "/tmp/local.txt"},
                ),
                ToolResultBlock(
                    tool_use_id="assistant-local",
                    content="local result",
                ),
                ServerToolUseBlock(
                    id="assistant-server",
                    name="web_search",
                    input={"query": "AgentsDock"},
                ),
                ServerToolResultBlock(
                    tool_use_id="assistant-server",
                    content={"type": "web_search_result", "results": []},
                ),
            ],
            model="claude-test",
            session_id="provider-assistant",
        )
        current_tools.update({
            "user-local": {
                "id": "user-local",
                "name": "Write",
                "input": {},
            },
            "user-server": {
                "id": "user-server",
                "name": "web_fetch",
                "input": {},
            },
        })
        user_message = UserMessage(content=[
            ToolResultBlock(
                tool_use_id="user-local",
                content="user local result",
                is_error=True,
            ),
            ServerToolResultBlock(
                tool_use_id="user-server",
                content={"type": "web_fetch_result", "status": 200},
            ),
        ])

        with patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            mark_ready,
        ):
            await agent_server.project_claude_sdk_message(
                "chat-claude",
                "run-claude",
                assistant_message,
                text_parts=[],
                current_tools=current_tools,
                changed_paths=set(),
            )
            await agent_server.project_claude_sdk_message(
                "chat-claude",
                "run-claude",
                user_message,
                text_parts=[],
                current_tools=current_tools,
                changed_paths=set(),
            )

        self.assertEqual(current_tools, {})
        mark_ready.assert_awaited_once_with(
            "chat-claude",
            "run-claude",
            "provider-assistant",
        )
        projected = [
            (call.args[1], call.args[2])
            for call in append_event.await_args_list
        ]
        self.assertEqual(
            [event_type for event_type, _payload in projected],
            [
                "tool_started",
                "tool_finished",
                "tool_started",
                "tool_finished",
                "tool_finished",
                "tool_finished",
            ],
        )
        finished = [
            payload
            for event_type, payload in projected
            if event_type == "tool_finished"
        ]
        self.assertEqual(
            [payload["tool_id"] for payload in finished],
            [
                "assistant-local",
                "assistant-server",
                "user-local",
                "user-server",
            ],
        )
        self.assertEqual(
            [payload["tool"]["name"] for payload in finished],
            ["Read", "web_search", "Write", "web_fetch"],
        )
        self.assertEqual(
            [payload["is_error"] for payload in finished],
            [False, False, True, False],
        )

    async def test_claude_thinking_summary_is_projected_to_reasoning(self) -> None:
        from claude_agent_sdk.types import AssistantMessage, ThinkingBlock

        append_event = AsyncMock(return_value={})

        with patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ):
            await agent_server.project_claude_sdk_message(
                "chat-claude",
                "run-claude",
                AssistantMessage(
                    content=[ThinkingBlock(
                        thinking="Checking the failed jobs before submission.",
                        signature="provider-summary",
                    )],
                    model="claude-test",
                    session_id="provider",
                ),
                text_parts=[],
                current_tools={},
                changed_paths=set(),
            )

        append_event.assert_awaited_once_with(
            "chat-claude",
            "reasoning_summary",
            {
                "run_id": "run-claude",
                "text": "Checking the failed jobs before submission.",
            },
        )

    async def test_typed_task_lifecycle_projects_only_snapshot_fields(self) -> None:
        from claude_agent_sdk.types import (
            TaskNotificationMessage,
            TaskProgressMessage,
            TaskStartedMessage,
            TaskUpdatedMessage,
            ToolResultBlock,
            UserMessage,
        )

        messages = [
            TaskStartedMessage(
                subtype="task_started",
                data={
                    "type": "system",
                    "subtype": "task_started",
                    "task_id": "task-1",
                    "tool_use_id": "agent-tool",
                    "task_type": "local_agent",
                    "description": "Review the server",
                    "prompt": "SECRET CHILD PROMPT",
                },
                task_id="task-1",
                description="Review the server",
                uuid="message-1",
                session_id="provider",
                tool_use_id="agent-tool",
                task_type="local_agent",
            ),
            TaskProgressMessage(
                subtype="task_progress",
                data={
                    "type": "system",
                    "subtype": "task_progress",
                    "task_id": "task-1",
                    "description": "Running tests",
                    "last_tool_name": "Bash",
                    "output": "SECRET CHILD OUTPUT",
                },
                task_id="task-1",
                description="Running tests",
                usage={"total_tokens": 10, "tool_uses": 1, "duration_ms": 25},
                uuid="message-2",
                session_id="provider",
                last_tool_name="Bash",
            ),
            TaskUpdatedMessage(
                subtype="task_updated",
                data={
                    "type": "system",
                    "subtype": "task_updated",
                    "task_id": "task-1",
                    "patch": {
                        "status": "completed",
                        "summary": "Review complete",
                        "result": "SECRET TASK RESULT",
                    },
                },
                task_id="task-1",
                patch={"status": "completed", "summary": "Review complete"},
                status="completed",
                session_id="provider",
            ),
            TaskNotificationMessage(
                subtype="task_notification",
                data={
                    "type": "system",
                    "subtype": "task_notification",
                    "task_id": "task-1",
                    "status": "completed",
                    "summary": "Review complete",
                    "output_file": "/private/secret-output.txt",
                },
                task_id="task-1",
                status="completed",
                output_file="/private/secret-output.txt",
                summary="Review complete",
                uuid="message-4",
                session_id="provider",
            ),
            UserMessage(
                content=[ToolResultBlock(
                    tool_use_id="agent-tool",
                    content="SECRET TOOL RESULT",
                )],
                tool_use_result={
                    "status": "async_launched",
                    "isAsync": True,
                    "agentId": "task-1",
                    "result": "SECRET ASYNC RESULT",
                },
            ),
        ]
        append_event = AsyncMock(return_value={})

        with patch.object(agent_server, "append_event", append_event), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ):
            for message in messages:
                await agent_server.project_claude_sdk_message(
                    "chat-claude",
                    "run-claude",
                    message,
                    text_parts=[],
                    current_tools={},
                    changed_paths=set(),
                )

        raw_payloads = [
            call.args[2]["raw"]
            for call in append_event.await_args_list
            if call.args[1] == "raw_event"
        ]
        self.assertEqual(len(raw_payloads), len(messages))
        serialized = "\n".join(raw_payloads)
        for secret in (
            "SECRET CHILD PROMPT",
            "SECRET CHILD OUTPUT",
            "SECRET TASK RESULT",
            "/private/secret-output.txt",
            "SECRET TOOL RESULT",
            "SECRET ASYNC RESULT",
        ):
            self.assertNotIn(secret, serialized)
        self.assertIn('"subtype":"task_started"', serialized)
        self.assertIn('"subtype":"task_progress"', serialized)
        self.assertIn('"status":"completed"', serialized)
        self.assertIn('"agentId":"task-1"', serialized)

    async def test_post_ack_first_activity_timeout_retires_visible_failure(self) -> None:
        handle = FakeClaudeRun(acknowledged=False)
        manager = FakeClaudeManager(handle)
        append_event = AsyncMock(return_value={})
        append_finished = AsyncMock(return_value={})
        release = AsyncMock(return_value=True)
        runtime_failure = Mock()
        schedule_next = Mock()

        with patch.object(
            agent_server,
            "CLAUDE_SDK_POST_ACK_FIRST_ACTIVITY_TIMEOUT_SECONDS",
            0.02,
        ), patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "project_claude_sdk_message",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            append_finished,
        ), patch.object(
            agent_server,
            "release_turn_slot",
            release,
        ), patch.object(
            agent_server,
            "record_runtime_success",
            Mock(),
        ), patch.object(
            agent_server,
            "record_runtime_failure",
            runtime_failure,
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=True,
        ), patch.object(
            agent_server,
            "schedule_next_queued_turn",
            schedule_next,
        ):
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            for _ in range(100):
                active = agent_server.ACTIVE.get("chat-claude") or {}
                if active.get("claude_sdk_run") is handle:
                    break
                await asyncio.sleep(0)

            # The timeout begins at the provider replay ACK, not when the
            # local query is merely written.
            await asyncio.sleep(0.05)
            self.assertFalse(runner.done())
            self.assertFalse(handle.acknowledged)

            handle.acknowledge()
            await asyncio.wait_for(runner, 0.5)

        self.assertGreaterEqual(handle.interrupt_calls, 1)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        release.assert_awaited_once_with(
            "chat-claude",
            expected_run_id="run-claude",
        )
        terminal = append_finished.await_args.args[1]
        self.assertEqual(terminal["exit_code"], 1)
        self.assertFalse(terminal["stopped"])
        self.assertTrue(any(
            call.args[1] == "error"
            and "produced no provider activity" in call.args[2]["message"]
            for call in append_event.await_args_list
        ))
        runtime_failure.assert_called_once()
        schedule_next.assert_called_once_with("chat-claude")

    async def test_pre_ack_timeout_retires_visible_failure(self) -> None:
        handle = FakeClaudeRun(acknowledged=False)
        manager, append_event, append_finished, runtime_failure = (
            await self._run_sdk_timeout_case(
                handle,
                pre_ack_timeout=0.02,
                post_ack_timeout=1.0,
                turn_timeout=1.0,
                idle_warn=0.5,
                idle_timeout=1.0,
            )
        )

        self.assertGreaterEqual(handle.interrupt_calls, 1)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        self.assertEqual(append_finished.await_args.args[1]["exit_code"], 1)
        self.assertTrue(any(
            call.args[1] == "error"
            and "did not confirm prompt delivery" in call.args[2]["message"]
            and call.args[2].get("delivery_unknown") is True
            for call in append_event.await_args_list
        ))
        self.assertTrue(
            append_finished.await_args.args[1].get("delivery_unknown")
        )
        runtime_failure.assert_called_once()

    async def test_pre_ack_timeout_wins_when_idle_limit_is_shorter(self) -> None:
        handle = FakeClaudeRun(acknowledged=False)
        _manager, append_event, append_finished, runtime_failure = (
            await self._run_sdk_timeout_case(
                handle,
                pre_ack_timeout=0.04,
                post_ack_timeout=1.0,
                turn_timeout=1.0,
                idle_warn=0.005,
                idle_timeout=0.01,
            )
        )

        self.assertTrue(any(
            call.args[1] == "error"
            and "did not confirm prompt delivery" in call.args[2]["message"]
            and call.args[2].get("delivery_unknown") is True
            for call in append_event.await_args_list
        ))
        self.assertFalse(any(
            call.args[1] == "idle_warning"
            for call in append_event.await_args_list
        ))
        self.assertTrue(
            append_finished.await_args.args[1].get("delivery_unknown")
        )
        runtime_failure.assert_called_once()

    async def test_idle_timeout_after_activity_retires_visible_failure(self) -> None:
        handle = FakeClaudeRun([{"type": "AssistantMessage"}])
        manager, append_event, append_finished, runtime_failure = (
            await self._run_sdk_timeout_case(
                handle,
                pre_ack_timeout=1.0,
                post_ack_timeout=1.0,
                turn_timeout=1.0,
                idle_warn=0.01,
                idle_timeout=0.03,
            )
        )

        self.assertGreaterEqual(handle.interrupt_calls, 1)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        self.assertEqual(append_finished.await_args.args[1]["exit_code"], 1)
        idle_warnings = [
            call for call in append_event.await_args_list
            if call.args[1] == "idle_warning"
        ]
        self.assertEqual(len(idle_warnings), 1)
        self.assertTrue(any(
            call.args[1] == "error"
            and "no provider activity" in call.args[2]["message"]
            for call in append_event.await_args_list
        ))
        runtime_failure.assert_called_once()

    async def test_absolute_timeout_bounds_an_active_sdk_turn(self) -> None:
        handle = FakeClaudeRun()
        manager, append_event, append_finished, runtime_failure = (
            await self._run_sdk_timeout_case(
                handle,
                pre_ack_timeout=1.0,
                post_ack_timeout=1.0,
                turn_timeout=0.02,
                idle_warn=0.5,
                idle_timeout=1.0,
            )
        )

        self.assertGreaterEqual(handle.interrupt_calls, 1)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        self.assertEqual(append_finished.await_args.args[1]["exit_code"], 1)
        self.assertTrue(any(
            call.args[1] == "error"
            and "absolute turn timeout" in call.args[2]["message"]
            for call in append_event.await_args_list
        ))
        runtime_failure.assert_called_once()

    async def test_absolute_timeout_cannot_be_starved_by_ready_frames(self) -> None:
        handle = NoisyClaudeRun()
        manager, append_event, append_finished, runtime_failure = (
            await self._run_sdk_timeout_case(
                handle,
                pre_ack_timeout=1.0,
                post_ack_timeout=1.0,
                turn_timeout=0.02,
                idle_warn=0.5,
                idle_timeout=1.0,
            )
        )

        self.assertGreaterEqual(handle.interrupt_calls, 1)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        self.assertEqual(append_finished.await_args.args[1]["exit_code"], 1)
        self.assertTrue(any(
            call.args[1] == "error"
            and "absolute turn timeout" in call.args[2]["message"]
            for call in append_event.await_args_list
        ))
        runtime_failure.assert_called_once()

    async def test_delivery_uncertain_stream_retires_without_empty_success(self) -> None:
        handle = FailingClaudeRun(ClaudeSDKQueryError("replay ACK missing"))
        manager = FakeClaudeManager(handle)
        append_event = AsyncMock(return_value={})
        append_finished = AsyncMock(return_value={})
        project = AsyncMock()

        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "project_claude_sdk_message",
            project,
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            append_finished,
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "record_runtime_failure",
            Mock(),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            await agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            )

        self.assertEqual(len(manager.start_calls), 1)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        project.assert_not_awaited()
        terminal = append_finished.await_args.args[1]
        self.assertEqual(terminal["exit_code"], 1)
        self.assertEqual(terminal["result_text"], "")
        self.assertTrue(any(
            call.args[1] == "error"
            and "replay ACK missing" in call.args[2]["message"]
            for call in append_event.await_args_list
        ))

    async def test_reused_client_generic_start_failure_evicts_stale_client(
        self,
    ) -> None:
        manager = FakeClaudeManagerFailingAfterOwnership(
            RuntimeError("client not authenticated")
        )
        append_event = AsyncMock(return_value={})
        append_finished = AsyncMock(return_value={})
        project = AsyncMock()

        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "project_claude_sdk_message",
            project,
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            append_finished,
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "record_runtime_failure",
            Mock(),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ), patch.object(
            agent_server,
            "schedule_next_queued_turn",
            Mock(),
        ):
            await agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            )

        self.assertEqual(len(manager.start_calls), 1)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        project.assert_not_awaited()
        terminal = append_finished.await_args.args[1]
        self.assertIsNone(terminal["exit_code"])
        self.assertEqual(terminal["result_text"], "")
        self.assertTrue(any(
            call.args[1] == "error"
            and "client not authenticated" in call.args[2]["message"]
            for call in append_event.await_args_list
        ))

    async def test_projection_failure_retires_provider_before_releasing_slot(self) -> None:
        handle = FakeClaudeRun([{"type": "assistant"}])
        manager = FakeClaudeManager(handle)
        release = AsyncMock(return_value=True)

        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "project_claude_sdk_message",
            AsyncMock(side_effect=RuntimeError("timeline write failed")),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            release,
        ), patch.object(
            agent_server,
            "record_runtime_failure",
            Mock(),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            await agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            )

        self.assertGreaterEqual(handle.interrupt_calls, 1)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        release.assert_awaited_once_with(
            "chat-claude",
            expected_run_id="run-claude",
        )

    async def test_natural_completion_wins_race_with_steering_interrupt(self) -> None:
        first = FakeClaudeRun()
        second = FakeClaudeRun(acknowledged=False)
        manager = SequencedClaudeManager([first, second])
        append_event = AsyncMock(return_value={})
        append_finished = AsyncMock(return_value={})

        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            append_finished,
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "build_user_provider_prompt",
            return_value="Steered prompt",
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "record_runtime_success",
            Mock(),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            for _ in range(100):
                active = agent_server.ACTIVE.get("chat-claude") or {}
                if active.get("native_steer_queue") is not None:
                    break
                await asyncio.sleep(0)
            native_queue = agent_server.ACTIVE["chat-claude"][
                "native_steer_queue"
            ]
            steer_future = asyncio.get_running_loop().create_future()
            await native_queue.put({
                "selected": {
                    "queued_id": "queued-next",
                    "prompt": "Steer",
                    "file_ids": [],
                },
                "remaining": 0,
                "future": steer_future,
            })
            for _ in range(100):
                if first.interrupt_calls:
                    break
                await asyncio.sleep(0)
            self.assertEqual(first.interrupt_calls, 1)
            await first.messages.put({
                "type": "result",
                "result": "Natural result",
                "session_id": "provider-1",
                "terminal_reason": "end_turn",
            })
            steer_result = await asyncio.wait_for(steer_future, 0.5)
            self.assertIs(
                agent_server.ACTIVE["chat-claude"]["claude_sdk_run"],
                second,
            )
            self.assertFalse(
                agent_server.ACTIVE["chat-claude"]["provider_turn_ready"]
            )
            self.assertTrue(
                agent_server.ACTIVE["chat-claude"]["provider_starting"]
            )
            second.acknowledge()
            for _ in range(100):
                if agent_server.ACTIVE["chat-claude"].get(
                    "provider_turn_ready"
                ):
                    break
                await asyncio.sleep(0)
            self.assertTrue(
                agent_server.ACTIVE["chat-claude"]["provider_turn_ready"]
            )
            await second.messages.put({
                "type": "result",
                "result": "Steered result",
                "session_id": "provider-2",
                "terminal_reason": "end_turn",
            })
            await asyncio.wait_for(runner, 0.5)

        self.assertFalse(steer_result["interrupted"])
        prior_finished = [
            call.args[1]
            for call in append_finished.await_args_list
            if call.args[1].get("run_id") == "run-claude"
        ]
        self.assertEqual(len(prior_finished), 1)
        self.assertEqual(prior_finished[0]["result_text"], "Natural result")
        prior_stopped = [
            call.args[2]
            for call in append_event.await_args_list
            if call.args[1] == "turn_stopped"
            and call.args[2].get("run_id") == "run-claude"
        ]
        self.assertEqual(prior_stopped, [])

    async def test_empty_natural_completion_during_steer_is_failed(self) -> None:
        first = FakeClaudeRun()
        second = FakeClaudeRun()
        manager = SequencedClaudeManager([first, second])
        append_event = AsyncMock(return_value={})
        append_finished = AsyncMock(return_value={})
        runtime_failure = Mock()

        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            append_finished,
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "build_user_provider_prompt",
            return_value="Steered prompt",
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "sample_claude_context_usage",
            AsyncMock(return_value=False),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "record_runtime_success",
            Mock(),
        ), patch.object(
            agent_server,
            "record_runtime_failure",
            runtime_failure,
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            for _ in range(100):
                active = agent_server.ACTIVE.get("chat-claude") or {}
                if active.get("native_steer_queue") is not None:
                    break
                await asyncio.sleep(0)
            steer_future = asyncio.get_running_loop().create_future()
            await agent_server.ACTIVE["chat-claude"][
                "native_steer_queue"
            ].put({
                "selected": {
                    "queued_id": "queued-next",
                    "prompt": "Steer",
                    "file_ids": [],
                },
                "remaining": 0,
                "future": steer_future,
            })
            for _ in range(100):
                if first.interrupt_calls:
                    break
                await asyncio.sleep(0)
            await first.messages.put({
                "type": "result",
                "result": "",
                "session_id": "provider-1",
                "terminal_reason": "end_turn",
            })
            steer_result = await asyncio.wait_for(steer_future, 0.5)
            await second.messages.put({
                "type": "result",
                "result": "Steered result",
                "session_id": "provider-2",
                "terminal_reason": "end_turn",
            })
            await asyncio.wait_for(runner, 0.5)

        self.assertFalse(steer_result["interrupted"])
        prior_finished = [
            call.args[1]
            for call in append_finished.await_args_list
            if call.args[1].get("run_id") == "run-claude"
        ]
        self.assertEqual(len(prior_finished), 1)
        self.assertEqual(prior_finished[0]["exit_code"], 1)
        self.assertEqual(prior_finished[0]["result_text"], "")
        self.assertTrue(any(
            call.args[1] == "error"
            and call.args[2].get("run_id") == "run-claude"
            and call.args[2].get("message")
            == agent_server.CLAUDE_EMPTY_TURN_ERROR
            for call in append_event.await_args_list
        ))
        runtime_failure.assert_any_call(
            agent_server.BACKEND_CLAUDE,
            agent_server.CLAUDE_EMPTY_TURN_ERROR,
        )

    async def test_system_init_provider_id_survives_stop_before_result(self) -> None:
        handle = FakeClaudeRun([
            {
                "type": "SystemMessage",
                "data": {"session_id": "provider-from-init"},
            }
        ])
        manager = FakeClaudeManager(handle)
        provider_seen = asyncio.Event()
        persist = AsyncMock()

        async def mark_ready(*_args: object, **_kwargs: object) -> None:
            provider_seen.set()

        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            side_effect=mark_ready,
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            persist,
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            await asyncio.wait_for(provider_seen.wait(), 0.5)
            runner.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await runner

        matching = [
            call
            for call in persist.await_args_list
            if call.args[:3] == (
                "chat-claude",
                "run-claude",
                agent_server.BACKEND_CLAUDE,
            )
        ]
        # Bind immediately at System init so a crash is resumable, then write
        # the same provider ID idempotently during final cleanup.
        self.assertEqual(len(matching), 2)
        self.assertTrue(
            all(call.args[3] == "provider-from-init" for call in matching)
        )
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])

    async def test_accepted_steer_cancellation_resolves_waiter_as_uncertain(self) -> None:
        first = FakeClaudeRun()
        second = FakeClaudeRun()
        manager = SequencedClaudeManager([first, second])
        handoff_bookkeeping = asyncio.Event()

        async def append_durable_event_batch(
            _session_id: str,
            event_specs: list[tuple[str, dict[str, object]]],
        ) -> list[dict[str, object]]:
            await self.append_durable_event_batch(_session_id, event_specs)
            if any(
                event_type == "turn_queue_run_now"
                for event_type, _payload in event_specs
            ):
                handoff_bookkeeping.set()
                await asyncio.Event().wait()
            return []

        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_durable_event_batch",
            side_effect=append_durable_event_batch,
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "build_user_provider_prompt",
            return_value="Steered prompt",
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            for _ in range(100):
                active = agent_server.ACTIVE.get("chat-claude") or {}
                if active.get("native_steer_queue") is not None:
                    break
                await asyncio.sleep(0)
            steer_future = asyncio.get_running_loop().create_future()
            await agent_server.ACTIVE["chat-claude"]["native_steer_queue"].put({
                "selected": {
                    "queued_id": "queued-next",
                    "prompt": "Steer",
                    "file_ids": [],
                },
                "remaining": 0,
                "future": steer_future,
            })
            for _ in range(100):
                if first.interrupt_calls:
                    break
                await asyncio.sleep(0)
            await first.messages.put({
                "type": "result",
                "result": "Interrupted result",
                "session_id": "provider-1",
                "terminal_reason": "aborted_streaming",
            })
            await asyncio.wait_for(handoff_bookkeeping.wait(), 0.5)
            runner.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await runner
            with self.assertRaises(agent_server.NativeSteerHandoffError) as raised:
                await asyncio.wait_for(steer_future, 0.5)

        self.assertTrue(raised.exception.delivery_uncertain)
        self.assertFalse(raised.exception.safe_to_requeue)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        fences = [
            payload
            for call in self.append_durable_event_batch.await_args_list
            for event_type, payload in call.args[1]
            if event_type == "turn_queue_delivery_fenced"
        ]
        self.assertEqual(len(fences), 1)
        self.assertEqual(fences[0]["queued_id"], "queued-next")

    async def test_safe_candidate_rejection_restores_only_predecessor_authority(
        self,
    ) -> None:
        first = FakeClaudeRun()
        manager = SafeFailingCandidateStartManager([first])
        predecessor_run_id = "run_claude"
        agent_server.CURRENT_TURNS["chat-claude"]["run_id"] = predecessor_run_id
        predecessor_path = await agent_server.issue_cross_chat_capability(
            "chat-claude",
            predecessor_run_id,
            [],
            actions={"jobs", "publish"},
        )
        predecessor_token = json.loads(
            predecessor_path.read_text(encoding="utf-8")
        )["provider_capability"]
        agent_server.QUEUED_TURNS["chat-claude"] = deque([{
            "queued_id": "queued-safe-rejection",
            "prompt": "Steer",
            "file_ids": [],
            "backend": agent_server.BACKEND_CLAUDE,
            "client_capabilities": [
                agent_server.CLAUDE_SDK_INTERACTIVE_CLIENT_CAPABILITY
            ],
            "_durable": True,
        }])
        cleanup_entered = asyncio.Event()
        release_cleanup = asyncio.Event()

        async def gated_cancel_interactions(*_args: object, **_kwargs: object) -> None:
            if _kwargs.get("resolution") == "turn_steered":
                return
            cleanup_entered.set()
            await release_cleanup.wait()

        stack = ExitStack()
        stack.enter_context(patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(side_effect=[{"head": "old"}, {"head": "candidate"}]),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ))
        stack.enter_context(patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "append_turn_finished_event",
            AsyncMock(return_value={}),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "project_claude_sdk_message",
            AsyncMock(return_value={
                "session_id": "provider",
                "result_text": "interrupted",
                "terminal_reason": "aborted_streaming",
                "is_error": False,
                "aborted": True,
                "error": "",
            }),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "build_user_provider_prompt",
            return_value="Steered prompt",
        ))
        stack.enter_context(patch.object(
            agent_server,
            "queued_claude_runtime_matches_active",
            return_value=True,
        ))
        stack.enter_context(patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "cancel_claude_interactions",
            side_effect=gated_cancel_interactions,
        ))
        stack.enter_context(patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ))

        with stack:
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                predecessor_run_id,
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            try:
                for _ in range(100):
                    active = agent_server.ACTIVE.get("chat-claude") or {}
                    if active.get("native_steer_queue") is not None:
                        break
                    await asyncio.sleep(0)
                force_send = asyncio.create_task(
                    agent_server.run_queued_turn_now(
                        "chat-claude",
                        "queued-safe-rejection",
                    )
                )
                for _ in range(100):
                    if first.interrupt_calls:
                        break
                    await asyncio.sleep(0)
                await first.messages.put({
                    "type": "result",
                    "result": "interrupted",
                    "session_id": "provider",
                    "terminal_reason": "aborted_streaming",
                })
                result = await asyncio.wait_for(force_send, 0.5)
                await asyncio.wait_for(cleanup_entered.wait(), 0.5)

                self.assertFalse(result["ok"])
                self.assertTrue(result["deferred"])
                self.assertTrue(result["retryable"])
                self.assertFalse(result["delivery_uncertain"])
                self.assertIsNotNone(manager.candidate_authority_path)
                self.assertFalse(manager.candidate_authority_path.exists())
                self.assertTrue(predecessor_path.exists())
                self.assertEqual(
                    {
                        str(capability.get("source_run_id") or "")
                        for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
                    },
                    {predecessor_run_id},
                )
                authorized = await agent_server.authorize_provider_jobs_operation(
                    self.provider_request(predecessor_token),
                    session_id="chat-claude",
                    operation="read",
                )
                self.assertEqual(
                    authorized["source_run_id"],
                    predecessor_run_id,
                )
                restored = agent_server.QUEUED_TURNS["chat-claude"][0]
                self.assertFalse(restored["_paused_after_stop"])
                self.assertNotIn("_native_delivery_fenced", restored)
                public = await agent_server.queued_turns_snapshot("chat-claude")
                self.assertFalse(public[0]["paused"])
                queue_lifecycle = [
                    event_type
                    for call in self.append_durable_event_batch.await_args_list
                    for event_type, _payload in call.args[1]
                    if event_type in {
                        "turn_queue_delivery_fenced",
                        "turn_queued",
                        "turn_queue_reordered",
                    }
                ]
                self.assertEqual(
                    queue_lifecycle,
                    [
                        "turn_queue_delivery_fenced",
                        "turn_queued",
                        "turn_queue_reordered",
                    ],
                )
            finally:
                release_cleanup.set()
                await asyncio.wait_for(runner, 0.5)

        self.assertTrue(predecessor_path.exists())
        self.assertEqual(
            {
                str(capability.get("source_run_id") or "")
                for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
            },
            {predecessor_run_id},
        )
        await agent_server.revoke_cross_chat_capability(predecessor_run_id)
        self.assertFalse(predecessor_path.exists())

    async def test_cancellation_during_candidate_query_is_never_replayed(self) -> None:
        first = FakeClaudeRun()
        manager = BlockingCandidateStartManager([first])
        collect_manifest = AsyncMock()
        predecessor_run_id = "run_claude"
        agent_server.CURRENT_TURNS["chat-claude"]["run_id"] = predecessor_run_id
        predecessor_path = await agent_server.issue_cross_chat_capability(
            "chat-claude",
            predecessor_run_id,
            [],
            actions={"jobs", "publish"},
        )
        real_revoke = agent_server.revoke_cross_chat_capability
        revoke_observations: list[tuple[str, bool]] = []

        async def record_ordered_revoke(run_id: str) -> None:
            active = agent_server.ACTIVE.get("chat-claude") or {}
            transition_ready = active.get("logical_transition_ready")
            revoke_observations.append((
                run_id,
                bool(
                    isinstance(transition_ready, asyncio.Event)
                    and transition_ready.is_set()
                ),
            ))
            await real_revoke(run_id)

        revoke_patcher = patch.object(
            agent_server,
            "revoke_cross_chat_capability",
            side_effect=record_ordered_revoke,
        )
        revoke_patcher.start()
        self.addCleanup(revoke_patcher.stop)

        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(side_effect=[{"head": "old"}, {"head": "candidate"}]),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "build_user_provider_prompt",
            return_value="Steered prompt",
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            collect_manifest,
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                predecessor_run_id,
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            for _ in range(100):
                active = agent_server.ACTIVE.get("chat-claude") or {}
                if active.get("native_steer_queue") is not None:
                    break
                await asyncio.sleep(0)
            steer_future = asyncio.get_running_loop().create_future()
            await agent_server.ACTIVE["chat-claude"]["native_steer_queue"].put({
                "selected": {
                    "queued_id": "queued-next",
                    "prompt": "Steer",
                    "file_ids": [],
                },
                "remaining": 0,
                "future": steer_future,
            })
            for _ in range(100):
                if first.interrupt_calls:
                    break
                await asyncio.sleep(0)
            await first.messages.put({
                "type": "result",
                "result": "interrupted",
                "session_id": "provider",
                "terminal_reason": "aborted_streaming",
            })
            await asyncio.wait_for(
                manager.candidate_query_started.wait(),
                0.5,
            )
            candidate_run_id = str(manager.start_calls[1][2])
            candidate_records = [
                capability
                for capability in agent_server.CROSS_CHAT_CAPABILITIES.values()
                if capability.get("source_run_id") == candidate_run_id
            ]
            self.assertEqual(len(candidate_records), 1)
            candidate_path = Path(str(
                candidate_records[0]["authority_path"]
            ))
            self.assertTrue(candidate_path.exists())
            runner.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await runner
            with self.assertRaises(
                agent_server.NativeSteerHandoffError,
            ) as raised:
                await asyncio.wait_for(steer_future, 0.5)

        self.assertTrue(raised.exception.delivery_uncertain)
        self.assertFalse(raised.exception.safe_to_requeue)
        self.assertFalse(predecessor_path.exists())
        self.assertFalse(candidate_path.exists())
        self.assertFalse(agent_server.CROSS_CHAT_CAPABILITIES)
        self.assertIn((candidate_run_id, False), revoke_observations)
        self.assertIn((predecessor_run_id, False), revoke_observations)
        self.assertEqual(manager.evict_calls, [("chat-claude", True)])
        self.assertTrue(any(
            call.args[:2] == ("chat-claude", candidate_run_id)
            for call in collect_manifest.await_args_list
        ))

    async def _assert_terminal_race_resolves_steer(
        self,
        *,
        let_steer_waiter_consume: bool,
    ) -> None:
        handle = FakeClaudeRun([{
            "type": "result",
            "result": "done",
            "session_id": "provider",
            "terminal_reason": "end_turn",
        }])
        manager = FakeClaudeManager(handle)
        steer_future: asyncio.Future[dict[str, object]] | None = None

        async def project_terminal(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal steer_future
            loop = asyncio.get_running_loop()
            steer_future = loop.create_future()
            active = agent_server.ACTIVE["chat-claude"]
            active["native_steer_queue"].put_nowait({
                "selected": {
                    "queued_id": "queued-race",
                    "prompt": "Steer after terminal",
                    "file_ids": [],
                },
                "remaining": 0,
                "future": steer_future,
            })
            if let_steer_waiter_consume:
                # Exercise the interleaving where queue.get() completes just
                # after asyncio.wait() selected the terminal provider message.
                await asyncio.sleep(0)
            return {
                "session_id": "provider",
                "result_text": "done",
                "terminal_reason": "end_turn",
                "is_error": False,
                "aborted": False,
                "error": "",
            }

        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "project_claude_sdk_message",
            project_terminal,
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "record_runtime_success",
            Mock(),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            await agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            )

        self.assertIsNotNone(steer_future)
        assert steer_future is not None
        with self.assertRaises(agent_server.NativeSteerHandoffError) as raised:
            await steer_future
        self.assertTrue(raised.exception.safe_to_requeue)
        self.assertFalse(raised.exception.delivery_uncertain)
        self.assertEqual(len(manager.start_calls), 1)

    async def test_terminal_race_resolves_steer_waiting_in_queue(self) -> None:
        await self._assert_terminal_race_resolves_steer(
            let_steer_waiter_consume=False,
        )

    async def test_terminal_race_resolves_steer_consumed_by_waiter(self) -> None:
        await self._assert_terminal_race_resolves_steer(
            let_steer_waiter_consume=True,
        )

    def test_native_steer_rejects_changed_working_directory(self) -> None:
        self.session["cwd"] = str(Path(self.cwd) / "other")
        active = {
            "provider_model": self.session["model"],
            "provider_effort": self.session["effort"],
            "cwd": self.cwd,
            "provider_configuration_key": "old-config",
        }

        self.assertFalse(
            agent_server.queued_claude_runtime_matches_active(
                "chat-claude",
                {},
                active,
            )
        )

    def test_pidless_sdk_turn_is_reported_as_active(self) -> None:
        snapshot = agent_server.active_process_snapshot(
            "chat-claude",
            {
                "proc": None,
                "pid": None,
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "cwd": self.cwd,
                "argv": ["claude", "<ClaudeSDKClient>"],
                "started_at": 1.0,
                "started_at_iso": "2026-08-05T00:00:00Z",
                "stop_requested": False,
                "stdout_lines": [],
            },
        )

        self.assertTrue(snapshot["active"])
        self.assertEqual(
            snapshot["transport"],
            agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
        )

    async def test_force_send_cannot_deliver_into_a_detached_terminal_queue(self) -> None:
        native_queue: asyncio.Queue[dict[str, object]] = asyncio.Queue(maxsize=1)
        selected = {
            "queued_id": "queued-race",
            "prompt": "Continue after completion",
            "file_ids": [],
            "backend": agent_server.BACKEND_CLAUDE,
            "client_capabilities": [
                agent_server.CLAUDE_SDK_INTERACTIVE_CLIENT_CAPABILITY
            ],
            "_durable": True,
            "_paused_after_stop": True,
        }
        agent_server.QUEUED_TURNS = {
            "chat-claude": deque([selected]),
        }
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "provider_turn_ready": True,
                "native_steer_queue": native_queue,
            }
        }

        def finish_during_selection(*_args: object) -> bool:
            # Reproduce the provider terminalizing after Force Send snapshots
            # ACTIVE but before it delivers into the native queue.
            agent_server.ACTIVE["chat-claude"]["provider_turn_ready"] = False
            agent_server.ACTIVE["chat-claude"]["native_steer_queue"] = None
            return True

        with patch.object(
            agent_server,
            "queued_claude_runtime_matches_active",
            side_effect=finish_during_selection,
        ):
            with self.assertRaises(agent_server.NativeSteerHandoffError) as raised:
                await asyncio.wait_for(
                    agent_server._run_queued_turn_now_once(
                        "chat-claude",
                        "queued-race",
                    ),
                    0.5,
                )

        self.assertTrue(raised.exception.safe_to_requeue)
        self.assertEqual(
            [
                item.get("queued_id")
                for item in agent_server.QUEUED_TURNS["chat-claude"]
            ],
            ["queued-race"],
        )
        self.assertFalse(selected["_paused_after_stop"])
        self.assertNotIn("_native_delivery_fenced", selected)
        lifecycle = self.append_durable_event_batch.await_args.args[1]
        self.assertEqual(
            [event_type for event_type, _payload in lifecycle],
            ["turn_queued", "turn_queue_reordered"],
        )
        public = await agent_server.queued_turns_snapshot("chat-claude")
        self.assertFalse(public[0]["paused"])
        self.assertTrue(native_queue.empty())

        agent_server.ACTIVE = {}
        agent_server.BUSY_SESSIONS.discard("chat-claude")
        start = AsyncMock(return_value={"run_id": "run-retry"})
        with patch.object(agent_server, "_start_turn_locked", start):
            await agent_server._start_next_queued_turn_locked(
                "chat-claude",
                admission_backend=agent_server.BACKEND_CLAUDE,
            )
        start.assert_awaited_once()
        self.assertEqual(start.await_args.args[1].prompt, selected["prompt"])

    async def test_force_send_defers_until_exact_claude_replay_ack(self) -> None:
        handle = FakeClaudeRun(acknowledged=False)
        manager = FakeClaudeManager(handle)
        append_event = AsyncMock(return_value={})

        with patch.object(
            agent_server,
            "resolve_claude_resume_provider",
            return_value=(None, None),
        ), patch.object(
            agent_server,
            "capture_git_baseline",
            AsyncMock(return_value={"head": "base"}),
        ), patch.object(
            agent_server,
            "build_claude_sdk_options",
            return_value=(object(), "config", "/usr/bin/claude"),
        ), patch.object(
            agent_server,
            "claude_sdk_manager",
            AsyncMock(return_value=manager),
        ), patch.object(
            agent_server,
            "watch_manifest_artifacts",
            wait_forever,
        ), patch.object(
            agent_server,
            "append_event",
            append_event,
        ), patch.object(
            agent_server,
            "append_turn_finished_event",
            AsyncMock(return_value={}),
        ), patch.object(
            agent_server,
            "mark_provider_turn_ready",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "persist_run_provider_session",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "sample_claude_context_usage",
            AsyncMock(return_value=False),
        ), patch.object(
            agent_server,
            "cancel_claude_interactions",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_manifest",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "collect_recent_leftover_manifests",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "publish_turn_code_diff",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "release_turn_slot",
            AsyncMock(return_value=True),
        ), patch.object(
            agent_server,
            "record_runtime_success",
            Mock(),
        ), patch.object(
            agent_server,
            "record_runtime_failure",
            Mock(),
        ), patch.object(
            agent_server,
            "should_schedule_queue_after_finish",
            return_value=False,
        ):
            runner = asyncio.create_task(agent_server.run_claude_sdk(
                "chat-claude",
                "run-claude",
                "Prompt",
                dict(self.session),
                Path(self.cwd) / ".manifest.json",
            ))
            for _ in range(100):
                active = agent_server.ACTIVE.get("chat-claude") or {}
                if active.get("claude_sdk_run") is handle:
                    break
                await asyncio.sleep(0)

            active = agent_server.ACTIVE["chat-claude"]
            self.assertIs(active["claude_sdk_run"], handle)
            self.assertFalse(active["provider_turn_ready"])
            self.assertTrue(active["provider_starting"])

            selected = {
                "queued_id": "queued-pre-ack",
                "prompt": "Steer only after delivery is certain",
                "file_ids": [],
                "backend": agent_server.BACKEND_CLAUDE,
                "client_capabilities": [
                    agent_server.CLAUDE_SDK_INTERACTIVE_CLIENT_CAPABILITY
                ],
            }
            agent_server.QUEUED_TURNS = {
                "chat-claude": deque([selected]),
            }
            deferred = await agent_server._run_queued_turn_now_once(
                "chat-claude",
                "queued-pre-ack",
            )

            self.assertTrue(deferred["deferred"])
            self.assertFalse(deferred["interrupted"])
            self.assertEqual(handle.interrupt_calls, 0)
            self.assertEqual(
                [
                    item.get("queued_id")
                    for item in agent_server.QUEUED_TURNS["chat-claude"]
                ],
                ["queued-pre-ack"],
            )
            self.assertTrue(
                agent_server.ACTIVE["chat-claude"][
                    "native_steer_queue"
                ].empty()
            )

            handle.acknowledge()
            for _ in range(100):
                if agent_server.ACTIVE["chat-claude"].get(
                    "provider_turn_ready"
                ):
                    break
                await asyncio.sleep(0)
            self.assertTrue(
                agent_server.ACTIVE["chat-claude"]["provider_turn_ready"]
            )
            self.assertFalse(
                agent_server.ACTIVE["chat-claude"]["provider_starting"]
            )

            await handle.messages.put({
                "type": "result",
                "result": "done",
                "session_id": "provider",
                "terminal_reason": "end_turn",
            })
            await asyncio.wait_for(runner, 0.5)

        self.assertTrue(any(
            call.args[1] == "turn_deferred"
            for call in append_event.await_args_list
        ))

    async def test_deletion_cleanup_waits_for_one_approval_not_sdk_receiver(self) -> None:
        manager = FakeClaudeManager()
        manager.active_run_id = "run-claude"
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "interactive_agent_sdk": True,
                "stop_requested": False,
                "claude_sdk_owner_token": manager.owner_token,
                "claude_permission_run_id": "run-claude",
                "claude_permissions_open": True,
            }
        }
        with patch.dict(sys.modules, fake_claude_sdk_modules()), patch.object(
            agent_server,
            "update_claude_pending_session_metadata",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ):
            callback = asyncio.create_task(
                agent_server.handle_claude_tool_permission(
                    "chat-claude",
                    "Bash",
                    {"command": "pwd"},
                    {"tool_use_id": "tool-1"},
                    owner_token=manager.owner_token,
                )
            )
            for _ in range(100):
                if agent_server.CLAUDE_PENDING_INTERACTIONS:
                    break
                await asyncio.sleep(0)
            self.assertTrue(agent_server.CLAUDE_PENDING_INTERACTIONS)

            agent_server.DELETING_SESSIONS.add("chat-claude")
            await agent_server.cancel_claude_interactions(
                "chat-claude",
                resolution="session_deleted",
            )
            self.assertTrue(
                await agent_server.wait_for_session_tasks(
                    agent_server.CLAUDE_INTERACTION_HANDLER_TASKS,
                    "chat-claude",
                    timeout=0.5,
                )
            )
            result = await asyncio.wait_for(callback, 0.5)

        self.assertIsInstance(result, FakePermissionResultDeny)
        self.assertTrue(getattr(result, "interrupt", False))
        self.assertFalse(agent_server.CLAUDE_PENDING_INTERACTIONS)

    async def test_delete_rejects_while_explicit_stop_cleanup_is_active(self) -> None:
        stop_operation = asyncio.create_task(wait_forever())
        try:
            with patch.object(
                agent_server,
                "EXPLICIT_STOP_OPERATIONS",
                {"chat-claude": stop_operation},
            ), patch.object(agent_server, "SESSION_LIFECYCLE_LOCKS", {}):
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.delete_session("chat-claude")

            self.assertEqual(raised.exception.status_code, 409)
            self.assertIn("Stop cleanup", str(raised.exception.detail))
            self.assertNotIn("chat-claude", agent_server.DELETING_SESSIONS)
        finally:
            stop_operation.cancel()
            await asyncio.gather(stop_operation, return_exceptions=True)

    async def test_delete_force_retires_sdk_when_interrupt_has_no_terminal_result(self) -> None:
        handle = FakeClaudeRun()
        manager = FakeClaudeManager(handle)
        manager.active_run_id = "run-claude"
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "claude_sdk_run": handle,
                "interactive_agent_sdk": True,
                "stop_requested": False,
                "claude_sdk_owner_token": manager.owner_token,
                "claude_permission_run_id": "run-claude",
                "claude_permissions_open": True,
            }
        }
        turn_task = asyncio.create_task(wait_forever())
        agent_server.register_session_task(
            agent_server.SESSION_TURN_TASKS,
            "chat-claude",
            turn_task,
        )

        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            (state_dir / "sessions" / "chat-claude").mkdir(parents=True)
            with patch.object(
                agent_server,
                "STATE_DIR",
                state_dir,
            ), patch.object(
                agent_server,
                "SESSIONS_FILE",
                state_dir / "sessions.json",
            ), patch.object(
                agent_server,
                "ensure_dirs",
            ), patch.object(
                agent_server,
                "CODEX_SESSION_CLEANUP_TIMEOUT_SECONDS",
                0.01,
            ), patch.object(
                agent_server,
                "wait_for_session_tasks",
                AsyncMock(side_effect=[True, True, False, True]),
            ), patch.object(
                agent_server.JOBS,
                "delete_for_session",
                AsyncMock(return_value=0),
            ), patch.object(
                agent_server,
                "kill_terminal_session",
            ):
                try:
                    result = await asyncio.wait_for(
                        agent_server.delete_session("chat-claude"),
                        0.5,
                    )
                finally:
                    agent_server.DELETED_SESSION_TOMBSTONES.discard(
                        "chat-claude"
                    )

        self.assertTrue(result["deleted"])
        self.assertGreaterEqual(handle.interrupt_calls, 1)
        self.assertIn(("chat-claude", True), manager.evict_calls)
        self.assertTrue(turn_task.cancelled() or turn_task.done())

    async def test_delete_bounds_cancellation_hostile_run_now_then_retries(self) -> None:
        cancellation_observed = asyncio.Event()
        release = asyncio.Event()

        async def cancellation_hostile_run_now() -> dict[str, object]:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                # Model a Force Send handoff that must finish provider-side
                # cleanup after receiving its first local cancellation.
                cancellation_observed.set()
                await release.wait()
            return {"ok": True}

        run_now_task = asyncio.create_task(cancellation_hostile_run_now())
        run_now_requests = {
            "chat-claude": ("queued-steer", run_now_task),
        }

        import tempfile
        try:
            with tempfile.TemporaryDirectory() as temporary:
                state_dir = Path(temporary)
                (state_dir / "sessions" / "chat-claude").mkdir(parents=True)
                with patch.object(
                    agent_server,
                    "STATE_DIR",
                    state_dir,
                ), patch.object(
                    agent_server,
                    "SESSIONS_FILE",
                    state_dir / "sessions.json",
                ), patch.object(
                    agent_server,
                    "ensure_dirs",
                ), patch.object(
                    agent_server,
                    "CODEX_SESSION_CLEANUP_TIMEOUT_SECONDS",
                    0.01,
                ), patch.object(
                    agent_server,
                    "RUN_NOW_REQUESTS",
                    run_now_requests,
                ), patch.object(
                    agent_server,
                    "CODEX_APP_SERVER_MANAGER",
                    None,
                ), patch.object(
                    agent_server.JOBS,
                    "delete_for_session",
                    AsyncMock(return_value=0),
                ), patch.object(
                    agent_server,
                    "kill_terminal_session",
                ):
                    with self.assertRaises(agent_server.HTTPException) as raised:
                        await asyncio.wait_for(
                            agent_server.delete_session("chat-claude"),
                            0.5,
                        )

                    self.assertEqual(raised.exception.status_code, 409)
                    self.assertIn("Force Send cleanup", str(raised.exception.detail))
                    await asyncio.wait_for(cancellation_observed.wait(), 0.5)
                    self.assertFalse(run_now_task.done())
                    self.assertIn("chat-claude", agent_server.STORE.sessions)
                    self.assertNotIn(
                        "chat-claude",
                        agent_server.DELETING_SESSIONS,
                    )

                    release.set()
                    self.assertEqual(
                        await asyncio.wait_for(run_now_task, 0.5),
                        {"ok": True},
                    )
                    result = await asyncio.wait_for(
                        agent_server.delete_session("chat-claude"),
                        0.5,
                    )

                    self.assertTrue(result["deleted"])
                    self.assertNotIn("chat-claude", run_now_requests)
                    self.assertNotIn("chat-claude", agent_server.STORE.sessions)
        finally:
            release.set()
            if not run_now_task.done():
                run_now_task.cancel()
            await asyncio.gather(run_now_task, return_exceptions=True)
            agent_server.DELETED_SESSION_TOMBSTONES.discard("chat-claude")

    async def test_late_approval_response_is_rejected_after_delete_reservation(self) -> None:
        agent_server.DELETING_SESSIONS.add("chat-claude")
        resolver = AsyncMock()

        with patch.object(
            agent_server,
            "resolve_claude_interaction",
            resolver,
        ):
            with self.assertRaises(agent_server.HTTPException) as raised:
                await agent_server.post_claude_interaction_response(
                    "chat-claude",
                    "interaction-1",
                    agent_server.ClaudeInteractionResponseRequest(
                        response={"decision": "accept"},
                    ),
                )

        self.assertEqual(raised.exception.status_code, 409)
        resolver.assert_not_awaited()

    async def test_approval_accepted_after_stop_fence_is_still_denied(self) -> None:
        manager = FakeClaudeManager()
        manager.active_run_id = "run-claude"
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "interactive_agent_sdk": True,
                "stop_requested": False,
                "claude_sdk_owner_token": manager.owner_token,
                "claude_permission_run_id": "run-claude",
                "claude_permissions_open": True,
            }
        }
        with patch.dict(sys.modules, fake_claude_sdk_modules()), patch.object(
            agent_server,
            "update_claude_pending_session_metadata",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ):
            callback = asyncio.create_task(
                agent_server.handle_claude_tool_permission(
                    "chat-claude",
                    "Bash",
                    {"command": "pwd"},
                    {"tool_use_id": "tool-stop-race"},
                    owner_token=manager.owner_token,
                )
            )
            for _ in range(100):
                if agent_server.CLAUDE_PENDING_INTERACTIONS:
                    break
                await asyncio.sleep(0)
            interaction_id = next(iter(
                agent_server.CLAUDE_PENDING_INTERACTIONS
            ))
            async with agent_server.ACTIVE_LOCK:
                active = agent_server.ACTIVE["chat-claude"]
                active["stop_requested"] = True
                active["claude_permissions_open"] = False
            await agent_server.resolve_claude_interaction(
                "chat-claude",
                interaction_id,
                {"decision": "accept"},
            )
            result = await asyncio.wait_for(callback, 0.5)

        self.assertIsInstance(result, FakePermissionResultDeny)
        self.assertTrue(getattr(result, "interrupt", False))
        self.assertFalse(agent_server.CLAUDE_PENDING_INTERACTIONS)

    async def test_ask_user_can_be_skipped_with_empty_answers(self) -> None:
        manager = FakeClaudeManager()
        manager.active_run_id = "run-claude"
        agent_server.CLAUDE_SDK_MANAGER = manager
        agent_server.ACTIVE = {
            "chat-claude": {
                "run_id": "run-claude",
                "backend": agent_server.BACKEND_CLAUDE,
                "transport": agent_server.CLAUDE_TRANSPORT_AGENT_SDK,
                "interactive_agent_sdk": True,
                "stop_requested": False,
                "claude_sdk_owner_token": manager.owner_token,
                "claude_permission_run_id": "run-claude",
                "claude_permissions_open": True,
            }
        }
        with patch.dict(sys.modules, fake_claude_sdk_modules()), patch.object(
            agent_server,
            "update_claude_pending_session_metadata",
            AsyncMock(),
        ), patch.object(
            agent_server,
            "append_event",
            AsyncMock(return_value={}),
        ):
            callback = asyncio.create_task(
                agent_server.handle_claude_tool_permission(
                    "chat-claude",
                    "AskUserQuestion",
                    {
                        "questions": [
                            {
                                "question": "Choose one",
                                "header": "Choice",
                                "multiSelect": False,
                                "options": [
                                    {"label": "A", "description": "First"},
                                ],
                            }
                        ]
                    },
                    {"tool_use_id": "question-1"},
                    owner_token=manager.owner_token,
                )
            )
            for _ in range(100):
                if agent_server.CLAUDE_PENDING_INTERACTIONS:
                    break
                await asyncio.sleep(0)
            interaction_id = next(iter(agent_server.CLAUDE_PENDING_INTERACTIONS))
            await agent_server.resolve_claude_interaction(
                "chat-claude",
                interaction_id,
                {"answers": {}},
            )
            result = await asyncio.wait_for(callback, 0.5)

        self.assertIsInstance(result, FakePermissionResultDeny)
        self.assertFalse(getattr(result, "interrupt", True))
        self.assertIn("skipped", str(getattr(result, "message", "")).lower())


if __name__ == "__main__":
    unittest.main()
