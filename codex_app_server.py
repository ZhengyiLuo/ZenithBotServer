"""Persistent, multiplexed JSON-RPC client for ``codex app-server``.

The app-server protocol is bidirectional JSONL over stdio.  One client owns
one lazily started process and can carry multiple Codex threads concurrently.
Transport failures are deliberately surfaced to callers; this module never
replays a request whose delivery may have succeeded.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import signal
import time
from collections import deque
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Sequence


class CodexAppServerError(RuntimeError):
    """Base error raised by the app-server transport."""

    def __init__(
        self,
        message: str,
        *,
        request_sent: bool = False,
        safe_to_retry: bool = False,
    ) -> None:
        super().__init__(message)
        self.request_sent = request_sent
        self.safe_to_retry = safe_to_retry
        # ``start_turn`` attaches its provisional routed handle here when the
        # request outcome is ambiguous.  Callers can keep observing the thread
        # instead of replaying the user message.
        self.pending_turn: CodexAppServerTurn | None = None


class CodexAppServerDisconnected(CodexAppServerError):
    """The shared app-server transport closed unexpectedly."""

    def __init__(
        self,
        message: str,
        *,
        request_sent: bool = False,
        safe_to_retry: bool = False,
        planned: bool = False,
    ) -> None:
        super().__init__(
            message,
            request_sent=request_sent,
            safe_to_retry=safe_to_retry,
        )
        self.planned = planned


class CodexAppServerTimeout(CodexAppServerError):
    """A request exceeded its deadline before or after transport delivery."""

    def __init__(
        self,
        method: str,
        timeout: float,
        *,
        request_sent: bool = True,
    ) -> None:
        self.method = method
        self.timeout = timeout
        super().__init__(
            f"{method} timed out after {timeout:g}s",
            request_sent=request_sent,
            safe_to_retry=not request_sent,
        )


class CodexAppServerRequestError(CodexAppServerError):
    """A JSON-RPC request was explicitly rejected by app-server."""

    def __init__(self, method: str, error: Any) -> None:
        self.method = method
        self.error = error
        self.code = error.get("code") if isinstance(error, dict) else None
        self.data = error.get("data") if isinstance(error, dict) else None
        if isinstance(error, dict):
            message = str(error.get("message") or error)
        else:
            message = str(error)
        super().__init__(
            f"{method} failed: {message}",
            request_sent=True,
            safe_to_retry=True,
        )


class CodexAppServerProtocolError(CodexAppServerError):
    """App-server returned a response that violated the expected contract."""


class CodexAppServerSubscriptionClosed(CodexAppServerError):
    """A local notification subscription is no longer active."""


ProcessFactory = Callable[..., Awaitable[asyncio.subprocess.Process]]
NotificationHandler = Callable[[dict[str, Any]], Awaitable[None] | None]
ServerRequestHandler = Callable[
    [Any, str, dict[str, Any]],
    Awaitable[dict[str, Any]] | dict[str, Any],
]
# ``(pid, process_group_id)``; the group id is None when it is not provably
# owned by the client (injected factories, non-POSIX hosts).
ProcessLifecycleHook = Callable[[int, int | None], None]

_THREAD_GOAL_STATUSES = frozenset(
    {
        "active",
        "paused",
        "blocked",
        "usageLimited",
        "budgetLimited",
        "complete",
    }
)
_TURN_STATUSES = frozenset({"completed", "interrupted", "failed", "inProgress"})
_REVIEW_DELIVERIES = frozenset({"inline", "detached"})
_REVIEW_TARGET_TYPES = frozenset(
    {"uncommittedChanges", "baseBranch", "commit", "custom"}
)


class _OmittedType:
    """Sentinel that distinguishes an omitted optional field from JSON null."""


_OMITTED = _OmittedType()


def _require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _protocol_object(method: str, result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise CodexAppServerProtocolError(
            f"{method} did not return an object",
            request_sent=True,
            safe_to_retry=False,
        )
    return result


def _protocol_empty_object(method: str, result: Any) -> None:
    _protocol_object(method, result)


def _protocol_cursor(method: str, result: dict[str, Any]) -> str | None:
    cursor = result.get("nextCursor")
    if cursor is not None and not isinstance(cursor, str):
        raise CodexAppServerProtocolError(
            f"{method} returned an invalid next cursor",
            request_sent=True,
            safe_to_retry=False,
        )
    return cursor


def _protocol_thread_goal(
    method: str,
    goal: Any,
    *,
    thread_id: str,
) -> dict[str, Any]:
    if not isinstance(goal, dict):
        raise CodexAppServerProtocolError(
            f"{method} did not return a goal object",
            request_sent=True,
            safe_to_retry=False,
        )
    if goal.get("threadId") != thread_id:
        raise CodexAppServerProtocolError(
            f"{method} returned a goal for a different thread",
            request_sent=True,
            safe_to_retry=False,
        )
    if not isinstance(goal.get("objective"), str) or not goal["objective"]:
        raise CodexAppServerProtocolError(
            f"{method} returned an invalid goal objective",
            request_sent=True,
            safe_to_retry=False,
        )
    if goal.get("status") not in _THREAD_GOAL_STATUSES:
        raise CodexAppServerProtocolError(
            f"{method} returned an invalid goal status",
            request_sent=True,
            safe_to_retry=False,
        )
    for field in (
        "createdAt",
        "updatedAt",
        "tokensUsed",
        "timeUsedSeconds",
    ):
        value = goal.get(field)
        if isinstance(value, bool) or not isinstance(value, int):
            raise CodexAppServerProtocolError(
                f"{method} returned an invalid goal {field}",
                request_sent=True,
                safe_to_retry=False,
            )
    token_budget = goal.get("tokenBudget")
    if (
        token_budget is not None
        and (isinstance(token_budget, bool) or not isinstance(token_budget, int))
    ):
        raise CodexAppServerProtocolError(
            f"{method} returned an invalid goal tokenBudget",
            request_sent=True,
            safe_to_retry=False,
        )
    return dict(goal)


def _protocol_turn(method: str, turn: Any) -> dict[str, Any]:
    if not isinstance(turn, dict) or not isinstance(turn.get("id"), str) or not turn["id"]:
        raise CodexAppServerProtocolError(
            f"{method} did not return a valid turn",
            request_sent=True,
            safe_to_retry=False,
        )
    if turn.get("status") not in _TURN_STATUSES or not isinstance(
        turn.get("items"), list
    ):
        raise CodexAppServerProtocolError(
            f"{method} returned an invalid turn payload",
            request_sent=True,
            safe_to_retry=False,
        )
    return dict(turn)


def _notification_scope(notification: dict[str, Any]) -> tuple[str, str]:
    params = notification.get("params")
    if not isinstance(params, dict):
        return "", ""

    thread_id = str(params.get("threadId") or "")
    turn_id = str(params.get("turnId") or "")

    thread = params.get("thread")
    if not thread_id and isinstance(thread, dict):
        thread_id = str(thread.get("id") or "")

    turn = params.get("turn")
    if not turn_id and isinstance(turn, dict):
        turn_id = str(turn.get("id") or "")

    return thread_id, turn_id


@dataclass(eq=False, slots=True)
class CodexAppServerSubscription:
    """A local filtered view of app-server notifications."""

    client: "CodexAppServerClient"
    thread_id: str | None
    turn_id: str | None
    _queue: asyncio.Queue[Any]
    _closed: bool = False
    _last_enqueued_sequence: int = 0

    def _matches(self, notification: dict[str, Any]) -> bool:
        notification_thread_id, notification_turn_id = _notification_scope(notification)
        if self.thread_id is not None and notification_thread_id != self.thread_id:
            return False
        if self.turn_id is not None and notification_turn_id != self.turn_id:
            return False
        return True

    def _put(self, value: Any) -> None:
        if self._closed:
            return
        try:
            self._last_enqueued_sequence += 1
            sequence = self._last_enqueued_sequence
            self._queue.put_nowait((sequence, value))
        except asyncio.QueueFull:
            self._finish(
                CodexAppServerDisconnected(
                    "app-server notification backlog exceeded its safety limit",
                    request_sent=True,
                    safe_to_retry=False,
                )
            )

    def _finish(self, error: BaseException | None = None) -> None:
        if self._closed:
            return
        if error is not None:
            while not self._queue.empty():
                with suppress(asyncio.QueueEmpty):
                    self._queue.get_nowait()
            self._queue.put_nowait(error)
        self._closed = True
        self.client._release_subscription(self)

    async def next_notification_with_sequence(
        self,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        if self._closed and self._queue.empty():
            raise CodexAppServerSubscriptionClosed("app-server notification subscription closed")
        waiter = self._queue.get()
        value = await (asyncio.wait_for(waiter, timeout) if timeout is not None else waiter)
        if isinstance(value, BaseException):
            raise value
        if (
            not isinstance(value, tuple)
            or len(value) != 2
            or not isinstance(value[0], int)
            or not isinstance(value[1], dict)
        ):
            raise CodexAppServerProtocolError("app-server notification was not an object")
        return value

    async def next_notification(self, timeout: float | None = None) -> dict[str, Any]:
        _sequence, notification = await self.next_notification_with_sequence(timeout)
        return notification

    def close(self) -> None:
        self._finish()


@dataclass(eq=False, slots=True)
class CodexAppServerTurn:
    """An accepted app-server turn and its routed notification stream."""

    client: "CodexAppServerClient"
    thread_id: str
    turn_id: str
    _subscription: CodexAppServerSubscription
    # Set at the exact stdin write boundary. A caller cancelled after delivery
    # must retire this generation, not the one observed before lazy start/init.
    transport_generation: int = 0
    _closed: bool = False
    _completed: bool = False

    async def next_notification(self, timeout: float | None = None) -> dict[str, Any]:
        return await self._subscription.next_notification(timeout)

    async def next_notification_with_sequence(
        self,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        return await self._subscription.next_notification_with_sequence(timeout)

    async def steer(
        self,
        input_items: list[dict[str, Any]],
        *,
        client_user_message_id: str | None = None,
    ) -> str:
        return await self.client.steer_turn(
            self.thread_id,
            self.turn_id,
            input_items,
            client_user_message_id=client_user_message_id,
        )

    async def steer_with_notification_watermark(
        self,
        input_items: list[dict[str, Any]],
        *,
        client_user_message_id: str | None = None,
    ) -> tuple[str, int]:
        return await self.client.steer_turn_with_notification_watermark(
            self.thread_id,
            self.turn_id,
            input_items,
            client_user_message_id=client_user_message_id,
            notification_subscription=self._subscription,
        )

    async def interrupt(self) -> None:
        await self.client.interrupt_turn(self.thread_id, self.turn_id)

    def adopt_turn_id(self, turn_id: str) -> None:
        """Bind a provisional turn after an ambiguous ``turn/start`` response."""
        resolved = str(turn_id or "")
        if not resolved:
            raise CodexAppServerProtocolError("cannot bind an empty app-server turn id")
        if self.turn_id and self.turn_id != resolved:
            raise CodexAppServerProtocolError(
                f"provisional turn already bound to {self.turn_id}, not {resolved}"
            )
        self.turn_id = resolved
        self._subscription.turn_id = resolved

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.client.release_turn(self)


async def decline_server_request(
    _request_id: Any,
    method: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Return the least-privileged valid response for interactive requests.

    AgentsServer launches Codex with non-interactive approval settings.  If a
    request nevertheless reaches this connection, silently approving it would
    be unsafe and waiting forever would wedge the turn.
    """

    if method in {
        "item/commandExecution/requestApproval",
        "item/fileChange/requestApproval",
    }:
        return {"decision": "decline"}
    if method in {"applyPatchApproval", "execCommandApproval"}:
        return {"decision": "denied"}
    if method == "item/tool/requestUserInput":
        return {"answers": {}}
    if method == "mcpServer/elicitation/request":
        return {"action": "decline"}
    if method == "item/permissions/requestApproval":
        return {"permissions": {}, "scope": "turn", "strictAutoReview": False}
    raise CodexAppServerRequestError(
        method,
        {
            "code": -32601,
            "message": f"AgentsServer does not handle server request {method}",
        },
    )


class CodexAppServerClient:
    """Supervise one local app-server process and multiplex active threads."""

    def __init__(
        self,
        codex_bin: str,
        *,
        cwd: str,
        env_factory: Callable[[], dict[str, str]],
        app_server_args: Sequence[str] = (),
        request_timeout: float = 30.0,
        lifecycle_timeout: float = 300.0,
        process_exit_timeout: float = 1.0,
        process_stream_limit: int = 16 * 1024 * 1024,
        notification_queue_limit: int = 8192,
        json_parse_thread_threshold: int = 1024 * 1024,
        fork_cleanup_grace: float = 30.0,
        process_factory: ProcessFactory | None = None,
        server_request_handler: ServerRequestHandler | None = None,
        initialize_params: dict[str, Any] | None = None,
        on_process_started: ProcessLifecycleHook | None = None,
        on_process_exited: ProcessLifecycleHook | None = None,
    ) -> None:
        self.codex_bin = codex_bin
        self.cwd = cwd
        self.env_factory = env_factory
        # Lifecycle hooks receive ``(pid, process_group_id)``. The group id is
        # None whenever start() could not prove it owns the child's session,
        # so a hook must never derive a signal target from the pid alone.
        self._on_process_started = on_process_started
        self._on_process_exited = on_process_exited
        self.app_server_args = tuple(str(value) for value in app_server_args)
        self.request_timeout = request_timeout
        self.lifecycle_timeout = lifecycle_timeout
        self.process_exit_timeout = max(0.0, float(process_exit_timeout))
        self.process_stream_limit = process_stream_limit
        self.notification_queue_limit = max(1, int(notification_queue_limit))
        self.json_parse_thread_threshold = max(
            0,
            int(json_parse_thread_threshold),
        )
        # Fork creation itself may consume the full lifecycle timeout. Allow a
        # substantial post-timeout window for the adjacent thread/started
        # notification instead of relying on sub-second scheduling luck.
        self.fork_cleanup_grace = max(0.0, float(fork_cleanup_grace))
        self._process_factory = process_factory or asyncio.create_subprocess_exec
        # Only the default launcher proves that ``start_new_session=True`` was
        # honored by the process we own. Tests and injected factories may use
        # arbitrary/recycled PIDs, so never derive a signal target from them.
        self._owns_spawned_process_groups = process_factory is None and os.name == "posix"
        self._server_request_handler = server_request_handler or decline_server_request
        self._initialize_params = initialize_params or {
            "clientInfo": {
                "name": "agents_server",
                "title": "AgentsServer",
                "version": "1",
            },
            "capabilities": {"experimentalApi": True},
        }
        self._proc: asyncio.subprocess.Process | None = None
        self._process_group_id: int | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._start_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        # A timed-out/cancelled thread/fork may still finish in app-server.
        # Keep each source serialized through its late-notification cleanup so
        # one watcher can never claim a later fork from the same source.
        self._fork_source_locks: dict[str, asyncio.Lock] = {}
        self._next_id = 0
        self._pending: dict[
            int,
            tuple[
                str,
                asyncio.Future[Any],
                CodexAppServerSubscription | None,
            ],
        ] = {}
        self._turns_by_thread: dict[str, CodexAppServerTurn] = {}
        self._loaded_threads: set[str] = set()
        # Provider identity outlives subscription/load state for one app-server
        # process. Fork cleanup uses this to distinguish a newly-created child
        # from an existing child that another operation merely resumed.
        self._known_thread_ids: set[str] = set()
        self._subscriptions: set[CodexAppServerSubscription] = set()
        self._notification_handlers: set[NotificationHandler] = set()
        self._callback_tasks: set[asyncio.Task[Any]] = set()
        self._callback_tails: dict[
            tuple[NotificationHandler, str],
            asyncio.Task[Any],
        ] = {}
        self._server_request_tasks: dict[Any, asyncio.Task[None]] = {}
        self._stderr_tail: deque[str] = deque(maxlen=40)
        # Diagnostic-only record of notifications _route_notification could
        # not match to any live subscription (see its docstring) - these are
        # otherwise dropped with no trace, which is exactly what makes a
        # stalled turn look like it hung for no reason.
        self._unmatched_notifications: deque[dict[str, Any]] = deque(maxlen=40)
        self._closing = False
        self._initialized = False
        self._initialize_result: dict[str, Any] | None = None
        self._generation = 0

    @property
    def ready(self) -> bool:
        return bool(
            self._initialized
            and self._proc is not None
            and self._proc.returncode is None
            and self._reader_task is not None
            and not self._reader_task.done()
        )

    @property
    def stderr_tail(self) -> list[str]:
        return list(self._stderr_tail)

    @property
    def unmatched_notifications(self) -> list[dict[str, Any]]:
        return list(self._unmatched_notifications)

    @property
    def process(self) -> asyncio.subprocess.Process | None:
        """The supervised process, exposed read-only for diagnostics."""

        return self._proc

    @property
    def generation(self) -> int:
        """Incremented after every successful initialize handshake."""

        return self._generation

    @property
    def initialize_result(self) -> dict[str, Any] | None:
        return dict(self._initialize_result) if self._initialize_result is not None else None

    def is_thread_loaded(self, thread_id: str) -> bool:
        return thread_id in self._loaded_threads

    async def start(self) -> None:
        """Start and initialize the process once, or reuse the live process."""

        if self.ready:
            return
        async with self._start_lock:
            if self.ready:
                return
            # A caller may subscribe before the first lazy start.  Preserve
            # those local subscriptions when there is no old transport to
            # discard.
            if (
                self._proc is not None
                or self._reader_task is not None
                or self._stderr_task is not None
                or self._pending
            ):
                await self._discard_process()
            self._closing = False
            try:
                proc = await self._process_factory(
                    self.codex_bin,
                    "app-server",
                    *self.app_server_args,
                    "--listen",
                    "stdio://",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.cwd,
                    env=self.env_factory(),
                    limit=self.process_stream_limit,
                    start_new_session=True,
                )
            except Exception as exc:
                raise CodexAppServerDisconnected(
                    f"failed to start codex app-server: {exc}",
                    request_sent=False,
                    safe_to_retry=True,
                ) from exc

            raw_pid = getattr(proc, "pid", None)
            self._process_group_id = (
                raw_pid
                if (
                    self._owns_spawned_process_groups
                    and isinstance(raw_pid, int)
                    and not isinstance(raw_pid, bool)
                    and raw_pid > 0
                )
                else None
            )
            self._proc = proc
            if (
                self._on_process_started is not None
                and isinstance(raw_pid, int)
                and not isinstance(raw_pid, bool)
                and raw_pid > 0
            ):
                # Registry/bookkeeping hooks must never break a provider
                # start; they exist so an orphaned child can be reaped later.
                with suppress(Exception):
                    self._on_process_started(raw_pid, self._process_group_id)
            self._reader_task = asyncio.create_task(
                self._reader_loop(proc),
                name="codex-app-server-reader",
            )
            self._stderr_task = asyncio.create_task(
                self._stderr_loop(proc),
                name="codex-app-server-stderr",
            )
            try:
                result = await self._request_connected(
                    "initialize",
                    dict(self._initialize_params),
                    discard_on_send_timeout=False,
                )
                self._initialize_result = result if isinstance(result, dict) else {}
                await self._send(
                    {"method": "initialized"},
                    discard_on_send_timeout=False,
                )
                self._initialized = True
                self._generation += 1
            except Exception:
                await self._discard_process()
                raise

    async def close(self) -> None:
        self._closing = True
        await self._discard_process()

    async def retire_generation(self, expected_generation: int) -> bool:
        """Stop only the transport generation that may own ambiguous work.

        A cancelled request can have crossed the stdin write boundary before
        its acknowledgement arrived.  Callers that cannot recover the native
        turn id must be able to retire that exact process without racing a
        replacement generation started by another task.
        """

        async with self._start_lock:
            if self._generation != expected_generation:
                return False
            await self._discard_process()
            return True

    async def __aenter__(self) -> "CodexAppServerClient":
        await self.start()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    def subscribe(
        self,
        *,
        thread_id: str | None = None,
        turn_id: str | None = None,
    ) -> CodexAppServerSubscription:
        if turn_id is not None and thread_id is None:
            raise ValueError("turn subscriptions require a thread_id")
        subscription = CodexAppServerSubscription(
            self,
            thread_id,
            turn_id,
            asyncio.Queue(maxsize=self.notification_queue_limit),
        )
        self._subscriptions.add(subscription)
        return subscription

    def subscribe_thread(self, thread_id: str) -> CodexAppServerSubscription:
        return self.subscribe(thread_id=thread_id)

    def subscribe_turn(self, thread_id: str, turn_id: str) -> CodexAppServerSubscription:
        return self.subscribe(thread_id=thread_id, turn_id=turn_id)

    def _release_subscription(self, subscription: CodexAppServerSubscription) -> None:
        self._subscriptions.discard(subscription)

    def _finish_scoped_subscriptions(
        self,
        thread_id: str,
        *,
        turn_id: str | None = None,
        include_thread_subscription: bool = False,
    ) -> None:
        for subscription in tuple(self._subscriptions):
            if subscription.thread_id != thread_id:
                continue
            if include_thread_subscription or subscription.turn_id == turn_id:
                subscription._finish()

    def add_notification_handler(self, handler: NotificationHandler) -> None:
        self._notification_handlers.add(handler)

    def remove_notification_handler(self, handler: NotificationHandler) -> None:
        self._notification_handlers.discard(handler)

    async def wait_for_notification_handler(
        self,
        handler: NotificationHandler,
        thread_id: str,
    ) -> None:
        """Wait through the latest callback received for one provider thread."""
        tail = self._callback_tails.get((handler, thread_id))
        if tail is None:
            return
        try:
            await asyncio.shield(tail)
        except Exception:
            # Callback failures are deliberately isolated from transport and
            # subscription consumers, matching normal callback dispatch.
            pass

    async def _discard_process(
        self,
        *,
        preserve_task: asyncio.Task[Any] | None = None,
    ) -> None:
        self._initialized = False
        self._initialize_result = None
        proc = self._proc
        self._proc = None
        process_group_id = self._process_group_id
        self._process_group_id = None
        current = asyncio.current_task()
        reader_task = self._reader_task
        stderr_task = self._stderr_task
        had_transport_state = bool(
            proc
            or reader_task
            or stderr_task
            or self._pending
            or self._turns_by_thread
            or self._known_thread_ids
            or self._subscriptions
            or self._server_request_tasks
        )
        self._reader_task = None
        self._stderr_task = None

        if proc:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 2.0
            if process_group_id is not None:
                # start() created this exact new session. The native child can
                # outlive the Node leader, so signal and verify the owned group
                # even when the leader's returncode has already been observed.
                group_alive = True
                try:
                    os.killpg(process_group_id, signal.SIGTERM)
                except ProcessLookupError:
                    group_alive = False
                except PermissionError:
                    # Keep the group target: signal 0/KILL below remain scoped
                    # to the same exact group and cannot hit a sibling service.
                    pass
                while group_alive and loop.time() < deadline:
                    try:
                        os.killpg(process_group_id, 0)
                    except ProcessLookupError:
                        group_alive = False
                        break
                    except PermissionError:
                        pass
                    await asyncio.sleep(0.05)
                if group_alive:
                    with suppress(ProcessLookupError, PermissionError):
                        os.killpg(process_group_id, signal.SIGKILL)
                if proc.returncode is None:
                    with suppress(Exception):
                        await asyncio.wait_for(proc.wait(), timeout=1.0)
            elif proc.returncode is None:
                with suppress(ProcessLookupError):
                    proc.terminate()
                with suppress(Exception):
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                if proc.returncode is None:
                    with suppress(ProcessLookupError):
                        proc.kill()
                    with suppress(Exception):
                        await asyncio.wait_for(proc.wait(), timeout=1.0)
            raw_pid = getattr(proc, "pid", None)
            if (
                self._on_process_exited is not None
                and isinstance(raw_pid, int)
                and not isinstance(raw_pid, bool)
                and raw_pid > 0
            ):
                with suppress(Exception):
                    self._on_process_exited(raw_pid, process_group_id)

        for task in (reader_task, stderr_task):
            if task and task is not current:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

        background_tasks = [
            task
            for task in (
                *self._server_request_tasks.values(),
                *self._callback_tasks,
            )
            if task is not current and task is not preserve_task
        ]
        for task in background_tasks:
            task.cancel()
        self._server_request_tasks.clear()
        self._callback_tasks.clear()
        self._callback_tails.clear()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)

        if had_transport_state:
            self._fail_all(
                CodexAppServerDisconnected(
                    (
                        "codex app-server stopped with AgentsServer"
                        if self._closing
                        else "codex app-server transport closed"
                    ),
                    request_sent=bool(self._pending),
                    safe_to_retry=not bool(self._pending),
                    planned=self._closing,
                )
            )

    def _fail_all(self, error: BaseException) -> None:
        for _, future, _notification_boundary_subscription in list(
            self._pending.values()
        ):
            if not future.done():
                future.set_exception(error)
        self._pending.clear()

        self._turns_by_thread.clear()
        self._loaded_threads.clear()
        self._known_thread_ids.clear()
        for subscription in tuple(self._subscriptions):
            subscription._finish(error)

    async def request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> Any:
        await self.start()
        return await self._request_connected(method, params, timeout=timeout)

    async def _request_connected(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float | None = None,
        notification_boundary_subscription: CodexAppServerSubscription | None = None,
        discard_on_send_timeout: bool = True,
        transport_turn: CodexAppServerTurn | None = None,
    ) -> Any:
        proc = self._proc
        if not proc or proc.returncode is not None or not proc.stdin:
            raise CodexAppServerDisconnected(
                "codex app-server is not connected",
                request_sent=False,
                safe_to_retry=True,
            )

        loop = asyncio.get_running_loop()
        self._next_id += 1
        request_id = self._next_id
        future: asyncio.Future[Any] = loop.create_future()
        self._pending[request_id] = (
            method,
            future,
            notification_boundary_subscription,
        )
        effective_timeout = self.request_timeout if timeout is None else timeout
        deadline = loop.time() + max(0.0, float(effective_timeout))
        try:
            await self._send(
                {"id": request_id, "method": method, "params": params},
                deadline=deadline,
                timeout=effective_timeout,
                expected_process=proc,
                discard_on_send_timeout=discard_on_send_timeout,
                transport_turn=transport_turn,
            )
            try:
                return await asyncio.wait_for(
                    asyncio.shield(future),
                    timeout=max(0.0, deadline - loop.time()),
                )
            except asyncio.TimeoutError as exc:
                raise CodexAppServerTimeout(method, effective_timeout) from exc
        finally:
            self._pending.pop(request_id, None)
            if not future.done():
                future.cancel()
            elif not future.cancelled():
                # Transport retirement can fail every pending future while
                # this request is unwinding from its write timeout. Consume
                # that superseded exception so asyncio does not report it as
                # an unretrieved future error.
                with suppress(BaseException):
                    future.exception()

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"method": method}
        if params is not None:
            payload["params"] = params
        await self._send(payload)

    async def _discard_process_after_write_timeout(
        self,
        proc: asyncio.subprocess.Process,
    ) -> None:
        """Retire exactly the process whose stdin missed its write deadline."""
        async with self._start_lock:
            if proc is not self._proc:
                return
            cleanup_task = asyncio.create_task(
                self._discard_process(preserve_task=asyncio.current_task())
            )
            cancelled = False
            while not cleanup_task.done():
                try:
                    await asyncio.shield(cleanup_task)
                except asyncio.CancelledError:
                    # _discard_process clears the owned process reference
                    # before its first await. Every subsequent cancellation
                    # must remain outside the cleanup task; a plain join here
                    # lets a second cancel abandon the now-unreachable child.
                    cancelled = True
            # Propagate cleanup failure before restoring caller cancellation.
            # result() also retrieves any exception when the task completed in
            # the same loop turn as a repeated cancel.
            cleanup_task.result()
            if cancelled:
                raise asyncio.CancelledError

    async def _send(
        self,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
        deadline: float | None = None,
        expected_process: asyncio.subprocess.Process | None = None,
        discard_on_send_timeout: bool = True,
        transport_turn: CodexAppServerTurn | None = None,
    ) -> None:
        loop = asyncio.get_running_loop()
        effective_timeout = self.request_timeout if timeout is None else timeout
        timeout_seconds = max(0.0, float(effective_timeout))
        if deadline is None:
            deadline = loop.time() + timeout_seconds
        method = str(payload.get("method") or "app-server write")
        encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
        proc = expected_process if expected_process is not None else self._proc
        if not proc or proc.returncode is not None or not proc.stdin:
            raise CodexAppServerDisconnected(
                "codex app-server stdin is unavailable",
                request_sent=False,
                safe_to_retry=True,
            )

        lock_acquired = False
        request_sent = False
        send_timeout: asyncio.TimeoutError | None = None
        try:
            try:
                await asyncio.wait_for(
                    self._write_lock.acquire(),
                    timeout=max(0.0, deadline - loop.time()),
                )
            except asyncio.TimeoutError as exc:
                send_timeout = exc
            else:
                lock_acquired = True
                # A process may be retired while this sender waits behind an
                # older write. Never put a request on that stale pipe.
                if (
                    proc is not self._proc
                    or proc.returncode is not None
                    or not proc.stdin
                ):
                    raise CodexAppServerDisconnected(
                        "codex app-server stdin is unavailable",
                        request_sent=False,
                        safe_to_retry=True,
                    )
                if loop.time() >= deadline:
                    send_timeout = asyncio.TimeoutError()
                else:
                    try:
                        if transport_turn is not None:
                            transport_turn.transport_generation = self._generation
                        proc.stdin.write(encoded)
                        request_sent = True
                        await asyncio.wait_for(
                            proc.stdin.drain(),
                            timeout=max(0.0, deadline - loop.time()),
                        )
                    except asyncio.TimeoutError as exc:
                        send_timeout = exc
                    except Exception as exc:
                        raise CodexAppServerDisconnected(
                            f"codex app-server write failed: {exc}",
                            request_sent=True,
                            safe_to_retry=False,
                        ) from exc
        except CodexAppServerError:
            raise
        finally:
            if lock_acquired:
                self._write_lock.release()

        if send_timeout is None:
            return
        if request_sent and discard_on_send_timeout:
            # Cleanup runs after releasing the shared writer lock. It is
            # serialized with start() so a fresh process cannot be spawned and
            # then accidentally cleared by retirement of the stale transport.
            await self._discard_process_after_write_timeout(proc)
        raise CodexAppServerTimeout(
            method,
            effective_timeout,
            request_sent=request_sent,
        ) from send_timeout

    async def _reader_loop(self, proc: asyncio.subprocess.Process) -> None:
        error: BaseException | None = None
        try:
            if not proc.stdout:
                raise CodexAppServerDisconnected(
                    "codex app-server stdout is unavailable",
                    request_sent=False,
                    safe_to_retry=True,
                )
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                try:
                    if (
                        self.json_parse_thread_threshold
                        and len(raw) >= self.json_parse_thread_threshold
                    ):
                        message = await asyncio.to_thread(json.loads, raw)
                    else:
                        message = json.loads(raw)
                except (TypeError, ValueError):
                    continue
                if not isinstance(message, dict):
                    continue

                request_id = message.get("id")
                if request_id is not None and ("result" in message or "error" in message):
                    pending = self._pending.get(request_id)
                    if pending:
                        (
                            request_method,
                            future,
                            notification_boundary_subscription,
                        ) = pending
                        if not future.done():
                            if "error" in message:
                                future.set_exception(
                                    CodexAppServerRequestError(
                                        request_method,
                                        message.get("error"),
                                    )
                                )
                            else:
                                result = message.get("result")
                                future.set_result(
                                    (
                                        result,
                                        notification_boundary_subscription._last_enqueued_sequence,
                                    )
                                    if notification_boundary_subscription is not None
                                    else result
                                )
                    continue

                if request_id is not None and message.get("method"):
                    params = message.get("params")
                    self._start_server_request(
                        request_id,
                        str(message.get("method") or ""),
                        params if isinstance(params, dict) else {},
                    )
                    continue

                method = str(message.get("method") or "")
                params = message.get("params")
                if method and isinstance(params, dict):
                    self._route_notification({"method": method, "params": params})
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = exc
        finally:
            if not self._closing and proc is self._proc:
                returncode = proc.returncode
                if returncode is None:
                    try:
                        returncode = await asyncio.wait_for(
                            proc.wait(),
                            timeout=self.process_exit_timeout,
                        )
                    except asyncio.TimeoutError:
                        returncode = proc.returncode
                    except Exception as exc:
                        error = error or exc
                # ``close()`` may have started while the reader was waiting
                # for the child status.  Let the planned shutdown path own
                # subscription cleanup instead of reporting a false crash.
                if not self._closing and proc is self._proc:
                    self._initialized = False
                    error = error or CodexAppServerDisconnected(
                        (
                            f"codex app-server exited with code {returncode}"
                            if returncode is not None
                            else (
                                "codex app-server closed stdout before its "
                                "process exit status became available"
                            )
                        ),
                        request_sent=bool(self._pending),
                        safe_to_retry=not bool(self._pending),
                    )
                    self._fail_all(error)
                    self._cancel_server_request_tasks()
                    # An unplanned exit must release the child's registry entry
                    # now; ``_discard_process`` only runs on the next start or
                    # on close, and a stale {pid, pgid} could be reused.
                    raw_pid = getattr(proc, "pid", None)
                    if (
                        self._on_process_exited is not None
                        and isinstance(raw_pid, int)
                        and not isinstance(raw_pid, bool)
                        and raw_pid > 0
                    ):
                        with suppress(Exception):
                            self._on_process_exited(raw_pid, self._process_group_id)

    async def _stderr_loop(self, proc: asyncio.subprocess.Process) -> None:
        if not proc.stderr:
            return
        while True:
            line = await proc.stderr.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").strip()
            if text:
                self._stderr_tail.append(text)

    def _route_notification(self, notification: dict[str, Any]) -> None:
        method = str(notification.get("method") or "")
        params = notification.get("params")
        if not isinstance(params, dict):
            return

        if method == "serverRequest/resolved":
            request_id = params.get("requestId")
            task = self._server_request_tasks.pop(request_id, None)
            if task:
                task.cancel()

        thread_id, turn_id = _notification_scope(notification)
        if method == "thread/started" and thread_id:
            self._loaded_threads.add(thread_id)
        elif method == "thread/closed" and thread_id:
            self._loaded_threads.discard(thread_id)

        active_turn = self._turns_by_thread.get(thread_id)
        if active_turn and turn_id:
            # A provisional turn may receive an item notification before the
            # turn/start response binds its id.  Once bound, only an explicit
            # turn/started notification may move the handle to another turn.
            # Native goals continue a thread by starting follow-up turns, so
            # keeping this id current is required for both event routing and
            # turn/interrupt to target the work that is actually running.
            if not active_turn.turn_id or method == "turn/started":
                active_turn.turn_id = turn_id
                active_turn._subscription.turn_id = turn_id

        matched = False
        for subscription in tuple(self._subscriptions):
            if subscription._matches(notification):
                subscription._put(notification)
                matched = True
        if not matched:
            self._unmatched_notifications.append({
                "method": method,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "at": time.time(),
            })

        for handler in tuple(self._notification_handlers):
            owner = (handler, thread_id or "")
            previous = self._callback_tails.get(owner)
            if previous is None:
                try:
                    result = handler(notification)
                except Exception:
                    continue
                if not inspect.isawaitable(result):
                    # Preserve the original inline contract for synchronous
                    # caches consumed by immediately following server requests.
                    continue
                task = asyncio.ensure_future(result)
            else:
                task = asyncio.create_task(
                    self._invoke_notification_handler(
                        handler,
                        notification,
                        previous,
                    )
                )
            self._callback_tails[owner] = task
            self._callback_tasks.add(task)
            task.add_done_callback(
                lambda completed, owner=owner: self._finish_callback_task(
                    owner,
                    completed,
                )
            )

        # Synchronous handlers (including the scoped fork watcher) must see
        # whether this identity was known *before* this notification. Record a
        # genuinely new notification only after they have made that decision.
        if method == "thread/started" and thread_id:
            self._known_thread_ids.add(thread_id)

        if method == "turn/completed" and active_turn:
            if not turn_id or not active_turn.turn_id or turn_id == active_turn.turn_id:
                active_turn._completed = True
                if self._turns_by_thread.get(thread_id) is active_turn:
                    self._turns_by_thread.pop(thread_id, None)
                active_turn._subscription._finish()
        if method == "turn/completed" and thread_id and turn_id:
            self._finish_scoped_subscriptions(thread_id, turn_id=turn_id)
        elif method == "thread/closed" and thread_id:
            self._finish_scoped_subscriptions(
                thread_id,
                include_thread_subscription=True,
            )

    async def _invoke_notification_handler(
        self,
        handler: NotificationHandler,
        notification: dict[str, Any],
        previous: asyncio.Task[Any] | None,
    ) -> None:
        if previous is not None:
            try:
                await previous
            except Exception:
                # One failed notification must not discard every later
                # notification already received for the same handler.
                pass
        try:
            result = handler(notification)
        except Exception:
            return
        if inspect.isawaitable(result):
            await result

    def _finish_callback_task(
        self,
        owner: tuple[NotificationHandler, str],
        task: asyncio.Task[Any],
    ) -> None:
        self._callback_tasks.discard(task)
        if self._callback_tails.get(owner) is task:
            self._callback_tails.pop(owner, None)
        if not task.cancelled():
            with suppress(Exception):
                task.result()

    def _cancel_server_request_tasks(self) -> None:
        tasks = list(self._server_request_tasks.values())
        self._server_request_tasks.clear()
        for task in tasks:
            task.cancel()

    def _start_server_request(
        self,
        request_id: Any,
        method: str,
        params: dict[str, Any],
    ) -> None:
        previous = self._server_request_tasks.pop(request_id, None)
        if previous:
            previous.cancel()
        task = asyncio.create_task(
            self._handle_server_request(request_id, method, params),
            name=f"codex-app-server-request-{request_id}",
        )
        self._server_request_tasks[request_id] = task
        task.add_done_callback(
            lambda done, rid=request_id: self._finish_server_request(rid, done)
        )

    def _finish_server_request(self, request_id: Any, task: asyncio.Task[None]) -> None:
        if self._server_request_tasks.get(request_id) is task:
            self._server_request_tasks.pop(request_id, None)
        if not task.cancelled():
            with suppress(Exception):
                task.result()

    async def _handle_server_request(
        self,
        request_id: Any,
        method: str,
        params: dict[str, Any],
    ) -> None:
        try:
            result = self._server_request_handler(request_id, method, params)
            if inspect.isawaitable(result):
                result = await result
            if not isinstance(result, dict):
                raise CodexAppServerProtocolError(
                    f"server request handler returned non-object for {method}"
                )
            await self._send({"id": request_id, "result": result})
        except asyncio.CancelledError:
            # Another app-server client or a turn transition resolved it.
            return
        except CodexAppServerRequestError as exc:
            with suppress(CodexAppServerError):
                await self._send(
                    {
                        "id": request_id,
                        "error": (
                            exc.error
                            if isinstance(exc.error, dict)
                            else {"code": -32000, "message": str(exc)}
                        ),
                    }
                )
        except Exception as exc:
            with suppress(CodexAppServerError):
                await self._send(
                    {
                        "id": request_id,
                        "error": {"code": -32000, "message": str(exc)},
                    }
                )

    async def start_thread(self, params: dict[str, Any]) -> str:
        result = await self.request(
            "thread/start",
            dict(params),
            timeout=self.lifecycle_timeout,
        )
        thread_id = self._thread_id_from_result("thread/start", result)
        self._known_thread_ids.add(thread_id)
        self._loaded_threads.add(thread_id)
        return thread_id

    async def resume_thread(
        self,
        thread_id: str,
        params: dict[str, Any] | None = None,
    ) -> str:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        # Register before the first await: thread/started can be routed before
        # the resume response and must not look like this process's late fork.
        self._known_thread_ids.add(thread_id)
        payload = dict(params or {})
        payload["threadId"] = thread_id
        payload.setdefault("excludeTurns", True)
        result = await self.request(
            "thread/resume",
            payload,
            timeout=self.lifecycle_timeout,
        )
        resolved = self._thread_id_from_result("thread/resume", result)
        self._known_thread_ids.add(resolved)
        if resolved != thread_id:
            raise CodexAppServerProtocolError(
                "thread/resume returned a different thread id",
                request_sent=True,
                safe_to_retry=False,
            )
        self._loaded_threads.add(resolved)
        return resolved

    async def fork_thread(
        self,
        thread_id: str,
        params: dict[str, Any] | None = None,
        *,
        last_turn_id: str | None = None,
    ) -> str:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        # The source itself is provider-owned even if it is currently unloaded.
        self._known_thread_ids.add(thread_id)
        source_lock = self._fork_source_locks.setdefault(
            thread_id,
            asyncio.Lock(),
        )
        async with source_lock:
            return await self._fork_thread_serialized(
                thread_id,
                params,
                last_turn_id=last_turn_id,
            )

    async def _fork_thread_serialized(
        self,
        thread_id: str,
        params: dict[str, Any] | None,
        *,
        last_turn_id: str | None,
    ) -> str:
        payload = dict(params or {})
        payload["threadId"] = thread_id
        payload.setdefault("excludeTurns", True)
        if last_turn_id is not None:
            payload["lastTurnId"] = last_turn_id
        expected_cwd = str(payload.get("cwd") or "").strip()
        fork_started_at = int(time.time())
        late_children: asyncio.Queue[str] = asyncio.Queue()
        queued_late_children: set[str] = set()

        def watch_started_fork(notification: dict[str, Any]) -> None:
            if notification.get("method") != "thread/started":
                return
            notification_params = notification.get("params")
            thread = (
                notification_params.get("thread")
                if isinstance(notification_params, dict)
                else None
            )
            if not isinstance(thread, dict):
                return
            child_id = str(thread.get("id") or "").strip()
            forked_from_id = str(thread.get("forkedFromId") or "").strip()
            child_cwd = str(thread.get("cwd") or "").strip()
            created_at = thread.get("createdAt")
            if (
                child_id
                and child_id != thread_id
                and forked_from_id == thread_id
                and child_id not in self._known_thread_ids
                and child_id not in queued_late_children
                # Destructive cleanup requires request-local evidence. An old
                # fork resumed after an app-server reconnect can share the same
                # ancestry but cannot share this creation window.
                and expected_cwd
                and child_cwd == expected_cwd
                and isinstance(created_at, int)
                and not isinstance(created_at, bool)
                and fork_started_at - 1 <= created_at <= int(time.time()) + 1
            ):
                queued_late_children.add(child_id)
                late_children.put_nowait(child_id)

        # This must be installed before the request is written. A fast provider
        # can announce the child before returning the JSON-RPC response.
        self.add_notification_handler(watch_started_fork)
        try:
            try:
                result = await self.request(
                    "thread/fork",
                    payload,
                    timeout=self.lifecycle_timeout,
                )
            except BaseException as exc:
                ambiguous = isinstance(
                    exc,
                    (asyncio.CancelledError, CodexAppServerTimeout),
                ) or (
                    isinstance(exc, CodexAppServerDisconnected)
                    and exc.request_sent
                )
                if ambiguous:
                    cleanup = asyncio.create_task(
                        self._delete_late_fork_child(late_children)
                    )
                    try:
                        unretired_thread_ids = await self._join_shielded_task(
                            cleanup
                        )
                    except BaseException:
                        # The timeout/cancellation is the actionable transport
                        # result. A cleanup failure before a child identity is
                        # known must not hide it.
                        pass
                    else:
                        if unretired_thread_ids:
                            # Preserve the original timeout/cancellation while
                            # handing the known provider identity to the owning
                            # layer for durable cleanup. A tuple prevents later
                            # mutation while the exception crosses task layers.
                            exc.unretired_fork_thread_ids = tuple(
                                unretired_thread_ids
                            )
                raise
        finally:
            self.remove_notification_handler(watch_started_fork)
        resolved = self._thread_id_from_result("thread/fork", result)
        self._known_thread_ids.add(resolved)
        if resolved == thread_id:
            raise CodexAppServerProtocolError(
                "thread/fork returned the source thread id",
                request_sent=True,
                safe_to_retry=False,
            )
        thread = result.get("thread") if isinstance(result, dict) else None
        forked_from_id = (
            thread.get("forkedFromId") if isinstance(thread, dict) else None
        )
        if forked_from_id is not None and forked_from_id != thread_id:
            error = CodexAppServerProtocolError(
                "thread/fork returned a thread with a different source id",
                request_sent=True,
                safe_to_retry=False,
            )
            cleanup = asyncio.create_task(self.delete_thread(resolved))
            try:
                await self._join_shielded_task(cleanup)
            except BaseException:
                # Preserve the ancestry violation even when an older provider
                # cannot delete the untrusted child.
                pass
            raise error
        self._loaded_threads.add(resolved)
        return resolved

    async def _delete_late_fork_child(
        self,
        late_children: asyncio.Queue[str],
    ) -> tuple[str, ...]:
        """Delete an announced child or return identities needing retirement."""

        try:
            child_id = await asyncio.wait_for(
                late_children.get(),
                timeout=self.fork_cleanup_grace,
            )
        except asyncio.TimeoutError:
            return ()
        # Drain notifications already routed in this event-loop turn. If more
        # than one request-correlated identity exists, ownership is ambiguous;
        # leak an unexposed provider fork rather than deleting user history.
        await asyncio.sleep(0)
        candidates = {child_id}
        while not late_children.empty():
            candidates.add(late_children.get_nowait())
        if len(candidates) != 1:
            return ()
        try:
            await self.delete_thread(child_id)
        except BaseException:
            return (child_id,)
        return ()

    @staticmethod
    async def _join_shielded_task(task: asyncio.Task[Any]) -> Any:
        """Join cleanup even if the caller receives repeated cancellation."""

        while True:
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                if task.done():
                    return task.result()

    @staticmethod
    def _thread_id_from_result(method: str, result: Any) -> str:
        thread = result.get("thread") if isinstance(result, dict) else None
        resolved = str(thread.get("id") or "") if isinstance(thread, dict) else ""
        if not resolved.strip():
            raise CodexAppServerProtocolError(
                f"{method} did not return a thread id",
                request_sent=True,
                safe_to_retry=False,
            )
        return resolved

    async def start_or_resume_thread(
        self,
        thread_id: str | None,
        start_params: dict[str, Any],
        resume_params: dict[str, Any] | None = None,
    ) -> str:
        if thread_id:
            return await self.resume_thread(
                thread_id,
                resume_params if resume_params is not None else start_params,
            )
        return await self.start_thread(start_params)

    async def inject_items(
        self,
        thread_id: str,
        items: list[dict[str, Any]],
    ) -> None:
        await self.request(
            "thread/inject_items",
            {"threadId": thread_id, "items": items},
        )

    async def read_thread(
        self,
        thread_id: str,
        *,
        include_turns: bool = False,
    ) -> dict[str, Any]:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        # A read is sufficient proof that the provider identity predates any
        # concurrent fork watcher, regardless of current load state.
        self._known_thread_ids.add(thread_id)
        result = await self.request(
            "thread/read",
            {"threadId": thread_id, "includeTurns": include_turns},
        )
        thread = result.get("thread") if isinstance(result, dict) else None
        returned_thread_id = (
            str(thread.get("id") or "").strip()
            if isinstance(thread, dict)
            else ""
        )
        if returned_thread_id:
            self._known_thread_ids.add(returned_thread_id)
        if not isinstance(thread, dict) or returned_thread_id != thread_id:
            raise CodexAppServerProtocolError(
                "thread/read did not return the requested thread",
                request_sent=True,
                safe_to_retry=False,
            )
        return thread

    async def delete_thread(self, thread_id: str) -> None:
        """Permanently remove a newly-created, unexposed provider thread."""
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        method = "thread/delete"
        _protocol_empty_object(
            method,
            await self.request(
                method,
                {"threadId": thread_id},
                timeout=self.lifecycle_timeout,
            ),
        )
        self._loaded_threads.discard(thread_id)
        self._known_thread_ids.discard(thread_id)

    async def list_turns(
        self,
        thread_id: str,
        *,
        limit: int = 4,
        items_view: str = "full",
        sort_direction: str = "desc",
    ) -> list[dict[str, Any]]:
        result = await self.request(
            "thread/turns/list",
            {
                "threadId": thread_id,
                "limit": max(1, int(limit)),
                "itemsView": items_view,
                "sortDirection": sort_direction,
            },
        )
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, list):
            raise CodexAppServerProtocolError(
                "thread/turns/list did not return a turn list",
                request_sent=True,
                safe_to_retry=False,
            )
        return [turn for turn in data if isinstance(turn, dict)]

    async def list_descendant_threads(
        self,
        thread_id: str,
        *,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """Return every persisted subagent descendant of ``thread_id``.

        Relationship filters are part of app-server's experimental API. The
        client enables that capability during initialization, so using the
        ancestor filter is both cheaper and more accurate than reconstructing
        the spawn tree from transcript items.
        """

        thread_id = _require_nonempty_string(thread_id, "thread_id")
        if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size < 1:
            raise ValueError("page_size must be a positive integer")

        method = "thread/list"
        descendants: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            params: dict[str, Any] = {
                "ancestorThreadId": thread_id,
                "limit": page_size,
                "useStateDbOnly": True,
                # Relationship-filtered requests must opt into subagent source
                # kinds. The ordinary omitted/default source filter is limited
                # to interactive threads on older app-server releases.
                "sourceKinds": [
                    "subAgent",
                    "subAgentReview",
                    "subAgentCompact",
                    "subAgentThreadSpawn",
                    "subAgentOther",
                ],
            }
            if cursor is not None:
                params["cursor"] = cursor
            result = _protocol_object(method, await self.request(method, params))
            data = result.get("data")
            if not isinstance(data, list):
                raise CodexAppServerProtocolError(
                    f"{method} did not return a thread list",
                    request_sent=True,
                    safe_to_retry=False,
                )
            for thread in data:
                if not isinstance(thread, dict) or not str(thread.get("id") or "").strip():
                    raise CodexAppServerProtocolError(
                        f"{method} returned an invalid thread",
                        request_sent=True,
                        safe_to_retry=False,
                    )
                self._known_thread_ids.add(str(thread["id"]).strip())
                descendants.append(dict(thread))

            cursor = _protocol_cursor(method, result)
            if cursor is None:
                return descendants
            if cursor in seen_cursors:
                raise CodexAppServerProtocolError(
                    f"{method} repeated a pagination cursor",
                    request_sent=True,
                    safe_to_retry=False,
                )
            seen_cursors.add(cursor)

    async def list_permission_profiles(
        self,
        *,
        cwd: str | None = None,
        page_size: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return every selectable permission profile across cursor pages."""

        if cwd is not None:
            _require_nonempty_string(cwd, "cwd")
        if page_size is not None and (
            isinstance(page_size, bool)
            or not isinstance(page_size, int)
            or page_size < 1
        ):
            raise ValueError("page_size must be a positive integer")

        profiles: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            params: dict[str, Any] = {}
            if cwd is not None:
                params["cwd"] = cwd
            if page_size is not None:
                params["limit"] = page_size
            if cursor is not None:
                params["cursor"] = cursor

            method = "permissionProfile/list"
            result = _protocol_object(method, await self.request(method, params))
            data = result.get("data")
            if not isinstance(data, list):
                raise CodexAppServerProtocolError(
                    f"{method} did not return a profile list",
                    request_sent=True,
                    safe_to_retry=False,
                )
            for profile in data:
                if not isinstance(profile, dict):
                    raise CodexAppServerProtocolError(
                        f"{method} returned a non-object profile",
                        request_sent=True,
                        safe_to_retry=False,
                    )
                profile_id = profile.get("id")
                allowed = profile.get("allowed")
                description = profile.get("description")
                if not isinstance(profile_id, str) or not profile_id:
                    raise CodexAppServerProtocolError(
                        f"{method} returned a profile without an id",
                        request_sent=True,
                        safe_to_retry=False,
                    )
                if not isinstance(allowed, bool) or (
                    description is not None and not isinstance(description, str)
                ):
                    raise CodexAppServerProtocolError(
                        f"{method} returned an invalid profile",
                        request_sent=True,
                        safe_to_retry=False,
                    )
                profiles.append(dict(profile))

            cursor = _protocol_cursor(method, result)
            if cursor is None:
                return profiles
            if cursor in seen_cursors:
                raise CodexAppServerProtocolError(
                    f"{method} repeated a pagination cursor",
                    request_sent=True,
                    safe_to_retry=False,
                )
            seen_cursors.add(cursor)

    async def set_thread_goal(
        self,
        thread_id: str,
        *,
        objective: str | None | _OmittedType = _OMITTED,
        status: str | None | _OmittedType = _OMITTED,
        token_budget: int | None | _OmittedType = _OMITTED,
    ) -> dict[str, Any]:
        """Set or update the native persisted goal for a thread."""

        thread_id = _require_nonempty_string(thread_id, "thread_id")
        params: dict[str, Any] = {"threadId": thread_id}
        if objective is not _OMITTED:
            if objective is not None:
                if not isinstance(objective, str) or not objective.strip():
                    raise ValueError("objective must be a non-empty string")
                if len(objective) > 4000:
                    raise ValueError("objective must be at most 4000 characters")
            params["objective"] = objective
        if status is not _OMITTED:
            if status is not None and status not in _THREAD_GOAL_STATUSES:
                raise ValueError(f"invalid thread goal status: {status}")
            params["status"] = status
        if token_budget is not _OMITTED:
            if token_budget is not None and (
                isinstance(token_budget, bool) or not isinstance(token_budget, int)
            ):
                raise ValueError("token_budget must be an integer or null")
            params["tokenBudget"] = token_budget

        method = "thread/goal/set"
        result = _protocol_object(method, await self.request(method, params))
        return _protocol_thread_goal(
            method,
            result.get("goal"),
            thread_id=thread_id,
        )

    async def get_thread_goal(self, thread_id: str) -> dict[str, Any] | None:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        method = "thread/goal/get"
        result = _protocol_object(
            method,
            await self.request(method, {"threadId": thread_id}),
        )
        goal = result.get("goal")
        if goal is None:
            return None
        return _protocol_thread_goal(method, goal, thread_id=thread_id)

    async def clear_thread_goal(self, thread_id: str) -> bool:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        method = "thread/goal/clear"
        result = _protocol_object(
            method,
            await self.request(method, {"threadId": thread_id}),
        )
        cleared = result.get("cleared")
        if not isinstance(cleared, bool):
            raise CodexAppServerProtocolError(
                f"{method} did not return a cleared flag",
                request_sent=True,
                safe_to_retry=False,
            )
        return cleared

    async def compact_thread(self, thread_id: str) -> None:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        method = "thread/compact/start"
        _protocol_empty_object(
            method,
            await self.request(method, {"threadId": thread_id}),
        )

    async def rollback_thread(
        self,
        thread_id: str,
        *,
        num_turns: int,
    ) -> dict[str, Any]:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        if (
            isinstance(num_turns, bool)
            or not isinstance(num_turns, int)
            or num_turns < 1
        ):
            raise ValueError("num_turns must be a positive integer")
        method = "thread/rollback"
        result = _protocol_object(
            method,
            await self.request(
                method,
                {"threadId": thread_id, "numTurns": num_turns},
                timeout=self.lifecycle_timeout,
            ),
        )
        thread = result.get("thread")
        if not isinstance(thread, dict) or thread.get("id") != thread_id:
            raise CodexAppServerProtocolError(
                f"{method} did not return the requested thread",
                request_sent=True,
                safe_to_retry=False,
            )
        return dict(thread)

    async def start_review(
        self,
        thread_id: str,
        target: dict[str, Any],
        *,
        delivery: str = "inline",
    ) -> dict[str, Any]:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        if delivery not in _REVIEW_DELIVERIES:
            raise ValueError(f"invalid review delivery: {delivery}")
        if not isinstance(target, dict):
            raise ValueError("review target must be an object")
        review_target = dict(target)
        target_type = review_target.get("type")
        if target_type not in _REVIEW_TARGET_TYPES:
            raise ValueError(f"invalid review target type: {target_type}")
        if target_type == "baseBranch":
            _require_nonempty_string(review_target.get("branch"), "target.branch")
        elif target_type == "commit":
            _require_nonempty_string(review_target.get("sha"), "target.sha")
            title = review_target.get("title")
            if title is not None and not isinstance(title, str):
                raise ValueError("target.title must be a string or null")
        elif target_type == "custom":
            _require_nonempty_string(
                review_target.get("instructions"),
                "target.instructions",
            )

        method = "review/start"
        result = _protocol_object(
            method,
            await self.request(
                method,
                {
                    "threadId": thread_id,
                    "target": review_target,
                    "delivery": delivery,
                },
                timeout=self.lifecycle_timeout,
            ),
        )
        review_thread_id = result.get("reviewThreadId")
        if not isinstance(review_thread_id, str) or not review_thread_id:
            raise CodexAppServerProtocolError(
                f"{method} did not return a review thread id",
                request_sent=True,
                safe_to_retry=False,
            )
        if delivery == "inline" and review_thread_id != thread_id:
            raise CodexAppServerProtocolError(
                f"{method} returned a detached thread for an inline review",
                request_sent=True,
                safe_to_retry=False,
            )
        validated = dict(result)
        validated["turn"] = _protocol_turn(method, result.get("turn"))
        return validated

    async def run_thread_shell_command(self, thread_id: str, command: str) -> None:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        command = _require_nonempty_string(command, "command")
        method = "thread/shellCommand"
        _protocol_empty_object(
            method,
            await self.request(
                method,
                {"threadId": thread_id, "command": command},
            ),
        )

    async def list_background_terminals(
        self,
        thread_id: str,
        *,
        page_size: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return every live background terminal across cursor pages."""

        thread_id = _require_nonempty_string(thread_id, "thread_id")
        if page_size is not None and (
            isinstance(page_size, bool)
            or not isinstance(page_size, int)
            or page_size < 1
        ):
            raise ValueError("page_size must be a positive integer")

        method = "thread/backgroundTerminals/list"
        terminals: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            params: dict[str, Any] = {"threadId": thread_id}
            if page_size is not None:
                params["limit"] = page_size
            if cursor is not None:
                params["cursor"] = cursor
            result = _protocol_object(method, await self.request(method, params))
            data = result.get("data")
            if not isinstance(data, list):
                raise CodexAppServerProtocolError(
                    f"{method} did not return a terminal list",
                    request_sent=True,
                    safe_to_retry=False,
                )
            for terminal in data:
                if not isinstance(terminal, dict):
                    raise CodexAppServerProtocolError(
                        f"{method} returned a non-object terminal",
                        request_sent=True,
                        safe_to_retry=False,
                    )
                for field in ("itemId", "processId", "command", "cwd"):
                    if not isinstance(terminal.get(field), str):
                        raise CodexAppServerProtocolError(
                            f"{method} returned a terminal with invalid {field}",
                            request_sent=True,
                            safe_to_retry=False,
                        )
                for field in ("osPid", "rssKb"):
                    value = terminal.get(field)
                    if value is not None and (
                        isinstance(value, bool) or not isinstance(value, int)
                    ):
                        raise CodexAppServerProtocolError(
                            f"{method} returned a terminal with invalid {field}",
                            request_sent=True,
                            safe_to_retry=False,
                        )
                cpu_percent = terminal.get("cpuPercent")
                if cpu_percent is not None and (
                    isinstance(cpu_percent, bool)
                    or not isinstance(cpu_percent, (int, float))
                ):
                    raise CodexAppServerProtocolError(
                        f"{method} returned a terminal with invalid cpuPercent",
                        request_sent=True,
                        safe_to_retry=False,
                    )
                terminals.append(dict(terminal))

            cursor = _protocol_cursor(method, result)
            if cursor is None:
                return terminals
            if cursor in seen_cursors:
                raise CodexAppServerProtocolError(
                    f"{method} repeated a pagination cursor",
                    request_sent=True,
                    safe_to_retry=False,
                )
            seen_cursors.add(cursor)

    async def terminate_background_terminal(
        self,
        thread_id: str,
        process_id: str,
    ) -> bool:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        process_id = _require_nonempty_string(process_id, "process_id")
        method = "thread/backgroundTerminals/terminate"
        result = _protocol_object(
            method,
            await self.request(
                method,
                {"threadId": thread_id, "processId": process_id},
            ),
        )
        terminated = result.get("terminated")
        if not isinstance(terminated, bool):
            raise CodexAppServerProtocolError(
                f"{method} did not return a terminated flag",
                request_sent=True,
                safe_to_retry=False,
            )
        return terminated

    async def clean_background_terminals(self, thread_id: str) -> None:
        thread_id = _require_nonempty_string(thread_id, "thread_id")
        method = "thread/backgroundTerminals/clean"
        _protocol_empty_object(
            method,
            await self.request(method, {"threadId": thread_id}),
        )

    async def unsubscribe_thread(self, thread_id: str) -> str:
        result = await self.request("thread/unsubscribe", {"threadId": thread_id})
        status = str(result.get("status") or "") if isinstance(result, dict) else ""
        if status not in {"notLoaded", "notSubscribed", "unsubscribed"}:
            raise CodexAppServerProtocolError(
                "thread/unsubscribe returned an invalid status",
                request_sent=True,
                safe_to_retry=False,
            )
        self._loaded_threads.discard(thread_id)
        self._finish_scoped_subscriptions(
            thread_id,
            include_thread_subscription=True,
        )
        return status

    async def steer_turn(
        self,
        thread_id: str,
        turn_id: str,
        input_items: list[dict[str, Any]],
        *,
        client_user_message_id: str | None = None,
    ) -> str:
        params: dict[str, Any] = {
            "threadId": thread_id,
            "expectedTurnId": turn_id,
            "input": input_items,
        }
        if client_user_message_id:
            params["clientUserMessageId"] = client_user_message_id
        result = await self.request("turn/steer", params)
        resolved = str(result.get("turnId") or "") if isinstance(result, dict) else ""
        if resolved != turn_id:
            raise CodexAppServerProtocolError(
                f"turn/steer returned unexpected turn id {resolved or '<missing>'}",
                request_sent=True,
                safe_to_retry=False,
            )
        return resolved

    async def steer_turn_with_notification_watermark(
        self,
        thread_id: str,
        turn_id: str,
        input_items: list[dict[str, Any]],
        *,
        client_user_message_id: str | None = None,
        notification_subscription: CodexAppServerSubscription | None = None,
    ) -> tuple[str, int]:
        """Return the exact receive-order boundary of the steer response.

        Notifications at or below the watermark were read before app-server's
        steer acknowledgement and therefore belong to the preceding logical
        AgentsDock run. Later notifications belong to the steered run.
        """
        params: dict[str, Any] = {
            "threadId": thread_id,
            "expectedTurnId": turn_id,
            "input": input_items,
        }
        if client_user_message_id:
            params["clientUserMessageId"] = client_user_message_id
        if notification_subscription is None:
            active_turn = self._turns_by_thread.get(thread_id)
            if active_turn is not None and active_turn.turn_id == turn_id:
                notification_subscription = active_turn._subscription
        if notification_subscription is None:
            raise CodexAppServerProtocolError(
                "turn/steer notification stream is unavailable",
                request_sent=False,
                safe_to_retry=True,
            )
        await self.start()
        response = await self._request_connected(
            "turn/steer",
            params,
            notification_boundary_subscription=notification_subscription,
        )
        if (
            not isinstance(response, tuple)
            or len(response) != 2
            or not isinstance(response[1], int)
        ):
            raise CodexAppServerProtocolError(
                "turn/steer did not return a notification watermark",
                request_sent=True,
                safe_to_retry=False,
            )
        result, watermark = response
        resolved = str(result.get("turnId") or "") if isinstance(result, dict) else ""
        if resolved != turn_id:
            raise CodexAppServerProtocolError(
                f"turn/steer returned unexpected turn id {resolved or '<missing>'}",
                request_sent=True,
                safe_to_retry=False,
            )
        return resolved, watermark

    async def interrupt_turn(self, thread_id: str, turn_id: str) -> None:
        await self.request(
            "turn/interrupt",
            {"threadId": thread_id, "turnId": turn_id},
        )

    async def start_turn(
        self,
        thread_id: str,
        input_items: list[dict[str, Any]],
        *,
        overrides: dict[str, Any] | None = None,
    ) -> CodexAppServerTurn:
        # Initialize before installing the provisional turn subscription.
        # Otherwise the first lazy start would correctly discard it as stale
        # transport state.
        await self.start()
        if thread_id in self._turns_by_thread:
            raise CodexAppServerError(
                f"thread {thread_id} already has an active app-server turn"
            )

        subscription = self.subscribe(thread_id=thread_id)
        provisional = CodexAppServerTurn(self, thread_id, "", subscription)
        self._turns_by_thread[thread_id] = provisional

        params = dict(overrides or {})
        params["threadId"] = thread_id
        params["input"] = input_items
        try:
            result = await self._request_connected(
                "turn/start",
                params,
                transport_turn=provisional,
            )
            turn = result.get("turn") if isinstance(result, dict) else None
            turn_id = str(turn.get("id") or "") if isinstance(turn, dict) else ""
            if not turn_id:
                raise CodexAppServerProtocolError(
                    "turn/start did not return a turn id",
                    request_sent=True,
                    safe_to_retry=False,
                )
            if provisional.turn_id and provisional.turn_id != turn_id:
                raise CodexAppServerProtocolError(
                    "turn/start response did not match its early notifications",
                    request_sent=True,
                    safe_to_retry=False,
                )
            provisional.turn_id = turn_id
            provisional._subscription.turn_id = turn_id
            return provisional
        except asyncio.CancelledError as exc:
            # turn/start may already have reached app-server. Transfer the
            # provisional handle to the owning runner so its cancellation
            # cleanup can interrupt/release it instead of leaving this thread
            # permanently occupied in _turns_by_thread.
            if self._turns_by_thread.get(thread_id) is provisional:
                exc.pending_turn = provisional
            else:
                provisional._subscription._finish()
            raise
        except CodexAppServerError as exc:
            if not exc.safe_to_retry:
                exc.pending_turn = provisional
                # A timeout can race the acceptance response.  Keep the
                # provisional subscription alive so later notifications can
                # bind the real turn id and prove acceptance.
                if self._turns_by_thread.get(thread_id) is provisional:
                    raise
            if self._turns_by_thread.get(thread_id) is provisional:
                self._turns_by_thread.pop(thread_id, None)
            provisional._subscription._finish()
            raise
        except Exception:
            if self._turns_by_thread.get(thread_id) is provisional:
                self._turns_by_thread.pop(thread_id, None)
            provisional._subscription._finish()
            raise

    def release_turn(self, turn: CodexAppServerTurn) -> None:
        if self._turns_by_thread.get(turn.thread_id) is turn:
            self._turns_by_thread.pop(turn.thread_id, None)
        turn._subscription._finish()

    def active_turn(self, thread_id: str) -> CodexAppServerTurn | None:
        return self._turns_by_thread.get(thread_id)


class CodexAppServerManager:
    """Lifecycle façade owning exactly one lazy shared app-server client."""

    def __init__(
        self,
        codex_bin: str,
        *,
        cwd: str,
        env_factory: Callable[[], dict[str, str]],
        app_server_args: Sequence[str] = (),
        request_timeout: float = 30.0,
        lifecycle_timeout: float = 300.0,
        process_stream_limit: int = 16 * 1024 * 1024,
        notification_queue_limit: int = 8192,
        json_parse_thread_threshold: int = 1024 * 1024,
        process_factory: ProcessFactory | None = None,
        server_request_handler: ServerRequestHandler | None = None,
        initialize_params: dict[str, Any] | None = None,
        on_process_started: ProcessLifecycleHook | None = None,
        on_process_exited: ProcessLifecycleHook | None = None,
    ) -> None:
        self.client = CodexAppServerClient(
            codex_bin,
            cwd=cwd,
            env_factory=env_factory,
            app_server_args=app_server_args,
            request_timeout=request_timeout,
            lifecycle_timeout=lifecycle_timeout,
            process_stream_limit=process_stream_limit,
            notification_queue_limit=notification_queue_limit,
            json_parse_thread_threshold=json_parse_thread_threshold,
            process_factory=process_factory,
            server_request_handler=server_request_handler,
            initialize_params=initialize_params,
            on_process_started=on_process_started,
            on_process_exited=on_process_exited,
        )

    @property
    def ready(self) -> bool:
        return self.client.ready

    @property
    def process(self) -> asyncio.subprocess.Process | None:
        return self.client.process

    @property
    def generation(self) -> int:
        return self.client.generation

    def is_thread_loaded(self, thread_id: str) -> bool:
        return self.client.is_thread_loaded(thread_id)

    async def start(self) -> None:
        await self.client.start()

    async def close(self) -> None:
        await self.client.close()

    async def retire_generation(self, expected_generation: int) -> bool:
        return await self.client.retire_generation(expected_generation)

    async def __aenter__(self) -> "CodexAppServerManager":
        await self.start()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    def subscribe_thread(self, thread_id: str) -> CodexAppServerSubscription:
        return self.client.subscribe_thread(thread_id)

    def subscribe_turn(
        self,
        thread_id: str,
        turn_id: str,
    ) -> CodexAppServerSubscription:
        return self.client.subscribe_turn(thread_id, turn_id)

    def add_notification_handler(self, handler: NotificationHandler) -> None:
        self.client.add_notification_handler(handler)

    def remove_notification_handler(self, handler: NotificationHandler) -> None:
        self.client.remove_notification_handler(handler)

    async def wait_for_notification_handler(
        self,
        handler: NotificationHandler,
        thread_id: str,
    ) -> None:
        await self.client.wait_for_notification_handler(handler, thread_id)

    async def request(
        self,
        method: str,
        params: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> Any:
        return await self.client.request(method, params, timeout=timeout)

    async def notify(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> None:
        await self.client.notify(method, params)

    async def start_thread(self, params: dict[str, Any]) -> str:
        return await self.client.start_thread(params)

    async def resume_thread(
        self,
        thread_id: str,
        params: dict[str, Any] | None = None,
    ) -> str:
        return await self.client.resume_thread(thread_id, params)

    async def start_or_resume_thread(
        self,
        thread_id: str | None,
        start_params: dict[str, Any],
        resume_params: dict[str, Any] | None = None,
    ) -> str:
        return await self.client.start_or_resume_thread(
            thread_id,
            start_params,
            resume_params,
        )

    async def fork_thread(
        self,
        thread_id: str,
        params: dict[str, Any] | None = None,
        *,
        last_turn_id: str | None = None,
    ) -> str:
        return await self.client.fork_thread(
            thread_id,
            params,
            last_turn_id=last_turn_id,
        )

    async def inject_items(
        self,
        thread_id: str,
        items: list[dict[str, Any]],
    ) -> None:
        await self.client.inject_items(thread_id, items)

    async def read_thread(
        self,
        thread_id: str,
        *,
        include_turns: bool = False,
    ) -> dict[str, Any]:
        return await self.client.read_thread(
            thread_id,
            include_turns=include_turns,
        )

    async def delete_thread(self, thread_id: str) -> None:
        await self.client.delete_thread(thread_id)

    async def list_turns(
        self,
        thread_id: str,
        *,
        limit: int = 4,
        items_view: str = "full",
        sort_direction: str = "desc",
    ) -> list[dict[str, Any]]:
        return await self.client.list_turns(
            thread_id,
            limit=limit,
            items_view=items_view,
            sort_direction=sort_direction,
        )

    async def list_descendant_threads(
        self,
        thread_id: str,
        *,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        return await self.client.list_descendant_threads(
            thread_id,
            page_size=page_size,
        )

    async def list_permission_profiles(
        self,
        *,
        cwd: str | None = None,
        page_size: int | None = None,
    ) -> list[dict[str, Any]]:
        return await self.client.list_permission_profiles(
            cwd=cwd,
            page_size=page_size,
        )

    async def set_thread_goal(
        self,
        thread_id: str,
        *,
        objective: str | None | _OmittedType = _OMITTED,
        status: str | None | _OmittedType = _OMITTED,
        token_budget: int | None | _OmittedType = _OMITTED,
    ) -> dict[str, Any]:
        return await self.client.set_thread_goal(
            thread_id,
            objective=objective,
            status=status,
            token_budget=token_budget,
        )

    async def get_thread_goal(self, thread_id: str) -> dict[str, Any] | None:
        return await self.client.get_thread_goal(thread_id)

    async def clear_thread_goal(self, thread_id: str) -> bool:
        return await self.client.clear_thread_goal(thread_id)

    async def compact_thread(self, thread_id: str) -> None:
        await self.client.compact_thread(thread_id)

    async def rollback_thread(
        self,
        thread_id: str,
        *,
        num_turns: int,
    ) -> dict[str, Any]:
        return await self.client.rollback_thread(thread_id, num_turns=num_turns)

    async def start_review(
        self,
        thread_id: str,
        target: dict[str, Any],
        *,
        delivery: str = "inline",
    ) -> dict[str, Any]:
        return await self.client.start_review(
            thread_id,
            target,
            delivery=delivery,
        )

    async def run_thread_shell_command(self, thread_id: str, command: str) -> None:
        await self.client.run_thread_shell_command(thread_id, command)

    async def list_background_terminals(
        self,
        thread_id: str,
        *,
        page_size: int | None = None,
    ) -> list[dict[str, Any]]:
        return await self.client.list_background_terminals(
            thread_id,
            page_size=page_size,
        )

    async def terminate_background_terminal(
        self,
        thread_id: str,
        process_id: str,
    ) -> bool:
        return await self.client.terminate_background_terminal(thread_id, process_id)

    async def clean_background_terminals(self, thread_id: str) -> None:
        await self.client.clean_background_terminals(thread_id)

    async def unsubscribe_thread(self, thread_id: str) -> str:
        return await self.client.unsubscribe_thread(thread_id)

    async def start_turn(
        self,
        thread_id: str,
        input_items: list[dict[str, Any]],
        *,
        overrides: dict[str, Any] | None = None,
    ) -> CodexAppServerTurn:
        return await self.client.start_turn(
            thread_id,
            input_items,
            overrides=overrides,
        )

    async def steer_turn(
        self,
        thread_id: str,
        turn_id: str,
        input_items: list[dict[str, Any]],
        *,
        client_user_message_id: str | None = None,
    ) -> str:
        return await self.client.steer_turn(
            thread_id,
            turn_id,
            input_items,
            client_user_message_id=client_user_message_id,
        )

    async def interrupt_turn(self, thread_id: str, turn_id: str) -> None:
        await self.client.interrupt_turn(thread_id, turn_id)

    def active_turn(self, thread_id: str) -> CodexAppServerTurn | None:
        return self.client.active_turn(thread_id)
