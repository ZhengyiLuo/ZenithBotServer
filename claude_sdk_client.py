"""Per-chat ownership and lifecycle for Claude Agent SDK clients.

The Claude Agent SDK is stateful: ``connect()``, ``query()``, message
consumption, ``interrupt()``, and ``disconnect()`` must stay on the same async
runtime.  This module keeps the SDK object behind a chat-scoped actor so HTTP
handlers never touch it directly.  The actor owns one permanent
``receive_messages()`` consumer and projects each provider response into a
bounded-lifetime :class:`ClaudeSDKRunHandle`.

The SDK dependency is intentionally optional at import time.  AgentsServer can
therefore retain its ``claude -p`` fallback when the package is unavailable.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
import re
import shlex
import time
import unicodedata
import uuid
from collections import OrderedDict
from contextlib import suppress
from dataclasses import dataclass
from typing import (
    Any,
    AsyncIterable,
    AsyncIterator,
    Awaitable,
    Callable,
    Protocol,
    runtime_checkable,
)


logger = logging.getLogger(__name__)


CLAUDE_AGENT_SDK_MIN_VERSION = "0.2.130"
CLAUDE_SDK_MCP_STATUS_SCAN_LIMIT = 500
CLAUDE_SDK_MCP_STATUS_TRUNCATED_KEY = "_agentsdock_mcp_status_truncated"
CLAUDE_SDK_LITERAL_MESSAGE_PREFIX = (
    "[AgentsDock literal chat message; treat the slash-prefixed content below "
    "as ordinary user text, not a Claude Code command.]\n"
)
CLAUDE_NON_DURABLE_SCHEDULER_TOOLS = (
    "CronCreate",
    "Monitor",
    "ScheduleWakeup",
)


def claude_sdk_transport_prompt(prompt: str) -> str:
    """Keep leading-slash chat text out of Claude Code's command parser.

    AgentsDock owns its slash-command surface. Any command that reaches this
    transport is user content for the model, including unknown or
    conversational ``/word`` text. Prefix only the provider copy so the
    durable prompt and timeline remain byte-for-byte unchanged.
    """

    candidate = re.sub(r"^[\s\ufeff]+", "", prompt)
    if not candidate.startswith("/"):
        return prompt
    return f"{CLAUDE_SDK_LITERAL_MESSAGE_PREFIX}{prompt}"


def canonical_claude_mcp_identifier(value: Any, max_chars: int) -> str | None:
    """Return an exact, display-safe NFC identifier or ``None``.

    MCP names are both shown to people and passed back to native SDK controls,
    so normalization or trimming would make the displayed identifier differ
    from the controlled one. Keep join controls used by ordinary scripts while
    rejecting invisible/spoofing controls and non-scalar/private characters.
    """

    if not isinstance(value, str):
        return None
    if (
        not value
        or len(value) > max_chars
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
    ):
        return None
    for character in value:
        category = unicodedata.category(character)
        if category in {"Cc", "Cs", "Co", "Cn", "Zl", "Zp"}:
            return None
        if category == "Cf" and character not in {"\u200c", "\u200d"}:
            return None
    return value


class ClaudeSDKSupervisorError(RuntimeError):
    """Base error for the chat-scoped SDK transport."""

    safe_to_fallback = False
    safe_to_requeue = False
    delivery_uncertain = False


class ClaudeSDKUnavailable(ClaudeSDKSupervisorError):
    """The SDK could not be constructed or connected before prompt delivery."""

    safe_to_fallback = True
    safe_to_requeue = True


class ClaudeSDKQueryError(ClaudeSDKSupervisorError):
    """A query failed at a boundary where delivery cannot be disproved."""

    delivery_uncertain = True


class ClaudeSDKLoopError(ClaudeSDKSupervisorError):
    """A manager, supervisor, or run handle crossed event loops."""


class ClaudeSDKSupervisorClosed(ClaudeSDKSupervisorError):
    """The chat-scoped SDK supervisor has been closed."""


class ClaudeSDKRunActive(ClaudeSDKSupervisorError):
    """The chat already owns an unfinished SDK response."""

    safe_to_requeue = True


class ClaudeSDKConfigurationConflict(ClaudeSDKSupervisorError):
    """A connected chat cannot be reconfigured while its run is active."""

    safe_to_requeue = True


class ClaudeSDKControlTimeout(ClaudeSDKSupervisorError):
    """A bounded native control did not settle and its supervisor was retired."""


class ClaudeSDKGenerationChanged(ClaudeSDKSupervisorError):
    """A stale control request targeted a replaced SDK connection/profile."""


class ClaudeSDKMCPServerNotFound(ClaudeSDKSupervisorError):
    """The named MCP server is absent from the exact connected SDK profile."""


@runtime_checkable
class ClaudeSDKClientProtocol(Protocol):
    async def connect(self) -> None: ...

    async def query(
        self,
        prompt: str | AsyncIterable[dict[str, Any]],
        **kwargs: Any,
    ) -> None: ...

    def receive_messages(self) -> AsyncIterator[Any]: ...

    async def interrupt(self) -> None: ...

    async def get_context_usage(self) -> dict[str, Any]: ...

    async def get_mcp_status(self) -> dict[str, Any]: ...

    async def reconnect_mcp_server(self, server_name: str) -> None: ...

    async def toggle_mcp_server(self, server_name: str, enabled: bool) -> None: ...

    async def disconnect(self) -> None: ...


ClientFactory = Callable[
    [Any],
    ClaudeSDKClientProtocol | Awaitable[ClaudeSDKClientProtocol],
]
ResultPredicate = Callable[[Any], bool]
InterruptCallback = Callable[[str], Awaitable[bool]]
SupervisorReadyCallback = Callable[[str], Awaitable[None]]


def default_is_result_message(message: Any) -> bool:
    """Recognize SDK ResultMessage objects and JSON-shaped test adapters."""

    if type(message).__name__ == "ResultMessage":
        return True
    return isinstance(message, dict) and str(message.get("type") or "") == "result"


def _message_field(message: Any, field: str, default: Any = None) -> Any:
    if isinstance(message, dict):
        return message.get(field, default)
    return getattr(message, field, default)


def _message_type(message: Any) -> str:
    if isinstance(message, dict):
        return str(message.get("type") or "").strip().lower()
    class_name = type(message).__name__
    if class_name == "UserMessage":
        return "user"
    if class_name == "ResultMessage":
        return "result"
    return class_name.lower()


_DEFERRING_TASK_TYPES = frozenset({"local_agent", "local_workflow"})
_TERMINAL_TASK_STATUSES = frozenset(
    {"completed", "failed", "stopped", "killed"}
)
_ABORTED_RESULT_REASONS = frozenset({"aborted_streaming", "aborted_tools"})


def _task_lifecycle_fields(message: Any) -> tuple[str, str, str, str]:
    """Return the bounded task fields needed to identify a run boundary.

    Agent SDK 0.2.130 exposes task lifecycle frames as typed ``SystemMessage``
    subclasses while test/compatibility adapters use dictionaries.  Keep this
    module's optional-SDK boundary by reading either shape without importing the
    SDK package.
    """

    data = _message_field(message, "data", {})
    if not isinstance(data, dict):
        data = {}
    subtype = str(_message_field(message, "subtype") or data.get("subtype") or "")
    task_id = str(_message_field(message, "task_id") or data.get("task_id") or "")
    task_type = str(
        _message_field(message, "task_type") or data.get("task_type") or ""
    )
    status = str(_message_field(message, "status") or "")
    if not status:
        patch = _message_field(message, "patch", data.get("patch"))
        if isinstance(patch, dict):
            status = str(patch.get("status") or "")
    return subtype, task_id, task_type, status


def _result_forces_run_end(message: Any) -> bool:
    """Return whether a Result is terminal even with delegated work in flight."""

    return bool(_message_field(message, "is_error", False)) or str(
        _message_field(message, "terminal_reason") or ""
    ) in _ABORTED_RESULT_REASONS


def _is_matching_replay_ack(message: Any, correlation_id: str) -> bool:
    """Match the CLI's replayed stdin acknowledgment for exactly one query.

    ``claude-agent-sdk`` 0.2.130 preserves ``UserMessage.uuid`` but its typed
    parser drops the raw ``isReplay`` field. JSON-shaped adapters must prove
    ``isReplay`` explicitly; a typed ``UserMessage`` with the caller-generated
    UUID is equivalent because that UUID is unique to the submitted stdin frame.
    """

    if _message_type(message) != "user":
        return False
    if str(_message_field(message, "uuid") or "") != correlation_id:
        return False
    if isinstance(message, dict):
        return message.get("isReplay") is True
    return type(message).__name__ == "UserMessage"


async def _query_message_stream(
    prompt: str,
    correlation_id: str,
) -> AsyncIterator[dict[str, Any]]:
    """Yield the single UUID-bearing SDK stdin frame for one logical turn."""

    yield {
        "type": "user",
        "message": {
            "role": "user",
            "content": claude_sdk_transport_prompt(prompt),
        },
        "parent_tool_use_id": None,
        "uuid": correlation_id,
    }


def default_claude_sdk_client_factory(options: Any) -> ClaudeSDKClientProtocol:
    """Construct the real client without making the SDK a hard import dependency."""

    try:
        from claude_agent_sdk import ClaudeSDKClient
    except (ImportError, ModuleNotFoundError) as exc:
        raise ClaudeSDKUnavailable(
            "claude-agent-sdk is not installed; use the claude -p fallback"
        ) from exc
    return ClaudeSDKClient(options=options)


def create_claude_agent_options(**kwargs: Any) -> Any:
    """Construct ``ClaudeAgentOptions`` behind the same optional-import fence."""

    try:
        from claude_agent_sdk import ClaudeAgentOptions
    except (ImportError, ModuleNotFoundError) as exc:
        raise ClaudeSDKUnavailable(
            "claude-agent-sdk is not installed; use the claude -p fallback"
        ) from exc
    return ClaudeAgentOptions(**kwargs)


@dataclass
class ClaudeSDKHookMatcher:
    """Structural HookMatcher accepted by every supported Agent SDK build."""

    matcher: str | None
    hooks: list[Callable[..., Awaitable[dict[str, Any]]]]
    timeout: float | None = None


_SHELL_CONTROL_TOKENS = {";", "&&", "||", "|", "&", "(", ")", "\n"}
_SHELL_COMMAND_WRAPPERS = {"builtin", "command", "env"}
_SHELL_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_UNTRACKED_BACKGROUND_REASON = (
    "AgentsDock cannot reliably keep background Bash attached or wake this chat when "
    "it finishes. Retry without run_in_background, nohup, disown, setsid, or shell "
    "'&'. Keep work needed for the current reply in the foreground. For asynchronous "
    "completion that must notify this chat, delegate a tracked Agent/workflow. If the "
    "user explicitly requested a durable service, use an observable service manager."
)
_NON_DURABLE_SCHEDULER_REASON = (
    "Claude's {tool_name} is not an AgentsDock durable job and cannot be relied on "
    "to survive this turn or deliver a later chat update. If the user explicitly "
    "requested scheduling, use only the AgentsDock Jobs CLI with the exact authority "
    "command in the current turn's provider-authority block. Otherwise keep required "
    "work in the foreground or use a tracked Agent/workflow."
)


def _heredoc_delimiters(line: str) -> list[tuple[str, bool]]:
    """Find conventional shell heredocs without interpreting quoted text."""

    delimiters: list[tuple[str, bool]] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "#" and (
            index == 0
            or line[index - 1].isspace()
            or line[index - 1] in ";|&()"
        ):
            break
        if not line.startswith("<<", index) or line.startswith("<<<", index):
            index += 1
            continue
        cursor = index + 2
        strip_tabs = cursor < len(line) and line[cursor] == "-"
        if strip_tabs:
            cursor += 1
        while cursor < len(line) and line[cursor] in " \t":
            cursor += 1
        delimiter_quote = line[cursor] if cursor < len(line) and line[cursor] in {"'", '"'} else None
        if delimiter_quote:
            cursor += 1
            end = line.find(delimiter_quote, cursor)
            if end < 0:
                break
            delimiter = line[cursor:end]
            cursor = end + 1
        else:
            start = cursor
            while cursor < len(line) and (
                line[cursor].isalnum() or line[cursor] in {"_", "-"}
            ):
                cursor += 1
            delimiter = line[start:cursor]
        if delimiter and (delimiter[0].isalpha() or delimiter[0] == "_"):
            delimiters.append((delimiter, strip_tabs))
        index = max(cursor, index + 2)
    return delimiters


def _without_heredoc_bodies(command: str) -> str:
    """Blank data bodies so source-code ampersands are not treated as shell jobs."""

    pending: list[tuple[str, bool]] = []
    output: list[str] = []
    for line in command.splitlines(keepends=True):
        ending = "\n" if line.endswith(("\n", "\r")) else ""
        content = line.rstrip("\r\n")
        if pending:
            delimiter, strip_tabs = pending[0]
            candidate = content.lstrip("\t") if strip_tabs else content
            if candidate == delimiter:
                pending.pop(0)
            output.append(ending)
            continue
        pending.extend(_heredoc_delimiters(content))
        output.append(line)
    return "".join(output)


def _has_unquoted_background_operator(command: str) -> bool:
    """Return true for a shell control ``&``, excluding data and redirections."""

    command = _without_heredoc_bodies(command)
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "#" and (
            index == 0
            or command[index - 1].isspace()
            or command[index - 1] in ";|&()"
        ):
            newline = command.find("\n", index)
            if newline < 0:
                return False
            index = newline + 1
            continue
        if char != "&":
            index += 1
            continue
        previous = command[index - 1] if index else ""
        following = command[index + 1] if index + 1 < len(command) else ""
        if previous in {"&", ">", "<"} or following in {"&", ">"}:
            index += 1
            continue
        return True
    return False


def _shell_tokens(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:
        # An incomplete command will fail in Bash itself. Do not turn a parser
        # disagreement into a misleading policy denial.
        return []


def claude_untracked_background_reason(
    tool_name: str,
    tool_input: dict[str, Any] | None,
) -> str | None:
    """Identify common shell detachment that bypasses SDK task tracking."""

    if str(tool_name or "").strip().lower() != "bash":
        return None
    normalized_input = tool_input or {}
    if normalized_input.get("run_in_background") is True:
        return _UNTRACKED_BACKGROUND_REASON
    command = str(normalized_input.get("command") or "")
    if not command.strip():
        return None
    if _has_unquoted_background_operator(command):
        return _UNTRACKED_BACKGROUND_REASON

    tokens = _shell_tokens(command)
    expect_command = True
    wrapper_active = False
    for index, token in enumerate(tokens):
        if token in _SHELL_CONTROL_TOKENS:
            expect_command = True
            wrapper_active = False
            continue
        if not expect_command:
            continue
        if _SHELL_ASSIGNMENT_RE.match(token):
            continue
        executable = token.rsplit("/", 1)[-1]
        if executable in _SHELL_COMMAND_WRAPPERS:
            wrapper_active = True
            continue
        if wrapper_active and token.startswith("-"):
            continue
        if executable in {"nohup", "disown"}:
            return _UNTRACKED_BACKGROUND_REASON
        if executable in {"bash", "dash", "ksh", "sh", "zsh"}:
            arguments = tokens[index + 1:]
            for argument_index, argument in enumerate(arguments[:-1]):
                if (
                    argument.startswith("-")
                    and not argument.startswith("--")
                    and "c" in argument[1:]
                    and claude_untracked_background_reason(
                        "Bash", {"command": arguments[argument_index + 1]}
                    ) is not None
                ):
                    return _UNTRACKED_BACKGROUND_REASON
        if executable == "setsid":
            # Even without --fork, a new session can escape process-group
            # cleanup if the provider/server disappears. Keep it out of the
            # untracked Bash path entirely.
            return _UNTRACKED_BACKGROUND_REASON
        expect_command = False
    return None


async def reject_untracked_background_hook(
    hook_input: dict[str, Any],
    _tool_use_id: str | None,
    _context: dict[str, Any],
) -> dict[str, Any]:
    """Keep Claude background work attached to the SDK's task lifecycle."""

    reason = claude_untracked_background_reason(
        str(hook_input.get("tool_name") or ""),
        hook_input.get("tool_input")
        if isinstance(hook_input.get("tool_input"), dict)
        else {},
    )
    if reason is None:
        return {}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def claude_nondurable_scheduler_reason(tool_name: Any) -> str | None:
    """Reject only the exact Claude tools that cannot create durable Dock work."""

    if tool_name not in CLAUDE_NON_DURABLE_SCHEDULER_TOOLS:
        return None
    return _NON_DURABLE_SCHEDULER_REASON.format(tool_name=tool_name)


async def reject_nondurable_scheduler_hook(
    hook_input: dict[str, Any],
    _tool_use_id: str | None,
    _context: dict[str, Any],
) -> dict[str, Any]:
    """Fail closed before Claude can arm a provider-local scheduler."""

    reason = claude_nondurable_scheduler_reason(hook_input.get("tool_name"))
    if reason is None:
        return {}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def claude_background_tracking_hooks() -> dict[str, list[ClaudeSDKHookMatcher]]:
    """Return SDK hooks for shell detachment and non-durable schedulers."""

    return {
        "PreToolUse": [
            ClaudeSDKHookMatcher(
                matcher="Bash",
                hooks=[reject_untracked_background_hook],
                timeout=5.0,
            ),
            *[
                ClaudeSDKHookMatcher(
                    matcher=tool_name,
                    hooks=[reject_nondurable_scheduler_hook],
                    timeout=5.0,
                )
                for tool_name in CLAUDE_NON_DURABLE_SCHEDULER_TOOLS
            ],
        ]
    }


def bind_permission_owner(options: Any, ownership_token: str) -> None:
    """Bind an AgentServer callback closure to one supervisor generation."""

    callback = (
        options.get("can_use_tool")
        if isinstance(options, dict)
        else getattr(options, "can_use_tool", None)
    )
    binder = getattr(callback, "_agentsdock_bind_owner", None)
    if callable(binder):
        binder(ownership_token)


_RUN_END = object()


@dataclass(frozen=True)
class _RunFailure:
    error: BaseException


class ClaudeSDKRunHandle:
    """An accepted query and its ordered stream of SDK messages.

    ``start_run()`` returns only after ``ClaudeSDKClient.query()`` succeeds.
    Consequently, receiving this handle is the transport's accepted boundary;
    failures raised before a handle is returned are classified by exception
    type for safe fallback decisions.
    """

    def __init__(
        self,
        chat_id: str,
        run_id: str,
        correlation_id: str,
        loop: asyncio.AbstractEventLoop,
        interrupt_callback: InterruptCallback,
    ) -> None:
        self.chat_id = chat_id
        self.run_id = run_id
        self.correlation_id = correlation_id
        self._loop = loop
        self._interrupt_callback = interrupt_callback
        self._messages: asyncio.Queue[Any] = asyncio.Queue()
        self._terminal: asyncio.Future[Any] = loop.create_future()
        self.accepted_at: float | None = None
        self._acknowledged = False
        self._acknowledged_event = asyncio.Event()

    def _check_loop(self) -> None:
        try:
            running = asyncio.get_running_loop()
        except RuntimeError as exc:
            raise ClaudeSDKLoopError("Claude SDK run handles require an event loop") from exc
        if running is not self._loop:
            raise ClaudeSDKLoopError(
                "Claude SDK run handle used from a different event loop"
            )

    @property
    def done(self) -> bool:
        return self._terminal.done()

    @property
    def accepted(self) -> bool:
        return self.accepted_at is not None

    @property
    def acknowledged(self) -> bool:
        return self._acknowledged

    async def wait_result(self) -> Any:
        """Return the terminal ResultMessage, or raise the terminal transport error."""

        self._check_loop()
        return await asyncio.shield(self._terminal)

    async def wait_acknowledged(self) -> None:
        """Wait until the CLI replays this query's exact UUID-bearing frame."""

        self._check_loop()
        await self._acknowledged_event.wait()

    async def interrupt(self) -> bool:
        """Interrupt only this accepted run, returning false once it is no longer active."""

        self._check_loop()
        return await self._interrupt_callback(self.run_id)

    def __aiter__(self) -> ClaudeSDKRunHandle:
        return self

    async def __anext__(self) -> Any:
        self._check_loop()
        value = await self._messages.get()
        if value is _RUN_END:
            raise StopAsyncIteration
        if isinstance(value, _RunFailure):
            raise value.error
        return value

    def _mark_accepted(self) -> None:
        if self.accepted_at is None:
            self.accepted_at = time.monotonic()

    def _deliver(self, message: Any) -> None:
        if not self.done:
            self._messages.put_nowait(message)

    def _acknowledge(self, message: Any) -> bool:
        if self._acknowledged or not _is_matching_replay_ack(
            message,
            self.correlation_id,
        ):
            return False
        self._acknowledged = True
        self._acknowledged_event.set()
        return True

    def _finish(self, terminal: Any) -> None:
        if self.done:
            return
        self._terminal.set_result(terminal)
        self._messages.put_nowait(_RUN_END)

    def _fail(self, error: BaseException) -> None:
        if self.done:
            return
        self._terminal.set_exception(error)
        # Retrieving the failure from the iterator and from wait_result() are
        # independent supported consumption modes. Marking the Future's
        # exception observed avoids noisy warnings when a caller uses only the
        # iterator.
        self._terminal.exception()
        self._messages.put_nowait(_RunFailure(error))
        self._messages.put_nowait(_RUN_END)


@dataclass(frozen=True)
class ClaudeSDKSupervisorSnapshot:
    chat_id: str
    configuration_key: str
    connected: bool
    active_run_id: str | None
    generation: int
    closed: bool
    last_used_at: float


@dataclass
class _StartRun:
    prompt: str
    run_id: str
    query_session_id: str | None
    on_supervisor_ready: SupervisorReadyCallback | None
    response: asyncio.Future[ClaudeSDKRunHandle]


@dataclass
class _Interrupt:
    run_id: str | None
    response: asyncio.Future[bool]


@dataclass
class _GetContextUsage:
    response: asyncio.Future[dict[str, Any] | None]


@dataclass
class _GetMCPStatus:
    response: asyncio.Future[tuple[dict[str, Any], str]]
    cancelled: bool = False


@dataclass
class _MutateMCPServer:
    action: str
    server_name: str | None
    expected_generation: str
    response: asyncio.Future[tuple[dict[str, Any], str]]
    cancelled: bool = False


@dataclass
class _Close:
    response: asyncio.Future[None]


@dataclass(frozen=True)
class _ReceivedMessage:
    generation: int
    message: Any


@dataclass(frozen=True)
class _ReceiverStopped:
    generation: int
    error: BaseException | None


@dataclass(frozen=True)
class _AckTimeout:
    generation: int
    run_id: str
    correlation_id: str


class ClaudeSDKSupervisor:
    """One lazy, restartable Claude SDK actor for one AgentsDock chat."""

    def __init__(
        self,
        chat_id: str,
        *,
        options: Any,
        configuration_key: str,
        client_factory: ClientFactory = default_claude_sdk_client_factory,
        is_result_message: ResultPredicate = default_is_result_message,
        connect_timeout_seconds: float = 30.0,
        disconnect_timeout_seconds: float = 2.0,
        ack_timeout_seconds: float = 60.0,
        query_delivery_timeout_seconds: float = 10.0,
        control_timeout_seconds: float = 15.0,
    ) -> None:
        clean_chat_id = str(chat_id or "").strip()
        if not clean_chat_id:
            raise ValueError("chat_id is required")
        self.chat_id = clean_chat_id
        self.options = options
        self.configuration_key = str(configuration_key)
        self.ownership_token = f"claudeowner_{uuid.uuid4().hex}"
        bind_permission_owner(self.options, self.ownership_token)
        self._client_factory = client_factory
        self._is_result_message = is_result_message
        if connect_timeout_seconds <= 0:
            raise ValueError("connect_timeout_seconds must be positive")
        self._connect_timeout_seconds = float(connect_timeout_seconds)
        if disconnect_timeout_seconds <= 0:
            raise ValueError("disconnect_timeout_seconds must be positive")
        self._disconnect_timeout_seconds = float(disconnect_timeout_seconds)
        if ack_timeout_seconds <= 0:
            raise ValueError("ack_timeout_seconds must be positive")
        self._ack_timeout_seconds = float(ack_timeout_seconds)
        if query_delivery_timeout_seconds <= 0:
            raise ValueError("query_delivery_timeout_seconds must be positive")
        self._query_delivery_timeout_seconds = float(query_delivery_timeout_seconds)
        if control_timeout_seconds <= 0:
            raise ValueError("control_timeout_seconds must be positive")
        self._control_timeout_seconds = float(control_timeout_seconds)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._commands: asyncio.Queue[Any] | None = None
        self._actor_task: asyncio.Task[None] | None = None
        self._client: ClaudeSDKClientProtocol | None = None
        self._connecting_client: ClaudeSDKClientProtocol | None = None
        self._connect_task: asyncio.Task[None] | None = None
        self._late_connect_cleanup_tasks: set[asyncio.Task[None]] = set()
        self._receiver_task: asyncio.Task[None] | None = None
        self._ack_timeout_task: asyncio.Task[None] | None = None
        self._active_run: ClaudeSDKRunHandle | None = None
        self._inflight_tasks: set[str] = set()
        self._generation = 0
        self._closed = False
        self._connected = False
        self._last_used_at = time.monotonic()
        self._inflight_response: asyncio.Future[Any] | None = None

    def _bind_loop(self) -> asyncio.AbstractEventLoop:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError as exc:
            raise ClaudeSDKLoopError("Claude SDK supervisors require an event loop") from exc
        if self._loop is None:
            self._loop = loop
            self._commands = asyncio.Queue()
        elif loop is not self._loop:
            raise ClaudeSDKLoopError(
                f"Claude SDK supervisor for {self.chat_id} used from a different event loop"
            )
        return loop

    def _ensure_actor(self) -> asyncio.AbstractEventLoop:
        loop = self._bind_loop()
        if self._closed:
            raise ClaudeSDKSupervisorClosed(
                f"Claude SDK supervisor for {self.chat_id} is closed"
            )
        if self._actor_task is None:
            self._actor_task = loop.create_task(
                self._actor_loop(),
                name=f"claude-sdk:{self.chat_id}",
            )
        return loop

    @property
    def active_run_id(self) -> str | None:
        active = self._active_run
        return active.run_id if active is not None and not active.done else None

    @property
    def is_active(self) -> bool:
        return self.active_run_id is not None

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def last_used_at(self) -> float:
        return self._last_used_at

    @property
    def control_generation(self) -> str | None:
        """Return an opaque revision bound to this supervisor and connection.

        The SDK's integer generation restarts when a supervisor is replaced.
        Hashing it with the random ownership token makes stale UI snapshots
        unable to target a different process/profile that also happens to be
        generation 1.
        """

        if not self._connected or self._generation < 1:
            return None
        digest = hashlib.sha256(
            f"{self.ownership_token}:{self._generation}".encode()
        ).hexdigest()[:24]
        return f"claudemcp_{digest}"

    def snapshot(self) -> ClaudeSDKSupervisorSnapshot:
        return ClaudeSDKSupervisorSnapshot(
            chat_id=self.chat_id,
            configuration_key=self.configuration_key,
            connected=self._connected,
            active_run_id=self.active_run_id,
            generation=self._generation,
            closed=self._closed,
            last_used_at=self._last_used_at,
        )

    async def start_run(
        self,
        prompt: str,
        *,
        run_id: str,
        query_session_id: str | None = None,
        on_supervisor_ready: SupervisorReadyCallback | None = None,
    ) -> ClaudeSDKRunHandle:
        """Submit one prompt and return after the SDK accepts ``query()``."""

        if not str(run_id or "").strip():
            raise ValueError("run_id is required")
        loop = self._ensure_actor()
        response: asyncio.Future[ClaudeSDKRunHandle] = loop.create_future()
        assert self._commands is not None
        await self._commands.put(
            _StartRun(
                prompt=str(prompt),
                run_id=str(run_id),
                query_session_id=(
                    str(query_session_id)
                    if query_session_id is not None
                    else None
                ),
                on_supervisor_ready=on_supervisor_ready,
                response=response,
            )
        )
        return await asyncio.shield(response)

    async def interrupt(self, *, run_id: str | None = None) -> bool:
        """Ask the SDK to interrupt this chat's active response."""

        loop = self._ensure_actor()
        response: asyncio.Future[bool] = loop.create_future()
        assert self._commands is not None
        await self._commands.put(_Interrupt(run_id=run_id, response=response))
        return await asyncio.shield(response)

    async def get_context_usage(self) -> dict[str, Any] | None:
        """Sample usage through the chat actor that owns the SDK client."""

        loop = self._ensure_actor()
        response: asyncio.Future[dict[str, Any] | None] = loop.create_future()
        assert self._commands is not None
        await self._commands.put(_GetContextUsage(response=response))
        return await asyncio.shield(response)

    async def get_mcp_status(self) -> tuple[dict[str, Any], str]:
        """Connect lazily and query MCP state on this chat-owned SDK actor."""

        loop = self._ensure_actor()
        response: asyncio.Future[tuple[dict[str, Any], str]] = loop.create_future()
        command = _GetMCPStatus(response=response)
        assert self._commands is not None
        await self._commands.put(command)
        try:
            return await asyncio.shield(response)
        except asyncio.CancelledError:
            # The manager retires this exact supervisor before allowing a
            # replacement. Marking the queued command also prevents a control
            # that has not started yet from running after its HTTP caller left.
            command.cancelled = True
            response.cancel()
            raise

    async def mutate_mcp_server(
        self,
        *,
        action: str,
        server_name: str | None,
        expected_generation: str,
    ) -> tuple[dict[str, Any], str]:
        """Run one generation-fenced MCP mutation on the owning SDK actor."""

        loop = self._ensure_actor()
        response: asyncio.Future[tuple[dict[str, Any], str]] = loop.create_future()
        command = _MutateMCPServer(
            action=str(action),
            server_name=(str(server_name) if server_name is not None else None),
            expected_generation=str(expected_generation),
            response=response,
        )
        assert self._commands is not None
        await self._commands.put(command)
        try:
            return await asyncio.shield(response)
        except asyncio.CancelledError:
            command.cancelled = True
            response.cancel()
            raise

    async def close(self) -> None:
        """Interrupt any active run and disconnect this chat's SDK process."""

        loop = self._bind_loop()
        if self._closed:
            task = self._actor_task
            if task is not None and not task.done():
                await asyncio.shield(task)
            return
        if self._actor_task is None:
            self._closed = True
            return
        response: asyncio.Future[None] = loop.create_future()
        assert self._commands is not None
        await self._commands.put(_Close(response=response))
        await asyncio.shield(response)
        task = self._actor_task
        if task is not None:
            await asyncio.shield(task)

    async def abort(self) -> None:
        """Cancel this chat-owned actor even when an SDK call is wedged."""

        self._bind_loop()
        if self._closed:
            task = self._actor_task
            if task is not None and not task.done():
                await asyncio.gather(task, return_exceptions=True)
            return
        self._closed = True
        task = self._actor_task
        if task is None:
            return
        actor_finished = await self._cancel_task_bounded(task)
        if actor_finished:
            return
        # A third-party SDK await may ignore task cancellation. Detach its
        # process resources directly and return after the bounded disconnect;
        # the stale actor no longer owns manager-visible state and cannot
        # block a later reconnect forever.
        self._fail_active(
            ClaudeSDKSupervisorClosed(
                f"Claude SDK supervisor for {self.chat_id} was aborted"
            )
        )
        client = self._client
        connecting_client = self._connecting_client
        receiver = self._receiver_task
        self._client = None
        self._connecting_client = None
        self._receiver_task = None
        self._connected = False
        response = self._inflight_response
        if response is not None and not response.done():
            response.set_exception(
                ClaudeSDKSupervisorClosed(
                    f"Claude SDK supervisor for {self.chat_id} was aborted"
                )
            )
            response.exception()
        if client is not None:
            await self._disconnect_client(client)
        if connecting_client is not None and connecting_client is not client:
            await self._disconnect_client(connecting_client)
        if receiver is not None and receiver is not task:
            await self._cancel_task_bounded(receiver)

    async def _disconnect_client(self, client: ClaudeSDKClientProtocol) -> None:
        """Best-effort bounded disconnect for cancellation/error cleanup."""

        task = asyncio.create_task(client.disconnect())
        done, _pending = await asyncio.wait(
            {task},
            timeout=self._disconnect_timeout_seconds,
        )
        if task in done:
            await asyncio.gather(task, return_exceptions=True)
            return
        task.cancel()

        def consume_result(completed: asyncio.Task[Any]) -> None:
            if not completed.cancelled():
                with suppress(BaseException):
                    completed.exception()

        # A cancellation-hostile third-party disconnect must not block Stop
        # or deletion. Consume its eventual result without awaiting it here.
        task.add_done_callback(consume_result)

    async def _cancel_task_bounded(self, task: asyncio.Task[Any]) -> bool:
        """Cancel one SDK-owned task without allowing teardown to wedge."""

        if task.done():
            await asyncio.gather(task, return_exceptions=True)
            return True
        task.cancel()
        done, _pending = await asyncio.wait(
            {task},
            timeout=self._disconnect_timeout_seconds,
        )
        if task in done:
            await asyncio.gather(task, return_exceptions=True)
            return True

        def consume_result(completed: asyncio.Task[Any]) -> None:
            if not completed.cancelled():
                with suppress(BaseException):
                    completed.exception()

        task.add_done_callback(consume_result)
        return False

    async def _disconnect_connecting_client(self) -> None:
        """Fence and clean up the exact client used by a cold connect attempt."""

        client = self._connecting_client
        task = self._connect_task
        self._connecting_client = None
        self._connect_task = None
        task_was_pending = task is not None and not task.done()
        if task_was_pending:
            assert task is not None
            task.cancel()
        if client is not None:
            await self._disconnect_client(client)
        if task is not None:
            if task_was_pending and client is not None:
                async def disconnect_after_late_connect() -> None:
                    await asyncio.gather(task, return_exceptions=True)
                    # A cancellation-hostile connect can establish its
                    # transport after the first disconnect already returned.
                    # Retire the exact client a second time once connect
                    # finally settles so no late CLI process is orphaned.
                    await self._disconnect_client(client)

                cleanup_task = asyncio.create_task(
                    disconnect_after_late_connect(),
                    name=f"claude-sdk-late-connect-cleanup:{self.chat_id}",
                )
                self._late_connect_cleanup_tasks.add(cleanup_task)

                def cleanup_finished(completed: asyncio.Task[None]) -> None:
                    self._late_connect_cleanup_tasks.discard(completed)
                    if not completed.cancelled():
                        with suppress(BaseException):
                            completed.exception()

                cleanup_task.add_done_callback(cleanup_finished)
                await self._cancel_task_bounded(task)
                await asyncio.wait(
                    {cleanup_task},
                    timeout=self._disconnect_timeout_seconds,
                )
            else:
                await self._cancel_task_bounded(task)

    def late_connect_cleanup_tasks(self) -> set[asyncio.Task[None]]:
        """Return cleanup owners retained after exact supervisor retirement."""

        return set(self._late_connect_cleanup_tasks)

    async def _new_client(self) -> ClaudeSDKClientProtocol:
        client: ClaudeSDKClientProtocol | None = None
        try:
            candidate = self._client_factory(self.options)
            client = await candidate if inspect.isawaitable(candidate) else candidate
            self._connecting_client = client
            connect_task = asyncio.create_task(
                client.connect(),
                name=f"claude-sdk-connect:{self.chat_id}",
            )
            self._connect_task = connect_task
            done, _pending = await asyncio.wait(
                {connect_task},
                timeout=self._connect_timeout_seconds,
            )
            if connect_task not in done:
                raise TimeoutError(
                    f"connect timed out after {self._connect_timeout_seconds:g}s"
                )
            await connect_task
            if self._closed or self._connecting_client is not client:
                raise ClaudeSDKSupervisorClosed(
                    f"Claude SDK supervisor for {self.chat_id} closed while connecting"
                )
        except asyncio.CancelledError:
            await self._disconnect_connecting_client()
            raise
        except (ClaudeSDKUnavailable, ClaudeSDKSupervisorClosed):
            await self._disconnect_connecting_client()
            raise
        except Exception as exc:
            await self._disconnect_connecting_client()
            raise ClaudeSDKUnavailable(
                f"Claude SDK could not connect for chat {self.chat_id}: {exc}"
            ) from exc
        finally:
            if self._connecting_client is client:
                self._connecting_client = None
            if self._connect_task is not None and self._connect_task.done():
                self._connect_task = None
        self._generation += 1
        self._client = client
        self._connected = True
        self._last_used_at = time.monotonic()
        generation = self._generation
        self._receiver_task = asyncio.create_task(
            self._receive_loop(client, generation),
            name=f"claude-sdk-recv:{self.chat_id}:{generation}",
        )
        return client

    async def _ensure_client(self) -> ClaudeSDKClientProtocol:
        client = self._client
        if client is None or not self._connected:
            client = await self._new_client()
        return client

    async def _receive_loop(
        self,
        client: ClaudeSDKClientProtocol,
        generation: int,
    ) -> None:
        error: BaseException | None = None
        try:
            async for message in client.receive_messages():
                commands = self._commands
                if commands is None:
                    return
                await commands.put(
                    _ReceivedMessage(generation=generation, message=message)
                )
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            error = exc
        finally:
            commands = self._commands
            if commands is not None:
                await commands.put(
                    _ReceiverStopped(generation=generation, error=error)
                )

    async def _disconnect_current_client(self) -> None:
        self._cancel_ack_timeout()
        client = self._client
        receiver = self._receiver_task
        self._client = None
        self._receiver_task = None
        self._connected = False
        if client is not None:
            await self._disconnect_client(client)
        if receiver is not None and receiver is not asyncio.current_task():
            await self._cancel_task_bounded(receiver)

    def _fail_active(self, error: BaseException) -> None:
        self._cancel_ack_timeout()
        active = self._active_run
        self._active_run = None
        self._inflight_tasks.clear()
        if active is not None:
            active._fail(error)

    def _cancel_ack_timeout(self) -> None:
        task = self._ack_timeout_task
        self._ack_timeout_task = None
        if task is not None and not task.done() and task is not asyncio.current_task():
            task.cancel()

    def _schedule_ack_timeout(self, handle: ClaudeSDKRunHandle) -> None:
        self._cancel_ack_timeout()
        generation = self._generation
        commands = self._commands
        assert commands is not None

        async def expire() -> None:
            try:
                await asyncio.sleep(self._ack_timeout_seconds)
                await commands.put(_AckTimeout(
                    generation=generation,
                    run_id=handle.run_id,
                    correlation_id=handle.correlation_id,
                ))
            except asyncio.CancelledError:
                return

        self._ack_timeout_task = asyncio.create_task(
            expire(),
            name=f"claude-sdk-ack:{self.chat_id}:{handle.run_id}",
        )

    async def _deliver_query_bounded(
        self,
        query: Awaitable[None],
        *,
        run_id: str,
    ) -> None:
        """Bound stdin delivery without awaiting cancellation-hostile SDK code."""

        task = asyncio.create_task(
            query,
            name=f"claude-sdk-query:{self.chat_id}:{run_id}",
        )

        def consume_result(completed: asyncio.Task[Any]) -> None:
            if not completed.cancelled():
                with suppress(BaseException):
                    completed.exception()

        try:
            done, _pending = await asyncio.wait(
                {task},
                timeout=self._query_delivery_timeout_seconds,
            )
        except BaseException:
            task.cancel()
            task.add_done_callback(consume_result)
            raise
        if task not in done:
            task.cancel()
            task.add_done_callback(consume_result)
            raise ClaudeSDKQueryError(
                f"Claude SDK query delivery timed out for chat {self.chat_id}; "
                "delivery is uncertain"
            )
        await task

    async def _handle_start(self, command: _StartRun) -> None:
        if self._active_run is not None and not self._active_run.done:
            if not command.response.done():
                command.response.set_exception(
                    ClaudeSDKRunActive(
                        f"Claude SDK chat {self.chat_id} already has active run "
                        f"{self._active_run.run_id}"
                    )
                )
            return
        self._active_run = None
        try:
            client = await self._ensure_client()
        except Exception as exc:
            if not command.response.done():
                command.response.set_exception(exc)
            return

        assert self._loop is not None
        async def interrupt_this_run(run_id: str) -> bool:
            return await self.interrupt(run_id=run_id)

        correlation_id = str(uuid.uuid4())
        handle = ClaudeSDKRunHandle(
            self.chat_id,
            command.run_id,
            correlation_id,
            self._loop,
            interrupt_this_run,
        )
        self._active_run = handle
        self._last_used_at = time.monotonic()
        if command.on_supervisor_ready is not None:
            try:
                # Run the admission fence after connect and after publishing
                # _active_run, at the last event-loop boundary before query.
                # This prevents Stop/Delete from winning during a slow SDK
                # connection and then having the prompt delivered afterward.
                await command.on_supervisor_ready(self.ownership_token)
            except BaseException as exc:
                self._active_run = None
                handle._fail(
                    exc
                    if isinstance(exc, Exception)
                    else ClaudeSDKSupervisorClosed(
                        f"Claude SDK query admission was cancelled for chat {self.chat_id}"
                    )
                )
                if not command.response.done():
                    command.response.set_exception(exc)
                return
        try:
            if self._closed:
                raise ClaudeSDKSupervisorClosed(
                    f"Claude SDK supervisor for {self.chat_id} closed before query"
                )
            if command.query_session_id is None:
                await self._deliver_query_bounded(
                    client.query(
                        _query_message_stream(command.prompt, correlation_id)
                    ),
                    run_id=command.run_id,
                )
            else:
                await self._deliver_query_bounded(
                    client.query(
                        _query_message_stream(command.prompt, correlation_id),
                        session_id=command.query_session_id,
                    ),
                    run_id=command.run_id,
                )
        except ClaudeSDKSupervisorClosed as exc:
            self._active_run = None
            handle._fail(exc)
            if not command.response.done():
                command.response.set_exception(exc)
            await self._disconnect_current_client()
            return
        except Exception as exc:
            error = ClaudeSDKQueryError(
                f"Claude SDK query delivery is uncertain for chat {self.chat_id}: {exc}"
            )
            self._active_run = None
            handle._fail(error)
            if not command.response.done():
                command.response.set_exception(error)
            # A query failure can leave protocol framing ambiguous. Retire only
            # this chat's process; the next run may resume its persisted Claude
            # session through a fresh client.
            await self._disconnect_current_client()
            return
        handle._mark_accepted()
        self._schedule_ack_timeout(handle)
        if not command.response.done():
            command.response.set_result(handle)

    async def _handle_interrupt(self, command: _Interrupt) -> None:
        active = self._active_run
        if (
            active is None
            or active.done
            or (command.run_id is not None and active.run_id != command.run_id)
        ):
            if not command.response.done():
                command.response.set_result(False)
            return
        client = self._client
        if client is None or not self._connected:
            if not command.response.done():
                command.response.set_exception(
                    ClaudeSDKSupervisorError(
                        f"Claude SDK client for {self.chat_id} is not connected"
                    )
                )
            return
        try:
            await client.interrupt()
        except Exception as exc:
            if not command.response.done():
                command.response.set_exception(
                    ClaudeSDKSupervisorError(
                        f"Claude SDK interrupt failed for chat {self.chat_id}: {exc}"
                    )
                )
            return
        if not active.acknowledged:
            error = ClaudeSDKQueryError(
                f"Claude SDK query {active.run_id} for chat {self.chat_id} was "
                "interrupted before its replay acknowledgment; delivery is uncertain"
            )
            self._fail_active(error)
            await self._disconnect_current_client()
        self._last_used_at = time.monotonic()
        if not command.response.done():
            command.response.set_result(True)

    async def _handle_get_context_usage(
        self,
        command: _GetContextUsage,
    ) -> None:
        client = self._client
        getter = getattr(client, "get_context_usage", None)
        if client is None or not self._connected or not callable(getter):
            if not command.response.done():
                command.response.set_result(None)
            return
        try:
            value = await getter()
        except Exception as exc:
            if not command.response.done():
                command.response.set_exception(
                    ClaudeSDKSupervisorError(
                        f"Claude SDK context usage failed for {self.chat_id}: {exc}"
                    )
                )
            return
        self._last_used_at = time.monotonic()
        if not command.response.done():
            command.response.set_result(dict(value) if isinstance(value, dict) else None)

    async def _mcp_control_bounded(
        self,
        operation: Awaitable[Any],
        *,
        label: str,
        retire_on_timeout: bool,
    ) -> Any:
        """Bound one native SDK control without leaving it on the actor queue."""

        task = asyncio.create_task(
            operation,
            name=f"claude-sdk-{label}:{self.chat_id}:{self._generation}",
        )

        def consume_result(completed: asyncio.Task[Any]) -> None:
            if not completed.cancelled():
                with suppress(BaseException):
                    completed.exception()

        try:
            done, _pending = await asyncio.wait(
                {task},
                timeout=self._control_timeout_seconds,
            )
        except BaseException:
            task.cancel()
            task.add_done_callback(consume_result)
            raise
        if task in done:
            return await task

        await self._cancel_task_bounded(task)
        if retire_on_timeout:
            # A timed-out mutation has uncertain provider delivery. Close this
            # actor before reporting failure so it can never be mistaken for a
            # later replacement with the same chat/profile.
            self._closed = True
            await self._disconnect_current_client()
            connecting = self._connecting_client
            self._connecting_client = None
            if connecting is not None:
                await self._disconnect_client(connecting)
        raise ClaudeSDKControlTimeout(
            f"Claude SDK {label} timed out for chat {self.chat_id}"
        )

    @staticmethod
    def _mcp_servers_from_status(value: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        if not isinstance(value, dict):
            raise ClaudeSDKSupervisorError("Claude SDK returned invalid MCP status")
        raw_servers = value.get("mcpServers")
        if not isinstance(raw_servers, list):
            raise ClaudeSDKSupervisorError("Claude SDK returned invalid MCP server list")
        servers: list[dict[str, Any]] = []
        scan_count = min(len(raw_servers), CLAUDE_SDK_MCP_STATUS_SCAN_LIMIT)
        for index in range(scan_count):
            item = raw_servers[index]
            if isinstance(item, dict):
                servers.append(item)
        status = {
            "mcpServers": servers,
            CLAUDE_SDK_MCP_STATUS_TRUNCATED_KEY: bool(
                value.get(CLAUDE_SDK_MCP_STATUS_TRUNCATED_KEY)
                or len(raw_servers) > scan_count
                or len(servers) < scan_count
            ),
        }
        return status, servers

    async def _read_mcp_status(self, client: ClaudeSDKClientProtocol) -> dict[str, Any]:
        getter = getattr(client, "get_mcp_status", None)
        if not callable(getter):
            raise ClaudeSDKUnavailable(
                "installed claude-agent-sdk does not support MCP status controls"
            )
        value = await getter()
        status, _servers = self._mcp_servers_from_status(value)
        return status

    async def _mcp_status_operation(self) -> tuple[dict[str, Any], str]:
        client = await self._ensure_client()
        value = await self._read_mcp_status(client)
        generation = self.control_generation
        if generation is None:
            raise ClaudeSDKSupervisorError(
                f"Claude SDK client for {self.chat_id} changed during MCP status"
            )
        return value, generation

    async def _handle_get_mcp_status(self, command: _GetMCPStatus) -> None:
        if command.cancelled:
            if not command.response.done():
                command.response.cancel()
            return
        if self.is_active:
            if not command.response.done():
                command.response.set_exception(
                    ClaudeSDKRunActive(
                        f"Claude SDK chat {self.chat_id} has an active run"
                    )
                )
            return
        try:
            value, generation = await self._mcp_control_bounded(
                self._mcp_status_operation(),
                label="mcp-status",
                retire_on_timeout=True,
            )
        except (
            ClaudeSDKUnavailable,
            ClaudeSDKControlTimeout,
            ClaudeSDKRunActive,
        ) as exc:
            if not command.response.done():
                command.response.set_exception(exc)
            return
        except Exception as exc:
            if not command.response.done():
                command.response.set_exception(
                    ClaudeSDKSupervisorError(
                        f"Claude SDK MCP status failed for {self.chat_id}: {exc}"
                    )
                )
            return
        self._last_used_at = time.monotonic()
        if not command.response.done():
            command.response.set_result((value, generation))

    async def _apply_mcp_mutation(
        self,
        client: ClaudeSDKClientProtocol,
        *,
        action: str,
        server_name: str | None,
    ) -> dict[str, Any]:
        current = await self._read_mcp_status(client)
        _value, servers = self._mcp_servers_from_status(current)
        by_name: dict[str, dict[str, Any]] = {}
        for item in servers:
            name = canonical_claude_mcp_identifier(item.get("name"), 512)
            if name is not None:
                by_name.setdefault(name, item)
        if action == "reconnect_all":
            reconnect = getattr(client, "reconnect_mcp_server", None)
            if not callable(reconnect):
                raise ClaudeSDKUnavailable(
                    "installed claude-agent-sdk does not support MCP reconnect"
                )
            for name, item in by_name.items():
                if str(item.get("status") or "") not in {"failed", "needs-auth"}:
                    continue
                # Reconnect-all is deliberately best effort. One unavailable
                # server must not prevent independent failed servers from
                # receiving their serialized native retry.
                with suppress(Exception):
                    await reconnect(name)
        else:
            clean_name = str(server_name or "")
            if clean_name not in by_name:
                raise ClaudeSDKMCPServerNotFound(
                    f"MCP server {clean_name!r} is not in the connected Claude profile"
                )
            if action == "reconnect":
                reconnect = getattr(client, "reconnect_mcp_server", None)
                if not callable(reconnect):
                    raise ClaudeSDKUnavailable(
                        "installed claude-agent-sdk does not support MCP reconnect"
                    )
                await reconnect(clean_name)
            elif action in {"enable", "disable"}:
                toggle = getattr(client, "toggle_mcp_server", None)
                if not callable(toggle):
                    raise ClaudeSDKUnavailable(
                        "installed claude-agent-sdk does not support MCP enable/disable"
                    )
                await toggle(clean_name, enabled=action == "enable")
            else:
                raise ValueError(f"unsupported MCP action: {action}")
        return await self._read_mcp_status(client)

    async def _mcp_mutation_operation(
        self,
        *,
        action: str,
        server_name: str | None,
        expected_generation: str,
    ) -> tuple[dict[str, Any], str]:
        client = await self._ensure_client()
        generation = self.control_generation
        if generation != expected_generation:
            raise ClaudeSDKGenerationChanged(
                f"Claude SDK MCP generation changed for chat {self.chat_id}"
            )
        value = await self._apply_mcp_mutation(
            client,
            action=action,
            server_name=server_name,
        )
        if self.control_generation != generation:
            raise ClaudeSDKGenerationChanged(
                f"Claude SDK MCP generation changed for chat {self.chat_id}"
            )
        return value, generation

    async def _handle_mutate_mcp_server(self, command: _MutateMCPServer) -> None:
        if command.cancelled:
            if not command.response.done():
                command.response.cancel()
            return
        if self.is_active:
            if not command.response.done():
                command.response.set_exception(
                    ClaudeSDKRunActive(
                        f"Claude SDK chat {self.chat_id} has an active run"
                    )
                )
            return
        try:
            value, generation = await self._mcp_control_bounded(
                self._mcp_mutation_operation(
                    action=command.action,
                    server_name=command.server_name,
                    expected_generation=command.expected_generation,
                ),
                label=f"mcp-{command.action}",
                retire_on_timeout=True,
            )
        except (
            ClaudeSDKControlTimeout,
            ClaudeSDKGenerationChanged,
            ClaudeSDKMCPServerNotFound,
            ClaudeSDKRunActive,
            ClaudeSDKUnavailable,
            ValueError,
        ) as exc:
            if not command.response.done():
                command.response.set_exception(exc)
            return
        except Exception as exc:
            if not command.response.done():
                command.response.set_exception(
                    ClaudeSDKSupervisorError(
                        f"Claude SDK MCP control failed for {self.chat_id}: {exc}"
                    )
                )
            return
        self._last_used_at = time.monotonic()
        if not command.response.done():
            command.response.set_result((value, generation))

    async def _handle_received(self, command: _ReceivedMessage) -> None:
        if command.generation != self._generation:
            return
        active = self._active_run
        if active is None or active.done:
            return
        self._last_used_at = time.monotonic()
        if not active.acknowledged:
            if active._acknowledge(command.message):
                self._cancel_ack_timeout()
                return
            # The persistent stream may contain resumed-session output from
            # before this query. Nothing owns the new run until its exact UUID
            # is replayed by the CLI.
            return
        elif _is_matching_replay_ack(
            command.message,
            active.correlation_id,
        ):
            # A duplicate acknowledgment is protocol metadata, never a second
            # user bubble.
            return

        if self._is_result_message(command.message):
            # A Claude Result ends one model turn, not necessarily the logical
            # run. Delegated local agents/workflows can outlive that Result;
            # their completion wakes Claude for a follow-up model turn and a
            # later Result. The Agent SDK itself uses this exact ledger to keep
            # its control channel open. Suppress the intermediate Result so the
            # runner cannot mistake it for the terminal response.
            had_inflight_tasks = bool(self._inflight_tasks)
            forced_run_end = _result_forces_run_end(command.message)
            if had_inflight_tasks and not forced_run_end:
                return
            active._deliver(command.message)
            self._cancel_ack_timeout()
            active._finish(command.message)
            self._active_run = None
            self._inflight_tasks.clear()
            if had_inflight_tasks and forced_run_end:
                # An interrupted/error response can strand provider-side task
                # frames after this logical run has ended. Retire only this
                # chat's connection so those late frames cannot cross the next
                # query's replay-ACK boundary and terminate a fresh run.
                await self._disconnect_current_client()
            return

        subtype, task_id, task_type, status = _task_lifecycle_fields(
            command.message
        )
        if task_id:
            if subtype == "task_started" and task_type in _DEFERRING_TASK_TYPES:
                self._inflight_tasks.add(task_id)
            elif subtype == "task_notification":
                self._inflight_tasks.discard(task_id)
            elif subtype == "task_updated" and status in _TERMINAL_TASK_STATUSES:
                self._inflight_tasks.discard(task_id)
        active._deliver(command.message)

    async def _handle_ack_timeout(self, command: _AckTimeout) -> None:
        if command.generation != self._generation:
            return
        active = self._active_run
        if (
            active is None
            or active.done
            or active.acknowledged
            or active.run_id != command.run_id
            or active.correlation_id != command.correlation_id
        ):
            return
        # Replay acknowledgements are an ownership fence, not a provider SLA.
        # Large resumed contexts can accept and persist the prompt immediately
        # while delaying the replay frame beyond this diagnostic threshold. Keep
        # waiting behind the exact-UUID gate; stream failure or an explicit
        # pre-ack interrupt still retires the uncertain delivery.
        logger.warning(
            "Claude SDK replay acknowledgement delayed for query %s in chat %s; "
            "continuing to wait",
            command.run_id,
            self.chat_id,
        )

    async def _handle_receiver_stopped(self, command: _ReceiverStopped) -> None:
        if command.generation != self._generation:
            return
        active = self._active_run
        error_type = (
            ClaudeSDKQueryError
            if active is not None and not active.acknowledged
            else ClaudeSDKSupervisorError
        )
        error = error_type(
            f"Claude SDK message stream stopped for chat {self.chat_id}"
            + (f": {command.error}" if command.error is not None else "")
        )
        self._fail_active(error)
        await self._disconnect_current_client()

    async def _handle_close(self, command: _Close) -> None:
        active = self._active_run
        client = self._client
        if active is not None and not active.done and client is not None:
            with suppress(Exception):
                await client.interrupt()
        self._fail_active(
            ClaudeSDKSupervisorClosed(
                f"Claude SDK supervisor for {self.chat_id} was closed"
            )
        )
        await self._disconnect_current_client()
        self._closed = True
        if not command.response.done():
            command.response.set_result(None)

    async def _actor_loop(self) -> None:
        assert self._commands is not None
        command: Any | None = None
        try:
            while not self._closed:
                command = await self._commands.get()
                response = getattr(command, "response", None)
                self._inflight_response = (
                    response if isinstance(response, asyncio.Future) else None
                )
                if isinstance(command, _StartRun):
                    await self._handle_start(command)
                elif isinstance(command, _Interrupt):
                    await self._handle_interrupt(command)
                elif isinstance(command, _GetContextUsage):
                    await self._handle_get_context_usage(command)
                elif isinstance(command, _GetMCPStatus):
                    await self._handle_get_mcp_status(command)
                elif isinstance(command, _MutateMCPServer):
                    await self._handle_mutate_mcp_server(command)
                elif isinstance(command, _ReceivedMessage):
                    await self._handle_received(command)
                elif isinstance(command, _AckTimeout):
                    await self._handle_ack_timeout(command)
                elif isinstance(command, _ReceiverStopped):
                    await self._handle_receiver_stopped(command)
                elif isinstance(command, _Close):
                    await self._handle_close(command)
                self._inflight_response = None
                command = None
        except asyncio.CancelledError:
            response = getattr(command, "response", None)
            if isinstance(response, asyncio.Future) and not response.done():
                response.set_exception(
                    ClaudeSDKSupervisorClosed(
                        f"Claude SDK supervisor for {self.chat_id} was aborted"
                    )
                )
                # A caller canceled by the same Stop request may no longer be
                # waiting on this command Future. Mark the exception observed
                # while preserving it for any remaining live waiter.
                response.exception()
            self._fail_active(
                ClaudeSDKSupervisorClosed(
                    f"Claude SDK supervisor for {self.chat_id} was closed"
                )
            )
            raise
        finally:
            await self._disconnect_current_client()
            self._closed = True
            while not self._commands.empty():
                command = self._commands.get_nowait()
                response = getattr(command, "response", None)
                if isinstance(response, asyncio.Future) and not response.done():
                    response.set_exception(
                        ClaudeSDKSupervisorClosed(
                            f"Claude SDK supervisor for {self.chat_id} is closed"
                        )
                    )


class ClaudeSDKSupervisorManager:
    """Lazy, bounded registry of independent chat-scoped supervisors."""

    def __init__(
        self,
        *,
        client_factory: ClientFactory = default_claude_sdk_client_factory,
        is_result_message: ResultPredicate = default_is_result_message,
        max_clients: int = 12,
        idle_ttl_seconds: float | None = 15 * 60,
        connect_timeout_seconds: float = 30.0,
        disconnect_timeout_seconds: float = 2.0,
        ack_timeout_seconds: float = 60.0,
        query_delivery_timeout_seconds: float = 10.0,
        control_timeout_seconds: float = 15.0,
    ) -> None:
        if max_clients < 1:
            raise ValueError("max_clients must be positive")
        if idle_ttl_seconds is not None and idle_ttl_seconds < 0:
            raise ValueError("idle_ttl_seconds must be non-negative or None")
        self._client_factory = client_factory
        self._is_result_message = is_result_message
        self._max_clients = int(max_clients)
        self._idle_ttl_seconds = idle_ttl_seconds
        if connect_timeout_seconds <= 0:
            raise ValueError("connect_timeout_seconds must be positive")
        self._connect_timeout_seconds = float(connect_timeout_seconds)
        if disconnect_timeout_seconds <= 0:
            raise ValueError("disconnect_timeout_seconds must be positive")
        self._disconnect_timeout_seconds = float(disconnect_timeout_seconds)
        if ack_timeout_seconds <= 0:
            raise ValueError("ack_timeout_seconds must be positive")
        self._ack_timeout_seconds = float(ack_timeout_seconds)
        if query_delivery_timeout_seconds <= 0:
            raise ValueError("query_delivery_timeout_seconds must be positive")
        self._query_delivery_timeout_seconds = float(query_delivery_timeout_seconds)
        if control_timeout_seconds <= 0:
            raise ValueError("control_timeout_seconds must be positive")
        self._control_timeout_seconds = float(control_timeout_seconds)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock: asyncio.Lock | None = None
        self._supervisors: OrderedDict[str, ClaudeSDKSupervisor] = OrderedDict()
        self._pins: dict[str, int] = {}
        self._evicting: dict[str, asyncio.Task[None]] = {}
        self._retired_cleanup_tasks: set[asyncio.Task[None]] = set()
        self._reaper_task: asyncio.Task[None] | None = None
        self._closed = False

    def _bind_loop(self) -> asyncio.AbstractEventLoop:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError as exc:
            raise ClaudeSDKLoopError("Claude SDK manager requires an event loop") from exc
        if self._loop is None:
            self._loop = loop
            self._lock = asyncio.Lock()
        elif loop is not self._loop:
            raise ClaudeSDKLoopError("Claude SDK manager used from a different event loop")
        if self._closed:
            raise ClaudeSDKSupervisorClosed("Claude SDK manager is closed")
        if (
            self._reaper_task is None
            and self._idle_ttl_seconds is not None
            and self._idle_ttl_seconds > 0
        ):
            self._reaper_task = loop.create_task(
                self._reaper_loop(),
                name="claude-sdk-idle-reaper",
            )
        return loop

    async def _reaper_loop(self) -> None:
        interval = min(
            60.0,
            max(1.0, float(self._idle_ttl_seconds or 1.0) / 2.0),
        )
        try:
            while not self._closed:
                await asyncio.sleep(interval)
                await self.evict_idle()
        except (asyncio.CancelledError, ClaudeSDKSupervisorClosed):
            return

    async def _wait_for_eviction(self, chat_id: str) -> None:
        """Serialize replacement behind complete teardown of the old client."""

        assert self._lock is not None
        while True:
            async with self._lock:
                task = self._evicting.get(chat_id)
            if task is None:
                return
            await asyncio.shield(task)
            async with self._lock:
                if self._evicting.get(chat_id) is task and task.done():
                    self._evicting.pop(chat_id, None)

    async def _get_locked(
        self,
        chat_id: str,
        *,
        options: Any,
        configuration_key: str,
    ) -> tuple[ClaudeSDKSupervisor, ClaudeSDKSupervisor | None]:
        old_to_close: ClaudeSDKSupervisor | None = None
        supervisor = self._supervisors.get(chat_id)
        if supervisor is not None and supervisor.closed:
            if self._pins.get(chat_id, 0):
                raise ClaudeSDKSupervisorClosed(
                    f"Claude SDK chat {chat_id} is retiring"
                )
            self._supervisors.pop(chat_id, None)
            old_to_close = supervisor
            supervisor = None
        if supervisor is not None and supervisor.configuration_key != configuration_key:
            if supervisor.is_active or self._pins.get(chat_id, 0):
                raise ClaudeSDKConfigurationConflict(
                    f"Claude SDK chat {chat_id} is active with another configuration"
                )
            self._supervisors.pop(chat_id, None)
            old_to_close = supervisor
            supervisor = None
        if supervisor is None:
            supervisor = ClaudeSDKSupervisor(
                chat_id,
                options=options,
                configuration_key=configuration_key,
                client_factory=self._client_factory,
                is_result_message=self._is_result_message,
                connect_timeout_seconds=self._connect_timeout_seconds,
                disconnect_timeout_seconds=self._disconnect_timeout_seconds,
                ack_timeout_seconds=self._ack_timeout_seconds,
                query_delivery_timeout_seconds=self._query_delivery_timeout_seconds,
                control_timeout_seconds=self._control_timeout_seconds,
            )
            self._supervisors[chat_id] = supervisor
        else:
            # A disconnected actor has no live provider state. Refresh its
            # lazy reconnect options so a newly persisted resume/fork binding
            # is honored after a stream failure without changing the stable
            # process-configuration key used by healthy persistent clients.
            if not supervisor.connected and not supervisor.is_active:
                supervisor.options = options
                bind_permission_owner(
                    supervisor.options,
                    supervisor.ownership_token,
                )
            self._supervisors.move_to_end(chat_id)
        return supervisor, old_to_close

    async def get(
        self,
        chat_id: str,
        *,
        options: Any,
        configuration_key: str,
    ) -> ClaudeSDKSupervisor:
        """Return the chat supervisor, replacing an idle stale configuration."""

        self._bind_loop()
        assert self._lock is not None
        clean_chat_id = str(chat_id or "").strip()
        if not clean_chat_id:
            raise ValueError("chat_id is required")
        await self._wait_for_eviction(clean_chat_id)
        async with self._lock:
            supervisor, old_to_close = await self._get_locked(
                clean_chat_id,
                options=options,
                configuration_key=str(configuration_key),
            )
        if old_to_close is not None:
            await old_to_close.close()
        await self.evict_idle(exclude={clean_chat_id})
        return supervisor

    async def start_run(
        self,
        chat_id: str,
        prompt: str,
        *,
        run_id: str,
        options: Any,
        configuration_key: str,
        query_session_id: str | None = None,
        on_supervisor_ready: SupervisorReadyCallback | None = None,
    ) -> ClaudeSDKRunHandle:
        """Pin a chat through query acceptance, then return its run handle."""

        self._bind_loop()
        assert self._lock is not None
        clean_chat_id = str(chat_id or "").strip()
        if not clean_chat_id:
            raise ValueError("chat_id is required")
        await self._wait_for_eviction(clean_chat_id)
        old_to_close: ClaudeSDKSupervisor | None = None
        async with self._lock:
            supervisor, old_to_close = await self._get_locked(
                clean_chat_id,
                options=options,
                configuration_key=str(configuration_key),
            )
            self._pins[clean_chat_id] = self._pins.get(clean_chat_id, 0) + 1
        if old_to_close is not None:
            await old_to_close.close()
        retire = False
        try:
            return await supervisor.start_run(
                prompt,
                run_id=run_id,
                query_session_id=query_session_id,
                on_supervisor_ready=on_supervisor_ready,
            )
        except (ClaudeSDKUnavailable, asyncio.CancelledError):
            # A cold-connect failure or a Stop that cancels start_run before
            # on_supervisor_ready has published an ownership token must evict
            # this exact owner. Otherwise its actor can retain a wedged
            # connect command and every later turn queues behind it forever.
            retire = True
            raise
        finally:
            if retire:
                await self._retire_exact_supervisor(
                    clean_chat_id,
                    supervisor,
                    task_name_prefix="claude-sdk-start-retire",
                )
            else:
                async with self._lock:
                    count = self._pins.get(clean_chat_id, 0) - 1
                    if count > 0:
                        self._pins[clean_chat_id] = count
                    else:
                        self._pins.pop(clean_chat_id, None)
                    if self._supervisors.get(clean_chat_id) is supervisor:
                        self._supervisors.move_to_end(clean_chat_id)
                await self.evict_idle(exclude={clean_chat_id})

    def owns_active_run(
        self,
        chat_id: str,
        ownership_token: str,
        run_id: str,
    ) -> bool:
        """Return whether the current registry owner is running this query."""

        supervisor = self._supervisors.get(str(chat_id))
        return bool(
            supervisor is not None
            and not supervisor.closed
            and supervisor.ownership_token == str(ownership_token)
            and supervisor.active_run_id == str(run_id)
        )

    async def interrupt(self, chat_id: str, *, run_id: str | None = None) -> bool:
        self._bind_loop()
        assert self._lock is not None
        async with self._lock:
            supervisor = self._supervisors.get(str(chat_id))
        if supervisor is None:
            return False
        return await supervisor.interrupt(run_id=run_id)

    async def get_context_usage(
        self,
        chat_id: str,
        *,
        ownership_token: str | None = None,
    ) -> tuple[dict[str, Any], int] | None:
        """Sample one chat's connected client with registry/generation fencing."""

        self._bind_loop()
        assert self._lock is not None
        clean_chat_id = str(chat_id)
        async with self._lock:
            supervisor = self._supervisors.get(clean_chat_id)
            if (
                supervisor is None
                or supervisor.closed
                or not supervisor.connected
                or (
                    ownership_token is not None
                    and supervisor.ownership_token != str(ownership_token)
                )
            ):
                return None
            self._pins[clean_chat_id] = self._pins.get(clean_chat_id, 0) + 1
            generation = supervisor.snapshot().generation
        try:
            usage = await supervisor.get_context_usage()
            if usage is None:
                return None
            async with self._lock:
                if (
                    self._supervisors.get(clean_chat_id) is not supervisor
                    or supervisor.closed
                    or supervisor.snapshot().generation != generation
                    or (
                        ownership_token is not None
                        and supervisor.ownership_token != str(ownership_token)
                    )
                ):
                    return None
                self._supervisors.move_to_end(clean_chat_id)
            return dict(usage), generation
        finally:
            async with self._lock:
                count = self._pins.get(clean_chat_id, 0) - 1
                if count > 0:
                    self._pins[clean_chat_id] = count
                else:
                    self._pins.pop(clean_chat_id, None)

    async def _pin_mcp_supervisor(
        self,
        chat_id: str,
        *,
        options: Any,
        configuration_key: str,
    ) -> ClaudeSDKSupervisor:
        """Return and pin the exact supervisor used by one MCP HTTP request."""

        self._bind_loop()
        assert self._lock is not None
        clean_chat_id = str(chat_id or "").strip()
        if not clean_chat_id:
            raise ValueError("chat_id is required")
        await self._wait_for_eviction(clean_chat_id)
        async with self._lock:
            supervisor, old_to_close = await self._get_locked(
                clean_chat_id,
                options=options,
                configuration_key=str(configuration_key),
            )
            self._pins[clean_chat_id] = self._pins.get(clean_chat_id, 0) + 1
        if old_to_close is not None:
            try:
                await old_to_close.close()
            except BaseException:
                await self._unpin_mcp_supervisor(clean_chat_id, supervisor)
                raise
        return supervisor

    async def _unpin_mcp_supervisor(
        self,
        chat_id: str,
        supervisor: ClaudeSDKSupervisor,
    ) -> None:
        assert self._lock is not None
        clean_chat_id = str(chat_id)
        async with self._lock:
            if self._supervisors.get(clean_chat_id) is not supervisor:
                # Exact-owner retirement already removed this pin. Never let
                # an old request decrement a replacement owner's count.
                return
            count = self._pins.get(clean_chat_id, 0) - 1
            if count > 0:
                self._pins[clean_chat_id] = count
            else:
                self._pins.pop(clean_chat_id, None)
            self._supervisors.move_to_end(clean_chat_id)

    async def _retire_exact_supervisor(
        self,
        chat_id: str,
        supervisor: ClaudeSDKSupervisor,
        *,
        task_name_prefix: str = "claude-sdk-mcp-retire",
    ) -> None:
        """Remove and abort only the owner involved in a failed operation."""

        assert self._lock is not None
        clean_chat_id = str(chat_id)
        async with self._lock:
            if self._supervisors.get(clean_chat_id) is not supervisor:
                return
            self._supervisors.pop(clean_chat_id, None)
            self._pins.pop(clean_chat_id, None)
            close_task = asyncio.create_task(
                supervisor.abort(),
                name=f"{task_name_prefix}:{clean_chat_id}",
            )
            self._evicting[clean_chat_id] = close_task

        def track_late_cleanup(_completed: asyncio.Task[None]) -> None:
            for cleanup_task in supervisor.late_connect_cleanup_tasks():
                self._retired_cleanup_tasks.add(cleanup_task)
                cleanup_task.add_done_callback(
                    self._retired_cleanup_tasks.discard
                )

        close_task.add_done_callback(track_late_cleanup)
        try:
            await asyncio.shield(close_task)
        finally:
            if close_task.done():
                async with self._lock:
                    if self._evicting.get(clean_chat_id) is close_task:
                        self._evicting.pop(clean_chat_id, None)

    async def get_mcp_status(
        self,
        chat_id: str,
        *,
        options: Any,
        configuration_key: str,
    ) -> tuple[dict[str, Any], str]:
        """Query MCP state through an exact, pinned chat/profile owner."""

        clean_chat_id = str(chat_id)
        supervisor = await self._pin_mcp_supervisor(
            clean_chat_id,
            options=options,
            configuration_key=configuration_key,
        )
        retire = False
        try:
            if supervisor.is_active:
                raise ClaudeSDKRunActive(
                    f"Claude SDK chat {clean_chat_id} has an active run"
                )
            try:
                status, generation = await supervisor.get_mcp_status()
            except ClaudeSDKControlTimeout:
                retire = True
                raise
            except asyncio.CancelledError:
                retire = True
                raise
            assert self._lock is not None
            async with self._lock:
                if (
                    self._supervisors.get(clean_chat_id) is not supervisor
                    or supervisor.closed
                    or supervisor.control_generation != generation
                ):
                    raise ClaudeSDKGenerationChanged(
                        f"Claude SDK MCP generation changed for chat {clean_chat_id}"
                    )
                self._supervisors.move_to_end(clean_chat_id)
            return dict(status), str(generation)
        finally:
            if retire:
                await self._retire_exact_supervisor(
                    clean_chat_id,
                    supervisor,
                )
            await self._unpin_mcp_supervisor(clean_chat_id, supervisor)

    async def mutate_mcp_server(
        self,
        chat_id: str,
        *,
        action: str,
        server_name: str | None,
        expected_generation: str,
        options: Any,
        configuration_key: str,
    ) -> tuple[dict[str, Any], str]:
        """Apply one exact-generation MCP mutation and return refreshed state."""

        clean_chat_id = str(chat_id)
        supervisor = await self._pin_mcp_supervisor(
            clean_chat_id,
            options=options,
            configuration_key=configuration_key,
        )
        retire = False
        try:
            if supervisor.is_active:
                raise ClaudeSDKRunActive(
                    f"Claude SDK chat {clean_chat_id} has an active run"
                )
            try:
                status, generation = await supervisor.mutate_mcp_server(
                    action=action,
                    server_name=server_name,
                    expected_generation=expected_generation,
                )
            except (ClaudeSDKControlTimeout, asyncio.CancelledError):
                # Mutation delivery is uncertain at this boundary. Remove the
                # exact owner before a replacement can be created.
                retire = True
                raise
            assert self._lock is not None
            async with self._lock:
                if (
                    self._supervisors.get(clean_chat_id) is not supervisor
                    or supervisor.closed
                    or supervisor.control_generation != generation
                ):
                    raise ClaudeSDKGenerationChanged(
                        f"Claude SDK MCP generation changed for chat {clean_chat_id}"
                    )
                self._supervisors.move_to_end(clean_chat_id)
            return dict(status), str(generation)
        finally:
            if retire:
                await self._retire_exact_supervisor(
                    clean_chat_id,
                    supervisor,
                )
            await self._unpin_mcp_supervisor(clean_chat_id, supervisor)

    def is_loaded(self, chat_id: str) -> bool:
        """Return whether this manager currently owns a connected SDK client."""

        supervisor = self._supervisors.get(str(chat_id))
        return bool(
            supervisor is not None
            and supervisor.connected
            and not supervisor.closed
        )

    async def evict(
        self,
        chat_id: str,
        *,
        force: bool = False,
        ownership_token: str | None = None,
    ) -> bool:
        """Disconnect one idle chat, or an active chat only when ``force`` is true."""

        self._bind_loop()
        assert self._lock is not None
        clean_chat_id = str(chat_id)
        async with self._lock:
            existing_close = self._evicting.get(clean_chat_id)
            supervisor = self._supervisors.get(clean_chat_id)
            if existing_close is not None:
                close_task = existing_close
            elif supervisor is None:
                return False
            else:
                if (
                    ownership_token is not None
                    and supervisor.ownership_token != str(ownership_token)
                ):
                    # A delayed finalizer from an older generation must not
                    # evict the replacement client now registered for chat.
                    return False
                if not force and (
                    supervisor.is_active or self._pins.get(clean_chat_id, 0)
                ):
                    return False
                self._supervisors.pop(clean_chat_id, None)
                self._pins.pop(clean_chat_id, None)
                close_task = asyncio.create_task(
                    supervisor.abort() if force else supervisor.close(),
                    name=f"claude-sdk-evict:{clean_chat_id}",
                )
                self._evicting[clean_chat_id] = close_task
        try:
            await asyncio.shield(close_task)
        finally:
            if close_task.done():
                async with self._lock:
                    if self._evicting.get(clean_chat_id) is close_task:
                        self._evicting.pop(clean_chat_id, None)
        return True

    async def evict_idle(self, *, exclude: set[str] | None = None) -> list[str]:
        """Apply TTL and LRU limits without ever evicting an active/pinned chat."""

        self._bind_loop()
        assert self._lock is not None
        excluded = {str(value) for value in (exclude or set())}
        now = time.monotonic()
        selected_ids: set[str] = set()
        async with self._lock:
            idle_candidates = [
                (chat_id, supervisor)
                for chat_id, supervisor in self._supervisors.items()
                if (
                    chat_id not in excluded
                    and not supervisor.is_active
                    and not self._pins.get(chat_id, 0)
                )
            ]
            idle_candidates.sort(key=lambda item: item[1].last_used_at)
            if self._idle_ttl_seconds is not None:
                for chat_id, supervisor in idle_candidates:
                    if now - supervisor.last_used_at >= self._idle_ttl_seconds:
                        selected_ids.add(chat_id)
            overflow = max(0, len(self._supervisors) - self._max_clients)
            if overflow:
                for chat_id, _supervisor in idle_candidates:
                    if len(selected_ids) >= overflow:
                        break
                    selected_ids.add(chat_id)
        if selected_ids:
            await asyncio.gather(
                *(self.evict(chat_id) for chat_id in selected_ids),
                return_exceptions=False,
            )
        return list(selected_ids)

    async def close_all(self) -> None:
        """Disconnect every per-chat process; used by AgentsServer shutdown."""

        try:
            self._bind_loop()
        except ClaudeSDKSupervisorClosed:
            return
        assert self._lock is not None
        async with self._lock:
            supervisors = list(self._supervisors.values())
            eviction_tasks = list(self._evicting.values())
            self._supervisors.clear()
            self._pins.clear()
            self._closed = True
            reaper_task = self._reaper_task
            self._reaper_task = None
        if reaper_task is not None and reaper_task is not asyncio.current_task():
            reaper_task.cancel()
            await asyncio.gather(reaper_task, return_exceptions=True)
        if supervisors:
            await asyncio.gather(
                *(supervisor.abort() for supervisor in supervisors),
                return_exceptions=False,
            )
        if eviction_tasks:
            await asyncio.gather(*eviction_tasks, return_exceptions=False)
        for supervisor in supervisors:
            for cleanup_task in supervisor.late_connect_cleanup_tasks():
                self._retired_cleanup_tasks.add(cleanup_task)
                cleanup_task.add_done_callback(
                    self._retired_cleanup_tasks.discard
                )
        retired_cleanup_tasks = tuple(self._retired_cleanup_tasks)
        if retired_cleanup_tasks:
            await asyncio.wait(
                retired_cleanup_tasks,
                timeout=self._disconnect_timeout_seconds,
            )
        async with self._lock:
            self._evicting.clear()

    def snapshots(self) -> list[ClaudeSDKSupervisorSnapshot]:
        return [supervisor.snapshot() for supervisor in self._supervisors.values()]
