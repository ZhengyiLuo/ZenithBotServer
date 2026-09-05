"""Strict loopback-first HTTP boundary for AgentsDock Team Hub V1."""

import asyncio
from collections import deque
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Annotated, Any, Callable, Literal
from urllib.parse import quote, urlsplit

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .auth import AuthenticationError, AuthorizationError
from .secure_peer import AttachmentFileLease
from .store import (
    MAX_NETWORK_BODY_BYTES,
    MAX_NETWORK_PAGE_ITEMS,
    MAX_HUMAN_ADMIN_PAGE_ITEMS,
    MAX_TEAM_MESSAGE_ATTACHMENTS,
    MAX_TEAM_MESSAGE_BODY_BYTES,
    MAX_TEAM_MESSAGE_RECIPIENTS,
    MAX_TEAM_SKILL_TAGS,
    TEAM_ATTACHMENT_CHUNK_BYTES,
    AccessClaims,
    HubError,
    HubStore,
)


MAX_JSON_BODY_BYTES = 65_536
# Team attachment bytes use one narrowly allowlisted binary lane instead of the
# JSON body pipeline: PUT chunks up to TEAM_ATTACHMENT_CHUNK_BYTES, GET/HEAD
# with Range. Nothing else escapes the JSON limits below.
TEAM_ATTACHMENT_CONTENT_RE = re.compile(
    r"^/v1/teams/[^/]+/network/attachments/[^/]+/content$"
)
_CONTENT_RANGE_RE = re.compile(
    r"^bytes (?P<start>[0-9]{1,15})-(?P<end>[0-9]{1,15})/(?P<total>[0-9]{1,15})$"
)
_RANGE_RE = re.compile(r"^bytes=(?P<start>[0-9]{0,15})-(?P<end>[0-9]{0,15})$")
_ATTACHMENT_STREAM_BLOCK_BYTES = 1024 * 1024
BODY_READ_TIMEOUT_SECONDS = 10.0
HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
TAILSCALE_SERVE_HEADERS_INFO = "https://tailscale.com/s/serve-headers"
# Set only by the authenticated parent AgentsServer mount. HTTP clients cannot
# manufacture ASGI scope extensions, so this keeps the core server credential
# out of the Team Hub credential realm while allowing every client authorized
# to the same AgentsServer to share its server-scoped Teamspace identity.
MANAGED_SERVER_SESSION_SCOPE_KEY = "agentsdock.team_hub.managed_server_session"


@dataclass(frozen=True)
class ManagedTransportIdentity:
    kind: Literal["loopback", "tailscale_serve", "direct_ip"]
    tailnet_login: str | None = None
    tailnet_user_name: str | None = None


@dataclass
class _RateBucket:
    bins: deque[tuple[int, int]]
    count: int
    last_seen: float


class _RateLimiter:
    """Bounded rolling-window limiter with one-second accounting bins."""

    def __init__(self, *, clock: Callable[[], float] | None = None) -> None:
        self._lock = threading.Lock()
        self._clock = time.monotonic if clock is None else clock
        self._buckets: dict[tuple[str, str], _RateBucket] = {}

    def _prune_locked(self, now: float) -> None:
        if len(self._buckets) <= 4096:
            return
        stale_before = now - 61.0
        self._buckets = {
            key: bucket
            for key, bucket in self._buckets.items()
            if bucket.last_seen > stale_before
        }
        if len(self._buckets) > 4096:
            oldest = sorted(
                self._buckets,
                key=lambda key: self._buckets[key].last_seen,
            )
            for key in oldest[: len(self._buckets) - 4096]:
                self._buckets.pop(key, None)

    def allow(self, peer: str, action: str, limit: int) -> bool:
        if limit <= 0:
            return False
        key = (peer, action)
        with self._lock:
            # Sample the clock only after acquiring the mutation lock. Two
            # callers can otherwise sample in chronological order but acquire
            # the lock in reverse order, leaving the pruning deque unsorted
            # and regressing last_seen.
            now = self._clock()
            current_second = int(now)
            cutoff = now - 60.0
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _RateBucket(deque(), 0, now)
                self._buckets[key] = bucket
            while bucket.bins and bucket.bins[0][0] + 1.0 <= cutoff:
                _second, expired_count = bucket.bins.popleft()
                bucket.count -= expired_count
            bucket.last_seen = now
            if bucket.count >= limit:
                self._prune_locked(now)
                return False
            if bucket.bins and bucket.bins[-1][0] == current_second:
                second, count = bucket.bins[-1]
                bucket.bins[-1] = (second, count + 1)
            else:
                bucket.bins.append((current_second, 1))
            bucket.count += 1
            self._prune_locked(now)
            return True


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class BootstrapRequest(StrictModel):
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=160)
    device_label: str = Field(min_length=1, max_length=160)


class RefreshRequest(StrictModel):
    refresh_token: str = Field(min_length=16, max_length=512)


class RevokeSessionRequest(StrictModel):
    refresh_token: str = Field(min_length=16, max_length=512)


class InviteRequest(StrictModel):
    invitee_email: str = Field(min_length=3, max_length=320)
    role: Literal["admin", "member", "guest"]
    ttl_seconds: int = Field(default=900, ge=30, le=86_400)


class MembershipUpdateRequest(StrictModel):
    role: Literal["admin", "member", "guest"] | None = None
    status: Literal["active", "suspended", "revoked"] | None = None

    @model_validator(mode="after")
    def exactly_one_change(self) -> "MembershipUpdateRequest":
        if (self.role is None) == (self.status is None):
            raise ValueError("exactly one membership change is required")
        return self


class RedeemInviteRequest(StrictModel):
    token: str = Field(min_length=16, max_length=512)
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=160)
    device_label: str = Field(min_length=1, max_length=160)


class AcceptInviteRequest(StrictModel):
    token: str = Field(min_length=16, max_length=512)


class RedeemRecoveryRequest(StrictModel):
    device_label: str = Field(min_length=1, max_length=160)


class NodeGrantRequest(StrictModel):
    server_identity: str = Field(min_length=8, max_length=240)
    display_name: str = Field(min_length=1, max_length=160)
    public_key: str = Field(min_length=32, max_length=16_384)
    ttl_seconds: int = Field(default=300, ge=30, le=900)


class NodeChallengeRequest(StrictModel):
    token: str = Field(min_length=16, max_length=512)
    server_identity: str = Field(min_length=8, max_length=240)
    display_name: str = Field(min_length=1, max_length=160)
    public_key: str = Field(min_length=32, max_length=16_384)


class NodeRedeemRequest(StrictModel):
    challenge_id: str = Field(min_length=8, max_length=240)
    signature: str = Field(min_length=80, max_length=128)


class ChannelRequest(StrictModel):
    kind: Literal["board", "announcements", "direct"]
    visibility: Literal["team", "private"] = "team"
    slug: str | None = Field(default=None, min_length=1, max_length=80)
    display_name: str | None = Field(default=None, min_length=1, max_length=160)
    participant_principal_ids: list[str] = Field(default_factory=list, max_length=256)
    idempotency_key: str = Field(min_length=8, max_length=240)


class MessageRequest(StrictModel):
    body: str = Field(min_length=1, max_length=65_536)
    body_format: Literal["plain", "markdown"] = "markdown"
    kind: Literal["post", "announcement"] = "post"
    thread_root_message_id: str | None = Field(default=None, min_length=1, max_length=240)
    parent_message_id: str | None = Field(default=None, min_length=1, max_length=240)
    idempotency_key: str = Field(min_length=8, max_length=240)


class NetworkAddress(StrictModel):
    kind: Literal["server", "agent"]
    id: str = Field(min_length=1, max_length=240)


class NetworkAgentRequest(StrictModel):
    external_agent_id: str = Field(min_length=1, max_length=240)
    backend: Literal["codex", "claude", "other"]
    display_name: str = Field(min_length=1, max_length=160)
    idempotency_key: str = Field(min_length=8, max_length=240)


class NetworkBulletinRequest(StrictModel):
    body: str = Field(min_length=1, max_length=MAX_NETWORK_BODY_BYTES)
    body_format: Literal["plain", "markdown"] = "markdown"
    reply_to_post_id: str | None = Field(default=None, min_length=1, max_length=240)
    idempotency_key: str = Field(min_length=8, max_length=240)


class NetworkMailboxRequest(StrictModel):
    to: NetworkAddress
    from_agent_id: str | None = Field(default=None, min_length=1, max_length=240)
    body: str = Field(min_length=1, max_length=MAX_NETWORK_BODY_BYTES)
    body_format: Literal["plain", "markdown"] = "markdown"
    idempotency_key: str = Field(min_length=8, max_length=240)


class NetworkPassiveRequest(NetworkMailboxRequest):
    expires_in_seconds: int = Field(default=86_400, ge=60, le=86_400)


class NetworkReplyRequest(StrictModel):
    from_agent_id: str | None = Field(default=None, min_length=1, max_length=240)
    body: str = Field(min_length=1, max_length=MAX_NETWORK_BODY_BYTES)
    body_format: Literal["plain", "markdown"] = "markdown"
    idempotency_key: str = Field(min_length=8, max_length=240)


class NetworkReceiptRequest(StrictModel):
    state: Literal["delivered", "read"]
    idempotency_key: str = Field(min_length=8, max_length=240)


class TeamRecipientRequest(StrictModel):
    kind: Literal["server", "human", "all"]
    id: str | None = Field(default=None, min_length=1, max_length=240)


class TeamSkillDetailsRequest(StrictModel):
    slug: str = Field(min_length=1, max_length=64)
    summary: str = Field(default="", max_length=280)
    tags: list[str] = Field(default_factory=list, max_length=MAX_TEAM_SKILL_TAGS)
    change_note: str = Field(default="", max_length=280)
    expected_version: int | None = Field(default=None, ge=1)


class TeamMessageRequest(StrictModel):
    kind: Literal["message", "skill"]
    title: str | None = Field(default=None, min_length=1, max_length=160)
    body: str = Field(min_length=1, max_length=MAX_TEAM_MESSAGE_BODY_BYTES)
    body_format: Literal["plain", "markdown"] = "markdown"
    recipients: list[TeamRecipientRequest] = Field(
        min_length=1, max_length=MAX_TEAM_MESSAGE_RECIPIENTS
    )
    attachment_ids: list[str] = Field(
        default_factory=list, max_length=MAX_TEAM_MESSAGE_ATTACHMENTS
    )
    in_reply_to_message_id: str | None = Field(default=None, min_length=8, max_length=240)
    skill: TeamSkillDetailsRequest | None = None
    provenance: dict[str, str | None] | None = None
    idempotency_key: str = Field(min_length=8, max_length=240)

    @field_validator("provenance")
    @classmethod
    def validate_provenance_keys(
        cls, value: dict[str, str | None] | None
    ) -> dict[str, str | None] | None:
        if value is not None and not set(value).issubset(
            {"via", "backend", "chat_id", "run_id"}
        ):
            raise ValueError("Team Message provenance contains unknown fields")
        return value


class TeamReceiptRequest(StrictModel):
    state: Literal["delivered", "read"]
    idempotency_key: str = Field(min_length=8, max_length=240)


class TeamAttachmentDeclareRequest(StrictModel):
    file_name: str = Field(min_length=1, max_length=255)
    media_type: str = Field(min_length=3, max_length=160)
    byte_size: int = Field(ge=1)
    sha256: str = Field(min_length=64, max_length=64)
    idempotency_key: str = Field(min_length=8, max_length=240)


class TeamSkillPinRequest(StrictModel):
    pinned: bool
    idempotency_key: str = Field(min_length=8, max_length=240)


class TeamSkillArchiveRequest(StrictModel):
    archived: bool
    idempotency_key: str = Field(min_length=8, max_length=240)


def attachment_content_response(
    request: Request,
    attachment: dict[str, Any],
    path: Path | int | AttachmentFileLease,
) -> Response:
    """Stream one ready attachment with byte-range support for video seeking."""

    size = int(attachment["byte_size"])
    headers = {
        "Accept-Ranges": "bytes",
        "Content-Disposition": (
            "inline; filename*=UTF-8''" + quote(str(attachment["file_name"]), safe="")
        ),
        "Cache-Control": "private, max-age=0",
        "X-Content-Type-Options": "nosniff",
        "ETag": f'"{attachment["sha256"]}"',
    }
    start, end, status = 0, size - 1, 200
    descriptor = path.descriptor if isinstance(path, AttachmentFileLease) else path

    def close_source() -> None:
        if isinstance(path, AttachmentFileLease):
            path.close()
        elif type(path) is int:
            try:
                os.close(path)
            except OSError:
                pass

    range_header = request.headers.get("range")
    if range_header:
        match = _RANGE_RE.fullmatch(range_header.strip())
        invalid = match is None
        if not invalid:
            raw_start, raw_end = match["start"], match["end"]
            if raw_start == "" and raw_end == "":
                invalid = True
            elif raw_start == "":
                suffix = int(raw_end)
                if suffix == 0:
                    invalid = True
                else:
                    start, end = max(0, size - suffix), size - 1
            else:
                start = int(raw_start)
                end = int(raw_end) if raw_end else size - 1
                if start >= size or end < start:
                    invalid = True
                end = min(end, size - 1)
        if invalid:
            close_source()
            return Response(
                status_code=416,
                headers={**headers, "Content-Range": f"bytes */{size}"},
            )
        status = 206
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    length = end - start + 1
    headers["Content-Length"] = str(length)
    media_type = str(attachment["media_type"])
    if request.method == "HEAD":
        close_source()
        return Response(status_code=status, headers=headers, media_type=media_type)

    def stream():
        if type(descriptor) is int:
            try:
                offset = start
                remaining = length
                while remaining > 0:
                    block = os.pread(
                        descriptor,
                        min(_ATTACHMENT_STREAM_BLOCK_BYTES, remaining),
                        offset,
                    )
                    if not block:
                        break
                    offset += len(block)
                    remaining -= len(block)
                    yield block
            finally:
                close_source()
            return
        with open(path, "rb") as handle:
            handle.seek(start)
            remaining = length
            while remaining > 0:
                block = handle.read(min(_ATTACHMENT_STREAM_BLOCK_BYTES, remaining))
                if not block:
                    break
                remaining -= len(block)
                yield block

    return StreamingResponse(
        stream(), status_code=status, headers=headers, media_type=media_type
    )


SecurePeerScope = Literal[
    "teamspace.read",
    "teamspace.write",
    "cross_chat.instruction",
    "cross_chat.request_reply",
]


class SecurePeerApprovalRequest(StrictModel):
    idempotency_key: str = Field(min_length=8, max_length=128)
    sas_confirmed: Literal[True]
    expected_peer_server_identity: str = Field(min_length=8, max_length=240)
    expected_transcript_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scopes: list[SecurePeerScope] = Field(min_length=1, max_length=4)


class SecurePeerRejectionRequest(StrictModel):
    idempotency_key: str = Field(min_length=8, max_length=128)
    expected_peer_server_identity: str = Field(min_length=8, max_length=240)
    expected_transcript_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str | None = Field(default=None, min_length=1, max_length=160)


class SecurePeerRevocationRequest(StrictModel):
    idempotency_key: str = Field(min_length=8, max_length=128)
    expected_certificate_fingerprint: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$"
    )


def _error(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"code": code, "message": message}})


def _is_loopback_peer(request: Request) -> bool:
    if request.client is None:
        return False
    try:
        return ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return False


def _has_loopback_authority(request: Request) -> bool:
    value = _exact_ascii_header(request, b"host")
    if value is None:
        return False
    host = _host_name(value)
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _host_name(authority: str) -> str | None:
    if not authority or "@" in authority or any(ord(char) < 33 or ord(char) > 126 for char in authority):
        return None
    port: str | None = None
    if authority.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::([0-9]+))?", authority)
        if match is None:
            return None
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            return None
        if address.version != 6:
            return None
        host = f"[{address.compressed}]"
        port = match.group(2)
    elif authority.count(":") > 1:
        try:
            address = ipaddress.ip_address(authority)
        except ValueError:
            return None
        if address.version != 6:
            return None
        host = address.compressed
    else:
        if ":" in authority:
            host, port = authority.rsplit(":", 1)
        else:
            host = authority
        if HOSTNAME_PATTERN.fullmatch(host) is None:
            return None
    if port is not None and (not port.isdigit() or not 1 <= int(port) <= 65535):
        return None
    return host.lower()


def _exact_ascii_header(request: Request, name: bytes) -> str | None:
    values = [
        value
        for key, value in request.scope.get("headers", [])
        if key.lower() == name
    ]
    if len(values) != 1:
        return None
    try:
        return values[0].decode("ascii")
    except UnicodeDecodeError:
        return None


def classify_managed_transport(
    request: Request,
    *,
    managed_transport: str,
    managed_hub_url: str,
) -> ManagedTransportIdentity | None:
    """Classify only a direct loopback call or the configured Serve proxy.

    Uvicorn deliberately runs with ``proxy_headers=False``. Therefore the
    socket peer and ASGI scheme remain the local Serve proxy and ``http``;
    forwarded values are evidence only when every Serve-owned header exactly
    matches the one configured public origin.
    """

    if request.url.scheme != "http":
        return None
    raw_names = [key.lower() for key, _value in request.scope.get("headers", [])]
    forwarded_names = {
        b"forwarded",
        b"x-forwarded-host",
        b"x-forwarded-proto",
        b"tailscale-user-login",
        b"tailscale-user-name",
        b"tailscale-headers-info",
        b"tailscale-funnel-request",
    }
    loopback_peer = _is_loopback_peer(request)
    if loopback_peer and _has_loopback_authority(request):
        if any(name in forwarded_names for name in raw_names):
            return None
        return ManagedTransportIdentity("loopback")
    if managed_transport == "direct_ip":
        direct_forbidden_headers = forwarded_names | {
            b"cookie",
            b"x-forwarded-for",
            b"x-forwarded-port",
            b"via",
        }
        if loopback_peer or any(name in direct_forbidden_headers for name in raw_names):
            return None
        try:
            parsed = urlsplit(managed_hub_url)
        except ValueError:
            return None
        if (
            parsed.scheme != "http"
            or not parsed.netloc
            or _exact_ascii_header(request, b"host") != parsed.netloc
        ):
            return None
        return ManagedTransportIdentity("direct_ip")
    if not loopback_peer:
        return None
    if managed_transport != "tailscale_serve":
        return None
    try:
        parsed = urlsplit(managed_hub_url)
    except ValueError:
        return None
    expected_authority = parsed.netloc
    if (
        parsed.scheme != "https"
        or not expected_authority
        or _exact_ascii_header(request, b"host") != expected_authority
        or _exact_ascii_header(request, b"x-forwarded-host") != expected_authority
        or _exact_ascii_header(request, b"x-forwarded-proto") != "https"
        or _exact_ascii_header(request, b"tailscale-headers-info")
        != TAILSCALE_SERVE_HEADERS_INFO
        or b"tailscale-funnel-request" in raw_names
        or b"forwarded" in raw_names
    ):
        return None
    login = _exact_ascii_header(request, b"tailscale-user-login")
    user_name = _exact_ascii_header(request, b"tailscale-user-name")
    if (
        login is None
        or user_name is None
        or login != login.strip().lower()
        or not 3 <= len(login) <= 320
        or "@" not in login
        or not 1 <= len(user_name.strip()) <= 160
        or any(ord(char) < 32 or ord(char) > 126 for char in login + user_name)
    ):
        return None
    return ManagedTransportIdentity(
        "tailscale_serve",
        tailnet_login=login,
        tailnet_user_name=user_name.strip(),
    )


def _mounted_route_path(request: Request) -> str:
    """Return the route-local path for standalone and mounted deployments."""

    path = str(request.scope.get("path") or request.url.path)
    root_path = str(request.scope.get("root_path") or "").rstrip("/")
    if root_path and path.startswith(root_path + "/"):
        return path[len(root_path) :]
    return path


def create_app(
    data_dir: str | Path,
    *,
    allowed_hosts: set[str] | None = None,
    allowed_origins: set[str] | None = None,
    managed_host_identity: str | None = None,
    managed_server_instance_id: str | None = None,
    managed_transport: str | None = None,
    managed_hub_url: str | None = None,
    managed_routes: dict[str, str] | None = None,
    secure_peer_manager: Any | None = None,
    managed_reactivation_hub_id: str | None = None,
    managed_reactivation_operation_id: str | None = None,
    managed_reactivation_snapshot: Path | None = None,
    managed_update_hub_id: str | None = None,
    managed_update_operation_id: str | None = None,
    managed_update_snapshot: Path | None = None,
    require_https_for_non_loopback: bool = False,
    require_loopback_transport: bool = False,
) -> FastAPI:
    store = HubStore(
        Path(data_dir),
        managed_host_identity=managed_host_identity,
        managed_server_instance_id=managed_server_instance_id,
        managed_reactivation_hub_id=managed_reactivation_hub_id,
        managed_reactivation_operation_id=managed_reactivation_operation_id,
        managed_reactivation_snapshot=managed_reactivation_snapshot,
        managed_update_hub_id=managed_update_hub_id,
        managed_update_operation_id=managed_update_operation_id,
        managed_update_snapshot=managed_update_snapshot,
    )
    hosts = allowed_hosts or {"127.0.0.1", "localhost", "[::1]", "::1"}
    origins = allowed_origins or set()
    rate_limiter = _RateLimiter()
    app = FastAPI(
        title="AgentsDock Team Hub",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url="/v1/openapi.json",
    )
    app.state.store = store
    app.state.rate_limiter = rate_limiter
    app.state.secure_peer_manager = secure_peer_manager

    @app.middleware("http")
    async def strict_transport(request: Request, call_next):
        raw_headers = request.scope.get("headers", [])
        managed_server_session = (
            request.scope.get(MANAGED_SERVER_SESSION_SCOPE_KEY) is True
        )
        values: dict[bytes, list[bytes]] = {}
        for key, value in raw_headers:
            values.setdefault(key.lower(), []).append(value)
        host_values = values.get(b"host", [])
        if len(host_values) != 1:
            return _error("invalid_request", "Invalid Host header", 400)
        try:
            host_header = host_values[0].decode("ascii")
        except UnicodeDecodeError:
            return _error("invalid_request", "Invalid Host header", 400)
        host_name = _host_name(host_header)
        if host_name is None or (
            not managed_server_session
            and host_name not in {item.lower() for item in hosts}
        ):
            return _error("invalid_request", "Invalid Host header", 400)
        managed_identity: ManagedTransportIdentity | None = None
        managed_identity_url: str | None = None
        configured_routes = managed_routes or (
            {managed_transport: managed_hub_url}
            if managed_transport is not None and managed_hub_url is not None
            else {}
        )
        if not managed_server_session and (
            managed_transport is not None or managed_routes is not None
        ):
            if not configured_routes:
                return _error("transport_configuration_invalid", "Transport is unavailable", 503)
            for route_kind, route_url in configured_routes.items():
                managed_identity = classify_managed_transport(
                    request,
                    managed_transport=route_kind,
                    managed_hub_url=route_url,
                )
                if managed_identity is not None:
                    managed_identity_url = route_url
                    break
            if managed_identity is None:
                return _error(
                    "local_preview_only",
                    "Embedded Team Hub transport is not permitted",
                    403,
                )
            request.state.team_hub_transport = managed_identity.kind
            request.state.team_hub_url = managed_identity_url
            request.state.tailnet_login = managed_identity.tailnet_login
        origin_values = values.get(b"origin", [])
        if len(origin_values) > 1:
            return _error("origin_forbidden", "Origin is not permitted", 403)
        if origin_values:
            try:
                origin = origin_values[0].decode("ascii")
            except UnicodeDecodeError:
                return _error("origin_forbidden", "Origin is not permitted", 403)
            if origin not in origins:
                return _error("origin_forbidden", "Origin is not permitted", 403)
        else:
            origin = None
        fetch_site = values.get(b"sec-fetch-site", [])
        if fetch_site and fetch_site[-1].lower() == b"cross-site":
            return _error("origin_forbidden", "Origin is not permitted", 403)
        if require_loopback_transport and (
            not _is_loopback_peer(request)
            or not _has_loopback_authority(request)
            or request.url.scheme != "http"
        ):
            return _error(
                "local_preview_only",
                "Embedded Team Hub is available only to this host",
                403,
            )
        if (
            require_https_for_non_loopback
            and not _is_loopback_peer(request)
            and request.url.scheme != "https"
        ):
            return _error(
                "transport_security_required",
                "Direct HTTPS is required for remote Team Hub access",
                403,
            )
        if request.method == "OPTIONS":
            requested_method = request.headers.get("access-control-request-method")
            if origin is None or requested_method not in {"GET", "POST", "PUT", "PATCH"}:
                return _error("origin_forbidden", "Origin is not permitted", 403)
            requested_headers = request.headers.get("access-control-request-headers", "")
            allowed_request_headers = {
                item.strip().lower() for item in requested_headers.split(",") if item.strip()
            }
            if not allowed_request_headers.issubset(
                {
                    "authorization",
                    "content-range",
                    "content-type",
                    "x-team-hub-bootstrap-proof",
                    "x-team-hub-bootstrap-request-id",
                    "x-team-hub-device-recovery-proof",
                    "x-team-hub-owner-recovery-proof",
                }
            ):
                return _error("origin_forbidden", "Origin is not permitted", 403)
            return Response(
                status_code=204,
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH",
                    "Access-Control-Allow-Headers": requested_headers,
                    "Vary": "Origin",
                },
            )

        def with_allowed_origin(response: Response) -> Response:
            if origin is not None:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Vary"] = "Origin"
            return response

        binary_lane_path = _mounted_route_path(request)
        binary_upload = (
            request.method == "PUT"
            and TEAM_ATTACHMENT_CONTENT_RE.fullmatch(binary_lane_path) is not None
        )
        unsafe_method = request.method not in {"GET", "HEAD", "OPTIONS"}
        if unsafe_method:
            try:
                maintenance_fenced = store.maintenance_fence() is not None
            except Exception:
                maintenance_fenced = True
            if maintenance_fenced:
                return with_allowed_origin(
                    _error(
                        "hub_maintenance",
                        "Team Hub is unavailable during server maintenance",
                        503,
                    )
                )
            if (
                managed_identity is not None
                and managed_identity.kind == "tailscale_serve"
                and managed_identity.tailnet_login is not None
            ):
                peer = "tailnet:" + hashlib.sha256(
                    managed_identity.tailnet_login.encode("utf-8")
                ).hexdigest()
            else:
                peer = request.client.host if request.client is not None else "unknown"
            route_path = binary_lane_path
            sensitive_limits = {
                "/v1/bootstrap/redeem": 8,
                "/v1/owner-recovery/redeem": 8,
                "/v1/device-recovery/redeem": 8,
                "/v1/sessions/refresh": 30,
                "/v1/invitations/redeem": 30,
                "/v1/node-enrollments/challenge": 30,
                "/v1/node-enrollments/redeem": 30,
            }
            if binary_upload:
                action, limit = "attachment_upload", 1_200
            else:
                action = (
                    route_path
                    if route_path in sensitive_limits
                    else f"other_{request.method.lower()}"
                )
                limit = sensitive_limits.get(route_path, 120)
            if (
                not rate_limiter.allow(peer, action, limit)
                or not rate_limiter.allow("*", action, limit * 100)
            ):
                return with_allowed_origin(
                    _error("rate_limited", "Too many requests", 429)
                )
        if values.get(b"transfer-encoding"):
            return with_allowed_origin(
                _error("invalid_request", "Transfer-Encoding is not accepted", 400)
            )
        lengths = values.get(b"content-length", [])
        if len(lengths) > 1:
            return with_allowed_origin(
                _error("invalid_request", "Duplicate Content-Length is not accepted", 400)
            )
        if binary_upload:
            # Attachment chunks: exact octet-stream body, one Content-Range, no
            # JSON parsing. The route handler and store re-validate the range.
            if len(lengths) != 1:
                return with_allowed_origin(
                    _error("invalid_request", "Exactly one Content-Length is required", 400)
                )
            try:
                raw_length = lengths[0].decode("ascii")
                body_length = int(raw_length, 10)
            except (UnicodeDecodeError, ValueError):
                return with_allowed_origin(
                    _error("invalid_request", "Content-Length is invalid", 400)
                )
            if raw_length != str(body_length) or not 1 <= body_length <= TEAM_ATTACHMENT_CHUNK_BYTES:
                return with_allowed_origin(
                    _error("request_too_large", "Attachment chunk size is invalid", 413)
                )
            if values.get(b"content-type", []) != [b"application/octet-stream"]:
                return with_allowed_origin(
                    _error(
                        "invalid_request",
                        "Content-Type must be application/octet-stream",
                        415,
                    )
                )
            if len(values.get(b"content-range", [])) != 1:
                return with_allowed_origin(
                    _error("invalid_request", "Exactly one Content-Range is required", 400)
                )
        elif request.method in {"POST", "PUT", "PATCH"}:
            if len(lengths) != 1:
                return with_allowed_origin(
                    _error("invalid_request", "Exactly one Content-Length is required", 400)
                )
            try:
                raw_length = lengths[0].decode("ascii")
                body_length = int(raw_length, 10)
            except (UnicodeDecodeError, ValueError):
                return with_allowed_origin(
                    _error("invalid_request", "Content-Length is invalid", 400)
                )
            if raw_length != str(body_length) or not 2 <= body_length <= MAX_JSON_BODY_BYTES:
                return with_allowed_origin(
                    _error("invalid_request", "JSON body size is invalid", 413)
                )
            content_types = values.get(b"content-type", [])
            if content_types != [b"application/json"]:
                return with_allowed_origin(
                    _error("invalid_request", "Content-Type must be application/json", 415)
                )
            try:
                body = await asyncio.wait_for(
                    request.body(), timeout=BODY_READ_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                return with_allowed_origin(
                    _error("request_timeout", "Request body timed out", 408)
                )
            if len(body) != body_length:
                return with_allowed_origin(
                    _error("invalid_request", "Content-Length does not match body", 400)
                )
            try:
                parsed = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return with_allowed_origin(
                    _error("invalid_request", "Request body must be valid JSON", 400)
                )
            if not isinstance(parsed, dict):
                return with_allowed_origin(
                    _error("invalid_request", "Request body must be a JSON object", 400)
                )
            try:
                json.dumps(parsed, ensure_ascii=False).encode("utf-8")
            except UnicodeEncodeError:
                return with_allowed_origin(
                    _error("invalid_request", "Request body contains invalid Unicode", 400)
                )
        return with_allowed_origin(await call_next(request))

    @app.exception_handler(HubError)
    async def hub_error_handler(_request: Request, exc: HubError):
        return _error(exc.code, exc.message, exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, _exc: RequestValidationError):
        return _error("invalid_request", "Request validation failed", 422)

    @app.exception_handler(HTTPException)
    async def http_error_handler(_request: Request, exc: HTTPException):
        if exc.status_code == 404:
            return _error("not_found", "Resource not found", 404)
        return _error("request_failed", "Request failed", exc.status_code)

    @app.exception_handler(AuthenticationError)
    async def authentication_error_handler(_request: Request, _exc: AuthenticationError):
        return _error("authentication_required", "Authentication required", 401)

    @app.exception_handler(AuthorizationError)
    async def authorization_error_handler(_request: Request, _exc: AuthorizationError):
        return _error("forbidden", "Operation is not permitted", 403)

    @app.exception_handler(ValueError)
    async def value_error_handler(_request: Request, _exc: ValueError):
        return _error("invalid_request", "Request validation failed", 422)

    @app.exception_handler(Exception)
    async def unexpected_error_handler(_request: Request, _exc: Exception):
        return _error("internal_error", "Internal server error", 500)

    def claims_from_request(request: Request) -> AccessClaims:
        if request.scope.get(MANAGED_SERVER_SESSION_SCOPE_KEY) is True:
            return store.managed_server_claims()
        raw = request.scope.get("headers", [])
        authorization = [value for key, value in raw if key.lower() == b"authorization"]
        if len(authorization) != 1:
            raise HubError("authentication_required", "Authentication required", 401)
        try:
            value = authorization[0].decode("ascii")
        except UnicodeDecodeError as exc:
            raise HubError("authentication_required", "Authentication required", 401) from exc
        if not value.startswith("Bearer ") or " " in value[7:] or not value[7:]:
            raise HubError("authentication_required", "Authentication required", 401)
        return store.verify_access(value[7:])

    Auth = Annotated[AccessClaims, Depends(claims_from_request)]

    @app.get("/v1/health")
    def health(request: Request) -> dict[str, Any]:
        result = store.health()
        if request.scope.get(MANAGED_SERVER_SESSION_SCOPE_KEY) is True:
            server_session_available = False
            if result["bootstrapped"]:
                try:
                    store.managed_server_claims()
                except Exception:
                    server_session_available = False
                else:
                    server_session_available = True
            result["server_session_available"] = server_session_available
        return result

    @app.get("/v1/server-session")
    def server_session(request: Request) -> dict[str, Any]:
        if request.scope.get(MANAGED_SERVER_SESSION_SCOPE_KEY) is not True:
            raise HubError("not_found", "Resource not found", 404)
        return store.session_snapshot(store.managed_server_claims())

    @app.post("/v1/bootstrap/redeem")
    def bootstrap(request: Request, body: BootstrapRequest) -> dict[str, Any]:
        proof = _exact_ascii_header(request, b"x-team-hub-bootstrap-proof")
        if proof is None:
            raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 403)
        transport = getattr(request.state, "team_hub_transport", None)
        if transport is None:
            transport = (
                "loopback"
                if _is_loopback_peer(request) and _has_loopback_authority(request)
                else None
            )
        if transport == "loopback":
            if _exact_ascii_header(
                request, b"x-team-hub-bootstrap-request-id"
            ) is not None:
                raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 403)
            return store.bootstrap(
                proof,
                body.email,
                body.display_name,
                body.device_label,
                transport="loopback",
            )
        if transport == "tailscale_serve":
            request_id = _exact_ascii_header(
                request, b"x-team-hub-bootstrap-request-id"
            )
            tailnet_login = getattr(request.state, "tailnet_login", None)
            route_hub_url = getattr(request.state, "team_hub_url", None)
            if request_id is None or tailnet_login is None or route_hub_url is None:
                raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 403)
            return store.bootstrap(
                proof,
                body.email,
                body.display_name,
                body.device_label,
                transport="tailscale_serve",
                request_id=request_id,
                tailnet_login=tailnet_login,
                hub_url=route_hub_url,
            )
        if transport == "direct_ip":
            request_id = _exact_ascii_header(
                request, b"x-team-hub-bootstrap-request-id"
            )
            route_hub_url = getattr(request.state, "team_hub_url", None)
            if request_id is None or route_hub_url is None:
                raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 403)
            return store.bootstrap(
                proof,
                body.email,
                body.display_name,
                body.device_label,
                transport="direct_ip",
                request_id=request_id,
                tailnet_login=body.email,
                hub_url=route_hub_url,
            )
        raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 403)

    @app.post("/v1/owner-recovery/redeem")
    def owner_recovery(request: Request, body: RedeemRecoveryRequest) -> dict[str, Any]:
        if not _is_loopback_peer(request) or not _has_loopback_authority(request):
            raise HubError("recovery_unavailable", "Owner recovery is unavailable", 403)
        proof = _exact_ascii_header(request, b"x-team-hub-owner-recovery-proof")
        if proof is None:
            raise HubError("recovery_unavailable", "Owner recovery is unavailable", 403)
        return store.redeem_owner_recovery(proof, body.device_label)

    @app.post("/v1/device-recovery/redeem")
    def device_recovery(request: Request, body: RedeemRecoveryRequest) -> dict[str, Any]:
        classified = getattr(request.state, "team_hub_transport", None)
        loopback_peer = _is_loopback_peer(request)
        if classified not in {"loopback", "tailscale_serve", "direct_ip"} and (
            (loopback_peer and not _has_loopback_authority(request))
            or (not loopback_peer and request.url.scheme != "https")
        ):
            raise HubError("recovery_unavailable", "Device recovery is unavailable", 403)
        proof = _exact_ascii_header(request, b"x-team-hub-device-recovery-proof")
        if proof is None:
            raise HubError("recovery_unavailable", "Device recovery is unavailable", 403)
        return store.redeem_device_recovery(proof, body.device_label)

    @app.post("/v1/sessions/refresh")
    def refresh(body: RefreshRequest) -> dict[str, Any]:
        return store.refresh(body.refresh_token)

    @app.post("/v1/sessions/revoke")
    def revoke_session(body: RevokeSessionRequest, claims: Auth) -> dict[str, Any]:
        return store.revoke_session(claims, body.refresh_token)

    @app.get("/v1/sessions")
    def device_sessions(
        claims: Auth,
        limit: Annotated[int, Query(ge=1, le=MAX_HUMAN_ADMIN_PAGE_ITEMS)] = 50,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
    ) -> dict[str, Any]:
        return store.list_device_sessions_page(
            claims,
            limit=limit,
            cursor=cursor,
        )

    @app.post("/v1/sessions/{session_id}/revoke")
    def revoke_device_session(session_id: str, claims: Auth) -> dict[str, Any]:
        return store.revoke_device_session(claims, session_id)

    @app.get("/v1/session")
    def session(claims: Auth) -> dict[str, Any]:
        return store.session_snapshot(claims)

    @app.get("/v1/teams")
    def teams(claims: Auth) -> dict[str, Any]:
        return store.list_teams(claims)

    @app.get("/v1/teams/{team_id}")
    def team(team_id: str, claims: Auth) -> dict[str, Any]:
        return store.get_team(claims, team_id)

    @app.get("/v1/teams/{team_id}/members")
    def members(
        team_id: str,
        claims: Auth,
        limit: Annotated[int, Query(ge=1, le=MAX_HUMAN_ADMIN_PAGE_ITEMS)] = 50,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
    ) -> dict[str, Any]:
        return store.list_members(claims, team_id, limit=limit, cursor=cursor)

    @app.get("/v1/teams/{team_id}/members/{principal_id}")
    def member(
        team_id: str,
        principal_id: str,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.get_member(claims, team_id, principal_id)

    @app.patch("/v1/teams/{team_id}/members/{principal_id}")
    def update_member(
        team_id: str,
        principal_id: str,
        body: MembershipUpdateRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.update_human_membership(
            claims,
            team_id,
            principal_id,
            role=body.role,
            status=body.status,
        )

    @app.post("/v1/teams/{team_id}/invitations")
    def invite(team_id: str, body: InviteRequest, claims: Auth) -> dict[str, Any]:
        return store.issue_invite(
            claims, team_id, body.invitee_email, body.role, body.ttl_seconds
        )

    @app.get("/v1/teams/{team_id}/invitations")
    def pending_invitations(
        team_id: str,
        claims: Auth,
        limit: Annotated[int, Query(ge=1, le=MAX_HUMAN_ADMIN_PAGE_ITEMS)] = 50,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
    ) -> dict[str, Any]:
        return store.list_pending_invitations(
            claims,
            team_id,
            limit=limit,
            cursor=cursor,
        )

    @app.post("/v1/teams/{team_id}/invitations/{invitation_id}/revoke")
    def revoke_invitation(
        team_id: str,
        invitation_id: str,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.revoke_invitation(claims, team_id, invitation_id)

    @app.post("/v1/invitations/redeem")
    def redeem_invite(body: RedeemInviteRequest) -> dict[str, Any]:
        return store.redeem_invite(
            body.token, body.email, body.display_name, body.device_label
        )

    @app.post("/v1/invitations/accept")
    def accept_invite(body: AcceptInviteRequest, claims: Auth) -> dict[str, Any]:
        return store.accept_invite(claims, body.token)

    @app.post("/v1/teams/{team_id}/node-enrollments")
    def node_grant(team_id: str, body: NodeGrantRequest, claims: Auth) -> dict[str, Any]:
        return store.issue_node_grant(
            claims,
            team_id,
            body.server_identity,
            body.display_name,
            body.public_key,
            body.ttl_seconds,
        )

    @app.post("/v1/node-enrollments/challenge")
    def node_challenge(body: NodeChallengeRequest) -> dict[str, Any]:
        return store.node_challenge(
            body.token, body.server_identity, body.display_name, body.public_key
        )

    @app.post("/v1/node-enrollments/redeem")
    def node_redeem(body: NodeRedeemRequest) -> dict[str, Any]:
        return store.redeem_node_challenge(body.challenge_id, body.signature)

    @app.get("/v1/teams/{team_id}/nodes")
    def nodes(team_id: str, claims: Auth) -> dict[str, Any]:
        return store.list_nodes(claims, team_id)

    @app.get("/v1/teams/{team_id}/secure-peers")
    def secure_peers(team_id: str, claims: Auth) -> dict[str, Any]:
        store.require_team_admin(claims, team_id)
        if secure_peer_manager is None:
            raise HubError(
                "secure_peer_unavailable",
                "Secure peer pairing is unavailable",
                503,
            )
        return secure_peer_manager.list_peers(team_id=team_id)

    @app.post("/v1/teams/{team_id}/secure-peers/{peer_id}/revoke")
    def revoke_secure_peer(
        team_id: str,
        peer_id: str,
        body: SecurePeerRevocationRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        store.require_team_admin(claims, team_id)
        if secure_peer_manager is None:
            raise HubError(
                "secure_peer_unavailable",
                "Secure peer pairing is unavailable",
                503,
            )
        return secure_peer_manager.revoke_peer(
            peer_id=peer_id,
            team_id=team_id,
            revoked_by=claims.principal_id,
            expected_certificate_fingerprint=(
                body.expected_certificate_fingerprint
            ),
            idempotency_key=body.idempotency_key,
        )

    @app.get("/v1/teams/{team_id}/network")
    def network(
        team_id: str,
        claims: Auth,
        after_server_id: Annotated[
            str | None, Query(min_length=8, max_length=240)
        ] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_NETWORK_PAGE_ITEMS)] = 50,
    ) -> dict[str, Any]:
        return store.get_network(
            claims,
            team_id,
            after_server_id=after_server_id,
            limit=limit,
        )

    @app.get("/v1/teams/{team_id}/network/servers/{server_id}")
    def network_server(
        team_id: str,
        server_id: str,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.get_network_server(claims, team_id, server_id)

    @app.post("/v1/teams/{team_id}/network/agents")
    def register_network_agent(
        team_id: str,
        body: NetworkAgentRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.register_network_agent(claims, team_id, body.model_dump())

    @app.get("/v1/teams/{team_id}/network/bulletin")
    def network_bulletin(
        team_id: str,
        claims: Auth,
        after_sequence: Annotated[
            int, Query(ge=0, le=9_223_372_036_854_775_807)
        ] = 0,
        limit: Annotated[int, Query(ge=1, le=MAX_NETWORK_PAGE_ITEMS)] = 50,
    ) -> dict[str, Any]:
        return store.list_network_bulletin(
            claims,
            team_id,
            after_sequence=after_sequence,
            limit=limit,
        )

    @app.post("/v1/teams/{team_id}/network/bulletin")
    def create_network_bulletin_post(
        team_id: str,
        body: NetworkBulletinRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.create_network_bulletin_post(
            claims, team_id, body.model_dump()
        )

    @app.get("/v1/teams/{team_id}/network/mailbox")
    def network_mailbox(
        team_id: str,
        claims: Auth,
        address_kind: Annotated[Literal["human", "server", "agent"], Query()],
        address_id: Annotated[str, Query(min_length=1, max_length=240)],
        after_sequence: Annotated[
            int, Query(ge=0, le=9_223_372_036_854_775_807)
        ] = 0,
        limit: Annotated[int, Query(ge=1, le=MAX_NETWORK_PAGE_ITEMS)] = 50,
    ) -> dict[str, Any]:
        return store.list_network_mailbox(
            claims,
            team_id,
            address_kind=address_kind,
            address_id=address_id,
            after_sequence=after_sequence,
            limit=limit,
        )

    @app.post("/v1/teams/{team_id}/network/mailbox")
    def send_network_mailbox_item(
        team_id: str,
        body: NetworkMailboxRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.create_network_mailbox_item(
            claims, team_id, body.model_dump()
        )

    @app.get("/v1/teams/{team_id}/network/items/{item_id}")
    def network_item(
        team_id: str,
        item_id: str,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.get_network_item(claims, team_id, item_id)

    @app.post("/v1/teams/{team_id}/network/deliveries/{delivery_id}/receipts")
    def network_delivery_receipt(
        team_id: str,
        delivery_id: str,
        body: NetworkReceiptRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.record_network_delivery_receipt(
            claims, team_id, delivery_id, body.model_dump()
        )

    @app.post("/v1/teams/{team_id}/network/requests")
    def create_network_request(
        team_id: str,
        body: NetworkPassiveRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.create_network_request(claims, team_id, body.model_dump())

    @app.get("/v1/teams/{team_id}/network/requests/{request_id}")
    def network_request(
        team_id: str,
        request_id: str,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.get_network_request(claims, team_id, request_id)

    @app.post("/v1/teams/{team_id}/network/requests/{request_id}/replies")
    def create_network_request_reply(
        team_id: str,
        request_id: str,
        body: NetworkReplyRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.create_network_request_reply(
            claims, team_id, request_id, body.model_dump()
        )

    @app.get("/v1/teams/{team_id}/network/messages")
    def team_messages(
        team_id: str,
        claims: Auth,
        box: Annotated[Literal["inbox", "feed", "sent"], Query()] = "inbox",
        address_kind: Annotated[Literal["server", "human"] | None, Query()] = None,
        address_id: Annotated[str | None, Query(min_length=1, max_length=240)] = None,
        unread: Annotated[bool, Query()] = False,
        from_kind: Annotated[Literal["server", "human"] | None, Query()] = None,
        from_id: Annotated[str | None, Query(min_length=1, max_length=240)] = None,
        since: Annotated[str | None, Query(min_length=1, max_length=40)] = None,
        after_sequence: Annotated[
            int, Query(ge=0, le=9_223_372_036_854_775_807)
        ] = 0,
        limit: Annotated[int, Query(ge=1, le=MAX_NETWORK_PAGE_ITEMS)] = 50,
    ) -> dict[str, Any]:
        return store.list_team_messages(
            claims,
            team_id,
            box=box,
            address_kind=address_kind,
            address_id=address_id,
            unread=unread,
            from_kind=from_kind,
            from_id=from_id,
            since=since,
            after_sequence=after_sequence,
            limit=limit,
        )

    @app.post("/v1/teams/{team_id}/network/messages")
    def create_team_message(
        team_id: str,
        body: TeamMessageRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.create_team_message(claims, team_id, body.model_dump())

    @app.get("/v1/teams/{team_id}/network/messages/{message_id}")
    def team_message(team_id: str, message_id: str, claims: Auth) -> dict[str, Any]:
        return store.get_team_message(claims, team_id, message_id)

    @app.post("/v1/teams/{team_id}/network/messages/{message_id}/receipts")
    def team_message_receipt(
        team_id: str,
        message_id: str,
        body: TeamReceiptRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.record_team_message_receipt(
            claims, team_id, message_id, body.model_dump()
        )

    @app.post("/v1/teams/{team_id}/network/attachments")
    def declare_team_attachment(
        team_id: str,
        body: TeamAttachmentDeclareRequest,
        claims: Auth,
    ) -> dict[str, Any]:
        return store.declare_team_attachment(claims, team_id, body.model_dump())

    @app.get("/v1/teams/{team_id}/network/attachments/{attachment_id}")
    def team_attachment(
        team_id: str, attachment_id: str, claims: Auth
    ) -> dict[str, Any]:
        return store.get_team_attachment(claims, team_id, attachment_id)

    @app.put("/v1/teams/{team_id}/network/attachments/{attachment_id}/content")
    async def upload_team_attachment_chunk(
        team_id: str,
        attachment_id: str,
        request: Request,
        claims: Auth,
    ) -> dict[str, Any]:
        match = _CONTENT_RANGE_RE.fullmatch(request.headers.get("content-range", "").strip())
        if match is None:
            raise HubError("invalid_request", "Content-Range is required", 422)
        start, end, total = int(match["start"]), int(match["end"]), int(match["total"])
        if end < start or total < 1 or end >= total:
            raise HubError("invalid_request", "Content-Range is invalid", 422)
        data = await asyncio.wait_for(request.body(), timeout=BODY_READ_TIMEOUT_SECONDS * 6)
        if len(data) != end - start + 1:
            raise HubError("invalid_request", "Chunk length does not match Content-Range", 422)
        return store.write_team_attachment_chunk(
            claims, team_id, attachment_id, offset=start, total=total, data=data
        )

    @app.api_route(
        "/v1/teams/{team_id}/network/attachments/{attachment_id}/content",
        methods=["GET", "HEAD"],
    )
    def download_team_attachment(
        team_id: str,
        attachment_id: str,
        request: Request,
        claims: Auth,
    ) -> Response:
        attachment, path = store.open_team_attachment(claims, team_id, attachment_id)
        return attachment_content_response(request, attachment, path)

    @app.get("/v1/teams/{team_id}/network/skills")
    def team_skills(
        team_id: str,
        claims: Auth,
        include_archived: Annotated[bool, Query()] = False,
        slug: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    ) -> dict[str, Any]:
        return store.list_team_skills(
            claims, team_id, include_archived=include_archived, slug=slug
        )

    @app.get("/v1/teams/{team_id}/network/skills/{skill_id}")
    def team_skill(team_id: str, skill_id: str, claims: Auth) -> dict[str, Any]:
        return store.get_team_skill(claims, team_id, skill_id)

    @app.get("/v1/teams/{team_id}/network/skills/{skill_id}/versions")
    def team_skill_versions(team_id: str, skill_id: str, claims: Auth) -> dict[str, Any]:
        return store.list_team_skill_versions(claims, team_id, skill_id)

    @app.get("/v1/teams/{team_id}/network/skills/{skill_id}/versions/{version}")
    def team_skill_version(
        team_id: str, skill_id: str, version: int, claims: Auth
    ) -> dict[str, Any]:
        return store.get_team_skill_version(claims, team_id, skill_id, version)

    @app.post("/v1/teams/{team_id}/network/skills/{skill_id}/pin")
    def pin_team_skill(
        team_id: str, skill_id: str, body: TeamSkillPinRequest, claims: Auth
    ) -> dict[str, Any]:
        return store.set_team_skill_pinned(claims, team_id, skill_id, body.model_dump())

    @app.post("/v1/teams/{team_id}/network/skills/{skill_id}/archive")
    def archive_team_skill(
        team_id: str, skill_id: str, body: TeamSkillArchiveRequest, claims: Auth
    ) -> dict[str, Any]:
        return store.set_team_skill_archived(claims, team_id, skill_id, body.model_dump())

    @app.get("/v1/teams/{team_id}/channels")
    def channels(team_id: str, claims: Auth) -> dict[str, Any]:
        return store.list_channels(claims, team_id)

    @app.post("/v1/teams/{team_id}/channels")
    def create_channel(team_id: str, body: ChannelRequest, claims: Auth) -> dict[str, Any]:
        return store.create_channel(claims, team_id, body.model_dump())

    @app.get("/v1/channels/{channel_id}/messages")
    def messages(
        channel_id: str,
        claims: Auth,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        before_sequence: Annotated[int | None, Query(ge=1)] = None,
    ) -> dict[str, Any]:
        return store.list_messages(claims, channel_id, limit, before_sequence)

    @app.post("/v1/channels/{channel_id}/messages")
    def create_message(channel_id: str, body: MessageRequest, claims: Auth) -> dict[str, Any]:
        return store.create_message(claims, channel_id, body.model_dump())

    @app.post("/v1/dispatches")
    def dispatch_unavailable(claims: Auth) -> dict[str, Any]:
        store.session_snapshot(claims)
        raise HubError(
            "dispatch_unavailable",
            "Dispatch requires a scoped capability and node connector",
            501,
        )

    return app
