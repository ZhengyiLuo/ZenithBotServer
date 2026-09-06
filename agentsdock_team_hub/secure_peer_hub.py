"""Fixed, in-process Team Hub adapter for authenticated secure peers.

The TLS gateway authenticates and authorizes the peer before constructing a
``ProxyRequest``.  This adapter never accepts a bearer token and never makes an
HTTP request: it maps the small V1 allowlist directly onto ``HubStore`` using a
synthetic, live-checked automation principal.
"""

from __future__ import annotations

from contextlib import suppress
import json
from collections import deque
import os
import re
import stat
import threading
import time
from typing import Any, Callable
from urllib.parse import parse_qsl, quote

from .auth import _identity
from .secure_peer import (
    AttachmentFileLease,
    AttachmentProxyRequest,
    AttachmentProxyResponse,
    PeerAuthorization,
    ProxyRequest,
    ProxyResponse,
)
from .security import canonical_json
from .store import MAX_NETWORK_BODY_BYTES, HubError, HubStore


_TEAM_PREFIX = "/v1/teams/"
_CHANNEL_PREFIX = "/v1/channels/"
_MESSAGE_SUFFIX = "/messages"
_NETWORK_CHILD = "network"
_CONTENT_RANGE_RE = re.compile(
    r"^bytes (?P<start>[0-9]{1,15})-(?P<end>[0-9]{1,15})/"
    r"(?P<total>[0-9]{1,15})$"
)
_RANGE_RE = re.compile(r"^bytes=(?P<start>[0-9]{0,15})-(?P<end>[0-9]{0,15})$")


class SecurePeerHubAdapter:
    """Translate the gateway's exact allowlist into Team Hub store calls."""

    def __init__(self, store: HubStore) -> None:
        self.store = store
        self._rate_lock = threading.Lock()
        self._rate_condition = threading.Condition(self._rate_lock)
        self._rate_events: dict[tuple[str, str], deque[float]] = {}
        self._in_flight: dict[str, int] = {}
        self._revoking: set[str] = set()
        self._stream_aborters: dict[str, set[Callable[[], None]]] = {}

    def _admit(
        self, peer_id: str, *, write: bool, attachment: bool = False
    ) -> None:
        """Bound authenticated-peer CPU/concurrency before touching SQLite."""

        now = time.monotonic()
        with self._rate_condition:
            if peer_id in self._revoking:
                raise HubError(
                    "forbidden", "Secure peer authorization is being revoked", 403
                )
            in_flight = self._in_flight.get(peer_id, 0)
            if in_flight >= 4:
                raise HubError(
                    "rate_limited",
                    "Secure peer has too many concurrent requests",
                    429,
                )
            limits = (
                (("attachment", 1_200),)
                if attachment
                else (("all", 240), ("write", 60))
            )
            for kind, limit in limits:
                if kind == "write" and not write:
                    continue
                key = (peer_id, kind)
                events = self._rate_events.setdefault(key, deque())
                while events and events[0] <= now - 60.0:
                    events.popleft()
                if len(events) >= limit:
                    raise HubError(
                        "rate_limited",
                        "Secure peer request limit exceeded",
                        429,
                    )
                events.append(now)
            self._in_flight[peer_id] = in_flight + 1

    def _release(self, peer_id: str) -> None:
        with self._rate_condition:
            remaining = self._in_flight.get(peer_id, 0) - 1
            if remaining > 0:
                self._in_flight[peer_id] = remaining
            else:
                self._in_flight.pop(peer_id, None)
            self._rate_condition.notify_all()

    def provision_peer(self, peer: dict[str, Any], *, display_name: str) -> str:
        """Bind an approved peer once, before request-time read-only claims."""

        return self.store.ensure_secure_peer_service(
            peer_id=str(peer["peer_id"]),
            peer_server_identity=str(peer["peer_server_identity"]),
            team_id=str(peer["team_id"]),
            display_name=display_name,
        )

    def preflight_team(self, team_id: str) -> None:
        self.store.require_secure_peer_target_team(team_id)

    def active_binding_peer_ids(
        self,
        peer_ids: list[str] | tuple[str, ...],
        peer_server_identity: str,
    ) -> set[str]:
        return self.store.active_secure_peer_binding_ids(
            peer_ids,
            peer_server_identity,
        )

    def record_peer_heartbeat(self, peer_id: str, team_id: str) -> None:
        self.store.record_secure_peer_heartbeat(peer_id, team_id)

    def expire_peer_leases(self, stale_before: int) -> int:
        return self.store.expire_secure_peer_leases(stale_before)

    def revoke_peer(self, *, peer_id: str, team_id: str) -> None:
        # The core peer credential is revoked before this projection call.
        # Fence new adapter work and wait for already-authorized response
        # streams so successful revocation proves no old peer still has bytes.
        with self._rate_condition:
            self._revoking.add(peer_id)
        while True:
            with self._rate_condition:
                if self._in_flight.get(peer_id, 0) <= 0:
                    break
                aborters = tuple(self._stream_aborters.get(peer_id, ()))
            for abort in aborters:
                with suppress(Exception):
                    abort()
            with self._rate_condition:
                if self._in_flight.get(peer_id, 0) > 0:
                    self._rate_condition.wait(timeout=0.25)
        try:
            self.store.revoke_secure_peer_service(peer_id=peer_id, team_id=team_id)
        finally:
            with self._rate_condition:
                self._revoking.discard(peer_id)
                self._rate_condition.notify_all()

    def resource_team(self, resource_kind: str, resource_id: str) -> str | None:
        return self.store.secure_peer_resource_team(resource_kind, resource_id)

    @staticmethod
    def _json(status: int, value: dict[str, Any]) -> ProxyResponse:
        return ProxyResponse(
            status=status,
            headers=(("content-type", "application/json"), ("cache-control", "no-store")),
            body=canonical_json(value),
        )

    @staticmethod
    def _claims(store: HubStore, peer: PeerAuthorization):
        return store.secure_peer_claims(
            peer_id=peer.peer_id,
            peer_server_identity=peer.peer_server_identity,
            team_id=peer.team_id,
            scopes=peer.scopes,
            expires_at=peer.certificate_expires_at,
            display_name=peer.peer_display_name,
        )

    @staticmethod
    def _message_body(request: ProxyRequest) -> dict[str, Any]:
        try:
            value = json.loads(request.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HubError("invalid_request", "Request body is invalid", 422) from exc
        if not isinstance(value, dict):
            raise HubError("invalid_request", "Request body is invalid", 422)
        allowed = {
            "body",
            "body_format",
            "kind",
            "thread_root_message_id",
            "parent_message_id",
            "idempotency_key",
        }
        if not set(value).issubset(allowed) or not {"body", "idempotency_key"}.issubset(value):
            raise HubError("invalid_request", "Request body is invalid", 422)
        body = value.get("body")
        key = value.get("idempotency_key")
        body_format = value.get("body_format", "markdown")
        kind = value.get("kind", "post")
        if (
            not isinstance(body, str)
            or not 1 <= len(body.encode("utf-8", "strict")) <= 65_536
            or not isinstance(key, str)
            or key != key.strip()
            or not 8 <= len(key.encode("utf-8", "strict")) <= 240
            or body_format not in {"plain", "markdown"}
            or kind not in {"post", "announcement"}
        ):
            raise HubError("invalid_request", "Request body is invalid", 422)
        result = {
            "body": body,
            "body_format": body_format,
            "kind": kind,
            "thread_root_message_id": value.get("thread_root_message_id"),
            "parent_message_id": value.get("parent_message_id"),
            "idempotency_key": key,
        }
        for field in ("thread_root_message_id", "parent_message_id"):
            item = result[field]
            if item is not None and (
                not isinstance(item, str)
                or item != item.strip()
                or not 1 <= len(item.encode("utf-8", "strict")) <= 240
            ):
                raise HubError("invalid_request", "Request body is invalid", 422)
        return result

    @staticmethod
    def _object_body(
        request: ProxyRequest,
        *,
        allowed: set[str],
        required: set[str],
    ) -> dict[str, Any]:
        try:
            value = json.loads(request.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HubError("invalid_request", "Request body is invalid", 422) from exc
        if (
            not isinstance(value, dict)
            or not set(value).issubset(allowed)
            or not required.issubset(value)
        ):
            raise HubError("invalid_request", "Request body is invalid", 422)
        return value

    @staticmethod
    def _identifier(
        value: Any,
        *,
        minimum: int = 1,
        maximum: int = 240,
    ) -> str:
        try:
            encoded = value.encode("utf-8", "strict") if isinstance(value, str) else b""
        except UnicodeEncodeError as exc:
            raise HubError("invalid_request", "Request body is invalid", 422) from exc
        if (
            not isinstance(value, str)
            or value != value.strip()
            or not minimum <= len(encoded) <= maximum
        ):
            raise HubError("invalid_request", "Request body is invalid", 422)
        return value

    @staticmethod
    def _resource_id(value: Any) -> str:
        try:
            return _identity(value) if isinstance(value, str) else _identity("")
        except ValueError as exc:
            raise HubError("invalid_request", "Resource identifier is invalid", 422) from exc

    @classmethod
    def _address(cls, value: Any) -> dict[str, str]:
        if not isinstance(value, dict) or set(value) != {"kind", "id"}:
            raise HubError("invalid_request", "Request body is invalid", 422)
        if value.get("kind") != "server":
            raise HubError("invalid_request", "Request body is invalid", 422)
        return {
            "kind": str(value["kind"]),
            "id": cls._identifier(value.get("id")),
        }

    @classmethod
    def _network_agent_body(cls, request: ProxyRequest) -> dict[str, Any]:
        value = cls._object_body(
            request,
            allowed={
                "external_agent_id",
                "backend",
                "display_name",
                "idempotency_key",
            },
            required={
                "external_agent_id",
                "backend",
                "display_name",
                "idempotency_key",
            },
        )
        if value.get("backend") not in {"codex", "claude", "other"}:
            raise HubError("invalid_request", "Request body is invalid", 422)
        return {
            "external_agent_id": cls._identifier(value["external_agent_id"]),
            "backend": value["backend"],
            "display_name": cls._identifier(value["display_name"], maximum=160),
            "idempotency_key": cls._identifier(
                value["idempotency_key"], minimum=8
            ),
        }

    @classmethod
    def _network_text_body(
        cls,
        request: ProxyRequest,
        *,
        mode: str,
    ) -> dict[str, Any]:
        if mode == "bulletin":
            allowed = {
                "body",
                "body_format",
                "reply_to_post_id",
                "idempotency_key",
            }
            required = {"body", "idempotency_key"}
        elif mode == "mailbox":
            allowed = {
                "to",
                "from_agent_id",
                "body",
                "body_format",
                "idempotency_key",
            }
            required = {"to", "body", "idempotency_key"}
        elif mode == "request":
            allowed = {
                "to",
                "from_agent_id",
                "body",
                "body_format",
                "expires_in_seconds",
                "idempotency_key",
            }
            required = {"to", "body", "idempotency_key"}
        elif mode == "reply":
            allowed = {
                "from_agent_id",
                "body",
                "body_format",
                "idempotency_key",
            }
            required = {"body", "idempotency_key"}
        else:  # pragma: no cover - internal contract only.
            raise RuntimeError("unknown Team Networks body mode")
        value = cls._object_body(
            request, allowed=allowed, required=required
        )
        body = value.get("body")
        try:
            body_bytes = body.encode("utf-8", "strict") if isinstance(body, str) else b""
        except UnicodeEncodeError as exc:
            raise HubError("invalid_request", "Request body is invalid", 422) from exc
        body_format = value.get("body_format", "markdown")
        if not 1 <= len(body_bytes) <= MAX_NETWORK_BODY_BYTES or body_format not in {"plain", "markdown"}:
            raise HubError("invalid_request", "Request body is invalid", 422)
        result: dict[str, Any] = {
            "body": body,
            "body_format": body_format,
            "idempotency_key": cls._identifier(
                value["idempotency_key"], minimum=8
            ),
        }
        from_agent = value.get("from_agent_id")
        if mode in {"mailbox", "request", "reply"} and from_agent is not None:
            # A secure peer speaks for its authenticated server identity.  It
            # may not forge an agent sender, even when replaying a legacy body.
            raise HubError("invalid_request", "Request body is invalid", 422)
        result["from_agent_id"] = None
        if mode in {"mailbox", "request"}:
            result["to"] = cls._address(value.get("to"))
        if mode == "bulletin":
            reply_to = value.get("reply_to_post_id")
            result["reply_to_post_id"] = (
                cls._identifier(reply_to) if reply_to is not None else None
            )
            result.pop("from_agent_id", None)
        if mode == "request":
            ttl = value.get("expires_in_seconds", 86_400)
            if type(ttl) is not int or not 60 <= ttl <= 86_400:
                raise HubError("invalid_request", "Request body is invalid", 422)
            result["expires_in_seconds"] = ttl
        return result

    @classmethod
    def _network_receipt_body(cls, request: ProxyRequest) -> dict[str, Any]:
        value = cls._object_body(
            request,
            allowed={"state", "idempotency_key"},
            required={"state", "idempotency_key"},
        )
        if value.get("state") not in {"delivered", "read"}:
            raise HubError("invalid_request", "Request body is invalid", 422)
        return {
            "state": value["state"],
            "idempotency_key": cls._identifier(
                value["idempotency_key"], minimum=8
            ),
        }

    @classmethod
    def _team_message_body(cls, request: ProxyRequest) -> dict[str, Any]:
        """Shape-check a Team Messages V2 create request; the store validates values."""

        value = cls._object_body(
            request,
            allowed={
                "kind",
                "title",
                "body",
                "body_format",
                "recipients",
                "attachment_ids",
                "in_reply_to_message_id",
                "skill",
                "provenance",
                "idempotency_key",
            },
            required={"kind", "body", "recipients", "idempotency_key"},
        )
        recipients = value.get("recipients")
        if (
            not isinstance(recipients, list)
            or not 1 <= len(recipients) <= 16
            or any(
                not isinstance(item, dict) or not set(item).issubset({"kind", "id"})
                for item in recipients
            )
        ):
            raise HubError("invalid_request", "Request body is invalid", 422)
        skill = value.get("skill")
        if skill is not None and (
            not isinstance(skill, dict)
            or not set(skill).issubset(
                {"slug", "summary", "tags", "change_note", "expected_version"}
            )
        ):
            raise HubError("invalid_request", "Request body is invalid", 422)
        value["idempotency_key"] = cls._identifier(value["idempotency_key"], minimum=8)
        return value

    @classmethod
    def _team_receipt_body(cls, request: ProxyRequest) -> dict[str, Any]:
        value = cls._object_body(
            request,
            allowed={"state", "idempotency_key"},
            required={"state", "idempotency_key"},
        )
        if value.get("state") not in {"delivered", "read"}:
            raise HubError("invalid_request", "Request body is invalid", 422)
        return {
            "state": value["state"],
            "idempotency_key": cls._identifier(value["idempotency_key"], minimum=8),
        }

    @classmethod
    def _team_attachment_body(cls, request: ProxyRequest) -> dict[str, Any]:
        value = cls._object_body(
            request,
            allowed={"file_name", "media_type", "byte_size", "sha256", "idempotency_key"},
            required={"file_name", "media_type", "byte_size", "sha256", "idempotency_key"},
        )
        value["idempotency_key"] = cls._identifier(value["idempotency_key"], minimum=8)
        return value

    @classmethod
    def _team_skill_flag_body(cls, request: ProxyRequest, flag: str) -> dict[str, Any]:
        value = cls._object_body(
            request,
            allowed={flag, "idempotency_key"},
            required={flag, "idempotency_key"},
        )
        if type(value.get(flag)) is not bool:
            raise HubError("invalid_request", "Request body is invalid", 422)
        return {
            flag: value[flag],
            "idempotency_key": cls._identifier(value["idempotency_key"], minimum=8),
        }

    @staticmethod
    def _team_query(request: ProxyRequest, *, allowed: set[str]) -> dict[str, str]:
        """Bound Team Messages V2 query strings without mailbox-specific rules."""

        try:
            pairs = parse_qsl(request.query, keep_blank_values=True, strict_parsing=True)
        except ValueError as exc:
            raise HubError("invalid_request", "Query is invalid", 422) from exc
        if len(pairs) != len({key for key, _value in pairs}) or any(
            key not in allowed for key, _value in pairs
        ):
            raise HubError("invalid_request", "Query is invalid", 422)
        values = dict(pairs)
        for key in ("after_sequence", "limit"):
            if key in values and (
                not values[key].isdigit() or str(int(values[key])) != values[key]
            ):
                raise HubError("invalid_request", "Query is invalid", 422)
        if "limit" in values and not 1 <= int(values["limit"]) <= 100:
            raise HubError("invalid_request", "Query is invalid", 422)
        if "cursor" in values:
            if re.fullmatch(r"v1\.[A-Za-z0-9_-]{38,500}", values["cursor"]) is None:
                raise HubError("invalid_request", "Query is invalid", 422)
        for key in ("address_id", "from_id"):
            if key in values:
                values[key] = SecurePeerHubAdapter._resource_id(values[key])
        return values

    @staticmethod
    def _query_flag(values: dict[str, str], key: str) -> bool:
        return values.get(key, "0") in {"1", "true"}

    @staticmethod
    def _query(
        request: ProxyRequest,
        *,
        allowed: set[str],
    ) -> dict[str, str]:
        try:
            pairs = parse_qsl(request.query, keep_blank_values=True, strict_parsing=True)
        except ValueError as exc:
            raise HubError("invalid_request", "Query is invalid", 422) from exc
        if len(pairs) != len({key for key, _value in pairs}) or any(
            key not in allowed for key, _value in pairs
        ):
            raise HubError("invalid_request", "Query is invalid", 422)
        values = dict(pairs)
        for key in ("after_sequence", "limit"):
            if key in values and (
                not values[key].isdigit()
                or str(int(values[key])) != values[key]
            ):
                raise HubError("invalid_request", "Query is invalid", 422)
        if "after_sequence" in values and not 0 <= int(
            values["after_sequence"]
        ) <= 9_223_372_036_854_775_807:
            raise HubError("invalid_request", "Query is invalid", 422)
        if "limit" in values and not 1 <= int(values["limit"]) <= 100:
            raise HubError("invalid_request", "Query is invalid", 422)
        if "address_kind" in values and values["address_kind"] != "server":
            raise HubError("invalid_request", "Query is invalid", 422)
        if "address_id" in values:
            values["address_id"] = SecurePeerHubAdapter._resource_id(
                values["address_id"]
            )
        if "after_server_id" in values:
            values["after_server_id"] = SecurePeerHubAdapter._resource_id(
                values["after_server_id"]
            )
        return values

    @staticmethod
    def _attachment_error(exc: HubError) -> AttachmentProxyResponse:
        body = canonical_json({"error": {"code": exc.code, "message": exc.message}})
        return AttachmentProxyResponse(
            status=exc.status_code,
            headers=(
                ("content-type", "application/json"),
                ("cache-control", "no-store"),
            ),
            body=body,
            length=len(body),
        )

    def forward_attachment(
        self, request: AttachmentProxyRequest
    ) -> AttachmentProxyResponse:
        """Serve the attachment-only binary lane after gateway authorization."""

        admitted = False
        deferred_release = False
        attachment_source: AttachmentFileLease | None = None
        attachment_source_transferred = False
        try:
            self._admit(
                request.peer.peer_id,
                write=request.method == "PUT",
                attachment=True,
            )
            admitted = True
            claims = self._claims(self.store, request.peer)
            pieces = request.path[len(_TEAM_PREFIX) :].split("/")
            if (
                len(pieces) != 5
                or pieces[1:3] != [_NETWORK_CHILD, "attachments"]
                or pieces[4] != "content"
            ):
                raise HubError("not_found", "Resource not found", 404)
            team_id = pieces[0]
            attachment_id = self._resource_id(pieces[3])
            headers = dict(request.headers)
            if request.method == "PUT":
                match = _CONTENT_RANGE_RE.fullmatch(headers.get("content-range", ""))
                if match is None:
                    raise HubError("invalid_request", "Content-Range is invalid", 422)
                start = int(match.group("start"))
                end = int(match.group("end"))
                total = int(match.group("total"))
                if end < start or end - start + 1 != len(request.body) or end >= total:
                    raise HubError("invalid_request", "Content-Range is invalid", 422)
                result = self.store.write_team_attachment_chunk(
                    claims,
                    team_id,
                    attachment_id,
                    offset=start,
                    total=total,
                    data=request.body,
                )
                body = canonical_json(result)
                return AttachmentProxyResponse(
                    status=200,
                    headers=(
                        ("content-type", "application/json"),
                        ("cache-control", "no-store"),
                    ),
                    body=body,
                    length=len(body),
                )

            attachment, source = self.store.open_team_attachment(
                claims, team_id, attachment_id
            )
            attachment_source = source
            size = int(attachment["byte_size"])
            response_headers: list[tuple[str, str]] = [
                ("accept-ranges", "bytes"),
                (
                    "content-disposition",
                    "inline; filename*=UTF-8''"
                    + quote(str(attachment["file_name"]), safe=""),
                ),
                ("cache-control", "private, max-age=0"),
                ("x-content-type-options", "nosniff"),
                ("etag", f'"{attachment["sha256"]}"'),
                ("content-type", str(attachment["media_type"])),
            ]
            start, end, status = 0, size - 1, 200
            range_value = headers.get("range")
            if range_value:
                match = _RANGE_RE.fullmatch(range_value)
                invalid = match is None
                if not invalid and match is not None:
                    raw_start, raw_end = match.group("start"), match.group("end")
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
                    source.close()
                    response_headers.append(("content-range", f"bytes */{size}"))
                    return AttachmentProxyResponse(
                        status=416,
                        headers=tuple(response_headers),
                    )
                status = 206
                response_headers.append(
                    ("content-range", f"bytes {start}-{end}/{size}")
                )
            descriptor = source.descriptor
            try:
                info = os.fstat(descriptor)
            except OSError as exc:
                source.close()
                raise HubError(
                    "attachment_unavailable", "Attachment content is unavailable", 409
                ) from exc
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_size != size
            ):
                source.close()
                raise HubError(
                    "attachment_unavailable", "Attachment content is unavailable", 409
                )

            stream_lock = threading.RLock()
            finalized = False
            cancelled = threading.Event()

            def abort() -> None:
                # Never close a descriptor from the revocation thread while
                # the gateway may be between pread calls. Descriptor numbers
                # can be reused process-wide. The gateway observes this flag,
                # owns descriptor closure, and releases the stream lease.
                cancelled.set()

            def finalize() -> None:
                nonlocal finalized
                with stream_lock:
                    if finalized:
                        return
                    finalized = True
                source.close()
                with self._rate_condition:
                    aborters = self._stream_aborters.get(request.peer.peer_id)
                    if aborters is not None:
                        aborters.discard(abort)
                        if not aborters:
                            self._stream_aborters.pop(request.peer.peer_id, None)
                self._release(request.peer.peer_id)

            with self._rate_condition:
                if request.peer.peer_id in self._revoking:
                    # The descriptor has not escaped to the gateway yet, so
                    # this thread still owns it and can close it synchronously.
                    source.close()
                    raise HubError(
                        "forbidden", "Secure peer authorization is being revoked", 403
                    )
                self._stream_aborters.setdefault(request.peer.peer_id, set()).add(
                    abort
                )
            response = AttachmentProxyResponse(
                status=status,
                headers=tuple(response_headers),
                descriptor=descriptor,
                offset=start,
                length=end - start + 1,
                finalizer=finalize,
                cancelled=cancelled.is_set,
            )
            deferred_release = True
            attachment_source_transferred = True
            return response
        except HubError as exc:
            return self._attachment_error(exc)
        finally:
            if attachment_source is not None and not attachment_source_transferred:
                attachment_source.close()
            if admitted and not deferred_release:
                self._release(request.peer.peer_id)

    def forward(self, request: ProxyRequest) -> ProxyResponse:
        """Serve one already-sanitized request without network recursion."""

        admitted = False
        try:
            self._admit(
                request.peer.peer_id,
                write=request.method not in {"GET", "HEAD"},
            )
            admitted = True
            claims = self._claims(self.store, request.peer)
            path = request.path
            if request.method == "GET" and path == "/v1/health":
                result = {**self.store.health(), "peer_session_available": True}
            elif request.method == "GET" and path in {"/v1/peer-session", "/v1/session"}:
                result = self.store.session_snapshot(claims)
            elif request.method == "GET" and path == "/v1/teams":
                result = self.store.list_teams(claims)
            elif request.method == "GET" and path.startswith(_TEAM_PREFIX):
                remainder = path[len(_TEAM_PREFIX) :]
                pieces = remainder.split("/")
                team_id = pieces[0]
                if len(pieces) == 1:
                    result = self.store.get_team(claims, team_id)
                elif len(pieces) == 2 and pieces[1] == "members":
                    values = self._query(request, allowed={"limit", "cursor"})
                    result = self.store.list_members(
                        claims,
                        team_id,
                        limit=int(values.get("limit", "50")),
                        cursor=values.get("cursor"),
                    )
                elif len(pieces) == 3 and pieces[1] == "members":
                    self._query(request, allowed=set())
                    result = self.store.get_member(claims, team_id, pieces[2])
                elif len(pieces) == 2 and pieces[1] == "nodes":
                    result = self.store.list_nodes(claims, team_id)
                elif len(pieces) == 2 and pieces[1] == "channels":
                    result = self.store.list_channels(claims, team_id)
                elif len(pieces) == 2 and pieces[1] == _NETWORK_CHILD:
                    values = self._query(
                        request, allowed={"after_server_id", "limit"}
                    )
                    result = self.store.get_network(
                        claims,
                        team_id,
                        after_server_id=values.get("after_server_id"),
                        limit=int(values.get("limit", "50")),
                    )
                elif (
                    len(pieces) == 4
                    and pieces[1:3] == [_NETWORK_CHILD, "servers"]
                ):
                    self._query(request, allowed=set())
                    result = self.store.get_network_server(
                        claims,
                        team_id,
                        self._resource_id(pieces[3]),
                    )
                elif len(pieces) == 3 and pieces[1:] == [_NETWORK_CHILD, "bulletin"]:
                    values = self._query(
                        request, allowed={"after_sequence", "limit"}
                    )
                    result = self.store.list_network_bulletin(
                        claims,
                        team_id,
                        after_sequence=int(values.get("after_sequence", "0")),
                        limit=int(values.get("limit", "50")),
                    )
                elif len(pieces) == 3 and pieces[1:] == [_NETWORK_CHILD, "mailbox"]:
                    values = self._query(
                        request,
                        allowed={
                            "address_kind",
                            "address_id",
                            "after_sequence",
                            "limit",
                        },
                    )
                    if not {"address_kind", "address_id"}.issubset(values):
                        raise HubError("invalid_request", "Query is invalid", 422)
                    result = self.store.list_network_mailbox(
                        claims,
                        team_id,
                        address_kind=values["address_kind"],
                        address_id=values["address_id"],
                        after_sequence=int(values.get("after_sequence", "0")),
                        limit=int(values.get("limit", "50")),
                    )
                elif (
                    len(pieces) == 4
                    and pieces[1:3] == [_NETWORK_CHILD, "items"]
                ):
                    result = self.store.get_network_item(
                        claims, team_id, self._resource_id(pieces[3])
                    )
                elif (
                    len(pieces) == 4
                    and pieces[1:3] == [_NETWORK_CHILD, "requests"]
                ):
                    result = self.store.get_network_request(
                        claims, team_id, self._resource_id(pieces[3])
                    )
                elif len(pieces) == 3 and pieces[1:] == [_NETWORK_CHILD, "messages"]:
                    values = self._team_query(
                        request,
                        allowed={
                            "box",
                            "address_kind",
                            "address_id",
                            "unread",
                            "from_kind",
                            "from_id",
                            "since",
                            "after_sequence",
                            "limit",
                        },
                    )
                    result = self.store.list_team_messages(
                        claims,
                        team_id,
                        box=values.get("box", "inbox"),
                        address_kind=values.get("address_kind"),
                        address_id=values.get("address_id"),
                        unread=self._query_flag(values, "unread"),
                        from_kind=values.get("from_kind"),
                        from_id=values.get("from_id"),
                        since=values.get("since"),
                        after_sequence=int(values.get("after_sequence", "0")),
                        limit=int(values.get("limit", "50")),
                    )
                elif len(pieces) == 4 and pieces[1:3] == [_NETWORK_CHILD, "messages"]:
                    result = self.store.get_team_message(
                        claims, team_id, self._resource_id(pieces[3])
                    )
                elif len(pieces) == 4 and pieces[1:3] == [_NETWORK_CHILD, "attachments"]:
                    result = self.store.get_team_attachment(
                        claims, team_id, self._resource_id(pieces[3])
                    )
                elif len(pieces) == 3 and pieces[1:] == [_NETWORK_CHILD, "skills"]:
                    values = self._team_query(request, allowed={"include_archived", "slug"})
                    result = self.store.list_team_skills(
                        claims,
                        team_id,
                        include_archived=self._query_flag(values, "include_archived"),
                        slug=values.get("slug"),
                    )
                elif len(pieces) == 4 and pieces[1:3] == [_NETWORK_CHILD, "skills"]:
                    result = self.store.get_team_skill(
                        claims, team_id, self._resource_id(pieces[3])
                    )
                elif (
                    len(pieces) == 5
                    and pieces[1:3] == [_NETWORK_CHILD, "skills"]
                    and pieces[4] == "versions"
                ):
                    result = self.store.list_team_skill_versions(
                        claims, team_id, self._resource_id(pieces[3])
                    )
                elif (
                    len(pieces) == 6
                    and pieces[1:3] == [_NETWORK_CHILD, "skills"]
                    and pieces[4] == "versions"
                    and pieces[5].isdigit()
                ):
                    result = self.store.get_team_skill_version(
                        claims, team_id, self._resource_id(pieces[3]), int(pieces[5])
                    )
                else:  # The gateway sanitizer should make this unreachable.
                    raise HubError("not_found", "Resource not found", 404)
            elif request.method == "POST" and path.startswith(_TEAM_PREFIX):
                remainder = path[len(_TEAM_PREFIX) :]
                pieces = remainder.split("/")
                team_id = pieces[0]
                if len(pieces) == 3 and pieces[1:] == [_NETWORK_CHILD, "agents"]:
                    result = self.store.register_network_agent(
                        claims, team_id, self._network_agent_body(request)
                    )
                elif len(pieces) == 3 and pieces[1:] == [_NETWORK_CHILD, "bulletin"]:
                    result = self.store.create_network_bulletin_post(
                        claims,
                        team_id,
                        self._network_text_body(request, mode="bulletin"),
                    )
                elif len(pieces) == 3 and pieces[1:] == [_NETWORK_CHILD, "mailbox"]:
                    result = self.store.create_network_mailbox_item(
                        claims,
                        team_id,
                        self._network_text_body(request, mode="mailbox"),
                    )
                elif len(pieces) == 3 and pieces[1:] == [_NETWORK_CHILD, "requests"]:
                    result = self.store.create_network_request(
                        claims,
                        team_id,
                        self._network_text_body(request, mode="request"),
                    )
                elif (
                    len(pieces) == 5
                    and pieces[1:3] == [_NETWORK_CHILD, "deliveries"]
                    and pieces[4] == "receipts"
                ):
                    result = self.store.record_network_delivery_receipt(
                        claims,
                        team_id,
                        self._resource_id(pieces[3]),
                        self._network_receipt_body(request),
                    )
                elif (
                    len(pieces) == 5
                    and pieces[1:3] == [_NETWORK_CHILD, "requests"]
                    and pieces[4] == "replies"
                ):
                    request_id = self._resource_id(pieces[3])
                    reply_body = self._network_text_body(request, mode="reply")
                    existing_request = self.store.get_network_request(
                        claims,
                        team_id,
                        request_id,
                    )
                    request_item = existing_request.get("item")
                    sender = (
                        request_item.get("from")
                        if isinstance(request_item, dict)
                        else None
                    )
                    recipient = (
                        request_item.get("to")
                        if isinstance(request_item, dict)
                        else None
                    )
                    if (
                        not isinstance(sender, dict)
                        or not isinstance(recipient, dict)
                        or sender.get("kind") == "agent"
                        or recipient.get("kind") == "agent"
                    ):
                        raise HubError(
                            "invalid_request",
                            "Agent-addressed peer replies are retired",
                            422,
                        )
                    result = self.store.create_network_request_reply(
                        claims,
                        team_id,
                        request_id,
                        reply_body,
                    )
                elif len(pieces) == 3 and pieces[1:] == [_NETWORK_CHILD, "messages"]:
                    result = self.store.create_team_message(
                        claims, team_id, self._team_message_body(request)
                    )
                elif (
                    len(pieces) == 5
                    and pieces[1:3] == [_NETWORK_CHILD, "messages"]
                    and pieces[4] == "receipts"
                ):
                    result = self.store.record_team_message_receipt(
                        claims,
                        team_id,
                        self._resource_id(pieces[3]),
                        self._team_receipt_body(request),
                    )
                elif len(pieces) == 3 and pieces[1:] == [_NETWORK_CHILD, "attachments"]:
                    result = self.store.declare_team_attachment(
                        claims, team_id, self._team_attachment_body(request)
                    )
                elif (
                    len(pieces) == 5
                    and pieces[1:3] == [_NETWORK_CHILD, "skills"]
                    and pieces[4] in {"pin", "archive"}
                ):
                    flag = "pinned" if pieces[4] == "pin" else "archived"
                    setter = (
                        self.store.set_team_skill_pinned
                        if flag == "pinned"
                        else self.store.set_team_skill_archived
                    )
                    result = setter(
                        claims,
                        team_id,
                        self._resource_id(pieces[3]),
                        self._team_skill_flag_body(request, flag),
                    )
                else:
                    raise HubError("not_found", "Resource not found", 404)
            elif path.startswith(_CHANNEL_PREFIX) and path.endswith(_MESSAGE_SUFFIX):
                channel_id = path[len(_CHANNEL_PREFIX) : -len(_MESSAGE_SUFFIX)]
                if request.method == "GET":
                    values = dict(parse_qsl(request.query, keep_blank_values=True))
                    result = self.store.list_messages(
                        claims,
                        channel_id,
                        int(values.get("limit", "50")),
                        (
                            int(values["before_sequence"])
                            if "before_sequence" in values
                            else None
                        ),
                    )
                elif request.method == "POST":
                    result = self.store.create_message(
                        claims,
                        channel_id,
                        self._message_body(request),
                    )
                else:
                    raise HubError("not_found", "Resource not found", 404)
            else:
                raise HubError("not_found", "Resource not found", 404)
            return self._json(200, result)
        except HubError as exc:
            return self._json(
                exc.status_code,
                {"error": {"code": exc.code, "message": exc.message}},
            )
        finally:
            if admitted:
                self._release(request.peer.peer_id)
