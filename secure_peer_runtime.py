"""AgentsServer lifecycle and local-control boundary for secure peer V1."""

from __future__ import annotations

from contextlib import suppress
from datetime import datetime, timezone
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import re
import socket
import stat
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, quote, urlencode
import uuid

from agentsdock_team_hub.secure_peer import (
    AttachmentFileLease,
    AttachmentProxyRequest,
    AttachmentProxyResponse,
    MAX_ATTACHMENT_PROTOCOL_BYTES,
    PAIRING_STATUS_LIMIT,
    PEER_HEARTBEAT_LEASE_SECONDS,
    PeerAuthorization,
    SecurePeerClient,
    SecurePeerError,
    SecurePeerGateway,
    SecurePeerStore,
    canonical_peer_ipv4,
    canonical_peer_port,
)
from agentsdock_team_hub.secure_peer_hub import SecurePeerHubAdapter
from agentsdock_team_hub.security import canonical_json, ensure_private_directory
from agentsdock_team_hub.store import (
    TEAM_ATTACHMENT_CHUNK_BYTES,
    TEAM_ATTACHMENT_FILE_NAME_RE,
    HubError,
    HubStore,
)
from secure_peer_delivery import SecurePeerDeliveryLedger


SECURE_PEER_CONTROL_VERSION = 2
SECURE_PEER_PROXY_PREFIX = "/api/team-hub-secure"
SECURE_PEER_HEARTBEAT_SECONDS = 30
SECURE_PEER_LEASE_SECONDS = PEER_HEARTBEAT_LEASE_SECONDS
SECURE_PEER_OFFLINE_FAILURES = 3
DEFAULT_TEAM_CACHE_MAX_BYTES = 10 * 1024 * 1024 * 1024
_TEAM_CACHE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,239}$")
_TEAM_CACHE_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TEAM_CACHE_META_NAME = ".metadata.json"
_TEAM_CACHE_META_MAX_BYTES = 4096
_TEAM_CACHE_DIRECTORY_SCAN_LIMIT = 4096
_TEAM_CACHE_OVERFLOW_RECOVERY_PASSES = 8
_TEAM_EXPORT_TTL_SECONDS = 60 * 60
_TEAM_EXPORT_MAX_BATCHES = 128
_TEAM_EXPORT_BATCH_RE = re.compile(r"^export-([0-9]{10})-([0-9a-f]{32})$")
_TEAM_EXPORT_TEMP_RE = re.compile(r"^\.export-([0-9a-f]{32})\.tmp$")
_PAIRING_ACTIONABLE_STATUSES = frozenset(
    {"requesting", "pending_approval", "approved", "connected"}
)
_CONFIG_KEYS = {
    "version",
    "server_identity",
    "enabled",
    "advertised_host",
    "listen_port",
}


class _UnavailableSecurePeerClient:
    """Fail-closed placeholder that keeps the optional feature boot-isolated."""

    def __init__(self, message: str) -> None:
        self.message = message

    def list_connections(self) -> list[dict[str, Any]]:
        return []

    def retire_agent_routes_locally(self) -> int:
        """Keep local chat lifecycle available when peer state is quarantined."""

        # A quarantined client has no trusted route store to mutate.  Relay is
        # disabled, so archive/delete must remain a local operation rather than
        # failing through ``__getattr__`` with an unrelated peer-state error.
        return 0

    def __getattr__(self, _name: str):
        def unavailable(*_args: Any, **_kwargs: Any) -> Any:
            raise SecurePeerError(
                "secure_peer_state_unavailable",
                self.message,
                503,
            )

        return unavailable


def _iso8601(value: Any) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(int(value), timezone.utc).isoformat().replace("+00:00", "Z")


def _fingerprint_public_key_pem(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_public_key(value.encode("ascii"))
        der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:
        return None
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _stable_uuid4(label: str) -> str:
    value = bytearray(hashlib.sha256(label.encode("utf-8")).digest()[:16])
    value[6] = (value[6] & 0x0F) | 0x40
    value[8] = (value[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(value)))


def _safe_status_error(value: Any) -> str:
    """Project a peer/local exception without controls or oversized UTF-8."""

    try:
        raw = str(value)
    except Exception:
        raw = "Secure peer operation failed"
    printable = "".join(
        " " if ord(character) < 0x20 or ord(character) == 0x7F else character
        for character in raw
    ).strip()
    if not printable:
        printable = "Secure peer operation failed"
    encoded = printable.encode("utf-8", "replace")
    if len(encoded) > 400:
        printable = encoded[:400].decode("utf-8", "ignore").rstrip()
    return printable or "Secure peer operation failed"


class SecurePeerRuntime:
    """Own the durable client, optional host listener, and Hub adapter."""

    def __init__(
        self,
        data_dir: Path,
        *,
        server_identity: str,
        server_instance_id: str,
        display_name: str | None = None,
        logger: Any = None,
        team_cache_max_bytes: int | None = None,
        agent_relay_enabled: bool = False,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.server_identity = str(server_identity)
        self.server_instance_id = str(server_instance_id)
        self.display_name = str(display_name or socket.gethostname() or "AgentsServer")[:160]
        self.logger = logger
        configured_cache_max = (
            os.environ.get("AGENTSDOCK_TEAM_CACHE_MAX_BYTES")
            if team_cache_max_bytes is None
            else str(team_cache_max_bytes)
        )
        try:
            parsed_cache_max = int(configured_cache_max or DEFAULT_TEAM_CACHE_MAX_BYTES)
        except (TypeError, ValueError):
            parsed_cache_max = DEFAULT_TEAM_CACHE_MAX_BYTES
        self.team_cache_max_bytes = (
            parsed_cache_max
            if 1 <= parsed_cache_max <= MAX_ATTACHMENT_PROTOCOL_BYTES
            else DEFAULT_TEAM_CACHE_MAX_BYTES
        )
        self.team_cache_dir = self.data_dir.parent / "team-cache"
        self.team_export_dir = self.data_dir.parent / "team-exports"
        self._team_cache_guard = threading.RLock()
        self._team_cache_pins: dict[Path, int] = {}
        self._team_cache_entry_locks: dict[
            Path, tuple[threading.Lock, int]
        ] = {}
        # Active staging bytes are counted at their full declared size and are
        # excluded from the filesystem scan. This preserves the cache bound
        # without holding the global cache lock during network or disk I/O.
        self._team_cache_reservations: dict[Path, int] = {}
        # Export reservations bound durable, caller-visible copies while their
        # bytes are written outside the global cache lock.
        self._team_export_reservations: dict[Path, int] = {}
        self.config_path = self.data_dir / "host-config.json"
        self._guard = threading.RLock()
        # Linearizes durable outbound intent creation with every local
        # route/connection retirement boundary. A handoff is either durably
        # pending before retirement (so retirement returns 409) or observes
        # the retired route and cannot be created.
        self._outbound_guard = threading.RLock()
        self._peer_admission = threading.Condition(threading.RLock())
        self._peer_accepting = False
        self._peer_in_flight = 0
        self._hub_store: HubStore | None = None
        self._host_store: SecurePeerStore | None = None
        self._adapter: SecurePeerHubAdapter | None = None
        self._gateway: SecurePeerGateway | None = None
        # Keep the authoritative Hub attachment recoverable when startup hits
        # a transient projection or listener failure.  The maintenance loop
        # retries this exact object identity instead of leaving a permanently
        # dead Retry button until the whole service is restarted.
        self._pending_host_attachment: tuple[str, Path, HubStore] | None = None
        self._host_error: str | None = None
        self._host_error_code: str | None = None
        self._host_action: str | None = None
        self._delivery_error: str | None = None
        self._client_error: str | None = None
        self._client_failure_counts: dict[str, int] = {}
        self._initialization_error: str | None = None
        # Teamspace transport and cross-server agent execution are separate
        # capabilities. AgentsServer production keeps the latter disabled so
        # paired servers exchange passive Team Network inbox records only.
        # The explicit constructor flag remains for isolated protocol tests
        # and migration tooling; pairing alone can never widen this value.
        self._relay_enabled = bool(agent_relay_enabled)
        self._remote_routes_cache: dict[str, list[dict[str, Any]]] = {}
        self._remote_routes_refreshed_at: dict[str, int] = {}
        self._delivery_target_validator: Any = None
        try:
            ensure_private_directory(self.data_dir)
            self._config = self._read_config()
            self.client: SecurePeerClient | _UnavailableSecurePeerClient = (
                SecurePeerClient(
                    self.data_dir / "client",
                    self.server_identity,
                    self.display_name,
                    pairing_capacity_lock=self._guard,
                    external_actionable_pairing_count=(
                        self._host_actionable_pairing_count
                    ),
                    pairing_capabilities=(
                        ("cert_renewal", "cross_chat", "teamspace")
                        if self._relay_enabled
                        else ("cert_renewal", "teamspace")
                    ),
                )
            )
            # Retire the client-side route outbox before this runtime can be
            # published to the HTTP handlers or background maintenance
            # loops.  Deferring this migration to the async connector leaves
            # a startup window where an old pending route revocation can make
            # one last cross-server agent RPC.
            if not self._relay_enabled:
                self.client.retire_agent_routes_locally()
            self.delivery_ledger: SecurePeerDeliveryLedger | None = (
                SecurePeerDeliveryLedger(self.data_dir / "deliveries.sqlite3")
            )
        except Exception as exc:
            # Secure peer is optional. Quarantine its state rather than taking
            # down the entire local control server, but never start a listener
            # or use credentials from a state tree that failed validation.
            self._config = self._default_config()
            self._initialization_error = (
                "Secure peer state failed safety validation; repair or remove "
                "it before enabling secure pairing."
            )
            self._host_error = self._initialization_error
            self.client = _UnavailableSecurePeerClient(self._initialization_error)
            self.delivery_ledger = None
            if self.logger is not None:
                self.logger.error(
                    "secure peer state quarantined error_type=%s",
                    type(exc).__name__,
                )

    def _default_config(self) -> dict[str, Any]:
        return {
            "version": 1,
            "server_identity": self.server_identity,
            "enabled": False,
            "advertised_host": None,
            "listen_port": 7851,
        }

    def _read_config(self) -> dict[str, Any]:
        try:
            descriptor = os.open(
                self.config_path,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return self._default_config()
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 2 <= info.st_size <= 4096
            ):
                raise PermissionError("secure peer host configuration is unsafe")
            raw = os.read(descriptor, 4097)
            if len(raw) != info.st_size:
                raise PermissionError("secure peer host configuration changed while reading")
        finally:
            os.close(descriptor)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermissionError("secure peer host configuration is invalid") from exc
        if not isinstance(value, dict) or set(value) != _CONFIG_KEYS:
            raise PermissionError("secure peer host configuration fields are invalid")
        if value.get("version") != 1 or value.get("server_identity") != self.server_identity:
            raise PermissionError("secure peer host configuration identity changed")
        enabled = value.get("enabled")
        if type(enabled) is not bool:
            raise PermissionError("secure peer host configuration is invalid")
        try:
            port = canonical_peer_port(value.get("listen_port"))
            host = (
                canonical_peer_ipv4(value.get("advertised_host"))
                if value.get("advertised_host") is not None
                else None
            )
        except (TypeError, ValueError) as exc:
            raise PermissionError("secure peer host configuration is invalid") from exc
        if enabled != (host is not None):
            raise PermissionError("secure peer host configuration is invalid")
        return {**value, "listen_port": port, "advertised_host": host}

    def _write_config(self, value: Mapping[str, Any]) -> None:
        exact = dict(value)
        if set(exact) != _CONFIG_KEYS:
            raise ValueError("secure peer host configuration fields are invalid")
        encoded = canonical_json(exact) + b"\n"
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory = os.open(self.data_dir, directory_flags)
        temporary_name = f".host-config.{os.getpid()}.{threading.get_ident()}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=directory,
            )
            os.fchmod(descriptor, 0o600)
            written = 0
            while written < len(encoded):
                written += os.write(descriptor, encoded[written:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary_name, self.config_path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=directory)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(directory)

    def mark_host_unavailable(
        self,
        message: str,
        *,
        error_code: str = "secure_peer_host_unavailable",
        action: str = "Retry after the Team Hub host finishes recovery.",
    ) -> None:
        with self._guard:
            self._host_error = _safe_status_error(message)
            self._host_error_code = str(error_code)[:64]
            self._host_action = _safe_status_error(action)

    def _host_actionable_pairing_count(self) -> int:
        store = self._host_store
        return store.actionable_pairing_count() if store is not None else 0

    def _client_actionable_pairing_count(self) -> int:
        return self.client.actionable_pairing_count()

    def attach_host_hub(
        self,
        *,
        hub_id: str,
        hub_data_dir: Path,
        hub_store: HubStore | None = None,
    ) -> None:
        """Attach after the authoritative Hub has acquired its runtime lease."""

        if self._initialization_error is not None:
            return
        if hub_store is None:
            raise RuntimeError("secure peer host attachment requires the live Hub store")
        attachment = (str(hub_id), Path(hub_data_dir), hub_store)
        with self._guard:
            if self._hub_store is not None and self._hub_store is not hub_store:
                raise RuntimeError("secure peer host is already attached")
            # Record the exact live Hub object before the first fallible
            # projection step. Startup recovery can then retry even when local
            # Agent Mail provisioning itself was the interrupted boundary.
            self._pending_host_attachment = attachment
            hub_store.provision_local_agent_mail()
            # An enabled attachment is complete only after its listener is
            # live. A prior gateway-start failure leaves the durable stores
            # installed specifically so this same pending attachment can
            # retry without restarting the service.
            if (
                self._hub_store is hub_store
                and self._host_store is not None
                and self._adapter is not None
                and self._host_error_code is None
                and (not self._config["enabled"] or self._gateway is not None)
            ):
                self._pending_host_attachment = None
                return
            host_store = SecurePeerStore(
                self.data_dir / "host",
                self.server_identity,
                str(hub_id),
                cross_chat_enabled=lambda: self._relay_enabled,
                pairing_capacity_lock=self._guard,
                external_actionable_pairing_count=(
                    self._client_actionable_pairing_count
                ),
            )
            consent = host_store.cross_chat_consent_status()
            if self._relay_enabled and int(consent.get("consent_epoch") or 0) == 0:
                seed = bytearray(hashlib.sha256(
                    (
                        "AgentsDock secure peer consent v1\0"
                        + self.server_identity
                        + "\0"
                        + str(hub_id)
                    ).encode("utf-8")
                ).digest()[:16])
                seed[6] = (seed[6] & 0x0F) | 0x40
                seed[8] = (seed[8] & 0x3F) | 0x80
                host_store.activate_cross_chat_consent(
                    expected_epoch=0,
                    idempotency_key=str(uuid.UUID(bytes=bytes(seed))),
                    activated_by="agentsserver-runtime-v1",
                )
            if not self._relay_enabled:
                host_store.retire_agent_routes_locally()
            adapter = SecurePeerHubAdapter(hub_store)
            initial_peers = host_store.list_peers(team_id=None)
            preferred_peer_ids: set[str] = set()
            logical_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for peer in initial_peers:
                if peer.get("status") != "active":
                    continue
                logical_groups.setdefault(
                    (
                        str(peer.get("team_id") or ""),
                        str(peer.get("peer_server_identity") or ""),
                    ),
                    [],
                ).append(peer)
            for (_team_id, peer_identity), peers in logical_groups.items():
                preferred_peer_ids.update(
                    adapter.active_binding_peer_ids(
                        tuple(str(peer["peer_id"]) for peer in peers),
                        peer_identity,
                    )
                )
            reconciliation = host_store.reconcile_active_logical_peers(
                preferred_peer_ids
            )
            if reconciliation.get("superseded_peer_ids") and self.logger is not None:
                self.logger.warning(
                    "reconciled duplicate secure peer credentials count=%s",
                    len(reconciliation["superseded_peer_ids"]),
                )
            # Install the control plane before projection replay.  A later
            # structural Hub error must not hide every peer record and make
            # administrative recovery impossible.
            self._hub_store = hub_store
            self._host_store = host_store
            self._adapter = adapter
            # Recover the approval -> service-principal transaction boundary.
            pairings = {
                item.get("pairing_id"): item
                for item in host_store.list_pairings(status=None)
            }
            recovered_peers = host_store.list_peers(team_id=None)
            # Revocations always replay first.  This ordering closes the
            # cross-database replacement boundary before a successor binding
            # is provisioned.
            for peer in recovered_peers:
                if peer.get("status") != "active" and peer.get("team_id"):
                    peer_id = str(peer["peer_id"])
                    if peer_id in adapter.active_binding_peer_ids(
                        (peer_id,),
                        str(peer.get("peer_server_identity") or ""),
                    ):
                        adapter.revoke_peer(
                            peer_id=peer_id,
                            team_id=str(peer["team_id"]),
                        )
            for peer in recovered_peers:
                if peer.get("status") == "active":
                    pairing = pairings.get(peer.get("pairing_id")) or {}
                    try:
                        adapter.provision_peer(
                            peer,
                            display_name=str(
                                peer.get("peer_display_name")
                                or pairing.get("peer_display_name")
                                or peer.get("peer_server_identity")
                            )[:160],
                        )
                    except HubError as exc:
                        if exc.code != "peer_identity_conflict":
                            raise
                        # A single orphan/corrupt peer cannot disable invites
                        # and administrative recovery for every other peer.
                        host_store.revoke_peer(
                            str(peer["peer_id"]),
                            str(peer["team_id"]),
                            str(peer["certificate_fingerprint"]),
                            _stable_uuid4(
                                "secure-peer-startup-quarantine\0"
                                + self.server_identity
                                + "\0"
                                + str(peer["peer_id"])
                            ),
                            "agentsserver-startup-quarantine",
                        )
                        adapter.revoke_peer(
                            peer_id=str(peer["peer_id"]),
                            team_id=str(peer["team_id"]),
                        )
                        if self.logger is not None:
                            self.logger.warning(
                                "quarantined conflicting secure peer peer_id=%s",
                                peer["peer_id"],
                            )
            self._host_error = None
            self._host_error_code = None
            self._host_action = None
            if self._config["enabled"]:
                gateway = SecurePeerGateway(
                    host_store,
                    str(self._config["advertised_host"]),
                    int(self._config["listen_port"]),
                    forwarder=self._forward_peer_request,
                    resource_team_resolver=adapter.resource_team,
                    attachment_max_bytes=lambda: hub_store.team_attachment_max_bytes,
                    relay_enabled=lambda: self._relay_enabled,
                    peer_heartbeat=self._record_authenticated_peer_heartbeat,
                    peer_revoker=self._revoke_authenticated_peer,
                )
                gateway.start()
                self._gateway = gateway
            with self._peer_admission:
                self._peer_accepting = self._gateway is not None
                self._peer_admission.notify_all()
            self._pending_host_attachment = None

    def retry_host_attachment(self) -> bool:
        """Retry the exact designated Hub attachment after a transient failure."""

        with self._guard:
            pending = self._pending_host_attachment
            if pending is None:
                return bool(
                    self._host_store is not None
                    and self._adapter is not None
                    and self._host_error_code is None
                )
        hub_id, hub_data_dir, hub_store = pending
        try:
            self.attach_host_hub(
                hub_id=hub_id,
                hub_data_dir=hub_data_dir,
                hub_store=hub_store,
            )
        except Exception as exc:
            self.mark_host_unavailable(
                "Secure peer host could not be initialized",
                error_code="secure_peer_host_initialization_failed",
                action="Retry secure peer host initialization.",
            )
            if self.logger is not None:
                self.logger.warning(
                    "secure peer host attachment retry deferred error_type=%s",
                    type(exc).__name__,
                )
            return False
        return True

    def configure_host(
        self,
        *,
        enabled: bool,
        advertised_host: str | None,
        listen_port: int,
    ) -> dict[str, Any]:
        if self._initialization_error is not None:
            raise SecurePeerError(
                "secure_peer_state_unavailable",
                self._initialization_error,
                503,
            )
        if type(enabled) is not bool:
            raise SecurePeerError("invalid_request", "Host setting is invalid", 422)
        host = canonical_peer_ipv4(advertised_host) if advertised_host is not None else None
        port = canonical_peer_port(listen_port)
        if enabled != (host is not None):
            raise SecurePeerError("invalid_request", "Advertised IP is required exactly when hosting", 422)
        if enabled:
            self.retry_host_attachment()
        with self._guard:
            if enabled and (
                self._host_store is None
                or self._adapter is None
                or self._host_error_code is not None
            ):
                raise SecurePeerError(
                    "host_unavailable",
                    "Secure hosting requires the active designated Team Hub",
                    409,
                )
            old_gateway = self._gateway
            old_config = dict(self._config)
            if enabled and old_gateway is not None and (
                old_gateway.address == (host, port)
            ):
                return self.status()
        # Disable admission and drain every already accepted mTLS request
        # before stopping or rebinding the listener.  Returning from this
        # control mutation therefore proves that no request from the prior
        # endpoint can commit afterward.
        self.close_host_admission()
        with self._guard:
            old_gateway = self._gateway
            old_config = dict(self._config)
            new_gateway: SecurePeerGateway | None = None
            try:
                if old_gateway is not None:
                    old_gateway.stop()
                    self._gateway = None
                if enabled:
                    assert self._host_store is not None and self._adapter is not None and host is not None
                    new_gateway = SecurePeerGateway(
                        self._host_store,
                        host,
                        port,
                        forwarder=self._forward_peer_request,
                        resource_team_resolver=self._adapter.resource_team,
                        attachment_max_bytes=(
                            lambda: self._hub_store.team_attachment_max_bytes
                            if self._hub_store is not None
                            else 0
                        ),
                        relay_enabled=lambda: self._relay_enabled,
                        peer_heartbeat=self._record_authenticated_peer_heartbeat,
                        peer_revoker=self._revoke_authenticated_peer,
                    )
                    new_gateway.start()
                next_config = {
                    "version": 1,
                    "server_identity": self.server_identity,
                    "enabled": enabled,
                    "advertised_host": host,
                    "listen_port": port,
                }
                self._write_config(next_config)
                self._config = next_config
                self._gateway = new_gateway
                self._host_error = None
                self._host_error_code = None
                self._host_action = None
            except BaseException:
                if new_gateway is not None:
                    new_gateway.stop()
                # Restore the previous live listener when persistence failed.
                if old_config["enabled"] and self._host_store is not None and self._adapter is not None:
                    restored = SecurePeerGateway(
                        self._host_store,
                        str(old_config["advertised_host"]),
                        int(old_config["listen_port"]),
                        forwarder=self._forward_peer_request,
                        resource_team_resolver=self._adapter.resource_team,
                        attachment_max_bytes=(
                            lambda: self._hub_store.team_attachment_max_bytes
                            if self._hub_store is not None
                            else 0
                        ),
                        relay_enabled=lambda: self._relay_enabled,
                        peer_heartbeat=self._record_authenticated_peer_heartbeat,
                        peer_revoker=self._revoke_authenticated_peer,
                    )
                    restored.start()
                    self._gateway = restored
                raise
            finally:
                if self._gateway is not None:
                    self.reopen_host_admission()
            return self.status()

    def begin_pairing(
        self,
        *,
        host: str,
        port: int,
        expected_ca_fingerprint: str | None,
        request_id: str,
        display_name: str,
        requested_scopes: list[str],
    ) -> dict[str, Any]:
        # The core persists the key/request before network delivery so an
        # ambiguous response can be retried with the exact same signed bytes.
        result = self.client.begin_pairing(
            host,
            port,
            expected_ca_fingerprint=expected_ca_fingerprint,
            request_id=request_id,
            requested_scopes=requested_scopes,
            display_name=display_name,
            resume_matching=True,
        )
        return self._outgoing_pairing(result)

    def poll_pairing(self, pairing_id: str) -> dict[str, Any]:
        connection = self._outgoing_for_pairing(pairing_id)
        result = self.client.poll_pairing(str(connection["connection_id"]))
        return self._outgoing_pairing(result)

    def cancel_pairing(self, pairing_id: str, *, idempotency_key: str) -> dict[str, Any]:
        connection = self._outgoing_for_pairing(pairing_id)
        self.client.cancel_pairing(
            str(connection["connection_id"]),
            idempotency_key=idempotency_key,
        )
        return self.status()

    def activate_pairing(
        self,
        pairing_id: str,
        *,
        expected_connection_id: str,
        expected_host_server_identity: str,
        expected_hub_id: str,
    ) -> dict[str, Any]:
        with self._outbound_guard:
            connection = self._outgoing_for_pairing(pairing_id)
            if (
                connection.get("connection_id") != expected_connection_id
                or connection.get("host_server_identity")
                != expected_host_server_identity
                or connection.get("hub_id") != expected_hub_id
            ):
                raise SecurePeerError(
                    "pairing_changed",
                    "Secure peer identity changed before activation",
                    409,
                )
            active = next(
                (
                    item
                    for item in self.client.list_connections()
                    if item.get("active")
                ),
                None,
            )
            active_id = str((active or {}).get("connection_id") or "")
            if active_id and active_id != expected_connection_id:
                # Switching would abandon every route published through the old
                # connection because the connector intentionally polls only one
                # active peer. Require an explicit, fully acknowledged
                # retirement/forget of the old connection first.
                raise SecurePeerError(
                    "active_connection_conflict",
                    "Forget the active secure peer before activating another one",
                    409,
                )
            self.client.set_active_connection(
                expected_connection_id,
                expected_current=active_id or None,
            )
            self._client_failure_counts.pop(expected_connection_id, None)
        return self.status()

    def deactivate_connection(
        self,
        connection_id: str,
        *,
        expected_host_server_identity: str,
        expected_hub_id: str,
    ) -> dict[str, Any]:
        with self._outbound_guard:
            self._require_connection_delivery_quiescent(connection_id)
            self.client.deactivate_connection(
                connection_id,
                expected_host_server_identity=expected_host_server_identity,
                expected_hub_id=expected_hub_id,
            )
            self._client_failure_counts.pop(connection_id, None)
        return self.status()

    def forget_connection(
        self,
        connection_id: str,
        *,
        expected_host_server_identity: str,
        expected_hub_id: str,
        expected_certificate_fingerprint: str,
    ) -> dict[str, Any]:
        with self._outbound_guard:
            self._require_connection_delivery_quiescent(connection_id)
            connection = next(
                (
                    item
                    for item in self.client.list_connections()
                    if item.get("connection_id") == connection_id
                ),
                None,
            )
            if (
                connection is None
                or connection.get("host_server_identity")
                != expected_host_server_identity
                or connection.get("hub_id") != expected_hub_id
                or connection.get("certificate_fingerprint")
                != expected_certificate_fingerprint
            ):
                raise SecurePeerError(
                    "connection_changed",
                    "Secure peer connection identity changed",
                    409,
                )
            if int(connection.get("certificate_expires_at") or 0) <= int(
                time.time()
            ):
                # An expired certificate cannot authenticate the remote revoke
                # endpoint. Exact identity/fingerprint CAS plus local key
                # retirement is therefore the only safe terminal transition.
                self.client.forget_expired_connection(
                    connection_id,
                    expected_host_server_identity=expected_host_server_identity,
                    expected_hub_id=expected_hub_id,
                    expected_certificate_fingerprint=(
                        expected_certificate_fingerprint
                    ),
                )
                self._client_failure_counts.pop(connection_id, None)
                return self.status()
            self.client.revoke_remote_connection(
                connection_id,
                idempotency_key=_stable_uuid4(
                    "secure-peer-connection-forget\0"
                    + self.server_identity
                    + "\0"
                    + connection_id
                    + "\0"
                    + expected_certificate_fingerprint
                ),
            )
            # The authenticated host revocation atomically retires every
            # route and envelope for this logical peer.  Convert the exact
            # receipt into local route tombstones before deleting the key.
            # This also recovers a response lost after the remote commit.
            self.client.retire_remote_revoked_connection(
                connection_id,
                expected_host_server_identity=expected_host_server_identity,
                expected_hub_id=expected_hub_id,
                expected_certificate_fingerprint=(
                    expected_certificate_fingerprint
                ),
            )
            self.client.forget_connection(
                connection_id,
                expected_host_server_identity=expected_host_server_identity,
                expected_hub_id=expected_hub_id,
                expected_certificate_fingerprint=expected_certificate_fingerprint,
            )
            self._client_failure_counts.pop(connection_id, None)
        return self.status()

    def _require_connection_delivery_quiescent(self, connection_id: str) -> None:
        if self.delivery_ledger is None:
            raise SecurePeerError(
                "secure_peer_unavailable",
                "Secure peer durable delivery state is unavailable",
                503,
            )
        pending_outbound = self.delivery_ledger.pending_outbound_for_connection(
            connection_id
        )
        pending_inbound = self.delivery_ledger.nonterminal_for_connection(
            connection_id
        )
        if pending_outbound or pending_inbound:
            raise SecurePeerError(
                "connection_delivery_pending",
                "Wait for encrypted peer deliveries to finish before changing this connection",
                409,
            )

    def _outgoing_for_pairing(self, pairing_id: str) -> dict[str, Any]:
        matches = [
            item
            for item in self.client.list_connections()
            if item.get("pairing_id") == pairing_id
        ]
        if len(matches) != 1:
            raise SecurePeerError("pairing_unavailable", "Pairing is unavailable", 404)
        return matches[0]

    @staticmethod
    def _status(value: Any, *, active: bool = False) -> str:
        if active and value == "approved":
            return "connected"
        return {
            "requesting": "requesting",
            "pending": "pending_approval",
            "pending_approval": "pending_approval",
            "approved": "approved",
            "connected": "connected" if active else "approved",
            "deactivated": "approved",
            "active": "approved",
            "rejected": "rejected",
            "revoked": "revoked",
            "cancelled": "rejected",
            "expired": "expired",
            "error": "error",
        }.get(str(value), "error")

    @staticmethod
    def _trust_state(value: Any) -> str:
        raw = str(value)
        if raw == "revoked":
            return "revoked"
        if raw in {"requesting", "pending", "pending_approval"}:
            return "pending"
        if raw in {"rejected", "cancelled", "expired", "error"}:
            return raw
        if raw in {"approved", "connected", "deactivated", "active"}:
            return "approved"
        return "error"

    def _transport_state(
        self,
        item: Mapping[str, Any],
        *,
        direction: str,
        active: bool,
    ) -> str:
        raw = str(item.get("status") or "")
        if raw == "revoked":
            return "revoked"
        if direction == "outgoing" and not active:
            return "disconnected"
        if direction == "incoming" and raw != "active":
            return "disconnected"
        last_seen = int(
            item.get("last_validated_at")
            or item.get("last_seen_at")
            or 0
        )
        now = int(time.time())
        if direction == "incoming":
            return (
                "online"
                if last_seen >= now - SECURE_PEER_LEASE_SECONDS
                else "offline"
            )
        connection_id = str(item.get("connection_id") or "")
        failures = self._client_failure_counts.get(connection_id, 0)
        if failures == 0 and last_seen >= now - SECURE_PEER_LEASE_SECONDS:
            return "online"
        if (
            failures < SECURE_PEER_OFFLINE_FAILURES
            and last_seen >= now - SECURE_PEER_LEASE_SECONDS
        ):
            return "reconnecting"
        return "offline"

    def _displayed_scopes(self, value: Any) -> list[str]:
        """Project only authority that this runtime can currently exercise."""

        scopes = [
            str(scope)
            for scope in (value or [])
            if isinstance(scope, str)
        ]
        if self._relay_enabled:
            return scopes
        return [
            scope
            for scope in scopes
            if scope in {"teamspace.read", "teamspace.write"}
        ]

    def _incoming_pairing(self, item: Mapping[str, Any]) -> dict[str, Any]:
        endpoint = str(item.get("source_endpoint") or item.get("remote_endpoint") or "")
        public_fp = item.get("peer_public_key_fingerprint") or _fingerprint_public_key_pem(
            item.get("peer_public_key_pem")
        )
        peer_id = item.get("peer_id")
        trust_state = self._trust_state(item.get("status"))
        transport_state = self._transport_state(
            item,
            direction="incoming",
            active=item.get("status") == "active",
        )
        return {
            "id": item.get("pairing_id"),
            "direction": "incoming",
            "status": self._status(item.get("status")),
            "trust_state": trust_state,
            "transport_state": transport_state,
            "peer_server_identity": item.get("peer_server_identity"),
            "peer_display_name": item.get("peer_display_name") or item.get("peer_server_identity"),
            "remote_endpoint": endpoint,
            "host_server_identity": self.server_identity,
            "host_ca_fingerprint": self._host_store.ca_fingerprint if self._host_store else None,
            "peer_public_key_fingerprint": public_fp,
            "transcript_hash": item.get("transcript_hash"),
            "sas_words": item.get("sas_words") or [],
            "requested_scopes": self._displayed_scopes(
                item.get("requested_scopes")
            ),
            "granted_scopes": self._displayed_scopes(item.get("scopes")),
            "team_id": item.get("team_id"),
            "team_display_name": item.get("team_display_name"),
            "hub_id": self._host_store.hub_id if self._host_store else None,
            # On a host, the durable peer record is the local connection
            # audience used for route publication. Pending requests do not
            # acquire one before approval commits.
            "connection_id": peer_id,
            "local_proxy_base_path": None,
            "certificate_expires_at": _iso8601(item.get("certificate_expires_at")),
            "certificate_fingerprint": item.get("certificate_fingerprint"),
            "last_seen_at": _iso8601(item.get("last_seen_at")),
            "expires_at": _iso8601(item.get("expires_at")),
            "error": item.get("error"),
        }

    def _outgoing_pairing(self, item: Mapping[str, Any]) -> dict[str, Any]:
        connection_id = str(item.get("connection_id"))
        active = bool(item.get("active"))
        trust_state = self._trust_state(item.get("status"))
        transport_state = self._transport_state(
            item,
            direction="outgoing",
            active=active,
        )
        return {
            "id": item.get("pairing_id"),
            "direction": "outgoing",
            "status": self._status(item.get("status"), active=active),
            "trust_state": trust_state,
            "transport_state": transport_state,
            "peer_server_identity": item.get("host_server_identity"),
            "peer_display_name": item.get("host_display_name") or item.get("host_server_identity"),
            "remote_endpoint": f"{item.get('host_ip')}:{item.get('port')}",
            "host_server_identity": item.get("host_server_identity"),
            "host_ca_fingerprint": item.get("host_ca_fingerprint"),
            "peer_public_key_fingerprint": item.get("peer_public_key_fingerprint"),
            "transcript_hash": item.get("transcript_hash"),
            "sas_words": item.get("sas_words") or [],
            "requested_scopes": self._displayed_scopes(
                item.get("requested_scopes")
            ),
            "granted_scopes": self._displayed_scopes(item.get("scopes")),
            "team_id": item.get("team_id"),
            "team_display_name": item.get("team_display_name"),
            "hub_id": item.get("hub_id"),
            "connection_id": connection_id,
            "local_proxy_base_path": (
                f"{SECURE_PEER_PROXY_PREFIX}/{connection_id}" if active else None
            ),
            "certificate_expires_at": _iso8601(item.get("certificate_expires_at")),
            "certificate_fingerprint": item.get("certificate_fingerprint"),
            "last_seen_at": _iso8601(item.get("last_validated_at")),
            "expires_at": _iso8601(item.get("expires_at") or item.get("pairing_expires_at")),
            "error": item.get("error"),
        }

    def list_pairings(self, *, team_id: str | None, status: str | None) -> dict[str, Any]:
        with self._guard:
            store = self._host_store
        if store is None:
            return {"pairings": []}
        pending = status in {"pending", "pending_approval"}
        return {
            "pairings": [
                self._incoming_pairing(item)
                for item in store.list_pairings(
                    # Pending entries are deliberately unassigned and are
                    # visible only after the service proves team ownership.
                    # Historical rows remain strictly team-scoped.
                    team_id=None if pending else team_id,
                    status="pending" if pending else None,
                )
            ]
        }

    def approve_pairing(self, **values: Any) -> dict[str, Any]:
        with self._guard:
            store, adapter = self._host_store, self._adapter
        if store is None or adapter is None:
            raise HubError("secure_peer_unavailable", "Secure peer pairing is unavailable", 503)
        try:
            # Validate the target in the live Hub before certificate/peer
            # approval commits in the separate secure-peer database.  A
            # stale or mistyped team can therefore never poison restart
            # reconciliation with a permanently approved, unprovisionable
            # peer.
            adapter.preflight_team(str(values["team_id"]))
            all_pairings = store.list_pairings(team_id=None, status=None)
            pairing = next(
                (
                    item
                    for item in all_pairings
                    if item.get("pairing_id") == values["pairing_id"]
                ),
                None,
            )
            if pairing is None:
                raise SecurePeerError(
                    "pairing_unavailable",
                    "Secure peer pairing is unavailable",
                    404,
                )
            if pairing.get("status") == "approved":
                # Recover a core-approval -> Hub-provision split even when the
                # desktop had no response and generated a new operation UUID.
                # Recovery is authorized only by an exact immutable target.
                if (
                    pairing.get("peer_server_identity")
                    != values["expected_peer_server_identity"]
                    or pairing.get("transcript_hash")
                    != values["expected_transcript_hash"]
                    or pairing.get("team_id") != values["team_id"]
                    or list(pairing.get("scopes") or []) != list(values["scopes"])
                ):
                    raise SecurePeerError(
                        "pairing_changed",
                        "Secure peer approval changed before recovery",
                        409,
                    )
                recovered_peer = next(
                    (
                        item
                        for item in store.list_peers(team_id=values["team_id"])
                        if item.get("pairing_id") == values["pairing_id"]
                    ),
                    None,
                )
                if recovered_peer is None:
                    raise SecurePeerError(
                        "pairing_incomplete",
                        "Secure peer approval is missing its peer record",
                        409,
                    )
                result = {"peer_id": recovered_peer.get("peer_id")}
            else:
                result = store.approve_pairing(**values)
                all_pairings = store.list_pairings(team_id=None, status=None)
                pairing = next(
                    item
                    for item in all_pairings
                    if item.get("pairing_id") == values["pairing_id"]
                )
            # The secure-peer database atomically supersedes the prior
            # credential for this logical server.  Replay those revocations
            # into Team Hub before provisioning the successor so a crash at
            # either database boundary remains recoverable and idempotent.
            for prior_peer in store.list_peers(team_id=values["team_id"]):
                if (
                    prior_peer.get("status") == "revoked"
                    and prior_peer.get("peer_server_identity")
                    == values["expected_peer_server_identity"]
                    and prior_peer.get("peer_id") != result.get("peer_id")
                ):
                    adapter.revoke_peer(
                        peer_id=str(prior_peer["peer_id"]),
                        team_id=str(prior_peer["team_id"]),
                    )
            peer = next(
                item for item in store.list_peers(team_id=values["team_id"])
                if item.get("peer_id") == result.get("peer_id")
            )
            adapter.provision_peer(
                peer,
                display_name=str(pairing.get("peer_display_name") or peer["peer_server_identity"]),
            )
            return {"pairing": self._incoming_pairing({**pairing, **peer})}
        except SecurePeerError as exc:
            raise HubError(exc.code, exc.message, exc.status_code) from exc

    def reject_pairing(self, **values: Any) -> dict[str, Any]:
        with self._guard:
            store = self._host_store
        if store is None:
            raise HubError("secure_peer_unavailable", "Secure peer pairing is unavailable", 503)
        try:
            store.reject_pairing(**values)
            pairing = next(
                item
                for item in store.list_pairings(team_id=None, status=None)
                if item.get("pairing_id") == values["pairing_id"]
            )
            return {"pairing": self._incoming_pairing(pairing)}
        except SecurePeerError as exc:
            raise HubError(exc.code, exc.message, exc.status_code) from exc

    def list_peers(self, *, team_id: str | None) -> dict[str, Any]:
        with self._guard:
            store = self._host_store
        if store is None:
            return {"peers": []}
        pairings = {
            item.get("pairing_id"): item
            for item in store.list_pairings(team_id=None, status=None)
        }
        return {
            "peers": [
                self._incoming_pairing({**pairings.get(item.get("pairing_id"), {}), **item})
                for item in store.list_peers(team_id=team_id)
            ]
        }

    def revoke_peer(self, **values: Any) -> dict[str, Any]:
        with self._guard:
            store, adapter = self._host_store, self._adapter
        if store is None or adapter is None:
            raise HubError("secure_peer_unavailable", "Secure peer pairing is unavailable", 503)
        try:
            store.revoke_peer(**values)
            # Always replay the Hub-side revoke after a cached core response.
            adapter.revoke_peer(peer_id=values["peer_id"], team_id=values["team_id"])
            peers = store.list_peers(team_id=values["team_id"])
            peer = next(item for item in peers if item.get("peer_id") == values["peer_id"])
            pairings = store.list_pairings(team_id=None, status=None)
            pairing = next(
                (item for item in pairings if item.get("pairing_id") == peer.get("pairing_id")),
                {},
            )
            return {"peer": self._incoming_pairing({**pairing, **peer})}
        except SecurePeerError as exc:
            raise HubError(exc.code, exc.message, exc.status_code) from exc

    def _client_connection(self, connection_id: str) -> dict[str, Any] | None:
        return next(
            (
                item
                for item in self.client.list_connections()
                if str(item.get("connection_id") or "") == connection_id
            ),
            None,
        )

    def _host_peer(self, connection_id: str) -> dict[str, Any] | None:
        with self._guard:
            store = self._host_store
        if store is None:
            return None
        return next(
            (
                item
                for item in store.list_peers(team_id=None)
                if str(item.get("peer_id") or "") == connection_id
            ),
            None,
        )

    @staticmethod
    def _route_projection(
        route: Mapping[str, Any],
        *,
        connection_id: str,
        peer_server_identity: str,
        peer_display_name: str,
        chat_id: str | None = None,
    ) -> dict[str, Any]:
        projected = {
            "peer_server_identity": peer_server_identity,
            "peer_display_name": peer_display_name,
            "connection_id": connection_id,
            "route_id": route.get("route_id"),
            "revision": route.get("revision"),
            "alias": route.get("alias"),
            "display_title": route.get("display_title"),
            "actions": list(route.get("actions") or []),
        }
        if chat_id is not None:
            projected.update({
                "chat_id": chat_id,
                "status": route.get("status") or "active",
            })
        return projected

    def _published_routes(self) -> list[dict[str, Any]]:
        routes: list[dict[str, Any]] = []
        connections = {
            str(item.get("connection_id") or ""): item
            for item in self.client.list_connections()
        }
        for route in self.client.list_published_routes():
            connection_id = str(route.get("connection_id") or "")
            connection = connections.get(connection_id)
            if connection is None:
                continue
            peer_identity = str(connection.get("host_server_identity") or "")
            routes.append(self._route_projection(
                route,
                connection_id=connection_id,
                peer_server_identity=peer_identity,
                peer_display_name=str(
                    connection.get("host_display_name") or peer_identity
                ),
                chat_id=str(route.get("chat_id") or ""),
            ))
        with self._guard:
            store = self._host_store
        if store is not None:
            for route in store.list_local_routes(include_revoked=True):
                routes.append(self._route_projection(
                    route,
                    connection_id=str(route.get("audience_peer_id") or ""),
                    peer_server_identity=str(
                        route.get("audience_peer_server_identity") or ""
                    ),
                    peer_display_name=str(
                        route.get("audience_peer_display_name")
                        or route.get("audience_peer_server_identity")
                        or "Paired server"
                    ),
                    chat_id=str(route.get("chat_id") or ""),
                ))
        return routes

    def _remote_routes(self) -> list[dict[str, Any]]:
        routes: list[dict[str, Any]] = []
        with self._guard:
            cache = {
                key: [dict(item) for item in value]
                for key, value in self._remote_routes_cache.items()
            }
            store = self._host_store
        for connection_id, values in cache.items():
            connection = self._client_connection(connection_id)
            if connection is None or not connection.get("active"):
                continue
            peer_identity = str(connection.get("host_server_identity") or "")
            for route in values:
                routes.append(self._route_projection(
                    route,
                    connection_id=connection_id,
                    peer_server_identity=peer_identity,
                    peer_display_name=str(
                        connection.get("host_display_name") or peer_identity
                    ),
                ))
        if store is not None:
            for peer in store.list_peers(team_id=None):
                if peer.get("status") != "active":
                    continue
                peer_id = str(peer.get("peer_id") or "")
                for route in store.list_remote_routes_for_peer(
                    peer_id,
                    include_revoked=False,
                ):
                    routes.append(self._route_projection(
                        route,
                        connection_id=peer_id,
                        peer_server_identity=str(
                            route.get("peer_server_identity")
                            or peer.get("peer_server_identity")
                            or ""
                        ),
                        peer_display_name=str(
                            route.get("peer_display_name")
                            or peer.get("peer_display_name")
                            or peer.get("peer_server_identity")
                            or "Paired server"
                        ),
                    ))
        return routes

    def publish_route(
        self,
        *,
        connection_id: str,
        chat_id: str,
        alias: str,
        display_title: str,
        actions: list[str],
        idempotency_key: str,
    ) -> dict[str, Any]:
        if not self.remote_route_delivery_available():
            raise SecurePeerError(
                "remote_route_delivery_unavailable",
                "Secure peer chat delivery is unavailable",
                503,
            )
        connection = self._client_connection(connection_id)
        if connection is not None:
            if not connection.get("active"):
                raise SecurePeerError(
                    "connection_unavailable",
                    "Secure peer connection is not active",
                    409,
                )
            self.client.publish_route(
                connection_id,
                chat_id,
                alias,
                display_title,
                actions,
            )
            return self.status()
        peer = self._host_peer(connection_id)
        with self._guard:
            store = self._host_store
        if peer is None or store is None or peer.get("status") != "active":
            raise SecurePeerError(
                "connection_unavailable",
                "Secure peer connection is unavailable",
                404,
            )
        store.publish_local_route(
            str(peer.get("team_id") or ""),
            connection_id,
            chat_id,
            alias,
            display_title,
            actions,
            idempotency_key=idempotency_key,
            published_by=f"host-admin:{self.server_identity}",
        )
        return self.status()

    def revoke_route(
        self,
        *,
        route_id: str,
        expected_connection_id: str,
        expected_revision: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        if not self._relay_enabled:
            self.retire_agent_routes_locally()
            raise SecurePeerError(
                "remote_route_delivery_unavailable",
                "Cross-server agent routes are retired; use Team Network Inbox",
                409,
            )
        with self._outbound_guard:
            self._require_route_outbound_quiescent(
                expected_connection_id,
                route_id,
                expected_revision,
            )
            return self._revoke_route_locked(
                route_id=route_id,
                expected_connection_id=expected_connection_id,
                expected_revision=expected_revision,
                idempotency_key=idempotency_key,
            )

    def _require_route_outbound_quiescent(
        self,
        connection_id: str,
        route_id: str,
        revision: str,
    ) -> None:
        if self.delivery_ledger is None:
            raise SecurePeerError(
                "secure_peer_unavailable",
                "Secure peer durable delivery state is unavailable",
                503,
            )
        if self.delivery_ledger.pending_outbound_for_route(
            connection_id,
            route_id,
            revision,
        ):
            raise SecurePeerError(
                "outbound_handoff_pending",
                "Wait for the encrypted handoff to finish before retiring this route",
                409,
            )

    def _revoke_route_locked(
        self,
        *,
        route_id: str,
        expected_connection_id: str,
        expected_revision: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        published = next(
            (
                item
                for item in self._published_routes()
                if str(item.get("route_id") or "") == route_id
            ),
            None,
        )
        if (
            published is None
            or published.get("connection_id") != expected_connection_id
        ):
            raise SecurePeerError(
                "route_changed",
                "Published secure peer route is unavailable or changed",
                409,
            )
        connection = self._client_connection(expected_connection_id)
        if connection is not None:
            try:
                self.client.revoke_published_route(
                    expected_connection_id,
                    route_id,
                    expected_revision,
                    idempotency_key,
                )
            except SecurePeerError as exc:
                if exc.status_code < 500 and exc.status_code not in {408, 425, 429}:
                    raise
                self._client_error = _safe_status_error(exc.message)
            return self.status()
        peer = self._host_peer(expected_connection_id)
        with self._guard:
            store = self._host_store
        if peer is None or store is None:
            raise SecurePeerError(
                "connection_unavailable",
                "Secure peer connection is unavailable",
                404,
            )
        store.revoke_route(
            route_id,
            str(peer.get("team_id") or ""),
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
            revoked_by=f"host-admin:{self.server_identity}",
        )
        return self.status()

    def route_local_chat(
        self,
        *,
        route_id: str,
        expected_connection_id: str,
        expected_revision: str,
    ) -> str:
        route = next((
            item
            for item in self._published_routes()
            if str(item.get("route_id") or "") == route_id
            and str(item.get("connection_id") or "")
            == expected_connection_id
            and str(item.get("revision") or "") == expected_revision
            and item.get("status") in {"publishing", "active"}
        ), None)
        if route is None or not str(route.get("chat_id") or ""):
            raise SecurePeerError(
                "route_changed",
                "Published secure peer route is unavailable or changed",
                409,
            )
        return str(route["chat_id"])

    def revoke_routes_for_chat(self, chat_id: str) -> int:
        """CAS-revoke every advertised route before archive/delete commits."""

        canonical_chat = str(chat_id or "")
        if not canonical_chat:
            raise SecurePeerError("invalid_request", "Chat id is invalid", 422)
        if not self._relay_enabled:
            # Agent routes are globally retired, so a chat archive/delete has
            # no remote CAS to perform.  Reapply the local tombstone in case
            # legacy state was restored after constructor migration.
            return self.retire_agent_routes_locally()
        with self._outbound_guard:
            if self.delivery_ledger is None:
                raise SecurePeerError(
                    "secure_peer_unavailable",
                    "Secure peer durable delivery state is unavailable",
                    503,
                )
            if self.delivery_ledger.pending_outbound_for_chat(canonical_chat):
                raise SecurePeerError(
                    "outbound_handoff_pending",
                    "Wait for the encrypted handoff to finish before retiring this chat",
                    409,
                )
            return self._revoke_routes_for_chat_locked(canonical_chat)

    def _revoke_routes_for_chat_locked(self, canonical_chat: str) -> int:
        revoked = 0
        for route in self.client.list_published_routes():
            if (
                route.get("chat_id") != canonical_chat
                or route.get("status") not in {"publishing", "active"}
            ):
                continue
            connection_id = str(route.get("connection_id") or "")
            route_id = str(route.get("route_id") or "")
            revision = str(route.get("revision") or "")
            try:
                self.client.revoke_published_route(
                    connection_id,
                    route_id,
                    revision,
                    _stable_uuid4(
                        "secure-peer-chat-retire\0"
                        + self.server_identity
                        + "\0"
                        + canonical_chat
                        + "\0"
                        + route_id
                        + "\0"
                        + revision
                    ),
                )
            except SecurePeerError as exc:
                if exc.status_code < 500 and exc.status_code not in {408, 425, 429}:
                    raise
                # The local tombstone is already durable. The maintenance
                # outbox will replay the exact remote CAS once the peer is
                # reachable; archive/delete must not be hostage to its uptime.
                self._client_error = _safe_status_error(exc.message)
            revoked += 1
        with self._guard:
            store = self._host_store
        if store is not None:
            for route in store.list_local_routes(include_revoked=False):
                if route.get("chat_id") != canonical_chat:
                    continue
                route_id = str(route.get("route_id") or "")
                revision = str(route.get("revision") or "")
                store.revoke_route(
                    route_id,
                    str(route.get("team_id") or ""),
                    expected_revision=revision,
                    idempotency_key=_stable_uuid4(
                        "secure-peer-chat-retire\0"
                        + self.server_identity
                        + "\0"
                        + canonical_chat
                        + "\0"
                        + route_id
                        + "\0"
                        + revision
                    ),
                    revoked_by=f"host-admin:{self.server_identity}",
                )
                revoked += 1
        return revoked

    def _status_pairings(
        self,
        incoming_items: list[dict[str, Any]],
        outgoing_items: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        ranked: list[tuple[int, str, str, dict[str, Any]]] = []
        for direction, items, projector in (
            ("incoming", incoming_items, self._incoming_pairing),
            ("outgoing", outgoing_items, self._outgoing_pairing),
        ):
            for item in items:
                public = projector(item)
                ranked.append((
                    int(item.get("updated_at") or item.get("created_at") or 0),
                    direction,
                    str(public.get("id") or ""),
                    public,
                ))
        ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
        actionable = [
            public
            for _timestamp, _direction, _identifier, public in ranked
            if public.get("status") in _PAIRING_ACTIONABLE_STATUSES
        ]
        if len(actionable) > PAIRING_STATUS_LIMIT:
            # Admissions share the snapshot lock and reserve durable client
            # attempts, so this can only represent pre-contract/corrupt state.
            # Do not silently hide a live trust relationship from its owner.
            raise SecurePeerError(
                "pairing_capacity",
                "Actionable secure peer pairing state exceeds the safe status limit",
                503,
            )
        terminal = [
            public
            for _timestamp, _direction, _identifier, public in ranked
            if public.get("status") not in _PAIRING_ACTIONABLE_STATUSES
        ]
        return actionable + terminal[: PAIRING_STATUS_LIMIT - len(actionable)]

    def status(self) -> dict[str, Any]:
        with self._guard:
            config = dict(self._config)
            store = self._host_store
            gateway = self._gateway
            host_error = self._host_error
            host_error_code = self._host_error_code
            host_action = self._host_action
            connections = self.client.list_connections()
            incoming_items: list[dict[str, Any]] = []
            if store is not None:
                pairings = {
                    item.get("pairing_id"): item
                    for item in store.list_pairings(team_id=None, status=None)
                }
                peers = {
                    item.get("pairing_id"): item
                    for item in store.list_peers(team_id=None)
                }
                incoming_items = [
                    {**item, **peers.get(pairing_id, {})}
                    for pairing_id, item in pairings.items()
                ]
            status_pairings = self._status_pairings(incoming_items, connections)
        host_available = bool(
            store is not None
            and self._initialization_error is None
            and host_error_code is None
        )
        host = config.get("advertised_host")
        port = int(config["listen_port"])
        ca_fingerprint = store.ca_fingerprint if store is not None else None
        route_delivery_available = self.remote_route_delivery_available()
        return {
            "version": SECURE_PEER_CONTROL_VERSION,
            "heartbeat_interval_seconds": SECURE_PEER_HEARTBEAT_SECONDS,
            "lease_seconds": SECURE_PEER_LEASE_SECONDS,
            "server_identity": self.server_identity,
            "server_instance_id": self.server_instance_id,
            "active_connection_id": next(
                (item.get("connection_id") for item in connections if item.get("active")),
                None,
            ),
            "host": {
                "available": host_available,
                "enabled": bool(config["enabled"] and gateway is not None),
                "listen_port": port,
                "advertised_host": host,
                "advertised_hosts": [host] if host else [],
                "ca_fingerprint": ca_fingerprint,
                "pairing_link": (
                    f"agentsdock://secure-peer/join?host={host}&port={port}&fingerprint={quote(ca_fingerprint, safe='')}"
                    if host and ca_fingerprint and gateway is not None
                    else None
                ),
                "certificate_expires_at": (
                    _iso8601(store.server_certificate_expires_at)
                    if store is not None
                    and bool(config["enabled"])
                    and gateway is not None
                    else None
                ),
                "error": host_error or self._initialization_error,
                "error_code": (
                    host_error_code
                    or (
                        "secure_peer_state_unavailable"
                        if self._initialization_error
                        else None
                    )
                ),
                "action": host_action,
            },
            "pairings": status_pairings,
            "remote_routes": (
                self._remote_routes() if route_delivery_available else []
            ),
            "published_routes": (
                self._published_routes() if route_delivery_available else []
            ),
            "remote_route_delivery_available": route_delivery_available,
            "connection_error": self._client_error,
            "delivery_error": self._delivery_error,
        }

    def state_available(self) -> bool:
        """Report only whether optional secure-peer state passed safety init."""

        return self._initialization_error is None

    def state_error_code(self) -> str | None:
        return (
            None
            if self._initialization_error is None
            else "secure_peer_state_unavailable"
        )

    def retire_agent_routes_locally(self) -> int:
        """Tombstone legacy agent routes while preserving Teamspace pairing."""

        retired = 0
        retire_client = getattr(self.client, "retire_agent_routes_locally", None)
        if callable(retire_client):
            retired += int(retire_client() or 0)
        with self._guard:
            store = self._host_store
            self._remote_routes_cache.clear()
            self._remote_routes_refreshed_at.clear()
        if store is not None:
            retired += int(store.retire_agent_routes_locally() or 0)
        return retired

    def _retire_remote_revoked_active_connection(
        self,
        observed: Mapping[str, Any],
        pairing_recovery: Mapping[str, Any],
    ) -> dict[str, Any]:
        connection_id = str(observed.get("connection_id") or "")
        with self._outbound_guard:
            connections = self.client.list_connections()
            current = next(
                (
                    item
                    for item in connections
                    if item.get("connection_id") == connection_id
                ),
                None,
            )
            if current is not None and (
                current.get("host_server_identity")
                != observed.get("host_server_identity")
                or current.get("hub_id") != observed.get("hub_id")
            ):
                raise SecurePeerError(
                    "connection_changed",
                    "Secure peer connection changed during revocation",
                    409,
                )
            if current is not None:
                self.client.retire_remote_revoked_connection(
                    connection_id,
                    expected_host_server_identity=str(
                        current.get("host_server_identity") or ""
                    ),
                    expected_hub_id=str(current.get("hub_id") or ""),
                    expected_certificate_fingerprint=str(
                        current.get("certificate_fingerprint") or ""
                    ),
                )
            replacement_active = any(
                item.get("active")
                and item.get("connection_id") != connection_id
                for item in connections
            )
        with self._guard:
            self._remote_routes_cache.pop(connection_id, None)
            self._remote_routes_refreshed_at.pop(connection_id, None)
        self._client_failure_counts.pop(connection_id, None)
        self._client_error = None
        return {
            "active": replacement_active,
            "renewed": False,
            "healthy": False,
            "revoked": True,
            "revoked_connection_id": connection_id,
            "error": "peer_revoked",
            "pairing_recovery": dict(pairing_recovery),
        }

    @staticmethod
    def _is_unconfirmed_peer_revocation(exc: BaseException | None) -> bool:
        return bool(
            isinstance(exc, SecurePeerError)
            and exc.code == "peer_revoked"
            and exc.status_code == 401
        )

    def _remote_revocation_confirmed(self, connection_id: str) -> bool | None:
        """Return terminal trust state only from the pinned status receipt."""

        try:
            status = self.client.remote_revocation_status(connection_id)
        except Exception as exc:
            if self.logger is not None:
                self.logger.warning(
                    "secure peer revocation confirmation deferred error_type=%s",
                    type(exc).__name__,
                )
            return None
        return status.get("status") == "revoked"

    def maintenance_once(self) -> dict[str, Any]:
        """Reconcile host leases and heartbeat the active peer independently."""

        if self._initialization_error is not None:
            return {
                "active": False,
                "renewed": False,
                "healthy": False,
                "error": "secure_peer_state_unavailable",
            }
        # A failed first attachment must be recoverable without restarting the
        # service.  This is intentionally independent of client maintenance.
        self.retry_host_attachment()
        with self._guard:
            adapter = self._adapter
            host_store = self._host_store
            gateway = self._gateway
        if gateway is not None:
            try:
                # The service-owned 30-second maintenance loop is the sole
                # scheduler. Rotation is synchronous and only swaps the TLS
                # context used by future accepts, so shutdown has no extra
                # task or worker to cancel.
                gateway.refresh_listener_identity()
            except Exception as exc:
                if self.logger is not None:
                    self.logger.warning(
                        "secure peer listener certificate rotation deferred error_type=%s",
                        type(exc).__name__,
                    )
        if adapter is not None and host_store is not None:
            # Replay each trust tombstone independently.  Already-retired Hub
            # bindings are skipped so a permanent tombstone does not generate
            # writes forever, and one malformed peer cannot suppress leases.
            try:
                host_peers = host_store.list_peers(team_id=None)
            except Exception as exc:
                host_peers = []
                if self.logger is not None:
                    self.logger.warning(
                        "secure peer host tombstone scan deferred error_type=%s",
                        type(exc).__name__,
                    )
            for peer in host_peers:
                if peer.get("status") == "active" or not peer.get("team_id"):
                    continue
                try:
                    peer_id = str(peer["peer_id"])
                    active_ids = adapter.active_binding_peer_ids(
                        (peer_id,),
                        str(peer.get("peer_server_identity") or ""),
                    )
                    if peer_id in active_ids:
                        adapter.revoke_peer(
                            peer_id=peer_id,
                            team_id=str(peer["team_id"]),
                        )
                except Exception as exc:
                    if self.logger is not None:
                        self.logger.warning(
                            "secure peer revocation replay deferred peer_id=%s error_type=%s",
                            peer.get("peer_id"),
                            type(exc).__name__,
                        )
            try:
                adapter.expire_peer_leases(
                    stale_before=int(time.time()) - SECURE_PEER_LEASE_SECONDS
                )
            except Exception as exc:
                if self.logger is not None:
                    self.logger.warning(
                        "secure peer lease expiry deferred error_type=%s",
                        type(exc).__name__,
                    )
        try:
            # Persist outgoing pending deadlines even when no operator is
            # viewing or polling Team Network. This is also the periodic
            # crash-retry boundary for local key retirement.
            self.client.expire_pending_pairings()
        except Exception as exc:
            if self.logger is not None:
                self.logger.warning(
                    "secure peer outgoing pairing expiry deferred error_type=%s",
                    type(exc).__name__,
                )
        try:
            pairing_recovery = self.client.recover_pairing_attempts(limit=2)
        except Exception as exc:
            pairing_recovery = {
                "remaining": 0,
                "error": (
                    exc.code
                    if isinstance(exc, SecurePeerError)
                    else "pairing_recovery_deferred"
                ),
            }
        recovery_error = pairing_recovery.get("error")
        active = next(
            (item for item in self.client.list_connections() if item.get("active")),
            None,
        )
        if active is None:
            self._client_error = (
                _safe_status_error(recovery_error) if recovery_error else None
            )
            return {
                "active": False,
                "renewed": False,
                "healthy": False,
                "pairing_recovery": pairing_recovery,
            }
        connection_id = str(active.get("connection_id") or "")
        revocation_observation = active
        renewal: dict[str, Any] = {"renewed": False}
        renewal_error: BaseException | None = None
        try:
            renewal = self.client.renew_if_due(connection_id)
            renewed_connection = renewal.get("connection")
            if (
                isinstance(renewed_connection, Mapping)
                and renewed_connection.get("connection_id") == connection_id
            ):
                revocation_observation = renewed_connection
        except Exception as exc:
            renewal_error = exc

        health: Mapping[str, Any] | None = None
        health_error: BaseException | None = None
        try:
            # This heartbeat always runs even when renewal or route maintenance
            # failed.  Presence is a transport signal, not an ancillary job.
            health = self.client.peer_health(connection_id)
        except Exception as exc:
            health_error = exc

        if health_error is not None:
            revocation_signal = next(
                (
                    exc
                    for exc in (health_error, renewal_error)
                    if self._is_unconfirmed_peer_revocation(exc)
                ),
                None,
            )
            if (
                revocation_signal is not None
                and self._remote_revocation_confirmed(connection_id) is True
            ):
                return self._retire_remote_revoked_active_connection(
                    revocation_observation,
                    pairing_recovery,
                )
            self._client_failure_counts[connection_id] = min(
                SECURE_PEER_OFFLINE_FAILURES,
                self._client_failure_counts.get(connection_id, 0) + 1,
            )
            self._client_error = _safe_status_error(
                health_error.message
                if isinstance(health_error, SecurePeerError)
                else health_error
            )
            return {
                "active": True,
                "renewed": bool(renewal.get("renewed")),
                "healthy": False,
                "error": (
                    health_error.code
                    if isinstance(health_error, SecurePeerError)
                    else "secure_peer_maintenance_failed"
                ),
                "pairing_recovery": pairing_recovery,
            }

        assert health is not None
        # The heartbeat succeeded, so ancillary failures must not make the
        # transport appear offline or increment its reconnect counter.
        self._client_failure_counts.pop(connection_id, None)
        retired_routes = 0
        ancillary_error = renewal_error
        if self._relay_enabled:
            try:
                retired_routes = (
                    self.client.flush_pending_route_revocations_for_connection(
                        connection_id,
                        limit=8,
                    )
                )
            except Exception as exc:
                ancillary_error = ancillary_error or exc
                if (
                    self._is_unconfirmed_peer_revocation(exc)
                    and self._remote_revocation_confirmed(connection_id) is True
                ):
                    return self._retire_remote_revoked_active_connection(
                        revocation_observation,
                        pairing_recovery,
                    )

        scope_values = (
            revocation_observation.get("scopes")
            or revocation_observation.get("granted_scopes")
            or ()
        )
        granted_scopes = {
            str(scope) for scope in scope_values if isinstance(scope, str)
        }
        cross_chat_scoped = bool(
            granted_scopes.intersection(
                {"cross_chat.instruction", "cross_chat.request_reply"}
            )
        )
        remote_routes: list[dict[str, Any]] | None = []
        if self._relay_enabled and cross_chat_scoped:
            try:
                remote_routes = self.client.list_remote_routes(connection_id)
            except Exception as exc:
                ancillary_error = ancillary_error or exc
                remote_routes = None
                if (
                    self._is_unconfirmed_peer_revocation(exc)
                    and self._remote_revocation_confirmed(connection_id) is True
                ):
                    return self._retire_remote_revoked_active_connection(
                        revocation_observation,
                        pairing_recovery,
                    )
        if remote_routes is not None:
            with self._guard:
                self._remote_routes_cache[connection_id] = [
                    dict(item) for item in remote_routes
                ]
                self._remote_routes_refreshed_at[connection_id] = int(time.time())

        # A verified heartbeat proves the secure transport remains usable.
        # Renewal/catalog cleanup failures are surfaced in this maintenance
        # result but must not suppress Team Hub or relay capability.
        self._client_error = None
        result = {
            "active": True,
            "renewed": bool(renewal.get("renewed")),
            "healthy": True,
            "hub_id": health.get("hub_id"),
            "retired_routes": retired_routes,
            "pairing_recovery": pairing_recovery,
        }
        if ancillary_error is not None:
            result["error"] = (
                ancillary_error.code
                if isinstance(ancillary_error, SecurePeerError)
                else "secure_peer_maintenance_degraded"
            )
        return result

    def remote_route_delivery_available(self) -> bool:
        """Return true only when both relay-side route CAS gates are live."""

        if (
            not self._relay_enabled
            or self._initialization_error is not None
            or self.delivery_ledger is None
            or self._delivery_target_validator is None
        ):
            return False
        active = next(
            (item for item in self.client.list_connections() if item.get("active")),
            None,
        )
        now = int(time.time())
        client_ready = self._client_delivery_ready(active, now=now)
        with self._guard:
            store = self._host_store
            gateway = self._gateway
            host_config_enabled = bool(self._config.get("enabled"))
        with self._peer_admission:
            peer_accepting = bool(self._peer_accepting)
        host_ready = False
        if (
            store is not None
            and gateway is not None
            and host_config_enabled
            and peer_accepting
        ):
            try:
                consent = store.cross_chat_consent_status()
                epoch = int(consent.get("consent_epoch") or 0)
                host_ready = bool(
                    consent.get("runtime_enabled")
                    and epoch > 0
                    and any(
                        peer.get("status") == "active"
                        and int(peer.get("certificate_expires_at") or 0)
                        > now + 60
                        and int(peer.get("cross_chat_grant_epoch") or 0) == epoch
                        and any(
                            str(scope).startswith("cross_chat.")
                            for scope in peer.get("scopes") or []
                        )
                        for peer in store.list_peers(team_id=None)
                    )
                )
            except Exception:
                host_ready = False
        return client_ready or host_ready

    def _client_delivery_ready(
        self,
        connection: Mapping[str, Any] | None,
        *,
        now: int | None = None,
    ) -> bool:
        timestamp = int(time.time()) if now is None else int(now)
        return bool(
            connection
            and connection.get("active")
            and connection.get("status") == "connected"
            and connection.get("remote_route_delivery_available") is True
            and self._client_error is None
            and int(connection.get("last_validated_at") or 0)
            >= timestamp - 120
            and int(connection.get("certificate_expires_at") or 0)
            > timestamp + 60
        )

    def _host_peer_delivery_ready(
        self,
        peer: Mapping[str, Any] | None,
        *,
        now: int | None = None,
    ) -> bool:
        timestamp = int(time.time()) if now is None else int(now)
        with self._guard:
            store = self._host_store
            gateway = self._gateway
            enabled = bool(self._config.get("enabled"))
        with self._peer_admission:
            accepting = bool(self._peer_accepting)
        if (
            peer is None
            or store is None
            or gateway is None
            or not enabled
            or not accepting
            or peer.get("status") != "active"
            or int(peer.get("certificate_expires_at") or 0)
            <= timestamp + 60
            or not any(
                str(scope).startswith("cross_chat.")
                for scope in peer.get("scopes") or []
            )
        ):
            return False
        try:
            consent = store.cross_chat_consent_status()
            return bool(
                consent.get("runtime_enabled")
                and int(consent.get("consent_epoch") or 0) > 0
                and int(peer.get("cross_chat_grant_epoch") or 0)
                == int(consent.get("consent_epoch") or 0)
            )
        except Exception:
            return False

    def set_delivery_target_validator(self, validator: Any) -> None:
        """Attach the local chat admission check used before remote receipt.

        Route resolution proves the opaque route revision. AgentsServer still
        owns live chat/archive/deletion state, so that final check is injected
        here and must complete before the durable delivered receipt is sent.
        """

        if validator is not None and not callable(validator):
            raise TypeError("secure peer delivery target validator must be callable")
        with self._guard:
            self._delivery_target_validator = validator

    def validate_remote_reference(
        self,
        source_session_id: str,
        reference: Mapping[str, Any],
        *,
        expected_snapshot: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Resolve both route grants without trusting renderer metadata."""

        if not self.remote_route_delivery_available():
            raise SecurePeerError(
                "remote_route_delivery_unavailable",
                "Secure peer chat delivery is not enabled",
                503,
            )
        action = str(reference.get("action") or "")
        connection_id = str(reference.get("target_connection_id") or "")
        target_route_id = str(reference.get("target_route_id") or "")
        target_revision = str(reference.get("target_route_revision") or "")
        target_server_identity = str(
            reference.get("target_server_identity") or ""
        )
        target = next(
            (
                route
                for route in self._remote_routes()
                if route.get("connection_id") == connection_id
                and route.get("route_id") == target_route_id
                and route.get("revision") == target_revision
                and route.get("peer_server_identity") == target_server_identity
                and action in set(route.get("actions") or [])
            ),
            None,
        )
        client_connection = self._client_connection(connection_id)
        host_peer = self._host_peer(connection_id)
        if target is None and client_connection is not None:
            with self._guard:
                refreshed_at = int(
                    self._remote_routes_refreshed_at.get(connection_id) or 0
                )
            if refreshed_at <= 0 or refreshed_at < int(time.time()) - 120:
                # An empty/stale cache is not evidence that the remote owner
                # revoked a route. In particular it is empty after restart
                # until a pinned mTLS catalog refresh succeeds. Keep durable
                # response intents retryable instead of misclassifying an
                # offline peer as an authoritative route revocation.
                raise SecurePeerError(
                    "remote_route_catalog_unavailable",
                    "Secure peer route catalog has not been freshly verified",
                    503,
                )
        sources = [
            route
            for route in self._published_routes()
            if route.get("connection_id") == connection_id
            and route.get("chat_id") == source_session_id
            and route.get("status") == "active"
            and action in set(route.get("actions") or [])
        ]
        if target is None or len(sources) != 1:
            raise SecurePeerError(
                "route_changed",
                "Secure peer route is unavailable or changed",
                409,
            )
        source = sources[0]
        if client_connection is not None:
            if not self._client_delivery_ready(client_connection):
                raise SecurePeerError(
                    "connection_unavailable",
                    "Secure peer connection is not freshly verified",
                    503,
                )
            role = "client"
            team_id = str(client_connection.get("team_id") or "")
            hub_id = str(client_connection.get("hub_id") or "")
        elif self._host_peer_delivery_ready(host_peer):
            role = "host"
            team_id = str(host_peer.get("team_id") or "")
            with self._guard:
                host_store = self._host_store
            hub_id = str(host_store.hub_id if host_store is not None else "")
        else:
            raise SecurePeerError(
                "connection_unavailable",
                "Secure peer connection is unavailable",
                409,
            )
        snapshot = {
            "version": 1,
            "role": role,
            "connection_id": connection_id,
            "team_id": team_id,
            "hub_id": hub_id,
            "source_server_identity": self.server_identity,
            "source_chat_id": source_session_id,
            "source_route_id": source.get("route_id"),
            "source_route_revision": source.get("revision"),
            "target_server_identity": target_server_identity,
            "target_route_id": target_route_id,
            "target_route_revision": target_revision,
            "action": action,
        }
        if expected_snapshot is not None and dict(expected_snapshot) != snapshot:
            raise SecurePeerError(
                "route_changed",
                "Secure peer route changed while the turn was queued",
                409,
            )
        return snapshot

    def submit_remote_handoff(
        self,
        snapshot: Mapping[str, Any],
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
        """Submit an initial or response leg through the exact route pair."""

        if not self.remote_route_delivery_available():
            raise SecurePeerError(
                "remote_route_delivery_unavailable",
                "Secure peer chat delivery is unavailable",
                503,
            )
        role = str(snapshot.get("role") or "")
        connection_id = str(snapshot.get("connection_id") or "")
        if role == "client":
            if not self._client_delivery_ready(
                self._client_connection(connection_id)
            ):
                raise SecurePeerError(
                    "connection_unavailable",
                    "Secure peer connection is not freshly verified",
                    503,
                )
        elif role == "host":
            if not self._host_peer_delivery_ready(
                self._host_peer(connection_id)
            ):
                raise SecurePeerError(
                    "connection_unavailable",
                    "Secure peer host route is not currently reachable",
                    503,
                )
        else:
            raise SecurePeerError(
                "connection_unavailable",
                "Secure peer route owner is unavailable",
                409,
            )
        matching_sources = [
            route
            for route in self._published_routes()
            if route.get("connection_id") == snapshot.get("connection_id")
            and route.get("chat_id") == snapshot.get("source_chat_id")
            and route.get("route_id") == snapshot.get("source_route_id")
            and route.get("revision") == snapshot.get("source_route_revision")
            and route.get("status") == "active"
            and action in set(route.get("actions") or [])
        ]
        if len(matching_sources) != 1:
            raise SecurePeerError(
                "route_changed",
                "Secure peer source route is unavailable or changed",
                409,
            )
        initial = exchange_id is None
        kind = action if initial else ("request_reply" if request_response else "response")
        deadline = int(expires_at or (time.time() + 72 * 60 * 60))
        payload = {
            "request_id": request_id,
            "source_route_id": snapshot.get("source_route_id"),
            "target_route_id": snapshot.get("target_route_id"),
            "target_route_revision": snapshot.get("target_route_revision"),
            "kind": kind,
            "exchange_id": exchange_id,
            "parent_envelope_id": parent_envelope_id,
            "expires_at": deadline,
            "body": {"message": body},
        }
        if role == "client":
            response = self.client.submit_envelope_from_published_route(
                connection_id,
                source_route_id=str(snapshot.get("source_route_id") or ""),
                source_route_revision=str(
                    snapshot.get("source_route_revision") or ""
                ),
                source_chat_id=str(snapshot.get("source_chat_id") or ""),
                action=action,
                payload=payload,
            )
        elif role == "host":
            with self._guard:
                store = self._host_store
            if store is None:
                raise SecurePeerError(
                    "host_unavailable",
                    "Secure peer host is unavailable",
                    503,
                )
            response = store.submit_local_envelope(
                str(snapshot.get("team_id") or ""),
                str(snapshot.get("source_route_id") or ""),
                payload,
            )
        else:
            raise SecurePeerError(
                "connection_unavailable",
                "Secure peer route owner is unavailable",
                409,
            )
        if not isinstance(response, dict) or set(response) != {
            "envelope_id",
            "status",
            "used_legs",
            "max_legs",
            "expires_at",
            "exchange_id",
        }:
            raise SecurePeerError(
                "remote_invalid",
                "Secure peer relay returned an invalid confirmation",
                502,
            )
        try:
            envelope_uuid = uuid.UUID(str(response.get("envelope_id") or ""))
            exchange_uuid = uuid.UUID(str(response.get("exchange_id") or ""))
        except (ValueError, AttributeError) as exc:
            raise SecurePeerError(
                "remote_invalid",
                "Secure peer relay returned invalid identifiers",
                502,
            ) from exc
        if (
            envelope_uuid.version != 4
            or str(envelope_uuid) != response.get("envelope_id")
            or exchange_uuid.version != 4
            or str(exchange_uuid) != response.get("exchange_id")
            or response.get("status")
            not in {"queued", "claimed", "delivered", "failed", "expired"}
            or type(response.get("used_legs")) is not int
            or not 1 <= int(response["used_legs"]) <= 6
            or response.get("max_legs") != 6
            or response.get("expires_at") != deadline
            or (exchange_id is not None and response.get("exchange_id") != exchange_id)
            or (
                expected_used_legs is not None
                and response.get("used_legs") != expected_used_legs
            )
            or (initial and response.get("used_legs") != 1)
        ):
            raise SecurePeerError(
                "remote_invalid",
                "Secure peer relay confirmation changed the accepted request",
                502,
            )
        return response

    def _resolve_claim_target(
        self,
        envelope: Mapping[str, Any],
        *,
        role: str,
        connection_id: str,
    ) -> tuple[str, str]:
        route_id = str(envelope.get("target_route_id") or "")
        revision = str(envelope.get("target_route_revision") or "")
        if role == "client":
            match = next(
                (
                    route
                    for route in self.client.list_published_routes()
                    if route.get("connection_id") == connection_id
                    and route.get("route_id") == route_id
                    and route.get("revision") == revision
                    and route.get("status") == "active"
                ),
                None,
            )
            if match is None:
                raise SecurePeerError(
                    "route_changed",
                    "Secure peer receive route is unavailable or changed",
                    409,
                )
            connection = self._client_connection(connection_id) or {}
            return str(match.get("chat_id") or ""), str(connection.get("team_id") or "")
        with self._guard:
            store = self._host_store
        if store is None:
            raise SecurePeerError("host_unavailable", "Secure peer host is unavailable", 503)
        match = next(
            (
                route
                for route in store.list_local_routes(
                    connection_id,
                    include_revoked=False,
                )
                if route.get("route_id") == route_id
                and route.get("revision") == revision
            ),
            None,
        )
        if match is None:
            raise SecurePeerError(
                "route_changed",
                "Secure peer receive route is unavailable or changed",
                409,
            )
        return str(match.get("chat_id") or ""), str(match.get("team_id") or "")

    def _receipt_claim(
        self,
        envelope: Mapping[str, Any],
        *,
        role: str,
        connection_id: str,
        team_id: str,
        lease_token: str,
        outcome: str,
    ) -> dict[str, Any]:
        if role == "client":
            return self.client.receipt_envelope_for_published_route(
                connection_id,
                str(envelope.get("envelope_id") or ""),
                target_route_id=str(
                    envelope.get("target_route_id") or ""
                ),
                target_route_revision=str(
                    envelope.get("target_route_revision") or ""
                ),
                lease_token=lease_token,
                outcome=outcome,
            )
        with self._guard:
            store = self._host_store
        if store is None:
            raise SecurePeerError("host_unavailable", "Secure peer host is unavailable", 503)
        return store.receipt_local_envelope(
            team_id,
            str(envelope.get("target_route_id") or ""),
            str(envelope.get("envelope_id") or ""),
            lease_token,
            outcome,
        )

    def claim_deliveries_once(self, *, limit: int = 20) -> list[dict[str, Any]]:
        # Linearize client claim + durable prepare with deactivate/forget. Once
        # retirement acquires this guard it either observes the prepared row and
        # returns 409, or completes before a claim can observe an active client.
        with self._outbound_guard:
            return self._claim_deliveries_once_locked(limit=limit)

    def _claim_deliveries_once_locked(
        self, *, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Claim and durably prepare inbound envelopes for lifecycle admission.

        The remote delivered receipt is intentionally deferred. AgentsServer
        must hold the target chat's lifecycle lock across that receipt and the
        durable queue/run owner handoff so archive/delete cannot cross it.
        """

        if not self.remote_route_delivery_available() or self.delivery_ledger is None:
            return []
        claims: list[tuple[str, str, str, dict[str, Any]]] = []
        lease_owner = f"agentsserver-{self.server_instance_id}"
        delivery_claim_attempted = False
        delivery_claim_error: str | None = None
        active = next(
            (item for item in self.client.list_connections() if item.get("active")),
            None,
        )
        if active is not None:
            delivery_claim_attempted = True
            connection_id = str(active.get("connection_id") or "")
            try:
                response = self.client.claim_inbox(
                    connection_id,
                    lease_owner=lease_owner,
                    limit=limit,
                )
                token = str(response.get("lease_token") or "")
                for envelope in response.get("envelopes") or []:
                    claims.append(("client", connection_id, token, dict(envelope)))
            except Exception as exc:
                # Relay inbox availability is an ancillary delivery signal. A
                # fresh authenticated heartbeat still proves that ordinary
                # Teamspace proxy traffic is usable, so never poison the
                # transport-health field (and its Team Hub capability gate)
                # with a relay-only failure.
                delivery_claim_error = _safe_status_error(
                    exc.message if isinstance(exc, SecurePeerError) else exc
                )
        with self._guard:
            store = self._host_store
        if store is not None:
            remaining = max(0, limit - len(claims))
            if remaining:
                delivery_claim_attempted = True
                try:
                    response = store.claim_local_inbox(
                        lease_owner,
                        limit=remaining,
                    )
                    token = str(response.get("lease_token") or "")
                    for envelope in response.get("envelopes") or []:
                        claims.append((
                            "host",
                            str(envelope.get("source_peer_id") or ""),
                            token,
                            dict(envelope),
                        ))
                except Exception as exc:
                    delivery_claim_error = delivery_claim_error or _safe_status_error(
                        exc.message if isinstance(exc, SecurePeerError) else exc
                    )
        if delivery_claim_attempted:
            self._delivery_error = delivery_claim_error
        ready: list[dict[str, Any]] = []
        for role, connection_id, lease_token, envelope in claims:
            if not lease_token:
                continue
            try:
                target_chat_id, team_id = self._resolve_claim_target(
                    envelope,
                    role=role,
                    connection_id=connection_id,
                )
                record, _created = self.delivery_ledger.prepare(
                    envelope,
                    transport_role=role,
                    connection_id=connection_id,
                    lease_token=lease_token,
                    target_chat_id=target_chat_id,
                )
                if record.get("state") == "prepared":
                    ready.append(record)
                elif record.get("state") in {"completed", "failed"}:
                    # A terminal local owner may be redelivered after a lost
                    # receipt acknowledgement. Reassert only its terminal
                    # failure; never recreate a turn.
                    self._receipt_claim(
                        envelope,
                        role=role,
                        connection_id=connection_id,
                        team_id=team_id,
                        lease_token=lease_token,
                        outcome=(
                            "delivered"
                            if record.get("state") == "completed"
                            else "failed"
                        ),
                    )
            except Exception:
                with suppress(Exception):
                    _target, team_id = self._resolve_claim_target(
                        envelope,
                        role=role,
                        connection_id=connection_id,
                    )
                    self._receipt_claim(
                        envelope,
                        role=role,
                        connection_id=connection_id,
                        team_id=team_id,
                        lease_token=lease_token,
                        outcome="failed",
                    )
                continue
        self.delivery_ledger.prune()
        return ready

    def recover_prepared_deliveries(self) -> list[dict[str, Any]]:
        """Return prepared rows for lifecycle-fenced receipt reconciliation."""

        if self.delivery_ledger is None:
            return []
        ready: list[dict[str, Any]] = []
        timestamp = int(time.time())
        for record in self.delivery_ledger.recoverable():
            if record.get("state") != "prepared":
                continue
            if int(record.get("expires_at") or 0) <= timestamp:
                self.delivery_ledger.finish(
                    str(record.get("envelope_id") or ""),
                    succeeded=False,
                    error="secure peer exchange expired before local admission",
                )
                continue
            ready.append(record)
        return ready

    def accept_prepared_delivery(self, envelope_id: str) -> dict[str, Any] | None:
        """Receipt then authorize one prepared row under the caller's lock."""

        if self.delivery_ledger is None:
            return None
        record = self.delivery_ledger.get(envelope_id)
        if record is None:
            return None
        if record.get("state") == "authorized":
            return record
        if record.get("state") != "prepared":
            return None
        if int(record.get("expires_at") or 0) <= int(time.time()):
            return self.delivery_ledger.finish(
                envelope_id,
                succeeded=False,
                error="secure peer exchange expired before local admission",
            )
        self._receipt_claim(
            record,
            role=str(record.get("transport_role") or ""),
            connection_id=str(record.get("connection_id") or ""),
            team_id=str(record.get("team_id") or ""),
            lease_token=str(record.get("lease_token") or ""),
            outcome="delivered",
        )
        return self.delivery_ledger.authorize(envelope_id)

    def reject_prepared_delivery(
        self,
        envelope_id: str,
        *,
        error: str,
    ) -> dict[str, Any] | None:
        """Fail a prepared target after best-effort remote rejection."""

        if self.delivery_ledger is None:
            return None
        record = self.delivery_ledger.get(envelope_id)
        if record is None:
            return None
        if record.get("state") == "prepared":
            try:
                self._receipt_claim(
                    record,
                    role=str(record.get("transport_role") or ""),
                    connection_id=str(record.get("connection_id") or ""),
                    team_id=str(record.get("team_id") or ""),
                    lease_token=str(record.get("lease_token") or ""),
                    outcome="failed",
                )
            except SecurePeerError as exc:
                if exc.code != "lease_unavailable" and exc.status_code < 500:
                    raise
            return self.delivery_ledger.finish(
                envelope_id,
                succeeded=False,
                error=error,
            )
        if record.get("state") == "authorized":
            # The remote delivered receipt has already committed. There is no
            # lease to reject now, but an ownerless authorization whose local
            # target disappeared must become terminal instead of retrying and
            # fencing chat/connection retirement forever. The ledger CAS
            # refuses this transition if queue/run ownership raced with it.
            return self.delivery_ledger.fail_ownerless_authorized(
                envelope_id,
                error=error,
            )
        return record

    def bind_delivery_owner(
        self,
        envelope_id: str,
        *,
        queued_id: str | None,
        run_id: str | None,
    ) -> dict[str, Any] | None:
        if self.delivery_ledger is None:
            return None
        return self.delivery_ledger.bind_owner(
            envelope_id,
            queued_id=queued_id,
            run_id=run_id,
        )

    def defer_delivery_admission(
        self,
        envelope_id: str,
        *,
        error: str,
    ) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.defer_admission(
                envelope_id,
                error=error,
            )
            if self.delivery_ledger is not None
            else None
        )

    def pending_delivery_admissions(
        self,
        *,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        return (
            self.delivery_ledger.pending_admissions(limit=limit)
            if self.delivery_ledger is not None
            else []
        )

    def nonterminal_deliveries_for_chat(
        self,
        chat_id: str,
    ) -> list[dict[str, Any]]:
        return (
            self.delivery_ledger.nonterminal_for_chat(chat_id)
            if self.delivery_ledger is not None
            else []
        )

    def delivery(self, envelope_id: str) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.get(envelope_id)
            if self.delivery_ledger is not None
            else None
        )

    def recoverable_deliveries(self) -> list[dict[str, Any]]:
        return (
            self.delivery_ledger.recoverable()
            if self.delivery_ledger is not None
            else []
        )

    def delivery_for_run(self, run_id: str) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.for_run(run_id)
            if self.delivery_ledger is not None
            else None
        )

    def prepare_delivery_response(
        self,
        envelope_id: str,
        *,
        request_id: str,
        body: str,
        request_response: bool,
    ) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.prepare_response(
                envelope_id,
                request_id=request_id,
                body=body,
                request_response=request_response,
            )
            if self.delivery_ledger is not None
            else None
        )

    def mark_delivery_response(
        self,
        envelope_id: str,
        *,
        request_id: str | None = None,
    ) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.mark_response_committed(
                envelope_id,
                request_id=request_id,
            )
            if self.delivery_ledger is not None
            else None
        )

    def clear_delivery_response(
        self,
        envelope_id: str,
        *,
        request_id: str,
    ) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.clear_response_intent(
                envelope_id,
                request_id=request_id,
            )
            if self.delivery_ledger is not None
            else None
        )

    def defer_delivery_response(
        self,
        envelope_id: str,
        *,
        request_id: str,
        error: str,
    ) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.defer_response(
                envelope_id,
                request_id=request_id,
                error=error,
            )
            if self.delivery_ledger is not None
            else None
        )

    def pending_delivery_responses(
        self,
        *,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        return (
            self.delivery_ledger.pending_responses(limit=limit)
            if self.delivery_ledger is not None
            else []
        )

    def prepare_outbound_handoff(
        self,
        *,
        request_id: str,
        source_session_id: str,
        source_run_id: str,
        snapshot: Mapping[str, Any],
        body: str,
        action: str,
        expires_at: int,
    ) -> tuple[dict[str, Any], bool]:
        if self.delivery_ledger is None:
            raise SecurePeerError(
                "secure_peer_unavailable",
                "Secure peer durable delivery state is unavailable",
                503,
            )
        with self._outbound_guard:
            exact_sources = [
                route
                for route in self._published_routes()
                if str(route.get("connection_id") or "")
                == str(snapshot.get("connection_id") or "")
                and str(route.get("chat_id") or "") == source_session_id
                and str(route.get("route_id") or "")
                == str(snapshot.get("source_route_id") or "")
                and str(route.get("revision") or "")
                == str(snapshot.get("source_route_revision") or "")
                and route.get("status") == "active"
                and action in set(route.get("actions") or [])
            ]
            if (
                len(exact_sources) != 1
                or str(snapshot.get("source_chat_id") or "")
                != source_session_id
                or str(snapshot.get("action") or "") != action
            ):
                raise SecurePeerError(
                    "route_changed",
                    "Secure peer source route is unavailable or changed",
                    409,
                )
            return self.delivery_ledger.prepare_outbound(
                request_id=request_id,
                source_session_id=source_session_id,
                source_run_id=source_run_id,
                snapshot=snapshot,
                body=body,
                action=action,
                expires_at=expires_at,
            )

    def outbound_handoff(self, request_id: str) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.outbound(request_id)
            if self.delivery_ledger is not None
            else None
        )

    def commit_outbound_handoff(
        self,
        request_id: str,
        response: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.commit_outbound(request_id, response)
            if self.delivery_ledger is not None
            else None
        )

    def defer_outbound_handoff(
        self,
        request_id: str,
        *,
        error: str,
    ) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.defer_outbound(request_id, error)
            if self.delivery_ledger is not None
            else None
        )

    def fail_outbound_handoff(
        self,
        request_id: str,
        *,
        error: str,
    ) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.fail_outbound(request_id, error)
            if self.delivery_ledger is not None
            else None
        )

    def pending_outbound_handoffs(
        self,
        *,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        return (
            self.delivery_ledger.pending_outbound(limit=limit)
            if self.delivery_ledger is not None
            else []
        )

    def recoverable_outbound_handoffs(
        self,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        return (
            self.delivery_ledger.recoverable_outbound(limit=limit)
            if self.delivery_ledger is not None
            else []
        )

    def finish_delivery(
        self,
        envelope_id: str,
        *,
        succeeded: bool,
        result_text: str = "",
        error: str | None = None,
    ) -> dict[str, Any] | None:
        return (
            self.delivery_ledger.finish(
                envelope_id,
                succeeded=succeeded,
                result_text=result_text,
                error=error,
            )
            if self.delivery_ledger is not None
            else None
        )

    def team_hub_capability(self) -> dict[str, Any] | None:
        active = next(
            (item for item in self.client.list_connections() if item.get("active")),
            None,
        )
        if active is None or active.get("status") not in {"approved", "connected"}:
            return None
        now = int(time.time())
        if (
            int(active.get("certificate_expires_at") or 0) <= now + 60
            or int(active.get("last_validated_at") or 0) < now - 120
            or self._client_error is not None
        ):
            return None
        connection_id = str(active["connection_id"])
        base_path = f"{SECURE_PEER_PROXY_PREFIX}/{connection_id}"
        route = {
            "transport": "secure_peer",
            "hub_url": None,
            "base_path": base_path,
            "connection_id": connection_id,
            "host_server_identity": active.get("host_server_identity"),
            "hub_id": active.get("hub_id"),
        }
        return {
            "available": True,
            "designated_host": False,
            "version": 1,
            "base_path": base_path,
            "transport": "secure_peer",
            "hub_url": None,
            "routes": [route],
            "hub_id": active.get("hub_id"),
            "host_server_identity": active.get("host_server_identity"),
            "connection_id": connection_id,
            "message": "This AgentsServer is paired to Teamspace over pinned TLS 1.3 and mutual certificates.",
            "action": None,
        }

    def _forward_peer_request(self, request):
        """Enter the same crash-consistency boundary as mounted Hub traffic."""

        deferred_release = False
        with self._peer_admission:
            if not self._peer_accepting:
                raise SecurePeerError(
                    "hub_maintenance",
                    "Team Hub is unavailable during server maintenance",
                    503,
                )
            self._peer_in_flight += 1
        try:
            with self._guard:
                adapter, hub_store = self._adapter, self._hub_store
            if adapter is None or hub_store is None:
                raise SecurePeerError("hub_unavailable", "Team Hub is unavailable", 503)
            if request.method in {"POST", "PUT", "DELETE"}:
                # Snapshot/fence creation takes this exact lock.  A write
                # therefore either commits before the snapshot begins or sees
                # the durable fence and fails before mutation.
                with HubStore.maintenance_control_lock(hub_store.data_dir):
                    if hub_store.maintenance_fence() is not None:
                        raise SecurePeerError(
                            "hub_maintenance",
                            "Team Hub is unavailable during server maintenance",
                            503,
                        )
                    result = (
                        adapter.forward_attachment(request)
                        if isinstance(request, AttachmentProxyRequest)
                        else adapter.forward(request)
                    )
            else:
                if hub_store.maintenance_fence() is not None:
                    raise SecurePeerError(
                        "hub_maintenance",
                        "Team Hub is unavailable during server maintenance",
                        503,
                    )
                result = (
                    adapter.forward_attachment(request)
                    if isinstance(request, AttachmentProxyRequest)
                    else adapter.forward(request)
                )
            if (
                isinstance(result, AttachmentProxyResponse)
                and result.descriptor is not None
                and callable(result.finalizer)
            ):
                inner_finalizer = result.finalizer
                finalizer_lock = threading.Lock()
                finalized = False

                def finalize() -> None:
                    nonlocal finalized
                    with finalizer_lock:
                        if finalized:
                            return
                        finalized = True
                    try:
                        inner_finalizer()
                    finally:
                        with self._peer_admission:
                            self._peer_in_flight = max(0, self._peer_in_flight - 1)
                            if self._peer_in_flight == 0:
                                self._peer_admission.notify_all()

                result = AttachmentProxyResponse(
                    status=result.status,
                    headers=result.headers,
                    body=result.body,
                    descriptor=result.descriptor,
                    offset=result.offset,
                    length=result.length,
                    finalizer=finalize,
                    cancelled=result.cancelled,
                )
                deferred_release = True
            return result
        finally:
            if not deferred_release:
                with self._peer_admission:
                    self._peer_in_flight = max(0, self._peer_in_flight - 1)
                    if self._peer_in_flight == 0:
                        self._peer_admission.notify_all()

    def _record_authenticated_peer_heartbeat(
        self,
        peer: PeerAuthorization,
    ) -> None:
        with self._guard:
            adapter = self._adapter
        if adapter is None:
            raise SecurePeerError(
                "hub_unavailable",
                "Team Hub is unavailable",
                503,
            )
        adapter.record_peer_heartbeat(peer.peer_id, peer.team_id)

    def _revoke_authenticated_peer(
        self,
        peer: PeerAuthorization,
        idempotency_key: str,
    ) -> dict[str, Any]:
        with self._guard:
            store, adapter = self._host_store, self._adapter
        if store is None or adapter is None:
            raise SecurePeerError(
                "host_unavailable",
                "Secure peer revocation is unavailable",
                503,
            )
        result = store.revoke_peer_for_self(peer, idempotency_key)
        # Replayed after a cached core response as well, closing the
        # secure-peer DB -> Team Hub DB crash boundary.
        adapter.revoke_peer(peer_id=peer.peer_id, team_id=peer.team_id)
        return result

    def close_host_admission(self) -> None:
        with self._peer_admission:
            self._peer_accepting = False
            while self._peer_in_flight:
                self._peer_admission.wait(timeout=0.25)

    def reopen_host_admission(self) -> None:
        with self._guard:
            ready = (
                self._hub_store is not None
                and self._adapter is not None
                and self._gateway is not None
            )
        with self._peer_admission:
            self._peer_accepting = ready
            self._peer_admission.notify_all()

    def proxy(
        self,
        connection_id: str,
        method: str,
        path: str,
        *,
        query: str,
        headers: Mapping[str, str] | None,
        body: bytes | None,
    ):
        reply_parent_path = self._enforce_inbox_only_outbound_proxy(
            method,
            path,
            query=query,
            body=body,
        )
        with self._outbound_guard:
            active = next(
                (
                    item
                    for item in self.client.list_connections()
                    if item.get("active")
                ),
                None,
            )
            if active is None or active.get("connection_id") != connection_id:
                raise SecurePeerError(
                    "connection_unavailable",
                    "Secure peer connection is unavailable",
                    404,
                )
            try:
                if reply_parent_path is not None:
                    parent_response = self.client.proxy(
                        connection_id,
                        "GET",
                        reply_parent_path,
                        query="",
                        headers={"accept": "application/json"},
                        body=None,
                    )
                    parent = self._decoded_proxy_json(
                        parent_response,
                        preserve_not_found=True,
                    )
                    item = parent.get("item")
                    sender = item.get("from") if isinstance(item, Mapping) else None
                    recipient = item.get("to") if isinstance(item, Mapping) else None
                    allowed_participant_kinds = {"server", "human"}
                    if (
                        not isinstance(sender, Mapping)
                        or not isinstance(recipient, Mapping)
                        or sender.get("kind") not in allowed_participant_kinds
                        or recipient.get("kind") not in allowed_participant_kinds
                    ):
                        raise SecurePeerError(
                            "invalid_request",
                            "Agent-addressed peer replies are retired",
                            422,
                        )
                return self.client.proxy(
                    connection_id,
                    method,
                    path,
                    query=query,
                    headers=headers,
                    body=body,
                )
            except SecurePeerError as exc:
                if (
                    self._is_unconfirmed_peer_revocation(exc)
                    and self._remote_revocation_confirmed(connection_id) is True
                ):
                    try:
                        self._retire_remote_revoked_active_connection(active, {})
                    except Exception as retire_error:
                        if self.logger is not None:
                            self.logger.warning(
                                "secure peer local revocation retirement deferred error_type=%s",
                                type(retire_error).__name__,
                            )
                raise

    @staticmethod
    def _enforce_inbox_only_outbound_proxy(
        method: str,
        path: str,
        *,
        query: str,
        body: bytes | Mapping[str, Any] | None,
    ) -> str | None:
        """Fence agent-addressed Team Network traffic before peer I/O.

        Hosts can run an older compatible build, so the client must enforce
        the server-inbox boundary instead of relying only on the receiver.
        The returned path identifies an immutable request that must be read
        before a reply can be posted.
        """

        normalized_method = str(method).upper()
        pieces = path.split("/")
        if not (
            len(pieces) >= 6
            and pieces[:3] == ["", "v1", "teams"]
            and pieces[4] == "network"
        ):
            return None

        def invalid() -> None:
            raise SecurePeerError(
                "invalid_request",
                "Cross-server Team Network mail accepts server inboxes only",
                422,
            )

        resource = pieces[5:]
        if normalized_method == "GET" and resource == ["mailbox"]:
            try:
                pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
            except ValueError:
                invalid()
            address_kinds = [value for key, value in pairs if key == "address_kind"]
            if address_kinds != ["server"]:
                invalid()
            return None
        if normalized_method == "GET" and resource == ["messages"]:
            try:
                pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
            except ValueError:
                invalid()
            for key, value in pairs:
                if key in {"address_kind", "from_kind"} and value not in {
                    "server",
                    "human",
                }:
                    invalid()
            return None
        if normalized_method != "POST":
            return None

        mode: str | None = None
        reply_parent: str | None = None
        if resource == ["mailbox"]:
            mode = "mailbox"
        elif resource == ["requests"]:
            mode = "request"
        elif len(resource) == 3 and resource[0] == "requests" and resource[2] == "replies":
            mode = "reply"
            reply_parent = "/".join(pieces[:-1])
        elif resource == ["messages"]:
            mode = "messages"
        else:
            return None

        if isinstance(body, Mapping):
            value = dict(body)
        else:
            try:
                value = json.loads(body) if isinstance(body, bytes) else None
            except (UnicodeDecodeError, json.JSONDecodeError):
                invalid()
        if not isinstance(value, dict):
            invalid()
        if mode in {"mailbox", "request"}:
            destination = value.get("to")
            if (
                not isinstance(destination, Mapping)
                or destination.get("kind") != "server"
                or not isinstance(destination.get("id"), str)
                or not destination.get("id")
                or value.get("from_agent_id") is not None
            ):
                invalid()
        elif mode == "reply":
            if value.get("from_agent_id") is not None:
                invalid()
        else:
            recipients = value.get("recipients")
            if (
                not isinstance(recipients, list)
                or not recipients
                or any(
                    not isinstance(recipient, Mapping)
                    or recipient.get("kind") not in {"server", "human", "all"}
                    for recipient in recipients
                )
            ):
                invalid()
        return reply_parent

    @staticmethod
    def _agent_mail_destinations(
        projection: Mapping[str, Any],
        *,
        realm: Mapping[str, Any],
        current_server_identity: str | None = None,
    ) -> list[dict[str, Any]]:
        servers = [
            dict(item)
            for item in projection.get("servers", [])
            if isinstance(item, Mapping)
        ]
        owned_server_ids = {
            str(item.get("id") or "")
            for item in servers
            if item.get("owned_by_caller") is True
        }
        network = projection.get("network")
        network_display_name = (
            str(network.get("display_name") or "Team Network")[:160]
            if isinstance(network, Mapping)
            else "Team Network"
        )
        destinations: list[dict[str, Any]] = []
        for server in servers:
            server_id = str(server.get("id") or "")
            server_identity = str(server.get("server_identity") or "")
            if (
                not server_id
                or server_id in owned_server_ids
                or server.get("status") != "active"
                or server.get("owned_by_caller") is not False
                or (
                    current_server_identity is not None
                    and server_identity == current_server_identity
                )
            ):
                continue
            destinations.append({
                **dict(realm),
                "destination_kind": "server",
                "destination_id": server_id,
                "display_name": str(server.get("display_name") or "Server")[:160],
                "backend": None,
                "network_display_name": network_display_name,
            })
        return destinations

    @staticmethod
    def _decoded_proxy_json(
        response: Any,
        *,
        preserve_not_found: bool = False,
    ) -> dict[str, Any]:
        if preserve_not_found and int(response.status) == 404:
            # Exact recipient lookups intentionally collapse missing,
            # cross-team, and retired identities to the same local 404. Do
            # not reinterpret that bounded absence as a transient transport
            # outage; no remote response detail crosses this boundary.
            raise SecurePeerError("not_found", "Resource not found", 404)
        if int(response.status) != 200:
            raise SecurePeerError(
                "team_mail_unavailable",
                "Team Network mail is unavailable",
                409,
            )
        try:
            decoded = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecurePeerError(
                "team_mail_unavailable",
                "Team Network mail returned an invalid response",
                502,
            ) from exc
        if not isinstance(decoded, dict):
            raise SecurePeerError(
                "team_mail_unavailable",
                "Team Network mail returned an invalid response",
                502,
            )
        return decoded

    @staticmethod
    def _validated_agent_mail_receipt(
        value: Any,
        *,
        kind: str,
        target_kind: str,
        target_id: str,
        message: str,
    ) -> dict[str, Any]:
        """Validate the remote Hub's committed receipt before reporting success."""

        item = value.get("item") if isinstance(value, Mapping) else None
        delivery = value.get("delivery") if isinstance(value, Mapping) else None
        recipient = item.get("to") if isinstance(item, Mapping) else None
        expected_kind = "request" if kind == "request" else "message"
        if not (
            isinstance(item, Mapping)
            and isinstance(delivery, Mapping)
            and isinstance(item.get("id"), str)
            and item.get("id")
            and item.get("kind") == expected_kind
            and item.get("body") == message
            and item.get("body_format") == "markdown"
            and isinstance(recipient, Mapping)
            and recipient.get("kind") == target_kind
            and recipient.get("id") == target_id
            and isinstance(delivery.get("id"), str)
            and delivery.get("id")
            and delivery.get("state") == "available"
        ):
            raise SecurePeerError(
                "team_mail_invalid_receipt",
                "Team Network mail returned an invalid receipt",
                502,
            )
        return dict(value)

    def agent_mail_route_profiles(self) -> list[dict[str, Any]]:
        """Snapshot exact passive-mail destinations without exposing credentials."""

        profiles: list[dict[str, Any]] = []
        maximum_pages = 100
        maximum_destinations = 512
        with self._guard:
            host_store = self._hub_store
            active = next(
                (
                    dict(item)
                    for item in self.client.list_connections()
                    if item.get("active")
                    and item.get("status") == "connected"
                    and "teamspace.read" in set(item.get("scopes") or [])
                    and "teamspace.write" in set(item.get("scopes") or [])
                ),
                None,
            )
        if host_store is not None:
            for team_id in host_store.local_agent_mail_team_ids():
                team_profiles: list[dict[str, Any]] = []
                try:
                    claims = host_store.local_agent_mail_claims(team_id)
                    after_server_id: str | None = None
                    seen_cursors: set[str] = set()
                    for _page in range(maximum_pages):
                        projection = host_store.get_network(
                            claims,
                            team_id,
                            after_server_id=after_server_id,
                            limit=100,
                        )
                        team_profiles.extend(self._agent_mail_destinations(
                            projection,
                            realm={
                                "realm": "host",
                                "team_id": team_id,
                                "hub_id": host_store.hub_id,
                                "server_identity": self.server_identity,
                            },
                            current_server_identity=self.server_identity,
                        ))
                        if len(profiles) + len(team_profiles) > maximum_destinations:
                            raise HubError(
                                "team_mail_unavailable",
                                "Team Network mail destination limit was exceeded",
                                409,
                            )
                        if projection.get("has_more") is not True:
                            break
                        cursor = str(
                            projection.get("next_after_server_id") or ""
                        )
                        if not cursor or cursor in seen_cursors:
                            raise HubError(
                                "team_mail_unavailable",
                                "Team Network mail pagination changed",
                                409,
                            )
                        seen_cursors.add(cursor)
                        after_server_id = cursor
                    else:
                        raise HubError(
                            "team_mail_unavailable",
                            "Team Network mail page limit was exceeded",
                            409,
                        )
                except HubError:
                    # A route list is one exact snapshot, not a best-effort
                    # merge. Never disguise one unavailable host team as a
                    # complete list of the remaining teams.
                    raise
                profiles.extend(team_profiles)
        if active is not None:
            team_id = str(active.get("team_id") or "")
            connection_id = str(active.get("connection_id") or "")
            after_server_id: str | None = None
            seen_cursors: set[str] = set()
            realm = {
                "realm": "secure_peer",
                "connection_id": connection_id,
                "team_id": team_id,
                "hub_id": str(active.get("hub_id") or ""),
                "host_server_identity": str(
                    active.get("host_server_identity") or ""
                ),
                "certificate_fingerprint": str(
                    active.get("certificate_fingerprint") or ""
                ),
            }
            for _page in range(maximum_pages):
                query = "limit=100"
                if after_server_id is not None:
                    query += "&after_server_id=" + quote(
                        after_server_id,
                        safe="",
                    )
                response = self.proxy(
                    connection_id,
                    "GET",
                    f"/v1/teams/{quote(team_id, safe='')}/network",
                    query=query,
                    headers={"accept": "application/json"},
                    body=None,
                )
                projection = self._decoded_proxy_json(response)
                profiles.extend(self._agent_mail_destinations(
                    projection,
                    realm=realm,
                    current_server_identity=self.server_identity,
                ))
                if len(profiles) > maximum_destinations:
                    raise SecurePeerError(
                        "team_mail_unavailable",
                        "Team Network mail destination limit was exceeded",
                        409,
                    )
                if projection.get("has_more") is not True:
                    break
                cursor = str(projection.get("next_after_server_id") or "")
                if not cursor or cursor in seen_cursors:
                    raise SecurePeerError(
                        "team_mail_unavailable",
                        "Team Network mail pagination changed",
                        409,
                    )
                seen_cursors.add(cursor)
                after_server_id = cursor
            else:
                raise SecurePeerError(
                    "team_mail_unavailable",
                    "Team Network mail page limit was exceeded",
                    409,
                )
        return profiles

    def send_agent_mail(
        self,
        profile: Mapping[str, Any],
        *,
        kind: str,
        message: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Send through one exact, freshly revalidated destination profile."""

        if kind not in {"message", "request"}:
            raise SecurePeerError("invalid_request", "Mail kind is invalid", 422)
        team_id = str(profile.get("team_id") or "")
        target_kind = str(profile.get("destination_kind") or "")
        target_id = str(profile.get("destination_id") or "")
        if target_kind != "server" or not target_id or not team_id:
            raise SecurePeerError(
                "team_mail_route_changed",
                "Team Network mail route is no longer available",
                409,
            )
        request_body = {
            "to": {"kind": target_kind, "id": target_id},
            "from_agent_id": None,
            "body": message,
            "body_format": "markdown",
            "idempotency_key": idempotency_key,
        }
        if kind == "request":
            request_body["expires_in_seconds"] = 86_400

        if profile.get("realm") == "host":
            with self._guard:
                store = self._hub_store
            if (
                store is None
                or store.hub_id != profile.get("hub_id")
                or self.server_identity != profile.get("server_identity")
            ):
                raise SecurePeerError(
                    "team_mail_route_changed",
                    "Team Network mail route is no longer available",
                    409,
                )
            claims = store.local_agent_mail_claims(team_id)
            if kind == "request":
                result = store.create_network_request(claims, team_id, request_body)
            else:
                result = store.create_network_mailbox_item(
                    claims, team_id, request_body
                )
            return self._validated_agent_mail_receipt(
                result,
                kind=kind,
                target_kind=target_kind,
                target_id=target_id,
                message=message,
            )

        if profile.get("realm") != "secure_peer":
            raise SecurePeerError(
                "team_mail_route_changed",
                "Team Network mail route is no longer available",
                409,
            )
        connection_id = str(profile.get("connection_id") or "")
        with self._guard:
            active = next(
                (
                    dict(item)
                    for item in self.client.list_connections()
                    if item.get("active")
                    and item.get("status") == "connected"
                    and item.get("connection_id") == connection_id
                ),
                None,
            )
        if (
            active is None
            or active.get("team_id") != team_id
            or active.get("hub_id") != profile.get("hub_id")
            or active.get("host_server_identity")
            != profile.get("host_server_identity")
            or active.get("certificate_fingerprint")
            != profile.get("certificate_fingerprint")
            or "teamspace.write" not in set(active.get("scopes") or [])
        ):
            raise SecurePeerError(
                "team_mail_route_changed",
                "Team Network mail route is no longer available",
                409,
            )
        response = self.proxy(
            connection_id,
            "POST",
            (
                f"/v1/teams/{quote(team_id, safe='')}/network/"
                + ("requests" if kind == "request" else "mailbox")
            ),
            query="",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
            },
            body=json.dumps(
                request_body,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        return self._validated_agent_mail_receipt(
            self._decoded_proxy_json(response),
            kind=kind,
            target_kind=target_kind,
            target_id=target_id,
            message=message,
        )

    # ------------------------------------------------------------------
    # Team Messages V2: the local server acts as its own node on the Hub.
    # Host realm talks to the in-process HubStore with process-local claims;
    # peer realm goes through the pinned mTLS connection and attachment-only
    # binary lane.

    @staticmethod
    def _team_attachment_path(team_id: str, attachment_id: str) -> str:
        return (
            f"/v1/teams/{quote(team_id, safe='')}/network/attachments/"
            f"{quote(attachment_id, safe='')}/content"
        )

    @staticmethod
    def _validate_team_attachment_metadata(
        value: Any, *, team_id: str, attachment_id: str
    ) -> dict[str, Any]:
        attachment = value.get("attachment") if isinstance(value, Mapping) else None
        if not isinstance(attachment, Mapping):
            raise SecurePeerError(
                "remote_invalid", "Team Hub returned invalid attachment metadata", 502
            )
        file_name = attachment.get("file_name")
        media_type = attachment.get("media_type")
        sha256 = attachment.get("sha256")
        size = attachment.get("byte_size")
        if (
            str(attachment.get("id") or "") != attachment_id
            or str(attachment.get("team_id") or team_id) != team_id
            or attachment.get("state") != "ready"
            or not isinstance(file_name, str)
            or TEAM_ATTACHMENT_FILE_NAME_RE.fullmatch(file_name) is None
            or file_name.strip() != file_name
            or file_name in {".", ".."}
            or not isinstance(media_type, str)
            or not 3 <= len(media_type) <= 160
            or not isinstance(sha256, str)
            or _TEAM_CACHE_SHA256_RE.fullmatch(sha256) is None
            or type(size) is not int
            or not 1 <= size <= MAX_ATTACHMENT_PROTOCOL_BYTES
        ):
            raise SecurePeerError(
                "remote_invalid", "Team Hub returned invalid attachment metadata", 502
            )
        return dict(attachment)

    def _active_team_connection(
        self, connection_id: str, team_id: str
    ) -> dict[str, Any]:
        active = next(
            (
                dict(item)
                for item in self.client.list_connections()
                if item.get("active")
                and item.get("status") == "connected"
                and item.get("connection_id") == connection_id
            ),
            None,
        )
        if active is None or active.get("team_id") != team_id:
            raise SecurePeerError(
                "connection_unavailable", "Secure peer connection is unavailable", 404
            )
        return active

    def _team_attachment_metadata(
        self, connection_id: str, team_id: str, attachment_id: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        active = self._active_team_connection(connection_id, team_id)
        response = self.proxy(
            connection_id,
            "GET",
            f"/v1/teams/{quote(team_id, safe='')}/network/attachments/"
            f"{quote(attachment_id, safe='')}",
            query="",
            headers={"accept": "application/json"},
            body=None,
        )
        if int(response.status) >= 400:
            raise SecurePeerError(
                "attachment_unavailable", "Team attachment is unavailable", response.status
            )
        try:
            value = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecurePeerError(
                "remote_invalid", "Team Hub returned invalid attachment metadata", 502
            ) from exc
        return active, self._validate_team_attachment_metadata(
            value, team_id=team_id, attachment_id=attachment_id
        )

    def proxy_team_attachment_chunk(
        self,
        connection_id: str,
        team_id: str,
        attachment_id: str,
        *,
        content_range: str,
        body: bytes,
    ):
        """Forward one content chunk, preserving active-connection retirement."""

        with self._outbound_guard:
            active = self._active_team_connection(connection_id, team_id)
            try:
                return self.client.upload_attachment_chunk(
                    connection_id,
                    self._team_attachment_path(team_id, attachment_id),
                    content_range=content_range,
                    body=body,
                )
            except SecurePeerError as exc:
                if (
                    self._is_unconfirmed_peer_revocation(exc)
                    and self._remote_revocation_confirmed(connection_id) is True
                ):
                    with suppress(Exception):
                        self._retire_remote_revoked_active_connection(active, {})
                raise

    def proxy_team_attachment_head(
        self, connection_id: str, team_id: str, attachment_id: str
    ):
        """Forward an attachment HEAD while enforcing the exact active route."""

        with self._outbound_guard:
            active = self._active_team_connection(connection_id, team_id)
            try:
                return self.client.head_attachment(
                    connection_id,
                    self._team_attachment_path(team_id, attachment_id),
                )
            except SecurePeerError as exc:
                if (
                    self._is_unconfirmed_peer_revocation(exc)
                    and self._remote_revocation_confirmed(connection_id) is True
                ):
                    with suppress(Exception):
                        self._retire_remote_revoked_active_connection(active, {})
                raise

    @staticmethod
    def _team_file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _team_cache_payload_name(file_name: str) -> str:
        """Keep ordinary names readable and bound oversized UTF-8 basenames."""

        if len(os.fsencode(file_name)) <= 240:
            return file_name
        digest = hashlib.sha256(file_name.encode("utf-8")).hexdigest()[:32]
        suffix = Path(file_name).suffix
        if (
            len(suffix.encode("utf-8")) > 32
            or re.fullmatch(r"\.[A-Za-z0-9._+-]{1,31}", suffix) is None
        ):
            suffix = ""
        return f"attachment-{digest}{suffix}"

    def _team_cache_paths(
        self,
        active: Mapping[str, Any],
        team_id: str,
        attachment_id: str,
        file_name: str,
    ) -> tuple[Path, Path]:
        with self._team_cache_guard:
            return self._team_cache_paths_locked(
                active, team_id, attachment_id, file_name
            )

    def _team_cache_paths_locked(
        self,
        active: Mapping[str, Any],
        team_id: str,
        attachment_id: str,
        file_name: str,
    ) -> tuple[Path, Path]:
        hub_id = str(active.get("hub_id") or "")
        for value in (hub_id, team_id, attachment_id):
            if _TEAM_CACHE_SEGMENT_RE.fullmatch(value) is None:
                raise SecurePeerError(
                    "remote_invalid", "Team attachment identity is invalid", 502
                )
        if TEAM_ATTACHMENT_FILE_NAME_RE.fullmatch(file_name) is None:
            raise SecurePeerError(
                "remote_invalid", "Team attachment file name is invalid", 502
            )
        directory = self.team_cache_dir
        # Validate each owner-only component instead of allowing mkdir's
        # parents walk to silently traverse a stale/symlinked cache segment.
        ensure_private_directory(directory)
        for component in (hub_id, team_id, attachment_id):
            directory = directory / component
            ensure_private_directory(directory)
        payload_directory = directory / "payload"
        ensure_private_directory(payload_directory)
        target = payload_directory / self._team_cache_payload_name(file_name)
        return target, directory / _TEAM_CACHE_META_NAME

    @staticmethod
    def _team_cache_read_sidecar(path: Path) -> dict[str, Any] | None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except (FileNotFoundError, OSError):
            return None
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_size < 2
                or info.st_size > _TEAM_CACHE_META_MAX_BYTES
            ):
                return None
            raw = os.read(descriptor, _TEAM_CACHE_META_MAX_BYTES + 1)
            if len(raw) != info.st_size:
                return None
        finally:
            os.close(descriptor)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def _team_cache_write_sidecar_at(
        parent_descriptor: int,
        name: str,
        value: Mapping[str, Any],
    ) -> None:
        encoded = canonical_json(dict(value))
        if not 2 <= len(encoded) <= _TEAM_CACHE_META_MAX_BYTES:
            raise SecurePeerError(
                "cache_unavailable", "Team attachment cache metadata is invalid", 503
            )
        temporary = f".metadata.{uuid.uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            temporary, flags, 0o600, dir_fd=parent_descriptor
        )
        try:
            try:
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("Team attachment cache sidecar write stalled")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(
                temporary,
                name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.fsync(parent_descriptor)
        except BaseException:
            with suppress(OSError):
                os.unlink(temporary, dir_fd=parent_descriptor)
            raise

    @staticmethod
    def _team_cache_stat_identity(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_uid,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    @staticmethod
    def _team_directory_identity(info: os.stat_result) -> tuple[int, int]:
        """Directory identity fields that remain stable while children change."""

        return info.st_dev, info.st_ino

    @staticmethod
    def _team_descriptor_sha256(descriptor: int, size: int) -> str:
        digest = hashlib.sha256()
        offset = 0
        while offset < size:
            block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
            if not block:
                raise OSError("Team attachment cache file is truncated")
            digest.update(block)
            offset += len(block)
        if os.pread(descriptor, 1, size):
            raise OSError("Team attachment cache file exceeded metadata")
        return digest.hexdigest()

    def _release_team_cache_descriptor_locked(
        self, target: Path, descriptor: int
    ) -> None:
        with suppress(OSError):
            os.close(descriptor)
        remaining = self._team_cache_pins.get(target, 0) - 1
        if remaining > 0:
            self._team_cache_pins[target] = remaining
        else:
            self._team_cache_pins.pop(target, None)

    def _verified_team_cache_descriptor(
        self, target: Path, sidecar: Path, attachment: Mapping[str, Any]
    ) -> int | None:
        """Hash a pinned inode outside the global lock, then re-CAS its path."""

        descriptor = -1
        with self._team_cache_guard:
            metadata = self._team_cache_read_sidecar(sidecar)
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(target, flags)
                before = os.fstat(descriptor)
                path_before = target.lstat()
                sidecar_before = sidecar.lstat()
            except OSError:
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
                return None
            if (
                metadata is None
                or metadata.get("version") != 1
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or before.st_size != int(attachment["byte_size"])
                or self._team_cache_stat_identity(path_before)
                != self._team_cache_stat_identity(before)
                or not stat.S_ISREG(sidecar_before.st_mode)
                or sidecar_before.st_nlink != 1
                or sidecar_before.st_uid != os.getuid()
                or metadata.get("sha256") != attachment["sha256"]
                or metadata.get("byte_size") != attachment["byte_size"]
                or metadata.get("file_name") != attachment["file_name"]
                or metadata.get("inode") != before.st_ino
                or metadata.get("mtime_ns") != before.st_mtime_ns
            ):
                os.close(descriptor)
                return None
            self._team_cache_pins[target] = self._team_cache_pins.get(target, 0) + 1

        try:
            digest = self._team_descriptor_sha256(descriptor, before.st_size)
        except OSError:
            with self._team_cache_guard:
                self._release_team_cache_descriptor_locked(target, descriptor)
            return None

        with self._team_cache_guard:
            try:
                after = os.fstat(descriptor)
                path_after = target.lstat()
                sidecar_after = sidecar.lstat()
            except OSError:
                self._release_team_cache_descriptor_locked(target, descriptor)
                return None
            current_metadata = self._team_cache_read_sidecar(sidecar)
            if (
                digest != attachment["sha256"]
                or self._team_cache_stat_identity(after)
                != self._team_cache_stat_identity(before)
                or self._team_cache_stat_identity(path_after)
                != self._team_cache_stat_identity(after)
                or self._team_cache_stat_identity(sidecar_after)
                != self._team_cache_stat_identity(sidecar_before)
                or current_metadata != metadata
            ):
                self._release_team_cache_descriptor_locked(target, descriptor)
                return None
            with suppress(OSError):
                os.utime(sidecar, None, follow_symlinks=False)
            # The caller owns both this descriptor and the matching cache pin.
            return descriptor

    def _prune_empty_team_cache_directories_locked(self) -> int:
        """Boundedly prune through verified directory descriptors only."""

        root = self.team_cache_dir
        protected_directories: set[Path] = set()
        protected_paths = (
            set(self._team_cache_entry_locks)
            | set(self._team_cache_pins)
            | set(self._team_cache_reservations)
        )
        for protected in protected_paths:
            current = protected.parent
            while current != root and root in current.parents:
                protected_directories.add(current)
                current = current.parent

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            root_descriptor = os.open(root, flags)
            root_info = os.fstat(root_descriptor)
        except OSError:
            return 0
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid()
        ):
            os.close(root_descriptor)
            return 0

        # Cache layout depth is root/hub/team/attachment/payload. Every child
        # is opened relative to its already-verified parent, never by a path
        # that can be redirected through a swapped symlink. rmdir(2) does not
        # follow a final symlink and is attempted only after the name still
        # matches the open child descriptor.
        examined = 0
        removed = 0

        def prune(
            directory_descriptor: int,
            logical_directory: Path,
            depth: int,
        ) -> None:
            nonlocal examined, removed
            try:
                entries = os.scandir(directory_descriptor)
            except OSError:
                return
            with entries:
                for entry in entries:
                    if examined >= _TEAM_CACHE_DIRECTORY_SCAN_LIMIT:
                        return
                    examined += 1
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if (
                        depth >= 4
                        or not stat.S_ISDIR(info.st_mode)
                        or info.st_uid != os.getuid()
                        or info.st_dev != root_info.st_dev
                    ):
                        continue
                    try:
                        child_descriptor = os.open(
                            entry.name, flags, dir_fd=directory_descriptor
                        )
                        opened = os.fstat(child_descriptor)
                    except OSError:
                        continue
                    try:
                        if (
                            self._team_directory_identity(opened)
                            != self._team_directory_identity(info)
                            or opened.st_dev != root_info.st_dev
                            or opened.st_uid != os.getuid()
                        ):
                            continue
                        child = logical_directory / entry.name
                        prune(child_descriptor, child, depth + 1)
                        if child in protected_directories:
                            continue
                        try:
                            opened_after = os.fstat(child_descriptor)
                            named_after = os.stat(
                                entry.name,
                                dir_fd=directory_descriptor,
                                follow_symlinks=False,
                            )
                        except OSError:
                            continue
                        if (
                            self._team_directory_identity(opened_after)
                            != self._team_directory_identity(named_after)
                            or not stat.S_ISDIR(named_after.st_mode)
                            or named_after.st_uid != os.getuid()
                            or named_after.st_dev != root_info.st_dev
                        ):
                            continue
                        try:
                            os.rmdir(entry.name, dir_fd=directory_descriptor)
                        except OSError:
                            pass
                        else:
                            removed += 1
                    finally:
                        os.close(child_descriptor)

        try:
            prune(root_descriptor, root, 0)
        finally:
            os.close(root_descriptor)
        return removed

    def _bounded_team_cache_regular_files_locked(
        self,
    ) -> tuple[dict[Path, os.stat_result], str]:
        """Scan the fixed cache shape without symlink following or fanout."""

        root = self.team_cache_dir
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            root_descriptor = os.open(root, flags)
            root_info = os.fstat(root_descriptor)
        except FileNotFoundError:
            return {}, "complete"
        except OSError:
            return {}, "unsafe"
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid()
        ):
            os.close(root_descriptor)
            return {}, "unsafe"

        regular: dict[Path, os.stat_result] = {}
        examined = 0
        overflow = False
        unsafe = False

        def scan(
            directory_descriptor: int,
            logical_directory: Path,
            depth: int,
        ) -> None:
            nonlocal examined, overflow, unsafe
            try:
                entries = os.scandir(directory_descriptor)
            except OSError:
                unsafe = True
                return
            with entries:
                for entry in entries:
                    if examined >= _TEAM_CACHE_DIRECTORY_SCAN_LIMIT:
                        overflow = True
                        return
                    examined += 1
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        unsafe = True
                        continue
                    candidate = logical_directory / entry.name
                    if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid():
                        if info.st_nlink != 1:
                            unsafe = True
                        else:
                            regular[candidate] = info
                        continue
                    if not stat.S_ISDIR(info.st_mode):
                        continue
                    if (
                        depth >= 4
                        or info.st_uid != os.getuid()
                        or info.st_dev != root_info.st_dev
                    ):
                        unsafe = True
                        continue
                    try:
                        child_descriptor = os.open(
                            entry.name, flags, dir_fd=directory_descriptor
                        )
                        opened = os.fstat(child_descriptor)
                    except OSError:
                        unsafe = True
                        continue
                    try:
                        if (
                            self._team_directory_identity(opened)
                            != self._team_directory_identity(info)
                            or opened.st_dev != root_info.st_dev
                            or opened.st_uid != os.getuid()
                        ):
                            unsafe = True
                            continue
                        scan(child_descriptor, candidate, depth + 1)
                    finally:
                        os.close(child_descriptor)

        try:
            scan(root_descriptor, root, 0)
        finally:
            os.close(root_descriptor)
        return regular, (
            "unsafe" if unsafe else "overflow" if overflow else "complete"
        )

    def _open_team_cache_parent_descriptor_locked(
        self, candidate: Path
    ) -> tuple[int, str]:
        """Open a scanned cache file's parent through pinned no-follow fds."""

        try:
            parts = candidate.relative_to(self.team_cache_dir).parts
        except ValueError as exc:
            raise OSError("cache path escaped root") from exc
        if not parts or len(parts) > 5 or any(
            not part or part in {".", ".."} for part in parts
        ):
            raise OSError("cache path shape is invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.team_cache_dir, flags)
        root_info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid()
        ):
            os.close(descriptor)
            raise OSError("cache root is unsafe")
        try:
            for component in parts[:-1]:
                child = os.open(component, flags, dir_fd=descriptor)
                child_info = os.fstat(child)
                if (
                    not stat.S_ISDIR(child_info.st_mode)
                    or child_info.st_uid != os.getuid()
                    or child_info.st_dev != root_info.st_dev
                ):
                    os.close(child)
                    raise OSError("cache ancestor is unsafe")
                os.close(descriptor)
                descriptor = child
            return descriptor, parts[-1]
        except BaseException:
            os.close(descriptor)
            raise

    def _team_cache_read_scanned_sidecar_locked(
        self, candidate: Path, expected: os.stat_result
    ) -> dict[str, Any] | None:
        try:
            parent_descriptor, name = (
                self._open_team_cache_parent_descriptor_locked(candidate)
            )
        except OSError:
            return None
        descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            info = os.fstat(descriptor)
            if (
                self._team_cache_stat_identity(info)
                != self._team_cache_stat_identity(expected)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or not 2 <= info.st_size <= _TEAM_CACHE_META_MAX_BYTES
            ):
                return None
            raw = bytearray()
            while len(raw) < info.st_size:
                block = os.read(descriptor, info.st_size - len(raw))
                if not block:
                    return None
                raw.extend(block)
            if os.read(descriptor, 1):
                return None
            try:
                value = json.loads(bytes(raw))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None
            return value if isinstance(value, dict) else None
        except OSError:
            return None
        finally:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            os.close(parent_descriptor)

    def _unlink_scanned_team_cache_file_locked(
        self, candidate: Path, expected: os.stat_result
    ) -> bool:
        try:
            parent_descriptor, name = (
                self._open_team_cache_parent_descriptor_locked(candidate)
            )
        except OSError:
            return False
        try:
            current = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                self._team_cache_stat_identity(current)
                != self._team_cache_stat_identity(expected)
                or not stat.S_ISREG(current.st_mode)
                or current.st_uid != os.getuid()
            ):
                return False
            os.unlink(name, dir_fd=parent_descriptor)
            return True
        except OSError:
            return False
        finally:
            os.close(parent_descriptor)

    def _evict_team_cache(
        self,
        *,
        protected: Path | None = None,
        reserve_bytes: int = 0,
        prune_empty: bool = True,
    ) -> None:
        if (
            type(reserve_bytes) is not int
            or reserve_bytes < 0
            or reserve_bytes > self.team_cache_max_bytes
        ):
            raise SecurePeerError(
                "attachment_limit", "Attachment exceeds the local cache limit", 413
            )
        active_staging = set(self._team_cache_reservations)
        reserved_bytes = sum(self._team_cache_reservations.values()) + reserve_bytes
        if reserved_bytes > self.team_cache_max_bytes:
            raise SecurePeerError(
                "cache_unavailable", "Team attachment cache cannot free enough space", 507
            )
        live_targets = set(self._team_cache_entry_locks) | {
            path for path, count in self._team_cache_pins.items() if count > 0
        }
        if protected is not None:
            live_targets.add(protected)
        protected_entry_directories = {
            path.parent.parent for path in live_targets
        } | {path.parent for path in self._team_cache_reservations}
        recovery_passes = 0
        while True:
            regular, scan_status = (
                self._bounded_team_cache_regular_files_locked()
            )
            progress = 0
            for candidate, info in tuple(regular.items()):
                if candidate in active_staging:
                    regular.pop(candidate, None)
                    continue
                # No cache operation remains live while this global lock is
                # held; these names can only be crash leftovers. Remove them
                # eagerly so failed downloads cannot accumulate outside LRU.
                try:
                    relative_parts = candidate.relative_to(
                        self.team_cache_dir
                    ).parts
                except ValueError:
                    relative_parts = ()
                if len(relative_parts) == 4 and (
                    candidate.name.startswith(".download.")
                    or (
                        candidate.name.startswith(".metadata.")
                        and candidate.name.endswith(".tmp")
                    )
                ) and self._unlink_scanned_team_cache_file_locked(
                    candidate, info
                ):
                    regular.pop(candidate, None)
                    progress += 1
            if scan_status == "unsafe":
                if prune_empty:
                    self._prune_empty_team_cache_directories_locked()
                raise SecurePeerError(
                    "cache_unavailable",
                    "Team attachment cache contains unsafe entries",
                    507,
                )
            if scan_status == "complete":
                break
            if recovery_passes >= _TEAM_CACHE_OVERFLOW_RECOVERY_PASSES:
                raise SecurePeerError(
                    "cache_unavailable",
                    "Team attachment cache recovery requires another bounded pass",
                    507,
                )
            # A pre-hardening cache can legitimately exceed today's bounded
            # scanner. Evict the verified, inactive portion of this one scan,
            # prune what became empty, and rescan. Work remains capped per
            # request; if more remains, the next request continues recovery.
            for candidate, info in tuple(regular.items()):
                try:
                    parts = candidate.relative_to(self.team_cache_dir).parts
                except ValueError:
                    continue
                entry_directory: Path | None
                if len(parts) == 4:
                    entry_directory = candidate.parent
                elif len(parts) == 5 and parts[-2] == "payload":
                    entry_directory = candidate.parent.parent
                else:
                    entry_directory = None
                if entry_directory in protected_entry_directories:
                    continue
                if self._unlink_scanned_team_cache_file_locked(candidate, info):
                    progress += 1
            progress += self._prune_empty_team_cache_directories_locked()
            if progress == 0:
                raise SecurePeerError(
                    "cache_unavailable",
                    "Team attachment cache overflow could not be recovered safely",
                    507,
                )
            recovery_passes += 1

        entries: list[tuple[int, int, tuple[Path, ...]]] = []
        total = 0

        grouped: set[Path] = set()
        for sidecar, side_info in tuple(regular.items()):
            target: Path | None = None
            if sidecar.name == _TEAM_CACHE_META_NAME:
                metadata = self._team_cache_read_scanned_sidecar_locked(
                    sidecar, side_info
                )
                file_name = metadata.get("file_name") if metadata else None
                if (
                    isinstance(file_name, str)
                    and TEAM_ATTACHMENT_FILE_NAME_RE.fullmatch(file_name) is not None
                    and file_name not in {".", ".."}
                ):
                    target = (
                        sidecar.parent
                        / "payload"
                        / self._team_cache_payload_name(file_name)
                    )
            elif sidecar.name.endswith(".agentsdock-meta"):
                target = sidecar.with_name(
                    sidecar.name[: -len(".agentsdock-meta")]
                )
            if target is None or target not in regular:
                if sidecar.name == _TEAM_CACHE_META_NAME or sidecar.name.endswith(
                    ".agentsdock-meta"
                ):
                    if self._unlink_scanned_team_cache_file_locked(
                        sidecar, side_info
                    ):
                        grouped.add(sidecar)
                continue
            target_info = regular[target]
            entry_size = target_info.st_size + side_info.st_size
            total += entry_size
            entries.append(
                (
                    side_info.st_mtime_ns,
                    entry_size,
                    (target, sidecar),
                )
            )
            grouped.update((target, sidecar))

        # Corrupt/missing-sidecar payloads and undeletable staging files still
        # consume the bound and are eligible for oldest-first cleanup.
        for candidate, info in regular.items():
            if candidate in grouped:
                continue
            total += info.st_size
            entries.append((info.st_mtime_ns, info.st_size, (candidate,)))

        for _used, size, paths in sorted(entries, key=lambda item: item[0]):
            if total + reserved_bytes <= self.team_cache_max_bytes:
                break
            if (
                protected is not None
                and protected in paths
                or any(self._team_cache_pins.get(path, 0) > 0 for path in paths)
            ):
                continue
            freed = 0
            for candidate in paths:
                info = regular.get(candidate)
                if (
                    info is not None
                    and self._unlink_scanned_team_cache_file_locked(
                        candidate, info
                    )
                ):
                    freed += info.st_size
            total -= freed
        if prune_empty:
            self._prune_empty_team_cache_directories_locked()
        if total + reserved_bytes > self.team_cache_max_bytes:
            raise SecurePeerError(
                "cache_unavailable", "Team attachment cache cannot free enough space", 507
            )

    def _reference_team_cache_entry_lock_locked(
        self, target: Path
    ) -> threading.Lock:
        entry = self._team_cache_entry_locks.get(target)
        if entry is None:
            lock = threading.Lock()
            references = 0
        else:
            lock, references = entry
        self._team_cache_entry_locks[target] = (lock, references + 1)
        return lock

    def _release_team_cache_entry_lock(
        self, target: Path, lock: threading.Lock
    ) -> None:
        lock.release()
        with self._team_cache_guard:
            current = self._team_cache_entry_locks.get(target)
            if current is None or current[0] is not lock:
                raise RuntimeError("Team attachment cache lock identity changed")
            remaining = current[1] - 1
            if remaining:
                self._team_cache_entry_locks[target] = (lock, remaining)
            else:
                self._team_cache_entry_locks.pop(target, None)
                self._prune_empty_team_cache_directories_locked()

    def _pin_team_cache_entry_locked(
        self,
        target: Path,
        sidecar: Path,
        attachment: Mapping[str, Any],
    ) -> AttachmentFileLease:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(target, flags)
            info = os.fstat(descriptor)
            metadata = self._team_cache_read_sidecar(sidecar)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_size != int(attachment["byte_size"])
                or metadata is None
                or metadata.get("inode") != info.st_ino
                or metadata.get("mtime_ns") != info.st_mtime_ns
                or metadata.get("sha256") != attachment["sha256"]
            ):
                raise OSError("Team attachment cache inode changed")
        except (OSError, ValueError) as exc:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            raise SecurePeerError(
                "cache_unavailable", "Team attachment cache is unavailable", 503
            ) from exc
        self._team_cache_pins[target] = self._team_cache_pins.get(target, 0) + 1
        return self._team_cache_lease_for_pinned_descriptor_locked(
            target, descriptor
        )

    def _team_cache_lease_for_pinned_descriptor_locked(
        self, target: Path, descriptor: int
    ) -> AttachmentFileLease:
        """Transfer one already-counted cache pin into a closeable lease."""

        finalizer_lock = threading.Lock()
        finalized = False

        def finalize() -> None:
            nonlocal finalized
            with finalizer_lock:
                if finalized:
                    return
                finalized = True
            with self._team_cache_guard:
                self._release_team_cache_descriptor_locked(target, descriptor)

        return AttachmentFileLease(descriptor, finalize)

    def _materialize_team_cache_entry(
        self,
        *,
        active: Mapping[str, Any],
        attachment: Mapping[str, Any],
        team_id: str,
        attachment_id: str,
        download: Callable[[Path], tuple[tuple[str, str], ...]],
        connection_id: str | None,
        pin: bool,
    ) -> Path | AttachmentFileLease:
        """Materialize one entry without global locks across transfer or hash."""

        required_cache_bytes = (
            int(attachment["byte_size"]) + _TEAM_CACHE_META_MAX_BYTES
        )
        if required_cache_bytes > self.team_cache_max_bytes:
            raise SecurePeerError(
                "attachment_limit", "Attachment exceeds the local cache limit", 413
            )
        # Directory creation and active-entry registration are one global-lock
        # operation, so bounded empty-directory pruning cannot remove a newly
        # created payload directory before its download reservation exists.
        with self._team_cache_guard:
            target, sidecar = self._team_cache_paths_locked(
                active,
                team_id,
                attachment_id,
                str(attachment["file_name"]),
            )
            entry_lock = self._reference_team_cache_entry_lock_locked(target)
        entry_lock.acquire()
        temporary: Path | None = None
        staging_parent_descriptor = -1
        target_parent_descriptor = -1
        staging_name = ""
        target_name = target.name
        staging_descriptor = -1
        staging_before: os.stat_result | None = None
        staging_digest: str | None = None
        replaced = False
        try:
            verified_descriptor = self._verified_team_cache_descriptor(
                target, sidecar, attachment
            )
            if verified_descriptor is not None:
                with self._team_cache_guard:
                    try:
                        self._evict_team_cache(protected=target)
                    except BaseException:
                        self._release_team_cache_descriptor_locked(
                            target, verified_descriptor
                        )
                        raise
                    if pin:
                        return self._team_cache_lease_for_pinned_descriptor_locked(
                            target, verified_descriptor
                        )
                    self._release_team_cache_descriptor_locked(
                        target, verified_descriptor
                    )
                    return target
            with self._team_cache_guard:
                if self._team_cache_pins.get(target, 0) > 0:
                    raise SecurePeerError(
                        "cache_unavailable",
                        "Team attachment cache entry is currently in use",
                        503,
                    )
                temporary = sidecar.parent / f".download.{uuid.uuid4().hex}"
                self._evict_team_cache(
                    reserve_bytes=required_cache_bytes,
                    prune_empty=False,
                )
                self._team_cache_reservations[temporary] = required_cache_bytes
                staging_parent_descriptor, staging_name = (
                    self._open_team_cache_parent_descriptor_locked(temporary)
                )
                directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(
                    os, "O_NOFOLLOW", 0
                )
                target_parent_descriptor = os.open(
                    "payload",
                    directory_flags,
                    dir_fd=staging_parent_descriptor,
                )
                target_parent_info = os.fstat(target_parent_descriptor)
                staging_parent_info = os.fstat(staging_parent_descriptor)
                if (
                    not stat.S_ISDIR(target_parent_info.st_mode)
                    or target_parent_info.st_uid != os.getuid()
                    or target_parent_info.st_dev != staging_parent_info.st_dev
                ):
                    raise SecurePeerError(
                        "cache_unavailable",
                        "Team attachment cache hierarchy is unsafe",
                        503,
                    )

            response_headers = download(temporary)
            header_map = dict(response_headers)
            if (
                header_map.get("etag") != f'"{attachment["sha256"]}"'
                or header_map.get("content-type") != attachment["media_type"]
                or header_map.get("accept-ranges") != "bytes"
            ):
                raise SecurePeerError(
                    "attachment_hash_mismatch",
                    "Downloaded attachment failed integrity verification",
                    502,
                )
            try:
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                staging_descriptor = os.open(
                    staging_name,
                    flags,
                    dir_fd=staging_parent_descriptor,
                )
                os.fchmod(staging_descriptor, 0o600)
                staging_before = os.fstat(staging_descriptor)
                staging_path_before = os.stat(
                    staging_name,
                    dir_fd=staging_parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(staging_before.st_mode)
                    or staging_before.st_nlink != 1
                    or staging_before.st_uid != os.getuid()
                    or staging_before.st_size != int(attachment["byte_size"])
                    or self._team_cache_stat_identity(staging_path_before)
                    != self._team_cache_stat_identity(staging_before)
                ):
                    raise OSError("Team attachment staging inode is invalid")
                # Hash the pinned staging inode without holding the cache-wide
                # lock. Publication below CASes both the descriptor and name.
                staging_digest = self._team_descriptor_sha256(
                    staging_descriptor, staging_before.st_size
                )
            except OSError as exc:
                raise SecurePeerError(
                    "attachment_hash_mismatch",
                    "Downloaded attachment failed integrity verification",
                    502,
                ) from exc

            def publish_locked() -> Path | AttachmentFileLease:
                nonlocal replaced, staging_descriptor
                assert temporary is not None
                assert staging_before is not None
                assert staging_digest is not None
                staging_after = os.fstat(staging_descriptor)
                staging_path_after = os.stat(
                    staging_name,
                    dir_fd=staging_parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    staging_digest != attachment["sha256"]
                    or self._team_cache_stat_identity(staging_after)
                    != self._team_cache_stat_identity(staging_before)
                    or self._team_cache_stat_identity(staging_path_after)
                    != self._team_cache_stat_identity(staging_after)
                ):
                    raise SecurePeerError(
                        "attachment_hash_mismatch",
                        "Downloaded attachment changed before cache publication",
                        502,
                    )
                os.replace(
                    staging_name,
                    target_name,
                    src_dir_fd=staging_parent_descriptor,
                    dst_dir_fd=target_parent_descriptor,
                )
                replaced = True
                info = os.stat(
                    target_name,
                    dir_fd=target_parent_descriptor,
                    follow_symlinks=False,
                )
                descriptor_info = os.fstat(staging_descriptor)
                if (
                    self._team_cache_stat_identity(info)
                    != self._team_cache_stat_identity(descriptor_info)
                ):
                    raise SecurePeerError(
                        "attachment_hash_mismatch",
                        "Downloaded attachment changed during cache publication",
                        502,
                    )
                self._team_cache_write_sidecar_at(
                    staging_parent_descriptor,
                    sidecar.name,
                    {
                        "version": 1,
                        "hub_id": active["hub_id"],
                        "team_id": team_id,
                        "attachment_id": attachment_id,
                        "file_name": attachment["file_name"],
                        "media_type": attachment["media_type"],
                        "byte_size": attachment["byte_size"],
                        "sha256": attachment["sha256"],
                        "inode": info.st_ino,
                        "mtime_ns": info.st_mtime_ns,
                    },
                )
                os.fsync(target_parent_descriptor)
                self._team_cache_reservations.pop(temporary, None)
                self._evict_team_cache(protected=target)
                logical_parent, logical_name = (
                    self._open_team_cache_parent_descriptor_locked(target)
                )
                try:
                    if (
                        logical_name != target_name
                        or os.fstat(logical_parent).st_dev
                        != os.fstat(target_parent_descriptor).st_dev
                        or os.fstat(logical_parent).st_ino
                        != os.fstat(target_parent_descriptor).st_ino
                        or self._team_cache_stat_identity(
                            os.stat(
                                logical_name,
                                dir_fd=logical_parent,
                                follow_symlinks=False,
                            )
                        )
                        != self._team_cache_stat_identity(descriptor_info)
                    ):
                        raise SecurePeerError(
                            "cache_unavailable",
                            "Team attachment cache hierarchy changed",
                            503,
                        )
                finally:
                    os.close(logical_parent)
                if not pin:
                    return target
                self._team_cache_pins[target] = (
                    self._team_cache_pins.get(target, 0) + 1
                )
                lease_descriptor = staging_descriptor
                staging_descriptor = -1
                return self._team_cache_lease_for_pinned_descriptor_locked(
                    target, lease_descriptor
                )

            if connection_id is None:
                with self._team_cache_guard:
                    return publish_locked()
            # Retirement may proceed while bytes stream, but cannot cross this
            # exact active/hub CAS and atomic cache publication boundary.
            with self._outbound_guard:
                current = self._active_team_connection(connection_id, team_id)
                if current.get("hub_id") != active.get("hub_id"):
                    raise SecurePeerError(
                        "connection_changed", "Secure peer connection changed", 409
                    )
                with self._team_cache_guard:
                    return publish_locked()
        except BaseException:
            with self._team_cache_guard:
                if temporary is not None:
                    self._team_cache_reservations.pop(temporary, None)
                    if staging_parent_descriptor >= 0 and staging_name:
                        with suppress(OSError):
                            os.unlink(
                                staging_name,
                                dir_fd=staging_parent_descriptor,
                            )
                if replaced:
                    if target_parent_descriptor >= 0:
                        with suppress(OSError):
                            os.unlink(
                                target_name,
                                dir_fd=target_parent_descriptor,
                            )
                    if staging_parent_descriptor >= 0:
                        with suppress(OSError):
                            os.unlink(
                                sidecar.name,
                                dir_fd=staging_parent_descriptor,
                            )
                self._prune_empty_team_cache_directories_locked()
            raise
        finally:
            if staging_descriptor >= 0:
                with suppress(OSError):
                    os.close(staging_descriptor)
            if target_parent_descriptor >= 0:
                with suppress(OSError):
                    os.close(target_parent_descriptor)
            if staging_parent_descriptor >= 0:
                with suppress(OSError):
                    os.close(staging_parent_descriptor)
            self._release_team_cache_entry_lock(target, entry_lock)

    def cache_team_attachment(
        self, connection_id: str, team_id: str, attachment_id: str
    ) -> tuple[dict[str, Any], Path]:
        """Return a verified local peer-cache path, downloading atomically once."""

        active, attachment = self._team_attachment_metadata(
            connection_id, team_id, attachment_id
        )

        def download(temporary: Path) -> tuple[tuple[str, str], ...]:
            try:
                return self.client.download_attachment_to(
                    connection_id,
                    self._team_attachment_path(team_id, attachment_id),
                    temporary,
                    expected_size=int(attachment["byte_size"]),
                )
            except SecurePeerError as exc:
                if (
                    self._is_unconfirmed_peer_revocation(exc)
                    and self._remote_revocation_confirmed(connection_id) is True
                ):
                    with suppress(Exception):
                        self._retire_remote_revoked_active_connection(active, {})
                raise

        target = self._materialize_team_cache_entry(
            active=active,
            attachment=attachment,
            team_id=team_id,
            attachment_id=attachment_id,
            download=download,
            connection_id=connection_id,
            pin=False,
        )
        assert isinstance(target, Path)
        return dict(attachment), target

    def open_cached_team_attachment(
        self, connection_id: str, team_id: str, attachment_id: str
    ) -> tuple[dict[str, Any], AttachmentFileLease]:
        """Pin a verified cache inode for a complete local HTTP response."""

        active, attachment = self._team_attachment_metadata(
            connection_id, team_id, attachment_id
        )

        def download(temporary: Path) -> tuple[tuple[str, str], ...]:
            try:
                return self.client.download_attachment_to(
                    connection_id,
                    self._team_attachment_path(team_id, attachment_id),
                    temporary,
                    expected_size=int(attachment["byte_size"]),
                )
            except SecurePeerError as exc:
                if (
                    self._is_unconfirmed_peer_revocation(exc)
                    and self._remote_revocation_confirmed(connection_id) is True
                ):
                    with suppress(Exception):
                        self._retire_remote_revoked_active_connection(active, {})
                raise

        lease = self._materialize_team_cache_entry(
            active=active,
            attachment=attachment,
            team_id=team_id,
            attachment_id=attachment_id,
            download=download,
            connection_id=connection_id,
            pin=True,
        )
        assert isinstance(lease, AttachmentFileLease)
        return dict(attachment), lease

    @staticmethod
    def _remove_team_export_directory_fd(
        root_descriptor: int,
        directory_name: str,
        directory_descriptor: int,
    ) -> bool:
        """Remove one verified flat export directory without path traversal."""

        try:
            entries = os.scandir(directory_descriptor)
        except OSError:
            return False
        removable = True
        with entries:
            for entry in entries:
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    removable = False
                    continue
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                ):
                    removable = False
                    continue
                with suppress(OSError):
                    os.unlink(entry.name, dir_fd=directory_descriptor)
                try:
                    os.stat(
                        entry.name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                except OSError:
                    removable = False
                else:
                    removable = False
        if not removable:
            return False
        try:
            opened = os.fstat(directory_descriptor)
            named = os.stat(
                directory_name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            return False
        if (
            opened.st_dev != named.st_dev
            or opened.st_ino != named.st_ino
            or not stat.S_ISDIR(named.st_mode)
            or named.st_uid != os.getuid()
        ):
            return False
        try:
            os.rmdir(directory_name, dir_fd=root_descriptor)
        except OSError:
            return False
        return True

    def _reserve_team_export_locked(self, required_bytes: int) -> tuple[int, int, str, Path]:
        """Clean expired exports and reserve one bounded owner-only batch."""

        if required_bytes > self.team_cache_max_bytes:
            raise SecurePeerError(
                "attachment_limit", "Attachment batch exceeds the export limit", 413
            )
        ensure_private_directory(self.team_export_dir)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            root_descriptor = os.open(self.team_export_dir, flags)
            root_info = os.fstat(root_descriptor)
        except OSError as exc:
            raise SecurePeerError(
                "cache_unavailable", "Team attachment export is unavailable", 503
            ) from exc
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid()
        ):
            os.close(root_descriptor)
            raise SecurePeerError(
                "cache_unavailable", "Team attachment export is unsafe", 503
            )

        timestamp = int(time.time())
        retained_batches = 0
        retained_bytes = 0
        examined = 0
        unsafe = False
        try:
            entries = os.scandir(root_descriptor)
            with entries:
                for entry in entries:
                    examined += 1
                    if examined > _TEAM_CACHE_DIRECTORY_SCAN_LIMIT:
                        unsafe = True
                        break
                    final_match = _TEAM_EXPORT_BATCH_RE.fullmatch(entry.name)
                    temporary_match = _TEAM_EXPORT_TEMP_RE.fullmatch(entry.name)
                    if final_match is None and temporary_match is None:
                        unsafe = True
                        continue
                    try:
                        listed = entry.stat(follow_symlinks=False)
                    except OSError:
                        unsafe = True
                        continue
                    if (
                        not stat.S_ISDIR(listed.st_mode)
                        or listed.st_uid != os.getuid()
                        or listed.st_dev != root_info.st_dev
                    ):
                        unsafe = True
                        continue
                    try:
                        directory_descriptor = os.open(
                            entry.name, flags, dir_fd=root_descriptor
                        )
                        opened = os.fstat(directory_descriptor)
                    except OSError:
                        unsafe = True
                        continue
                    try:
                        if (
                            self._team_directory_identity(opened)
                            != self._team_directory_identity(listed)
                            or opened.st_uid != os.getuid()
                            or opened.st_dev != root_info.st_dev
                        ):
                            unsafe = True
                            continue
                        logical = self.team_export_dir / entry.name
                        is_active = logical in self._team_export_reservations
                        # The reservation already accounts for this batch's
                        # declared bytes and count. Its writer may be adding
                        # children right now, so do not enumerate a live temp
                        # directory or mistake benign directory mutations for
                        # corruption.
                        if temporary_match is not None and is_active:
                            continue
                        batch_bytes = 0
                        batch_safe = True
                        children = os.scandir(directory_descriptor)
                        with children:
                            for child in children:
                                examined += 1
                                if examined > _TEAM_CACHE_DIRECTORY_SCAN_LIMIT:
                                    batch_safe = False
                                    unsafe = True
                                    break
                                try:
                                    child_info = child.stat(follow_symlinks=False)
                                except OSError:
                                    batch_safe = False
                                    continue
                                if (
                                    not stat.S_ISREG(child_info.st_mode)
                                    or child_info.st_uid != os.getuid()
                                    or child_info.st_nlink != 1
                                    or child_info.st_dev != root_info.st_dev
                                ):
                                    batch_safe = False
                                    continue
                                batch_bytes += child_info.st_size
                        expired = bool(
                            final_match is not None
                            and int(final_match.group(1))
                            <= timestamp - _TEAM_EXPORT_TTL_SECONDS
                        )
                        if batch_safe and not is_active and (
                            temporary_match is not None or expired
                        ):
                            if not self._remove_team_export_directory_fd(
                                root_descriptor,
                                entry.name,
                                directory_descriptor,
                            ):
                                unsafe = True
                            continue
                        if temporary_match is not None:
                            if not is_active:
                                unsafe = True
                            continue
                        retained_batches += 1
                        retained_bytes += batch_bytes
                        if not batch_safe:
                            unsafe = True
                    finally:
                        os.close(directory_descriptor)

            reserved_bytes = sum(self._team_export_reservations.values())
            reserved_batches = len(self._team_export_reservations)
            if (
                unsafe
                or retained_batches + reserved_batches + 1
                > _TEAM_EXPORT_MAX_BATCHES
                or retained_bytes + reserved_bytes + required_bytes
                > self.team_cache_max_bytes
            ):
                raise SecurePeerError(
                    "cache_unavailable",
                    "Team attachment export capacity is unavailable",
                    507,
                )
            token = uuid.uuid4().hex
            temporary_name = f".export-{token}.tmp"
            temporary_path = self.team_export_dir / temporary_name
            os.mkdir(temporary_name, 0o700, dir_fd=root_descriptor)
            directory_descriptor = os.open(
                temporary_name, flags, dir_fd=root_descriptor
            )
            self._team_export_reservations[temporary_path] = required_bytes
            return root_descriptor, directory_descriptor, temporary_name, temporary_path
        except BaseException:
            os.close(root_descriptor)
            raise

    def _export_team_attachment_batch(
        self,
        attachments: list[dict[str, Any]],
        leases: list[AttachmentFileLease],
    ) -> list[dict[str, Any]]:
        """Copy verified cache inodes into bounded, one-hour durable exports."""

        if not attachments:
            return []
        if len(attachments) != len(leases):
            raise RuntimeError("Team attachment export lease count changed")
        required_bytes = sum(int(item["byte_size"]) for item in attachments)
        with self._team_cache_guard:
            (
                root_descriptor,
                directory_descriptor,
                temporary_name,
                temporary_path,
            ) = self._reserve_team_export_locked(required_bytes)
        published_name: str | None = None
        output_names: list[str] = []
        try:
            for index, (attachment, lease) in enumerate(zip(attachments, leases)):
                suffix = Path(str(attachment["file_name"])).suffix
                if (
                    len(suffix.encode("utf-8")) > 24
                    or re.fullmatch(r"\.[A-Za-z0-9._+-]{1,23}", suffix) is None
                ):
                    suffix = ""
                name_digest = hashlib.sha256(
                    (
                        str(attachment["id"])
                        + "\0"
                        + str(attachment["file_name"])
                    ).encode("utf-8")
                ).hexdigest()[:24]
                output_name = f"attachment-{index:03d}-{name_digest}{suffix}"
                output_names.append(output_name)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(
                    os, "O_NOFOLLOW", 0
                )
                output = os.open(
                    output_name,
                    flags,
                    0o600,
                    dir_fd=directory_descriptor,
                )
                source_before = os.fstat(lease.descriptor)
                digest = hashlib.sha256()
                offset = 0
                try:
                    expected_size = int(attachment["byte_size"])
                    while offset < expected_size:
                        block = os.pread(
                            lease.descriptor,
                            min(1024 * 1024, expected_size - offset),
                            offset,
                        )
                        if not block:
                            raise OSError("Team attachment cache export was truncated")
                        digest.update(block)
                        view = memoryview(block)
                        while view:
                            written = os.write(output, view)
                            if written <= 0:
                                raise OSError("Team attachment export write stalled")
                            view = view[written:]
                        offset += len(block)
                    if os.pread(lease.descriptor, 1, expected_size):
                        raise OSError("Team attachment cache export exceeded metadata")
                    os.fsync(output)
                finally:
                    os.close(output)
                source_after = os.fstat(lease.descriptor)
                if (
                    self._team_cache_stat_identity(source_before)
                    != self._team_cache_stat_identity(source_after)
                    or source_after.st_size != int(attachment["byte_size"])
                    or digest.hexdigest() != attachment["sha256"]
                ):
                    raise SecurePeerError(
                        "attachment_hash_mismatch",
                        "Team attachment changed during durable export",
                        502,
                    )
            os.fsync(directory_descriptor)
            timestamp = int(time.time())
            final_name = f"export-{timestamp:010d}-{uuid.uuid4().hex}"
            with self._team_cache_guard:
                root_opened = os.fstat(root_descriptor)
                root_named = self.team_export_dir.lstat()
                opened = os.fstat(directory_descriptor)
                named = os.stat(
                    temporary_name,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
                if (
                    self._team_directory_identity(root_opened)
                    != self._team_directory_identity(root_named)
                    or not stat.S_ISDIR(root_named.st_mode)
                    or root_named.st_uid != os.getuid()
                    or self._team_directory_identity(opened)
                    != self._team_directory_identity(named)
                    or not stat.S_ISDIR(named.st_mode)
                    or named.st_uid != os.getuid()
                ):
                    raise SecurePeerError(
                        "cache_unavailable", "Team attachment export changed", 503
                    )
                os.rename(
                    temporary_name,
                    final_name,
                    src_dir_fd=root_descriptor,
                    dst_dir_fd=root_descriptor,
                )
                published_name = final_name
                self._team_export_reservations.pop(temporary_path, None)
                os.fsync(root_descriptor)
            return [
                {
                    **attachment,
                    "local_path": str(
                        self.team_export_dir / final_name / output_name
                    ),
                }
                for attachment, output_name in zip(attachments, output_names)
            ]
        except BaseException:
            with self._team_cache_guard:
                self._team_export_reservations.pop(temporary_path, None)
                self._remove_team_export_directory_fd(
                    root_descriptor,
                    published_name or temporary_name,
                    directory_descriptor,
                )
            raise
        finally:
            os.close(directory_descriptor)
            os.close(root_descriptor)

    def team_realms(self) -> list[dict[str, Any]]:
        """Every team this server can act in, in deterministic order."""

        realms: list[dict[str, Any]] = []
        with self._guard:
            host_store = self._hub_store
            active = next(
                (
                    dict(item)
                    for item in self.client.list_connections()
                    if item.get("active")
                    and item.get("status") == "connected"
                    and "teamspace.read" in set(item.get("scopes") or [])
                ),
                None,
            )
        if host_store is not None:
            for team_id in host_store.local_agent_mail_team_ids():
                realms.append({
                    "realm": "host",
                    "team_id": team_id,
                    "hub_id": host_store.hub_id,
                    "server_identity": self.server_identity,
                    "can_write": True,
                })
        if active is not None:
            realms.append({
                "realm": "secure_peer",
                "connection_id": str(active.get("connection_id") or ""),
                "team_id": str(active.get("team_id") or ""),
                "hub_id": str(active.get("hub_id") or ""),
                "host_server_identity": str(active.get("host_server_identity") or ""),
                "certificate_fingerprint": str(active.get("certificate_fingerprint") or ""),
                "can_write": "teamspace.write" in set(active.get("scopes") or []),
            })
        return realms

    def team_realm(self, team_id: str | None = None) -> dict[str, Any]:
        realms = self.team_realms()
        if not realms:
            raise SecurePeerError(
                "team_unavailable", "This server is not connected to a Team Network", 409
            )
        if team_id:
            for realm in realms:
                if realm["team_id"] == team_id:
                    return realm
            raise SecurePeerError("team_unavailable", "Unknown team for this server", 404)
        if len(realms) > 1:
            raise SecurePeerError(
                "team_ambiguous",
                "This server belongs to several teams; pass --team "
                + ", ".join(realm["team_id"] for realm in realms),
                409,
            )
        return realms[0]

    def resolve_team_references(
        self,
        references: list[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Resolve frozen ``@@`` grants against the current Hub projection.

        A structured client record is not authority by itself: the opaque ID,
        visible label, team, recipient kind, and (for skills) slug must still
        describe the same live Hub object when provider authority is minted.
        Results may carry private routing metadata but are never returned to
        the desktop or written into the provider authority file.
        """

        accessible_realms: dict[str, dict[str, Any]] = {}
        for item in self.team_realms():
            team_id = str(item.get("team_id") or "")
            if team_id:
                accessible_realms.setdefault(team_id, dict(item))
        if not accessible_realms:
            raise SecurePeerError(
                "team_unavailable",
                "This server is not connected to a Team Network",
                409,
            )
        realms: dict[str, dict[str, Any]] = {}
        server_targets: dict[tuple[str, str], dict[str, Any] | None] = {}
        member_targets: dict[tuple[str, str], dict[str, Any] | None] = {}
        skills: dict[str, dict[str, dict[str, Any]]] = {}

        def realm_for(team_id: str) -> dict[str, Any]:
            if team_id not in realms:
                realm = accessible_realms.get(team_id)
                if realm is None:
                    # A disconnected peer can recover without editing the
                    # visible mention; keep this a transient availability
                    # failure rather than classifying it as a stale target.
                    raise SecurePeerError(
                        "team_unavailable", "Unknown team for this server", 409
                    )
                realms[team_id] = realm
            return realms[team_id]

        def network_server(team_id: str, server_id: str) -> dict[str, Any] | None:
            cache_key = (team_id, server_id)
            if cache_key in server_targets:
                return server_targets[cache_key]
            realm = realm_for(team_id)
            try:
                if realm["realm"] == "host":
                    with self._guard:
                        store = self._hub_store
                    if store is None or store.hub_id != realm.get("hub_id"):
                        raise SecurePeerError(
                            "team_unavailable", "Team Hub is unavailable", 409
                        )
                    projection = store.get_network_server(
                        store.local_agent_mail_claims(team_id),
                        team_id,
                        server_id,
                    )
                else:
                    projection = self._team_hub_get(
                        realm,
                        f"/v1/teams/{quote(team_id, safe='')}/network/servers/"
                        f"{quote(server_id, safe='')}",
                        {},
                        preserve_not_found=True,
                    )
            except (HubError, SecurePeerError) as exc:
                if getattr(exc, "status_code", None) == 404:
                    server_targets[cache_key] = None
                    return None
                raise
            item = projection.get("server") if isinstance(projection, Mapping) else None
            if (
                not isinstance(item, Mapping)
                or str(item.get("id") or "") != server_id
            ):
                raise SecurePeerError(
                    "team_reference_invalid",
                    "Team Network server projection is invalid",
                    409,
                )
            server_targets[cache_key] = dict(item)
            return server_targets[cache_key]

        def team_member(team_id: str, principal_id: str) -> dict[str, Any] | None:
            cache_key = (team_id, principal_id)
            if cache_key in member_targets:
                return member_targets[cache_key]
            realm = realm_for(team_id)
            try:
                if realm["realm"] == "host":
                    with self._guard:
                        store = self._hub_store
                    if store is None or store.hub_id != realm.get("hub_id"):
                        raise SecurePeerError(
                            "team_unavailable", "Team Hub is unavailable", 409
                        )
                    projection = store.get_member(
                        store.local_agent_mail_claims(team_id),
                        team_id,
                        principal_id,
                    )
                else:
                    projection = self._team_hub_get(
                        realm,
                        f"/v1/teams/{quote(team_id, safe='')}/members/"
                        f"{quote(principal_id, safe='')}",
                        {},
                        preserve_not_found=True,
                    )
            except (HubError, SecurePeerError) as exc:
                if getattr(exc, "status_code", None) == 404:
                    member_targets[cache_key] = None
                    return None
                raise
            item = projection.get("member") if isinstance(projection, Mapping) else None
            if (
                not isinstance(item, Mapping)
                or str(item.get("principal_id") or "") != principal_id
                or item.get("status") != "active"
                or item.get("role") == "automation"
            ):
                raise SecurePeerError(
                    "team_reference_invalid",
                    "Team member projection is invalid",
                    409,
                )
            member_targets[cache_key] = dict(item)
            return member_targets[cache_key]

        def team_skills(team_id: str) -> dict[str, dict[str, Any]]:
            if team_id in skills:
                return skills[team_id]
            projection = self.team_list_skills(
                include_archived=True,
                team_id=team_id,
            )
            collected = {
                str(item["id"]): dict(item)
                for item in (projection.get("skills") or [])
                if isinstance(item, Mapping) and item.get("id")
            }
            skills[team_id] = collected
            return collected

        resolved: list[dict[str, Any]] = []
        for raw in references:
            reference = dict(raw)
            team_id = str(reference.get("team_id") or "")
            target_id = str(reference.get("target_id") or "")
            display_name = str(reference.get("display_name_snapshot") or "")
            realm_for(team_id)
            if reference.get("kind") == "skill":
                target = team_skills(team_id).get(target_id)
                if target is None or target.get("archived") is True:
                    raise SecurePeerError(
                        "team_reference_invalid",
                        "Mentioned Team Network skill is unavailable",
                        409,
                    )
                slug = str(target.get("slug") or "")
                title = str(target.get("title") or "")
                if not slug or display_name not in {slug, title}:
                    raise SecurePeerError(
                        "team_reference_invalid",
                        "Mentioned Team Network skill changed",
                        409,
                    )
                reference["authorized_skill_slug"] = slug
            elif reference.get("recipient_kind") == "all":
                if target_id != "all" or display_name != "all":
                    raise SecurePeerError(
                        "team_reference_invalid",
                        "Team-wide references must use @@all",
                        409,
                    )
            elif reference.get("recipient_kind") == "server":
                target = network_server(team_id, target_id)
                if (
                    target is None
                    or str(target.get("display_name") or "") != display_name
                ):
                    raise SecurePeerError(
                        "team_reference_invalid",
                        "Mentioned Team Network server is unavailable or changed",
                        409,
                    )
            elif reference.get("recipient_kind") == "human":
                target = team_member(team_id, target_id)
                if (
                    target is None
                    or str(target.get("display_name") or "") != display_name
                ):
                    raise SecurePeerError(
                        "team_reference_invalid",
                        "Mentioned Team Network member is unavailable or changed",
                        409,
                    )
            else:
                raise SecurePeerError(
                    "team_reference_invalid", "Team Network reference is invalid", 409
                )
            resolved.append(reference)

        return resolved

    def _team_hub_get(
        self,
        realm: dict[str, Any],
        path: str,
        query: dict[str, Any],
        *,
        preserve_not_found: bool = False,
    ) -> dict[str, Any]:
        clean = {
            key: ("1" if value is True else str(value))
            for key, value in query.items()
            if value not in (None, "", False)
        }
        if realm["realm"] == "host":
            return self._team_host_call(realm, "GET", path, clean, None)
        response = self.proxy(
            str(realm["connection_id"]),
            "GET",
            path,
            query=urlencode(clean),
            headers={"accept": "application/json"},
            body=None,
        )
        return self._decoded_proxy_json(
            response,
            preserve_not_found=preserve_not_found,
        )

    def _team_hub_post(self, realm: dict[str, Any], path: str, body: dict[str, Any]) -> dict[str, Any]:
        if realm["realm"] == "host":
            return self._team_host_call(realm, "POST", path, {}, body)
        if not realm.get("can_write"):
            raise SecurePeerError(
                "forbidden", "This server's Team Network connection is read-only", 403
            )
        response = self.proxy(
            str(realm["connection_id"]),
            "POST",
            path,
            query="",
            headers={"accept": "application/json", "content-type": "application/json"},
            body=json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        )
        return self._decoded_proxy_json(response)

    def _team_hub_delete(
        self,
        realm: dict[str, Any],
        path: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        if realm["realm"] == "host":
            return self._team_host_call(realm, "DELETE", path, {}, body)
        if not realm.get("can_write"):
            raise SecurePeerError(
                "forbidden",
                "This server's Team Network connection is read-only",
                403,
            )
        response = self.proxy(
            str(realm["connection_id"]),
            "DELETE",
            path,
            query="",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
            },
            body=json.dumps(
                body,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        return self._decoded_proxy_json(response)

    def _team_host_call(
        self,
        realm: dict[str, Any],
        method: str,
        path: str,
        query: dict[str, str],
        body: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Serve a host-realm Team Messages call directly from the HubStore."""

        with self._guard:
            store = self._hub_store
        if store is None or store.hub_id != realm.get("hub_id"):
            raise SecurePeerError("team_unavailable", "Team Hub is unavailable", 409)
        team_id = str(realm["team_id"])
        claims = store.local_agent_mail_claims(team_id)
        prefix = f"/v1/teams/{quote(team_id, safe='')}/network/"
        if not path.startswith(prefix):
            raise SecurePeerError("route_forbidden", "Hub route is not permitted", 403)
        pieces = [piece for piece in path[len(prefix):].split("/") if piece]
        flag = lambda key: query.get(key, "0") in {"1", "true"}  # noqa: E731
        if method == "GET" and pieces == ["messages"]:
            return store.list_team_messages(
                claims,
                team_id,
                box=query.get("box", "inbox"),
                address_kind=query.get("address_kind"),
                address_id=query.get("address_id"),
                unread=flag("unread"),
                from_kind=query.get("from_kind"),
                from_id=query.get("from_id"),
                since=query.get("since"),
                after_sequence=int(query.get("after_sequence", "0")),
                limit=int(query.get("limit", "50")),
            )
        if method == "GET" and pieces == ["deletions"]:
            return store.list_network_content_deletions(
                claims,
                team_id,
                after_sequence=int(query.get("after_sequence", "0")),
                limit=int(query.get("limit", "50")),
            )
        if method == "GET" and len(pieces) == 2 and pieces[0] == "messages":
            return store.get_team_message(claims, team_id, pieces[1])
        if method == "POST" and pieces == ["messages"]:
            return store.create_team_message(claims, team_id, dict(body or {}))
        if method == "POST" and len(pieces) == 3 and pieces[0] == "messages" and pieces[2] == "receipts":
            return store.record_team_message_receipt(claims, team_id, pieces[1], dict(body or {}))
        if method == "DELETE" and len(pieces) == 2 and pieces[0] == "messages":
            return store.delete_team_message(
                claims,
                team_id,
                pieces[1],
                dict(body or {}),
            )
        if method == "DELETE" and len(pieces) == 2 and pieces[0] == "bulletin":
            return store.delete_network_bulletin_post(
                claims,
                team_id,
                pieces[1],
                dict(body or {}),
            )
        if method == "GET" and pieces == ["skills"]:
            return store.list_team_skills(
                claims, team_id, include_archived=flag("include_archived"), slug=query.get("slug")
            )
        if method == "GET" and len(pieces) == 2 and pieces[0] == "skills":
            return store.get_team_skill(claims, team_id, pieces[1])
        if method == "GET" and len(pieces) == 4 and pieces[0] == "skills" and pieces[2] == "versions":
            return store.get_team_skill_version(claims, team_id, pieces[1], int(pieces[3]))
        if method == "GET" and len(pieces) == 2 and pieces[0] == "attachments":
            return store.get_team_attachment(claims, team_id, pieces[1])
        if method == "POST" and pieces == ["attachments"]:
            return store.declare_team_attachment(claims, team_id, dict(body or {}))
        raise SecurePeerError("route_forbidden", "Hub route is not permitted", 403)

    def team_list_messages(
        self,
        *,
        box: str,
        team_id: str | None = None,
        unread: bool = False,
        since: str | None = None,
        after_sequence: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        realm = self.team_realm(team_id)
        result = self._team_hub_get(
            realm,
            f"/v1/teams/{quote(realm['team_id'], safe='')}/network/messages",
            {
                "box": box,
                "unread": unread,
                "since": since,
                "after_sequence": after_sequence,
                "limit": limit,
            },
        )
        result["team_id"] = realm["team_id"]
        return result

    def team_get_message(self, message_id: str, *, team_id: str | None = None) -> dict[str, Any]:
        realm = self.team_realm(team_id)
        result = self._team_hub_get(
            realm,
            f"/v1/teams/{quote(realm['team_id'], safe='')}/network/messages/{quote(message_id, safe='')}",
            {},
        )
        result["team_id"] = realm["team_id"]
        return result

    def team_list_deletions(
        self,
        *,
        team_id: str | None = None,
        after_sequence: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        realm = self.team_realm(team_id)
        result = self._team_hub_get(
            realm,
            f"/v1/teams/{quote(realm['team_id'], safe='')}/network/deletions",
            {"after_sequence": after_sequence, "limit": limit},
        )
        result["team_id"] = realm["team_id"]
        return result

    def team_delete_message(
        self,
        message_id: str,
        idempotency_key: str,
        *,
        team_id: str | None = None,
    ) -> dict[str, Any]:
        realm = self.team_realm(team_id)
        team_path = (
            f"/v1/teams/{quote(realm['team_id'], safe='')}/network/messages"
        )
        return self._team_hub_delete(
            realm,
            f"{team_path}/{quote(message_id, safe='')}",
            {"idempotency_key": idempotency_key},
        )

    def team_delete_bulletin_post(
        self,
        post_id: str,
        idempotency_key: str,
        *,
        team_id: str | None = None,
    ) -> dict[str, Any]:
        realm = self.team_realm(team_id)
        team_path = (
            f"/v1/teams/{quote(realm['team_id'], safe='')}/network/bulletin"
        )
        return self._team_hub_delete(
            realm,
            f"{team_path}/{quote(post_id, safe='')}",
            {"idempotency_key": idempotency_key},
        )

    def team_list_skills(self, *, include_archived: bool = False, team_id: str | None = None) -> dict[str, Any]:
        realm = self.team_realm(team_id)
        result = self._team_hub_get(
            realm,
            f"/v1/teams/{quote(realm['team_id'], safe='')}/network/skills",
            {"include_archived": include_archived},
        )
        result["team_id"] = realm["team_id"]
        return result

    def team_get_skill(
        self,
        slug: str,
        *,
        version: int | None = None,
        team_id: str | None = None,
    ) -> dict[str, Any]:
        realm = self.team_realm(team_id)
        team_path = f"/v1/teams/{quote(realm['team_id'], safe='')}/network/skills"
        listed = self._team_hub_get(realm, team_path, {"slug": slug, "include_archived": True})
        skills = listed.get("skills") if isinstance(listed, dict) else None
        if not isinstance(skills, list) or len(skills) != 1 or not isinstance(skills[0], dict):
            raise SecurePeerError("not_found", f"No team skill named {slug!r}", 404)
        skill_id = str(skills[0].get("id") or "")
        if version is None:
            result = self._team_hub_get(realm, f"{team_path}/{quote(skill_id, safe='')}", {})
        else:
            result = self._team_hub_get(
                realm, f"{team_path}/{quote(skill_id, safe='')}/versions/{int(version)}", {}
            )
        result["team_id"] = realm["team_id"]
        return result

    def team_send_message(
        self,
        reference: Mapping[str, Any],
        *,
        payload: Mapping[str, Any],
        attachment_paths: list[str],
        idempotency_key: str,
        provenance: Mapping[str, str],
    ) -> dict[str, Any]:
        """Create one team message for a frozen @@ reference, with attachments."""

        realm = self.team_realm(str(reference.get("team_id") or "") or None)
        if not realm.get("can_write"):
            raise SecurePeerError(
                "forbidden", "This server's Team Network connection is read-only", 403
            )
        team_path = f"/v1/teams/{quote(realm['team_id'], safe='')}/network"
        kind = str(payload.get("kind") or "message")
        if reference.get("kind") == "skill" and kind != "skill":
            raise SecurePeerError(
                "team_reference_invalid",
                "A mentioned Team skill route cannot send a general message",
                409,
            )
        if reference.get("kind") == "skill":
            requested_slug = str(
                (payload.get("skill") or {}).get("slug")
                if isinstance(payload.get("skill"), Mapping)
                else ""
            ).strip().lower()
            if requested_slug != str(reference.get("authorized_skill_slug") or ""):
                raise SecurePeerError(
                    "team_reference_invalid",
                    "The requested skill does not match the mentioned Team skill",
                    409,
                )
        if reference.get("kind") == "skill":
            recipients = [{"kind": "all"}]
        elif reference.get("recipient_kind") == "all":
            recipients = [{"kind": "all"}]
        else:
            recipients = [
                {"kind": str(reference.get("recipient_kind")), "id": str(reference.get("target_id"))}
            ]
        attachment_ids: list[str] = []
        for index, path in enumerate(attachment_paths):
            attachment_ids.append(
                self._team_upload_attachment(
                    realm,
                    Path(path),
                    idempotency_key=f"{idempotency_key}:attachment:{index}",
                )
            )
        body: dict[str, Any] = {
            "kind": kind,
            "body": str(payload.get("body") or ""),
            "body_format": str(payload.get("body_format") or "markdown"),
            "recipients": recipients,
            "attachment_ids": attachment_ids,
            "provenance": dict(provenance),
            "idempotency_key": idempotency_key,
        }
        if payload.get("title"):
            body["title"] = str(payload["title"])
        skill = payload.get("skill")
        if kind == "skill":
            details = dict(skill or {})
            if reference.get("kind") == "skill" and not details.get("slug"):
                raise SecurePeerError(
                    "invalid_request", "Publishing to a mentioned skill requires --skill-slug", 422
                )
            body["skill"] = details
        return self._team_hub_post(realm, f"{team_path}/messages", body)

    def _team_upload_attachment(
        self,
        realm: dict[str, Any],
        path: Path,
        *,
        idempotency_key: str,
    ) -> str:
        """Stream one local file into the Hub and return its attachment id."""

        descriptor, initial = self._open_team_attachment_source(path)
        try:
            digest = hashlib.sha256()
            hashed_bytes = 0
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                hashed_bytes += len(block)
            after_hash = os.fstat(descriptor)
            identity = lambda info: (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
            if hashed_bytes != initial.st_size or identity(after_hash) != identity(initial):
                raise SecurePeerError(
                    "invalid_request", "Attachment changed while it was being read", 422
                )
            os.lseek(descriptor, 0, os.SEEK_SET)
            return self._team_upload_attachment_descriptor(
                realm,
                path,
                descriptor,
                initial,
                digest.hexdigest(),
                idempotency_key=idempotency_key,
            )
        finally:
            with suppress(OSError):
                os.close(descriptor)

    @staticmethod
    def _open_team_attachment_source(path: Path) -> tuple[int, os.stat_result]:
        """Open one absolute regular file without following any path symlink."""

        path = Path(path)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        try:
            canonical = path.resolve(strict=True)
        except (OSError, RuntimeError):
            canonical = None
        if (
            not path.is_absolute()
            or canonical != path
            or not nofollow
            or not directory_flag
        ):
            raise SecurePeerError(
                "invalid_request", "Attachment path cannot be opened safely", 422
            )
        directory = os.open(
            os.sep,
            os.O_RDONLY | directory_flag | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            for component in path.parts[1:-1]:
                if component in {"", ".", ".."}:
                    raise OSError("unsafe attachment path component")
                next_directory = os.open(
                    component,
                    os.O_RDONLY | directory_flag | nofollow | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory,
                )
                os.close(directory)
                directory = next_directory
            descriptor = os.open(
                path.name,
                os.O_RDONLY
                | nofollow
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory,
            )
        except (OSError, ValueError) as exc:
            raise SecurePeerError(
                "invalid_request", f"Attachment is not a readable regular file: {path}", 422
            ) from exc
        finally:
            with suppress(OSError):
                os.close(directory)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or not 1 <= info.st_size <= MAX_ATTACHMENT_PROTOCOL_BYTES
            ):
                raise OSError("unsafe attachment inode")
            return descriptor, info
        except (OSError, ValueError) as exc:
            with suppress(OSError):
                os.close(descriptor)
            raise SecurePeerError(
                "invalid_request", f"Attachment is not a readable regular file: {path}", 422
            ) from exc

    def _team_upload_attachment_descriptor(
        self,
        realm: dict[str, Any],
        path: Path,
        descriptor: int,
        source_info: os.stat_result,
        expected_sha256: str,
        *,
        idempotency_key: str,
    ) -> str:
        """Declare and stream the exact inode already validated and hashed."""

        size = source_info.st_size
        media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        declared = self._team_hub_post(
            realm,
            f"/v1/teams/{quote(realm['team_id'], safe='')}/network/attachments",
            {
                "file_name": path.name,
                "media_type": media_type,
                "byte_size": size,
                "sha256": expected_sha256,
                "idempotency_key": idempotency_key,
            },
        )
        declared_attachment = (
            declared.get("attachment") if isinstance(declared, dict) else None
        )
        if not isinstance(declared_attachment, dict) or not declared_attachment.get("id"):
            raise SecurePeerError(
                "remote_invalid", "Team Hub returned an invalid attachment", 502
            )
        attachment_id = str(declared_attachment["id"])
        live = self._team_hub_get(
            realm,
            f"/v1/teams/{quote(realm['team_id'], safe='')}/network/attachments/"
            f"{quote(attachment_id, safe='')}",
            {},
        )
        attachment = live.get("attachment") if isinstance(live, dict) else None
        if (
            not isinstance(attachment, dict)
            or attachment.get("id") != attachment_id
            or attachment.get("file_name") != path.name
            or attachment.get("byte_size") != size
            or attachment.get("sha256") != expected_sha256
            or attachment.get("state") not in {"uploading", "ready"}
            or type(attachment.get("received_bytes")) is not int
            or not 0 <= attachment["received_bytes"] <= size
        ):
            raise SecurePeerError(
                "remote_invalid", "Team Hub returned an invalid attachment", 502
            )
        if attachment.get("state") == "ready":
            if attachment["received_bytes"] != size:
                raise SecurePeerError(
                    "remote_invalid", "Team Hub returned an invalid attachment", 502
                )
            return attachment_id
        chunk_bytes = declared.get("chunk_bytes")
        if (
            type(chunk_bytes) is not int
            or not 1 <= chunk_bytes <= TEAM_ATTACHMENT_CHUNK_BYTES
        ):
            raise SecurePeerError(
                "remote_invalid", "Team Hub returned an invalid attachment chunk size", 502
            )
        store = None
        claims = None
        if realm["realm"] == "host":
            with self._guard:
                store = self._hub_store
            if store is None:
                raise SecurePeerError("team_unavailable", "Team Hub is unavailable", 409)
            claims = store.local_agent_mail_claims(str(realm["team_id"]))
        offset = int(attachment["received_bytes"])
        os.lseek(descriptor, offset, os.SEEK_SET)
        while offset < size:
            chunk = os.read(descriptor, min(chunk_bytes, size - offset))
            if not chunk:
                break
            if realm["realm"] == "host":
                assert store is not None and claims is not None
                store.write_team_attachment_chunk(
                    claims,
                    str(realm["team_id"]),
                    attachment_id,
                    offset=offset,
                    total=size,
                    data=chunk,
                )
            else:
                response = self.proxy_team_attachment_chunk(
                    str(realm["connection_id"]),
                    str(realm["team_id"]),
                    attachment_id,
                    content_range=(
                        f"bytes {offset}-{offset + len(chunk) - 1}/{size}"
                    ),
                    body=chunk,
                )
                if int(response.status) != 200:
                    raise SecurePeerError(
                        "attachment_unavailable",
                        "Team attachment upload failed",
                        int(response.status),
                    )
            offset += len(chunk)
        after_upload = os.fstat(descriptor)
        if (
            after_upload.st_dev,
            after_upload.st_ino,
            after_upload.st_size,
            after_upload.st_mtime_ns,
            after_upload.st_ctime_ns,
        ) != (
            source_info.st_dev,
            source_info.st_ino,
            source_info.st_size,
            source_info.st_mtime_ns,
            source_info.st_ctime_ns,
        ):
            raise SecurePeerError(
                "invalid_request", "Attachment changed while it was being uploaded", 422
            )
        completed = self._team_hub_get(
            realm,
            f"/v1/teams/{quote(realm['team_id'], safe='')}/network/attachments/"
            f"{quote(attachment_id, safe='')}",
            {},
        )
        completed_attachment = (
            completed.get("attachment") if isinstance(completed, dict) else None
        )
        if (
            not isinstance(completed_attachment, dict)
            or completed_attachment.get("id") != attachment_id
            or completed_attachment.get("state") != "ready"
            or completed_attachment.get("received_bytes") != size
            or completed_attachment.get("byte_size") != size
            or completed_attachment.get("sha256") != expected_sha256
        ):
            raise SecurePeerError(
                "attachment_unavailable", "Team attachment upload did not complete", 502
            )
        return attachment_id

    def team_attachment_local_paths(
        self,
        attachments: list[Mapping[str, Any]],
        *,
        team_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Resolve into bounded durable exports that outlive cache eviction."""

        realm = self.team_realm(team_id)
        resolved: list[dict[str, Any]] = []
        batch_leases: list[tuple[Path, AttachmentFileLease]] = []
        try:
            if realm["realm"] != "host":
                for attachment in attachments:
                    attachment_id = str(attachment.get("id") or "")
                    public, lease = self.open_cached_team_attachment(
                        str(realm["connection_id"]),
                        str(realm["team_id"]),
                        attachment_id,
                    )
                    try:
                        path, _sidecar = self._team_cache_paths(
                            realm,
                            str(realm["team_id"]),
                            attachment_id,
                            str(public["file_name"]),
                        )
                    except BaseException:
                        lease.close()
                        raise
                    batch_leases.append((path, lease))
                    resolved.append({**public, "local_path": str(path)})
            else:
                with self._guard:
                    store = self._hub_store
                if store is None:
                    raise SecurePeerError(
                        "team_unavailable", "Team Hub is unavailable", 409
                    )
                claims = store.local_agent_mail_claims(str(realm["team_id"]))
                for attachment in attachments:
                    canonical_team = str(realm["team_id"])
                    attachment_id = str(attachment.get("id") or "")
                    public, source = store.open_team_attachment(
                        claims,
                        canonical_team,
                        attachment_id,
                    )
                    try:
                        if public.get("message_id") is None:
                            raise HubError("not_found", "Resource not found", 404)
                        verified = self._validate_team_attachment_metadata(
                            {"attachment": public},
                            team_id=canonical_team,
                            attachment_id=attachment_id,
                        )

                        def copy_to_cache(
                            temporary: Path,
                            *,
                            descriptor: int = source.descriptor,
                            expected_size: int = int(verified["byte_size"]),
                            expected_sha256: str = str(verified["sha256"]),
                            media_type: str = str(verified["media_type"]),
                        ) -> tuple[tuple[str, str], ...]:
                            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(
                                os, "O_NOFOLLOW", 0
                            )
                            output = os.open(temporary, flags, 0o600)
                            try:
                                os.lseek(descriptor, 0, os.SEEK_SET)
                                remaining = expected_size
                                while remaining:
                                    block = os.read(
                                        descriptor, min(1024 * 1024, remaining)
                                    )
                                    if not block:
                                        raise SecurePeerError(
                                            "attachment_unavailable",
                                            "Team attachment bytes are truncated",
                                            404,
                                        )
                                    view = memoryview(block)
                                    while view:
                                        written = os.write(output, view)
                                        if written <= 0:
                                            raise OSError(
                                                "Team attachment cache write stalled"
                                            )
                                        view = view[written:]
                                    remaining -= len(block)
                                if os.read(descriptor, 1):
                                    raise SecurePeerError(
                                        "attachment_unavailable",
                                        "Team attachment bytes exceeded metadata",
                                        409,
                                    )
                                os.fsync(output)
                            except BaseException:
                                with suppress(OSError):
                                    os.close(output)
                                with suppress(OSError):
                                    temporary.unlink()
                                raise
                            else:
                                os.close(output)
                            return (
                                ("etag", f'"{expected_sha256}"'),
                                ("content-type", media_type),
                                ("accept-ranges", "bytes"),
                            )

                        lease = self._materialize_team_cache_entry(
                            active={"hub_id": store.hub_id},
                            attachment=verified,
                            team_id=canonical_team,
                            attachment_id=attachment_id,
                            download=copy_to_cache,
                            connection_id=None,
                            pin=True,
                        )
                        assert isinstance(lease, AttachmentFileLease)
                    finally:
                        source.close()
                    try:
                        path, _sidecar = self._team_cache_paths(
                            {"hub_id": store.hub_id},
                            canonical_team,
                            attachment_id,
                            str(verified["file_name"]),
                        )
                    except BaseException:
                        lease.close()
                        raise
                    batch_leases.append((path, lease))
                    resolved.append({**verified, "local_path": str(path)})

            # Keep every earlier entry pinned while materializing later ones,
            # then prove the complete returned name set still resolves to the
            # exact verified inodes. A too-small cache therefore fails the
            # entire request instead of returning already-evicted paths.
            with self._team_cache_guard:
                for path, lease in batch_leases:
                    try:
                        path_info = path.lstat()
                        descriptor_info = os.fstat(lease.descriptor)
                    except OSError as exc:
                        raise SecurePeerError(
                            "cache_unavailable",
                            "Team attachment cache changed during batch resolution",
                            503,
                        ) from exc
                    if (
                        not stat.S_ISREG(path_info.st_mode)
                        or path_info.st_nlink != 1
                        or path_info.st_uid != os.getuid()
                        or self._team_cache_stat_identity(path_info)
                        != self._team_cache_stat_identity(descriptor_info)
                    ):
                        raise SecurePeerError(
                            "cache_unavailable",
                            "Team attachment cache changed during batch resolution",
                            503,
                        )
            return self._export_team_attachment_batch(
                resolved,
                [lease for _path, lease in batch_leases],
            )
        finally:
            for _path, lease in reversed(batch_leases):
                lease.close()

    def shutdown(self) -> None:
        self.close_host_admission()
        with self._guard:
            gateway = self._gateway
            self._gateway = None
        if gateway is not None:
            gateway.stop()
