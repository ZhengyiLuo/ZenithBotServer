"""Authenticated, encrypted AgentsServer peer pairing and relay primitives.

This module deliberately uses ordinary TLS 1.3, X.509, and Ed25519 from
``cryptography``.  It does not implement or claim end-to-end encryption: the
designated Team Hub terminates TLS and remains authoritative for its data.

The state in this module is separate from the Team Hub schema so that peer
credentials can be revoked even while the Hub application is unavailable.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import stat
import threading
import time
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from .security import canonical_json, create_secret_file, ensure_private_directory, read_secret_file


PROTOCOL_VERSION = 1
PAIRING_TTL_SECONDS = 10 * 60
PAIRING_ATTEMPT_RETENTION_SECONDS = 7 * 24 * 60 * 60
CLIENT_CERT_TTL_SECONDS = 30 * 24 * 60 * 60
CLIENT_CERT_RENEW_WINDOW_SECONDS = 7 * 24 * 60 * 60
CLIENT_CERT_OVERLAP_SECONDS = 10 * 60
RENEWAL_REQUEST_TTL_SECONDS = 24 * 60 * 60
RETIRED_RENEWAL_MATERIAL_LIMIT = 8
ACTIVATED_RENEWAL_HISTORY_LIMIT = 8
MAX_RELAY_TTL_SECONDS = 72 * 60 * 60
MAX_RELAY_LEGS = 6
RELAY_LEASE_SECONDS = 60
PEER_HEARTBEAT_LEASE_SECONDS = 90
PEER_HEARTBEAT_COALESCE_SECONDS = 15
PAIRING_STATUS_LIMIT = 512
PAIRING_TERMINAL_RETAINED_LIMIT = 512
ROUTE_ACTIVE_PER_PEER_LIMIT = 128
ROUTE_TOTAL_PER_PEER_LIMIT = 512
ROUTE_GLOBAL_LIMIT = 10_000
RELAY_ACTIVE_PER_PEER_LIMIT = 256
RELAY_ACTIVE_GLOBAL_LIMIT = 4_096
RELAY_RETAINED_PER_PEER_LIMIT = 2_048
RELAY_USAGE_WINDOW_SECONDS = 24 * 60 * 60
RELAY_SUBMISSIONS_PER_PEER_WINDOW_LIMIT = 256
RELAY_BYTES_PER_PEER_WINDOW_LIMIT = 4 * 1024 * 1024
RELAY_TERMINAL_RETENTION_SECONDS = 7 * 24 * 60 * 60
AUDIT_RETENTION_SECONDS = 90 * 24 * 60 * 60
AUDIT_EVENT_LIMIT = 100_000
SECURE_STATE_LIVE_BYTES_LIMIT = 128 * 1024 * 1024
MAX_PAIRING_BODY_BYTES = 64 * 1024
MAX_PROXY_BODY_BYTES = 65_536
MAX_RESPONSE_BODY_BYTES = 2 * 1024 * 1024
MAX_ATTACHMENT_CHUNK_BYTES = 8 * 1024 * 1024
# The Hub's per-file limit is configurable.  This is only the wire-format
# ceiling implied by the 15-digit Content-Range grammar; the gateway applies
# the live Hub limit before dispatching or streaming bytes.
MAX_ATTACHMENT_PROTOCOL_BYTES = 999_999_999_999_999
MAX_ATTACHMENT_BYTES = 512 * 1024 * 1024
MAX_HEADERS = 48
MAX_HEADER_VALUE_BYTES = 8192
MAX_HEADER_BLOCK_BYTES = 32 * 1024
PAIRING_TOKEN_HEADER = "X-AgentsDock-Pairing-Token"
PEER_BINDING_OID = ObjectIdentifier("1.3.6.1.4.1.62177.1.1")
SCOPES = frozenset(
    {
        "teamspace.read",
        "teamspace.write",
        "cross_chat.instruction",
        "cross_chat.request_reply",
    }
)
SCOPE_ORDER = (
    "teamspace.read",
    "teamspace.write",
    "cross_chat.instruction",
    "cross_chat.request_reply",
)
CAPABILITIES = frozenset({"teamspace", "cross_chat", "cert_renewal"})

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{7,239}$")
_LABEL_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,160}$")
_HEX_FP_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_POLL_TOKEN_RE = re.compile(r"^pairpoll\.[A-Za-z0-9_-]{43}$")
_HUB_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,239}"
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_PAIR_ID_RE = _UUID4_RE
_PEER_ID_RE = _UUID4_RE
_ENVELOPE_ID_RE = _UUID4_RE


class SecurePeerError(RuntimeError):
    """A fail-closed protocol error safe to map to a small JSON response."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = int(status_code)


@dataclass(frozen=True)
class PeerAuthorization:
    peer_id: str
    pairing_id: str
    peer_server_identity: str
    team_id: str
    scopes: frozenset[str]
    certificate_fingerprint: str
    certificate_expires_at: int
    peer_display_name: str
    cross_chat_grant_epoch: int | None = None


@dataclass(frozen=True)
class ProxyRequest:
    method: str
    path: str
    query: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    peer: PeerAuthorization


@dataclass(frozen=True)
class ProxyResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True)
class AttachmentProxyRequest:
    """One authenticated request on the attachment-only binary lane."""

    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    peer: PeerAuthorization


@dataclass(frozen=True)
class AttachmentProxyResponse:
    """A bounded inline response or an already-open authorized file slice."""

    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes = b""
    descriptor: int | None = None
    offset: int = 0
    length: int = 0
    finalizer: Callable[[], None] | None = None
    cancelled: Callable[[], bool] | None = None


class AttachmentFileLease:
    """Own a pinned local attachment descriptor until HTTP streaming finishes."""

    __slots__ = ("descriptor", "_release", "_guard", "_closed")

    def __init__(self, descriptor: int, release: Callable[[], None]) -> None:
        self.descriptor = descriptor
        self._release = release
        self._guard = threading.Lock()
        self._closed = False

    def close(self) -> None:
        with self._guard:
            if self._closed:
                return
            self._closed = True
        with suppress(Exception):
            self._release()

    def __del__(self) -> None:
        # Covers a cancelled local request whose worker completed after the
        # awaiting coroutine disappeared. Normal response paths close eagerly.
        with suppress(Exception):
            self.close()


def _now(value: int | float | None = None) -> int:
    result = int(time.time() if value is None else value)
    if result < 0:
        raise ValueError("timestamp must be non-negative")
    return result


def _new_id(prefix: str) -> str:
    del prefix
    return str(uuid.uuid4())


def _fingerprint(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _certificate_fingerprint(certificate: x509.Certificate) -> str:
    return _fingerprint(certificate.public_bytes(serialization.Encoding.DER))


def _require_exact_keys(value: Any, expected: set[str], *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise SecurePeerError("invalid_request", f"{context} fields are invalid", 422)
    return value


def _bounded_text(value: Any, field: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str):
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422) from exc
    normalized = value.strip()
    if (
        value != normalized
        or not minimum <= len(encoded) <= maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422)
    return value


def _bounded_pem(value: Any, field: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str):
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422) from exc
    if (
        not minimum <= len(encoded) <= maximum
        or not value.endswith("\n")
        or value.startswith((" ", "\t", "\r", "\n"))
        or "\x00" in value
        or "\r" in value
    ):
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422)
    return value


def _identifier(value: Any, field: str = "server identity") -> str:
    result = _bounded_text(value, field, 8, 240)
    if _ID_RE.fullmatch(result) is None:
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422)
    return result


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422) from exc
    canonical = str(parsed)
    if canonical != value or parsed.version != 4:
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422)
    return canonical


def _decode_b64(value: Any, field: str, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum * 2:
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422)
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422) from exc
    if not minimum <= len(decoded) <= maximum:
        raise SecurePeerError("invalid_request", f"{field} is invalid", 422)
    return decoded


def _atomic_secret(path: Path, data: bytes) -> None:
    try:
        create_secret_file(path, data)
    except FileExistsError:
        pass


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(read_secret_file(path), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PermissionError("secure peer key is not Ed25519")
    return key


def _private_key_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _public_key_pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


_SAS_LEFT = (
    "amber", "brisk", "cedar", "delta", "ember", "frost", "green", "honey",
    "indigo", "jade", "kind", "lunar", "maple", "navy", "opal", "pearl",
)
_SAS_RIGHT = (
    "arch", "bird", "cloud", "drum", "elm", "field", "gate", "harbor",
    "isle", "jet", "kite", "lake", "moon", "north", "oak", "pine",
)


def sas_words(transcript_hash: bytes | str) -> tuple[str, ...]:
    raw = bytes.fromhex(transcript_hash) if isinstance(transcript_hash, str) else transcript_hash
    if len(raw) < 6:
        raise ValueError("transcript hash is too short")
    return tuple(f"{_SAS_LEFT[b >> 4]}-{_SAS_RIGHT[b & 15]}" for b in raw[:6])


class SecurePeerStore:
    """Durable host-side pairing, certificate, and relay authority."""

    def __init__(
        self,
        data_dir: str | Path,
        host_server_identity: str,
        hub_id: str,
        *,
        clock: Callable[[], float] = time.time,
        cross_chat_enabled: bool | Callable[[], bool] = False,
        pairing_capacity_lock: threading.RLock | None = None,
        external_actionable_pairing_count: Callable[[], int] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        ensure_private_directory(self.data_dir)
        self.host_server_identity = _identifier(host_server_identity, "host server identity")
        self.hub_id = _identifier(hub_id, "hub id")
        self._clock = clock
        self.cross_chat_enabled = cross_chat_enabled
        self._guard = threading.RLock()
        self._pairing_capacity_lock = pairing_capacity_lock or threading.RLock()
        self._external_actionable_pairing_count = (
            external_actionable_pairing_count
        )
        self.db_path = self.data_dir / "secure-peers.sqlite3"
        self._database_was_new = not self.db_path.exists()
        self.ca_key_path = self.data_dir / "host-ca-key.pem"
        self.ca_certificate_path = self.data_dir / "host-ca-certificate.pem"
        self.server_key_path = self.data_dir / "host-server-key.pem"
        self.server_certificate_path = self.data_dir / "host-server-certificate.pem"
        self.poll_key_path = self.data_dir / "pairing-poll.key"
        self.identity_ready_path = self.data_dir / "host-identity.ready"
        self._ensure_identity()
        self._initialize_database()

    def _timestamp(self) -> int:
        return _now(self._clock())

    @staticmethod
    def _actionable_pairing_count(connection: sqlite3.Connection) -> int:
        return int(
            connection.execute(
                """SELECT COUNT(*) AS count
                FROM pairing_requests AS pairing
                LEFT JOIN peers AS peer ON peer.pairing_id=pairing.id
                WHERE pairing.status='pending'
                OR (pairing.status='approved'
                    AND (peer.status IS NULL OR peer.status='active'))"""
            ).fetchone()["count"]
        )

    def actionable_pairing_count(self) -> int:
        connection = self._connect()
        try:
            return self._actionable_pairing_count(connection)
        finally:
            connection.close()

    def _external_pairing_count(self) -> int:
        if self._external_actionable_pairing_count is None:
            return 0
        try:
            count = self._external_actionable_pairing_count()
        except Exception as exc:
            raise SecurePeerError(
                "pairing_capacity",
                "Pairing capacity cannot be verified safely",
                503,
            ) from exc
        if type(count) is not int or not 0 <= count <= PAIRING_STATUS_LIMIT:
            raise SecurePeerError(
                "pairing_capacity",
                "Pairing capacity cannot be verified safely",
                503,
            )
        return count

    def _cross_chat_available(self) -> bool:
        try:
            return bool(
                self.cross_chat_enabled()
                if callable(self.cross_chat_enabled)
                else self.cross_chat_enabled
            )
        except Exception:
            return False

    def _cross_chat_epoch(
        self, connection: sqlite3.Connection | None = None
    ) -> int:
        owned = connection is None
        selected = self._connect() if owned else connection
        assert selected is not None
        try:
            row = selected.execute(
                "SELECT value FROM host_meta WHERE key='cross_chat_consent_epoch'"
            ).fetchone()
            return int(row["value"]) if row is not None else 0
        finally:
            if owned:
                selected.close()

    def _require_cross_chat(
        self,
        peer: PeerAuthorization | None = None,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> int:
        if not self._cross_chat_available():
            raise SecurePeerError(
                "cross_chat_unavailable",
                "Secure cross-chat delivery is not enabled",
                409,
            )
        owned = connection is None
        selected = self._connect() if owned else connection
        assert selected is not None
        try:
            epoch = self._cross_chat_epoch(selected)
            if epoch <= 0:
                raise SecurePeerError(
                    "cross_chat_consent_required",
                    "Secure cross-chat consent must be activated before use",
                    409,
                )
            if peer is None or not peer.peer_id:
                return epoch
            if peer.cross_chat_grant_epoch != epoch:
                raise SecurePeerError(
                    "cross_chat_reapproval_required",
                    "Peer cross-chat approval is not current",
                    403,
                )
            row = selected.execute(
                """SELECT pairing_id,peer_server_identity,team_id,scopes_json,
                status,cross_chat_grant_epoch FROM peers WHERE id=?""",
                (peer.peer_id,),
            ).fetchone()
            try:
                raw_scopes = (
                    json.loads(row["scopes_json"]) if row is not None else None
                )
                persisted_scopes = (
                    frozenset(raw_scopes)
                    if isinstance(raw_scopes, list)
                    and all(isinstance(scope, str) for scope in raw_scopes)
                    else None
                )
            except (TypeError, ValueError):
                persisted_scopes = None
            if (
                row is None
                or row["status"] != "active"
                or row["pairing_id"] != peer.pairing_id
                or row["peer_server_identity"] != peer.peer_server_identity
                or row["team_id"] != peer.team_id
                or persisted_scopes != peer.scopes
            ):
                raise SecurePeerError(
                    "peer_revoked", "Peer authentication is unavailable", 401
                )
            if row["cross_chat_grant_epoch"] != epoch:
                raise SecurePeerError(
                    "cross_chat_reapproval_required",
                    "Peer cross-chat approval is not current",
                    403,
                )
            return epoch
        finally:
            if owned:
                selected.close()

    def _ensure_identity(self) -> None:
        with self._guard:
            paths = (
                self.ca_key_path,
                self.ca_certificate_path,
                self.server_key_path,
                self.server_certificate_path,
                self.poll_key_path,
            )
            present = [path.exists() for path in paths]
            committed = self.identity_ready_path.exists()
            if committed and not all(present):
                raise PermissionError("committed secure peer host identity is incomplete")
            if not committed and any(present) and not all(present):
                # A first-start crash before the commit marker cannot have
                # exposed a usable listener identity.  Discard only that
                # incomplete generated set and retry creation.
                for path, exists in zip(paths, present):
                    if exists:
                        path.unlink()
                present = [False] * len(paths)
            if not any(present):
                now = datetime.now(timezone.utc)
                ca_key = Ed25519PrivateKey.generate()
                ca_subject = x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentsDock"),
                        x509.NameAttribute(NameOID.COMMON_NAME, self.host_server_identity),
                    ]
                )
                ca_cert = (
                    x509.CertificateBuilder()
                    .subject_name(ca_subject)
                    .issuer_name(ca_subject)
                    .public_key(ca_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=5))
                    .not_valid_after(now + timedelta(days=3650))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .add_extension(
                        x509.KeyUsage(
                            digital_signature=True,
                            content_commitment=False,
                            key_encipherment=False,
                            data_encipherment=False,
                            key_agreement=False,
                            key_cert_sign=True,
                            crl_sign=True,
                            encipher_only=False,
                            decipher_only=False,
                        ),
                        critical=True,
                    )
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
                    .sign(ca_key, algorithm=None)
                )
                server_key = Ed25519PrivateKey.generate()
                server_cert = self._issue_server_certificate(ca_key, ca_cert, server_key, now)
                material = {
                    self.ca_key_path: _private_key_pem(ca_key),
                    self.ca_certificate_path: ca_cert.public_bytes(
                        serialization.Encoding.PEM
                    ),
                    self.server_key_path: _private_key_pem(server_key),
                    self.server_certificate_path: server_cert.public_bytes(
                        serialization.Encoding.PEM
                    ),
                    self.poll_key_path: secrets.token_bytes(32),
                }
                suffix = secrets.token_hex(8)
                staged: list[tuple[Path, Path]] = []
                try:
                    for destination, data in material.items():
                        temporary = self.data_dir / (
                            f".identity-staging-{suffix}-{destination.name}"
                        )
                        create_secret_file(temporary, data)
                        staged.append((temporary, destination))
                    for temporary, destination in staged:
                        os.replace(temporary, destination)
                    directory = os.open(
                        self.data_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    )
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                finally:
                    for temporary, _destination in staged:
                        try:
                            temporary.unlink()
                        except FileNotFoundError:
                            pass
            self._ca_key = _load_private_key(self.ca_key_path)
            self._ca_certificate = x509.load_pem_x509_certificate(
                read_secret_file(self.ca_certificate_path)
            )
            self._server_certificate = x509.load_pem_x509_certificate(
                read_secret_file(self.server_certificate_path)
            )
            server_key = _load_private_key(self.server_key_path)
            self._poll_key = read_secret_file(self.poll_key_path)
            if len(self._poll_key) != 32:
                raise PermissionError("pairing poll key is invalid")
            try:
                now = datetime.now(timezone.utc)
                ca_constraints = self._ca_certificate.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
                ca_usage = self._ca_certificate.extensions.get_extension_for_class(
                    x509.KeyUsage
                ).value
                server_constraints = self._server_certificate.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
                server_eku = self._server_certificate.extensions.get_extension_for_class(
                    x509.ExtendedKeyUsage
                ).value
                server_sans = self._server_certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
                server_uris = server_sans.get_values_for_type(
                    x509.UniformResourceIdentifier
                )
                ca_names = self._ca_certificate.subject.get_attributes_for_oid(
                    NameOID.COMMON_NAME
                )
                server_names = self._server_certificate.subject.get_attributes_for_oid(
                    NameOID.COMMON_NAME
                )
                self._ca_certificate.public_key().verify(
                    self._ca_certificate.signature,
                    self._ca_certificate.tbs_certificate_bytes,
                )
                self._ca_certificate.public_key().verify(
                    self._server_certificate.signature,
                    self._server_certificate.tbs_certificate_bytes,
                )
            except Exception as exc:
                raise PermissionError("secure peer host identity is invalid") from exc
            if (
                self._ca_certificate.subject != self._ca_certificate.issuer
                or self._server_certificate.issuer != self._ca_certificate.subject
                or len(ca_names) != 1
                or ca_names[0].value != self.host_server_identity
                or len(server_names) != 1
                or server_names[0].value != self.host_server_identity
                or not ca_constraints.ca
                or ca_constraints.path_length != 0
                or not ca_usage.key_cert_sign
                or not ca_usage.crl_sign
                or server_constraints.ca
                or ExtendedKeyUsageOID.SERVER_AUTH not in server_eku
                or ExtendedKeyUsageOID.CLIENT_AUTH in server_eku
                or server_uris
                != [f"urn:agentsdock:server:{self.host_server_identity}"]
                or self._ca_key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                != self._ca_certificate.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                or server_key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                != self._server_certificate.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                or not self._ca_certificate.not_valid_before_utc
                <= now
                < self._ca_certificate.not_valid_after_utc
                or not self._server_certificate.not_valid_before_utc
                <= now
                < self._server_certificate.not_valid_after_utc
            ):
                raise PermissionError("secure peer host identity is invalid")
            if not committed:
                create_secret_file(self.identity_ready_path, secrets.token_bytes(32))

    def _issue_server_certificate(
        self,
        ca_key: Ed25519PrivateKey,
        ca_cert: x509.Certificate,
        server_key: Ed25519PrivateKey,
        now: datetime,
    ) -> x509.Certificate:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.host_server_identity)])
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(f"urn:agentsdock:server:{self.host_server_identity}")]
                ),
                False,
            )
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .sign(ca_key, algorithm=None)
        )

    @property
    def ca_certificate_pem(self) -> str:
        return self._ca_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

    @property
    def ca_fingerprint(self) -> str:
        return _certificate_fingerprint(self._ca_certificate)

    @property
    def server_certificate_expires_at(self) -> int:
        return int(self._server_certificate.not_valid_after_utc.timestamp())

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5, isolation_level=None)
        os.chmod(self.db_path, 0o600)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize_database(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS host_meta(
                    key TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pairing_requests(
                    id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
                    request_digest BLOB NOT NULL, request_json TEXT NOT NULL,
                    poll_token_hash BLOB NOT NULL, peer_server_identity TEXT NOT NULL,
                    peer_display_name TEXT NOT NULL, peer_public_key_pem TEXT NOT NULL,
                    csr_pem TEXT NOT NULL, peer_nonce TEXT NOT NULL,
                    requested_scopes_json TEXT NOT NULL,
                    source_ip TEXT, source_endpoint TEXT,
                    transcript_hash TEXT NOT NULL, sas_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','cancelled','expired')),
                    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                    decided_at INTEGER, team_id TEXT, scopes_json TEXT,
                    approved_by TEXT, client_certificate_pem TEXT,
                    peer_id TEXT, rejection_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS peers(
                    id TEXT PRIMARY KEY, pairing_id TEXT NOT NULL UNIQUE,
                    peer_server_identity TEXT NOT NULL, team_id TEXT NOT NULL,
                    scopes_json TEXT NOT NULL, transcript_hash TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    cross_chat_grant_epoch INTEGER,
                    last_seen_at INTEGER, lease_expires_at INTEGER,
                    created_at INTEGER NOT NULL, revoked_at INTEGER, revoked_by TEXT,
                    FOREIGN KEY(pairing_id) REFERENCES pairing_requests(id)
                );
                CREATE TABLE IF NOT EXISTS peer_certificates(
                    fingerprint TEXT PRIMARY KEY, peer_id TEXT NOT NULL, serial TEXT NOT NULL UNIQUE,
                    certificate_pem TEXT NOT NULL, public_key_pem TEXT NOT NULL,
                    issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                    superseded_at INTEGER, valid_until INTEGER NOT NULL, revoked_at INTEGER,
                    activation_required INTEGER NOT NULL DEFAULT 0 CHECK(activation_required IN (0,1)),
                    FOREIGN KEY(peer_id) REFERENCES peers(id)
                );
                CREATE TABLE IF NOT EXISTS renewal_requests(
                    request_id TEXT PRIMARY KEY, peer_id TEXT NOT NULL,
                    current_fingerprint TEXT NOT NULL, new_fingerprint TEXT NOT NULL UNIQUE,
                    request_digest BLOB NOT NULL, response_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('issued','activated')),
                    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, activated_at INTEGER,
                    FOREIGN KEY(peer_id) REFERENCES peers(id)
                );
                CREATE TABLE IF NOT EXISTS peer_routes(
                    id TEXT PRIMARY KEY, server_identity TEXT NOT NULL,
                    target_kind TEXT NOT NULL CHECK(target_kind IN ('host','peer')),
                    peer_id TEXT, audience_peer_id TEXT, team_id TEXT NOT NULL,
                    revision TEXT NOT NULL, alias TEXT NOT NULL, display_title TEXT NOT NULL,
                    actions_json TEXT NOT NULL, chat_id TEXT,
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, revoked_at INTEGER,
                    FOREIGN KEY(peer_id) REFERENCES peers(id),
                    FOREIGN KEY(audience_peer_id) REFERENCES peers(id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS active_peer_route_alias
                  ON peer_routes(team_id,peer_id,alias) WHERE status='active';
                CREATE TABLE IF NOT EXISTS relay_exchanges(
                    id TEXT PRIMARY KEY, team_id TEXT NOT NULL,
                    first_route_id TEXT NOT NULL, second_route_id TEXT NOT NULL,
                    last_envelope_id TEXT, used_legs INTEGER NOT NULL,
                    max_legs INTEGER NOT NULL CHECK(max_legs=6),
                    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('open','complete','expired')),
                    FOREIGN KEY(first_route_id) REFERENCES peer_routes(id),
                    FOREIGN KEY(second_route_id) REFERENCES peer_routes(id)
                );
                CREATE TABLE IF NOT EXISTS relay_envelopes(
                    id TEXT PRIMARY KEY, request_id TEXT NOT NULL, source_peer_id TEXT,
                    source_route_id TEXT NOT NULL, source_server_identity TEXT NOT NULL,
                    source_route_revision TEXT NOT NULL,
                    request_digest BLOB NOT NULL, target_server_identity TEXT NOT NULL,
                    target_route_id TEXT NOT NULL, target_peer_id TEXT,
                    target_route_revision TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('instruction','request_reply','response')),
                    exchange_id TEXT NOT NULL, parent_envelope_id TEXT, parent_leg INTEGER,
                    max_legs INTEGER NOT NULL CHECK(max_legs=6), used_legs INTEGER NOT NULL,
                    body_json TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('queued','claimed','delivered','failed','expired')),
                    lease_owner TEXT, lease_token_hash BLOB, lease_expires_at INTEGER,
                    UNIQUE(source_route_id, request_id), FOREIGN KEY(source_peer_id) REFERENCES peers(id),
                    FOREIGN KEY(source_route_id) REFERENCES peer_routes(id),
                    FOREIGN KEY(target_route_id) REFERENCES peer_routes(id),
                    FOREIGN KEY(target_peer_id) REFERENCES peers(id),
                    FOREIGN KEY(exchange_id) REFERENCES relay_exchanges(id)
                );
                CREATE INDEX IF NOT EXISTS relay_target_status
                  ON relay_envelopes(target_server_identity,status,created_at);
                CREATE TABLE IF NOT EXISTS relay_receipts(
                    envelope_id TEXT PRIMARY KEY, target_peer_id TEXT,
                    target_route_id TEXT NOT NULL,
                    outcome TEXT NOT NULL, received_at INTEGER NOT NULL,
                    FOREIGN KEY(envelope_id) REFERENCES relay_envelopes(id),
                    FOREIGN KEY(target_peer_id) REFERENCES peers(id),
                    FOREIGN KEY(target_route_id) REFERENCES peer_routes(id)
                );
                CREATE TABLE IF NOT EXISTS relay_usage_windows(
                    peer_id TEXT NOT NULL, window_start INTEGER NOT NULL,
                    submissions INTEGER NOT NULL, body_bytes INTEGER NOT NULL,
                    PRIMARY KEY(peer_id,window_start),
                    FOREIGN KEY(peer_id) REFERENCES peers(id)
                );
                CREATE TABLE IF NOT EXISTS audit_events(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at INTEGER NOT NULL,
                    actor TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT NOT NULL,
                    detail_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotency_records(
                    realm TEXT NOT NULL, operation_id TEXT NOT NULL,
                    request_digest BLOB NOT NULL, response_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY(realm,operation_id)
                );
                COMMIT;
                """
            )
            # Legacy repair is one migration, not a sequence of autocommit
            # statements.  In particular, a crash after adding the immutable
            # source-route revision must not leave the pre-ledger envelopes in
            # place: on the next start the new column would otherwise suppress
            # the fail-closed purge below.
            connection.execute("BEGIN IMMEDIATE")
            # Development builds predating the per-route grant ledger may
            # already have created this owner-private database.  Preserve the
            # immutable source grant on those databases instead of silently
            # accepting envelopes without it.
            relay_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(relay_envelopes)").fetchall()
            }
            if "source_route_revision" not in relay_columns:
                connection.execute(
                    "ALTER TABLE relay_envelopes ADD COLUMN source_route_revision TEXT"
                )
                # No pre-ledger envelope can prove the source route revision
                # that authorized it.  Fail closed rather than guessing from
                # the route's current mutable state.
                connection.execute("DELETE FROM relay_receipts")
                connection.execute("DELETE FROM relay_envelopes")
                connection.execute("DELETE FROM relay_exchanges")
            peer_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(peers)").fetchall()
            }
            if "cross_chat_grant_epoch" not in peer_columns:
                connection.execute(
                    "ALTER TABLE peers ADD COLUMN cross_chat_grant_epoch INTEGER"
                )
            if "last_seen_at" not in peer_columns:
                connection.execute(
                    "ALTER TABLE peers ADD COLUMN last_seen_at INTEGER"
                )
            if "lease_expires_at" not in peer_columns:
                connection.execute(
                    "ALTER TABLE peers ADD COLUMN lease_expires_at INTEGER"
                )
            migration_timestamp = self._timestamp()
            duplicate_host_routes = connection.execute(
                """SELECT DISTINCT a.id FROM peer_routes a
                JOIN peer_routes b ON b.id<>a.id
                AND b.team_id=a.team_id
                AND b.audience_peer_id=a.audience_peer_id
                AND (b.chat_id=a.chat_id OR b.alias=a.alias)
                WHERE a.target_kind='host' AND b.target_kind='host'
                AND a.status='active' AND b.status='active'"""
            ).fetchall()
            if duplicate_host_routes:
                route_ids = [row["id"] for row in duplicate_host_routes]
                placeholders = ",".join("?" for _ in route_ids)
                connection.execute(
                    f"""UPDATE peer_routes SET status='revoked',revoked_at=?,updated_at=?,
                    revision=? WHERE id IN ({placeholders})""",
                    (
                        migration_timestamp,
                        migration_timestamp,
                        "rev_" + uuid.uuid4().hex,
                        *route_ids,
                    ),
                )
                connection.execute(
                    f"""UPDATE relay_envelopes SET status='expired',lease_owner=NULL,
                    lease_token_hash=NULL,lease_expires_at=NULL
                    WHERE source_route_id IN ({placeholders})
                    OR target_route_id IN ({placeholders})""",
                    (*route_ids, *route_ids),
                )
            connection.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS active_host_route_chat
                ON peer_routes(team_id,audience_peer_id,chat_id)
                WHERE target_kind='host' AND status='active'"""
            )
            connection.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS active_host_route_alias
                ON peer_routes(team_id,audience_peer_id,alias)
                WHERE target_kind='host' AND status='active'"""
            )
            expected = {
                "format": "1",
                "host_server_identity": self.host_server_identity,
                "hub_id": self.hub_id,
                "ca_fingerprint": self.ca_fingerprint,
            }
            try:
                for key, value in expected.items():
                    row = connection.execute("SELECT value FROM host_meta WHERE key=?", (key,)).fetchone()
                    if row is None:
                        connection.execute("INSERT INTO host_meta(key,value) VALUES (?,?)", (key, value))
                    elif row["value"] != value:
                        raise PermissionError(f"secure peer state {key} does not match host identity")
                consent = connection.execute(
                    "SELECT value FROM host_meta WHERE key='cross_chat_consent_epoch'"
                ).fetchone()
                if consent is None:
                    initial_epoch = (
                        1
                        if self._database_was_new and self._cross_chat_available()
                        else 0
                    )
                    connection.execute(
                        "INSERT INTO host_meta(key,value) VALUES ('cross_chat_consent_epoch',?)",
                        (str(initial_epoch),),
                    )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        timestamp: int,
        actor: str,
        action: str,
        object_id: str,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        SecurePeerStore._prune_history(connection, timestamp, audit_reserve=1)
        connection.execute(
            "INSERT INTO audit_events(occurred_at,actor,action,object_id,detail_json) VALUES (?,?,?,?,?)",
            (timestamp, actor, action, object_id, canonical_json(dict(detail or {})).decode("utf-8")),
        )

    @staticmethod
    def _prune_history(
        connection: sqlite3.Connection,
        timestamp: int,
        *,
        audit_reserve: int = 0,
    ) -> None:
        connection.execute(
            "DELETE FROM audit_events WHERE occurred_at<?",
            (timestamp - AUDIT_RETENTION_SECONDS,),
        )
        count = int(
            connection.execute("SELECT COUNT(*) AS count FROM audit_events").fetchone()[
                "count"
            ]
        )
        excess = count - AUDIT_EVENT_LIMIT + audit_reserve
        if excess > 0:
            connection.execute(
                """DELETE FROM audit_events WHERE sequence IN (
                SELECT sequence FROM audit_events ORDER BY sequence LIMIT ?
                )""",
                (excess,),
            )
        connection.execute(
            "DELETE FROM idempotency_records WHERE created_at<?",
            (timestamp - AUDIT_RETENTION_SECONDS,),
        )
        idempotency_count = int(
            connection.execute(
                "SELECT COUNT(*) AS count FROM idempotency_records"
            ).fetchone()["count"]
        )
        idempotency_excess = idempotency_count - AUDIT_EVENT_LIMIT
        if idempotency_excess > 0:
            connection.execute(
                """DELETE FROM idempotency_records WHERE rowid IN (
                SELECT rowid FROM idempotency_records ORDER BY created_at,rowid LIMIT ?
                )""",
                (idempotency_excess,),
            )

    @staticmethod
    def _database_live_bytes(connection: sqlite3.Connection) -> int:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        free_pages = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
        return page_size * max(0, page_count - free_pages)

    @staticmethod
    def _prune_relay_state(
        connection: sqlite3.Connection, timestamp: int
    ) -> None:
        connection.execute(
            """UPDATE relay_envelopes SET status='expired',lease_owner=NULL,
            lease_token_hash=NULL,lease_expires_at=NULL
            WHERE expires_at<=? AND status IN ('queued','claimed')""",
            (timestamp,),
        )
        connection.execute(
            """UPDATE relay_exchanges SET status='expired'
            WHERE expires_at<=? AND status='open'""",
            (timestamp,),
        )
        cutoff = timestamp - RELAY_TERMINAL_RETENTION_SECONDS
        connection.execute(
            """DELETE FROM relay_receipts WHERE envelope_id IN (
            SELECT id FROM relay_envelopes
            WHERE status IN ('delivered','failed','expired') AND created_at<?
            )""",
            (cutoff,),
        )
        connection.execute(
            """DELETE FROM relay_envelopes
            WHERE status IN ('delivered','failed','expired') AND created_at<?""",
            (cutoff,),
        )
        connection.execute(
            """DELETE FROM relay_exchanges
            WHERE status IN ('complete','expired') AND created_at<?
            AND NOT EXISTS (
                SELECT 1 FROM relay_envelopes e WHERE e.exchange_id=relay_exchanges.id
            )""",
            (cutoff,),
        )
        current_window = timestamp - (timestamp % RELAY_USAGE_WINDOW_SECONDS)
        connection.execute(
            "DELETE FROM relay_usage_windows WHERE window_start<?",
            (current_window - 2 * RELAY_USAGE_WINDOW_SECONDS,),
        )

    def configure_listener_identity(self, advertised_ip: str) -> None:
        """Ensure the TLS server leaf has the exact advertised literal IP SAN."""

        try:
            canonical = canonical_peer_ipv4(advertised_ip)
            address = ipaddress.IPv4Address(canonical)
        except ValueError as exc:
            raise ValueError("secure peer listener requires a literal IP") from exc
        with self._guard:
            try:
                sans = self._server_certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
                current = sans.get_values_for_type(x509.IPAddress)
            except x509.ExtensionNotFound:
                current = []
            now = datetime.now(timezone.utc)
            if (
                current == [address]
                and self._server_certificate.not_valid_after_utc
                > now + timedelta(days=30)
            ):
                return
            key = _load_private_key(self.server_key_path)
            subject = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, self.host_server_identity)]
            )
            certificate = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self._ca_certificate.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=825))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .add_extension(
                    x509.SubjectAlternativeName(
                        [
                            x509.IPAddress(address),
                            x509.UniformResourceIdentifier(
                                f"urn:agentsdock:server:{self.host_server_identity}"
                            ),
                        ]
                    ),
                    False,
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        self._ca_key.public_key()
                    ),
                    False,
                )
                .sign(self._ca_key, algorithm=None)
            )
            temporary = self.data_dir / f".server-certificate-{secrets.token_hex(8)}.tmp"
            create_secret_file(temporary, certificate.public_bytes(serialization.Encoding.PEM))
            os.replace(temporary, self.server_certificate_path)
            directory = os.open(self.data_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self._server_certificate = certificate

    def tls_server_context(self, advertised_ip: str) -> ssl.SSLContext:
        self.configure_listener_identity(advertised_ip)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_OPTIONAL
        context.load_cert_chain(self.server_certificate_path, self.server_key_path)
        context.load_verify_locations(cafile=self.ca_certificate_path)
        context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
        return context

    def public_health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "service": "agentsdock-secure-peer",
            "protocol_version": PROTOCOL_VERSION,
            "host_server_identity": self.host_server_identity,
            "hub_id": self.hub_id,
            "host_ca_fingerprint": self.ca_fingerprint,
            "pairing_available": True,
        }

    def cross_chat_consent_status(self) -> dict[str, Any]:
        return {
            "runtime_enabled": self._cross_chat_available(),
            "consent_epoch": self._cross_chat_epoch(),
        }

    def cross_chat_authorized(self, peer: PeerAuthorization) -> bool:
        if not self._cross_chat_available() or not any(
            scope.startswith("cross_chat.") for scope in peer.scopes
        ):
            return False
        try:
            epoch = self._cross_chat_epoch()
        except Exception:
            return False
        return epoch > 0 and peer.cross_chat_grant_epoch == epoch

    def activate_cross_chat_consent(
        self,
        *,
        expected_epoch: int,
        idempotency_key: str,
        activated_by: str,
    ) -> dict[str, Any]:
        """Start a fresh persisted consent epoch for newly approved peers.

        Rotating the epoch invalidates every earlier cross-chat peer grant and
        route.  It never upgrades an existing certificate in place.
        """

        if not self._cross_chat_available():
            raise SecurePeerError(
                "cross_chat_unavailable",
                "Secure cross-chat delivery is not enabled",
                409,
            )
        if type(expected_epoch) is not int or expected_epoch < 0:
            raise SecurePeerError("invalid_request", "expected_epoch is invalid", 422)
        actor = _identifier(activated_by, "activated_by")
        request = {
            "expected_epoch": expected_epoch,
            "activated_by": actor,
        }
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            digest, cached = self._operation(
                connection, "cross-chat-consent", idempotency_key, request
            )
            if cached is not None:
                connection.execute("COMMIT")
                return cached
            current = self._cross_chat_epoch(connection)
            if current != expected_epoch:
                raise SecurePeerError(
                    "cross_chat_consent_changed",
                    "Cross-chat consent epoch changed",
                    409,
                )
            next_epoch = current + 1
            if connection.execute(
                """UPDATE host_meta SET value=?
                WHERE key='cross_chat_consent_epoch' AND value=?""",
                (str(next_epoch), str(current)),
            ).rowcount != 1:
                raise SecurePeerError(
                    "cross_chat_consent_changed",
                    "Cross-chat consent epoch changed",
                    409,
                )
            revision = "rev_" + uuid.uuid4().hex
            connection.execute(
                """UPDATE peer_routes SET status='revoked',revision=?,revoked_at=?,updated_at=?
                WHERE status='active'""",
                (revision, timestamp, timestamp),
            )
            connection.execute(
                """UPDATE relay_envelopes SET status='expired',lease_owner=NULL,
                lease_token_hash=NULL,lease_expires_at=NULL
                WHERE status IN ('queued','claimed')"""
            )
            connection.execute(
                "UPDATE relay_exchanges SET status='expired' WHERE status='open'"
            )
            response = {
                "consent_epoch": next_epoch,
                "previous_epoch": current,
                "activated_at": timestamp,
            }
            self._record_operation(
                connection,
                "cross-chat-consent",
                idempotency_key,
                digest,
                response,
                timestamp,
            )
            self._audit(
                connection,
                timestamp,
                actor,
                "cross_chat.consent.activate",
                str(next_epoch),
                response,
            )
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _poll_token(self, pairing_id: str, request_digest: bytes) -> str:
        digest = hmac.new(
            self._poll_key,
            b"agentsdock-pair-poll-v1\0" + pairing_id.encode("ascii") + request_digest,
            hashlib.sha256,
        ).digest()
        return "pairpoll." + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    @staticmethod
    def _poll_hash(token: str) -> bytes:
        if not isinstance(token, str) or _POLL_TOKEN_RE.fullmatch(token) is None:
            hashlib.sha256(b"invalid-pair-poll").digest()
            raise SecurePeerError("pairing_unavailable", "Pairing is unavailable", 404)
        try:
            return hashlib.sha256(token.encode("ascii")).digest()
        except UnicodeEncodeError as exc:
            raise SecurePeerError("pairing_unavailable", "Pairing is unavailable", 404) from exc

    def _normalize_pairing_payload(
        self, payload: Any
    ) -> tuple[dict[str, Any], bytes, x509.CertificateSigningRequest]:
        value = _require_exact_keys(
            payload,
            {
                "protocol_version",
                "request_id",
                "created_at",
                "peer_server_identity",
                "peer_display_name",
                "peer_public_key_pem",
                "csr_pem",
                "nonce",
                "host_ca_fingerprint",
                "capabilities",
                "requested_scopes",
                "signature",
            },
            context="pairing request",
        )
        if type(value["protocol_version"]) is not int or value["protocol_version"] != PROTOCOL_VERSION:
            raise SecurePeerError("protocol_unsupported", "Pairing protocol is unsupported", 422)
        request_id = _uuid(value["request_id"], "request_id")
        if type(value["created_at"]) is not int:
            raise SecurePeerError("invalid_request", "created_at is invalid", 422)
        created_at = _now(value["created_at"])
        identity = _identifier(value["peer_server_identity"], "peer server identity")
        label = _bounded_text(value["peer_display_name"], "peer display name", 1, 160)
        host_fp = value["host_ca_fingerprint"]
        if not isinstance(host_fp, str) or not hmac.compare_digest(host_fp, self.ca_fingerprint):
            raise SecurePeerError("host_identity_mismatch", "Host identity does not match pairing request", 409)
        capabilities = value["capabilities"]
        if (
            not isinstance(capabilities, list)
            or any(not isinstance(item, str) for item in capabilities)
            or capabilities != sorted(set(capabilities))
            or not set(capabilities).issubset(CAPABILITIES)
        ):
            raise SecurePeerError("invalid_request", "capabilities are invalid", 422)
        requested_scopes = value["requested_scopes"]
        if not isinstance(requested_scopes, list):
            raise SecurePeerError("invalid_request", "requested_scopes are invalid", 422)
        canonical_requested_scopes = self._canonical_scopes(requested_scopes)
        if requested_scopes != canonical_requested_scopes:
            raise SecurePeerError("invalid_request", "requested_scopes must be canonical", 422)
        nonce = _decode_b64(value["nonce"], "nonce", 32, 32)
        public_pem = _bounded_pem(value["peer_public_key_pem"], "peer public key", 64, 4096)
        csr_pem = _bounded_pem(value["csr_pem"], "CSR", 128, 16384)
        try:
            public_key = serialization.load_pem_public_key(public_pem.encode("ascii"))
            csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise SecurePeerError("invalid_request", "Peer key or CSR is invalid", 422) from exc
        if not isinstance(public_key, Ed25519PublicKey) or not isinstance(csr.public_key(), Ed25519PublicKey):
            raise SecurePeerError("invalid_request", "Peer key and CSR must use Ed25519", 422)
        if not csr.is_signature_valid:
            raise SecurePeerError("invalid_request", "CSR proof of possession is invalid", 422)
        canonical_public = _public_key_pem(public_key)
        csr_public = _public_key_pem(csr.public_key())
        if canonical_public != public_pem or not hmac.compare_digest(canonical_public, csr_public):
            raise SecurePeerError("key_mismatch", "CSR does not match peer public key", 422)
        try:
            common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            uris = sans.get_values_for_type(x509.UniformResourceIdentifier)
        except x509.ExtensionNotFound as exc:
            raise SecurePeerError("invalid_request", "CSR identity is invalid", 422) from exc
        expected_uri = f"urn:agentsdock:server:{identity}"
        if len(common_names) != 1 or common_names[0].value != identity or uris != [expected_uri]:
            raise SecurePeerError("identity_mismatch", "CSR identity does not match request", 422)
        signature = _decode_b64(value["signature"], "signature", 64, 64)
        unsigned = {key: value[key] for key in value if key != "signature"}
        try:
            public_key.verify(signature, canonical_json(unsigned))
        except Exception as exc:
            raise SecurePeerError("signature_invalid", "Pairing signature is invalid", 422) from exc
        normalized = {
            **unsigned,
            "request_id": request_id,
            "created_at": created_at,
            "peer_server_identity": identity,
            "peer_display_name": label,
            "peer_public_key_pem": canonical_public,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "capabilities": capabilities,
            "requested_scopes": canonical_requested_scopes,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        return normalized, hashlib.sha256(canonical_json(normalized)).digest(), csr

    def _pairing_public(self, row: sqlite3.Row, *, include_poll: bool = False) -> dict[str, Any]:
        response: dict[str, Any] = {
            "pairing_id": row["id"],
            "status": row["status"],
            "expires_at": int(row["expires_at"]),
            "host_server_identity": self.host_server_identity,
            "hub_id": self.hub_id,
            "host_ca_certificate_pem": self.ca_certificate_pem,
            "host_ca_fingerprint": self.ca_fingerprint,
            "transcript_hash": row["transcript_hash"],
            "sas_words": json.loads(row["sas_json"]),
            "requested_scopes": json.loads(row["requested_scopes_json"]),
            "peer_public_key_fingerprint": _fingerprint(
                serialization.load_pem_public_key(
                    row["peer_public_key_pem"].encode("ascii")
                ).public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
        }
        if include_poll:
            response["poll_token"] = self._poll_token(row["id"], bytes(row["request_digest"]))
        if row["status"] == "approved":
            response.update(
                {
                    "peer_id": row["peer_id"],
                    "team_id": row["team_id"],
                    "scopes": json.loads(row["scopes_json"]),
                    "client_certificate_pem": row["client_certificate_pem"],
                }
            )
        elif row["status"] == "rejected":
            response["reason"] = row["rejection_reason"] or "Pairing request was rejected"
        return response

    @staticmethod
    def _expire_pending_pairings(
        connection: sqlite3.Connection,
        timestamp: int,
        *,
        pairing_id: str | None = None,
    ) -> int:
        arguments: list[Any] = [timestamp, timestamp]
        identity_clause = ""
        if pairing_id is not None:
            identity_clause = " AND id=?"
            arguments.append(pairing_id)
        return int(
            connection.execute(
                "UPDATE pairing_requests SET status='expired',decided_at=? "
                "WHERE status='pending' AND expires_at<=?" + identity_clause,
                arguments,
            ).rowcount
        )

    def submit_pairing(
        self,
        payload: Any,
        *,
        source_ip: str | None = None,
        source_port: int | None = None,
    ) -> dict[str, Any]:
        normalized, request_digest, _csr = self._normalize_pairing_payload(payload)
        source_endpoint: str | None = None
        if source_ip is not None:
            try:
                source_address = ipaddress.ip_address(source_ip)
            except ValueError as exc:
                raise SecurePeerError("invalid_request", "Pairing source address is invalid", 400) from exc
            source_ip = str(source_address)
            if type(source_port) is not int or not 1024 <= source_port <= 65535:
                raise SecurePeerError("invalid_request", "Pairing source endpoint is invalid", 400)
            source_endpoint = f"[{source_ip}]:{source_port}" if source_address.version == 6 else f"{source_ip}:{source_port}"
        timestamp = self._timestamp()
        expires_at = min(
            int(normalized["created_at"]) + PAIRING_TTL_SECONDS,
            timestamp + PAIRING_TTL_SECONDS,
        )
        transcript_value = {
            "protocol_version": PROTOCOL_VERSION,
            "request": {key: normalized[key] for key in normalized if key != "signature"},
            "host_server_identity": self.host_server_identity,
            "hub_id": self.hub_id,
            "host_ca_fingerprint": self.ca_fingerprint,
        }
        transcript_hash = hashlib.sha256(canonical_json(transcript_value)).hexdigest()
        pairing_id = _new_id("pair")
        poll_token = self._poll_token(pairing_id, request_digest)
        self._pairing_capacity_lock.acquire()
        try:
            connection = self._connect()
        except BaseException:
            self._pairing_capacity_lock.release()
            raise
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM pairing_requests WHERE request_id=?",
                (normalized["request_id"],),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(bytes(existing["request_digest"]), request_digest):
                    raise SecurePeerError("idempotency_conflict", "request_id was reused with different content", 409)
                if (
                    existing["status"] == "pending"
                    and int(existing["expires_at"]) <= timestamp
                ):
                    connection.execute(
                        """UPDATE pairing_requests SET status='expired',decided_at=?
                        WHERE id=? AND status='pending'""",
                        (timestamp, existing["id"]),
                    )
                    existing = connection.execute(
                        "SELECT * FROM pairing_requests WHERE id=?",
                        (existing["id"],),
                    ).fetchone()
                    assert existing is not None
                connection.execute("COMMIT")
                return self._pairing_public(existing, include_poll=True)
            if (
                int(normalized["created_at"]) < timestamp - 300
                or int(normalized["created_at"]) > timestamp + 300
            ):
                raise SecurePeerError(
                    "pairing_expired",
                    "Pairing request time is outside the allowed window",
                    410,
                )
            if expires_at <= timestamp:
                raise SecurePeerError("pairing_expired", "Pairing request has expired", 410)
            connection.execute(
                """UPDATE pairing_requests SET status='expired',decided_at=?
                WHERE status='pending' AND expires_at<=?""",
                (timestamp, timestamp),
            )
            connection.execute(
                """DELETE FROM pairing_requests WHERE status IN ('expired','rejected','cancelled')
                AND COALESCE(decided_at,expires_at)<?""",
                (timestamp - 7 * 24 * 60 * 60,),
            )
            terminal_count = int(
                connection.execute(
                    """SELECT COUNT(*) AS count FROM pairing_requests
                    WHERE status IN ('expired','rejected','cancelled')"""
                ).fetchone()["count"]
            )
            terminal_excess = terminal_count - PAIRING_TERMINAL_RETAINED_LIMIT
            if terminal_excess > 0:
                connection.execute(
                    """DELETE FROM pairing_requests WHERE id IN (
                    SELECT id FROM pairing_requests
                    WHERE status IN ('expired','rejected','cancelled')
                    ORDER BY COALESCE(decided_at,expires_at),created_at,id
                    LIMIT ?
                    )""",
                    (terminal_excess,),
                )
            self._prune_history(connection, timestamp)
            pending_count = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM pairing_requests WHERE status='pending'"
                ).fetchone()["count"]
            )
            actionable_count = self._actionable_pairing_count(connection)
            external_actionable_count = self._external_pairing_count()
            total_count = int(
                connection.execute("SELECT COUNT(*) AS count FROM pairing_requests").fetchone()["count"]
            )
            source_pending = (
                int(
                    connection.execute(
                        """SELECT COUNT(*) AS count FROM pairing_requests
                        WHERE status='pending' AND source_ip=?""",
                        (source_ip,),
                    ).fetchone()["count"]
                )
                if source_ip is not None
                else 0
            )
            if source_pending >= 16:
                raise SecurePeerError("rate_limited", "Too many pending pairings from this source", 429)
            if (
                pending_count >= PAIRING_STATUS_LIMIT
                or actionable_count + external_actionable_count
                >= PAIRING_STATUS_LIMIT
                or total_count >= 5_000
                or self._database_live_bytes(connection)
                >= SECURE_STATE_LIVE_BYTES_LIMIT
            ):
                raise SecurePeerError("pairing_capacity", "Pairing request capacity is temporarily full", 503)
            connection.execute(
                """INSERT INTO pairing_requests(
                    id,request_id,request_digest,request_json,poll_token_hash,
                    peer_server_identity,peer_display_name,peer_public_key_pem,csr_pem,
                    peer_nonce,requested_scopes_json,source_ip,source_endpoint,
                    transcript_hash,sas_json,status,created_at,expires_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    pairing_id,
                    normalized["request_id"],
                    request_digest,
                    canonical_json(normalized).decode("utf-8"),
                    self._poll_hash(poll_token),
                    normalized["peer_server_identity"],
                    normalized["peer_display_name"],
                    normalized["peer_public_key_pem"],
                    normalized["csr_pem"],
                    normalized["nonce"],
                    canonical_json(normalized["requested_scopes"]).decode("utf-8"),
                    source_ip,
                    source_endpoint,
                    transcript_hash,
                    canonical_json(list(sas_words(transcript_hash))).decode("utf-8"),
                    "pending",
                    timestamp,
                    expires_at,
                ),
            )
            self._audit(
                connection,
                timestamp,
                normalized["peer_server_identity"],
                "pairing.request",
                pairing_id,
                {"source_ip": source_ip},
            )
            row = connection.execute("SELECT * FROM pairing_requests WHERE id=?", (pairing_id,)).fetchone()
            connection.execute("COMMIT")
            assert row is not None
            return self._pairing_public(row, include_poll=True)
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
            self._pairing_capacity_lock.release()

    def _authenticated_pairing(
        self, connection: sqlite3.Connection, pairing_id: str, poll_token: str
    ) -> sqlite3.Row:
        if _PAIR_ID_RE.fullmatch(pairing_id) is None:
            raise SecurePeerError("pairing_unavailable", "Pairing is unavailable", 404)
        digest = self._poll_hash(poll_token)
        row = connection.execute("SELECT * FROM pairing_requests WHERE id=?", (pairing_id,)).fetchone()
        if row is None or not hmac.compare_digest(bytes(row["poll_token_hash"]), digest):
            raise SecurePeerError("pairing_unavailable", "Pairing is unavailable", 404)
        timestamp = self._timestamp()
        if row["status"] == "pending" and int(row["expires_at"]) <= timestamp:
            connection.execute(
                "UPDATE pairing_requests SET status='expired',decided_at=? WHERE id=? AND status='pending'",
                (timestamp, pairing_id),
            )
            row = connection.execute("SELECT * FROM pairing_requests WHERE id=?", (pairing_id,)).fetchone()
        assert row is not None
        return row

    def poll_pairing(self, pairing_id: str, poll_token: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = self._authenticated_pairing(connection, pairing_id, poll_token)
            return self._pairing_public(row)
        finally:
            connection.close()

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        realm: str,
        operation_id: str,
        request: Mapping[str, Any],
    ) -> tuple[bytes, dict[str, Any] | None]:
        canonical_id = _uuid(operation_id, "idempotency_key")
        digest = hashlib.sha256(canonical_json(dict(request))).digest()
        row = connection.execute(
            "SELECT request_digest,response_json FROM idempotency_records WHERE realm=? AND operation_id=?",
            (realm, canonical_id),
        ).fetchone()
        if row is None:
            return digest, None
        if not hmac.compare_digest(bytes(row["request_digest"]), digest):
            raise SecurePeerError("idempotency_conflict", "idempotency key was reused with different content", 409)
        return digest, json.loads(row["response_json"])

    @staticmethod
    def _record_operation(
        connection: sqlite3.Connection,
        realm: str,
        operation_id: str,
        digest: bytes,
        response: Mapping[str, Any],
        timestamp: int,
    ) -> None:
        connection.execute(
            "INSERT INTO idempotency_records(realm,operation_id,request_digest,response_json,created_at) VALUES (?,?,?,?,?)",
            (realm, operation_id, digest, canonical_json(dict(response)).decode("utf-8"), timestamp),
        )

    def cancel_pairing(
        self, pairing_id: str, poll_token: str, idempotency_key: str
    ) -> dict[str, Any]:
        timestamp = self._timestamp()
        request = {"pairing_id": pairing_id, "action": "cancel"}
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._authenticated_pairing(connection, pairing_id, poll_token)
            digest, cached = self._operation(
                connection, f"pairing-cancel:{pairing_id}", idempotency_key, request
            )
            if cached is not None:
                connection.execute("COMMIT")
                return cached
            if row["status"] != "pending":
                raise SecurePeerError("pairing_not_pending", "Pairing is no longer pending", 409)
            connection.execute(
                "UPDATE pairing_requests SET status='cancelled',decided_at=? WHERE id=? AND status='pending'",
                (timestamp, pairing_id),
            )
            response = {"pairing_id": pairing_id, "status": "cancelled"}
            self._record_operation(
                connection, f"pairing-cancel:{pairing_id}", idempotency_key, digest, response, timestamp
            )
            self._audit(connection, timestamp, row["peer_server_identity"], "pairing.cancel", pairing_id)
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def list_pairings(
        self, *, team_id: str | None = None, status: str | None = None
    ) -> list[dict[str, Any]]:
        if status not in {None, "pending", "approved", "rejected", "cancelled", "expired"}:
            raise ValueError("invalid pairing status")
        conditions: list[str] = []
        arguments: list[Any] = []
        if team_id is not None:
            conditions.append("(team_id=? OR (team_id IS NULL AND status='pending'))")
            arguments.append(_identifier(team_id, "team_id"))
        if status is not None:
            conditions.append("status=?")
            arguments.append(status)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._expire_pending_pairings(connection, self._timestamp())
            rows = connection.execute(
                "SELECT * FROM pairing_requests" + where + " ORDER BY created_at DESC,id DESC",
                arguments,
            ).fetchall()
            result = [
                {
                    "pairing_id": row["id"],
                    "peer_server_identity": row["peer_server_identity"],
                    "peer_display_name": row["peer_display_name"],
                    "transcript_hash": row["transcript_hash"],
                    "sas_words": json.loads(row["sas_json"]),
                    "status": row["status"],
                    "created_at": int(row["created_at"]),
                    "expires_at": int(row["expires_at"]),
                    "team_id": row["team_id"],
                    "scopes": json.loads(row["scopes_json"]) if row["scopes_json"] else [],
                    "requested_scopes": json.loads(row["requested_scopes_json"]),
                    "source_ip": row["source_ip"],
                    "source_endpoint": row["source_endpoint"],
                    "peer_public_key_fingerprint": _fingerprint(
                        serialization.load_pem_public_key(
                            row["peer_public_key_pem"].encode("ascii")
                        ).public_bytes(
                            serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                    ),
                }
                for row in rows
            ]
            connection.execute("COMMIT")
            return result
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _canonical_scopes(scopes: Iterable[str]) -> list[str]:
        values = list(scopes)
        if not values or any(not isinstance(item, str) for item in values):
            raise SecurePeerError("invalid_request", "scopes are invalid", 422)
        if len(values) != len(set(values)) or not set(values).issubset(SCOPES):
            raise SecurePeerError("invalid_request", "scopes are invalid", 422)
        return [item for item in SCOPE_ORDER if item in values]

    def _issue_client_certificate(
        self,
        *,
        csr: x509.CertificateSigningRequest,
        peer_id: str,
        pairing_id: str,
        peer_server_identity: str,
        team_id: str,
        scopes: list[str],
        transcript_hash: str,
        timestamp: int,
    ) -> tuple[x509.Certificate, dict[str, Any]]:
        binding = {
            "version": 1,
            "peer_id": peer_id,
            "pairing_id": pairing_id,
            "peer_server_identity": peer_server_identity,
            "team_id": team_id,
            "scopes": scopes,
            "transcript_hash": transcript_hash,
        }
        now = datetime.fromtimestamp(timestamp, timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._ca_certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=2))
            .not_valid_after(now + timedelta(seconds=CLIENT_CERT_TTL_SECONDS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, False)
            # OpenSSL rejects unknown critical extensions before the application
            # can validate them. The signed non-critical binding is mandatory
            # in authenticate_peer and is therefore still fail-closed.
            .add_extension(x509.UnrecognizedExtension(PEER_BINDING_OID, canonical_json(binding)), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()), False
            )
            .sign(self._ca_key, algorithm=None)
        )
        return certificate, binding

    def _revoke_peer_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        peer_id: str,
        timestamp: int,
        actor: str,
        action: str,
        detail: Mapping[str, Any] | None = None,
    ) -> bool:
        """Revoke every authority derived from one peer in the caller's transaction."""

        changed = connection.execute(
            """UPDATE peers SET status='revoked',revoked_at=?,revoked_by=?
            WHERE id=? AND status='active'""",
            (timestamp, actor, peer_id),
        ).rowcount
        if changed != 1:
            return False
        connection.execute(
            """UPDATE peer_certificates SET revoked_at=COALESCE(revoked_at,?),
            valid_until=CASE WHEN valid_until>? THEN ? ELSE valid_until END
            WHERE peer_id=?""",
            (timestamp, timestamp, timestamp, peer_id),
        )
        connection.execute(
            """UPDATE peer_routes SET status='revoked',revoked_at=?,updated_at=?,revision=?
            WHERE (peer_id=? OR audience_peer_id=?) AND status='active'""",
            (
                timestamp,
                timestamp,
                "rev_" + uuid.uuid4().hex,
                peer_id,
                peer_id,
            ),
        )
        connection.execute(
            """UPDATE relay_envelopes SET status='expired',lease_owner=NULL,
            lease_token_hash=NULL,lease_expires_at=NULL
            WHERE status IN ('queued','claimed') AND (
                source_peer_id=? OR target_peer_id=? OR
                source_route_id IN (
                    SELECT id FROM peer_routes
                    WHERE peer_id=? OR audience_peer_id=?
                ) OR target_route_id IN (
                    SELECT id FROM peer_routes
                    WHERE peer_id=? OR audience_peer_id=?
                )
            )""",
            (peer_id, peer_id, peer_id, peer_id, peer_id, peer_id),
        )
        self._audit(connection, timestamp, actor, action, peer_id, detail)
        return True

    def reconcile_active_logical_peers(
        self,
        preferred_peer_ids: Iterable[str],
        *,
        actor: str = "agentsserver-startup-reconciliation",
    ) -> dict[str, Any]:
        """Collapse duplicate active logical peers before enforcing uniqueness.

        A Hub-bound peer is authoritative when exactly one preferred peer is
        present in a duplicate group.  Corrupt input containing more than one
        preferred peer remains deterministic by retaining the oldest preferred
        record.  Without a preferred peer, the oldest record is retained.
        """

        if isinstance(preferred_peer_ids, (str, bytes)):
            raise SecurePeerError(
                "invalid_request", "preferred peer ids are invalid", 422
            )
        preferred = {
            _uuid(peer_id, "preferred_peer_id") for peer_id in preferred_peer_ids
        }
        canonical_actor = _identifier(actor, "reconciliation actor")
        timestamp = self._timestamp()
        retained_peer_ids: list[str] = []
        superseded_peer_ids: list[str] = []
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """SELECT id,team_id,peer_server_identity,created_at
                FROM peers WHERE status='active'
                ORDER BY team_id,peer_server_identity,created_at,id"""
            ).fetchall()
            groups: dict[tuple[str, str], list[sqlite3.Row]] = {}
            for row in rows:
                groups.setdefault(
                    (row["team_id"], row["peer_server_identity"]), []
                ).append(row)
            for members in groups.values():
                if len(members) == 1:
                    retained_peer_ids.append(members[0]["id"])
                    continue
                preferred_members = [
                    member for member in members if member["id"] in preferred
                ]
                retained = preferred_members[0] if preferred_members else members[0]
                retained_peer_ids.append(retained["id"])
                for member in members:
                    if member["id"] == retained["id"]:
                        continue
                    if self._revoke_peer_in_transaction(
                        connection,
                        peer_id=member["id"],
                        timestamp=timestamp,
                        actor=canonical_actor,
                        action="peer.supersede",
                        detail={
                            "reason": "duplicate_active_logical_peer",
                            "retained_peer_id": retained["id"],
                            "retained_peer_was_preferred": retained["id"]
                            in preferred,
                        },
                    ):
                        superseded_peer_ids.append(member["id"])
            connection.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS active_peer_logical_identity
                ON peers(team_id,peer_server_identity) WHERE status='active'"""
            )
            connection.execute("COMMIT")
            return {
                "retained_peer_ids": retained_peer_ids,
                "superseded_peer_ids": superseded_peer_ids,
            }
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def approve_pairing(
        self,
        pairing_id: str,
        team_id: str,
        scopes: Iterable[str],
        approved_by: str,
        *,
        expected_peer_server_identity: str,
        expected_transcript_hash: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        pairing_id = _uuid(pairing_id, "pairing_id")
        canonical_team = _identifier(team_id, "team_id")
        canonical_actor = _identifier(approved_by, "approved_by")
        expected_identity = _identifier(expected_peer_server_identity, "expected peer identity")
        if not isinstance(expected_transcript_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_transcript_hash) is None:
            raise SecurePeerError("invalid_request", "expected transcript hash is invalid", 422)
        canonical_scopes = self._canonical_scopes(scopes)
        has_cross_chat = any(
            scope.startswith("cross_chat.") for scope in canonical_scopes
        )
        request = {
            "pairing_id": pairing_id,
            "team_id": canonical_team,
            "scopes": canonical_scopes,
            "approved_by": canonical_actor,
            "expected_peer_server_identity": expected_identity,
            "expected_transcript_hash": expected_transcript_hash,
        }
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            digest, cached = self._operation(connection, "pairing-approve", idempotency_key, request)
            if cached is not None:
                connection.execute("COMMIT")
                return cached
            grant_epoch = (
                self._require_cross_chat(connection=connection)
                if has_cross_chat
                else None
            )
            row = connection.execute("SELECT * FROM pairing_requests WHERE id=?", (pairing_id,)).fetchone()
            if row is None:
                raise SecurePeerError("pairing_unavailable", "Pairing is unavailable", 404)
            if row["status"] == "pending" and int(row["expires_at"]) <= timestamp:
                self._expire_pending_pairings(
                    connection,
                    timestamp,
                    pairing_id=pairing_id,
                )
                connection.execute("COMMIT")
                raise SecurePeerError("pairing_not_pending", "Pairing is no longer pending", 409)
            if row["status"] != "pending":
                raise SecurePeerError("pairing_not_pending", "Pairing is no longer pending", 409)
            if row["peer_server_identity"] != expected_identity or not hmac.compare_digest(
                row["transcript_hash"], expected_transcript_hash
            ):
                raise SecurePeerError("pairing_changed", "Pairing identity confirmation failed", 409)
            if not set(canonical_scopes).issubset(set(json.loads(row["requested_scopes_json"]))):
                raise SecurePeerError("scope_escalation", "Approval scopes exceed the signed request", 409)
            csr = x509.load_pem_x509_csr(row["csr_pem"].encode("ascii"))
            peer_id = _new_id("peer")
            certificate, _binding = self._issue_client_certificate(
                csr=csr,
                peer_id=peer_id,
                pairing_id=pairing_id,
                peer_server_identity=row["peer_server_identity"],
                team_id=canonical_team,
                scopes=canonical_scopes,
                transcript_hash=row["transcript_hash"],
                timestamp=timestamp,
            )
            certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
            certificate_fp = _certificate_fingerprint(certificate)
            expires_at = int(certificate.not_valid_after_utc.timestamp())
            superseded_peer_ids: list[str] = []
            prior_peers = connection.execute(
                """SELECT id FROM peers WHERE team_id=? AND peer_server_identity=?
                AND status='active' ORDER BY created_at,id""",
                (canonical_team, row["peer_server_identity"]),
            ).fetchall()
            for prior_peer in prior_peers:
                if self._revoke_peer_in_transaction(
                    connection,
                    peer_id=prior_peer["id"],
                    timestamp=timestamp,
                    actor=canonical_actor,
                    action="peer.supersede",
                    detail={
                        "reason": "logical_peer_reapproved",
                        "successor_peer_id": peer_id,
                        "successor_pairing_id": pairing_id,
                    },
                ):
                    superseded_peer_ids.append(prior_peer["id"])
            connection.execute(
                """INSERT INTO peers(
                id,pairing_id,peer_server_identity,team_id,scopes_json,transcript_hash,
                public_key_pem,status,cross_chat_grant_epoch,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    peer_id,
                    pairing_id,
                    row["peer_server_identity"],
                    canonical_team,
                    canonical_json(canonical_scopes).decode("utf-8"),
                    row["transcript_hash"],
                    row["peer_public_key_pem"],
                    "active",
                    grant_epoch,
                    timestamp,
                ),
            )
            connection.execute(
                "INSERT INTO peer_certificates(fingerprint,peer_id,serial,certificate_pem,public_key_pem,issued_at,expires_at,valid_until) VALUES (?,?,?,?,?,?,?,?)",
                (
                    certificate_fp,
                    peer_id,
                    format(certificate.serial_number, "x"),
                    certificate_pem,
                    row["peer_public_key_pem"],
                    timestamp,
                    expires_at,
                    expires_at,
                ),
            )
            connection.execute(
                "UPDATE pairing_requests SET status='approved',decided_at=?,team_id=?,scopes_json=?,approved_by=?,client_certificate_pem=?,peer_id=? WHERE id=? AND status='pending'",
                (
                    timestamp,
                    canonical_team,
                    canonical_json(canonical_scopes).decode("utf-8"),
                    canonical_actor,
                    certificate_pem,
                    peer_id,
                    pairing_id,
                ),
            )
            response = {
                "pairing_id": pairing_id,
                "status": "approved",
                "peer_id": peer_id,
                "team_id": canonical_team,
                "scopes": canonical_scopes,
                "certificate_fingerprint": certificate_fp,
                "certificate_expires_at": expires_at,
                "cross_chat_grant_epoch": grant_epoch,
                "superseded_peer_ids": superseded_peer_ids,
            }
            self._record_operation(connection, "pairing-approve", idempotency_key, digest, response, timestamp)
            self._audit(connection, timestamp, canonical_actor, "pairing.approve", pairing_id, response)
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def reject_pairing(
        self,
        pairing_id: str,
        rejected_by: str,
        reason: str,
        *,
        expected_peer_server_identity: str,
        expected_transcript_hash: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        pairing_id = _uuid(pairing_id, "pairing_id")
        actor = _identifier(rejected_by, "rejected_by")
        expected_identity = _identifier(expected_peer_server_identity, "expected peer identity")
        if (
            not isinstance(expected_transcript_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_transcript_hash) is None
        ):
            raise SecurePeerError(
                "invalid_request", "expected transcript hash is invalid", 422
            )
        clean_reason = _bounded_text(reason, "reason", 1, 160)
        request = {
            "pairing_id": pairing_id,
            "rejected_by": actor,
            "reason": clean_reason,
            "expected_peer_server_identity": expected_identity,
            "expected_transcript_hash": expected_transcript_hash,
        }
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            digest, cached = self._operation(connection, "pairing-reject", idempotency_key, request)
            if cached is not None:
                connection.execute("COMMIT")
                return cached
            row = connection.execute("SELECT * FROM pairing_requests WHERE id=?", (pairing_id,)).fetchone()
            if row is None:
                raise SecurePeerError("pairing_unavailable", "Pairing is unavailable", 404)
            if row["status"] == "pending" and int(row["expires_at"]) <= timestamp:
                self._expire_pending_pairings(
                    connection,
                    timestamp,
                    pairing_id=pairing_id,
                )
                connection.execute("COMMIT")
                raise SecurePeerError("pairing_not_pending", "Pairing is no longer pending", 409)
            if row["status"] != "pending":
                raise SecurePeerError("pairing_not_pending", "Pairing is no longer pending", 409)
            if row["peer_server_identity"] != expected_identity or not hmac.compare_digest(
                row["transcript_hash"], expected_transcript_hash
            ):
                raise SecurePeerError("pairing_changed", "Pairing identity confirmation failed", 409)
            connection.execute(
                "UPDATE pairing_requests SET status='rejected',decided_at=?,approved_by=?,rejection_reason=? WHERE id=? AND status='pending'",
                (timestamp, actor, clean_reason, pairing_id),
            )
            response = {"pairing_id": pairing_id, "status": "rejected"}
            self._record_operation(connection, "pairing-reject", idempotency_key, digest, response, timestamp)
            self._audit(connection, timestamp, actor, "pairing.reject", pairing_id, {"reason": clean_reason})
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def list_peers(self, *, team_id: str | None = None) -> list[dict[str, Any]]:
        arguments: tuple[Any, ...] = ()
        where = ""
        if team_id is not None:
            where = " WHERE p.team_id=?"
            arguments = (_identifier(team_id, "team_id"),)
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT p.*,q.peer_display_name,c.fingerprint,
                c.expires_at AS certificate_expires_at
                FROM peers p
                JOIN pairing_requests q ON q.id=p.pairing_id
                JOIN peer_certificates c ON c.peer_id=p.id
                WHERE c.superseded_at IS NULL AND c.activation_required=0"""
                + (" AND p.team_id=?" if where else "")
                + " ORDER BY p.created_at DESC,p.id DESC",
                arguments,
            ).fetchall()
            return [
                {
                    "peer_id": row["id"],
                    "pairing_id": row["pairing_id"],
                    "peer_server_identity": row["peer_server_identity"],
                    "peer_display_name": row["peer_display_name"],
                    "team_id": row["team_id"],
                    "scopes": json.loads(row["scopes_json"]),
                    "status": row["status"],
                    "certificate_fingerprint": row["fingerprint"],
                    "certificate_expires_at": int(row["certificate_expires_at"]),
                    "cross_chat_grant_epoch": row["cross_chat_grant_epoch"],
                    "last_seen_at": (
                        int(row["last_seen_at"])
                        if row["last_seen_at"] is not None
                        else None
                    ),
                    "lease_expires_at": (
                        int(row["lease_expires_at"])
                        if row["lease_expires_at"] is not None
                        else None
                    ),
                    "revoked_at": row["revoked_at"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def record_peer_heartbeat(self, peer_id: str) -> dict[str, Any]:
        """Extend an active peer lease while coalescing rapid health checks."""

        canonical_peer_id = _uuid(peer_id, "peer_id")
        timestamp = self._timestamp()

        def snapshot(row: sqlite3.Row) -> tuple[int | None, int | None]:
            return (
                int(row["last_seen_at"])
                if row["last_seen_at"] is not None
                else None,
                int(row["lease_expires_at"])
                if row["lease_expires_at"] is not None
                else None,
            )

        def write_due(last_seen_at: int | None, lease_expires_at: int | None) -> bool:
            return (
                last_seen_at is None
                or lease_expires_at is None
                or lease_expires_at <= timestamp
                or timestamp - last_seen_at >= PEER_HEARTBEAT_COALESCE_SECONDS
            )

        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT status,last_seen_at,lease_expires_at FROM peers
                WHERE id=?""",
                (canonical_peer_id,),
            ).fetchone()
            if row is None:
                raise SecurePeerError("peer_unavailable", "Peer is unavailable", 404)
            if row["status"] != "active":
                raise SecurePeerError(
                    "peer_revoked", "Peer authentication is unavailable", 401
                )
            last_seen_at, lease_expires_at = snapshot(row)
            if not write_due(last_seen_at, lease_expires_at):
                return {
                    "peer_id": canonical_peer_id,
                    "last_seen_at": last_seen_at,
                    "lease_expires_at": lease_expires_at,
                    "recorded": False,
                }

            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT status,last_seen_at,lease_expires_at FROM peers
                WHERE id=?""",
                (canonical_peer_id,),
            ).fetchone()
            if row is None:
                raise SecurePeerError("peer_unavailable", "Peer is unavailable", 404)
            if row["status"] != "active":
                raise SecurePeerError(
                    "peer_revoked", "Peer authentication is unavailable", 401
                )
            last_seen_at, lease_expires_at = snapshot(row)
            if write_due(last_seen_at, lease_expires_at):
                last_seen_at = timestamp
                lease_expires_at = timestamp + PEER_HEARTBEAT_LEASE_SECONDS
                if connection.execute(
                    """UPDATE peers SET last_seen_at=?,lease_expires_at=?
                    WHERE id=? AND status='active'""",
                    (last_seen_at, lease_expires_at, canonical_peer_id),
                ).rowcount != 1:
                    raise SecurePeerError(
                        "peer_revoked", "Peer authentication is unavailable", 401
                    )
                recorded = True
            else:
                recorded = False
            connection.execute("COMMIT")
            return {
                "peer_id": canonical_peer_id,
                "last_seen_at": last_seen_at,
                "lease_expires_at": lease_expires_at,
                "recorded": recorded,
            }
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def authenticate_peer(
        self, certificate_der: bytes, *, allow_pending_renewal: bool = False
    ) -> PeerAuthorization:
        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
            self._ca_certificate.public_key().verify(
                certificate.signature, certificate.tbs_certificate_bytes
            )
            eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in eku or ExtendedKeyUsageOID.SERVER_AUTH in eku:
                raise ValueError("wrong certificate purpose")
            binding_raw = certificate.extensions.get_extension_for_oid(PEER_BINDING_OID).value.value
            binding = json.loads(binding_raw)
        except Exception as exc:
            raise SecurePeerError("peer_authentication_required", "Peer authentication is required", 401) from exc
        timestamp = self._timestamp()
        if not certificate.not_valid_before_utc.timestamp() <= timestamp < certificate.not_valid_after_utc.timestamp():
            raise SecurePeerError("peer_authentication_required", "Peer authentication is required", 401)
        fingerprint = _certificate_fingerprint(certificate)
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT p.*,q.peer_display_name,c.fingerprint,c.valid_until,c.expires_at,
                c.activation_required,
                c.revoked_at AS cert_revoked_at FROM peer_certificates c
                JOIN peers p ON p.id=c.peer_id JOIN pairing_requests q ON q.id=p.pairing_id
                WHERE c.fingerprint=?""",
                (fingerprint,),
            ).fetchone()
            if (
                row is None
                or row["status"] != "active"
                or row["cert_revoked_at"] is not None
                or int(row["valid_until"]) <= timestamp
                or (int(row["activation_required"]) != 0 and not allow_pending_renewal)
            ):
                raise SecurePeerError("peer_revoked", "Peer authentication is unavailable", 401)
            expected = {
                "version": 1,
                "peer_id": row["id"],
                "pairing_id": row["pairing_id"],
                "peer_server_identity": row["peer_server_identity"],
                "team_id": row["team_id"],
                "scopes": json.loads(row["scopes_json"]),
                "transcript_hash": row["transcript_hash"],
            }
            if binding != expected:
                raise SecurePeerError("peer_authentication_required", "Peer authentication is required", 401)
            return PeerAuthorization(
                row["id"], row["pairing_id"], row["peer_server_identity"], row["team_id"],
                frozenset(expected["scopes"]), fingerprint, int(row["expires_at"]),
                row["peer_display_name"], row["cross_chat_grant_epoch"],
            )
        finally:
            connection.close()

    def authorize_peer_self_revocation(
        self,
        certificate_der: bytes,
    ) -> PeerAuthorization:
        """Authenticate a certificate only for revoking its logical peer.

        A client can lose the renewal-activation response after the host has
        already promoted a successor certificate.  The presented certificate
        can therefore be superseded (or belong to an already-revoked peer),
        but it must still be a currently valid certificate issued by this CA
        with an exact signed binding to the same durable peer.  This authority
        is used only by ``/v1/peer/revoke`` and cannot access any other route.
        """

        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
            self._ca_certificate.public_key().verify(
                certificate.signature, certificate.tbs_certificate_bytes
            )
            eku = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            if (
                ExtendedKeyUsageOID.CLIENT_AUTH not in eku
                or ExtendedKeyUsageOID.SERVER_AUTH in eku
            ):
                raise ValueError("wrong certificate purpose")
            binding_raw = certificate.extensions.get_extension_for_oid(
                PEER_BINDING_OID
            ).value.value
            binding = json.loads(binding_raw)
        except Exception as exc:
            raise SecurePeerError(
                "peer_authentication_required",
                "Peer authentication is required",
                401,
            ) from exc
        timestamp = self._timestamp()
        if not (
            certificate.not_valid_before_utc.timestamp()
            <= timestamp
            < certificate.not_valid_after_utc.timestamp()
        ):
            raise SecurePeerError(
                "peer_authentication_required",
                "Peer authentication is required",
                401,
            )
        fingerprint = _certificate_fingerprint(certificate)
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT p.*,q.peer_display_name,c.fingerprint,c.expires_at
                FROM peer_certificates c
                JOIN peers p ON p.id=c.peer_id
                JOIN pairing_requests q ON q.id=p.pairing_id
                WHERE c.fingerprint=?""",
                (fingerprint,),
            ).fetchone()
            if row is None:
                raise SecurePeerError(
                    "peer_authentication_required",
                    "Peer authentication is required",
                    401,
                )
            expected = {
                "version": 1,
                "peer_id": row["id"],
                "pairing_id": row["pairing_id"],
                "peer_server_identity": row["peer_server_identity"],
                "team_id": row["team_id"],
                "scopes": json.loads(row["scopes_json"]),
                "transcript_hash": row["transcript_hash"],
            }
            if binding != expected:
                raise SecurePeerError(
                    "peer_authentication_required",
                    "Peer authentication is required",
                    401,
                )
            return PeerAuthorization(
                row["id"],
                row["pairing_id"],
                row["peer_server_identity"],
                row["team_id"],
                frozenset(expected["scopes"]),
                fingerprint,
                int(row["expires_at"]),
                row["peer_display_name"],
                row["cross_chat_grant_epoch"],
            )
        finally:
            connection.close()

    def revoke_peer_for_self(
        self,
        peer: PeerAuthorization,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Atomically revoke a logical peer from any certificate it owns."""

        operation_id = _uuid(idempotency_key, "idempotency_key")
        request = {
            "peer_id": peer.peer_id,
            "team_id": peer.team_id,
            "presented_certificate_fingerprint": peer.certificate_fingerprint,
        }
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            digest, cached = self._operation(
                connection,
                "peer-self-revoke",
                operation_id,
                request,
            )
            if cached is not None:
                connection.execute("COMMIT")
                return cached
            row = connection.execute(
                """SELECT p.id,p.team_id,p.status,p.revoked_at,c.fingerprint
                FROM peers p JOIN peer_certificates c ON c.peer_id=p.id
                WHERE p.id=? AND c.fingerprint=?""",
                (peer.peer_id, peer.certificate_fingerprint),
            ).fetchone()
            if (
                row is None
                or row["team_id"] != peer.team_id
                or row["status"] not in {"active", "revoked"}
                or not hmac.compare_digest(
                    row["fingerprint"], peer.certificate_fingerprint
                )
            ):
                raise SecurePeerError(
                    "peer_changed",
                    "Peer certificate confirmation failed",
                    409,
                )
            revoked_at = (
                int(row["revoked_at"])
                if row["revoked_at"] is not None
                else timestamp
            )
            if row["status"] == "active":
                if not self._revoke_peer_in_transaction(
                    connection,
                    peer_id=peer.peer_id,
                    timestamp=timestamp,
                    actor=f"peer:{peer.peer_id}",
                    action="peer.self_revoke",
                    detail={
                        "presented_certificate_fingerprint": (
                            peer.certificate_fingerprint
                        )
                    },
                ):
                    raise SecurePeerError(
                        "peer_changed",
                        "Peer certificate confirmation failed",
                        409,
                    )
                revoked_at = timestamp
            response = {
                "peer_id": peer.peer_id,
                "status": "revoked",
                "revoked_at": revoked_at,
                "idempotency_key": operation_id,
                "presented_certificate_fingerprint": (
                    peer.certificate_fingerprint
                ),
            }
            self._record_operation(
                connection,
                "peer-self-revoke",
                operation_id,
                digest,
                response,
                timestamp,
            )
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def peer_revocation_status(
        self,
        peer: PeerAuthorization,
    ) -> dict[str, Any]:
        """Return exact logical trust state to one certificate it owns."""

        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT p.id,p.team_id,p.status,p.revoked_at,c.fingerprint
                FROM peers p JOIN peer_certificates c ON c.peer_id=p.id
                WHERE p.id=? AND c.fingerprint=?""",
                (peer.peer_id, peer.certificate_fingerprint),
            ).fetchone()
            if (
                row is None
                or row["team_id"] != peer.team_id
                or row["status"] not in {"active", "revoked"}
                or not hmac.compare_digest(
                    row["fingerprint"], peer.certificate_fingerprint
                )
            ):
                raise SecurePeerError(
                    "peer_changed",
                    "Peer certificate confirmation failed",
                    409,
                )
            return {
                "peer_id": peer.peer_id,
                "status": str(row["status"]),
                "revoked_at": (
                    int(row["revoked_at"])
                    if row["revoked_at"] is not None
                    else None
                ),
                "presented_certificate_fingerprint": (
                    peer.certificate_fingerprint
                ),
            }
        finally:
            connection.close()

    def revoke_peer(
        self,
        peer_id: str,
        team_id: str,
        expected_certificate_fingerprint: str,
        idempotency_key: str,
        revoked_by: str,
    ) -> dict[str, Any]:
        peer_id = _uuid(peer_id, "peer_id")
        if (
            not isinstance(expected_certificate_fingerprint, str)
            or _HEX_FP_RE.fullmatch(expected_certificate_fingerprint) is None
        ):
            raise SecurePeerError("invalid_request", "peer revocation target is invalid", 422)
        canonical_team = _identifier(team_id, "team_id")
        actor = _identifier(revoked_by, "revoked_by")
        request = {
            "peer_id": peer_id,
            "team_id": canonical_team,
            "expected_certificate_fingerprint": expected_certificate_fingerprint,
            "revoked_by": actor,
        }
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            digest, cached = self._operation(connection, "peer-revoke", idempotency_key, request)
            if cached is not None:
                connection.execute("COMMIT")
                return cached
            row = connection.execute(
                """SELECT p.*,c.fingerprint FROM peers p JOIN peer_certificates c ON c.peer_id=p.id
                WHERE p.id=? AND c.fingerprint=? AND c.superseded_at IS NULL
                AND c.activation_required=0""",
                (peer_id, expected_certificate_fingerprint),
            ).fetchone()
            if row is None or row["team_id"] != canonical_team:
                raise SecurePeerError("peer_unavailable", "Peer is unavailable", 404)
            if row["status"] != "active" or not hmac.compare_digest(
                row["fingerprint"], expected_certificate_fingerprint
            ):
                raise SecurePeerError("peer_changed", "Peer certificate confirmation failed", 409)
            if not self._revoke_peer_in_transaction(
                connection,
                peer_id=peer_id,
                timestamp=timestamp,
                actor=actor,
                action="peer.revoke",
            ):
                raise SecurePeerError(
                    "peer_changed", "Peer certificate confirmation failed", 409
                )
            response = {"peer_id": peer_id, "status": "revoked", "revoked_at": timestamp}
            self._record_operation(connection, "peer-revoke", idempotency_key, digest, response, timestamp)
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def renew_peer(self, peer: PeerAuthorization, payload: Any) -> dict[str, Any]:
        value = _require_exact_keys(
            payload,
            {"request_id", "created_at", "peer_public_key_pem", "csr_pem", "nonce", "signature"},
            context="renewal request",
        )
        request_id = _uuid(value["request_id"], "request_id")
        if type(value["created_at"]) is not int:
            raise SecurePeerError("invalid_request", "created_at is invalid", 422)
        timestamp = self._timestamp()
        _decode_b64(value["nonce"], "nonce", 32, 32)
        public_pem = _bounded_pem(value["peer_public_key_pem"], "peer public key", 64, 4096)
        csr_pem = _bounded_pem(value["csr_pem"], "CSR", 128, 16384)
        try:
            public_key = serialization.load_pem_public_key(public_pem.encode("ascii"))
            csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise SecurePeerError("invalid_request", "Renewal key or CSR is invalid", 422) from exc
        if (
            not isinstance(public_key, Ed25519PublicKey)
            or not isinstance(csr.public_key(), Ed25519PublicKey)
            or not csr.is_signature_valid
            or _public_key_pem(public_key) != public_pem
            or _public_key_pem(csr.public_key()) != public_pem
        ):
            raise SecurePeerError("key_mismatch", "Renewal CSR does not match peer key", 422)
        unsigned = {key: value[key] for key in value if key != "signature"}
        signature = _decode_b64(value["signature"], "signature", 64, 64)
        try:
            public_key.verify(signature, canonical_json(unsigned))
        except Exception as exc:
            raise SecurePeerError("signature_invalid", "Renewal signature is invalid", 422) from exc
        try:
            common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            uris = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.UniformResourceIdentifier
            )
        except x509.ExtensionNotFound as exc:
            raise SecurePeerError("identity_mismatch", "Renewal CSR identity is invalid", 422) from exc
        if (
            len(common_names) != 1
            or common_names[0].value != peer.peer_server_identity
            or uris != [f"urn:agentsdock:server:{peer.peer_server_identity}"]
        ):
            raise SecurePeerError("identity_mismatch", "Renewal CSR identity does not match peer", 422)
        normalized = {
            **unsigned,
            "peer_public_key_pem": public_pem,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            digest = hashlib.sha256(canonical_json(normalized)).digest()
            existing = connection.execute(
                "SELECT * FROM renewal_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["peer_id"] != peer.peer_id
                    or not hmac.compare_digest(bytes(existing["request_digest"]), digest)
                ):
                    raise SecurePeerError(
                        "idempotency_conflict",
                        "renewal request_id was reused with different content",
                        409,
                    )
                if int(existing["expires_at"]) <= timestamp:
                    raise SecurePeerError("renewal_expired", "Renewal request has expired", 410)
                connection.execute("COMMIT")
                return json.loads(existing["response_json"])
            if abs(timestamp - int(value["created_at"])) > 300:
                raise SecurePeerError(
                    "renewal_expired",
                    "Renewal request time is outside the allowed window",
                    410,
                )
            current = connection.execute(
                """SELECT p.*,c.expires_at,c.fingerprint FROM peers p
                JOIN peer_certificates c ON c.peer_id=p.id WHERE p.id=? AND c.fingerprint=?
                AND c.revoked_at IS NULL AND c.superseded_at IS NULL AND c.activation_required=0""",
                (peer.peer_id, peer.certificate_fingerprint),
            ).fetchone()
            if current is None or current["status"] != "active":
                raise SecurePeerError("peer_revoked", "Peer authentication is unavailable", 401)
            if int(current["expires_at"]) - timestamp > CLIENT_CERT_RENEW_WINDOW_SECONDS:
                raise SecurePeerError("renewal_not_due", "Client certificate renewal is not due", 409)
            pending = connection.execute(
                """SELECT 1 FROM renewal_requests WHERE peer_id=? AND current_fingerprint=?
                AND status='issued' AND expires_at>?""",
                (peer.peer_id, peer.certificate_fingerprint, timestamp),
            ).fetchone()
            if pending is not None:
                raise SecurePeerError("renewal_pending", "A certificate renewal is already pending", 409)
            scopes = json.loads(current["scopes_json"])
            certificate, _binding = self._issue_client_certificate(
                csr=csr,
                peer_id=peer.peer_id,
                pairing_id=current["pairing_id"],
                peer_server_identity=current["peer_server_identity"],
                team_id=current["team_id"],
                scopes=scopes,
                transcript_hash=current["transcript_hash"],
                timestamp=timestamp,
            )
            pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
            fingerprint = _certificate_fingerprint(certificate)
            expires_at = int(certificate.not_valid_after_utc.timestamp())
            connection.execute(
                """INSERT INTO peer_certificates(
                fingerprint,peer_id,serial,certificate_pem,public_key_pem,issued_at,
                expires_at,valid_until,activation_required
                ) VALUES (?,?,?,?,?,?,?,?,1)""",
                (
                    fingerprint,
                    peer.peer_id,
                    format(certificate.serial_number, "x"),
                    pem,
                    public_pem,
                    timestamp,
                    expires_at,
                    expires_at,
                ),
            )
            response = {
                "peer_id": peer.peer_id,
                "request_id": request_id,
                "client_certificate_pem": pem,
                "certificate_fingerprint": fingerprint,
                "certificate_expires_at": expires_at,
                "activation_required": True,
            }
            connection.execute(
                """INSERT INTO renewal_requests(
                request_id,peer_id,current_fingerprint,new_fingerprint,request_digest,response_json,
                status,created_at,expires_at
                ) VALUES (?,?,?,?,?,?,'issued',?,?)""",
                (
                    request_id,
                    peer.peer_id,
                    current["fingerprint"],
                    fingerprint,
                    digest,
                    canonical_json(response).decode("utf-8"),
                    timestamp,
                    timestamp + RENEWAL_REQUEST_TTL_SECONDS,
                ),
            )
            self._audit(connection, timestamp, peer.peer_id, "peer.certificate.renew.issue", fingerprint)
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def activate_renewal(
        self, peer: PeerAuthorization, request_id: str
    ) -> dict[str, Any]:
        renewal_id = _uuid(request_id, "request_id")
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM renewal_requests WHERE request_id=? AND peer_id=?",
                (renewal_id, peer.peer_id),
            ).fetchone()
            if row is None or row["new_fingerprint"] != peer.certificate_fingerprint:
                raise SecurePeerError("renewal_unavailable", "Certificate renewal is unavailable", 404)
            if row["status"] == "activated":
                connection.execute("COMMIT")
                return {
                    "peer_id": peer.peer_id,
                    "request_id": renewal_id,
                    "certificate_fingerprint": row["new_fingerprint"],
                    "activated": True,
                }
            if int(row["expires_at"]) <= timestamp:
                raise SecurePeerError("renewal_expired", "Certificate renewal has expired", 410)
            old = connection.execute(
                """SELECT expires_at FROM peer_certificates WHERE fingerprint=? AND peer_id=?
                AND superseded_at IS NULL AND revoked_at IS NULL AND activation_required=0""",
                (row["current_fingerprint"], peer.peer_id),
            ).fetchone()
            new = connection.execute(
                """SELECT public_key_pem FROM peer_certificates WHERE fingerprint=? AND peer_id=?
                AND revoked_at IS NULL AND activation_required=1""",
                (row["new_fingerprint"], peer.peer_id),
            ).fetchone()
            if old is None or new is None:
                raise SecurePeerError("renewal_conflict", "Certificate renewal state changed", 409)
            overlap_until = min(int(old["expires_at"]), timestamp + CLIENT_CERT_OVERLAP_SECONDS)
            if connection.execute(
                """UPDATE peer_certificates SET superseded_at=?,valid_until=? WHERE fingerprint=?
                AND peer_id=? AND superseded_at IS NULL AND revoked_at IS NULL AND activation_required=0""",
                (timestamp, overlap_until, row["current_fingerprint"], peer.peer_id),
            ).rowcount != 1:
                raise SecurePeerError("renewal_conflict", "Certificate renewal state changed", 409)
            if connection.execute(
                """UPDATE peer_certificates SET activation_required=0 WHERE fingerprint=?
                AND peer_id=? AND activation_required=1 AND revoked_at IS NULL""",
                (row["new_fingerprint"], peer.peer_id),
            ).rowcount != 1:
                raise SecurePeerError("renewal_conflict", "Certificate renewal state changed", 409)
            connection.execute(
                "UPDATE peers SET public_key_pem=? WHERE id=? AND status='active'",
                (new["public_key_pem"], peer.peer_id),
            )
            connection.execute(
                "UPDATE renewal_requests SET status='activated',activated_at=? WHERE request_id=? AND status='issued'",
                (timestamp, renewal_id),
            )
            # Retain the current activation and a small replay window without
            # allowing successful renewals to grow this ledger forever.
            connection.execute(
                """DELETE FROM renewal_requests WHERE request_id IN (
                SELECT request_id FROM renewal_requests
                WHERE peer_id=? AND status='activated' AND request_id<>?
                ORDER BY activated_at DESC,request_id DESC
                LIMIT -1 OFFSET ?
                )""",
                (
                    peer.peer_id,
                    renewal_id,
                    ACTIVATED_RENEWAL_HISTORY_LIMIT - 1,
                ),
            )
            response = {
                "peer_id": peer.peer_id,
                "request_id": renewal_id,
                "certificate_fingerprint": row["new_fingerprint"],
                "activated": True,
                "old_certificate_valid_until": overlap_until,
            }
            self._audit(connection, timestamp, peer.peer_id, "peer.certificate.renew.activate", row["new_fingerprint"])
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _relay_scope(peer: PeerAuthorization, kind: str) -> None:
        required = (
            "cross_chat.instruction"
            if kind == "instruction"
            else "cross_chat.request_reply"
        )
        if required not in peer.scopes:
            raise SecurePeerError("forbidden", "Peer scope does not permit this relay", 403)

    @staticmethod
    def _route_public(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "route_id": row["id"],
            "peer_server_identity": row["server_identity"],
            "target_kind": row["target_kind"],
            "team_id": row["team_id"],
            "revision": row["revision"],
            "alias": row["alias"],
            "display_title": row["display_title"],
            "actions": json.loads(row["actions_json"]),
            "status": row["status"],
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
            "revoked_at": row["revoked_at"],
        }

    @staticmethod
    def _route_descriptor(
        route_id: Any,
        revision: Any,
        alias: Any,
        display_title: Any,
        actions: Any,
    ) -> tuple[str, str, str, str, list[str]]:
        route = _uuid(route_id, "route_id")
        if not isinstance(revision, str) or re.fullmatch(r"rev_[0-9a-f]{32}", revision) is None:
            raise SecurePeerError("invalid_request", "route revision is invalid", 422)
        if not isinstance(alias, str) or re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", alias) is None:
            raise SecurePeerError("invalid_request", "route alias is invalid", 422)
        title = _bounded_text(display_title, "display_title", 1, 160)
        if not isinstance(actions, list) or not actions or len(actions) != len(set(actions)):
            raise SecurePeerError("invalid_request", "route actions are invalid", 422)
        selected = set(actions)
        if not selected.issubset({"instruction", "request_reply"}):
            raise SecurePeerError("invalid_request", "route actions are invalid", 422)
        canonical_actions = [item for item in ("instruction", "request_reply") if item in selected]
        return route, revision, alias, title, canonical_actions

    def list_routes(
        self,
        team_id: str,
        *,
        target_kind: str | None = None,
        peer_id: str | None = None,
        include_revoked: bool = False,
    ) -> list[dict[str, Any]]:
        self._require_cross_chat()
        team = _identifier(team_id, "team_id")
        if target_kind not in {None, "host", "peer"}:
            raise ValueError("target_kind is invalid")
        conditions = ["team_id=?"]
        arguments: list[Any] = [team]
        if target_kind is not None:
            conditions.append("target_kind=?")
            arguments.append(target_kind)
        if peer_id is not None:
            conditions.append("peer_id=?")
            arguments.append(_uuid(peer_id, "peer_id"))
        if not include_revoked:
            conditions.append("status='active'")
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM peer_routes WHERE " + " AND ".join(conditions) + " ORDER BY alias,id",
                arguments,
            ).fetchall()
            return [self._route_public(row) for row in rows]
        finally:
            connection.close()

    def list_remote_routes(self, peer: PeerAuthorization) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            self._require_cross_chat(peer, connection=connection)
            rows = connection.execute(
                """SELECT * FROM peer_routes WHERE team_id=? AND target_kind='host'
                AND audience_peer_id=? AND status='active' ORDER BY alias,id""",
                (peer.team_id, peer.peer_id),
            ).fetchall()
            return [self._route_public(row) for row in rows]
        finally:
            connection.close()

    def list_local_routes(
        self,
        peer_id: str | None = None,
        *,
        include_revoked: bool = True,
    ) -> list[dict[str, Any]]:
        """Return owner-local chat grants, including the private chat target.

        This projection is for the loopback control plane only.  ``chat_id``
        is intentionally absent from every mTLS route-catalog response.
        """

        self._require_cross_chat()
        conditions = ["r.target_kind='host'"]
        arguments: list[Any] = []
        if peer_id is not None:
            conditions.append("r.audience_peer_id=?")
            arguments.append(_uuid(peer_id, "peer_id"))
        if not include_revoked:
            conditions.append("r.status='active'")
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT r.*,p.peer_server_identity AS audience_server_identity,
                q.peer_display_name AS audience_display_name
                FROM peer_routes r
                JOIN peers p ON p.id=r.audience_peer_id
                JOIN pairing_requests q ON q.id=p.pairing_id
                WHERE """
                + " AND ".join(conditions)
                + " ORDER BY r.team_id,r.alias,r.id",
                arguments,
            ).fetchall()
            return [
                {
                    **self._route_public(row),
                    "audience_peer_id": row["audience_peer_id"],
                    "audience_peer_server_identity": row["audience_server_identity"],
                    "audience_peer_display_name": row["audience_display_name"],
                    "chat_id": row["chat_id"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def retire_agent_routes_locally(self) -> int:
        """Atomically retire host routes and every nonterminal relay record."""

        timestamp = self._timestamp()
        with self._guard:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                active_route_ids = [
                    str(row["id"])
                    for row in connection.execute(
                        "SELECT id FROM peer_routes WHERE status='active' ORDER BY id"
                    ).fetchall()
                ]
                for route_id in active_route_ids:
                    connection.execute(
                        """UPDATE peer_routes SET status='revoked',revision=?,
                        revoked_at=?,updated_at=? WHERE id=? AND status='active'""",
                        (
                            "rev_" + uuid.uuid4().hex,
                            timestamp,
                            timestamp,
                            route_id,
                        ),
                    )
                connection.execute(
                    """UPDATE relay_envelopes SET status='expired',
                    lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL
                    WHERE status IN ('queued','claimed')"""
                )
                connection.execute(
                    """UPDATE relay_exchanges SET status='expired'
                    WHERE status='open'"""
                )
                connection.execute("COMMIT")
                return len(active_route_ids)
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()

    def list_remote_routes_for_peer(
        self,
        peer_id: str,
        *,
        include_revoked: bool = True,
    ) -> list[dict[str, Any]]:
        """Return the routes one authenticated peer published to this host."""

        self._require_cross_chat()
        canonical_peer = _uuid(peer_id, "peer_id")
        conditions = ["r.target_kind='peer'", "r.peer_id=?"]
        arguments: list[Any] = [canonical_peer]
        if not include_revoked:
            conditions.append("r.status='active'")
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT r.*,q.peer_display_name FROM peer_routes r
                JOIN peers p ON p.id=r.peer_id
                JOIN pairing_requests q ON q.id=p.pairing_id
                WHERE """
                + " AND ".join(conditions)
                + " ORDER BY r.team_id,r.alias,r.id",
                arguments,
            ).fetchall()
            return [
                {
                    **self._route_public(row),
                    "peer_id": row["peer_id"],
                    "peer_display_name": row["peer_display_name"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def publish_local_route(
        self,
        team_id: str,
        audience_peer_id: str,
        chat_id: str,
        alias: str,
        display_title: str,
        actions: list[str],
        *,
        idempotency_key: str,
        published_by: str,
    ) -> dict[str, Any]:
        self._require_cross_chat()
        team = _identifier(team_id, "team_id")
        audience = _uuid(audience_peer_id, "audience_peer_id")
        local_chat = _identifier(chat_id, "chat_id")
        actor = _identifier(published_by, "published_by")
        route_id = str(uuid.uuid4())
        revision = "rev_" + uuid.uuid4().hex
        route_id, revision, alias, title, canonical_actions = self._route_descriptor(
            route_id, revision, alias, display_title, actions
        )
        request = {
            "team_id": team,
            "audience_peer_id": audience,
            "chat_id": local_chat,
            "alias": alias,
            "display_title": title,
            "actions": canonical_actions,
            "published_by": actor,
        }
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current_epoch = self._require_cross_chat(connection=connection)
            digest, cached = self._operation(connection, "local-route-publish", idempotency_key, request)
            if cached is not None:
                connection.execute("COMMIT")
                return cached
            self._prune_history(connection, timestamp)
            peer_row = connection.execute(
                """SELECT p.scopes_json,p.cross_chat_grant_epoch,
                p.peer_server_identity,q.peer_display_name
                FROM peers p JOIN pairing_requests q ON q.id=p.pairing_id
                WHERE p.id=? AND p.team_id=? AND p.status='active'""", (audience, team)
            ).fetchone()
            if peer_row is None:
                raise SecurePeerError("peer_unavailable", "Route audience peer is unavailable", 404)
            if peer_row["cross_chat_grant_epoch"] != current_epoch:
                raise SecurePeerError(
                    "cross_chat_reapproval_required",
                    "Route audience peer requires fresh cross-chat approval",
                    403,
                )
            duplicate = connection.execute(
                """SELECT id FROM peer_routes WHERE target_kind='host'
                AND status='active' AND team_id=? AND audience_peer_id=?
                AND (chat_id=? OR alias=?) LIMIT 1""",
                (team, audience, local_chat, alias),
            ).fetchone()
            if duplicate is not None:
                raise SecurePeerError(
                    "route_conflict",
                    "This peer already has a route for that chat or alias",
                    409,
                )
            peer_scopes = frozenset(json.loads(peer_row["scopes_json"]))
            for action in canonical_actions:
                self._relay_scope(
                    PeerAuthorization(audience, "", "peer-route", team, peer_scopes, "", 0, "peer"),
                    action,
                )
            audience_active = int(
                connection.execute(
                    """SELECT COUNT(*) AS count FROM peer_routes
                    WHERE audience_peer_id=? AND status='active'""",
                    (audience,),
                ).fetchone()["count"]
            )
            audience_total = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM peer_routes WHERE audience_peer_id=?",
                    (audience,),
                ).fetchone()["count"]
            )
            global_total = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM peer_routes"
                ).fetchone()["count"]
            )
            if (
                audience_active >= ROUTE_ACTIVE_PER_PEER_LIMIT
                or audience_total >= ROUTE_TOTAL_PER_PEER_LIMIT
                or global_total >= ROUTE_GLOBAL_LIMIT
                or self._database_live_bytes(connection)
                >= SECURE_STATE_LIVE_BYTES_LIMIT
            ):
                raise SecurePeerError(
                    "route_capacity", "Secure route capacity is full", 503
                )
            connection.execute(
                """INSERT INTO peer_routes(
                id,server_identity,target_kind,peer_id,audience_peer_id,team_id,revision,
                alias,display_title,actions_json,chat_id,status,created_at,updated_at
                ) VALUES (?,?,'host',NULL,?,?,?,?,?,?,?,'active',?,?)""",
                (
                    route_id,
                    self.host_server_identity,
                    audience,
                    team,
                    revision,
                    alias,
                    title,
                    canonical_json(canonical_actions).decode("utf-8"),
                    local_chat,
                    timestamp,
                    timestamp,
                ),
            )
            current = connection.execute("SELECT * FROM peer_routes WHERE id=?", (route_id,)).fetchone()
            assert current is not None
            response = {
                **self._route_public(current),
                "audience_peer_id": audience,
                "audience_peer_server_identity": peer_row[
                    "peer_server_identity"
                ],
                "audience_peer_display_name": peer_row["peer_display_name"],
                "chat_id": local_chat,
            }
            self._record_operation(connection, "local-route-publish", idempotency_key, digest, response, timestamp)
            self._audit(connection, timestamp, actor, "route.publish", route_id, response)
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def publish_peer_route(self, peer: PeerAuthorization, payload: Any) -> dict[str, Any]:
        self._require_cross_chat(peer)
        value = _require_exact_keys(
            payload,
            {"route_id", "revision", "alias", "display_title", "actions"},
            context="peer route",
        )
        route_id, revision, alias, title, actions = self._route_descriptor(
            value["route_id"], value["revision"], value["alias"], value["display_title"], value["actions"]
        )
        for action in actions:
            self._relay_scope(peer, action)
        request = {"route_id": route_id, "revision": revision, "alias": alias, "display_title": title, "actions": actions}
        digest = hashlib.sha256(canonical_json(request)).digest()
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_cross_chat(peer, connection=connection)
            existing = connection.execute("SELECT * FROM peer_routes WHERE id=?", (route_id,)).fetchone()
            if existing is not None:
                existing_request = {
                    "route_id": existing["id"], "revision": existing["revision"],
                    "alias": existing["alias"], "display_title": existing["display_title"],
                    "actions": json.loads(existing["actions_json"]),
                }
                if (
                    existing["peer_id"] != peer.peer_id
                    or not hmac.compare_digest(hashlib.sha256(canonical_json(existing_request)).digest(), digest)
                ):
                    raise SecurePeerError("idempotency_conflict", "route_id was reused with different content", 409)
                connection.execute("COMMIT")
                return self._route_public(existing)
            self._prune_history(connection, timestamp)
            peer_active = int(
                connection.execute(
                    """SELECT COUNT(*) AS count FROM peer_routes
                    WHERE peer_id=? AND status='active'""",
                    (peer.peer_id,),
                ).fetchone()["count"]
            )
            peer_total = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM peer_routes WHERE peer_id=?",
                    (peer.peer_id,),
                ).fetchone()["count"]
            )
            global_total = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM peer_routes"
                ).fetchone()["count"]
            )
            if (
                peer_active >= ROUTE_ACTIVE_PER_PEER_LIMIT
                or peer_total >= ROUTE_TOTAL_PER_PEER_LIMIT
                or global_total >= ROUTE_GLOBAL_LIMIT
                or self._database_live_bytes(connection)
                >= SECURE_STATE_LIVE_BYTES_LIMIT
            ):
                raise SecurePeerError(
                    "route_capacity", "Secure route capacity is full", 503
                )
            connection.execute(
                """INSERT INTO peer_routes(
                id,server_identity,target_kind,peer_id,audience_peer_id,team_id,revision,
                alias,display_title,actions_json,chat_id,status,created_at,updated_at
                ) VALUES (?,?,'peer',?,NULL,?,?,?,?,?,NULL,'active',?,?)""",
                (
                    route_id, peer.peer_server_identity, peer.peer_id, peer.team_id,
                    revision, alias, title, canonical_json(actions).decode("utf-8"), timestamp, timestamp,
                ),
            )
            current = connection.execute("SELECT * FROM peer_routes WHERE id=?", (route_id,)).fetchone()
            assert current is not None
            response = self._route_public(current)
            self._audit(connection, timestamp, peer.peer_id, "route.publish", route_id, response)
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def revoke_route(
        self,
        route_id: str,
        team_id: str,
        *,
        expected_revision: str,
        idempotency_key: str,
        revoked_by: str,
    ) -> dict[str, Any]:
        self._require_cross_chat()
        route = _uuid(route_id, "route_id")
        team = _identifier(team_id, "team_id")
        actor = _identifier(revoked_by, "revoked_by")
        if not isinstance(expected_revision, str) or re.fullmatch(r"rev_[0-9a-f]{32}", expected_revision) is None:
            raise SecurePeerError("invalid_request", "expected route revision is invalid", 422)
        request = {"route_id": route, "team_id": team, "expected_revision": expected_revision, "revoked_by": actor}
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_cross_chat(connection=connection)
            digest, cached = self._operation(connection, "local-route-revoke", idempotency_key, request)
            if cached is not None:
                connection.execute("COMMIT")
                return cached
            next_revision = "rev_" + uuid.uuid4().hex
            changed = connection.execute(
                """UPDATE peer_routes SET revision=?,status='revoked',revoked_at=?,updated_at=?
                WHERE id=? AND team_id=? AND revision=? AND status='active'""",
                (next_revision, timestamp, timestamp, route, team, expected_revision),
            ).rowcount
            if changed != 1:
                raise SecurePeerError("route_changed", "Local route is unavailable or changed", 409)
            connection.execute(
                """UPDATE relay_exchanges SET status='expired'
                WHERE status='open' AND id IN (
                    SELECT exchange_id FROM relay_envelopes
                    WHERE source_route_id=? OR target_route_id=?
                )""",
                (route, route),
            )
            connection.execute(
                """UPDATE relay_envelopes SET status='expired',lease_owner=NULL,
                lease_token_hash=NULL,lease_expires_at=NULL
                WHERE status IN ('queued','claimed')
                AND (source_route_id=? OR target_route_id=?)""",
                (route, route),
            )
            row = connection.execute("SELECT * FROM peer_routes WHERE id=?", (route,)).fetchone()
            assert row is not None
            response = self._route_public(row)
            self._record_operation(connection, "local-route-revoke", idempotency_key, digest, response, timestamp)
            self._audit(connection, timestamp, actor, "route.revoke", route, response)
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def revoke_peer_route(
        self,
        peer: PeerAuthorization,
        route_id: str,
        expected_revision: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require_cross_chat(peer)
        route = _uuid(route_id, "route_id")
        if not isinstance(expected_revision, str) or re.fullmatch(r"rev_[0-9a-f]{32}", expected_revision) is None:
            raise SecurePeerError("invalid_request", "expected route revision is invalid", 422)
        request = {"route_id": route, "expected_revision": expected_revision, "peer_id": peer.peer_id}
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_cross_chat(peer, connection=connection)
            digest, cached = self._operation(
                connection, f"peer-route-revoke:{peer.peer_id}", idempotency_key, request
            )
            if cached is not None:
                connection.execute("COMMIT")
                return cached
            next_revision = "rev_" + uuid.uuid4().hex
            changed = connection.execute(
                """UPDATE peer_routes SET revision=?,status='revoked',revoked_at=?,updated_at=?
                WHERE id=? AND peer_id=? AND team_id=? AND revision=? AND status='active'""",
                (next_revision, timestamp, timestamp, route, peer.peer_id, peer.team_id, expected_revision),
            ).rowcount
            if changed != 1:
                raise SecurePeerError("route_changed", "Peer route is unavailable or changed", 409)
            connection.execute(
                """UPDATE relay_exchanges SET status='expired'
                WHERE status='open' AND id IN (
                    SELECT exchange_id FROM relay_envelopes
                    WHERE source_route_id=? OR target_route_id=?
                )""",
                (route, route),
            )
            connection.execute(
                """UPDATE relay_envelopes SET status='expired',lease_owner=NULL,
                lease_token_hash=NULL,lease_expires_at=NULL
                WHERE status IN ('queued','claimed')
                AND (source_route_id=? OR target_route_id=?)""",
                (route, route),
            )
            row = connection.execute("SELECT * FROM peer_routes WHERE id=?", (route,)).fetchone()
            assert row is not None
            response = self._route_public(row)
            self._record_operation(
                connection, f"peer-route-revoke:{peer.peer_id}", idempotency_key, digest, response, timestamp
            )
            self._audit(connection, timestamp, peer.peer_id, "route.revoke", route, response)
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def submit_envelope(
        self,
        peer: PeerAuthorization,
        payload: Any,
        *,
        _source_route_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_cross_chat(peer)
        value = _require_exact_keys(
            payload,
            {
                "request_id",
                "source_route_id",
                "target_route_id",
                "target_route_revision",
                "kind",
                "exchange_id",
                "parent_envelope_id",
                "expires_at",
                "body",
            },
            context="relay envelope",
        )
        request_id = _uuid(value["request_id"], "request_id")
        source_route_id = _uuid(value["source_route_id"], "source_route_id")
        if _source_route_id is not None and source_route_id != _source_route_id:
            raise SecurePeerError("route_unavailable", "Source route does not match local authorization", 409)
        target_route_id = _uuid(value["target_route_id"], "target_route_id")
        kind = value["kind"]
        if kind not in {"instruction", "request_reply", "response"}:
            raise SecurePeerError("invalid_request", "relay kind is invalid", 422)
        self._relay_scope(peer, kind)
        route_revision = value["target_route_revision"]
        if not isinstance(route_revision, str) or re.fullmatch(r"rev_[0-9a-f]{32}", route_revision) is None:
            raise SecurePeerError("invalid_request", "target route revision is invalid", 422)
        exchange_id_input = value["exchange_id"]
        parent_id_input = value["parent_envelope_id"]
        if exchange_id_input is not None:
            exchange_id_input = _uuid(exchange_id_input, "exchange_id")
        if parent_id_input is not None:
            parent_id_input = _uuid(parent_id_input, "parent_envelope_id")
        timestamp = self._timestamp()
        if type(value["expires_at"]) is not int or not timestamp < value["expires_at"] <= timestamp + MAX_RELAY_TTL_SECONDS:
            raise SecurePeerError("invalid_request", "expires_at is outside the 72 hour bound", 422)
        if (
            not isinstance(value["body"], dict)
            or set(value["body"]) != {"message"}
            or not isinstance(value["body"].get("message"), str)
            or not value["body"]["message"].strip()
            or len(value["body"]["message"]) > 100_000
        ):
            raise SecurePeerError(
                "invalid_request",
                "relay body must contain exactly one bounded message",
                422,
            )
        normalized = {
            **value,
            "request_id": request_id,
            "source_route_id": source_route_id,
            "target_route_id": target_route_id,
            "exchange_id": exchange_id_input,
            "parent_envelope_id": parent_id_input,
        }
        encoded = canonical_json(normalized)
        if len(encoded) > MAX_PROXY_BODY_BYTES:
            raise SecurePeerError("request_too_large", "Relay envelope is too large", 413)
        digest = hashlib.sha256(encoded).digest()
        envelope_id = _new_id("env")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current_epoch = self._require_cross_chat(peer, connection=connection)
            self._prune_relay_state(connection, timestamp)
            self._prune_history(connection, timestamp)
            if _source_route_id is None:
                source_route = connection.execute(
                    """SELECT * FROM peer_routes WHERE peer_id=? AND team_id=?
                    AND id=? AND target_kind='peer' AND status='active'""",
                    (peer.peer_id, peer.team_id, source_route_id),
                ).fetchone()
            else:
                source_route = connection.execute(
                    """SELECT * FROM peer_routes WHERE id=? AND team_id=?
                    AND target_kind='host' AND status='active'""",
                    (_source_route_id, peer.team_id),
                ).fetchone()
            if source_route is None:
                raise SecurePeerError("route_unavailable", "Source route is unavailable", 409)
            existing = connection.execute(
                "SELECT * FROM relay_envelopes WHERE source_route_id=? AND request_id=?",
                (source_route["id"], request_id),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(bytes(existing["request_digest"]), digest):
                    raise SecurePeerError("idempotency_conflict", "request_id was reused with different content", 409)
                connection.execute("COMMIT")
                return {
                    "envelope_id": existing["id"],
                    "status": existing["status"],
                    "used_legs": int(existing["used_legs"]),
                    "max_legs": MAX_RELAY_LEGS,
                    "expires_at": int(existing["expires_at"]),
                    "exchange_id": existing["exchange_id"],
                }
            active_global = int(
                connection.execute(
                    """SELECT COUNT(*) AS count FROM relay_envelopes
                    WHERE status IN ('queued','claimed')"""
                ).fetchone()["count"]
            )
            active_for_peer = 0
            retained_for_peer = 0
            usage_submissions = 0
            usage_body_bytes = 0
            usage_window = timestamp - (timestamp % RELAY_USAGE_WINDOW_SECONDS)
            message_bytes = len(value["body"]["message"].encode("utf-8"))
            if peer.peer_id:
                active_for_peer = int(
                    connection.execute(
                        """SELECT COUNT(*) AS count FROM relay_envelopes
                        WHERE source_peer_id=? AND status IN ('queued','claimed')""",
                        (peer.peer_id,),
                    ).fetchone()["count"]
                )
                retained_for_peer = int(
                    connection.execute(
                        """SELECT COUNT(*) AS count FROM relay_envelopes
                        WHERE source_peer_id=?""",
                        (peer.peer_id,),
                    ).fetchone()["count"]
                )
                usage = connection.execute(
                    """SELECT submissions,body_bytes FROM relay_usage_windows
                    WHERE peer_id=? AND window_start=?""",
                    (peer.peer_id, usage_window),
                ).fetchone()
                if usage is not None:
                    usage_submissions = int(usage["submissions"])
                    usage_body_bytes = int(usage["body_bytes"])
            if (
                active_for_peer >= RELAY_ACTIVE_PER_PEER_LIMIT
                or active_global >= RELAY_ACTIVE_GLOBAL_LIMIT
                or self._database_live_bytes(connection)
                >= SECURE_STATE_LIVE_BYTES_LIMIT
            ):
                raise SecurePeerError(
                    "relay_capacity", "Secure relay capacity is full", 503
                )
            if peer.peer_id and (
                retained_for_peer >= RELAY_RETAINED_PER_PEER_LIMIT
                or usage_submissions >= RELAY_SUBMISSIONS_PER_PEER_WINDOW_LIMIT
                or usage_body_bytes + message_bytes
                > RELAY_BYTES_PER_PEER_WINDOW_LIMIT
            ):
                raise SecurePeerError(
                    "rate_limited",
                    "Secure relay limit for this peer is temporarily full",
                    429,
                )
            route = connection.execute(
                """SELECT r.*,p.status AS peer_status,p.scopes_json,
                p.cross_chat_grant_epoch,
                (SELECT c.expires_at FROM peer_certificates c
                 WHERE c.peer_id=p.id AND c.superseded_at IS NULL
                 AND c.activation_required=0 AND c.revoked_at IS NULL
                 LIMIT 1) AS peer_certificate_expires_at
                FROM peer_routes r LEFT JOIN peers p ON p.id=r.peer_id WHERE r.id=?""",
                (target_route_id,),
            ).fetchone()
            if (
                route is None
                or route["team_id"] != peer.team_id
                or (route["target_kind"] == "peer" and route["peer_status"] != "active")
                or (
                    route["target_kind"] == "peer"
                    and int(route["peer_certificate_expires_at"] or 0)
                    <= timestamp + 60
                )
                or route["status"] != "active"
                or route["revision"] != route_revision
                or (
                    route["target_kind"] == "peer"
                    and route["cross_chat_grant_epoch"] != current_epoch
                )
            ):
                raise SecurePeerError("route_unavailable", "Target route is unavailable or changed", 409)
            target = route["server_identity"]
            if (
                source_route["target_kind"] == "peer"
                and (
                    route["target_kind"] != "host"
                    or route["audience_peer_id"] != peer.peer_id
                )
            ) or (
                source_route["target_kind"] == "host"
                and (
                    route["target_kind"] != "peer"
                    or source_route["audience_peer_id"] != route["peer_id"]
                )
            ):
                raise SecurePeerError("route_unavailable", "Routes are not paired for delivery", 409)
            required_action = "instruction" if kind == "instruction" else "request_reply"
            if required_action not in json.loads(source_route["actions_json"]):
                raise SecurePeerError(
                    "route_action_forbidden",
                    "Source route does not grant this action",
                    403,
                )
            if required_action not in json.loads(route["actions_json"]):
                raise SecurePeerError("route_action_forbidden", "Target route does not allow this action", 403)
            if route["target_kind"] == "peer":
                target_scopes = frozenset(json.loads(route["scopes_json"]))
                self._relay_scope(
                    PeerAuthorization(
                        route["peer_id"], "", target, route["team_id"], target_scopes, "", 0, target
                    ),
                    kind,
                )

            if exchange_id_input is None:
                if parent_id_input is not None or kind == "response":
                    raise SecurePeerError("invalid_request", "Initial relay leg is invalid", 422)
                exchange_id = str(uuid.uuid4())
                used_legs = 1
                parent_leg = None
                exchange_expires = int(value["expires_at"])
                connection.execute(
                    """INSERT INTO relay_exchanges(
                    id,team_id,first_route_id,second_route_id,used_legs,max_legs,created_at,expires_at,status
                    ) VALUES (?,?,?,?,?,6,?,?,'open')""",
                    (
                        exchange_id,
                        peer.team_id,
                        source_route["id"],
                        route["id"],
                        used_legs,
                        timestamp,
                        exchange_expires,
                    ),
                )
            else:
                if parent_id_input is None:
                    raise SecurePeerError("invalid_request", "Relay continuation requires its parent envelope", 422)
                exchange = connection.execute(
                    "SELECT * FROM relay_exchanges WHERE id=?",
                    (exchange_id_input,),
                ).fetchone()
                parent = connection.execute(
                    "SELECT * FROM relay_envelopes WHERE id=? AND exchange_id=?",
                    (parent_id_input, exchange_id_input),
                ).fetchone()
                if (
                    exchange is None
                    or parent is None
                    or exchange["status"] != "open"
                    or exchange["last_envelope_id"] != parent_id_input
                    or parent["target_route_id"] != source_route["id"]
                    or parent["source_route_id"] != route["id"]
                    or parent["target_route_revision"] != source_route["revision"]
                    or parent["source_route_revision"] != route["revision"]
                    or parent["kind"] != "request_reply"
                    or int(exchange["expires_at"]) <= timestamp
                    or int(value["expires_at"]) != int(exchange["expires_at"])
                ):
                    raise SecurePeerError("exchange_changed", "Relay exchange state changed", 409)
                exchange_id = exchange_id_input
                used_legs = int(exchange["used_legs"]) + 1
                parent_leg = int(parent["used_legs"])
                exchange_expires = int(exchange["expires_at"])
                if used_legs > MAX_RELAY_LEGS:
                    raise SecurePeerError("leg_budget_exhausted", "Relay exchange leg budget is exhausted", 409)
                if kind == "instruction":
                    raise SecurePeerError("invalid_request", "Relay continuation must be a response", 422)
                if kind == "request_reply" and MAX_RELAY_LEGS - used_legs < 1:
                    raise SecurePeerError("leg_budget_exhausted", "Follow-up requires one terminal response slot", 409)
            if peer.peer_id:
                connection.execute(
                    """INSERT INTO relay_usage_windows(
                    peer_id,window_start,submissions,body_bytes
                    ) VALUES (?,?,1,?)
                    ON CONFLICT(peer_id,window_start) DO UPDATE SET
                    submissions=submissions+1,body_bytes=body_bytes+excluded.body_bytes""",
                    (peer.peer_id, usage_window, message_bytes),
                )
            connection.execute(
                """INSERT INTO relay_envelopes(
                    id,request_id,source_peer_id,source_route_id,source_server_identity,
                    source_route_revision,request_digest,target_server_identity,target_route_id,target_peer_id,
                    target_route_revision,kind,exchange_id,parent_envelope_id,
                    parent_leg,max_legs,used_legs,body_json,created_at,expires_at,status
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'queued')""",
                (
                    envelope_id,
                    request_id,
                    peer.peer_id or None,
                    source_route["id"],
                    source_route["server_identity"],
                    source_route["revision"],
                    digest,
                    target,
                    route["id"],
                    route["peer_id"],
                    route_revision,
                    kind,
                    exchange_id,
                    parent_id_input,
                    parent_leg,
                    MAX_RELAY_LEGS,
                    used_legs,
                    canonical_json(value["body"]).decode("utf-8"),
                    timestamp,
                    exchange_expires,
                ),
            )
            terminal = kind in {"instruction", "response"}
            changed = connection.execute(
                """UPDATE relay_exchanges SET last_envelope_id=?,used_legs=?,status=?
                WHERE id=? AND used_legs=? AND status='open'""",
                (
                    envelope_id,
                    used_legs,
                    "complete" if terminal else "open",
                    exchange_id,
                    used_legs - 1 if used_legs > 1 else 1,
                ),
            ).rowcount
            # For a freshly inserted first-leg exchange used_legs is already 1.
            if changed != 1:
                raise SecurePeerError("exchange_changed", "Relay exchange state changed", 409)
            self._audit(connection, timestamp, peer.peer_id or source_route["id"], "relay.submit", envelope_id, {"target": target})
            connection.execute("COMMIT")
            return {
                "envelope_id": envelope_id,
                "status": "queued",
                "used_legs": used_legs,
                "max_legs": MAX_RELAY_LEGS,
                "expires_at": exchange_expires,
                "exchange_id": exchange_id,
            }
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def submit_local_envelope(
        self,
        team_id: str,
        source_route_id: str,
        payload: Any,
    ) -> dict[str, Any]:
        team = _identifier(team_id, "team_id")
        route = _uuid(source_route_id, "source_route_id")
        local = PeerAuthorization(
            "",
            "",
            self.host_server_identity,
            team,
            frozenset({"cross_chat.instruction", "cross_chat.request_reply"}),
            "",
            2**63 - 1,
            self.host_server_identity,
        )
        return self.submit_envelope(local, payload, _source_route_id=route)

    def claim_inbox(
        self,
        peer: PeerAuthorization,
        lease_owner: str,
        *,
        limit: int = 20,
        _target_route_id: str | None = None,
        _target_peer_id: str | None = None,
        _all_local: bool = False,
    ) -> dict[str, Any]:
        self._require_cross_chat(peer)
        if sum(
            (
                _target_route_id is not None,
                _target_peer_id is not None,
                bool(_all_local),
            )
        ) > 1:
            raise ValueError("only one local inbox selector is permitted")
        owner = _identifier(lease_owner, "lease_owner")
        bounded = int(limit)
        if not 1 <= bounded <= 50:
            raise SecurePeerError("invalid_request", "limit is invalid", 422)
        timestamp = self._timestamp()
        lease_token = "lease." + secrets.token_urlsafe(32)
        lease_digest = hashlib.sha256(lease_token.encode("ascii")).digest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_cross_chat(peer, connection=connection)
            self._prune_relay_state(connection, timestamp)
            connection.execute(
                "UPDATE relay_envelopes SET status='queued',lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL WHERE status='claimed' AND lease_expires_at<=? AND expires_at>?",
                (timestamp, timestamp),
            )
            if (
                _target_route_id is None
                and _target_peer_id is None
                and not _all_local
            ):
                rows = connection.execute(
                    """SELECT e.*,s.actions_json AS source_actions_json,
                    r.actions_json AS target_actions_json,
                    r.team_id AS envelope_team_id
                    FROM relay_envelopes e
                    JOIN peer_routes r ON r.id=e.target_route_id
                    JOIN peer_routes s ON s.id=e.source_route_id
                    WHERE r.peer_id=? AND r.server_identity=? AND r.team_id=?
                    AND r.target_kind='peer' AND r.status='active'
                    AND e.target_route_revision=r.revision
                    AND s.target_kind='host' AND s.status='active'
                    AND s.audience_peer_id=r.peer_id AND s.team_id=r.team_id
                    AND s.server_identity=e.source_server_identity
                    AND e.source_route_revision=s.revision AND e.status='queued'
                    ORDER BY e.created_at,e.id LIMIT ?""",
                    (peer.peer_id, peer.peer_server_identity, peer.team_id, bounded),
                ).fetchall()
            elif _target_route_id is not None:
                route = connection.execute(
                    """SELECT * FROM peer_routes WHERE id=? AND server_identity=?
                    AND team_id=? AND target_kind='host' AND status='active'""",
                    (_target_route_id, peer.peer_server_identity, peer.team_id),
                ).fetchone()
                if route is None:
                    raise SecurePeerError("route_unavailable", "Receive route is unavailable", 409)
                rows = connection.execute(
                    """SELECT e.*,s.actions_json AS source_actions_json,
                    t.actions_json AS target_actions_json,
                    t.team_id AS envelope_team_id
                    FROM relay_envelopes e
                    JOIN peer_routes s ON s.id=e.source_route_id
                    JOIN peer_routes t ON t.id=e.target_route_id
                    JOIN peers p ON p.id=s.peer_id
                    WHERE e.target_route_id=? AND e.target_server_identity=?
                    AND e.target_route_revision=? AND e.status='queued'
                    AND t.status='active' AND t.revision=e.target_route_revision
                    AND s.status='active' AND s.revision=e.source_route_revision
                    AND s.target_kind='peer' AND t.target_kind='host'
                    AND s.peer_id=t.audience_peer_id AND s.team_id=t.team_id
                    AND p.status='active' AND p.cross_chat_grant_epoch=?
                    ORDER BY e.created_at,e.id LIMIT ?""",
                    (
                        route["id"],
                        peer.peer_server_identity,
                        route["revision"],
                        self._cross_chat_epoch(connection),
                        bounded,
                    ),
                ).fetchall()
            else:
                conditions = [
                    "e.target_server_identity=?",
                    "e.status='queued'",
                    "t.target_kind='host'",
                    "t.status='active'",
                    "t.revision=e.target_route_revision",
                    "s.target_kind='peer'",
                    "s.status='active'",
                    "s.revision=e.source_route_revision",
                    "s.peer_id=t.audience_peer_id",
                    "s.team_id=t.team_id",
                    "p.status='active'",
                    "p.cross_chat_grant_epoch=?",
                ]
                arguments: list[Any] = [
                    self.host_server_identity,
                    self._cross_chat_epoch(connection),
                ]
                if _target_peer_id is not None:
                    conditions.append("p.id=?")
                    arguments.append(_target_peer_id)
                arguments.append(bounded)
                rows = connection.execute(
                    """SELECT e.*,s.actions_json AS source_actions_json,
                    t.actions_json AS target_actions_json,
                    t.team_id AS envelope_team_id
                    FROM relay_envelopes e
                    JOIN peer_routes s ON s.id=e.source_route_id
                    JOIN peer_routes t ON t.id=e.target_route_id
                    JOIN peers p ON p.id=s.peer_id
                    WHERE """
                    + " AND ".join(conditions)
                    + " ORDER BY e.created_at,e.id LIMIT ?",
                    arguments,
                ).fetchall()
            for row in rows:
                required_action = (
                    "instruction" if row["kind"] == "instruction" else "request_reply"
                )
                if (
                    required_action not in json.loads(row["source_actions_json"])
                    or required_action not in json.loads(row["target_actions_json"])
                ):
                    raise SecurePeerError(
                        "route_action_forbidden",
                        "Relay route grant no longer permits this action",
                        403,
                    )
                if (
                    _target_route_id is None
                    and _target_peer_id is None
                    and not _all_local
                ):
                    self._relay_scope(peer, row["kind"])
            ids = [row["id"] for row in rows]
            for envelope_id in ids:
                connection.execute(
                    "UPDATE relay_envelopes SET status='claimed',lease_owner=?,lease_token_hash=?,lease_expires_at=? WHERE id=? AND status='queued'",
                    (owner, lease_digest, timestamp + RELAY_LEASE_SECONDS, envelope_id),
                )
            connection.execute("COMMIT")
            return {
                "lease_token": lease_token if rows else None,
                "lease_expires_at": timestamp + RELAY_LEASE_SECONDS if rows else None,
                "envelopes": [
                    {
                        "envelope_id": row["id"],
                        "request_id": row["request_id"],
                        "source_peer_id": row["source_peer_id"],
                        "source_server_identity": row["source_server_identity"],
                        "source_route_id": row["source_route_id"],
                        "source_route_revision": row["source_route_revision"],
                        "target_server_identity": row["target_server_identity"],
                        "target_peer_id": row["target_peer_id"],
                        "target_route_id": row["target_route_id"],
                        "target_route_revision": row["target_route_revision"],
                        "team_id": row["envelope_team_id"],
                        "kind": row["kind"],
                        "action": (
                            "instruction" if row["kind"] == "instruction" else "request_reply"
                        ),
                        "exchange_id": row["exchange_id"],
                        "parent_envelope_id": row["parent_envelope_id"],
                        "parent_leg": row["parent_leg"],
                        "used_legs": int(row["used_legs"]),
                        "max_legs": MAX_RELAY_LEGS,
                        "expires_at": int(row["expires_at"]),
                        "body": json.loads(row["body_json"]),
                    }
                    for row in rows
                ],
            }
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _resolve_local_claim_targets(
        self, result: dict[str, Any]
    ) -> dict[str, Any]:
        connection = self._connect()
        try:
            resolved: list[dict[str, Any]] = []
            for envelope in result["envelopes"]:
                row = connection.execute(
                    """SELECT chat_id FROM peer_routes WHERE id=? AND team_id=?
                    AND target_kind='host' AND revision=? AND status='active'""",
                    (
                        envelope["target_route_id"],
                        envelope["team_id"],
                        envelope["target_route_revision"],
                    ),
                ).fetchone()
                if row is None or row["chat_id"] is None:
                    raise SecurePeerError(
                        "route_changed",
                        "Local receive route changed before claim resolution",
                        409,
                    )
                resolved.append({**envelope, "target_chat_id": row["chat_id"]})
            return {**result, "envelopes": resolved}
        finally:
            connection.close()

    def claim_local_inbox(
        self,
        lease_owner: str,
        *,
        peer_id: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        canonical_peer = _uuid(peer_id, "peer_id") if peer_id is not None else None
        local = PeerAuthorization(
            "",
            "",
            self.host_server_identity,
            "local-host",
            frozenset({"cross_chat.instruction", "cross_chat.request_reply"}),
            "",
            2**63 - 1,
            self.host_server_identity,
        )
        return self._resolve_local_claim_targets(
            self.claim_inbox(
                local,
                lease_owner,
                limit=limit,
                _target_peer_id=canonical_peer,
                _all_local=canonical_peer is None,
            )
        )

    def claim_local_route_inbox(
        self,
        team_id: str,
        target_route_id: str,
        lease_owner: str,
        *,
        limit: int = 20,
    ) -> dict[str, Any]:
        team = _identifier(team_id, "team_id")
        route = _uuid(target_route_id, "target_route_id")
        local = PeerAuthorization(
            "",
            "",
            self.host_server_identity,
            team,
            frozenset({"cross_chat.instruction", "cross_chat.request_reply"}),
            "",
            2**63 - 1,
            self.host_server_identity,
        )
        return self._resolve_local_claim_targets(
            self.claim_inbox(
                local, lease_owner, limit=limit, _target_route_id=route
            )
        )

    def receipt_envelope(
        self,
        peer: PeerAuthorization,
        envelope_id: str,
        lease_token: str,
        outcome: str,
        _target_route_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_cross_chat(peer)
        if _ENVELOPE_ID_RE.fullmatch(envelope_id) is None or outcome not in {"delivered", "failed"}:
            raise SecurePeerError("invalid_request", "relay receipt is invalid", 422)
        if not isinstance(lease_token, str) or not 32 <= len(lease_token) <= 96:
            raise SecurePeerError("lease_unavailable", "Relay lease is unavailable", 409)
        digest = hashlib.sha256(lease_token.encode("utf-8")).digest()
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_cross_chat(peer, connection=connection)
            existing = connection.execute("SELECT * FROM relay_receipts WHERE envelope_id=?", (envelope_id,)).fetchone()
            if existing is not None:
                expected_target_peer = peer.peer_id or None
                if (
                    existing["target_peer_id"] != expected_target_peer
                    or (
                        _target_route_id is not None
                        and existing["target_route_id"] != _target_route_id
                    )
                    or existing["outcome"] != outcome
                ):
                    raise SecurePeerError("receipt_conflict", "Relay receipt conflicts with prior outcome", 409)
                connection.execute("COMMIT")
                return {"envelope_id": envelope_id, "status": outcome, "received_at": int(existing["received_at"])}
            row = connection.execute("SELECT * FROM relay_envelopes WHERE id=?", (envelope_id,)).fetchone()
            if (
                row is None
                or row["target_server_identity"] != peer.peer_server_identity
                or (
                    _target_route_id is None
                    and row["target_peer_id"] != peer.peer_id
                )
                or (
                    _target_route_id is not None
                    and row["target_route_id"] != _target_route_id
                )
                or row["status"] != "claimed"
                or row["lease_token_hash"] is None
                or not hmac.compare_digest(bytes(row["lease_token_hash"]), digest)
                or int(row["lease_expires_at"] or 0) <= timestamp
            ):
                raise SecurePeerError("lease_unavailable", "Relay lease is unavailable", 409)
            if int(row["expires_at"] or 0) <= timestamp:
                connection.execute(
                    """UPDATE relay_envelopes SET status='expired',lease_owner=NULL,
                    lease_token_hash=NULL,lease_expires_at=NULL
                    WHERE id=? AND status='claimed'""",
                    (envelope_id,),
                )
                connection.execute(
                    "UPDATE relay_exchanges SET status='expired' WHERE id=? AND status='open'",
                    (row["exchange_id"],),
                )
                connection.execute("COMMIT")
                raise SecurePeerError(
                    "exchange_expired", "Relay exchange expired", 410
                )
            if _target_route_id is None:
                route = connection.execute(
                    """SELECT * FROM peer_routes WHERE id=? AND peer_id=? AND server_identity=?
                    AND team_id=? AND target_kind='peer' AND status='active'""",
                    (row["target_route_id"], peer.peer_id, peer.peer_server_identity, peer.team_id),
                ).fetchone()
            else:
                route = connection.execute(
                    """SELECT * FROM peer_routes WHERE id=? AND server_identity=?
                    AND team_id=? AND target_kind='host' AND status='active'""",
                    (_target_route_id, peer.peer_server_identity, peer.team_id),
                ).fetchone()
            if route is None or route["revision"] != row["target_route_revision"]:
                raise SecurePeerError("route_unavailable", "Receive route is unavailable or changed", 409)
            source_route = connection.execute(
                """SELECT * FROM peer_routes WHERE id=? AND team_id=?
                AND server_identity=? AND revision=? AND status='active'""",
                (
                    row["source_route_id"],
                    peer.team_id,
                    row["source_server_identity"],
                    row["source_route_revision"],
                ),
            ).fetchone()
            required_action = (
                "instruction" if row["kind"] == "instruction" else "request_reply"
            )
            if (
                source_route is None
                or required_action not in json.loads(source_route["actions_json"])
                or required_action not in json.loads(route["actions_json"])
            ):
                raise SecurePeerError(
                    "route_action_forbidden",
                    "Relay route grant no longer permits this action",
                    403,
                )
            if _target_route_id is None:
                self._relay_scope(peer, row["kind"])
            connection.execute(
                "UPDATE relay_envelopes SET status=?,lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL WHERE id=?",
                (outcome, envelope_id),
            )
            connection.execute(
                """INSERT INTO relay_receipts(
                envelope_id,target_peer_id,target_route_id,outcome,received_at
                ) VALUES (?,?,?,?,?)""",
                (envelope_id, peer.peer_id or None, route["id"], outcome, timestamp),
            )
            self._audit(connection, timestamp, peer.peer_id, "relay.receipt", envelope_id, {"outcome": outcome})
            connection.execute("COMMIT")
            return {"envelope_id": envelope_id, "status": outcome, "received_at": timestamp}
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def receipt_local_envelope(
        self,
        team_id: str,
        target_route_id: str,
        envelope_id: str,
        lease_token: str,
        outcome: str,
    ) -> dict[str, Any]:
        team = _identifier(team_id, "team_id")
        route = _uuid(target_route_id, "target_route_id")
        local = PeerAuthorization(
            "",
            "",
            self.host_server_identity,
            team,
            frozenset({"cross_chat.instruction", "cross_chat.request_reply"}),
            "",
            2**63 - 1,
            self.host_server_identity,
        )
        return self.receipt_envelope(
            local,
            envelope_id,
            lease_token,
            outcome,
            _target_route_id=route,
        )


def canonical_peer_ipv4(value: str) -> str:
    """Validate the v1 literal-IPv4 endpoint matrix shared with the UI."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("peer host must be a canonical literal IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError("peer host must be a canonical literal IPv4 address") from exc
    first = int(value.split(".", 1)[0]) if value.split(".", 1)[0].isdigit() else -1
    if (
        str(address) != value
        or first == 0
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or int(address) >= int(ipaddress.IPv4Address("224.0.0.0"))
        or value == "255.255.255.255"
    ):
        raise ValueError("peer host must be a canonical non-loopback unicast IPv4 address")
    return value


def canonical_peer_port(value: int) -> int:
    if type(value) is not int or not 1024 <= value <= 65535:
        raise ValueError("secure peer port must be between 1024 and 65535")
    return value


_TEAM_ROUTE_RE = re.compile(
    rf"^/v1/teams/(?P<team>{_HUB_SEGMENT})(?:/(?P<child>members|nodes|channels|invitations))?$"
)
_TEAM_MEMBER_ROUTE_RE = re.compile(
    rf"^/v1/teams/(?P<team>{_HUB_SEGMENT})/members/(?P<principal>{_HUB_SEGMENT})$"
)
_CHANNEL_MESSAGES_RE = re.compile(rf"^/v1/channels/(?P<channel>{_HUB_SEGMENT})/messages$")
_NETWORK_ROUTE_RE = re.compile(
    rf"^/v1/teams/(?P<team>{_HUB_SEGMENT})/network(?P<suffix>(?:/{_HUB_SEGMENT}){{0,4}})$"
)
_ATTACHMENT_CONTENT_ROUTE_RE = re.compile(
    rf"^/v1/teams/(?P<team>{_HUB_SEGMENT})/network/attachments/"
    rf"(?P<attachment>{_HUB_SEGMENT})/content$"
)
_ATTACHMENT_CONTENT_RANGE_RE = re.compile(
    r"^bytes (?P<start>[0-9]{1,15})-(?P<end>[0-9]{1,15})/"
    r"(?P<total>[0-9]{1,15})$"
)
_ATTACHMENT_RANGE_RE = re.compile(
    r"^bytes=(?P<start>[0-9]{0,15})-(?P<end>[0-9]{0,15})$"
)
_BLOCKED_PROXY_PREFIXES = (
    "/v1/bootstrap",
    "/v1/owner-recovery",
    "/v1/device-recovery",
    "/v1/node-enrollments",
    "/v1/dispatches",
    "/v1/invitations",
    "/v1/sessions",
    "/v1/openapi.json",
)
_STRIP_REQUEST_HEADERS = {
    "host",
    "content-length",
    "connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "cookie",
    "origin",
    "referer",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "expect",
    "authorization",
}
_PASS_REQUEST_HEADERS = {"accept", "content-type"}
_STRIP_RESPONSE_HEADERS = {
    "connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "set-cookie",
    "content-length",
}


def is_attachment_proxy_path(path: str) -> bool:
    return isinstance(path, str) and _ATTACHMENT_CONTENT_ROUTE_RE.fullmatch(path) is not None


def sanitize_attachment_proxy_request(
    peer: PeerAuthorization,
    method: str,
    path: str,
    query: str,
    headers: Iterable[tuple[str, str]],
    body: bytes,
    *,
    maximum_attachment_bytes: int = MAX_ATTACHMENT_BYTES,
) -> AttachmentProxyRequest:
    """Authorize the only routes allowed to escape the JSON proxy bounds."""

    if (
        type(maximum_attachment_bytes) is not int
        or not 1 <= maximum_attachment_bytes <= MAX_ATTACHMENT_PROTOCOL_BYTES
    ):
        raise SecurePeerError(
            "hub_unavailable", "Team Hub attachment limit is invalid", 503
        )
    normalized_method = str(method).upper()
    match = (
        _ATTACHMENT_CONTENT_ROUTE_RE.fullmatch(path)
        if isinstance(path, str) and len(path) <= 1024 and "%" not in path and "\\" not in path
        else None
    )
    if match is None or match.group("team") != peer.team_id:
        raise SecurePeerError("route_forbidden", "Hub route is not permitted", 403)
    if normalized_method not in {"PUT", "GET", "HEAD"}:
        raise SecurePeerError("method_not_allowed", "Proxy method is not permitted", 405)
    if query:
        raise SecurePeerError("invalid_request", "Query is not accepted for this route", 422)
    required_scope = "teamspace.write" if normalized_method == "PUT" else "teamspace.read"
    if required_scope not in peer.scopes:
        raise SecurePeerError("forbidden", "Peer scope does not permit this Hub request", 403)
    if not isinstance(body, bytes):
        raise SecurePeerError("invalid_request", "Attachment request body is invalid", 400)

    incoming = list(headers)
    if len(incoming) > MAX_HEADERS:
        raise SecurePeerError("invalid_request", "Too many request headers", 431)
    seen: set[str] = set()
    forwarded: list[tuple[str, str]] = []
    allowed = {"accept", "content-type", "content-range", "range"}
    for raw_name, raw_value in incoming:
        name = str(raw_name).strip().lower()
        value = str(raw_value).strip()
        if (
            not name
            or len(name) > 80
            or len(value.encode("utf-8", "strict")) > MAX_HEADER_VALUE_BYTES
            or "\r" in value
            or "\n" in value
            or name in seen
        ):
            raise SecurePeerError("invalid_request", "Proxy request headers are invalid", 400)
        seen.add(name)
        if (
            name in _STRIP_REQUEST_HEADERS
            or name.startswith("x-forwarded-")
            or name.startswith("x-team-hub-")
            or name.startswith("x-agentsdock-")
            or name.startswith("sec-")
        ):
            continue
        if name in allowed:
            forwarded.append((name, value))

    values = dict(forwarded)
    if normalized_method == "PUT":
        if not 1 <= len(body) <= MAX_ATTACHMENT_CHUNK_BYTES:
            raise SecurePeerError("request_too_large", "Attachment chunk size is invalid", 413)
        if values.get("content-type") != "application/octet-stream":
            raise SecurePeerError(
                "invalid_request", "Content-Type must be application/octet-stream", 415
            )
        content_range = values.get("content-range")
        range_match = (
            _ATTACHMENT_CONTENT_RANGE_RE.fullmatch(content_range)
            if content_range is not None
            else None
        )
        if range_match is None:
            raise SecurePeerError("invalid_request", "Content-Range is invalid", 422)
        start = int(range_match.group("start"))
        end = int(range_match.group("end"))
        total = int(range_match.group("total"))
        if (
            end < start
            or end - start + 1 != len(body)
            or end >= total
            or not 1 <= total <= maximum_attachment_bytes
            or "range" in values
        ):
            raise SecurePeerError("invalid_request", "Content-Range is invalid", 422)
    else:
        if body or "content-type" in values or "content-range" in values:
            raise SecurePeerError(
                "invalid_request", "Attachment download requests cannot carry a body", 422
            )
        range_value = values.get("range")
        if range_value is not None:
            range_match = _ATTACHMENT_RANGE_RE.fullmatch(range_value)
            if range_match is None or (
                range_match.group("start") == "" and range_match.group("end") == ""
            ):
                raise SecurePeerError("invalid_request", "Range is invalid", 422)

    return AttachmentProxyRequest(
        normalized_method,
        path,
        tuple(forwarded),
        body,
        peer,
    )


def sanitize_attachment_proxy_response(
    response: AttachmentProxyResponse,
    *,
    maximum_attachment_bytes: int = MAX_ATTACHMENT_PROTOCOL_BYTES,
) -> AttachmentProxyResponse:
    """Validate an adapter response before exposing it on the mTLS socket."""

    if (
        type(maximum_attachment_bytes) is not int
        or not 1 <= maximum_attachment_bytes <= MAX_ATTACHMENT_PROTOCOL_BYTES
    ):
        raise SecurePeerError(
            "hub_unavailable", "Team Hub attachment limit is invalid", 503
        )
    if (
        not isinstance(response, AttachmentProxyResponse)
        or type(response.status) is not int
        or not 200 <= response.status <= 599
        or 300 <= response.status <= 399
    ):
        raise SecurePeerError("upstream_invalid", "Hub returned an invalid response", 502)
    incoming = list(response.headers)
    if len(incoming) > MAX_HEADERS:
        raise SecurePeerError("upstream_invalid", "Hub returned too many headers", 502)
    allowed_headers = {
        "accept-ranges",
        "cache-control",
        "content-disposition",
        "content-range",
        "content-type",
        "etag",
        "x-content-type-options",
    }
    headers: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_name, raw_value in incoming:
        name = str(raw_name).lower().strip()
        value = str(raw_value)
        if (
            not name
            or len(name) > 80
            or len(value.encode("utf-8", "strict")) > MAX_HEADER_VALUE_BYTES
            or "\r" in value
            or "\n" in value
            or name in seen
        ):
            raise SecurePeerError("upstream_invalid", "Hub returned invalid headers", 502)
        seen.add(name)
        if name in allowed_headers:
            headers.append((name, value))

    body = response.body
    descriptor = response.descriptor
    offset = response.offset
    length = response.length
    if descriptor is None:
        if not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BODY_BYTES:
            raise SecurePeerError("upstream_invalid", "Hub response is too large", 502)
        if (
            offset != 0
            or length not in {0, len(body)}
            or response.finalizer is not None
            or response.cancelled is not None
        ):
            raise SecurePeerError("upstream_invalid", "Hub returned an invalid response", 502)
        length = len(body)
    else:
        if type(descriptor) is not int or descriptor < 0:
            raise SecurePeerError(
                "upstream_invalid", "Hub returned an invalid attachment", 502
            )
        try:
            info = os.fstat(descriptor)
        except (OSError, ValueError) as exc:
            raise SecurePeerError("upstream_invalid", "Hub attachment is unavailable", 502) from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or not isinstance(body, bytes)
            or body
            or type(offset) is not int
            or type(length) is not int
            or offset < 0
            or length < 0
            or offset + length > info.st_size
            or length > maximum_attachment_bytes
            or not callable(response.finalizer)
            or not callable(response.cancelled)
        ):
            raise SecurePeerError("upstream_invalid", "Hub returned an invalid attachment", 502)
    return AttachmentProxyResponse(
        response.status,
        tuple(headers),
        body=body,
        descriptor=descriptor,
        offset=offset,
        length=length,
        finalizer=response.finalizer,
        cancelled=response.cancelled,
    )


def finalize_attachment_proxy_response(response: Any) -> None:
    """Release one adapter/runtime stream lease without masking the caller."""

    finalizer = getattr(response, "finalizer", None)
    if callable(finalizer):
        with suppress(Exception):
            finalizer()


def sanitize_proxy_request(
    peer: PeerAuthorization,
    method: str,
    path: str,
    query: str,
    headers: Iterable[tuple[str, str]],
    body: bytes,
    *,
    resource_team_resolver: Callable[[str, str], str | None] | None = None,
) -> ProxyRequest:
    """Authorize and normalize one request for the fixed loopback Hub target."""

    normalized_method = str(method).upper()
    if normalized_method not in {"GET", "POST", "DELETE"}:
        raise SecurePeerError("method_not_allowed", "Proxy method is not permitted", 405)
    if (
        not isinstance(path, str)
        or len(path) > 1024
        or not path.startswith("/v1/")
        or "//" in path
        or "%" in path
        or "\\" in path
        or any(ord(character) < 33 or ord(character) > 126 for character in path)
        or any(path == prefix or path.startswith(prefix + "/") for prefix in _BLOCKED_PROXY_PREFIXES)
    ):
        raise SecurePeerError("route_forbidden", "Hub route is not permitted", 403)
    if not isinstance(query, str) or len(query) > 2048 or "#" in query:
        raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
    if not isinstance(body, bytes) or len(body) > MAX_PROXY_BODY_BYTES:
        raise SecurePeerError("request_too_large", "Proxy request is too large", 413)

    required_scope: str
    resource: tuple[str, str] | None = None
    allow_query = False
    allowed_query_keys: set[str] = set()
    if normalized_method == "GET" and path == "/v1/health":
        required_scope = "teamspace.read"
    elif path in {"/v1/peer-session", "/v1/session", "/v1/teams"} and normalized_method == "GET":
        required_scope = "teamspace.read"
    else:
        team_match = _TEAM_ROUTE_RE.fullmatch(path)
        member_match = _TEAM_MEMBER_ROUTE_RE.fullmatch(path)
        channel_match = _CHANNEL_MESSAGES_RE.fullmatch(path)
        network_match = _NETWORK_ROUTE_RE.fullmatch(path)
        if member_match is not None:
            if member_match.group("team") != peer.team_id:
                raise SecurePeerError("route_forbidden", "Hub route is outside the paired team", 403)
            if normalized_method != "GET":
                raise SecurePeerError("route_forbidden", "Hub route is not permitted", 403)
            required_scope = "teamspace.read"
        elif team_match is not None:
            if team_match.group("team") != peer.team_id:
                raise SecurePeerError("route_forbidden", "Hub route is outside the paired team", 403)
            child = team_match.group("child")
            if normalized_method == "GET" and child in {None, "members", "nodes", "channels"}:
                required_scope = "teamspace.read"
                if child == "members":
                    allow_query = True
                    allowed_query_keys = {"limit", "cursor"}
            else:
                raise SecurePeerError("route_forbidden", "Hub route is not permitted", 403)
        elif channel_match is not None:
            channel_id = channel_match.group("channel")
            resource = ("channel", channel_id)
            required_scope = "teamspace.read" if normalized_method == "GET" else "teamspace.write"
            allow_query = normalized_method == "GET"
            allowed_query_keys = {"limit", "before_sequence"}
        elif network_match is not None:
            if network_match.group("team") != peer.team_id:
                raise SecurePeerError("route_forbidden", "Hub route is outside the paired team", 403)
            suffix = network_match.group("suffix")
            pieces = [piece for piece in suffix.split("/") if piece]
            route_allowed = False
            if not pieces and normalized_method == "GET":
                route_allowed = True
                allow_query = True
                allowed_query_keys = {"after_server_id", "limit"}
            elif (
                len(pieces) == 2
                and pieces[0] == "servers"
                and normalized_method == "GET"
            ):
                route_allowed = True
            elif pieces == ["agents"] and normalized_method == "POST":
                route_allowed = True
            elif pieces == ["bulletin"] and normalized_method in {"GET", "POST"}:
                route_allowed = True
                allow_query = normalized_method == "GET"
                allowed_query_keys = {"after_sequence", "limit"}
            elif (
                len(pieces) == 2
                and pieces[0] == "bulletin"
                and normalized_method == "DELETE"
            ):
                route_allowed = True
            elif pieces == ["mailbox"] and normalized_method in {"GET", "POST"}:
                route_allowed = True
                allow_query = normalized_method == "GET"
                allowed_query_keys = {
                    "address_kind",
                    "address_id",
                    "after_sequence",
                    "limit",
                }
            elif (
                len(pieces) == 2
                and pieces[0] == "items"
                and normalized_method == "GET"
            ):
                route_allowed = True
            elif pieces == ["requests"] and normalized_method == "POST":
                route_allowed = True
            elif (
                len(pieces) == 2
                and pieces[0] == "requests"
                and normalized_method == "GET"
            ):
                route_allowed = True
            elif (
                len(pieces) == 3
                and pieces[0] == "requests"
                and pieces[2] == "replies"
                and normalized_method == "POST"
            ):
                route_allowed = True
            elif (
                len(pieces) == 3
                and pieces[0] == "deliveries"
                and pieces[2] == "receipts"
                and normalized_method == "POST"
            ):
                route_allowed = True
            # Team Messages V2 JSON routes. Attachment *content* is deliberately
            # absent here: bytes travel on the separate binary lane.
            elif pieces == ["messages"] and normalized_method in {"GET", "POST"}:
                route_allowed = True
                allow_query = normalized_method == "GET"
                allowed_query_keys = {
                    "box",
                    "address_kind",
                    "address_id",
                    "unread",
                    "from_kind",
                    "from_id",
                    "since",
                    "after_sequence",
                    "limit",
                }
            elif (
                len(pieces) == 2
                and pieces[0] == "messages"
                and normalized_method in {"GET", "DELETE"}
            ):
                route_allowed = True
            elif pieces == ["deletions"] and normalized_method == "GET":
                route_allowed = True
                allow_query = True
                allowed_query_keys = {"after_sequence", "limit"}
            elif (
                len(pieces) == 3
                and pieces[0] == "messages"
                and pieces[2] == "receipts"
                and normalized_method == "POST"
            ):
                route_allowed = True
            elif pieces == ["attachments"] and normalized_method == "POST":
                route_allowed = True
            elif (
                len(pieces) == 2
                and pieces[0] == "attachments"
                and normalized_method == "GET"
            ):
                route_allowed = True
            elif pieces == ["skills"] and normalized_method == "GET":
                route_allowed = True
                allow_query = True
                allowed_query_keys = {"include_archived", "slug"}
            elif (
                len(pieces) == 2
                and pieces[0] == "skills"
                and normalized_method == "GET"
            ):
                route_allowed = True
            elif (
                len(pieces) == 3
                and pieces[0] == "skills"
                and pieces[2] == "versions"
                and normalized_method == "GET"
            ):
                route_allowed = True
            elif (
                len(pieces) == 4
                and pieces[0] == "skills"
                and pieces[2] == "versions"
                and pieces[3].isdigit()
                and normalized_method == "GET"
            ):
                route_allowed = True
            elif (
                len(pieces) == 3
                and pieces[0] == "skills"
                and pieces[2] in {"pin", "archive"}
                and normalized_method == "POST"
            ):
                route_allowed = True
            if not route_allowed:
                raise SecurePeerError("route_forbidden", "Hub route is not permitted", 403)
            required_scope = (
                "teamspace.read" if normalized_method == "GET" else "teamspace.write"
            )
        else:
            raise SecurePeerError("route_forbidden", "Hub route is not permitted", 403)
    if required_scope not in peer.scopes:
        raise SecurePeerError("forbidden", "Peer scope does not permit this Hub request", 403)
    if resource is not None:
        if resource_team_resolver is None or resource_team_resolver(*resource) != peer.team_id:
            raise SecurePeerError("route_forbidden", "Hub resource is outside the paired team", 403)
    if query:
        if not allow_query:
            raise SecurePeerError("invalid_request", "Query is not accepted for this route", 422)
        try:
            pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
        except ValueError as exc:
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422) from exc
        if (
            len(pairs) > len(allowed_query_keys)
            or len({key for key, _value in pairs}) != len(pairs)
            or any(key not in allowed_query_keys for key, _value in pairs)
        ):
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        values = dict(pairs)
        for key in ("limit", "before_sequence", "after_sequence"):
            if key in values and (
                not values[key].isdigit() or str(int(values[key])) != values[key]
            ):
                raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        if "limit" in values and not 1 <= int(values["limit"]) <= 100:
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        if "cursor" in values:
            if re.fullmatch(r"v1\.[A-Za-z0-9_-]{38,500}", values["cursor"]) is None:
                raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        if "before_sequence" in values and int(values["before_sequence"]) < 1:
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        if "after_sequence" in values and not 0 <= int(
            values["after_sequence"]
        ) <= 9_223_372_036_854_775_807:
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        if "after_server_id" in values and _ID_RE.fullmatch(
            values["after_server_id"]
        ) is None:
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        messages_route = path.endswith("/network/messages")
        mailbox_route = path.endswith("/network/mailbox")
        if "address_kind" in values and values["address_kind"] not in (
            {"server"}
            if mailbox_route
            else ({"server", "human"} if messages_route else {"server", "agent"})
        ):
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        for identifier_key in ("address_id", "from_id"):
            if identifier_key in values and (
                not values[identifier_key]
                or len(values[identifier_key]) > 240
                or any(
                    ord(character) < 33 or ord(character) > 126
                    for character in values[identifier_key]
                )
            ):
                raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        if "box" in values and values["box"] not in {"inbox", "feed", "sent"}:
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        for flag_key in ("unread", "include_archived"):
            if flag_key in values and values[flag_key] not in {"0", "1", "true", "false"}:
                raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        if "from_kind" in values and values["from_kind"] not in {"server", "human"}:
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        if "since" in values and (
            not values["since"]
            or len(values["since"]) > 40
            or any(ord(character) < 33 or ord(character) > 126 for character in values["since"])
        ):
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        if "slug" in values and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", values["slug"]) is None:
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        if path.endswith("/network/mailbox") and normalized_method == "GET" and not {
            "address_kind",
            "address_id",
        }.issubset(values):
            raise SecurePeerError("invalid_request", "Proxy query is invalid", 422)
        query = urlencode(pairs)

    incoming = list(headers)
    if len(incoming) > MAX_HEADERS:
        raise SecurePeerError("invalid_request", "Too many request headers", 431)
    seen: set[str] = set()
    forwarded: list[tuple[str, str]] = []
    for raw_name, raw_value in incoming:
        name = str(raw_name).strip().lower()
        value = str(raw_value)
        if (
            not name
            or len(name) > 80
            or len(value.encode("utf-8", "strict")) > MAX_HEADER_VALUE_BYTES
            or name in seen
        ):
            raise SecurePeerError("invalid_request", "Proxy request headers are invalid", 400)
        seen.add(name)
        if (
            name in _STRIP_REQUEST_HEADERS
            or name.startswith("x-forwarded-")
            or name.startswith("x-team-hub-bootstrap-")
            or name.startswith("x-team-hub-owner-recovery-")
            or name.startswith("x-team-hub-device-recovery-")
            or name.startswith("x-agentsdock-")
            or name.startswith("sec-")
        ):
            continue
        if name in _PASS_REQUEST_HEADERS:
            if "\r" in value or "\n" in value:
                raise SecurePeerError("invalid_request", "Proxy request headers are invalid", 400)
            forwarded.append((name, value))
    content_types = [value for name, value in forwarded if name == "content-type"]
    if normalized_method in {"POST", "DELETE"}:
        if content_types != ["application/json"] or not body:
            raise SecurePeerError("invalid_request", "JSON proxy body is required", 415)
        try:
            if not isinstance(json.loads(body), dict):
                raise ValueError
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise SecurePeerError("invalid_request", "Proxy body must be a JSON object", 422) from exc
    elif body:
        raise SecurePeerError("invalid_request", "Proxy request body is not permitted", 422)
    return ProxyRequest(normalized_method, path, query, tuple(forwarded), body, peer)


def sanitize_proxy_response(response: ProxyResponse) -> ProxyResponse:
    if (
        type(response.status) is not int
        or not 200 <= response.status <= 599
        or 300 <= response.status <= 399
    ):
        raise SecurePeerError("upstream_invalid", "Hub returned an invalid response", 502)
    if not isinstance(response.body, bytes) or len(response.body) > MAX_RESPONSE_BODY_BYTES:
        raise SecurePeerError("upstream_invalid", "Hub response is too large", 502)
    incoming = list(response.headers)
    if len(incoming) > MAX_HEADERS:
        raise SecurePeerError("upstream_invalid", "Hub returned too many headers", 502)
    headers: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_name, raw_value in incoming:
        name = str(raw_name).lower().strip()
        value = str(raw_value)
        if (
            not name
            or len(name) > 80
            or len(value.encode("utf-8", "strict")) > MAX_HEADER_VALUE_BYTES
            or "\r" in value
            or "\n" in value
            or name in seen
        ):
            raise SecurePeerError("upstream_invalid", "Hub returned invalid headers", 502)
        seen.add(name)
        if name in _STRIP_RESPONSE_HEADERS:
            continue
        if name in {"content-type", "cache-control", "etag"}:
            headers.append((name, value))
    return ProxyResponse(response.status, tuple(headers), response.body)


class _GatewayHTTPServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True
    # Host disable/re-enable and updater restarts must be able to reclaim the
    # exact pinned endpoint after accepted sockets enter TIME_WAIT.  This sets
    # SO_REUSEADDR only; it does not enable SO_REUSEPORT or permit a second
    # live listener to share the port.
    allow_reuse_address = True

    def __init__(self, *args: Any, maximum_workers: int = 32, **kwargs: Any) -> None:
        self._worker_slots = threading.BoundedSemaphore(maximum_workers)
        self._source_guard = threading.Lock()
        self._source_connections: dict[str, int] = {}
        self._worker_guard = threading.Condition()
        self._workers: set[threading.Thread] = set()
        self._maximum_per_source = 8
        self.tls_context: ssl.SSLContext | None = None
        super().__init__(*args, **kwargs)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        source = str(client_address[0])
        with self._source_guard:
            count = self._source_connections.get(source, 0)
            if count >= self._maximum_per_source:
                self._worker_slots.release()
                self.shutdown_request(request)
                return
            self._source_connections[source] = count + 1
        try:
            thread = threading.Thread(
                target=self._process_tls_request,
                args=(request, client_address),
                name="agentsdock-secure-peer-connection",
                daemon=True,
            )
            with self._worker_guard:
                self._workers.add(thread)
            thread.start()
        except BaseException:
            with self._worker_guard:
                self._workers.discard(locals().get("thread"))
                self._worker_guard.notify_all()
            with self._source_guard:
                remaining = self._source_connections.get(source, 1) - 1
                if remaining:
                    self._source_connections[source] = remaining
                else:
                    self._source_connections.pop(source, None)
            self._worker_slots.release()
            raise

    def wait_for_workers(self, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout_seconds))
        current = threading.current_thread()
        with self._worker_guard:
            while any(worker is not current for worker in self._workers):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._worker_guard.wait(timeout=remaining)
            return True

    def _process_tls_request(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        tls_socket: ssl.SSLSocket | None = None
        try:
            context = self.tls_context
            if context is None:
                raise RuntimeError("TLS context is unavailable")
            request.settimeout(3)
            tls_socket = context.wrap_socket(
                request, server_side=True, do_handshake_on_connect=False
            )
            tls_socket.do_handshake()
            tls_socket.settimeout(10)
            self.finish_request(tls_socket, client_address)
            self.shutdown_request(tls_socket)
        except (OSError, ssl.SSLError, TimeoutError):
            try:
                (tls_socket or request).close()
            except OSError:
                pass
        except BaseException:
            self.handle_error(request, client_address)
            try:
                (tls_socket or request).close()
            except OSError:
                pass
        finally:
            source = str(client_address[0])
            with self._source_guard:
                remaining = self._source_connections.get(source, 1) - 1
                if remaining:
                    self._source_connections[source] = remaining
                else:
                    self._source_connections.pop(source, None)
            self._worker_slots.release()
            with self._worker_guard:
                self._workers.discard(threading.current_thread())
                self._worker_guard.notify_all()


class SecurePeerGateway:
    """Small TLS 1.3 gateway exposing pairing, relay, and a fixed Hub proxy."""

    def __init__(
        self,
        store: SecurePeerStore,
        bind_ip: str,
        port: int = 7851,
        *,
        forwarder: Callable[
            [ProxyRequest | AttachmentProxyRequest],
            ProxyResponse | AttachmentProxyResponse,
        ]
        | None = None,
        resource_team_resolver: Callable[[str, str], str | None] | None = None,
        attachment_max_bytes: int | Callable[[], int] = MAX_ATTACHMENT_BYTES,
        relay_enabled: bool | Callable[[], bool] = False,
        peer_heartbeat: Callable[[PeerAuthorization], None] | None = None,
        peer_revoker: Callable[[PeerAuthorization, str], Mapping[str, Any]]
        | None = None,
    ) -> None:
        self.store = store
        self.bind_ip = canonical_peer_ipv4(bind_ip)
        self.port = canonical_peer_port(port)
        self.forwarder = forwarder
        self.resource_team_resolver = resource_team_resolver
        self.attachment_max_bytes = attachment_max_bytes
        self.relay_enabled = relay_enabled
        self.peer_heartbeat = peer_heartbeat
        self.peer_revoker = peer_revoker
        self._server: _GatewayHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._guard = threading.RLock()
        self._rate_guard = threading.Lock()
        self._pairing_rate: dict[str, tuple[int, int]] = {}

    def _relay_available(self) -> bool:
        try:
            return bool(
                self.relay_enabled()
                if callable(self.relay_enabled)
                else self.relay_enabled
            )
        except Exception:
            return False

    def _attachment_bytes_limit(self) -> int:
        try:
            value = (
                self.attachment_max_bytes()
                if callable(self.attachment_max_bytes)
                else self.attachment_max_bytes
            )
        except Exception as exc:
            raise SecurePeerError(
                "hub_unavailable", "Team Hub attachment limit is unavailable", 503
            ) from exc
        if (
            type(value) is not int
            or not 1 <= value <= MAX_ATTACHMENT_PROTOCOL_BYTES
        ):
            raise SecurePeerError(
                "hub_unavailable", "Team Hub attachment limit is invalid", 503
            )
        return value

    def _peer_relay_available(self, peer: PeerAuthorization) -> bool:
        return self._relay_available() and self.store.cross_chat_authorized(peer)

    def _prune_rate_buckets_locked(self, window: int) -> None:
        if len(self._pairing_rate) > 4096:
            self._pairing_rate = {
                key: value
                for key, value in self._pairing_rate.items()
                if value[0] >= window - 1
            }

    def _allow_request(self, source: str, action: str) -> bool:
        window = self.store._timestamp() // 60
        limits = {
            "pair": (8, 200),
            "health": (60, 2_000),
            "poll": (120, 10_000),
        }
        per_source, global_limit = limits[action]
        with self._rate_guard:
            source_key = f"{action}:{source}"
            previous_window, source_count = self._pairing_rate.get(
                source_key, (window, 0)
            )
            if previous_window != window:
                source_count = 0
            source_count += 1
            self._pairing_rate[source_key] = (window, source_count)
            self._prune_rate_buckets_locked(window)
            # A source that has exhausted its private allowance must not be
            # able to consume the shared allowance for every other source.
            if source_count > per_source:
                return False

            global_key = f"{action}:*"
            previous_window, global_count = self._pairing_rate.get(
                global_key, (window, 0)
            )
            if previous_window != window:
                global_count = 0
            global_count += 1
            self._pairing_rate[global_key] = (window, global_count)
            self._prune_rate_buckets_locked(window)
        return global_count <= global_limit

    def _allow_peer_request(self, peer: PeerAuthorization, action: str) -> bool:
        limits = {
            "health": (120, 4_000),
            "revoke": (8, 500),
            "renew": (10, 500),
            "route_read": (120, 4_000),
            "route_write": (60, 2_000),
            "relay_submit": (120, 4_000),
            "relay_claim": (120, 4_000),
            "relay_receipt": (240, 8_000),
            "proxy": (600, 20_000),
            "attachment_read": (1_200, 40_000),
            "attachment_upload": (1_200, 40_000),
        }
        if action not in limits:
            raise ValueError("authenticated rate action is invalid")
        per_peer, global_limit = limits[action]
        window = self.store._timestamp() // 60
        with self._rate_guard:
            peer_key = f"peer:{peer.peer_id}:{action}"
            previous_window, peer_count = self._pairing_rate.get(
                peer_key, (window, 0)
            )
            if previous_window != window:
                peer_count = 0
            peer_count += 1
            self._pairing_rate[peer_key] = (window, peer_count)
            self._prune_rate_buckets_locked(window)
            # Hierarchical accounting: traffic already rejected by the
            # peer-specific bucket never charges the shared peer bucket.
            if peer_count > per_peer:
                return False

            global_key = f"peer:*:{action}"
            previous_window, global_count = self._pairing_rate.get(
                global_key, (window, 0)
            )
            if previous_window != window:
                global_count = 0
            global_count += 1
            self._pairing_rate[global_key] = (window, global_count)
            self._prune_rate_buckets_locked(window)
        return global_count <= global_limit

    @property
    def address(self) -> tuple[str, int]:
        return self.bind_ip, self.port

    def start(self) -> None:
        with self._guard:
            if self._server is not None:
                return
            gateway = self

            class Handler(http.server.BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"
                server_version = "AgentsDockSecurePeer/1"
                sys_version = ""

                def setup(self) -> None:
                    super().setup()
                    self.connection.settimeout(10)

                def log_message(self, _format: str, *_args: Any) -> None:
                    return

                def _error(self, exc: SecurePeerError) -> None:
                    self._json(exc.status_code, {"error": {"code": exc.code, "message": exc.message}})

                def _json(self, status: int, value: Mapping[str, Any]) -> None:
                    body = canonical_json(dict(value))
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(body)
                    self.close_connection = True

                def _exact_header(self, name: str, *, required: bool = False) -> str | None:
                    values = self.headers.get_all(name, failobj=[])
                    if len(values) > 1 or (required and len(values) != 1):
                        raise SecurePeerError("invalid_request", f"{name} header is invalid", 400)
                    if not values:
                        return None
                    value = values[0]
                    if len(value.encode("latin-1")) > MAX_HEADER_VALUE_BYTES or "\r" in value or "\n" in value:
                        raise SecurePeerError("invalid_request", f"{name} header is invalid", 400)
                    return value

                def _body(self, maximum: int, *, required: bool = True) -> bytes:
                    if len(self.headers) > MAX_HEADERS:
                        raise SecurePeerError("invalid_request", "Too many request headers", 431)
                    if self.headers.get_all("Transfer-Encoding", failobj=[]):
                        raise SecurePeerError("invalid_request", "Transfer-Encoding is not accepted", 400)
                    lengths = self.headers.get_all("Content-Length", failobj=[])
                    if len(lengths) != 1:
                        if not required and not lengths:
                            return b""
                        raise SecurePeerError("invalid_request", "Exactly one Content-Length is required", 411)
                    raw = lengths[0]
                    if not raw.isdigit() or str(int(raw)) != raw:
                        raise SecurePeerError("invalid_request", "Content-Length is invalid", 400)
                    length = int(raw)
                    if (required and length < 2) or length > maximum:
                        raise SecurePeerError("request_too_large", "Request body size is invalid", 413)
                    content_type = self._exact_header("Content-Type", required=required)
                    if required and content_type != "application/json":
                        raise SecurePeerError("invalid_request", "Content-Type must be application/json", 415)
                    self.connection.settimeout(10)
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise SecurePeerError("invalid_request", "Request body is truncated", 400)
                    return body

                def _json_body(self, maximum: int = MAX_PAIRING_BODY_BYTES) -> dict[str, Any]:
                    body = self._body(maximum)
                    try:
                        value = json.loads(body)
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise SecurePeerError("invalid_request", "Request body must be valid JSON", 400) from exc
                    if not isinstance(value, dict):
                        raise SecurePeerError("invalid_request", "Request body must be a JSON object", 422)
                    return value

                def _attachment_body(self) -> bytes:
                    """Read one fixed-size binary chunk without entering JSON parsing."""

                    if self.headers.get_all("Transfer-Encoding", failobj=[]):
                        raise SecurePeerError(
                            "invalid_request", "Transfer-Encoding is not accepted", 400
                        )
                    lengths = self.headers.get_all("Content-Length", failobj=[])
                    if len(lengths) != 1:
                        raise SecurePeerError(
                            "invalid_request", "Exactly one Content-Length is required", 411
                        )
                    raw = lengths[0]
                    if not raw.isdigit() or str(int(raw)) != raw:
                        raise SecurePeerError(
                            "invalid_request", "Content-Length is invalid", 400
                        )
                    length = int(raw)
                    if not 1 <= length <= MAX_ATTACHMENT_CHUNK_BYTES:
                        raise SecurePeerError(
                            "request_too_large", "Attachment chunk size is invalid", 413
                        )
                    if self._exact_header("Content-Type", required=True) != "application/octet-stream":
                        raise SecurePeerError(
                            "invalid_request",
                            "Content-Type must be application/octet-stream",
                            415,
                        )
                    self.connection.settimeout(60)
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise SecurePeerError(
                            "invalid_request", "Request body is truncated", 400
                        )
                    return body

                def _peer(self, *, allow_pending_renewal: bool = False) -> PeerAuthorization:
                    certificate = self.connection.getpeercert(binary_form=True)
                    if not certificate:
                        raise SecurePeerError("peer_authentication_required", "Peer authentication is required", 401)
                    peer = gateway.store.authenticate_peer(
                        certificate, allow_pending_renewal=allow_pending_renewal
                    )
                    gateway.store.record_peer_heartbeat(peer.peer_id)
                    return peer

                def _peer_for_self_revocation(self) -> PeerAuthorization:
                    certificate = self.connection.getpeercert(binary_form=True)
                    if not certificate:
                        raise SecurePeerError(
                            "peer_authentication_required",
                            "Peer authentication is required",
                            401,
                        )
                    return gateway.store.authorize_peer_self_revocation(
                        certificate
                    )

                def _peer_rate(
                    self, peer: PeerAuthorization, action: str
                ) -> None:
                    if not gateway._allow_peer_request(peer, action):
                        raise SecurePeerError(
                            "rate_limited",
                            "Too many authenticated peer requests",
                            429,
                        )

                def _split(self) -> tuple[str, str]:
                    if not isinstance(self.path, str) or len(self.path) > 4096:
                        raise SecurePeerError(
                            "invalid_request", "Request target is too large", 414
                        )
                    parsed = urlsplit(self.path)
                    if (
                        parsed.scheme
                        or parsed.netloc
                        or parsed.fragment
                        or len(parsed.path) > 2048
                        or len(parsed.query) > 2048
                    ):
                        raise SecurePeerError("invalid_request", "Request target is invalid", 400)
                    return parsed.path, parsed.query

                def _validate_headers(self) -> None:
                    values = list(self.headers.items())
                    if len(values) > MAX_HEADERS:
                        raise SecurePeerError(
                            "invalid_request", "Too many request headers", 431
                        )
                    total = 0
                    for name, value in values:
                        try:
                            encoded_name = name.encode("ascii")
                            encoded_value = value.encode("latin-1")
                        except UnicodeEncodeError as exc:
                            raise SecurePeerError(
                                "invalid_request", "Request headers are invalid", 400
                            ) from exc
                        total += len(encoded_name) + len(encoded_value) + 4
                        if (
                            not encoded_name
                            or len(encoded_name) > 80
                            or len(encoded_value) > MAX_HEADER_VALUE_BYTES
                            or any(byte < 33 or byte > 126 for byte in encoded_name)
                            or any(
                                (byte < 32 and byte != 9) or byte == 127
                                for byte in encoded_value
                            )
                        ):
                            raise SecurePeerError(
                                "invalid_request", "Request headers are invalid", 400
                            )
                    if total > MAX_HEADER_BLOCK_BYTES:
                        raise SecurePeerError(
                            "invalid_request", "Request headers are too large", 431
                        )

                def do_GET(self) -> None:  # noqa: N802
                    try:
                        path, query = self._split()
                        self._validate_headers()
                        if path == "/v1/health" and not query:
                            source = str(self.client_address[0]) if self.client_address else "unknown"
                            if not gateway._allow_request(source, "health"):
                                raise SecurePeerError("rate_limited", "Too many health requests", 429)
                            self._json(200, gateway.store.public_health())
                            return
                        match = re.fullmatch(r"/v1/pairings/([0-9a-f-]{36})", path)
                        if match is not None and not query:
                            source = str(self.client_address[0]) if self.client_address else "unknown"
                            if not gateway._allow_request(source, "poll"):
                                raise SecurePeerError("rate_limited", "Too many pairing polls", 429)
                            token = self._exact_header(PAIRING_TOKEN_HEADER, required=True)
                            assert token is not None
                            self._json(200, gateway.store.poll_pairing(match.group(1), token))
                            return
                        if path == "/v1/peer/health" and not query:
                            peer = self._peer()
                            self._peer_rate(peer, "health")
                            if gateway.peer_heartbeat is not None:
                                gateway.peer_heartbeat(peer)
                            self._json(
                                200,
                                {
                                    "ok": True,
                                    "peer_id": peer.peer_id,
                                    "team_id": peer.team_id,
                                    "host_server_identity": gateway.store.host_server_identity,
                                    "hub_id": gateway.store.hub_id,
                                    "host_ca_fingerprint": gateway.store.ca_fingerprint,
                                    "certificate_fingerprint": peer.certificate_fingerprint,
                                    "certificate_expires_at": peer.certificate_expires_at,
                                    "peer_display_name": peer.peer_display_name,
                                    "remote_route_delivery_available": gateway._peer_relay_available(peer),
                                },
                            )
                            return
                        if path == "/v1/peer/status" and not query:
                            peer = self._peer_for_self_revocation()
                            self._peer_rate(peer, "health")
                            self._json(
                                200,
                                gateway.store.peer_revocation_status(peer),
                            )
                            return
                        if path == "/v1/routes" and not query:
                            if not gateway._relay_available():
                                raise SecurePeerError("not_found", "Resource not found", 404)
                            peer = self._peer()
                            self._peer_rate(peer, "route_read")
                            self._json(200, {"routes": gateway.store.list_remote_routes(peer)})
                            return
                        if path.startswith("/v1/hub/"):
                            self._proxy(path, query, b"")
                            return
                        raise SecurePeerError("not_found", "Resource not found", 404)
                    except SecurePeerError as exc:
                        self._error(exc)
                    except Exception:
                        self._error(SecurePeerError("internal_error", "Internal server error", 500))

                def do_HEAD(self) -> None:  # noqa: N802
                    try:
                        path, query = self._split()
                        self._validate_headers()
                        if path.startswith("/v1/hub/"):
                            self._proxy(path, query, b"")
                            return
                        raise SecurePeerError("not_found", "Resource not found", 404)
                    except SecurePeerError as exc:
                        self._error(exc)
                    except Exception:
                        self._error(SecurePeerError("internal_error", "Internal server error", 500))

                def do_PUT(self) -> None:  # noqa: N802
                    try:
                        path, query = self._split()
                        self._validate_headers()
                        if query:
                            raise SecurePeerError(
                                "invalid_request", "Query is not accepted", 422
                            )
                        target_path = path[len("/v1/hub") :] if path.startswith("/v1/hub/") else ""
                        if is_attachment_proxy_path(target_path):
                            # Authenticate before accepting up to an 8 MiB
                            # body from the TLS socket. The proxy repeats the
                            # check at dispatch to close revocation races.
                            self._peer()
                            self._proxy(path, "", self._attachment_body())
                            return
                        raise SecurePeerError("not_found", "Resource not found", 404)
                    except SecurePeerError as exc:
                        self._error(exc)
                    except Exception:
                        self._error(SecurePeerError("internal_error", "Internal server error", 500))

                def do_POST(self) -> None:  # noqa: N802
                    try:
                        path, query = self._split()
                        self._validate_headers()
                        if query:
                            raise SecurePeerError("invalid_request", "Query is not accepted", 422)
                        if path == "/v1/pairings":
                            self._reject_browser_headers()
                            source = str(self.client_address[0]) if self.client_address else "unknown"
                            if not gateway._allow_request(source, "pair"):
                                raise SecurePeerError("rate_limited", "Too many pairing requests", 429)
                            self._json(
                                201,
                                gateway.store.submit_pairing(
                                    self._json_body(),
                                    source_ip=source,
                                    source_port=int(self.client_address[1]),
                                ),
                            )
                            return
                        cancel = re.fullmatch(r"/v1/pairings/([0-9a-f-]{36})/cancel", path)
                        if cancel is not None:
                            self._reject_browser_headers()
                            source = str(self.client_address[0]) if self.client_address else "unknown"
                            if not gateway._allow_request(source, "poll"):
                                raise SecurePeerError(
                                    "rate_limited", "Too many pairing requests", 429
                                )
                            token = self._exact_header(PAIRING_TOKEN_HEADER, required=True)
                            body = _require_exact_keys(
                                self._json_body(), {"idempotency_key"}, context="pairing cancellation"
                            )
                            assert token is not None
                            self._json(
                                200,
                                gateway.store.cancel_pairing(
                                    cancel.group(1), token, body["idempotency_key"]
                                ),
                            )
                            return
                        activation = re.fullmatch(
                            r"/v1/renewals/([0-9a-f-]{36})/activate", path
                        )
                        if activation is not None:
                            peer = self._peer(allow_pending_renewal=True)
                            self._peer_rate(peer, "renew")
                            value = _require_exact_keys(
                                self._json_body(), {"request_id"}, context="renewal activation"
                            )
                            if value["request_id"] != activation.group(1):
                                raise SecurePeerError(
                                    "invalid_request", "renewal request identity mismatch", 422
                                )
                            self._json(
                                200,
                                gateway.store.activate_renewal(peer, value["request_id"]),
                            )
                            return
                        if (
                            path == "/v1/routes"
                            or path.startswith("/v1/routes/")
                            or path.startswith("/v1/relay/")
                        ) and not gateway._relay_available():
                            raise SecurePeerError("not_found", "Resource not found", 404)
                        if path == "/v1/peer/revoke":
                            peer = self._peer_for_self_revocation()
                            self._peer_rate(peer, "revoke")
                            value = _require_exact_keys(
                                self._json_body(),
                                {"idempotency_key"},
                                context="peer self-revocation",
                            )
                            if gateway.peer_revoker is None:
                                raise SecurePeerError(
                                    "host_unavailable",
                                    "Secure peer revocation is unavailable",
                                    503,
                                )
                            self._json(
                                200,
                                gateway.peer_revoker(
                                    peer,
                                    _uuid(
                                        value["idempotency_key"],
                                        "idempotency_key",
                                    ),
                                ),
                            )
                            return
                        peer = self._peer()
                        if path == "/v1/renew":
                            self._peer_rate(peer, "renew")
                            self._json(200, gateway.store.renew_peer(peer, self._json_body()))
                            return
                        if path == "/v1/routes":
                            if not gateway._relay_available():
                                raise SecurePeerError("not_found", "Resource not found", 404)
                            self._peer_rate(peer, "route_write")
                            self._json(201, gateway.store.publish_peer_route(peer, self._json_body()))
                            return
                        route_revoke = re.fullmatch(
                            r"/v1/routes/([0-9a-f-]{36})/revoke", path
                        )
                        if route_revoke is not None:
                            if not gateway._relay_available():
                                raise SecurePeerError("not_found", "Resource not found", 404)
                            self._peer_rate(peer, "route_write")
                            value = _require_exact_keys(
                                self._json_body(),
                                {"expected_revision", "idempotency_key"},
                                context="route revocation",
                            )
                            self._json(
                                200,
                                gateway.store.revoke_peer_route(
                                    peer,
                                    route_revoke.group(1),
                                    value["expected_revision"],
                                    value["idempotency_key"],
                                ),
                            )
                            return
                        if path == "/v1/relay/envelopes":
                            if not gateway._relay_available():
                                raise SecurePeerError("not_found", "Resource not found", 404)
                            self._peer_rate(peer, "relay_submit")
                            self._json(201, gateway.store.submit_envelope(peer, self._json_body(MAX_PROXY_BODY_BYTES)))
                            return
                        if path == "/v1/relay/inbox/claim":
                            if not gateway._relay_available():
                                raise SecurePeerError("not_found", "Resource not found", 404)
                            self._peer_rate(peer, "relay_claim")
                            value = _require_exact_keys(
                                self._json_body(), {"lease_owner", "limit"}, context="relay claim"
                            )
                            self._json(
                                200,
                                gateway.store.claim_inbox(peer, value["lease_owner"], limit=value["limit"]),
                            )
                            return
                        receipt = re.fullmatch(r"/v1/relay/envelopes/([0-9a-f-]{36})/receipt", path)
                        if receipt is not None:
                            if not gateway._relay_available():
                                raise SecurePeerError("not_found", "Resource not found", 404)
                            self._peer_rate(peer, "relay_receipt")
                            value = _require_exact_keys(
                                self._json_body(), {"lease_token", "outcome"}, context="relay receipt"
                            )
                            self._json(
                                200,
                                gateway.store.receipt_envelope(
                                    peer, receipt.group(1), value["lease_token"], value["outcome"]
                                ),
                            )
                            return
                        if path.startswith("/v1/hub/"):
                            self._proxy(path, "", self._body(MAX_PROXY_BODY_BYTES))
                            return
                        raise SecurePeerError("not_found", "Resource not found", 404)
                    except SecurePeerError as exc:
                        self._error(exc)
                    except Exception:
                        self._error(SecurePeerError("internal_error", "Internal server error", 500))

                def do_DELETE(self) -> None:  # noqa: N802
                    try:
                        path, query = self._split()
                        self._validate_headers()
                        if query:
                            raise SecurePeerError(
                                "invalid_request",
                                "Query is not accepted",
                                422,
                            )
                        if path.startswith("/v1/hub/"):
                            self._proxy(
                                path,
                                "",
                                self._body(MAX_PROXY_BODY_BYTES),
                            )
                            return
                        raise SecurePeerError(
                            "not_found",
                            "Resource not found",
                            404,
                        )
                    except SecurePeerError as exc:
                        self._error(exc)
                    except Exception:
                        self._error(
                            SecurePeerError(
                                "internal_error",
                                "Internal server error",
                                500,
                            )
                        )

                def _reject_browser_headers(self) -> None:
                    forbidden = {
                        "origin", "cookie", "referer", "forwarded", "x-forwarded-for",
                        "x-forwarded-host", "x-forwarded-proto", "sec-fetch-site",
                    }
                    if any(name.lower() in forbidden for name in self.headers.keys()):
                        raise SecurePeerError("forbidden", "Browser-originated pairing is not accepted", 403)

                def _proxy(self, path: str, query: str, body: bytes) -> None:
                    if gateway.forwarder is None:
                        raise SecurePeerError("hub_unavailable", "Team Hub proxy is unavailable", 503)
                    peer = self._peer()
                    target_path = path[len("/v1/hub") :]
                    if is_attachment_proxy_path(target_path):
                        self._peer_rate(
                            peer,
                            "attachment_upload" if self.command == "PUT" else "attachment_read",
                        )
                        request = sanitize_attachment_proxy_request(
                            peer,
                            self.command,
                            target_path,
                            query,
                            tuple((name, value) for name, value in self.headers.items()),
                            body,
                            maximum_attachment_bytes=gateway._attachment_bytes_limit(),
                        )
                        raw_response = gateway.forwarder(request)
                        try:
                            response = sanitize_attachment_proxy_response(
                                raw_response,
                                maximum_attachment_bytes=MAX_ATTACHMENT_PROTOCOL_BYTES,
                            )
                        except BaseException:
                            finalize_attachment_proxy_response(raw_response)
                            raise
                        try:
                            # Once the status line is emitted, any file/socket
                            # failure must terminate this connection. Emitting
                            # a second JSON status line would corrupt the bytes
                            # promised by Content-Length.
                            try:
                                self.send_response(response.status)
                                for name, value in response.headers:
                                    self.send_header(name, value)
                                self.send_header("Content-Length", str(response.length))
                                self.send_header("Connection", "close")
                                self.end_headers()
                                if self.command != "HEAD":
                                    if response.descriptor is None:
                                        self.wfile.write(response.body)
                                    else:
                                        remaining = response.length
                                        offset = response.offset
                                        while remaining > 0:
                                            if response.cancelled is not None and response.cancelled():
                                                raise OSError("Hub attachment stream was revoked")
                                            block = os.pread(
                                                response.descriptor,
                                                min(1024 * 1024, remaining),
                                                offset,
                                            )
                                            if not block:
                                                raise OSError(
                                                    "Hub attachment was truncated"
                                                )
                                            if response.cancelled is not None and response.cancelled():
                                                raise OSError("Hub attachment stream was revoked")
                                            self.wfile.write(block)
                                            remaining -= len(block)
                                            offset += len(block)
                            except Exception:
                                self.close_connection = True
                                return
                            self.close_connection = True
                            return
                        finally:
                            finalize_attachment_proxy_response(response)
                    self._peer_rate(peer, "proxy")
                    request = sanitize_proxy_request(
                        peer,
                        self.command,
                        target_path,
                        query,
                        tuple((name, value) for name, value in self.headers.items()),
                        body,
                        resource_team_resolver=gateway.resource_team_resolver,
                    )
                    response = sanitize_proxy_response(gateway.forwarder(request))
                    self.send_response(response.status)
                    for name, value in response.headers:
                        self.send_header(name, value)
                    self.send_header("Content-Length", str(len(response.body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(response.body)
                    self.close_connection = True

            server = _GatewayHTTPServer((self.bind_ip, self.port), Handler, bind_and_activate=False)
            try:
                server.server_bind()
                server.server_activate()
                server.tls_context = self.store.tls_server_context(self.bind_ip)
            except BaseException:
                server.server_close()
                raise
            thread = threading.Thread(
                target=server.serve_forever,
                name="agentsdock-secure-peer-gateway",
                daemon=True,
            )
            self._server = server
            self._thread = thread
            try:
                thread.start()
            except BaseException:
                # Binding/listening has already succeeded, but the runtime
                # cannot retain this gateway until its serving thread starts.
                # Release the listener here so a designated-host retry can
                # bind the exact same endpoint.  shutdown() is safe only once
                # Thread.start() actually admitted the thread.
                self._server = None
                self._thread = None
                started = thread.ident is not None
                if started:
                    with suppress(Exception):
                        server.shutdown()
                with suppress(Exception):
                    server.server_close()
                if started and thread is not threading.current_thread():
                    with suppress(Exception):
                        thread.join(timeout=5)
                raise

    def stop(self, *, timeout_seconds: float = 15.0) -> None:
        with self._guard:
            server, thread = self._server, self._thread
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)
        if server is not None and not server.wait_for_workers(timeout_seconds):
            raise RuntimeError("secure peer gateway did not drain active requests")
        with self._guard:
            if self._server is server:
                self._server = None
                self._thread = None


class _NoSNIHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection used only during the explicitly unverified discovery phase."""

    def connect(self) -> None:
        if self._tunnel_host:
            raise OSError("HTTP tunneling is not permitted")
        raw = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock = self._context.wrap_socket(raw, server_hostname=None)
        except BaseException:
            raw.close()
            raise


def _client_csr(
    private_key: Ed25519PrivateKey, server_identity: str
) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_identity)]))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"urn:agentsdock:server:{server_identity}")]
            ),
            False,
        )
        .sign(private_key, algorithm=None)
    )


def build_pairing_request(
    private_key: Ed25519PrivateKey,
    *,
    server_identity: str,
    display_name: str,
    host_ca_fingerprint: str,
    request_id: str | None = None,
    created_at: int | None = None,
    nonce: bytes | None = None,
    capabilities: Iterable[str] = ("cert_renewal", "cross_chat", "teamspace"),
    requested_scopes: Iterable[str],
) -> dict[str, Any]:
    identity = _identifier(server_identity, "peer server identity")
    label = _bounded_text(display_name, "peer display name", 1, 160)
    if _HEX_FP_RE.fullmatch(host_ca_fingerprint) is None:
        raise ValueError("host CA fingerprint is invalid")
    canonical_capabilities = sorted(list(capabilities))
    if (
        len(canonical_capabilities) != len(set(canonical_capabilities))
        or not set(canonical_capabilities).issubset(CAPABILITIES)
    ):
        raise ValueError("capabilities are invalid")
    requested_values = list(requested_scopes)
    if (
        not requested_values
        or len(requested_values) != len(set(requested_values))
        or not set(requested_values).issubset(SCOPES)
    ):
        raise ValueError("requested scopes are invalid")
    canonical_requested = [item for item in SCOPE_ORDER if item in requested_values]
    nonce_bytes = secrets.token_bytes(32) if nonce is None else bytes(nonce)
    if len(nonce_bytes) != 32:
        raise ValueError("pairing nonce must contain 32 bytes")
    csr = _client_csr(private_key, identity)
    unsigned: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": str(uuid.uuid4()) if request_id is None else _uuid(request_id, "request_id"),
        "created_at": _now(created_at),
        "peer_server_identity": identity,
        "peer_display_name": label,
        "peer_public_key_pem": _public_key_pem(private_key.public_key()),
        "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "nonce": base64.b64encode(nonce_bytes).decode("ascii"),
        "host_ca_fingerprint": host_ca_fingerprint,
        "capabilities": canonical_capabilities,
        "requested_scopes": canonical_requested,
    }
    return {
        **unsigned,
        "signature": base64.b64encode(private_key.sign(canonical_json(unsigned))).decode("ascii"),
    }


class SecurePeerClient:
    """Owner-private multi-connection client and synchronous TLS transport."""

    _PUBLIC_CONNECTION_FIELDS = (
        "connection_id",
        "host_ip",
        "port",
        "status",
        "pairing_id",
        "peer_id",
        "team_id",
        "scopes_json",
        "host_server_identity",
        "hub_id",
        "host_ca_fingerprint",
        "transcript_hash",
        "sas_json",
        "requested_scopes_json",
        "peer_public_key_fingerprint",
        "certificate_fingerprint",
        "certificate_expires_at",
        "relay_available",
        "created_at",
        "updated_at",
        "last_validated_at",
    )

    def __init__(
        self,
        data_dir: str | Path,
        server_identity: str,
        display_name: str,
        *,
        clock: Callable[[], float] = time.time,
        timeout_seconds: float = 10.0,
        pairing_capacity_lock: threading.RLock | None = None,
        external_actionable_pairing_count: Callable[[], int] | None = None,
        pairing_capabilities: Iterable[str] = (
            "cert_renewal",
            "cross_chat",
            "teamspace",
        ),
    ) -> None:
        self.data_dir = Path(data_dir)
        ensure_private_directory(self.data_dir)
        self.keys_dir = self.data_dir / "keys"
        ensure_private_directory(self.keys_dir)
        self.server_identity = _identifier(server_identity, "peer server identity")
        self.display_name = _bounded_text(display_name, "peer display name", 1, 160)
        canonical_capabilities = tuple(sorted(pairing_capabilities))
        if (
            len(canonical_capabilities) != len(set(canonical_capabilities))
            or not set(canonical_capabilities).issubset(CAPABILITIES)
        ):
            raise ValueError("pairing capabilities are invalid")
        self._pairing_capabilities = canonical_capabilities
        self._clock = clock
        self.timeout_seconds = max(1.0, min(float(timeout_seconds), 30.0))
        self._route_guard = threading.RLock()
        self._pairing_request_guard = threading.RLock()
        self._pairing_capacity_lock = pairing_capacity_lock or threading.RLock()
        self._external_actionable_pairing_count = (
            external_actionable_pairing_count
        )
        self.db_path = self.data_dir / "secure-peer-client.sqlite3"
        self._initialize_database()

    def _pairing_request_matches_configured_policy(
        self,
        request: Mapping[str, Any],
    ) -> bool:
        """Reject replay of signed requests from a wider pre-upgrade policy."""

        capabilities = request.get("capabilities")
        try:
            requested_scopes = SecurePeerStore._canonical_scopes(
                request.get("requested_scopes")
            )
        except (SecurePeerError, TypeError, ValueError):
            return False
        return (
            isinstance(capabilities, list)
            and capabilities == list(self._pairing_capabilities)
            and (
                "cross_chat" in self._pairing_capabilities
                or not any(scope.startswith("cross_chat.") for scope in requested_scopes)
            )
        )

    def _require_pairing_scopes_allowed(self, requested_scopes: Iterable[str]) -> None:
        if (
            "cross_chat" not in self._pairing_capabilities
            and any(str(scope).startswith("cross_chat.") for scope in requested_scopes)
        ):
            raise SecurePeerError(
                "pairing_capability_unavailable",
                "Cross-server agent pairing scopes are retired",
                409,
            )

    def _timestamp(self) -> int:
        return _now(self._clock())

    @staticmethod
    def _actionable_pairing_count(connection: sqlite3.Connection) -> int:
        connections = int(
            connection.execute(
                """SELECT COUNT(*) AS count FROM client_connections
                WHERE status IN ('pending','approved','connected','deactivated')"""
            ).fetchone()["count"]
        )
        attempts = int(
            connection.execute(
                "SELECT COUNT(*) AS count FROM client_pairing_attempts"
            ).fetchone()["count"]
        )
        return connections + attempts

    def actionable_pairing_count(self) -> int:
        connection = self._connect()
        try:
            return self._actionable_pairing_count(connection)
        finally:
            connection.close()

    def _external_pairing_count(self) -> int:
        if self._external_actionable_pairing_count is None:
            return 0
        try:
            count = self._external_actionable_pairing_count()
        except Exception as exc:
            raise SecurePeerError(
                "pairing_capacity",
                "Pairing capacity cannot be verified safely",
                503,
            ) from exc
        if type(count) is not int or not 0 <= count <= PAIRING_STATUS_LIMIT:
            raise SecurePeerError(
                "pairing_capacity",
                "Pairing capacity cannot be verified safely",
                503,
            )
        return count

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5, isolation_level=None)
        os.chmod(self.db_path, 0o600)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize_database(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS client_meta(key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE IF NOT EXISTS client_connections(
                    connection_id TEXT PRIMARY KEY, host_ip TEXT NOT NULL, port INTEGER NOT NULL,
                    status TEXT NOT NULL, pairing_id TEXT NOT NULL UNIQUE,
                    pairing_request_id TEXT NOT NULL UNIQUE, poll_token TEXT NOT NULL,
                    pairing_request_json TEXT, pairing_request_digest BLOB,
                    peer_id TEXT, team_id TEXT, scopes_json TEXT,
                    host_server_identity TEXT NOT NULL, hub_id TEXT NOT NULL,
                    host_ca_certificate_pem TEXT NOT NULL, host_ca_fingerprint TEXT NOT NULL,
                    transcript_hash TEXT NOT NULL, sas_json TEXT NOT NULL,
                    requested_scopes_json TEXT NOT NULL,
                    peer_public_key_fingerprint TEXT,
                    key_path TEXT NOT NULL, certificate_path TEXT,
                    certificate_fingerprint TEXT, certificate_expires_at INTEGER,
                    relay_available INTEGER NOT NULL DEFAULT 0
                      CHECK(relay_available IN (0,1)),
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                    last_validated_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS client_pairing_attempts(
                    request_id TEXT PRIMARY KEY, connection_id TEXT NOT NULL UNIQUE,
                    host_ip TEXT NOT NULL, port INTEGER NOT NULL,
                    observed_ca_fingerprint TEXT NOT NULL, health_leaf_fingerprint TEXT NOT NULL,
                    host_server_identity TEXT NOT NULL, hub_id TEXT NOT NULL,
                    request_json TEXT NOT NULL, key_path TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS client_routes(
                    route_id TEXT PRIMARY KEY, connection_id TEXT NOT NULL,
                    revision TEXT NOT NULL, alias TEXT NOT NULL, display_title TEXT NOT NULL,
                    actions_json TEXT NOT NULL, chat_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('publishing','active','revoked')),
                    revoke_pending INTEGER NOT NULL DEFAULT 0
                      CHECK(revoke_pending IN (0,1)),
                    revoke_expected_revision TEXT,
                    revoke_idempotency_key TEXT,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                    UNIQUE(connection_id,chat_id),
                    FOREIGN KEY(connection_id) REFERENCES client_connections(connection_id)
                );
                CREATE TABLE IF NOT EXISTS client_renewals(
                    request_id TEXT PRIMARY KEY, connection_id TEXT NOT NULL,
                    old_certificate_fingerprint TEXT NOT NULL,
                    request_json TEXT NOT NULL, key_path TEXT NOT NULL,
                    certificate_path TEXT, certificate_fingerprint TEXT,
                    status TEXT NOT NULL CHECK(status IN ('pending','certificate_saved','activated')),
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                    FOREIGN KEY(connection_id) REFERENCES client_connections(connection_id)
                );
                INSERT OR IGNORE INTO client_meta(key,value) VALUES ('format','1');
                INSERT OR IGNORE INTO client_meta(key,value) VALUES ('active_connection_id',NULL);
                COMMIT;
                """
            )
            # Keep every compatibility ALTER and the identity binding in one
            # transaction.  Closing the connection rolls this transaction back
            # if validation or key inspection below fails partway through.
            connection.execute("BEGIN IMMEDIATE")
            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(client_connections)"
                ).fetchall()
            }
            if "peer_public_key_fingerprint" not in columns:
                connection.execute(
                    "ALTER TABLE client_connections "
                    "ADD COLUMN peer_public_key_fingerprint TEXT"
                )
            if "pairing_request_json" not in columns:
                connection.execute(
                    "ALTER TABLE client_connections ADD COLUMN pairing_request_json TEXT"
                )
            if "pairing_request_digest" not in columns:
                connection.execute(
                    "ALTER TABLE client_connections ADD COLUMN pairing_request_digest BLOB"
                )
            route_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(client_routes)"
                ).fetchall()
            }
            for name, declaration in (
                ("revoke_pending", "INTEGER NOT NULL DEFAULT 0"),
                ("revoke_expected_revision", "TEXT"),
                ("revoke_idempotency_key", "TEXT"),
            ):
                if name not in route_columns:
                    connection.execute(
                        f"ALTER TABLE client_routes ADD COLUMN {name} {declaration}"
                    )
            if "relay_available" not in columns:
                connection.execute(
                    "ALTER TABLE client_connections "
                    "ADD COLUMN relay_available INTEGER NOT NULL DEFAULT 0"
                )
            stored_identity = connection.execute(
                "SELECT value FROM client_meta WHERE key='server_identity'"
            ).fetchone()
            if stored_identity is None:
                discovered: set[str] = set()
                for attempt in connection.execute(
                    "SELECT request_json FROM client_pairing_attempts"
                ).fetchall():
                    try:
                        identity = json.loads(attempt["request_json"]).get(
                            "peer_server_identity"
                        )
                    except (TypeError, json.JSONDecodeError):
                        identity = None
                    if isinstance(identity, str):
                        discovered.add(identity)
                rows = connection.execute(
                    """SELECT certificate_path FROM client_connections
                    WHERE certificate_path IS NOT NULL"""
                ).fetchall()
                for row in rows:
                    try:
                        certificate = x509.load_pem_x509_certificate(
                            read_secret_file(Path(row["certificate_path"]))
                        )
                        binding = json.loads(
                            certificate.extensions.get_extension_for_oid(
                                PEER_BINDING_OID
                            ).value.value
                        )
                        identity = binding.get("peer_server_identity")
                    except Exception:
                        identity = None
                    if isinstance(identity, str):
                        discovered.add(identity)
                connection_count = int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM client_connections"
                    ).fetchone()["count"]
                )
                if discovered and discovered != {self.server_identity}:
                    raise PermissionError(
                        "secure peer client state is quarantined for another server identity"
                    )
                if connection_count and not discovered:
                    raise PermissionError(
                        "legacy secure peer client state cannot be identity-bound safely"
                    )
                connection.execute(
                    "INSERT INTO client_meta(key,value) VALUES ('server_identity',?)",
                    (self.server_identity,),
                )
            elif stored_identity["value"] != self.server_identity:
                raise PermissionError(
                    "secure peer client state is quarantined for another server identity"
                )
            for row in connection.execute(
                """SELECT connection_id,key_path FROM client_connections
                WHERE peer_public_key_fingerprint IS NULL"""
            ).fetchall():
                key = _load_private_key(Path(row["key_path"]))
                key_fingerprint = _fingerprint(
                    key.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
                connection.execute(
                    """UPDATE client_connections
                    SET peer_public_key_fingerprint=? WHERE connection_id=?
                    AND peer_public_key_fingerprint IS NULL""",
                    (key_fingerprint, row["connection_id"]),
                )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _decode_json_response(status: int, headers: list[tuple[str, str]], body: bytes) -> dict[str, Any]:
        content_types = [value.split(";", 1)[0].strip().lower() for name, value in headers if name.lower() == "content-type"]
        if content_types != ["application/json"]:
            raise SecurePeerError("remote_invalid", "Peer returned a non-JSON response", 502)
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecurePeerError("remote_invalid", "Peer returned invalid JSON", 502) from exc
        if not isinstance(value, dict):
            raise SecurePeerError("remote_invalid", "Peer returned invalid JSON", 502)
        if status >= 400:
            error = value.get("error") if isinstance(value.get("error"), dict) else {}
            code = error.get("code")
            message = error.get("message")
            if (
                not isinstance(code, str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None
                or not isinstance(message, str)
            ):
                raise SecurePeerError(
                    "remote_invalid", "Peer returned an invalid error response", 502
                )
            try:
                clean_message = _bounded_text(
                    message, "peer error message", 1, 400
                )
            except SecurePeerError as exc:
                raise SecurePeerError(
                    "remote_invalid", "Peer returned an invalid error response", 502
                ) from exc
            raise SecurePeerError(
                code,
                clean_message,
                status,
            )
        return value

    def _request(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | bytes | None = None,
        headers: Mapping[str, str] | None = None,
        context: ssl.SSLContext,
        no_sni: bool = False,
        maximum_response: int = MAX_RESPONSE_BODY_BYTES,
        timeout_seconds: float | None = None,
    ) -> tuple[int, list[tuple[str, str]], bytes, bytes]:
        connection_type = _NoSNIHTTPSConnection if no_sni else http.client.HTTPSConnection
        request_timeout = (
            self.timeout_seconds if timeout_seconds is None else float(timeout_seconds)
        )
        if not 0.1 <= request_timeout <= 600.0:
            raise ValueError("client request timeout is invalid")
        connection = connection_type(host, port, timeout=request_timeout, context=context)
        encoded: bytes | None
        # ``http.client`` treats header names case-insensitively, while a Python
        # dict does not.  Normalize caller-provided names before adding our
        # required headers so a forwarded ``accept`` cannot become a duplicate
        # wire-level header when we enforce the JSON accept header below.
        request_headers: dict[str, str] = {}
        for raw_name, raw_value in (headers or {}).items():
            name = str(raw_name).strip().lower()
            value = str(raw_value)
            if not name or name in request_headers:
                raise ValueError("client request headers are invalid")
            request_headers[name] = value
        if isinstance(body, Mapping):
            encoded = canonical_json(dict(body))
            request_headers["content-type"] = "application/json"
        else:
            encoded = body
        if encoded is not None:
            request_headers["content-length"] = str(len(encoded))
        request_headers["accept"] = "application/json"
        request_headers["connection"] = "close"
        if len(request_headers) > MAX_HEADERS or any(
            len(name) > 80 or len(value.encode("utf-8")) > MAX_HEADER_VALUE_BYTES
            or "\r" in value or "\n" in value
            for name, value in request_headers.items()
        ):
            raise ValueError("client request headers are invalid")
        try:
            connection.request(method, path, body=encoded, headers=request_headers)
            sock = connection.sock
            if sock is None:
                raise SecurePeerError("transport_failed", "TLS connection closed unexpectedly", 502)
            leaf = sock.getpeercert(binary_form=True)
            response = connection.getresponse()
            response_headers = response.getheaders()
            header_bytes = 0
            if len(response_headers) > MAX_HEADERS:
                raise SecurePeerError("remote_invalid", "Peer returned too many headers", 502)
            for name, value in response_headers:
                try:
                    encoded_name = name.encode("ascii")
                    encoded_value = value.encode("latin-1")
                except UnicodeEncodeError as exc:
                    raise SecurePeerError(
                        "remote_invalid", "Peer returned invalid headers", 502
                    ) from exc
                header_bytes += len(encoded_name) + len(encoded_value) + 4
                if (
                    not encoded_name
                    or len(encoded_name) > 80
                    or len(encoded_value) > MAX_HEADER_VALUE_BYTES
                ):
                    raise SecurePeerError(
                        "remote_invalid", "Peer returned invalid headers", 502
                    )
            if header_bytes > MAX_HEADER_BLOCK_BYTES:
                raise SecurePeerError(
                    "remote_invalid", "Peer returned oversized headers", 502
                )
            transfers = [value for name, value in response_headers if name.lower() == "transfer-encoding"]
            lengths = [value for name, value in response_headers if name.lower() == "content-length"]
            if (
                transfers
                or len(lengths) != 1
                or not lengths[0].isdigit()
                or len(lengths[0]) > len(str(MAX_ATTACHMENT_PROTOCOL_BYTES))
            ):
                raise SecurePeerError("remote_invalid", "Peer response length is invalid", 502)
            length = int(lengths[0])
            if length > MAX_ATTACHMENT_PROTOCOL_BYTES:
                raise SecurePeerError("remote_invalid", "Peer response length is invalid", 502)
            if method.upper() != "HEAD" and length > maximum_response:
                raise SecurePeerError("remote_invalid", "Peer response is too large", 502)
            response_body = b"" if method.upper() == "HEAD" else response.read(length + 1)
            if method.upper() != "HEAD" and len(response_body) != length:
                raise SecurePeerError("remote_invalid", "Peer response is truncated", 502)
            return response.status, response_headers, response_body, leaf
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise SecurePeerError("transport_failed", "Secure peer connection failed", 502) from exc
        finally:
            connection.close()

    @staticmethod
    def _unverified_context() -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
        return context

    @staticmethod
    def _validate_initial_identity(
        *,
        host_ip: str,
        expected_host_server_identity: str,
        leaf_der: bytes,
        ca_pem: str,
        expected_ca_fingerprint: str,
    ) -> tuple[x509.Certificate, x509.Certificate]:
        try:
            leaf = x509.load_der_x509_certificate(leaf_der)
            ca = x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
            ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)
            ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes)
            eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            addresses = sans.get_values_for_type(x509.IPAddress)
            identities = sans.get_values_for_type(x509.UniformResourceIdentifier)
            ca_constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
            ca_usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
            leaf_constraints = leaf.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except Exception as exc:
            raise SecurePeerError("host_identity_mismatch", "Host TLS identity is invalid", 409) from exc
        timestamp = datetime.now(timezone.utc)
        if (
            _certificate_fingerprint(ca) != expected_ca_fingerprint
            or leaf.issuer != ca.subject
            or not ca_constraints.ca
            or not ca_usage.key_cert_sign
            or leaf_constraints.ca
            or ExtendedKeyUsageOID.SERVER_AUTH not in eku
            or ExtendedKeyUsageOID.CLIENT_AUTH in eku
            or addresses != [ipaddress.ip_address(host_ip)]
            or identities
            != [f"urn:agentsdock:server:{expected_host_server_identity}"]
            or not ca.not_valid_before_utc <= timestamp < ca.not_valid_after_utc
            or not leaf.not_valid_before_utc <= timestamp < leaf.not_valid_after_utc
        ):
            raise SecurePeerError("host_identity_mismatch", "Host TLS identity does not match pairing", 409)
        return leaf, ca

    def _matching_pairing_attempt(
        self,
        host: str,
        port: int,
        *,
        expected_ca_fingerprint: str | None,
        requested_scopes: list[str],
        display_name: str,
    ) -> sqlite3.Row | None:
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT * FROM client_pairing_attempts
                WHERE host_ip=? AND port=? ORDER BY created_at,request_id""",
                (host, port),
            ).fetchall()
        finally:
            connection.close()
        for row in rows:
            try:
                request = json.loads(row["request_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise PermissionError("persisted pairing request is invalid") from exc
            if (
                request.get("request_id") != row["request_id"]
                or request.get("peer_server_identity") != self.server_identity
                or request.get("host_ca_fingerprint")
                != row["observed_ca_fingerprint"]
            ):
                raise PermissionError("persisted pairing request is invalid")
            if (
                (expected_ca_fingerprint is None
                 or row["observed_ca_fingerprint"] == expected_ca_fingerprint)
                and request.get("peer_display_name") == display_name
                and request.get("requested_scopes") == requested_scopes
            ):
                return row
        return None

    def begin_pairing(
        self,
        host_ip: str,
        port: int = 7851,
        *,
        expected_ca_fingerprint: str | None = None,
        request_id: str | None = None,
        requested_scopes: Iterable[str],
        display_name: str | None = None,
        resume_matching: bool = False,
    ) -> dict[str, Any]:
        with self._pairing_request_guard:
            host = canonical_peer_ipv4(host_ip)
            canonical_port = canonical_peer_port(port)
            requested_values = SecurePeerStore._canonical_scopes(requested_scopes)
            self._require_pairing_scopes_allowed(requested_values)
            selected_display_name = (
                self.display_name
                if display_name is None
                else _bounded_text(display_name, "peer display name", 1, 160)
            )
            if resume_matching:
                existing = self._matching_pairing_attempt(
                    host,
                    canonical_port,
                    expected_ca_fingerprint=expected_ca_fingerprint,
                    requested_scopes=requested_values,
                    display_name=selected_display_name,
                )
                if existing is not None:
                    request_id = str(existing["request_id"])
                    if expected_ca_fingerprint is None:
                        expected_ca_fingerprint = str(
                            existing["observed_ca_fingerprint"]
                        )
            return self._begin_pairing_locked(
                host,
                canonical_port,
                expected_ca_fingerprint=expected_ca_fingerprint,
                request_id=request_id,
                requested_scopes=requested_values,
                display_name=selected_display_name,
            )

    def _begin_pairing_locked(
        self,
        host_ip: str,
        port: int = 7851,
        *,
        expected_ca_fingerprint: str | None = None,
        request_id: str | None = None,
        requested_scopes: Iterable[str],
        display_name: str | None = None,
    ) -> dict[str, Any]:
        host = canonical_peer_ipv4(host_ip)
        canonical_port = canonical_peer_port(port)
        requested_values = SecurePeerStore._canonical_scopes(requested_scopes)
        self._require_pairing_scopes_allowed(requested_values)
        if expected_ca_fingerprint is not None and _HEX_FP_RE.fullmatch(expected_ca_fingerprint) is None:
            raise ValueError("expected CA fingerprint is invalid")
        context = self._unverified_context()
        status, headers, raw, health_leaf = self._request(
            host, canonical_port, "GET", "/v1/health", context=context, no_sni=True
        )
        health = self._decode_json_response(status, headers, raw)
        observed_fp = health.get("host_ca_fingerprint")
        try:
            host_server_identity = _identifier(
                health.get("host_server_identity"), "host server identity"
            )
            hub_id = _identifier(health.get("hub_id"), "Hub identity")
        except SecurePeerError as exc:
            raise SecurePeerError(
                "host_identity_mismatch",
                "Host discovery identity is invalid",
                409,
            ) from exc
        if (
            health.get("protocol_version") != PROTOCOL_VERSION
            or not isinstance(observed_fp, str)
            or _HEX_FP_RE.fullmatch(observed_fp) is None
            or expected_ca_fingerprint is not None
            and not hmac.compare_digest(observed_fp, expected_ca_fingerprint)
        ):
            raise SecurePeerError("host_identity_mismatch", "Host discovery identity is invalid", 409)
        health["host_server_identity"] = host_server_identity
        health["hub_id"] = hub_id
        timestamp = self._timestamp()
        canonical_request_id = (
            str(uuid.uuid4()) if request_id is None else _uuid(request_id, "request_id")
        )
        selected_display_name = (
            self.display_name
            if display_name is None
            else _bounded_text(display_name, "peer display name", 1, 160)
        )
        connection = self._connect()
        try:
            completed = connection.execute(
                "SELECT * FROM client_connections WHERE pairing_request_id=?",
                (canonical_request_id,),
            ).fetchone()
            if completed is not None:
                request_json = completed["pairing_request_json"]
                request_digest = completed["pairing_request_digest"]
                if (
                    completed["host_ip"] != host
                    or int(completed["port"]) != canonical_port
                    or completed["host_ca_fingerprint"] != observed_fp
                    or completed["host_server_identity"]
                    != health["host_server_identity"]
                    or completed["hub_id"] != health["hub_id"]
                    or request_json is None
                    or request_digest is None
                ):
                    raise SecurePeerError(
                        "idempotency_conflict",
                        "pairing request_id was reused for another host",
                        409,
                    )
                try:
                    persisted_request = json.loads(request_json)
                    persisted_unsigned = {
                        name: value
                        for name, value in persisted_request.items()
                        if name != "signature"
                    }
                    persisted_signature = _decode_b64(
                        persisted_request.get("signature"), "signature", 64, 64
                    )
                    persisted_key = _load_private_key(Path(completed["key_path"]))
                    persisted_key.public_key().verify(
                        persisted_signature, canonical_json(persisted_unsigned)
                    )
                except Exception as exc:
                    raise PermissionError(
                        "persisted pairing request is invalid"
                    ) from exc
                if (
                    not hmac.compare_digest(
                        bytes(request_digest),
                        hashlib.sha256(canonical_json(persisted_request)).digest(),
                    )
                    or persisted_request.get("request_id") != canonical_request_id
                    or persisted_request.get("peer_server_identity")
                    != self.server_identity
                    or persisted_request.get("peer_display_name")
                    != selected_display_name
                    or persisted_request.get("host_ca_fingerprint") != observed_fp
                    or persisted_request.get("requested_scopes") != requested_values
                    or not self._pairing_request_matches_configured_policy(
                        persisted_request
                    )
                    or completed["requested_scopes_json"]
                    != canonical_json(requested_values).decode("utf-8")
                ):
                    raise SecurePeerError(
                        "idempotency_conflict",
                        "pairing request_id was reused with different content",
                        409,
                    )
                return self.get_connection(completed["connection_id"])
            attempt = connection.execute(
                "SELECT * FROM client_pairing_attempts WHERE request_id=?",
                (canonical_request_id,),
            ).fetchone()
        finally:
            connection.close()
        if attempt is None:
            key = Ed25519PrivateKey.generate()
            request = build_pairing_request(
                key,
                server_identity=self.server_identity,
                display_name=selected_display_name,
                host_ca_fingerprint=observed_fp,
                request_id=canonical_request_id,
                created_at=timestamp,
                capabilities=self._pairing_capabilities,
                requested_scopes=requested_values,
            )
            connection_id = str(uuid.uuid4())
            key_path = self.keys_dir / f"{connection_id}.key.pem"
            create_secret_file(key_path, _private_key_pem(key))
            attempt_persisted = False
            self._pairing_capacity_lock.acquire()
            try:
                connection = self._connect()
            except BaseException:
                self._pairing_capacity_lock.release()
                # The key is created immediately before capacity admission.  A
                # database-open failure happens before the transaction/finally
                # below, so retire this exact, not-yet-persisted key here.
                with suppress(OSError):
                    key_path.unlink(missing_ok=True)
                raise
            try:
                connection.execute("BEGIN IMMEDIATE")
                if (
                    self._actionable_pairing_count(connection)
                    + self._external_pairing_count()
                    >= PAIRING_STATUS_LIMIT
                ):
                    raise SecurePeerError(
                        "pairing_capacity",
                        "Pairing request capacity is temporarily full",
                        503,
                    )
                connection.execute(
                    """INSERT INTO client_pairing_attempts(
                    request_id,connection_id,host_ip,port,observed_ca_fingerprint,
                    health_leaf_fingerprint,host_server_identity,hub_id,request_json,key_path,created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        canonical_request_id,
                        connection_id,
                        host,
                        canonical_port,
                        observed_fp,
                        _fingerprint(health_leaf),
                        health["host_server_identity"],
                        health["hub_id"],
                        canonical_json(request).decode("utf-8"),
                        str(key_path),
                        timestamp,
                    ),
                )
                connection.execute("COMMIT")
                attempt_persisted = True
                attempt = connection.execute(
                    "SELECT * FROM client_pairing_attempts WHERE request_id=?",
                    (canonical_request_id,),
                ).fetchone()
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
                self._pairing_capacity_lock.release()
                if not attempt_persisted:
                    key_path.unlink(missing_ok=True)
        else:
            request = json.loads(attempt["request_json"])
            expected_scopes = requested_values
            if (
                attempt["host_ip"] != host
                or int(attempt["port"]) != canonical_port
                or attempt["observed_ca_fingerprint"] != observed_fp
                or attempt["health_leaf_fingerprint"] != _fingerprint(health_leaf)
                or attempt["host_server_identity"] != health["host_server_identity"]
                or attempt["hub_id"] != health["hub_id"]
                or request.get("requested_scopes") != expected_scopes
                or request.get("peer_display_name") != selected_display_name
                or not self._pairing_request_matches_configured_policy(request)
            ):
                raise SecurePeerError(
                    "idempotency_conflict",
                    "pairing request_id was reused with different content",
                    409,
                )
            connection_id = attempt["connection_id"]
            key_path = Path(attempt["key_path"])
            _load_private_key(key_path)
        assert attempt is not None
        pairing_key = _load_private_key(Path(attempt["key_path"]))
        peer_public_key_fingerprint = _fingerprint(
            pairing_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        status, headers, raw, pair_leaf = self._request(
            host,
            canonical_port,
            "POST",
            "/v1/pairings",
            body=request,
            context=context,
            no_sni=True,
        )
        response = self._decode_json_response(status, headers, raw)
        if not hmac.compare_digest(_fingerprint(health_leaf), _fingerprint(pair_leaf)):
            self._retire_pairing_attempt(attempt)
            raise SecurePeerError("host_identity_mismatch", "Host TLS leaf changed during pairing", 409)
        ca_pem = response.get("host_ca_certificate_pem")
        try:
            ca_pem = _bounded_pem(ca_pem, "host CA", 128, 16_384)
        except SecurePeerError as exc:
            self._retire_pairing_attempt(attempt)
            raise SecurePeerError("remote_invalid", "Pairing response omitted host CA", 502)
        try:
            self._validate_initial_identity(
                host_ip=host,
                expected_host_server_identity=health["host_server_identity"],
                leaf_der=pair_leaf,
                ca_pem=ca_pem,
                expected_ca_fingerprint=observed_fp,
            )
        except SecurePeerError:
            self._retire_pairing_attempt(attempt)
            raise
        transcript = {
            "protocol_version": PROTOCOL_VERSION,
            "request": {key_name: request[key_name] for key_name in request if key_name != "signature"},
            "host_server_identity": health["host_server_identity"],
            "hub_id": health["hub_id"],
            "host_ca_fingerprint": observed_fp,
        }
        transcript_hash = hashlib.sha256(canonical_json(transcript)).hexdigest()
        if (
            response.get("host_server_identity") != health["host_server_identity"]
            or response.get("hub_id") != health["hub_id"]
            or response.get("host_ca_fingerprint") != observed_fp
            or response.get("transcript_hash") != transcript_hash
            or response.get("sas_words") != list(sas_words(transcript_hash))
            or response.get("requested_scopes") != request["requested_scopes"]
            or response.get("peer_public_key_fingerprint")
            != peer_public_key_fingerprint
            or not isinstance(response.get("pairing_id"), str)
            or _PAIR_ID_RE.fullmatch(response["pairing_id"]) is None
            or not isinstance(response.get("poll_token"), str)
            or _POLL_TOKEN_RE.fullmatch(response["poll_token"]) is None
            or type(response.get("expires_at")) is not int
            or response.get("status")
            not in {"pending", "approved", "rejected", "cancelled", "expired"}
        ):
            self._retire_pairing_attempt(attempt)
            raise SecurePeerError("transcript_mismatch", "Pairing transcript confirmation failed", 409)
        if response["status"] in {"rejected", "cancelled", "expired"}:
            self._retire_pairing_attempt(attempt)
            terminal_status = str(response["status"])
            raise SecurePeerError(
                f"pairing_{terminal_status}",
                f"Secure peer pairing was {terminal_status}",
                410,
            )
        ca_path = self.keys_dir / f"{connection_id}.ca.pem"
        if not ca_path.exists():
            create_secret_file(ca_path, ca_pem.encode("ascii"))
        elif read_secret_file(ca_path) != ca_pem.encode("ascii"):
            raise PermissionError("persisted pairing CA changed")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO client_connections(
                    connection_id,host_ip,port,status,pairing_id,pairing_request_id,poll_token,
                    pairing_request_json,pairing_request_digest,
                    host_server_identity,hub_id,host_ca_certificate_pem,host_ca_fingerprint,
                    transcript_hash,sas_json,key_path,created_at,updated_at
                    ,requested_scopes_json,peer_public_key_fingerprint
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    connection_id,
                    host,
                    canonical_port,
                    "pending",
                    response["pairing_id"],
                    canonical_request_id,
                    response["poll_token"],
                    canonical_json(request).decode("utf-8"),
                    hashlib.sha256(canonical_json(request)).digest(),
                    health["host_server_identity"],
                    health["hub_id"],
                    ca_pem,
                    observed_fp,
                    transcript_hash,
                    canonical_json(response["sas_words"]).decode("utf-8"),
                    str(key_path),
                    timestamp,
                    timestamp,
                    canonical_json(request["requested_scopes"]).decode("utf-8"),
                    peer_public_key_fingerprint,
                ),
            )
            connection.execute(
                "DELETE FROM client_pairing_attempts WHERE request_id=? AND connection_id=?",
                (canonical_request_id, connection_id),
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return self.get_connection(connection_id)

    def _retire_pairing_attempt(self, row: Mapping[str, Any]) -> bool:
        request_id = _uuid(row["request_id"], "request_id")
        connection_id = _uuid(row["connection_id"], "connection_id")
        expected_key_path = self.keys_dir / f"{connection_id}.key.pem"
        expected_ca_path = self.keys_dir / f"{connection_id}.ca.pem"
        if Path(row["key_path"]) != expected_key_path:
            raise PermissionError("persisted pairing key path is invalid")
        with self._pairing_capacity_lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """DELETE FROM client_pairing_attempts
                    WHERE request_id=? AND connection_id=? AND key_path=?""",
                    (request_id, connection_id, str(expected_key_path)),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        if cursor.rowcount == 1:
            cleanup_error: OSError | None = None
            for material_path in (expected_key_path, expected_ca_path):
                try:
                    material_path.unlink(missing_ok=True)
                except OSError as exc:
                    cleanup_error = cleanup_error or exc
            if cleanup_error is not None:
                raise cleanup_error
            return True
        return False

    def recover_pairing_attempts(self, *, limit: int = 2) -> dict[str, Any]:
        """Replay persisted pre-response pairing requests with their exact key/UUID."""

        bounded_limit = max(1, min(int(limit), 8))
        with self._pairing_request_guard:
            connection = self._connect()
            try:
                rows = connection.execute(
                    """SELECT * FROM client_pairing_attempts
                    ORDER BY created_at,request_id LIMIT ?""",
                    (bounded_limit,),
                ).fetchall()
            finally:
                connection.close()
            attempted = 0
            recovered: list[str] = []
            retired = 0
            first_error: tuple[str, str] | None = None
            timestamp = self._timestamp()
            for row in rows:
                if int(row["created_at"]) <= timestamp - PAIRING_ATTEMPT_RETENTION_SECONDS:
                    retired += int(self._retire_pairing_attempt(row))
                    continue
                try:
                    request = json.loads(row["request_json"])
                    if not isinstance(request, dict):
                        raise PermissionError("persisted pairing request is invalid")
                    requested = SecurePeerStore._canonical_scopes(
                        request.get("requested_scopes")
                    )
                    display = _bounded_text(
                        request.get("peer_display_name"),
                        "peer display name",
                        1,
                        160,
                    )
                    if (
                        request.get("request_id") != row["request_id"]
                        or request.get("peer_server_identity") != self.server_identity
                        or request.get("host_ca_fingerprint")
                        != row["observed_ca_fingerprint"]
                        or not self._pairing_request_matches_configured_policy(
                            request
                        )
                    ):
                        retired += int(self._retire_pairing_attempt(row))
                        continue
                    attempted += 1
                    result = self._begin_pairing_locked(
                        str(row["host_ip"]),
                        int(row["port"]),
                        expected_ca_fingerprint=str(
                            row["observed_ca_fingerprint"]
                        ),
                        request_id=str(row["request_id"]),
                        requested_scopes=requested,
                        display_name=display,
                    )
                    recovered.append(str(result["connection_id"]))
                except SecurePeerError as exc:
                    if exc.code == "pairing_expired":
                        retired += int(self._retire_pairing_attempt(row))
                    elif first_error is None:
                        first_error = (exc.code, exc.message)
                except Exception:
                    if first_error is None:
                        first_error = (
                            "pairing_recovery_failed",
                            "A persisted secure pairing request could not be recovered",
                        )
            connection = self._connect()
            try:
                remaining = int(
                    connection.execute(
                        "SELECT COUNT(*) AS count FROM client_pairing_attempts"
                    ).fetchone()["count"]
                )
            finally:
                connection.close()
            return {
                "attempted": attempted,
                "recovered": recovered,
                "retired": retired,
                "remaining": remaining,
                "error_code": first_error[0] if first_error else None,
                "error": first_error[1] if first_error else None,
            }

    @staticmethod
    def _public_connection(row: sqlite3.Row, active: str | None) -> dict[str, Any]:
        result = {field: row[field] for field in SecurePeerClient._PUBLIC_CONNECTION_FIELDS}
        result["port"] = int(result["port"])
        result["scopes"] = json.loads(result.pop("scopes_json")) if result["scopes_json"] else []
        result["sas_words"] = json.loads(result.pop("sas_json"))
        result["requested_scopes"] = json.loads(result.pop("requested_scopes_json"))
        relay_available = bool(result.pop("relay_available"))
        result["active"] = row["connection_id"] == active
        result["local_proxy_base_path"] = (
            f"/api/team-hub-secure/{row['connection_id']}"
            if result["active"] and row["status"] == "connected"
            else None
        )
        result["remote_route_delivery_available"] = bool(
            result["active"] and row["status"] == "connected" and relay_available
        )
        return result

    def _active_id(self, connection: sqlite3.Connection) -> str | None:
        row = connection.execute("SELECT value FROM client_meta WHERE key='active_connection_id'").fetchone()
        return row["value"] if row is not None else None

    def list_connections(self) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            active = self._active_id(connection)
            rows = connection.execute("SELECT * FROM client_connections ORDER BY created_at DESC").fetchall()
            return [self._public_connection(row, active) for row in rows]
        finally:
            connection.close()

    def get_connection(self, connection_id: str) -> dict[str, Any]:
        canonical = _uuid(connection_id, "connection_id")
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM client_connections WHERE connection_id=?", (canonical,)).fetchone()
            if row is None:
                raise SecurePeerError("connection_unavailable", "Secure peer connection is unavailable", 404)
            return self._public_connection(row, self._active_id(connection))
        finally:
            connection.close()

    def _connection_row(self, connection_id: str) -> sqlite3.Row:
        canonical = _uuid(connection_id, "connection_id")
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM client_connections WHERE connection_id=?", (canonical,)).fetchone()
            if row is None:
                raise SecurePeerError("connection_unavailable", "Secure peer connection is unavailable", 404)
            return row
        finally:
            connection.close()

    def _pinned_context(
        self,
        row: sqlite3.Row,
        *,
        mutual_tls: bool,
        certificate_path: str | None = None,
        key_path: str | None = None,
    ) -> ssl.SSLContext:
        ca = x509.load_pem_x509_certificate(row["host_ca_certificate_pem"].encode("ascii"))
        if _certificate_fingerprint(ca) != row["host_ca_fingerprint"]:
            raise PermissionError("stored host CA fingerprint is invalid")
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cadata=row["host_ca_certificate_pem"]
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if mutual_tls:
            selected_certificate = certificate_path or row["certificate_path"]
            selected_key = key_path or row["key_path"]
            if not selected_certificate:
                raise SecurePeerError("pairing_incomplete", "Peer certificate is unavailable", 409)
            context.load_cert_chain(selected_certificate, selected_key)
        return context

    def _validate_issued_client_certificate(
        self,
        pem: str,
        row: Mapping[str, Any],
        key: Ed25519PrivateKey,
        *,
        expected_peer_id: str,
        expected_team_id: str,
        expected_scopes: list[str],
        expected_transcript_hash: str,
    ) -> tuple[x509.Certificate, str, int]:
        try:
            certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
            ca = x509.load_pem_x509_certificate(
                str(row["host_ca_certificate_pem"]).encode("ascii")
            )
            ca.public_key().verify(
                certificate.signature, certificate.tbs_certificate_bytes
            )
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            eku = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            sans = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            uris = sans.get_values_for_type(x509.UniformResourceIdentifier)
            common_names = certificate.subject.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )
            binding = json.loads(
                certificate.extensions.get_extension_for_oid(
                    PEER_BINDING_OID
                ).value.value
            )
        except Exception as exc:
            raise SecurePeerError(
                "certificate_invalid", "Issued client certificate is invalid", 502
            ) from exc
        timestamp = datetime.fromtimestamp(self._timestamp(), timezone.utc)
        expected_binding = {
            "version": 1,
            "peer_id": expected_peer_id,
            "pairing_id": row["pairing_id"],
            "peer_server_identity": self.server_identity,
            "team_id": expected_team_id,
            "scopes": expected_scopes,
            "transcript_hash": expected_transcript_hash,
        }
        if (
            certificate.issuer != ca.subject
            or _certificate_fingerprint(ca) != row["host_ca_fingerprint"]
            or constraints.ca
            or ExtendedKeyUsageOID.CLIENT_AUTH not in eku
            or ExtendedKeyUsageOID.SERVER_AUTH in eku
            or len(common_names) != 1
            or common_names[0].value != self.server_identity
            or uris != [f"urn:agentsdock:server:{self.server_identity}"]
            or _public_key_pem(certificate.public_key())
            != _public_key_pem(key.public_key())
            or binding != expected_binding
            or not certificate.not_valid_before_utc
            <= timestamp
            < certificate.not_valid_after_utc
        ):
            raise SecurePeerError(
                "certificate_invalid", "Issued client certificate binding is invalid", 502
            )
        fingerprint = _certificate_fingerprint(certificate)
        expires_at = int(certificate.not_valid_after_utc.timestamp())
        return certificate, fingerprint, expires_at

    def poll_pairing(self, connection_id: str) -> dict[str, Any]:
        with self._pairing_request_guard:
            return self._poll_pairing_locked(connection_id)

    def _poll_pairing_locked(self, connection_id: str) -> dict[str, Any]:
        row = self._connection_row(connection_id)
        if row["status"] in {"rejected", "cancelled", "expired"}:
            # A process may have crashed after committing the terminal row but
            # before retiring its live-directory key and pinned CA files.
            self._retire_client_key_material(connection_id)
            return self.get_connection(connection_id)
        if row["status"] in {
            "approved",
            "connected",
            "deactivated",
        }:
            return self.get_connection(connection_id)
        status, headers, raw, _leaf = self._request(
            row["host_ip"],
            int(row["port"]),
            "GET",
            f"/v1/pairings/{row['pairing_id']}",
            headers={PAIRING_TOKEN_HEADER: row["poll_token"]},
            context=self._pinned_context(row, mutual_tls=False),
        )
        response = self._decode_json_response(status, headers, raw)
        if (
            response.get("pairing_id") != row["pairing_id"]
            or response.get("host_server_identity") != row["host_server_identity"]
            or response.get("hub_id") != row["hub_id"]
            or response.get("host_ca_fingerprint") != row["host_ca_fingerprint"]
            or response.get("transcript_hash") != row["transcript_hash"]
            or response.get("sas_words") != json.loads(row["sas_json"])
            or response.get("requested_scopes") != json.loads(row["requested_scopes_json"])
            or response.get("peer_public_key_fingerprint")
            != row["peer_public_key_fingerprint"]
        ):
            raise SecurePeerError("transcript_mismatch", "Pairing response identity changed", 409)
        remote_status = response.get("status")
        if remote_status not in {"pending", "approved", "rejected", "cancelled", "expired"}:
            raise SecurePeerError("remote_invalid", "Pairing response status is invalid", 502)
        timestamp = self._timestamp()
        certificate_path: str | None = row["certificate_path"]
        certificate_fp: str | None = row["certificate_fingerprint"]
        certificate_expires: int | None = row["certificate_expires_at"]
        if remote_status == "approved":
            pem = response.get("client_certificate_pem")
            if not isinstance(pem, str):
                raise SecurePeerError("remote_invalid", "Approved pairing omitted client certificate", 502)
            expected_peer_id = _uuid(response.get("peer_id"), "peer_id")
            expected_team_id = _identifier(response.get("team_id"), "team_id")
            expected_scopes = SecurePeerStore._canonical_scopes(
                response.get("scopes") if isinstance(response.get("scopes"), list) else []
            )
            if not set(expected_scopes).issubset(
                set(json.loads(row["requested_scopes_json"]))
            ):
                raise SecurePeerError(
                    "certificate_invalid", "Approved client scopes changed", 502
                )
            certificate, certificate_fp, certificate_expires = (
                self._validate_issued_client_certificate(
                    pem,
                    row,
                    _load_private_key(Path(row["key_path"])),
                    expected_peer_id=expected_peer_id,
                    expected_team_id=expected_team_id,
                    expected_scopes=expected_scopes,
                    expected_transcript_hash=row["transcript_hash"],
                )
            )
            cert_path = self.keys_dir / f"{connection_id}.certificate.pem"
            if not cert_path.exists():
                create_secret_file(cert_path, pem.encode("ascii"))
            elif read_secret_file(cert_path) != pem.encode("ascii"):
                raise PermissionError("approved certificate changed after persistence")
            certificate_path = str(cert_path)
        connection = self._connect()
        transitioned = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                """UPDATE client_connections SET status=?,peer_id=?,team_id=?,scopes_json=?,
                certificate_path=?,certificate_fingerprint=?,certificate_expires_at=?,updated_at=?
                WHERE connection_id=? AND pairing_id=? AND status='pending'""",
                (
                    remote_status,
                    response.get("peer_id"),
                    response.get("team_id"),
                    canonical_json(response.get("scopes", [])).decode("utf-8") if remote_status == "approved" else None,
                    certificate_path,
                    certificate_fp,
                    certificate_expires,
                    timestamp,
                    connection_id,
                    row["pairing_id"],
                ),
            ).rowcount
            if changed == 1:
                connection.execute("COMMIT")
                transitioned = True
            else:
                connection.execute("ROLLBACK")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        if not transitioned:
            # Another poll/client instance or an explicit Cancel won the exact
            # pending-state transition. Never replay this stale remote status.
            # If cancellation won after certificate validation, retire the
            # newly written credential material as well.
            current = self.get_connection(connection_id)
            if current["status"] in {"rejected", "cancelled", "expired"}:
                self._retire_client_key_material(connection_id)
                current = self.get_connection(connection_id)
            return current
        if remote_status in {"rejected", "cancelled", "expired"}:
            # Direct terminal polls own the same cleanup obligation as a
            # terminal state that wins the CAS in another client instance.
            # This removes the per-connection private key and pinned CA file
            # while retaining the non-secret database tombstone for replay.
            self._retire_client_key_material(connection_id)
        return self.get_connection(connection_id)

    def _retire_client_key_material(
        self,
        connection_id: str,
        *,
        renewal_request_id: str | None = None,
    ) -> None:
        """Move exact retired client material out of the live key directory."""

        canonical = _uuid(connection_id, "connection_id")
        stem = (
            f"{canonical}-{_uuid(renewal_request_id, 'request_id')}"
            if renewal_request_id is not None
            else canonical
        )
        retired = self.data_dir / "retired"
        ensure_private_directory(retired)
        if renewal_request_id is not None:
            retired = retired / "renewals" / canonical
            ensure_private_directory(retired.parent)
            ensure_private_directory(retired)
        for path in self.keys_dir.iterdir():
            if path.is_symlink() or not path.is_file():
                continue
            matches = (
                path.name.startswith(stem + ".")
                if renewal_request_id is not None
                else (
                    path.name.startswith(canonical + ".")
                    or path.name.startswith(canonical + "-")
                )
            )
            if not matches:
                continue
            destination = retired / f"{canonical}-{uuid.uuid4().hex}-{path.name}"
            try:
                os.replace(path, destination)
                os.chmod(destination, 0o600)
            except OSError:
                # The durable row no longer refers to this owner-only file. An
                # orphan is safer than recreating live authority after commit.
                pass
        if renewal_request_id is not None:
            candidates: list[tuple[int, str, Path]] = []
            for path in retired.iterdir():
                try:
                    info = path.lstat()
                except OSError:
                    continue
                if (
                    path.is_symlink()
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                ):
                    continue
                candidates.append((info.st_mtime_ns, path.name, path))
            for _mtime, _name, path in sorted(candidates, reverse=True)[
                RETIRED_RENEWAL_MATERIAL_LIMIT:
            ]:
                with suppress(OSError):
                    path.unlink()

    def _validated_live_client_material_path(
        self,
        connection_id: str,
        value: Any,
        kind: str,
    ) -> Path:
        """Validate one exact active key/certificate path before retirement."""

        canonical = _uuid(connection_id, "connection_id")
        if kind not in {"key", "certificate"}:
            raise ValueError("client material kind is invalid")
        candidate = Path(value) if isinstance(value, (str, os.PathLike)) else Path()
        if candidate.parent != self.keys_dir:
            raise PermissionError("persisted client material path is invalid")
        initial_name = f"{canonical}.{kind}.pem"
        renewal_match = re.fullmatch(
            rf"{re.escape(canonical)}-([0-9a-f-]{{36}})\.{kind}\.pem",
            candidate.name,
        )
        if candidate.name != initial_name:
            if renewal_match is None:
                raise PermissionError("persisted client material path is invalid")
            _uuid(renewal_match.group(1), "renewal request_id")
        return candidate

    def _retire_exact_superseded_client_material(
        self,
        connection_id: str,
        paths: Iterable[Path],
    ) -> None:
        """Move only transaction-captured superseded credentials, then bound them."""

        canonical = _uuid(connection_id, "connection_id")
        retired = self.data_dir / "retired" / "renewals" / canonical
        ensure_private_directory(retired.parent)
        ensure_private_directory(retired)
        for path in paths:
            destination = retired / f"{canonical}-{uuid.uuid4().hex}-{path.name}"
            try:
                os.replace(path, destination)
                os.chmod(destination, 0o600)
            except FileNotFoundError:
                continue
            except OSError:
                # The committed active row no longer references this exact
                # owner-private path; never risk moving any substitute name.
                continue
        candidates: list[tuple[int, str, Path]] = []
        for path in retired.iterdir():
            try:
                info = path.lstat()
            except OSError:
                continue
            if (
                path.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
            ):
                continue
            candidates.append((info.st_mtime_ns, path.name, path))
        for _mtime, _name, path in sorted(candidates, reverse=True)[
            RETIRED_RENEWAL_MATERIAL_LIMIT:
        ]:
            with suppress(OSError):
                path.unlink()

    def _abandon_uncredentialed_connection(
        self,
        row: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Retire authority while preserving an idempotent terminal tombstone."""

        canonical = _uuid(row["connection_id"], "connection_id")
        allowed = {"pending", "rejected", "cancelled", "expired"}
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM client_connections WHERE connection_id=?",
                (canonical,),
            ).fetchone()
            if (
                current is None
                or current["pairing_id"] != row["pairing_id"]
                or current["host_server_identity"] != row["host_server_identity"]
                or current["hub_id"] != row["hub_id"]
                or current["status"] not in allowed
                or current["certificate_path"] is not None
                or current["certificate_fingerprint"] is not None
            ):
                raise SecurePeerError(
                    "connection_changed",
                    "Secure peer pairing changed before local retirement",
                    409,
                )
            connection.execute(
                "UPDATE client_meta SET value=NULL "
                "WHERE key='active_connection_id' AND value=?",
                (canonical,),
            )
            connection.execute(
                "DELETE FROM client_routes WHERE connection_id=?", (canonical,)
            )
            connection.execute(
                "DELETE FROM client_renewals WHERE connection_id=?", (canonical,)
            )
            connection.execute(
                """UPDATE client_connections SET status='cancelled',updated_at=?
                WHERE connection_id=?""",
                (self._timestamp(), canonical),
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        self._retire_client_key_material(canonical)
        return self.get_connection(canonical)

    def cancel_pairing(
        self, connection_id: str, idempotency_key: str
    ) -> dict[str, Any]:
        with self._pairing_request_guard:
            return self._cancel_pairing_locked(connection_id, idempotency_key)

    def _cancel_pairing_locked(
        self, connection_id: str, idempotency_key: str
    ) -> dict[str, Any]:
        row = self._connection_row(connection_id)
        if row["status"] in {"rejected", "cancelled", "expired"}:
            return self._abandon_uncredentialed_connection(row)
        if row["status"] != "pending":
            raise SecurePeerError("pairing_not_pending", "Pairing is no longer pending", 409)
        try:
            status, headers, raw, _leaf = self._request(
                row["host_ip"],
                int(row["port"]),
                "POST",
                f"/v1/pairings/{row['pairing_id']}/cancel",
                body={"idempotency_key": _uuid(idempotency_key, "idempotency_key")},
                headers={PAIRING_TOKEN_HEADER: row["poll_token"]},
                context=self._pinned_context(row, mutual_tls=False),
            )
            response = self._decode_json_response(status, headers, raw)
            if response != {
                "pairing_id": row["pairing_id"],
                "status": "cancelled",
            }:
                raise SecurePeerError(
                    "remote_invalid", "Pairing cancellation response is invalid", 502
                )
        except SecurePeerError:
            # A pending pairing holds no usable client certificate.  If the
            # pinned host is gone, already pruned the request, or approved it
            # concurrently, retiring the local private key still makes the
            # operator's explicit Cancel terminal on this server. This is a
            # deliberate local-authority result, not a claim that the remote
            # cancellation committed; the terminal tombstone makes a lost
            # local response safely replayable with no second network request.
            return self._abandon_uncredentialed_connection(row)
        return self._abandon_uncredentialed_connection(row)

    def peer_health(self, connection_id: str) -> dict[str, Any]:
        with self._route_guard:
            return self._peer_health_locked(connection_id)

    def _peer_health_locked(self, connection_id: str) -> dict[str, Any]:
        row = self._connection_row(connection_id)
        if row["status"] not in {"approved", "connected", "deactivated"}:
            raise SecurePeerError("pairing_incomplete", "Secure peer connection is not approved", 409)
        status, headers, raw, _leaf = self._request(
            row["host_ip"], int(row["port"]), "GET", "/v1/peer/health",
            context=self._pinned_context(row, mutual_tls=True)
        )
        value = self._decode_json_response(status, headers, raw)
        if (
            value.get("peer_id") != row["peer_id"]
            or value.get("team_id") != row["team_id"]
            or value.get("host_server_identity") != row["host_server_identity"]
            or value.get("hub_id") != row["hub_id"]
            or value.get("host_ca_fingerprint") != row["host_ca_fingerprint"]
            or value.get("certificate_fingerprint") != row["certificate_fingerprint"]
            or value.get("certificate_expires_at") != row["certificate_expires_at"]
            or type(value.get("remote_route_delivery_available")) is not bool
        ):
            raise SecurePeerError("host_identity_mismatch", "Connected peer health identity changed", 409)
        validated_at = self._timestamp()
        connection = self._connect()
        try:
            changed = connection.execute(
                """UPDATE client_connections SET last_validated_at=?,updated_at=?,relay_available=?
                WHERE connection_id=? AND certificate_fingerprint=?""",
                (
                    validated_at,
                    validated_at,
                    int(value["remote_route_delivery_available"]),
                    connection_id,
                    row["certificate_fingerprint"],
                ),
            ).rowcount
            if changed != 1:
                raise SecurePeerError(
                    "connection_changed",
                    "Secure peer credential changed during validation",
                    409,
                )
        finally:
            connection.close()
        return value

    def set_active_connection(
        self, connection_id: str, *, expected_current: str | None
    ) -> dict[str, Any]:
        with self._route_guard:
            return self._set_active_connection_locked(
                connection_id,
                expected_current=expected_current,
            )

    def _set_active_connection_locked(
        self, connection_id: str, *, expected_current: str | None
    ) -> dict[str, Any]:
        canonical = _uuid(connection_id, "connection_id")
        if expected_current is not None:
            expected_current = _uuid(expected_current, "expected_current")
        self.peer_health(canonical)
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = self._active_id(connection)
            if current != expected_current:
                raise SecurePeerError("active_connection_changed", "Active secure peer connection changed", 409)
            row = connection.execute("SELECT status FROM client_connections WHERE connection_id=?", (canonical,)).fetchone()
            if row is None or row["status"] not in {"approved", "connected", "deactivated"}:
                raise SecurePeerError("pairing_incomplete", "Secure peer connection is not approved", 409)
            connection.execute(
                "UPDATE client_meta SET value=? WHERE key='active_connection_id'",
                (canonical,),
            )
            connection.execute(
                """UPDATE client_connections SET status='connected',last_validated_at=?,updated_at=?
                WHERE connection_id=?""",
                (timestamp, timestamp, canonical),
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return self.get_connection(canonical)

    activate_after_health = set_active_connection

    def deactivate_connection(
        self,
        connection_id: str,
        *,
        expected_host_server_identity: str,
        expected_hub_id: str,
    ) -> dict[str, Any]:
        with self._route_guard:
            return self._deactivate_connection_locked(
                connection_id,
                expected_host_server_identity=expected_host_server_identity,
                expected_hub_id=expected_hub_id,
            )

    def _deactivate_connection_locked(
        self,
        connection_id: str,
        *,
        expected_host_server_identity: str,
        expected_hub_id: str,
    ) -> dict[str, Any]:
        canonical = _uuid(connection_id, "connection_id")
        expected_host = _identifier(expected_host_server_identity, "expected host identity")
        expected_hub = _identifier(expected_hub_id, "expected hub id")
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM client_connections WHERE connection_id=?", (canonical,)
            ).fetchone()
            if (
                row is None
                or row["host_server_identity"] != expected_host
                or row["hub_id"] != expected_hub
            ):
                raise SecurePeerError("connection_changed", "Secure peer connection identity changed", 409)
            active = self._active_id(connection)
            if active == canonical:
                connection.execute(
                    "UPDATE client_meta SET value=NULL WHERE key='active_connection_id' AND value=?",
                    (canonical,),
                )
            if row["status"] not in {"approved", "connected", "deactivated"}:
                raise SecurePeerError(
                    "pairing_incomplete",
                    "Secure peer connection is not approved",
                    409,
                )
            connection.execute(
                "UPDATE client_connections SET status='deactivated',updated_at=? WHERE connection_id=?",
                (timestamp, canonical),
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return self.get_connection(canonical)

    def forget_connection(
        self,
        connection_id: str,
        *,
        expected_host_server_identity: str,
        expected_hub_id: str,
        expected_certificate_fingerprint: str,
    ) -> dict[str, Any]:
        with self._route_guard:
            return self._forget_connection_locked(
                connection_id,
                expected_host_server_identity=expected_host_server_identity,
                expected_hub_id=expected_hub_id,
                expected_certificate_fingerprint=expected_certificate_fingerprint,
            )

    def retire_remote_revoked_connection(
        self,
        connection_id: str,
        *,
        expected_host_server_identity: str,
        expected_hub_id: str,
        expected_certificate_fingerprint: str,
    ) -> dict[str, Any]:
        """Persist a pinned host's terminal revocation without forgetting its tombstone."""

        with self._route_guard:
            canonical = _uuid(connection_id, "connection_id")
            expected_host = _identifier(
                expected_host_server_identity,
                "expected host identity",
            )
            expected_hub = _identifier(expected_hub_id, "expected hub id")
            if _HEX_FP_RE.fullmatch(expected_certificate_fingerprint) is None:
                raise SecurePeerError(
                    "invalid_request",
                    "expected certificate fingerprint is invalid",
                    422,
                )
            timestamp = self._timestamp()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM client_connections WHERE connection_id=?",
                    (canonical,),
                ).fetchone()
                if (
                    row is None
                    or row["host_server_identity"] != expected_host
                    or row["hub_id"] != expected_hub
                    or row["certificate_fingerprint"]
                    != expected_certificate_fingerprint
                    or row["status"]
                    not in {"approved", "connected", "deactivated", "revoked"}
                ):
                    raise SecurePeerError(
                        "connection_changed",
                        "Secure peer connection identity changed",
                        409,
                    )
                connection.execute(
                    "UPDATE client_meta SET value=NULL "
                    "WHERE key='active_connection_id' AND value=?",
                    (canonical,),
                )
                connection.execute(
                    """UPDATE client_connections SET status='revoked',
                    relay_available=0,updated_at=?
                    WHERE connection_id=? AND certificate_fingerprint=?""",
                    (
                        timestamp,
                        canonical,
                        expected_certificate_fingerprint,
                    ),
                )
                # The authenticated host has already revoked this peer and all
                # routes associated with it. These local rows are terminal
                # receipts, not an outbox: retrying them with the revoked
                # credential can never succeed.
                connection.execute(
                    """UPDATE client_routes SET status='revoked',
                    revoke_pending=0,revoke_expected_revision=NULL,
                    revoke_idempotency_key=NULL,updated_at=?
                    WHERE connection_id=?""",
                    (timestamp, canonical),
                )
                connection.execute(
                    "DELETE FROM client_renewals WHERE connection_id=?",
                    (canonical,),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
            return self.get_connection(canonical)

    def _forget_connection_locked(
        self,
        connection_id: str,
        *,
        expected_host_server_identity: str,
        expected_hub_id: str,
        expected_certificate_fingerprint: str,
    ) -> dict[str, Any]:
        canonical = _uuid(connection_id, "connection_id")
        expected_host = _identifier(expected_host_server_identity, "expected host identity")
        expected_hub = _identifier(expected_hub_id, "expected hub id")
        if _HEX_FP_RE.fullmatch(expected_certificate_fingerprint) is None:
            raise SecurePeerError("invalid_request", "expected certificate fingerprint is invalid", 422)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM client_connections WHERE connection_id=?", (canonical,)
            ).fetchone()
            if (
                row is None
                or row["host_server_identity"] != expected_host
                or row["hub_id"] != expected_hub
                or row["certificate_fingerprint"] != expected_certificate_fingerprint
            ):
                raise SecurePeerError("connection_changed", "Secure peer connection identity changed", 409)
            unfinished_routes = int(
                connection.execute(
                    """SELECT COUNT(*) AS count FROM client_routes
                    WHERE connection_id=? AND NOT (
                        status='revoked' AND revoke_pending=0
                    )""",
                    (canonical,),
                ).fetchone()["count"]
            )
            if unfinished_routes:
                raise SecurePeerError(
                    "connection_retirement_pending",
                    "Published routes must finish retiring before this connection can be forgotten",
                    409,
                )
            active = self._active_id(connection)
            if active == canonical:
                connection.execute(
                    "UPDATE client_meta SET value=NULL WHERE key='active_connection_id' AND value=?",
                    (canonical,),
                )
            connection.execute("DELETE FROM client_routes WHERE connection_id=?", (canonical,))
            connection.execute("DELETE FROM client_renewals WHERE connection_id=?", (canonical,))
            connection.execute("DELETE FROM client_connections WHERE connection_id=?", (canonical,))
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        self._retire_client_key_material(canonical)
        return {
            "connection_id": canonical,
            "host_server_identity": expected_host,
            "hub_id": expected_hub,
            "certificate_fingerprint": expected_certificate_fingerprint,
            "status": "forgotten",
            "active": False,
        }

    def forget_expired_connection(
        self,
        connection_id: str,
        *,
        expected_host_server_identity: str,
        expected_hub_id: str,
        expected_certificate_fingerprint: str,
    ) -> dict[str, Any]:
        """Locally retire an exact credential the pinned host can no longer accept."""

        with self._route_guard:
            canonical = _uuid(connection_id, "connection_id")
            expected_host = _identifier(
                expected_host_server_identity, "expected host identity"
            )
            expected_hub = _identifier(expected_hub_id, "expected hub id")
            if _HEX_FP_RE.fullmatch(expected_certificate_fingerprint) is None:
                raise SecurePeerError(
                    "invalid_request",
                    "expected certificate fingerprint is invalid",
                    422,
                )
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM client_connections WHERE connection_id=?",
                    (canonical,),
                ).fetchone()
                if (
                    row is None
                    or row["host_server_identity"] != expected_host
                    or row["hub_id"] != expected_hub
                    or row["certificate_fingerprint"]
                    != expected_certificate_fingerprint
                ):
                    raise SecurePeerError(
                        "connection_changed",
                        "Secure peer connection identity changed",
                        409,
                    )
                if int(row["certificate_expires_at"] or 0) > self._timestamp():
                    raise SecurePeerError(
                        "certificate_not_expired",
                        "Secure peer certificate is still valid",
                        409,
                    )
                connection.execute(
                    "UPDATE client_meta SET value=NULL "
                    "WHERE key='active_connection_id' AND value=?",
                    (canonical,),
                )
                connection.execute(
                    "DELETE FROM client_routes WHERE connection_id=?", (canonical,)
                )
                connection.execute(
                    "DELETE FROM client_renewals WHERE connection_id=?", (canonical,)
                )
                connection.execute(
                    "DELETE FROM client_connections WHERE connection_id=?", (canonical,)
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
            self._retire_client_key_material(canonical)
            return {
                "connection_id": canonical,
                "host_server_identity": expected_host,
                "hub_id": expected_hub,
                "certificate_fingerprint": expected_certificate_fingerprint,
                "status": "forgotten",
                "active": False,
            }

    def _mutual_json(
        self,
        connection_id: str,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        row = self._connection_row(connection_id)
        status, response_headers, raw, _leaf = self._request(
            row["host_ip"], int(row["port"]), method, path, body=body, headers=headers,
            context=self._pinned_context(row, mutual_tls=True)
        )
        return self._decode_json_response(status, response_headers, raw)

    def revoke_remote_connection(
        self,
        connection_id: str,
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Revoke this exact mTLS credential before local Forget deletes it.

        Only the host's exact 200 revocation receipt is an acknowledgement.
        Generic authentication failures remain retryable and preserve local
        keys because they cannot prove that the logical peer was retired.
        """

        canonical = _uuid(connection_id, "connection_id")
        operation_id = _uuid(idempotency_key, "idempotency_key")
        row = self._connection_row(canonical)
        if row["status"] not in {
            "approved",
            "connected",
            "deactivated",
            "revoked",
        }:
            raise SecurePeerError(
                "pairing_incomplete",
                "Secure peer connection is not approved",
                409,
            )
        response = self._mutual_json(
            canonical,
            "POST",
            "/v1/peer/revoke",
            {"idempotency_key": operation_id},
        )
        if (
            response.get("peer_id") != row["peer_id"]
            or response.get("status") != "revoked"
            or response.get("idempotency_key") != operation_id
            or response.get("presented_certificate_fingerprint")
            != row["certificate_fingerprint"]
            or type(response.get("revoked_at")) is not int
        ):
            raise SecurePeerError(
                "remote_invalid",
                "Peer returned an invalid revocation response",
                502,
            )
        return {**response, "acknowledged": True}

    def remote_revocation_status(self, connection_id: str) -> dict[str, Any]:
        """Disambiguate logical revocation from a superseded certificate."""

        canonical = _uuid(connection_id, "connection_id")
        row = self._connection_row(canonical)
        response = self._mutual_json(
            canonical,
            "GET",
            "/v1/peer/status",
        )
        if (
            response.get("peer_id") != row["peer_id"]
            or response.get("status") not in {"active", "revoked"}
            or response.get("presented_certificate_fingerprint")
            != row["certificate_fingerprint"]
            or (
                response.get("revoked_at") is not None
                and type(response.get("revoked_at")) is not int
            )
            or (
                response.get("status") == "active"
                and response.get("revoked_at") is not None
            )
            or (
                response.get("status") == "revoked"
                and type(response.get("revoked_at")) is not int
            )
        ):
            raise SecurePeerError(
                "remote_invalid",
                "Peer returned an invalid trust-status response",
                502,
            )
        return response

    def _require_active_connection_locked(
        self,
        connection_id: str,
        *,
        relay_required: bool,
    ) -> sqlite3.Row:
        canonical = _uuid(connection_id, "connection_id")
        connection = self._connect()
        try:
            active_id = self._active_id(connection)
            row = connection.execute(
                "SELECT * FROM client_connections WHERE connection_id=?",
                (canonical,),
            ).fetchone()
        finally:
            connection.close()
        timestamp = self._timestamp()
        if (
            active_id != canonical
            or row is None
            or row["status"] != "connected"
            or (relay_required and not int(row["relay_available"] or 0))
            or int(row["last_validated_at"] or 0) < timestamp - 120
            or int(row["certificate_expires_at"] or 0) <= timestamp + 60
        ):
            raise SecurePeerError(
                "connection_unavailable",
                "Secure peer connection is not active and freshly verified",
                409,
            )
        return row

    def proxy(
        self,
        connection_id: str,
        method: str,
        hub_path: str,
        *,
        query: str = "",
        headers: Mapping[str, str] | None = None,
        body: Mapping[str, Any] | bytes | None = None,
    ) -> ProxyResponse:
        with self._route_guard:
            self._require_active_connection_locked(
                connection_id,
                relay_required=False,
            )
            response = self._proxy_locked(
                connection_id,
                method,
                hub_path,
                query=query,
                headers=headers,
                body=body,
            )
            # Proxy errors normally remain byte-for-byte upstream responses.
            # A pinned host's structured terminal revocation is the one
            # exception: surface it as a typed error so the runtime can retire
            # this exact credential before returning the same failure locally.
            if response.status == 401:
                try:
                    self._decode_json_response(
                        response.status,
                        list(response.headers),
                        response.body,
                    )
                except SecurePeerError as exc:
                    if exc.code == "peer_revoked" and exc.status_code == 401:
                        raise
            return response

    def _proxy_locked(
        self,
        connection_id: str,
        method: str,
        hub_path: str,
        *,
        query: str = "",
        headers: Mapping[str, str] | None = None,
        body: Mapping[str, Any] | bytes | None = None,
    ) -> ProxyResponse:
        if not hub_path.startswith("/v1/"):
            raise ValueError("Hub path must begin with /v1/")
        row = self._connection_row(connection_id)
        suffix = "?" + query if query else ""
        status, response_headers, raw, _leaf = self._request(
            row["host_ip"], int(row["port"]), method.upper(), "/v1/hub" + hub_path + suffix,
            body=body, headers=headers, context=self._pinned_context(row, mutual_tls=True)
        )
        return sanitize_proxy_response(
            ProxyResponse(status, tuple(response_headers), raw)
        )

    @staticmethod
    def _attachment_response_headers(
        status: int,
        response_headers: Iterable[tuple[str, str]],
    ) -> tuple[tuple[str, str], ...]:
        if not 200 <= status <= 599 or 300 <= status <= 399:
            raise SecurePeerError("remote_invalid", "Peer returned an invalid response", 502)
        allowed = {
            "accept-ranges",
            "cache-control",
            "content-disposition",
            "content-length",
            "content-range",
            "content-type",
            "etag",
            "x-content-type-options",
        }
        result: list[tuple[str, str]] = []
        seen: set[str] = set()
        for raw_name, raw_value in response_headers:
            name = str(raw_name).strip().lower()
            value = str(raw_value)
            if (
                not name
                or name in seen
                or len(name) > 80
                or len(value.encode("latin-1", "strict")) > MAX_HEADER_VALUE_BYTES
                or "\r" in value
                or "\n" in value
            ):
                raise SecurePeerError("remote_invalid", "Peer returned invalid headers", 502)
            seen.add(name)
            if name in allowed:
                result.append((name, value))
        return tuple(result)

    def upload_attachment_chunk(
        self,
        connection_id: str,
        hub_path: str,
        *,
        content_range: str,
        body: bytes,
    ) -> ProxyResponse:
        """Send one bounded, fixed-range attachment chunk over pinned mTLS."""

        if not is_attachment_proxy_path(hub_path):
            raise ValueError("attachment path is invalid")
        if not isinstance(body, bytes) or not 1 <= len(body) <= MAX_ATTACHMENT_CHUNK_BYTES:
            raise ValueError("attachment chunk is invalid")
        with self._route_guard:
            self._require_active_connection_locked(connection_id, relay_required=False)
            row = self._connection_row(connection_id)
            status, response_headers, raw, _leaf = self._request(
                row["host_ip"],
                int(row["port"]),
                "PUT",
                "/v1/hub" + hub_path,
                body=body,
                headers={
                    "content-type": "application/octet-stream",
                    "content-range": content_range,
                },
                context=self._pinned_context(row, mutual_tls=True),
                # A final chunk performs a whole-file hash and fsync before
                # replying. Keep the socket bounded but do not inherit the
                # ordinary 10-second JSON-control timeout.
                timeout_seconds=max(self.timeout_seconds, 300.0),
            )
            if status >= 400:
                self._decode_json_response(status, response_headers, raw)
            return ProxyResponse(
                status,
                self._attachment_response_headers(status, response_headers),
                raw,
            )

    def head_attachment(
        self, connection_id: str, hub_path: str
    ) -> ProxyResponse:
        """Read immutable attachment metadata without downloading its body."""

        if not is_attachment_proxy_path(hub_path):
            raise ValueError("attachment path is invalid")
        with self._route_guard:
            self._require_active_connection_locked(connection_id, relay_required=False)
            row = self._connection_row(connection_id)
            status, response_headers, raw, _leaf = self._request(
                row["host_ip"],
                int(row["port"]),
                "HEAD",
                "/v1/hub" + hub_path,
                context=self._pinned_context(row, mutual_tls=True),
                maximum_response=MAX_ATTACHMENT_PROTOCOL_BYTES,
            )
            if status >= 400:
                # HEAD intentionally has no error body. Preserve a small typed
                # failure without trusting an absent JSON envelope. A 401 is
                # kept as an unconfirmed revoke signal so the runtime can use
                # the separately pinned revocation-status endpoint before it
                # retires the durable connection.
                raise SecurePeerError(
                    "peer_revoked" if status == 401 else "attachment_unavailable",
                    (
                        "Secure peer authorization is no longer active"
                        if status == 401
                        else "Remote Team attachment is unavailable"
                    ),
                    status,
                )
            return ProxyResponse(
                status,
                self._attachment_response_headers(status, response_headers),
                raw,
            )

    def read_attachment_range(
        self,
        connection_id: str,
        hub_path: str,
        range_header: str,
        *,
        maximum_response: int = MAX_ATTACHMENT_CHUNK_BYTES,
    ) -> ProxyResponse:
        """Read one bounded range; full downloads must use download_attachment_to."""

        if not is_attachment_proxy_path(hub_path):
            raise ValueError("attachment path is invalid")
        if not 1 <= int(maximum_response) <= MAX_ATTACHMENT_BYTES:
            raise ValueError("maximum response is invalid")
        if _ATTACHMENT_RANGE_RE.fullmatch(str(range_header)) is None:
            raise ValueError("attachment range is invalid")
        with self._route_guard:
            self._require_active_connection_locked(connection_id, relay_required=False)
            row = self._connection_row(connection_id)
            status, response_headers, raw, _leaf = self._request(
                row["host_ip"],
                int(row["port"]),
                "GET",
                "/v1/hub" + hub_path,
                headers={"range": str(range_header)},
                context=self._pinned_context(row, mutual_tls=True),
                maximum_response=int(maximum_response),
            )
            if status >= 400 and status != 416:
                self._decode_json_response(status, response_headers, raw)
            return ProxyResponse(
                status,
                self._attachment_response_headers(status, response_headers),
                raw,
            )

    def download_attachment_to(
        self,
        connection_id: str,
        hub_path: str,
        destination: Path,
        *,
        expected_size: int,
    ) -> tuple[tuple[str, str], ...]:
        """Stream a full attachment to a new file without buffering it in RAM."""

        if not is_attachment_proxy_path(hub_path):
            raise ValueError("attachment path is invalid")
        if (
            type(expected_size) is not int
            or not 1 <= expected_size <= MAX_ATTACHMENT_PROTOCOL_BYTES
        ):
            raise ValueError("attachment size is invalid")
        destination = Path(destination)
        with self._route_guard:
            self._require_active_connection_locked(connection_id, relay_required=False)
            row = self._connection_row(connection_id)
            host = str(row["host_ip"])
            port = int(row["port"])
            context = self._pinned_context(row, mutual_tls=True)

        # Loading the exact certificate/key and validating active authority are
        # serialized with retirement. The potentially multi-gigabyte response
        # body is not: callers re-CAS the connection before publishing the
        # staged file, so unrelated route/health operations stay responsive.
        def download() -> tuple[tuple[str, str], ...]:
            connection = http.client.HTTPSConnection(
                host,
                port,
                timeout=max(self.timeout_seconds, 30.0),
                context=context,
            )
            try:
                connection.request(
                    "GET",
                    "/v1/hub" + hub_path,
                    headers={"Accept": "application/octet-stream", "Connection": "close"},
                )
                response = connection.getresponse()
                response_headers = response.getheaders()
                transfers = [
                    value
                    for name, value in response_headers
                    if name.lower() == "transfer-encoding"
                ]
                lengths = [
                    value
                    for name, value in response_headers
                    if name.lower() == "content-length"
                ]
                if (
                    transfers
                    or len(lengths) != 1
                    or not lengths[0].isdigit()
                    or int(lengths[0]) > MAX_ATTACHMENT_PROTOCOL_BYTES
                ):
                    raise SecurePeerError(
                        "remote_invalid", "Peer response length is invalid", 502
                    )
                length = int(lengths[0])
                if response.status >= 400:
                    if length > MAX_RESPONSE_BODY_BYTES:
                        raise SecurePeerError(
                            "remote_invalid", "Peer error response is too large", 502
                        )
                    raw = response.read(length + 1)
                    if len(raw) != length:
                        raise SecurePeerError(
                            "remote_invalid", "Peer response is truncated", 502
                        )
                    self._decode_json_response(response.status, response_headers, raw)
                if response.status != 200 or length != expected_size:
                    raise SecurePeerError(
                        "remote_invalid", "Peer attachment size changed", 502
                    )
                clean_headers = self._attachment_response_headers(
                    response.status, response_headers
                )
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(destination, flags, 0o600)
                try:
                    remaining = length
                    while remaining:
                        block = response.read(min(1024 * 1024, remaining))
                        if not block:
                            raise SecurePeerError(
                                "remote_invalid", "Peer attachment is truncated", 502
                            )
                        view = memoryview(block)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise OSError("Team attachment cache write stalled")
                            view = view[written:]
                        remaining -= len(block)
                    if response.read(1):
                        raise SecurePeerError(
                            "remote_invalid", "Peer attachment exceeded its length", 502
                        )
                    os.fsync(descriptor)
                except BaseException:
                    with suppress(OSError):
                        os.close(descriptor)
                    with suppress(OSError):
                        destination.unlink()
                    raise
                else:
                    os.close(descriptor)
                return clean_headers
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                with suppress(OSError):
                    destination.unlink()
                raise SecurePeerError(
                    "transport_failed", "Secure peer connection failed", 502
                ) from exc
            finally:
                connection.close()

        return download()

    def list_remote_routes(self, connection_id: str) -> list[dict[str, Any]]:
        row = self._connection_row(connection_id)
        response = self._mutual_json(connection_id, "GET", "/v1/routes")
        routes = response.get("routes")
        if not isinstance(routes, list) or len(routes) > 2_000:
            raise SecurePeerError("remote_invalid", "Remote route catalog is invalid", 502)
        result: list[dict[str, Any]] = []
        for value in routes:
            if not isinstance(value, dict):
                raise SecurePeerError("remote_invalid", "Remote route catalog is invalid", 502)
            route_id, revision, alias, title, actions = SecurePeerStore._route_descriptor(
                value.get("route_id"),
                value.get("revision"),
                value.get("alias"),
                value.get("display_title"),
                value.get("actions"),
            )
            result.append(
                {
                    "connection_id": connection_id,
                    "peer_server_identity": row["host_server_identity"],
                    "peer_display_name": row["host_server_identity"],
                    "team_id": row["team_id"],
                    "route_id": route_id,
                    "revision": revision,
                    "alias": alias,
                    "display_title": title,
                    "actions": actions,
                    "status": "active",
                }
            )
        return result

    def publish_route(
        self,
        connection_id: str,
        chat_id: str,
        alias: str,
        display_title: str,
        actions: list[str],
    ) -> dict[str, Any]:
        with self._route_guard:
            return self._publish_route_locked(
                connection_id,
                chat_id,
                alias,
                display_title,
                actions,
            )

    def _publish_route_locked(
        self,
        connection_id: str,
        chat_id: str,
        alias: str,
        display_title: str,
        actions: list[str],
    ) -> dict[str, Any]:
        canonical_connection = _uuid(connection_id, "connection_id")
        local_chat = _identifier(chat_id, "chat_id")
        timestamp = self._timestamp()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM client_routes WHERE connection_id=? AND chat_id=?",
                (canonical_connection, local_chat),
            ).fetchone()
            if existing is None:
                route_id = str(uuid.uuid4())
                revision = "rev_" + uuid.uuid4().hex
                route_id, revision, clean_alias, title, clean_actions = SecurePeerStore._route_descriptor(
                    route_id, revision, alias, display_title, actions
                )
                connection.execute(
                    """INSERT INTO client_routes(
                    route_id,connection_id,revision,alias,display_title,actions_json,chat_id,
                    status,created_at,updated_at
                    ) VALUES (?,?,?,?,?,?,?,'publishing',?,?)""",
                    (
                        route_id,
                        canonical_connection,
                        revision,
                        clean_alias,
                        title,
                        canonical_json(clean_actions).decode("utf-8"),
                        local_chat,
                        timestamp,
                        timestamp,
                    ),
                )
                existing = connection.execute(
                    "SELECT * FROM client_routes WHERE route_id=?", (route_id,)
                ).fetchone()
            else:
                if existing["status"] == "revoked":
                    if int(existing["revoke_pending"] or 0):
                        raise SecurePeerError(
                            "route_retirement_pending",
                            "The previous route is still being retired; retry after the peer reconnects",
                            503,
                        )
                    route_id = str(uuid.uuid4())
                    revision = "rev_" + uuid.uuid4().hex
                    route_id, revision, clean_alias, title, clean_actions = SecurePeerStore._route_descriptor(
                        route_id, revision, alias, display_title, actions
                    )
                    old_route_id = str(existing["route_id"])
                    connection.execute(
                        """UPDATE client_routes SET
                        route_id=?,revision=?,alias=?,display_title=?,actions_json=?,
                        status='publishing',revoke_pending=0,
                        revoke_expected_revision=NULL,revoke_idempotency_key=NULL,
                        updated_at=? WHERE route_id=? AND status='revoked'
                        AND revoke_pending=0""",
                        (
                            route_id,
                            revision,
                            clean_alias,
                            title,
                            canonical_json(clean_actions).decode("utf-8"),
                            timestamp,
                            old_route_id,
                        ),
                    )
                    existing = connection.execute(
                        "SELECT * FROM client_routes WHERE route_id=?",
                        (route_id,),
                    ).fetchone()
                else:
                    _route, _revision, clean_alias, title, clean_actions = SecurePeerStore._route_descriptor(
                        existing["route_id"], existing["revision"], alias, display_title, actions
                    )
                if (
                    existing is None
                    or existing["alias"] != clean_alias
                    or existing["display_title"] != title
                    or json.loads(existing["actions_json"]) != clean_actions
                ):
                    raise SecurePeerError("route_conflict", "This chat already has a different route", 409)
            connection.execute("COMMIT")
            assert existing is not None
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        descriptor = {
            "route_id": existing["route_id"],
            "revision": existing["revision"],
            "alias": existing["alias"],
            "display_title": existing["display_title"],
            "actions": json.loads(existing["actions_json"]),
        }
        remote = self._mutual_json(canonical_connection, "POST", "/v1/routes", descriptor)
        if any(remote.get(key) != value for key, value in descriptor.items()):
            raise SecurePeerError("remote_invalid", "Published route confirmation changed", 502)
        connection = self._connect()
        try:
            connection.execute(
                "UPDATE client_routes SET status='active',updated_at=? WHERE route_id=? AND status IN ('publishing','active')",
                (self._timestamp(), existing["route_id"]),
            )
        finally:
            connection.close()
        connection_state = self._connection_row(canonical_connection)
        return {
            **descriptor,
            "connection_id": canonical_connection,
            "peer_server_identity": connection_state["host_server_identity"],
            "team_id": connection_state["team_id"],
            "chat_id": local_chat,
            "status": "active",
        }

    def list_published_routes(self) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT r.*,c.host_server_identity,c.team_id
                FROM client_routes r JOIN client_connections c
                ON c.connection_id=r.connection_id
                ORDER BY r.created_at,r.route_id"""
            ).fetchall()
            return [
                {
                    "route_id": row["route_id"],
                    "connection_id": row["connection_id"],
                    "peer_server_identity": row["host_server_identity"],
                    "team_id": row["team_id"],
                    "revision": row["revision"],
                    "alias": row["alias"],
                    "display_title": row["display_title"],
                    "actions": json.loads(row["actions_json"]),
                    "chat_id": row["chat_id"],
                    "status": row["status"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def retire_agent_routes_locally(self) -> int:
        """Tombstone client routes and wider legacy pairing attempts offline."""

        with self._route_guard:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                changed = int(connection.execute(
                    """UPDATE client_routes SET status='revoked',revoke_pending=0,
                    revoke_expected_revision=NULL,revoke_idempotency_key=NULL,
                    updated_at=?
                    WHERE status IN ('publishing','active')
                    OR (status='revoked' AND revoke_pending=1)""",
                    (self._timestamp(),),
                ).rowcount or 0)
                incompatible_attempts = []
                for row in connection.execute(
                    "SELECT * FROM client_pairing_attempts ORDER BY created_at,request_id"
                ).fetchall():
                    try:
                        request = json.loads(row["request_json"])
                    except (TypeError, json.JSONDecodeError):
                        request = None
                    if not isinstance(request, dict) or not (
                        self._pairing_request_matches_configured_policy(request)
                    ):
                        incompatible_attempts.append(row)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
            for attempt in incompatible_attempts:
                changed += int(self._retire_pairing_attempt(attempt))
            return changed

    def revoke_published_route(
        self,
        connection_id: str,
        route_id: str,
        expected_revision: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        with self._route_guard:
            return self._revoke_published_route_locked(
                connection_id,
                route_id,
                expected_revision,
                idempotency_key,
            )

    def _revoke_published_route_locked(
        self,
        connection_id: str,
        route_id: str,
        expected_revision: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        canonical_connection = _uuid(connection_id, "connection_id")
        route = _uuid(route_id, "route_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM client_routes WHERE route_id=? AND connection_id=?",
                (route, canonical_connection),
            ).fetchone()
            if row is None:
                raise SecurePeerError("route_changed", "Local route state changed", 409)
            if (
                row["status"] in {"publishing", "active"}
                and row["revision"] == expected_revision
            ):
                connection.execute(
                    """UPDATE client_routes SET status='revoked',revoke_pending=1,
                    revoke_expected_revision=?,revoke_idempotency_key=?,updated_at=?
                    WHERE route_id=? AND connection_id=?
                    AND status IN ('publishing','active')
                    AND revision=?""",
                    (
                        expected_revision,
                        idempotency_key,
                        self._timestamp(),
                        route,
                        canonical_connection,
                        expected_revision,
                    ),
                )
            elif not (
                row["status"] == "revoked"
                and row["revoke_expected_revision"] == expected_revision
                and row["revoke_idempotency_key"] == idempotency_key
            ):
                raise SecurePeerError("route_changed", "Local route state changed", 409)
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return self._flush_published_route_revocation(route)

    def _flush_published_route_revocation(self, route_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM client_routes WHERE route_id=?",
                (route_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None or row["status"] != "revoked":
            raise SecurePeerError("route_changed", "Local route state changed", 409)
        if not int(row["revoke_pending"] or 0):
            return {
                "route_id": row["route_id"],
                "revision": row["revision"],
                "status": "revoked",
                "connection_id": row["connection_id"],
            }
        try:
            response = self._mutual_json(
                str(row["connection_id"]),
                "POST",
                f"/v1/routes/{row['route_id']}/revoke",
                {
                    "expected_revision": row["revoke_expected_revision"],
                    "idempotency_key": row["revoke_idempotency_key"],
                },
            )
        except SecurePeerError as exc:
            # A locally persisted `publishing` row may have crashed on either
            # side of the remote commit. With per-client route operations
            # serialized, a definite route_changed response proves that no
            # future publish of this immutable ID/revision can race in. Treat
            # the absent/already-retired remote route as a completed tombstone.
            if exc.code != "route_changed" or exc.status_code != 409:
                raise
            response = {
                "route_id": row["route_id"],
                "revision": "rev_" + uuid.uuid4().hex,
                "status": "revoked",
            }
        if (
            response.get("route_id") != row["route_id"]
            or response.get("status") != "revoked"
            or not isinstance(response.get("revision"), str)
        ):
            raise SecurePeerError("remote_invalid", "Route revocation response is invalid", 502)
        connection = self._connect()
        try:
            changed = connection.execute(
                """UPDATE client_routes SET revision=?,revoke_pending=0,updated_at=?
                WHERE route_id=? AND connection_id=? AND status='revoked'
                AND revoke_pending=1 AND revoke_expected_revision=?
                AND revoke_idempotency_key=?""",
                (
                    response["revision"],
                    self._timestamp(),
                    row["route_id"],
                    row["connection_id"],
                    row["revoke_expected_revision"],
                    row["revoke_idempotency_key"],
                ),
            ).rowcount
            if changed != 1:
                raise SecurePeerError("route_changed", "Local route state changed", 409)
        finally:
            connection.close()
        return {**response, "connection_id": row["connection_id"]}

    def flush_pending_route_revocations(self, *, limit: int = 20) -> int:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise SecurePeerError("invalid_request", "limit is invalid", 422)
        with self._route_guard:
            connection = self._connect()
            try:
                route_ids = [
                    str(row["route_id"])
                    for row in connection.execute(
                        """SELECT route_id FROM client_routes
                        WHERE status='revoked' AND revoke_pending=1
                        ORDER BY updated_at,route_id LIMIT ?""",
                        (limit,),
                    ).fetchall()
                ]
            finally:
                connection.close()
            flushed = 0
            first_error: SecurePeerError | None = None
            for pending_route_id in route_ids:
                try:
                    self._flush_published_route_revocation(pending_route_id)
                    flushed += 1
                except SecurePeerError as exc:
                    if first_error is None:
                        first_error = exc
            if first_error is not None:
                raise first_error
            return flushed

    def flush_pending_route_revocations_for_connection(
        self,
        connection_id: str,
        *,
        limit: int = 2_000,
    ) -> int:
        """Flush only one connection's durable tombstones before forgetting it."""

        canonical_connection = _uuid(connection_id, "connection_id")
        if type(limit) is not int or not 1 <= limit <= 2_000:
            raise SecurePeerError("invalid_request", "limit is invalid", 422)
        with self._route_guard:
            connection = self._connect()
            try:
                route_ids = [
                    str(row["route_id"])
                    for row in connection.execute(
                        """SELECT route_id FROM client_routes
                        WHERE connection_id=? AND status='revoked'
                        AND revoke_pending=1 ORDER BY updated_at,route_id LIMIT ?""",
                        (canonical_connection, limit),
                    ).fetchall()
                ]
            finally:
                connection.close()
            flushed = 0
            for pending_route_id in route_ids:
                self._flush_published_route_revocation(pending_route_id)
                flushed += 1
            return flushed

    def submit_envelope(self, connection_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        response = self._mutual_json(
            connection_id, "POST", "/v1/relay/envelopes", payload
        )
        if set(response) != {
            "envelope_id",
            "status",
            "used_legs",
            "max_legs",
            "expires_at",
            "exchange_id",
        }:
            raise SecurePeerError(
                "remote_invalid", "Relay confirmation is invalid", 502
            )
        try:
            envelope_id = _uuid(response.get("envelope_id"), "envelope_id")
            exchange_id = _uuid(response.get("exchange_id"), "exchange_id")
        except SecurePeerError as exc:
            raise SecurePeerError(
                "remote_invalid", "Relay confirmation identifiers are invalid", 502
            ) from exc
        requested_exchange = payload.get("exchange_id")
        if (
            response.get("status")
            not in {"queued", "claimed", "delivered", "failed", "expired"}
            or type(response.get("used_legs")) is not int
            or not 1 <= int(response["used_legs"]) <= MAX_RELAY_LEGS
            or response.get("max_legs") != MAX_RELAY_LEGS
            or type(response.get("expires_at")) is not int
            or response.get("expires_at") != payload.get("expires_at")
            or (
                requested_exchange is not None
                and exchange_id
                != str(uuid.UUID(str(requested_exchange)))
            )
            or (requested_exchange is None and response.get("used_legs") != 1)
        ):
            raise SecurePeerError(
                "remote_invalid", "Relay confirmation changed the request", 502
            )
        return {
            **response,
            "envelope_id": envelope_id,
            "exchange_id": exchange_id,
        }

    def submit_envelope_from_published_route(
        self,
        connection_id: str,
        *,
        source_route_id: str,
        source_route_revision: str,
        source_chat_id: str,
        action: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Linearize local route authorization with the remote submission."""

        canonical_connection = _uuid(connection_id, "connection_id")
        canonical_route = _uuid(source_route_id, "source_route_id")
        local_chat = _identifier(source_chat_id, "source chat id")
        if action not in {"instruction", "request_reply"}:
            raise SecurePeerError("invalid_request", "route action is invalid", 422)
        with self._route_guard:
            connection = self._connect()
            try:
                row = connection.execute(
                    """SELECT * FROM client_routes WHERE route_id=?
                    AND connection_id=? AND chat_id=? AND revision=?
                    AND status='active'""",
                    (
                        canonical_route,
                        canonical_connection,
                        local_chat,
                        source_route_revision,
                    ),
                ).fetchone()
                active_id = self._active_id(connection)
                connection_row = connection.execute(
                    """SELECT status,relay_available,last_validated_at,
                    certificate_expires_at FROM client_connections
                    WHERE connection_id=?""",
                    (canonical_connection,),
                ).fetchone()
            finally:
                connection.close()
            timestamp = self._timestamp()
            if (
                row is None
                or action not in set(json.loads(row["actions_json"]))
                or active_id != canonical_connection
                or connection_row is None
                or connection_row["status"] != "connected"
                or not int(connection_row["relay_available"] or 0)
                or int(connection_row["last_validated_at"] or 0)
                < timestamp - 120
                or int(connection_row["certificate_expires_at"] or 0)
                <= timestamp + 60
            ):
                raise SecurePeerError(
                    "route_changed",
                    "Secure peer source route is unavailable or changed",
                    409,
                )
            return self.submit_envelope(canonical_connection, payload)

    def claim_inbox(
        self, connection_id: str, *, lease_owner: str, limit: int = 20
    ) -> dict[str, Any]:
        with self._route_guard:
            self._require_active_connection_locked(
                connection_id,
                relay_required=True,
            )
            return self._claim_inbox_locked(
                connection_id,
                lease_owner=lease_owner,
                limit=limit,
            )

    def _claim_inbox_locked(
        self, connection_id: str, *, lease_owner: str, limit: int = 20
    ) -> dict[str, Any]:
        canonical_connection = _uuid(connection_id, "connection_id")
        if type(limit) is not int or not 1 <= limit <= 50:
            raise SecurePeerError("invalid_request", "limit is invalid", 422)
        owner = _identifier(lease_owner, "lease_owner")
        result = self._mutual_json(
            canonical_connection,
            "POST",
            "/v1/relay/inbox/claim",
            {"lease_owner": owner, "limit": limit},
        )
        envelopes = result.get("envelopes")
        if (
            set(result) != {"lease_token", "lease_expires_at", "envelopes"}
            or not isinstance(envelopes, list)
            or len(envelopes) > limit
        ):
            raise SecurePeerError("remote_invalid", "Relay claim response is invalid", 502)
        lease_token = result.get("lease_token")
        lease_expires_at = result.get("lease_expires_at")
        now = self._timestamp()
        if envelopes:
            if (
                not isinstance(lease_token, str)
                or not lease_token.startswith("lease.")
                or not 32 <= len(lease_token) <= 96
                or type(lease_expires_at) is not int
                or not now < lease_expires_at <= now + RELAY_LEASE_SECONDS + 5
            ):
                raise SecurePeerError(
                    "remote_invalid", "Relay claim lease is invalid", 502
                )
        elif lease_token is not None or lease_expires_at is not None:
            raise SecurePeerError("remote_invalid", "Empty relay claim has a lease", 502)
        connection_row = self._connection_row(canonical_connection)
        envelope_fields = {
            "envelope_id",
            "request_id",
            "source_peer_id",
            "source_server_identity",
            "source_route_id",
            "source_route_revision",
            "target_server_identity",
            "target_peer_id",
            "target_route_id",
            "target_route_revision",
            "team_id",
            "kind",
            "action",
            "exchange_id",
            "parent_envelope_id",
            "parent_leg",
            "used_legs",
            "max_legs",
            "expires_at",
            "body",
        }
        connection = self._connect()
        try:
            resolved: list[dict[str, Any]] = []
            seen_envelopes: set[str] = set()
            for envelope in envelopes:
                if not isinstance(envelope, dict) or set(envelope) != envelope_fields:
                    raise SecurePeerError(
                        "remote_invalid", "Relay claim response is invalid", 502
                    )
                uuid_fields = (
                    "envelope_id",
                    "request_id",
                    "source_route_id",
                    "target_route_id",
                    "exchange_id",
                )
                if any(
                    not isinstance(envelope.get(field), str)
                    or _UUID4_RE.fullmatch(envelope[field]) is None
                    for field in uuid_fields
                ):
                    raise SecurePeerError(
                        "remote_invalid", "Relay envelope identity is invalid", 502
                    )
                if (
                    envelope["parent_envelope_id"] is not None
                    and (
                        not isinstance(envelope["parent_envelope_id"], str)
                        or _UUID4_RE.fullmatch(envelope["parent_envelope_id"])
                        is None
                    )
                ):
                    raise SecurePeerError(
                        "remote_invalid", "Relay parent identity is invalid", 502
                    )
                if envelope["envelope_id"] in seen_envelopes:
                    raise SecurePeerError(
                        "remote_invalid", "Relay claim contains a duplicate", 502
                    )
                seen_envelopes.add(envelope["envelope_id"])
                route_id = envelope["target_route_id"]
                revision = envelope.get("target_route_revision")
                source_revision = envelope.get("source_route_revision")
                kind = envelope.get("kind")
                expected_action = (
                    "instruction" if kind == "instruction" else "request_reply"
                )
                if (
                    envelope.get("target_server_identity") != self.server_identity
                    or envelope.get("target_peer_id") != connection_row["peer_id"]
                    or envelope.get("team_id") != connection_row["team_id"]
                    or envelope.get("source_peer_id") is not None
                    or envelope.get("source_server_identity")
                    != connection_row["host_server_identity"]
                    or not isinstance(revision, str)
                    or re.fullmatch(r"rev_[0-9a-f]{32}", revision) is None
                    or not isinstance(source_revision, str)
                    or re.fullmatch(r"rev_[0-9a-f]{32}", source_revision) is None
                    or kind not in {"instruction", "request_reply", "response"}
                    or envelope.get("action") != expected_action
                    or type(envelope.get("used_legs")) is not int
                    or not 1 <= envelope["used_legs"] <= MAX_RELAY_LEGS
                    or envelope.get("max_legs") != MAX_RELAY_LEGS
                    or (
                        envelope["used_legs"] == 1
                        and (
                            envelope.get("parent_envelope_id") is not None
                            or envelope.get("parent_leg") is not None
                        )
                    )
                    or (
                        envelope["used_legs"] > 1
                        and (
                            envelope.get("parent_envelope_id") is None
                            or envelope.get("parent_leg")
                            != envelope["used_legs"] - 1
                        )
                    )
                    or (
                        envelope.get("parent_leg") is not None
                        and (
                            type(envelope["parent_leg"]) is not int
                            or not 1 <= envelope["parent_leg"] < envelope["used_legs"]
                        )
                    )
                    or type(envelope.get("expires_at")) is not int
                    or not now < envelope["expires_at"] <= now + MAX_RELAY_TTL_SECONDS
                    or not isinstance(envelope.get("body"), dict)
                    or len(canonical_json(envelope["body"])) > MAX_PROXY_BODY_BYTES
                ):
                    raise SecurePeerError(
                        "remote_invalid", "Relay envelope authorization is invalid", 502
                    )
                route = connection.execute(
                    """SELECT * FROM client_routes WHERE route_id=?
                    AND connection_id=? AND revision=? AND status='active'""",
                    (route_id, canonical_connection, revision),
                ).fetchone()
                if (
                    route is None
                    or expected_action not in json.loads(route["actions_json"])
                ):
                    # A publish response can be lost after the host commits the
                    # route while the client retains only its local
                    # ``publishing`` row.  That stale envelope must not poison
                    # otherwise valid siblings in the shared leased batch.
                    # Best-effort terminal receipt also prevents it from being
                    # reclaimed forever; a transient receipt failure is safe to
                    # retry on a later claim and still must not hide siblings.
                    try:
                        self._receipt_envelope_locked(
                            canonical_connection,
                            envelope["envelope_id"],
                            lease_token=lease_token,
                            outcome="failed",
                        )
                    except SecurePeerError:
                        pass
                    continue
                resolved.append({**envelope, "target_chat_id": route["chat_id"]})
            return {**result, "envelopes": resolved}
        finally:
            connection.close()

    def receipt_envelope(
        self,
        connection_id: str,
        envelope_id: str,
        *,
        lease_token: str,
        outcome: str,
    ) -> dict[str, Any]:
        with self._route_guard:
            self._require_active_connection_locked(
                connection_id,
                relay_required=True,
            )
            return self._receipt_envelope_locked(
                connection_id,
                envelope_id,
                lease_token=lease_token,
                outcome=outcome,
            )

    def receipt_envelope_for_published_route(
        self,
        connection_id: str,
        envelope_id: str,
        *,
        target_route_id: str,
        target_route_revision: str,
        lease_token: str,
        outcome: str,
    ) -> dict[str, Any]:
        canonical_connection = _uuid(connection_id, "connection_id")
        canonical_route = _uuid(target_route_id, "target_route_id")
        with self._route_guard:
            self._require_active_connection_locked(
                canonical_connection,
                relay_required=True,
            )
            connection = self._connect()
            try:
                route = connection.execute(
                    """SELECT route_id FROM client_routes WHERE route_id=?
                    AND connection_id=? AND revision=? AND status='active'""",
                    (
                        canonical_route,
                        canonical_connection,
                        target_route_revision,
                    ),
                ).fetchone()
            finally:
                connection.close()
            if route is None:
                raise SecurePeerError(
                    "route_changed",
                    "Secure peer receive route is unavailable or changed",
                    409,
                )
            return self._receipt_envelope_locked(
                canonical_connection,
                envelope_id,
                lease_token=lease_token,
                outcome=outcome,
            )

    def _receipt_envelope_locked(
        self,
        connection_id: str,
        envelope_id: str,
        *,
        lease_token: str,
        outcome: str,
    ) -> dict[str, Any]:
        return self._mutual_json(
            connection_id,
            "POST",
            f"/v1/relay/envelopes/{_uuid(envelope_id, 'envelope_id')}/receipt",
            {"lease_token": lease_token, "outcome": outcome},
        )

    def renew_if_due(self, connection_id: str) -> dict[str, Any]:
        with self._route_guard:
            return self._renew_if_due_locked(connection_id)

    def _discard_expired_client_renewal(
        self,
        connection_id: str,
        renewal: Mapping[str, Any],
    ) -> None:
        """CAS-retire one host-expired renewal so a fresh request can proceed."""

        canonical_connection = _uuid(connection_id, "connection_id")
        request_id = _uuid(renewal["request_id"], "request_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM client_renewals WHERE request_id=? AND connection_id=?",
                (request_id, canonical_connection),
            ).fetchone()
            if (
                current is None
                or current["status"] != renewal["status"]
                or current["old_certificate_fingerprint"]
                != renewal["old_certificate_fingerprint"]
                or current["key_path"] != renewal["key_path"]
                or current["certificate_path"] != renewal["certificate_path"]
                or current["certificate_fingerprint"]
                != renewal["certificate_fingerprint"]
            ):
                raise SecurePeerError(
                    "renewal_conflict", "Local renewal state changed", 409
                )
            if connection.execute(
                "DELETE FROM client_renewals WHERE request_id=? AND connection_id=?",
                (request_id, canonical_connection),
            ).rowcount != 1:
                raise SecurePeerError(
                    "renewal_conflict", "Local renewal state changed", 409
                )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        self._retire_client_key_material(
            canonical_connection,
            renewal_request_id=request_id,
        )

    def _renew_if_due_locked(
        self,
        connection_id: str,
        *,
        retry_expired: bool = True,
    ) -> dict[str, Any]:
        row = self._connection_row(connection_id)
        timestamp = self._timestamp()
        connection = self._connect()
        created_renewal_key: Path | None = None
        remove_unpersisted_key = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            pending = connection.execute(
                """SELECT * FROM client_renewals WHERE connection_id=?
                AND status IN ('pending','certificate_saved') ORDER BY created_at LIMIT 1""",
                (connection_id,),
            ).fetchone()
            if pending is None:
                if (
                    row["certificate_expires_at"] is None
                    or int(row["certificate_expires_at"]) - timestamp
                    > CLIENT_CERT_RENEW_WINDOW_SECONDS
                ):
                    connection.execute("COMMIT")
                    return {
                        "renewed": False,
                        "connection": self.get_connection(connection_id),
                    }
                if not row["certificate_fingerprint"]:
                    raise SecurePeerError(
                        "pairing_incomplete", "Current client certificate is unavailable", 409
                    )
                new_key = Ed25519PrivateKey.generate()
                request_id = str(uuid.uuid4())
                csr = _client_csr(new_key, self.server_identity)
                unsigned = {
                    "request_id": request_id,
                    "created_at": timestamp,
                    "peer_public_key_pem": _public_key_pem(new_key.public_key()),
                    "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                    "nonce": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                }
                payload = {
                    **unsigned,
                    "signature": base64.b64encode(
                        new_key.sign(canonical_json(unsigned))
                    ).decode("ascii"),
                }
                key_path = self.keys_dir / f"{connection_id}-{request_id}.key.pem"
                create_secret_file(key_path, _private_key_pem(new_key))
                created_renewal_key = key_path
                connection.execute(
                    """INSERT INTO client_renewals(
                    request_id,connection_id,old_certificate_fingerprint,request_json,key_path,
                    status,created_at,updated_at
                    ) VALUES (?,?,?,?,?,'pending',?,?)""",
                    (
                        request_id,
                        connection_id,
                        row["certificate_fingerprint"],
                        canonical_json(payload).decode("utf-8"),
                        str(key_path),
                        timestamp,
                        timestamp,
                    ),
                )
                pending = connection.execute(
                    "SELECT * FROM client_renewals WHERE request_id=?", (request_id,)
                ).fetchone()
            connection.execute("COMMIT")
            assert pending is not None
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            if created_renewal_key is not None:
                # COMMIT can fail ambiguously. Keep the key only when this
                # exact renewal row is now durably visible; otherwise the key
                # has no replay owner and must not accumulate in live keys.
                try:
                    persisted = connection.execute(
                        """SELECT key_path FROM client_renewals
                        WHERE request_id=? AND connection_id=?""",
                        (request_id, connection_id),
                    ).fetchone()
                except Exception:
                    persisted = {"key_path": str(created_renewal_key)}
                remove_unpersisted_key = (
                    persisted is None
                    or persisted["key_path"] != str(created_renewal_key)
                )
            raise
        finally:
            try:
                connection.close()
            finally:
                if remove_unpersisted_key and created_renewal_key is not None:
                    with suppress(OSError):
                        created_renewal_key.unlink(missing_ok=True)

        payload = json.loads(pending["request_json"])
        expected_renewal_key = (
            self.keys_dir
            / f"{_uuid(connection_id, 'connection_id')}-{_uuid(pending['request_id'], 'request_id')}.key.pem"
        )
        if Path(pending["key_path"]) != expected_renewal_key:
            raise PermissionError("persisted renewal key path is invalid")
        new_key = _load_private_key(expected_renewal_key)
        certificate_path = pending["certificate_path"]
        certificate_fingerprint = pending["certificate_fingerprint"]
        if pending["status"] == "pending":
            try:
                response = self._mutual_json(
                    connection_id, "POST", "/v1/renew", payload
                )
            except SecurePeerError as exc:
                if (
                    exc.code != "renewal_expired"
                    or not retry_expired
                    or int(pending["created_at"])
                    > self._timestamp() - RENEWAL_REQUEST_TTL_SECONDS
                ):
                    raise
                self._discard_expired_client_renewal(connection_id, pending)
                return self._renew_if_due_locked(
                    connection_id,
                    retry_expired=False,
                )
            pem = response.get("client_certificate_pem")
            if (
                set(response)
                != {
                    "peer_id",
                    "request_id",
                    "client_certificate_pem",
                    "certificate_fingerprint",
                    "certificate_expires_at",
                    "activation_required",
                }
                or not isinstance(pem, str)
                or response.get("peer_id") != row["peer_id"]
                or response.get("request_id") != pending["request_id"]
                or response.get("activation_required") is not True
            ):
                raise SecurePeerError("remote_invalid", "Renewal response is invalid", 502)
            certificate, certificate_fingerprint, certificate_expires_at = (
                self._validate_issued_client_certificate(
                    pem,
                    row,
                    new_key,
                    expected_peer_id=row["peer_id"],
                    expected_team_id=row["team_id"],
                    expected_scopes=json.loads(row["scopes_json"]),
                    expected_transcript_hash=row["transcript_hash"],
                )
            )
            if (
                response.get("certificate_fingerprint")
                != certificate_fingerprint
                or response.get("certificate_expires_at")
                != certificate_expires_at
            ):
                raise SecurePeerError(
                    "certificate_invalid",
                    "Renewed certificate confirmation changed",
                    502,
                )
            cert_path = self.keys_dir / f"{connection_id}-{pending['request_id']}.certificate.pem"
            if not cert_path.exists():
                create_secret_file(cert_path, pem.encode("ascii"))
            elif read_secret_file(cert_path) != pem.encode("ascii"):
                raise PermissionError("persisted renewal certificate changed")
            certificate_path = str(cert_path)
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    """UPDATE client_renewals SET certificate_path=?,certificate_fingerprint=?,
                    status='certificate_saved',updated_at=? WHERE request_id=? AND status='pending'""",
                    (
                        certificate_path,
                        certificate_fingerprint,
                        self._timestamp(),
                        pending["request_id"],
                    ),
                ).rowcount != 1:
                    raise SecurePeerError("renewal_conflict", "Local renewal state changed", 409)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        assert certificate_path and certificate_fingerprint
        certificate = x509.load_pem_x509_certificate(
            read_secret_file(Path(certificate_path))
        )
        try:
            status, response_headers, raw, _leaf = self._request(
                row["host_ip"],
                int(row["port"]),
                "POST",
                f"/v1/renewals/{pending['request_id']}/activate",
                body={"request_id": pending["request_id"]},
                context=self._pinned_context(
                    row,
                    mutual_tls=True,
                    certificate_path=certificate_path,
                    key_path=pending["key_path"],
                ),
            )
            activation = self._decode_json_response(status, response_headers, raw)
        except SecurePeerError as exc:
            if (
                exc.code not in {"renewal_expired", "renewal_unavailable"}
                or not retry_expired
                or (
                    exc.code == "renewal_expired"
                    and int(pending["created_at"])
                    > self._timestamp() - RENEWAL_REQUEST_TTL_SECONDS
                )
            ):
                raise
            # Always attempted activation first: an earlier response may have
            # been lost after the host committed, in which case activation is
            # idempotently successful even beyond the request TTL.
            self._discard_expired_client_renewal(connection_id, pending)
            return self._renew_if_due_locked(
                connection_id,
                retry_expired=False,
            )
        if (
            activation.get("activated") is not True
            or activation.get("request_id") != pending["request_id"]
            or activation.get("certificate_fingerprint") != certificate_fingerprint
        ):
            raise SecurePeerError("remote_invalid", "Renewal activation response is invalid", 502)
        connection = self._connect()
        superseded_material: tuple[Path, Path] | None = None
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                """SELECT key_path,certificate_path,certificate_fingerprint
                FROM client_connections WHERE connection_id=?""",
                (connection_id,),
            ).fetchone()
            if current is None:
                raise SecurePeerError(
                    "renewal_conflict", "Local certificate state changed", 409
                )
            if current["certificate_fingerprint"] == pending[
                "old_certificate_fingerprint"
            ]:
                old_key_path = self._validated_live_client_material_path(
                    connection_id, current["key_path"], "key"
                )
                old_certificate_path = self._validated_live_client_material_path(
                    connection_id, current["certificate_path"], "certificate"
                )
                superseded_material = (old_key_path, old_certificate_path)
            changed = connection.execute(
                """UPDATE client_connections SET key_path=?,certificate_path=?,
                certificate_fingerprint=?,certificate_expires_at=?,updated_at=?
                WHERE connection_id=? AND certificate_fingerprint=?""",
                (
                    pending["key_path"],
                    certificate_path,
                    certificate_fingerprint,
                    int(certificate.not_valid_after_utc.timestamp()),
                    self._timestamp(),
                    connection_id,
                    pending["old_certificate_fingerprint"],
                ),
            ).rowcount
            if changed != 1:
                if current is None or current["certificate_fingerprint"] != certificate_fingerprint:
                    raise SecurePeerError("renewal_conflict", "Local certificate state changed", 409)
                superseded_material = None
            if connection.execute(
                """UPDATE client_renewals SET status='activated',updated_at=?
                WHERE request_id=? AND connection_id=?
                AND status='certificate_saved'""",
                (self._timestamp(), pending["request_id"], connection_id),
            ).rowcount != 1:
                raise SecurePeerError(
                    "renewal_conflict", "Local renewal state changed", 409
                )
            connection.execute(
                """DELETE FROM client_renewals WHERE request_id IN (
                SELECT request_id FROM client_renewals
                WHERE connection_id=? AND status='activated' AND request_id<>?
                ORDER BY updated_at DESC,request_id DESC
                LIMIT -1 OFFSET ?
                )""",
                (
                    connection_id,
                    pending["request_id"],
                    ACTIVATED_RENEWAL_HISTORY_LIMIT - 1,
                ),
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        if superseded_material is not None:
            self._retire_exact_superseded_client_material(
                connection_id, superseded_material
            )
        return {"renewed": True, "connection": self.get_connection(connection_id)}
