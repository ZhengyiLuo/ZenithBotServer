"""Transactional application service for the runnable Team Hub V1 API."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
from contextlib import contextmanager, suppress
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

try:
    import fcntl
except ImportError:  # pragma: no cover - Team Hub storage is Unix-only in V1.
    fcntl = None  # type: ignore[assignment]

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .auth import (
    AuthenticationError,
    AuthorizationError,
    INVITATION_MAX_TTL_SECONDS,
    _bounded_text,
    _canonical_ed25519_public_key,
    _email,
    _id,
    _identity,
    _require_team_role,
    _token_digest,
    _ttl,
    _write_transaction,
    bootstrap_personal_team,
    issue_invitation,
    issue_node_enrollment,
    redeem_invitation,
)
from .database import LATEST_SCHEMA_VERSION, MIGRATIONS, open_database
from .security import (
    ACCESS_TOKEN_TTL_SECONDS,
    BOOTSTRAP_PROOF_TTL_SECONDS,
    SESSION_TTL_SECONDS,
    AccessTokenSigner,
    TokenError,
    canonical_fingerprint,
    canonical_json,
    create_secret_file,
    ensure_private_directory,
    load_or_create_signing_key,
    now_seconds,
    opaque_secret,
    read_secret_file,
    token_hash,
)
from .secure_peer import AttachmentFileLease


NODE_CHALLENGE_TTL_SECONDS = 2 * 60
RECOVERY_PROOF_TTL_SECONDS = 10 * 60
TAILNET_BOOTSTRAP_PROOF_TTL_SECONDS = 5 * 60
MAX_BOOTSTRAP_DELEGATION_LEDGER_ROWS = 256
MAX_NETWORK_AGENTS_PER_SERVER = 256
MAX_NETWORK_BODY_BYTES = 8_192
MAX_NETWORK_PAGE_ITEMS = 100
MAX_HUMAN_ADMIN_PAGE_ITEMS = 100
MAX_SECURE_PEER_BINDING_LOOKUP_IDS = 512
SECURE_PEER_HEARTBEAT_WRITE_INTERVAL_SECONDS = 15
# Secure-peer responses are hard-capped at 2 MiB. Keep paged network payloads
# below that transport ceiling, including JSON escaping and envelope fields.
MAX_NETWORK_PAGE_RESPONSE_BYTES = 1_900_000
# Team Messages V2 (docs/TEAM_MESSAGES_V2.md). Bodies stay inside the 64 KiB
# JSON request limit; attachment bytes never travel through JSON or SQLite.
MAX_TEAM_MESSAGE_BODY_BYTES = 49_152
MAX_TEAM_MESSAGE_RECIPIENTS = 16
MAX_TEAM_MESSAGE_ATTACHMENTS = 16
MAX_TEAM_MESSAGE_ATTACHMENT_BYTES = 2 * 1024 * 1024 * 1024
MAX_TEAM_MESSAGE_TITLE_CHARS = 160
MAX_TEAM_MESSAGE_PREVIEW_CHARS = 280
TEAM_MESSAGE_PROVENANCE_KEYS = ("via", "backend", "chat_id", "run_id")
DEFAULT_TEAM_ATTACHMENT_MAX_BYTES = 512 * 1024 * 1024
DEFAULT_TEAM_ATTACHMENT_QUOTA_BYTES = 50 * 1024 * 1024 * 1024
TEAM_ATTACHMENT_CHUNK_BYTES = 8 * 1024 * 1024
# The secure-peer Content-Length and Content-Range grammar permits at most
# fifteen decimal digits. Keep persisted Hub settings inside that protocol
# ceiling so health never advertises a file size the binary lane will reject.
MAX_TEAM_ATTACHMENT_PROTOCOL_BYTES = 999_999_999_999_999
MAX_SQLITE_SIGNED_INTEGER = 9_223_372_036_854_775_807
TEAM_ATTACHMENT_UPLOAD_TTL_SECONDS = 24 * 60 * 60
# Opportunistic cleanup is intentionally bounded so an ordinary declaration
# cannot turn into an unbounded maintenance request after a long offline period.
TEAM_ATTACHMENT_RECLAIM_BATCH = 128
TEAM_ATTACHMENT_CLEANUP_BATCH = 2 * TEAM_ATTACHMENT_RECLAIM_BATCH
MAX_TEAM_SKILLS_PER_TEAM = 500
MAX_TEAM_SKILL_VERSIONS = 200
MAX_TEAM_SKILL_TAGS = 8
RESTORE_TRANSACTION_JOURNAL_NAME = ".restore-transaction.json"
RESTORE_COMPLETION_RECEIPT_NAME = ".restore-completion.json"
SNAPSHOT_REBASE_JOURNAL_NAME = ".snapshot-rebase.json"
HOST_REACTIVATION_HANDOFF_NAME = ".host-reactivation-handoff.json"
MANAGED_STARTUP_GUARD_NAME = ".managed-startup-guard.json"
MANAGED_STARTUP_AUTHORITY_NAME = ".managed-startup-authority.json"
MAINTENANCE_FENCE_STAGING_RE = re.compile(
    r"^\.maintenance-fence-host-reactivation-[0-9a-f]{24}\.pending$"
)
SNAPSHOT_REBASE_RETIRED_RE = re.compile(
    r"^\.snapshot-rebase-[0-9a-f]{24}\.old$"
)
RESTORE_STAGING_NAME_RE = re.compile(r"^\.restore-[1-9][0-9]*-[0-9a-f]{16}$")
SNAPSHOT_STAGING_NAME_RE = re.compile(
    r"^\.snapshot_[0-9]{20}_[0-9a-f]{16}\.tmp$"
)
TEAM_SKILL_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
TEAM_SKILL_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
TEAM_ATTACHMENT_FILE_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f/\\]{1,255}$")
TEAM_ATTACHMENT_MEDIA_TYPE_RE = re.compile(
    r"^[A-Za-z0-9!#$&^_.+-]{1,64}/[A-Za-z0-9!#$&^_.+-]{1,64}(?:;[ -~]{1,90})?$"
)
TEAM_ATTACHMENT_ID_RE = re.compile(r"^tatt_[0-9a-f]{32}$")
TEAM_ATTACHMENT_STORAGE_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
LOCAL_CONTROL_PRINCIPAL_ID = "service_local_control"
MANAGED_SERVER_PRINCIPAL_ID = "service_managed_server"
MANAGED_SERVER_SERVICE_IDENTIFIER = "agentsdock.team-hub.managed-server"
NETWORK_AUTOMATION_AUTH_KINDS = frozenset(
    {"secure_peer", "local_agent_mail", "managed_server"}
)
MANAGED_HOST_AUTH_KINDS = frozenset({"local_agent_mail", "managed_server"})


class HubError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class _TeamAttachmentFailure(Exception):
    """Carry a terminal upload error out of a rolled-back chunk transaction."""

    def __init__(self, error: HubError) -> None:
        super().__init__(error.message)
        self.error = error


@dataclass(frozen=True)
class _TeamAttachmentSnapshotFile:
    """One file required to make attachment metadata restorable."""

    relative_path: str
    byte_size: int
    content_sha256: str | None


@dataclass(frozen=True)
class AccessClaims:
    principal_id: str
    session_id: str
    jti: str
    expires_at: int
    auth_kind: str = "human"
    team_id: str | None = None
    scopes: frozenset[str] = frozenset()
    peer_id: str | None = None


def _now(value: int | None = None) -> int:
    return now_seconds() if value is None else int(value)


def _positive_int_env(name: str, default: int, *, maximum: int) -> int:
    """Read a host-level size limit; malformed or non-positive values fall back."""

    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if 0 < value <= maximum else default


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def _iso8601(value: int | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _maintenance_operation_id(value: str) -> str:
    operation_id = _bounded_text(value, "operation_id", 1, 128)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", operation_id) is None:
        raise ValueError("operation_id is invalid")
    return operation_id


class HubStore:
    """One authoritative SQLite-backed Hub with per-operation connections."""

    @staticmethod
    def _open_lock_file(path: Path) -> int:
        ensure_private_directory(path.parent)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
            ):
                raise PermissionError("Team Hub lock file is unsafe")
            os.fchmod(descriptor, 0o600)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @classmethod
    def acquire_managed_runtime_lease(cls, data_dir: Path) -> int:
        """Acquire the one-process lease required by an embedded listener."""

        if fcntl is None:
            raise RuntimeError("managed Team Hub host locking is unavailable")
        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        # Keep the lease beside, not inside, the Hub directory so a foreign
        # copied bound database can be rejected without changing its file set.
        descriptor = cls._open_lock_file(
            root.parent / f".{root.name}.managed-host.lock"
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(descriptor)
            raise RuntimeError("another managed Team Hub host is already active") from exc
        return descriptor

    @staticmethod
    def release_managed_runtime_lease(descriptor: int | None) -> None:
        if descriptor is None:
            return
        if fcntl is None:
            os.close(descriptor)
            return
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    @classmethod
    @contextmanager
    def maintenance_control_lock(
        cls,
        data_dir: Path,
        *,
        timeout_seconds: float = 5.0,
    ):
        """Serialize local proof control, snapshots, and offline restores."""

        if fcntl is None:
            raise RuntimeError("Team Hub local-control locking is unavailable")
        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        descriptor = cls._open_lock_file(root / "maintenance-control.lock")
        deadline = time.monotonic() + max(0.1, float(timeout_seconds))
        try:
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Team Hub local control is busy")
                    time.sleep(0.025)
            cls._cleanup_orphaned_maintenance_fence_staging_unlocked(root)
            if cls._snapshot_rebase_pending(root):
                attachment_lease = cls.acquire_attachment_control_lease(root)
                try:
                    cls._recover_snapshot_rebase_unlocked(root)
                finally:
                    cls.release_attachment_control_lease(attachment_lease)
            attachment_lease = cls.acquire_attachment_control_lease(root)
            try:
                cls._cleanup_orphaned_snapshot_rebase_retired_unlocked(root)
            finally:
                cls.release_attachment_control_lease(attachment_lease)
            if cls._restore_recovery_pending(root):
                attachment_lease = cls.acquire_attachment_control_lease(root)
                try:
                    journal_pending = cls._restore_transaction_pending(root)
                    protected_staging: Path | None = None
                    if journal_pending:
                        _journal, protected_staging, _old, _new = (
                            cls._read_restore_transaction_journal(root)
                        )
                    cls._cleanup_abandoned_restore_staging_unlocked(
                        root,
                        protected_staging=protected_staging,
                    )
                    if journal_pending:
                        cls._recover_interrupted_restore_unlocked(root)
                    cls._cleanup_abandoned_restore_staging_unlocked(root)
                    cls._clear_orphaned_host_reactivation_restore_fence_unlocked(
                        root
                    )
                finally:
                    cls.release_attachment_control_lease(attachment_lease)
            yield
        finally:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @classmethod
    def acquire_attachment_control_lease(
        cls,
        data_dir: Path,
        *,
        timeout_seconds: float = 30.0,
    ) -> int:
        """Serialize attachment file mutation with maintenance snapshots."""

        if fcntl is None:
            raise RuntimeError("Team Hub attachment locking is unavailable")
        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        descriptor = cls._open_lock_file(root / "attachment-control.lock")
        deadline = time.monotonic() + max(0.1, float(timeout_seconds))
        try:
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return descriptor
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Team Hub attachment control is busy")
                    time.sleep(0.025)
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def release_attachment_control_lease(descriptor: int | None) -> None:
        if descriptor is None:
            return
        if fcntl is None:
            os.close(descriptor)
            return
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def __init__(
        self,
        data_dir: Path,
        *,
        now: int | None = None,
        managed_host_identity: str | None = None,
        managed_server_instance_id: str | None = None,
        managed_host_display_name: str = "Team Hub host",
        allow_bound_control: bool = False,
        maintenance_control_locked: bool = False,
        managed_reactivation_hub_id: str | None = None,
        managed_reactivation_operation_id: str | None = None,
        managed_reactivation_snapshot: Path | None = None,
        managed_update_hub_id: str | None = None,
        managed_update_operation_id: str | None = None,
        managed_update_snapshot: Path | None = None,
    ) -> None:
        self.data_dir = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        self.database_path = self.data_dir / "team-hub.sqlite3"
        self.signing_key_path = self.data_dir / "access-token-signing.key"
        self.bootstrap_proof_path = self.data_dir / "bootstrap-owner.proof"
        self.maintenance_fence_path = self.data_dir / "maintenance-fence.json"
        if maintenance_control_locked and not allow_bound_control:
            raise RuntimeError("Team Hub control-lock ownership is invalid")
        try:
            self._read_managed_startup_guard_unlocked(self.data_dir)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("Team Hub cold handoff startup guard is active")
        # A completed offline snapshot restore is not safe to expose until the
        # outer release-activation ledger has durably restored the prior
        # links/configuration.  Keep every ordinary constructor fail-closed in
        # that crash window; only the exact offline confirm/acknowledge control
        # path below may inspect and retire this receipt.
        if (
            self._read_restore_completion_receipt_unlocked(self.data_dir) is not None
            and not self._restore_transaction_pending(self.data_dir)
        ):
            raise RuntimeError("Team Hub rollback settlement is pending")
        self.managed_host_identity: str | None = None
        self.managed_server_instance_id = (
            _identity(managed_server_instance_id)
            if managed_server_instance_id is not None
            else None
        )
        self.managed_host_display_name = _bounded_text(
            managed_host_display_name,
            "managed_host_display_name",
            1,
            160,
        )
        ensure_private_directory(self.data_dir)
        self.reactivation_fenced_start = False
        self.maintenance_fenced_start = False
        self.maintenance_fence_reason: str | None = None
        self.maintenance_operation_id: str | None = None
        self.maintenance_fence_snapshot: Path | None = None
        reactivation_values = (
            managed_reactivation_hub_id,
            managed_reactivation_operation_id,
            managed_reactivation_snapshot,
        )
        update_values = (
            managed_update_hub_id,
            managed_update_operation_id,
            managed_update_snapshot,
        )
        if any(value is not None for value in reactivation_values) and not all(
            value is not None for value in reactivation_values
        ):
            raise RuntimeError(
                "Team Hub reactivation startup authority is incomplete"
            )
        if any(value is not None for value in update_values) and not all(
            value is not None for value in update_values
        ):
            raise RuntimeError("Team Hub update startup authority is incomplete")
        if all(value is not None for value in reactivation_values) and all(
            value is not None for value in update_values
        ):
            raise RuntimeError("Team Hub startup authority is ambiguous")
        startup_authority: tuple[str, str, str, Path] | None = None
        if all(value is not None for value in reactivation_values):
            assert managed_reactivation_hub_id is not None
            assert managed_reactivation_operation_id is not None
            assert managed_reactivation_snapshot is not None
            startup_authority = (
                "host-reactivation",
                managed_reactivation_hub_id,
                managed_reactivation_operation_id,
                Path(managed_reactivation_snapshot),
            )
        elif all(value is not None for value in update_values):
            assert managed_update_hub_id is not None
            assert managed_update_operation_id is not None
            assert managed_update_snapshot is not None
            startup_authority = (
                "server-update",
                managed_update_hub_id,
                managed_update_operation_id,
                Path(managed_update_snapshot),
            )
        persisted_authority: dict[str, str] | None = None
        try:
            fence_raw = self._read_private_regular_file(
                self.maintenance_fence_path,
                maximum_bytes=16 * 1024,
            )
        except FileNotFoundError:
            if startup_authority is not None:
                raise RuntimeError("Team Hub startup authority is stale")
            # The fence is the only admission capability. A SIGKILL after
            # committing its unlink may leave a complete, partial, or empty
            # authority control file. Remove that powerless residue before
            # ordinary startup, without trying to parse attacker-controlled
            # or crash-truncated bytes. The control lock makes this atomic
            # with every supported fence/authority publisher.
            @contextmanager
            def authority_cleanup_lock():
                if maintenance_control_locked:
                    yield
                else:
                    with self.maintenance_control_lock(self.data_dir):
                        yield

            with authority_cleanup_lock():
                try:
                    self.maintenance_fence_path.lstat()
                except FileNotFoundError:
                    authority_path = self.data_dir / MANAGED_STARTUP_AUTHORITY_NAME
                    try:
                        authority_info = authority_path.lstat()
                    except FileNotFoundError:
                        pass
                    else:
                        if (
                            not stat.S_ISREG(authority_info.st_mode)
                            or authority_info.st_uid != os.getuid()
                            or authority_info.st_nlink != 1
                            or stat.S_IMODE(authority_info.st_mode) != 0o600
                        ):
                            raise PermissionError(
                                "Team Hub startup authority file is unsafe"
                            )
                        authority_path.unlink()
                        self._fsync_directory(self.data_dir)
                else:
                    raise RuntimeError("Team Hub startup authority fence changed")
        else:
            try:
                persisted_authority = self._read_managed_startup_authority_unlocked(
                    self.data_dir
                )
            except FileNotFoundError:
                persisted_authority = None
            if persisted_authority is not None:
                file_authority = (
                    str(persisted_authority["reason"]),
                    str(persisted_authority["hub_id"]),
                    str(persisted_authority["operation_id"]),
                    self.data_dir
                    / "maintenance-backups"
                    / str(persisted_authority["snapshot"]),
                )
                if (
                    startup_authority is not None
                    and startup_authority != file_authority
                ):
                    raise RuntimeError("Team Hub startup authority is ambiguous")
                startup_authority = file_authority
            try:
                fence = json.loads(fence_raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("Team Hub maintenance fence is invalid") from exc
            if not self._maintenance_fence_payload_valid(fence):
                raise RuntimeError("Team Hub maintenance fence is invalid")
            if fence.get("reason") in {"host-reactivation", "server-update"}:
                if fence.get("format") != 1:
                    raise RuntimeError(
                        "Team Hub fenced restore requires offline recovery"
                    )
                expected_host = (
                    _identity(managed_host_identity)
                    if managed_host_identity is not None
                    else None
                )
                authority_reason = (
                    startup_authority[0]
                    if startup_authority is not None
                    else None
                )
                authority_hub_id = (
                    startup_authority[1]
                    if startup_authority is not None
                    else None
                )
                authority_operation_id = (
                    startup_authority[2]
                    if startup_authority is not None
                    else None
                )
                authority_snapshot = (
                    startup_authority[3]
                    if startup_authority is not None
                    else None
                )
                snapshot = (
                    Path(
                        os.path.abspath(
                            os.path.expanduser(
                                os.fspath(authority_snapshot)
                            )
                        )
                    )
                    if authority_snapshot is not None
                    else None
                )
                if (
                    expected_host is None
                    or authority_reason != fence.get("reason")
                    or authority_hub_id is None
                    or authority_operation_id is None
                    or snapshot is None
                    or snapshot.parent
                    != self.data_dir / "maintenance-backups"
                    or fence.get("host_server_identity") != expected_host
                    or fence.get("hub_id") != authority_hub_id
                    or fence.get("operation_id")
                    != authority_operation_id
                    or fence.get("snapshot") != snapshot.name
                    or not isinstance(
                        fence.get("snapshot_manifest_sha256"), str
                    )
                    or (
                        persisted_authority is not None
                        and (
                            persisted_authority["host_server_identity"]
                            != expected_host
                            or persisted_authority[
                                "snapshot_manifest_sha256"
                            ]
                            != fence.get("snapshot_manifest_sha256")
                        )
                    )
                ):
                    raise RuntimeError(
                        "Team Hub startup authority does not match"
                    )
                self.verify_maintenance_snapshot(
                    self.data_dir,
                    snapshot,
                    expected_host_identity=expected_host,
                    expected_hub_id=authority_hub_id,
                    expected_operation_id=authority_operation_id,
                    expected_reason=authority_reason,
                )
                self.maintenance_fenced_start = True
                self.maintenance_fence_reason = authority_reason
                self.maintenance_operation_id = authority_operation_id
                self.maintenance_fence_snapshot = snapshot
                self.reactivation_fenced_start = (
                    authority_reason == "host-reactivation"
                )
            elif startup_authority is not None:
                raise RuntimeError("Team Hub startup authority does not match")
        # A restore swaps several independent filesystem objects. Complete or
        # roll back any durable transaction before SQLite can observe them,
        # but never let an ordinary host startup mutate a protected update or
        # reactivation generation before exact startup authority is checked.
        if self._restore_recovery_pending(self.data_dir):
            with self.maintenance_control_lock(self.data_dir):
                pass
        if self._read_restore_completion_receipt_unlocked(self.data_dir) is not None:
            raise RuntimeError("Team Hub rollback settlement is pending")
        self.team_attachment_max_bytes = _positive_int_env(
            "AGENTSDOCK_TEAM_ATTACHMENT_MAX_BYTES",
            DEFAULT_TEAM_ATTACHMENT_MAX_BYTES,
            maximum=MAX_TEAM_ATTACHMENT_PROTOCOL_BYTES,
        )
        self.team_attachment_quota_bytes = _positive_int_env(
            "AGENTSDOCK_TEAM_ATTACHMENT_QUOTA_BYTES",
            DEFAULT_TEAM_ATTACHMENT_QUOTA_BYTES,
            maximum=MAX_SQLITE_SIGNED_INTEGER,
        )
        self.instance_id = _id("hub_instance")
        self.hub_id = ""
        expected_host = (
            _identity(managed_host_identity)
            if managed_host_identity is not None
            else None
        )
        self._preflight_managed_host_binding(
            expected_host,
            allow_bound_control=allow_bound_control,
        )
        self._initialize(
            _now(now),
            expected_host,
            allow_bound_control=allow_bound_control,
        )
        # Host binding is checked or won transactionally before a missing key
        # is created. A foreign copied database therefore cannot mutate local
        # credential state merely by attempting activation.
        signing_key = load_or_create_signing_key(self.signing_key_path)
        self.signer = AccessTokenSigner(signing_key)
        self._human_admin_cursor_key = hashlib.sha256(
            b"agentsdock-team-hub-human-admin-cursor-v1\0" + signing_key
        ).digest()

    def _preflight_managed_host_binding(
        self,
        expected_host_identity: str | None,
        *,
        allow_bound_control: bool,
    ) -> None:
        """Reject a foreign bound database before WAL setup or migrations."""

        try:
            info = self.database_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PermissionError("Team Hub database must be a single-link regular file")
        if info.st_size == 0:
            return
        bound_identity = self._read_managed_binding_without_source_mutation()
        if bound_identity is None:
            return
        if expected_host_identity is not None:
            if bound_identity != expected_host_identity:
                raise RuntimeError(
                    "Team Hub database is bound to a different AgentsServer host"
                )
        elif not allow_bound_control:
            raise RuntimeError("managed Team Hub databases cannot be served standalone")

    @staticmethod
    def _copy_private_regular_file(source: Path, destination: Path) -> tuple[int, ...]:
        """Copy one stable owner-only file without following source links."""

        return HubStore._copy_private_regular_file_with_links(
            source,
            destination,
            allow_source_hardlinks=False,
        )

    @staticmethod
    def _copy_private_regular_file_with_links(
        source: Path,
        destination: Path,
        *,
        allow_source_hardlinks: bool,
    ) -> tuple[int, ...]:
        """Copy one stable private file, optionally accepting immutable links."""

        read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        read_flags |= getattr(os, "O_NOFOLLOW", 0)
        source_descriptor = os.open(source, read_flags)
        destination_descriptor = -1
        try:
            before = os.fstat(source_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink < 1
                or (not allow_source_hardlinks and before.st_nlink != 1)
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
            ):
                raise PermissionError(
                    "Team Hub database files must be owner-only regular files"
                )
            write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            write_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            destination_descriptor = os.open(destination, write_flags, 0o600)
            while True:
                chunk = os.read(source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                offset = 0
                while offset < len(chunk):
                    offset += os.write(destination_descriptor, chunk[offset:])
            os.fsync(destination_descriptor)
            after = os.fstat(source_descriptor)
            linked = os.stat(source, follow_symlinks=False)
            signature = (
                int(before.st_dev),
                int(before.st_ino),
                int(before.st_size),
                int(before.st_mtime_ns),
            )
            if signature != (
                int(after.st_dev),
                int(after.st_ino),
                int(after.st_size),
                int(after.st_mtime_ns),
            ) or signature != (
                int(linked.st_dev),
                int(linked.st_ino),
                int(linked.st_size),
                int(linked.st_mtime_ns),
            ):
                raise RuntimeError("Team Hub database changed during host-binding preflight")
            return signature
        finally:
            if destination_descriptor >= 0:
                os.close(destination_descriptor)
            os.close(source_descriptor)

    @classmethod
    def _link_or_copy_immutable_private_file(
        cls,
        source: Path,
        destination: Path,
    ) -> bool:
        """Hard-link one immutable blob when safe, otherwise copy it.

        The attachment-control lease excludes all application writers. Keep an
        open no-follow descriptor across link publication and compare both path
        names back to that inode, closing the only pathname race left to a
        same-user process. Unsupported/cross-device links fall back to a stable
        byte copy; an observed identity race fails closed.
        """

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink < 1
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise PermissionError(
                    "Team Hub immutable attachment is not owner-only"
                )
            try:
                os.link(source, destination, follow_symlinks=False)
            except OSError as exc:
                fallback_errors = {
                    errno.EACCES,
                    errno.EMLINK,
                    errno.EPERM,
                    errno.EXDEV,
                }
                for name in ("ENOTSUP", "EOPNOTSUPP"):
                    value = getattr(errno, name, None)
                    if isinstance(value, int):
                        fallback_errors.add(value)
                if exc.errno not in fallback_errors:
                    raise
                cls._copy_private_regular_file_with_links(
                    source,
                    destination,
                    allow_source_hardlinks=True,
                )
                return False

            try:
                after = os.fstat(descriptor)
                linked_source = os.stat(source, follow_symlinks=False)
                linked_destination = os.stat(destination, follow_symlinks=False)
                expected = (
                    int(opened.st_dev),
                    int(opened.st_ino),
                    int(opened.st_size),
                    int(opened.st_mtime_ns),
                )
                if (
                    expected
                    != (
                        int(after.st_dev),
                        int(after.st_ino),
                        int(after.st_size),
                        int(after.st_mtime_ns),
                    )
                    or expected
                    != (
                        int(linked_source.st_dev),
                        int(linked_source.st_ino),
                        int(linked_source.st_size),
                        int(linked_source.st_mtime_ns),
                    )
                    or expected
                    != (
                        int(linked_destination.st_dev),
                        int(linked_destination.st_ino),
                        int(linked_destination.st_size),
                        int(linked_destination.st_mtime_ns),
                    )
                    or linked_destination.st_nlink < 2
                    or linked_destination.st_uid != os.getuid()
                    or stat.S_IMODE(linked_destination.st_mode) != 0o600
                ):
                    raise RuntimeError(
                        "Team Hub immutable attachment changed during snapshot"
                    )
            except BaseException:
                with suppress(OSError):
                    destination.unlink()
                raise
            return True
        finally:
            os.close(descriptor)

    def _read_managed_binding_without_source_mutation(self) -> str | None:
        """Read the main DB plus any live WAL through a private stable copy."""

        wal_path = self.database_path.with_name(self.database_path.name + "-wal")
        for _attempt in range(3):
            with tempfile.TemporaryDirectory(prefix="team-hub-binding-preflight-") as root:
                copied = Path(root) / self.database_path.name
                try:
                    database_signature = self._copy_private_regular_file(
                        self.database_path, copied
                    )
                    wal_existed = False
                    try:
                        self._copy_private_regular_file(
                            wal_path, copied.with_name(copied.name + "-wal")
                        )
                        wal_existed = True
                    except FileNotFoundError:
                        pass
                    latest_database = self.database_path.lstat()
                    latest_signature = (
                        int(latest_database.st_dev),
                        int(latest_database.st_ino),
                        int(latest_database.st_size),
                        int(latest_database.st_mtime_ns),
                    )
                    if latest_signature != database_signature:
                        continue
                    try:
                        wal_now_exists = wal_path.lstat().st_size >= 0
                    except FileNotFoundError:
                        wal_now_exists = False
                    if wal_now_exists != wal_existed:
                        continue
                    connection = sqlite3.connect(str(copied), isolation_level=None)
                    try:
                        table = connection.execute(
                            """
                            SELECT 1 FROM sqlite_master
                            WHERE type = 'table' AND name = 'managed_host_bindings'
                            """
                        ).fetchone()
                        if table is None:
                            return None
                        binding = connection.execute(
                            """
                            SELECT server_identity
                            FROM managed_host_bindings WHERE singleton = 1
                            """
                        ).fetchone()
                        return str(binding[0]) if binding is not None else None
                    finally:
                        connection.close()
                except RuntimeError:
                    continue
                except sqlite3.DatabaseError as exc:
                    raise RuntimeError(
                        "Team Hub host-binding preflight could not verify the database"
                    ) from exc
        raise RuntimeError("Team Hub host-binding preflight could not obtain a stable snapshot")

    @classmethod
    def managed_host_binding_without_source_mutation(
        cls,
        data_dir: Path,
    ) -> str | None:
        """Read a preserved Hub's host binding without opening/migrating it."""

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        cls._validate_private_directory_without_mutation(root)
        probe = object.__new__(cls)
        probe.data_dir = root
        probe.database_path = root / "team-hub.sqlite3"
        return probe._read_managed_binding_without_source_mutation()

    @staticmethod
    def _sha256_private_regular_file(
        path: Path,
        *,
        allow_hardlinks: bool = False,
    ) -> str:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink < 1
                or (not allow_hardlinks and info.st_nlink != 1)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise PermissionError("Team Hub snapshot file is not owner-only")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(descriptor)

    @staticmethod
    def _read_private_regular_file(
        path: Path,
        *,
        minimum_bytes: int = 1,
        maximum_bytes: int = 1024 * 1024,
    ) -> bytes:
        """Read a bounded owner-only file without following or racing links."""

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or not minimum_bytes <= info.st_size <= maximum_bytes
            ):
                raise PermissionError("Team Hub snapshot file is invalid")
            chunks: list[bytes] = []
            remaining = maximum_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            value = b"".join(chunks)
            if not minimum_bytes <= len(value) <= maximum_bytes:
                raise PermissionError("Team Hub snapshot file is invalid")
            linked = os.stat(path, follow_symlinks=False)
            after = os.fstat(descriptor)
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino):
                raise RuntimeError("Team Hub snapshot file changed while reading")
            return value
        finally:
            os.close(descriptor)

    @staticmethod
    def _validate_private_directory_without_mutation(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise PermissionError("Team Hub snapshot directory is not owner-only")
        finally:
            os.close(descriptor)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @classmethod
    def _create_owned_maintenance_fence(
        cls,
        path: Path,
        value: bytes,
    ) -> os.stat_result:
        """Publish one fence while retaining exact creator-inode ownership.

        Unlike the general secret-file helper, every failure after O_EXCL has
        enough descriptor identity to remove only this invocation's inode.
        A replaced path is never unlinked and therefore remains fail-closed.
        """

        ensure_private_directory(path.parent)
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
            os, "O_DIRECTORY", 0
        )
        directory = os.open(path.parent, directory_flags)
        descriptor: int | None = None
        created: os.stat_result | None = None
        try:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path.name, flags, 0o600, dir_fd=directory)
            created = os.fstat(descriptor)
            os.fchmod(descriptor, 0o600)
            written = 0
            while written < len(value):
                written += os.write(descriptor, value[written:])
            os.fsync(descriptor)
            created = os.fstat(descriptor)
            if (
                not stat.S_ISREG(created.st_mode)
                or created.st_uid != os.getuid()
                or created.st_nlink != 1
                or stat.S_IMODE(created.st_mode) != 0o600
            ):
                raise PermissionError("Team Hub maintenance fence is unsafe")
            cls._fsync_directory(path.parent)
            linked = path.lstat()
            if (
                linked.st_dev != created.st_dev
                or linked.st_ino != created.st_ino
                or linked.st_uid != os.getuid()
                or linked.st_nlink != 1
                or not stat.S_ISREG(linked.st_mode)
                or stat.S_IMODE(linked.st_mode) != 0o600
            ):
                raise RuntimeError("Team Hub maintenance fence changed")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if not hmac.compare_digest(os.read(descriptor, len(value) + 1), value):
                raise RuntimeError("Team Hub maintenance fence changed")
            return created
        except BaseException as publish_error:
            if created is not None:
                try:
                    linked = path.lstat()
                    if (
                        linked.st_dev != created.st_dev
                        or linked.st_ino != created.st_ino
                    ):
                        raise RuntimeError("Team Hub maintenance fence changed")
                    path.unlink()
                    cls._fsync_directory(path.parent)
                except FileNotFoundError:
                    pass
                except BaseException as cleanup_error:
                    raise RuntimeError(
                        "Team Hub maintenance fence remains fail-closed"
                    ) from cleanup_error
            raise publish_error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    @staticmethod
    def _restore_transaction_pending(root: Path) -> bool:
        try:
            (root / RESTORE_TRANSACTION_JOURNAL_NAME).lstat()
        except FileNotFoundError:
            return False
        return True

    @staticmethod
    def _snapshot_rebase_pending(root: Path) -> bool:
        try:
            (root / SNAPSHOT_REBASE_JOURNAL_NAME).lstat()
        except FileNotFoundError:
            return False
        return True

    @classmethod
    def _cleanup_orphaned_maintenance_fence_staging_unlocked(
        cls,
        root: Path,
    ) -> None:
        try:
            (root / HOST_REACTIVATION_HANDOFF_NAME).lstat()
        except FileNotFoundError:
            pass
        else:
            return
        try:
            entries = list(os.scandir(root))
        except FileNotFoundError:
            return
        candidates = [
            root / entry.name
            for entry in entries
            if MAINTENANCE_FENCE_STAGING_RE.fullmatch(entry.name) is not None
        ]
        for path in candidates:
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise PermissionError(
                    "Team Hub maintenance fence staging file is unsafe"
                )
        for path in candidates:
            path.unlink()
        if candidates:
            cls._fsync_directory(root)

    @classmethod
    def _read_host_reactivation_handoff_unlocked(
        cls,
        root: Path,
    ) -> dict[str, Any] | None:
        try:
            raw = cls._read_private_regular_file(
                root / HOST_REACTIVATION_HANDOFF_NAME,
                maximum_bytes=16 * 1024,
            )
        except FileNotFoundError:
            return None
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "Team Hub reactivation handoff is invalid"
            ) from exc
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "format",
                "state",
                "hub_id",
                "host_server_identity",
                "operation_id",
                "snapshot",
                "fence_device",
                "fence_inode",
                "fence_staging",
            }
            or value.get("format") != 2
            or value.get("state")
            not in {"creating", "unclaimed", "adopted"}
            or not isinstance(value.get("hub_id"), str)
            or re.fullmatch(r"[A-Za-z0-9_.:-]{8,240}", value["hub_id"])
            is None
            or not isinstance(value.get("host_server_identity"), str)
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:@/-]{7,239}",
                value["host_server_identity"],
            )
            is None
            or not isinstance(value.get("operation_id"), str)
            or re.fullmatch(
                r"host-reactivation-[0-9a-f]{24}",
                value["operation_id"],
            )
            is None
            or not isinstance(value.get("snapshot"), str)
            or re.fullmatch(r"snapshot_[A-Za-z0-9_]+", value["snapshot"])
            is None
            or isinstance(value.get("fence_device"), bool)
            or not isinstance(value.get("fence_device"), int)
            or value["fence_device"] < 0
            or isinstance(value.get("fence_inode"), bool)
            or not isinstance(value.get("fence_inode"), int)
            or value["fence_inode"] <= 0
            or not isinstance(value.get("fence_staging"), str)
            or MAINTENANCE_FENCE_STAGING_RE.fullmatch(
                value["fence_staging"]
            )
            is None
        ):
            raise RuntimeError("Team Hub reactivation handoff is invalid")
        return value

    @classmethod
    def _read_managed_startup_guard_unlocked(
        cls,
        root: Path,
    ) -> dict[str, str]:
        raw = cls._read_private_regular_file(
            root / MANAGED_STARTUP_GUARD_NAME,
            maximum_bytes=4096,
        )
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Team Hub startup guard is invalid") from exc
        if (
            not isinstance(value, dict)
            or set(value) != {"format", "host_server_identity", "guard_id"}
            or value.get("format") != 1
            or not isinstance(value.get("host_server_identity"), str)
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:@/-]{7,239}",
                value["host_server_identity"],
            )
            is None
            or not isinstance(value.get("guard_id"), str)
            or re.fullmatch(r"cold-handoff-[0-9a-f]{24}", value["guard_id"])
            is None
        ):
            raise RuntimeError("Team Hub startup guard is invalid")
        return value

    @classmethod
    def _read_managed_startup_authority_unlocked(
        cls,
        root: Path,
    ) -> dict[str, str]:
        raw = cls._read_private_regular_file(
            root / MANAGED_STARTUP_AUTHORITY_NAME,
            maximum_bytes=16 * 1024,
        )
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Team Hub startup authority file is invalid") from exc
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "format",
                "reason",
                "hub_id",
                "host_server_identity",
                "operation_id",
                "snapshot",
                "snapshot_manifest_sha256",
            }
            or value.get("format") != 1
            or value.get("reason") not in {"server-update", "host-reactivation"}
            or not isinstance(value.get("hub_id"), str)
            or re.fullmatch(r"[A-Za-z0-9_.:-]{8,240}", value["hub_id"])
            is None
            or not isinstance(value.get("host_server_identity"), str)
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:@/-]{7,239}",
                value["host_server_identity"],
            )
            is None
            or not isinstance(value.get("operation_id"), str)
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                value["operation_id"],
            )
            is None
            or not isinstance(value.get("snapshot"), str)
            or re.fullmatch(r"snapshot_[A-Za-z0-9_]+", value["snapshot"])
            is None
            or not isinstance(value.get("snapshot_manifest_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", value["snapshot_manifest_sha256"]
            )
            is None
        ):
            raise RuntimeError("Team Hub startup authority file is invalid")
        return value

    @classmethod
    def _replace_private_control_file_unlocked(
        cls,
        path: Path,
        payload: bytes,
    ) -> None:
        temporary = path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
        try:
            create_secret_file(temporary, payload)
            os.replace(temporary, path)
            last_fsync_error: OSError | None = None
            for _attempt in range(3):
                try:
                    cls._fsync_directory(path.parent)
                except OSError as exc:
                    last_fsync_error = exc
                else:
                    last_fsync_error = None
                    break
            if last_fsync_error is not None:
                raise last_fsync_error
        except BaseException as publish_error:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise publish_error

    @classmethod
    def _recover_host_reactivation_handoff_unlocked(
        cls,
        root: Path,
    ) -> dict[str, Any] | None:
        handoff = cls._read_host_reactivation_handoff_unlocked(root)
        if handoff is None:
            return None
        if handoff["state"] == "creating":
            marker_path = root / "maintenance-fence.json"
            staging_path = root / str(handoff["fence_staging"])
            try:
                marker_info = marker_path.lstat()
            except FileNotFoundError:
                marker_info = None
            try:
                staging_info = staging_path.lstat()
            except FileNotFoundError:
                staging_info = None
            for info in (marker_info, staging_info):
                if info is not None and (
                    info.st_dev != handoff["fence_device"]
                    or info.st_ino != handoff["fence_inode"]
                ):
                    raise RuntimeError(
                        "Team Hub creating reactivation fence ownership changed"
                    )
            if marker_info is None and staging_info is None:
                (root / HOST_REACTIVATION_HANDOFF_NAME).unlink()
                cls._fsync_directory(root)
                return None
            if marker_info is None:
                raw = cls._read_private_regular_file(
                    staging_path,
                    maximum_bytes=16 * 1024,
                )
                try:
                    staged_marker = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise RuntimeError(
                        "Team Hub creating reactivation fence is invalid"
                    ) from exc
                if (
                    not cls._maintenance_fence_payload_valid(staged_marker)
                    or staged_marker.get("hub_id") != handoff["hub_id"]
                    or staged_marker.get("host_server_identity")
                    != handoff["host_server_identity"]
                    or staged_marker.get("reason") != "host-reactivation"
                    or staged_marker.get("operation_id")
                    != handoff["operation_id"]
                    or staged_marker.get("snapshot") != handoff["snapshot"]
                ):
                    raise RuntimeError(
                        "Team Hub creating reactivation fence does not match"
                    )
                staging_path.unlink()
                (root / HOST_REACTIVATION_HANDOFF_NAME).unlink()
                cls._fsync_directory(root)
                return None
            if staging_info is not None:
                # A crash after link but before unlink leaves two names for
                # the same inode. Retire only that exact staging name before
                # normal private-file verification (which requires nlink=1).
                staging_path.unlink()
                cls._fsync_directory(root)
        if handoff["state"] == "adopted":
            marker = cls._maintenance_fence_control_unlocked(
                root,
                expected_hub_id=str(handoff["hub_id"]),
                expected_host_identity=str(handoff["host_server_identity"]),
                expected_reason="host-reactivation",
                expected_operation_id=str(handoff["operation_id"]),
                expected_snapshot=(
                    root / "maintenance-backups" / str(handoff["snapshot"])
                ),
            )
            if marker is None:
                # Fence consumption is the irreversible commit point. A
                # crash or directory-fsync error may leave only the advisory
                # handoff; it no longer owns Hub admission.
                (root / HOST_REACTIVATION_HANDOFF_NAME).unlink()
                cls._fsync_directory(root)
                return None
            marker_info = (root / "maintenance-fence.json").lstat()
            if (
                marker is None
                or marker_info.st_dev != handoff["fence_device"]
                or marker_info.st_ino != handoff["fence_inode"]
            ):
                raise RuntimeError(
                    "Team Hub adopted reactivation fence ownership changed"
                )
            return handoff
        marker = cls._maintenance_fence_control_unlocked(
            root,
            expected_hub_id=str(handoff["hub_id"]),
            expected_host_identity=str(handoff["host_server_identity"]),
            expected_reason="host-reactivation",
            expected_operation_id=str(handoff["operation_id"]),
            expected_snapshot=(
                root / "maintenance-backups" / str(handoff["snapshot"])
            ),
        )
        if marker is not None:
            marker_info = (root / "maintenance-fence.json").lstat()
            if (
                marker_info.st_dev != handoff["fence_device"]
                or marker_info.st_ino != handoff["fence_inode"]
            ):
                raise RuntimeError(
                    "Team Hub reactivation handoff fence ownership changed"
                )
            (root / "maintenance-fence.json").unlink()
        (root / HOST_REACTIVATION_HANDOFF_NAME).unlink()
        cls._fsync_directory(root)
        return None

    @classmethod
    def _consume_host_reactivation_handoff_unlocked(
        cls,
        root: Path,
        *,
        expected_hub_id: str,
        expected_host_identity: str,
        expected_operation_id: str,
        expected_snapshot: Path,
        remove: bool = True,
        expected_state: str = "adopted",
    ) -> None:
        handoff = cls._read_host_reactivation_handoff_unlocked(root)
        if handoff is None:
            return
        if (
            handoff.get("hub_id") != expected_hub_id
            or handoff.get("host_server_identity") != expected_host_identity
            or handoff.get("operation_id") != expected_operation_id
            or handoff.get("snapshot") != Path(expected_snapshot).name
            or handoff.get("state") != expected_state
        ):
            raise RuntimeError("Team Hub reactivation handoff does not match")
        if not remove:
            marker_info = (root / "maintenance-fence.json").lstat()
            if (
                marker_info.st_dev != handoff["fence_device"]
                or marker_info.st_ino != handoff["fence_inode"]
            ):
                raise RuntimeError(
                    "Team Hub reactivation fence ownership changed"
                )
        if remove:
            (root / HOST_REACTIVATION_HANDOFF_NAME).unlink()

    @classmethod
    def _restore_recovery_pending(cls, root: Path) -> bool:
        if (
            cls._restore_transaction_pending(root)
            or cls._snapshot_rebase_pending(root)
        ):
            return True
        try:
            with os.scandir(root) as entries:
                return any(
                    entry.name == "maintenance-fence.json"
                    or SNAPSHOT_REBASE_RETIRED_RE.fullmatch(entry.name)
                    is not None
                    or RESTORE_STAGING_NAME_RE.fullmatch(entry.name) is not None
                    for entry in entries
                )
        except FileNotFoundError:
            return False

    @classmethod
    def _remove_snapshot_generation_unlocked(cls, path: Path) -> None:
        cls._validate_private_directory_without_mutation(path)
        for directory, directory_names, file_names in os.walk(
            path,
            topdown=True,
            followlinks=False,
        ):
            current = Path(directory)
            cls._validate_private_directory_without_mutation(current)
            for name in directory_names:
                cls._validate_private_directory_without_mutation(current / name)
            for name in file_names:
                candidate = current / name
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(candidate, flags)
                try:
                    info = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.getuid()
                    ):
                        raise PermissionError(
                            "Team Hub snapshot generation contains an unsafe file"
                        )
                finally:
                    os.close(descriptor)
        shutil.rmtree(path)

    @classmethod
    def _verify_snapshot_rebase_generation_unlocked(
        cls,
        root: Path,
        path: Path,
        *,
        journal: dict[str, Any],
        manifest_digest_key: str,
    ) -> tuple[int, int]:
        before = path.lstat()
        if not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid():
            raise PermissionError("Team Hub snapshot rebase generation is unsafe")
        expected_digest = journal.get(manifest_digest_key)
        if (
            not isinstance(expected_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
            or not hmac.compare_digest(
                cls._sha256_private_regular_file(path / "manifest.json"),
                expected_digest,
            )
        ):
            raise RuntimeError("Team Hub snapshot rebase generation changed")
        cls._restore_maintenance_snapshot_unlocked(
            root,
            path,
            expected_host_identity=str(journal["host_server_identity"]),
            expected_hub_id=str(journal["hub_id"]),
            expected_operation_id=None,
            expected_reason="server-update",
            verify_only=True,
            require_fence=False,
            allow_rebase_snapshot=True,
        )
        after = path.lstat()
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or not hmac.compare_digest(
                cls._sha256_private_regular_file(path / "manifest.json"),
                expected_digest,
            )
        ):
            raise RuntimeError(
                "Team Hub snapshot rebase generation changed during verification"
            )
        return before.st_dev, before.st_ino

    @classmethod
    def _recover_snapshot_rebase_unlocked(cls, root: Path) -> None:
        journal_path = root / SNAPSHOT_REBASE_JOURNAL_NAME
        try:
            raw = cls._read_private_regular_file(
                journal_path,
                maximum_bytes=16 * 1024,
            )
        except FileNotFoundError:
            return
        try:
            journal = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Team Hub snapshot rebase journal is invalid") from exc
        expected_keys = {
            "format",
            "hub_id",
            "host_server_identity",
            "operation_id",
            "target",
            "target_manifest_sha256",
            "replacement",
            "replacement_manifest_sha256",
            "retired",
        }
        if (
            not isinstance(journal, dict)
            or set(journal) != expected_keys
            or journal.get("format") != 1
            or not isinstance(journal.get("target"), str)
            or re.fullmatch(r"snapshot_[A-Za-z0-9_]+", journal["target"])
            is None
            or not isinstance(journal.get("replacement"), str)
            or re.fullmatch(
                r"snapshot_[A-Za-z0-9_]+", journal["replacement"]
            )
            is None
            or journal["replacement"] == journal["target"]
            or not isinstance(journal.get("target_manifest_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", journal["target_manifest_sha256"]
            )
            is None
            or not isinstance(
                journal.get("replacement_manifest_sha256"), str
            )
            or re.fullmatch(
                r"[0-9a-f]{64}", journal["replacement_manifest_sha256"]
            )
            is None
            or not isinstance(journal.get("retired"), str)
            or SNAPSHOT_REBASE_RETIRED_RE.fullmatch(journal["retired"])
            is None
        ):
            raise RuntimeError("Team Hub snapshot rebase journal is invalid")
        backups = root / "maintenance-backups"
        cls._validate_private_directory_without_mutation(backups)
        target = backups / journal["target"]
        replacement = backups / journal["replacement"]
        retired = backups / journal["retired"]
        marker = cls._maintenance_fence_control_unlocked(
            root,
            expected_hub_id=str(journal.get("hub_id") or ""),
            expected_host_identity=str(journal.get("host_server_identity") or ""),
            expected_reason="server-update",
            expected_operation_id=str(journal.get("operation_id") or ""),
            expected_snapshot=target,
            verify_snapshot_digest=False,
        )
        if marker is None:
            raise RuntimeError("Team Hub snapshot rebase fence is missing")

        def bind_selected_generation(digest: str) -> None:
            updated_marker = dict(marker)
            updated_marker["snapshot_manifest_sha256"] = digest
            cls._replace_private_control_file_unlocked(
                root / "maintenance-fence.json",
                canonical_json(updated_marker) + b"\n",
            )

        selected_digest: str | None = None
        target_exists = target.exists() and not target.is_symlink()
        replacement_exists = replacement.exists() and not replacement.is_symlink()
        retired_exists = retired.exists() and not retired.is_symlink()
        if target_exists and replacement_exists and not retired_exists:
            # Journal committed before the first rename: the old target is
            # still authoritative. Verify it before consuming the journal;
            # the uncommitted replacement can then be discarded.
            cls._verify_snapshot_rebase_generation_unlocked(
                root,
                target,
                journal=journal,
                manifest_digest_key="target_manifest_sha256",
            )
            cls._remove_snapshot_generation_unlocked(replacement)
            selected_digest = str(journal["target_manifest_sha256"])
        elif not target_exists and replacement_exists and retired_exists:
            # The old target was retired. Both generations must still match
            # the journal before a corrupt replacement can consume the only
            # known-good rollback image.
            cls._verify_snapshot_rebase_generation_unlocked(
                root,
                retired,
                journal=journal,
                manifest_digest_key="target_manifest_sha256",
            )
            try:
                cls._verify_snapshot_rebase_generation_unlocked(
                    root,
                    replacement,
                    journal=journal,
                    manifest_digest_key="replacement_manifest_sha256",
                )
            except BaseException:
                cls._remove_snapshot_generation_unlocked(replacement)
                cls._fsync_directory(backups)
                os.replace(retired, target)
                cls._fsync_directory(backups)
                bind_selected_generation(
                    str(journal["target_manifest_sha256"])
                )
                journal_path.unlink()
                cls._fsync_directory(root)
                raise
            else:
                os.replace(replacement, target)
                cls._fsync_directory(backups)
                selected_digest = str(
                    journal["replacement_manifest_sha256"]
                )
        elif target_exists and not replacement_exists and retired_exists:
            # Replacement is already published under the stable name. Keep
            # the retired generation until both sides have been verified.
            cls._verify_snapshot_rebase_generation_unlocked(
                root,
                retired,
                journal=journal,
                manifest_digest_key="target_manifest_sha256",
            )
            try:
                cls._verify_snapshot_rebase_generation_unlocked(
                    root,
                    target,
                    journal=journal,
                    manifest_digest_key="replacement_manifest_sha256",
                )
            except BaseException:
                cls._remove_snapshot_generation_unlocked(target)
                cls._fsync_directory(backups)
                os.replace(retired, target)
                cls._fsync_directory(backups)
                bind_selected_generation(
                    str(journal["target_manifest_sha256"])
                )
                journal_path.unlink()
                cls._fsync_directory(root)
                raise
            else:
                selected_digest = str(
                    journal["replacement_manifest_sha256"]
                )
        elif not target_exists and not replacement_exists and retired_exists:
            # No new generation survived, so put the verified old target back.
            cls._verify_snapshot_rebase_generation_unlocked(
                root,
                retired,
                journal=journal,
                manifest_digest_key="target_manifest_sha256",
            )
            os.replace(retired, target)
            cls._fsync_directory(backups)
            retired_exists = False
            selected_digest = str(journal["target_manifest_sha256"])
        elif target_exists and not replacement_exists and not retired_exists:
            # Recovery may itself have crashed after restoring the old target
            # but before consuming the journal. Only the journal-bound old
            # generation makes this state replayable.
            cls._verify_snapshot_rebase_generation_unlocked(
                root,
                target,
                journal=journal,
                manifest_digest_key="target_manifest_sha256",
            )
            selected_digest = str(journal["target_manifest_sha256"])
        else:
            raise RuntimeError("Team Hub snapshot rebase state is invalid")
        if selected_digest is None:
            raise RuntimeError("Team Hub snapshot rebase selection is invalid")
        bind_selected_generation(selected_digest)
        cls._verify_snapshot_rebase_generation_unlocked(
            root,
            target,
            journal=journal,
            manifest_digest_key=(
                "replacement_manifest_sha256"
                if hmac.compare_digest(
                    selected_digest,
                    str(journal["replacement_manifest_sha256"]),
                )
                else "target_manifest_sha256"
            ),
        )
        journal_path.unlink()
        cls._fsync_directory(root)
        if retired_exists and retired.exists() and not retired.is_symlink():
            cls._remove_snapshot_generation_unlocked(retired)
            cls._fsync_directory(backups)

    @classmethod
    def _cleanup_orphaned_snapshot_rebase_retired_unlocked(
        cls,
        root: Path,
    ) -> None:
        if cls._snapshot_rebase_pending(root):
            return
        backups = root / "maintenance-backups"
        try:
            entries = list(os.scandir(backups))
        except FileNotFoundError:
            return
        retired = [
            backups / entry.name
            for entry in entries
            if SNAPSHOT_REBASE_RETIRED_RE.fullmatch(entry.name) is not None
        ]
        for path in retired:
            cls._validate_private_directory_without_mutation(path)
        for path in retired:
            cls._remove_snapshot_generation_unlocked(path)
        if retired:
            cls._fsync_directory(backups)

    @staticmethod
    def _maintenance_fence_payload_valid(value: Any) -> bool:
        base_keys = {
            "format",
            "reason",
            "operation_id",
            "hub_id",
            "host_server_identity",
            "snapshot",
            "created_at",
        }
        if not isinstance(value, dict):
            return False
        digest_keys = {"snapshot_manifest_sha256"}
        if value.get("format") == 1:
            expected_keys = (
                base_keys | digest_keys
                if "snapshot_manifest_sha256" in value
                else base_keys
            )
        elif value.get("format") == 2:
            expected_keys = base_keys | {"restore_transaction"}
            if "snapshot_manifest_sha256" in value:
                expected_keys |= digest_keys
            if (
                value.get("restore_transaction") != "host-reactivation"
                or value.get("reason") != "host-reactivation"
                or not isinstance(value.get("operation_id"), str)
                or re.fullmatch(
                    r"host-reactivation-[0-9a-f]{24}",
                    value["operation_id"],
                )
                is None
            ):
                return False
        else:
            return False
        return (
            set(value) == expected_keys
            and isinstance(value.get("hub_id"), str)
            and re.fullmatch(r"[A-Za-z0-9_.:-]{8,240}", value["hub_id"])
            is not None
            and isinstance(value.get("host_server_identity"), str)
            and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:@/-]{7,239}",
                value["host_server_identity"],
            )
            is not None
            and isinstance(value.get("reason"), str)
            and 1 <= len(value["reason"]) <= 80
            and isinstance(value.get("operation_id"), str)
            and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                value["operation_id"],
            )
            is not None
            and isinstance(value.get("snapshot"), str)
            and re.fullmatch(r"snapshot_[A-Za-z0-9_]+", value["snapshot"])
            is not None
            and isinstance(value.get("created_at"), str)
            and (
                "snapshot_manifest_sha256" not in value
                or (
                    isinstance(value["snapshot_manifest_sha256"], str)
                    and re.fullmatch(
                        r"[0-9a-f]{64}",
                        value["snapshot_manifest_sha256"],
                    )
                    is not None
                )
            )
        )

    @classmethod
    def _clear_orphaned_host_reactivation_restore_fence_unlocked(
        cls,
        root: Path,
    ) -> None:
        """Clear only the private restore fence whose owner no longer exists.

        Format 2 is emitted solely by ``restore_host_reactivation_snapshot``.
        Holding both control leases proves no live restore owns it, while an
        absent journal/staging generation proves no multi-file transition has
        begun. Ordinary update/shutdown fences remain untouched.
        """

        if cls._restore_transaction_pending(root):
            return
        try:
            with os.scandir(root) as entries:
                if any(
                    RESTORE_STAGING_NAME_RE.fullmatch(entry.name) is not None
                    for entry in entries
                ):
                    return
        except FileNotFoundError:
            return
        marker_path = root / "maintenance-fence.json"
        try:
            raw = cls._read_private_regular_file(
                marker_path,
                maximum_bytes=16 * 1024,
            )
        except FileNotFoundError:
            return
        try:
            marker = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Team Hub maintenance fence is invalid") from exc
        if not isinstance(marker, dict) or marker.get("format") != 2:
            return
        if not cls._maintenance_fence_payload_valid(marker):
            raise RuntimeError("Team Hub maintenance fence is invalid")
        marker_path.unlink()
        cls._fsync_directory(root)

    @classmethod
    def _cleanup_abandoned_restore_staging_unlocked(
        cls,
        root: Path,
        *,
        protected_staging: Path | None = None,
    ) -> None:
        """Remove only validated pre-journal restore generations.

        The caller owns the maintenance and attachment locks, so an exact
        unjournaled generation cannot still be active. A valid journal's
        staging path is excluded until commit/rollback recovery consumes it.
        """

        candidates: list[Path] = []
        with os.scandir(root) as entries:
            for entry in entries:
                if RESTORE_STAGING_NAME_RE.fullmatch(entry.name) is None:
                    continue
                candidate = root / entry.name
                if protected_staging is not None and candidate == protected_staging:
                    continue
                candidates.append(candidate)

        # Validate every candidate before deleting any of them. An unsafe
        # lookalike therefore fails closed without partially cleaning state.
        for candidate in candidates:
            if not cls._restore_target_exists(candidate, "directory"):
                continue  # pragma: no cover - scandir observed the entry.
            for directory, directory_names, file_names in os.walk(
                candidate,
                topdown=True,
                followlinks=False,
            ):
                current = Path(directory)
                cls._restore_target_exists(current, "directory")
                for name in directory_names:
                    cls._restore_target_exists(current / name, "directory")
                for name in file_names:
                    cls._restore_target_exists(current / name, "file")

        for candidate in sorted(candidates, key=lambda path: path.name):
            shutil.rmtree(candidate)
            cls._fsync_directory(root)

    @classmethod
    def _cleanup_abandoned_snapshot_staging_unlocked(cls, backups: Path) -> None:
        """Remove validated snapshot temporaries left by a killed process.

        The caller owns both the maintenance-control and attachment leases, so
        no matching temporary can still belong to a live snapshot writer.
        Validate every candidate before deleting any to fail closed on unsafe
        lookalikes.
        """

        candidates: list[Path] = []
        with os.scandir(backups) as entries:
            for entry in entries:
                if SNAPSHOT_STAGING_NAME_RE.fullmatch(entry.name) is not None:
                    candidates.append(backups / entry.name)

        for candidate in candidates:
            if not cls._restore_target_exists(candidate, "directory"):
                continue  # pragma: no cover - scandir observed the entry.
            for directory, directory_names, file_names in os.walk(
                candidate,
                topdown=True,
                followlinks=False,
            ):
                current = Path(directory)
                cls._restore_target_exists(current, "directory")
                for name in directory_names:
                    cls._restore_target_exists(current / name, "directory")
                for name in file_names:
                    cls._restore_target_exists(current / name, "file")

        for candidate in sorted(candidates, key=lambda path: path.name):
            shutil.rmtree(candidate)
        if candidates:
            cls._fsync_directory(backups)

    @staticmethod
    def _restore_target_kind(name: str) -> str:
        if name == "attachments":
            return "directory"
        if name in {
            "team-hub.sqlite3",
            "access-token-signing.key",
            "team-hub.sqlite3-wal",
            "team-hub.sqlite3-shm",
            "bootstrap-owner.proof",
            "maintenance-fence.json",
        } or re.fullmatch(r"[A-Za-z0-9_]{8,240}\.proof", name):
            return "file"
        raise RuntimeError("Team Hub restore transaction target is invalid")

    @classmethod
    def _restore_target_exists(cls, path: Path, kind: str) -> bool:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if info.st_uid != os.getuid():
            raise PermissionError("Team Hub restore transaction target is unsafe")
        if kind == "file":
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise PermissionError("Team Hub restore transaction target is unsafe")
        elif kind == "directory":
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise PermissionError("Team Hub restore transaction target is unsafe")
        else:  # pragma: no cover - only validated journal values reach this helper.
            raise RuntimeError("Team Hub restore transaction target is invalid")
        return True

    @classmethod
    def _restore_transaction_targets(
        cls,
        raw: Any,
    ) -> dict[str, str]:
        if not isinstance(raw, list) or len(raw) > 4104:
            raise RuntimeError("Team Hub restore transaction journal is invalid")
        targets: dict[str, str] = {}
        for entry in raw:
            if not isinstance(entry, dict) or set(entry) != {"name", "kind"}:
                raise RuntimeError("Team Hub restore transaction journal is invalid")
            name = entry.get("name")
            kind = entry.get("kind")
            if (
                not isinstance(name, str)
                or not isinstance(kind, str)
                or kind != cls._restore_target_kind(name)
                or name in targets
            ):
                raise RuntimeError("Team Hub restore transaction journal is invalid")
            targets[name] = kind
        return targets

    @classmethod
    def _restore_transaction_generation(
        cls,
        raw: Any,
        new_targets: dict[str, str],
    ) -> dict[str, Any]:
        if not isinstance(raw, dict) or set(raw) != {
            "database_sha256",
            "signing_key_sha256",
            "proofs",
            "attachments",
        }:
            raise RuntimeError("Team Hub restore transaction journal is invalid")
        for field in ("database_sha256", "signing_key_sha256"):
            if (
                not isinstance(raw.get(field), str)
                or re.fullmatch(r"[0-9a-f]{64}", raw[field]) is None
            ):
                raise RuntimeError("Team Hub restore transaction journal is invalid")
        raw_proofs = raw.get("proofs")
        if not isinstance(raw_proofs, list) or len(raw_proofs) > 4096:
            raise RuntimeError("Team Hub restore transaction journal is invalid")
        proof_names = {
            name
            for name in new_targets
            if name == "bootstrap-owner.proof"
            or re.fullmatch(r"[A-Za-z0-9_]{8,240}\.proof", name)
        }
        proof_digests: dict[str, str] = {}
        for entry in raw_proofs:
            if not isinstance(entry, dict) or set(entry) != {"name", "sha256"}:
                raise RuntimeError("Team Hub restore transaction journal is invalid")
            name = entry.get("name")
            digest = entry.get("sha256")
            if (
                not isinstance(name, str)
                or name not in proof_names
                or name in proof_digests
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise RuntimeError("Team Hub restore transaction journal is invalid")
            proof_digests[name] = digest
        if proof_digests.keys() != proof_names:
            raise RuntimeError("Team Hub restore transaction journal is invalid")
        attachments = raw.get("attachments")
        if (
            not isinstance(attachments, dict)
            or set(attachments) != {"file_count", "byte_size", "sha256"}
            or isinstance(attachments.get("file_count"), bool)
            or not isinstance(attachments.get("file_count"), int)
            or attachments["file_count"] < 0
            or isinstance(attachments.get("byte_size"), bool)
            or not isinstance(attachments.get("byte_size"), int)
            or attachments["byte_size"] < 0
            or not isinstance(attachments.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", attachments["sha256"]) is None
        ):
            raise RuntimeError("Team Hub restore transaction journal is invalid")
        return raw

    @classmethod
    def _restore_completion_receipt_value(
        cls,
        raw: Any,
    ) -> dict[str, Any]:
        if (
            not isinstance(raw, dict)
            or set(raw)
            != {
                "format",
                "state",
                "reason",
                "hub_id",
                "host_server_identity",
                "operation_id",
                "snapshot",
                "snapshot_manifest_sha256",
                "generation",
            }
            or raw.get("format") != 1
            or raw.get("state") not in {"prepared", "committed"}
            or raw.get("reason") not in {"server-update", "host-reactivation"}
            or not isinstance(raw.get("hub_id"), str)
            or re.fullmatch(r"[A-Za-z0-9_.:-]{8,240}", raw["hub_id"]) is None
            or not isinstance(raw.get("host_server_identity"), str)
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:@/-]{7,239}",
                raw["host_server_identity"],
            )
            is None
            or not isinstance(raw.get("operation_id"), str)
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", raw["operation_id"]
            )
            is None
            or not isinstance(raw.get("snapshot"), str)
            or re.fullmatch(r"snapshot_[A-Za-z0-9_]+", raw["snapshot"]) is None
            or not isinstance(raw.get("snapshot_manifest_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", raw["snapshot_manifest_sha256"])
            is None
        ):
            raise RuntimeError("Team Hub restore completion receipt is invalid")
        generation = raw.get("generation")
        proof_items = generation.get("proofs") if isinstance(generation, dict) else None
        if not isinstance(proof_items, list) or any(
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or (
                item["name"] != "bootstrap-owner.proof"
                and re.fullmatch(r"[A-Za-z0-9_]{8,240}\.proof", item["name"])
                is None
            )
            for item in proof_items
        ):
            raise RuntimeError("Team Hub restore completion receipt is invalid")
        proof_names = {
            str(item.get("name"))
            for item in proof_items
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        new_targets = {
            "team-hub.sqlite3": "file",
            "access-token-signing.key": "file",
            "attachments": "directory",
            **{name: "file" for name in proof_names},
        }
        try:
            cls._restore_transaction_generation(generation, new_targets)
        except RuntimeError as exc:
            raise RuntimeError("Team Hub restore completion receipt is invalid") from exc
        return raw

    @classmethod
    def _read_restore_completion_receipt_unlocked(
        cls,
        root: Path,
    ) -> dict[str, Any] | None:
        try:
            raw = cls._read_private_regular_file(
                root / RESTORE_COMPLETION_RECEIPT_NAME,
                maximum_bytes=512 * 1024,
            )
        except FileNotFoundError:
            return None
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Team Hub restore completion receipt is invalid") from exc
        return cls._restore_completion_receipt_value(value)

    @classmethod
    def _write_restore_completion_receipt_unlocked(
        cls,
        root: Path,
        receipt: dict[str, Any],
    ) -> None:
        validated = cls._restore_completion_receipt_value(receipt)
        existing = cls._read_restore_completion_receipt_unlocked(root)
        if existing is not None:
            existing_identity = dict(existing)
            new_identity = dict(validated)
            existing_identity.pop("state", None)
            new_identity.pop("state", None)
            if existing_identity != new_identity:
                raise RuntimeError("another Team Hub restore receipt is pending")
            if existing["state"] == "committed" and validated["state"] == "prepared":
                raise RuntimeError("the Team Hub restore is already committed")
        cls._replace_private_control_file_unlocked(
            root / RESTORE_COMPLETION_RECEIPT_NAME,
            canonical_json(validated) + b"\n",
        )

    @classmethod
    def _read_restore_transaction_journal(
        cls,
        root: Path,
    ) -> tuple[dict[str, Any], Path, dict[str, str], dict[str, str]]:
        raw = cls._read_private_regular_file(
            root / RESTORE_TRANSACTION_JOURNAL_NAME,
            maximum_bytes=512 * 1024,
        )
        try:
            journal = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Team Hub restore transaction journal is invalid") from exc
        if (
            not isinstance(journal, dict)
            or set(journal)
            != {
                "format",
                "state",
                "staging",
                "old_targets",
                "new_targets",
                "new_generation",
            }
            or journal.get("format") != 1
            or journal.get("state") not in {"prepared", "committed"}
            or not isinstance(journal.get("staging"), str)
            or RESTORE_STAGING_NAME_RE.fullmatch(journal["staging"]) is None
        ):
            raise RuntimeError("Team Hub restore transaction journal is invalid")
        old_targets = cls._restore_transaction_targets(journal["old_targets"])
        new_targets = cls._restore_transaction_targets(journal["new_targets"])
        if (
            not {"team-hub.sqlite3", "access-token-signing.key", "maintenance-fence.json"}
            .issubset(old_targets)
            or not {"team-hub.sqlite3", "access-token-signing.key", "attachments"}
            .issubset(new_targets)
            or {"team-hub.sqlite3-wal", "team-hub.sqlite3-shm", "maintenance-fence.json"}
            & new_targets.keys()
        ):
            raise RuntimeError("Team Hub restore transaction journal is invalid")
        cls._restore_transaction_generation(journal["new_generation"], new_targets)
        staging = root / journal["staging"]
        if staging.parent != root:
            raise RuntimeError("Team Hub restore transaction journal is invalid")
        return journal, staging, old_targets, new_targets

    @classmethod
    def _write_restore_transaction_journal(
        cls,
        root: Path,
        journal: dict[str, Any],
    ) -> None:
        # Validate the exact record before making it the recovery authority.
        old_targets = cls._restore_transaction_targets(journal.get("old_targets"))
        new_targets = cls._restore_transaction_targets(journal.get("new_targets"))
        if (
            set(journal)
            != {
                "format",
                "state",
                "staging",
                "old_targets",
                "new_targets",
                "new_generation",
            }
            or journal.get("format") != 1
            or journal.get("state") not in {"prepared", "committed"}
            or not isinstance(journal.get("staging"), str)
            or RESTORE_STAGING_NAME_RE.fullmatch(journal["staging"]) is None
            or not {"team-hub.sqlite3", "access-token-signing.key", "maintenance-fence.json"}
            .issubset(old_targets)
            or not {"team-hub.sqlite3", "access-token-signing.key", "attachments"}
            .issubset(new_targets)
            or {"team-hub.sqlite3-wal", "team-hub.sqlite3-shm", "maintenance-fence.json"}
            & new_targets.keys()
            or len(old_targets) > 4104
        ):
            raise RuntimeError("Team Hub restore transaction journal is invalid")
        cls._restore_transaction_generation(journal.get("new_generation"), new_targets)
        payload = canonical_json(journal) + b"\n"
        temporary = root / (
            ".restore-transaction.tmp-"
            f"{os.getpid()}-{secrets.token_hex(8)}"
        )
        descriptor = -1
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600)
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, root / RESTORE_TRANSACTION_JOURNAL_NAME)
            cls._fsync_directory(root)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                temporary.unlink()

    @classmethod
    def _recover_interrupted_restore_unlocked(cls, root: Path) -> None:
        """Resolve one durable restore transaction before SQLite opens.

        A prepared transaction always rolls back. A committed transaction has
        already fsynced and verified the complete replacement generation, so
        recovery keeps it and only finishes cleanup. Every recovery rename is
        itself replay-safe if the process is interrupted again.
        """

        journal, staging, old_targets, new_targets = (
            cls._read_restore_transaction_journal(root)
        )
        receipt = cls._read_restore_completion_receipt_unlocked(root)
        expected_generation = cls._restore_transaction_generation(
            journal["new_generation"], new_targets
        )
        if receipt is None or receipt["generation"] != expected_generation:
            raise RuntimeError("Team Hub restore completion receipt is missing")
        if journal["state"] == "committed" and receipt["state"] != "committed":
            raise RuntimeError("Team Hub committed restore receipt is incomplete")
        staging_exists = cls._restore_target_exists(staging, "directory")
        if journal["state"] == "prepared":
            previous = staging / "previous"
            previous_exists = False
            if staging_exists:
                previous_exists = cls._restore_target_exists(previous, "directory")
            if previous_exists:
                discarded = staging / "recovery-discarded"
                ensure_private_directory(discarded)
                cls._fsync_directory(staging)
                for name in sorted(old_targets.keys() | new_targets.keys()):
                    kind = old_targets.get(name, new_targets.get(name))
                    assert kind is not None
                    target = root / name
                    prior = previous / name
                    prior_exists = cls._restore_target_exists(prior, kind)
                    target_exists = cls._restore_target_exists(target, kind)
                    if name in old_targets:
                        if prior_exists:
                            if target_exists:
                                discard = discarded / f"{name}-{secrets.token_hex(8)}"
                                os.replace(target, discard)
                                cls._fsync_directory(root)
                                cls._fsync_directory(discarded)
                            os.replace(prior, target)
                            cls._fsync_directory(previous)
                            cls._fsync_directory(root)
                        elif not target_exists:
                            raise RuntimeError(
                                "Team Hub restore transaction cannot recover old state"
                            )
                    else:
                        if prior_exists:
                            raise RuntimeError(
                                "Team Hub restore transaction journal is inconsistent"
                            )
                        if target_exists:
                            discard = discarded / f"{name}-{secrets.token_hex(8)}"
                            os.replace(target, discard)
                            cls._fsync_directory(root)
                            cls._fsync_directory(discarded)

            for name, kind in old_targets.items():
                if not cls._restore_target_exists(root / name, kind):
                    raise RuntimeError(
                        "Team Hub restore transaction cannot recover old state"
                    )
            for name, kind in new_targets.items():
                if name not in old_targets and cls._restore_target_exists(root / name, kind):
                    raise RuntimeError(
                        "Team Hub restore transaction rollback is incomplete"
                    )
        else:
            for name, kind in new_targets.items():
                if not cls._restore_target_exists(root / name, kind):
                    raise RuntimeError(
                        "Team Hub committed restore transaction is incomplete"
                    )
            for name, kind in old_targets.items():
                if name not in new_targets and cls._restore_target_exists(root / name, kind):
                    raise RuntimeError(
                        "Team Hub committed restore transaction is inconsistent"
                    )
            generation = cls._restore_transaction_generation(
                journal["new_generation"], new_targets
            )
            if (
                not hmac.compare_digest(
                    cls._sha256_private_regular_file(root / "team-hub.sqlite3"),
                    generation["database_sha256"],
                )
                or not hmac.compare_digest(
                    cls._sha256_private_regular_file(root / "access-token-signing.key"),
                    generation["signing_key_sha256"],
                )
            ):
                raise RuntimeError(
                    "Team Hub committed restore transaction generation is invalid"
                )
            for proof in generation["proofs"]:
                if not hmac.compare_digest(
                    cls._sha256_private_regular_file(root / proof["name"]),
                    proof["sha256"],
                ):
                    raise RuntimeError(
                        "Team Hub committed restore transaction generation is invalid"
                    )
            connection = sqlite3.connect(
                f"file:{root / 'team-hub.sqlite3'}?mode=ro&immutable=1",
                uri=True,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            try:
                attachment_files = cls._team_attachment_snapshot_files(connection)
            finally:
                connection.close()
            if cls._attachment_generation_summary(
                root / "attachments",
                attachment_files,
                exact_tree=True,
                require_root=True,
            ) != generation["attachments"]:
                raise RuntimeError(
                    "Team Hub committed restore transaction generation is invalid"
                )

        if staging_exists:
            shutil.rmtree(staging)
            cls._fsync_directory(root)
        journal_path = root / RESTORE_TRANSACTION_JOURNAL_NAME
        journal_path.unlink()
        cls._fsync_directory(root)
        if journal["state"] == "prepared":
            # A prepared receipt is itself a fail-closed retry token. Retire
            # the journal first: a crash can then leave that receipt for the
            # next exact restore to adopt, whereas journal-without-receipt is
            # not safely distinguishable from a corrupted transaction.
            (root / RESTORE_COMPLETION_RECEIPT_NAME).unlink()
            cls._fsync_directory(root)

    @classmethod
    def _verify_restore_receipt_generation_unlocked(
        cls,
        root: Path,
        generation: dict[str, Any],
    ) -> None:
        for name in (
            "maintenance-fence.json",
            "team-hub.sqlite3-wal",
            "team-hub.sqlite3-shm",
        ):
            try:
                (root / name).lstat()
            except FileNotFoundError:
                continue
            raise RuntimeError("Team Hub restored generation is not quiescent")
        if not hmac.compare_digest(
            cls._sha256_private_regular_file(root / "team-hub.sqlite3"),
            generation["database_sha256"],
        ) or not hmac.compare_digest(
            cls._sha256_private_regular_file(root / "access-token-signing.key"),
            generation["signing_key_sha256"],
        ):
            raise RuntimeError("Team Hub restored generation changed")
        expected_proofs = {
            str(entry["name"]): str(entry["sha256"])
            for entry in generation["proofs"]
        }
        actual_proofs = {
            entry.name
            for entry in os.scandir(root)
            if entry.name == "bootstrap-owner.proof"
            or re.fullmatch(r"[A-Za-z0-9_]{8,240}\.proof", entry.name) is not None
        }
        if actual_proofs != expected_proofs.keys():
            raise RuntimeError("Team Hub restored proof generation changed")
        for name, digest in expected_proofs.items():
            if not hmac.compare_digest(
                cls._sha256_private_regular_file(root / name), digest
            ):
                raise RuntimeError("Team Hub restored proof generation changed")
        connection = sqlite3.connect(
            f"file:{root / 'team-hub.sqlite3'}?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            attachment_files = cls._team_attachment_snapshot_files(connection)
        finally:
            connection.close()
        if cls._attachment_generation_summary(
            root / "attachments",
            attachment_files,
            exact_tree=True,
            require_root=True,
        ) != generation["attachments"]:
            raise RuntimeError("Team Hub restored attachment generation changed")

    @classmethod
    def _matching_restore_receipt_unlocked(
        cls,
        root: Path,
        snapshot: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str,
        expected_reason: str,
    ) -> dict[str, Any]:
        receipt = cls._read_restore_completion_receipt_unlocked(root)
        if receipt is None or receipt["state"] != "committed":
            raise RuntimeError("Team Hub restore completion receipt is missing")
        manifest_digest = cls._sha256_private_regular_file(
            snapshot / "manifest.json"
        )
        if (
            receipt["reason"] != expected_reason
            or receipt["hub_id"] != expected_hub_id
            or receipt["host_server_identity"] != expected_host_identity
            or receipt["operation_id"] != expected_operation_id
            or receipt["snapshot"] != snapshot.name
            or not hmac.compare_digest(
                receipt["snapshot_manifest_sha256"], manifest_digest
            )
        ):
            raise RuntimeError("Team Hub restore completion receipt does not match")
        return receipt

    @classmethod
    def confirm_restored_maintenance_snapshot(
        cls,
        data_dir: Path,
        snapshot_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str,
        expected_reason: str = "server-update",
    ) -> None:
        """Prove an exact prior restore whose fence was already consumed."""

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        snapshot = Path(
            os.path.abspath(os.path.expanduser(os.fspath(snapshot_dir)))
        )
        identity = _identity(expected_host_identity)
        hub_id = _identity(expected_hub_id)
        operation_id = _maintenance_operation_id(expected_operation_id)
        lease = cls.acquire_managed_runtime_lease(root)
        try:
            with cls.maintenance_control_lock(root):
                attachment_lease = cls.acquire_attachment_control_lease(root)
                try:
                    receipt = cls._matching_restore_receipt_unlocked(
                        root,
                        snapshot,
                        expected_host_identity=identity,
                        expected_hub_id=hub_id,
                        expected_operation_id=operation_id,
                        expected_reason=expected_reason,
                    )
                    cls._restore_maintenance_snapshot_unlocked(
                        root,
                        snapshot,
                        expected_host_identity=identity,
                        expected_hub_id=hub_id,
                        expected_operation_id=None,
                        expected_reason=expected_reason,
                        verify_only=True,
                        require_fence=False,
                    )
                    cls._verify_restore_receipt_generation_unlocked(
                        root, receipt["generation"]
                    )
                    if expected_reason == "host-reactivation":
                        handoff = cls._read_host_reactivation_handoff_unlocked(root)
                        if handoff is not None:
                            if (
                                handoff.get("state") != "adopted"
                                or handoff.get("hub_id") != hub_id
                                or handoff.get("host_server_identity") != identity
                                or handoff.get("operation_id") != operation_id
                                or handoff.get("snapshot") != snapshot.name
                            ):
                                raise RuntimeError(
                                    "Team Hub reactivation handoff does not match"
                                )
                            (root / HOST_REACTIVATION_HANDOFF_NAME).unlink()
                            cls._fsync_directory(root)
                finally:
                    cls.release_attachment_control_lease(attachment_lease)
        finally:
            cls.release_managed_runtime_lease(lease)

    @classmethod
    def acknowledge_restored_maintenance_snapshot(
        cls,
        data_dir: Path,
        snapshot_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str,
        expected_reason: str = "server-update",
        allow_missing: bool = False,
    ) -> None:
        """Retire a receipt after the outer activation journal is rolled back."""

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        snapshot = Path(
            os.path.abspath(os.path.expanduser(os.fspath(snapshot_dir)))
        )
        identity = _identity(expected_host_identity)
        hub_id = _identity(expected_hub_id)
        operation_id = _maintenance_operation_id(expected_operation_id)
        lease = cls.acquire_managed_runtime_lease(root)
        try:
            with cls.maintenance_control_lock(root):
                attachment_lease = cls.acquire_attachment_control_lease(root)
                try:
                    try:
                        receipt = cls._matching_restore_receipt_unlocked(
                            root,
                            snapshot,
                            expected_host_identity=identity,
                            expected_hub_id=hub_id,
                            expected_operation_id=operation_id,
                            expected_reason=expected_reason,
                        )
                    except RuntimeError:
                        if (
                            allow_missing
                            and cls._read_restore_completion_receipt_unlocked(root)
                            is None
                        ):
                            # Retry after an unlink whose caller did not
                            # observe the final directory fsync.  Re-fsync the
                            # namespace before acknowledging idempotent
                            # completion.
                            cls._fsync_directory(root)
                            return
                        raise
                    # The installer records its exact link/config rollback
                    # before acknowledgement and cannot start the old service
                    # while this receipt exists.  Revalidate the complete
                    # restored generation under both lifecycle leases before
                    # consuming the last startup blocker.
                    cls._verify_restore_receipt_generation_unlocked(
                        root, receipt["generation"]
                    )
                    (root / RESTORE_COMPLETION_RECEIPT_NAME).unlink()
                    cls._fsync_directory(root)
                finally:
                    cls.release_attachment_control_lease(attachment_lease)
        finally:
            cls.release_managed_runtime_lease(lease)

    @classmethod
    def _team_attachment_snapshot_files(
        cls,
        connection: sqlite3.Connection,
    ) -> list[_TeamAttachmentSnapshotFile]:
        """Derive the exact external files required by one database image."""

        schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if schema_version < 9:
            return []
        try:
            rows = connection.execute(
                """
                SELECT id,storage_key,sha256,state,byte_size,received_bytes
                FROM team_attachments ORDER BY id
                """
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise RuntimeError("Team Hub snapshot attachment schema is invalid") from exc
        files: dict[str, _TeamAttachmentSnapshotFile] = {}
        for row in rows:
            attachment_id = str(row["id"])
            storage_key = str(row["storage_key"])
            raw_digest = row["sha256"]
            state = str(row["state"])
            byte_size = int(row["byte_size"])
            received_bytes = int(row["received_bytes"])
            if (
                re.fullmatch(r"[A-Za-z0-9_]{8,240}", attachment_id) is None
                or re.fullmatch(r"[0-9a-f]{64}", storage_key) is None
                or not isinstance(raw_digest, bytes)
                or not hmac.compare_digest(raw_digest, bytes.fromhex(storage_key))
                or state not in {"uploading", "ready", "failed"}
                or byte_size < 1
                or not 0 <= received_bytes <= byte_size
            ):
                raise RuntimeError("Team Hub snapshot attachment metadata is invalid")
            if state == "ready":
                if received_bytes != byte_size:
                    raise RuntimeError("Team Hub snapshot attachment metadata is invalid")
                spec = _TeamAttachmentSnapshotFile(
                    relative_path=f"{storage_key[:2]}/{storage_key}",
                    byte_size=byte_size,
                    content_sha256=storage_key,
                )
            elif state == "uploading" and received_bytes > 0:
                spec = _TeamAttachmentSnapshotFile(
                    relative_path=f"uploads/{attachment_id}.part",
                    byte_size=received_bytes,
                    content_sha256=None,
                )
            else:
                continue
            previous = files.get(spec.relative_path)
            if previous is not None and previous != spec:
                raise RuntimeError("Team Hub snapshot attachment metadata is invalid")
            files[spec.relative_path] = spec
        return [files[path] for path in sorted(files)]

    @classmethod
    def _attachment_generation_summary(
        cls,
        root: Path,
        files: list[_TeamAttachmentSnapshotFile],
        *,
        exact_tree: bool,
        require_root: bool,
    ) -> dict[str, Any]:
        """Verify one private attachment tree and return its anchored digest."""

        if not root.exists():
            if require_root or files:
                raise RuntimeError("Team Hub snapshot attachment tree is missing")
            return {
                "file_count": 0,
                "byte_size": 0,
                "sha256": hashlib.sha256().hexdigest(),
            }
        try:
            cls._validate_private_directory_without_mutation(root)
            expected_paths = {item.relative_path for item in files}
            expected_directories = {""}
            for relative_path in expected_paths:
                pieces = relative_path.split("/")
                expected_directories.update(
                    "/".join(pieces[:index]) for index in range(1, len(pieces))
                )
            if exact_tree:
                actual_paths: set[str] = set()
                actual_directories = {""}
                for directory, directory_names, file_names in os.walk(
                    root, topdown=True, followlinks=False
                ):
                    current = Path(directory)
                    cls._validate_private_directory_without_mutation(current)
                    relative_directory = current.relative_to(root).as_posix()
                    if relative_directory == ".":
                        relative_directory = ""
                    for name in directory_names:
                        child = current / name
                        info = child.lstat()
                        if (
                            not stat.S_ISDIR(info.st_mode)
                            or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) != 0o700
                        ):
                            raise PermissionError(
                                "Team Hub snapshot attachment directory is unsafe"
                            )
                        actual_directories.add(
                            "/".join(part for part in (relative_directory, name) if part)
                        )
                    for name in file_names:
                        relative = "/".join(
                            part for part in (relative_directory, name) if part
                        )
                        actual_paths.add(relative)
                if actual_paths != expected_paths or actual_directories != expected_directories:
                    raise RuntimeError("Team Hub snapshot attachment tree is invalid")

            digest = hashlib.sha256()
            total_bytes = 0
            for item in files:
                path = root.joinpath(*item.relative_path.split("/"))
                parent = path.parent
                while parent != root:
                    cls._validate_private_directory_without_mutation(parent)
                    parent = parent.parent
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or int(info.st_size) != item.byte_size:
                    raise RuntimeError("Team Hub snapshot attachment file size is invalid")
                file_digest = cls._sha256_private_regular_file(
                    path,
                    allow_hardlinks=item.content_sha256 is not None,
                )
                if item.content_sha256 is not None and not hmac.compare_digest(
                    file_digest, item.content_sha256
                ):
                    raise RuntimeError("Team Hub snapshot attachment digest is invalid")
                record = canonical_json(
                    {
                        "path": item.relative_path,
                        "byte_size": item.byte_size,
                        "sha256": file_digest,
                    }
                )
                digest.update(len(record).to_bytes(8, "big"))
                digest.update(record)
                total_bytes += item.byte_size
            return {
                "file_count": len(files),
                "byte_size": total_bytes,
                "sha256": digest.hexdigest(),
            }
        except (OSError, ValueError) as exc:
            raise RuntimeError("Team Hub snapshot attachment tree is invalid") from exc

    @classmethod
    def _copy_attachment_generation(
        cls,
        source_root: Path,
        destination_root: Path,
        files: list[_TeamAttachmentSnapshotFile],
    ) -> dict[str, Any]:
        """Copy only files required by the database into a fresh private tree."""

        ensure_private_directory(destination_root)
        if files:
            cls._validate_private_directory_without_mutation(source_root)
        for item in files:
            source = source_root.joinpath(*item.relative_path.split("/"))
            source_parent = source.parent
            while source_parent != source_root:
                cls._validate_private_directory_without_mutation(source_parent)
                source_parent = source_parent.parent
            destination = destination_root.joinpath(*item.relative_path.split("/"))
            ensure_private_directory(destination.parent)
            if item.content_sha256 is not None:
                cls._link_or_copy_immutable_private_file(source, destination)
            else:
                # Resumable uploads are mutable and must remain an independent
                # generation even when source and destination share a device.
                cls._copy_private_regular_file(source, destination)
        summary = cls._attachment_generation_summary(
            destination_root,
            files,
            exact_tree=True,
            require_root=True,
        )
        directories = sorted(
            (path for path in destination_root.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        )
        for directory in directories:
            cls._fsync_directory(directory)
        cls._fsync_directory(destination_root)
        return summary

    def connect(self) -> sqlite3.Connection:
        return open_database(self.database_path)

    def _initialize(
        self,
        timestamp: int,
        expected_host_identity: str | None,
        *,
        allow_bound_control: bool,
    ) -> None:
        connection = self.connect()
        try:
            with _write_transaction(connection):
                row = connection.execute(
                    "SELECT hub_id FROM hub_metadata WHERE singleton = 1"
                ).fetchone()
                if row is None:
                    self.hub_id = _id("hub")
                    connection.execute(
                        "INSERT INTO hub_metadata(singleton, hub_id, created_at) VALUES (1, ?, ?)",
                        (self.hub_id, timestamp),
                    )
                else:
                    self.hub_id = str(row["hub_id"])
                binding = connection.execute(
                    """
                    SELECT hub_id, server_identity
                    FROM managed_host_bindings WHERE singleton = 1
                    """
                ).fetchone()
                if expected_host_identity is not None:
                    if binding is None:
                        connection.execute(
                            """
                            INSERT INTO managed_host_bindings(
                                singleton, hub_id, server_identity, created_at
                            ) VALUES (1, ?, ?, ?)
                            """,
                            (self.hub_id, expected_host_identity, timestamp),
                        )
                        self.managed_host_identity = expected_host_identity
                    elif (
                        str(binding["hub_id"]) != self.hub_id
                        or str(binding["server_identity"]) != expected_host_identity
                    ):
                        raise RuntimeError(
                            "Team Hub database is bound to a different AgentsServer host"
                        )
                    else:
                        self.managed_host_identity = expected_host_identity
                elif binding is not None:
                    if not allow_bound_control:
                        raise RuntimeError(
                            "managed Team Hub databases cannot be served standalone"
                        )
                    self.managed_host_identity = str(binding["server_identity"])
                self._validate_owner_invariants(connection)
                bootstrapped = self._is_bootstrapped(connection)
                if bootstrapped and self.managed_host_identity is not None:
                    team_owners = connection.execute(
                        """
                        SELECT t.id AS team_id,m.principal_id AS owner_principal_id
                        FROM teams AS t
                        JOIN memberships AS m
                          ON m.team_id=t.id AND m.role='owner' AND m.status='active'
                        ORDER BY t.created_at,t.id
                        """
                    ).fetchall()
                    # A managed AgentsServer identity is one logical server and
                    # cannot be silently attached to multiple team networks.
                    # Existing single-team databases are upgraded eagerly;
                    # multi-team stores bind only through an explicit peer/team
                    # approval path.
                    if len(team_owners) == 1:
                        team_owner = team_owners[0]
                        self._ensure_managed_host_node(
                            connection, team_owner["team_id"], timestamp
                        )
                        self._managed_server_principal(
                            connection, team_owner["team_id"], timestamp
                        )
                        self._ensure_network_board(
                            connection,
                            team_owner["team_id"],
                            team_owner["owner_principal_id"],
                            timestamp,
                        )
                if not bootstrapped:
                    if not self._globally_empty(connection):
                        raise RuntimeError(
                            "Team Hub refuses a partial unbootstrapped identity database"
                        )
                    self._ensure_bootstrap_claim(connection, timestamp)
        finally:
            connection.close()

    @staticmethod
    def _is_bootstrapped(connection: sqlite3.Connection) -> bool:
        return bool(connection.execute("SELECT EXISTS(SELECT 1 FROM teams)").fetchone()[0])

    @staticmethod
    def _globally_empty(connection: sqlite3.Connection) -> bool:
        return all(
            int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]) == 0
            for table in ("principals", "teams", "memberships", "device_sessions")
        )

    @staticmethod
    def _validate_owner_invariants(connection: sqlite3.Connection) -> None:
        invalid = connection.execute(
            """
            SELECT t.id
            FROM teams AS t
            LEFT JOIN memberships AS m
              ON m.team_id = t.id AND m.role = 'owner' AND m.status = 'active'
            LEFT JOIN principals AS p ON p.id = m.principal_id AND p.status = 'active'
            GROUP BY t.id
            HAVING count(m.id) <> 1 OR count(p.id) <> 1
            LIMIT 1
            """
        ).fetchone()
        if invalid is not None:
            raise RuntimeError(
                f"Team Hub refuses a team without exactly one active owner: {invalid['id']}"
            )

    def _read_local_proof(self, path: Path) -> str | None:
        try:
            value = read_secret_file(path).decode("ascii").strip()
        except (FileNotFoundError, UnicodeError, OSError, PermissionError):
            return None
        return value if 16 <= len(value) <= 512 else None

    def _ensure_bootstrap_claim(
        self,
        connection: sqlite3.Connection,
        timestamp: int,
        *,
        force_local: bool = False,
    ) -> None:
        active = connection.execute(
            """
            SELECT c.id, c.token_hash, c.expires_at,
                   d.server_instance_id AS delegated_server_instance_id
            FROM bootstrap_claims AS c
            LEFT JOIN bootstrap_delegations AS d ON d.bootstrap_claim_id = c.id
            WHERE c.consumed_at IS NULL AND c.revoked_at IS NULL AND c.expires_at > ?
            ORDER BY c.created_at DESC LIMIT 1
            """,
            (timestamp,),
        ).fetchone()
        local_proof = self._read_local_proof(self.bootstrap_proof_path)
        if (
            not force_local
            and active is not None
            and active["delegated_server_instance_id"] is not None
            and str(active["delegated_server_instance_id"])
            == self.managed_server_instance_id
            and local_proof is None
        ):
            return
        if (
            not force_local
            and active is not None
            and active["delegated_server_instance_id"] is None
            and local_proof is not None
            and hmac.compare_digest(active["token_hash"], token_hash(local_proof))
        ):
            return
        connection.execute(
            """
            UPDATE bootstrap_claims SET revoked_at = ?
            WHERE consumed_at IS NULL AND revoked_at IS NULL
            """,
            (timestamp,),
        )
        try:
            self.bootstrap_proof_path.unlink(missing_ok=True)
        except OSError as exc:
            raise PermissionError("cannot replace stale bootstrap proof") from exc
        proof, digest = opaque_secret("bootstrap")
        create_secret_file(self.bootstrap_proof_path, (proof + "\n").encode("ascii"))
        connection.execute(
            """
            INSERT INTO bootstrap_claims(
                id, token_hash, created_at, expires_at
            ) VALUES (?, ?, ?, ?)
            """,
            (_id("bootstrap_claim"), digest, timestamp, timestamp + BOOTSTRAP_PROOF_TTL_SECONDS),
        )

    def health(self) -> dict[str, Any]:
        connection = self.connect()
        try:
            bootstrapped = self._is_bootstrapped(connection)
            return {
                "ok": True,
                "service": "agentsdock-team-hub",
                "api_version": 1,
                "schema_version": LATEST_SCHEMA_VERSION,
                "hub_id": self.hub_id,
                "instance_id": self.instance_id,
                "bootstrapped": bootstrapped,
                "bootstrap_required": not bootstrapped,
                "capabilities": {
                    "team_network_v1": {
                        "available": True,
                        "version": 1,
                        "logical_servers": True,
                        "agent_registry": True,
                        "bulletin": True,
                        "mailbox": True,
                        "delivery_receipts": ["delivered", "read"],
                        "passive_requests": True,
                        "server_invites": False,
                        "skill_attachments": False,
                        "dispatch": False,
                        "max_agents_per_server": MAX_NETWORK_AGENTS_PER_SERVER,
                        "max_page_items": MAX_NETWORK_PAGE_ITEMS,
                        "max_body_bytes": MAX_NETWORK_BODY_BYTES,
                    },
                    # Sibling object: clients that parse team_network_v1 with
                    # an exact key list keep working unchanged.
                    "team_messages_v1": self.team_messages_capability(),
                },
            }
        finally:
            connection.close()

    def maintenance_snapshot(self, reason: str, *, keep: int = 3) -> Path:
        with self.maintenance_control_lock(self.data_dir):
            return self._maintenance_snapshot_unlocked(reason, keep=keep)

    @classmethod
    def prepare_managed_host_reactivation(
        cls,
        data_dir: Path,
        *,
        expected_host_identity: str,
    ) -> tuple[str, Path, str, int, int]:
        """Verify and snapshot one exact preserved host before reactivation.

        The candidate runtime may contain newer migrations than the disabled
        host. Open the source read-only and use SQLite's online backup instead
        of constructing HubStore normally, so the rollback generation always
        captures the exact pre-reactivation schema.
        """

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        identity = _identity(expected_host_identity)
        lease = cls.acquire_managed_runtime_lease(root)
        try:
            bound_identity = cls.managed_host_binding_without_source_mutation(root)
            if bound_identity is None:
                raise RuntimeError(
                    "preserved Team Hub state has no managed host binding"
                )
            if not hmac.compare_digest(bound_identity, identity):
                raise RuntimeError(
                    "preserved Team Hub state is bound to a different AgentsServer host"
                )
            probe = object.__new__(cls)
            probe.data_dir = root
            probe.database_path = root / "team-hub.sqlite3"
            probe.signing_key_path = root / "access-token-signing.key"
            probe.bootstrap_proof_path = root / "bootstrap-owner.proof"
            probe.maintenance_fence_path = root / "maintenance-fence.json"
            probe.managed_host_identity = identity
            probe.hub_id = ""
            operation_id = f"host-reactivation-{secrets.token_hex(12)}"

            def connect_read_only() -> sqlite3.Connection:
                connection = sqlite3.connect(
                    f"{probe.database_path.as_uri()}?mode=ro",
                    uri=True,
                    isolation_level=None,
                )
                connection.row_factory = sqlite3.Row
                return connection

            probe.connect = connect_read_only
            with cls.maintenance_control_lock(root):
                resumable = cls._recover_host_reactivation_handoff_unlocked(root)
                if resumable is not None:
                    snapshot = (
                        root
                        / "maintenance-backups"
                        / str(resumable["snapshot"])
                    )
                    attachment_lease = cls.acquire_attachment_control_lease(root)
                    try:
                        cls._restore_maintenance_snapshot_unlocked(
                            root,
                            snapshot,
                            expected_host_identity=identity,
                            expected_hub_id=str(resumable["hub_id"]),
                            expected_operation_id=str(resumable["operation_id"]),
                            expected_reason="host-reactivation",
                            verify_only=True,
                        )
                    finally:
                        cls.release_attachment_control_lease(attachment_lease)
                    return (
                        str(resumable["hub_id"]),
                        snapshot,
                        str(resumable["operation_id"]),
                        int(resumable["fence_device"]),
                        int(resumable["fence_inode"]),
                    )
                if probe.maintenance_fence() is not None:
                    raise RuntimeError(
                        "preserved Team Hub state is already in managed maintenance"
                    )
                snapshot = probe._maintenance_snapshot_unlocked(
                    "host-reactivation",
                    source_read_only=True,
                    allow_legacy_schema=True,
                    derive_hub_id=True,
                    verify_host_reactivation_before_publish=True,
                )
                # Commit a durable source-generation fence before releasing
                # either the snapshot/control lock or the runtime lease. The
                # installer carries this exact operation identity through
                # candidate health or rollback, so no HTTP or supported local
                # control mutation can become newer than the rollback image.
                marker = {
                    "format": 1,
                    "reason": "host-reactivation",
                    "operation_id": operation_id,
                    "hub_id": probe.hub_id,
                    "host_server_identity": identity,
                    "snapshot": snapshot.name,
                    "snapshot_manifest_sha256": cls._sha256_private_regular_file(
                        snapshot / "manifest.json"
                    ),
                    "created_at": _iso8601(_now()),
                }
                marker_bytes = canonical_json(marker) + b"\n"
                fence_staging = (
                    root / f".maintenance-fence-{operation_id}.pending"
                )
                created_fence_info = cls._create_owned_maintenance_fence(
                    fence_staging,
                    marker_bytes,
                )
                handoff = {
                    "format": 2,
                    "state": "creating",
                    "hub_id": probe.hub_id,
                    "host_server_identity": identity,
                    "operation_id": operation_id,
                    "snapshot": snapshot.name,
                    "fence_device": created_fence_info.st_dev,
                    "fence_inode": created_fence_info.st_ino,
                    "fence_staging": fence_staging.name,
                }
                handoff_path = root / HOST_REACTIVATION_HANDOFF_NAME
                handoff_bytes = canonical_json(handoff) + b"\n"
                try:
                    cls._create_owned_maintenance_fence(
                        handoff_path,
                        handoff_bytes,
                    )
                    os.link(
                        fence_staging,
                        probe.maintenance_fence_path,
                        follow_symlinks=False,
                    )
                    linked_info = probe.maintenance_fence_path.lstat()
                    if (
                        linked_info.st_dev != created_fence_info.st_dev
                        or linked_info.st_ino != created_fence_info.st_ino
                    ):
                        raise RuntimeError(
                            "Team Hub reactivation source fence changed"
                        )
                    fence_staging.unlink()
                    cls._fsync_directory(root)
                    if cls._maintenance_fence_control_unlocked(
                        root,
                        expected_hub_id=probe.hub_id,
                        expected_host_identity=identity,
                        expected_reason="host-reactivation",
                        expected_operation_id=operation_id,
                        expected_snapshot=snapshot,
                    ) is None:
                        raise RuntimeError(
                            "Team Hub reactivation source fence could not be verified"
                        )
                    handoff.update(
                        {
                            "state": "unclaimed",
                        }
                    )
                    cls._replace_private_control_file_unlocked(
                        handoff_path,
                        canonical_json(handoff) + b"\n",
                    )
                except BaseException as fence_error:
                    # No caller has received the operation identity yet.
                    # Remove only paths that still name the exact staged
                    # fence inode; replacements remain fail-closed.
                    for candidate in (
                        probe.maintenance_fence_path,
                        fence_staging,
                    ):
                        try:
                            current_info = candidate.lstat()
                        except FileNotFoundError:
                            continue
                        if (
                            current_info.st_dev != created_fence_info.st_dev
                            or current_info.st_ino != created_fence_info.st_ino
                        ):
                            raise RuntimeError(
                                "Team Hub reactivation source fence remains fail-closed"
                            ) from fence_error
                        candidate.unlink()
                    try:
                        current_handoff = cls._read_host_reactivation_handoff_unlocked(
                            root
                        )
                    except FileNotFoundError:
                        current_handoff = None
                    if current_handoff is not None:
                        if (
                            current_handoff.get("operation_id") != operation_id
                            or current_handoff.get("state")
                            not in {"creating", "unclaimed"}
                            or current_handoff.get("fence_device")
                            != created_fence_info.st_dev
                            or current_handoff.get("fence_inode")
                            != created_fence_info.st_ino
                        ):
                            raise RuntimeError(
                                "Team Hub reactivation handoff remains fail-closed"
                            ) from fence_error
                        handoff_path.unlink()
                    cls._fsync_directory(root)
                    raise fence_error
            return (
                probe.hub_id,
                snapshot,
                operation_id,
                created_fence_info.st_dev,
                created_fence_info.st_ino,
            )
        finally:
            cls.release_managed_runtime_lease(lease)

    @classmethod
    def begin_managed_startup_guard(
        cls,
        data_dir: Path,
        *,
        expected_host_identity: str,
    ) -> tuple[str, int, int]:
        """Publish or resume the exact guard used while old code is unlinked."""

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        identity = _identity(expected_host_identity)
        bound_identity = cls.managed_host_binding_without_source_mutation(root)
        if bound_identity is None or not hmac.compare_digest(
            bound_identity,
            identity,
        ):
            raise RuntimeError("Team Hub startup guard binding does not match")
        with cls.maintenance_control_lock(root):
            try:
                existing = cls._read_managed_startup_guard_unlocked(root)
            except FileNotFoundError:
                existing = None
            path = root / MANAGED_STARTUP_GUARD_NAME
            if existing is not None:
                if existing["host_server_identity"] != identity:
                    raise RuntimeError("Team Hub startup guard does not match")
                info = path.lstat()
                return existing["guard_id"], info.st_dev, info.st_ino
            guard_id = f"cold-handoff-{secrets.token_hex(12)}"
            payload = canonical_json(
                {
                    "format": 1,
                    "host_server_identity": identity,
                    "guard_id": guard_id,
                }
            ) + b"\n"
            info = cls._create_owned_maintenance_fence(path, payload)
            return guard_id, info.st_dev, info.st_ino

    @classmethod
    def clear_managed_startup_guard(
        cls,
        data_dir: Path,
        *,
        expected_host_identity: str,
        expected_guard_id: str,
        expected_device: int,
        expected_inode: int,
    ) -> bool:
        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        identity = _identity(expected_host_identity)
        with cls.maintenance_control_lock(root):
            try:
                guard = cls._read_managed_startup_guard_unlocked(root)
            except FileNotFoundError:
                return False
            path = root / MANAGED_STARTUP_GUARD_NAME
            info = path.lstat()
            if (
                guard.get("host_server_identity") != identity
                or guard.get("guard_id") != expected_guard_id
                or info.st_dev != expected_device
                or info.st_ino != expected_inode
            ):
                raise RuntimeError("Team Hub startup guard does not match")
            path.unlink()
            try:
                cls._fsync_directory(root)
            except BaseException:
                try:
                    path.lstat()
                except FileNotFoundError:
                    return True
                raise
            return True

    @classmethod
    def publish_managed_startup_authority(
        cls,
        data_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_reason: str,
        expected_operation_id: str,
        expected_snapshot: Path,
    ) -> None:
        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        snapshot = Path(
            os.path.abspath(os.path.expanduser(os.fspath(expected_snapshot)))
        )
        identity = _identity(expected_host_identity)
        with cls.maintenance_control_lock(root):
            marker = cls._maintenance_fence_control_unlocked(
                root,
                expected_hub_id=expected_hub_id,
                expected_host_identity=identity,
                expected_reason=expected_reason,
                expected_operation_id=expected_operation_id,
                expected_snapshot=snapshot,
            )
            if marker is None or not isinstance(
                marker.get("snapshot_manifest_sha256"), str
            ):
                raise RuntimeError("Team Hub startup authority fence is missing")
            if expected_reason == "host-reactivation":
                cls._consume_host_reactivation_handoff_unlocked(
                    root,
                    expected_hub_id=expected_hub_id,
                    expected_host_identity=identity,
                    expected_operation_id=expected_operation_id,
                    expected_snapshot=snapshot,
                    remove=False,
                )
            payload = canonical_json(
                {
                    "format": 1,
                    "reason": expected_reason,
                    "hub_id": expected_hub_id,
                    "host_server_identity": identity,
                    "operation_id": expected_operation_id,
                    "snapshot": snapshot.name,
                    "snapshot_manifest_sha256": marker[
                        "snapshot_manifest_sha256"
                    ],
                }
            ) + b"\n"
            path = root / MANAGED_STARTUP_AUTHORITY_NAME
            try:
                current = cls._read_private_regular_file(
                    path,
                    maximum_bytes=16 * 1024,
                )
            except FileNotFoundError:
                cls._create_owned_maintenance_fence(path, payload)
            else:
                if hmac.compare_digest(current, payload):
                    cls._fsync_directory(root)
                else:
                    # A no-fence crash residue is powerless. Once this exact
                    # new fence has been authenticated, replace it atomically
                    # rather than permanently wedging the next update.
                    cls._replace_private_control_file_unlocked(path, payload)

    @classmethod
    def clear_managed_startup_authority(
        cls,
        data_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_reason: str,
        expected_operation_id: str,
        expected_snapshot: Path,
    ) -> bool:
        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        with cls.maintenance_control_lock(root):
            try:
                authority = cls._read_managed_startup_authority_unlocked(root)
            except FileNotFoundError:
                return False
            if (
                authority["host_server_identity"] != expected_host_identity
                or authority["hub_id"] != expected_hub_id
                or authority["reason"] != expected_reason
                or authority["operation_id"] != expected_operation_id
                or authority["snapshot"] != Path(expected_snapshot).name
            ):
                raise RuntimeError("Team Hub startup authority does not match")
            path = root / MANAGED_STARTUP_AUTHORITY_NAME
            path.unlink()
            try:
                cls._fsync_directory(root)
            except BaseException:
                try:
                    path.lstat()
                except FileNotFoundError:
                    return True
                raise
            return True

    @classmethod
    def adopt_prepared_host_reactivation(
        cls,
        data_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str,
        expected_snapshot: Path,
        expected_device: int,
        expected_inode: int,
    ) -> None:
        """Atomically transfer an unclaimed preflight to its installer."""

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        identity = _identity(expected_host_identity)
        snapshot = Path(
            os.path.abspath(os.path.expanduser(os.fspath(expected_snapshot)))
        )
        lease = cls.acquire_managed_runtime_lease(root)
        try:
            with cls.maintenance_control_lock(root):
                handoff = cls._read_host_reactivation_handoff_unlocked(root)
                if handoff is None:
                    raise RuntimeError("Team Hub reactivation handoff is missing")
                expected_fields = (
                    handoff.get("hub_id") == expected_hub_id
                    and handoff.get("host_server_identity") == identity
                    and handoff.get("operation_id") == expected_operation_id
                    and handoff.get("snapshot") == snapshot.name
                    and handoff.get("fence_device") == expected_device
                    and handoff.get("fence_inode") == expected_inode
                )
                if not expected_fields or handoff.get("state") not in {
                    "unclaimed",
                    "adopted",
                }:
                    raise RuntimeError(
                        "Team Hub reactivation handoff does not match"
                    )
                marker = cls._maintenance_fence_control_unlocked(
                    root,
                    expected_hub_id=expected_hub_id,
                    expected_host_identity=identity,
                    expected_reason="host-reactivation",
                    expected_operation_id=expected_operation_id,
                    expected_snapshot=snapshot,
                )
                marker_info = (root / "maintenance-fence.json").lstat()
                if (
                    marker is None
                    or marker_info.st_dev != expected_device
                    or marker_info.st_ino != expected_inode
                ):
                    raise RuntimeError(
                        "Team Hub reactivation fence ownership changed"
                    )
                attachment_lease = cls.acquire_attachment_control_lease(root)
                try:
                    cls._restore_maintenance_snapshot_unlocked(
                        root,
                        snapshot,
                        expected_host_identity=identity,
                        expected_hub_id=expected_hub_id,
                        expected_operation_id=expected_operation_id,
                        expected_reason="host-reactivation",
                        verify_only=True,
                    )
                finally:
                    cls.release_attachment_control_lease(attachment_lease)
                marker_after = (root / "maintenance-fence.json").lstat()
                if (
                    marker_after.st_dev != expected_device
                    or marker_after.st_ino != expected_inode
                ):
                    raise RuntimeError(
                        "Team Hub reactivation fence ownership changed"
                    )
                current_handoff = cls._read_host_reactivation_handoff_unlocked(
                    root
                )
                if current_handoff != handoff:
                    raise RuntimeError(
                        "Team Hub reactivation handoff changed during adoption"
                    )
                if handoff["state"] == "unclaimed":
                    handoff["state"] = "adopted"
                    cls._replace_private_control_file_unlocked(
                        root / HOST_REACTIVATION_HANDOFF_NAME,
                        canonical_json(handoff) + b"\n",
                    )
                else:
                    # An earlier adoption may have committed its rename but
                    # reported a directory-fsync failure. The idempotent
                    # retry cannot claim success until durability is proven.
                    cls._fsync_directory(root)
        finally:
            cls.release_managed_runtime_lease(lease)

    @classmethod
    def abort_prepared_host_reactivation(
        cls,
        data_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str,
        expected_snapshot: Path,
        expected_device: int,
        expected_inode: int,
    ) -> bool:
        """Clear a fully verified pre-takeover reactivation fence.

        This recovery path exists for a shell that died after the CLI
        committed the fence but before it adopted the returned operation.
        The managed runtime lease and exact inode/content recheck ensure no
        active candidate or replaced marker is consumed.
        """

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        identity = _identity(expected_host_identity)
        lease = cls.acquire_managed_runtime_lease(root)
        try:
            with cls.maintenance_control_lock(root):
                marker_path = root / "maintenance-fence.json"
                try:
                    before = marker_path.lstat()
                    raw = cls._read_private_regular_file(
                        marker_path,
                        maximum_bytes=16 * 1024,
                    )
                except FileNotFoundError:
                    return False
                try:
                    marker = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise RuntimeError("Team Hub maintenance fence is invalid") from exc
                snapshot = Path(
                    os.path.abspath(
                        os.path.expanduser(os.fspath(expected_snapshot))
                    )
                )
                cls._maintenance_fence_control_unlocked(
                    root,
                    expected_hub_id=expected_hub_id,
                    expected_host_identity=identity,
                    expected_reason="host-reactivation",
                    expected_operation_id=expected_operation_id,
                    expected_snapshot=snapshot,
                )
                if (
                    marker.get("format") != 1
                    or before.st_dev != expected_device
                    or before.st_ino != expected_inode
                ):
                    raise RuntimeError(
                        "Team Hub reactivation preflight fence does not match"
                    )
                attachment_lease = cls.acquire_attachment_control_lease(root)
                try:
                    cls._restore_maintenance_snapshot_unlocked(
                        root,
                        snapshot,
                        expected_host_identity=identity,
                        expected_hub_id=expected_hub_id,
                        expected_operation_id=expected_operation_id,
                        expected_reason="host-reactivation",
                        verify_only=True,
                    )
                finally:
                    cls.release_attachment_control_lease(attachment_lease)
                after = marker_path.lstat()
                current = cls._read_private_regular_file(
                    marker_path,
                    maximum_bytes=16 * 1024,
                )
                if (
                    before.st_dev != after.st_dev
                    or before.st_ino != after.st_ino
                    or after.st_dev != expected_device
                    or after.st_ino != expected_inode
                    or not hmac.compare_digest(raw, current)
                ):
                    raise RuntimeError(
                        "Team Hub reactivation preflight fence changed"
                    )
                cls._consume_host_reactivation_handoff_unlocked(
                    root,
                    expected_hub_id=expected_hub_id,
                    expected_host_identity=identity,
                    expected_operation_id=expected_operation_id,
                    expected_snapshot=snapshot,
                    remove=False,
                    expected_state="unclaimed",
                )
                marker_path.unlink()
                cls._consume_host_reactivation_handoff_unlocked(
                    root,
                    expected_hub_id=expected_hub_id,
                    expected_host_identity=identity,
                    expected_operation_id=expected_operation_id,
                    expected_snapshot=snapshot,
                    expected_state="unclaimed",
                )
                cls._fsync_directory(root)
                return True
        finally:
            cls.release_managed_runtime_lease(lease)

    def maintenance_snapshot_and_fence(
        self,
        reason: str,
        *,
        operation_id: str,
        keep: int = 3,
    ) -> Path:
        """Create a snapshot and durably exclude local/HTTP writes afterward."""

        clean_operation_id = _maintenance_operation_id(operation_id)
        with self.maintenance_control_lock(self.data_dir):
            if self.maintenance_fence_path.exists():
                raise RuntimeError("Team Hub maintenance is already active")
            snapshot = self._maintenance_snapshot_unlocked(reason, keep=keep)
            clean_reason = _bounded_text(reason, "reason", 1, 80)
            marker = {
                "format": 1,
                "reason": clean_reason,
                "operation_id": clean_operation_id,
                "hub_id": self.hub_id,
                "host_server_identity": self.managed_host_identity,
                "snapshot": snapshot.name,
                "snapshot_manifest_sha256": self._sha256_private_regular_file(
                    snapshot / "manifest.json"
                ),
                "created_at": _iso8601(_now()),
            }
            try:
                create_secret_file(
                    self.maintenance_fence_path,
                    canonical_json(marker) + b"\n",
                )
            except BaseException:
                # A directory fsync or final validation can report failure
                # after the no-replace fence creation already committed.  An
                # exact, fully verified marker is therefore success; making
                # the caller guess would strand the snapshot identity needed
                # to clear it safely.
                if self._maintenance_fence_control_unlocked(
                    self.data_dir,
                    expected_hub_id=self.hub_id,
                    expected_host_identity=str(self.managed_host_identity),
                    expected_reason=clean_reason,
                    expected_operation_id=clean_operation_id,
                    expected_snapshot=snapshot,
                ) is not None:
                    # The reported failure may have been the first directory
                    # fsync itself. Retry it before treating the exact marker
                    # as the durable admission boundary.
                    self._fsync_directory(self.data_dir)
                    return snapshot
                raise
            return snapshot

    def maintenance_fence(self) -> dict[str, Any] | None:
        try:
            raw = self._read_private_regular_file(
                self.maintenance_fence_path,
                maximum_bytes=16 * 1024,
            )
        except FileNotFoundError:
            return None
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Team Hub maintenance fence is invalid") from exc
        if (
            not self._maintenance_fence_payload_valid(value)
            or value.get("hub_id") != self.hub_id
            or value.get("host_server_identity") != self.managed_host_identity
        ):
            raise RuntimeError("Team Hub maintenance fence is invalid")
        return value

    def clear_maintenance_fence(
        self,
        *,
        expected_reason: str,
        expected_operation_id: str,
        expected_snapshot: Path,
    ) -> bool:
        """Clear one exact completed/cancelled maintenance generation."""

        clean_reason = _bounded_text(expected_reason, "reason", 1, 80)
        clean_operation_id = _maintenance_operation_id(expected_operation_id)
        with self.maintenance_control_lock(self.data_dir):
            marker = self._maintenance_fence_control_unlocked(
                self.data_dir,
                expected_hub_id=self.hub_id,
                expected_host_identity=str(self.managed_host_identity),
                expected_reason=clean_reason,
                expected_operation_id=clean_operation_id,
                expected_snapshot=expected_snapshot,
            )
            if marker is None:
                return False
            if clean_reason == "host-reactivation":
                self._consume_host_reactivation_handoff_unlocked(
                    self.data_dir,
                    expected_hub_id=self.hub_id,
                    expected_host_identity=str(self.managed_host_identity),
                    expected_operation_id=clean_operation_id,
                    expected_snapshot=expected_snapshot,
                    remove=False,
                )
            self.maintenance_fence_path.unlink()
            try:
                if clean_reason == "host-reactivation":
                    self._consume_host_reactivation_handoff_unlocked(
                        self.data_dir,
                        expected_hub_id=self.hub_id,
                        expected_host_identity=str(self.managed_host_identity),
                        expected_operation_id=clean_operation_id,
                        expected_snapshot=expected_snapshot,
                    )
                self._fsync_directory(self.data_dir)
            except BaseException:
                try:
                    self.maintenance_fence_path.lstat()
                except FileNotFoundError:
                    # The unlink is the irreversible admission commit. A
                    # directory-fsync error is reported by storage but must
                    # never send the installer down the rollback path.
                    return True
                raise
            return True

    @classmethod
    def _maintenance_fence_control_unlocked(
        cls,
        root: Path,
        *,
        expected_hub_id: str,
        expected_host_identity: str,
        expected_reason: str,
        expected_operation_id: str,
        expected_snapshot: Path,
        verify_snapshot_digest: bool = True,
    ) -> dict[str, Any] | None:
        marker_path = root / "maintenance-fence.json"
        try:
            raw = cls._read_private_regular_file(
                marker_path, maximum_bytes=16 * 1024
            )
        except FileNotFoundError:
            return None
        try:
            marker = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Team Hub maintenance fence is invalid") from exc
        if (
            not cls._maintenance_fence_payload_valid(marker)
            or marker.get("hub_id") != expected_hub_id
            or marker.get("host_server_identity") != expected_host_identity
            or marker.get("reason") != expected_reason
        ):
            raise RuntimeError("Team Hub maintenance fence does not match")
        if marker.get("operation_id") != _maintenance_operation_id(
            expected_operation_id
        ):
            raise RuntimeError("Team Hub maintenance operation does not match")
        if marker.get("snapshot") != Path(expected_snapshot).name:
            raise RuntimeError("Team Hub maintenance snapshot does not match")
        expected_digest = marker.get("snapshot_manifest_sha256")
        if verify_snapshot_digest and expected_digest is not None:
            try:
                actual_digest = cls._sha256_private_regular_file(
                    Path(expected_snapshot) / "manifest.json"
                )
            except FileNotFoundError as exc:
                raise RuntimeError(
                    "Team Hub maintenance snapshot generation is missing"
                ) from exc
            if not hmac.compare_digest(expected_digest, actual_digest):
                raise RuntimeError(
                    "Team Hub maintenance snapshot generation changed"
                )
        return marker

    @classmethod
    def maintenance_fence_matches_control(
        cls,
        data_dir: Path,
        *,
        expected_hub_id: str,
        expected_host_identity: str,
        expected_reason: str,
        expected_operation_id: str,
        expected_snapshot: Path,
    ) -> bool:
        """Check an exact fence without opening or migrating its database."""

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        with cls.maintenance_control_lock(root):
            return cls._maintenance_fence_control_unlocked(
                root,
                expected_hub_id=expected_hub_id,
                expected_host_identity=expected_host_identity,
                expected_reason=expected_reason,
                expected_operation_id=expected_operation_id,
                expected_snapshot=expected_snapshot,
            ) is not None

    @classmethod
    def clear_maintenance_fence_control(
        cls,
        data_dir: Path,
        *,
        expected_hub_id: str,
        expected_host_identity: str,
        expected_reason: str,
        expected_operation_id: str,
        expected_snapshot: Path,
        expected_device: int | None = None,
        expected_inode: int | None = None,
    ) -> bool:
        """Clear an exact fence without opening or migrating its database.

        The detached updater intentionally runs from the previous release and
        therefore may not understand a candidate's newer SQLite schema.
        """

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        marker_path = root / "maintenance-fence.json"
        with cls.maintenance_control_lock(root):
            marker = cls._maintenance_fence_control_unlocked(
                root,
                expected_hub_id=expected_hub_id,
                expected_host_identity=expected_host_identity,
                expected_reason=expected_reason,
                expected_operation_id=expected_operation_id,
                expected_snapshot=expected_snapshot,
            )
            if marker is None:
                return False
            marker_info = marker_path.lstat()
            if (
                (expected_device is None) != (expected_inode is None)
                or (
                    expected_device is not None
                    and (
                        marker_info.st_dev != expected_device
                        or marker_info.st_ino != expected_inode
                    )
                )
            ):
                raise RuntimeError("Team Hub maintenance fence ownership changed")
            if expected_reason == "host-reactivation":
                cls._consume_host_reactivation_handoff_unlocked(
                    root,
                    expected_hub_id=expected_hub_id,
                    expected_host_identity=expected_host_identity,
                    expected_operation_id=expected_operation_id,
                    expected_snapshot=expected_snapshot,
                    remove=False,
                )
            marker_path.unlink()
            try:
                if expected_reason == "host-reactivation":
                    cls._consume_host_reactivation_handoff_unlocked(
                        root,
                        expected_hub_id=expected_hub_id,
                        expected_host_identity=expected_host_identity,
                        expected_operation_id=expected_operation_id,
                        expected_snapshot=expected_snapshot,
                    )
                cls._fsync_directory(root)
            except BaseException:
                try:
                    marker_path.lstat()
                except FileNotFoundError:
                    return True
                raise
            return True

    def _maintenance_snapshot_unlocked(
        self,
        reason: str,
        *,
        keep: int = 3,
        source_read_only: bool = False,
        allow_legacy_schema: bool = False,
        derive_hub_id: bool = False,
        verify_host_reactivation_before_publish: bool = False,
        verify_before_publish: bool = False,
    ) -> Path:
        """Checkpoint and durably snapshot the bound Hub before replacement.

        SQLite's online backup captures the complete logical database after a
        successful WAL checkpoint. The signing key, exact attachment tree, and
        a manifest containing only hashes and stable identities are written
        into the same private generation; the manifest is written last and the
        directory rename is the commit point. Existing verified generations
        are pruned only after the new generation is complete.
        """

        if self.managed_host_identity is None:
            raise RuntimeError("maintenance snapshots require a managed Hub binding")
        clean_reason = _bounded_text(reason, "reason", 1, 80)
        retained = max(1, min(int(keep), 10))
        backups = self.data_dir / "maintenance-backups"
        ensure_private_directory(backups)
        generation = f"snapshot_{time.time_ns():020d}_{secrets.token_hex(8)}"
        temporary = backups / f".{generation}.tmp"
        final = backups / generation
        source: sqlite3.Connection | None = None
        destination: sqlite3.Connection | None = None
        attachment_lease = self.acquire_attachment_control_lease(self.data_dir)
        try:
            self._cleanup_abandoned_snapshot_staging_unlocked(backups)
            ensure_private_directory(temporary)
            source = self.connect()
            snapshot_time = _now()
            # A delegated bootstrap proof is scoped to the live AgentsServer
            # instance. Maintenance may replace that instance, so revoke the
            # remote authority before the durable snapshot is taken. The
            # immutable delegation row remains as audit/idempotency evidence.
            if not source_read_only:
                with _write_transaction(source):
                    source.execute(
                        """
                        UPDATE bootstrap_claims SET revoked_at = ?
                        WHERE consumed_at IS NULL AND revoked_at IS NULL
                          AND EXISTS (
                              SELECT 1 FROM bootstrap_delegations AS d
                              WHERE d.bootstrap_claim_id = bootstrap_claims.id
                          )
                        """,
                        (snapshot_time,),
                    )
                checkpoint = source.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if checkpoint is None or int(checkpoint[0]) != 0:
                    raise RuntimeError("Team Hub WAL checkpoint could not drain")

            database_copy = temporary / "team-hub.sqlite3"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(database_copy, flags, 0o600)
            os.close(descriptor)
            destination = sqlite3.connect(str(database_copy), isolation_level=None)
            destination.row_factory = sqlite3.Row
            source.backup(destination)
            integrity = str(destination.execute("PRAGMA integrity_check").fetchone()[0])
            if integrity != "ok":
                raise RuntimeError("Team Hub maintenance backup failed integrity verification")
            version = int(destination.execute("PRAGMA user_version").fetchone()[0])
            metadata = destination.execute(
                "SELECT hub_id FROM hub_metadata WHERE singleton = 1"
            ).fetchone()
            binding = destination.execute(
                """
                SELECT hub_id, server_identity
                FROM managed_host_bindings WHERE singleton = 1
                """
            ).fetchone()
            if (
                (
                    version != LATEST_SCHEMA_VERSION
                    if not allow_legacy_schema
                    else not 4 <= version <= LATEST_SCHEMA_VERSION
                )
                or metadata is None
                or binding is None
                or str(binding[0]) != str(metadata[0])
                or str(binding[1]) != self.managed_host_identity
            ):
                raise RuntimeError("Team Hub maintenance backup identity verification failed")
            if derive_hub_id:
                self.hub_id = str(metadata[0])
            elif str(metadata[0]) != self.hub_id:
                raise RuntimeError("Team Hub maintenance backup identity verification failed")
            attachment_files = self._team_attachment_snapshot_files(destination)
            proof_rows: list[tuple[str, str, bytes]] = []
            if version >= 5:
                bootstrap_claims = destination.execute(
                    """
                    SELECT c.id, c.token_hash FROM bootstrap_claims AS c
                    LEFT JOIN bootstrap_delegations AS d
                      ON d.bootstrap_claim_id = c.id
                    WHERE c.consumed_at IS NULL AND c.revoked_at IS NULL
                      AND c.expires_at > ? AND d.bootstrap_claim_id IS NULL
                    ORDER BY c.created_at, c.id
                    """,
                    (snapshot_time,),
                ).fetchall()
            else:
                # Schema 4 predates delegated bootstrap authority, so every
                # still-live claim is necessarily backed by the local proof.
                bootstrap_claims = destination.execute(
                    """
                    SELECT id, token_hash FROM bootstrap_claims
                    WHERE consumed_at IS NULL AND revoked_at IS NULL
                      AND expires_at > ?
                    ORDER BY created_at, id
                    """,
                    (snapshot_time,),
                ).fetchall()
            if len(bootstrap_claims) > 1:
                raise RuntimeError("Team Hub has multiple active bootstrap proofs")
            if bootstrap_claims:
                proof_rows.append(
                    (
                        "bootstrap-owner.proof",
                        str(bootstrap_claims[0]["id"]),
                        bytes(bootstrap_claims[0]["token_hash"]),
                    )
                )
            for claim in destination.execute(
                """
                SELECT id, token_hash FROM owner_recovery_claims
                WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?
                ORDER BY created_at, id
                """,
                (snapshot_time,),
            ):
                claim_id = str(claim["id"])
                if re.fullmatch(r"[A-Za-z0-9_]{8,240}", claim_id) is None:
                    raise RuntimeError("Team Hub recovery proof identity is invalid")
                proof_rows.append(
                    (f"{claim_id}.proof", claim_id, bytes(claim["token_hash"]))
                )
            destination.close()
            destination = None
            source.close()
            source = None
            os.chmod(database_copy, 0o600)
            with database_copy.open("rb") as stream:
                os.fsync(stream.fileno())

            key = read_secret_file(self.signing_key_path)
            key_copy = temporary / "access-token-signing.key"
            create_secret_file(key_copy, key)
            proof_manifest: list[dict[str, str]] = []
            if proof_rows:
                proof_directory = temporary / "proofs"
                ensure_private_directory(proof_directory)
                for filename, claim_id, expected_digest in proof_rows:
                    source_path = self.data_dir / filename
                    proof_bytes = read_secret_file(source_path)
                    try:
                        proof_value = proof_bytes.decode("ascii").strip()
                        actual_digest = token_hash(proof_value)
                    except (UnicodeError, TokenError) as exc:
                        raise RuntimeError(
                            "Team Hub active local proof could not be verified"
                        ) from exc
                    if not hmac.compare_digest(expected_digest, actual_digest):
                        raise RuntimeError(
                            "Team Hub active local proof does not match its claim"
                        )
                    create_secret_file(proof_directory / filename, proof_bytes)
                    proof_manifest.append(
                        {
                            "claim_id": claim_id,
                            "filename": filename,
                            "sha256": hashlib.sha256(proof_bytes).hexdigest(),
                        }
                    )
            attachment_summary = self._copy_attachment_generation(
                self.data_dir / "attachments",
                temporary / "attachments",
                attachment_files,
            )
            database_digest = self._sha256_private_regular_file(database_copy)
            key_digest = hashlib.sha256(key).hexdigest()
            manifest = {
                "format": 2,
                "reason": clean_reason,
                "hub_id": self.hub_id,
                "host_server_identity": self.managed_host_identity,
                "schema_version": version,
                "database_sha256": database_digest,
                "signing_key_sha256": key_digest,
                "proofs": proof_manifest,
                "attachments": attachment_summary,
                "created_at": _iso8601(_now()),
            }
            create_secret_file(
                temporary / "manifest.json",
                canonical_json(manifest) + b"\n",
            )
            directory_descriptor = os.open(
                temporary,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
            if verify_host_reactivation_before_publish or verify_before_publish:
                if (
                    clean_reason
                    not in (
                        {"host-reactivation"}
                        if verify_host_reactivation_before_publish
                        else {"server-update", "host-reactivation"}
                    )
                    or not source_read_only
                    or not allow_legacy_schema
                ):
                    raise RuntimeError(
                        "pre-publication reactivation verification is invalid"
                    )
                self._restore_maintenance_snapshot_unlocked(
                    self.data_dir,
                    temporary,
                    expected_host_identity=self.managed_host_identity,
                    expected_hub_id=self.hub_id,
                    expected_operation_id=None,
                    expected_reason=clean_reason,
                    verify_only=True,
                    require_fence=False,
                    allow_staging_snapshot=True,
                )
            os.replace(temporary, final)
            backups_descriptor = os.open(
                backups,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(backups_descriptor)
            finally:
                os.close(backups_descriptor)

            generations = sorted(
                (
                    entry
                    for entry in backups.iterdir()
                    if entry.name.startswith("snapshot_")
                    and not entry.is_symlink()
                    and entry.is_dir()
                ),
                key=lambda entry: entry.name,
                reverse=True,
            )
            fence = self.maintenance_fence()
            protected_generation = (
                str(fence["snapshot"])
                if fence is not None
                else None
            )
            protected_reactivation_generation: str | None = None
            for generation_path in generations:
                try:
                    generation_manifest = json.loads(
                        self._read_private_regular_file(
                            generation_path / "manifest.json",
                            maximum_bytes=1024 * 1024,
                        )
                    )
                except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError):
                    continue
                if (
                    isinstance(generation_manifest, dict)
                    and generation_manifest.get("reason") == "host-reactivation"
                    and generation_manifest.get("hub_id") == self.hub_id
                    and generation_manifest.get("host_server_identity")
                    == self.managed_host_identity
                ):
                    # Keep the newest exact pre-reactivation generation even
                    # after the candidate host emits enough restart/shutdown
                    # snapshots to exceed the ordinary retention window.
                    protected_reactivation_generation = generation_path.name
                    break
            for expired in generations[retained:]:
                if expired.name in {
                    protected_generation,
                    protected_reactivation_generation,
                }:
                    continue
                shutil.rmtree(expired)
            return final
        except BaseException:
            if destination is not None:
                destination.close()
            if source is not None:
                source.close()
            if temporary.exists() and not temporary.is_symlink():
                shutil.rmtree(temporary, ignore_errors=True)
            raise
        finally:
            self.release_attachment_control_lease(attachment_lease)

    @classmethod
    def verify_maintenance_snapshot(
        cls,
        data_dir: Path,
        snapshot_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str,
        expected_reason: str = "server-update",
    ) -> None:
        """Fully verify an exact fenced rollback generation without restoring it."""

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        cls._validate_private_directory_without_mutation(root)
        with cls.maintenance_control_lock(root):
            attachment_lease = cls.acquire_attachment_control_lease(root)
            try:
                cls._restore_maintenance_snapshot_unlocked(
                    root,
                    snapshot_dir,
                    expected_host_identity=expected_host_identity,
                    expected_hub_id=expected_hub_id,
                    expected_operation_id=expected_operation_id,
                    expected_reason=expected_reason,
                    verify_only=True,
                )
                if expected_reason == "host-reactivation":
                    cls._consume_host_reactivation_handoff_unlocked(
                        root,
                        expected_hub_id=expected_hub_id,
                        expected_host_identity=expected_host_identity,
                        expected_operation_id=expected_operation_id,
                        expected_snapshot=snapshot_dir,
                        remove=False,
                    )
            finally:
                cls.release_attachment_control_lease(attachment_lease)

    @classmethod
    def rebase_maintenance_snapshot(
        cls,
        data_dir: Path,
        snapshot_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str,
    ) -> Path:
        """Refresh a stable update snapshot from a stopped legacy source.

        The durable update row and fence keep their original snapshot path.
        A small journal atomically swaps a fully verified cold generation
        underneath that stable name, so crash recovery never needs a
        cross-directory status/fence transaction.
        """

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        target = Path(
            os.path.abspath(os.path.expanduser(os.fspath(snapshot_dir)))
        )
        identity = _identity(expected_host_identity)
        hub_id = _identity(expected_hub_id)
        operation_id = _maintenance_operation_id(expected_operation_id)
        if target.parent != root / "maintenance-backups":
            raise RuntimeError("Team Hub maintenance snapshot path is invalid")
        lease = cls.acquire_managed_runtime_lease(root)
        try:
            with cls.maintenance_control_lock(root):
                marker = cls._maintenance_fence_control_unlocked(
                    root,
                    expected_hub_id=hub_id,
                    expected_host_identity=identity,
                    expected_reason="server-update",
                    expected_operation_id=operation_id,
                    expected_snapshot=target,
                )
                if marker is None:
                    raise RuntimeError("Team Hub maintenance fence is missing")
                attachment_lease = cls.acquire_attachment_control_lease(root)
                try:
                    cls._restore_maintenance_snapshot_unlocked(
                        root,
                        target,
                        expected_host_identity=identity,
                        expected_hub_id=hub_id,
                        expected_operation_id=operation_id,
                        expected_reason="server-update",
                        verify_only=True,
                    )
                finally:
                    cls.release_attachment_control_lease(attachment_lease)
                probe = object.__new__(cls)
                probe.data_dir = root
                probe.database_path = root / "team-hub.sqlite3"
                probe.signing_key_path = root / "access-token-signing.key"
                probe.bootstrap_proof_path = root / "bootstrap-owner.proof"
                probe.maintenance_fence_path = root / "maintenance-fence.json"
                probe.managed_host_identity = identity
                probe.hub_id = hub_id

                def connect_read_only() -> sqlite3.Connection:
                    connection = sqlite3.connect(
                        f"{probe.database_path.as_uri()}?mode=ro",
                        uri=True,
                        isolation_level=None,
                    )
                    connection.row_factory = sqlite3.Row
                    return connection

                probe.connect = connect_read_only
                replacement = probe._maintenance_snapshot_unlocked(
                    "server-update",
                    source_read_only=True,
                    allow_legacy_schema=True,
                    derive_hub_id=True,
                    verify_before_publish=True,
                )
                if probe.hub_id != hub_id:
                    raise RuntimeError("Team Hub maintenance source identity changed")
                backups = root / "maintenance-backups"
                retired = backups / (
                    f".snapshot-rebase-{secrets.token_hex(12)}.old"
                )
                journal = {
                    "format": 1,
                    "hub_id": hub_id,
                    "host_server_identity": identity,
                    "operation_id": operation_id,
                    "target": target.name,
                    "target_manifest_sha256": cls._sha256_private_regular_file(
                        target / "manifest.json"
                    ),
                    "replacement": replacement.name,
                    "replacement_manifest_sha256": cls._sha256_private_regular_file(
                        replacement / "manifest.json"
                    ),
                    "retired": retired.name,
                }
                create_secret_file(
                    root / SNAPSHOT_REBASE_JOURNAL_NAME,
                    canonical_json(journal) + b"\n",
                )
                try:
                    os.replace(target, retired)
                    cls._fsync_directory(backups)
                    os.replace(replacement, target)
                    cls._fsync_directory(backups)
                    cls._recover_snapshot_rebase_unlocked(root)
                except BaseException:
                    cls._recover_snapshot_rebase_unlocked(root)
                    raise
                return target
        finally:
            cls.release_managed_runtime_lease(lease)

    @classmethod
    def verify_host_reactivation_snapshot(
        cls,
        data_dir: Path,
        snapshot_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str,
    ) -> None:
        """Verify the exact snapshot and its durable source-generation fence."""

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        cls._validate_private_directory_without_mutation(root)
        with cls.maintenance_control_lock(root):
            attachment_lease = cls.acquire_attachment_control_lease(root)
            try:
                cls._restore_maintenance_snapshot_unlocked(
                    root,
                    snapshot_dir,
                    expected_host_identity=expected_host_identity,
                    expected_hub_id=expected_hub_id,
                    expected_operation_id=expected_operation_id,
                    expected_reason="host-reactivation",
                    verify_only=True,
                )
                cls._consume_host_reactivation_handoff_unlocked(
                    root,
                    expected_hub_id=expected_hub_id,
                    expected_host_identity=expected_host_identity,
                    expected_operation_id=expected_operation_id,
                    expected_snapshot=snapshot_dir,
                    remove=False,
                )
            finally:
                cls.release_attachment_control_lease(attachment_lease)

    @classmethod
    def restore_maintenance_snapshot(
        cls,
        data_dir: Path,
        snapshot_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str,
        expected_reason: str = "server-update",
    ) -> None:
        lease = cls.acquire_managed_runtime_lease(data_dir)
        try:
            with cls.maintenance_control_lock(data_dir):
                attachment_lease = cls.acquire_attachment_control_lease(data_dir)
                try:
                    cls._restore_maintenance_snapshot_unlocked(
                        data_dir,
                        snapshot_dir,
                        expected_host_identity=expected_host_identity,
                        expected_hub_id=expected_hub_id,
                        expected_operation_id=expected_operation_id,
                        expected_reason=expected_reason,
                        verify_only=False,
                    )
                finally:
                    cls.release_attachment_control_lease(attachment_lease)
        finally:
            cls.release_managed_runtime_lease(lease)

    @classmethod
    def restore_host_reactivation_snapshot(
        cls,
        data_dir: Path,
        snapshot_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str,
    ) -> None:
        """Consume the fenced reactivation generation in an offline restore."""

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        snapshot = Path(
            os.path.abspath(os.path.expanduser(os.fspath(snapshot_dir)))
        )
        identity = _identity(expected_host_identity)
        hub_id = str(expected_hub_id).strip()
        operation_id = _maintenance_operation_id(expected_operation_id)
        lease = cls.acquire_managed_runtime_lease(root)
        try:
            with cls.maintenance_control_lock(root):
                cls._consume_host_reactivation_handoff_unlocked(
                    root,
                    expected_hub_id=hub_id,
                    expected_host_identity=identity,
                    expected_operation_id=operation_id,
                    expected_snapshot=snapshot,
                    remove=False,
                )
                attachment_lease = cls.acquire_attachment_control_lease(root)
                try:
                    # Revalidate the snapshot against the exact fence that has
                    # excluded source mutations since its commit point.
                    cls._restore_maintenance_snapshot_unlocked(
                        root,
                        snapshot,
                        expected_host_identity=identity,
                        expected_hub_id=hub_id,
                        expected_operation_id=operation_id,
                        expected_reason="host-reactivation",
                        verify_only=True,
                    )
                    # The transactional replacement includes the fence among
                    # its old targets. A committed restore therefore consumes
                    # it atomically; any pre-commit failure leaves it fail-
                    # closed for an exact retry.
                    cls._restore_maintenance_snapshot_unlocked(
                        root,
                        snapshot,
                        expected_host_identity=identity,
                        expected_hub_id=hub_id,
                        expected_operation_id=operation_id,
                        expected_reason="host-reactivation",
                        verify_only=False,
                    )
                    cls._consume_host_reactivation_handoff_unlocked(
                        root,
                        expected_hub_id=hub_id,
                        expected_host_identity=identity,
                        expected_operation_id=operation_id,
                        expected_snapshot=snapshot,
                    )
                    cls._fsync_directory(root)
                finally:
                    cls.release_attachment_control_lease(attachment_lease)
        finally:
            cls.release_managed_runtime_lease(lease)

    @classmethod
    def _restore_maintenance_snapshot_unlocked(
        cls,
        data_dir: Path,
        snapshot_dir: Path,
        *,
        expected_host_identity: str,
        expected_hub_id: str,
        expected_operation_id: str | None,
        expected_reason: str,
        verify_only: bool,
        require_fence: bool = True,
        allow_staging_snapshot: bool = False,
        allow_rebase_snapshot: bool = False,
    ) -> None:
        """Verify and restore one maintenance generation while Hub is offline.

        The managed listener must be stopped before this control-plane method
        runs. Every replacement is staged on the Hub filesystem, and an
        ordinary I/O failure rolls all already-replaced files back before the
        method returns. The old service is only restarted after a successful
        return, so it never observes a partial logical restore.
        """

        root = Path(os.path.abspath(os.path.expanduser(os.fspath(data_dir))))
        snapshot = Path(
            os.path.abspath(os.path.expanduser(os.fspath(snapshot_dir)))
        )
        host_identity = _identity(expected_host_identity)
        hub_id = str(expected_hub_id).strip()
        if (
            not 8 <= len(hub_id) <= 240
            or re.fullmatch(r"[A-Za-z0-9_.:-]+", hub_id) is None
        ):
            raise ValueError("expected Hub identity is invalid")
        if verify_only:
            cls._validate_private_directory_without_mutation(root)
        else:
            ensure_private_directory(root)
        backups = root / "maintenance-backups"
        if allow_staging_snapshot:
            valid_snapshot_name = (
                SNAPSHOT_STAGING_NAME_RE.fullmatch(snapshot.name) is not None
            )
        elif allow_rebase_snapshot:
            valid_snapshot_name = (
                snapshot.name.startswith("snapshot_")
                or SNAPSHOT_REBASE_RETIRED_RE.fullmatch(snapshot.name)
                is not None
            )
        else:
            valid_snapshot_name = snapshot.name.startswith("snapshot_")
        if snapshot.parent != backups or not valid_snapshot_name:
            raise PermissionError("snapshot must be a Team Hub maintenance generation")
        if allow_staging_snapshot and (
            not verify_only
            or require_fence
            or expected_reason not in {"host-reactivation", "server-update"}
            or expected_operation_id is not None
        ):
            raise RuntimeError("staged snapshot verification is not allowed")
        if allow_rebase_snapshot and (
            not verify_only
            or require_fence
            or allow_staging_snapshot
            or expected_reason != "server-update"
            or expected_operation_id is not None
        ):
            raise RuntimeError("rebase snapshot verification is not allowed")
        if require_fence:
            if expected_operation_id is None:
                raise RuntimeError("Team Hub maintenance operation is missing")
            if cls._maintenance_fence_control_unlocked(
                root,
                expected_hub_id=hub_id,
                expected_host_identity=host_identity,
                expected_reason=expected_reason,
                expected_operation_id=expected_operation_id,
                expected_snapshot=snapshot,
            ) is None:
                raise RuntimeError("Team Hub maintenance fence is missing")
        else:
            if (
                expected_reason not in {"host-reactivation", "server-update"}
                or expected_operation_id is not None
            ):
                raise RuntimeError("unfenced Team Hub snapshot verification is not allowed")
            marker_path = root / "maintenance-fence.json"
            try:
                marker_path.lstat()
            except FileNotFoundError:
                pass
            else:
                if (
                    (allow_staging_snapshot or allow_rebase_snapshot)
                    and expected_reason == "server-update"
                ):
                    marker_path = None
                else:
                    raise RuntimeError("preserved Team Hub state is already in maintenance")
            if marker_path is None:
                pass
            elif marker_path.exists():
                raise RuntimeError("preserved Team Hub state is already in maintenance")
        cls._validate_private_directory_without_mutation(backups)
        cls._validate_private_directory_without_mutation(snapshot)

        manifest_bytes = cls._read_private_regular_file(
            snapshot / "manifest.json", maximum_bytes=1024 * 1024
        )
        try:
            manifest = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Team Hub snapshot manifest is invalid") from exc
        base_manifest_keys = {
            "format",
            "reason",
            "hub_id",
            "host_server_identity",
            "schema_version",
            "database_sha256",
            "signing_key_sha256",
            "proofs",
            "created_at",
        }
        if not isinstance(manifest, dict):
            raise RuntimeError("Team Hub snapshot manifest is invalid")
        snapshot_format = manifest.get("format")
        if snapshot_format == 1:
            required_manifest_keys = base_manifest_keys
        elif snapshot_format == 2:
            required_manifest_keys = base_manifest_keys | {"attachments"}
        else:
            raise RuntimeError("Team Hub snapshot manifest is invalid")
        if set(manifest) != required_manifest_keys:
            raise RuntimeError("Team Hub snapshot manifest is invalid")
        schema_version = manifest.get("schema_version")
        if (
            manifest.get("hub_id") != hub_id
            or manifest.get("host_server_identity") != host_identity
            or manifest.get("reason") != expected_reason
            or isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or not 4 <= schema_version <= LATEST_SCHEMA_VERSION
            or not isinstance(manifest.get("reason"), str)
            or not 1 <= len(manifest["reason"]) <= 80
            or not isinstance(manifest.get("created_at"), str)
        ):
            raise RuntimeError("Team Hub snapshot identity is invalid")
        try:
            snapshot_time = int(
                datetime.fromisoformat(
                    manifest["created_at"].replace("Z", "+00:00")
                ).timestamp()
            )
        except (ValueError, OverflowError) as exc:
            raise RuntimeError("Team Hub snapshot timestamp is invalid") from exc
        if snapshot_time < 0:
            raise RuntimeError("Team Hub snapshot timestamp is invalid")
        for digest_name in ("database_sha256", "signing_key_sha256"):
            digest = manifest.get(digest_name)
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise RuntimeError("Team Hub snapshot manifest digest is invalid")

        attachment_manifest: dict[str, Any] | None = None
        if snapshot_format == 2:
            raw_attachments = manifest.get("attachments")
            if (
                not isinstance(raw_attachments, dict)
                or set(raw_attachments) != {"file_count", "byte_size", "sha256"}
                or isinstance(raw_attachments.get("file_count"), bool)
                or not isinstance(raw_attachments.get("file_count"), int)
                or raw_attachments["file_count"] < 0
                or isinstance(raw_attachments.get("byte_size"), bool)
                or not isinstance(raw_attachments.get("byte_size"), int)
                or raw_attachments["byte_size"] < 0
                or not isinstance(raw_attachments.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", raw_attachments["sha256"])
                is None
            ):
                raise RuntimeError("Team Hub snapshot attachment manifest is invalid")
            attachment_manifest = raw_attachments

        raw_proofs = manifest.get("proofs")
        if not isinstance(raw_proofs, list) or len(raw_proofs) > 4096:
            raise RuntimeError("Team Hub snapshot proof manifest is invalid")
        proof_entries: dict[str, tuple[str, str]] = {}
        for raw in raw_proofs:
            if not isinstance(raw, dict) or set(raw) != {"claim_id", "filename", "sha256"}:
                raise RuntimeError("Team Hub snapshot proof manifest is invalid")
            claim_id = raw.get("claim_id")
            filename = raw.get("filename")
            digest = raw.get("sha256")
            if (
                not isinstance(claim_id, str)
                or re.fullmatch(r"[A-Za-z0-9_]{8,240}", claim_id) is None
                or not isinstance(filename, str)
                or filename
                not in {"bootstrap-owner.proof", f"{claim_id}.proof"}
                or filename in proof_entries
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise RuntimeError("Team Hub snapshot proof manifest is invalid")
            proof_entries[filename] = (claim_id, digest)

        verification_directory: tempfile.TemporaryDirectory[str] | None = None
        if verify_only:
            verification_directory = tempfile.TemporaryDirectory(
                prefix="team-hub-snapshot-verify-"
            )
            staging = Path(verification_directory.name)
            cls._validate_private_directory_without_mutation(staging)
        else:
            staging = root / f".restore-{os.getpid()}-{secrets.token_hex(8)}"
            ensure_private_directory(staging)
        connection: sqlite3.Connection | None = None
        try:
            staged_database = staging / "team-hub.sqlite3"
            staged_key = staging / "access-token-signing.key"
            cls._copy_private_regular_file(
                snapshot / "team-hub.sqlite3", staged_database
            )
            cls._copy_private_regular_file(
                snapshot / "access-token-signing.key", staged_key
            )
            if not hmac.compare_digest(
                cls._sha256_private_regular_file(staged_database),
                manifest["database_sha256"],
            ) or not hmac.compare_digest(
                cls._sha256_private_regular_file(staged_key),
                manifest["signing_key_sha256"],
            ):
                raise RuntimeError("Team Hub snapshot file digest is invalid")
            key_bytes = cls._read_private_regular_file(
                staged_key, minimum_bytes=32, maximum_bytes=4096
            )
            if hashlib.sha256(key_bytes).hexdigest() != manifest["signing_key_sha256"]:
                raise RuntimeError("Team Hub snapshot signing key is invalid")

            staged_proofs = staging / "proofs"
            if proof_entries:
                cls._validate_private_directory_without_mutation(snapshot / "proofs")
                ensure_private_directory(staged_proofs)
                for filename, (_claim_id, digest) in proof_entries.items():
                    destination = staged_proofs / filename
                    cls._copy_private_regular_file(
                        snapshot / "proofs" / filename, destination
                    )
                    if not hmac.compare_digest(
                        cls._sha256_private_regular_file(destination), digest
                    ):
                        raise RuntimeError("Team Hub snapshot proof digest is invalid")

            connection = sqlite3.connect(
                f"file:{staged_database}?mode=ro&immutable=1",
                uri=True,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            if str(connection.execute("PRAGMA integrity_check").fetchone()[0]) != "ok":
                raise RuntimeError("Team Hub snapshot database integrity check failed")
            if int(connection.execute("PRAGMA user_version").fetchone()[0]) != schema_version:
                raise RuntimeError("Team Hub snapshot schema version is invalid")
            migrations = connection.execute(
                "SELECT version, name, sha256 FROM schema_migrations ORDER BY version"
            ).fetchall()
            expected_migrations = MIGRATIONS[:schema_version]
            if len(migrations) != len(expected_migrations) or any(
                (
                    int(row["version"]),
                    str(row["name"]),
                    str(row["sha256"]),
                )
                != (item.version, item.name, item.sha256)
                for row, item in zip(migrations, expected_migrations)
            ):
                raise RuntimeError("Team Hub snapshot migration ledger is invalid")
            metadata = connection.execute(
                "SELECT hub_id FROM hub_metadata WHERE singleton = 1"
            ).fetchone()
            binding = connection.execute(
                "SELECT hub_id, server_identity FROM managed_host_bindings WHERE singleton = 1"
            ).fetchone()
            if (
                metadata is None
                or str(metadata["hub_id"]) != hub_id
                or binding is None
                or str(binding["hub_id"]) != hub_id
                or str(binding["server_identity"]) != host_identity
            ):
                raise RuntimeError("Team Hub snapshot host binding is invalid")

            database_proofs: dict[str, tuple[str, bytes, int]] = {}
            try:
                if schema_version >= 5:
                    # Delegated bootstrap claims were introduced by migration
                    # 0005. They never have a local proof file and must remain
                    # excluded from schema-5 snapshots. Schema 4 predates that
                    # table, so its active claim is necessarily the local proof.
                    bootstrap_proofs = connection.execute(
                        """
                        SELECT c.id, c.token_hash, c.expires_at
                        FROM bootstrap_claims AS c
                        LEFT JOIN bootstrap_delegations AS d
                          ON d.bootstrap_claim_id = c.id
                        WHERE c.consumed_at IS NULL AND c.revoked_at IS NULL
                          AND d.bootstrap_claim_id IS NULL
                        """
                    ).fetchall()
                else:
                    bootstrap_proofs = connection.execute(
                        """
                        SELECT id, token_hash, expires_at
                        FROM bootstrap_claims
                        WHERE consumed_at IS NULL AND revoked_at IS NULL
                        """
                    ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise RuntimeError(
                    "Team Hub snapshot bootstrap proof schema is invalid"
                ) from exc
            for row in bootstrap_proofs:
                database_proofs["bootstrap-owner.proof"] = (
                    str(row["id"]), bytes(row["token_hash"]), int(row["expires_at"])
                )
            for row in connection.execute(
                """
                SELECT id, token_hash, expires_at FROM owner_recovery_claims
                WHERE consumed_at IS NULL AND revoked_at IS NULL
                """
            ):
                claim_id = str(row["id"])
                database_proofs[f"{claim_id}.proof"] = (
                    claim_id, bytes(row["token_hash"]), int(row["expires_at"])
                )
            for filename, (claim_id, _digest) in proof_entries.items():
                database_entry = database_proofs.get(filename)
                if database_entry is None or database_entry[0] != claim_id:
                    raise RuntimeError("Team Hub snapshot proof claim is invalid")
                proof_bytes = cls._read_private_regular_file(
                    staged_proofs / filename, maximum_bytes=4096
                )
                try:
                    proof_value = proof_bytes.decode("ascii").strip()
                    proof_digest = token_hash(proof_value)
                except (UnicodeError, TokenError) as exc:
                    raise RuntimeError("Team Hub snapshot proof is invalid") from exc
                if not hmac.compare_digest(proof_digest, database_entry[1]):
                    raise RuntimeError("Team Hub snapshot proof claim is invalid")
            active_at_snapshot = {
                filename
                for filename, (_claim_id, _digest, expires_at) in database_proofs.items()
                if expires_at > snapshot_time
            }
            if not active_at_snapshot.issubset(proof_entries):
                raise RuntimeError("Team Hub snapshot omits an active local proof")
            attachment_files = cls._team_attachment_snapshot_files(connection)
            if snapshot_format == 2:
                attachment_source = snapshot / "attachments"
                attachment_summary = cls._attachment_generation_summary(
                    attachment_source,
                    attachment_files,
                    exact_tree=True,
                    require_root=True,
                )
                if attachment_summary != attachment_manifest:
                    raise RuntimeError("Team Hub snapshot attachment manifest is invalid")
            else:
                # Format 1 predates external attachment generations. A schema-9
                # snapshot can still be rolled back safely only while its exact
                # content-addressed files remain in the fenced live tree. A
                # partial upload has no digest in the legacy manifest, so it
                # cannot be attributed to that snapshot generation safely.
                if any(item.content_sha256 is None for item in attachment_files):
                    raise RuntimeError(
                        "Legacy Team Hub snapshot omits a resumable attachment generation"
                    )
                # New files are excluded when the staged generation is
                # assembled below.
                attachment_source = root / "attachments"
                attachment_summary = cls._attachment_generation_summary(
                    attachment_source,
                    attachment_files,
                    exact_tree=False,
                    require_root=bool(attachment_files),
                )
            connection.close()
            connection = None

            if verify_only:
                return

            staged_attachments = staging / "attachments"
            staged_attachment_summary = cls._copy_attachment_generation(
                attachment_source,
                staged_attachments,
                attachment_files,
            )
            if staged_attachment_summary != attachment_summary:
                raise RuntimeError("Team Hub snapshot attachment generation changed")

            old_directory = staging / "previous"
            ensure_private_directory(old_directory)
            managed_targets = {
                root / "team-hub.sqlite3",
                root / "access-token-signing.key",
                root / "team-hub.sqlite3-wal",
                root / "team-hub.sqlite3-shm",
                root / "bootstrap-owner.proof",
                root / "maintenance-fence.json",
            }
            for entry in root.glob("*.proof"):
                if re.fullmatch(r"[A-Za-z0-9_]{8,240}\.proof", entry.name):
                    managed_targets.add(entry)
            attachment_target = root / "attachments"
            replacements = [
                (staged_database, root / "team-hub.sqlite3"),
                (staged_key, root / "access-token-signing.key"),
            ]
            replacements.extend(
                (staged_proofs / filename, root / filename)
                for filename in sorted(proof_entries)
            )
            replacements.append((staged_attachments, attachment_target))

            old_targets: dict[str, str] = {}
            for target in sorted(managed_targets, key=lambda item: item.name):
                kind = cls._restore_target_kind(target.name)
                if cls._restore_target_exists(target, kind):
                    old_targets[target.name] = kind
            if cls._restore_target_exists(attachment_target, "directory"):
                old_targets[attachment_target.name] = "directory"
            new_targets = {
                target.name: cls._restore_target_kind(target.name)
                for _source, target in replacements
            }
            for source, target in replacements:
                if not cls._restore_target_exists(source, new_targets[target.name]):
                    raise RuntimeError("Team Hub staged restore generation is incomplete")

            if proof_entries:
                cls._fsync_directory(staged_proofs)
            cls._fsync_directory(old_directory)
            cls._fsync_directory(staging)
            restored_generation = {
                "database_sha256": manifest["database_sha256"],
                "signing_key_sha256": manifest["signing_key_sha256"],
                "proofs": [
                    {"name": filename, "sha256": proof_entries[filename][1]}
                    for filename in sorted(proof_entries)
                ],
                "attachments": attachment_summary,
            }
            receipt = {
                "format": 1,
                "state": "prepared",
                "reason": expected_reason,
                "hub_id": hub_id,
                "host_server_identity": host_identity,
                "operation_id": expected_operation_id,
                "snapshot": snapshot.name,
                "snapshot_manifest_sha256": hashlib.sha256(
                    manifest_bytes
                ).hexdigest(),
                "generation": restored_generation,
            }
            # This receipt is durable before the fence is moved away from the
            # live root. A post-restore installer retry can therefore prove an
            # exact committed generation instead of inferring from absence.
            cls._write_restore_completion_receipt_unlocked(root, receipt)
            journal = {
                "format": 1,
                "state": "prepared",
                "staging": staging.name,
                "old_targets": [
                    {"name": name, "kind": old_targets[name]}
                    for name in sorted(old_targets)
                ],
                "new_targets": [
                    {"name": name, "kind": new_targets[name]}
                    for name in sorted(new_targets)
                ],
                "new_generation": restored_generation,
            }
            cls._write_restore_transaction_journal(root, journal)

            for name in sorted(old_targets):
                os.replace(root / name, old_directory / name)
            cls._fsync_directory(old_directory)
            cls._fsync_directory(root)
            for source, target in replacements:
                os.replace(source, target)
            cls._fsync_directory(staging)
            cls._fsync_directory(root)
            if (
                cls._sha256_private_regular_file(root / "team-hub.sqlite3")
                != manifest["database_sha256"]
                or cls._sha256_private_regular_file(root / "access-token-signing.key")
                != manifest["signing_key_sha256"]
                or cls._attachment_generation_summary(
                    attachment_target,
                    attachment_files,
                    exact_tree=True,
                    require_root=True,
                )
                != attachment_summary
            ):
                raise RuntimeError("Team Hub restored state verification failed")
            committed_journal = dict(journal)
            committed_journal["state"] = "committed"
            committed_receipt = dict(receipt)
            committed_receipt["state"] = "committed"
            cls._write_restore_completion_receipt_unlocked(
                root, committed_receipt
            )
            cls._write_restore_transaction_journal(root, committed_journal)
            cls._recover_interrupted_restore_unlocked(root)
        except BaseException:
            if connection is not None:
                connection.close()
            recovered_committed = False
            if not verify_only and cls._restore_transaction_pending(root):
                try:
                    pending_journal, _staging, _old, _new = (
                        cls._read_restore_transaction_journal(root)
                    )
                    recovered_committed = pending_journal["state"] == "committed"
                    cls._recover_interrupted_restore_unlocked(root)
                except BaseException as recovery_error:
                    raise RuntimeError(
                        "Team Hub interrupted restore recovery failed"
                    ) from recovery_error
            if recovered_committed:
                return
            raise
        finally:
            if verification_directory is not None:
                verification_directory.cleanup()
            elif not cls._restore_transaction_pending(root):
                try:
                    staging_info = staging.lstat()
                except FileNotFoundError:
                    pass
                else:
                    if stat.S_ISDIR(staging_info.st_mode):
                        shutil.rmtree(staging, ignore_errors=True)

    def renew_bootstrap_proof(self) -> Path:
        timestamp = _now()
        connection = self.connect()
        try:
            with _write_transaction(connection):
                if self._is_bootstrapped(connection) or not self._globally_empty(connection):
                    raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 409)
                self._ensure_bootstrap_claim(
                    connection,
                    timestamp,
                    force_local=True,
                )
            return self.bootstrap_proof_path
        finally:
            connection.close()

    @staticmethod
    def _canonical_request_id(value: str) -> str:
        try:
            parsed = uuid.UUID(str(value))
            canonical = str(parsed)
        except (ValueError, AttributeError) as exc:
            raise ValueError("request_id is invalid") from exc
        if parsed.version != 4 or canonical != str(value):
            raise ValueError("request_id must be a canonical UUIDv4")
        return canonical

    def _tailnet_bootstrap_proof(self, fingerprint: bytes) -> str:
        key = read_secret_file(self.signing_key_path)
        digest = hmac.new(
            key,
            b"agentsdock-team-hub-tailnet-bootstrap-v1\0" + fingerprint,
            hashlib.sha256,
        ).digest()
        encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return f"bootstrap_remote.{encoded}"

    def issue_tailnet_bootstrap_proof(
        self,
        *,
        request_id: str,
        server_identity: str,
        server_instance_id: str,
        hub_url: str,
        tailnet_login: str,
        recipient_email: str,
        display_name: str,
        device_label: str,
        transport: str = "tailscale_serve",
    ) -> dict[str, Any]:
        """Issue an idempotent, hash-only first-owner proof for one remote route."""

        timestamp = _now()
        clean_request_id = self._canonical_request_id(request_id)
        clean_server_identity = _identity(server_identity)
        clean_server_instance_id = _identity(server_instance_id)
        clean_hub_url = _bounded_text(hub_url, "hub_url", 16, 2048)
        clean_login = _email(tailnet_login)
        clean_recipient = _email(recipient_email)
        clean_display_name = _bounded_text(display_name, "display_name", 1, 160)
        clean_device_label = _bounded_text(device_label, "device_label", 1, 160)
        if transport not in {"tailscale_serve", "direct_ip"}:
            raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 403)
        try:
            hub_scheme = urlsplit(clean_hub_url).scheme
        except ValueError as exc:
            raise HubError(
                "bootstrap_unavailable", "Bootstrap is unavailable", 403
            ) from exc
        if (
            transport == "tailscale_serve" and hub_scheme != "https"
        ) or (
            transport == "direct_ip" and hub_scheme != "http"
        ):
            raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 403)
        if clean_login != clean_recipient:
            raise HubError(
                "bootstrap_identity_mismatch",
                (
                    "Bootstrap recipient does not match the verified Tailnet identity"
                    if transport == "tailscale_serve"
                    else "Bootstrap recipient does not match the confirmed direct-IP owner"
                ),
                403,
            )
        if (
            self.managed_host_identity is None
            or clean_server_identity != self.managed_host_identity
            or self.managed_server_instance_id is None
            or clean_server_instance_id != self.managed_server_instance_id
        ):
            raise HubError(
                "bootstrap_target_changed",
                "The designated Team Hub host changed before confirmation",
                409,
            )
        fingerprint = canonical_fingerprint(
            {
                "request_id": clean_request_id,
                "server_identity": clean_server_identity,
                "server_instance_id": clean_server_instance_id,
                "hub_id": self.hub_id,
                "hub_url": clean_hub_url,
                "transport": transport,
                "tailnet_login": clean_login,
                "recipient_email": clean_recipient,
                "display_name": clean_display_name,
                "device_label": clean_device_label,
            }
        )
        proof = self._tailnet_bootstrap_proof(fingerprint)
        digest = token_hash(proof)
        expires_at = timestamp + TAILNET_BOOTSTRAP_PROOF_TTL_SECONDS
        connection = self.connect()
        try:
            with _write_transaction(connection):
                if self._is_bootstrapped(connection) or not self._globally_empty(connection):
                    raise HubError(
                        "bootstrap_unavailable", "Bootstrap is unavailable", 409
                    )
                prior = connection.execute(
                    """
                    SELECT d.request_fingerprint, d.expires_at,
                           c.token_hash, c.consumed_at, c.revoked_at
                    FROM bootstrap_delegations AS d
                    JOIN bootstrap_claims AS c ON c.id = d.bootstrap_claim_id
                    WHERE d.request_id = ?
                    """,
                    (clean_request_id,),
                ).fetchone()
                if prior is not None:
                    if not hmac.compare_digest(
                        bytes(prior["request_fingerprint"]), fingerprint
                    ):
                        raise HubError(
                            "idempotency_conflict",
                            "Bootstrap request_id was already used for another request",
                            409,
                        )
                    if (
                        prior["consumed_at"] is not None
                        or prior["revoked_at"] is not None
                        or int(prior["expires_at"]) <= timestamp
                        or not hmac.compare_digest(bytes(prior["token_hash"]), digest)
                    ):
                        raise HubError(
                            "bootstrap_unavailable", "Bootstrap is unavailable", 409
                        )
                    expires_at = int(prior["expires_at"])
                else:
                    delegation_count = int(
                        connection.execute(
                            "SELECT count(*) FROM bootstrap_delegations"
                        ).fetchone()[0]
                    )
                    if delegation_count >= MAX_BOOTSTRAP_DELEGATION_LEDGER_ROWS:
                        raise HubError(
                            "bootstrap_ledger_exhausted",
                            (
                                "Remote bootstrap proof issuance is exhausted; "
                                "complete first-owner setup from the host"
                            ),
                            409,
                        )
                    competing = connection.execute(
                        """
                        SELECT c.id, d.request_id, d.server_identity,
                               d.server_instance_id, d.hub_id, d.hub_url,
                               d.tailnet_login_normalized,
                               d.recipient_email_normalized
                        FROM bootstrap_delegations AS d
                        JOIN bootstrap_claims AS c
                          ON c.id = d.bootstrap_claim_id
                        WHERE c.consumed_at IS NULL AND c.revoked_at IS NULL
                          AND c.expires_at > ?
                        LIMIT 1
                        """,
                        (timestamp,),
                    ).fetchone()
                    if competing is not None:
                        same_authority = (
                            str(competing["server_identity"])
                            == clean_server_identity
                            and str(competing["server_instance_id"])
                            == clean_server_instance_id
                            and str(competing["hub_id"]) == self.hub_id
                            and str(competing["hub_url"]) == clean_hub_url
                            and str(competing["tailnet_login_normalized"])
                            == clean_login
                            and str(competing["recipient_email_normalized"])
                            == clean_recipient
                        )
                        if not same_authority:
                            raise HubError(
                                "bootstrap_request_in_progress",
                                "Another bootstrap confirmation is still active",
                                409,
                            )
                        # A confirmation UI can be closed after proof issuance.
                        # Let the same authenticated route/recipient atomically
                        # replace that abandoned request, while the immutable
                        # ledger keeps the old proof permanently revocable and
                        # the hard row cap bounds repeated retries.
                        changed = connection.execute(
                            """
                            UPDATE bootstrap_claims SET revoked_at = ?
                            WHERE id = ? AND consumed_at IS NULL
                              AND revoked_at IS NULL AND expires_at > ?
                            """,
                            (timestamp, str(competing["id"]), timestamp),
                        ).rowcount
                        if changed != 1:
                            raise HubError(
                                "bootstrap_unavailable",
                                "Bootstrap is unavailable",
                                409,
                            )
                    connection.execute(
                        """
                        UPDATE bootstrap_claims SET revoked_at = ?
                        WHERE consumed_at IS NULL AND revoked_at IS NULL
                        """,
                        (timestamp,),
                    )
                    claim_id = _id("bootstrap_claim")
                    connection.execute(
                        """
                        INSERT INTO bootstrap_claims(
                            id, token_hash, created_at, expires_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (claim_id, digest, timestamp, expires_at),
                    )
                    connection.execute(
                        """
                        INSERT INTO bootstrap_delegations(
                            bootstrap_claim_id, request_id, request_fingerprint,
                            server_identity, server_instance_id, hub_id, hub_url,
                            tailnet_login_normalized, recipient_email_normalized,
                            display_name, device_label, created_at, expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            claim_id,
                            clean_request_id,
                            fingerprint,
                            clean_server_identity,
                            clean_server_instance_id,
                            self.hub_id,
                            clean_hub_url,
                            clean_login,
                            clean_recipient,
                            clean_display_name,
                            clean_device_label,
                            timestamp,
                            expires_at,
                        ),
                    )
            try:
                self.bootstrap_proof_path.unlink(missing_ok=True)
            except OSError:
                pass
            return {
                "request_id": clean_request_id,
                "server_identity": clean_server_identity,
                "server_instance_id": clean_server_instance_id,
                "hub_id": self.hub_id,
                "tailnet_login": clean_login,
                "expires_at": _iso8601(expires_at),
                "bootstrap_proof": proof,
            }
        finally:
            connection.close()

    def verify_access(self, value: str) -> AccessClaims:
        try:
            payload = self.signer.verify(value)
        except TokenError as exc:
            raise HubError("authentication_required", "Authentication required", 401) from exc
        return AccessClaims(
            str(payload["sub"]), str(payload["sid"]), str(payload["jti"]), int(payload["exp"])
        )

    def local_agent_mail_team_ids(self) -> list[str]:
        """Return active local teams for the in-process agent-mail broker.

        This is deliberately not exposed through the HTTP service. The caller
        must already own this ``HubStore`` object inside the managed
        AgentsServer process.
        """

        connection = self.connect()
        try:
            return [
                str(row["team_id"])
                for row in connection.execute(
                    """
                    SELECT m.team_id
                    FROM memberships AS m
                    JOIN nodes AS n ON n.team_id=m.team_id
                    WHERE m.principal_id=? AND m.role='automation'
                      AND m.status='active' AND n.server_identity=?
                      AND n.status='active'
                    ORDER BY m.team_id
                    """,
                    (LOCAL_CONTROL_PRINCIPAL_ID, self.managed_host_identity),
                )
            ]
        finally:
            connection.close()

    def provision_local_agent_mail(self) -> None:
        """Provision the in-process mail actor during managed Hub setup."""

        timestamp = _now()
        connection = self.connect()
        try:
            with _write_transaction(connection):
                for row in connection.execute(
                    """
                    SELECT team_id FROM nodes
                    WHERE server_identity=? AND status='active'
                    ORDER BY team_id
                    """,
                    (self.managed_host_identity,),
                ):
                    team_id = str(row["team_id"])
                    self._local_control_principal(connection, team_id, timestamp)
        finally:
            connection.close()

    def local_agent_mail_claims(self, team_id: str) -> AccessClaims:
        """Return narrow, process-local claims for the managed host mailbox.

        These claims are never serialized or accepted by the public auth
        layer. They can read Team Network projection and send passive mailbox
        items as this installation's designated server, and nothing else.
        """

        clean_team_id = _identity(team_id)
        timestamp = _now()
        connection = self.connect()
        try:
            provisioned = connection.execute(
                """
                SELECT 1
                FROM memberships AS m
                JOIN principals AS p ON p.id=m.principal_id
                JOIN service_accounts AS s ON s.principal_id=p.id
                JOIN nodes AS n ON n.team_id=m.team_id
                WHERE m.team_id=? AND m.principal_id=?
                  AND m.role='automation' AND m.status='active'
                  AND p.kind='service' AND p.status='active'
                  AND s.service_identifier='agentsdock.team-hub.local-control'
                  AND n.server_identity=? AND n.status='active'
                """,
                (
                    clean_team_id,
                    LOCAL_CONTROL_PRINCIPAL_ID,
                    self.managed_host_identity,
                ),
            ).fetchone()
            if provisioned is None:
                raise HubError(
                    "network_host_unavailable",
                    "Designated host server identity is unavailable",
                    409,
                )
        finally:
            connection.close()
        return AccessClaims(
            principal_id=LOCAL_CONTROL_PRINCIPAL_ID,
            session_id=f"local_agent_mail_session_{clean_team_id}",
            jti=f"local_agent_mail_{clean_team_id}",
            expires_at=timestamp + 60,
            auth_kind="local_agent_mail",
            team_id=clean_team_id,
            scopes=frozenset({"teamspace.read", "teamspace.write"}),
        )

    def managed_server_claims(self) -> AccessClaims:
        """Return the one server-scoped Teamspace actor for this Hub host.

        The parent AgentsServer authenticates the client before requesting
        these process-local claims. No bearer or refresh credential is minted,
        serialized, persisted by a client, or accepted on the public Hub mount.
        A managed host identity belongs to exactly one active Team Network.
        """

        timestamp = _now()
        connection = self.connect()
        try:
            rows = connection.execute(
                """
                SELECT m.team_id
                FROM memberships AS m
                JOIN principals AS p ON p.id=m.principal_id
                JOIN service_accounts AS s ON s.principal_id=p.id
                JOIN nodes AS n ON n.team_id=m.team_id
                JOIN managed_host_bindings AS managed
                  ON managed.singleton=1
                 AND managed.server_identity=n.server_identity
                WHERE m.principal_id=? AND m.role='automation'
                  AND m.status='active' AND p.kind='service'
                  AND p.scope_team_id IS NULL AND p.status='active'
                  AND s.service_identifier=? AND n.status='active'
                ORDER BY m.team_id
                """,
                (MANAGED_SERVER_PRINCIPAL_ID, MANAGED_SERVER_SERVICE_IDENTIFIER),
            ).fetchall()
        finally:
            connection.close()
        if len(rows) != 1:
            raise HubError(
                "server_session_unavailable",
                "Server-scoped Teamspace access is unavailable",
                409,
            )
        team_id = str(rows[0]["team_id"])
        return AccessClaims(
            principal_id=MANAGED_SERVER_PRINCIPAL_ID,
            session_id=f"managed_server_session_{team_id}",
            jti=f"managed_server_{team_id}",
            expires_at=timestamp + 60,
            auth_kind="managed_server",
            team_id=team_id,
            scopes=frozenset({"teamspace.read", "teamspace.write"}),
        )

    @staticmethod
    def _require_session(
        connection: sqlite3.Connection, claims: AccessClaims, timestamp: int
    ) -> sqlite3.Row:
        if claims.auth_kind == "local_agent_mail":
            if (
                claims.principal_id != LOCAL_CONTROL_PRINCIPAL_ID
                or claims.team_id is None
                or claims.expires_at <= timestamp
                or claims.session_id
                != f"local_agent_mail_session_{claims.team_id}"
                or claims.scopes
                != frozenset({"teamspace.read", "teamspace.write"})
                or claims.peer_id is not None
            ):
                raise HubError("authentication_required", "Authentication required", 401)
            row = connection.execute(
                """
                SELECT ? AS id, p.id AS human_principal_id,
                       ? AS device_label, ? AS expires_at,
                       NULL AS email_normalized, p.display_name,
                       p.kind AS principal_kind
                FROM principals AS p
                JOIN service_accounts AS s ON s.principal_id=p.id
                JOIN memberships AS m ON m.principal_id=p.id
                WHERE p.id=? AND p.kind='service'
                  AND p.scope_team_id IS NULL AND p.status='active'
                  AND s.service_identifier='agentsdock.team-hub.local-control'
                  AND m.team_id=? AND m.role='automation'
                  AND m.status='active'
                """,
                (
                    claims.session_id,
                    "AgentsDock agent mail",
                    claims.expires_at,
                    LOCAL_CONTROL_PRINCIPAL_ID,
                    claims.team_id,
                ),
            ).fetchone()
            if row is None:
                raise HubError("authentication_required", "Authentication required", 401)
            return row
        if claims.auth_kind == "managed_server":
            if (
                claims.principal_id != MANAGED_SERVER_PRINCIPAL_ID
                or claims.team_id is None
                or claims.expires_at <= timestamp
                or claims.session_id
                != f"managed_server_session_{claims.team_id}"
                or claims.jti != f"managed_server_{claims.team_id}"
                or claims.scopes
                != frozenset({"teamspace.read", "teamspace.write"})
                or claims.peer_id is not None
            ):
                raise HubError("authentication_required", "Authentication required", 401)
            row = connection.execute(
                """
                SELECT ? AS id, p.id AS human_principal_id,
                       ? AS device_label, ? AS expires_at,
                       NULL AS email_normalized, p.display_name,
                       p.kind AS principal_kind
                FROM principals AS p
                JOIN service_accounts AS s ON s.principal_id=p.id
                JOIN memberships AS m ON m.principal_id=p.id
                JOIN nodes AS n ON n.team_id=m.team_id
                JOIN managed_host_bindings AS managed
                  ON managed.singleton=1
                 AND managed.server_identity=n.server_identity
                WHERE p.id=? AND p.kind='service'
                  AND p.scope_team_id IS NULL AND p.status='active'
                  AND s.service_identifier=?
                  AND m.team_id=? AND m.role='automation'
                  AND m.status='active' AND n.status='active'
                """,
                (
                    claims.session_id,
                    "AgentsDock managed server",
                    claims.expires_at,
                    MANAGED_SERVER_PRINCIPAL_ID,
                    MANAGED_SERVER_SERVICE_IDENTIFIER,
                    claims.team_id,
                ),
            ).fetchone()
            if row is None:
                raise HubError("authentication_required", "Authentication required", 401)
            return row
        if claims.auth_kind == "secure_peer":
            if (
                claims.team_id is None
                or claims.peer_id is None
                or claims.expires_at <= timestamp
                or claims.session_id != f"secure_peer_session_{claims.peer_id}"
            ):
                raise HubError("authentication_required", "Authentication required", 401)
            row = connection.execute(
                """
                SELECT ? AS id, p.id AS human_principal_id,
                       ? AS device_label, ? AS expires_at,
                       NULL AS email_normalized, p.display_name,
                       p.kind AS principal_kind
                FROM principals AS p
                JOIN service_accounts AS s ON s.principal_id = p.id
                JOIN memberships AS m ON m.principal_id = p.id
                WHERE p.id = ? AND p.kind = 'service'
                  AND p.scope_team_id IS NULL AND p.status = 'active'
                  AND s.service_identifier = ?
                  AND m.team_id = ? AND m.role = 'automation'
                  AND m.status = 'active'
                """,
                (
                    claims.session_id,
                    "Secure paired server",
                    claims.expires_at,
                    claims.principal_id,
                    f"agentsdock.secure-peer.{claims.peer_id}",
                    claims.team_id,
                ),
            ).fetchone()
            if row is None:
                raise HubError("authentication_required", "Authentication required", 401)
            return row
        if claims.auth_kind != "human":
            raise HubError("authentication_required", "Authentication required", 401)
        row = connection.execute(
            """
            SELECT s.id, s.human_principal_id, s.device_label, s.expires_at,
                   h.email_normalized, p.display_name,
                   p.kind AS principal_kind
            FROM device_sessions AS s
            JOIN human_accounts AS h ON h.principal_id = s.human_principal_id
            JOIN principals AS p ON p.id = s.human_principal_id
            WHERE s.id = ? AND s.human_principal_id = ?
              AND s.revoked_at IS NULL AND s.expires_at > ?
              AND p.status = 'active'
              AND NOT EXISTS (
                SELECT 1 FROM access_token_revocations AS r
                WHERE r.device_session_id = s.id
                  AND r.jti_hash = ? AND r.expires_at > ?
              )
            """,
            (
                claims.session_id,
                claims.principal_id,
                timestamp,
                hashlib.sha256(claims.jti.encode("utf-8")).digest(),
                timestamp,
            ),
        ).fetchone()
        if row is None:
            raise HubError("authentication_required", "Authentication required", 401)
        return row

    def _teams_for(self, connection: sqlite3.Connection, principal_id: str) -> list[dict[str, Any]]:
        return [
            _row_dict(row)
            for row in connection.execute(
                """
                SELECT t.id, t.kind, t.slug, t.display_name, m.role, m.status
                FROM memberships AS m
                JOIN teams AS t ON t.id = m.team_id
                WHERE m.principal_id = ? AND m.status = 'active'
                ORDER BY t.display_name COLLATE NOCASE, t.id
                """,
                (principal_id,),
            )
        ]

    @staticmethod
    def _local_control_principal(
        connection: sqlite3.Connection, team_id: str, timestamp: int
    ) -> str:
        """Return the team-scoped membership for the host control-plane actor.

        Recovery proofs are issued by the owner of the Hub data directory, not
        by the human being recovered.  A stable service principal keeps that
        distinction honest in the immutable audit ledger.  It is created only
        after a team exists and in the same transaction as the operation that
        needs it, so it cannot make an empty database ineligible for bootstrap.
        """

        principal = connection.execute(
            """
            SELECT p.kind, p.scope_team_id, p.display_name, p.status,
                   s.service_identifier
            FROM principals AS p
            LEFT JOIN service_accounts AS s ON s.principal_id = p.id
            WHERE p.id = ?
            """,
            (LOCAL_CONTROL_PRINCIPAL_ID,),
        ).fetchone()
        if principal is None:
            connection.execute(
                """
                INSERT INTO principals(
                    id, kind, scope_team_id, display_name, status,
                    created_at, updated_at
                ) VALUES (?, 'service', NULL, ?, 'active', ?, ?)
                """,
                (
                    LOCAL_CONTROL_PRINCIPAL_ID,
                    "Team Hub local control",
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO service_accounts(
                    principal_id, service_identifier, created_at
                ) VALUES (?, ?, ?)
                """,
                (
                    LOCAL_CONTROL_PRINCIPAL_ID,
                    "agentsdock.team-hub.local-control",
                    timestamp,
                ),
            )
        elif (
            principal["kind"] != "service"
            or principal["scope_team_id"] is not None
            or principal["status"] != "active"
            or principal["service_identifier"] != "agentsdock.team-hub.local-control"
        ):
            raise RuntimeError("invalid Team Hub local-control service principal")

        membership = connection.execute(
            """
            SELECT role, status FROM memberships
            WHERE team_id = ? AND principal_id = ?
            """,
            (team_id, LOCAL_CONTROL_PRINCIPAL_ID),
        ).fetchone()
        if membership is None:
            connection.execute(
                """
                INSERT INTO memberships(
                    id, team_id, principal_id, role, status,
                    invited_by_principal_id, created_at, updated_at
                ) VALUES (?, ?, ?, 'automation', 'active', NULL, ?, ?)
                """,
                (
                    _id("membership"),
                    team_id,
                    LOCAL_CONTROL_PRINCIPAL_ID,
                    timestamp,
                    timestamp,
                ),
            )
        elif membership["role"] != "automation" or membership["status"] != "active":
            raise RuntimeError("invalid Team Hub local-control team membership")
        return LOCAL_CONTROL_PRINCIPAL_ID

    @staticmethod
    def _managed_server_principal(
        connection: sqlite3.Connection, team_id: str, timestamp: int
    ) -> str:
        """Provision the managed AgentsServer as its own automation actor."""

        principal = connection.execute(
            """
            SELECT p.kind, p.scope_team_id, p.display_name, p.status,
                   s.service_identifier
            FROM principals AS p
            LEFT JOIN service_accounts AS s ON s.principal_id = p.id
            WHERE p.id = ?
            """,
            (MANAGED_SERVER_PRINCIPAL_ID,),
        ).fetchone()
        if principal is None:
            connection.execute(
                """
                INSERT INTO principals(
                    id, kind, scope_team_id, display_name, status,
                    created_at, updated_at
                ) VALUES (?, 'service', NULL, ?, 'active', ?, ?)
                """,
                (
                    MANAGED_SERVER_PRINCIPAL_ID,
                    "AgentsDock managed server",
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO service_accounts(
                    principal_id, service_identifier, created_at
                ) VALUES (?, ?, ?)
                """,
                (
                    MANAGED_SERVER_PRINCIPAL_ID,
                    MANAGED_SERVER_SERVICE_IDENTIFIER,
                    timestamp,
                ),
            )
        elif (
            principal["kind"] != "service"
            or principal["scope_team_id"] is not None
            or principal["status"] != "active"
            or principal["service_identifier"] != MANAGED_SERVER_SERVICE_IDENTIFIER
        ):
            raise RuntimeError("invalid Team Hub managed-server service principal")

        membership = connection.execute(
            """
            SELECT role, status FROM memberships
            WHERE team_id = ? AND principal_id = ?
            """,
            (team_id, MANAGED_SERVER_PRINCIPAL_ID),
        ).fetchone()
        if membership is None:
            connection.execute(
                """
                INSERT INTO memberships(
                    id, team_id, principal_id, role, status,
                    invited_by_principal_id, created_at, updated_at
                ) VALUES (?, ?, ?, 'automation', 'active', NULL, ?, ?)
                """,
                (
                    _id("membership"),
                    team_id,
                    MANAGED_SERVER_PRINCIPAL_ID,
                    timestamp,
                    timestamp,
                ),
            )
        elif membership["role"] != "automation" or membership["status"] != "active":
            raise RuntimeError("invalid Team Hub managed-server team membership")
        return MANAGED_SERVER_PRINCIPAL_ID

    @staticmethod
    def _secure_peer_principal_id(peer_id: str) -> str:
        try:
            parsed = uuid.UUID(peer_id)
        except (ValueError, AttributeError) as exc:
            raise HubError("peer_unavailable", "Secure peer is unavailable", 404) from exc
        if parsed.version != 4 or str(parsed) != peer_id:
            raise HubError("peer_unavailable", "Secure peer is unavailable", 404)
        return "service_secure_peer_" + parsed.hex

    def _ensure_managed_host_node(
        self,
        connection: sqlite3.Connection,
        team_id: str,
        timestamp: int,
    ) -> str | None:
        """Materialize the designated host as one ordinary logical server."""

        identity = self.managed_host_identity
        if identity is None:
            return None
        row = connection.execute(
            """
            SELECT n.id,n.team_id,n.principal_id,n.display_name AS node_display_name,
                   n.status,p.kind AS principal_kind,p.scope_team_id,
                   p.display_name AS principal_display_name,
                   p.status AS principal_status
            FROM nodes AS n JOIN principals AS p ON p.id=n.principal_id
            WHERE n.server_identity=?
            """,
            (identity,),
        ).fetchone()
        if row is not None:
            if (
                row["team_id"] != team_id
                or row["principal_kind"] != "node"
                or row["scope_team_id"] != team_id
                or row["principal_status"] != "active"
                or row["status"] == "revoked"
            ):
                raise HubError(
                    "server_identity_conflict",
                    "Managed server identity conflicts with Team Hub state",
                    409,
                )
            label = self.managed_host_display_name
            if row["status"] != "active" or row["node_display_name"] != label:
                connection.execute(
                    """
                    UPDATE nodes
                    SET display_name=?,status='active',last_seen_at=?
                    WHERE id=?
                    """,
                    (label, timestamp, row["id"]),
                )
            if row["principal_display_name"] != label:
                connection.execute(
                    "UPDATE principals SET display_name=?,updated_at=? WHERE id=?",
                    (label, timestamp, row["principal_id"]),
                )
            return str(row["id"])
        principal_id = _id("node_principal")
        node_id = _id("node")
        label = self.managed_host_display_name
        connection.execute(
            """
            INSERT INTO principals(
                id,kind,scope_team_id,display_name,status,created_at,updated_at
            ) VALUES (?,'node',?,?,'active',?,?)
            """,
            (principal_id, team_id, label, timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO nodes(
                id,team_id,principal_id,server_identity,display_name,status,
                enrolled_at,last_seen_at
            ) VALUES (?,?,?,?,?,'active',?,?)
            """,
            (node_id, team_id, principal_id, identity, label, timestamp, timestamp),
        )
        return node_id

    def ensure_secure_peer_service(
        self,
        *,
        peer_id: str,
        peer_server_identity: str,
        team_id: str,
        display_name: str,
    ) -> str:
        """Idempotently bind one approved mTLS peer to an automation member.

        The certificate and scope authority remain in the separate secure-peer
        store and are rechecked for every proxied request.  This row supplies
        only an auditable Team Hub author principal; it cannot authenticate on
        any ordinary HTTP Hub route.
        """

        principal_id = self._secure_peer_principal_id(peer_id)
        identity = _identity(peer_server_identity)
        label = _bounded_text(display_name, "display_name", 1, 160)
        clean_team = _identity(team_id)
        timestamp = _now()
        service_identifier = f"agentsdock.secure-peer.{peer_id}"
        changed = False
        connection = self.connect()
        try:
            with _write_transaction(connection):
                team = connection.execute(
                    "SELECT id FROM teams WHERE id = ?",
                    (clean_team,),
                ).fetchone()
                if team is None:
                    raise HubError("not_found", "Resource not found", 404)
                self._ensure_managed_host_node(connection, clean_team, timestamp)
                principal = connection.execute(
                    """
                    SELECT p.kind,p.scope_team_id,p.display_name,p.status,
                           s.service_identifier
                    FROM principals AS p
                    LEFT JOIN service_accounts AS s ON s.principal_id=p.id
                    WHERE p.id=?
                    """,
                    (principal_id,),
                ).fetchone()
                if principal is None:
                    connection.execute(
                        """
                        INSERT INTO principals(
                            id,kind,scope_team_id,display_name,status,
                            created_at,updated_at
                        ) VALUES (?,'service',NULL,?,'active',?,?)
                        """,
                        (principal_id, label, timestamp, timestamp),
                    )
                    connection.execute(
                        """
                        INSERT INTO service_accounts(
                            principal_id,service_identifier,created_at
                        ) VALUES (?,?,?)
                        """,
                        (principal_id, service_identifier, timestamp),
                    )
                    changed = True
                elif (
                    principal["kind"] != "service"
                    or principal["scope_team_id"] is not None
                    or principal["status"] != "active"
                    or principal["service_identifier"] != service_identifier
                    or principal["display_name"] != label
                ):
                    raise HubError(
                        "peer_identity_conflict",
                        "Secure peer identity conflicts with Team Hub state",
                        409,
                    )
                membership = connection.execute(
                    """
                    SELECT role,status FROM memberships
                    WHERE team_id=? AND principal_id=?
                    """,
                    (clean_team, principal_id),
                ).fetchone()
                if membership is None:
                    connection.execute(
                        """
                        INSERT INTO memberships(
                            id,team_id,principal_id,role,status,
                            invited_by_principal_id,created_at,updated_at
                        ) VALUES (?,?,?,'automation','active',NULL,?,?)
                        """,
                        (
                            _id("membership"),
                            clean_team,
                            principal_id,
                            timestamp,
                            timestamp,
                        ),
                    )
                    changed = True
                elif membership["role"] != "automation" or membership["status"] != "active":
                    raise HubError(
                        "peer_identity_conflict",
                        "Secure peer membership conflicts with Team Hub state",
                        409,
                    )
                self._ensure_network_board(
                    connection, clean_team, principal_id, timestamp
                )
                node = connection.execute(
                    """
                    SELECT n.id,n.team_id,n.principal_id,n.display_name,n.status,
                           p.kind AS principal_kind,p.scope_team_id,p.status AS principal_status
                    FROM nodes AS n
                    JOIN principals AS p ON p.id=n.principal_id
                    WHERE n.server_identity=?
                    """,
                    (identity,),
                ).fetchone()
                if node is None:
                    node_principal_id = _id("node_principal")
                    node_id = _id("node")
                    connection.execute(
                        """
                        INSERT INTO principals(
                            id,kind,scope_team_id,display_name,status,
                            created_at,updated_at
                        ) VALUES (?,'node',?,?,'active',?,?)
                        """,
                        (node_principal_id, clean_team, label, timestamp, timestamp),
                    )
                    connection.execute(
                        """
                        INSERT INTO nodes(
                            id,team_id,principal_id,server_identity,display_name,
                            status,enrolled_at,last_seen_at
                        ) VALUES (?,?,?,?,?,'offline',?,NULL)
                        """,
                        (
                            node_id,
                            clean_team,
                            node_principal_id,
                            identity,
                            label,
                            timestamp,
                        ),
                    )
                    changed = True
                else:
                    if (
                        node["team_id"] != clean_team
                        or node["principal_kind"] != "node"
                        or node["scope_team_id"] != clean_team
                        or node["principal_status"] != "active"
                        or node["status"] == "revoked"
                    ):
                        raise HubError(
                            "peer_identity_conflict",
                            "Secure peer server identity conflicts with Team Hub state",
                            409,
                        )
                    node_id = str(node["id"])
                    if node["display_name"] != label:
                        connection.execute(
                            """
                            UPDATE nodes
                            SET display_name=?
                            WHERE id=?
                            """,
                            (label, node_id),
                        )
                        connection.execute(
                            """
                            UPDATE principals SET display_name=?,updated_at=?
                            WHERE id=?
                            """,
                            (label, timestamp, node["principal_id"]),
                        )
                        changed = True
                binding = connection.execute(
                    """
                    SELECT peer_id,node_id,service_principal_id,
                           peer_server_identity,status
                    FROM network_peer_bindings WHERE peer_id=?
                    """,
                    (peer_id,),
                ).fetchone()
                active_for_node = connection.execute(
                    """
                    SELECT peer_id FROM network_peer_bindings
                    WHERE team_id=? AND node_id=? AND status='active'
                    """,
                    (clean_team, node_id),
                ).fetchone()
                if binding is None:
                    if active_for_node is not None:
                        raise HubError(
                            "peer_identity_conflict",
                            "Server already has an active secure peer connection",
                            409,
                        )
                    connection.execute(
                        """
                        INSERT INTO network_peer_bindings(
                            peer_id,team_id,node_id,service_principal_id,
                            peer_server_identity,status,created_at
                        ) VALUES (?,?,?,?,?,'active',?)
                        """,
                        (
                            peer_id,
                            clean_team,
                            node_id,
                            principal_id,
                            identity,
                            timestamp,
                        ),
                    )
                    changed = True
                elif (
                    binding["node_id"] != node_id
                    or binding["service_principal_id"] != principal_id
                    or binding["peer_server_identity"] != identity
                    or binding["status"] != "active"
                ):
                    raise HubError(
                        "peer_identity_conflict",
                        "Secure peer binding conflicts with Team Hub state",
                        409,
                    )
                # Existing public channels predate the automation ACL role.
                # Install only the shared role entry; private/direct channels
                # require an explicit principal ACL and remain invisible.
                channels = connection.execute(
                    """
                    SELECT id,kind FROM channels
                    WHERE team_id=? AND visibility='team' AND archived_at IS NULL
                    """,
                    (clean_team,),
                ).fetchall()
                for channel in channels:
                    inserted = connection.execute(
                        """
                        INSERT OR IGNORE INTO channel_acl_entries(
                            id,team_id,channel_id,subject_kind,
                            subject_principal_id,subject_role,
                            can_read,can_post,can_manage,can_dispatch,created_at
                        ) VALUES (?,?,?,'role',NULL,'automation',1,?,0,0,?)
                        """,
                        (
                            _id("channel_acl"),
                            clean_team,
                            channel["id"],
                            0 if channel["kind"] == "announcements" else 1,
                            timestamp,
                        ),
                    ).rowcount
                    changed = changed or inserted == 1
                if changed:
                    self._audit(
                        connection,
                        clean_team,
                        principal_id,
                        "secure_peer.bind",
                        "secure_peer",
                        peer_id,
                        "succeeded",
                        {"server_identity": identity, "node_id": node_id},
                        timestamp,
                    )
            return principal_id
        finally:
            connection.close()

    def active_secure_peer_binding_ids(
        self,
        peer_ids: list[str] | tuple[str, ...],
        peer_server_identity: str,
    ) -> set[str]:
        """Return exact, live trust bindings for one logical peer identity.

        Presence is deliberately not part of this lookup: an offline logical
        node still owns its active trust binding and must win restart
        reconciliation over an unbound duplicate peer record.
        """

        identity = _identity(peer_server_identity)
        if not isinstance(peer_ids, (list, tuple)):
            raise ValueError("peer_ids must be a bounded list")
        if len(peer_ids) > MAX_SECURE_PEER_BINDING_LOOKUP_IDS:
            raise ValueError("too many secure peer binding candidates")
        candidates: list[str] = []
        seen: set[str] = set()
        for value in peer_ids:
            self._secure_peer_principal_id(value)
            if value not in seen:
                candidates.append(value)
                seen.add(value)
        if not candidates:
            return set()

        placeholders = ",".join("?" for _value in candidates)
        connection = self.connect()
        try:
            rows = connection.execute(
                f"""
                SELECT b.peer_id
                FROM network_peer_bindings AS b
                JOIN nodes AS n
                  ON n.team_id=b.team_id AND n.id=b.node_id
                JOIN principals AS np ON np.id=n.principal_id
                JOIN principals AS sp ON sp.id=b.service_principal_id
                JOIN service_accounts AS sa
                  ON sa.principal_id=b.service_principal_id
                JOIN memberships AS m
                  ON m.team_id=b.team_id
                 AND m.principal_id=b.service_principal_id
                WHERE b.peer_id IN ({placeholders})
                  AND b.peer_server_identity=?
                  AND b.status='active'
                  AND n.server_identity=b.peer_server_identity
                  AND n.status<>'revoked'
                  AND np.kind='node'
                  AND np.scope_team_id=b.team_id
                  AND np.status='active'
                  AND sp.kind='service'
                  AND sp.scope_team_id IS NULL
                  AND sp.status='active'
                  AND sa.service_identifier='agentsdock.secure-peer.' || b.peer_id
                  AND m.role='automation'
                  AND m.status='active'
                """,
                (*candidates, identity),
            ).fetchall()
            return {str(row["peer_id"]) for row in rows}
        finally:
            connection.close()

    def record_secure_peer_heartbeat(self, peer_id: str, team_id: str) -> None:
        """Mark one exactly bound logical node online and advance its lease."""

        principal_id = self._secure_peer_principal_id(peer_id)
        team = _identity(team_id)
        timestamp = _now()
        binding_query = """
                    SELECT b.node_id,n.status,n.last_seen_at
                    FROM network_peer_bindings AS b
                    JOIN nodes AS n
                      ON n.team_id=b.team_id AND n.id=b.node_id
                    JOIN principals AS np ON np.id=n.principal_id
                    JOIN principals AS sp ON sp.id=b.service_principal_id
                    JOIN service_accounts AS sa
                      ON sa.principal_id=b.service_principal_id
                    JOIN memberships AS m
                      ON m.team_id=b.team_id
                     AND m.principal_id=b.service_principal_id
                    WHERE b.peer_id=? AND b.team_id=?
                      AND b.service_principal_id=?
                      AND b.status='active'
                      AND n.server_identity=b.peer_server_identity
                      AND n.status IN ('active','offline')
                      AND np.kind='node'
                      AND np.scope_team_id=b.team_id
                      AND np.status='active'
                      AND sp.kind='service'
                      AND sp.scope_team_id IS NULL
                      AND sp.status='active'
                      AND sa.service_identifier='agentsdock.secure-peer.' || b.peer_id
                      AND m.role='automation'
                      AND m.status='active'
                    """
        connection = self.connect()
        try:
            binding = connection.execute(
                binding_query,
                (peer_id, team, principal_id),
            ).fetchone()
            if binding is None:
                raise HubError(
                    "peer_unavailable",
                    "Secure peer is unavailable",
                    404,
                )
            last_seen_at = (
                int(binding["last_seen_at"])
                if binding["last_seen_at"] is not None
                else None
            )
            if (
                binding["status"] == "active"
                and last_seen_at is not None
                and last_seen_at
                > timestamp - SECURE_PEER_HEARTBEAT_WRITE_INTERVAL_SECONDS
            ):
                return
            with _write_transaction(connection):
                binding = connection.execute(
                    binding_query,
                    (peer_id, team, principal_id),
                ).fetchone()
                if binding is None:
                    raise HubError(
                        "peer_unavailable",
                        "Secure peer is unavailable",
                        404,
                    )
                last_seen_at = (
                    int(binding["last_seen_at"])
                    if binding["last_seen_at"] is not None
                    else None
                )
                if (
                    binding["status"] == "active"
                    and last_seen_at is not None
                    and last_seen_at
                    > timestamp
                    - SECURE_PEER_HEARTBEAT_WRITE_INTERVAL_SECONDS
                ):
                    return
                changed = connection.execute(
                    """
                    UPDATE nodes
                    SET status='active',
                        last_seen_at=CASE
                            WHEN last_seen_at IS NULL OR last_seen_at < ? THEN ?
                            ELSE last_seen_at
                        END
                    WHERE team_id=? AND id=? AND status IN ('active','offline')
                    """,
                    (timestamp, timestamp, team, binding["node_id"]),
                ).rowcount
                if changed != 1:
                    raise HubError(
                        "peer_unavailable",
                        "Secure peer is unavailable",
                        404,
                    )
        finally:
            connection.close()

    def expire_secure_peer_leases(self, stale_before: int) -> int:
        """Mark stale active peer nodes offline without changing trust rows."""

        if type(stale_before) is not int or stale_before < 0:
            raise ValueError("stale_before must be a non-negative integer")
        connection = self.connect()
        try:
            with _write_transaction(connection):
                return connection.execute(
                    """
                    UPDATE nodes AS n
                    SET status='offline'
                    WHERE n.status='active'
                      AND (n.last_seen_at IS NULL OR n.last_seen_at < ?)
                      AND EXISTS (
                          SELECT 1 FROM network_peer_bindings AS b
                          WHERE b.team_id=n.team_id
                            AND b.node_id=n.id
                            AND b.peer_server_identity=n.server_identity
                            AND b.status='active'
                      )
                    """,
                    (stale_before,),
                ).rowcount
        finally:
            connection.close()

    def require_secure_peer_target_team(self, team_id: str) -> None:
        """Preflight an approval target before the peer certificate commits."""

        team = _identity(team_id)
        connection = self.connect()
        try:
            row = connection.execute(
                "SELECT id FROM teams WHERE id=?",
                (team,),
            ).fetchone()
            if row is None:
                raise HubError(
                    "team_not_found",
                    "Secure peer approval target team is unavailable",
                    404,
                )
        finally:
            connection.close()

    def secure_peer_claims(
        self,
        *,
        peer_id: str,
        peer_server_identity: str,
        team_id: str,
        scopes: frozenset[str],
        expires_at: int,
        display_name: str | None = None,
    ) -> AccessClaims:
        allowed = {
            "teamspace.read",
            "teamspace.write",
            "cross_chat.instruction",
            "cross_chat.request_reply",
        }
        if not scopes or not scopes.issubset(allowed):
            raise HubError("peer_unavailable", "Secure peer is unavailable", 403)
        # Provisioning is an explicit approval-time mutation.  Request-time
        # claims remain read-only so a paired peer cannot turn GET traffic
        # into an unbounded audit/SQLite write stream.
        principal_id = self._secure_peer_principal_id(peer_id)
        _identity(peer_server_identity)
        _identity(team_id)
        if display_name is not None:
            _bounded_text(display_name, "display_name", 1, 160)
        return AccessClaims(
            principal_id=principal_id,
            session_id=f"secure_peer_session_{peer_id}",
            jti=f"secure_peer_{peer_id}",
            expires_at=int(expires_at),
            auth_kind="secure_peer",
            team_id=team_id,
            scopes=frozenset(scopes),
            peer_id=peer_id,
        )

    def revoke_secure_peer_service(
        self,
        *,
        peer_id: str,
        team_id: str,
    ) -> None:
        principal_id = self._secure_peer_principal_id(peer_id)
        timestamp = _now()
        connection = self.connect()
        try:
            with _write_transaction(connection):
                binding = connection.execute(
                    """
                    SELECT node_id,status FROM network_peer_bindings
                    WHERE peer_id=? AND team_id=?
                    """,
                    (peer_id, team_id),
                ).fetchone()
                if binding is not None and binding["status"] == "active":
                    connection.execute(
                        """
                        UPDATE network_peer_bindings
                        SET status='revoked',revoked_at=?
                        WHERE peer_id=? AND team_id=? AND status='active'
                        """,
                        (timestamp, peer_id, team_id),
                    )
                    connection.execute(
                        """
                        UPDATE nodes SET status='offline',last_seen_at=?
                        WHERE team_id=? AND id=? AND status='active'
                        """,
                        (timestamp, team_id, binding["node_id"]),
                    )
                connection.execute(
                    """
                    UPDATE memberships SET status='revoked',updated_at=?
                    WHERE team_id=? AND principal_id=? AND status='active'
                    """,
                    (timestamp, team_id, principal_id),
                )
                connection.execute(
                    """
                    UPDATE principals SET status='revoked',updated_at=?
                    WHERE id=? AND status='active'
                    """,
                    (timestamp, principal_id),
                )
        finally:
            connection.close()

    def secure_peer_resource_team(
        self,
        resource_kind: str,
        resource_id: str,
    ) -> str | None:
        """Resolve only the small resource set accepted by the mTLS proxy."""

        if resource_kind != "channel":
            return None
        clean_id = _identity(resource_id)
        connection = self.connect()
        try:
            row = connection.execute(
                "SELECT team_id FROM channels WHERE id=? AND archived_at IS NULL",
                (clean_id,),
            ).fetchone()
            return str(row["team_id"]) if row is not None else None
        finally:
            connection.close()

    def _session_public(
        self, connection: sqlite3.Connection, session: sqlite3.Row
    ) -> dict[str, Any]:
        return {
            "session": {
                "id": session["id"],
                "device_label": session["device_label"],
                "expires_at": _iso8601(session["expires_at"]),
            },
            "principal": {
                "id": session["human_principal_id"],
                "email": session["email_normalized"],
                "display_name": session["display_name"],
                "kind": session["principal_kind"],
            },
            "teams": self._teams_for(connection, str(session["human_principal_id"])),
        }

    def _create_session(
        self,
        connection: sqlite3.Connection,
        principal_id: str,
        device_label: str,
        timestamp: int,
    ) -> tuple[sqlite3.Row, str, int]:
        label = _bounded_text(device_label, "device_label", 1, 160)
        session_id = _id("device")
        refresh, digest = opaque_secret("refresh")
        refresh_id = _id("refresh")
        expires_at = timestamp + SESSION_TTL_SECONDS
        connection.execute(
            """
            INSERT INTO device_sessions(
                id, human_principal_id, device_label, refresh_generation,
                created_at, last_seen_at, expires_at
            ) VALUES (?, ?, ?, 0, ?, ?, ?)
            """,
            (session_id, principal_id, label, timestamp, timestamp, expires_at),
        )
        connection.execute(
            """
            INSERT INTO refresh_tokens(
                id, device_session_id, token_hash, generation, created_at, expires_at
            ) VALUES (?, ?, ?, 0, ?, ?)
            """,
            (refresh_id, session_id, digest, timestamp, expires_at),
        )
        row = connection.execute(
            """
            SELECT s.id, s.human_principal_id, s.device_label, s.expires_at,
                   h.email_normalized, p.display_name,
                   p.kind AS principal_kind
            FROM device_sessions AS s
            JOIN human_accounts AS h ON h.principal_id = s.human_principal_id
            JOIN principals AS p ON p.id = s.human_principal_id
            WHERE s.id = ?
            """,
            (session_id,),
        ).fetchone()
        assert row is not None
        return row, refresh, expires_at

    def _auth_bundle(
        self,
        connection: sqlite3.Connection,
        session: sqlite3.Row,
        refresh: str,
        refresh_expires_at: int,
        timestamp: int,
    ) -> dict[str, Any]:
        access = self.signer.mint(
            str(session["human_principal_id"]), str(session["id"]), now=timestamp
        )
        return {
            "access_token": access.token,
            "token_type": "Bearer",
            "access_expires_at": _iso8601(access.expires_at),
            "refresh_token": refresh,
            "refresh_expires_at": _iso8601(refresh_expires_at),
            **self._session_public(connection, session),
        }

    def bootstrap(
        self,
        proof: str,
        email: str,
        display_name: str,
        device_label: str,
        *,
        transport: str = "loopback",
        request_id: str | None = None,
        tailnet_login: str | None = None,
        hub_url: str | None = None,
    ) -> dict[str, Any]:
        timestamp = _now()
        if transport not in {"loopback", "tailscale_serve", "direct_ip"}:
            raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 403)
        try:
            digest = token_hash(proof)
        except TokenError as exc:
            raise HubError(
                "bootstrap_unavailable", "Bootstrap is unavailable", 403
            ) from exc
        connection = self.connect()
        try:
            with _write_transaction(connection):
                if not self._globally_empty(connection):
                    raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 409)
                claim = connection.execute(
                    """
                    SELECT c.id, c.token_hash,
                           d.request_id, d.server_identity, d.server_instance_id,
                           d.hub_id, d.hub_url, d.tailnet_login_normalized,
                           d.recipient_email_normalized, d.display_name,
                           d.device_label
                    FROM bootstrap_claims AS c
                    LEFT JOIN bootstrap_delegations AS d
                      ON d.bootstrap_claim_id = c.id
                    WHERE c.token_hash = ? AND c.consumed_at IS NULL
                      AND c.revoked_at IS NULL AND c.expires_at > ?
                    """,
                    (digest, timestamp),
                ).fetchone()
                if claim is None or not hmac.compare_digest(claim["token_hash"], digest):
                    raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 403)
                delegated = claim["request_id"] is not None
                if transport == "loopback":
                    if delegated or request_id is not None or not proof.startswith("bootstrap."):
                        raise HubError(
                            "bootstrap_unavailable", "Bootstrap is unavailable", 403
                        )
                else:
                    try:
                        clean_request_id = self._canonical_request_id(str(request_id or ""))
                        clean_login = _email(str(tailnet_login or ""))
                        clean_email = _email(email)
                        clean_display_name = _bounded_text(
                            display_name, "display_name", 1, 160
                        )
                        clean_device_label = _bounded_text(
                            device_label, "device_label", 1, 160
                        )
                    except ValueError as exc:
                        raise HubError(
                            "bootstrap_unavailable", "Bootstrap is unavailable", 403
                        ) from exc
                    if (
                        not delegated
                        or not proof.startswith("bootstrap_remote.")
                        or clean_request_id != str(claim["request_id"])
                        or self.managed_host_identity is None
                        or str(claim["server_identity"])
                        != self.managed_host_identity
                        or self.managed_server_instance_id is None
                        or str(claim["server_instance_id"])
                        != self.managed_server_instance_id
                        or str(claim["hub_id"]) != self.hub_id
                        or str(claim["hub_url"]) != str(hub_url or "")
                        or (
                            transport == "tailscale_serve"
                            and urlsplit(str(claim["hub_url"])).scheme != "https"
                        )
                        or (
                            transport == "direct_ip"
                            and urlsplit(str(claim["hub_url"])).scheme != "http"
                        )
                        or str(claim["tailnet_login_normalized"]) != clean_login
                        or str(claim["recipient_email_normalized"]) != clean_email
                        or str(claim["display_name"]) != clean_display_name
                        or str(claim["device_label"]) != clean_device_label
                    ):
                        raise HubError(
                            "bootstrap_unavailable", "Bootstrap is unavailable", 403
                        )
                result = bootstrap_personal_team(
                    connection, email, display_name, now=timestamp
                )
                self._ensure_managed_host_node(
                    connection, result.team_id, timestamp
                )
                self._local_control_principal(
                    connection, result.team_id, timestamp
                )
                self._managed_server_principal(
                    connection, result.team_id, timestamp
                )
                self._ensure_network_board(
                    connection,
                    result.team_id,
                    result.human_principal_id,
                    timestamp,
                )
                changed = connection.execute(
                    """
                    UPDATE bootstrap_claims
                    SET consumed_at = ?, consumed_by_principal_id = ?
                    WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL
                      AND expires_at > ?
                    """,
                    (timestamp, result.human_principal_id, claim["id"], timestamp),
                ).rowcount
                if changed != 1:
                    raise HubError("bootstrap_unavailable", "Bootstrap is unavailable", 403)
                session, refresh, refresh_exp = self._create_session(
                    connection, result.human_principal_id, device_label, timestamp
                )
                self._audit(
                    connection,
                    result.team_id,
                    result.human_principal_id,
                    "team.bootstrap",
                    "team",
                    result.team_id,
                    "succeeded",
                    {},
                    timestamp,
                )
                bundle = self._auth_bundle(connection, session, refresh, refresh_exp, timestamp)
            try:
                self.bootstrap_proof_path.unlink(missing_ok=True)
            except OSError:
                pass
            return bundle
        finally:
            connection.close()

    def session_snapshot(self, claims: AccessClaims) -> dict[str, Any]:
        timestamp = _now()
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            session = self._require_session(connection, claims, timestamp)
            response = self._session_public(connection, session)
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        timestamp = _now()
        try:
            digest = token_hash(refresh_token)
        except TokenError as exc:
            raise HubError("authentication_required", "Authentication required", 401) from exc
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT r.id AS refresh_id, r.device_session_id, r.token_hash,
                           r.generation, r.expires_at AS refresh_expires_at,
                           r.consumed_at, r.revoked_at,
                           s.human_principal_id, s.device_label, s.expires_at,
                           s.refresh_generation,
                           s.revoked_at AS session_revoked_at,
                           h.email_normalized, p.display_name, p.status AS principal_status
                    FROM refresh_tokens AS r
                    JOIN device_sessions AS s ON s.id = r.device_session_id
                    JOIN human_accounts AS h ON h.principal_id = s.human_principal_id
                    JOIN principals AS p ON p.id = s.human_principal_id
                    WHERE r.token_hash = ?
                    """,
                    (digest,),
                ).fetchone()
                if row is None or not hmac.compare_digest(row["token_hash"], digest):
                    raise HubError("authentication_required", "Authentication required", 401)
                if (
                    row["consumed_at"] is not None
                    or int(row["generation"]) != int(row["refresh_generation"])
                ):
                    connection.execute(
                        "UPDATE device_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                        (timestamp, row["device_session_id"]),
                    )
                    connection.execute(
                        """
                        UPDATE refresh_tokens SET revoked_at = ?
                        WHERE device_session_id = ? AND consumed_at IS NULL AND revoked_at IS NULL
                        """,
                        (timestamp, row["device_session_id"]),
                    )
                    self._audit_principal_teams(
                        connection,
                        str(row["human_principal_id"]),
                        "session.refresh_replay",
                        "device_session",
                        str(row["device_session_id"]),
                        "denied",
                        timestamp,
                    )
                    connection.execute("COMMIT")
                    raise HubError("authentication_required", "Authentication required", 401)
                if (
                    row["revoked_at"] is not None
                    or row["session_revoked_at"] is not None
                    or row["principal_status"] != "active"
                    or int(row["refresh_expires_at"]) <= timestamp
                    or int(row["expires_at"]) <= timestamp
                ):
                    raise HubError("authentication_required", "Authentication required", 401)
                replacement, replacement_hash = opaque_secret("refresh")
                next_generation = int(row["generation"]) + 1
                replacement_id = _id("refresh")
                connection.execute(
                    """
                    INSERT INTO refresh_tokens(
                        id, device_session_id, token_hash, generation,
                        created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        replacement_id,
                        row["device_session_id"],
                        replacement_hash,
                        next_generation,
                        timestamp,
                        row["expires_at"],
                    ),
                )
                changed = connection.execute(
                    """
                    UPDATE refresh_tokens SET consumed_at = ?, replaced_by_token_id = ?
                    WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL
                    """,
                    (timestamp, replacement_id, row["refresh_id"]),
                ).rowcount
                if changed != 1:
                    raise HubError("authentication_required", "Authentication required", 401)
                connection.execute(
                    """
                    UPDATE device_sessions
                    SET refresh_generation = ?, last_seen_at = ?
                    WHERE id = ? AND revoked_at IS NULL
                    """,
                    (next_generation, timestamp, row["device_session_id"]),
                )
                current = connection.execute(
                    """
                    SELECT s.id, s.human_principal_id, s.device_label, s.expires_at,
                           h.email_normalized, p.display_name,
                           p.kind AS principal_kind
                    FROM device_sessions AS s
                    JOIN human_accounts AS h ON h.principal_id = s.human_principal_id
                    JOIN principals AS p ON p.id = s.human_principal_id
                    WHERE s.id = ?
                    """,
                    (row["device_session_id"],),
                ).fetchone()
                assert current is not None
                bundle = self._auth_bundle(
                    connection, current, replacement, int(row["expires_at"]), timestamp
                )
                self._audit_principal_teams(
                    connection,
                    str(row["human_principal_id"]),
                    "session.refresh",
                    "device_session",
                    str(row["device_session_id"]),
                    "succeeded",
                    timestamp,
                )
                connection.execute("COMMIT")
                return bundle
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()

    def revoke_session(self, claims: AccessClaims, refresh_token: str) -> dict[str, bool]:
        timestamp = _now()
        try:
            digest = token_hash(refresh_token)
        except TokenError as exc:
            raise HubError("authentication_required", "Authentication required", 401) from exc
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_session(connection, claims, timestamp)
                belongs = connection.execute(
                    "SELECT 1 FROM refresh_tokens WHERE device_session_id = ? AND token_hash = ?",
                    (claims.session_id, digest),
                ).fetchone()
                if belongs is None:
                    raise HubError("authentication_required", "Authentication required", 401)
                connection.execute(
                    "UPDATE device_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                    (timestamp, claims.session_id),
                )
                connection.execute(
                    """
                    UPDATE refresh_tokens SET revoked_at = ?
                    WHERE device_session_id = ? AND consumed_at IS NULL AND revoked_at IS NULL
                    """,
                    (timestamp, claims.session_id),
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO access_token_revocations(
                        jti_hash, device_session_id, expires_at, revoked_at, reason
                    ) VALUES (?, ?, ?, ?, 'session logout')
                    """,
                    (
                        hashlib.sha256(claims.jti.encode("utf-8")).digest(),
                        claims.session_id,
                        claims.expires_at,
                        timestamp,
                    ),
                )
                self._audit_principal_teams(
                    connection,
                    claims.principal_id,
                    "session.revoke",
                    "device_session",
                    claims.session_id,
                    "succeeded",
                    timestamp,
                )
            return {"revoked": True}
        finally:
            connection.close()

    def list_device_sessions(self, claims: AccessClaims) -> dict[str, Any]:
        """List only the authenticated human's own device-session ledger."""

        return self.list_device_sessions_page(claims)

    def _human_admin_page_cursor(
        self,
        value: str | None,
        *,
        resource_kind: str,
        scope_id: str,
        viewer_id: str,
        visibility: str,
    ) -> tuple[int, int, str] | None:
        if value is None:
            return None
        raw = str(value)
        associated_data = b"agentsdock-team-hub-human-admin-cursor-v1\0" + canonical_json(
            {
                "k": resource_kind,
                "s": scope_id,
                "u": viewer_id,
                "f": visibility,
            }
        )
        try:
            if (
                len(raw) > 512
                or re.fullmatch(r"v1\.[A-Za-z0-9_-]{38,500}", raw) is None
            ):
                raise ValueError("cursor encoding is invalid")
            encoded = raw[3:].encode("ascii")
            ciphertext = base64.b64decode(
                encoded + b"=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            )
            if len(ciphertext) < 12 + 16:
                raise ValueError("cursor encoding is truncated")
            plaintext = AESGCM(self._human_admin_cursor_key).decrypt(
                ciphertext[:12],
                ciphertext[12:],
                associated_data,
            )
            payload = json.loads(plaintext)
            if (
                not isinstance(payload, dict)
                or set(payload) != {"v", "h", "t", "i"}
                or payload["v"] != 1
                or type(payload["h"]) is not int
                or type(payload["t"]) is not int
                or not 0 <= payload["h"] <= MAX_SQLITE_SIGNED_INTEGER
                or not 0 <= payload["t"] <= MAX_SQLITE_SIGNED_INTEGER
            ):
                raise ValueError("cursor payload is invalid")
            clean_id = _identity(payload["i"])
        except (
            ValueError,
            TypeError,
            UnicodeError,
            binascii.Error,
            json.JSONDecodeError,
            InvalidTag,
        ) as exc:
            raise HubError("invalid_cursor", "Page cursor is invalid", 422) from exc
        return int(payload["h"]), int(payload["t"]), clean_id

    def _encode_human_admin_page_cursor(
        self,
        *,
        resource_kind: str,
        scope_id: str,
        viewer_id: str,
        visibility: str,
        highwater: int,
        timestamp: int,
        resource_id: str,
    ) -> str:
        payload = canonical_json(
            {
                "v": 1,
                "h": int(highwater),
                "t": int(timestamp),
                "i": _identity(resource_id),
            }
        )
        associated_data = b"agentsdock-team-hub-human-admin-cursor-v1\0" + canonical_json(
            {
                "k": resource_kind,
                "s": scope_id,
                "u": viewer_id,
                "f": visibility,
            }
        )
        nonce = secrets.token_bytes(12)
        ciphertext = nonce + AESGCM(self._human_admin_cursor_key).encrypt(
            nonce,
            payload,
            associated_data,
        )
        cursor = "v1." + base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode(
            "ascii"
        )
        if len(cursor) > 512:
            raise RuntimeError("human administration page cursor exceeds its wire bound")
        return cursor

    def list_device_sessions_page(
        self,
        claims: AccessClaims,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        page_limit = int(limit)
        if not 1 <= page_limit <= MAX_HUMAN_ADMIN_PAGE_ITEMS:
            raise HubError("invalid_request", "Page limit is invalid", 422)

        timestamp = _now()
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            session = self._require_session(connection, claims, timestamp)
            if session["principal_kind"] != "human":
                raise HubError("forbidden", "Operation is not permitted", 403)
            boundary = self._human_admin_page_cursor(
                cursor,
                resource_kind="device_session",
                scope_id=claims.principal_id,
                viewer_id=claims.principal_id,
                visibility="self",
            )
            highwater = (
                boundary[0]
                if boundary is not None
                else int(
                    connection.execute(
                        "SELECT COALESCE(MAX(sequence),0) "
                        "FROM human_admin_page_entries",
                    ).fetchone()[0]
                )
            )
            query = """
                SELECT s.id,s.device_label,s.created_at,s.last_seen_at,
                       s.expires_at,s.revoked_at
                FROM device_sessions AS s
                JOIN human_admin_page_entries AS page
                  ON page.resource_kind='device_session' AND page.resource_id=s.id
                WHERE s.human_principal_id=? AND page.sequence<=?
            """
            parameters: list[Any] = [claims.principal_id, highwater]
            if boundary is not None:
                query += " AND (s.created_at<? OR (s.created_at=? AND s.id<?))"
                parameters.extend((boundary[1], boundary[1], boundary[2]))
            query += " ORDER BY s.created_at DESC,s.id DESC LIMIT ?"
            parameters.append(page_limit + 1)
            rows = list(connection.execute(query, parameters))
            visible = rows[:page_limit]
            sessions = [
                {
                    "id": str(row["id"]),
                    "device_label": str(row["device_label"]),
                    "created_at": _iso8601(int(row["created_at"])),
                    "last_seen_at": _iso8601(int(row["last_seen_at"])),
                    "expires_at": _iso8601(int(row["expires_at"])),
                    "revoked_at": _iso8601(row["revoked_at"]),
                    "current": str(row["id"]) == claims.session_id,
                }
                for row in visible
            ]
            has_more = len(rows) > page_limit
            next_cursor = (
                self._encode_human_admin_page_cursor(
                    resource_kind="device_session",
                    scope_id=claims.principal_id,
                    viewer_id=claims.principal_id,
                    visibility="self",
                    highwater=highwater,
                    timestamp=int(visible[-1]["created_at"]),
                    resource_id=str(visible[-1]["id"]),
                )
                if has_more and visible
                else None
            )
            connection.execute("COMMIT")
            return {
                "sessions": sessions,
                "has_more": has_more,
                "next_cursor": next_cursor,
            }
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def revoke_device_session(
        self,
        claims: AccessClaims,
        device_session_id: str,
    ) -> dict[str, bool]:
        """Revoke one device owned by the authenticated human principal."""

        try:
            device_session_id = _identity(device_session_id)
        except ValueError as exc:
            raise HubError("not_found", "Resource not found", 404) from exc
        timestamp = _now()
        connection = self.connect()
        try:
            with _write_transaction(connection):
                session = self._require_session(connection, claims, timestamp)
                if session["principal_kind"] != "human":
                    raise HubError("forbidden", "Operation is not permitted", 403)
                target = connection.execute(
                    """
                    SELECT id,revoked_at FROM device_sessions
                    WHERE id=? AND human_principal_id=?
                    """,
                    (device_session_id, claims.principal_id),
                ).fetchone()
                if target is None:
                    raise HubError("not_found", "Resource not found", 404)
                connection.execute(
                    """
                    UPDATE device_sessions SET revoked_at=?
                    WHERE id=? AND revoked_at IS NULL
                    """,
                    (timestamp, device_session_id),
                )
                connection.execute(
                    """
                    UPDATE refresh_tokens SET revoked_at=?
                    WHERE device_session_id=?
                      AND consumed_at IS NULL AND revoked_at IS NULL
                    """,
                    (timestamp, device_session_id),
                )
                self._audit_principal_teams(
                    connection,
                    claims.principal_id,
                    "session.device_revoke",
                    "device_session",
                    device_session_id,
                    "succeeded",
                    timestamp,
                )
                return {"revoked": True}
        finally:
            connection.close()

    def list_teams(self, claims: AccessClaims) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_session(connection, claims, _now())
            result = {"teams": self._teams_for(connection, claims.principal_id)}
            connection.execute("COMMIT")
            return result
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def get_team(self, claims: AccessClaims, team_id: str) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_session(connection, claims, _now())
            membership = _require_team_role(
                connection,
                team_id,
                claims.principal_id,
                ("owner", "admin", "member", "guest", "automation"),
            )
            row = connection.execute(
                "SELECT id, kind, slug, display_name FROM teams WHERE id = ?",
                (team_id,),
            ).fetchone()
            if row is None:
                raise HubError("not_found", "Resource not found", 404)
            team = _row_dict(row)
            team.update({"role": membership["role"], "status": "active"})
            connection.execute("COMMIT")
            return {"team": team}
        except (AuthorizationError, AuthenticationError) as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise HubError("not_found", "Resource not found", 404) from exc
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def list_members(
        self,
        claims: AccessClaims,
        team_id: str,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        page_limit = int(limit)
        if not 1 <= page_limit <= MAX_HUMAN_ADMIN_PAGE_ITEMS:
            raise HubError("invalid_request", "Page limit is invalid", 422)
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_session(connection, claims, _now())
            viewer = _require_team_role(
                connection,
                team_id,
                claims.principal_id,
                ("owner", "admin", "member", "guest", "automation"),
            )
            email_projection = "h.email_normalized" if viewer["role"] in ("owner", "admin") else "NULL"
            membership_projection = (
                "m.status IN ('active','suspended')"
                if viewer["role"] in ("owner", "admin")
                else "m.status = 'active'"
            )
            membership_visibility = (
                "manageable"
                if viewer["role"] in ("owner", "admin")
                else "active"
            )
            boundary = self._human_admin_page_cursor(
                cursor,
                resource_kind="membership",
                scope_id=team_id,
                viewer_id=claims.principal_id,
                visibility=membership_visibility,
            )
            highwater = (
                boundary[0]
                if boundary is not None
                else int(
                    connection.execute(
                        "SELECT COALESCE(MAX(sequence),0) "
                        "FROM human_admin_page_entries",
                    ).fetchone()[0]
                )
            )
            query = f"""
                    SELECT m.principal_id, {email_projection} AS email,
                           p.display_name, m.role, m.status, m.created_at
                    FROM memberships AS m
                    JOIN human_admin_page_entries AS page
                      ON page.resource_kind='membership' AND page.resource_id=m.id
                    JOIN principals AS p ON p.id = m.principal_id
                    LEFT JOIN human_accounts AS h ON h.principal_id = m.principal_id
                    WHERE m.team_id = ? AND page.sequence<=? AND {membership_projection}
                      AND p.status = 'active'
                      AND (
                        p.kind = 'human'
                        OR (p.kind = 'service' AND p.id = ?)
                      )
            """
            parameters: list[Any] = [team_id, highwater, claims.principal_id]
            if boundary is not None:
                query += " AND (m.created_at<? OR (m.created_at=? AND m.principal_id<?))"
                parameters.extend((boundary[1], boundary[1], boundary[2]))
            query += " ORDER BY m.created_at DESC,m.principal_id DESC LIMIT ?"
            parameters.append(page_limit + 1)
            rows = list(connection.execute(query, parameters))
            visible = rows[:page_limit]
            members = [
                {
                    "principal_id": str(row["principal_id"]),
                    "email": row["email"],
                    "display_name": str(row["display_name"]),
                    "role": str(row["role"]),
                    "status": str(row["status"]),
                }
                for row in visible
            ]
            has_more = len(rows) > page_limit
            next_cursor = (
                self._encode_human_admin_page_cursor(
                    resource_kind="membership",
                    scope_id=team_id,
                    viewer_id=claims.principal_id,
                    visibility=membership_visibility,
                    highwater=highwater,
                    timestamp=int(visible[-1]["created_at"]),
                    resource_id=str(visible[-1]["principal_id"]),
                )
                if has_more and visible
                else None
            )
            connection.execute("COMMIT")
            return {
                "members": members,
                "has_more": has_more,
                "next_cursor": next_cursor,
            }
        except (AuthorizationError, AuthenticationError) as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise HubError("not_found", "Resource not found", 404) from exc
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _require_team_owner_for_human_administration(
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
    ) -> str:
        try:
            team_id = _identity(team_id)
        except ValueError as exc:
            raise HubError("not_found", "Resource not found", 404) from exc
        try:
            viewer = _require_team_role(
                connection,
                team_id,
                claims.principal_id,
                ("owner", "admin", "member", "guest", "automation"),
            )
        except AuthorizationError as exc:
            raise HubError("not_found", "Resource not found", 404) from exc
        if viewer["role"] != "owner":
            raise HubError("forbidden", "Operation is not permitted", 403)
        return team_id

    def list_pending_invitations(
        self,
        claims: AccessClaims,
        team_id: str,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        page_limit = int(limit)
        if not 1 <= page_limit <= MAX_HUMAN_ADMIN_PAGE_ITEMS:
            raise HubError("invalid_request", "Page limit is invalid", 422)
        timestamp = _now()
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_session(connection, claims, timestamp)
            team_id = self._require_team_owner_for_human_administration(
                connection, claims, team_id
            )
            boundary = self._human_admin_page_cursor(
                cursor,
                resource_kind="invitation",
                scope_id=team_id,
                viewer_id=claims.principal_id,
                visibility="pending",
            )
            highwater = (
                boundary[0]
                if boundary is not None
                else int(
                    connection.execute(
                        "SELECT COALESCE(MAX(sequence),0) "
                        "FROM human_admin_page_entries",
                    ).fetchone()[0]
                )
            )
            query = """
                SELECT i.id,i.invitee_email_normalized,i.role,
                       i.issued_by_principal_id,i.created_at,i.expires_at
                FROM invitations AS i
                JOIN human_admin_page_entries AS page
                  ON page.resource_kind='invitation' AND page.resource_id=i.id
                WHERE i.team_id=? AND i.redeemed_at IS NULL
                  AND i.revoked_at IS NULL AND i.expires_at>?
                  AND i.created_at>? AND page.sequence<=?
            """
            parameters: list[Any] = [
                team_id,
                timestamp,
                max(0, timestamp - INVITATION_MAX_TTL_SECONDS),
                highwater,
            ]
            if boundary is not None:
                query += " AND (i.created_at<? OR (i.created_at=? AND i.id<?))"
                parameters.extend((boundary[1], boundary[1], boundary[2]))
            query += " ORDER BY i.created_at DESC,i.id DESC LIMIT ?"
            parameters.append(page_limit + 1)
            rows = list(connection.execute(query, parameters))
            visible = rows[:page_limit]
            invitations = [
                {
                    "id": str(row["id"]),
                    "invitee_email": str(row["invitee_email_normalized"]),
                    "role": str(row["role"]),
                    "issued_by_principal_id": str(row["issued_by_principal_id"]),
                    "created_at": _iso8601(int(row["created_at"])),
                    "expires_at": _iso8601(int(row["expires_at"])),
                }
                for row in visible
            ]
            has_more = len(rows) > page_limit
            next_cursor = (
                self._encode_human_admin_page_cursor(
                    resource_kind="invitation",
                    scope_id=team_id,
                    viewer_id=claims.principal_id,
                    visibility="pending",
                    highwater=highwater,
                    timestamp=int(visible[-1]["created_at"]),
                    resource_id=str(visible[-1]["id"]),
                )
                if has_more and visible
                else None
            )
            connection.execute("COMMIT")
            return {
                "invitations": invitations,
                "has_more": has_more,
                "next_cursor": next_cursor,
            }
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def revoke_invitation(
        self,
        claims: AccessClaims,
        team_id: str,
        invitation_id: str,
    ) -> dict[str, bool]:
        try:
            invitation_id = _identity(invitation_id)
        except ValueError as exc:
            raise HubError("not_found", "Resource not found", 404) from exc
        timestamp = _now()
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_session(connection, claims, timestamp)
                team_id = self._require_team_owner_for_human_administration(
                    connection, claims, team_id
                )
                changed = connection.execute(
                    """
                    UPDATE invitations SET revoked_at=?
                    WHERE id=? AND team_id=? AND redeemed_at IS NULL
                      AND revoked_at IS NULL AND expires_at>?
                    """,
                    (timestamp, invitation_id, team_id, timestamp),
                ).rowcount
                if changed != 1:
                    raise HubError("not_found", "Resource not found", 404)
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "invitation.revoke",
                    "invitation",
                    invitation_id,
                    "succeeded",
                    {},
                    timestamp,
                )
                return {"revoked": True}
        finally:
            connection.close()

    def get_member(
        self,
        claims: AccessClaims,
        team_id: str,
        principal_id: str,
    ) -> dict[str, Any]:
        """Return one member under the caller's existing list visibility."""

        try:
            target_id = _identity(principal_id)
        except ValueError as exc:
            raise HubError("not_found", "Resource not found", 404) from exc
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_session(connection, claims, _now())
            viewer = _require_team_role(
                connection,
                team_id,
                claims.principal_id,
                ("owner", "admin", "member", "guest", "automation"),
            )
            manageable = viewer["role"] in ("owner", "admin")
            row = connection.execute(
                f"""
                SELECT m.principal_id,
                       {"h.email_normalized" if manageable else "NULL"} AS email,
                       p.display_name,m.role,m.status,p.kind
                FROM memberships AS m
                JOIN principals AS p ON p.id=m.principal_id
                LEFT JOIN human_accounts AS h ON h.principal_id=m.principal_id
                WHERE m.team_id=? AND m.principal_id=?
                  AND {"m.status IN ('active','suspended')" if manageable else "m.status='active'"}
                  AND p.status='active'
                  AND (p.kind='human' OR (p.kind='service' AND p.id=?))
                """,
                (team_id, target_id, claims.principal_id),
            ).fetchone()
            if row is None:
                raise HubError("not_found", "Resource not found", 404)
            connection.execute("COMMIT")
            return {
                "member": {
                    "principal_id": str(row["principal_id"]),
                    "email": row["email"],
                    "display_name": str(row["display_name"]),
                    "role": str(row["role"]),
                    "status": str(row["status"]),
                }
            }
        except (AuthorizationError, AuthenticationError) as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise HubError("not_found", "Resource not found", 404) from exc
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def update_human_membership(
        self,
        claims: AccessClaims,
        team_id: str,
        principal_id: str,
        *,
        role: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        try:
            principal_id = _identity(principal_id)
        except ValueError as exc:
            raise HubError("not_found", "Resource not found", 404) from exc
        if (role is None) == (status is None):
            raise HubError(
                "invalid_request",
                "Exactly one membership change is required",
                422,
            )
        if role is not None and role not in {"admin", "member", "guest"}:
            raise HubError("invalid_request", "Membership role is invalid", 422)
        if status is not None and status not in {"active", "suspended", "revoked"}:
            raise HubError("invalid_request", "Membership status is invalid", 422)

        timestamp = _now()
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_session(connection, claims, timestamp)
                team_id = self._require_team_owner_for_human_administration(
                    connection, claims, team_id
                )
                target = connection.execute(
                    """
                    SELECT m.role,m.status,p.kind,p.display_name,h.email_normalized
                    FROM memberships AS m
                    JOIN principals AS p ON p.id=m.principal_id
                    LEFT JOIN human_accounts AS h ON h.principal_id=p.id
                    WHERE m.team_id=? AND m.principal_id=?
                    """,
                    (team_id, principal_id),
                ).fetchone()
                if (
                    target is None
                    or principal_id == claims.principal_id
                    or target["kind"] != "human"
                    or target["role"] in {"owner", "automation"}
                ):
                    raise HubError("not_found", "Resource not found", 404)
                old_role = str(target["role"])
                old_status = str(target["status"])
                if old_status == "revoked":
                    raise HubError(
                        "membership_terminal",
                        "Membership has been permanently revoked",
                        409,
                    )
                if role is not None:
                    if old_status != "active":
                        raise HubError(
                            "membership_not_active",
                            "Membership must be active before changing role",
                            409,
                        )
                    connection.execute(
                        "UPDATE memberships SET role=?,updated_at=? "
                        "WHERE team_id=? AND principal_id=?",
                        (role, timestamp, team_id, principal_id),
                    )
                    action = "membership.role_change"
                    metadata = {"old_role": old_role, "new_role": role}
                    new_role = role
                    new_status = old_status
                else:
                    assert status is not None
                    if old_status == "active" and status not in {"active", "suspended", "revoked"}:
                        raise HubError("invalid_membership_transition", "Membership transition is invalid", 409)
                    if old_status == "suspended" and status not in {"active", "suspended", "revoked"}:
                        raise HubError("invalid_membership_transition", "Membership transition is invalid", 409)
                    connection.execute(
                        "UPDATE memberships SET status=?,updated_at=? "
                        "WHERE team_id=? AND principal_id=?",
                        (status, timestamp, team_id, principal_id),
                    )
                    action = "membership.status_change"
                    metadata = {"old_status": old_status, "new_status": status}
                    new_role = old_role
                    new_status = status
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    action,
                    "membership",
                    principal_id,
                    "succeeded",
                    metadata,
                    timestamp,
                )
                return {
                    "member": {
                        "principal_id": principal_id,
                        "email": target["email_normalized"],
                        "display_name": str(target["display_name"]),
                        "role": new_role,
                        "status": new_status,
                    }
                }
        finally:
            connection.close()

    def issue_invite(
        self,
        claims: AccessClaims,
        team_id: str,
        invitee_email: str,
        role: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        timestamp = _now()
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_session(connection, claims, timestamp)
                issued = issue_invitation(
                    connection,
                    team_id,
                    claims.principal_id,
                    role,
                    invitee_email=invitee_email,
                    ttl_seconds=ttl_seconds,
                    now=timestamp,
                )
                normalized = _email(invitee_email)
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "invitation.issue",
                    "invitation",
                    issued.id,
                    "succeeded",
                    {"role": role},
                    timestamp,
                )
                return {
                    "invitation": {
                        "id": issued.id,
                        "team_id": team_id,
                        "invitee_email": normalized,
                        "role": role,
                        "expires_at": _iso8601(issued.expires_at),
                    },
                    "token": issued.token,
                }
        except AuthorizationError as exc:
            raise HubError("forbidden", "Operation is not permitted", 403) from exc
        finally:
            connection.close()

    def redeem_invite(
        self,
        invite_token: str,
        email: str,
        display_name: str,
        device_label: str,
    ) -> dict[str, Any]:
        timestamp = _now()
        normalized_email = _email(email)
        try:
            digest = _token_digest(invite_token)
        except (AuthenticationError, UnicodeError) as exc:
            raise HubError("invitation_unavailable", "Invitation is unavailable", 403) from exc
        connection = self.connect()
        try:
            with _write_transaction(connection):
                invitation = connection.execute(
                    """
                    SELECT id, team_id, invitee_email_normalized
                    FROM invitations
                    WHERE token_hash = ? AND redeemed_at IS NULL AND revoked_at IS NULL
                      AND expires_at > ?
                    """,
                    (digest, timestamp),
                ).fetchone()
                if (
                    invitation is None
                    or invitation["invitee_email_normalized"] is None
                    or str(invitation["invitee_email_normalized"]) != normalized_email
                ):
                    raise HubError("invitation_unavailable", "Invitation is unavailable", 403)
                human = connection.execute(
                    "SELECT principal_id FROM human_accounts WHERE email_normalized = ?",
                    (normalized_email,),
                ).fetchone()
                if human is not None:
                    raise HubError(
                        "invitation_requires_authentication",
                        "Sign in to accept this invitation",
                        409,
                    )
                principal_id = _id("human")
                name = _bounded_text(display_name, "display_name", 1, 160)
                connection.execute(
                    """
                    INSERT INTO principals(id, kind, display_name, created_at, updated_at)
                    VALUES (?, 'human', ?, ?, ?)
                    """,
                    (principal_id, name, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO human_accounts(principal_id, email_normalized, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (principal_id, normalized_email, timestamp),
                )
                membership_id = redeem_invitation(
                    connection, invite_token, principal_id, now=timestamp
                )
                session, refresh, refresh_exp = self._create_session(
                    connection, principal_id, device_label, timestamp
                )
                self._audit(
                    connection,
                    str(invitation["team_id"]),
                    principal_id,
                    "invitation.redeem",
                    "membership",
                    membership_id,
                    "succeeded",
                    {},
                    timestamp,
                )
                return self._auth_bundle(connection, session, refresh, refresh_exp, timestamp)
        except (AuthenticationError, AuthorizationError) as exc:
            raise HubError("invitation_unavailable", "Invitation is unavailable", 403) from exc
        finally:
            connection.close()

    def accept_invite(self, claims: AccessClaims, invite_token: str) -> dict[str, Any]:
        timestamp = _now()
        try:
            digest = _token_digest(invite_token)
        except (AuthenticationError, UnicodeError) as exc:
            raise HubError("invitation_unavailable", "Invitation is unavailable", 403) from exc
        connection = self.connect()
        try:
            with _write_transaction(connection):
                session = self._require_session(connection, claims, timestamp)
                invitation = connection.execute(
                    """
                    SELECT team_id, invitee_email_normalized, role
                    FROM invitations
                    WHERE token_hash = ? AND redeemed_at IS NULL AND revoked_at IS NULL
                      AND expires_at > ?
                    """,
                    (digest, timestamp),
                ).fetchone()
                if (
                    invitation is None
                    or invitation["invitee_email_normalized"] is None
                    or str(invitation["invitee_email_normalized"])
                    != str(session["email_normalized"])
                ):
                    raise HubError("invitation_unavailable", "Invitation is unavailable", 403)
                membership_id = redeem_invitation(
                    connection, invite_token, claims.principal_id, now=timestamp
                )
                membership = connection.execute(
                    """
                    SELECT id, team_id, principal_id, role, status
                    FROM memberships WHERE id = ?
                    """,
                    (membership_id,),
                ).fetchone()
                assert membership is not None
                self._audit(
                    connection,
                    str(invitation["team_id"]),
                    claims.principal_id,
                    "invitation.accept",
                    "membership",
                    membership_id,
                    "succeeded",
                    {},
                    timestamp,
                )
                return {
                    "membership": _row_dict(membership),
                    "teams": self._teams_for(connection, claims.principal_id),
                }
        except (AuthenticationError, AuthorizationError) as exc:
            raise HubError("invitation_unavailable", "Invitation is unavailable", 403) from exc
        finally:
            connection.close()

    def issue_owner_recovery(
        self,
        email: str,
        device_label: str,
        *,
        team_id: str | None = None,
        now: int | None = None,
    ) -> Path:
        """Compatibility wrapper restricted to an active owner membership."""

        return self.issue_device_recovery(
            email,
            device_label,
            team_id=team_id,
            require_owner=True,
            now=now,
        )

    def issue_device_recovery(
        self,
        email: str,
        device_label: str,
        *,
        team_id: str | None = None,
        require_owner: bool = False,
        now: int | None = None,
    ) -> Path:
        """Issue a host-control recovery proof for one existing human principal."""

        timestamp = _now(now)
        normalized = _email(email)
        label = _bounded_text(device_label, "device_label", 1, 160)
        connection = self.connect()
        proof_path: Path | None = None
        superseded_ids: list[str] = []
        try:
            with _write_transaction(connection):
                role_clause = "AND m.role = 'owner'" if require_owner else ""
                memberships = connection.execute(
                    f"""
                    SELECT m.team_id, m.principal_id
                    FROM memberships AS m
                    JOIN human_accounts AS h ON h.principal_id = m.principal_id
                    JOIN principals AS p ON p.id = m.principal_id
                    WHERE h.email_normalized = ?
                      AND m.status = 'active' AND p.status = 'active'
                      AND (? IS NULL OR m.team_id = ?)
                      {role_clause}
                    """,
                    (normalized, team_id, team_id),
                ).fetchall()
                if len(memberships) != 1:
                    raise HubError("recovery_unavailable", "Device recovery is unavailable", 409)
                principal_id = str(memberships[0]["principal_id"])
                revoked_session_count = int(
                    connection.execute(
                        """
                        SELECT count(*) FROM device_sessions
                        WHERE human_principal_id = ? AND revoked_at IS NULL
                        """,
                        (principal_id,),
                    ).fetchone()[0]
                )
                # Issuing recovery is the host operator's lost-device action.
                # Revoke the old authority in this same transaction so the
                # compromised device does not stay live while the replacement
                # proof is transported (or if that proof is never redeemed).
                connection.execute(
                    """
                    UPDATE device_sessions SET revoked_at = ?
                    WHERE human_principal_id = ? AND revoked_at IS NULL
                    """,
                    (timestamp, principal_id),
                )
                connection.execute(
                    """
                    UPDATE refresh_tokens SET revoked_at = ?
                    WHERE consumed_at IS NULL AND revoked_at IS NULL
                      AND device_session_id IN (
                        SELECT id FROM device_sessions
                        WHERE human_principal_id = ?
                      )
                    """,
                    (timestamp, principal_id),
                )
                superseded_ids = [
                    str(row["id"])
                    for row in connection.execute(
                        """
                        SELECT id FROM owner_recovery_claims
                        WHERE owner_principal_id = ? AND consumed_at IS NULL
                          AND revoked_at IS NULL
                        """,
                        (principal_id,),
                    )
                ]
                connection.execute(
                    """
                    UPDATE owner_recovery_claims SET revoked_at = ?
                    WHERE owner_principal_id = ? AND consumed_at IS NULL
                      AND revoked_at IS NULL
                    """,
                    (timestamp, principal_id),
                )
                proof, digest = opaque_secret("owner-recovery")
                claim_id = _id("owner_recovery")
                proof_path = self.data_dir / f"{claim_id}.proof"
                create_secret_file(proof_path, (proof + "\n").encode("ascii"))
                connection.execute(
                    """
                    INSERT INTO owner_recovery_claims(
                        id, team_id, owner_principal_id, token_hash,
                        device_label, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_id,
                        memberships[0]["team_id"],
                        principal_id,
                        digest,
                        label,
                        timestamp,
                        timestamp + RECOVERY_PROOF_TTL_SECONDS,
                    ),
                )
                local_control_id = self._local_control_principal(
                    connection, str(memberships[0]["team_id"]), timestamp
                )
                self._audit(
                    connection,
                    str(memberships[0]["team_id"]),
                    local_control_id,
                    "device_recovery.issue",
                    "device_recovery",
                    claim_id,
                    "accepted",
                    {
                        "authority": "local_host_recovery",
                        "subject_principal_id": principal_id,
                        "revoked_session_count": revoked_session_count,
                    },
                    timestamp,
                )
            for superseded_id in superseded_ids:
                try:
                    (self.data_dir / f"{superseded_id}.proof").unlink(missing_ok=True)
                except OSError:
                    pass
            return proof_path
        except BaseException:
            if proof_path is not None:
                try:
                    proof_path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
        finally:
            connection.close()

    def redeem_owner_recovery(self, proof: str, device_label: str) -> dict[str, Any]:
        return self.redeem_device_recovery(proof, device_label)

    def redeem_device_recovery(self, proof: str, device_label: str) -> dict[str, Any]:
        timestamp = _now()
        try:
            digest = token_hash(proof)
        except TokenError as exc:
            raise HubError("recovery_unavailable", "Device recovery is unavailable", 403) from exc
        label = _bounded_text(device_label, "device_label", 1, 160)
        connection = self.connect()
        claim_id = ""
        try:
            with _write_transaction(connection):
                claim = connection.execute(
                    """
                    SELECT c.id, c.team_id, c.owner_principal_id, c.token_hash,
                           c.device_label
                    FROM owner_recovery_claims AS c
                    JOIN memberships AS m
                      ON m.team_id = c.team_id AND m.principal_id = c.owner_principal_id
                    JOIN principals AS p ON p.id = c.owner_principal_id
                    WHERE c.token_hash = ? AND c.consumed_at IS NULL
                      AND c.revoked_at IS NULL AND c.expires_at > ?
                      AND m.status = 'active' AND p.status = 'active'
                    """,
                    (digest, timestamp),
                ).fetchone()
                if (
                    claim is None
                    or not hmac.compare_digest(claim["token_hash"], digest)
                    or str(claim["device_label"]) != label
                ):
                    raise HubError("recovery_unavailable", "Device recovery is unavailable", 403)
                prior_session_count = int(
                    connection.execute(
                        """
                        SELECT count(*) FROM device_sessions
                        WHERE human_principal_id = ? AND revoked_at IS NULL
                        """,
                        (claim["owner_principal_id"],),
                    ).fetchone()[0]
                )
                connection.execute(
                    """
                    UPDATE device_sessions SET revoked_at = ?
                    WHERE human_principal_id = ? AND revoked_at IS NULL
                    """,
                    (timestamp, claim["owner_principal_id"]),
                )
                connection.execute(
                    """
                    UPDATE refresh_tokens SET revoked_at = ?
                    WHERE consumed_at IS NULL AND revoked_at IS NULL
                      AND device_session_id IN (
                        SELECT id FROM device_sessions WHERE human_principal_id = ?
                      )
                    """,
                    (timestamp, claim["owner_principal_id"]),
                )
                session, refresh, refresh_exp = self._create_session(
                    connection, str(claim["owner_principal_id"]), label, timestamp
                )
                claim_id = str(claim["id"])
                changed = connection.execute(
                    """
                    UPDATE owner_recovery_claims
                    SET consumed_at = ?, consumed_by_session_id = ?
                    WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL
                      AND expires_at > ?
                    """,
                    (timestamp, session["id"], claim_id, timestamp),
                ).rowcount
                if changed != 1:
                    raise HubError("recovery_unavailable", "Device recovery is unavailable", 403)
                local_control_id = self._local_control_principal(
                    connection, str(claim["team_id"]), timestamp
                )
                self._audit(
                    connection,
                    str(claim["team_id"]),
                    local_control_id,
                    "device_recovery.redeem",
                    "device_session",
                    str(session["id"]),
                    "succeeded",
                    {
                        "authority": "local_host_recovery",
                        "subject_principal_id": str(claim["owner_principal_id"]),
                        "revoked_prior_session_count": prior_session_count,
                    },
                    timestamp,
                )
                bundle = self._auth_bundle(connection, session, refresh, refresh_exp, timestamp)
            try:
                (self.data_dir / f"{claim_id}.proof").unlink(missing_ok=True)
            except OSError:
                pass
            return bundle
        finally:
            connection.close()

    def issue_node_grant(
        self,
        claims: AccessClaims,
        team_id: str,
        server_identity: str,
        display_name: str,
        public_key: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        timestamp = _now()
        identity = _identity(server_identity)
        name = _bounded_text(display_name, "display_name", 1, 160)
        canonical_key, fingerprint = _canonical_ed25519_public_key(public_key)
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_session(connection, claims, timestamp)
                _require_team_role(
                    connection, team_id, claims.principal_id, ("owner", "admin")
                )
                collision = connection.execute(
                    """
                    SELECT 1
                    FROM node_enrollment_bindings AS b
                    JOIN node_enrollment_grants AS g ON g.id = b.grant_id
                    WHERE b.team_id = ? AND b.expected_server_identity = ?
                      AND g.consumed_at IS NULL AND g.revoked_at IS NULL
                      AND g.expires_at > ?
                    """,
                    (team_id, identity, timestamp),
                ).fetchone()
                if collision is not None:
                    raise HubError("enrollment_conflict", "A live enrollment already exists", 409)
                existing_node = connection.execute(
                    "SELECT 1 FROM nodes WHERE server_identity = ?",
                    (identity,),
                ).fetchone()
                if existing_node is not None:
                    raise HubError("enrollment_conflict", "Server identity is already enrolled", 409)
                legacy = connection.execute(
                    """
                    SELECT team_id, node_id FROM legacy_server_bindings
                    WHERE server_identity = ?
                    """,
                    (identity,),
                ).fetchone()
                if legacy is not None and (
                    str(legacy["team_id"]) != team_id or legacy["node_id"] is not None
                ):
                    raise HubError("enrollment_conflict", "Server identity is unavailable", 409)
                issued = issue_node_enrollment(
                    connection,
                    team_id,
                    claims.principal_id,
                    ttl_seconds=ttl_seconds,
                    now=timestamp,
                )
                connection.execute(
                    """
                    INSERT INTO node_enrollment_bindings(
                        grant_id, team_id, expected_server_identity,
                        expected_display_name, expected_public_material,
                        expected_public_key_fingerprint, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        issued.id,
                        team_id,
                        identity,
                        name,
                        canonical_key,
                        fingerprint,
                        timestamp,
                    ),
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "node_enrollment.issue",
                    "node_enrollment",
                    issued.id,
                    "succeeded",
                    {"server_identity": identity, "fingerprint": fingerprint.hex()},
                    timestamp,
                )
                return {
                    "enrollment": {
                        "id": issued.id,
                        "team_id": team_id,
                        "server_identity": identity,
                        "display_name": name,
                        "public_key_fingerprint": fingerprint.hex(),
                        "expires_at": _iso8601(issued.expires_at),
                    },
                    "token": issued.token,
                }
        except AuthorizationError as exc:
            raise HubError("forbidden", "Operation is not permitted", 403) from exc
        finally:
            connection.close()

    def node_challenge(
        self, grant_token: str, server_identity: str, display_name: str, public_key: str
    ) -> dict[str, Any]:
        timestamp = _now()
        try:
            digest = _token_digest(grant_token)
        except (AuthenticationError, UnicodeError) as exc:
            raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403) from exc
        identity = _identity(server_identity)
        name = _bounded_text(display_name, "display_name", 1, 160)
        canonical_key, fingerprint = _canonical_ed25519_public_key(public_key)
        connection = self.connect()
        try:
            with _write_transaction(connection):
                grant = connection.execute(
                    """
                    SELECT g.id, g.team_id, g.token_hash, g.expires_at,
                           b.expected_server_identity, b.expected_display_name,
                           b.expected_public_material, b.expected_public_key_fingerprint
                    FROM node_enrollment_grants AS g
                    JOIN node_enrollment_bindings AS b
                      ON b.grant_id = g.id AND b.team_id = g.team_id
                    JOIN memberships AS issuer
                      ON issuer.team_id = g.team_id
                     AND issuer.principal_id = g.issued_by_principal_id
                    JOIN principals AS issuer_principal ON issuer_principal.id = issuer.principal_id
                    WHERE g.token_hash = ? AND g.consumed_at IS NULL
                      AND g.revoked_at IS NULL AND g.expires_at > ?
                      AND issuer.status = 'active' AND issuer.role IN ('owner', 'admin')
                      AND issuer_principal.status = 'active'
                    """,
                    (digest, timestamp),
                ).fetchone()
                if grant is None or not hmac.compare_digest(grant["token_hash"], digest):
                    raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403)
                if (
                    str(grant["expected_server_identity"]) != identity
                    or str(grant["expected_display_name"]) != name
                    or str(grant["expected_public_material"]) != canonical_key
                    or not hmac.compare_digest(grant["expected_public_key_fingerprint"], fingerprint)
                ):
                    raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403)
                existing = connection.execute(
                    "SELECT * FROM node_enrollment_challenges WHERE grant_id = ?",
                    (grant["id"],),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["consumed_at"] is None
                        and existing["revoked_at"] is None
                        and int(existing["expires_at"]) > timestamp
                        and hmac.compare_digest(existing["public_key_fingerprint"], fingerprint)
                    ):
                        payload = str(existing["signing_payload"])
                        payload_data = json.loads(payload.split("\n", 1)[1])
                        return {
                            "challenge_id": existing["id"],
                            "nonce": payload_data["nonce"],
                            "expires_at": _iso8601(existing["expires_at"]),
                            "signing_payload": payload,
                        }
                    raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403)
                challenge_id = _id("node_challenge")
                nonce = secrets.token_urlsafe(32)
                expires_at = min(timestamp + NODE_CHALLENGE_TTL_SECONDS, int(grant["expires_at"]))
                payload_data = {
                    "challenge_id": challenge_id,
                    "grant_id": grant["id"],
                    "team_id": grant["team_id"],
                    "server_identity": identity,
                    "public_key_fingerprint": fingerprint.hex(),
                    "nonce": nonce,
                    "expires_at": expires_at,
                }
                signing_payload = (
                    "AgentsDock-Team-Hub-Node-Enrollment-v1\n"
                    + canonical_json(payload_data).decode("utf-8")
                )
                connection.execute(
                    """
                    INSERT INTO node_enrollment_challenges(
                        id, grant_id, team_id, public_material,
                        public_key_fingerprint, nonce_hash, signing_payload,
                        created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        challenge_id,
                        grant["id"],
                        grant["team_id"],
                        canonical_key,
                        fingerprint,
                        hashlib.sha256(nonce.encode("ascii")).digest(),
                        signing_payload,
                        timestamp,
                        expires_at,
                    ),
                )
                return {
                    "challenge_id": challenge_id,
                    "nonce": nonce,
                    "expires_at": _iso8601(expires_at),
                    "signing_payload": signing_payload,
                }
        finally:
            connection.close()

    def redeem_node_challenge(self, challenge_id: str, signature: str) -> dict[str, Any]:
        timestamp = _now()
        try:
            signature_bytes = base64.b64decode(signature.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as exc:
            raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403) from exc
        if len(signature_bytes) != 64:
            raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403)
        connection = self.connect()
        try:
            with _write_transaction(connection):
                row = connection.execute(
                    """
                    SELECT c.*, b.expected_server_identity, b.expected_display_name,
                           b.expected_public_material, b.expected_public_key_fingerprint,
                           g.token_hash, g.expires_at AS grant_expires_at,
                           g.consumed_at AS grant_consumed_at, g.revoked_at AS grant_revoked_at,
                           g.issued_by_principal_id
                    FROM node_enrollment_challenges AS c
                    JOIN node_enrollment_bindings AS b
                      ON b.grant_id = c.grant_id AND b.team_id = c.team_id
                    JOIN node_enrollment_grants AS g
                      ON g.id = c.grant_id AND g.team_id = c.team_id
                    JOIN memberships AS issuer
                      ON issuer.team_id = g.team_id
                     AND issuer.principal_id = g.issued_by_principal_id
                    JOIN principals AS issuer_principal ON issuer_principal.id = issuer.principal_id
                    WHERE c.id = ? AND c.consumed_at IS NULL AND c.revoked_at IS NULL
                      AND c.expires_at > ? AND g.expires_at > ?
                      AND g.consumed_at IS NULL AND g.revoked_at IS NULL
                      AND issuer.status = 'active' AND issuer.role IN ('owner', 'admin')
                      AND issuer_principal.status = 'active'
                    """,
                    (challenge_id, timestamp, timestamp),
                ).fetchone()
                if row is None:
                    raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403)
                legacy = connection.execute(
                    """
                    SELECT team_id, node_id FROM legacy_server_bindings
                    WHERE server_identity = ?
                    """,
                    (row["expected_server_identity"],),
                ).fetchone()
                if legacy is not None and (
                    str(legacy["team_id"]) != str(row["team_id"])
                    or legacy["node_id"] is not None
                ):
                    raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403)
                if (
                    str(row["public_material"]) != str(row["expected_public_material"])
                    or not hmac.compare_digest(
                        row["public_key_fingerprint"], row["expected_public_key_fingerprint"]
                    )
                ):
                    raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403)
                try:
                    key = serialization.load_ssh_public_key(
                        str(row["public_material"]).encode("ascii")
                    )
                    if not isinstance(key, Ed25519PublicKey):
                        raise ValueError("not Ed25519")
                    key.verify(signature_bytes, str(row["signing_payload"]).encode("utf-8"))
                except Exception as exc:
                    raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403) from exc
                if legacy is None:
                    connection.execute(
                        """
                        INSERT INTO legacy_server_bindings(
                            id, team_id, server_identity, node_id, created_at
                        ) VALUES (?, ?, ?, NULL, ?)
                        """,
                        (
                            _id("legacy_binding"),
                            row["team_id"],
                            row["expected_server_identity"],
                            timestamp,
                        ),
                    )
                principal_id = _id("node_principal")
                node_id = _id("node")
                credential_id = _id("node_credential")
                connection.execute(
                    """
                    INSERT INTO principals(
                        id, kind, scope_team_id, display_name, created_at, updated_at
                    ) VALUES (?, 'node', ?, ?, ?, ?)
                    """,
                    (
                        principal_id,
                        row["team_id"],
                        row["expected_display_name"],
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO nodes(
                        id, team_id, principal_id, server_identity,
                        display_name, enrolled_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        node_id,
                        row["team_id"],
                        principal_id,
                        row["expected_server_identity"],
                        row["expected_display_name"],
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO node_credentials(
                        id, team_id, node_id, credential_kind, public_material,
                        fingerprint_sha256, created_at
                    ) VALUES (?, ?, ?, 'ed25519', ?, ?, ?)
                    """,
                    (
                        credential_id,
                        row["team_id"],
                        node_id,
                        row["public_material"],
                        row["public_key_fingerprint"],
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    UPDATE legacy_server_bindings SET node_id = ?
                    WHERE team_id = ? AND server_identity = ? AND node_id IS NULL
                    """,
                    (node_id, row["team_id"], row["expected_server_identity"]),
                )
                grant_changed = connection.execute(
                    """
                    UPDATE node_enrollment_grants
                    SET consumed_at = ?, consumed_by_node_id = ?
                    WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL
                      AND expires_at > ?
                    """,
                    (timestamp, node_id, row["grant_id"], timestamp),
                ).rowcount
                challenge_changed = connection.execute(
                    """
                    UPDATE node_enrollment_challenges SET consumed_at = ?
                    WHERE id = ? AND consumed_at IS NULL AND revoked_at IS NULL
                      AND expires_at > ?
                    """,
                    (timestamp, challenge_id, timestamp),
                ).rowcount
                if grant_changed != 1 or challenge_changed != 1:
                    raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403)
                self._audit(
                    connection,
                    str(row["team_id"]),
                    principal_id,
                    "node.enroll",
                    "node",
                    node_id,
                    "succeeded",
                    {"server_identity": row["expected_server_identity"]},
                    timestamp,
                    node_id=node_id,
                )
                return {
                    "node": {
                        "id": node_id,
                        "team_id": row["team_id"],
                        "server_identity": row["expected_server_identity"],
                        "display_name": row["expected_display_name"],
                        "status": "active",
                        "enrolled_at": _iso8601(timestamp),
                        "last_seen_at": None,
                        "public_key_fingerprint": row["public_key_fingerprint"].hex(),
                    }
                }
        except sqlite3.IntegrityError as exc:
            raise HubError("enrollment_unavailable", "Enrollment is unavailable", 403) from exc
        finally:
            connection.close()

    def list_nodes(self, claims: AccessClaims, team_id: str) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_session(connection, claims, _now())
            _require_team_role(
                connection,
                team_id,
                claims.principal_id,
                ("owner", "admin"),
            )
            nodes = [
                {
                    **_row_dict(row),
                    "public_key_fingerprint": row["public_key_fingerprint"].hex(),
                    "enrolled_at": _iso8601(row["enrolled_at"]),
                    "last_seen_at": _iso8601(row["last_seen_at"]),
                }
                for row in connection.execute(
                    """
                    SELECT n.id, n.team_id, n.server_identity, n.display_name,
                           n.status, n.enrolled_at, n.last_seen_at,
                           c.fingerprint_sha256 AS public_key_fingerprint
                    FROM nodes AS n
                    JOIN node_credentials AS c
                      ON c.team_id = n.team_id AND c.node_id = n.id
                     AND c.revoked_at IS NULL
                    WHERE n.team_id = ?
                    ORDER BY n.display_name COLLATE NOCASE, n.id
                    """,
                    (team_id,),
                )
            ]
            connection.execute("COMMIT")
            return {"nodes": nodes}
        except (AuthorizationError, AuthenticationError) as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise HubError("not_found", "Resource not found", 404) from exc
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def require_team_admin(
        self,
        claims: AccessClaims,
        team_id: str,
    ) -> dict[str, str]:
        """Prove a live owner/admin session without leaking team existence."""

        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_session(connection, claims, _now())
            membership = _require_team_role(
                connection,
                team_id,
                claims.principal_id,
                ("owner", "admin"),
            )
            connection.execute("COMMIT")
            return {
                "team_id": team_id,
                "principal_id": claims.principal_id,
                "role": str(membership["role"]),
            }
        except (AuthorizationError, AuthenticationError) as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise HubError("not_found", "Resource not found", 404) from exc
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def require_team_owner(
        self,
        claims: AccessClaims,
        team_id: str,
    ) -> dict[str, str]:
        """Prove a live owner session without leaking team existence.

        Unassigned inbound peer-pairing requests are host-global until an
        owner deliberately binds one to a team.  Team administrators must not
        be able to inspect or claim that global queue merely by choosing a
        team id they administer.
        """

        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_session(connection, claims, _now())
            membership = _require_team_role(
                connection,
                team_id,
                claims.principal_id,
                ("owner",),
            )
            connection.execute("COMMIT")
            return {
                "team_id": team_id,
                "principal_id": claims.principal_id,
                "role": str(membership["role"]),
            }
        except (AuthorizationError, AuthenticationError) as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise HubError("not_found", "Resource not found", 404) from exc
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _channel_permission(
        connection: sqlite3.Connection,
        channel: sqlite3.Row,
        principal_id: str,
        permission: str,
    ) -> bool:
        membership = connection.execute(
            """
            SELECT m.role
            FROM memberships AS m
            JOIN principals AS p ON p.id = m.principal_id
            WHERE m.team_id = ? AND m.principal_id = ?
              AND m.status = 'active' AND p.status = 'active'
            """,
            (channel["team_id"], principal_id),
        ).fetchone()
        if membership is None:
            return False
        if channel["kind"] == "direct":
            participants = [
                str(row["principal_id"])
                for row in connection.execute(
                    """
                    SELECT principal_id FROM channel_participants
                    WHERE channel_id = ? AND status = 'active' ORDER BY principal_id
                    """,
                    (channel["id"],),
                )
            ]
            expected_pair = (
                hashlib.sha256("\0".join(participants).encode("utf-8")).digest()
                if len(participants) == 2
                else b""
            )
            if (
                len(participants) != 2
                or principal_id not in participants
                or not hmac.compare_digest(channel["direct_pair_key"], expected_pair)
            ):
                return False
        column = {
            "read": "can_read",
            "post": "can_post",
            "manage": "can_manage",
            "dispatch": "can_dispatch",
        }.get(permission)
        if column is None:
            return False
        explicit = connection.execute(
            f"""
            SELECT {column} AS allowed FROM channel_acl_entries
            WHERE channel_id = ? AND subject_kind = 'principal'
              AND subject_principal_id = ?
            """,
            (channel["id"], principal_id),
        ).fetchone()
        if explicit is not None:
            return bool(explicit["allowed"])
        role_acl = connection.execute(
            f"""
            SELECT {column} AS allowed FROM channel_acl_entries
            WHERE channel_id = ? AND subject_kind = 'role' AND subject_role = ?
            """,
            (channel["id"], membership["role"]),
        ).fetchone()
        if role_acl is not None:
            return bool(role_acl["allowed"])
        return False

    def _channel_dict(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        principal_id: str | None = None,
    ) -> dict[str, Any]:
        participants = [
            str(item["principal_id"])
            for item in connection.execute(
                """
                SELECT principal_id FROM channel_participants
                WHERE channel_id = ? AND status = 'active'
                ORDER BY principal_id
                """,
                (row["id"],),
            )
        ]
        result = {
            "id": row["id"],
            "team_id": row["team_id"],
            "kind": row["kind"],
            "visibility": row["visibility"],
            "slug": row["slug"],
            "display_name": row["display_name"],
            "created_by_principal_id": row["created_by_principal_id"],
            "created_at": _iso8601(row["created_at"]),
            "updated_at": _iso8601(row["updated_at"]),
            "archived_at": _iso8601(row["archived_at"]),
            "participants": participants,
        }
        if principal_id is not None:
            result["permissions"] = {
                permission: self._channel_permission(
                    connection, row, principal_id, permission
                )
                for permission in ("read", "post", "manage", "dispatch")
            }
        return result

    @staticmethod
    def _idempotency_lookup(
        connection: sqlite3.Connection,
        team_id: str,
        principal_id: str,
        operation: str,
        key: str,
        fingerprint: bytes,
    ) -> dict[str, Any] | None:
        if not 8 <= len(key) <= 240:
            raise HubError("invalid_request", "idempotency_key must be 8-240 characters", 422)
        try:
            key_digest = hashlib.sha256(key.encode("utf-8")).digest()
        except UnicodeEncodeError as exc:
            raise HubError("invalid_request", "idempotency_key is invalid", 422) from exc
        row = connection.execute(
            """
            SELECT request_fingerprint, response_json
            FROM request_idempotency
            WHERE team_id = ? AND principal_id = ? AND operation = ? AND key_hash = ?
            """,
            (team_id, principal_id, operation, key_digest),
        ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(row["request_fingerprint"], fingerprint):
            raise HubError(
                "idempotency_conflict",
                "Idempotency key was already used with a different request",
                409,
            )
        return json.loads(str(row["response_json"]))

    @staticmethod
    def _idempotency_store(
        connection: sqlite3.Connection,
        team_id: str,
        principal_id: str,
        operation: str,
        key: str,
        fingerprint: bytes,
        resource_type: str,
        resource_id: str,
        response: dict[str, Any],
        timestamp: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO request_idempotency(
                id, team_id, principal_id, operation, key_hash,
                request_fingerprint, resource_type, resource_id,
                response_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _id("idempotency"),
                team_id,
                principal_id,
                operation,
                hashlib.sha256(key.encode("utf-8")).digest(),
                fingerprint,
                resource_type,
                resource_id,
                canonical_json(response).decode("utf-8"),
                timestamp,
            ),
        )

    @staticmethod
    def _require_network_scope(
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
        *,
        write: bool,
    ) -> sqlite3.Row:
        HubStore._require_session(connection, claims, _now())
        if claims.auth_kind in NETWORK_AUTOMATION_AUTH_KINDS:
            expected_scope = "teamspace.write" if write else "teamspace.read"
            if claims.team_id != team_id or expected_scope not in claims.scopes:
                raise HubError("forbidden", "Operation is not permitted", 403)
            roles = ("automation",)
        else:
            roles = (
                ("owner", "admin", "member")
                if write
                else ("owner", "admin", "member", "guest")
            )
        try:
            return _require_team_role(
                connection, team_id, claims.principal_id, roles
            )
        except (AuthorizationError, AuthenticationError) as exc:
            raise HubError("not_found", "Resource not found", 404) from exc

    @staticmethod
    def _bound_network_node(
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
    ) -> sqlite3.Row:
        if claims.auth_kind != "secure_peer" or claims.peer_id is None:
            raise HubError(
                "network_peer_required",
                "A bound server connection is required",
                403,
            )
        row = connection.execute(
            """
            SELECT b.node_id,n.principal_id,n.server_identity,n.display_name,n.status
            FROM network_peer_bindings AS b
            JOIN nodes AS n ON n.team_id=b.team_id AND n.id=b.node_id
            WHERE b.peer_id=? AND b.team_id=?
              AND b.service_principal_id=? AND b.status='active'
              AND n.status='active'
            """,
            (claims.peer_id, team_id, claims.principal_id),
        ).fetchone()
        if row is None:
            raise HubError(
                "network_peer_unavailable",
                "Bound server identity is unavailable",
                403,
            )
        return row

    def _caller_network_node(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
    ) -> sqlite3.Row:
        """Resolve the one logical server this authenticated caller controls.

        An incoming secure peer is fenced by its durable certificate binding.
        An ordinary Team Hub session acts only for this installation's
        designated managed host, never for another server listed in the team.
        """

        if claims.auth_kind == "secure_peer":
            return self._bound_network_node(connection, claims, team_id)
        try:
            _require_team_role(
                connection,
                team_id,
                claims.principal_id,
                (
                    ("automation",)
                    if claims.auth_kind in MANAGED_HOST_AUTH_KINDS
                    else ("owner", "admin", "member")
                ),
            )
        except (AuthorizationError, AuthenticationError) as exc:
            raise HubError("not_found", "Resource not found", 404) from exc
        if self.managed_host_identity is None:
            raise HubError(
                "network_host_unavailable",
                "Designated host server identity is unavailable",
                409,
            )
        row = connection.execute(
            """
            SELECT n.id AS node_id,n.principal_id,n.server_identity,
                   n.display_name,n.status
            FROM nodes AS n
            JOIN principals AS p ON p.id=n.principal_id
            WHERE n.team_id=? AND n.server_identity=?
              AND n.status='active' AND p.status='active'
            """,
            (team_id, self.managed_host_identity),
        ).fetchone()
        if row is None:
            raise HubError(
                "network_host_unavailable",
                "Designated host server identity is unavailable",
                409,
            )
        return row

    @staticmethod
    def _agent_public(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "server_id": row["node_id"],
            "external_agent_id": row["external_agent_id"],
            "backend": row["backend"],
            "display_name": row["display_name"],
            "status": row["status"],
        }

    def get_network(
        self,
        claims: AccessClaims,
        team_id: str,
        *,
        after_server_id: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        if type(limit) is not int or not 1 <= limit <= MAX_NETWORK_PAGE_ITEMS:
            raise HubError("invalid_request", "Network page limit is invalid", 422)
        bounded_limit = limit
        clean_after: str | None = None
        if after_server_id is not None:
            try:
                clean_after = _identity(after_server_id)
            except (AttributeError, TypeError, ValueError) as exc:
                raise HubError(
                    "invalid_request", "Network page cursor is invalid", 422
                ) from exc
            if clean_after != after_server_id:
                raise HubError(
                    "invalid_request", "Network page cursor is invalid", 422
                )
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            membership = self._require_network_scope(
                connection, claims, team_id, write=False
            )
            team = connection.execute(
                "SELECT id,display_name FROM teams WHERE id=?",
                (team_id,),
            ).fetchone()
            if team is None:
                raise HubError("not_found", "Resource not found", 404)
            owned_node_id: str | None = None
            if claims.auth_kind in NETWORK_AUTOMATION_AUTH_KINDS:
                owned_node_id = str(
                    self._caller_network_node(connection, claims, team_id)["node_id"]
                )
            elif membership["role"] in {"owner", "admin", "member"}:
                try:
                    owned_node_id = str(
                        self._caller_network_node(
                            connection, claims, team_id
                        )["node_id"]
                    )
                except HubError as exc:
                    if exc.code != "network_host_unavailable":
                        raise
            network = {
                "id": team["id"],
                "display_name": team["display_name"],
                "hub_id": self.hub_id,
            }
            # Presence and trust are separate: an offline node with an exact
            # live binding remains visible, while a secure-peer-backed node
            # whose authority was retired does not. Managed-host and legacy
            # no-binding nodes are independent of secure-peer authority. Apply
            # this lifecycle filter before the cursor and LIMIT page boundary.
            server_rows = list(
                connection.execute(
                    """
                    SELECT n.id,n.server_identity,n.display_name,n.status
                    FROM nodes AS n
                    WHERE n.team_id=? AND n.status<>'revoked' AND n.id>?
                      AND (
                        n.server_identity=?
                        OR NOT EXISTS (
                            SELECT 1 FROM network_peer_bindings AS history
                            WHERE history.team_id=n.team_id
                              AND history.node_id=n.id
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM network_peer_bindings AS live
                            JOIN principals AS service_principal
                              ON service_principal.id=live.service_principal_id
                            JOIN service_accounts AS service_account
                              ON service_account.principal_id=service_principal.id
                            JOIN memberships AS service_membership
                              ON service_membership.team_id=live.team_id
                             AND service_membership.principal_id=service_principal.id
                            WHERE live.team_id=n.team_id
                              AND live.node_id=n.id
                              AND live.peer_server_identity=n.server_identity
                              AND live.status='active'
                              AND service_principal.kind='service'
                              AND service_principal.status='active'
                              AND service_account.service_identifier=
                                  'agentsdock.secure-peer.' || live.peer_id
                              AND service_membership.role='automation'
                              AND service_membership.status='active'
                        )
                      )
                    ORDER BY n.id
                    LIMIT ?
                    """,
                    (
                        team_id,
                        clean_after or "",
                        self.managed_host_identity,
                        bounded_limit + 1,
                    ),
                )
            )
            candidate_rows = server_rows[:bounded_limit]
            servers: list[dict[str, Any]] = []
            agents: list[dict[str, Any]] = []
            visible_rows: list[sqlite3.Row] = []
            for row in candidate_rows:
                server = {
                    "id": row["id"],
                    "server_identity": row["server_identity"],
                    "display_name": row["display_name"],
                    "status": row["status"],
                    "is_host": bool(
                        self.managed_host_identity is not None
                        and row["server_identity"] == self.managed_host_identity
                    ),
                    "owned_by_caller": row["id"] == owned_node_id,
                }
                # Materialize at most one server's bounded agent group at a
                # time. A page that reaches its byte ceiling never loads the
                # remaining candidate groups into memory.
                group_agents = [
                    self._agent_public(agent_row)
                    for agent_row in connection.execute(
                        """
                        SELECT id,node_id,external_agent_id,backend,
                               display_name,status
                        FROM agents
                        WHERE team_id=? AND node_id=? AND status<>'retired'
                        ORDER BY id
                        """,
                        (team_id, row["id"]),
                    )
                ]
                candidate_response = {
                    "network": network,
                    "servers": [*servers, server],
                    "agents": [*agents, *group_agents],
                    "next_after_server_id": row["id"],
                    # false is one byte larger than true in canonical JSON, so
                    # it is the conservative value for the transport bound.
                    "has_more": False,
                }
                if (
                    len(canonical_json(candidate_response))
                    > MAX_NETWORK_PAGE_RESPONSE_BYTES
                ):
                    break
                servers.append(server)
                agents.extend(group_agents)
                visible_rows.append(row)
            if candidate_rows and not visible_rows:
                raise RuntimeError(
                    "one bounded network server group exceeds the page response limit"
                )
            has_more = len(visible_rows) < len(server_rows)
            response = {
                "network": network,
                "servers": servers,
                "agents": agents,
                "next_after_server_id": (
                    str(visible_rows[-1]["id"]) if visible_rows else None
                ),
                "has_more": has_more,
            }
            if len(canonical_json(response)) > MAX_NETWORK_PAGE_RESPONSE_BYTES:
                raise RuntimeError("bounded network page exceeds the response limit")
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def get_network_server(
        self,
        claims: AccessClaims,
        team_id: str,
        server_id: str,
    ) -> dict[str, Any]:
        """Return one visible logical server without enumerating its team."""

        try:
            clean_server_id = _identity(server_id)
        except (AttributeError, TypeError, ValueError) as exc:
            raise HubError("not_found", "Resource not found", 404) from exc
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            membership = self._require_network_scope(
                connection, claims, team_id, write=False
            )
            owned_node_id: str | None = None
            if claims.auth_kind in NETWORK_AUTOMATION_AUTH_KINDS:
                owned_node_id = str(
                    self._caller_network_node(connection, claims, team_id)["node_id"]
                )
            elif membership["role"] in {"owner", "admin", "member"}:
                try:
                    owned_node_id = str(
                        self._caller_network_node(connection, claims, team_id)[
                            "node_id"
                        ]
                    )
                except HubError as exc:
                    if exc.code != "network_host_unavailable":
                        raise
            row = connection.execute(
                """
                SELECT n.id,n.server_identity,n.display_name,n.status
                FROM nodes AS n
                WHERE n.team_id=? AND n.id=? AND n.status<>'revoked'
                  AND (
                    n.server_identity=?
                    OR NOT EXISTS (
                        SELECT 1 FROM network_peer_bindings AS history
                        WHERE history.team_id=n.team_id
                          AND history.node_id=n.id
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM network_peer_bindings AS live
                        JOIN principals AS service_principal
                          ON service_principal.id=live.service_principal_id
                        JOIN service_accounts AS service_account
                          ON service_account.principal_id=service_principal.id
                        JOIN memberships AS service_membership
                          ON service_membership.team_id=live.team_id
                         AND service_membership.principal_id=service_principal.id
                        WHERE live.team_id=n.team_id
                          AND live.node_id=n.id
                          AND live.peer_server_identity=n.server_identity
                          AND live.status='active'
                          AND service_principal.kind='service'
                          AND service_principal.status='active'
                          AND service_account.service_identifier=
                              'agentsdock.secure-peer.' || live.peer_id
                          AND service_membership.role='automation'
                          AND service_membership.status='active'
                    )
                  )
                """,
                (team_id, clean_server_id, self.managed_host_identity),
            ).fetchone()
            if row is None:
                raise HubError("not_found", "Resource not found", 404)
            result = {
                "server": {
                    "id": str(row["id"]),
                    "server_identity": str(row["server_identity"]),
                    "display_name": str(row["display_name"]),
                    "status": str(row["status"]),
                    "is_host": bool(
                        self.managed_host_identity is not None
                        and row["server_identity"] == self.managed_host_identity
                    ),
                    "owned_by_caller": row["id"] == owned_node_id,
                }
            }
            connection.execute("COMMIT")
            return result
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def register_network_agent(
        self,
        claims: AccessClaims,
        team_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        timestamp = _now()
        external_id = _bounded_text(
            request.get("external_agent_id") or "",
            "external_agent_id",
            1,
            240,
        )
        display_name = _bounded_text(
            request.get("display_name") or "", "display_name", 1, 160
        )
        backend = request.get("backend")
        if backend not in {"codex", "claude", "other"}:
            raise HubError("invalid_request", "Agent backend is invalid", 422)
        fingerprint = canonical_fingerprint(
            {
                "team_id": team_id,
                "external_agent_id": external_id,
                "backend": backend,
                "display_name": display_name,
            }
        )
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_network_scope(connection, claims, team_id, write=True)
                if claims.auth_kind == "human":
                    try:
                        _require_team_role(
                            connection,
                            team_id,
                            claims.principal_id,
                            ("owner", "admin"),
                        )
                    except (AuthorizationError, AuthenticationError) as exc:
                        raise HubError(
                            "forbidden", "Operation is not permitted", 403
                        ) from exc
                node = self._caller_network_node(connection, claims, team_id)
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.agent.register",
                    request["idempotency_key"],
                    fingerprint,
                )
                if cached is not None:
                    return cached
                if connection.execute(
                    "SELECT 1 FROM agents WHERE node_id=? AND external_agent_id=?",
                    (node["node_id"], external_id),
                ).fetchone() is not None:
                    raise HubError(
                        "agent_conflict",
                        "Agent identity is already registered",
                        409,
                    )
                agent_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM agents WHERE node_id=?",
                        (node["node_id"],),
                    ).fetchone()[0]
                )
                if agent_count >= MAX_NETWORK_AGENTS_PER_SERVER:
                    raise HubError(
                        "agent_limit_reached",
                        "Server agent limit has been reached",
                        409,
                    )
                principal_id = _id("agent_principal")
                agent_id = _id("agent")
                connection.execute(
                    """
                    INSERT INTO principals(
                        id,kind,scope_team_id,display_name,status,
                        created_at,updated_at
                    ) VALUES (?,'agent',?,?,'active',?,?)
                    """,
                    (principal_id, team_id, display_name, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO agents(
                        id,team_id,principal_id,node_id,external_agent_id,
                        backend,display_name,status,created_at,updated_at
                    ) VALUES (?,?,?,?,?,?,?,'active',?,?)
                    """,
                    (
                        agent_id,
                        team_id,
                        principal_id,
                        node["node_id"],
                        external_id,
                        backend,
                        display_name,
                        timestamp,
                        timestamp,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT id,node_id,external_agent_id,backend,display_name,status
                    FROM agents WHERE id=?
                    """,
                    (agent_id,),
                ).fetchone()
                assert row is not None
                response = {"agent": self._agent_public(row)}
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.agent.register",
                    request["idempotency_key"],
                    fingerprint,
                    "agent",
                    agent_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.agent.register",
                    "agent",
                    agent_id,
                    "succeeded",
                    {"node_id": node["node_id"], "backend": backend},
                    timestamp,
                )
                self._outbox(
                    connection, team_id, "agent", agent_id, "network.agent.registered", timestamp
                )
                return response
        finally:
            connection.close()

    def _ensure_network_board(
        self,
        connection: sqlite3.Connection,
        team_id: str,
        creator_principal_id: str,
        timestamp: int,
    ) -> sqlite3.Row:
        binding = connection.execute(
            """
            SELECT c.*,b.channel_id AS bound_channel_id
            FROM network_boards AS b
            LEFT JOIN channels AS c
              ON c.team_id=b.team_id AND c.id=b.channel_id
            WHERE b.team_id=?
            """,
            (team_id,),
        ).fetchone()
        if (
            binding is not None
            and binding["id"] is not None
            and binding["kind"] == "board"
            and binding["visibility"] == "team"
            and binding["archived_at"] is None
        ):
            return binding
        membership = _require_team_role(
            connection,
            team_id,
            creator_principal_id,
            ("owner", "admin", "member", "automation"),
        )
        channel_id = _id("channel")
        occupied_slugs = {
            str(row["slug"])
            for row in connection.execute(
                "SELECT slug FROM channels WHERE team_id=? AND slug IS NOT NULL",
                (team_id,),
            )
        }
        primary_slug = "agentsdock-bulletin"
        fallback_slug = "agentsdock-bulletin-v1"
        if primary_slug not in occupied_slugs:
            slug = primary_slug
        elif fallback_slug not in occupied_slugs:
            slug = fallback_slug
        else:
            suffix = 2
            while f"{fallback_slug}-{suffix}" in occupied_slugs:
                suffix += 1
            slug = f"{fallback_slug}-{suffix}"
        connection.execute(
            """
            INSERT INTO channels(
                id,team_id,kind,visibility,slug,display_name,
                direct_pair_key,created_by_principal_id,
                created_at,updated_at
            ) VALUES (?,?,'board','team',?,'Bulletin',NULL,?,?,?)
            """,
            (
                channel_id,
                team_id,
                slug,
                creator_principal_id,
                timestamp,
                timestamp,
            ),
        )
        role_permissions = {
            "owner": (1, 1, 1),
            "admin": (1, 1, 1),
            "member": (1, 1, 0),
            "guest": (1, 0, 0),
            "automation": (1, 1, 0),
        }
        for role, (can_read, can_post, can_manage) in role_permissions.items():
            connection.execute(
                """
                INSERT INTO channel_acl_entries(
                    id,team_id,channel_id,subject_kind,
                    subject_principal_id,subject_role,
                    can_read,can_post,can_manage,can_dispatch,created_at
                ) VALUES (?,?,?,'role',NULL,?,?,?,?,0,?)
                """,
                (
                    _id("channel_acl"),
                    team_id,
                    channel_id,
                    role,
                    can_read,
                    can_post,
                    can_manage,
                    timestamp,
                ),
            )
        if binding is None:
            connection.execute(
                """
                INSERT INTO network_boards(team_id,channel_id,created_at)
                VALUES (?,?,?)
                """,
                (team_id, channel_id, timestamp),
            )
        else:
            connection.execute(
                "UPDATE network_boards SET channel_id=? WHERE team_id=?",
                (channel_id, team_id),
            )
        row = connection.execute(
            "SELECT * FROM channels WHERE id=?", (channel_id,)
        ).fetchone()
        assert row is not None
        self._audit(
            connection,
            team_id,
            creator_principal_id,
            "network.bulletin.create",
            "network_bulletin",
            team_id,
            "succeeded",
            {
                "creator_role": membership["role"],
                "replaced_unavailable_binding": binding is not None,
                "reserved_slug": slug,
            },
            timestamp,
        )
        return row

    @staticmethod
    def _bulletin_post_public(row: sqlite3.Row) -> dict[str, Any]:
        author_kind = "server" if row["author_node_id"] is not None else "human"
        return {
            "id": row["id"],
            "sequence": int(row["channel_sequence"]),
            "author": {
                "kind": author_kind,
                "id": (
                    row["author_node_id"]
                    if author_kind == "server"
                    else row["author_principal_id"]
                ),
                "display_name": (
                    row["author_node_display_name"]
                    if author_kind == "server"
                    else row["author_principal_display_name"]
                ),
            },
            "body_format": row["body_format"],
            "body": row["body"],
            "thread_root_post_id": row["thread_root_message_id"],
            "reply_to_post_id": row["parent_message_id"],
            "created_at": _iso8601(row["created_at"]),
        }

    @staticmethod
    def _bulletin_post_select() -> str:
        return """
            SELECT m.*,p.display_name AS author_principal_display_name,
                   COALESCE(b.node_id, managed_node.id) AS author_node_id,
                   COALESCE(peer_node.display_name, managed_node.display_name)
                       AS author_node_display_name
            FROM messages AS m
            JOIN principals AS p ON p.id=m.author_principal_id
            LEFT JOIN network_peer_bindings AS b
              ON b.service_principal_id=m.author_principal_id
             AND b.team_id=m.team_id
            LEFT JOIN nodes AS peer_node
              ON peer_node.team_id=b.team_id AND peer_node.id=b.node_id
            LEFT JOIN service_accounts AS managed_author
              ON managed_author.principal_id=m.author_principal_id
             AND (
                (
                    m.author_principal_id='service_local_control'
                    AND managed_author.service_identifier=
                        'agentsdock.team-hub.local-control'
                )
                OR (
                    m.author_principal_id='service_managed_server'
                    AND managed_author.service_identifier=
                        'agentsdock.team-hub.managed-server'
                )
             )
            LEFT JOIN managed_host_bindings AS managed
              ON managed.singleton=1 AND managed_author.principal_id IS NOT NULL
            LEFT JOIN nodes AS managed_node
              ON managed_node.team_id=m.team_id
             AND managed_node.server_identity=managed.server_identity
             AND managed_node.status='active'
        """

    @staticmethod
    def _bounded_network_page(
        rows: list[sqlite3.Row],
        *,
        clean_after: int,
        bounded_limit: int,
        collection_key: str,
        sequence_column: str,
        render: Callable[[sqlite3.Row], dict[str, Any]],
    ) -> dict[str, Any]:
        visible_rows: list[sqlite3.Row] = []
        visible_items: list[dict[str, Any]] = []
        encoded_collection_bytes = 2  # JSON array brackets.
        collection_budget = MAX_NETWORK_PAGE_RESPONSE_BYTES - 1_024
        for row in rows[:bounded_limit]:
            item = render(row)
            item_bytes = len(canonical_json(item))
            separator_bytes = 1 if visible_items else 0
            if (
                encoded_collection_bytes + separator_bytes + item_bytes
                > collection_budget
            ):
                break
            encoded_collection_bytes += separator_bytes + item_bytes
            visible_rows.append(row)
            visible_items.append(item)
        if rows and not visible_rows:
            raise RuntimeError("one bounded network item exceeds the page response limit")
        response = {
            collection_key: visible_items,
            "next_after_sequence": (
                int(visible_rows[-1][sequence_column])
                if visible_rows
                else clean_after
            ),
            "has_more": len(visible_rows) < len(rows),
        }
        if len(canonical_json(response)) > MAX_NETWORK_PAGE_RESPONSE_BYTES:
            raise RuntimeError("bounded network page exceeds the response limit")
        return response

    def list_network_bulletin(
        self,
        claims: AccessClaims,
        team_id: str,
        *,
        after_sequence: int,
        limit: int,
    ) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_network_scope(connection, claims, team_id, write=False)
            board = connection.execute(
                """
                SELECT c.* FROM network_boards AS b
                JOIN channels AS c ON c.team_id=b.team_id AND c.id=b.channel_id
                WHERE b.team_id=? AND c.archived_at IS NULL
                """,
                (team_id,),
            ).fetchone()
            bounded_limit = max(1, min(int(limit), MAX_NETWORK_PAGE_ITEMS))
            clean_after = max(0, int(after_sequence))
            if board is None:
                rows: list[sqlite3.Row] = []
            else:
                if not self._channel_permission(
                    connection, board, claims.principal_id, "read"
                ):
                    raise HubError("not_found", "Resource not found", 404)
                rows = connection.execute(
                    self._bulletin_post_select()
                    + """
                    WHERE m.channel_id=? AND m.channel_sequence>?
                      AND m.deleted_at IS NULL
                    ORDER BY m.channel_sequence ASC LIMIT ?
                    """,
                    (board["id"], clean_after, bounded_limit + 1),
                ).fetchall()
            response = self._bounded_network_page(
                rows,
                clean_after=clean_after,
                bounded_limit=bounded_limit,
                collection_key="posts",
                sequence_column="channel_sequence",
                render=self._bulletin_post_public,
            )
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def create_network_bulletin_post(
        self,
        claims: AccessClaims,
        team_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        timestamp = _now()
        body = request.get("body")
        try:
            encoded = body.encode("utf-8") if isinstance(body, str) else b""
        except UnicodeEncodeError as exc:
            raise HubError("invalid_request", "Bulletin body is invalid", 422) from exc
        if not 1 <= len(encoded) <= MAX_NETWORK_BODY_BYTES:
            raise HubError("invalid_request", "Bulletin body is invalid", 422)
        body_format = request.get("body_format")
        if body_format not in {"plain", "markdown"}:
            raise HubError("invalid_request", "Bulletin body format is invalid", 422)
        reply_to = request.get("reply_to_post_id")
        fingerprint = canonical_fingerprint(
            {
                "team_id": team_id,
                "body": body,
                "body_format": body_format,
                "reply_to_post_id": reply_to,
            }
        )
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_network_scope(connection, claims, team_id, write=True)
                board = self._ensure_network_board(
                    connection, team_id, claims.principal_id, timestamp
                )
                if not self._channel_permission(
                    connection, board, claims.principal_id, "post"
                ):
                    raise HubError("forbidden", "Operation is not permitted", 403)
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.bulletin.post",
                    request["idempotency_key"],
                    fingerprint,
                )
                if cached is not None:
                    return cached
                root_id: str | None = None
                if reply_to is not None:
                    parent = connection.execute(
                        """
                        SELECT id,thread_root_message_id FROM messages
                        WHERE team_id=? AND channel_id=? AND id=?
                          AND deleted_at IS NULL
                        """,
                        (team_id, board["id"], reply_to),
                    ).fetchone()
                    if parent is None:
                        raise HubError(
                            "invalid_request", "Bulletin reply target is unavailable", 422
                        )
                    root_id = str(parent["thread_root_message_id"] or parent["id"])
                self._charge_network_peer_write(
                    connection, claims, team_id, len(encoded), timestamp
                )
                sequence = int(board["next_message_sequence"])
                message_id = _id("message")
                connection.execute(
                    "UPDATE channels SET next_message_sequence=?,updated_at=? WHERE id=?",
                    (sequence + 1, timestamp, board["id"]),
                )
                connection.execute(
                    """
                    INSERT INTO messages(
                        id,team_id,channel_id,channel_sequence,kind,
                        thread_root_message_id,parent_message_id,
                        author_principal_id,body_format,body,
                        idempotency_key,created_at
                    ) VALUES (?,?,?,?,'post',?,?,?,?,?,?,?)
                    """,
                    (
                        message_id,
                        team_id,
                        board["id"],
                        sequence,
                        root_id,
                        reply_to,
                        claims.principal_id,
                        body_format,
                        body,
                        hashlib.sha256(
                            f"{team_id}\0{claims.principal_id}\0network.bulletin.post\0{request['idempotency_key']}".encode(
                                "utf-8"
                            )
                        ).digest(),
                        timestamp,
                    ),
                )
                row = connection.execute(
                    self._bulletin_post_select() + " WHERE m.id=?",
                    (message_id,),
                ).fetchone()
                assert row is not None
                response = {"post": self._bulletin_post_public(row)}
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.bulletin.post",
                    request["idempotency_key"],
                    fingerprint,
                    "network_bulletin_post",
                    message_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.bulletin.post",
                    "network_bulletin_post",
                    message_id,
                    "succeeded",
                    {"reply": reply_to is not None},
                    timestamp,
                )
                self._outbox(
                    connection,
                    team_id,
                    "network_bulletin_post",
                    message_id,
                    "network.bulletin.posted",
                    timestamp,
                )
                return response
        finally:
            connection.close()

    @staticmethod
    def _network_item_select() -> str:
        return """
            SELECT i.*,i.id AS request_item_id,
                   d.id AS delivery_id,d.state AS delivery_state,
                   d.available_at,d.delivered_at,d.read_at,
                   sp.display_name AS sender_principal_display_name,
                   sn.server_identity AS sender_server_identity,
                   sn.display_name AS sender_server_display_name,
                   sa.display_name AS sender_agent_display_name,
                   sa.backend AS sender_agent_backend,
                   rp.display_name AS recipient_principal_display_name,
                   rn.server_identity AS recipient_server_identity,
                   rn.display_name AS recipient_server_display_name,
                   ra.display_name AS recipient_agent_display_name,
                   ra.backend AS recipient_agent_backend,
                   (SELECT pr.status FROM network_passive_requests AS pr
                    WHERE pr.team_id=i.team_id AND pr.request_item_id=i.id)
                       AS request_status,
                   (SELECT pr.expires_at FROM network_passive_requests AS pr
                    WHERE pr.team_id=i.team_id AND pr.request_item_id=i.id)
                       AS request_expires_at,
                   (SELECT pr.reply_item_id FROM network_passive_requests AS pr
                    WHERE pr.team_id=i.team_id AND pr.request_item_id=i.id)
                       AS reply_item_id
            FROM network_mailbox_items AS i
            JOIN network_deliveries AS d
              ON d.team_id=i.team_id AND d.item_id=i.id
            JOIN principals AS sp ON sp.id=i.sender_principal_id
            JOIN principals AS rp ON rp.id=i.recipient_principal_id
            LEFT JOIN nodes AS sn
              ON sn.team_id=i.team_id AND sn.id=i.sender_node_id
            LEFT JOIN agents AS sa
              ON sa.team_id=i.team_id AND sa.id=i.sender_agent_id
            LEFT JOIN nodes AS rn
              ON rn.team_id=i.team_id AND rn.id=i.recipient_node_id
            LEFT JOIN agents AS ra
              ON ra.team_id=i.team_id AND ra.id=i.recipient_agent_id
        """

    @staticmethod
    def _network_address(row: sqlite3.Row, prefix: str) -> dict[str, Any]:
        kind = str(row[f"{prefix}_kind"])
        if kind == "human":
            return {
                "kind": "human",
                "id": row[f"{prefix}_principal_id"],
                "display_name": row[f"{prefix}_principal_display_name"],
            }
        if kind == "server":
            return {
                "kind": "server",
                "id": row[f"{prefix}_node_id"],
                "server_identity": row[f"{prefix}_server_identity"],
                "display_name": row[f"{prefix}_server_display_name"],
            }
        return {
            "kind": "agent",
            "id": row[f"{prefix}_agent_id"],
            "server_id": row[f"{prefix}_node_id"],
            "backend": row[f"{prefix}_agent_backend"],
            "display_name": row[f"{prefix}_agent_display_name"],
        }

    @classmethod
    def _network_item_public(cls, row: sqlite3.Row) -> dict[str, Any]:
        kind = str(row["kind"])
        request_id = (
            row["id"]
            if kind == "request"
            else row["root_request_item_id"]
            if kind == "reply"
            else None
        )
        return {
            "id": row["id"],
            "sequence": int(row["queue_ordinal"]),
            "kind": kind,
            "from": cls._network_address(row, "sender"),
            "to": cls._network_address(row, "recipient"),
            "body_format": row["body_format"],
            "body": row["body"],
            "request_id": request_id,
            "created_at": _iso8601(row["created_at"]),
            "expires_at": _iso8601(row["expires_at"]),
        }

    @staticmethod
    def _network_delivery_public(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["delivery_id"],
            "state": row["delivery_state"],
            "available_at": _iso8601(row["available_at"]),
            "delivered_at": _iso8601(row["delivered_at"]),
            "read_at": _iso8601(row["read_at"]),
        }

    def _network_sender(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
        from_agent_id: str | None,
    ) -> dict[str, str | None]:
        if claims.auth_kind == "human":
            if from_agent_id is not None:
                raise HubError(
                    "forbidden", "A human session cannot claim agent authorship", 403
                )
            return {
                "kind": "human",
                "principal_id": claims.principal_id,
                "node_id": None,
                "agent_id": None,
            }
        node = self._caller_network_node(connection, claims, team_id)
        if from_agent_id is None:
            return {
                "kind": "server",
                "principal_id": claims.principal_id,
                "node_id": str(node["node_id"]),
                "agent_id": None,
            }
        agent_id = _identity(from_agent_id)
        agent = connection.execute(
            """
            SELECT id FROM agents
            WHERE team_id=? AND node_id=? AND id=? AND status='active'
            """,
            (team_id, node["node_id"], agent_id),
        ).fetchone()
        if agent is None:
            raise HubError("forbidden", "Agent is not owned by this server", 403)
        return {
            "kind": "agent",
            "principal_id": claims.principal_id,
            "node_id": str(node["node_id"]),
            "agent_id": agent_id,
        }

    @staticmethod
    def _require_server_inbox_write(
        request: dict[str, Any],
        *,
        destination_required: bool,
    ) -> None:
        """Keep agent records readable while retiring them as mail parties."""

        destination = request.get("to")
        if request.get("from_agent_id") is not None or (
            destination_required
            and (
                not isinstance(destination, dict)
                or destination.get("kind") != "server"
            )
        ):
            raise HubError(
                "invalid_request",
                "Team Network mail accepts server inboxes only",
                422,
            )

    @staticmethod
    def _network_recipient(
        connection: sqlite3.Connection,
        team_id: str,
        target: dict[str, Any],
    ) -> dict[str, str | None]:
        kind = target.get("kind")
        identifier = _identity(str(target.get("id") or ""))
        if kind == "server":
            row = connection.execute(
                """
                SELECT id,principal_id FROM nodes
                WHERE team_id=? AND id=? AND status='active'
                """,
                (team_id, identifier),
            ).fetchone()
            if row is None:
                raise HubError("recipient_unavailable", "Recipient is unavailable", 404)
            return {
                "kind": "server",
                "principal_id": str(row["principal_id"]),
                "node_id": str(row["id"]),
                "agent_id": None,
            }
        if kind == "agent":
            row = connection.execute(
                """
                SELECT a.id,a.node_id,a.principal_id
                FROM agents AS a
                JOIN nodes AS n ON n.team_id=a.team_id AND n.id=a.node_id
                JOIN principals AS p ON p.id=a.principal_id
                WHERE a.team_id=? AND a.id=? AND a.status='active'
                  AND n.status='active' AND p.status='active'
                """,
                (team_id, identifier),
            ).fetchone()
            if row is None:
                raise HubError("recipient_unavailable", "Recipient is unavailable", 404)
            return {
                "kind": "agent",
                "principal_id": str(row["principal_id"]),
                "node_id": str(row["node_id"]),
                "agent_id": str(row["id"]),
            }
        raise HubError("invalid_request", "Recipient kind is invalid", 422)

    @staticmethod
    def _network_body(request: dict[str, Any]) -> tuple[str, str, int]:
        body = request.get("body")
        try:
            encoded = body.encode("utf-8") if isinstance(body, str) else b""
        except UnicodeEncodeError as exc:
            raise HubError("invalid_request", "Mailbox body is invalid", 422) from exc
        if not 1 <= len(encoded) <= MAX_NETWORK_BODY_BYTES:
            raise HubError("invalid_request", "Mailbox body is invalid", 422)
        body_format = request.get("body_format")
        if body_format not in {"plain", "markdown"}:
            raise HubError("invalid_request", "Mailbox body format is invalid", 422)
        return body, str(body_format), len(encoded)

    def _insert_network_item(
        self,
        connection: sqlite3.Connection,
        *,
        team_id: str,
        kind: str,
        sender: dict[str, str | None],
        recipient: dict[str, str | None],
        body: str,
        body_format: str,
        operation: str,
        idempotency_key: str,
        timestamp: int,
        root_request_item_id: str | None = None,
        expires_at: int | None = None,
    ) -> tuple[dict[str, Any], sqlite3.Row]:
        item_id = _id("network_item")
        delivery_id = _id("network_delivery")
        connection.execute(
            """
            INSERT INTO network_mailbox_items(
                id,team_id,kind,sender_kind,sender_principal_id,
                sender_node_id,sender_agent_id,
                recipient_kind,recipient_principal_id,
                recipient_node_id,recipient_agent_id,root_request_item_id,
                body_format,body,idempotency_key,created_at,expires_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item_id,
                team_id,
                kind,
                sender["kind"],
                sender["principal_id"],
                sender["node_id"],
                sender["agent_id"],
                recipient["kind"],
                recipient["principal_id"],
                recipient["node_id"],
                recipient["agent_id"],
                root_request_item_id,
                body_format,
                body,
                hashlib.sha256(
                    f"{team_id}\0{sender['principal_id']}\0{operation}\0{idempotency_key}".encode(
                        "utf-8"
                    )
                ).digest(),
                timestamp,
                expires_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO network_deliveries(
                id,team_id,item_id,state,available_at
            ) VALUES (?,?,?,'available',?)
            """,
            (delivery_id, team_id, item_id, timestamp),
        )
        row = connection.execute(
            self._network_item_select() + " WHERE i.id=?",
            (item_id,),
        ).fetchone()
        assert row is not None
        response = {
            "item": self._network_item_public(row),
            "delivery": self._network_delivery_public(row),
        }
        return response, row

    @staticmethod
    def _network_automation_rate_subject(claims: AccessClaims) -> str | None:
        if claims.auth_kind == "secure_peer":
            return f"secure-peer:{claims.peer_id or claims.principal_id}"
        if claims.auth_kind == "local_agent_mail":
            return f"local-agent-mail:{claims.principal_id}"
        if claims.auth_kind == "managed_server":
            return f"managed-server:{claims.principal_id}"
        return None

    def _charge_network_peer_write(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
        body_bytes: int,
        timestamp: int,
    ) -> None:
        subject = self._network_automation_rate_subject(claims)
        if subject is None:
            return
        self._charge_rate_bucket(
            connection,
            team_id=team_id,
            subject_key=subject,
            action="network.mailbox.count.minute",
            timestamp=timestamp,
            window_seconds=60,
            cost=1,
            limit=60,
        )
        self._charge_rate_bucket(
            connection,
            team_id=team_id,
            subject_key=subject,
            action="network.mailbox.bytes.hour",
            timestamp=timestamp,
            window_seconds=3_600,
            cost=body_bytes,
            limit=4 * 1024 * 1024,
        )

    def create_network_mailbox_item(
        self,
        claims: AccessClaims,
        team_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        self._require_server_inbox_write(request, destination_required=True)
        timestamp = _now()
        body, body_format, body_bytes = self._network_body(request)
        fingerprint = canonical_fingerprint(
            {
                "team_id": team_id,
                "to": request.get("to"),
                "from_agent_id": request.get("from_agent_id"),
                "body": body,
                "body_format": body_format,
            }
        )
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_network_scope(connection, claims, team_id, write=True)
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.mailbox.send",
                    request["idempotency_key"],
                    fingerprint,
                )
                if cached is not None:
                    return cached
                sender = self._network_sender(
                    connection, claims, team_id, request.get("from_agent_id")
                )
                recipient = self._network_recipient(
                    connection, team_id, dict(request.get("to") or {})
                )
                self._charge_network_peer_write(
                    connection, claims, team_id, body_bytes, timestamp
                )
                response, row = self._insert_network_item(
                    connection,
                    team_id=team_id,
                    kind="message",
                    sender=sender,
                    recipient=recipient,
                    body=body,
                    body_format=body_format,
                    operation="network.mailbox.send",
                    idempotency_key=request["idempotency_key"],
                    timestamp=timestamp,
                )
                item_id = str(row["id"])
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.mailbox.send",
                    request["idempotency_key"],
                    fingerprint,
                    "network_mailbox_item",
                    item_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.mailbox.send",
                    "network_mailbox_item",
                    item_id,
                    "succeeded",
                    {
                        "sender_kind": sender["kind"],
                        "recipient_kind": recipient["kind"],
                    },
                    timestamp,
                )
                self._outbox(
                    connection,
                    team_id,
                    "network_mailbox_item",
                    item_id,
                    "network.mailbox.available",
                    timestamp,
                )
                return response
        finally:
            connection.close()

    def _require_network_address_owner(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
        address_kind: str,
        address_id: str,
    ) -> tuple[str | None, str | None]:
        identifier = _identity(address_id)
        if address_kind == "human":
            if (
                address_id != identifier
                or claims.auth_kind != "human"
                or identifier != claims.principal_id
            ):
                raise HubError("not_found", "Resource not found", 404)
            human = connection.execute(
                """
                SELECT p.id FROM principals AS p
                JOIN memberships AS m
                  ON m.team_id=? AND m.principal_id=p.id
                WHERE p.id=? AND p.kind='human' AND p.status='active'
                  AND m.status='active'
                """,
                (team_id, identifier),
            ).fetchone()
            if human is None:
                raise HubError("not_found", "Resource not found", 404)
            return None, None
        node = self._caller_network_node(connection, claims, team_id)
        if address_kind == "server":
            if identifier != node["node_id"]:
                raise HubError("not_found", "Resource not found", 404)
            return str(node["node_id"]), None
        if address_kind == "agent":
            agent = connection.execute(
                """
                SELECT id FROM agents
                WHERE team_id=? AND node_id=? AND id=? AND status='active'
                """,
                (team_id, node["node_id"], identifier),
            ).fetchone()
            if agent is None:
                raise HubError("not_found", "Resource not found", 404)
            return str(node["node_id"]), identifier
        raise HubError("invalid_request", "Mailbox address kind is invalid", 422)

    def list_network_mailbox(
        self,
        claims: AccessClaims,
        team_id: str,
        *,
        address_kind: str,
        address_id: str,
        after_sequence: int,
        limit: int,
    ) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_network_scope(connection, claims, team_id, write=False)
            node_id, agent_id = self._require_network_address_owner(
                connection, claims, team_id, address_kind, address_id
            )
            bounded_limit = max(1, min(int(limit), MAX_NETWORK_PAGE_ITEMS))
            clean_after = max(0, int(after_sequence))
            if address_kind == "human":
                routing = (
                    "i.recipient_kind='human' AND i.recipient_principal_id=?"
                )
                routing_values = (claims.principal_id,)
            elif agent_id is None:
                routing = "i.recipient_kind='server' AND i.recipient_node_id=?"
                routing_values: tuple[Any, ...] = (node_id,)
            else:
                routing = (
                    "i.recipient_kind='agent' AND i.recipient_node_id=? "
                    "AND i.recipient_agent_id=?"
                )
                routing_values = (node_id, agent_id)
            rows = connection.execute(
                self._network_item_select()
                + f"""
                WHERE i.team_id=? AND {routing} AND i.queue_ordinal>?
                ORDER BY i.queue_ordinal ASC LIMIT ?
                """,
                (team_id, *routing_values, clean_after, bounded_limit + 1),
            ).fetchall()
            response = self._bounded_network_page(
                rows,
                clean_after=clean_after,
                bounded_limit=bounded_limit,
                collection_key="items",
                sequence_column="queue_ordinal",
                render=lambda row: {
                    "item": self._network_item_public(row),
                    "delivery": self._network_delivery_public(row),
                },
            )
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _network_item_participant(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
        row: sqlite3.Row,
    ) -> bool:
        if claims.auth_kind == "human" and claims.principal_id in {
            row["sender_principal_id"],
            row["recipient_principal_id"],
        }:
            return True
        node = self._caller_network_node(connection, claims, team_id)
        return node["node_id"] in {
            row["sender_node_id"],
            row["recipient_node_id"],
        }

    def get_network_item(
        self,
        claims: AccessClaims,
        team_id: str,
        item_id: str,
    ) -> dict[str, Any]:
        clean_id = _identity(item_id)
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_network_scope(connection, claims, team_id, write=False)
            row = connection.execute(
                self._network_item_select() + " WHERE i.team_id=? AND i.id=?",
                (team_id, clean_id),
            ).fetchone()
            if row is None or not self._network_item_participant(
                connection, claims, team_id, row
            ):
                raise HubError("not_found", "Resource not found", 404)
            response = {
                "item": self._network_item_public(row),
                "delivery": self._network_delivery_public(row),
            }
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def record_network_delivery_receipt(
        self,
        claims: AccessClaims,
        team_id: str,
        delivery_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        timestamp = _now()
        clean_id = _identity(delivery_id)
        target_state = request.get("state")
        if target_state not in {"delivered", "read"}:
            raise HubError("invalid_request", "Receipt state is invalid", 422)
        fingerprint = canonical_fingerprint(
            {"team_id": team_id, "delivery_id": clean_id, "state": target_state}
        )
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_network_scope(connection, claims, team_id, write=True)
                row = connection.execute(
                    self._network_item_select()
                    + " WHERE i.team_id=? AND d.id=?",
                    (team_id, clean_id),
                ).fetchone()
                if row is None:
                    raise HubError("not_found", "Resource not found", 404)
                if (
                    claims.auth_kind == "human"
                    and row["recipient_kind"] == "human"
                    and row["recipient_principal_id"] == claims.principal_id
                ):
                    authorized = True
                else:
                    node = self._caller_network_node(
                        connection, claims, team_id
                    )
                    authorized = row["recipient_node_id"] == node["node_id"]
                if not authorized:
                    raise HubError("not_found", "Resource not found", 404)
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.delivery.receipt",
                    request["idempotency_key"],
                    fingerprint,
                )
                if cached is not None:
                    return cached
                current = str(row["delivery_state"])
                if (
                    target_state == "delivered"
                    and current in {"delivered", "read"}
                ) or (target_state == "read" and current == "read"):
                    return {"delivery": self._network_delivery_public(row)}
                if target_state == "delivered" and current != "available":
                    raise HubError(
                        "receipt_conflict", "Receipt state is invalid", 409
                    )
                if target_state == "read" and current == "available":
                    raise HubError(
                        "receipt_conflict",
                        "Delivery must be recorded before it is read",
                        409,
                    )
                if target_state == "read" and current != "delivered":
                    raise HubError(
                        "receipt_conflict", "Receipt state is invalid", 409
                    )
                self._charge_network_peer_write(
                    connection, claims, team_id, 0, timestamp
                )
                if target_state == "delivered":
                    connection.execute(
                        """
                        UPDATE network_deliveries
                        SET state='delivered',delivered_at=? WHERE id=?
                        """,
                        (timestamp, clean_id),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE network_deliveries
                        SET state='read',read_at=? WHERE id=?
                        """,
                        (timestamp, clean_id),
                    )
                updated = connection.execute(
                    self._network_item_select()
                    + " WHERE i.team_id=? AND d.id=?",
                    (team_id, clean_id),
                ).fetchone()
                assert updated is not None
                response = {"delivery": self._network_delivery_public(updated)}
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.delivery.receipt",
                    request["idempotency_key"],
                    fingerprint,
                    "network_delivery",
                    clean_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.delivery.receipt",
                    "network_delivery",
                    clean_id,
                    "succeeded",
                    {"state": target_state},
                    timestamp,
                )
                self._outbox(
                    connection,
                    team_id,
                    "network_delivery",
                    clean_id,
                    f"network.delivery.{target_state}",
                    timestamp,
                )
                return response
        finally:
            connection.close()

    @staticmethod
    def _network_request_public(
        request_row: sqlite3.Row,
        *,
        timestamp: int,
    ) -> dict[str, Any]:
        status = str(request_row["request_status"])
        if status == "open" and int(request_row["request_expires_at"]) <= timestamp:
            status = "expired"
        return {
            "id": request_row["request_item_id"],
            "status": status,
            "expires_at": _iso8601(request_row["request_expires_at"]),
            "reply_item_id": request_row["reply_item_id"],
        }

    def create_network_request(
        self,
        claims: AccessClaims,
        team_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        self._require_server_inbox_write(request, destination_required=True)
        timestamp = _now()
        body, body_format, body_bytes = self._network_body(request)
        ttl = int(request.get("expires_in_seconds", 86_400))
        if not 60 <= ttl <= 86_400:
            raise HubError("invalid_request", "Request expiry is invalid", 422)
        expires_at = timestamp + ttl
        fingerprint = canonical_fingerprint(
            {
                "team_id": team_id,
                "to": request.get("to"),
                "from_agent_id": request.get("from_agent_id"),
                "body": body,
                "body_format": body_format,
                "expires_in_seconds": ttl,
            }
        )
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_network_scope(connection, claims, team_id, write=True)
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.request.create",
                    request["idempotency_key"],
                    fingerprint,
                )
                if cached is not None:
                    return cached
                sender = self._network_sender(
                    connection, claims, team_id, request.get("from_agent_id")
                )
                recipient = self._network_recipient(
                    connection, team_id, dict(request.get("to") or {})
                )
                self._charge_network_peer_write(
                    connection, claims, team_id, body_bytes, timestamp
                )
                response, row = self._insert_network_item(
                    connection,
                    team_id=team_id,
                    kind="request",
                    sender=sender,
                    recipient=recipient,
                    body=body,
                    body_format=body_format,
                    operation="network.request.create",
                    idempotency_key=request["idempotency_key"],
                    timestamp=timestamp,
                    expires_at=expires_at,
                )
                item_id = str(row["id"])
                connection.execute(
                    """
                    INSERT INTO network_passive_requests(
                        request_item_id,team_id,status,created_at,expires_at
                    ) VALUES (?,?,'open',?,?)
                    """,
                    (item_id, team_id, timestamp, expires_at),
                )
                request_row = connection.execute(
                    """
                    SELECT request_item_id,status AS request_status,
                           expires_at AS request_expires_at,reply_item_id
                    FROM network_passive_requests WHERE request_item_id=?
                    """,
                    (item_id,),
                ).fetchone()
                assert request_row is not None
                response["request"] = self._network_request_public(
                    request_row, timestamp=timestamp
                )
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.request.create",
                    request["idempotency_key"],
                    fingerprint,
                    "network_request",
                    item_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.request.create",
                    "network_request",
                    item_id,
                    "succeeded",
                    {
                        "sender_kind": sender["kind"],
                        "recipient_kind": recipient["kind"],
                        "expires_at": expires_at,
                        "passive": True,
                    },
                    timestamp,
                )
                self._outbox(
                    connection,
                    team_id,
                    "network_request",
                    item_id,
                    "network.request.available",
                    timestamp,
                )
                return response
        finally:
            connection.close()

    def _request_participant_row(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
        request_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            self._network_item_select()
            + """
            JOIN network_passive_requests AS pr
              ON pr.team_id=i.team_id AND pr.request_item_id=i.id
            WHERE i.team_id=? AND i.id=? AND i.kind='request'
            """,
            (team_id, request_id),
        ).fetchone()
        if row is None or not self._network_item_participant(
            connection, claims, team_id, row
        ):
            raise HubError("not_found", "Resource not found", 404)
        return row

    def get_network_request(
        self,
        claims: AccessClaims,
        team_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        clean_id = _identity(request_id)
        timestamp = _now()
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_network_scope(connection, claims, team_id, write=False)
            row = self._request_participant_row(
                connection, claims, team_id, clean_id
            )
            response: dict[str, Any] = {
                "item": self._network_item_public(row),
                "delivery": self._network_delivery_public(row),
                "request": self._network_request_public(row, timestamp=timestamp),
                "reply": None,
            }
            if row["reply_item_id"] is not None:
                reply = connection.execute(
                    self._network_item_select() + " WHERE i.id=?",
                    (row["reply_item_id"],),
                ).fetchone()
                if reply is None:
                    raise RuntimeError("passive request reply is missing")
                response["reply"] = {
                    "item": self._network_item_public(reply),
                    "delivery": self._network_delivery_public(reply),
                }
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _network_reply_recipient(
        connection: sqlite3.Connection,
        team_id: str,
        request_item: sqlite3.Row,
    ) -> dict[str, str | None]:
        sender_kind = str(request_item["sender_kind"])
        if sender_kind == "human":
            human = connection.execute(
                """
                SELECT p.id FROM principals AS p
                JOIN memberships AS m
                  ON m.team_id=? AND m.principal_id=p.id
                WHERE p.id=? AND p.kind='human' AND p.status='active'
                  AND m.status='active'
                """,
                (team_id, request_item["sender_principal_id"]),
            ).fetchone()
            if human is None:
                raise HubError(
                    "request_unavailable", "Requester is unavailable", 409
                )
            return {
                "kind": "human",
                "principal_id": str(human["id"]),
                "node_id": None,
                "agent_id": None,
            }
        if sender_kind == "server":
            node = connection.execute(
                """
                SELECT n.id,n.principal_id FROM nodes AS n
                JOIN principals AS p ON p.id=n.principal_id
                WHERE n.team_id=? AND n.id=? AND n.status='active'
                  AND p.status='active'
                """,
                (team_id, request_item["sender_node_id"]),
            ).fetchone()
            if node is None:
                raise HubError(
                    "request_unavailable", "Requester is unavailable", 409
                )
            return {
                "kind": "server",
                "principal_id": str(node["principal_id"]),
                "node_id": str(node["id"]),
                "agent_id": None,
            }
        agent = connection.execute(
            """
            SELECT a.id,a.node_id,a.principal_id FROM agents AS a
            JOIN principals AS p ON p.id=a.principal_id
            JOIN nodes AS n ON n.team_id=a.team_id AND n.id=a.node_id
            WHERE a.team_id=? AND a.id=? AND a.node_id=?
              AND a.status='active' AND p.status='active' AND n.status='active'
            """,
            (
                team_id,
                request_item["sender_agent_id"],
                request_item["sender_node_id"],
            ),
        ).fetchone()
        if agent is None:
            raise HubError("request_unavailable", "Requester is unavailable", 409)
        return {
            "kind": "agent",
            "principal_id": str(agent["principal_id"]),
            "node_id": str(agent["node_id"]),
            "agent_id": str(agent["id"]),
        }

    def create_network_request_reply(
        self,
        claims: AccessClaims,
        team_id: str,
        request_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        self._require_server_inbox_write(request, destination_required=False)
        clean_id = _identity(request_id)
        timestamp = _now()
        body, body_format, body_bytes = self._network_body(request)
        fingerprint = canonical_fingerprint(
            {
                "team_id": team_id,
                "request_id": clean_id,
                "from_agent_id": request.get("from_agent_id"),
                "body": body,
                "body_format": body_format,
            }
        )
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_network_scope(connection, claims, team_id, write=True)
                request_item = connection.execute(
                    self._network_item_select()
                    + """
                    JOIN network_passive_requests AS pr
                      ON pr.team_id=i.team_id AND pr.request_item_id=i.id
                    WHERE i.team_id=? AND i.id=? AND i.kind='request'
                    """,
                    (team_id, clean_id),
                ).fetchone()
                if request_item is None:
                    raise HubError("not_found", "Resource not found", 404)
                if (
                    request_item["sender_kind"] == "agent"
                    or request_item["recipient_kind"] == "agent"
                ):
                    # Retain legacy agent-addressed request history, but never
                    # append a new cross-server agent-authored/directed reply.
                    raise HubError(
                        "invalid_request",
                        "Agent-addressed Team Network requests are retired",
                        422,
                    )
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.request.reply",
                    request["idempotency_key"],
                    fingerprint,
                )
                if cached is not None:
                    return cached
                if request_item["request_status"] != "open" or int(
                    request_item["request_expires_at"]
                ) <= timestamp:
                    raise HubError(
                        "request_unavailable", "Passive request is no longer open", 409
                    )
                if (
                    claims.auth_kind == "human"
                    and request_item["recipient_kind"] == "human"
                    and request_item["recipient_principal_id"]
                    == claims.principal_id
                ):
                    authorized = True
                else:
                    bound = self._caller_network_node(
                        connection, claims, team_id
                    )
                    authorized = (
                        request_item["recipient_node_id"] == bound["node_id"]
                    )
                if not authorized:
                    raise HubError("not_found", "Resource not found", 404)
                from_agent_id = request.get("from_agent_id")
                if request_item["recipient_kind"] == "agent":
                    if claims.auth_kind == "human":
                        agent_author_matches = from_agent_id is None
                    else:
                        agent_author_matches = (
                            from_agent_id == request_item["recipient_agent_id"]
                        )
                    if not agent_author_matches:
                        raise HubError(
                            "forbidden",
                            "The addressed agent must author this reply",
                            403,
                        )
                sender = self._network_sender(
                    connection, claims, team_id, from_agent_id
                )
                recipient = self._network_reply_recipient(
                    connection, team_id, request_item
                )
                self._charge_network_peer_write(
                    connection, claims, team_id, body_bytes, timestamp
                )
                response, reply_row = self._insert_network_item(
                    connection,
                    team_id=team_id,
                    kind="reply",
                    sender=sender,
                    recipient=recipient,
                    body=body,
                    body_format=body_format,
                    operation="network.request.reply",
                    idempotency_key=request["idempotency_key"],
                    timestamp=timestamp,
                    root_request_item_id=clean_id,
                )
                reply_id = str(reply_row["id"])
                changed = connection.execute(
                    """
                    UPDATE network_passive_requests
                    SET status='replied',reply_item_id=?,replied_at=?
                    WHERE request_item_id=? AND status='open'
                    """,
                    (reply_id, timestamp, clean_id),
                ).rowcount
                if changed != 1:
                    raise HubError(
                        "request_unavailable", "Passive request is no longer open", 409
                    )
                updated_request = connection.execute(
                    """
                    SELECT request_item_id,status AS request_status,
                           expires_at AS request_expires_at,reply_item_id
                    FROM network_passive_requests WHERE request_item_id=?
                    """,
                    (clean_id,),
                ).fetchone()
                assert updated_request is not None
                response["request"] = self._network_request_public(
                    updated_request, timestamp=timestamp
                )
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.request.reply",
                    request["idempotency_key"],
                    fingerprint,
                    "network_request_reply",
                    reply_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "network.request.reply",
                    "network_request",
                    clean_id,
                    "succeeded",
                    {"reply_item_id": reply_id, "passive": True},
                    timestamp,
                )
                self._outbox(
                    connection,
                    team_id,
                    "network_request_reply",
                    reply_id,
                    "network.request.replied",
                    timestamp,
                )
                return response
        finally:
            connection.close()

    def list_channels(self, claims: AccessClaims, team_id: str) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_session(connection, claims, _now())
            _require_team_role(
                connection,
                team_id,
                claims.principal_id,
                ("owner", "admin", "member", "guest", "automation"),
            )
            rows = connection.execute(
                """
                SELECT * FROM channels WHERE team_id = ? AND archived_at IS NULL
                ORDER BY kind, display_name COLLATE NOCASE, id
                """,
                (team_id,),
            ).fetchall()
            channels = [
                self._channel_dict(connection, row, claims.principal_id)
                for row in rows
                if self._channel_permission(connection, row, claims.principal_id, "read")
            ]
            connection.execute("COMMIT")
            return {"channels": channels}
        except (AuthorizationError, AuthenticationError) as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise HubError("not_found", "Resource not found", 404) from exc
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def create_channel(
        self,
        claims: AccessClaims,
        team_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        timestamp = _now()
        request = dict(request)
        request["participant_principal_ids"] = sorted(
            set(request.get("participant_principal_ids") or [])
        )
        if request.get("kind") != "direct" and request.get("visibility") == "private":
            request["participant_principal_ids"] = sorted(
                set(request["participant_principal_ids"] + [claims.principal_id])
            )
        fingerprint = canonical_fingerprint(
            {"team_id": team_id, **{k: v for k, v in request.items() if k != "idempotency_key"}}
        )
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_session(connection, claims, timestamp)
                membership = _require_team_role(
                    connection,
                    team_id,
                    claims.principal_id,
                    ("owner", "admin", "member"),
                )
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "channel.create",
                    request["idempotency_key"],
                    fingerprint,
                )
                if cached is not None:
                    return cached
                kind = request["kind"]
                visibility = request["visibility"]
                participants = sorted(set(request.get("participant_principal_ids") or []))
                if kind == "direct":
                    if visibility != "private" or request.get("slug") is not None:
                        raise HubError("invalid_request", "Direct channels are private and have no slug", 422)
                    if len(participants) != 2 or claims.principal_id not in participants:
                        raise HubError(
                            "invalid_request",
                            "Direct channels require exactly the caller and one other participant",
                            422,
                        )
                    pair_key = hashlib.sha256("\0".join(participants).encode("utf-8")).digest()
                    slug = None
                    display_name = (
                        _bounded_text(request["display_name"], "display_name", 1, 160)
                        if request.get("display_name")
                        else None
                    )
                else:
                    if kind not in ("board", "announcements"):
                        raise HubError("invalid_request", "Unknown channel kind", 422)
                    if kind == "announcements" and membership["role"] not in ("owner", "admin"):
                        raise HubError("forbidden", "Operation is not permitted", 403)
                    slug_value = _bounded_text(request.get("slug") or "", "slug", 1, 80).lower()
                    if not all(character.isalnum() or character in "-_" for character in slug_value):
                        raise HubError("invalid_request", "slug contains unsupported characters", 422)
                    slug = slug_value
                    display_name = _bounded_text(
                        request.get("display_name") or "", "display_name", 1, 160
                    )
                    pair_key = None
                    if visibility == "private" and claims.principal_id not in participants:
                        participants.append(claims.principal_id)
                        participants.sort()
                for participant in participants:
                    valid = connection.execute(
                        """
                        SELECT 1 FROM principals AS p
                        WHERE p.id = ? AND p.status = 'active'
                          AND (
                            p.scope_team_id = ?
                            OR EXISTS (
                              SELECT 1 FROM memberships AS m
                              WHERE m.team_id = ? AND m.principal_id = p.id
                                AND m.status = 'active'
                            )
                          )
                        """,
                        (participant, team_id, team_id),
                    ).fetchone()
                    if valid is None:
                        raise HubError("invalid_request", "Channel participant is unavailable", 422)
                channel_id = _id("channel")
                connection.execute(
                    """
                    INSERT INTO channels(
                        id, team_id, kind, visibility, slug, display_name,
                        direct_pair_key, created_by_principal_id,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        channel_id,
                        team_id,
                        kind,
                        visibility,
                        slug,
                        display_name,
                        pair_key,
                        claims.principal_id,
                        timestamp,
                        timestamp,
                    ),
                )
                for participant in participants:
                    connection.execute(
                        """
                        INSERT INTO channel_participants(
                            team_id, channel_id, principal_id, participant_role,
                            status, joined_at, updated_at
                        ) VALUES (?, ?, ?, ?, 'active', ?, ?)
                        """,
                        (
                            team_id,
                            channel_id,
                            participant,
                            "manager" if participant == claims.principal_id else "member",
                            timestamp,
                            timestamp,
                        ),
                    )
                if kind == "direct" or visibility == "private":
                    for participant in participants:
                        connection.execute(
                            """
                            INSERT INTO channel_acl_entries(
                                id, team_id, channel_id, subject_kind,
                                subject_principal_id, subject_role,
                                can_read, can_post, can_manage, can_dispatch, created_at
                            ) VALUES (?, ?, ?, 'principal', ?, NULL, 1, 1, ?, 0, ?)
                            """,
                            (
                                _id("channel_acl"),
                                team_id,
                                channel_id,
                                participant,
                                1 if participant == claims.principal_id else 0,
                                timestamp,
                            ),
                        )
                else:
                    role_permissions = {
                        "owner": (1, 1, 1),
                        "admin": (1, 1, 1),
                        "member": (1, 0 if kind == "announcements" else 1, 0),
                        "guest": (1, 0, 0),
                        # Secure paired servers are automation principals. The
                        # gateway separately checks the peer's live mTLS
                        # certificate and teamspace.read/write scope on every
                        # request; this ACL only makes shared channels visible.
                        "automation": (
                            1,
                            0 if kind == "announcements" else 1,
                            0,
                        ),
                    }
                    for role, (can_read, can_post, can_manage) in role_permissions.items():
                        connection.execute(
                            """
                            INSERT INTO channel_acl_entries(
                                id, team_id, channel_id, subject_kind,
                                subject_principal_id, subject_role,
                                can_read, can_post, can_manage, can_dispatch, created_at
                            ) VALUES (?, ?, ?, 'role', NULL, ?, ?, ?, ?, 0, ?)
                            """,
                            (
                                _id("channel_acl"),
                                team_id,
                                channel_id,
                                role,
                                can_read,
                                can_post,
                                can_manage,
                                timestamp,
                            ),
                        )
                row = connection.execute("SELECT * FROM channels WHERE id = ?", (channel_id,)).fetchone()
                assert row is not None
                response = {
                    "channel": self._channel_dict(
                        connection, row, claims.principal_id
                    )
                }
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "channel.create",
                    request["idempotency_key"],
                    fingerprint,
                    "channel",
                    channel_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "channel.create",
                    "channel",
                    channel_id,
                    "succeeded",
                    {"kind": kind, "visibility": visibility},
                    timestamp,
                )
                self._outbox(
                    connection, team_id, "channel", channel_id, "channel.created", timestamp
                )
                return response
        except AuthorizationError as exc:
            raise HubError("forbidden", "Operation is not permitted", 403) from exc
        except sqlite3.IntegrityError as exc:
            raise HubError("conflict", "Channel already exists", 409) from exc
        finally:
            connection.close()

    # ------------------------------------------------------------------
    # Team Messages V2: messages with recipients and attachments, plus the
    # versioned Skills library.  See docs/TEAM_MESSAGES_V2.md in AgentsDock.

    def team_messages_capability(self) -> dict[str, Any]:
        return {
            "available": True,
            "version": 1,
            "kinds": ["message", "skill"],
            "recipient_kinds": ["server", "human", "all"],
            "max_body_bytes": MAX_TEAM_MESSAGE_BODY_BYTES,
            "max_recipients_per_message": MAX_TEAM_MESSAGE_RECIPIENTS,
            "max_page_items": MAX_NETWORK_PAGE_ITEMS,
            "attachments": {
                "max_bytes_per_file": self.team_attachment_max_bytes,
                "max_files_per_message": MAX_TEAM_MESSAGE_ATTACHMENTS,
                "max_bytes_per_message": MAX_TEAM_MESSAGE_ATTACHMENT_BYTES,
                "chunk_bytes": TEAM_ATTACHMENT_CHUNK_BYTES,
                "range_downloads": True,
                "team_quota_bytes": self.team_attachment_quota_bytes,
            },
            "skills": {
                "slug_pattern": TEAM_SKILL_SLUG_RE.pattern,
                "max_per_team": MAX_TEAM_SKILLS_PER_TEAM,
                "max_versions_per_skill": MAX_TEAM_SKILL_VERSIONS,
                "max_tags": MAX_TEAM_SKILL_TAGS,
            },
        }

    # -- validation helpers -------------------------------------------------

    @staticmethod
    def _team_text(
        value: Any,
        field: str,
        minimum: int,
        maximum: int,
        *,
        allow_none: bool = False,
    ) -> str | None:
        if value is None:
            if allow_none:
                return None
            if minimum == 0:
                return ""
            raise HubError("invalid_request", f"{field} is required", 422)
        if not isinstance(value, str):
            raise HubError("invalid_request", f"{field} is invalid", 422)
        normalized = " ".join(value.split())
        if not minimum <= len(normalized) <= maximum:
            raise HubError(
                "invalid_request",
                f"{field} must be between {minimum} and {maximum} characters",
                422,
            )
        return normalized

    @staticmethod
    def _team_body(request: dict[str, Any]) -> tuple[str, str, bytes, int]:
        body = request.get("body")
        if not isinstance(body, str):
            raise HubError("invalid_request", "Message body is invalid", 422)
        try:
            encoded = body.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise HubError("invalid_request", "Message body is invalid", 422) from exc
        if not 1 <= len(encoded) <= MAX_TEAM_MESSAGE_BODY_BYTES:
            raise HubError("invalid_request", "Message body is invalid", 422)
        body_format = request.get("body_format", "markdown")
        if body_format not in {"plain", "markdown"}:
            raise HubError("invalid_request", "Message body format is invalid", 422)
        return body, body_format, hashlib.sha256(encoded).digest(), len(encoded)

    @staticmethod
    def _team_slug(value: Any) -> str:
        slug = str(value or "").strip().lower()
        if TEAM_SKILL_SLUG_RE.fullmatch(slug) is None:
            raise HubError("invalid_request", "Skill slug is invalid", 422)
        return slug

    @staticmethod
    def _team_tags(value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list) or len(value) > MAX_TEAM_SKILL_TAGS:
            raise HubError("invalid_request", "Skill tags are invalid", 422)
        tags: list[str] = []
        for item in value:
            tag = item.strip().lower() if isinstance(item, str) else ""
            if TEAM_SKILL_TAG_RE.fullmatch(tag) is None:
                raise HubError("invalid_request", "Skill tags are invalid", 422)
            if tag not in tags:
                tags.append(tag)
        return tags

    @staticmethod
    def _team_provenance_field_valid(key: str, value: Any) -> bool:
        if value is None:
            return True
        if not isinstance(value, str):
            return False
        try:
            utf16_length = len(value.encode("utf-16-le")) // 2
        except UnicodeEncodeError:
            return False
        if key == "via":
            return value in {"agent", "desktop"}
        if key == "backend":
            return (
                1 <= utf16_length <= 80
                and value.strip() == value
                and re.search(r"[\x00-\x1f\x7f]", value) is None
            )
        return (
            1 <= utf16_length <= 240
            and value.strip() == value
            and re.search(r"[\x00-\x1f\x7f]", value) is None
        )

    @classmethod
    def _team_provenance(cls, value: Any) -> str:
        if value is None:
            return "{}"
        if (
            not isinstance(value, dict)
            or any(key not in TEAM_MESSAGE_PROVENANCE_KEYS for key in value)
            or any(
                not isinstance(key, str)
                or not cls._team_provenance_field_valid(key, item)
                for key, item in value.items()
            )
        ):
            raise HubError("invalid_request", "Provenance is invalid", 422)
        encoded = canonical_json(value)
        if len(encoded) > 2_048:
            raise HubError("invalid_request", "Provenance is invalid", 422)
        return encoded.decode("utf-8")

    @classmethod
    def _team_provenance_public(cls, value: Any) -> dict[str, str | None]:
        try:
            decoded = json.loads(str(value or "{}"))
        except (TypeError, ValueError):
            return {}
        if not isinstance(decoded, dict):
            return {}
        return {
            key: decoded[key]
            for key in TEAM_MESSAGE_PROVENANCE_KEYS
            if key in decoded and cls._team_provenance_field_valid(key, decoded[key])
        }

    @staticmethod
    def _team_idempotency_key(request: dict[str, Any]) -> str:
        key = request.get("idempotency_key")
        if not isinstance(key, str) or not 8 <= len(key) <= 240:
            raise HubError("invalid_request", "idempotency_key must be 8-240 characters", 422)
        return key

    @staticmethod
    def _team_sha256_hex(value: Any) -> str:
        digest = str(value or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise HubError("invalid_request", "sha256 must be 64 hex characters", 422)
        return digest

    @staticmethod
    def _team_since(value: Any) -> int | None:
        if value is None or value == "":
            return None
        if isinstance(value, bool):
            raise HubError("invalid_request", "since is invalid", 422)
        if isinstance(value, int):
            if value < 0:
                raise HubError("invalid_request", "since is invalid", 422)
            return value
        if isinstance(value, str):
            text = value.strip()
            if text.isdigit():
                return int(text)
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError as exc:
                raise HubError("invalid_request", "since is invalid", 422) from exc
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp())
        raise HubError("invalid_request", "since is invalid", 422)

    @staticmethod
    def _team_party(kind: str, identity: str, display_name: str | None) -> dict[str, Any]:
        return {
            "kind": kind,
            "id": identity,
            "display_name": display_name or ("Team" if kind == "all" else identity),
        }

    # -- identity helpers ---------------------------------------------------

    def _team_sender(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
    ) -> tuple[str, str | None]:
        if claims.auth_kind in NETWORK_AUTOMATION_AUTH_KINDS:
            node = self._caller_network_node(connection, claims, team_id)
            return "server", str(node["node_id"])
        return "human", None

    def _team_owned_addresses(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
        membership_role: str | None,
    ) -> list[tuple[str, str]]:
        """Addresses whose inbox this caller may read and receipt."""

        if claims.auth_kind in NETWORK_AUTOMATION_AUTH_KINDS:
            node = self._caller_network_node(connection, claims, team_id)
            return [("server", str(node["node_id"]))]
        owned: list[tuple[str, str]] = [("human", claims.principal_id)]
        if membership_role in {"owner", "admin", "member"}:
            try:
                node = self._caller_network_node(connection, claims, team_id)
            except HubError as exc:
                if exc.code != "network_host_unavailable":
                    raise
            else:
                owned.append(("server", str(node["node_id"])))
        return owned

    @staticmethod
    def _team_can_write(claims: AccessClaims, membership_role: str | None) -> bool:
        if claims.auth_kind in NETWORK_AUTOMATION_AUTH_KINDS:
            return "teamspace.write" in claims.scopes
        return membership_role in {"owner", "admin", "member"}

    # -- projections --------------------------------------------------------

    @staticmethod
    def _team_message_select() -> str:
        return """
            SELECT m.*, length(CAST(m.body AS BLOB)) AS body_bytes,
                   sp.display_name AS sender_principal_display_name,
                   sn.display_name AS sender_node_display_name,
                   s.slug AS skill_slug
            FROM team_messages AS m
            JOIN principals AS sp ON sp.id=m.sender_principal_id
            LEFT JOIN nodes AS sn ON sn.team_id=m.team_id AND sn.id=m.sender_node_id
            LEFT JOIN team_skills AS s ON s.team_id=m.team_id AND s.id=m.skill_id
        """

    @staticmethod
    def _team_sender_party(row: sqlite3.Row, prefix: str = "sender") -> dict[str, Any]:
        if row[f"{prefix}_kind"] == "server":
            return HubStore._team_party(
                "server",
                str(row[f"{prefix}_node_id"]),
                row[f"{prefix}_node_display_name"],
            )
        return HubStore._team_party(
            "human",
            str(row[f"{prefix}_principal_id"]),
            row[f"{prefix}_principal_display_name"],
        )

    @staticmethod
    def _team_recipient_public(row: sqlite3.Row) -> dict[str, Any]:
        kind = str(row["recipient_kind"])
        if kind == "server":
            party = HubStore._team_party(
                "server", str(row["recipient_node_id"]), row["node_display_name"]
            )
        elif kind == "human":
            party = HubStore._team_party(
                "human", str(row["recipient_principal_id"]), row["principal_display_name"]
            )
        else:
            party = HubStore._team_party("all", "all", "Team")
        return {
            **party,
            "state": row["state"],
            "delivered_at": _iso8601(row["delivered_at"]),
            "read_at": _iso8601(row["read_at"]),
        }

    @staticmethod
    def _team_attachment_public(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "message_id": row["message_id"],
            "file_name": row["file_name"],
            "media_type": row["media_type"],
            "byte_size": int(row["byte_size"]),
            "sha256": row["storage_key"],
            "state": row["state"],
            "received_bytes": int(row["received_bytes"]),
            "created_at": _iso8601(row["created_at"]),
            "ready_at": _iso8601(row["ready_at"]),
        }

    def _team_message_recipients(
        self, connection: sqlite3.Connection, team_id: str, message_id: str
    ) -> list[sqlite3.Row]:
        return connection.execute(
            """
            SELECT r.*, rp.display_name AS principal_display_name,
                   rn.display_name AS node_display_name
            FROM team_message_recipients AS r
            LEFT JOIN principals AS rp ON rp.id=r.recipient_principal_id
            LEFT JOIN nodes AS rn ON rn.team_id=r.team_id AND rn.id=r.recipient_node_id
            WHERE r.team_id=? AND r.message_id=?
            ORDER BY r.recipient_kind, r.id
            """,
            (team_id, message_id),
        ).fetchall()

    def _team_message_attachments(
        self, connection: sqlite3.Connection, team_id: str, message_id: str
    ) -> list[dict[str, Any]]:
        return [
            self._team_attachment_public(row)
            for row in connection.execute(
                """
                SELECT * FROM team_attachments
                WHERE team_id=? AND message_id=?
                ORDER BY created_at, id
                """,
                (team_id, message_id),
            )
        ]

    def _team_message_public(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        include_body: bool,
        owned: list[tuple[str, str]] | None = None,
        delivery_address: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        team_id = str(row["team_id"])
        message_id = str(row["id"])
        recipient_rows = self._team_message_recipients(connection, team_id, message_id)
        body = str(row["body"])
        item: dict[str, Any] = {
            "id": message_id,
            "sequence": int(row["queue_ordinal"]),
            "kind": row["kind"],
            # Old pre-V2 writers could persist a title on an ordinary message.
            # Keep the wire contract strict so one legacy row cannot poison a
            # client's entire inbox/feed response.
            "title": row["title"] if row["kind"] == "skill" else None,
            "body_format": row["body_format"],
            "body_bytes": int(row["body_bytes"]),
            "body_sha256": bytes(row["body_sha256"]).hex(),
            "sender": self._team_sender_party(row),
            "recipients": [self._team_recipient_public(item) for item in recipient_rows],
            "attachments": self._team_message_attachments(connection, team_id, message_id),
            "in_reply_to_message_id": row["in_reply_to_message_id"],
            "skill": (
                {
                    "id": row["skill_id"],
                    "slug": row["skill_slug"],
                    "version": int(row["skill_version"]),
                }
                if row["skill_id"] is not None
                else None
            ),
            "provenance": self._team_provenance_public(row["provenance_json"]),
            "created_at": _iso8601(row["created_at"]),
        }
        if include_body:
            item["body"] = body
        else:
            preview = " ".join(body.split())
            if len(preview) > MAX_TEAM_MESSAGE_PREVIEW_CHARS:
                preview = preview[: MAX_TEAM_MESSAGE_PREVIEW_CHARS - 1] + "…"
            item["preview"] = preview
        if owned is not None:
            mine = [
                self._team_recipient_public(recipient)
                for recipient in recipient_rows
                if recipient["recipient_kind"] != "all"
                and (
                    str(recipient["recipient_kind"]),
                    str(recipient["recipient_node_id"] or recipient["recipient_principal_id"]),
                )
                in owned
            ]
            if delivery_address is not None:
                delivery_kind, delivery_id = delivery_address
                mine = [
                    recipient
                    for recipient in mine
                    if recipient["kind"] == delivery_kind
                    and recipient["id"] == delivery_id
                ]
            item["delivery"] = mine[0] if mine else None
        return item

    def _team_message_visible(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        row: sqlite3.Row,
        owned: list[tuple[str, str]],
    ) -> bool:
        if row["sender_kind"] == "human" and row["sender_principal_id"] == claims.principal_id:
            return True
        if row["sender_kind"] == "server" and ("server", str(row["sender_node_id"])) in owned:
            return True
        for recipient in connection.execute(
            """
            SELECT recipient_kind, recipient_node_id, recipient_principal_id
            FROM team_message_recipients WHERE team_id=? AND message_id=?
            """,
            (row["team_id"], row["id"]),
        ):
            kind = str(recipient["recipient_kind"])
            if kind == "all":
                return True
            identity = recipient["recipient_node_id"] or recipient["recipient_principal_id"]
            if (kind, str(identity)) in owned:
                return True
        return False

    # -- messages -----------------------------------------------------------

    def create_team_message(
        self,
        claims: AccessClaims,
        team_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        timestamp = _now()
        kind = request.get("kind")
        if kind not in {"message", "skill"}:
            raise HubError("invalid_request", "Message kind is invalid", 422)
        title = self._team_text(
            request.get("title"), "title", 1, MAX_TEAM_MESSAGE_TITLE_CHARS, allow_none=True
        )
        if kind == "message" and title is not None:
            raise HubError("invalid_request", "Only skill posts carry a title", 422)
        body, body_format, body_digest, body_bytes = self._team_body(request)
        provenance_json = self._team_provenance(request.get("provenance"))
        idempotency_key = self._team_idempotency_key(request)
        reply_to = request.get("in_reply_to_message_id")
        if reply_to is not None and (not isinstance(reply_to, str) or not 8 <= len(reply_to) <= 240):
            raise HubError("invalid_request", "in_reply_to_message_id is invalid", 422)
        raw_recipients = request.get("recipients")
        if (
            not isinstance(raw_recipients, list)
            or not 1 <= len(raw_recipients) <= MAX_TEAM_MESSAGE_RECIPIENTS
        ):
            raise HubError("invalid_request", "Message recipients are invalid", 422)
        requested: list[tuple[str, str | None]] = []
        for entry in raw_recipients:
            if not isinstance(entry, dict) or entry.get("kind") not in {"server", "human", "all"}:
                raise HubError("invalid_request", "Message recipients are invalid", 422)
            recipient_kind = str(entry["kind"])
            recipient_id = entry.get("id")
            if recipient_kind == "all":
                if recipient_id not in (None, "all"):
                    raise HubError("invalid_request", "Message recipients are invalid", 422)
                recipient_id = None
            elif not isinstance(recipient_id, str) or not 1 <= len(recipient_id) <= 240:
                raise HubError("invalid_request", "Message recipients are invalid", 422)
            if (recipient_kind, recipient_id) not in requested:
                requested.append((recipient_kind, recipient_id))
        raw_attachments = request.get("attachment_ids") or []
        if (
            not isinstance(raw_attachments, list)
            or len(raw_attachments) > MAX_TEAM_MESSAGE_ATTACHMENTS
            or any(not isinstance(item, str) or not 8 <= len(item) <= 240 for item in raw_attachments)
            or len(set(raw_attachments)) != len(raw_attachments)
        ):
            raise HubError("invalid_request", "Message attachments are invalid", 422)
        skill_request = request.get("skill")
        slug: str | None = None
        skill_summary = ""
        skill_tags: list[str] = []
        change_note = ""
        expected_version: int | None = None
        if kind == "skill":
            if title is None:
                raise HubError("invalid_request", "A skill post requires a title", 422)
            if not isinstance(skill_request, dict):
                raise HubError("invalid_request", "A skill post requires skill details", 422)
            if requested != [("all", None)]:
                raise HubError(
                    "invalid_request", "A skill post must be addressed to the whole team", 422
                )
            slug = self._team_slug(skill_request.get("slug"))
            skill_summary = str(self._team_text(skill_request.get("summary"), "summary", 0, 280))
            skill_tags = self._team_tags(skill_request.get("tags"))
            change_note = str(
                self._team_text(skill_request.get("change_note"), "change note", 0, 280)
            )
            expected_version = skill_request.get("expected_version")
            if expected_version is not None and (
                type(expected_version) is not int or expected_version < 1
            ):
                raise HubError("invalid_request", "expected_version is invalid", 422)
        elif skill_request is not None:
            raise HubError("invalid_request", "Only skill posts carry skill details", 422)
        fingerprint = canonical_fingerprint(
            {
                "team_id": team_id,
                "kind": kind,
                "title": title,
                "body": body,
                "body_format": body_format,
                "recipients": requested,
                "attachment_ids": list(raw_attachments),
                "in_reply_to_message_id": reply_to,
                "skill": (
                    {
                        "slug": slug,
                        "summary": skill_summary,
                        "tags": skill_tags,
                        "change_note": change_note,
                        "expected_version": expected_version,
                    }
                    if kind == "skill"
                    else None
                ),
                "provenance": provenance_json,
            }
        )
        connection = self.connect()
        try:
            with _write_transaction(connection):
                membership = self._require_network_scope(connection, claims, team_id, write=True)
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "team.message.create",
                    idempotency_key,
                    fingerprint,
                )
                if cached is not None:
                    return cached
                sender_kind, sender_node_id = self._team_sender(connection, claims, team_id)
                resolved: list[tuple[str, str | None, str | None]] = []
                for recipient_kind, recipient_id in requested:
                    if recipient_kind == "all":
                        resolved.append(("all", None, None))
                        continue
                    if recipient_kind == "server":
                        found = connection.execute(
                            """
                            SELECT id FROM nodes
                            WHERE team_id=? AND id=? AND status<>'revoked'
                            """,
                            (team_id, recipient_id),
                        ).fetchone()
                        if found is None:
                            raise HubError(
                                "recipient_unavailable",
                                "Team Network server recipient is unavailable",
                                404,
                            )
                        resolved.append(("server", str(found["id"]), None))
                        continue
                    found = connection.execute(
                        """
                        SELECT p.id FROM principals AS p
                        JOIN memberships AS m ON m.team_id=? AND m.principal_id=p.id
                        WHERE p.id=? AND p.kind='human' AND p.status='active'
                          AND m.status='active'
                        """,
                        (team_id, recipient_id),
                    ).fetchone()
                    if found is None:
                        raise HubError(
                            "recipient_unavailable",
                            "Team Network member recipient is unavailable",
                            404,
                        )
                    resolved.append(("human", None, str(found["id"])))
                if reply_to is not None:
                    parent = connection.execute(
                        "SELECT id FROM team_messages WHERE team_id=? AND id=?",
                        (team_id, reply_to),
                    ).fetchone()
                    if parent is None:
                        raise HubError("invalid_request", "Reply target is unavailable", 422)
                attachment_rows: list[sqlite3.Row] = []
                attachment_bytes = 0
                for attachment_id in raw_attachments:
                    attachment = connection.execute(
                        "SELECT * FROM team_attachments WHERE team_id=? AND id=?",
                        (team_id, attachment_id),
                    ).fetchone()
                    if (
                        attachment is None
                        or attachment["state"] != "ready"
                        or attachment["message_id"] is not None
                        or attachment["uploaded_by_principal_id"] != claims.principal_id
                        or int(attachment["expires_at"]) <= timestamp
                    ):
                        raise HubError(
                            "attachment_unavailable",
                            "An attachment is missing, unfinished, expired, or already used",
                            409,
                        )
                    attachment_rows.append(attachment)
                    attachment_bytes += int(attachment["byte_size"])
                if attachment_bytes > MAX_TEAM_MESSAGE_ATTACHMENT_BYTES:
                    raise HubError(
                        "attachment_limit", "Attachments exceed the per-message limit", 413
                    )
                self._charge_network_peer_write(
                    connection, claims, team_id, body_bytes, timestamp
                )
                message_id = _id("tmsg")
                skill_id: str | None = None
                skill_version: int | None = None
                if kind == "skill":
                    assert slug is not None and title is not None
                    skill = connection.execute(
                        "SELECT * FROM team_skills WHERE team_id=? AND slug=?",
                        (team_id, slug),
                    ).fetchone()
                    if skill is None:
                        if expected_version is not None:
                            raise HubError(
                                "skill_version_conflict",
                                "The skill does not exist yet; omit expected_version",
                                409,
                            )
                        count = connection.execute(
                            "SELECT COUNT(*) FROM team_skills WHERE team_id=?", (team_id,)
                        ).fetchone()[0]
                        if int(count) >= MAX_TEAM_SKILLS_PER_TEAM:
                            raise HubError(
                                "skill_limit", "This team has reached its skill limit", 409
                            )
                        skill_id = _id("tskill")
                        skill_version = 1
                        connection.execute(
                            """
                            INSERT INTO team_skills(
                                id,team_id,slug,title,summary,tags_json,current_version,
                                created_by_principal_id,created_at,updated_at
                            ) VALUES (?,?,?,?,?,?,1,?,?,?)
                            """,
                            (
                                skill_id,
                                team_id,
                                slug,
                                title,
                                skill_summary,
                                json.dumps(skill_tags, separators=(",", ":")),
                                claims.principal_id,
                                timestamp,
                                timestamp,
                            ),
                        )
                    else:
                        if skill["archived_at"] is not None:
                            raise HubError(
                                "skill_archived", "Restore the skill before updating it", 409
                            )
                        if expected_version is None or expected_version != int(
                            skill["current_version"]
                        ):
                            raise HubError(
                                "skill_version_conflict",
                                "The skill changed since it was loaded",
                                409,
                            )
                        versions = connection.execute(
                            "SELECT COUNT(*) FROM team_skill_versions WHERE skill_id=?",
                            (skill["id"],),
                        ).fetchone()[0]
                        if int(versions) >= MAX_TEAM_SKILL_VERSIONS:
                            raise HubError(
                                "skill_limit", "This skill has reached its version limit", 409
                            )
                        skill_id = str(skill["id"])
                        skill_version = expected_version + 1
                        connection.execute(
                            """
                            UPDATE team_skills
                            SET title=?,summary=?,tags_json=?,current_version=?,updated_at=?
                            WHERE team_id=? AND id=?
                            """,
                            (
                                title,
                                skill_summary,
                                json.dumps(skill_tags, separators=(",", ":")),
                                skill_version,
                                timestamp,
                                team_id,
                                skill_id,
                            ),
                        )
                connection.execute(
                    """
                    INSERT INTO team_messages(
                        id,team_id,kind,title,body_format,body,body_sha256,
                        sender_kind,sender_principal_id,sender_node_id,provenance_json,
                        in_reply_to_message_id,skill_id,skill_version,
                        attachment_count,attachment_bytes,idempotency_key,created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        message_id,
                        team_id,
                        kind,
                        title,
                        body_format,
                        body,
                        body_digest,
                        sender_kind,
                        claims.principal_id,
                        sender_node_id,
                        provenance_json,
                        reply_to,
                        skill_id,
                        skill_version,
                        len(attachment_rows),
                        attachment_bytes,
                        hashlib.sha256(
                            f"{team_id}\0{claims.principal_id}\0team.message.create\0{idempotency_key}".encode(
                                "utf-8"
                            )
                        ).digest(),
                        timestamp,
                    ),
                )
                for recipient_kind, node_id, principal_id in resolved:
                    connection.execute(
                        """
                        INSERT INTO team_message_recipients(
                            id,team_id,message_id,recipient_kind,recipient_node_id,
                            recipient_principal_id,state
                        ) VALUES (?,?,?,?,?,?,'available')
                        """,
                        (_id("trcpt"), team_id, message_id, recipient_kind, node_id, principal_id),
                    )
                for attachment in attachment_rows:
                    bound = connection.execute(
                        """
                        UPDATE team_attachments SET message_id=?
                        WHERE team_id=? AND id=? AND message_id IS NULL AND state='ready'
                          AND expires_at>?
                        """,
                        (message_id, team_id, attachment["id"], timestamp),
                    )
                    if bound.rowcount != 1:
                        raise HubError(
                            "attachment_unavailable",
                            "An attachment is missing, unfinished, expired, or already used",
                            409,
                        )
                skill_version_id: str | None = None
                if kind == "skill":
                    assert skill_id is not None and skill_version is not None
                    skill_version_id = _id("tskillv")
                    connection.execute(
                        """
                        INSERT INTO team_skill_versions(
                            id,team_id,skill_id,version,message_id,title,summary,
                            tags_json,change_note,created_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            skill_version_id,
                            team_id,
                            skill_id,
                            skill_version,
                            message_id,
                            title,
                            skill_summary,
                            json.dumps(skill_tags, separators=(",", ":")),
                            change_note,
                            timestamp,
                        ),
                    )
                row = connection.execute(
                    self._team_message_select() + " WHERE m.team_id=? AND m.id=?",
                    (team_id, message_id),
                ).fetchone()
                assert row is not None
                response = {
                    "message": self._team_message_public(connection, row, include_body=True)
                }
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "team.message.create",
                    idempotency_key,
                    fingerprint,
                    "team_message",
                    message_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "team.message.create",
                    "team_message",
                    message_id,
                    "succeeded",
                    {
                        "kind": kind,
                        "recipient_kinds": sorted({item[0] for item in resolved}),
                        "attachments": len(attachment_rows),
                        "skill_slug": slug,
                        "skill_version": skill_version,
                    },
                    timestamp,
                )
                self._outbox(
                    connection, team_id, "team_message", message_id, "team.message.created", timestamp
                )
                if skill_version_id is not None:
                    # Outbox effects are deduplicated per aggregate and event
                    # type, so each version is its own aggregate.
                    self._outbox(
                        connection,
                        team_id,
                        "team_skill_version",
                        skill_version_id,
                        "team.skill.versioned",
                        timestamp,
                    )
                return response
        except sqlite3.IntegrityError as exc:
            raise HubError("conflict", "Team message conflicts with existing data", 409) from exc
        finally:
            connection.close()

    def list_team_messages(
        self,
        claims: AccessClaims,
        team_id: str,
        *,
        box: str,
        address_kind: str | None = None,
        address_id: str | None = None,
        unread: bool = False,
        from_kind: str | None = None,
        from_id: str | None = None,
        since: Any = None,
        after_sequence: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        if box not in {"inbox", "feed", "sent"}:
            raise HubError("invalid_request", "Message box is invalid", 422)
        if type(limit) is not int or not 1 <= limit <= MAX_NETWORK_PAGE_ITEMS:
            raise HubError("invalid_request", "Message page limit is invalid", 422)
        if type(after_sequence) is not int or after_sequence < 0:
            raise HubError("invalid_request", "Message page cursor is invalid", 422)
        if from_kind is not None and from_kind not in {"server", "human"}:
            raise HubError("invalid_request", "Sender filter is invalid", 422)
        if (from_kind is None) != (from_id is None):
            raise HubError("invalid_request", "Sender filter is invalid", 422)
        since_epoch = self._team_since(since)
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            membership = self._require_network_scope(connection, claims, team_id, write=False)
            owned = self._team_owned_addresses(
                connection, claims, team_id, str(membership["role"])
            )
            where = ["m.team_id=?", "m.queue_ordinal>?"]
            params: list[Any] = [team_id, after_sequence]
            joins = ""
            if box == "feed":
                joins = (
                    " JOIN team_message_recipients AS r"
                    " ON r.team_id=m.team_id AND r.message_id=m.id"
                    " AND r.recipient_kind='all'"
                )
            elif box == "inbox":
                if address_kind is None and address_id is None:
                    address_kind, address_id = owned[0]
                if (address_kind, address_id) not in owned:
                    raise HubError(
                        "forbidden", "This mailbox is not owned by the caller", 403
                    )
                column = (
                    "recipient_node_id" if address_kind == "server" else "recipient_principal_id"
                )
                joins = (
                    " JOIN team_message_recipients AS r"
                    " ON r.team_id=m.team_id AND r.message_id=m.id"
                    f" AND r.recipient_kind=? AND r.{column}=?"
                )
                params = [address_kind, address_id, *params]
                if unread:
                    where.append("r.state<>'read'")
            else:
                if claims.auth_kind in NETWORK_AUTOMATION_AUTH_KINDS:
                    server_ids = [identity for kind, identity in owned if kind == "server"]
                    where.append("m.sender_kind='server' AND m.sender_node_id=?")
                    params.append(server_ids[0])
                else:
                    where.append("m.sender_kind='human' AND m.sender_principal_id=?")
                    params.append(claims.principal_id)
            if from_kind == "server":
                where.append("m.sender_kind='server' AND m.sender_node_id=?")
                params.append(from_id)
            elif from_kind == "human":
                where.append("m.sender_kind='human' AND m.sender_principal_id=?")
                params.append(from_id)
            if since_epoch is not None:
                where.append("m.created_at>=?")
                params.append(since_epoch)
            rows = connection.execute(
                self._team_message_select()
                + joins
                + " WHERE "
                + " AND ".join(where)
                + " ORDER BY m.queue_ordinal ASC LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
            visible = rows[:limit]
            messages = [
                self._team_message_public(
                    connection,
                    row,
                    include_body=False,
                    owned=owned if box == "inbox" else None,
                    delivery_address=(str(address_kind), str(address_id))
                    if box == "inbox"
                    else None,
                )
                for row in visible
            ]
            response = {
                "box": box,
                "address": (
                    {"kind": address_kind, "id": address_id} if box == "inbox" else None
                ),
                "messages": messages,
                "next_after_sequence": (
                    int(visible[-1]["queue_ordinal"]) if visible else after_sequence
                ),
                "has_more": len(rows) > limit,
            }
            if len(canonical_json(response)) > MAX_NETWORK_PAGE_RESPONSE_BYTES:
                raise HubError(
                    "invalid_request", "Message page exceeds the response limit; lower limit", 422
                )
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def get_team_message(
        self, claims: AccessClaims, team_id: str, message_id: str
    ) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            membership = self._require_network_scope(connection, claims, team_id, write=False)
            row = connection.execute(
                self._team_message_select() + " WHERE m.team_id=? AND m.id=?",
                (team_id, message_id),
            ).fetchone()
            if row is None:
                raise HubError("not_found", "Resource not found", 404)
            owned = self._team_owned_addresses(
                connection, claims, team_id, str(membership["role"])
            )
            if not self._team_message_visible(connection, claims, row, owned):
                raise HubError("not_found", "Resource not found", 404)
            response = {
                "message": self._team_message_public(
                    connection, row, include_body=True, owned=owned
                )
            }
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def record_team_message_receipt(
        self,
        claims: AccessClaims,
        team_id: str,
        message_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        timestamp = _now()
        state = request.get("state")
        if state not in {"delivered", "read"}:
            raise HubError("invalid_request", "Receipt state is invalid", 422)
        idempotency_key = self._team_idempotency_key(request)
        fingerprint = canonical_fingerprint(
            {"team_id": team_id, "message_id": message_id, "state": state}
        )
        connection = self.connect()
        try:
            with _write_transaction(connection):
                membership = self._require_network_scope(connection, claims, team_id, write=False)
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "team.message.receipt",
                    idempotency_key,
                    fingerprint,
                )
                if cached is not None:
                    return cached
                owned = self._team_owned_addresses(
                    connection, claims, team_id, str(membership["role"])
                )
                rows = [
                    recipient
                    for recipient in self._team_message_recipients(connection, team_id, message_id)
                    if recipient["recipient_kind"] != "all"
                    and (
                        str(recipient["recipient_kind"]),
                        str(recipient["recipient_node_id"] or recipient["recipient_principal_id"]),
                    )
                    in owned
                ]
                if not rows:
                    raise HubError("forbidden", "This message is not addressed to the caller", 403)
                changed_recipient_ids: list[str] = []
                for recipient in rows:
                    current = str(recipient["state"])
                    if current == "read" or (current == "delivered" and state == "delivered"):
                        continue
                    if state == "delivered":
                        connection.execute(
                            """
                            UPDATE team_message_recipients
                            SET state='delivered',delivered_at=? WHERE id=?
                            """,
                            (timestamp, recipient["id"]),
                        )
                    else:
                        connection.execute(
                            """
                            UPDATE team_message_recipients
                            SET state='read',delivered_at=COALESCE(delivered_at,?),read_at=?
                            WHERE id=?
                            """,
                            (timestamp, timestamp, recipient["id"]),
                        )
                    changed_recipient_ids.append(str(recipient["id"]))
                updated = [
                    self._team_recipient_public(recipient)
                    for recipient in self._team_message_recipients(connection, team_id, message_id)
                    if recipient["id"] in {item["id"] for item in rows}
                ]
                response = {"message_id": message_id, "recipients": updated}
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "team.message.receipt",
                    idempotency_key,
                    fingerprint,
                    "team_message",
                    message_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "team.message.receipt",
                    "team_message",
                    message_id,
                    "succeeded",
                    {"state": state},
                    timestamp,
                )
                for recipient_id in changed_recipient_ids:
                    self._outbox(
                        connection,
                        team_id,
                        "team_message_recipient",
                        recipient_id,
                        f"team.message.{state}",
                        timestamp,
                    )
                return response
        finally:
            connection.close()

    # -- attachments --------------------------------------------------------

    @property
    def team_attachment_root(self) -> Path:
        root = self.data_dir / "attachments"
        ensure_private_directory(root)
        return root

    def _team_attachment_storage_path(self, storage_key: str) -> Path:
        return self.team_attachment_root / storage_key[:2] / storage_key

    def _team_attachment_staging_path(self, attachment_id: str) -> Path:
        uploads = self.team_attachment_root / "uploads"
        ensure_private_directory(uploads)
        return uploads / f"{attachment_id}.part"

    @staticmethod
    def _team_attachment_file_signature(info: os.stat_result) -> tuple[int, ...]:
        """Return the identity and mutation fields anchored by attachment I/O."""

        return (
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_mode),
            int(info.st_nlink),
            int(info.st_uid),
            int(info.st_size),
            int(info.st_mtime_ns),
            int(info.st_ctime_ns),
        )

    @classmethod
    def _verify_team_attachment_descriptor(
        cls,
        descriptor: int,
        *,
        expected_size: int,
        require_single_link: bool,
        linked_stat: Callable[[], os.stat_result],
    ) -> str:
        """Hash one exact, stable private inode and verify its live pathname."""

        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink < 1
            or (require_single_link and before.st_nlink != 1)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != expected_size
        ):
            raise PermissionError("Team attachment file is unsafe")
        digest = hashlib.sha256()
        offset = 0
        while offset < expected_size:
            block = os.pread(descriptor, min(1024 * 1024, expected_size - offset), offset)
            if not block:
                raise RuntimeError("Team attachment file changed while hashing")
            digest.update(block)
            offset += len(block)
        after = os.fstat(descriptor)
        linked = linked_stat()
        signature = cls._team_attachment_file_signature(before)
        if (
            signature != cls._team_attachment_file_signature(after)
            or signature != cls._team_attachment_file_signature(linked)
        ):
            raise RuntimeError("Team attachment file changed while hashing")
        return digest.hexdigest()

    def _open_verified_team_attachment_blob(
        self,
        storage_key: str,
        byte_size: int,
    ) -> int:
        """Open and authenticate one immutable content-addressed attachment."""

        path = self._team_attachment_storage_path(storage_key)
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
            os, "O_DIRECTORY", 0
        )
        directory = os.open(path.parent, directory_flags)
        descriptor = -1
        try:
            directory_info = os.fstat(directory)
            if (
                not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != os.getuid()
                or stat.S_IMODE(directory_info.st_mode) != 0o700
            ):
                raise PermissionError("Team attachment content directory is unsafe")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(path.name, flags, dir_fd=directory)
            digest = self._verify_team_attachment_descriptor(
                descriptor,
                expected_size=byte_size,
                # Snapshot generations may hold safe immutable hard links to
                # a live blob while the attachment-control lease is held.
                require_single_link=False,
                linked_stat=lambda: os.stat(
                    path.name,
                    dir_fd=directory,
                    follow_symlinks=False,
                ),
            )
            if not hmac.compare_digest(digest, storage_key):
                raise PermissionError("Team attachment digest is invalid")
            return descriptor
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        finally:
            os.close(directory)

    def _open_team_attachment_staging(
        self,
        attachment_id: str,
        received: int,
    ) -> tuple[int, int, str]:
        """Create first-chunk staging exclusively or pin a safe resumed inode."""

        staging = self._team_attachment_staging_path(attachment_id)
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
            os, "O_DIRECTORY", 0
        )
        directory = os.open(staging.parent, directory_flags)
        descriptor = -1
        try:
            directory_info = os.fstat(directory)
            if (
                not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != os.getuid()
                or stat.S_IMODE(directory_info.st_mode) != 0o700
            ):
                raise PermissionError("Team attachment staging directory is unsafe")
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            if received == 0:
                # Never open/truncate an attacker-precreated hard link, FIFO,
                # device, or stale pathname on the first chunk.
                flags |= os.O_CREAT | os.O_EXCL
            descriptor = os.open(staging.name, flags, 0o600, dir_fd=directory)
            if received == 0:
                os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            linked = os.stat(staging.name, dir_fd=directory, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or self._team_attachment_file_signature(opened)
                != self._team_attachment_file_signature(linked)
            ):
                raise PermissionError("Team attachment staging file is unsafe")
            if opened.st_size > received:
                # A crash after file fsync but before SQLite commit is safely
                # resumable from the last durable database offset.
                os.ftruncate(descriptor, received)
            elif opened.st_size < received:
                raise RuntimeError("Team attachment upload state was lost")
            current = os.fstat(descriptor)
            linked = os.stat(staging.name, dir_fd=directory, follow_symlinks=False)
            if (
                current.st_size != received
                or self._team_attachment_file_signature(current)
                != self._team_attachment_file_signature(linked)
            ):
                raise RuntimeError("Team attachment staging file changed")
            return descriptor, directory, staging.name
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory)
            raise

    def _team_attachment_staging_absent(self, attachment_id: str) -> bool:
        """Observe exact staging-name absence through its private directory."""

        staging = self._team_attachment_staging_path(attachment_id)
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
            os, "O_DIRECTORY", 0
        )
        directory = os.open(staging.parent, directory_flags)
        try:
            directory_info = os.fstat(directory)
            if (
                not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != os.getuid()
                or stat.S_IMODE(directory_info.st_mode) != 0o700
            ):
                raise PermissionError("Team attachment staging directory is unsafe")
            try:
                os.stat(staging.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return True
            return False
        finally:
            os.close(directory)

    @classmethod
    def _unlink_open_team_attachment_staging(
        cls,
        descriptor: int,
        directory: int,
        filename: str,
    ) -> None:
        """Unlink only when the staging name still denotes the pinned inode."""

        opened = os.fstat(descriptor)
        linked = os.stat(filename, dir_fd=directory, follow_symlinks=False)
        if (
            opened.st_nlink != 1
            or cls._team_attachment_file_signature(opened)
            != cls._team_attachment_file_signature(linked)
        ):
            raise RuntimeError("Team attachment staging file changed")
        os.unlink(filename, dir_fd=directory)
        os.fsync(directory)

    def _mark_team_attachment_ready_locked(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        claims: AccessClaims,
        team_id: str,
        timestamp: int,
    ) -> None:
        """Publish ready metadata, audit, and outbox in the caller's transaction."""

        attachment_id = str(row["id"])
        byte_size = int(row["byte_size"])
        connection.execute(
            """
            UPDATE team_attachments
            SET received_bytes=?,state='ready',ready_at=?,expires_at=?
            WHERE id=? AND state='uploading'
            """,
            (
                byte_size,
                timestamp,
                timestamp + TEAM_ATTACHMENT_UPLOAD_TTL_SECONDS,
                attachment_id,
            ),
        )
        self._audit(
            connection,
            team_id,
            claims.principal_id,
            "team.attachment.ready",
            "team_attachment",
            attachment_id,
            "succeeded",
            {"byte_size": byte_size},
            timestamp,
        )
        self._outbox(
            connection,
            team_id,
            "team_attachment",
            attachment_id,
            "team.attachment.ready",
            timestamp,
        )

    @staticmethod
    def _validate_team_attachment_cleanup_key(path_kind: str, path_key: str) -> None:
        if path_kind == "staging" and TEAM_ATTACHMENT_ID_RE.fullmatch(path_key):
            return
        if path_kind == "content" and TEAM_ATTACHMENT_STORAGE_KEY_RE.fullmatch(path_key):
            return
        raise RuntimeError("Team attachment cleanup key is invalid")

    def _unlink_team_attachment_cleanup_path(
        self,
        path_kind: str,
        path_key: str,
    ) -> None:
        """Unlink one exact owner-only attachment file without following links."""

        self._validate_team_attachment_cleanup_key(path_kind, path_key)
        root = self.team_attachment_root
        if path_kind == "staging":
            parent = root / "uploads"
            filename = f"{path_key}.part"
        else:
            parent = root / path_key[:2]
            filename = path_key
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
            os, "O_DIRECTORY", 0
        )
        try:
            directory = os.open(parent, directory_flags)
        except FileNotFoundError:
            return
        descriptor = -1
        try:
            directory_info = os.fstat(directory)
            if (
                not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != os.getuid()
                or stat.S_IMODE(directory_info.st_mode) != 0o700
            ):
                raise PermissionError("Team attachment cleanup directory is unsafe")
            file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            file_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
                os, "O_NONBLOCK", 0
            )
            try:
                descriptor = os.open(filename, file_flags, dir_fd=directory)
            except FileNotFoundError:
                # A prior attempt may have unlinked the file and crashed before
                # retiring its tombstone. Anchor the observed absence before
                # committing the cleanup record deletion.
                os.fsync(directory)
                return
            opened = os.fstat(descriptor)
            linked = os.stat(filename, dir_fd=directory, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink < 1
                or (path_kind == "staging" and opened.st_nlink != 1)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
            ):
                raise PermissionError("Team attachment cleanup file is unsafe")
            os.unlink(filename, dir_fd=directory)
            os.fsync(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory)

    def _drain_team_attachment_cleanup_queue_locked(
        self,
        connection: sqlite3.Connection,
        *,
        limit: int,
    ) -> int:
        """Retry a bounded set of committed attachment cleanup tombstones.

        The caller holds the cross-process attachment lease. Content tombstones
        are rechecked against ready metadata so a blob reused after an earlier
        unlink failure is never removed. Unsafe or transiently undeletable
        paths stay queued for a later pass.
        """

        pending = connection.execute(
            """
            SELECT path_kind,path_key FROM team_attachment_cleanup_queue
            ORDER BY attempt_count,created_at,path_kind,path_key LIMIT ?
            """,
            (limit,),
        ).fetchall()
        completed: list[tuple[str, str]] = []
        failed: list[tuple[str, str]] = []
        for row in pending:
            path_kind = str(row["path_kind"])
            path_key = str(row["path_key"])
            try:
                self._validate_team_attachment_cleanup_key(path_kind, path_key)
            except RuntimeError:
                # The migration constrains these values. If an externally
                # corrupted database bypasses that invariant, fail closed on
                # filesystem mutation and retain the evidence for repair.
                failed.append((path_kind, path_key))
                continue
            if path_kind == "staging":
                protected = connection.execute(
                    "SELECT 1 FROM team_attachments WHERE id=? LIMIT 1",
                    (path_key,),
                ).fetchone()
            else:
                protected = connection.execute(
                    """
                    SELECT 1 FROM team_attachments
                    WHERE storage_key=? AND state='ready' LIMIT 1
                    """,
                    (path_key,),
                ).fetchone()
            if protected is not None:
                completed.append((path_kind, path_key))
                continue
            try:
                self._unlink_team_attachment_cleanup_path(path_kind, path_key)
            except (OSError, RuntimeError):
                failed.append((path_kind, path_key))
                continue
            completed.append((path_kind, path_key))
        if completed or failed:
            with _write_transaction(connection):
                connection.executemany(
                    """
                    DELETE FROM team_attachment_cleanup_queue
                    WHERE path_kind=? AND path_key=?
                    """,
                    completed,
                )
                connection.executemany(
                    """
                    UPDATE team_attachment_cleanup_queue
                    SET attempt_count=attempt_count+1
                    WHERE path_kind=? AND path_key=?
                    """,
                    failed,
                )
        return len(completed)

    def declare_team_attachment(
        self,
        claims: AccessClaims,
        team_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        timestamp = _now()
        file_name = request.get("file_name")
        if (
            not isinstance(file_name, str)
            or TEAM_ATTACHMENT_FILE_NAME_RE.fullmatch(file_name) is None
            or file_name.strip() != file_name
            or file_name in {".", ".."}
        ):
            raise HubError("invalid_request", "Attachment file name is invalid", 422)
        media_type = request.get("media_type")
        if not isinstance(media_type, str) or TEAM_ATTACHMENT_MEDIA_TYPE_RE.fullmatch(
            media_type.strip()
        ) is None:
            raise HubError("invalid_request", "Attachment media type is invalid", 422)
        media_type = media_type.strip()
        byte_size = request.get("byte_size")
        if type(byte_size) is not int or byte_size < 1:
            raise HubError("invalid_request", "Attachment size is invalid", 422)
        if byte_size > self.team_attachment_max_bytes:
            raise HubError(
                "attachment_limit", "Attachment exceeds the per-file size limit", 413
            )
        storage_key = self._team_sha256_hex(request.get("sha256"))
        idempotency_key = self._team_idempotency_key(request)
        fingerprint = canonical_fingerprint(
            {
                "team_id": team_id,
                "file_name": file_name,
                "media_type": media_type,
                "byte_size": byte_size,
                "sha256": storage_key,
            }
        )
        # A failed message/skill request deliberately leaves a ready upload
        # available for retry. Once that bounded window expires, reclaim a small
        # batch before admitting more bytes. The quota query below independently
        # excludes every expired unbound row, so a backlog cannot wedge uploads.
        self.purge_expired_team_attachments(
            timestamp,
            team_id=team_id,
            limit=TEAM_ATTACHMENT_RECLAIM_BATCH,
        )
        # Keep the duplicate-ready decision and row insertion serialized with
        # collector unlinking. Otherwise a declaration that read the soon-to-be
        # deleted ready row could publish a new ready reference after the
        # collector commits but before it unlinks the shared blob.
        attachment_lease = self.acquire_attachment_control_lease(self.data_dir)
        connection: sqlite3.Connection | None = None
        try:
            connection = self.connect()
            with _write_transaction(connection):
                self._require_network_scope(connection, claims, team_id, write=True)
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "team.attachment.declare",
                    idempotency_key,
                    fingerprint,
                )
                if cached is not None:
                    cached_attachment = cached.get("attachment")
                    cached_attachment_id = (
                        cached_attachment.get("id")
                        if isinstance(cached_attachment, dict)
                        else None
                    )
                    existing = (
                        connection.execute(
                            "SELECT message_id,expires_at FROM team_attachments "
                            "WHERE team_id=? AND id=?",
                            (team_id, cached_attachment_id),
                        ).fetchone()
                        if isinstance(cached_attachment_id, str)
                        else None
                    )
                    if existing is None or (
                        existing["message_id"] is None
                        and int(existing["expires_at"]) <= timestamp
                    ):
                        raise HubError(
                            "attachment_unavailable",
                            "Attachment declaration expired; declare it again with a new idempotency key",
                            409,
                        )
                    return cached
                used = connection.execute(
                    """
                    SELECT COALESCE(SUM(byte_size),0) FROM team_attachments
                    WHERE team_id=? AND state IN ('uploading','ready')
                      AND (message_id IS NOT NULL OR expires_at>?)
                    """,
                    (team_id, timestamp),
                ).fetchone()[0]
                if int(used) + byte_size > self.team_attachment_quota_bytes:
                    raise HubError(
                        "attachment_limit", "Team attachment storage quota exceeded", 413
                    )
                _sender_kind, uploader_node_id = self._team_sender(connection, claims, team_id)
                attachment_id = _id("tatt")
                duplicate_ready = connection.execute(
                    """
                    SELECT 1 FROM team_attachments
                    WHERE team_id=? AND storage_key=? AND state='ready' AND byte_size=?
                      AND (message_id IS NOT NULL OR expires_at>?)
                    LIMIT 1
                    """,
                    (team_id, storage_key, byte_size, timestamp),
                ).fetchone()
                already_stored = False
                if duplicate_ready is not None:
                    verified_descriptor = -1
                    try:
                        verified_descriptor = self._open_verified_team_attachment_blob(
                            storage_key,
                            byte_size,
                        )
                    except (OSError, RuntimeError):
                        # Corrupt or unsafe bytes are never promoted by
                        # metadata-only deduplication. A fresh upload can
                        # repair the content-addressed name atomically.
                        pass
                    else:
                        already_stored = True
                    finally:
                        if verified_descriptor >= 0:
                            os.close(verified_descriptor)
                connection.execute(
                    """
                    INSERT INTO team_attachments(
                        id,team_id,message_id,file_name,media_type,byte_size,sha256,
                        storage_key,state,received_bytes,uploaded_by_principal_id,
                        uploader_node_id,idempotency_key,created_at,ready_at,expires_at
                    ) VALUES (?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        attachment_id,
                        team_id,
                        file_name,
                        media_type,
                        byte_size,
                        bytes.fromhex(storage_key),
                        storage_key,
                        "ready" if already_stored else "uploading",
                        byte_size if already_stored else 0,
                        claims.principal_id,
                        uploader_node_id,
                        hashlib.sha256(
                            f"{team_id}\0{claims.principal_id}\0team.attachment.declare\0{idempotency_key}".encode(
                                "utf-8"
                            )
                        ).digest(),
                        timestamp,
                        timestamp if already_stored else None,
                        timestamp + TEAM_ATTACHMENT_UPLOAD_TTL_SECONDS,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM team_attachments WHERE team_id=? AND id=?",
                    (team_id, attachment_id),
                ).fetchone()
                assert row is not None
                response = {
                    "attachment": self._team_attachment_public(row),
                    "chunk_bytes": TEAM_ATTACHMENT_CHUNK_BYTES,
                }
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "team.attachment.declare",
                    idempotency_key,
                    fingerprint,
                    "team_attachment",
                    attachment_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "team.attachment.declare",
                    "team_attachment",
                    attachment_id,
                    "succeeded",
                    {"byte_size": byte_size, "deduplicated": already_stored},
                    timestamp,
                )
                self._outbox(
                    connection,
                    team_id,
                    "team_attachment",
                    attachment_id,
                    "team.attachment.declared",
                    timestamp,
                )
                return response
        finally:
            if connection is not None:
                connection.close()
            self.release_attachment_control_lease(attachment_lease)

    def write_team_attachment_chunk(
        self,
        claims: AccessClaims,
        team_id: str,
        attachment_id: str,
        *,
        offset: int,
        total: int,
        data: bytes,
    ) -> dict[str, Any]:
        """Append one contiguous chunk; finish, verify, and publish on the last one."""

        if not isinstance(data, (bytes, bytearray)) or not data:
            raise HubError("invalid_request", "Attachment chunk is empty", 422)
        if len(data) > TEAM_ATTACHMENT_CHUNK_BYTES:
            raise HubError("request_too_large", "Attachment chunk is too large", 413)
        if type(offset) is not int or offset < 0 or type(total) is not int or total < 1:
            raise HubError("invalid_request", "Attachment range is invalid", 422)
        timestamp = _now()
        attachment_lease = self.acquire_attachment_control_lease(self.data_dir)
        connection: sqlite3.Connection | None = None
        try:
            connection = self.connect()
            try:
                return self._write_team_attachment_chunk_locked(
                    connection,
                    claims,
                    team_id,
                    attachment_id,
                    offset=offset,
                    total=total,
                    data=bytes(data),
                    timestamp=timestamp,
                )
            except _TeamAttachmentFailure as failure:
                # The chunk transaction rolled back; record the terminal state
                # in its own transaction so a retry cannot resume a bad upload.
                with _write_transaction(connection):
                    connection.execute(
                        """
                        UPDATE team_attachments SET state='failed'
                        WHERE team_id=? AND id=? AND state='uploading'
                        """,
                        (team_id, attachment_id),
                    )
                raise failure.error from None
        finally:
            if connection is not None:
                connection.close()
            self.release_attachment_control_lease(attachment_lease)

    def _write_team_attachment_chunk_locked(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
        attachment_id: str,
        *,
        offset: int,
        total: int,
        data: bytes,
        timestamp: int,
    ) -> dict[str, Any]:
        with _write_transaction(connection):
                self._require_network_scope(connection, claims, team_id, write=True)
                row = connection.execute(
                    "SELECT * FROM team_attachments WHERE team_id=? AND id=?",
                    (team_id, attachment_id),
                ).fetchone()
                if row is None or row["uploaded_by_principal_id"] != claims.principal_id:
                    raise HubError("not_found", "Resource not found", 404)
                if row["message_id"] is None and int(row["expires_at"]) <= timestamp:
                    raise _TeamAttachmentFailure(
                        HubError(
                            "attachment_unavailable",
                            "Attachment upload expired; declare it again",
                            409,
                        )
                    )
                byte_size = int(row["byte_size"])
                if total != byte_size:
                    raise HubError("invalid_request", "Attachment range total is wrong", 422)
                received = int(row["received_bytes"])
                if row["state"] == "ready":
                    if offset + len(data) <= byte_size:
                        return {"attachment": self._team_attachment_public(row)}
                    raise HubError("conflict", "Attachment is already complete", 409)
                if row["state"] == "failed":
                    raise HubError(
                        "attachment_unavailable", "Attachment upload failed; declare it again", 409
                    )
                if offset == received and received + len(data) == byte_size:
                    # os.replace()+directory fsync can survive a process death
                    # before the surrounding SQLite transaction commits ready
                    # metadata. Reconcile only an exact final-chunk replay: the
                    # staging name must be absent, the content-addressed final
                    # inode must fully authenticate, and its replayed suffix
                    # must equal this request.
                    final_descriptor = -1
                    if self._team_attachment_staging_absent(attachment_id):
                        try:
                            final_descriptor = self._open_verified_team_attachment_blob(
                                str(row["storage_key"]),
                                byte_size,
                            )
                        except (OSError, RuntimeError):
                            pass
                        else:
                            replayed = os.pread(final_descriptor, len(data), offset)
                            if (
                                hmac.compare_digest(replayed, data)
                                and self._team_attachment_staging_absent(attachment_id)
                            ):
                                self._mark_team_attachment_ready_locked(
                                    connection,
                                    row,
                                    claims,
                                    team_id,
                                    timestamp,
                                )
                                updated = connection.execute(
                                    "SELECT * FROM team_attachments WHERE team_id=? AND id=?",
                                    (team_id, attachment_id),
                                ).fetchone()
                                assert updated is not None
                                return {
                                    "attachment": self._team_attachment_public(updated)
                                }
                        finally:
                            if final_descriptor >= 0:
                                os.close(final_descriptor)
                if offset + len(data) <= received:
                    return {"attachment": self._team_attachment_public(row)}
                if offset != received:
                    raise HubError("conflict", "Attachment chunk offset is not contiguous", 409)
                if received + len(data) > byte_size:
                    raise HubError(
                        "invalid_request", "Attachment chunk exceeds the declared size", 422
                    )
                descriptor = -1
                staging_directory = -1
                try:
                    try:
                        (
                            descriptor,
                            staging_directory,
                            staging_filename,
                        ) = self._open_team_attachment_staging(
                            attachment_id,
                            received,
                        )
                    except (OSError, RuntimeError) as exc:
                        raise _TeamAttachmentFailure(
                            HubError(
                                "attachment_unavailable",
                                "Attachment upload staging is unsafe; declare it again",
                                409,
                            )
                        ) from exc
                    os.lseek(descriptor, received, os.SEEK_SET)
                    view = memoryview(data)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise OSError("Attachment staging write made no progress")
                        view = view[written:]
                    os.fsync(descriptor)
                    new_received = received + len(data)
                    if new_received < byte_size:
                        connection.execute(
                            "UPDATE team_attachments SET received_bytes=? WHERE id=?",
                            (new_received, attachment_id),
                        )
                    else:
                        try:
                            digest = self._verify_team_attachment_descriptor(
                                descriptor,
                                expected_size=byte_size,
                                require_single_link=True,
                                linked_stat=lambda: os.stat(
                                    staging_filename,
                                    dir_fd=staging_directory,
                                    follow_symlinks=False,
                                ),
                            )
                        except (OSError, RuntimeError) as exc:
                            raise _TeamAttachmentFailure(
                                HubError(
                                    "attachment_unavailable",
                                    "Attachment upload staging changed; declare it again",
                                    409,
                                )
                            ) from exc
                        if not hmac.compare_digest(digest, str(row["storage_key"])):
                            with suppress(OSError, RuntimeError):
                                self._unlink_open_team_attachment_staging(
                                    descriptor,
                                    staging_directory,
                                    staging_filename,
                                )
                            raise _TeamAttachmentFailure(
                                HubError(
                                    "attachment_hash_mismatch",
                                    "Uploaded bytes do not match the declared SHA-256",
                                    422,
                                )
                            )
                        final = self._team_attachment_storage_path(
                            str(row["storage_key"])
                        )
                        ensure_private_directory(final.parent)
                        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                        directory_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
                            os, "O_DIRECTORY", 0
                        )
                        final_directory = os.open(final.parent, directory_flags)
                        try:
                            directory_info = os.fstat(final_directory)
                            if (
                                not stat.S_ISDIR(directory_info.st_mode)
                                or directory_info.st_uid != os.getuid()
                                or stat.S_IMODE(directory_info.st_mode) != 0o700
                            ):
                                raise PermissionError(
                                    "Team attachment content directory is unsafe"
                                )
                            opened = os.fstat(descriptor)
                            linked = os.stat(
                                staging_filename,
                                dir_fd=staging_directory,
                                follow_symlinks=False,
                            )
                            if (
                                opened.st_nlink != 1
                                or self._team_attachment_file_signature(opened)
                                != self._team_attachment_file_signature(linked)
                            ):
                                raise PermissionError(
                                    "Team attachment staging file changed"
                                )
                            # The verified staging inode is authoritative. A
                            # same-sized blob at the digest name may be corrupt;
                            # replacing the name is atomic and leaves existing
                            # download descriptors safely pinned to their inode.
                            os.replace(
                                staging_filename,
                                final.name,
                                src_dir_fd=staging_directory,
                                dst_dir_fd=final_directory,
                            )
                            published = os.stat(
                                final.name,
                                dir_fd=final_directory,
                                follow_symlinks=False,
                            )
                            after = os.fstat(descriptor)
                            if (
                                self._team_attachment_file_signature(after)
                                != self._team_attachment_file_signature(published)
                            ):
                                raise RuntimeError(
                                    "Team attachment publication changed inode"
                                )
                            os.fsync(final_directory)
                            os.fsync(staging_directory)
                        finally:
                            os.close(final_directory)
                        self._mark_team_attachment_ready_locked(
                            connection,
                            row,
                            claims,
                            team_id,
                            timestamp,
                        )
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                    if staging_directory >= 0:
                        os.close(staging_directory)
                updated = connection.execute(
                    "SELECT * FROM team_attachments WHERE team_id=? AND id=?",
                    (team_id, attachment_id),
                ).fetchone()
                assert updated is not None
                return {"attachment": self._team_attachment_public(updated)}

    def _team_attachment_row_visible(
        self,
        connection: sqlite3.Connection,
        claims: AccessClaims,
        team_id: str,
        row: sqlite3.Row,
        membership_role: str,
    ) -> bool:
        if row["message_id"] is None:
            return (
                row["uploaded_by_principal_id"] == claims.principal_id
                and int(row["expires_at"]) > _now()
            )
        message = connection.execute(
            self._team_message_select() + " WHERE m.team_id=? AND m.id=?",
            (team_id, row["message_id"]),
        ).fetchone()
        if message is None:
            return False
        owned = self._team_owned_addresses(connection, claims, team_id, membership_role)
        return self._team_message_visible(connection, claims, message, owned)

    def get_team_attachment(
        self, claims: AccessClaims, team_id: str, attachment_id: str
    ) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            membership = self._require_network_scope(connection, claims, team_id, write=False)
            row = connection.execute(
                "SELECT * FROM team_attachments WHERE team_id=? AND id=?",
                (team_id, attachment_id),
            ).fetchone()
            if row is None or not self._team_attachment_row_visible(
                connection, claims, team_id, row, str(membership["role"])
            ):
                raise HubError("not_found", "Resource not found", 404)
            response = {"attachment": self._team_attachment_public(row)}
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def open_team_attachment(
        self, claims: AccessClaims, team_id: str, attachment_id: str
    ) -> tuple[dict[str, Any], AttachmentFileLease]:
        """Authorize a download and pin its exact inode before reclamation.

        The collector may unlink an expired orphan immediately after this
        method returns. Opening a no-follow descriptor while serialized with
        collection keeps an already-authorized stream valid without holding
        the global attachment-control lock for the duration of a download.
        """

        attachment_lease = self.acquire_attachment_control_lease(self.data_dir)
        connection: sqlite3.Connection | None = None
        descriptor = -1
        try:
            connection = self.connect()
            connection.execute("BEGIN")
            membership = self._require_network_scope(connection, claims, team_id, write=False)
            row = connection.execute(
                "SELECT * FROM team_attachments WHERE team_id=? AND id=?",
                (team_id, attachment_id),
            ).fetchone()
            if row is None or not self._team_attachment_row_visible(
                connection, claims, team_id, row, str(membership["role"])
            ):
                raise HubError("not_found", "Resource not found", 404)
            if row["state"] != "ready":
                raise HubError(
                    "attachment_unavailable", "Attachment upload is not complete", 409
                )
            try:
                descriptor = self._open_verified_team_attachment_blob(
                    str(row["storage_key"]),
                    int(row["byte_size"]),
                )
            except (OSError, RuntimeError) as exc:
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
                    descriptor = -1
                raise HubError(
                    "attachment_unavailable", "Attachment bytes are unavailable", 404
                ) from exc
            public = self._team_attachment_public(row)
            connection.execute("COMMIT")
            pinned_descriptor = descriptor
            descriptor = -1
            return public, AttachmentFileLease(
                pinned_descriptor,
                lambda: os.close(pinned_descriptor),
            )
        except BaseException:
            if connection is not None and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            if connection is not None:
                connection.close()
            self.release_attachment_control_lease(attachment_lease)

    def bound_team_attachment_local_path(
        self, claims: AccessClaims, team_id: str, attachment_id: str
    ) -> tuple[dict[str, Any], Path]:
        """Return a local path only for immutable message-bound content.

        Unbound uploads can expire and be reclaimed, so callers that need a
        path beyond this method's transaction must never receive one for those
        rows. HTTP streaming uses :meth:`open_team_attachment` and its pinned
        descriptor instead.
        """

        attachment_lease = self.acquire_attachment_control_lease(self.data_dir)
        connection: sqlite3.Connection | None = None
        try:
            connection = self.connect()
            connection.execute("BEGIN")
            membership = self._require_network_scope(
                connection, claims, team_id, write=False
            )
            row = connection.execute(
                "SELECT * FROM team_attachments WHERE team_id=? AND id=?",
                (team_id, attachment_id),
            ).fetchone()
            if (
                row is None
                or row["message_id"] is None
                or not self._team_attachment_row_visible(
                    connection, claims, team_id, row, str(membership["role"])
                )
            ):
                raise HubError("not_found", "Resource not found", 404)
            if row["state"] != "ready":
                raise HubError(
                    "attachment_unavailable", "Attachment upload is not complete", 409
                )
            path = self._team_attachment_storage_path(str(row["storage_key"]))
            descriptor = -1
            try:
                descriptor = self._open_verified_team_attachment_blob(
                    str(row["storage_key"]),
                    int(row["byte_size"]),
                )
            except (OSError, RuntimeError) as exc:
                raise HubError(
                    "attachment_unavailable", "Attachment bytes are unavailable", 404
                ) from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            public = self._team_attachment_public(row)
            connection.execute("COMMIT")
            return public, path
        except BaseException:
            if connection is not None and connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            if connection is not None:
                connection.close()
            self.release_attachment_control_lease(attachment_lease)

    def purge_expired_team_attachments(
        self,
        now: int | None = None,
        *,
        team_id: str | None = None,
        limit: int = TEAM_ATTACHMENT_RECLAIM_BATCH,
    ) -> int:
        """Reclaim a bounded batch of expired, unbound attachment declarations.

        Ready uploads remain bindable for their full TTL even after a message or
        skill request fails. A content-addressed blob is removed only after its
        last ready metadata reference is gone; message-bound rows are never
        candidates.
        """

        timestamp = _now(now)
        if type(limit) is not int or not 1 <= limit <= 4096:
            raise ValueError("attachment reclaim limit must be between 1 and 4096")
        attachment_lease = self.acquire_attachment_control_lease(self.data_dir)
        connection: sqlite3.Connection | None = None
        stale: list[sqlite3.Row] = []
        try:
            connection = self.connect()
            with _write_transaction(connection):
                query = """
                    SELECT id,storage_key,state FROM team_attachments
                    WHERE message_id IS NULL AND expires_at<=?
                """
                parameters: list[Any] = [timestamp]
                if team_id is not None:
                    query += " AND team_id=?"
                    parameters.append(team_id)
                query += " ORDER BY expires_at,id LIMIT ?"
                parameters.append(limit)
                stale = connection.execute(query, parameters).fetchall()
                for row in stale:
                    attachment_id = str(row["id"])
                    self._validate_team_attachment_cleanup_key(
                        "staging", attachment_id
                    )
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO team_attachment_cleanup_queue(
                            path_kind,path_key,created_at
                        ) VALUES ('staging',?,?)
                        """,
                        (attachment_id, timestamp),
                    )
                    connection.execute(
                        "DELETE FROM team_attachments WHERE id=?", (attachment_id,)
                    )
                # An uploading row may already have published its verified
                # final blob if the process died after rename+fsync but before
                # the SQLite ready transaction committed. Queue every expired
                # row's content key; missing files are replay-safe cleanup, and
                # a surviving ready reference protects shared content below.
                for storage_key in {str(row["storage_key"]) for row in stale}:
                    self._validate_team_attachment_cleanup_key("content", storage_key)
                    still_referenced = connection.execute(
                        """
                        SELECT 1 FROM team_attachments
                        WHERE storage_key=? AND state='ready'
                        LIMIT 1
                        """,
                        (storage_key,),
                    ).fetchone()
                    if still_referenced is None:
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO team_attachment_cleanup_queue(
                                path_kind,path_key,created_at
                            ) VALUES ('content',?,?)
                            """,
                            (storage_key, timestamp),
                        )

            # Tombstones and metadata deletion commit together. Physical
            # cleanup is replay-safe: failed paths remain queued, while a
            # successful unlink followed by a crash becomes a missing-file
            # success on the next pass.
            cleanup_limit = min(
                8192,
                max(TEAM_ATTACHMENT_CLEANUP_BATCH, limit * 2),
            )
            self._drain_team_attachment_cleanup_queue_locked(
                connection,
                limit=cleanup_limit,
            )
            return len(stale)
        finally:
            if connection is not None:
                connection.close()
            self.release_attachment_control_lease(attachment_lease)

    # -- skills -------------------------------------------------------------

    @staticmethod
    def _team_skill_select() -> str:
        return """
            SELECT s.*, v.id AS version_id, v.message_id AS version_message_id,
                   v.change_note AS version_change_note,
                   v.created_at AS version_created_at,
                   m.sender_kind AS author_kind, m.sender_principal_id AS author_principal_id,
                   m.sender_node_id AS author_node_id,
                   ap.display_name AS author_principal_display_name,
                   an.display_name AS author_node_display_name,
                   m.body AS version_body, m.body_format AS version_body_format,
                   length(CAST(m.body AS BLOB)) AS version_body_bytes,
                   (SELECT COUNT(*) FROM team_skill_versions AS c WHERE c.skill_id=s.id)
                       AS versions_count
            FROM team_skills AS s
            JOIN team_skill_versions AS v
              ON v.team_id=s.team_id AND v.skill_id=s.id AND v.version=s.current_version
            JOIN team_messages AS m ON m.team_id=v.team_id AND m.id=v.message_id
            JOIN principals AS ap ON ap.id=m.sender_principal_id
            LEFT JOIN nodes AS an ON an.team_id=m.team_id AND an.id=m.sender_node_id
        """

    def _team_skill_public(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        include_body: bool,
        can_write: bool,
    ) -> dict[str, Any]:
        item: dict[str, Any] = {
            "id": row["id"],
            "slug": row["slug"],
            "title": row["title"],
            "summary": row["summary"],
            "tags": json.loads(str(row["tags_json"] or "[]")),
            "version": int(row["current_version"]),
            "versions_count": int(row["versions_count"]),
            "pinned": row["pinned_at"] is not None,
            "pinned_at": _iso8601(row["pinned_at"]),
            "archived": row["archived_at"] is not None,
            "archived_at": _iso8601(row["archived_at"]),
            "author": self._team_sender_party(row, "author"),
            "body_bytes": int(row["version_body_bytes"]),
            "current": {
                "version": int(row["current_version"]),
                "message_id": row["version_message_id"],
                "change_note": row["version_change_note"],
                "created_at": _iso8601(row["version_created_at"]),
            },
            "created_at": _iso8601(row["created_at"]),
            "updated_at": _iso8601(row["updated_at"]),
            "permissions": {
                "edit": can_write and row["archived_at"] is None,
                "manage": can_write,
            },
        }
        if include_body:
            item["body"] = row["version_body"]
            item["body_format"] = row["version_body_format"]
            item["attachments"] = self._team_message_attachments(
                connection, str(row["team_id"]), str(row["version_message_id"])
            )
        return item

    def _team_skill_version_public(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        include_body: bool,
    ) -> dict[str, Any]:
        item: dict[str, Any] = {
            "version": int(row["version"]),
            "message_id": row["message_id"],
            "title": row["title"],
            "summary": row["summary"],
            "tags": json.loads(str(row["tags_json"] or "[]")),
            "change_note": row["change_note"],
            "author": self._team_sender_party(row, "author"),
            "body_bytes": int(row["version_body_bytes"]),
            "attachments": self._team_message_attachments(
                connection, str(row["team_id"]), str(row["message_id"])
            ),
            "created_at": _iso8601(row["created_at"]),
        }
        if include_body:
            item["body"] = row["version_body"]
            item["body_format"] = row["version_body_format"]
        return item

    @staticmethod
    def _team_skill_version_select() -> str:
        return """
            SELECT v.*, m.sender_kind AS author_kind,
                   m.sender_principal_id AS author_principal_id,
                   m.sender_node_id AS author_node_id,
                   ap.display_name AS author_principal_display_name,
                   an.display_name AS author_node_display_name,
                   m.body AS version_body, m.body_format AS version_body_format,
                   length(CAST(m.body AS BLOB)) AS version_body_bytes
            FROM team_skill_versions AS v
            JOIN team_messages AS m ON m.team_id=v.team_id AND m.id=v.message_id
            JOIN principals AS ap ON ap.id=m.sender_principal_id
            LEFT JOIN nodes AS an ON an.team_id=m.team_id AND an.id=m.sender_node_id
        """

    def list_team_skills(
        self,
        claims: AccessClaims,
        team_id: str,
        *,
        include_archived: bool = False,
        slug: str | None = None,
    ) -> dict[str, Any]:
        clean_slug = self._team_slug(slug) if slug is not None else None
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            membership = self._require_network_scope(connection, claims, team_id, write=False)
            can_write = self._team_can_write(claims, str(membership["role"]))
            where = ["s.team_id=?"]
            params: list[Any] = [team_id]
            if not include_archived:
                where.append("s.archived_at IS NULL")
            if clean_slug is not None:
                where.append("s.slug=?")
                params.append(clean_slug)
            rows = connection.execute(
                self._team_skill_select()
                + " WHERE "
                + " AND ".join(where)
                + " ORDER BY s.pinned_at IS NULL, s.pinned_at DESC, s.updated_at DESC, s.id"
                + f" LIMIT {MAX_TEAM_SKILLS_PER_TEAM}",
                params,
            ).fetchall()
            response = {
                "skills": [
                    self._team_skill_public(
                        connection, row, include_body=False, can_write=can_write
                    )
                    for row in rows
                ]
            }
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def get_team_skill(
        self, claims: AccessClaims, team_id: str, skill_id: str
    ) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            membership = self._require_network_scope(connection, claims, team_id, write=False)
            row = connection.execute(
                self._team_skill_select() + " WHERE s.team_id=? AND s.id=?",
                (team_id, skill_id),
            ).fetchone()
            if row is None:
                raise HubError("not_found", "Resource not found", 404)
            response = {
                "skill": self._team_skill_public(
                    connection,
                    row,
                    include_body=True,
                    can_write=self._team_can_write(claims, str(membership["role"])),
                )
            }
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def list_team_skill_versions(
        self, claims: AccessClaims, team_id: str, skill_id: str
    ) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_network_scope(connection, claims, team_id, write=False)
            exists = connection.execute(
                "SELECT 1 FROM team_skills WHERE team_id=? AND id=?", (team_id, skill_id)
            ).fetchone()
            if exists is None:
                raise HubError("not_found", "Resource not found", 404)
            rows = connection.execute(
                self._team_skill_version_select()
                + " WHERE v.team_id=? AND v.skill_id=? ORDER BY v.version DESC",
                (team_id, skill_id),
            ).fetchall()
            response = {
                "skill_id": skill_id,
                "versions": [
                    self._team_skill_version_public(connection, row, include_body=False)
                    for row in rows
                ],
            }
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def get_team_skill_version(
        self, claims: AccessClaims, team_id: str, skill_id: str, version: int
    ) -> dict[str, Any]:
        if type(version) is not int or version < 1:
            raise HubError("invalid_request", "Skill version is invalid", 422)
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_network_scope(connection, claims, team_id, write=False)
            row = connection.execute(
                self._team_skill_version_select()
                + " WHERE v.team_id=? AND v.skill_id=? AND v.version=?",
                (team_id, skill_id, version),
            ).fetchone()
            if row is None:
                raise HubError("not_found", "Resource not found", 404)
            response = {
                "skill_id": skill_id,
                "version": self._team_skill_version_public(connection, row, include_body=True),
            }
            connection.execute("COMMIT")
            return response
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _set_team_skill_flag(
        self,
        claims: AccessClaims,
        team_id: str,
        skill_id: str,
        request: dict[str, Any],
        *,
        flag: str,
    ) -> dict[str, Any]:
        timestamp = _now()
        value = request.get(flag)
        if type(value) is not bool:
            raise HubError("invalid_request", f"{flag} must be a boolean", 422)
        idempotency_key = self._team_idempotency_key(request)
        operation = f"team.skill.{flag}"
        fingerprint = canonical_fingerprint(
            {"team_id": team_id, "skill_id": skill_id, flag: value}
        )
        connection = self.connect()
        try:
            with _write_transaction(connection):
                membership = self._require_network_scope(connection, claims, team_id, write=True)
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    operation,
                    idempotency_key,
                    fingerprint,
                )
                if cached is not None:
                    return cached
                skill = connection.execute(
                    "SELECT * FROM team_skills WHERE team_id=? AND id=?", (team_id, skill_id)
                ).fetchone()
                if skill is None:
                    raise HubError("not_found", "Resource not found", 404)
                if flag == "pinned":
                    if value and skill["archived_at"] is not None:
                        raise HubError("skill_archived", "Restore the skill before pinning it", 409)
                    if value != (skill["pinned_at"] is not None):
                        connection.execute(
                            """
                            UPDATE team_skills SET pinned_at=?,pinned_by_principal_id=?
                            WHERE team_id=? AND id=?
                            """,
                            (
                                timestamp if value else None,
                                claims.principal_id if value else None,
                                team_id,
                                skill_id,
                            ),
                        )
                else:
                    if value != (skill["archived_at"] is not None):
                        connection.execute(
                            """
                            UPDATE team_skills
                            SET archived_at=?,archived_by_principal_id=?,
                                pinned_at=CASE WHEN ? THEN NULL ELSE pinned_at END,
                                pinned_by_principal_id=
                                    CASE WHEN ? THEN NULL ELSE pinned_by_principal_id END,
                                updated_at=?
                            WHERE team_id=? AND id=?
                            """,
                            (
                                timestamp if value else None,
                                claims.principal_id if value else None,
                                1 if value else 0,
                                1 if value else 0,
                                timestamp,
                                team_id,
                                skill_id,
                            ),
                        )
                row = connection.execute(
                    self._team_skill_select() + " WHERE s.team_id=? AND s.id=?",
                    (team_id, skill_id),
                ).fetchone()
                assert row is not None
                response = {
                    "skill": self._team_skill_public(
                        connection,
                        row,
                        include_body=False,
                        can_write=self._team_can_write(claims, str(membership["role"])),
                    )
                }
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    operation,
                    idempotency_key,
                    fingerprint,
                    "team_skill",
                    skill_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    operation,
                    "team_skill",
                    skill_id,
                    "succeeded",
                    {flag: value},
                    timestamp,
                )
                # Pin and archive toggle back and forth, so each change is its
                # own outbox aggregate rather than a deduplicated per-skill row.
                self._outbox(
                    connection,
                    team_id,
                    "team_skill_change",
                    _id("tskillchange"),
                    f"team.skill.{flag}.{'on' if value else 'off'}",
                    timestamp,
                )
                return response
        finally:
            connection.close()

    def set_team_skill_pinned(
        self, claims: AccessClaims, team_id: str, skill_id: str, request: dict[str, Any]
    ) -> dict[str, Any]:
        return self._set_team_skill_flag(claims, team_id, skill_id, request, flag="pinned")

    def set_team_skill_archived(
        self, claims: AccessClaims, team_id: str, skill_id: str, request: dict[str, Any]
    ) -> dict[str, Any]:
        return self._set_team_skill_flag(claims, team_id, skill_id, request, flag="archived")

    @staticmethod
    def _message_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "team_id": row["team_id"],
            "channel_id": row["channel_id"],
            "channel_sequence": row["channel_sequence"],
            "kind": row["kind"],
            "thread_root_message_id": row["thread_root_message_id"],
            "parent_message_id": row["parent_message_id"],
            "author_principal_id": row["author_principal_id"],
            "body_format": row["body_format"],
            "body": row["body"],
            "created_at": _iso8601(row["created_at"]),
            "edited_at": _iso8601(row["edited_at"]),
            "deleted_at": _iso8601(row["deleted_at"]),
        }

    def list_messages(
        self, claims: AccessClaims, channel_id: str, limit: int, before_sequence: int | None
    ) -> dict[str, Any]:
        connection = self.connect()
        try:
            connection.execute("BEGIN")
            self._require_session(connection, claims, _now())
            channel = connection.execute("SELECT * FROM channels WHERE id = ?", (channel_id,)).fetchone()
            if channel is None or not self._channel_permission(
                connection, channel, claims.principal_id, "read"
            ):
                raise HubError("not_found", "Resource not found", 404)
            bounded_limit = max(1, min(int(limit), 100))
            cutoff = before_sequence if before_sequence is not None else 2**63 - 1
            rows = connection.execute(
                """
                SELECT * FROM messages
                WHERE channel_id = ? AND channel_sequence < ? AND deleted_at IS NULL
                ORDER BY channel_sequence DESC LIMIT ?
                """,
                (channel_id, cutoff, bounded_limit),
            ).fetchall()
            messages = [self._message_dict(row) for row in reversed(rows)]
            next_before = int(rows[-1]["channel_sequence"]) if len(rows) == bounded_limit else None
            connection.execute("COMMIT")
            return {"messages": messages, "next_before_sequence": next_before}
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def create_message(
        self, claims: AccessClaims, channel_id: str, request: dict[str, Any]
    ) -> dict[str, Any]:
        timestamp = _now()
        connection = self.connect()
        try:
            with _write_transaction(connection):
                self._require_session(connection, claims, timestamp)
                channel = connection.execute("SELECT * FROM channels WHERE id = ?", (channel_id,)).fetchone()
                if channel is None or not self._channel_permission(
                    connection, channel, claims.principal_id, "post"
                ):
                    raise HubError("not_found", "Resource not found", 404)
                team_id = str(channel["team_id"])
                body = request["body"]
                try:
                    encoded_body = body.encode("utf-8") if isinstance(body, str) else b""
                except UnicodeEncodeError as exc:
                    raise HubError("invalid_request", "Message body is invalid", 422) from exc
                if not isinstance(body, str) or not 1 <= len(encoded_body) <= 65536:
                    raise HubError("invalid_request", "Message body is invalid", 422)
                if request.get("body_format") not in ("plain", "markdown"):
                    raise HubError("invalid_request", "Message body format is invalid", 422)
                kind = request["kind"]
                if channel["kind"] == "announcements" and kind != "announcement":
                    raise HubError("invalid_request", "Announcements channels accept announcements only", 422)
                if kind == "announcement" and channel["kind"] != "announcements":
                    raise HubError("invalid_request", "Announcements require an announcements channel", 422)
                if kind != "announcement" and kind != "post":
                    raise HubError("invalid_request", "Unknown message kind", 422)
                fingerprint = canonical_fingerprint(
                    {"channel_id": channel_id, **{k: v for k, v in request.items() if k != "idempotency_key"}}
                )
                cached = self._idempotency_lookup(
                    connection,
                    team_id,
                    claims.principal_id,
                    "message.create",
                    request["idempotency_key"],
                    fingerprint,
                )
                if cached is not None:
                    return cached
                subject = self._network_automation_rate_subject(claims)
                if subject is not None:
                    # These durable buckets bound remote write amplification
                    # by automation actors even across gateway/server restarts.
                    # Replays with the same idempotency key return above without
                    # being charged.
                    self._charge_rate_bucket(
                        connection,
                        team_id=team_id,
                        subject_key=subject,
                        action="peer.message.count.minute",
                        timestamp=timestamp,
                        window_seconds=60,
                        cost=1,
                        limit=60,
                    )
                    self._charge_rate_bucket(
                        connection,
                        team_id=team_id,
                        subject_key=subject,
                        action="peer.message.count.day",
                        timestamp=timestamp,
                        window_seconds=86_400,
                        cost=1,
                        limit=5_000,
                    )
                    self._charge_rate_bucket(
                        connection,
                        team_id=team_id,
                        subject_key=subject,
                        action="peer.message.bytes.hour",
                        timestamp=timestamp,
                        window_seconds=3_600,
                        cost=len(encoded_body),
                        limit=4 * 1024 * 1024,
                    )
                root_id = request.get("thread_root_message_id")
                parent_id = request.get("parent_message_id")
                if parent_id is not None and root_id is None:
                    raise HubError("invalid_request", "A reply requires a thread root", 422)
                if root_id is not None:
                    root = connection.execute(
                        """
                        SELECT id FROM messages
                        WHERE id = ? AND channel_id = ? AND deleted_at IS NULL
                          AND thread_root_message_id IS NULL AND parent_message_id IS NULL
                        """,
                        (root_id, channel_id),
                    ).fetchone()
                    if root is None:
                        raise HubError("invalid_request", "Thread root is unavailable", 422)
                if parent_id is not None:
                    parent = connection.execute(
                        """
                        SELECT id, thread_root_message_id FROM messages
                        WHERE id = ? AND channel_id = ? AND deleted_at IS NULL
                        """,
                        (parent_id, channel_id),
                    ).fetchone()
                    if parent is None or (
                        str(parent["id"]) != root_id
                        and str(parent["thread_root_message_id"]) != root_id
                    ):
                        raise HubError("invalid_request", "Thread parent is unavailable", 422)
                sequence = int(channel["next_message_sequence"])
                connection.execute(
                    "UPDATE channels SET next_message_sequence = ?, updated_at = ? WHERE id = ?",
                    (sequence + 1, timestamp, channel_id),
                )
                message_id = _id("message")
                connection.execute(
                    """
                    INSERT INTO messages(
                        id, team_id, channel_id, channel_sequence, kind,
                        thread_root_message_id, parent_message_id,
                        author_principal_id, body_format, body,
                        idempotency_key, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        message_id,
                        team_id,
                        channel_id,
                        sequence,
                        kind,
                        root_id,
                        parent_id,
                        claims.principal_id,
                        request["body_format"],
                        body,
                        hashlib.sha256(
                            f"{team_id}\0{claims.principal_id}\0message.create\0{request['idempotency_key']}".encode(
                                "utf-8"
                            )
                        ).digest(),
                        timestamp,
                    ),
                )
                if channel["kind"] == "direct":
                    for recipient in connection.execute(
                        """
                        SELECT principal_id FROM channel_participants
                        WHERE channel_id = ? AND status = 'active' AND principal_id <> ?
                        """,
                        (channel_id, claims.principal_id),
                    ):
                        recipient_id = _id("recipient")
                        connection.execute(
                            """
                            INSERT INTO message_recipients(
                                id, team_id, message_id, recipient_principal_id,
                                reason, delivery_key, state, created_at
                            ) VALUES (?, ?, ?, ?, 'direct', ?, 'available', ?)
                            """,
                            (
                                recipient_id,
                                team_id,
                                message_id,
                                recipient["principal_id"],
                                hashlib.sha256(f"{message_id}\0{recipient['principal_id']}".encode()).digest(),
                                timestamp,
                            ),
                        )
                row = connection.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
                assert row is not None
                response = {"message": self._message_dict(row)}
                self._idempotency_store(
                    connection,
                    team_id,
                    claims.principal_id,
                    "message.create",
                    request["idempotency_key"],
                    fingerprint,
                    "message",
                    message_id,
                    response,
                    timestamp,
                )
                self._audit(
                    connection,
                    team_id,
                    claims.principal_id,
                    "message.post",
                    "message",
                    message_id,
                    "succeeded",
                    {"channel_id": channel_id, "kind": kind},
                    timestamp,
                )
                self._outbox(
                    connection, team_id, "message", message_id, "message.created", timestamp
                )
                return response
        finally:
            connection.close()

    @staticmethod
    def _charge_rate_bucket(
        connection: sqlite3.Connection,
        *,
        team_id: str,
        subject_key: str,
        action: str,
        timestamp: int,
        window_seconds: int,
        cost: int,
        limit: int,
    ) -> None:
        if cost < 0 or limit <= 0 or window_seconds <= 0:
            raise RuntimeError("invalid durable rate bucket")
        row = connection.execute(
            """
            SELECT window_started_at, count FROM rate_limit_buckets
            WHERE team_id=? AND subject_key=? AND action=?
            """,
            (team_id, subject_key, action),
        ).fetchone()
        if row is None or int(row["window_started_at"]) + window_seconds <= timestamp:
            window_started = timestamp
            next_count = cost
        else:
            window_started = int(row["window_started_at"])
            next_count = int(row["count"]) + cost
        if next_count > limit:
            raise HubError(
                "rate_limited",
                "Secure peer write limit exceeded; retry after the current window",
                429,
            )
        connection.execute(
            """
            INSERT INTO rate_limit_buckets(
                team_id, subject_key, action, window_started_at, count, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(team_id, subject_key, action) DO UPDATE SET
                window_started_at=excluded.window_started_at,
                count=excluded.count,
                updated_at=excluded.updated_at
            """,
            (team_id, subject_key, action, window_started, next_count, timestamp),
        )

    @staticmethod
    def _outbox(
        connection: sqlite3.Connection,
        team_id: str,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        timestamp: int,
    ) -> None:
        effect_key = hashlib.sha256(
            f"{team_id}\0{aggregate_type}\0{aggregate_id}\0{event_type}".encode("utf-8")
        ).digest()
        connection.execute(
            """
            INSERT INTO outbox_events(
                id, team_id, aggregate_type, aggregate_id, event_type,
                metadata_json, idempotency_key, state, available_at,
                attempt_count, created_at
            ) VALUES (?, ?, ?, ?, ?, '{}', ?, 'pending', ?, 0, ?)
            """,
            (
                _id("outbox"),
                team_id,
                aggregate_type,
                aggregate_id,
                event_type,
                effect_key,
                timestamp,
                timestamp,
            ),
        )

    @classmethod
    def _audit_principal_teams(
        cls,
        connection: sqlite3.Connection,
        principal_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: str,
        timestamp: int,
    ) -> None:
        for row in connection.execute(
            """
            SELECT team_id FROM memberships
            WHERE principal_id = ? AND status = 'active' ORDER BY team_id
            """,
            (principal_id,),
        ):
            cls._audit(
                connection,
                str(row["team_id"]),
                principal_id,
                action,
                resource_type,
                resource_id,
                outcome,
                {},
                timestamp,
            )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        team_id: str,
        actor_principal_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: str,
        metadata: dict[str, Any],
        timestamp: int,
        *,
        node_id: str | None = None,
    ) -> None:
        head = connection.execute(
            "SELECT event_hash, sequence FROM audit_chain_heads WHERE team_id = ?",
            (team_id,),
        ).fetchone()
        previous_hash = head["event_hash"] if head is not None else None
        sequence = int(head["sequence"]) + 1 if head is not None else 1
        event_id = _id("audit")
        metadata_json = canonical_json(metadata).decode("utf-8")
        event_hash = hashlib.sha256(
            canonical_json(
                {
                    "id": event_id,
                    "team_id": team_id,
                    "actor_principal_id": actor_principal_id,
                    "node_id": node_id,
                    "action": action,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "outcome": outcome,
                    "metadata": metadata,
                    "previous_event_hash": previous_hash.hex() if previous_hash else None,
                    "sequence": sequence,
                    "created_at": timestamp,
                }
            )
        ).digest()
        connection.execute(
            """
            INSERT INTO audit_events(
                id, team_id, actor_principal_id, node_id, action,
                resource_type, resource_id, outcome, metadata_json,
                previous_event_hash, event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                team_id,
                actor_principal_id,
                node_id,
                action,
                resource_type,
                resource_id,
                outcome,
                metadata_json,
                previous_hash,
                event_hash,
                timestamp,
            ),
        )
        if head is None:
            connection.execute(
                """
                INSERT INTO audit_chain_heads(team_id, event_id, event_hash, sequence, updated_at)
                VALUES (?, ?, ?, 1, ?)
                """,
                (team_id, event_id, event_hash, timestamp),
            )
        else:
            connection.execute(
                """
                UPDATE audit_chain_heads
                SET event_id = ?, event_hash = ?, sequence = ?, updated_at = ?
                WHERE team_id = ?
                """,
                (event_id, event_hash, sequence, timestamp, team_id),
            )
