"""Team Hub local control and development-listener command line."""

from __future__ import annotations

import argparse
from contextlib import suppress
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import secrets
import stat
import sys

import uvicorn

from .security import validate_tls_files
from .service import create_app
from .store import HubError, HubStore


DEFAULT_DATA_DIR = Path.home() / ".agentsdock" / "team-hub"
SERVER_IDENTITY_RE = re.compile(r"[0-9a-f]{24}")


def _legacy_server_identity(state_dir: Path) -> str:
    machine = ""
    for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        with suppress(Exception):
            machine = path.read_text(encoding="utf-8").strip()
            if machine:
                break
    if not machine:
        machine = os.uname().nodename
    payload = f"{machine}|{state_dir.resolve()}".encode(
        "utf-8",
        errors="ignore",
    )
    return hashlib.sha256(payload).hexdigest()[:24]


def _read_server_identity_file(path: Path) -> str | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise PermissionError("AgentsServer identity is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise PermissionError("AgentsServer identity file is unsafe")
        raw = os.read(descriptor, 256)
        if os.read(descriptor, 1):
            raise RuntimeError("AgentsServer identity file is too large")
    finally:
        os.close(descriptor)
    try:
        identity = raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise RuntimeError("AgentsServer identity is not ASCII") from exc
    if SERVER_IDENTITY_RE.fullmatch(identity) is None:
        raise RuntimeError("AgentsServer identity is invalid")
    return identity


def _persist_server_identity(path: Path, identity: str) -> str:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise PermissionError("AgentsServer state directory is unsafe")
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    published = False
    published_identity: tuple[int, int] | None = None
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            # Creation mode is still filtered by the caller's umask. Restore
            # the exact owner-only invariant before this inode can be linked
            # into the durable identity path.
            os.fchmod(stream.fileno(), 0o600)
            stream.write(identity + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            opened = os.fstat(stream.fileno())
            published_identity = (int(opened.st_dev), int(opened.st_ino))
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            pass
        else:
            published = True
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        persisted = _read_server_identity_file(path)
        if persisted is None or not secrets.compare_digest(persisted, identity):
            raise RuntimeError("AgentsServer identity changed during reactivation")
        return persisted
    except BaseException:
        if published and published_identity is not None:
            try:
                linked = path.lstat()
                if (int(linked.st_dev), int(linked.st_ino)) == published_identity:
                    path.unlink()
                    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    directory = os.open(path.parent, directory_flags)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
            except OSError:
                pass
        raise
    finally:
        with suppress(OSError):
            temporary.unlink()


def _reactivation_server_identity(state_dir: Path) -> tuple[str, Path]:
    root = Path(os.path.abspath(os.path.expanduser(os.fspath(state_dir))))
    identity_path = root / "server-identity"
    persisted = _read_server_identity_file(identity_path)
    return (persisted or _legacy_server_identity(root), identity_path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentsdock-team-hub")
    subcommands = parser.add_subparsers(dest="command", required=True)

    serve = subcommands.add_parser("serve", help="run the Team Hub API")
    serve.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=7851)
    serve.add_argument("--allowed-host", action="append", default=[])
    serve.add_argument("--allowed-origin", action="append", default=[])
    serve.add_argument("--ssl-certfile", type=Path)
    serve.add_argument("--ssl-keyfile", type=Path)

    proof = subcommands.add_parser(
        "bootstrap-proof", help="renew or locate the local initial-owner proof"
    )
    proof.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)

    recovery = subcommands.add_parser(
        "owner-recovery",
        help=(
            "revoke the owner's existing device sessions and issue a local "
            "one-time recovery proof"
        ),
    )
    recovery.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    recovery.add_argument("--email", required=True)
    recovery.add_argument("--device-label", required=True)
    recovery.add_argument("--team-id")

    device_recovery = subcommands.add_parser(
        "device-recovery",
        help=(
            "revoke a member's existing device sessions and issue a local "
            "one-time recovery proof"
        ),
    )
    device_recovery.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    device_recovery.add_argument("--email", required=True)
    device_recovery.add_argument("--device-label", required=True)
    device_recovery.add_argument("--team-id")

    for command, help_text in (
        (
            "verify-snapshot",
            "verify an exact managed rollback snapshot without changing Hub state",
        ),
        (
            "rebase-snapshot",
            "refresh an update snapshot from one stopped legacy source",
        ),
        (
            "restore-snapshot",
            "offline verified restore of an exact managed rollback snapshot",
        ),
    ):
        snapshot = subcommands.add_parser(command, help=help_text)
        snapshot.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
        snapshot.add_argument("--snapshot", type=Path, required=True)
        snapshot.add_argument("--expected-host-identity", required=True)
        snapshot.add_argument("--expected-hub-id", required=True)
        snapshot.add_argument("--expected-operation-id", required=True)
    for command, help_text in (
        (
            "confirm-restored-snapshot",
            "verify an exact completed managed rollback restore",
        ),
        (
            "acknowledge-restored-snapshot",
            "retire an exact completed managed rollback restore receipt",
        ),
        (
            "confirm-restored-host-reactivation-snapshot",
            "verify an exact completed host-reactivation rollback restore",
        ),
        (
            "acknowledge-restored-host-reactivation-snapshot",
            "retire an exact completed host-reactivation rollback receipt",
        ),
    ):
        restored = subcommands.add_parser(command, help=help_text)
        restored.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
        restored.add_argument("--snapshot", type=Path, required=True)
        restored.add_argument("--expected-host-identity", required=True)
        restored.add_argument("--expected-hub-id", required=True)
        restored.add_argument("--expected-operation-id", required=True)
        if command.startswith("acknowledge-"):
            restored.add_argument("--allow-missing", action="store_true")
    for command, help_text in (
        (
            "publish-fenced-start-authority",
            "publish exact private candidate startup authority",
        ),
        (
            "clear-fenced-start-authority",
            "clear exact private candidate startup authority",
        ),
    ):
        authority = subcommands.add_parser(command, help=help_text)
        authority.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
        authority.add_argument("--snapshot", type=Path, required=True)
        authority.add_argument("--expected-host-identity", required=True)
        authority.add_argument("--expected-hub-id", required=True)
        authority.add_argument("--expected-reason", required=True)
        authority.add_argument("--expected-operation-id", required=True)
        if command == "clear-fenced-start-authority":
            authority.add_argument("--allow-missing", action="store_true")
    reactivation = subcommands.add_parser(
        "prepare-host-reactivation",
        help=(
            "verify and snapshot preserved managed Hub state before explicitly "
            "reactivating it"
        ),
    )
    reactivation.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    reactivation.add_argument("--server-state-dir", type=Path, required=True)
    begin_guard = subcommands.add_parser(
        "begin-host-cold-handoff",
        help="publish a durable guard before unlinking a legacy host runtime",
    )
    begin_guard.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    begin_guard.add_argument("--server-state-dir", type=Path, required=True)
    clear_guard = subcommands.add_parser(
        "clear-host-cold-handoff",
        help="clear one exact durable cold-handoff startup guard",
    )
    clear_guard.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    clear_guard.add_argument("--server-state-dir", type=Path, required=True)
    clear_guard.add_argument("--expected-guard-id", required=True)
    clear_guard.add_argument("--expected-device", type=int, required=True)
    clear_guard.add_argument("--expected-inode", type=int, required=True)
    identity_check = subcommands.add_parser(
        "verify-server-identity",
        help="verify the exact persisted AgentsServer identity without mutation",
    )
    identity_check.add_argument("--server-state-dir", type=Path, required=True)
    identity_check.add_argument("--expected-identity", required=True)
    abort_reactivation = subcommands.add_parser(
        "abort-host-reactivation-preflight",
        help="release an exact pre-takeover reactivation fence",
    )
    abort_reactivation.add_argument(
        "--data-dir", type=Path, default=DEFAULT_DATA_DIR
    )
    abort_reactivation.add_argument("--server-state-dir", type=Path, required=True)
    abort_reactivation.add_argument("--expected-hub-id", required=True)
    abort_reactivation.add_argument("--expected-operation-id", required=True)
    abort_reactivation.add_argument("--expected-snapshot", type=Path, required=True)
    abort_reactivation.add_argument("--expected-device", type=int, required=True)
    abort_reactivation.add_argument("--expected-inode", type=int, required=True)
    adopt_reactivation = subcommands.add_parser(
        "adopt-host-reactivation-preflight",
        help="atomically adopt an exact prepared reactivation fence",
    )
    adopt_reactivation.add_argument(
        "--data-dir", type=Path, default=DEFAULT_DATA_DIR
    )
    adopt_reactivation.add_argument("--server-state-dir", type=Path, required=True)
    adopt_reactivation.add_argument("--expected-hub-id", required=True)
    adopt_reactivation.add_argument("--expected-operation-id", required=True)
    adopt_reactivation.add_argument("--expected-snapshot", type=Path, required=True)
    adopt_reactivation.add_argument("--expected-device", type=int, required=True)
    adopt_reactivation.add_argument("--expected-inode", type=int, required=True)
    for command, help_text in (
        (
            "verify-host-reactivation-snapshot",
            "verify an exact disabled-host reactivation snapshot",
        ),
        (
            "restore-host-reactivation-snapshot",
            "offline restore of an exact disabled-host reactivation snapshot",
        ),
    ):
        reactivation_snapshot = subcommands.add_parser(command, help=help_text)
        reactivation_snapshot.add_argument(
            "--data-dir", type=Path, default=DEFAULT_DATA_DIR
        )
        reactivation_snapshot.add_argument("--snapshot", type=Path, required=True)
        reactivation_snapshot.add_argument(
            "--expected-host-identity", required=True
        )
        reactivation_snapshot.add_argument("--expected-hub-id", required=True)
        reactivation_snapshot.add_argument(
            "--expected-operation-id", required=True
        )
    return parser


def _loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value.lower() == "localhost"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise ValueError("port must be between 1 and 65535")
            if (args.ssl_certfile is None) != (args.ssl_keyfile is None):
                raise ValueError("--ssl-certfile and --ssl-keyfile must be supplied together")
            cert_and_key = args.ssl_certfile is not None and args.ssl_keyfile is not None
            if not _loopback(args.host) and not cert_and_key:
                raise ValueError(
                    "non-loopback Team Hub listeners require --ssl-certfile and --ssl-keyfile"
                )
            if cert_and_key:
                validate_tls_files(args.ssl_certfile, args.ssl_keyfile)
            allowed_hosts = set(args.allowed_host)
            allowed_hosts.add(args.host)
            if _loopback(args.host):
                allowed_hosts.update({"127.0.0.1", "localhost", "[::1]", "::1"})
            lease = HubStore.acquire_managed_runtime_lease(args.data_dir)
            try:
                app = create_app(
                    args.data_dir,
                    allowed_hosts=allowed_hosts,
                    allowed_origins=set(args.allowed_origin),
                )
                store: HubStore = app.state.store
                scheme = "https" if cert_and_key else "http"
                print(f"Team Hub {store.hub_id} listening at {scheme}://{args.host}:{args.port}")
                if store.health()["bootstrap_required"]:
                    print(
                        "Initial-owner proof file: "
                        f"{store.bootstrap_proof_path} (the secret itself is never printed)"
                    )
                uvicorn.run(
                    app,
                    host=args.host,
                    port=args.port,
                    ssl_certfile=str(args.ssl_certfile) if args.ssl_certfile else None,
                    ssl_keyfile=str(args.ssl_keyfile) if args.ssl_keyfile else None,
                    proxy_headers=False,
                    server_header=False,
                )
            finally:
                HubStore.release_managed_runtime_lease(lease)
            return 0
        if args.command in {
            "verify-snapshot",
            "rebase-snapshot",
            "restore-snapshot",
        }:
            operation = {
                "verify-snapshot": HubStore.verify_maintenance_snapshot,
                "rebase-snapshot": HubStore.rebase_maintenance_snapshot,
                "restore-snapshot": HubStore.restore_maintenance_snapshot,
            }[args.command]
            operation(
                args.data_dir,
                args.snapshot,
                expected_host_identity=args.expected_host_identity,
                expected_hub_id=args.expected_hub_id,
                expected_operation_id=args.expected_operation_id,
            )
            print(args.snapshot)
            return 0
        if args.command in {
            "confirm-restored-snapshot",
            "acknowledge-restored-snapshot",
            "confirm-restored-host-reactivation-snapshot",
            "acknowledge-restored-host-reactivation-snapshot",
        }:
            host_reactivation = "host-reactivation" in args.command
            expected_reason = (
                "host-reactivation" if host_reactivation else "server-update"
            )
            if args.command.startswith("confirm-"):
                HubStore.confirm_restored_maintenance_snapshot(
                    args.data_dir,
                    args.snapshot,
                    expected_host_identity=args.expected_host_identity,
                    expected_hub_id=args.expected_hub_id,
                    expected_operation_id=args.expected_operation_id,
                    expected_reason=expected_reason,
                )
            else:
                HubStore.acknowledge_restored_maintenance_snapshot(
                    args.data_dir,
                    args.snapshot,
                    expected_host_identity=args.expected_host_identity,
                    expected_hub_id=args.expected_hub_id,
                    expected_operation_id=args.expected_operation_id,
                    expected_reason=expected_reason,
                    allow_missing=args.allow_missing,
                )
            print(args.snapshot)
            return 0
        if args.command in {
            "publish-fenced-start-authority",
            "clear-fenced-start-authority",
        }:
            common = {
                "expected_host_identity": args.expected_host_identity,
                "expected_hub_id": args.expected_hub_id,
                "expected_reason": args.expected_reason,
                "expected_operation_id": args.expected_operation_id,
                "expected_snapshot": args.snapshot,
            }
            if args.command == "publish-fenced-start-authority":
                HubStore.publish_managed_startup_authority(
                    args.data_dir,
                    **common,
                )
            elif not HubStore.clear_managed_startup_authority(
                args.data_dir,
                **common,
            ) and not args.allow_missing:
                raise RuntimeError("exact Team Hub startup authority is missing")
            print(args.snapshot)
            return 0
        if args.command == "prepare-host-reactivation":
            identity, identity_path = _reactivation_server_identity(
                args.server_state_dir
            )
            (
                hub_id,
                snapshot,
                operation_id,
                fence_device,
                fence_inode,
            ) = HubStore.prepare_managed_host_reactivation(
                args.data_dir,
                expected_host_identity=identity,
            )
            try:
                persisted = _persist_server_identity(identity_path, identity)
                print(persisted)
                print(hub_id)
                print(operation_id)
                print(snapshot)
                print(fence_device)
                print(fence_inode)
            except BaseException as output_error:
                try:
                    cleared = HubStore.abort_prepared_host_reactivation(
                        args.data_dir,
                        expected_host_identity=identity,
                        expected_hub_id=hub_id,
                        expected_operation_id=operation_id,
                        expected_snapshot=snapshot,
                        expected_device=fence_device,
                        expected_inode=fence_inode,
                    )
                    if not cleared:
                        raise RuntimeError(
                            "exact Team Hub reactivation fence is missing"
                        )
                except BaseException as cleanup_error:
                    raise RuntimeError(
                        "Team Hub reactivation preflight failed after fencing; "
                        "the source remains fail-closed"
                    ) from cleanup_error
                raise output_error
            return 0
        if args.command == "begin-host-cold-handoff":
            identity, _identity_path = _reactivation_server_identity(
                args.server_state_dir
            )
            guard_id, guard_device, guard_inode = (
                HubStore.begin_managed_startup_guard(
                    args.data_dir,
                    expected_host_identity=identity,
                )
            )
            print(identity)
            print(guard_id)
            print(guard_device)
            print(guard_inode)
            return 0
        if args.command == "clear-host-cold-handoff":
            identity, _identity_path = _reactivation_server_identity(
                args.server_state_dir
            )
            if not HubStore.clear_managed_startup_guard(
                args.data_dir,
                expected_host_identity=identity,
                expected_guard_id=args.expected_guard_id,
                expected_device=args.expected_device,
                expected_inode=args.expected_inode,
            ):
                raise RuntimeError("exact Team Hub startup guard is missing")
            print(identity)
            return 0
        if args.command == "adopt-host-reactivation-preflight":
            identity, _identity_path = _reactivation_server_identity(
                args.server_state_dir
            )
            HubStore.adopt_prepared_host_reactivation(
                args.data_dir,
                expected_host_identity=identity,
                expected_hub_id=args.expected_hub_id,
                expected_operation_id=args.expected_operation_id,
                expected_snapshot=args.expected_snapshot,
                expected_device=args.expected_device,
                expected_inode=args.expected_inode,
            )
            print(identity)
            return 0
        if args.command == "verify-server-identity":
            expected = str(args.expected_identity)
            if SERVER_IDENTITY_RE.fullmatch(expected) is None:
                raise RuntimeError("expected AgentsServer identity is invalid")
            root = Path(
                os.path.abspath(
                    os.path.expanduser(os.fspath(args.server_state_dir))
                )
            )
            persisted = _read_server_identity_file(root / "server-identity")
            if persisted is None or not secrets.compare_digest(persisted, expected):
                raise RuntimeError(
                    "AgentsServer identity changed during Team Hub activation"
                )
            print(persisted)
            return 0
        if args.command == "abort-host-reactivation-preflight":
            identity, _identity_path = _reactivation_server_identity(
                args.server_state_dir
            )
            if not HubStore.abort_prepared_host_reactivation(
                args.data_dir,
                expected_host_identity=identity,
                expected_hub_id=args.expected_hub_id,
                expected_operation_id=args.expected_operation_id,
                expected_snapshot=args.expected_snapshot,
                expected_device=args.expected_device,
                expected_inode=args.expected_inode,
            ):
                raise RuntimeError(
                    "exact Team Hub reactivation preflight fence is missing"
                )
            print(identity)
            return 0
        if args.command == "verify-host-reactivation-snapshot":
            HubStore.verify_host_reactivation_snapshot(
                args.data_dir,
                args.snapshot,
                expected_host_identity=args.expected_host_identity,
                expected_hub_id=args.expected_hub_id,
                expected_operation_id=args.expected_operation_id,
            )
            print(args.snapshot)
            return 0
        if args.command == "restore-host-reactivation-snapshot":
            HubStore.restore_host_reactivation_snapshot(
                args.data_dir,
                args.snapshot,
                expected_host_identity=args.expected_host_identity,
                expected_hub_id=args.expected_hub_id,
                expected_operation_id=args.expected_operation_id,
            )
            print(args.snapshot)
            return 0
        # Local control commands remain available for a managed-bound Hub,
        # while the standalone listener above refuses to serve that database.
        # The same bounded interprocess lock fences proof-file changes from an
        # update/restart snapshot.
        with HubStore.maintenance_control_lock(args.data_dir):
            store = HubStore(
                args.data_dir,
                allow_bound_control=True,
                maintenance_control_locked=True,
            )
            if store.maintenance_fence() is not None:
                raise RuntimeError(
                    "Team Hub local control is unavailable during managed maintenance"
                )
            if args.command == "bootstrap-proof":
                path = store.renew_bootstrap_proof()
                print(path)
                return 0
            if args.command == "owner-recovery":
                path = store.issue_owner_recovery(
                    args.email,
                    args.device_label,
                    team_id=args.team_id,
                )
                print(path)
                return 0
            if args.command == "device-recovery":
                path = store.issue_device_recovery(
                    args.email,
                    args.device_label,
                    team_id=args.team_id,
                )
                print(path)
                return 0
    except (HubError, RuntimeError, ValueError, PermissionError) as exc:
        print(f"Team Hub: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
