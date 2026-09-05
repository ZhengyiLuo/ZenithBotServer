"""Crash-safe provenance for one AgentsServer release activation.

The installer deliberately keeps this small ledger outside any release tree.
It exists only from the last pre-takeover snapshot of links/configuration until
either candidate health or verified rollback.  A later installer must recover
that exact transaction before it may choose a new rollback baseline.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
from typing import Any


FORMAT = 1
MAX_CONTROL_BYTES = 256 * 1024
MAX_CONFIG_BYTES = 16 * 1024 * 1024
PHASES = {
    "prepared",
    "guarded",
    "linking",
    "linked",
    "stopping",
    "stopped",
    "fencing",
    "fenced",
    "authorizing",
    "authority",
    "candidate-starting",
    "candidate-healthy",
    "committing",
    "committed",
    "rolling-back",
    "rolled-back",
    "rollback-healthy",
}
TRANSITIONS = {
    "prepared": {"guarded", "linking", "rolling-back"},
    "guarded": {"linking", "rolling-back"},
    "linking": {"linked", "rolling-back"},
    "linked": {"stopping", "candidate-starting", "rolling-back"},
    "stopping": {"stopped", "rolling-back"},
    "stopped": {"fencing", "fenced", "authorizing", "rolling-back"},
    "fencing": {"fenced", "rolling-back"},
    "fenced": {"authorizing", "rolling-back"},
    "authorizing": {"authority", "rolling-back"},
    "authority": {"candidate-starting", "rolling-back"},
    "candidate-starting": {"candidate-healthy", "rolling-back"},
    "candidate-healthy": {"committing", "rolling-back"},
    "committing": {"committed"},
    "committed": set(),
    "rolling-back": {"rolled-back"},
    "rolled-back": {"rollback-healthy"},
    "rollback-healthy": set(),
}
MANIFEST_TEMP_RE = re.compile(r"^\.manifest\.json\.[0-9a-f]{24}\.tmp$")
GC_DIRECTORY_RE = re.compile(r"^\.activation-transaction-gc-activation-[0-9a-f]{24}$")
BEGIN_DIRECTORY_RE = re.compile(r"^\.activation-transaction\.[0-9a-f]{24}\.tmp$")


def _absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_text(value: Any, name: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RuntimeError(f"activation transaction {name} is invalid")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise RuntimeError(f"activation transaction {name} is invalid")
    return value


def _read_private(path: Path, *, maximum: int = MAX_CONTROL_BYTES) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 <= before.st_size <= maximum
        ):
            raise PermissionError("activation transaction file is unsafe")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
        linked = path.lstat()
        if (
            len(value) > maximum
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RuntimeError("activation transaction file changed while reading")
        return value
    finally:
        os.close(descriptor)


def _read_owned_regular(path: Path, *, maximum: int = MAX_CONFIG_BYTES) -> bytes:
    """Read an installer-owned config, allowing 0600 or ordinary 0644 mode."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 0 <= before.st_size <= maximum
        ):
            raise PermissionError("activation configuration file is unsafe")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
        linked = path.lstat()
        if (
            len(value) > maximum
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RuntimeError("activation configuration changed while reading")
        return value
    finally:
        os.close(descriptor)


def _write_new_private(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(value):
            written += os.write(descriptor, value[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_private(path: Path, value: bytes) -> None:
    temporary = path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
    try:
        _write_new_private(temporary, value)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(_read_private(path, maximum=MAX_CONFIG_BYTES)).hexdigest()


def _owned_regular_sha256(path: Path, *, maximum: int = 4096) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 1 <= before.st_size <= maximum
        ):
            raise PermissionError("activation release identity is unsafe")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
        linked = path.lstat()
        if (
            not 1 <= len(value) <= maximum
            or len(value) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RuntimeError("activation release identity changed while reading")
        return hashlib.sha256(value).hexdigest()
    finally:
        os.close(descriptor)


def _release_identity(source: Path | None, target: Path | None) -> dict[str, Any]:
    if source is None or target is None:
        return {}
    info = source.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise PermissionError("activation rollback release is unsafe")
    return {
        "source": str(source),
        "target": str(target),
        "device": info.st_dev,
        "inode": info.st_ino,
        "version_sha256": _owned_regular_sha256(source / "VERSION"),
    }


def _release_matches(path: Path, release: dict[str, Any]) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and not stat.S_IMODE(info.st_mode) & 0o022
        and info.st_dev == release["device"]
        and info.st_ino == release["inode"]
        and _owned_regular_sha256(path / "VERSION")
        == release["version_sha256"]
    )


def _locate_release(
    release: dict[str, Any],
    *,
    extras: tuple[Path, ...] = (),
) -> Path | None:
    candidates = [
        _absolute(release["source"]),
        _absolute(release["target"]),
        *extras,
    ]
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if _release_matches(candidate, release):
            return candidate
    return None


def _copy_config(source: Path, destination: Path) -> tuple[str, int]:
    source_info = source.lstat()
    value = _read_owned_regular(source, maximum=MAX_CONFIG_BYTES)
    linked_info = source.lstat()
    if (source_info.st_dev, source_info.st_ino) != (
        linked_info.st_dev,
        linked_info.st_ino,
    ):
        raise RuntimeError("activation configuration changed while capturing it")
    _write_new_private(destination, value)
    return hashlib.sha256(value).hexdigest(), stat.S_IMODE(source_info.st_mode)


def _configuration(
    path: Path,
    backup: Path,
    *,
    allowed_modes: set[int],
) -> dict[str, Any]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {
            "existed": False,
            "backup": backup.name,
            "sha256": None,
            "mode": None,
        }
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise PermissionError(f"configuration path is unsafe: {path}")
    digest, mode = _copy_config(path, backup)
    if mode not in allowed_modes:
        raise PermissionError(f"configuration mode cannot be restored safely: {path}")
    return {
        "existed": True,
        "backup": backup.name,
        "sha256": digest,
        "mode": mode,
    }


def _link_state(path: Path, *, allow_directory: bool) -> dict[str, str]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return {"kind": "missing", "target": ""}
    if stat.S_ISLNK(before.st_mode):
        target = _safe_text(os.readlink(path), "link target")
        after = path.lstat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise RuntimeError("activation link changed while reading")
        return {"kind": "symlink", "target": target}
    if allow_directory and stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid():
        return {"kind": "directory", "target": ""}
    raise RuntimeError(f"activation path is not supported: {path}")


def _linked_release_identity(path: Path) -> dict[str, Any]:
    state = _link_state(path, allow_directory=False)
    if state["kind"] != "symlink":
        return {}
    target = Path(state["target"])
    if not target.is_absolute():
        target = path.parent / target
    target = _absolute(target)
    try:
        return _release_identity(target, target)
    except FileNotFoundError:
        # A pre-existing dangling previous link remains restorable as an exact
        # link value, but it carries no directory-identity claim.
        return {}


def _validate_root(root: Path) -> None:
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise PermissionError("activation transaction root is unsafe")


def _validate_releases_root(root: Path) -> Path:
    releases = root / "releases"
    info = releases.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise PermissionError("activation releases root is unsafe")
    return releases


def _validate_guard_metadata(guard: Any) -> None:
    if guard == {}:
        return
    if (
        not isinstance(guard, dict)
        or set(guard) != {"id", "device", "inode"}
        or not isinstance(guard.get("id"), str)
        or re.fullmatch(r"cold-handoff-[0-9a-f]{24}", guard["id"]) is None
        or isinstance(guard.get("device"), bool)
        or not isinstance(guard.get("device"), int)
        or guard["device"] <= 0
        or isinstance(guard.get("inode"), bool)
        or not isinstance(guard.get("inode"), int)
        or guard["inode"] <= 0
    ):
        raise RuntimeError("activation transaction guard state is invalid")


def _validate_hub_metadata(hub: Any, *, intent: str) -> None:
    if hub == {}:
        return
    if not isinstance(hub, dict) or set(hub) != {
        "kind",
        "data_dir",
        "hub_id",
        "host_identity",
        "operation_id",
        "snapshot",
        "fence_device",
        "fence_inode",
    }:
        raise RuntimeError("activation transaction Hub state is invalid")
    data_dir_raw = hub.get("data_dir")
    snapshot_raw = hub.get("snapshot")
    if not isinstance(data_dir_raw, str) or not isinstance(snapshot_raw, str):
        raise RuntimeError("activation transaction Hub state is invalid")
    data_dir = _absolute(data_dir_raw)
    snapshot = _absolute(snapshot_raw)
    if (
        data_dir_raw != str(data_dir)
        or snapshot_raw != str(snapshot)
        or snapshot.parent != data_dir / "maintenance-backups"
        or re.fullmatch(r"snapshot_[A-Za-z0-9_]+", snapshot.name) is None
        or hub.get("kind") not in {"server-update", "host-reactivation"}
        or not isinstance(hub.get("hub_id"), str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]{8,240}", hub["hub_id"]) is None
        or not isinstance(hub.get("host_identity"), str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:@/-]{7,239}",
            hub["host_identity"],
        )
        is None
        or not isinstance(hub.get("operation_id"), str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", hub["operation_id"])
        is None
        or isinstance(hub.get("fence_device"), bool)
        or not isinstance(hub.get("fence_device"), int)
        or hub["fence_device"] <= 0
        or isinstance(hub.get("fence_inode"), bool)
        or not isinstance(hub.get("fence_inode"), int)
        or hub["fence_inode"] <= 0
    ):
        raise RuntimeError("activation transaction Hub state is invalid")
    if (
        (hub["kind"] == "server-update" and intent != "server-update")
        or (
            hub["kind"] == "host-reactivation"
            and intent not in {"host-reactivation", "failed-host-repair"}
        )
    ):
        raise RuntimeError("activation transaction Hub intent changed")


def _manifest_path(root: Path) -> Path:
    return root / ".activation-transaction" / "manifest.json"


def _cleanup_manifest_temps(directory: Path) -> None:
    removed = False
    for entry in list(os.scandir(directory)):
        if MANIFEST_TEMP_RE.fullmatch(entry.name) is None:
            continue
        path = directory / entry.name
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise PermissionError("activation transaction staging file is unsafe")
        path.unlink()
        removed = True
    if removed:
        _fsync_directory(directory)


def _remove_private_transaction_directory(directory: Path) -> None:
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise PermissionError("retired activation transaction is unsafe")
    for child in list(os.scandir(directory)):
        child_path = directory / child.name
        child_info = child_path.lstat()
        if child.name == "candidate.retired":
            if (
                not stat.S_ISDIR(child_info.st_mode)
                or child_info.st_uid != os.getuid()
                or not shutil.rmtree.avoids_symlink_attacks
            ):
                raise PermissionError("retired activation candidate is unsafe")
            shutil.rmtree(child_path)
            continue
        if (
            child.name
            not in {"manifest.json", "env.backup", "service.backup"}
            and MANIFEST_TEMP_RE.fullmatch(child.name) is None
        ) or (
            not stat.S_ISREG(child_info.st_mode)
            or child_info.st_uid != os.getuid()
            or child_info.st_nlink != 1
            or stat.S_IMODE(child_info.st_mode) != 0o600
        ):
            raise PermissionError("retired activation transaction is unsafe")
        child_path.unlink()
    directory.rmdir()


def _cleanup_retired_transactions(root: Path) -> None:
    removed = False
    for entry in list(os.scandir(root)):
        if (
            GC_DIRECTORY_RE.fullmatch(entry.name) is None
            and BEGIN_DIRECTORY_RE.fullmatch(entry.name) is None
        ):
            continue
        directory = root / entry.name
        _remove_private_transaction_directory(directory)
        removed = True
    if removed:
        _fsync_directory(root)


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _read_manifest(
    root: Path,
    *,
    directory: Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    _validate_root(root)
    releases = _validate_releases_root(root)
    directory = directory or (root / ".activation-transaction")
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise PermissionError("activation transaction directory is unsafe")
    _cleanup_manifest_temps(directory)
    try:
        value = json.loads(_read_private(directory / "manifest.json"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("activation transaction manifest is invalid") from exc
    expected = {
        "format",
        "transaction_id",
        "release_version",
        "release_dir",
        "candidate_release",
        "old_target",
        "old_release",
        "current",
        "previous",
        "previous_release",
        "env_path",
        "env",
        "service_path",
        "service",
        "service_state",
        "service_enabled",
        "legacy_service_state",
        "legacy_service_enabled",
        "prior_port",
        "prior_bind_address",
        "intent",
        "client_binding",
        "desired_env",
        "desired_service",
        "phase",
        "rollback_from",
        "hub",
        "guard",
        "authority_pending",
        "observed_env_sha256",
        "observed_service_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("format") != FORMAT:
        raise RuntimeError("activation transaction manifest is invalid")
    if value.get("phase") not in PHASES:
        raise RuntimeError("activation transaction phase is invalid")
    rollback_from = value.get("rollback_from")
    if rollback_from is not None and (
        rollback_from not in PHASES
        or rollback_from
        in {
            "rolling-back",
            "rolled-back",
            "rollback-healthy",
            "committing",
            "committed",
        }
        or value["phase"]
        not in {"rolling-back", "rolled-back", "rollback-healthy"}
    ):
        raise RuntimeError("activation transaction rollback origin is invalid")
    if value["phase"] in {"rolling-back", "rolled-back", "rollback-healthy"} and rollback_from is None:
        raise RuntimeError("activation transaction rollback origin is missing")
    transaction_id = _safe_text(value.get("transaction_id"), "id", maximum=64)
    if re.fullmatch(r"activation-[0-9a-f]{24}", transaction_id) is None:
        raise RuntimeError("activation transaction id is invalid")
    _safe_text(value.get("release_version"), "version", maximum=128)
    for field in ("release_dir", "env_path", "service_path"):
        _safe_text(value.get(field), field)
    if not isinstance(value.get("old_target"), str) or any(
        character in value["old_target"] for character in "\x00\r\n"
    ):
        raise RuntimeError("activation transaction old target is invalid")
    def valid_release(release: Any) -> bool:
        return (
            isinstance(release, dict)
            and set(release)
            == {"source", "target", "device", "inode", "version_sha256"}
            and isinstance(release.get("source"), str)
            and isinstance(release.get("target"), str)
            and release["source"].startswith("/")
            and release["target"].startswith("/")
            and isinstance(release.get("device"), int)
            and release["device"] >= 0
            and isinstance(release.get("inode"), int)
            and release["inode"] > 0
            and isinstance(release.get("version_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", release["version_sha256"])
            is not None
        )

    old_release = value.get("old_release")
    if old_release != {} and not valid_release(old_release):
        raise RuntimeError("activation transaction rollback release is invalid")
    previous_release = value.get("previous_release")
    if previous_release != {} and not valid_release(previous_release):
        raise RuntimeError("activation transaction previous release is invalid")
    for field in ("current", "previous"):
        item = value.get(field)
        if (
            not isinstance(item, dict)
            or set(item) != {"kind", "target"}
            or item.get("kind") not in {"missing", "symlink", "directory"}
            or not isinstance(item.get("target"), str)
            or "\n" in item["target"]
            or "\r" in item["target"]
            or "\x00" in item["target"]
            or (field == "previous" and item["kind"] == "directory")
        ):
            raise RuntimeError("activation transaction link state is invalid")
    for field in ("env", "service"):
        item = value.get(field)
        if (
            not isinstance(item, dict)
            or set(item) != {"existed", "backup", "sha256", "mode"}
            or not isinstance(item.get("existed"), bool)
            or item.get("backup") not in {"env.backup", "service.backup"}
            or (
                item["existed"]
                and (
                    not isinstance(item.get("sha256"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                    is None
                )
            )
            or (
                item["existed"]
                and (
                    not isinstance(item.get("mode"), int)
                    or item["mode"] not in {0o600, 0o640, 0o644}
                )
            )
            or (
                not item["existed"]
                and (item.get("sha256") is not None or item.get("mode") is not None)
            )
        ):
            raise RuntimeError("activation transaction backup metadata is invalid")
        if item["existed"] and _sha256(directory / item["backup"]) != item["sha256"]:
            raise RuntimeError("activation transaction backup changed")
    if value.get("service_state") not in {"absent", "stopped", "running"}:
        raise RuntimeError("activation transaction service state is invalid")
    if not isinstance(value.get("service_enabled"), bool):
        raise RuntimeError("activation transaction service enablement is invalid")
    if value.get("legacy_service_state") not in {"absent", "stopped", "running"}:
        raise RuntimeError("activation transaction legacy service state is invalid")
    if not isinstance(value.get("legacy_service_enabled"), bool):
        raise RuntimeError("activation transaction legacy enablement is invalid")
    prior_port = value.get("prior_port")
    if not isinstance(prior_port, int) or not 1 <= prior_port <= 65535:
        raise RuntimeError("activation transaction prior port is invalid")
    prior_bind = _safe_text(
        value.get("prior_bind_address"), "prior bind", maximum=64
    )
    if prior_bind != "localhost":
        try:
            parsed_bind = ipaddress.ip_address(prior_bind)
        except ValueError as exc:
            raise RuntimeError(
                "activation transaction prior bind is invalid"
            ) from exc
        if str(parsed_bind) != prior_bind:
            raise RuntimeError("activation transaction prior bind is noncanonical")
    if value.get("intent") not in {
        "ordinary",
        "server-update",
        "host-reactivation",
        "failed-host-repair",
    }:
        raise RuntimeError("activation transaction intent is invalid")
    client_binding = value.get("client_binding")
    if (
        not isinstance(client_binding, str)
        or len(client_binding) > 64 * 1024
        or any(character in client_binding for character in "\x00\r\n")
    ):
        raise RuntimeError("activation transaction client binding is invalid")
    for field in ("desired_env", "desired_service"):
        item = value.get(field)
        kind = field.removeprefix("desired_")
        destination = _absolute(
            value["env_path" if kind == "env" else "service_path"]
        )
        expected_source, _expected_secured = _config_staging_paths(
            destination,
            value["transaction_id"],
            kind,
        )
        if item is not None and (
            not isinstance(item, dict)
            or set(item) != {"sha256", "mode", "source", "device", "inode"}
            or not isinstance(item.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
            or not isinstance(item.get("mode"), int)
            or item["mode"] not in (
                {0o600} if field == "desired_env" else {0o600, 0o644}
            )
            or item.get("source") != str(expected_source)
            or isinstance(item.get("device"), bool)
            or not isinstance(item.get("device"), int)
            or item["device"] <= 0
            or isinstance(item.get("inode"), bool)
            or not isinstance(item.get("inode"), int)
            or item["inode"] <= 0
        ):
            raise RuntimeError("activation desired configuration is invalid")
    if not isinstance(value.get("authority_pending"), bool):
        raise RuntimeError("activation transaction authority state is invalid")
    for field in ("observed_env_sha256", "observed_service_sha256"):
        items = value.get(field)
        if not isinstance(items, list) or any(
            item is not None
            and (
                not isinstance(item, str)
                or re.fullmatch(r"[0-9a-f]{64}", item) is None
            )
            for item in items
        ):
            raise RuntimeError("activation transaction configuration history is invalid")
    candidate_release = value.get("candidate_release")
    if not valid_release(candidate_release):
        raise RuntimeError("activation transaction candidate release is invalid")
    release_version = value["release_version"]
    release_dir = _absolute(value["release_dir"])
    candidate_source = _absolute(candidate_release["source"])
    candidate_target = _absolute(candidate_release["target"])
    if (
        value["release_dir"] != str(release_dir)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", release_version)
        is None
        or release_dir != releases / release_version
        or candidate_release["source"] != str(candidate_source)
        or candidate_release["target"] != str(candidate_target)
        or candidate_source.parent != releases
        or candidate_source == candidate_target
        or candidate_target != release_dir
    ):
        raise RuntimeError("activation transaction release path is invalid")
    if old_release:
        old_source = _absolute(old_release["source"])
        old_target = _absolute(old_release["target"])
        if (
            old_release["source"] != str(old_source)
            or old_release["target"] != str(old_target)
            or old_target.parent != releases
            or (old_source.parent != releases and old_source != root / "current")
            or value["old_target"] != str(old_target)
        ):
            raise RuntimeError("activation transaction rollback release path is invalid")
    elif value["old_target"]:
        raise RuntimeError("activation transaction rollback release path is invalid")
    if previous_release:
        previous_source = _absolute(previous_release["source"])
        previous_target = _absolute(previous_release["target"])
        if (
            previous_release["source"] != str(previous_source)
            or previous_release["target"] != str(previous_target)
            or previous_source.parent != releases
            or previous_target.parent != releases
        ):
            raise RuntimeError("activation transaction previous release path is invalid")
    hub = value.get("hub")
    _validate_hub_metadata(hub, intent=value["intent"])
    guard = value.get("guard")
    _validate_guard_metadata(guard)
    return directory, value


def _current_config_metadata(path: Path) -> dict[str, Any] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    payload = _read_owned_regular(path, maximum=MAX_CONFIG_BYTES)
    linked_info = path.lstat()
    if (info.st_dev, info.st_ino) != (linked_info.st_dev, linked_info.st_ino):
        raise RuntimeError("activation configuration changed while verifying it")
    return {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "mode": stat.S_IMODE(info.st_mode),
    }


def _current_config_digest(path: Path) -> str | None:
    metadata = _current_config_metadata(path)
    return None if metadata is None else str(metadata["sha256"])


def _config_staging_paths(
    destination: Path,
    transaction_id: str,
    kind: str,
) -> tuple[Path, Path]:
    prefix = f".{destination.name}.activation-{transaction_id}-{kind}"
    return (
        destination.parent / f"{prefix}.source",
        destination.parent / f"{prefix}.publication",
    )


def _desired_content_metadata(desired: dict[str, Any]) -> dict[str, Any]:
    return {"sha256": desired["sha256"], "mode": desired["mode"]}


def _config_identity_matches(info: os.stat_result, desired: dict[str, Any]) -> bool:
    return (info.st_dev, info.st_ino) == (desired["device"], desired["inode"])


def _config_path_matches_desired(path: Path, desired: dict[str, Any]) -> bool:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return False
    if not _config_identity_matches(before, desired):
        return False
    if _current_config_metadata(path) != _desired_content_metadata(desired):
        return False
    after = path.lstat()
    return (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)


def _open_config_staging_source(path: Path) -> tuple[int, os.stat_result, bytes]:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 0 <= before.st_size <= MAX_CONFIG_BYTES
        ):
            raise PermissionError("activation configuration staging file is unsafe")
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        linked = path.lstat()
        if (
            len(payload) > MAX_CONFIG_BYTES
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RuntimeError("activation configuration staging file changed")
        return descriptor, before, payload
    except BaseException:
        os.close(descriptor)
        raise


def _staged_config_metadata(path: Path) -> tuple[dict[str, Any], os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink not in {1, 2}
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 0 <= before.st_size <= MAX_CONFIG_BYTES
        ):
            raise PermissionError("activation configuration publication is unsafe")
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        linked = path.lstat()
        if (
            len(payload) > MAX_CONFIG_BYTES
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RuntimeError("activation configuration publication changed")
        return {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "mode": stat.S_IMODE(before.st_mode),
        }, before
    finally:
        os.close(descriptor)


def _unlink_if_same_file(path: Path, identity: os.stat_result) -> None:
    try:
        linked = path.lstat()
    except FileNotFoundError:
        return
    if (linked.st_dev, linked.st_ino) == (identity.st_dev, identity.st_ino):
        path.unlink()


def _fsync_staging_directory(path: Path) -> None:
    """Persist the private staging link before the final publish rename."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_staged_config(
    *,
    staged: Path,
    source: Path,
    destination: Path,
    desired: dict[str, Any],
) -> None:
    metadata, identity = _staged_config_metadata(staged)
    if (
        metadata != _desired_content_metadata(desired)
        or not _config_identity_matches(identity, desired)
    ):
        raise RuntimeError("activation staged configuration does not match its journal")
    _unlink_if_same_file(source, identity)
    _fsync_staging_directory(source.parent)
    if staged.parent != source.parent:
        _fsync_staging_directory(staged.parent)
    try:
        os.replace(staged, destination)
    except BaseException:
        # A normal rename failure leaves the exact staged inode available for
        # retry. Restore the caller's source name when possible so an in-process
        # retry retains the original interface; a process crash instead leaves
        # the fsynced deterministic staging name for recovery.
        try:
            staged.lstat()
            source.lstat()
        except FileNotFoundError:
            try:
                staged.lstat()
            except FileNotFoundError:
                pass
            else:
                os.rename(staged, source)
                _fsync_staging_directory(source.parent)
        raise
    _fsync_directory(destination.parent)
    if not _config_path_matches_desired(destination, desired):
        raise RuntimeError("activation configuration changed after publication")


def _cleanup_config_staging(
    directory: Path,
    value: dict[str, Any],
) -> None:
    """Remove only schema-closed staging inodes owned by this transaction."""

    for kind in ("env", "service"):
        desired = value[f"desired_{kind}"]
        destination = _absolute(
            value["env_path" if kind == "env" else "service_path"]
        )
        source, secured = _config_staging_paths(
            destination,
            value["transaction_id"],
            kind,
        )

        try:
            secured_metadata, secured_info = _staged_config_metadata(secured)
        except FileNotFoundError:
            secured_metadata = None
            secured_info = None

        try:
            source_metadata, source_info = _staged_config_metadata(source)
        except FileNotFoundError:
            pass
        else:
            if desired is None:
                if (
                    source_info.st_nlink != 1
                    or stat.S_IMODE(source_info.st_mode) != 0o600
                ):
                    raise PermissionError(
                        "activation unjournaled configuration staging is unsafe"
                    )
            elif (
                source_metadata != _desired_content_metadata(desired)
                or not _config_identity_matches(source_info, desired)
            ):
                # A later rewrite may have populated this private reserved
                # source and crashed before its new intent was journaled.  No
                # matching publication inode can exist before that
                # write-ahead update, so an independent nlink-1 draft is safe
                # to discard even while the prior exact publication is being
                # resumed.
                if (
                    source_info.st_nlink != 1
                    or stat.S_IMODE(source_info.st_mode) != 0o600
                    or (
                        secured_info is not None
                        and (
                            desired is None
                            or secured_metadata
                            != _desired_content_metadata(desired)
                            or not _config_identity_matches(
                                secured_info,
                                desired,
                            )
                        )
                    )
                ):
                    raise RuntimeError(
                        "activation configuration staging ownership changed"
                    )
            source.unlink()
            _fsync_directory(source.parent)

        if secured_info is None:
            continue
        if desired is None or (
            secured_metadata != _desired_content_metadata(desired)
            or not _config_identity_matches(secured_info, desired)
        ):
            raise RuntimeError(
                "activation configuration publication ownership changed"
            )
        secured.unlink()
        _fsync_directory(destination.parent)


def begin(args: argparse.Namespace) -> None:
    root = _absolute(args.root)
    _validate_root(root)
    releases = _validate_releases_root(root)
    _cleanup_retired_transactions(root)
    current = _absolute(args.current)
    previous = _absolute(args.previous)
    env_path = _absolute(args.env)
    service_path = _absolute(args.service)
    release_dir = _absolute(args.release_dir)
    candidate_source = _absolute(args.candidate_source)
    old_source = _absolute(args.old_source) if args.old_source else None
    old_target = _absolute(args.old_target) if args.old_target else None
    release_version = _safe_text(args.release_version, "version", maximum=128)
    if (
        current != root / "current"
        or previous != root / "previous"
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", release_version)
        is None
        or release_dir != releases / release_version
        or candidate_source.parent != releases
        or candidate_source == release_dir
        or (
            old_target is not None and old_target.parent != releases
        )
        or (
            old_source is not None
            and old_source.parent != releases
            and old_source != current
        )
        or ((old_source is None) != (old_target is None))
    ):
        raise RuntimeError("activation transaction paths are invalid")
    final = root / ".activation-transaction"
    try:
        final.lstat()
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError("an activation transaction is already pending")
    temporary = root / f".activation-transaction.{secrets.token_hex(12)}.tmp"
    os.mkdir(temporary, 0o700)
    os.chmod(temporary, 0o700)
    try:
        env = _configuration(
            env_path,
            temporary / "env.backup",
            allowed_modes={0o600},
        )
        service = _configuration(
            service_path,
            temporary / "service.backup",
            allowed_modes={0o600, 0o640, 0o644},
        )
        current_state = _link_state(current, allow_directory=True)
        old_release = _release_identity(old_source, old_target)
        if current_state["kind"] == "missing":
            if old_release:
                raise RuntimeError(
                    "activation rollback identity exists without a current release"
                )
        elif not old_release:
            raise RuntimeError("activation current release has no rollback identity")
        elif current_state["kind"] == "directory":
            if old_source != current or not _release_matches(current, old_release):
                raise RuntimeError("activation legacy current rollback identity changed")
        else:
            current_target = Path(current_state["target"])
            if not current_target.is_absolute():
                current_target = current.parent / current_target
            if not _release_matches(_absolute(current_target), old_release):
                raise RuntimeError("activation current rollback identity changed")
        candidate_release = _release_identity(candidate_source, release_dir)
        version_payload = _read_owned_regular(
            candidate_source / "VERSION",
            maximum=4096,
        )
        try:
            candidate_version = version_payload.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise RuntimeError("activation candidate version is invalid") from exc
        if candidate_version != release_version:
            raise RuntimeError("activation candidate release version changed")
        value: dict[str, Any] = {
            "format": FORMAT,
            "transaction_id": f"activation-{secrets.token_hex(12)}",
            "release_version": release_version,
            "release_dir": str(release_dir),
            "candidate_release": candidate_release,
            "old_target": str(old_target) if old_target is not None else "",
            "old_release": old_release,
            "current": current_state,
            "previous": _link_state(previous, allow_directory=False),
            "previous_release": _linked_release_identity(previous),
            "env_path": str(env_path),
            "env": env,
            "service_path": str(service_path),
            "service": service,
            "service_state": args.service_state,
            "service_enabled": args.service_enabled == "true",
            "legacy_service_state": args.legacy_service_state,
            "legacy_service_enabled": args.legacy_service_enabled == "true",
            "prior_port": args.prior_port,
            "prior_bind_address": args.prior_bind_address,
            "intent": args.intent,
            "client_binding": args.client_binding,
            "desired_env": None,
            "desired_service": None,
            "phase": "prepared",
            "rollback_from": None,
            "hub": {},
            "guard": {},
            "authority_pending": False,
            "observed_env_sha256": [env["sha256"]],
            "observed_service_sha256": [service["sha256"]],
        }
        _write_new_private(temporary / "manifest.json", _canonical(value))
        _fsync_directory(temporary)
        _verified_directory, verified_value = _read_manifest(
            root,
            directory=temporary,
        )
        _validate_invocation(
            args,
            verified_value,
            transaction_directory=temporary,
        )
        os.rename(temporary, final)
        _fsync_directory(root)
        sys.stdout.write(str(value["transaction_id"]) + "\n")
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _validate_invocation(
    args: argparse.Namespace,
    value: dict[str, Any],
    *,
    allow_missing_candidate: bool = False,
    transaction_directory: Path | None = None,
) -> None:
    root = _absolute(args.root)
    if (
        _absolute(value["env_path"]) != _absolute(args.env)
        or _absolute(value["service_path"]) != _absolute(args.service)
        or _absolute(args.current) != root / "current"
        or _absolute(args.previous) != root / "previous"
    ):
        raise RuntimeError("pending activation belongs to a different layout")
    if getattr(args, "transaction_id", None) not in {None, ""} and (
        args.transaction_id != value["transaction_id"]
    ):
        raise RuntimeError("activation transaction ownership changed")
    if getattr(args, "release_version", None) not in {None, ""} and (
        value["release_version"] != args.release_version
    ):
        raise RuntimeError("activation transaction release version changed")
    if getattr(args, "release_dir", None) not in {None, ""} and (
        _absolute(value["release_dir"]) != _absolute(args.release_dir)
    ):
        raise RuntimeError("activation transaction release path changed")
    candidate_retired = root / "releases" / (
        ".activation-candidate-retired-" + str(value["transaction_id"])
    )
    candidate_parked = (
        transaction_directory or (root / ".activation-transaction")
    ) / "candidate.retired"
    old_release = value["old_release"]
    if old_release and _locate_release(old_release) is None:
        raise RuntimeError("activation rollback release identity changed")
    candidate_location = _locate_release(
        value["candidate_release"],
        extras=(candidate_retired, candidate_parked),
    )
    if candidate_location is None and not allow_missing_candidate:
        raise RuntimeError("activation candidate release identity changed")

    def link_points_to(path: Path, release: dict[str, Any]) -> bool:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISLNK(info.st_mode):
            return False
        raw_target = os.readlink(path)
        target = Path(raw_target)
        if not target.is_absolute():
            target = path.parent / target
        return _release_matches(_absolute(target), release)

    current_path = _absolute(args.current)
    previous_path = _absolute(args.previous)
    current_state = _link_state(current_path, allow_directory=True)
    original_current = value["current"]
    candidate_current = {"kind": "symlink", "target": value["release_dir"]}
    phase = value["phase"]
    candidate_link_target_missing = False
    if current_state == candidate_current:
        raw_target = Path(current_state["target"])
        if not raw_target.is_absolute():
            raw_target = current_path.parent / raw_target
        try:
            raw_target.lstat()
        except FileNotFoundError:
            candidate_link_target_missing = True
    points_to_candidate = (
        current_state == candidate_current
        and link_points_to(current_path, value["candidate_release"])
    )
    points_to_old = (
        bool(old_release)
        and current_state == original_current
        and (
            (
                original_current["kind"] == "symlink"
                and link_points_to(current_path, old_release)
            )
            or (
                original_current["kind"] == "directory"
                and _release_matches(current_path, old_release)
            )
        )
    )
    original_current_valid = current_state == original_current and (
        original_current["kind"] == "missing" or points_to_old
    )
    candidate_current_valid = points_to_candidate or (
        allow_missing_candidate
        and current_state == candidate_current
        and candidate_link_target_missing
    )
    current_missing = current_state == {"kind": "missing", "target": ""}
    if phase in {"prepared", "guarded"}:
        if not original_current_valid:
            raise RuntimeError("current release changed before link takeover")
    elif phase in {"linking", "rolling-back"}:
        if not (
            original_current_valid
            or candidate_current_valid
            or current_missing
            or (
                current_state == candidate_current
                and candidate_link_target_missing
            )
        ):
            raise RuntimeError("current release target changed during activation")
    elif phase in {"rolled-back", "rollback-healthy"}:
        if not original_current_valid:
            raise RuntimeError("current release was not restored")
    elif not candidate_current_valid:
        raise RuntimeError("current release does not resolve to the candidate")

    previous_state = _link_state(previous_path, allow_directory=False)
    candidate_previous = (
        {"kind": "symlink", "target": value["old_target"]}
        if value["old_target"]
        else None
    )
    previous_release = value["previous_release"]
    original_previous_valid = previous_state == value["previous"] and (
        not previous_release or link_points_to(previous_path, previous_release)
    )
    candidate_previous_valid = (
        candidate_previous is None
        and original_previous_valid
    ) or (
        candidate_previous is not None
        and previous_state == candidate_previous
        and bool(old_release)
        and link_points_to(previous_path, old_release)
    )
    dangling_candidate_previous = (
        phase == "rolling-back"
        and candidate_previous is not None
        and previous_state == candidate_previous
        and bool(old_release)
        and _release_matches(_absolute(old_release["source"]), old_release)
    )
    previous_missing = previous_state == {"kind": "missing", "target": ""}
    if phase in {"prepared", "guarded"}:
        if not original_previous_valid:
            raise RuntimeError("previous release changed before link takeover")
    elif phase in {"linking", "rolling-back"}:
        if not (
            original_previous_valid
            or candidate_previous_valid
            or dangling_candidate_previous
            or previous_missing
        ):
            raise RuntimeError("previous release changed during activation")
    elif phase in {"rolled-back", "rollback-healthy"}:
        if not original_previous_valid:
            raise RuntimeError("previous release link was not restored")
    elif not candidate_previous_valid:
        raise RuntimeError("previous release does not resolve to the rollback release")

    env_metadata = _current_config_metadata(_absolute(args.env))
    service_metadata = _current_config_metadata(_absolute(args.service))

    def original_configuration(field: str) -> dict[str, Any] | None:
        item = value[field]
        if not item["existed"]:
            return None
        return {"sha256": item["sha256"], "mode": item["mode"]}

    def authorized_configuration(
        metadata: dict[str, Any] | None,
        history_field: str,
        *,
        modes: set[int],
    ) -> bool:
        if metadata is None:
            return None in value[history_field]
        return (
            metadata["sha256"] in value[history_field]
            and metadata["mode"] in modes
        )

    original_env = original_configuration("env")
    original_service = original_configuration("service")
    desired_env = value["desired_env"]
    desired_service = value["desired_service"]
    if phase in {"prepared", "guarded", "linking", "stopping", "stopped", "fencing"}:
        configs_valid = (
            env_metadata == original_env and service_metadata == original_service
        )
    elif phase in {"linked", "fenced", "authorizing", "authority", "rolling-back"}:
        configs_valid = authorized_configuration(
            env_metadata,
            "observed_env_sha256",
            modes={0o600},
        ) and authorized_configuration(
            service_metadata,
            "observed_service_sha256",
            modes={0o600, 0o640, 0o644},
        )
    elif phase in {"rolled-back", "rollback-healthy"}:
        configs_valid = (
            env_metadata == original_env and service_metadata == original_service
        )
    else:
        configs_valid = (
            desired_env is not None
            and desired_service is not None
            and _config_path_matches_desired(_absolute(args.env), desired_env)
            and _config_path_matches_desired(
                _absolute(args.service), desired_service
            )
        )
    if not configs_valid:
        raise RuntimeError("activation configuration does not match its phase")


def load(args: argparse.Namespace) -> None:
    root = _absolute(args.root)
    _directory, value = _read_manifest(root)
    _validate_invocation(args, value, allow_missing_candidate=True)
    hub = value["hub"]
    guard = value["guard"]
    candidate_retired = root / "releases" / (
        ".activation-candidate-retired-" + str(value["transaction_id"])
    )
    candidate_parked = root / ".activation-transaction" / "candidate.retired"
    candidate_path = _locate_release(
        value["candidate_release"],
        extras=(candidate_retired, candidate_parked),
    )
    fields = [
        value["transaction_id"],
        value["release_version"],
        value["release_dir"],
        value["phase"],
        str(value.get("rollback_from") or ""),
        value["old_target"],
        str(value["old_release"].get("source", "")),
        value["current"]["kind"],
        value["current"]["target"],
        value["previous"]["kind"],
        value["previous"]["target"],
        "true" if value["env"]["existed"] else "false",
        str(root / ".activation-transaction" / value["env"]["backup"]),
        "true" if value["service"]["existed"] else "false",
        str(root / ".activation-transaction" / value["service"]["backup"]),
        value["service_state"],
        "true" if value["service_enabled"] else "false",
        value["legacy_service_state"],
        "true" if value["legacy_service_enabled"] else "false",
        value["intent"],
        value["client_binding"],
        str(hub.get("kind", "")),
        str(hub.get("data_dir", "")),
        str(hub.get("hub_id", "")),
        str(hub.get("host_identity", "")),
        str(hub.get("operation_id", "")),
        str(hub.get("snapshot", "")),
        str(hub.get("fence_device", "")),
        str(hub.get("fence_inode", "")),
        str(guard.get("id", "")),
        str(guard.get("device", "")),
        str(guard.get("inode", "")),
        "true" if value["authority_pending"] else "false",
        (
            "true"
            if (
                value["rollback_from"]
                if value["phase"]
                in {"rolling-back", "rolled-back", "rollback-healthy"}
                else value["phase"]
            )
            in {
                "linking",
                "linked",
                "stopping",
                "stopped",
                "fencing",
                "fenced",
                "authorizing",
                "authority",
                "candidate-starting",
                "candidate-healthy",
                "committing",
                "committed",
                "rolling-back",
            }
            else "false"
        ),
        str(candidate_path) if candidate_path is not None else "",
        str(value["prior_port"]),
        value["prior_bind_address"],
        "activation-end",
    ]
    for index, field in enumerate(fields):
        if "\n" in field or "\r" in field or "\x00" in field:
            raise RuntimeError(f"activation transaction output field {index} is invalid")
    sys.stdout.write("\n".join(fields) + "\n")


def record(args: argparse.Namespace) -> None:
    root = _absolute(args.root)
    directory, value = _read_manifest(root)
    _validate_invocation(
        args,
        value,
        allow_missing_candidate=args.phase
        in {"rolling-back", "rolled-back", "rollback-healthy"},
    )
    if args.phase not in PHASES:
        raise RuntimeError("activation transaction phase is invalid")
    original_value = json.loads(json.dumps(value))
    previous_phase = value["phase"]
    if args.phase != value["phase"]:
        if args.phase not in TRANSITIONS[value["phase"]]:
            raise RuntimeError("activation transaction phase transition is invalid")
        value["phase"] = args.phase
        if args.phase == "rolling-back":
            value["rollback_from"] = previous_phase
    if args.hub_kind:
        try:
            fence_device = int(args.fence_device or 0)
            fence_inode = int(args.fence_inode or 0)
        except ValueError as exc:
            raise RuntimeError("activation transaction Hub coordinates are invalid") from exc
        data_dir = _absolute(args.hub_data_dir)
        snapshot = _absolute(args.snapshot)
        hub = {
            "kind": args.hub_kind,
            "data_dir": str(data_dir),
            "hub_id": _safe_text(args.hub_id, "Hub id", maximum=240),
            "host_identity": _safe_text(args.host_identity, "host identity", maximum=240),
            "operation_id": _safe_text(args.operation_id, "operation id", maximum=128),
            "snapshot": str(snapshot),
            "fence_device": fence_device or 1,
            "fence_inode": fence_inode or 1,
        }
        _validate_hub_metadata(hub, intent=value["intent"])
        if args.hub_data_dir != str(data_dir) or args.snapshot != str(snapshot):
            raise RuntimeError("activation transaction Hub path is invalid")
        for hub_directory in (data_dir, data_dir / "maintenance-backups"):
            hub_directory_info = hub_directory.lstat()
            if (
                not stat.S_ISDIR(hub_directory_info.st_mode)
                or hub_directory_info.st_uid != os.getuid()
            ):
                raise PermissionError("activation Team Hub directory is unsafe")
        fence_path = data_dir / "maintenance-fence.json"
        fence_info = fence_path.lstat()
        if (
            not stat.S_ISREG(fence_info.st_mode)
            or fence_info.st_uid != os.getuid()
            or fence_info.st_nlink != 1
            or stat.S_IMODE(fence_info.st_mode) != 0o600
        ):
            raise PermissionError("activation Team Hub fence is unsafe")
        if fence_device == 0 and fence_inode == 0:
            fence_device = fence_info.st_dev
            fence_inode = fence_info.st_ino
        elif (
            fence_device != fence_info.st_dev
            or fence_inode != fence_info.st_ino
        ):
            raise RuntimeError("activation Team Hub fence ownership changed")
        hub["fence_device"] = fence_device
        hub["fence_inode"] = fence_inode
        _validate_hub_metadata(hub, intent=value["intent"])
        if value["hub"] and value["hub"] != hub:
            existing_without_inode = {
                key: item
                for key, item in value["hub"].items()
                if key not in {"fence_device", "fence_inode"}
            }
            new_without_inode = {
                key: item
                for key, item in hub.items()
                if key not in {"fence_device", "fence_inode"}
            }
            if not (
                previous_phase == "fencing"
                and args.phase in {"fenced", "rolling-back"}
                and existing_without_inode == new_without_inode
            ):
                raise RuntimeError("activation Team Hub ownership changed")
        value["hub"] = hub
    elif any(
        (
            args.hub_data_dir,
            args.hub_id,
            args.host_identity,
            args.operation_id,
            args.snapshot,
            args.fence_device,
            args.fence_inode,
        )
    ):
        raise RuntimeError("activation transaction Hub metadata has no kind")
    if args.guard_id:
        try:
            guard = {
                "id": _safe_text(args.guard_id, "guard id", maximum=64),
                "device": int(args.guard_device),
                "inode": int(args.guard_inode),
            }
        except ValueError as exc:
            raise RuntimeError("activation transaction guard coordinates are invalid") from exc
        _validate_guard_metadata(guard)
        if value["guard"] and value["guard"] != guard:
            raise RuntimeError("activation Team Hub guard ownership changed")
        value["guard"] = guard
    elif args.guard_device or args.guard_inode:
        raise RuntimeError("activation transaction guard coordinates have no id")
    if args.authority_pending != "unchanged":
        value["authority_pending"] = args.authority_pending == "true"
    _validate_hub_metadata(value["hub"], intent=value["intent"])
    _validate_guard_metadata(value["guard"])
    if previous_phase in {"committed", "rollback-healthy"} and value != original_value:
        raise RuntimeError("terminal activation transaction metadata is immutable")
    _validate_invocation(
        args,
        value,
        allow_missing_candidate=args.phase
        in {"rolling-back", "rolled-back", "rollback-healthy"},
    )
    _replace_private(directory / "manifest.json", _canonical(value))
    if args.hub_kind:
        sys.stdout.write(
            f"{value['hub']['fence_device']}\n{value['hub']['fence_inode']}\n"
        )


def replace_config(args: argparse.Namespace) -> None:
    """Write-ahead and atomically publish one installer-generated config."""

    root = _absolute(args.root)
    directory, value = _read_manifest(root)
    _validate_invocation(args, value)
    if value["phase"] in {
        "committing",
        "committed",
        "rolling-back",
        "rolled-back",
        "rollback-healthy",
    }:
        raise RuntimeError("activation configuration cannot change in this phase")
    source = _absolute(args.source)
    field = "env_path" if args.kind == "env" else "service_path"
    history_field = (
        "observed_env_sha256"
        if args.kind == "env"
        else "observed_service_sha256"
    )
    destination = _absolute(value[field])
    expected_source, secured = _config_staging_paths(
        destination,
        value["transaction_id"],
        args.kind,
    )
    if source != expected_source:
        raise RuntimeError("activation configuration staging path is invalid")
    mode = int(args.mode, 8)
    expected_modes = {0o600} if args.kind == "env" else {0o600, 0o644}
    if mode not in expected_modes:
        raise RuntimeError("activation configuration mode is invalid")
    desired_field = "desired_env" if args.kind == "env" else "desired_service"
    journaled_desired = value[desired_field]
    try:
        source.lstat()
    except FileNotFoundError:
        if journaled_desired is None or journaled_desired.get("mode") != mode:
            raise RuntimeError("activation configuration staging file is missing")
        try:
            secured.lstat()
        except FileNotFoundError:
            if not _config_path_matches_desired(destination, journaled_desired):
                raise RuntimeError(
                    "activation configuration publication is incomplete"
                )
            _fsync_directory(destination.parent)
            return
        _publish_staged_config(
            staged=secured,
            source=source,
            destination=destination,
            desired=journaled_desired,
        )
        return
    try:
        secured.lstat()
    except FileNotFoundError:
        pass
    else:
        if journaled_desired is None or journaled_desired.get("mode") != mode:
            raise RuntimeError("activation configuration publication path exists")
        _publish_staged_config(
            staged=secured,
            source=source,
            destination=destination,
            desired=journaled_desired,
        )
        return

    descriptor, source_identity, payload = _open_config_staging_source(source)
    digest = hashlib.sha256(payload).hexdigest()
    desired = {
        "sha256": digest,
        "mode": mode,
        "source": str(source),
        "device": source_identity.st_dev,
        "inode": source_identity.st_ino,
    }
    value[desired_field] = desired
    if digest not in value[history_field]:
        value[history_field].append(digest)
    try:
        _replace_private(directory / "manifest.json", _canonical(value))
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.link(source, secured, follow_symlinks=False)
        _fsync_staging_directory(source.parent)
        secured_info = secured.lstat()
        source_after = os.fstat(descriptor)
        if (
            (source_identity.st_dev, source_identity.st_ino)
            != (source_after.st_dev, source_after.st_ino)
            or (source_identity.st_dev, source_identity.st_ino)
            != (secured_info.st_dev, secured_info.st_ino)
            or hashlib.sha256(payload).hexdigest() != digest
        ):
            raise RuntimeError("activation configuration staging identity changed")
    finally:
        os.close(descriptor)
    _publish_staged_config(
        staged=secured,
        source=source,
        destination=destination,
        desired=desired,
    )


def _replace_symlink(path: Path, target: str) -> None:
    temporary = path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
    try:
        os.symlink(target, temporary)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _rename_and_fsync(source: Path, destination: Path) -> None:
    """Rename one entry and durably publish both affected directories."""

    os.rename(source, destination)
    _fsync_directory(source.parent)
    if destination.parent != source.parent:
        _fsync_directory(destination.parent)


def activate_files(args: argparse.Namespace) -> None:
    """Idempotently perform the release moves and exact link takeover."""

    root = _absolute(args.root)
    _directory, value = _read_manifest(root)
    _validate_invocation(args, value)
    if value["phase"] != "linking":
        raise RuntimeError("activation transaction is not linking")

    old_release = value["old_release"]
    if old_release and old_release["source"] != old_release["target"]:
        old_source = _absolute(old_release["source"])
        old_target = _absolute(old_release["target"])
        if _release_matches(old_source, old_release):
            try:
                old_target.lstat()
            except FileNotFoundError:
                _rename_and_fsync(old_source, old_target)
            else:
                raise RuntimeError("activation rollback quarantine already exists")
        elif not _release_matches(old_target, old_release):
            raise RuntimeError("activation rollback release is missing")

    candidate = value["candidate_release"]
    candidate_source = _absolute(candidate["source"])
    candidate_target = _absolute(candidate["target"])
    if not _release_matches(candidate_target, candidate):
        if not _release_matches(candidate_source, candidate):
            raise RuntimeError("activation candidate release is missing")
        try:
            candidate_target.lstat()
        except FileNotFoundError:
            _rename_and_fsync(candidate_source, candidate_target)
        else:
            raise RuntimeError("activation candidate destination changed")

    old_target = value["old_target"]
    if old_target:
        _replace_symlink(_absolute(args.previous), old_target)
    _replace_symlink(_absolute(args.current), value["release_dir"])
    if not _release_matches(candidate_target, candidate):
        raise RuntimeError("activation candidate release changed after link takeover")


def _restore_configuration(
    destination: Path,
    directory: Path,
    metadata: dict[str, Any],
) -> None:
    if not metadata["existed"]:
        try:
            info = destination.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise PermissionError("activation configuration destination is unsafe")
        destination.unlink()
        _fsync_directory(destination.parent)
        return
    value = _read_private(
        directory / metadata["backup"],
        maximum=MAX_CONFIG_BYTES,
    )
    temporary = destination.parent / f".{destination.name}.{secrets.token_hex(12)}.tmp"
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, int(metadata["mode"]))
        os.fchmod(descriptor, int(metadata["mode"]))
        written = 0
        while written < len(value):
            written += os.write(descriptor, value[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def restore_files(args: argparse.Namespace) -> None:
    """Restore exact pre-activation links/configuration under the journal."""

    root = _absolute(args.root)
    directory, value = _read_manifest(root)
    _validate_invocation(args, value, allow_missing_candidate=True)
    if value["phase"] != "rolling-back":
        raise RuntimeError("activation transaction is not rolling back")
    current = _absolute(args.current)
    previous = _absolute(args.previous)
    old_release = value["old_release"]
    if old_release and old_release["source"] != old_release["target"]:
        old_source = _absolute(old_release["source"])
        old_target = _absolute(old_release["target"])

        if not _release_matches(old_source, old_release):
            if not _release_matches(old_target, old_release):
                raise RuntimeError("activation rollback release is missing")
            try:
                old_source_info = old_source.lstat()
            except FileNotFoundError:
                pass
            else:
                candidate = value["candidate_release"]
                if stat.S_ISLNK(old_source_info.st_mode) and old_source == current:
                    old_source.unlink()
                    _fsync_directory(old_source.parent)
                else:
                    if not _release_matches(old_source, candidate):
                        raise RuntimeError("activation candidate release changed")
                    retired_candidate = directory / "candidate.retired"
                    if not _release_matches(retired_candidate, candidate):
                        try:
                            retired_candidate.lstat()
                        except FileNotFoundError:
                            _rename_and_fsync(old_source, retired_candidate)
                        else:
                            raise RuntimeError(
                                "activation candidate retirement path exists"
                            )
            _rename_and_fsync(old_target, old_source)
    original_current = value["current"]
    if original_current["kind"] == "symlink":
        _replace_symlink(current, original_current["target"])
    elif original_current["kind"] == "missing":
        try:
            current_info = current.lstat()
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISLNK(current_info.st_mode):
                raise RuntimeError("current release path changed during rollback")
            current.unlink()
            _fsync_directory(current.parent)
    else:
        old_target = _absolute(value["old_target"])
        try:
            current_info = current.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(current_info.st_mode):
                current.unlink()
                _fsync_directory(current.parent)
            elif stat.S_ISDIR(current_info.st_mode):
                # The legacy directory was never moved.
                old_target = current
            else:
                raise RuntimeError("legacy current path changed during rollback")
        if old_target != current:
            _rename_and_fsync(old_target, current)

    original_previous = value["previous"]
    if original_previous["kind"] == "symlink":
        _replace_symlink(previous, original_previous["target"])
    else:
        try:
            previous_info = previous.lstat()
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISLNK(previous_info.st_mode):
                raise RuntimeError("previous release path changed during rollback")
            previous.unlink()
            _fsync_directory(previous.parent)

    _cleanup_config_staging(directory, value)
    _restore_configuration(
        _absolute(value["env_path"]),
        directory,
        value["env"],
    )
    _restore_configuration(
        _absolute(value["service_path"]),
        directory,
        value["service"],
    )


def finish(args: argparse.Namespace) -> None:
    root = _absolute(args.root)
    _validate_root(root)
    _validate_releases_root(root)
    if re.fullmatch(r"activation-[0-9a-f]{24}", args.transaction_id) is None:
        raise RuntimeError("activation transaction id is invalid")
    active = root / ".activation-transaction"
    retired = root / (
        ".activation-transaction-gc-" + str(args.transaction_id)
    )
    try:
        active.lstat()
    except FileNotFoundError:
        try:
            retired.lstat()
        except FileNotFoundError:
            # A prior exact finish may have retired and removed the directory
            # before its caller observed success. The unguessable transaction
            # id is the idempotency key; absence is already the terminal state.
            _fsync_directory(root)
            return
        try:
            directory, value = _read_manifest(root, directory=retired)
        except FileNotFoundError:
            # Retired-directory cleanup can itself be interrupted after the
            # manifest unlink. Only this exact transaction-id directory is
            # eligible for bounded, schema-closed cleanup.
            _remove_private_transaction_directory(retired)
            _fsync_directory(root)
            return
    else:
        # Any missing or malformed control in the live transaction is an
        # unsettled activation, never evidence that finish already succeeded.
        directory, value = _read_manifest(root, directory=active)
    _validate_invocation(
        args,
        value,
        allow_missing_candidate=value["phase"] == "rollback-healthy",
        transaction_directory=directory,
    )
    if value["phase"] not in {"committed", "rollback-healthy"}:
        raise RuntimeError("activation transaction is not terminal")
    if value["phase"] == "rollback-healthy":
        candidate = value["candidate_release"]
        retired_candidate = root / "releases" / (
            ".activation-candidate-retired-" + value["transaction_id"]
        )
        parked_candidate = directory / "candidate.retired"
        candidate_path = _locate_release(
            candidate,
            extras=(retired_candidate, parked_candidate),
        )
        if candidate_path is not None and candidate_path != parked_candidate:
            try:
                parked_candidate.lstat()
            except FileNotFoundError:
                _rename_and_fsync(candidate_path, parked_candidate)
            else:
                raise RuntimeError("activation candidate retirement path exists")
    _cleanup_config_staging(directory, value)
    allowed = {"manifest.json"}
    if value["env"]["existed"]:
        allowed.add("env.backup")
    if value["service"]["existed"]:
        allowed.add("service.backup")
    if value["phase"] == "rollback-healthy" and (directory / "candidate.retired").exists():
        allowed.add("candidate.retired")
    if {entry.name for entry in directory.iterdir()} != allowed:
        raise RuntimeError("activation transaction directory contains unexpected files")
    if directory != retired:
        try:
            retired.lstat()
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("activation transaction retirement path exists")
        os.rename(directory, retired)
        _fsync_directory(root)
    _cleanup_retired_transactions(root)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)

    def layout(command: argparse.ArgumentParser) -> None:
        command.add_argument("--root", required=True)
        command.add_argument("--current", required=True)
        command.add_argument("--previous", required=True)
        command.add_argument("--env", required=True)
        command.add_argument("--service", required=True)

    def owned(command: argparse.ArgumentParser) -> None:
        layout(command)
        command.add_argument("--release-dir", required=True)
        command.add_argument("--release-version", required=True)
        command.add_argument("--transaction-id", required=True)

    begin_parser = subparsers.add_parser("begin")
    layout(begin_parser)
    begin_parser.add_argument("--release-dir", required=True)
    begin_parser.add_argument("--release-version", required=True)
    begin_parser.add_argument("--old-target", required=True)
    begin_parser.add_argument("--old-source", required=True)
    begin_parser.add_argument("--candidate-source", required=True)
    begin_parser.add_argument(
        "--service-state",
        choices=("absent", "stopped", "running"),
        required=True,
    )
    begin_parser.add_argument(
        "--service-enabled",
        choices=("true", "false"),
        required=True,
    )
    begin_parser.add_argument(
        "--legacy-service-state",
        choices=("absent", "stopped", "running"),
        required=True,
    )
    begin_parser.add_argument(
        "--legacy-service-enabled",
        choices=("true", "false"),
        required=True,
    )
    begin_parser.add_argument("--prior-port", type=int, required=True)
    begin_parser.add_argument("--prior-bind-address", required=True)
    begin_parser.add_argument(
        "--intent",
        choices=(
            "ordinary",
            "server-update",
            "host-reactivation",
            "failed-host-repair",
        ),
        required=True,
    )
    begin_parser.add_argument("--client-binding", default="")

    load_parser = subparsers.add_parser("load")
    layout(load_parser)

    record_parser = subparsers.add_parser("record")
    owned(record_parser)
    record_parser.add_argument("--phase", required=True)
    record_parser.add_argument("--hub-kind", default="")
    record_parser.add_argument("--hub-data-dir", default="")
    record_parser.add_argument("--hub-id", default="")
    record_parser.add_argument("--host-identity", default="")
    record_parser.add_argument("--operation-id", default="")
    record_parser.add_argument("--snapshot", default="")
    record_parser.add_argument("--fence-device", default="")
    record_parser.add_argument("--fence-inode", default="")
    record_parser.add_argument("--guard-id", default="")
    record_parser.add_argument("--guard-device", default="")
    record_parser.add_argument("--guard-inode", default="")
    record_parser.add_argument(
        "--authority-pending",
        choices=("true", "false", "unchanged"),
        default="unchanged",
    )

    replace_parser = subparsers.add_parser("replace-config")
    owned(replace_parser)
    replace_parser.add_argument("--kind", choices=("env", "service"), required=True)
    replace_parser.add_argument("--source", required=True)
    replace_parser.add_argument("--mode", required=True)

    activate_parser = subparsers.add_parser("activate-files")
    owned(activate_parser)

    restore_parser = subparsers.add_parser("restore-files")
    owned(restore_parser)

    finish_parser = subparsers.add_parser("finish")
    owned(finish_parser)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    {
        "begin": begin,
        "load": load,
        "record": record,
        "replace-config": replace_config,
        "activate-files": activate_files,
        "restore-files": restore_files,
        "finish": finish,
    }[args.command](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
