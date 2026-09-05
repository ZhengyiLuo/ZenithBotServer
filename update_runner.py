#!/usr/bin/env python3
"""Download, verify, and atomically install an AgentsServer release."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
import signal
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from urllib.error import HTTPError
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


RELEASE_REPOSITORY = "ZhengyiLuo/AgentsServer"
RELEASE_BASE = f"https://github.com/{RELEASE_REPOSITORY}/releases"
RELEASES_API_URL = f"https://api.github.com/repos/{RELEASE_REPOSITORY}/releases?per_page=100"
RELEASES_PAGE_URL = f"https://github.com/{RELEASE_REPOSITORY}/releases"
MAX_METADATA_BYTES = 1_000_000
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
SERVER_IDLE_CHECK_TIMEOUT_SECONDS = 10.0
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
# The standalone installer allows dependency synchronization to run for up to
# 1,200 seconds. Keep this enclosing budget comfortably above that so the
# updater cannot terminate a healthy installer first.
INSTALLER_TIMEOUT_SECONDS = 1_800
INSTALLER_HEARTBEAT_SECONDS = 10.0
# After install.sh starts there is no trustworthy out-of-process proof that it
# has not activated a candidate. Its TERM handler may therefore be stopping the
# candidate, restoring an arbitrarily large verified Team Hub snapshot, and
# restarting the old release. Never put a finite SIGKILL deadline around that
# recovery transaction. Polling keeps the owning update observable while the
# installer's signal-masked rollback reaches a safe terminal state.
INSTALLER_TERMINATION_POLL_SECONDS = 10.0
INSTALLER_LOG_TAIL_BYTES = 64 * 1024
INSTALLER_LOG_TAIL_LINES = 12
INSTALLER_ERROR_MAX_CHARS = 4_000
INSTALLER_ENVIRONMENT_SELECTORS = (
    "AGENTSDOCK_AGENT_TOKEN",
    "AGENTSDOCK_EXPECTED_SERVICE_CGROUP",
    "AGENTSDOCK_MANAGED_UPDATE_ID",
    "AGENTSDOCK_PROVIDER_AUTHORITY_FILE",
    "AGENTSDOCK_PUBLISH_TOKEN",
    "CONDA_PREFIX",
    "PYTHONHOME",
    "PYTHONPATH",
    "UV_CONFIG_FILE",
    "UV_NO_PROJECT",
    "UV_PROJECT",
    "UV_PROJECT_ENVIRONMENT",
    "UV_PYTHON",
    "UV_WORKING_DIR",
    "VIRTUAL_ENV",
    "ZENITHBOT_AGENT_TOKEN",
    "ZENITHDOCK_AGENT_TOKEN",
)
RELEASE_TRACKS = {"stable", "beta"}
RUNNER_OWNED_ACTIVE_PHASES = {
    "starting",
    "checking",
    "downloading",
    "verifying",
    "installing",
    "restarting",
}
SECURE_PEER_HEALTH_REQUIREMENTS = {
    "available": True,
    "state_available": True,
    "state_error_code": None,
    "required": False,
    "version": 1,
    "control_path": "/api/admin/secure-peers/v1/status",
    "proxy_prefix": "/api/team-hub-secure",
}


class ReleaseUnavailableError(RuntimeError):
    """Raised when the repository has not published a signed release yet."""


class UpdateOwnershipLostError(RuntimeError):
    """Raised when a detached updater no longer owns the durable status row."""


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


@contextmanager
def server_update_status_lock(path: Path):
    """Cross-process lock shared by the server and detached updater."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
        ):
            raise PermissionError("server update status lock is unsafe")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _read_status_unlocked(path: Path) -> dict[str, Any]:
    try:
        current = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return current if isinstance(current, dict) else {}


def _update_status_unlocked(path: Path, current: dict[str, Any], **changes: Any) -> dict[str, Any]:
    current = dict(current)
    current.update(changes)
    current["updated_at"] = utc_now()
    atomic_json(path, current)
    return current


def update_status(
    path: Path,
    *,
    expected_update_id: str | None = None,
    **changes: Any,
) -> dict[str, Any]:
    with server_update_status_lock(path):
        current = _read_status_unlocked(path)
        if (
            expected_update_id is not None
            and (
                str(current.get("update_id") or "") != expected_update_id
                or str(current.get("phase") or "")
                not in RUNNER_OWNED_ACTIVE_PHASES
            )
        ):
            raise UpdateOwnershipLostError(
                "detached updater no longer owns the server update status"
            )
        return _update_status_unlocked(path, current, **changes)


def installer_log_tail(log_path: Path) -> str:
    """Read a bounded diagnostic tail without loading a large install log."""
    try:
        with log_path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            truncated = size > INSTALLER_LOG_TAIL_BYTES
            stream.seek(max(0, size - INSTALLER_LOG_TAIL_BYTES))
            content = stream.read(INSTALLER_LOG_TAIL_BYTES)
    except OSError:
        return ""
    lines = content.decode("utf-8", "replace").splitlines()
    if truncated and lines:
        # The bounded read may begin inside a secret whose identifying key was
        # before the cutoff. Never surface that unclassifiable partial line.
        lines = lines[1:]
    safe_lines: list[str] = []
    for line in lines:
        if "AGENTSDOCK_SETUP_RESULT=" in line:
            continue
        line = re.sub(
            r"(?i)(Authorization\s*:\s*Bearer\s+)\S+",
            r"\1[REDACTED]",
            line,
        )
        line = re.sub(
            r"(?i)(\bBearer\s+)\S+",
            r"\1[REDACTED]",
            line,
        )
        line = re.sub(
            r"(?i)([\"']?(?:AGENTSDOCK_AGENT_TOKEN|ZENITHDOCK_AGENT_TOKEN|ZENITHBOT_AGENT_TOKEN|AGENTSDOCK_PUBLISH_TOKEN|AGENTSDOCK_PROVIDER_AUTHORITY_FILE|access_token)[\"']?\s*[=:]\s*).*$",
            r"\1[REDACTED]",
            line,
        )
        safe_lines.append(line)
    tail = "\n".join(safe_lines[-INSTALLER_LOG_TAIL_LINES:])
    return tail[-INSTALLER_ERROR_MAX_CHARS:].strip()


def terminate_installer(
    process: subprocess.Popen[Any],
    *,
    on_wait: Callable[[], None] | None = None,
) -> None:
    """Request installer termination and join its protected recovery.

    install.sh cannot currently prove to this process whether activation has
    begun. Once it has begun, SIGKILL can strand the service stopped or sever a
    Team Hub restore before the old release is restarted. TERM is cooperative:
    the installer kills ordinary stage workers, then masks further termination
    while it completes rollback. Wait without a force-kill deadline.
    """
    if process.poll() is not None:
        return
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except OSError:
            process.terminate()
    else:
        process.terminate()
    while True:
        if on_wait is not None:
            try:
                on_wait()
            except Exception:
                # Losing status ownership must not turn a safe join back into
                # a detached installer or a force-kill boundary.
                pass
        try:
            process.wait(timeout=INSTALLER_TERMINATION_POLL_SECONDS)
            return
        except subprocess.TimeoutExpired:
            continue


def installer_environment() -> dict[str, str]:
    """Return an installer environment detached from the caller's workspace."""
    environment = os.environ.copy()
    for name in INSTALLER_ENVIRONMENT_SELECTORS:
        environment.pop(name, None)
    return environment


def run_installer(
    command: list[str],
    *,
    cwd: Path,
    status_path: Path,
    log_path: Path,
    version: str,
    expected_update_id: str | None = None,
    managed_update_id: str | None = None,
    expected_service_cgroup: str | None = None,
    timeout_seconds: float = INSTALLER_TIMEOUT_SECONDS,
    heartbeat_seconds: float = INSTALLER_HEARTBEAT_SECONDS,
    on_started: Callable[[], None] | None = None,
) -> None:
    """Run the installer with live logging and a durable status heartbeat."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = started + timeout_seconds
    environment = installer_environment()
    if managed_update_id is not None:
        environment["AGENTSDOCK_MANAGED_UPDATE_ID"] = managed_update_id
    if expected_service_cgroup is not None:
        environment["AGENTSDOCK_EXPECTED_SERVICE_CGROUP"] = expected_service_cgroup
    with log_path.open("wb") as log:
        os.chmod(log_path, 0o600)
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=environment,
        )
        if on_started is not None:
            on_started()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                def report_protected_recovery() -> None:
                    elapsed = max(1, int(time.monotonic() - started))
                    update_status(
                        status_path,
                        expected_update_id=expected_update_id,
                        phase="installing",
                        message=(
                            "Installer timeout reached; waiting for its protected "
                            f"rollback to finish ({elapsed}s elapsed)."
                        ),
                        heartbeat_at=utc_now(),
                        elapsed_seconds=elapsed,
                    )

                terminate_installer(process, on_wait=report_protected_recovery)
                log.flush()
                tail = installer_log_tail(log_path)
                detail = f": {tail}" if tail else ""
                raise RuntimeError(
                    f"installer timed out after {timeout_seconds:g} seconds{detail}"
                )
            try:
                returncode = process.wait(timeout=min(heartbeat_seconds, remaining))
                break
            except subprocess.TimeoutExpired:
                elapsed = max(1, int(time.monotonic() - started))
                try:
                    update_status(
                        status_path,
                        expected_update_id=expected_update_id,
                        phase="installing",
                        message=f"Installing AgentsServer {version} ({elapsed}s elapsed).",
                        heartbeat_at=utc_now(),
                        elapsed_seconds=elapsed,
                    )
                except UpdateOwnershipLostError:
                    terminate_installer(process)
                    raise
        log.flush()

    if returncode != 0:
        tail = installer_log_tail(log_path)
        raise RuntimeError(
            f"installer failed ({returncode}): {tail or 'no output; inspect server-update.log'}"
        )


def download_bytes(url: str, limit: int, timeout: float = 30.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "AgentsServer-Updater/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        declared = int(response.headers.get("Content-Length") or 0)
        if declared > limit:
            raise RuntimeError(f"download exceeds the {limit}-byte safety limit")
        content = response.read(limit + 1)
    if len(content) > limit:
        raise RuntimeError(f"download exceeds the {limit}-byte safety limit")
    return content


def server_health_snapshot(
    port: int,
    *,
    token: str | None = None,
    timeout: float = SERVER_IDLE_CHECK_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Read one bounded authenticated AgentsServer health document."""

    headers = {"User-Agent": "AgentsServer-Updater/1"}
    clean_token = str(token or "").strip()
    if clean_token:
        headers["Authorization"] = f"Bearer {clean_token}"
    request = urllib.request.Request(
        f"http://127.0.0.1:{int(port)}/api/health",
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        content = response.read(MAX_METADATA_BYTES + 1)
    if len(content) > MAX_METADATA_BYTES:
        raise RuntimeError("server health response exceeds its safety limit")
    try:
        health = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError("server health response is invalid JSON") from exc
    if not isinstance(health, dict) or health.get("ok") is not True:
        raise RuntimeError("server health response is not healthy")
    return health


def server_work_snapshot(
    port: int,
    *,
    token: str | None = None,
    timeout: float = SERVER_IDLE_CHECK_TIMEOUT_SECONDS,
    require_cgroup_safe: bool = False,
    require_verified_service_cgroup: bool = False,
) -> tuple[int, int]:
    """Read the live workload immediately before invoking the installer."""

    health = server_health_snapshot(port, token=token, timeout=timeout)

    active = health.get("active")
    raw_active_count = health.get("active_count")
    if isinstance(raw_active_count, bool):
        raise RuntimeError("server health response has an invalid active count")
    if isinstance(raw_active_count, int):
        active_count = max(0, raw_active_count)
    elif isinstance(active, list):
        active_count = len(active)
    else:
        raise RuntimeError("server health response is missing its active count")

    raw_blocking_queued_count = health.get("update_blocking_queued_count")
    if raw_blocking_queued_count is not None:
        if (
            isinstance(raw_blocking_queued_count, bool)
            or not isinstance(raw_blocking_queued_count, int)
            or raw_blocking_queued_count < 0
        ):
            raise RuntimeError(
                "server health response has an invalid update-blocking queued count"
            )
        queued_count = raw_blocking_queued_count
    else:
        # Older servers did not distinguish durable preserved messages from
        # volatile queue state. Retain their fail-closed behavior.
        queued = health.get("queued")
        if not isinstance(queued, dict):
            raise RuntimeError("server health response is missing its queued turns")
        queued_count = 0
        for value in queued.values():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RuntimeError("server health response has an invalid queued count")
            queued_count += value
    if require_cgroup_safe and not active_count and not queued_count:
        cgroup = health.get("update_service_cgroup")
        if not isinstance(cgroup, dict):
            raise RuntimeError(
                "server health response is missing its service-cgroup admission proof"
            )
        raw_count = cgroup.get("unknown_descendant_count")
        if (
            cgroup.get("safe") is not True
            or isinstance(raw_count, bool)
            or not isinstance(raw_count, int)
            or raw_count != 0
        ):
            raise RuntimeError(
                "AgentsServer has an unverified or nonempty service cgroup"
            )
        if (
            require_verified_service_cgroup
            and cgroup.get("inspection") != "verified"
        ):
            raise RuntimeError(
                "AgentsServer did not return a verified systemd service-cgroup proof"
            )
    return active_count, queued_count


def assert_post_update_identity(
    port: int,
    *,
    token: str | None,
    expected_server_identity: str,
    expected_team_hub_id: str | None = None,
    expected_team_hub_transport: str | None = None,
    expected_team_hub_url: str | None = None,
    expected_team_hub_direct_ip_url: str | None = None,
) -> None:
    """Fence a replacement by stable server and managed Hub identities."""

    health = server_health_snapshot(port, token=token)
    if str(health.get("server_identity") or "") != expected_server_identity:
        raise RuntimeError("updated AgentsServer stable identity does not match")
    capabilities = health.get("capabilities")
    secure_peer_capability = (
        capabilities.get("secure_peer_v1")
        if isinstance(capabilities, dict)
        else None
    )
    if not isinstance(secure_peer_capability, dict) or any(
        secure_peer_capability.get(name) != value
        for name, value in SECURE_PEER_HEALTH_REQUIREMENTS.items()
    ):
        raise RuntimeError("updated AgentsServer secure-peer state is unavailable")
    if expected_team_hub_id is None:
        if (
            expected_team_hub_transport is not None
            or expected_team_hub_url is not None
            or expected_team_hub_direct_ip_url is not None
        ):
            raise RuntimeError("managed Team Hub transport has no bound Hub identity")
        return
    capability = (
        capabilities.get("team_hub_v1")
        if isinstance(capabilities, dict)
        else None
    )
    expected_capability = {
        "available": True,
        "designated_host": True,
        "version": 1,
        "base_path": "/api/team-hub",
        "hub_id": expected_team_hub_id,
        "host_server_identity": expected_server_identity,
    }
    if not isinstance(capability, dict) or any(
        capability.get(name) != value
        for name, value in expected_capability.items()
    ):
        raise RuntimeError("updated AgentsServer lost or changed its Team Hub identity")
    actual_transport = capability.get("transport")
    actual_hub_url = capability.get("hub_url")
    if expected_team_hub_transport is None:
        if actual_transport not in {None, "loopback"} or actual_hub_url is not None:
            raise RuntimeError("updated AgentsServer changed its legacy Team Hub transport")
    elif (
        actual_transport != expected_team_hub_transport
        or actual_hub_url != expected_team_hub_url
    ):
        raise RuntimeError("updated AgentsServer changed its Team Hub transport")
    if expected_team_hub_direct_ip_url is not None:
        expected_routes = [
            {
                "transport": expected_team_hub_transport or "loopback",
                "hub_url": expected_team_hub_url,
            }
        ]
        if (
            expected_team_hub_direct_ip_url
            and expected_team_hub_transport != "direct_ip"
        ):
            expected_routes.append(
                {
                    "transport": "direct_ip",
                    "hub_url": expected_team_hub_direct_ip_url,
                }
            )
        if capability.get("routes") != expected_routes:
            raise RuntimeError("updated AgentsServer changed its Team Hub routes")


def assert_repaired_team_hub_identity(
    port: int,
    *,
    token: str | None,
    expected_server_identity: str,
    expected_team_hub_transport: str,
    expected_team_hub_url: str | None,
    expected_team_hub_direct_ip_url: str,
) -> str:
    """Verify that an unavailable managed host was repaired in place."""

    health = server_health_snapshot(port, token=token)
    capabilities = health.get("capabilities")
    capability = (
        capabilities.get("team_hub_v1")
        if isinstance(capabilities, dict)
        else None
    )
    required = {
        "available": True,
        "designated_host": True,
        "version": 1,
        "base_path": "/api/team-hub",
        "host_server_identity": expected_server_identity,
        "transport": expected_team_hub_transport,
        "hub_url": expected_team_hub_url,
    }
    if not isinstance(capability, dict) or any(
        capability.get(name) != value for name, value in required.items()
    ):
        raise RuntimeError("updated AgentsServer did not repair its Team Hub host")
    hub_id = capability.get("hub_id")
    if not isinstance(hub_id, str) or re.fullmatch(
        r"[A-Za-z0-9_.:-]{8,240}", hub_id
    ) is None:
        raise RuntimeError("repaired Team Hub identity is invalid")
    expected_routes = [
        {
            "transport": expected_team_hub_transport,
            "hub_url": expected_team_hub_url,
        }
    ]
    if (
        expected_team_hub_direct_ip_url
        and expected_team_hub_transport != "direct_ip"
    ):
        expected_routes.append(
            {
                "transport": "direct_ip",
                "hub_url": expected_team_hub_direct_ip_url,
            }
        )
    if capability.get("routes") != expected_routes:
        raise RuntimeError("repaired Team Hub routes changed")
    return hub_id


def assert_server_idle(
    port: int,
    *,
    token: str | None = None,
    require_verified_service_cgroup: bool = False,
) -> None:
    """Fail closed if work appeared after the update was accepted."""

    try:
        active_count, queued_count = server_work_snapshot(
            port,
            token=token,
            require_cgroup_safe=True,
            require_verified_service_cgroup=require_verified_service_cgroup,
        )
    except Exception as exc:
        raise RuntimeError(
            f"could not verify that AgentsServer is idle before restart: {exc}"
        ) from exc
    if active_count or queued_count:
        parts: list[str] = []
        if active_count:
            parts.append(
                f"{active_count} active agent run{'s' if active_count != 1 else ''}"
            )
        if queued_count:
            parts.append(
                f"{queued_count} queued turn{'s' if queued_count != 1 else ''}"
            )
        raise RuntimeError(
            "server became busy before restart: "
            + " and ".join(parts)
            + "; retry the update after work finishes"
        )


def consume_auth_token_file(path: str | None) -> str:
    """Read and immediately remove the updater's one-time health credential."""

    clean_path = str(path or "").strip()
    if not clean_path:
        return ""
    token_path = Path(clean_path).expanduser().resolve()
    try:
        value = json.loads(token_path.read_text())
        token = str(value.get("token") or "") if isinstance(value, dict) else ""
    finally:
        try:
            token_path.unlink()
        except FileNotFoundError:
            pass
    if not token:
        raise RuntimeError("server update health credential is empty")
    return token


def clear_team_hub_maintenance(args: argparse.Namespace) -> bool:
    """Clear the exact durable update fence without opening the Hub DB."""

    hub_id = str(getattr(args, "expected_team_hub_id", "") or "").strip()
    snapshot = str(getattr(args, "team_hub_snapshot", "") or "").strip()
    data_dir = str(getattr(args, "team_hub_data_dir", "") or "").strip()
    host_identity = str(
        getattr(args, "expected_server_identity", "") or ""
    ).strip()
    operation_id = str(getattr(args, "update_id", "") or "").strip()
    if not any((hub_id, snapshot, data_dir)):
        return False
    if not all((hub_id, snapshot, data_dir, host_identity, operation_id)):
        raise RuntimeError("managed Team Hub maintenance arguments are incomplete")
    from agentsdock_team_hub.store import HubStore

    return HubStore.clear_maintenance_fence_control(
        Path(data_dir),
        expected_hub_id=hub_id,
        expected_host_identity=host_identity,
        expected_reason="server-update",
        expected_operation_id=operation_id,
        expected_snapshot=Path(snapshot),
    )


def team_hub_maintenance_fence_present(args: argparse.Namespace) -> bool:
    """Return whether this exact update still has an on-disk Hub fence."""

    hub_id = str(getattr(args, "expected_team_hub_id", "") or "").strip()
    snapshot = str(getattr(args, "team_hub_snapshot", "") or "").strip()
    data_dir = str(getattr(args, "team_hub_data_dir", "") or "").strip()
    host_identity = str(
        getattr(args, "expected_server_identity", "") or ""
    ).strip()
    operation_id = str(getattr(args, "update_id", "") or "").strip()
    if not any((hub_id, snapshot, data_dir)):
        return False
    if not all((hub_id, snapshot, data_dir, host_identity, operation_id)):
        raise RuntimeError("managed Team Hub maintenance arguments are incomplete")
    from agentsdock_team_hub.store import HubStore

    return HubStore.maintenance_fence_matches_control(
        Path(data_dir),
        expected_hub_id=hub_id,
        expected_host_identity=host_identity,
        expected_reason="server-update",
        expected_operation_id=operation_id,
        expected_snapshot=Path(snapshot),
    )


def version_is_prerelease(version: str) -> bool:
    return "-" in version.split("+", 1)[0]


def release_track(version: str) -> str:
    return "beta" if version_is_prerelease(version) else "stable"


def normalized_release_track(track: str | None) -> str:
    value = str(track or "stable").strip().lower()
    if value not in RELEASE_TRACKS:
        raise ValueError(f"invalid release track: {track}")
    return value


def version_key(version: str) -> tuple[Any, ...]:
    """Return a SemVer-compatible key for a trusted release version."""
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError(f"invalid release version: {version}")
    without_build = version.split("+", 1)[0]
    core, separator, prerelease = without_build.partition("-")
    major, minor, patch = (int(part) for part in core.split("."))
    identifiers: tuple[tuple[int, int | str], ...] = ()
    if separator:
        identifiers = tuple(
            (0, int(part)) if part.isdigit() else (1, part)
            for part in prerelease.split(".")
        )
    return major, minor, patch, 0 if separator else 1, identifiers


def release_manifest_url(version: str) -> str:
    return f"{RELEASE_BASE}/download/v{version}/agents-server-manifest.json"


def release_signature_url(version: str) -> str:
    return f"{RELEASE_BASE}/download/v{version}/agents-server-manifest.sig"


def release_candidates(releases: Any, track: str = "stable") -> list[str]:
    track = normalized_release_track(track)
    if not isinstance(releases, list):
        raise RuntimeError("GitHub releases response must be a JSON array")
    candidates: set[str] = set()
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") is True:
            continue
        tag = str(release.get("tag_name") or "")
        if not tag.startswith("v"):
            continue
        version = tag[1:]
        if not VERSION_PATTERN.fullmatch(version) or release_track(version) != track:
            continue
        declared_prerelease = release.get("prerelease")
        if declared_prerelease is not None and bool(declared_prerelease) != version_is_prerelease(version):
            continue
        candidates.add(version)
    return sorted(candidates, key=version_key, reverse=True)


def stable_release_candidates(releases: Any) -> list[str]:
    """Backward-compatible stable release discovery."""
    return release_candidates(releases, "stable")


def release_versions_from_html(content: bytes, track: str = "stable") -> set[str]:
    track = normalized_release_track(track)
    text = content.decode("utf-8", "replace")
    prefix = f"/{RELEASE_REPOSITORY}/releases/tag/v"
    return {
        match.group(1)
        for match in re.finditer(re.escape(prefix) + r"([^\"'<>/?#]+)", text)
        if VERSION_PATTERN.fullmatch(match.group(1)) and release_track(match.group(1)) == track
    }


def release_candidates_from_public_pages(track: str = "stable", max_pages: int = 20) -> list[str]:
    track = normalized_release_track(track)
    versions: set[str] = set()
    for page in range(1, max_pages + 1):
        url = RELEASES_PAGE_URL if page == 1 else f"{RELEASES_PAGE_URL}?page={page}"
        content = download_bytes(url, MAX_METADATA_BYTES)
        versions.update(release_versions_from_html(content, track))
        next_page = f"{RELEASES_PAGE_URL.removeprefix('https://github.com')}?page={page + 1}"
        if next_page not in content.decode("utf-8", "replace"):
            break
    return sorted(versions, key=version_key, reverse=True)


def stable_release_candidates_from_public_pages(max_pages: int = 20) -> list[str]:
    """Backward-compatible stable release discovery."""
    return release_candidates_from_public_pages("stable", max_pages)


def verify_manifest(
    manifest_bytes: bytes,
    signature: bytes,
    public_key_path: Path,
    *,
    expected_version: str | None = None,
    track: str = "stable",
) -> dict[str, Any]:
    track = normalized_release_track(track)
    key = serialization.load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise RuntimeError("release public key is not an Ed25519 key")
    key.verify(signature, manifest_bytes)
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict):
        raise RuntimeError("release manifest must be a JSON object")
    version = str(manifest.get("version") or "")
    if not VERSION_PATTERN.fullmatch(version):
        raise RuntimeError("release manifest contains an invalid version")
    actual_track = release_track(version)
    if actual_track != track:
        raise RuntimeError(f"release manifest is not on the requested {track} track")
    if expected_version is not None and version != expected_version:
        raise RuntimeError("release manifest version does not match its immutable release tag")
    expected_prerelease = actual_track == "beta"
    if manifest.get("prerelease") not in {None, expected_prerelease}:
        raise RuntimeError("release manifest prerelease metadata is inconsistent")
    if manifest.get("track") not in {None, actual_track}:
        raise RuntimeError("release manifest track metadata is inconsistent")
    archive = manifest.get("archive")
    if not isinstance(archive, dict):
        raise RuntimeError("release manifest is missing archive metadata")
    expected_name = f"agents-server-{version}.tar.gz"
    archive_name = str(archive.get("name") or "")
    archive_url = str(archive.get("url") or "")
    archive_sha = str(archive.get("sha256") or "").lower()
    expected_prefix = f"{RELEASE_BASE}/download/v{version}/"
    if archive_name != expected_name or archive_url != expected_prefix + expected_name:
        raise RuntimeError("release archive location is not trusted")
    if not re.fullmatch(r"[0-9a-f]{64}", archive_sha):
        raise RuntimeError("release archive checksum is invalid")
    return manifest


def check_release(
    public_key_path: Path,
    track: str = "stable",
    *,
    expected_version: str | None = None,
    require_latest: bool = False,
) -> dict[str, Any]:
    track = normalized_release_track(track)
    if expected_version is not None:
        version = str(expected_version).strip()
        if not VERSION_PATTERN.fullmatch(version):
            raise RuntimeError("expected release version is invalid")
        if release_track(version) != track:
            raise RuntimeError(
                f"expected release {version} is not on the requested {track} track"
            )
        if require_latest:
            latest_manifest = check_release(public_key_path, track)
            latest_version = str(latest_manifest.get("version") or "")
            if latest_version != version:
                raise RuntimeError(
                    f"requested {track} release {version} is no longer the latest "
                    f"signed {track} release {latest_version}"
                )
            # The discovery path verified this manifest against the immutable
            # versioned tag URL. Return that exact pinned document instead of
            # fetching a mutable 'latest' alias or selecting a newer release.
            return latest_manifest
        try:
            manifest_bytes = download_bytes(
                release_manifest_url(version),
                MAX_METADATA_BYTES,
            )
            signature = download_bytes(
                release_signature_url(version),
                MAX_METADATA_BYTES,
            )
        except HTTPError as exc:
            if exc.code == 404:
                raise ReleaseUnavailableError(
                    f"Signed {track} AgentsServer release {version} is unavailable."
                ) from exc
            raise
        return verify_manifest(
            manifest_bytes,
            signature,
            public_key_path,
            expected_version=version,
            track=track,
        )

    try:
        releases_bytes = download_bytes(RELEASES_API_URL, MAX_METADATA_BYTES)
    except HTTPError as exc:
        if exc.code == 404:
            raise ReleaseUnavailableError("No signed AgentsServer release has been published yet.") from exc
        if exc.code not in {403, 429}:
            raise
        candidates = release_candidates_from_public_pages(track)
    else:
        try:
            releases = json.loads(releases_bytes)
        except json.JSONDecodeError as exc:
            raise RuntimeError("GitHub releases response is invalid JSON") from exc
        candidates = release_candidates(releases, track)
    if not candidates:
        raise ReleaseUnavailableError(f"No signed {track} AgentsServer release is available.")

    for version in candidates:
        try:
            manifest_bytes = download_bytes(release_manifest_url(version), MAX_METADATA_BYTES)
            signature = download_bytes(release_signature_url(version), MAX_METADATA_BYTES)
        except HTTPError as exc:
            if exc.code == 404:
                continue
            raise
        return verify_manifest(
            manifest_bytes,
            signature,
            public_key_path,
            expected_version=version,
            track=track,
        )
    raise ReleaseUnavailableError(f"No signed {track} AgentsServer release is available.")


def release_transition_allowed(current: str, target: str, track: str = "stable") -> bool:
    """Allow forward updates and an explicit prerelease-to-stable channel exit."""
    track = normalized_release_track(track)
    if release_track(target) != track:
        return False
    if version_key(target) > version_key(current):
        return True
    return (
        version_key(target) < version_key(current)
        and track == "stable"
        and version_is_prerelease(current)
        and not version_is_prerelease(target)
    )


def safe_extract(archive_path: Path, destination: Path) -> Path:
    destination = destination.resolve()
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            target = (destination / member.name).resolve()
            if destination != target and destination not in target.parents:
                raise RuntimeError("release archive contains an unsafe path")
            if member.issym() or member.islnk():
                raise RuntimeError("release archive must not contain links")
        archive.extractall(destination, members=members, filter="data")
    roots = [entry for entry in destination.iterdir() if entry.is_dir()]
    if len(roots) != 1 or not (roots[0] / "install.sh").is_file():
        raise RuntimeError("release archive has an invalid layout")
    return roots[0]


def run_update(args: argparse.Namespace) -> None:
    status_path = Path(args.status_file).expanduser().resolve()
    public_key = Path(args.public_key).expanduser().resolve()
    track = normalized_release_track(getattr(args, "track", "stable"))
    auth_token = consume_auth_token_file(getattr(args, "auth_token_file", None))
    expected_server_identity = str(
        getattr(args, "expected_server_identity", "") or ""
    ).strip()
    if not expected_server_identity:
        raise RuntimeError("managed update is missing the stable server identity")
    update_id = str(getattr(args, "update_id", "") or "").strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", update_id) is None:
        raise RuntimeError("managed update is missing a valid update ID")
    expected_service_cgroup = str(
        getattr(args, "expected_service_cgroup", "") or ""
    ).strip() or None
    if expected_service_cgroup is not None and re.fullmatch(
        r"/(?:[A-Za-z0-9_.@:-]+/)*[A-Za-z0-9_.@:-]+",
        expected_service_cgroup,
    ) is None:
        raise RuntimeError("managed update has an invalid service cgroup")
    repair_failed_team_hub_host = bool(
        getattr(args, "repair_failed_team_hub_host", False)
    )
    expected_team_hub_id = str(
        getattr(args, "expected_team_hub_id", "") or ""
    ).strip() or None
    raw_team_hub_transport = getattr(args, "expected_team_hub_transport", None)
    expected_team_hub_transport = (
        str(raw_team_hub_transport).strip()
        if raw_team_hub_transport is not None
        else None
    )
    raw_team_hub_url = getattr(args, "expected_team_hub_url", None)
    expected_team_hub_url = (
        str(raw_team_hub_url).strip()
        if raw_team_hub_url is not None
        else None
    )
    raw_team_hub_direct_ip_url = getattr(
        args, "expected_team_hub_direct_ip_url", None
    )
    expected_team_hub_direct_ip_url = (
        str(raw_team_hub_direct_ip_url).strip()
        if raw_team_hub_direct_ip_url is not None
        else None
    )
    team_hub_snapshot = str(
        getattr(args, "team_hub_snapshot", "") or ""
    ).strip() or None
    team_hub_data_dir = str(
        getattr(args, "team_hub_data_dir", "") or ""
    ).strip() or None
    if any((expected_team_hub_id, team_hub_snapshot, team_hub_data_dir)) and not all(
        (expected_team_hub_id, team_hub_snapshot, team_hub_data_dir)
    ):
        raise RuntimeError("managed Team Hub rollback arguments must be complete")
    if repair_failed_team_hub_host and any(
        (expected_team_hub_id, team_hub_snapshot, team_hub_data_dir)
    ):
        raise RuntimeError(
            "failed Team Hub repair cannot reuse live-host rollback arguments"
        )
    if expected_team_hub_id is None and not repair_failed_team_hub_host:
        if (
            expected_team_hub_transport is not None
            or expected_team_hub_url is not None
            or expected_team_hub_direct_ip_url is not None
        ):
            raise RuntimeError("managed Team Hub transport arguments require a Hub identity")
    if repair_failed_team_hub_host and (
        raw_team_hub_transport is None
        or raw_team_hub_url is None
        or raw_team_hub_direct_ip_url is None
    ):
        raise RuntimeError(
            "failed Team Hub repair requires exact transport continuity arguments"
        )
    if (
        expected_team_hub_id is not None or repair_failed_team_hub_host
    ) and expected_team_hub_transport is None:
        if raw_team_hub_url is not None:
            raise RuntimeError("legacy loopback Team Hub cannot have a remote URL")
    elif expected_team_hub_id is not None or repair_failed_team_hub_host:
        if expected_team_hub_transport == "loopback":
            if raw_team_hub_url is None or expected_team_hub_url != "":
                raise RuntimeError("loopback Team Hub cannot have a remote URL")
            expected_team_hub_url = None
        elif expected_team_hub_transport in {"tailscale_serve", "direct_ip"}:
            if expected_team_hub_url is None:
                raise RuntimeError("remote Team Hub transport requires its exact URL")
            try:
                from team_hub_host import (  # Imported only for the managed-Hub path.
                    TEAM_HUB_MODE_HOST,
                    configured_team_hub_endpoint,
                )

                resolved_transport, resolved_url, _host, config_error = (
                    configured_team_hub_endpoint(
                        TEAM_HUB_MODE_HOST,
                        expected_team_hub_url,
                        expected_team_hub_transport,
                        args.port,
                    )
                )
            except Exception as exc:
                raise RuntimeError("could not validate the expected Team Hub URL") from exc
            if (
                config_error is not None
                or resolved_transport != expected_team_hub_transport
                or resolved_url != expected_team_hub_url
            ):
                raise RuntimeError("expected Team Hub URL is invalid")
        else:
            raise RuntimeError("managed Team Hub transport is invalid")
    if expected_team_hub_direct_ip_url is not None:
        if expected_team_hub_id is None and not repair_failed_team_hub_host:
            raise RuntimeError("managed Team Hub direct-IP route requires a Hub identity")
        if expected_team_hub_direct_ip_url:
            try:
                from team_hub_host import (
                    TEAM_HUB_MODE_HOST,
                    configured_team_hub_endpoint,
                )

                direct_transport, direct_url, _host, direct_error = (
                    configured_team_hub_endpoint(
                        TEAM_HUB_MODE_HOST,
                        expected_team_hub_direct_ip_url,
                        "direct_ip",
                        args.port,
                    )
                )
            except Exception as exc:
                raise RuntimeError(
                    "could not validate the expected Team Hub direct-IP route"
                ) from exc
            if (
                direct_error is not None
                or direct_transport != "direct_ip"
                or direct_url != expected_team_hub_direct_ip_url
            ):
                raise RuntimeError("expected Team Hub direct-IP route is invalid")
        if (
            expected_team_hub_transport == "direct_ip"
            and expected_team_hub_direct_ip_url != expected_team_hub_url
        ):
            raise RuntimeError("primary direct-IP Team Hub route changed")
    if repair_failed_team_hub_host:
        with server_update_status_lock(status_path):
            admitted = _read_status_unlocked(status_path)
        expected_repair_routes = [
            {
                "transport": expected_team_hub_transport,
                "hub_url": expected_team_hub_url,
            }
        ]
        if (
            expected_team_hub_direct_ip_url
            and expected_team_hub_transport != "direct_ip"
        ):
            expected_repair_routes.append(
                {
                    "transport": "direct_ip",
                    "hub_url": expected_team_hub_direct_ip_url,
                }
            )
        expected_status = {
            "update_id": update_id,
            "phase": "starting",
            "team_hub_repair_mode": "failed_start",
            "team_hub_host_server_identity": expected_server_identity,
            "team_hub_transport": expected_team_hub_transport,
            "team_hub_url": expected_team_hub_url,
            "team_hub_direct_ip_url": expected_team_hub_direct_ip_url,
            "team_hub_routes": expected_repair_routes,
        }
        if any(admitted.get(name) != value for name, value in expected_status.items()):
            raise RuntimeError(
                "failed Team Hub repair is not owned by the exact admitted update"
            )
    update_status(
        status_path,
        expected_update_id=update_id,
        phase="checking",
        track=track,
        runner_pid=os.getpid(),
        heartbeat_at=utc_now(),
        message=f"Checking the signed {track} release manifest.",
    )
    expected_version = (
        str(getattr(args, "expected_version", "") or "").strip() or None
    )
    current_version = str(
        getattr(args, "current_version", "") or ""
    ).strip()
    require_latest = (
        track == "stable"
        and bool(current_version)
        and version_is_prerelease(current_version)
    )
    manifest = check_release(
        public_key,
        track,
        expected_version=expected_version,
        require_latest=require_latest,
    )
    version = str(manifest["version"])
    if expected_version and version != expected_version:
        raise RuntimeError(
            f"resolved signed release is {version}, not {expected_version}"
        )
    if current_version and not release_transition_allowed(current_version, version, track):
        raise RuntimeError(
            f"resolved release {version} is not newer than installed version {current_version}; "
            "managed updates only permit forward updates or an explicit beta-to-stable channel switch"
        )

    with tempfile.TemporaryDirectory(prefix="agents-server-update-") as temporary:
        root = Path(temporary)
        archive_path = root / str(manifest["archive"]["name"])
        update_status(
            status_path,
            expected_update_id=update_id,
            phase="downloading",
            track=track,
            target_version=version,
            message=f"Downloading AgentsServer {version}.",
        )
        archive_bytes = download_bytes(str(manifest["archive"]["url"]), MAX_ARCHIVE_BYTES, timeout=120.0)
        digest = hashlib.sha256(archive_bytes).hexdigest()
        if digest != manifest["archive"]["sha256"]:
            raise RuntimeError("release archive checksum does not match the signed manifest")
        archive_path.write_bytes(archive_bytes)

        update_status(
            status_path,
            expected_update_id=update_id,
            phase="verifying",
            message="Signature and archive checksum verified.",
        )
        source = safe_extract(archive_path, root / "extracted")
        install = source / "install.sh"
        install.chmod(0o755)
        command = [
            str(install),
            "--non-interactive",
            "--release-version", version,
            "--port", str(args.port),
            "--bind", args.bind,
            "--expected-server-identity", expected_server_identity,
        ]
        if expected_team_hub_id is not None:
            command.extend(
                [
                    "--expected-team-hub-id", expected_team_hub_id,
                    "--team-hub-snapshot", str(team_hub_snapshot),
                    "--team-hub-data-dir", str(team_hub_data_dir),
                    "--team-hub-operation-id", update_id,
                ]
            )
            if expected_team_hub_transport is not None:
                command.extend(
                    [
                        "--expected-team-hub-transport",
                        expected_team_hub_transport,
                        "--expected-team-hub-url",
                        expected_team_hub_url or "",
                    ]
                )
            if expected_team_hub_direct_ip_url is not None:
                command.extend(
                    [
                        "--expected-team-hub-direct-ip-url",
                        expected_team_hub_direct_ip_url,
                    ]
                )
        elif repair_failed_team_hub_host:
            command.extend(
                [
                    "--repair-failed-team-hub-host",
                    "--managed-update-id",
                    update_id,
                    "--expected-team-hub-transport",
                    expected_team_hub_transport or "",
                    "--expected-team-hub-url",
                    expected_team_hub_url or "",
                    "--expected-team-hub-direct-ip-url",
                    expected_team_hub_direct_ip_url or "",
                ]
            )
        assert_server_idle(
            args.port,
            token=auth_token,
            require_verified_service_cgroup=expected_service_cgroup is not None,
        )
        update_status(
            status_path,
            expected_update_id=update_id,
            phase="installing",
            message=f"Installing AgentsServer {version} with rollback protection.",
        )
        log_path = status_path.with_name("server-update.log")
        run_installer(
            command,
            cwd=source,
            status_path=status_path,
            log_path=log_path,
            version=version,
            expected_update_id=update_id,
            managed_update_id=(
                update_id
                if expected_service_cgroup is not None
                or repair_failed_team_hub_host
                else None
            ),
            expected_service_cgroup=expected_service_cgroup,
        )
        identity_arguments: dict[str, Any] = {
            "token": auth_token,
            "expected_server_identity": expected_server_identity,
            "expected_team_hub_id": expected_team_hub_id,
        }
        if expected_team_hub_transport is not None and not repair_failed_team_hub_host:
            identity_arguments["expected_team_hub_transport"] = (
                expected_team_hub_transport
            )
        if expected_team_hub_url is not None and not repair_failed_team_hub_host:
            identity_arguments["expected_team_hub_url"] = expected_team_hub_url
        if (
            expected_team_hub_direct_ip_url is not None
            and not repair_failed_team_hub_host
        ):
            identity_arguments["expected_team_hub_direct_ip_url"] = (
                expected_team_hub_direct_ip_url
            )
        assert_post_update_identity(args.port, **identity_arguments)
        if repair_failed_team_hub_host:
            assert_repaired_team_hub_identity(
                args.port,
                token=auth_token,
                expected_server_identity=expected_server_identity,
                expected_team_hub_transport=expected_team_hub_transport or "",
                expected_team_hub_url=expected_team_hub_url,
                expected_team_hub_direct_ip_url=(
                    expected_team_hub_direct_ip_url or ""
                ),
            )
        # install.sh owns the success clear while it can still stop the
        # candidate, restore the verified snapshot, and restart the old
        # release. The runner clears only failures before install starts.

    update_status(
        status_path,
        expected_update_id=update_id,
        phase="complete",
        update_available=False,
        message=f"AgentsServer {version} is installed and healthy.",
        track=track,
        installed_version=version,
        heartbeat_at=None,
        elapsed_seconds=None,
        runner_pid=None,
        error_code=None,
        error_action=None,
        retryable=None,
        finished_at=utc_now(),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status-file", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--expected-version")
    parser.add_argument("--current-version")
    parser.add_argument("--track", choices=sorted(RELEASE_TRACKS), default="stable")
    parser.add_argument("--auth-token-file")
    parser.add_argument("--expected-server-identity", required=True)
    parser.add_argument("--update-id", required=True)
    parser.add_argument("--expected-service-cgroup")
    parser.add_argument("--expected-team-hub-id")
    parser.add_argument("--expected-team-hub-transport")
    parser.add_argument("--expected-team-hub-url")
    parser.add_argument("--expected-team-hub-direct-ip-url")
    parser.add_argument("--team-hub-snapshot")
    parser.add_argument("--team-hub-data-dir")
    parser.add_argument("--repair-failed-team-hub-host", action="store_true")
    args = parser.parse_args()
    try:
        run_update(args)
        return 0
    except Exception as exc:
        status_path = Path(args.status_file).expanduser().resolve()
        update_id = str(getattr(args, "update_id", "") or "").strip()
        try:
            with server_update_status_lock(status_path):
                current = _read_status_unlocked(status_path)
                if (
                    str(current.get("update_id") or "") != update_id
                    or str(current.get("phase") or "")
                    not in RUNNER_OWNED_ACTIVE_PHASES
                ):
                    return 1
                phase = str(current.get("phase") or "")
                if phase in {
                    "starting",
                    "checking",
                    "downloading",
                    "verifying",
                }:
                    # Keep the owning active status in place until its exact
                    # Hub fence is cleared. A clear failure therefore remains
                    # fail-closed instead of publishing a false terminal row.
                    clear_team_hub_maintenance(args)
                elif phase in {"installing", "restarting"} and \
                        team_hub_maintenance_fence_present(args):
                    # Once install.sh starts, only its verified rollback or
                    # successful candidate handoff may clear the fence. Keep
                    # the active row if recovery was not proven complete.
                    return 1
                _update_status_unlocked(
                    status_path,
                    current,
                    phase="failed",
                    message=str(exc),
                    heartbeat_at=None,
                    runner_pid=None,
                    finished_at=utc_now(),
                )
        except (UpdateOwnershipLostError, RuntimeError, OSError):
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
