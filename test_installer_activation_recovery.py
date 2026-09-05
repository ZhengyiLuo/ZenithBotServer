from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parent
INSTALLER = ROOT / "install.sh"


def _between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


class InstallerActivationRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        cls.installer_source = source
        cls.layout_validation_function = _between(
            source,
            "validate_install_layout_paths() {",
            "backup_runtime_configuration() {",
        )
        cls.lock_functions = (
            _between(
                source,
                "install_lock_python() {",
                "team_hub_transaction_requires_recovery() {",
            )
            + _between(
                source,
                "acquire_install_lock() {",
                "validate_exclusive_install_state() {",
            )
        )
        cls.rollback_function = _between(
            source,
            "restore_previous_release_transaction() {",
            "restore_previous_release() {",
        )
        cls.previous_health_function = _between(
            source,
            "wait_for_previous_release_health() {",
            "ensure_committed_candidate_service() {",
        )
        cls.restart_service_function = _between(
            source,
            "restart_service() {",
            "restore_previous_release_transaction() {",
        )
        cls.launchd_state_functions = _between(
            source,
            "launchd_target_snapshot() {",
            "wait_for_launch_agent_removal() {",
        )
        cls.restore_service_state_function = _between(
            source,
            "restore_prior_service_state() {",
            "restore_team_hub_snapshot() {",
        )
        cls.complete_commit_function = _between(
            source,
            "complete_activation_commit() {",
            "load_pending_activation_transaction() {",
        )
        cls.load_activation_function = _between(
            source,
            "load_pending_activation_transaction() {",
            "recover_pending_activation_transaction() {",
        )
        cls.recover_activation_function = _between(
            source,
            "recover_pending_activation_transaction() {",
            'if [[ "$ACTIVATION_TRANSACTION_RESUMED" == "true" ]]; then',
        )
        cls.network_preservation_block = _between(
            source,
            'if [[ "$PORT_EXPLICIT" != "true" ]]; then',
            'EXISTING_ENV_TEAM_HUB_MODE_SET="false"',
        )

    def _lock_prefix(self, root: Path) -> str:
        runtime = root / "runtime"
        python = runtime / ".venv" / "bin" / "python"
        python.parent.mkdir(parents=True, exist_ok=True)
        if not python.exists():
            python.symlink_to(sys.executable)
        return f"""
set -u
INSTALL_ROOT={root!s}
RELEASES_ROOT={root / 'releases'!s}
INSTALL_LOCK_DIR={root / '.install-lock'!s}
INSTALL_LOCK_HELD=false
INSTALL_LOCK_DEVICE=
INSTALL_LOCK_INODE=
STAGE_DIR={runtime!s}
RELEASE_DIR={root / 'release'!s}
CURRENT_LINK={root / 'current'!s}
ACTIVATION_TRANSACTION_DIR={root / '.activation-transaction'!s}
{self.layout_validation_function}
{self.lock_functions}
"""

    def test_empty_install_lock_is_atomically_replaced_and_released(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / ".install-lock"
            lock.mkdir(mode=0o700)
            result = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    self._lock_prefix(root)
                    + "acquire_install_lock\n"
                    + 'test "$(cat "$INSTALL_LOCK_DIR/pid")" = "$$"\n'
                    + "test ! -L \"$INSTALL_LOCK_DIR\"\n"
                    + "release_install_lock\n"
                    + "test ! -e \"$INSTALL_LOCK_DIR\"\n",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(lock.exists())

    def test_symlinked_install_or_releases_root_aborts_without_mutation(self) -> None:
        for kind in ("install", "releases"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                home = root / "home"
                fake_bin = root / "bin"
                victim = root / "victim"
                home.mkdir()
                fake_bin.mkdir()
                victim.mkdir()
                sentinel = victim / "sentinel"
                sentinel.write_text("preserve\n", encoding="ascii")
                for name, source in {
                    "uname": "#!/bin/sh\necho Linux\n",
                    "curl": "#!/bin/sh\nexit 0\n",
                    "systemctl": "#!/bin/sh\nexit 0\n",
                    "tmux": "#!/bin/sh\nexit 0\n",
                    "uv": "#!/bin/sh\nexit 0\n",
                }.items():
                    executable = fake_bin / name
                    executable.write_text(source, encoding="ascii")
                    executable.chmod(0o755)
                install_root = root / "install"
                if kind == "install":
                    install_root.symlink_to(victim, target_is_directory=True)
                else:
                    install_root.mkdir()
                    (install_root / "releases").symlink_to(
                        victim,
                        target_is_directory=True,
                    )
                before = sorted(
                    (entry.relative_to(victim), entry.read_bytes())
                    for entry in victim.iterdir()
                    if entry.is_file()
                )
                environment = {
                    **os.environ,
                    "HOME": str(home),
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "AGENTS_SERVER_INSTALL_DIR": str(install_root),
                    "AGENTS_SERVER_CONFIG_DIR": str(root / "config"),
                    "AGENTSDOCK_STATE_DIR": str(root / "state"),
                }
                result = subprocess.run(
                    ["/bin/bash", str(INSTALLER), "--non-interactive"],
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(
                    "install layout contains an unsafe directory" in result.stderr
                    or "Refusing symbolic-link managed root" in result.stderr,
                    result.stderr,
                )
                self.assertEqual(
                    sorted(
                        (entry.relative_to(victim), entry.read_bytes())
                        for entry in victim.iterdir()
                        if entry.is_file()
                    ),
                    before,
                )
                self.assertFalse((root / "config").exists())
                self.assertFalse((root / "state").exists())

    def test_default_state_physical_alias_still_rejects_unsafe_legacy_source(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir()
            legacy = home / ".zenithbot-agent"
            legacy.write_text("must-not-move\n", encoding="ascii")
            environment = os.environ.copy()
            for name in (
                "AGENTSDOCK_STATE_DIR",
                "AGENTS_SERVER_STATE_DIR",
                "ZENITHBOT_AGENT_DIR",
            ):
                environment.pop(name, None)
            environment.update(
                {
                    "HOME": str(home),
                    "AGENTS_SERVER_INSTALL_DIR": str(root / "install"),
                    "AGENTS_SERVER_CONFIG_DIR": str(root / "config"),
                }
            )
            result = subprocess.run(
                ["/bin/bash", str(INSTALLER), "--non-interactive"],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("not a safe owned directory", result.stderr)
            self.assertEqual(legacy.read_text(encoding="ascii"), "must-not-move\n")
            self.assertFalse((home / ".agentsdock").exists())

    def test_stale_reaper_pinned_before_replacement_never_removes_new_owner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / ".install-lock"
            lock.mkdir(mode=0o700)
            owner = lock / "pid"
            owner.write_text("99999999\n", encoding="ascii")
            owner.chmod(0o600)
            paused = root / "paused"
            resume = root / "resume"
            stop = root / "stop"
            hook = root / "hook"
            hook.mkdir()
            (hook / "sitecustomize.py").write_text(
                """
import os
from pathlib import Path
import time

_real_kill = os.kill

def _controlled_kill(pid, signal):
    try:
        return _real_kill(pid, signal)
    except ProcessLookupError:
        paused = os.environ.get("LOCK_TEST_PAUSED")
        resume = os.environ.get("LOCK_TEST_RESUME")
        if paused and resume and pid == 99999999:
            Path(paused).touch()
            deadline = time.monotonic() + 5
            while not Path(resume).exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("lock test interleaving timed out")
                time.sleep(0.01)
        raise

os.kill = _controlled_kill
""",
                encoding="utf-8",
            )
            first_result = root / "result-a"
            second_result = root / "result-b"
            contender = """
if acquire_install_lock; then
  printf 'acquired %s\n' "$$" > "$RESULT"
  while [[ ! -e "$STOP" ]]; do sleep 0.01; done
  release_install_lock
  exit 0
fi
printf 'failed %s\n' "$$" > "$RESULT"
exit 42
"""
            first_environment = os.environ.copy()
            first_environment.update(
                {
                    "LOCK_TEST_PAUSED": str(paused),
                    "LOCK_TEST_RESUME": str(resume),
                    "PYTHONPATH": str(hook),
                    "RESULT": str(first_result),
                    "STOP": str(stop),
                }
            )
            first = subprocess.Popen(
                ["/bin/bash", "-c", self._lock_prefix(root) + contender],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=first_environment,
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not paused.exists():
                time.sleep(0.01)
            self.assertTrue(paused.exists(), "first reaper did not pin the stale lock")
            second_environment = os.environ.copy()
            second_environment.update(
                {"RESULT": str(second_result), "STOP": str(stop)}
            )
            second = subprocess.Popen(
                ["/bin/bash", "-c", self._lock_prefix(root) + contender],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=second_environment,
            )
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not second_result.exists():
                    time.sleep(0.01)
                self.assertTrue(second_result.exists())
                second_state = second_result.read_text(encoding="ascii").strip()
                self.assertTrue(second_state.startswith("acquired "), second_state)
                live_pid = second_state.split()[1]
                self.assertEqual(owner.read_text(encoding="ascii").strip(), live_pid)
                self.assertTrue(lock.is_dir())
                resume.touch()
                first_stdout, first_stderr = first.communicate(timeout=5)
                self.assertEqual(first.returncode, 42, first_stdout + first_stderr)
                self.assertEqual(
                    first_result.read_text(encoding="ascii").strip().split()[0],
                    "failed",
                )
                self.assertEqual(owner.read_text(encoding="ascii").strip(), live_pid)
            finally:
                stop.touch()
                if first.poll() is None:
                    resume.touch()
                    first.communicate(timeout=5)
            second_stdout, second_stderr = second.communicate(timeout=5)
            self.assertEqual(second.returncode, 0, second_stdout + second_stderr)
            self.assertFalse(lock.exists())

    def _rollback_script(self, body: str) -> str:
        return f"""
set -u
ACTIVATION_TRANSACTION_ID=activation-0123456789abcdef01234567
ACTIVATION_TRANSACTION_PHASE=rolling-back
ACTIVATION_ROLLBACK_FROM=candidate-starting
ACTIVATION_HUB_KIND=server-update
CANDIDATE_RUNTIME_ROOT=/candidate
STAGE_DIR=/stage
ACTIVATION_TRANSACTION_DIR=/transaction
TEAM_HUB_COLD_GUARD_PENDING=false
TEAM_HUB_REACTIVATION_FENCE_PENDING=false
TEAM_HUB_OPERATION_PENDING=true
TEAM_HUB_OPERATION_FINALIZED=false
TEAM_HUB_REACTIVATION_FINALIZED=false
TEAM_HUB_STARTUP_AUTHORITY_PENDING=true
TEAM_HUB_REACTIVATION_REQUESTED=false
TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED=false
EXPECTED_TEAM_HUB_CLIENT_BINDING=binding
OLD_TARGET=/old
PRIOR_SERVICE_STATE=running
FAIL_ROLLED_BACK_RECORD=false
FAIL_ACK=false
LOG=$(mktemp)
RECEIPT=$(mktemp)
SUPPRESSION=$(mktemp)
log() {{ printf '%s\n' "$1" >> "$LOG"; }}
finish_activation_transaction() {{ log finish; ACTIVATION_TRANSACTION_ID=; }}
prepare_team_hub_reactivation() {{ return 1; }}
record_activation_phase() {{
  log "record:$1"
  if [[ "$1" = rolled-back ]]; then
    pre_service_phase=false
    case "$ACTIVATION_ROLLBACK_FROM" in
      linking|linked|stopping|stopped|fencing|fenced|authorizing|authority)
        pre_service_phase=true
        ;;
    esac
    if [[ "$PRIOR_SERVICE_STATE" != absent \
      || "$pre_service_phase" != true ]]; then
      test -e "$SUPPRESSION" || return 91
    fi
    [[ -z "$ACTIVATION_HUB_KIND" ]] || test -e "$RECEIPT" || return 91
    [[ "$FAIL_ROLLED_BACK_RECORD" != true ]] || return 92
  fi
  ACTIVATION_TRANSACTION_PHASE="$1"
}}
suppress_service_autostart_for_rollback() {{ log suppress; : > "$SUPPRESSION"; }}
stop_service() {{ log stop; }}
restore_team_hub_snapshot() {{ log restore-hub; : > "$RECEIPT"; }}
clear_team_hub_startup_authority() {{ log clear-authority; }}
restore_activation_files() {{ log restore-files; }}
clear_team_hub_cold_guard() {{ return 0; }}
acknowledge_team_hub_restore_receipt() {{
  [[ -n "$ACTIVATION_HUB_KIND" ]] || return 0
  log acknowledge
  [[ "$FAIL_ACK" != true ]] || return 93
  rm -f "$RECEIPT"
}}
restore_prior_service_state() {{
  log restore-service
  [[ "$ACTIVATION_TRANSACTION_PHASE" = rolled-back ]]
  [[ ! -e "$RECEIPT" ]]
  rm -f "$SUPPRESSION"
}}
wait_for_previous_release_health() {{ log health; [[ ! -e "$SUPPRESSION" ]]; }}
wait_for_health() {{ return 99; }}
{self.rollback_function}
{body}
"""

    def test_rollback_receipt_is_consumed_only_after_durable_file_rollback(self) -> None:
        body = """
restore_previous_release_transaction
expected='suppress
stop
restore-hub
restore-files
record:rolled-back
clear-authority
acknowledge
restore-service
health
record:rollback-healthy
finish'
test "$(cat "$LOG")" = "$expected"
test ! -e "$RECEIPT"
test ! -e "$SUPPRESSION"
"""
        result = subprocess.run(
            ["/bin/bash", "-c", self._rollback_script(body)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_restore_files_cut_keeps_service_suppressed_and_receipt_pending(self) -> None:
        body = """
FAIL_ROLLED_BACK_RECORD=true
restore_previous_release_transaction && exit 80
test "$ACTIVATION_TRANSACTION_PHASE" = rolling-back
test -e "$RECEIPT"
test -e "$SUPPRESSION"
test "$(grep -c '^restore-service$' "$LOG" || true)" = 0
FAIL_ROLLED_BACK_RECORD=false
restore_previous_release_transaction
test "$(grep -c '^restore-hub$' "$LOG")" = 2
test "$(grep -c '^restore-files$' "$LOG")" = 2
test ! -e "$RECEIPT"
test ! -e "$SUPPRESSION"
"""
        result = subprocess.run(
            ["/bin/bash", "-c", self._rollback_script(body)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_acknowledgement_failure_never_restarts_the_old_service(self) -> None:
        body = """
ACTIVATION_TRANSACTION_PHASE=rolled-back
FAIL_ACK=true
restore_previous_release_transaction && exit 80
test -e "$RECEIPT"
test -e "$SUPPRESSION"
test "$(grep -c '^restore-service$' "$LOG" || true)" = 0
FAIL_ACK=false
restore_previous_release_transaction
test ! -e "$RECEIPT"
test ! -e "$SUPPRESSION"
"""
        result = subprocess.run(
            ["/bin/bash", "-c", self._rollback_script(body)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_committed_journal_load_resumes_exact_final_health_and_retires(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install_root = root / "install"
            releases = install_root / "releases"
            release = releases / "0.1.26-beta.33"
            stage = root / "stage"
            config = root / "config"
            install_root.mkdir()
            releases.mkdir()
            release.mkdir()
            stage.mkdir()
            config.mkdir()
            script = f"""
set -u
INSTALL_ROOT={install_root!s}
RELEASES_ROOT={releases!s}
CURRENT_LINK={install_root / 'current'!s}
PREVIOUS_LINK={install_root / 'previous'!s}
ENV_FILE={config / 'env'!s}
STAGE_DIR={stage!s}
STATE_ROOT={root / 'state'!s}
PORT=7850
BIND_ADDRESS=127.0.0.1
TOKEN=test-token
TEAM_HUB_MODE=disabled
TEAM_HUB_TRANSPORT=loopback
TEAM_HUB_URL=
TEAM_HUB_DIRECT_IP_URL=
EXPECTED_TEAM_HUB_ID=
EXPECTED_SERVER_IDENTITY=
EXPECTED_TEAM_HUB_CLIENT_BINDING=
TEAM_HUB_REACTIVATION_HUB_ID=
TEAM_HUB_OPERATION_ID=
TEAM_HUB_SNAPSHOT=
TEAM_HUB_DATA_DIR=
TEAM_HUB_REACTIVATION_OPERATION_ID=
TEAM_HUB_REACTIVATION_SNAPSHOT=
TEAM_HUB_CANONICAL_DATA_DIR=
TEAM_HUB_OPERATION_FENCE_DEVICE=
TEAM_HUB_OPERATION_FENCE_INODE=
TEAM_HUB_REACTIVATION_FENCE_DEVICE=
TEAM_HUB_REACTIVATION_FENCE_INODE=
TEAM_HUB_COLD_GUARD_ID=
TEAM_HUB_COLD_GUARD_DEVICE=
TEAM_HUB_COLD_GUARD_INODE=
PREVIOUS_TEAM_HUB_TRANSPORT=loopback
PREVIOUS_TEAM_HUB_URL=
PREVIOUS_TEAM_HUB_DIRECT_IP_URL=
ACTIVATION_TRANSACTION_RESUMED=true
ACTIVATION_TRANSACTION_ID=
ACTIVATION_TRANSACTION_PHASE=
ACTIVATION_ROLLBACK_FROM=
ACTIVATION_TRANSACTION_DIR={install_root / '.activation-transaction'!s}
ACTIVATION_HUB_KIND=
ACTIVATION_INTENT=
CANDIDATE_RUNTIME_ROOT=
CANDIDATE_SERVICE_MAY_HAVE_STARTED=false
SERVICE_STOPPED_FOR_COLD_HANDOFF=false
RELEASE_ACTIVATED=false
RELEASE_VERSION=0.1.26-beta.33
RELEASE_DIR={release!s}
REQUESTED_RELEASE_VERSION=0.1.26-beta.33
OLD_TARGET=
ORIGINAL_OLD_SOURCE=
ROLLBACK_RELEASE_ROOT=
PRESERVE_SOURCE=
ENV_CONFIG_EXISTED=false
ENV_CONFIG_BACKUP=
ENV_CONFIG_CAPTURED=false
SERVICE_CONFIG_EXISTED=false
SERVICE_CONFIG_BACKUP=
SERVICE_CONFIG_CAPTURED=false
PRIOR_SERVICE_STATE=absent
PRIOR_SERVICE_ENABLED=false
PRIOR_LEGACY_SERVICE_STATE=absent
PRIOR_LEGACY_SERVICE_ENABLED=false
CURRENT_LINK_STATE_CAPTURED=false
CURRENT_LINK_WAS_SYMLINK=false
CURRENT_LINK_WAS_DIRECTORY=false
CURRENT_LINK_TARGET=
PREVIOUS_LINK_STATE_CAPTURED=false
PREVIOUS_LINK_WAS_SYMLINK=false
PREVIOUS_LINK_TARGET=
TEAM_HUB_OPERATION_PENDING=false
TEAM_HUB_REACTIVATION_FENCE_PENDING=false
TEAM_HUB_OPERATION_FINALIZED=false
TEAM_HUB_REACTIVATION_FINALIZED=false
TEAM_HUB_REACTIVATION_REQUESTED=false
TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED=false
TEAM_HUB_STARTUP_AUTHORITY_PENDING=false
TEAM_HUB_COLD_GUARD_PENDING=false
IN_EXIT_CLEANUP=false
LOG={root / 'events.log'!s}
activation_service_config_path() {{ printf '%s\n' {root / 'service'!s}; }}
read_env_value() {{ return 0; }}
validate_bind_address() {{
  test "$1" = 127.0.0.1
  test -n "$2"
}}
activation_transaction_command() {{
  test "$2" = load
  cat <<'EOF'
activation-0123456789abcdef01234567
0.1.26-beta.33
{release!s}
committed



missing

missing

false

false

absent
false
absent
false
ordinary







0
0

0
0
false
true
{release!s}
7860
127.0.0.1
activation-end
EOF
}}
ensure_committed_candidate_service() {{ printf 'ensure\n' >> "$LOG"; }}
wait_for_final_release_health() {{ printf 'final-health\n' >> "$LOG"; }}
resume_settlement_signals() {{ :; }}
finish_activation_transaction() {{ printf 'finish\n' >> "$LOG"; ACTIVATION_TRANSACTION_ID=; }}
{self.complete_commit_function}
{self.load_activation_function}
{self.recover_activation_function}
load_pending_activation_transaction
test "$ACTIVATION_TRANSACTION_PHASE" = committed
test "$CANDIDATE_RUNTIME_ROOT" = {release!s}
test "$PRIOR_PORT" = 7860
test "$PRIOR_BIND_ADDRESS" = 127.0.0.1
recover_pending_activation_transaction
test -z "$ACTIVATION_TRANSACTION_ID"
test "$(cat "$LOG")" = 'ensure
final-health
finish'
"""
            result = subprocess.run(
                ["/bin/bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_modern_network_keys_in_legacy_env_are_preserved_without_flags(
        self,
    ) -> None:
        script = f"""
set -u
PORT_EXPLICIT=false
BIND_EXPLICIT=false
PORT=7850
BIND_ADDRESS=0.0.0.0
ENV_FILE=/missing/new/env
LEGACY_ENV_FILE=/legacy/service/env
existing_network_value=
read_env_value() {{
  if [[ "$1" = "$LEGACY_ENV_FILE" && "$2" = AGENTSDOCK_AGENT_PORT ]]; then
    printf '7864\n'
  elif [[ "$1" = "$LEGACY_ENV_FILE" && "$2" = AGENTSDOCK_AGENT_BIND ]]; then
    printf '127.0.0.1\n'
  fi
}}
validate_bind_address() {{ test "$1" = 127.0.0.1; }}
{self.network_preservation_block}
test "$PORT" = 7864
test "$BIND_ADDRESS" = 127.0.0.1
"""
        result = subprocess.run(
            ["/bin/bash", "-c", script],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_candidate_failure_has_no_unjournaled_legacy_restart_escape(self) -> None:
        self.assertNotIn(
            'systemctl --user enable --now "$LEGACY_SERVICE_NAME.service"',
            self.installer_source,
        )

    def test_linked_candidate_is_stopped_before_files_are_rolled_back(self) -> None:
        body = """
ACTIVATION_ROLLBACK_FROM=linked
ACTIVATION_HUB_KIND=
TEAM_HUB_OPERATION_PENDING=false
TEAM_HUB_STARTUP_AUTHORITY_PENDING=false
rm -f "$RECEIPT"
restore_previous_release_transaction
test "$(grep -c '^suppress$' "$LOG")" = 1
test "$(grep -c '^stop$' "$LOG")" = 1
test "$(grep -c '^restore-files$' "$LOG")" = 1
test "$(grep -c '^restore-service$' "$LOG")" = 1
test "$(grep -c '^record:rolled-back$' "$LOG")" = 1
test "$(grep -c '^record:rollback-healthy$' "$LOG")" = 1
"""
        result = subprocess.run(
            ["/bin/bash", "-c", self._rollback_script(body)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_first_install_linked_cut_never_stops_an_absent_service(self) -> None:
        body = """
ACTIVATION_ROLLBACK_FROM=linked
ACTIVATION_HUB_KIND=
TEAM_HUB_OPERATION_PENDING=false
TEAM_HUB_STARTUP_AUTHORITY_PENDING=false
PRIOR_SERVICE_STATE=absent
OLD_TARGET=
EXPECTED_TEAM_HUB_CLIENT_BINDING=
rm -f "$RECEIPT"
restore_previous_release_transaction
test "$(grep -c '^suppress$' "$LOG" || true)" = 0
test "$(grep -c '^stop$' "$LOG" || true)" = 0
test "$(grep -c '^restore-service$' "$LOG" || true)" = 0
test "$(grep -c '^restore-files$' "$LOG")" = 1
test "$(grep -c '^record:rolled-back$' "$LOG")" = 1
test "$(grep -c '^record:rollback-healthy$' "$LOG")" = 1
"""
        result = subprocess.run(
            ["/bin/bash", "-c", self._rollback_script(body)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_pre_service_stopping_cut_never_stops_an_absent_service(self) -> None:
        body = """
ACTIVATION_ROLLBACK_FROM=stopping
ACTIVATION_HUB_KIND=
TEAM_HUB_OPERATION_PENDING=false
TEAM_HUB_STARTUP_AUTHORITY_PENDING=false
PRIOR_SERVICE_STATE=absent
OLD_TARGET=
EXPECTED_TEAM_HUB_CLIENT_BINDING=
rm -f "$RECEIPT"
restore_previous_release_transaction
test "$(grep -c '^suppress$' "$LOG" || true)" = 0
test "$(grep -c '^stop$' "$LOG" || true)" = 0
test "$(grep -c '^restore-service$' "$LOG" || true)" = 0
test "$(grep -c '^restore-files$' "$LOG")" = 1
test "$(grep -c '^record:rolled-back$' "$LOG")" = 1
test "$(grep -c '^record:rollback-healthy$' "$LOG")" = 1
"""
        result = subprocess.run(
            ["/bin/bash", "-c", self._rollback_script(body)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_settled_update_rollback_still_requires_the_exact_old_hub(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            previous = Path(temporary) / "previous"
            previous.mkdir()
            (previous / "VERSION").write_text("0.1.25-beta.31\n", encoding="ascii")
            script = f"""
set -u
ROLLBACK_RELEASE_ROOT={previous!s}
OLD_TARGET={previous!s}
HEALTH_CHECK_ATTEMPTS=3
ROLLBACK_HEALTH_CHECK_MAX_ATTEMPTS=45
EXPECTED_TEAM_HUB_ID=hub_rollback_health_12345678
EXPECTED_SERVER_IDENTITY=server_rollback_health_12345678
PREVIOUS_TEAM_HUB_TRANSPORT=tailscale_serve
PREVIOUS_TEAM_HUB_URL=https://hub.example.test/api/team-hub
PREVIOUS_TEAM_HUB_DIRECT_IP_URL=
PREVIOUS_TEAM_HUB_MODE=host
PRIOR_PORT=7850
PRIOR_BIND_ADDRESS=127.0.0.1
TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED=false
TEAM_HUB_OPERATION_PENDING=false
ACTIVATION_HUB_KIND=server-update
wait_for_exact_release_health() {{
  test "$4" = host
  test "$5" = hub_rollback_health_12345678
  test "$6" = tailscale_serve
  test "$7" = https://hub.example.test/api/team-hub
}}
{self.previous_health_function}
wait_for_previous_release_health
"""
            result = subprocess.run(
                ["/bin/bash", "-c", script],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def _darwin_service_script(self, body: str) -> str:
        return f"""
set -u
OS_NAME=Darwin
LABEL=com.agentsdock.server
SERVICE_NAME=agents-server
LEGACY_SERVICE_NAME=zenithbot-agent
MANAGED_UPDATE_ID=
ENABLED=false
LOADED=false
LOG=$(mktemp)
launchctl() {{
  command="$1"
  shift
  case "$command" in
    print)
      if [[ "$LOADED" = true ]]; then
        return 0
      fi
      printf 'Could not find service\n' >&2
      return 3
      ;;
    enable) printf 'enable\n' >> "$LOG"; ENABLED=true ;;
    disable) printf 'disable\n' >> "$LOG"; ENABLED=false ;;
    bootout) printf 'bootout\n' >> "$LOG"; LOADED=false ;;
    kickstart)
      [[ "$ENABLED" = true ]] || return 91
      printf 'kickstart\n' >> "$LOG"
      LOADED=true
      ;;
    *) return 92 ;;
  esac
}}
wait_for_launch_agent_removal() {{ [[ "$LOADED" = false ]]; }}
bootstrap_launch_agent() {{
  [[ "$ENABLED" = true ]] || return 93
  printf 'bootstrap\n' >> "$LOG"
  LOADED=true
}}
stop_service() {{ printf 'stop\n' >> "$LOG"; LOADED=false; }}
{self.launchd_state_functions}
{self.restart_service_function}
{self.restore_service_state_function}
{body}
"""

    def test_darwin_candidate_clears_disabled_override_before_bootstrap(self) -> None:
        result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                self._darwin_service_script(
                    """
restart_service
test "$ENABLED" = true
test "$LOADED" = true
test "$(cat "$LOG")" = 'enable
bootstrap'
"""
                ),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_darwin_rollback_restores_running_enabled_matrix(self) -> None:
        cases = (
            ("running", "true", "true", "true", "enable\nbootstrap"),
            ("running", "false", "false", "true", "enable\nbootstrap\ndisable"),
            ("stopped", "true", "true", "false", "enable\nstop"),
            ("stopped", "false", "false", "false", "disable\nstop"),
            ("absent", "false", "false", "false", "disable\nstop"),
        )
        for state, prior_enabled, enabled, loaded, expected_log in cases:
            with self.subTest(state=state, enabled=prior_enabled):
                service_existed = "false" if state == "absent" else "true"
                body = f"""
PRIOR_SERVICE_STATE={state}
PRIOR_SERVICE_ENABLED={prior_enabled}
SERVICE_CONFIG_EXISTED={service_existed}
PRIOR_LEGACY_SERVICE_ENABLED=false
PRIOR_LEGACY_SERVICE_STATE=absent
restore_prior_service_state
test "$ENABLED" = {enabled}
test "$LOADED" = {loaded}
test "$(cat "$LOG")" = '{expected_log}'
"""
                result = subprocess.run(
                    ["/bin/bash", "-c", self._darwin_service_script(body)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
