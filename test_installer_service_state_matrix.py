from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
INSTALLER = ROOT / "install.sh"
LABEL = "com.agentsdock.server"
DOMAIN = "gui/501"
SERVICE_TARGET = f"{DOMAIN}/{LABEL}"


def _between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


class InstallerServiceStateMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        cls.systemd_snapshot_helper = _between(
            source,
            "systemd_unit_snapshot() {",
            "backup_runtime_configuration() {",
        )
        cls.launchd_helpers = _between(
            source,
            "launchd_target_snapshot() {",
            "systemd_service_active_state() {",
        )
        cls.restart_service = _between(
            source,
            "restart_service() {",
            "restore_previous_release_transaction() {",
        )
        cls.rollback_transaction = _between(
            source,
            "restore_previous_release_transaction() {",
            "restore_previous_release() {",
        )
        cls.service_restore_functions = _between(
            source,
            "stop_service() {",
            "restore_team_hub_snapshot() {",
        )

    @staticmethod
    def _write_executable(path: Path, body: str) -> None:
        path.write_text(body, encoding="utf-8")
        path.chmod(0o700)

    def _darwin_harness(
        self,
        *,
        invocation: str,
        initially_running: bool,
        initially_disabled: bool,
        config_exists: bool,
        include_restart: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], list[str], bool, bool, bool]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            event_log = root / "launchctl.log"
            running = root / "running"
            disabled = root / "disabled"
            plist = root / "agents-server.plist"
            if initially_running:
                running.touch()
            if initially_disabled:
                disabled.touch()
            if config_exists:
                plist.write_text("fixture\n", encoding="ascii")

            self._write_executable(
                fake_bin / "launchctl",
                """#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_LAUNCHCTL_LOG"
case "$1" in
  print)
    if test -e "$FAKE_LAUNCHCTL_RUNNING"; then
      printf '%s\n' 'state = running'
    else
      printf '%s\n' 'Could not find service' >&2
      exit 113
    fi
    ;;
  enable)
    /bin/rm -f "$FAKE_LAUNCHCTL_DISABLED"
    ;;
  disable)
    : > "$FAKE_LAUNCHCTL_DISABLED"
    ;;
  bootstrap)
    test ! -e "$FAKE_LAUNCHCTL_DISABLED" || exit 71
    test -f "$3" || exit 72
    : > "$FAKE_LAUNCHCTL_RUNNING"
    ;;
  kickstart)
    test ! -e "$FAKE_LAUNCHCTL_DISABLED" || exit 73
    : > "$FAKE_LAUNCHCTL_RUNNING"
    ;;
  bootout)
    /bin/rm -f "$FAKE_LAUNCHCTL_RUNNING"
    ;;
  *)
    exit 74
    ;;
esac
""",
            )
            self._write_executable(fake_bin / "sleep", "#!/bin/sh\nexit 0\n")
            functions = self.launchd_helpers + self.service_restore_functions
            if include_restart:
                functions = self.launchd_helpers + self.restart_service
            script = f"""
set -euo pipefail
OS_NAME=Darwin
LABEL={LABEL}
PLIST={shlex.quote(str(plist))}
SERVICE_NAME=agents-server
LEGACY_SERVICE_NAME=zenithbot-agent
MANAGED_UPDATE_ID=
LAUNCHCTL_STOP_ATTEMPTS=3
LAUNCHCTL_STOP_DELAY=0
LAUNCHCTL_BOOTSTRAP_ATTEMPTS=3
id() {{ printf '501\n'; }}
{functions}
{invocation}
"""
            result = subprocess.run(
                ["/bin/bash", "-c", script],
                env={
                    **os.environ,
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "FAKE_LAUNCHCTL_LOG": str(event_log),
                    "FAKE_LAUNCHCTL_RUNNING": str(running),
                    "FAKE_LAUNCHCTL_DISABLED": str(disabled),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            events = (
                event_log.read_text(encoding="utf-8").splitlines()
                if event_log.exists()
                else []
            )
            events = [line.replace(str(plist), "<PLIST>") for line in events]
            final_running = running.exists()
            final_disabled = disabled.exists()
            final_config = plist.exists()
        return result, events, final_running, final_disabled, final_config

    def _assert_darwin_restore(
        self,
        *,
        prior_state: str,
        prior_enabled: bool,
        expected_events: list[str],
        initially_running: bool = False,
    ) -> None:
        result, events, running, disabled, config_exists = self._darwin_harness(
            invocation=(
                f"PRIOR_SERVICE_STATE={prior_state}; "
                f"PRIOR_SERVICE_ENABLED={'true' if prior_enabled else 'false'}; "
                "restore_prior_service_state"
            ),
            initially_running=initially_running,
            # Rollback suppression leaves the candidate disabled before exact
            # prior state is restored.
            initially_disabled=True,
            config_exists=prior_state != "absent",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, expected_events)
        self.assertEqual(running, prior_state == "running")
        self.assertEqual(disabled, not prior_enabled)
        self.assertEqual(config_exists, prior_state != "absent")

    def test_darwin_candidate_clears_disabled_override_before_bootstrap(self) -> None:
        result, events, running, disabled, config_exists = self._darwin_harness(
            invocation="restart_service",
            initially_running=False,
            initially_disabled=True,
            config_exists=True,
            include_restart=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            events,
            [
                f"print {SERVICE_TARGET}",
                f"enable {SERVICE_TARGET}",
                f"bootstrap {DOMAIN} <PLIST>",
            ],
        )
        self.assertTrue(running)
        self.assertFalse(disabled)
        self.assertTrue(config_exists)

    def test_darwin_running_disabled_restore_bootstraps_then_redisables(self) -> None:
        self._assert_darwin_restore(
            prior_state="running",
            prior_enabled=False,
            expected_events=[
                f"enable {SERVICE_TARGET}",
                f"print {SERVICE_TARGET}",
                f"bootstrap {DOMAIN} <PLIST>",
                f"disable {SERVICE_TARGET}",
            ],
        )

    def test_darwin_running_disabled_loaded_job_kickstarts_then_redisables(
        self,
    ) -> None:
        self._assert_darwin_restore(
            prior_state="running",
            prior_enabled=False,
            initially_running=True,
            expected_events=[
                f"enable {SERVICE_TARGET}",
                f"print {SERVICE_TARGET}",
                f"kickstart -k {SERVICE_TARGET}",
                f"disable {SERVICE_TARGET}",
            ],
        )

    def test_darwin_running_enabled_state_is_restored_exactly(self) -> None:
        result, events, running, disabled, config_exists = self._darwin_harness(
            invocation="PRIOR_SERVICE_STATE=running; PRIOR_SERVICE_ENABLED=true; "
            "restore_prior_service_state",
            initially_running=False,
            initially_disabled=True,
            config_exists=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events[:2], [f"enable {SERVICE_TARGET}", f"print {SERVICE_TARGET}"])
        self.assertEqual(events[2], f"bootstrap {DOMAIN} <PLIST>")
        self.assertEqual(len(events), 3)
        self.assertTrue(running)
        self.assertFalse(disabled)
        self.assertTrue(config_exists)

    def test_darwin_stopped_enabled_state_is_restored_exactly(self) -> None:
        self._assert_darwin_restore(
            prior_state="stopped",
            prior_enabled=True,
            expected_events=[
                f"enable {SERVICE_TARGET}",
                f"print {SERVICE_TARGET}",
                f"print {SERVICE_TARGET}",
            ],
        )

    def test_darwin_stopped_disabled_state_is_restored_exactly(self) -> None:
        self._assert_darwin_restore(
            prior_state="stopped",
            prior_enabled=False,
            expected_events=[
                f"disable {SERVICE_TARGET}",
                f"print {SERVICE_TARGET}",
                f"print {SERVICE_TARGET}",
            ],
        )

    def test_darwin_absent_config_keeps_persisted_disabled_override(self) -> None:
        self._assert_darwin_restore(
            prior_state="absent",
            prior_enabled=False,
            expected_events=[
                f"disable {SERVICE_TARGET}",
                f"print {SERVICE_TARGET}",
                f"print {SERVICE_TARGET}",
            ],
        )

    def test_linux_absent_pre_start_rollback_never_touches_systemd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            event_log = root / "systemctl.log"
            event_log.touch()
            self._write_executable(
                fake_bin / "systemctl",
                """#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
exit 0
""",
            )
            script = f"""
set -euo pipefail
OS_NAME=Linux
SERVICE_NAME=agents-server
LEGACY_SERVICE_NAME=zenithbot-agent
MANAGED_UPDATE_ID=
ACTIVATION_TRANSACTION_ID=activation-0123456789abcdef01234567
ACTIVATION_TRANSACTION_PHASE=linked
ACTIVATION_ROLLBACK_FROM=
ACTIVATION_HUB_KIND=
CANDIDATE_RUNTIME_ROOT={shlex.quote(str(root / 'candidate'))}
STAGE_DIR={shlex.quote(str(root / 'stage'))}
ACTIVATION_TRANSACTION_DIR={shlex.quote(str(root / 'transaction'))}
TEAM_HUB_COLD_GUARD_PENDING=false
TEAM_HUB_REACTIVATION_FENCE_PENDING=false
TEAM_HUB_OPERATION_PENDING=false
TEAM_HUB_OPERATION_FINALIZED=true
TEAM_HUB_REACTIVATION_FINALIZED=true
TEAM_HUB_STARTUP_AUTHORITY_PENDING=false
TEAM_HUB_REACTIVATION_REQUESTED=false
TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED=false
EXPECTED_TEAM_HUB_CLIENT_BINDING=
OLD_TARGET=
PRIOR_SERVICE_STATE=absent
PRIOR_SERVICE_ENABLED=false
PRIOR_LEGACY_SERVICE_STATE=absent
PRIOR_LEGACY_SERVICE_ENABLED=false
record_activation_phase() {{ ACTIVATION_TRANSACTION_PHASE="$1"; }}
finish_activation_transaction() {{ ACTIVATION_TRANSACTION_ID=; }}
prepare_team_hub_reactivation() {{ return 99; }}
restore_team_hub_snapshot() {{ return 99; }}
restore_activation_files() {{ return 0; }}
clear_team_hub_cold_guard() {{ return 0; }}
clear_team_hub_startup_authority() {{ return 0; }}
acknowledge_team_hub_restore_receipt() {{ return 0; }}
wait_for_previous_release_health() {{ return 99; }}
wait_for_health() {{ return 99; }}
{self.systemd_snapshot_helper}
{self.launchd_helpers}
{self.rollback_transaction}
{self.service_restore_functions}
restore_previous_release_transaction
"""
            result = subprocess.run(
                ["/bin/bash", "-c", script],
                env={
                    **os.environ,
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "FAKE_SYSTEMCTL_LOG": str(event_log),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            events = event_log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, [])

    def test_linux_legacy_only_rollback_requires_authenticated_health(self) -> None:
        for health_succeeds in (False, True):
            with self.subTest(health_succeeds=health_succeeds):
                result, phases, health_events, systemctl_events = (
                    self._run_linux_legacy_only_rollback(
                        health_succeeds=health_succeeds
                    )
                )
                self.assertEqual(health_events, ["exact"])
                self.assertIn("--user enable zenithbot-agent.service", systemctl_events)
                self.assertIn("--user start zenithbot-agent.service", systemctl_events)
                if health_succeeds:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(phases[-1], "rollback-healthy")
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("rollback-healthy", phases)

    def _run_linux_legacy_only_rollback(
        self,
        *,
        health_succeeds: bool,
    ) -> tuple[subprocess.CompletedProcess[str], list[str], list[str], list[str]]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            systemctl_log = root / "systemctl.log"
            phase_log = root / "phase.log"
            health_log = root / "health.log"
            main_service = root / "agents-server.service"
            legacy_service = root / "zenithbot-agent.service"
            legacy_service.write_text("[Service]\n", encoding="ascii")
            for path in (systemctl_log, phase_log, health_log):
                path.touch()
            self._write_executable(
                fake_bin / "systemctl",
                """#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
case "$*" in
  "--user show agents-server.service --property=LoadState --value")
    printf 'not-found\n'
    ;;
  "--user show agents-server.service --property=ActiveState --value")
    printf 'inactive\n'
    ;;
  "--user is-enabled agents-server.service")
    printf 'not-found\n'
    exit 1
    ;;
esac
exit 0
""",
            )
            script = f"""
set -euo pipefail
OS_NAME=Linux
SERVICE_NAME=agents-server
LEGACY_SERVICE_NAME=zenithbot-agent
SYSTEMD_SERVICE_FILE={shlex.quote(str(main_service))}
LEGACY_SERVICE_FILE={shlex.quote(str(legacy_service))}
MANAGED_UPDATE_ID=
ACTIVATION_TRANSACTION_ID=activation-0123456789abcdef01234567
ACTIVATION_TRANSACTION_PHASE=candidate-starting
ACTIVATION_ROLLBACK_FROM=
ACTIVATION_HUB_KIND=
CANDIDATE_RUNTIME_ROOT={shlex.quote(str(root / 'candidate'))}
STAGE_DIR={shlex.quote(str(root / 'stage'))}
ACTIVATION_TRANSACTION_DIR={shlex.quote(str(root / 'transaction'))}
TEAM_HUB_COLD_GUARD_PENDING=false
TEAM_HUB_REACTIVATION_FENCE_PENDING=false
TEAM_HUB_OPERATION_PENDING=false
TEAM_HUB_OPERATION_FINALIZED=true
TEAM_HUB_REACTIVATION_FINALIZED=true
TEAM_HUB_STARTUP_AUTHORITY_PENDING=false
TEAM_HUB_REACTIVATION_REQUESTED=false
TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED=false
EXPECTED_TEAM_HUB_CLIENT_BINDING=
OLD_TARGET=
PRIOR_SERVICE_STATE=absent
PRIOR_SERVICE_ENABLED=false
PRIOR_LEGACY_SERVICE_STATE=running
PRIOR_LEGACY_SERVICE_ENABLED=true
record_activation_phase() {{
  printf '%s\n' "$1" >> "$FAKE_PHASE_LOG"
  ACTIVATION_TRANSACTION_PHASE="$1"
}}
finish_activation_transaction() {{ ACTIVATION_TRANSACTION_ID=; }}
prepare_team_hub_reactivation() {{ return 99; }}
restore_team_hub_snapshot() {{ return 99; }}
restore_activation_files() {{ return 0; }}
clear_team_hub_cold_guard() {{ return 0; }}
clear_team_hub_startup_authority() {{ return 0; }}
acknowledge_team_hub_restore_receipt() {{ return 0; }}
wait_for_previous_release_health() {{
  printf 'wrong-release-helper\n' >> "$FAKE_HEALTH_LOG"
  return 98
}}
wait_for_legacy_release_health() {{
  printf 'exact\n' >> "$FAKE_HEALTH_LOG"
  [[ "$FAKE_HEALTH_SUCCEEDS" = true ]]
}}
wait_for_health() {{
  printf 'generic\n' >> "$FAKE_HEALTH_LOG"
  return 98
}}
{self.systemd_snapshot_helper}
{self.launchd_helpers}
{self.rollback_transaction}
{self.service_restore_functions}
restore_previous_release_transaction
"""
            result = subprocess.run(
                ["/bin/bash", "-c", script],
                env={
                    **os.environ,
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "FAKE_SYSTEMCTL_LOG": str(systemctl_log),
                    "FAKE_PHASE_LOG": str(phase_log),
                    "FAKE_HEALTH_LOG": str(health_log),
                    "FAKE_HEALTH_SUCCEEDS": (
                        "true" if health_succeeds else "false"
                    ),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            phases = phase_log.read_text(encoding="utf-8").splitlines()
            health_events = health_log.read_text(encoding="utf-8").splitlines()
            systemctl_events = systemctl_log.read_text(
                encoding="utf-8"
            ).splitlines()
        return result, phases, health_events, systemctl_events


if __name__ == "__main__":
    unittest.main()
