from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
INSTALLER = ROOT / "install.sh"


def _between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def _write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


class InstallerHealthSecurityTests(unittest.TestCase):
    """Network-free regressions for installer listener authentication.

    Every HTTP and service-manager command in these tests is a temporary fake.
    In particular, none of the fixtures binds a port or contacts a live server.
    """

    @classmethod
    def setUpClass(cls) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        cls.address_functions = _between(
            source,
            "health_host_for_bind() {",
            "service_manager_main_pid() {",
        )
        cls.preflight_health_function = cls.address_functions + _between(
            source, "health_check_once() {", "fetch_managed_json() {"
        )
        cls.managed_fetch_function = _between(
            source,
            "pinned_managed_http_get() {",
            "managed_secure_peer_binding_from_responses() {",
        )
        cls.health_functions = _between(
            source,
            "HEALTH_CHECK_HEARTBEAT_ATTEMPTS=5",
            "wait_for_previous_release_health() {",
        )
        fallback_start = source.index('ORIGINAL_PORT="$PORT"')
        fallback_end = source.index(
            '\n  echo "[4/7] Installing the user service',
            fallback_start,
        )
        cls.fallback_selection_fragment = source[fallback_start:fallback_end]
        cls.fallback_settlement_fragment = _between(
            source,
            'if [[ "$PORT_FALLBACK_BLOCKED" == "true" ]]; then',
            'echo "[6/7] Checking optional agent runtimes"',
        )
        cls.installer_source = source
        cls.advertised_url_fragment = _between(
            source,
            'TAILSCALE_IP=""',
            'echo "[7/7] AgentsServer',
        )

    def test_occupied_port_preflight_never_discloses_preserved_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            curl_log = root / "curl.log"
            token = "preserved_token_must_not_reach_foreign_listener_0123456789"
            _write_executable(
                fake_bin / "curl",
                """#!/bin/sh
printf '%s\\n' "$@" >> "$FAKE_CURL_LOG"
if [ "${1:-}" = "--version" ]; then
  exit 0
fi
# Model an occupied port whose foreign listener is willing to claim health.
exit 0
""",
            )
            script = f"""
TOKEN={token}
{self.preflight_health_function}
health_check_once 17850
"""
            result = subprocess.run(
                ["/bin/bash", "-c", script],
                env={
                    **os.environ,
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "FAKE_CURL_LOG": str(curl_log),
                },
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            invocation = curl_log.read_text(encoding="utf-8")
            self.assertNotIn(token, invocation)
            self.assertNotIn("Authorization: Bearer", invocation)
            arguments = invocation.splitlines()
            self.assertEqual(arguments[0], "--version")
            self.assertIn("-q", arguments)
            self.assertTrue(
                any(
                    arguments[index : index + 2] in (["--noproxy", "*"], ["--proxy", ""])
                    for index in range(max(0, len(arguments) - 1))
                ),
                "the unauthenticated loopback probe did not bypass ambient proxies",
            )

    def test_authenticated_health_uses_a_secret_fd_not_client_argv_or_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            runtime = root / "candidate"
            (runtime / ".venv" / "bin").mkdir(parents=True)
            output = root / "health.json"
            output.write_text("", encoding="ascii")
            output.chmod(0o600)
            python_log = root / "python.log"
            curl_log = root / "unexpected-curl.log"
            token = "authenticated_token_must_not_appear_in_argv_0123456789"
            _write_executable(
                fake_bin / "curl",
                "#!/bin/sh\nprintf 'called\\n' >> \"$FAKE_CURL_LOG\"\nexit 99\n",
            )
            _write_executable(
                runtime / ".venv" / "bin" / "python",
                """#!/bin/bash
for argument in "$@"; do printf 'ARG=%s\\n' "$argument"; done >> "$FAKE_PYTHON_LOG"
env | sed 's/=.*$/=<redacted>/' >> "$FAKE_PYTHON_LOG"
IFS= read -r secret <&3 || exit 91
printf 'FD3_LENGTH=%s\\n' "${#secret}" >> "$FAKE_PYTHON_LOG"
exit 1
""",
            )
            script = f"""
TOKEN={token}
BIND_ADDRESS=127.0.0.1
OS_NAME=Linux
SERVICE_NAME=agents-server
LEGACY_SERVICE_NAME=zenithbot-agent
LABEL=com.agentsdock.server
run_without_server_secrets() {{ command "$@"; }}
service_manager_main_pid() {{ printf '%s\\n' 4242; }}
{self.address_functions}
{self.managed_fetch_function}
fetch_managed_json 7850 /api/health core {output!s} {runtime!s}
"""
            result = subprocess.run(
                ["/bin/bash", "-c", script],
                env={
                    **os.environ,
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "FAKE_CURL_LOG": str(curl_log),
                    "FAKE_PYTHON_LOG": str(python_log),
                    "http_proxy": "http://attacker.invalid:8080",
                    "HTTP_PROXY": "http://attacker.invalid:8080",
                    "https_proxy": "http://attacker.invalid:8080",
                    "HTTPS_PROXY": "http://attacker.invalid:8080",
                    "all_proxy": "socks5://attacker.invalid:1080",
                    "ALL_PROXY": "socks5://attacker.invalid:1080",
                    "NO_PROXY": "",
                    "no_proxy": "",
                },
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0, result.stderr)
            log = python_log.read_text(encoding="utf-8")
            self.assertNotIn(token, log)
            self.assertIn(f"FD3_LENGTH={len(token)}", log)
            self.assertFalse(curl_log.exists(), "authenticated health invoked curl")
            self.assertNotIn(
                "wget",
                self.health_functions,
                "authenticated health must not retain an argv-only wget header path",
            )

    def test_foreign_exact_json_cannot_spoof_fresh_host_final_health(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            runtime = root / "candidate"
            state = root / "state"
            (runtime / ".venv" / "bin").mkdir(parents=True)
            (state / "admin").mkdir(parents=True)
            fake_bin.mkdir()
            (runtime / ".venv" / "bin" / "python").symlink_to(sys.executable)

            curl_log = root / "curl.log"
            systemctl_log = root / "systemctl.log"
            token = "candidate_token_must_not_reach_foreign_listener_0123456789"
            identity = "server_persisted_identity_12345678"
            hub_id = "hub_foreign_spoof_12345678"
            health = {
                "ok": True,
                "server_version": "0.1.26-beta.33",
                "server_identity": identity,
                "capabilities": {
                    "team_hub_v1": {
                        "available": True,
                        "designated_host": True,
                        "version": 1,
                        "base_path": "/api/team-hub",
                        "hub_id": hub_id,
                        "host_server_identity": identity,
                        "transport": "loopback",
                        "hub_url": None,
                        "routes": [{"transport": "loopback", "hub_url": None}],
                    },
                    "secure_peer_v1": {
                        "available": True,
                        "state_available": True,
                        "state_error_code": None,
                        "required": False,
                        "version": 1,
                        "control_path": "/api/admin/secure-peers/v1/status",
                        "proxy_prefix": "/api/team-hub-secure",
                    },
                },
            }
            status = {
                "server_identity": identity,
                "host": {
                    "available": True,
                    "error": None,
                    "error_code": None,
                },
            }
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "FAKE_CURL_LOG": str(curl_log),
                "FAKE_SYSTEMCTL_LOG": str(systemctl_log),
                "FAKE_HEALTH_JSON": json.dumps(health, separators=(",", ":")),
                "FAKE_STATUS_JSON": json.dumps(status, separators=(",", ":")),
            }
            _write_executable(
                fake_bin / "curl",
                """#!/bin/sh
printf '%s\\n' "$@" >> "$FAKE_CURL_LOG"
if [ "${1:-}" = "--version" ]; then
  exit 0
fi
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="${2:-}"; shift 2 ;;
    http://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  */api/health) payload="$FAKE_HEALTH_JSON" ;;
  */api/admin/secure-peers/v1/status) payload="$FAKE_STATUS_JSON" ;;
  *) exit 22 ;;
esac
if [ -n "$output" ]; then
  printf '%s\\n' "$payload" > "$output"
else
  printf '%s\\n' "$payload"
fi
""",
            )
            _write_executable(
                fake_bin / "systemctl",
                """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
case "$*" in
  *MainPID*) printf '%s\\n' 424242 ;;
esac
""",
            )
            # If ownership is checked through process/socket inventory rather
            # than /proc directly, these fakes consistently report a foreign
            # process, never systemd's claimed MainPID.
            _write_executable(
                fake_bin / "lsof",
                """#!/bin/sh
printf '%s\\n' 'COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME'
printf '%s\\n' 'foreign 31337 user 7u IPv4 0t0 TCP 127.0.0.1:7850 (LISTEN)'
""",
            )
            _write_executable(
                fake_bin / "ss",
                """#!/bin/sh
printf '%s\\n' 'LISTEN 0 128 127.0.0.1:7850 0.0.0.0:* users:(("foreign",pid=31337,fd=7))'
""",
            )
            script = f"""
OS_NAME=Linux
SERVICE_NAME=agents-server
PORT=7850
TOKEN={token}
STATE_ROOT={state!s}
RELEASE_DIR={runtime!s}
RELEASE_VERSION=0.1.26-beta.33
EXPECTED_SERVER_IDENTITY=
TEAM_HUB_MODE=host
EXPECTED_TEAM_HUB_ID=
TEAM_HUB_REACTIVATION_HUB_ID=
TEAM_HUB_TRANSPORT=loopback
TEAM_HUB_URL=
TEAM_HUB_DIRECT_IP_URL=
EXPECTED_TEAM_HUB_CLIENT_BINDING=
HEALTH_CHECK_ATTEMPTS=1
run_without_server_secrets() {{
  case " $* " in
    *" -m agentsdock_team_hub.cli verify-server-identity "*)
      # The attacker knows and echoes the non-secret persisted identity.  That
      # JSON equality is deliberately insufficient without socket/PID proof.
      return 0
      ;;
  esac
  command "$@"
}}
{self.health_functions}
wait_for_final_release_health
"""
            result = subprocess.run(
                ["/bin/bash", "-c", script],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(
                result.returncode,
                0,
                "a foreign process returned exact expected JSON and was accepted",
            )
            service_queries = (
                systemctl_log.read_text(encoding="utf-8")
                if systemctl_log.exists()
                else ""
            )
            self.assertIn("MainPID", service_queries)
            invocation = (
                curl_log.read_text(encoding="utf-8") if curl_log.exists() else ""
            )
            self.assertNotIn(token, invocation)

    def test_listener_takeover_after_pid_precheck_never_receives_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "bin"
            runtime = root / "candidate"
            state = root / "state"
            (runtime / ".venv" / "bin").mkdir(parents=True)
            (state / "admin").mkdir(parents=True)
            fake_bin.mkdir()
            (runtime / ".venv" / "bin" / "python").symlink_to(sys.executable)
            curl_log = root / "foreign-curl.log"
            proof_count = root / "proof-count"
            token = "takeover_token_must_not_reach_foreign_listener_0123456789"
            identity = "server_expected_takeover_12345678"
            health = {
                "ok": True,
                "server_version": "0.1.26-beta.33",
                "server_identity": identity,
                "capabilities": {
                    "team_hub_v1": {
                        "available": False,
                        "designated_host": False,
                        "version": 1,
                        "base_path": None,
                        "hub_id": None,
                        "host_server_identity": None,
                        "transport": None,
                        "hub_url": None,
                        "routes": [],
                    },
                    "secure_peer_v1": {
                        "available": True,
                        "state_available": True,
                        "state_error_code": None,
                        "required": False,
                        "version": 1,
                        "control_path": "/api/admin/secure-peers/v1/status",
                        "proxy_prefix": "/api/team-hub-secure",
                    },
                },
            }
            _write_executable(
                fake_bin / "curl",
                """#!/bin/sh
stdin="$(cat)"
printf 'STDIN=%s\\n' "$stdin" >> "$FAKE_CURL_LOG"
for argument in "$@"; do
  printf 'ARG=%s\\n' "$argument" >> "$FAKE_CURL_LOG"
done
if [ "${1:-}" = "--version" ]; then
  exit 0
fi
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="${2:-}"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$output" ] || exit 90
printf '%s\\n' "$FAKE_HEALTH_JSON" > "$output"
exit 0
""",
            )
            script = f"""
OS_NAME=Linux
SERVICE_NAME=agents-server
LEGACY_SERVICE_NAME=zenithbot-agent
TOKEN={token}
STATE_ROOT={state!s}
TEAM_HUB_DIRECT_IP_URL=
EXPECTED_TEAM_HUB_CLIENT_BINDING=
run_without_server_secrets() {{ command "$@"; }}
{self.health_functions}
# The legitimate candidate owns the listener at the first snapshot. It exits
# immediately afterward and a foreign exact-JSON listener wins the port before
# the separate curl process connects.
service_manager_owns_listener() {{
  count="$(cat {proof_count!s} 2>/dev/null || printf 0)"
  count=$((count + 1))
  printf '%s\\n' "$count" > {proof_count!s}
  [[ "$count" = 1 ]]
}}
release_health_check_once \
  7850 {runtime!s} 0.1.26-beta.33 {identity} disabled '' loopback '' false
"""
            result = subprocess.run(
                ["/bin/bash", "-c", script],
                env={
                    **os.environ,
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "FAKE_CURL_LOG": str(curl_log),
                    "FAKE_HEALTH_JSON": json.dumps(health, separators=(",", ":")),
                },
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(
                result.returncode,
                0,
                "a listener takeover after the PID snapshot passed exact health",
            )
            transcript = (
                curl_log.read_text(encoding="utf-8") if curl_log.exists() else ""
            )
            self.assertNotIn(
                token,
                transcript,
                "the bearer was written to a connection not bound to the proven PID",
            )

    def test_external_team_hub_routes_disable_port_fallback(self) -> None:
        route_cases = (
            (
                "tailscale_serve",
                "https://dock.example.ts.net:8444/api/team-hub",
                "",
            ),
            (
                "direct_ip",
                "http://100.64.0.8:7850/api/team-hub",
                "http://100.64.0.8:7850/api/team-hub",
            ),
        )
        for transport, hub_url, direct_url in route_cases:
            with self.subTest(transport=transport), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                selected = root / "selected-port"
                writes = root / "runtime-env-writes"
                script = f"""
PORT=7850
PORT_FALLBACK=true
PORT_FALLBACK_ATTEMPTS=5
TEAM_HUB_MODE=host
TEAM_HUB_TRANSPORT={transport}
TEAM_HUB_URL={hub_url}
TEAM_HUB_DIRECT_IP_URL={direct_url}
port_has_listener() {{ [[ "$1" = 7850 ]]; }}
health_check_once() {{ return 1; }}
describe_port_listener() {{ :; }}
write_runtime_env() {{ printf '%s\\n' "$PORT" >> {writes!s}; }}
select_installer_port() {{
{self.fallback_selection_fragment}
  break
done
{self.fallback_settlement_fragment}
}}
select_installer_port
result=$?
printf '%s\\n' "$PORT" > {selected!s}
exit "$result"
"""
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertNotEqual(
                    result.returncode,
                    0,
                    f"{transport} route allowed an unsafe automatic port change",
                )
                self.assertEqual(selected.read_text(encoding="ascii").strip(), "7850")
                self.assertFalse(writes.exists())

    def test_health_probe_targets_the_selected_specific_bind(self) -> None:
        cases = (
            ("0.0.0.0", "http://127.0.0.1:7850/api/health"),
            ("127.0.0.1", "http://127.0.0.1:7850/api/health"),
            ("192.0.2.50", "http://192.0.2.50:7850/api/health"),
        )
        for bind_address, expected_url in cases:
            with self.subTest(bind_address=bind_address), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fake_bin = root / "bin"
                fake_bin.mkdir()
                curl_log = root / "curl.log"
                _write_executable(
                    fake_bin / "curl",
                    """#!/bin/sh
for argument in "$@"; do printf '%s\\n' "$argument"; done >> "$FAKE_CURL_LOG"
exit 0
""",
                )
                script = f"""
BIND_ADDRESS={bind_address}
TOKEN=unused
{self.preflight_health_function}
health_check_once 7850
"""
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    env={
                        **os.environ,
                        "PATH": f"{fake_bin}:/usr/bin:/bin",
                        "FAKE_CURL_LOG": str(curl_log),
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected_url, curl_log.read_text(encoding="utf-8"))

    def test_installer_never_downloads_or_executes_a_uv_bootstrap_script(self) -> None:
        self.assertNotIn("download_uv_installer", self.installer_source)
        self.assertNotIn("install_uv_runtime", self.installer_source)
        self.assertNotIn("astral.sh/uv/", self.installer_source)
        self.assertNotIn("command -v wget", self.installer_source)

    def test_trusted_uv_is_required_during_read_only_preflight(self) -> None:
        preflight_end = self.installer_source.index(
            "preflight_prerequisites || exit 1"
        )
        mutation_start = self.installer_source.index('echo "[1/7] Preparing')
        requirement = self.installer_source.index("require_uv_runtime")
        self.assertLess(requirement, preflight_end)
        self.assertLess(preflight_end, mutation_start)

    def test_advertised_server_url_is_reachable_from_the_selected_bind(self) -> None:
        cases = (
            ("127.0.0.1", "http://127.0.0.1:7850"),
            ("192.0.2.50", "http://192.0.2.50:7850"),
            ("0.0.0.0", "http://100.64.0.9:7850"),
        )
        for bind_address, expected in cases:
            with self.subTest(bind_address=bind_address), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fake_bin = root / "bin"
                fake_bin.mkdir()
                _write_executable(
                    fake_bin / "tailscale",
                    """#!/bin/sh
if [ "${1:-}" = ip ] && [ "${2:-}" = -4 ]; then
  printf '%s\\n' 100.64.0.9
fi
""",
                )
                script = f"""
BIND_ADDRESS={bind_address}
PORT=7850
{self.address_functions}
{self.advertised_url_fragment}
printf '%s\\n' "$SERVER_URL"
"""
                result = subprocess.run(
                    ["/bin/bash", "-c", script],
                    env={**os.environ, "PATH": f"{fake_bin}:/usr/bin:/bin"},
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)


if __name__ == "__main__":
    unittest.main()
