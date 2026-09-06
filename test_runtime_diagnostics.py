import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

import agent_server


def completed(args: list[str], returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout, stderr=stderr)


class RuntimeDiagnosticTests(unittest.TestCase):
    def setUp(self) -> None:
        with agent_server.RUNTIME_DIAGNOSTICS_LOCK:
            agent_server.RUNTIME_DIAGNOSTICS.clear()
            agent_server.RUNTIME_DIAGNOSTIC_GENERATIONS.clear()

    def test_missing_runtime_is_explicit(self) -> None:
        with patch.object(agent_server.shutil, "which", return_value=None):
            diagnostic = agent_server.probe_runtime(agent_server.BACKEND_CLAUDE)
        self.assertEqual(diagnostic["status"], "missing")
        self.assertFalse(diagnostic["available"])
        self.assertIn("Install Claude Code", diagnostic["action"])

    def test_broken_tmux_is_reported_unavailable_but_optional(self) -> None:
        with patch.object(agent_server.shutil, "which", return_value="/usr/local/bin/tmux"), patch.object(
            agent_server.subprocess,
            "run",
            return_value=completed(["/usr/local/bin/tmux", "-V"], returncode=127),
        ) as run:
            capability = agent_server.tmux_capability()

        self.assertFalse(capability["available"])
        self.assertFalse(capability["required"])
        self.assertIn("failed its version check", capability["message"])
        run.assert_called_once()

    def test_failed_tmux_probe_is_cached_for_health_polling(self) -> None:
        agent_server.TMUX_PROBE_CACHE.update({
            "path": None,
            "available": False,
            "checked_at": 0.0,
        })
        with patch.object(
            agent_server.shutil,
            "which",
            return_value="/usr/local/bin/tmux",
        ), patch.object(
            agent_server.subprocess,
            "run",
            side_effect=OSError("cannot execute tmux"),
        ) as run:
            self.assertIsNone(agent_server.working_tmux_bin(use_cache=True))
            self.assertIsNone(agent_server.working_tmux_bin(use_cache=True))

        run.assert_called_once()

    def test_missing_tmux_is_reported_unavailable_but_optional(self) -> None:
        with patch.object(agent_server.shutil, "which", return_value=None), patch.object(
            agent_server.subprocess,
            "run",
        ) as run:
            capability = agent_server.tmux_capability()

        self.assertFalse(capability["available"])
        self.assertFalse(capability["required"])
        self.assertIn("rest of AgentsServer works without it", capability["message"])
        run.assert_not_called()

    def test_working_tmux_is_reported_available(self) -> None:
        with patch.object(agent_server.shutil, "which", return_value="/usr/local/bin/tmux"), patch.object(
            agent_server.subprocess,
            "run",
            return_value=completed(["/usr/local/bin/tmux", "-V"]),
        ):
            capability = agent_server.tmux_capability()

        self.assertTrue(capability["available"])
        self.assertFalse(capability["required"])

    def test_claude_ready_probe_does_not_expose_identity(self) -> None:
        responses = [
            completed(["claude", "--version"], stdout="2.3.4 (Claude Code)\n"),
            completed(
                ["claude", "auth", "status", "--json"],
                stdout=json.dumps({"loggedIn": True, "email": "private@example.com", "organizationName": "Secret"}),
            ),
        ]
        with patch.object(agent_server.shutil, "which", return_value="/usr/local/bin/claude"), patch.object(
            agent_server, "runtime_command", side_effect=responses
        ):
            diagnostic = agent_server.probe_runtime(agent_server.BACKEND_CLAUDE)
        self.assertEqual(diagnostic["status"], "ready")
        self.assertEqual(diagnostic["version"], "2.3.4 (Claude Code)")
        self.assertNotIn("private@example.com", json.dumps(diagnostic))
        self.assertNotIn("Secret", json.dumps(diagnostic))

    def test_codex_auth_failure_is_actionable(self) -> None:
        responses = [
            completed(["codex", "--version"], stdout="codex-cli 1.2.3\n"),
            completed(["codex", "login", "status"], returncode=1, stderr="Not logged in"),
        ]
        with patch.object(agent_server.shutil, "which", return_value="/usr/local/bin/codex"), patch.object(
            agent_server, "runtime_command", side_effect=responses
        ):
            diagnostic = agent_server.probe_runtime(agent_server.BACKEND_CODEX)
        self.assertEqual(diagnostic["status"], "unauthenticated")
        self.assertIn("codex login", diagnostic["action"])

    def test_cursor_prefers_first_compatible_candidate_not_first_installed(self) -> None:
        compatible_help = """
-p, --print --output-format stream-json --resume --model --trust --force
--mode plan --list-models
"""

        def which(candidate: str, **_kwargs: object) -> str | None:
            return {
                "cursor-agent": "/legacy/cursor-agent",
                "agent": "/current/agent",
            }.get(candidate)

        def command(args: list[str]) -> subprocess.CompletedProcess[str]:
            if args == ["/legacy/cursor-agent", "--help"]:
                return completed(args, stdout="-p --output-format")
            if args == ["/current/agent", "--help"]:
                return completed(args, stdout=compatible_help)
            if args == ["/current/agent", "about"]:
                return completed(args, stdout="About Cursor CLI\n")
            if args == ["/current/agent", "--version"]:
                return completed(args, stdout="2026.08.11-e8db854\n")
            if args == ["/current/agent", "status"]:
                return completed(args, stdout="Logged in as user@example.com\n")
            raise AssertionError(args)

        with patch.object(agent_server.shutil, "which", side_effect=which), patch.object(
            agent_server, "runtime_command", side_effect=command
        ):
            diagnostic = agent_server.probe_runtime(agent_server.BACKEND_CURSOR)

        self.assertEqual(diagnostic["status"], "ready")
        self.assertEqual(diagnostic["_executable"], "/current/agent")

    def test_cursor_nonzero_status_cannot_false_report_authenticated(self) -> None:
        secret = "private-account@example.com"
        compatible_help = (
            "-p --print --output-format stream-json --resume --model --trust "
            "--force --mode plan --list-models"
        )
        responses = [
            completed(["/bin/agent", "--help"], stdout=compatible_help),
            completed(["/bin/agent", "about"], stdout="About Cursor CLI\n"),
            completed(["/bin/agent", "--version"], stdout="2026.08\n"),
            completed(
                ["/bin/agent", "status"],
                returncode=2,
                stderr=f"authenticated cache for {secret} could not be read",
            ),
        ]
        with patch.object(agent_server.shutil, "which", return_value="/bin/agent"), patch.object(
            agent_server, "runtime_command", side_effect=responses
        ):
            diagnostic = agent_server.probe_runtime(agent_server.BACKEND_CURSOR)

        self.assertEqual(diagnostic["status"], "error")
        self.assertIsNone(diagnostic["authenticated"])
        self.assertNotIn(secret, json.dumps(diagnostic))
        self.assertIn("output was omitted", diagnostic["message"])

    def test_cursor_agent_name_collision_is_rejected_by_identity_probe(self) -> None:
        compatible_help = (
            "-p --print --output-format stream-json --resume --model --trust "
            "--force --mode plan --list-models"
        )
        with patch.object(
            agent_server,
            "cursor_executable_candidates",
            return_value=("agent",),
        ), patch.object(
            agent_server.shutil,
            "which",
            return_value="/bin/agent",
        ), patch.object(
            agent_server,
            "runtime_command",
            side_effect=[
                completed(["/bin/agent", "--help"], stdout=compatible_help),
                completed(["/bin/agent", "about"], stdout="About Grok CLI\n"),
            ],
        ):
            compatible, installed, missing, error = (
                agent_server.cursor_executable_resolution()
            )
        self.assertIsNone(compatible)
        self.assertEqual(installed, str(Path("/bin/agent").resolve()))
        self.assertEqual(missing, ())
        self.assertEqual(error, "identity probe did not identify Cursor CLI")
        self.assertNotIn("Grok", error)

    def test_cursor_resolution_pins_realpath_before_compatibility_probe(self) -> None:
        compatible_help = (
            "-p --print --output-format stream-json --resume --model --trust "
            "--force --mode plan --list-models"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "agent-v1"
            second = root / "agent-v2"
            first.write_text("v1")
            second.write_text("v2")
            resolved_first = str(first.resolve())
            alias = root / "agent"
            alias.symlink_to(first)

            def command(args: list[str]) -> subprocess.CompletedProcess[str]:
                self.assertEqual(args[0], resolved_first)
                if args[1] == "--help":
                    alias.unlink()
                    alias.symlink_to(second)
                    return completed(args, stdout=compatible_help)
                return completed(args, stdout="About Cursor CLI\n")

            with patch.object(
                agent_server,
                "cursor_executable_candidates",
                return_value=("agent",),
            ), patch.object(
                agent_server.shutil,
                "which",
                return_value=str(alias),
            ), patch.object(
                agent_server,
                "runtime_command",
                side_effect=command,
            ):
                compatible, _installed, _missing, _error = (
                    agent_server.cursor_executable_resolution()
                )
        self.assertEqual(compatible, resolved_first)

    def test_cursor_auth_parser_uses_combined_stdout_and_stderr(self) -> None:
        compatible_help = (
            "-p --print --output-format stream-json --resume --model --trust "
            "--force --mode plan --list-models"
        )
        responses = [
            completed(["/bin/agent", "--help"], stdout=compatible_help),
            completed(["/bin/agent", "about"], stdout="About Cursor CLI\n"),
            completed(["/bin/agent", "--version"], stdout="2026.08\n"),
            completed(["/bin/agent", "status"], stdout="Cursor status\n", stderr="Authenticated: false\n"),
        ]
        with patch.object(agent_server.shutil, "which", return_value="/bin/agent"), patch.object(
            agent_server, "runtime_command", side_effect=responses
        ):
            diagnostic = agent_server.probe_runtime(agent_server.BACKEND_CURSOR)
        self.assertEqual(diagnostic["status"], "unauthenticated")

    def test_cursor_api_key_readiness_does_not_use_stored_login_status(self) -> None:
        with patch.object(
            agent_server,
            "cursor_executable_resolution",
            return_value=("/bin/agent", "/bin/agent", (), None),
        ), patch.object(
            agent_server,
            "runner_env",
            return_value={"CURSOR_API_KEY": "configured-secret"},
        ), patch.object(
            agent_server,
            "runtime_command",
            side_effect=[
                completed(
                    ["/bin/agent", "--version"],
                    stdout="2026.08.25-3e8eec8\n",
                ),
                completed(
                    ["/bin/agent", "--list-models"],
                    stdout="Auto\n",
                ),
            ],
        ) as command:
            diagnostic = agent_server.probe_runtime(
                agent_server.BACKEND_CURSOR
            )

        self.assertEqual(command.call_count, 2)
        command.assert_any_call(["/bin/agent", "--version"])
        command.assert_any_call(["/bin/agent", "--list-models"])
        self.assertEqual(diagnostic["status"], "ready")
        self.assertTrue(diagnostic["available"])
        self.assertTrue(diagnostic["authenticated"])

    def test_cursor_auth_confirmation_ignores_project_owned_401_text(self) -> None:
        with patch.object(
            agent_server,
            "runner_env",
            return_value={},
        ), patch.object(
            agent_server,
            "runtime_command",
            return_value=completed(
                ["/bin/agent", "status"],
                stdout="Project command failed: 401 Unauthorized\n",
            ),
        ):
            confirmed = agent_server.cursor_auth_failure_confirmed(
                "/bin/agent"
            )

        self.assertFalse(confirmed)

    def test_cursor_api_key_failure_is_ambiguous_not_confirmed_auth(self) -> None:
        with patch.object(
            agent_server,
            "runner_env",
            return_value={"CURSOR_API_KEY": "configured-secret"},
        ), patch.object(
            agent_server,
            "runtime_command",
            return_value=completed(
                ["/bin/agent", "--list-models"],
                returncode=1,
                stderr="Invalid API key",
            ),
        ) as command:
            confirmed = agent_server.cursor_auth_failure_confirmed(
                "/bin/agent"
            )

        self.assertFalse(confirmed)
        command.assert_called_once_with(["/bin/agent", "--list-models"])

    def test_force_refresh_cannot_restore_ready_for_unchanged_bad_api_key(
        self,
    ) -> None:
        agent_server.store_runtime_diagnostic(
            agent_server.runtime_diagnostic_payload(
                agent_server.BACKEND_CURSOR,
                "unauthenticated",
                installed=True,
                authenticated=False,
                executable="/bin/agent",
            )
        )
        with patch.object(
            agent_server,
            "cursor_executable_resolution",
            return_value=("/bin/agent", "/bin/agent", (), None),
        ), patch.object(
            agent_server,
            "runner_env",
            return_value={"CURSOR_API_KEY": "unchanged-bad-secret"},
        ), patch.object(
            agent_server,
            "runtime_command",
            side_effect=[
                completed(
                    ["/bin/agent", "--version"],
                    stdout="2026.08.25-3e8eec8\n",
                ),
                completed(
                    ["/bin/agent", "--list-models"],
                    returncode=1,
                    stderr="Invalid API key",
                ),
            ],
        ):
            diagnostic = agent_server.runtime_diagnostic(
                agent_server.BACKEND_CURSOR,
                force=True,
            )

        self.assertEqual(diagnostic["status"], "error")
        self.assertFalse(diagnostic["available"])
        self.assertIsNone(diagnostic["authenticated"])

    def test_stale_probe_cannot_overwrite_newer_runtime_failure(self) -> None:
        probe_started = threading.Event()
        release_probe = threading.Event()
        result: dict[str, dict] = {}

        def slow_probe(_backend: str) -> dict:
            probe_started.set()
            self.assertTrue(release_probe.wait(timeout=5))
            return agent_server.runtime_diagnostic_payload(
                agent_server.BACKEND_CURSOR,
                "ready",
                installed=True,
                authenticated=True,
                executable="/bin/agent",
            )

        def refresh() -> None:
            result["diagnostic"] = agent_server.runtime_diagnostic(
                agent_server.BACKEND_CURSOR,
                force=True,
            )

        with patch.object(agent_server, "probe_runtime", side_effect=slow_probe):
            thread = threading.Thread(target=refresh)
            thread.start()
            self.assertTrue(probe_started.wait(timeout=5))
            agent_server.record_runtime_failure(
                agent_server.BACKEND_CURSOR,
                "Cursor authentication failed.",
                executable="/bin/agent",
                auth_failure=True,
            )
            release_probe.set()
            thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(result["diagnostic"]["status"], "unauthenticated")
        self.assertEqual(
            agent_server.RUNTIME_DIAGNOSTICS[agent_server.BACKEND_CURSOR][
                "status"
            ],
            "unauthenticated",
        )

    def test_missing_cursor_action_does_not_require_server_restart(self) -> None:
        action = agent_server.runtime_action(
            agent_server.BACKEND_CURSOR,
            "missing",
            executable="cursor-agent",
        )
        self.assertIn("cursor.com/install", action)
        self.assertIn("Recheck CLIs", action)
        self.assertNotIn("restart", action.lower())

    def test_cursor_unauthenticated_action_includes_api_key_option(self) -> None:
        action = agent_server.runtime_action(
            agent_server.BACKEND_CURSOR,
            "unauthenticated",
            executable="cursor-agent",
        )
        self.assertIn("`cursor-agent login`", action)
        self.assertIn("`CURSOR_API_KEY`", action)
        self.assertIn("Recheck CLIs", action)

    def test_cursor_public_diagnostic_does_not_leak_absolute_executable(self) -> None:
        diagnostic = agent_server.runtime_diagnostic_payload(
            agent_server.BACKEND_CURSOR,
            "error",
            installed=True,
            authenticated=None,
            executable="/private/server/bin/agent",
        )
        public = agent_server.public_runtime_diagnostic(diagnostic)
        self.assertNotIn("_executable", public)
        self.assertNotIn("/private/server/bin", json.dumps(public))
        self.assertIn("`agent --version`", public["action"])

    def test_incompatible_cursor_runtime_skips_model_catalog_subprocesses(self) -> None:
        diagnostic = agent_server.runtime_diagnostic_payload(
            agent_server.BACKEND_CURSOR,
            "error",
            installed=True,
            authenticated=None,
        )
        diagnostics = {
            agent_server.BACKEND_CLAUDE: agent_server.runtime_diagnostic_payload(
                agent_server.BACKEND_CLAUDE, "missing", installed=False,
                authenticated=False,
            ),
            agent_server.BACKEND_CODEX: agent_server.runtime_diagnostic_payload(
                agent_server.BACKEND_CODEX, "missing", installed=False,
                authenticated=False,
            ),
            agent_server.BACKEND_CURSOR: diagnostic,
        }
        static = {
            "models": [], "efforts": [], "default_model": None,
            "default_effort": None,
        }
        with patch.object(
            agent_server, "refresh_runtime_diagnostics", return_value=diagnostics
        ), patch.object(
            agent_server, "parse_claude_help_catalog", return_value=dict(static)
        ), patch.object(
            agent_server, "discover_codex_catalog", return_value=dict(static)
        ), patch.object(agent_server, "discover_cursor_catalog") as cursor_catalog:
            catalog = agent_server.discover_runtime_catalog()

        cursor_catalog.assert_not_called()
        self.assertFalse(catalog["backends"]["cursor"]["available"])
        self.assertEqual(
            catalog["backends"]["cursor"]["permission_modes"],
            ["default", "full_access", "plan"],
        )

    def test_codex_model_effort_validation_accepts_supported_ultra(self) -> None:
        self.assertEqual(
            agent_server.normalize_runtime_effort_for_model(
                agent_server.BACKEND_CODEX,
                "gpt-5.6-sol",
                "ultra",
                strict=True,
            ),
            "ultra",
        )

    def test_codex_model_effort_validation_rejects_known_bad_pair(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            agent_server.normalize_runtime_effort_for_model(
                agent_server.BACKEND_CODEX,
                "gpt-5.6-luna",
                "ultra",
                strict=True,
            )
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("gpt-5.6-luna", str(raised.exception.detail))
        self.assertIn("does not support effort ultra", str(raised.exception.detail))

    def test_codex_model_effort_validation_leaves_custom_models_provider_owned(self) -> None:
        self.assertEqual(
            agent_server.normalize_runtime_effort_for_model(
                agent_server.BACKEND_CODEX,
                "custom-provider-model",
                "ultra",
                strict=True,
            ),
            "ultra",
        )

    def test_codex_catalog_preserves_model_scoped_efforts(self) -> None:
        payload = {
            "models": [
                {
                    "slug": "gpt-5.6-sol",
                    "display_name": "GPT-5.6-Sol",
                    "visibility": "list",
                    "supported_in_api": True,
                    "default_reasoning_level": "medium",
                    "supported_reasoning_levels": [
                        {"effort": "medium"},
                        {"effort": "ultra"},
                    ],
                },
                {
                    "slug": "gpt-5.6-luna",
                    "display_name": "GPT-5.6-Luna",
                    "visibility": "list",
                    "supported_in_api": True,
                    "default_reasoning_level": "medium",
                    "supported_reasoning_levels": [
                        {"effort": "medium"},
                        {"effort": "max"},
                    ],
                },
            ]
        }
        with patch.object(
            agent_server,
            "run_catalog_command",
            return_value=json.dumps(payload),
        ), patch.object(
            agent_server,
            "codex_user_config_defaults",
            return_value=("gpt-5.6-sol", "medium", "priority"),
        ):
            catalog = agent_server.discover_codex_catalog()

        self.assertEqual(
            [option["value"] for option in catalog["model_efforts"]["gpt-5.6-sol"]],
            ["medium", "ultra"],
        )
        self.assertEqual(
            [option["value"] for option in catalog["model_efforts"]["gpt-5.6-luna"]],
            ["medium", "max"],
        )

    def test_codex_catalog_default_matches_runtime_fallback(self) -> None:
        payload = {
            "models": [
                {
                    "slug": "gpt-5.6-sol",
                    "display_name": "GPT-5.6-Sol",
                    "visibility": "list",
                    "supported_in_api": True,
                    "default_reasoning_level": "medium",
                    "supported_reasoning_levels": [{"effort": "ultra"}],
                },
                {
                    "slug": agent_server.CODEX_DEFAULT_MODEL,
                    "display_name": "Runtime fallback",
                    "visibility": "list",
                    "supported_in_api": True,
                    "default_reasoning_level": "xhigh",
                    "supported_reasoning_levels": [{"effort": "xhigh"}],
                },
            ]
        }
        with patch.object(
            agent_server,
            "run_catalog_command",
            return_value=json.dumps(payload),
        ), patch.object(
            agent_server,
            "codex_user_config_defaults",
            return_value=("", "", ""),
        ):
            catalog = agent_server.discover_codex_catalog()

        self.assertEqual(catalog["default_model"], agent_server.CODEX_DEFAULT_MODEL)

    def test_codex_catalog_default_stays_truthful_when_runtime_fallback_is_not_discovered(self) -> None:
        payload = {
            "models": [
                {
                    "slug": "gpt-5.6-sol",
                    "display_name": "GPT-5.6-Sol",
                    "visibility": "list",
                    "supported_in_api": True,
                    "default_reasoning_level": "medium",
                    "supported_reasoning_levels": [
                        {"effort": "medium"},
                        {"effort": "ultra"},
                    ],
                },
            ]
        }
        session = {
            "id": "chat",
            "backend": agent_server.BACKEND_CODEX,
            "model": None,
            "effort": None,
        }
        with patch.object(
            agent_server,
            "run_catalog_command",
            return_value=json.dumps(payload),
        ), patch.object(
            agent_server,
            "codex_user_config_defaults",
            return_value=("", "", ""),
        ), patch.object(
            agent_server,
            "CODEX_DEFAULT_MODEL",
            "gpt-5.5",
        ), patch.object(
            agent_server,
            "CODEX_DEFAULT_EFFORT",
            "xhigh",
        ):
            catalog = agent_server.discover_codex_catalog()
            runtime_model, runtime_effort, runtime_service_tier = (
                agent_server.codex_runtime_settings(session)
            )
            command = agent_server.build_codex_cmd(
                "chat",
                session,
                "probe",
                Path("/tmp/current.json"),
            )

        self.assertEqual(catalog["default_model"], runtime_model)
        self.assertEqual(catalog["default_effort"], runtime_effort)
        self.assertEqual(catalog["default_service_tier"] or "", runtime_service_tier)
        self.assertEqual(
            catalog["models"][0]["label"],
            f"Server default ({agent_server.title_model_label(runtime_model)})",
        )
        self.assertEqual(catalog["models"][0]["value"], "")
        self.assertIn(
            "gpt-5.6-sol",
            [option["value"] for option in catalog["models"]],
        )
        self.assertEqual(
            [
                option["value"]
                for option in catalog["model_efforts"][runtime_model]
            ],
            ["low", "medium", "high", "xhigh"],
        )
        self.assertEqual(command[command.index("--model") + 1], runtime_model)
        self.assertIn(f"model_reasoning_effort={runtime_effort}", command)

    def test_transient_provider_failure_keeps_cli_ready(self) -> None:
        agent_server.store_runtime_diagnostic(agent_server.runtime_diagnostic_payload(
            agent_server.BACKEND_CLAUDE,
            "ready",
            installed=True,
            authenticated=True,
            version="2.3.4",
        ))
        agent_server.record_runtime_failure(agent_server.BACKEND_CLAUDE, "529 overloaded")
        snapshot = agent_server.runtime_diagnostics_snapshot()[agent_server.BACKEND_CLAUDE]
        self.assertEqual(snapshot["status"], "ready")
        self.assertIsNotNone(snapshot["last_error"])
        self.assertNotIn("checked_at_epoch", snapshot)

    def test_provider_thread_not_found_does_not_mark_cli_missing(self) -> None:
        agent_server.store_runtime_diagnostic(agent_server.runtime_diagnostic_payload(
            agent_server.BACKEND_CODEX,
            "ready",
            installed=True,
            authenticated=True,
            version="1.2.3",
        ))
        agent_server.record_runtime_failure(
            agent_server.BACKEND_CODEX,
            "No conversation found with session ID: external-thread",
        )
        diagnostic = agent_server.runtime_diagnostics_snapshot()[agent_server.BACKEND_CODEX]
        self.assertEqual(diagnostic["status"], "ready")
        self.assertTrue(diagnostic["installed"])

    def test_spawn_failure_marks_cli_missing(self) -> None:
        agent_server.record_runtime_failure(
            agent_server.BACKEND_CODEX,
            FileNotFoundError(2, "No such file or directory", "codex"),
            spawn_failure=True,
        )
        diagnostic = agent_server.runtime_diagnostics_snapshot()[agent_server.BACKEND_CODEX]
        self.assertEqual(diagnostic["status"], "missing")
        self.assertFalse(diagnostic["installed"])

    def test_claude_catalog_parses_wrapped_effort_levels(self) -> None:
        help_text = """\
  --effort <level>                      Effort level for the current session
                                        (low, medium, high, xhigh, max)
  --exclude-dynamic-system-prompt-sections
"""
        with patch.object(agent_server, "run_catalog_command", return_value=help_text), patch.object(
            agent_server, "claude_supports_effort", return_value=False
        ), patch.object(
            agent_server,
            "discover_claude_provider_models",
            return_value=([], "unavailable"),
        ):
            catalog = agent_server.parse_claude_help_catalog()
        self.assertEqual(
            [option["value"] for option in catalog["efforts"]],
            ["", "low", "medium", "high", "xhigh", "max"],
        )

    def test_claude_catalog_advertises_supported_ultracode_effort(self) -> None:
        help_text = """\
  --effort <level>                      Effort level for the current session
                                        (low, medium, high, xhigh, max)
"""
        with patch.object(agent_server, "run_catalog_command", return_value=help_text), patch.object(
            agent_server, "claude_supports_effort", return_value=True
        ), patch.object(
            agent_server,
            "discover_claude_provider_models",
            return_value=([], "unavailable"),
        ):
            catalog = agent_server.parse_claude_help_catalog()
        self.assertEqual(
            [option["value"] for option in catalog["efforts"]],
            ["", "low", "medium", "high", "xhigh", "max", "ultracode"],
        )

    def test_claude_help_model_parser_keeps_aliases_and_full_name_example(self) -> None:
        help_text = """\
  --model <model>                       Provide an alias for the latest model
                                        (e.g. 'fable', 'opus', or 'sonnet') or
                                        a model's full name (e.g.
                                        'claude-fable-5-1').
  -n, --name <name>                     Set a display name
"""
        self.assertEqual(
            [
                option["value"]
                for option in agent_server.parse_claude_help_model_options(help_text)
            ],
            ["fable", "opus", "sonnet", "claude-fable-5-1"],
        )

    def test_claude_catalog_fallback_includes_current_official_models(self) -> None:
        help_text = """\
  --model <model>                       Provide an alias for the latest model
                                        (e.g. 'fable', 'opus', or 'sonnet')
"""
        with patch.object(agent_server, "run_catalog_command", return_value=help_text), patch.object(
            agent_server, "claude_supports_effort", return_value=False
        ), patch.object(
            agent_server,
            "discover_claude_provider_models",
            return_value=([], "unavailable"),
        ):
            catalog = agent_server.parse_claude_help_catalog()

        by_value = {option["value"]: option for option in catalog["models"]}
        self.assertIn("fable", by_value)
        self.assertIn("opus", by_value)
        self.assertIn("sonnet", by_value)
        self.assertEqual(by_value["claude-fable-5-1"]["label"], "Fable 5.1")
        self.assertEqual(by_value["claude-mythos-5-1"]["availability"], "limited")
        self.assertIn("claude-opus-5", by_value)
        self.assertIn("claude-sonnet-5", by_value)
        self.assertIn("current fallback", catalog["model_source"])

    def test_claude_catalog_uses_account_scoped_models_without_extra_pins(self) -> None:
        provider_options = [
            agent_server.runtime_option("claude-account-model-7", "Account Model 7")
        ]
        help_text = """\
  --model <model>                       Provide an alias for the latest model
                                        (e.g. 'fable', 'opus', or 'sonnet') or
                                        a model's full name (e.g.
                                        'claude-fable-5' or
                                        'anthropic.claude-fable-5')
"""
        with patch.object(agent_server, "run_catalog_command", return_value=help_text), patch.object(
            agent_server, "claude_supports_effort", return_value=False
        ), patch.object(
            agent_server,
            "discover_claude_provider_models",
            return_value=(provider_options, "success"),
        ):
            catalog = agent_server.parse_claude_help_catalog()

        values = [option["value"] for option in catalog["models"]]
        self.assertIn("fable", values)
        self.assertIn("claude-account-model-7", values)
        self.assertNotIn("claude-fable-5-1", values)
        self.assertNotIn("claude-fable-5", values)
        self.assertNotIn("anthropic.claude-fable-5", values)
        self.assertNotIn("claude-opus-4-8[1m]", values)
        self.assertIn("Anthropic Models API", catalog["model_source"])
        self.assertNotIn("current fallback", catalog["model_source"])

    def test_claude_catalog_treats_successful_empty_provider_list_as_authoritative(self) -> None:
        help_text = """\
  --model <model>                       Provide an alias for the latest model
                                        (e.g. 'fable', 'opus', or 'sonnet') or
                                        a full name (e.g. 'claude-fable-5')
"""
        with patch.object(agent_server, "run_catalog_command", return_value=help_text), patch.object(
            agent_server, "claude_supports_effort", return_value=False
        ), patch.object(
            agent_server,
            "discover_claude_provider_models",
            return_value=([], "success"),
        ):
            catalog = agent_server.parse_claude_help_catalog()

        values = [option["value"] for option in catalog["models"]]
        self.assertIn("fable", values)
        self.assertIn("opus", values)
        self.assertIn("sonnet", values)
        self.assertNotIn("claude-fable-5", values)
        self.assertNotIn("claude-fable-5-1", values)
        self.assertNotIn("claude-opus-4-8[1m]", values)
        self.assertIn("Anthropic Models API", catalog["model_source"])
        self.assertNotIn("current fallback", catalog["model_source"])

    def test_claude_models_api_discovery_is_account_scoped_and_bounded(self) -> None:
        payload = json.dumps({
            "data": [
                {"id": "claude-fable-5-1", "display_name": "Claude Fable 5.1"},
                {"id": "not valid whitespace", "display_name": "Invalid"},
            ]
        }).encode("utf-8")
        captured: dict[str, object] = {}

        def run_curl(args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            captured["headers"] = kwargs["input"].decode("utf-8")
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=payload,
                stderr=b"",
            )

        with patch.dict(
            agent_server.os.environ,
            {
                "ANTHROPIC_API_KEY": "test-secret-never-log",
                "ANTHROPIC_BASE_URL": "https://api.anthropic.com",
            },
        ), patch.object(
            agent_server.shutil,
            "which",
            return_value="/usr/bin/curl",
        ), patch.object(
            agent_server.subprocess,
            "run",
            side_effect=run_curl,
        ):
            options, status = agent_server.discover_claude_provider_models()

        self.assertEqual(status, "success")
        self.assertEqual(
            options,
            [{"value": "claude-fable-5-1", "label": "Claude Fable 5.1"}],
        )
        args = captured["args"]
        kwargs = captured["kwargs"]
        self.assertEqual(args[1], "--disable")
        self.assertEqual(args[-1], "https://api.anthropic.com/v1/models?limit=1000")
        self.assertNotIn("--noproxy", args)
        self.assertIn("--max-time", args)
        self.assertIn("--max-filesize", args)
        self.assertEqual(args[args.index("--header") + 1], "@-")
        self.assertNotIn("test-secret-never-log", " ".join(args))
        self.assertIn("x-api-key: test-secret-never-log", captured["headers"])
        for secret_name in agent_server.CLAUDE_PROVIDER_SECRET_ENV_NAMES:
            self.assertNotIn(secret_name, kwargs["env"])
        self.assertLessEqual(kwargs["timeout"], 7.0)

    def test_claude_models_api_is_not_contacted_without_api_key(self) -> None:
        with patch.dict(agent_server.os.environ, {"ANTHROPIC_API_KEY": ""}), patch.object(
            agent_server.shutil,
            "which",
        ) as which:
            self.assertEqual(
                agent_server.discover_claude_provider_models(),
                ([], "unavailable"),
            )
        which.assert_not_called()

    def test_claude_models_api_rejects_non_loopback_plain_http(self) -> None:
        with patch.dict(
            agent_server.os.environ,
            {
                "ANTHROPIC_API_KEY": "test-secret-never-log",
                "ANTHROPIC_BASE_URL": "http://models.example.test",
            },
        ), patch.object(agent_server.shutil, "which") as which, patch.object(
            agent_server.subprocess,
            "run",
        ) as run:
            self.assertEqual(
                agent_server.discover_claude_provider_models(),
                ([], "failed"),
            )
        which.assert_not_called()
        run.assert_not_called()

    def test_claude_models_api_allows_loopback_plain_http(self) -> None:
        result = subprocess.CompletedProcess(
            args=["curl"],
            returncode=0,
            stdout=b'{"data": []}',
            stderr=b"",
        )
        with patch.dict(
            agent_server.os.environ,
            {
                "ANTHROPIC_API_KEY": "test-secret-never-log",
                "ANTHROPIC_BASE_URL": "http://127.0.0.1:8099/v1",
                "ALL_PROXY": "http://proxy.example.test:8080",
                "HTTP_PROXY": "http://proxy.example.test:8080",
            },
        ), patch.object(
            agent_server.shutil,
            "which",
            return_value="/usr/bin/curl",
        ), patch.object(
            agent_server.subprocess,
            "run",
            return_value=result,
        ) as run:
            self.assertEqual(
                agent_server.discover_claude_provider_models(),
                ([], "success"),
            )
        self.assertEqual(
            run.call_args.args[0][-1],
            "http://127.0.0.1:8099/v1/models?limit=1000",
        )
        args = run.call_args.args[0]
        self.assertEqual(args[1], "--disable")
        self.assertEqual(args[args.index("--noproxy") + 1], "*")

    def test_claude_models_api_trickle_has_hard_process_deadline(self) -> None:
        with patch.dict(
            agent_server.os.environ,
            {
                "ANTHROPIC_API_KEY": "test-secret-never-log",
                "ANTHROPIC_BASE_URL": "https://api.anthropic.com",
            },
        ), patch.object(
            agent_server.shutil,
            "which",
            return_value="/usr/bin/curl",
        ), patch.object(
            agent_server.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("curl", 7),
        ) as run:
            self.assertEqual(
                agent_server.discover_claude_provider_models(),
                ([], "failed"),
            )

        args = run.call_args.args[0]
        kwargs = run.call_args.kwargs
        self.assertIn("--max-time", args)
        self.assertLessEqual(float(args[args.index("--max-time") + 1]), 6.0)
        self.assertLessEqual(kwargs["timeout"], 7.0)
        self.assertNotIn("test-secret-never-log", " ".join(args))

    def test_claude_effort_probe_rejects_unknown_values(self) -> None:
        warning = "Warning: Unknown --effort value 'ultracode' - ignoring it and using the default effort."
        with patch.object(agent_server.subprocess, "run", return_value=completed([], stderr=warning)):
            self.assertFalse(agent_server.claude_supports_effort("ultracode"))

    def test_claude_effort_probe_accepts_silent_values(self) -> None:
        with patch.object(agent_server.subprocess, "run", return_value=completed([], stdout="2.1.207 (Claude Code)\n")):
            self.assertTrue(agent_server.claude_supports_effort("ultracode"))

    def test_cursor_catalog_locks_named_models_on_free_plan(self) -> None:
        list_models_output = (
            "Available models\n\n"
            "auto - Auto (default)\n"
            "gpt-5.2 - GPT-5.2\n"
        )
        about_output = (
            "About Cursor CLI\n\n"
            "CLI Version         2026.08.11-e8db854\n"
            "Subscription Tier   Free\n"
            "User Email          user@example.com\n"
        )
        with patch.object(
            agent_server, "run_catalog_command", side_effect=[list_models_output, about_output]
        ):
            catalog = agent_server.discover_cursor_catalog(
                executable="/fake/agent"
            )

        by_value = {option["value"]: option for option in catalog["models"]}
        self.assertNotIn("locked", by_value["auto"])
        self.assertTrue(by_value["gpt-5.2"]["locked"])
        self.assertIn("free plan", by_value["gpt-5.2"]["locked_reason"])
        # The synthetic "Server default" entry mirrors "auto" (the default),
        # so it must stay selectable too - only named models lock.
        self.assertNotIn("locked", by_value[""])

    def test_cursor_catalog_does_not_lock_models_on_paid_plan(self) -> None:
        list_models_output = (
            "Available models\n\n"
            "auto - Auto (default)\n"
            "gpt-5.2 - GPT-5.2\n"
        )
        about_output = (
            "About Cursor CLI\n\n"
            "Subscription Tier   Pro\n"
            "User Email          user@example.com\n"
        )
        with patch.object(
            agent_server, "run_catalog_command", side_effect=[list_models_output, about_output]
        ):
            catalog = agent_server.discover_cursor_catalog(
                executable="/fake/agent"
            )

        for option in catalog["models"]:
            self.assertNotIn("locked", option)

    def test_cursor_catalog_does_not_assume_unknown_tier_is_free(self) -> None:
        list_models_output = "Available models\n\nauto - Auto (default)\ngpt-5.2 - GPT-5.2\n"
        with patch.object(
            agent_server,
            "run_catalog_command",
            side_effect=[list_models_output, RuntimeError("agent about exited 1")],
        ):
            catalog = agent_server.discover_cursor_catalog(
                executable="/fake/agent"
            )

        by_value = {option["value"]: option for option in catalog["models"]}
        self.assertNotIn("locked", by_value["gpt-5.2"])


class RuntimePreflightTests(unittest.IsolatedAsyncioTestCase):
    async def test_unavailable_runtime_fails_before_launch(self) -> None:
        diagnostic = agent_server.runtime_diagnostic_payload(
            agent_server.BACKEND_CODEX,
            "unauthenticated",
            installed=True,
            authenticated=False,
        )
        with patch.object(agent_server, "runtime_diagnostic", return_value=diagnostic):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.ensure_runtime_available(agent_server.BACKEND_CODEX)
        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.detail["code"], "runtime_unavailable")
        self.assertEqual(raised.exception.detail["backend"], "codex")

    async def test_cursor_ready_cache_backfills_one_compatible_executable(self) -> None:
        diagnostic = agent_server.runtime_diagnostic_payload(
            agent_server.BACKEND_CURSOR,
            "ready",
            installed=True,
            authenticated=True,
            version="2026.08.11-e8db854",
        )
        with patch.object(
            agent_server,
            "runtime_diagnostic",
            return_value=diagnostic,
        ), patch.object(
            agent_server,
            "resolve_cursor_executable",
            return_value="/compatible/agent",
        ) as resolve, patch.object(
            agent_server,
            "store_runtime_diagnostic",
        ) as store:
            result = await agent_server.ensure_runtime_available(
                agent_server.BACKEND_CURSOR
            )

        resolve.assert_called_once_with()
        store.assert_called_once()
        self.assertEqual(result["_executable"], "/compatible/agent")

    async def test_cursor_ready_cache_reuses_fenced_executable(self) -> None:
        diagnostic = agent_server.runtime_diagnostic_payload(
            agent_server.BACKEND_CURSOR,
            "ready",
            installed=True,
            authenticated=True,
            version="2026.08.11-e8db854",
            executable="/already-probed/agent",
        )
        with patch.object(
            agent_server,
            "runtime_diagnostic",
            return_value=diagnostic,
        ), patch.object(
            agent_server,
            "resolve_cursor_executable",
        ) as resolve:
            result = await agent_server.ensure_runtime_available(
                agent_server.BACKEND_CURSOR
            )

        resolve.assert_not_called()
        self.assertEqual(result["_executable"], "/already-probed/agent")

    async def test_cursor_ready_cache_without_compatible_binary_fails_closed(
        self,
    ) -> None:
        cached = agent_server.runtime_diagnostic_payload(
            agent_server.BACKEND_CURSOR,
            "ready",
            installed=True,
            authenticated=True,
            version="stale",
        )
        refreshed = agent_server.runtime_diagnostic_payload(
            agent_server.BACKEND_CURSOR,
            "error",
            installed=True,
            authenticated=None,
            version="legacy",
        )
        with patch.object(
            agent_server,
            "runtime_diagnostic",
            side_effect=[cached, refreshed],
        ), patch.object(
            agent_server,
            "resolve_cursor_executable",
            return_value=None,
        ):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.ensure_runtime_available(
                    agent_server.BACKEND_CURSOR
                )

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.detail["backend"], "cursor")


class SessionRuntimeValidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_load_normalizes_legacy_cursor_mode_and_rejects_bad_resume_id(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sessions_file = Path(temporary) / "sessions.json"
            sessions_file.write_text(json.dumps({
                "cursor-chat": {
                    "id": "cursor-chat",
                    "backend": agent_server.BACKEND_CURSOR,
                    "session_id": "invalid cursor id with spaces",
                    "cursor_session_id": "invalid cursor id with spaces",
                    "cursor_permission_mode": "auto_review",
                    "cursor_instruction_hash": "legacy-hash",
                    "cursor_instruction_version": "legacy-version",
                }
            }))
            store = agent_server.SessionStore()
            save = AsyncMock()
            with patch.object(
                agent_server,
                "SESSIONS_FILE",
                sessions_file,
            ), patch.object(
                agent_server,
                "ensure_dirs",
            ), patch.object(
                store,
                "save",
                save,
            ):
                await store.load()

        session = store.sessions["cursor-chat"]
        self.assertEqual(session["cursor_permission_mode"], "default")
        self.assertIsNone(session["session_id"])
        self.assertIsNone(session["cursor_session_id"])
        self.assertNotIn("cursor_instruction_hash", session)
        self.assertNotIn("cursor_instruction_version", session)
        save.assert_awaited()

    async def test_update_rejects_incompatible_effort_without_mutating_session(self) -> None:
        store = agent_server.SessionStore()
        store.sessions = {
            "chat": {
                "id": "chat",
                "backend": agent_server.BACKEND_CODEX,
                "model": "gpt-5.6-luna",
                "effort": "medium",
                "folder": "General",
            }
        }
        with patch.object(store, "save", AsyncMock()):
            with self.assertRaises(HTTPException):
                await store.update("chat", {"effort": "ultra"})

        self.assertEqual(store.sessions["chat"]["effort"], "medium")

    async def test_model_only_change_clears_existing_incompatible_effort(self) -> None:
        store = agent_server.SessionStore()
        store.sessions = {
            "chat": {
                "id": "chat",
                "backend": agent_server.BACKEND_CODEX,
                "model": "gpt-5.6-sol",
                "effort": "ultra",
                "folder": "General",
            }
        }
        with patch.object(store, "save", AsyncMock()):
            updated = await store.update("chat", {"model": "gpt-5.6-luna"})

        self.assertEqual(updated["model"], "gpt-5.6-luna")
        self.assertIsNone(updated["effort"])

    async def test_explicit_incompatible_model_effort_pair_is_rejected(self) -> None:
        store = agent_server.SessionStore()
        store.sessions = {
            "chat": {
                "id": "chat",
                "backend": agent_server.BACKEND_CODEX,
                "model": "gpt-5.6-sol",
                "effort": "ultra",
                "folder": "General",
            }
        }
        with patch.object(store, "save", AsyncMock()):
            with self.assertRaises(HTTPException):
                await store.update(
                    "chat",
                    {"model": "gpt-5.6-luna", "effort": "ultra"},
                )

        self.assertEqual(store.sessions["chat"]["model"], "gpt-5.6-sol")
        self.assertEqual(store.sessions["chat"]["effort"], "ultra")

    async def test_supported_ultra_pair_is_persisted(self) -> None:
        store = agent_server.SessionStore()
        store.sessions = {
            "chat": {
                "id": "chat",
                "backend": agent_server.BACKEND_CODEX,
                "model": "gpt-5.6-sol",
                "effort": "medium",
                "folder": "General",
            }
        }
        save = AsyncMock()
        with patch.object(store, "save", save):
            updated = await store.update("chat", {"effort": "ultra"})

        self.assertEqual(updated["effort"], "ultra")
        save.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
