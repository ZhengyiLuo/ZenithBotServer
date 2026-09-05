import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import agent_server


class TerminalShellInitializationTests(unittest.TestCase):
    def test_tmux_bootstrap_environment_allowlists_and_drops_server_secrets(self) -> None:
        with patch.dict(
            agent_server.os.environ,
            {
                "HOME": "/home/user",
                "USER": "user",
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "AGENTSDOCK_AGENT_TOKEN": "admin-a",
                "ZENITHDOCK_AGENT_TOKEN": "admin-b",
                "ZENITHBOT_AGENT_TOKEN": "admin-c",
                "AGENTSDOCK_PUBLISH_TOKEN": "publish",
                "AGENTSDOCK_PROVIDER_AUTHORITY_FILE": "/tmp/authority",
                "HTTPS_PROXY": "https://secret-proxy.invalid",
            },
            clear=True,
        ), patch.object(
            agent_server,
            "server_update_runner_environment",
            return_value={"XDG_RUNTIME_DIR": "/run/user/1000"},
        ):
            environment = agent_server.tmux_bootstrap_environment()

        self.assertEqual(environment["HOME"], "/home/user")
        self.assertEqual(environment["XDG_RUNTIME_DIR"], "/run/user/1000")
        for name in (*agent_server.PROVIDER_SECRET_ENV_NAMES, "HTTPS_PROXY"):
            self.assertNotIn(name, environment)

    def test_existing_tmux_daemon_global_environment_is_scrubbed(self) -> None:
        with patch.object(
            agent_server,
            "tmux_server_pid",
            return_value=4321,
        ), patch.object(
            agent_server,
            "run_tmux",
            side_effect=lambda args, **_kwargs: subprocess.CompletedProcess(
                args,
                0,
                stdout="zd_one\nother\n" if args[0] == "list-sessions" else "",
                stderr="",
            ),
        ) as run_tmux:
            agent_server.scrub_tmux_global_secret_environment()

        commands = [call.args[0] for call in run_tmux.call_args_list]
        rendered = " ; ".join(" ".join(command) for command in commands)
        for name in agent_server.PROVIDER_SECRET_ENV_NAMES:
            self.assertIn(f"set-environment -gu {name}", rendered)
            self.assertIn(f"set-environment -t zd_one -u {name}", rendered)
            self.assertIn(f"set-environment -t other -u {name}", rendered)

    def test_terminal_attach_client_does_not_inherit_server_secrets(self) -> None:
        inherited = {
            name: f"secret-{index}"
            for index, name in enumerate(agent_server.PROVIDER_SECRET_ENV_NAMES)
        }
        captured: dict[str, str] = {}

        def popen(*_args, env: dict[str, str], **_kwargs):
            captured.update(env)
            return SimpleNamespace(pid=1234)

        with (
            patch.dict(agent_server.os.environ, inherited, clear=False),
            patch.dict(
                agent_server.STORE.sessions,
                {"chat": {"id": "chat", "cwd": "/tmp"}},
            ),
            patch.object(
                agent_server,
                "ensure_terminal_session",
                return_value={"name": "zd_chat", "cwd": "/tmp"},
            ),
            patch.object(agent_server.pty, "openpty", return_value=(10, 11)),
            patch.object(agent_server, "set_pty_dimensions"),
            patch.object(agent_server.subprocess, "Popen", side_effect=popen),
            patch.object(agent_server.os, "close"),
            patch.object(agent_server.os, "set_blocking") as set_blocking,
            patch.object(agent_server, "tmux_bin", return_value="tmux"),
        ):
            agent_server.spawn_terminal_client("chat", "/tmp", 80, 24)

        set_blocking.assert_called_once_with(10, False)
        for name in agent_server.PROVIDER_SECRET_ENV_NAMES:
            self.assertNotIn(name, captured)

    def test_shell_validation_rejects_disabled_relative_directory_and_null_paths(self) -> None:
        self.assertIsNone(agent_server.valid_terminal_login_shell("/usr/sbin/nologin"))
        self.assertIsNone(agent_server.valid_terminal_login_shell("relative/bash"))
        self.assertIsNone(agent_server.valid_terminal_login_shell("~/bin/bash"))
        self.assertIsNone(agent_server.valid_terminal_login_shell("/"))
        self.assertIsNone(agent_server.valid_terminal_login_shell("/bin/bash\x00suffix"))

    def test_account_shell_is_resolved_from_passwd_not_inherited_shell(self) -> None:
        validate = lambda value: value if value == "/bin/bash" else None
        with patch.object(
            agent_server.pwd,
            "getpwuid",
            return_value=SimpleNamespace(pw_shell="/bin/bash"),
        ), patch.object(
            agent_server,
            "valid_terminal_login_shell",
            side_effect=validate,
        ), patch.dict(agent_server.os.environ, {"SHELL": "/bin/sh"}):
            self.assertEqual(agent_server.resolve_terminal_login_shell(), "/bin/bash")

    def test_disabled_account_shell_fails_closed(self) -> None:
        with patch.object(
            agent_server.pwd,
            "getpwuid",
            return_value=SimpleNamespace(pw_shell="/usr/sbin/nologin"),
        ):
            with self.assertRaises(agent_server.HTTPException) as raised:
                agent_server.resolve_terminal_login_shell()

        self.assertEqual(raised.exception.status_code, 503)
        self.assertIn("disabled login shell", str(raised.exception.detail))

    def test_invalid_explicit_account_shell_does_not_grant_a_fallback_shell(self) -> None:
        with patch.object(
            agent_server.pwd,
            "getpwuid",
            return_value=SimpleNamespace(pw_shell="/missing/account-shell"),
        ), patch.object(
            agent_server,
            "valid_terminal_login_shell",
            return_value=None,
        ) as validate:
            with self.assertRaises(agent_server.HTTPException) as raised:
                agent_server.resolve_terminal_login_shell()

        self.assertEqual(raised.exception.status_code, 503)
        self.assertIn("configured login shell is unavailable", str(raised.exception.detail))
        validate.assert_called_once_with("/missing/account-shell")

    def test_missing_account_record_uses_validated_fallback(self) -> None:
        def validate(value: str | None) -> str | None:
            return "/bin/zsh" if value == "/bin/zsh" else None

        with patch.object(agent_server.pwd, "getpwuid", side_effect=KeyError), patch.object(
            agent_server,
            "valid_terminal_login_shell",
            side_effect=validate,
        ):
            self.assertEqual(agent_server.resolve_terminal_login_shell(), "/bin/zsh")

    def test_blank_account_shell_uses_validated_fallback(self) -> None:
        def validate(value: str | None) -> str | None:
            return "/bin/bash" if value == "/bin/bash" else None

        with patch.object(
            agent_server.pwd,
            "getpwuid",
            return_value=SimpleNamespace(pw_shell="   "),
        ), patch.object(
            agent_server,
            "valid_terminal_login_shell",
            side_effect=validate,
        ):
            self.assertEqual(agent_server.resolve_terminal_login_shell(), "/bin/bash")

    def test_session_path_enriches_and_deduplicates_minimal_path(self) -> None:
        with patch.object(
            agent_server,
            "runner_env",
            return_value={"PATH": "/usr/bin:/bin:/usr/bin"},
        ):
            entries = agent_server.terminal_session_path().split(agent_server.os.pathsep)

        self.assertEqual(entries.count("/usr/bin"), 1)
        self.assertEqual(entries.count("/bin"), 1)
        self.assertIn("/usr/local/bin", entries)
        self.assertIn("/usr/sbin", entries)
        self.assertIn("/sbin", entries)

    def test_new_session_uses_login_shell_and_scoped_shell_defaults(self) -> None:
        session_id = "terminal-shell-test"
        session_name = agent_server.terminal_session_name(session_id)
        calls: list[tuple[list[str], bool]] = []

        def fake_tmux(
            args: list[str],
            *,
            check: bool = True,
            timeout: float = 0,
        ) -> subprocess.CompletedProcess[str]:
            del timeout
            calls.append((args, check))
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        with patch.dict(
            agent_server.STORE.sessions,
            {session_id: {"id": session_id, "cwd": "/workspace", "archived": False}},
        ), patch.object(
            agent_server,
            "tmux_session_exists",
            return_value=False,
        ), patch.object(
            agent_server,
            "existing_cwd",
            return_value="/workspace",
        ), patch.object(
            agent_server,
            "resolve_terminal_login_shell",
            return_value="/bin/bash",
        ), patch.object(
            agent_server,
            "terminal_session_path",
            return_value="/home/user/.local/bin:/usr/bin:/bin",
        ), patch.object(
            agent_server,
            "run_tmux",
            side_effect=fake_tmux,
        ), patch.object(
            agent_server,
            "terminal_snapshot",
            return_value={"name": session_name},
        ):
            agent_server.ensure_terminal_session(session_id)

        commands = [args for args, _check in calls]
        new_session = next(args for args in commands if args[0] == "new-session")
        self.assertEqual(
            new_session[-1],
            "SHELL=/bin/bash PATH=/home/user/.local/bin:/usr/bin:/bin "
            "exec /bin/bash -l",
        )
        self.assertIn(["set-environment", "-t", session_name, "SHELL", "/bin/bash"], commands)
        self.assertIn(
            [
                "set-environment",
                "-t",
                session_name,
                "PATH",
                "/home/user/.local/bin:/usr/bin:/bin",
            ],
            commands,
        )
        core_commands = {
            "SHELL": ["set-environment", "-t", session_name, "SHELL", "/bin/bash"],
            "PATH": [
                "set-environment",
                "-t",
                session_name,
                "PATH",
                "/home/user/.local/bin:/usr/bin:/bin",
            ],
            "default-shell": ["set-option", "-t", session_name, "default-shell", "/bin/bash"],
            "default-command": [
                "set-option",
                "-t",
                session_name,
                "default-command",
                "exec /bin/bash -l",
            ],
        }
        checks_by_command = {tuple(args): check for args, check in calls}
        for command in core_commands.values():
            self.assertTrue(checks_by_command[tuple(command)])
        self.assertFalse(any("-g" in args for args in commands))
        self.assertIn(["set-option", "-t", session_name, "default-shell", "/bin/bash"], commands)
        self.assertIn(
            [
                "set-option",
                "-t",
                session_name,
                "default-command",
                "exec /bin/bash -l",
            ],
            commands,
        )

    def test_existing_session_is_reconfigured_without_respawning_active_pane(self) -> None:
        session_id = "existing-terminal-shell-test"
        calls: list[list[str]] = []

        def fake_tmux(
            args: list[str],
            *,
            check: bool = True,
            timeout: float = 0,
        ) -> subprocess.CompletedProcess[str]:
            del check, timeout
            calls.append(args)
            stdout = "1\n" if "show-options" in args else ""
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

        with patch.dict(
            agent_server.STORE.sessions,
            {session_id: {"id": session_id, "cwd": "/workspace", "archived": False}},
        ), patch.object(
            agent_server,
            "tmux_session_exists",
            return_value=True,
        ), patch.object(
            agent_server,
            "resolve_terminal_login_shell",
            return_value="/bin/bash",
        ), patch.object(
            agent_server,
            "terminal_session_path",
            return_value="/usr/bin:/bin",
        ), patch.object(
            agent_server,
            "run_tmux",
            side_effect=fake_tmux,
        ), patch.object(
            agent_server,
            "terminal_snapshot",
            return_value={},
        ):
            agent_server.ensure_terminal_session(session_id)

        self.assertFalse(
            any(args[0] in {"new-session", "respawn-pane", "send-keys"} for args in calls)
        )
        self.assertTrue(any(args[-2:] == ["default-shell", "/bin/bash"] for args in calls))

    def test_session_shell_configuration_failure_is_not_silenced(self) -> None:
        failure = agent_server.HTTPException(status_code=500, detail="tmux rejected option")
        with patch.object(agent_server, "run_tmux", side_effect=failure):
            with self.assertRaises(agent_server.HTTPException) as raised:
                agent_server.configure_terminal_session_shell(
                    "zd_chat",
                    "/bin/bash",
                    "/usr/bin:/bin",
                )

        self.assertIs(raised.exception, failure)


class TerminalHistoryScrollingTests(unittest.TestCase):
    session_id = "terminal-history-test"

    def run_scroll(
        self,
        delta: int,
        *,
        initially_in_mode: bool,
        hidden_entry_returncode: int = 0,
        managed: bool = False,
    ) -> tuple[bool, list[list[str]]]:
        calls: list[list[str]] = []
        in_mode = initially_in_mode

        def fake_tmux(
            args: list[str],
            *,
            check: bool = True,
            timeout: float = 0,
        ) -> subprocess.CompletedProcess[str]:
            nonlocal in_mode
            del check, timeout
            calls.append(args)
            if args[0] == "display-message":
                return subprocess.CompletedProcess(args, 0, stdout=f"{int(in_mode)}\n", stderr="")
            if args[:2] == ["copy-mode", "-eH"]:
                if hidden_entry_returncode == 0:
                    in_mode = True
                return subprocess.CompletedProcess(args, hidden_entry_returncode, stdout="", stderr="")
            if args[:2] == ["copy-mode", "-e"]:
                in_mode = True
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        with patch.dict(
            agent_server.STORE.sessions,
            {self.session_id: {"id": self.session_id, "archived": False}},
        ), patch.object(
            agent_server,
            "tmux_session_exists",
            return_value=True,
        ), patch.object(
            agent_server,
            "run_tmux",
            side_effect=fake_tmux,
        ):
            result = agent_server.scroll_terminal_history(
                self.session_id,
                delta,
                managed=managed,
            )

        return result, calls

    def test_upward_scroll_enters_copy_mode_without_top_row_indicator(self) -> None:
        result, calls = self.run_scroll(-6, initially_in_mode=False)
        name = agent_server.terminal_session_name(self.session_id)

        self.assertTrue(result)
        self.assertIn(["copy-mode", "-eH", "-t", name], calls)
        self.assertNotIn(["copy-mode", "-e", "-t", name], calls)
        self.assertIn(["send-keys", "-X", "-N", "6", "-t", name, "scroll-up"], calls)

    def test_upward_scroll_falls_back_for_tmux_without_hidden_indicator_support(self) -> None:
        result, calls = self.run_scroll(
            -6,
            initially_in_mode=False,
            hidden_entry_returncode=1,
        )
        name = agent_server.terminal_session_name(self.session_id)

        self.assertTrue(result)
        self.assertIn(["copy-mode", "-eH", "-t", name], calls)
        self.assertIn(["copy-mode", "-e", "-t", name], calls)
        self.assertIn(["send-keys", "-X", "-N", "6", "-t", name, "scroll-up"], calls)

    def test_upward_scroll_reuses_existing_copy_mode(self) -> None:
        result, calls = self.run_scroll(-3, initially_in_mode=True)

        self.assertFalse(result)
        self.assertFalse(any(args[0] == "copy-mode" for args in calls))
        self.assertTrue(any(args[-1] == "scroll-up" for args in calls))

    def test_repeated_scroll_preserves_app_owned_copy_mode(self) -> None:
        result, calls = self.run_scroll(-3, initially_in_mode=True, managed=True)

        self.assertTrue(result)
        self.assertFalse(any(args[0] == "copy-mode" for args in calls))
        self.assertTrue(any(args[-1] == "scroll-up" for args in calls))

    def test_downward_scroll_only_moves_when_copy_mode_is_active(self) -> None:
        active_result, active_calls = self.run_scroll(
            4,
            initially_in_mode=True,
            managed=True,
        )
        user_mode_result, user_mode_calls = self.run_scroll(4, initially_in_mode=True)
        inactive_result, inactive_calls = self.run_scroll(4, initially_in_mode=False)

        self.assertTrue(active_result)
        self.assertTrue(any(args[-1] == "scroll-down" for args in active_calls))
        self.assertFalse(user_mode_result)
        self.assertTrue(any(args[-1] == "scroll-down" for args in user_mode_calls))
        self.assertFalse(inactive_result)
        self.assertFalse(any(args[-1] == "scroll-down" for args in inactive_calls))


if __name__ == "__main__":
    unittest.main()
