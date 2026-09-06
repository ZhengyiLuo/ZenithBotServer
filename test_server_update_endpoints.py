import asyncio
import hashlib
import os
import sqlite3
import tempfile
import threading
import unittest
from collections import deque
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import agent_server
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient


class ServerUpdateEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_update_endpoint_direct_invocation_repeats_native_auth(self):
        request = Request({
            "type": "http",
            "method": "POST",
            "path": "/api/admin/update/start",
            "headers": [(b"authorization", b"Bearer test-secret")],
            "query_string": b"",
            "scheme": "http",
            "server": ("127.0.0.1", 7850),
            "client": ("127.0.0.1", 41000),
        })
        with patch.object(agent_server, "AGENT_TOKEN", "test-secret"):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.start_server_update_endpoint(
                    agent_server.ServerUpdateRequest(
                        version="1.1.0",
                        expected_server_identity="server-test",
                        expected_server_instance_id="instance-test",
                    ),
                    request,
                )

        self.assertEqual(raised.exception.status_code, 401)

    def test_update_admin_routes_reject_query_credentials_before_body_parsing(self):
        cases = (
            ("GET", "/api/admin/update?token=test-secret", None),
            ("POST", "/api/admin/update/check?token=test-secret", b"{"),
            ("POST", "/api/admin/update/start?token=test-secret", b"{"),
            ("POST", "/api/admin/update/cancel?token=test-secret", b"{"),
        )
        with patch.object(agent_server, "AGENT_TOKEN", "test-secret"):
            client = TestClient(agent_server.app)
            for method, path, body in cases:
                with self.subTest(method=method, path=path):
                    response = client.request(
                        method,
                        path,
                        content=body,
                        headers=(
                            {"Content-Type": "application/json"}
                            if body is not None
                            else None
                        ),
                    )

                    self.assertEqual(response.status_code, 401)

    def test_update_admin_routes_reject_browser_origins_before_body_parsing(self):
        cases = (
            ("GET", "/api/admin/update", None),
            ("POST", "/api/admin/update/check", b"{"),
            ("POST", "/api/admin/update/start", b"{"),
            ("POST", "/api/admin/update/cancel", b"{"),
        )
        with patch.object(agent_server, "AGENT_TOKEN", "test-secret"):
            client = TestClient(agent_server.app)
            for method, path, body in cases:
                with self.subTest(method=method, path=path):
                    response = client.request(
                        method,
                        path,
                        content=body,
                        headers={
                            "Origin": "https://attacker.example",
                            "X-AgentsDock-Token": "test-secret",
                            **(
                                {"Content-Type": "application/json"}
                                if body is not None
                                else {}
                            ),
                        },
                    )

                    self.assertEqual(response.status_code, 403)

    def test_update_admin_routes_require_exactly_one_supported_token_header(self):
        cases = (
            [("Authorization", "Bearer test-secret")],
            [
                ("X-AgentsDock-Token", "test-secret"),
                ("X-AgentsDock-Token", "test-secret"),
            ],
            [
                ("X-AgentsDock-Token", "test-secret"),
                ("X-ZenithDock-Token", "test-secret"),
            ],
        )
        with patch.object(agent_server, "AGENT_TOKEN", "test-secret"):
            client = TestClient(agent_server.app)
            for headers in cases:
                with self.subTest(headers=headers):
                    response = client.get(
                        "/api/admin/update",
                        headers=headers,
                    )

                    self.assertEqual(response.status_code, 401)

    def test_update_admin_routes_bound_body_before_model_parsing(self):
        with patch.object(agent_server, "AGENT_TOKEN", "test-secret"):
            client = TestClient(agent_server.app)
            response = client.post(
                "/api/admin/update/start",
                headers={
                    "X-AgentsDock-Token": "test-secret",
                    "Content-Type": "application/json",
                    "Content-Length": str(
                        agent_server.PRIVILEGED_NATIVE_UPDATE_MAX_BODY_BYTES + 1
                    ),
                },
                content=b"{",
            )

        self.assertEqual(response.status_code, 413)

    def test_update_status_and_cancel_keep_legacy_mobile_header_and_unbound_shape(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "AGENT_TOKEN", "test-secret"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(
                 agent_server,
                 "schedule_rebuilt_queued_turns",
                 return_value=0,
             ):
            pending = agent_server.write_fresh_server_update_status(
                phase=agent_server.SERVER_UPDATE_PENDING_PHASE,
                schedule_id="a" * 32,
                target_version="1.1.0",
                latest_version="1.1.0",
                track="stable",
                when_idle=True,
                cancelable=True,
            )
            client = TestClient(agent_server.app)

            canonical_status_response = client.get(
                "/api/admin/update",
                headers={"X-AgentsDock-Token": "test-secret"},
            )
            status_response = client.get(
                "/api/admin/update",
                headers={"X-ZenithDock-Token": "test-secret"},
            )
            cancel_response = client.post(
                "/api/admin/update/cancel",
                headers={"X-ZenithDock-Token": "test-secret"},
                json={"schedule_id": pending["schedule_id"]},
            )

        self.assertEqual(canonical_status_response.status_code, 200)
        self.assertEqual(canonical_status_response.json()["phase"], "pending")
        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(status_response.json()["phase"], "pending")
        self.assertEqual(cancel_response.status_code, 200)
        self.assertEqual(cancel_response.json()["phase"], "available")

    def test_update_check_and_start_require_exact_live_target(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "AGENT_TOKEN", "test-secret"), \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(agent_server, "SERVER_INSTANCE_ID", "instance-test"), \
             patch.object(agent_server, "server_identity", return_value="server-test"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(
                 agent_server,
                 "signed_release_manifest",
                 AsyncMock(return_value={"version": "1.0.0"}),
             ):
            client = TestClient(agent_server.app)
            headers = {"X-AgentsDock-Token": "test-secret"}

            missing_check = client.post(
                "/api/admin/update/check",
                headers=headers,
                json={"track": "stable"},
            )
            missing_start = client.post(
                "/api/admin/update/start",
                headers=headers,
                json={"version": "1.0.0", "track": "stable"},
            )
            bound_check = client.post(
                "/api/admin/update/check",
                headers=headers,
                json={
                    "track": "stable",
                    "expected_server_identity": "server-test",
                    "expected_server_instance_id": "instance-test",
                },
            )
            bound_start = client.post(
                "/api/admin/update/start",
                headers=headers,
                json={
                    "version": "1.0.0",
                    "track": "stable",
                    "expected_server_identity": "server-test",
                    "expected_server_instance_id": "instance-test",
                },
            )

        self.assertEqual(missing_check.status_code, 400)
        self.assertEqual(missing_start.status_code, 400)
        self.assertEqual(bound_check.status_code, 200)
        self.assertEqual(bound_start.status_code, 200)

    def test_agents_server_systemd_cgroup_handles_unified_and_legacy_paths(self):
        paths = (
            "/user.slice/user-1000.slice/user@1000.service/app.slice/agents-server.service",
            "/unrelated",
        )
        with patch.object(agent_server, "process_cgroup_paths", return_value=paths):
            cgroup = agent_server.agents_server_systemd_cgroup(123)

        self.assertEqual(cgroup, paths[0])
        self.assertTrue(agent_server.cgroup_is_within(f"{cgroup}/child", cgroup))
        self.assertFalse(agent_server.cgroup_is_within("/agents-server.service-old", cgroup))

    def test_managed_update_rejects_tmux_inside_service_cgroup_structurally(self):
        cgroup = "/user.slice/user@1000.service/app.slice/agents-server.service"
        with patch.object(agent_server, "agents_server_systemd_cgroup", return_value=cgroup), \
             patch.object(agent_server, "tmux_server_pid", return_value=4242), \
             patch.object(agent_server, "process_cgroup_paths", return_value=(cgroup,)):
            with self.assertRaises(HTTPException) as raised:
                agent_server.ensure_managed_update_tmux_isolated()

        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(raised.exception.detail["code"], "unsafe_update_tmux_cgroup")
        self.assertTrue(raised.exception.detail["retryable"])
        self.assertIn("terminated by the restart", raised.exception.detail["message"])
        self.assertIn("login shell", raised.exception.detail["action"])

    def test_managed_update_preserves_non_systemd_and_macos_behavior(self):
        with patch.object(agent_server, "agents_server_systemd_cgroup", return_value=None), \
             patch.object(agent_server, "tmux_server_pid") as tmux_pid:
            agent_server.ensure_managed_update_tmux_isolated()

        tmux_pid.assert_not_called()

    def test_tmux_guard_does_not_false_open_when_service_appears_on_reprobe(self):
        cgroup = "/user.slice/user@1000.service/app.slice/agents-server.service"
        server_pid = os.getpid()
        paths = {
            server_pid: (cgroup,),
            4242: ("/user.slice/user@1000.service/app.slice/updater.scope",),
        }
        with patch.object(agent_server.sys, "platform", "linux"), \
             patch.object(agent_server, "agents_server_systemd_cgroup", return_value=None), \
             patch.object(agent_server, "linux_process_ids", return_value=(server_pid,)), \
             patch.object(
                 agent_server,
                 "process_cgroup_paths",
                 side_effect=lambda pid: paths[pid],
             ), \
             patch.object(agent_server, "tmux_server_pid", return_value=4242):
            verified = agent_server.ensure_managed_update_tmux_isolated()

        self.assertEqual(verified, cgroup)

    def test_service_cgroup_probe_fails_closed_on_a_stubborn_descendant(self):
        cgroup = "/user.slice/user@1000.service/app.slice/agents-server.service"
        server_pid = os.getpid()
        paths = {
            server_pid: (cgroup,),
            4242: (cgroup,),
            5151: ("/user.slice/user@1000.service/app.slice/other.service",),
        }
        with patch.object(agent_server.sys, "platform", "linux"), \
             patch.object(
                 agent_server,
                 "linux_process_ids",
                 return_value=tuple(paths),
             ), \
             patch.object(
                 agent_server,
                 "process_cgroup_paths",
                 side_effect=lambda pid: paths[pid],
             ):
            state = agent_server.managed_update_service_cgroup_state(
                service_cgroup=cgroup,
            )
            with self.assertRaises(HTTPException) as raised:
                agent_server.ensure_managed_update_service_cgroup_clear(
                    service_cgroup=cgroup,
                )

        self.assertFalse(state["safe"])
        self.assertEqual(state["unknown_descendant_count"], 1)
        self.assertNotIn("4242", str(raised.exception.detail))
        self.assertNotIn(cgroup, str(raised.exception.detail))
        self.assertEqual(
            raised.exception.detail["code"],
            "unsafe_update_service_cgroup",
        )

    def test_service_cgroup_probe_fails_closed_when_proc_is_unavailable(self):
        cgroup = "/user.slice/user@1000.service/app.slice/agents-server.service"
        with patch.object(agent_server.sys, "platform", "linux"), \
             patch.object(agent_server, "linux_process_ids", return_value=None):
            state = agent_server.managed_update_service_cgroup_state(
                service_cgroup=cgroup,
            )

        self.assertFalse(state["safe"])
        self.assertIsNone(state["unknown_descendant_count"])
        public = agent_server.public_managed_update_service_cgroup_state(state)
        self.assertEqual(public, {
            "safe": False,
            "unknown_descendant_count": None,
            "inspection": "process-list-unavailable",
        })

    def test_service_cgroup_probe_fails_closed_on_unreadable_live_membership(self):
        cgroup = "/user.slice/user@1000.service/app.slice/agents-server.service"
        server_pid = os.getpid()
        with patch.object(agent_server.sys, "platform", "linux"), \
             patch.object(
                 agent_server,
                 "linux_process_ids",
                 return_value=(server_pid, 4242),
             ), \
             patch.object(
                 agent_server,
                 "process_cgroup_paths",
                 side_effect=lambda pid: (cgroup,) if pid == server_pid else (),
             ), \
             patch.object(
                 agent_server,
                 "linux_process_still_exists",
                 return_value=True,
             ):
            state = agent_server.managed_update_service_cgroup_state(
                service_cgroup=cgroup,
            )

        self.assertFalse(state["safe"])
        self.assertIsNone(state["unknown_descendant_count"])
        self.assertEqual(state["inspection"], "process-cgroup-unavailable")

    async def test_update_quiesce_orders_terminal_drain_before_final_proof(self):
        cgroup = "/user.slice/user@1000.service/app.slice/agents-server.service"
        order: list[str] = []
        terminal_attachments = MagicMock()

        async def close_terminals():
            order.append("terminals")
            return 2

        async def close_providers():
            order.append("providers")

        async def prove_empty(*, service_cgroup):
            self.assertEqual(service_cgroup, cgroup)
            order.append("cgroup")
            return {
                "safe": True,
                "unknown_descendant_count": 0,
                "inspection": "verified",
            }

        terminal_attachments.close_admission_and_all = close_terminals
        with patch.object(
            agent_server,
            "TERMINAL_ATTACHMENTS",
            terminal_attachments,
        ), patch.object(
            agent_server,
            "close_managed_update_provider_managers",
            side_effect=close_providers,
        ), patch.object(
            agent_server,
            "wait_for_managed_update_service_cgroup_clear",
            side_effect=prove_empty,
        ):
            await agent_server.quiesce_managed_update_service_cgroup(
                service_cgroup=cgroup,
            )

        self.assertEqual(order, ["terminals", "providers", "cgroup"])

    async def test_service_cgroup_settle_rechecks_until_verified_empty(self):
        cgroup = "/user.slice/user@1000.service/app.slice/agents-server.service"
        blocked = HTTPException(
            status_code=409,
            detail=agent_server.unsafe_update_service_cgroup_detail({
                "unknown_descendant_count": 1,
            }),
        )
        verified = {
            "safe": True,
            "unknown_descendant_count": 0,
            "inspection": "verified",
        }
        with patch.object(
            agent_server,
            "ensure_managed_update_service_cgroup_clear",
            side_effect=[blocked, verified],
        ) as proof, patch.object(
            agent_server,
            "MANAGED_UPDATE_CGROUP_SETTLE_INTERVAL_SECONDS",
            0.001,
        ), patch.object(
            agent_server,
            "MANAGED_UPDATE_CGROUP_SETTLE_TIMEOUT_SECONDS",
            1.0,
        ):
            state = await agent_server.wait_for_managed_update_service_cgroup_clear(
                service_cgroup=cgroup,
            )

        self.assertEqual(state, verified)
        self.assertEqual(proof.call_count, 2)

    async def test_provider_quiesce_has_a_bounded_retryable_timeout(self):
        never = asyncio.Event()

        async def block_forever():
            await never.wait()

        with patch.object(
            agent_server,
            "close_claude_sdk_manager",
            side_effect=block_forever,
        ), patch.object(
            agent_server,
            "close_codex_app_server_manager",
            side_effect=block_forever,
        ), patch.object(
            agent_server,
            "MANAGED_UPDATE_PROVIDER_QUIESCE_TIMEOUT_SECONDS",
            0.01,
        ):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.close_managed_update_provider_managers()

        self.assertEqual(raised.exception.status_code, 504)
        self.assertEqual(
            raised.exception.detail["code"],
            "provider_quiesce_timeout",
        )
        self.assertTrue(raised.exception.detail["retryable"])

    def test_service_cgroup_probe_distinguishes_nonservice_from_unreadable_self_cgroup(self):
        with patch.object(agent_server.sys, "platform", "linux"), \
             patch.object(agent_server, "agents_server_systemd_cgroup", return_value=None), \
             patch.object(agent_server, "process_cgroup_paths", return_value=()):
            unavailable = agent_server.managed_update_service_cgroup_state()

        self.assertEqual(
            agent_server.public_managed_update_service_cgroup_state(unavailable),
            {
                "safe": False,
                "unknown_descendant_count": None,
                "inspection": "self-cgroup-unavailable",
            },
        )

        with patch.object(agent_server.sys, "platform", "linux"), \
             patch.object(agent_server, "agents_server_systemd_cgroup", return_value=None), \
             patch.object(
                 agent_server,
                 "process_cgroup_paths",
                 return_value=("/user.slice/user@1000.service/session.scope",),
             ):
            direct = agent_server.managed_update_service_cgroup_state()

        self.assertTrue(direct["safe"])
        self.assertEqual(direct["inspection"], "not-systemd-managed")

    def test_missing_tmux_server_is_bootstrapped_in_a_user_scope(self):
        cgroup = "/user.slice/user@1000.service/app.slice/agents-server.service"
        completed = MagicMock(returncode=0, stdout="", stderr="")
        with patch.object(agent_server, "agents_server_systemd_cgroup", return_value=cgroup), \
             patch.object(agent_server, "tmux_server_pid", side_effect=[None, 4242]), \
             patch.object(agent_server.shutil, "which", return_value="/usr/bin/systemd-run"), \
             patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
             patch.object(
                 agent_server,
                 "server_update_runner_environment",
                 return_value={"XDG_RUNTIME_DIR": "/run/user/1000"},
             ), \
             patch.object(agent_server.subprocess, "run", return_value=completed) as run, \
             patch.object(
                 agent_server,
                 "process_cgroup_paths",
                 return_value=("/user.slice/user@1000.service/app.slice/agents-server-tmux.scope",),
             ), \
             patch.object(agent_server, "run_tmux") as run_tmux:
            isolated = agent_server.bootstrap_isolated_tmux_server()

        self.assertTrue(isolated)
        command = run.call_args.args[0]
        self.assertEqual(command[:4], [
            "/usr/bin/systemd-run", "--user", "--scope", "--quiet",
        ])
        self.assertIn("--collect", command)
        self.assertIn("/usr/bin/tmux", command)
        self.assertIn("env", run.call_args.kwargs)
        self.assertEqual(
            run.call_args.kwargs["env"]["XDG_RUNTIME_DIR"],
            "/run/user/1000",
        )
        self.assertEqual(run_tmux.call_args_list[0].args[0], [
            "set-option", "-g", "exit-empty", "off",
        ])
        self.assertEqual(run_tmux.call_args_list[1].args[0][:3], [
            "kill-session", "-t", command[-2],
        ])

    async def test_start_cgroup_guard_runs_before_drain_or_tmux_launch(self):
        blocker = HTTPException(
            status_code=409,
            detail=agent_server.unsafe_update_tmux_detail(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            status_path = root / "status.json"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(
                     agent_server,
                     "ensure_managed_update_tmux_isolated",
                     side_effect=blocker,
                 ) as guard, \
                 patch.object(agent_server, "run_tmux") as run_tmux:
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(version="1.1.0"),
                    )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(raised.exception.detail["code"], "unsafe_update_tmux_cgroup")
        guard.assert_called_once_with()
        run_tmux.assert_not_called()
        self.assertFalse(status_path.exists())

    async def test_residual_service_descendant_reopens_admission_before_launch(self):
        cgroup = "/user.slice/user@1000.service/app.slice/agents-server.service"
        blocker = HTTPException(
            status_code=409,
            detail={
                "code": "unsafe_update_service_cgroup",
                "message": "Managed update cannot safely start.",
                "action": "Retry.",
                "retryable": True,
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            status_path = root / "status.json"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            quiesce = AsyncMock(side_effect=blocker)
            terminal_attachments = MagicMock()
            terminal_attachments.reopen_admission = AsyncMock()
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(
                     agent_server,
                     "ensure_managed_update_tmux_isolated",
                     return_value=cgroup,
                 ), \
                 patch.object(
                     agent_server,
                     "quiesce_managed_update_service_cgroup",
                     new=quiesce,
                 ), \
                 patch.object(
                     agent_server,
                     "TERMINAL_ATTACHMENTS",
                     terminal_attachments,
                 ), \
                 patch.object(agent_server, "run_tmux") as run_tmux:
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(version="1.1.0"),
                    )
                status = agent_server.read_server_update_status()
                admission_blocker = agent_server.managed_server_update_blocker()

        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(
            raised.exception.detail["code"],
            "unsafe_update_service_cgroup",
        )
        self.assertEqual(status["phase"], "available")
        self.assertTrue(status["update_available"])
        self.assertEqual(status["error_code"], "unsafe_update_service_cgroup")
        self.assertEqual(status["error_action"], "Retry.")
        self.assertTrue(status["retryable"])
        self.assertNotIn("409:", status["message"])
        self.assertIsNone(admission_blocker)
        quiesce.assert_awaited_once_with(service_cgroup=cgroup)
        terminal_attachments.reopen_admission.assert_awaited_once_with()
        run_tmux.assert_not_called()

    async def test_cancelled_prelaunch_quiesce_reopens_admission(self):
        cgroup = "/user.slice/user@1000.service/app.slice/agents-server.service"
        entered = asyncio.Event()
        release = asyncio.Event()
        cleanup_entered = asyncio.Event()
        release_cleanup = asyncio.Event()
        operation_lock = asyncio.Lock()
        contender_acquired = asyncio.Event()

        async def slow_quiesce(*, service_cgroup):
            self.assertEqual(service_cgroup, cgroup)
            entered.set()
            await release.wait()

        async def slow_reopen() -> None:
            cleanup_entered.set()
            await release_cleanup.wait()

        async def operation_contender() -> None:
            async with operation_lock:
                contender_acquired.set()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            status_path = root / "status.json"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            terminal_attachments = MagicMock()
            terminal_attachments.reopen_admission = AsyncMock()
            with ExitStack() as patches:
                for target, name, value in (
                    (agent_server, "SERVER_VERSION", "1.0.0"),
                    (agent_server, "SERVER_UPDATE_STATUS_FILE", status_path),
                    (agent_server, "SERVER_UPDATE_RUNNER", runner),
                    (agent_server, "SERVER_UPDATE_PUBLIC_KEY", key),
                    (agent_server, "SERVER_UPDATE_OPERATION_LOCK", operation_lock),
                    (agent_server, "AGENT_TOKEN", ""),
                    (agent_server, "BUSY_SESSIONS", set()),
                    (agent_server, "ACTIVE", {}),
                    (agent_server, "QUEUED_TURNS", {}),
                    (agent_server, "RUN_NOW_TURNS", {}),
                    (agent_server, "SERVER_MAINTENANCE_SESSIONS", set()),
                    (agent_server, "TERMINAL_ATTACHMENTS", terminal_attachments),
                ):
                    patches.enter_context(patch.object(target, name, value))
                patches.enter_context(patch.object(
                    agent_server,
                    "managed_server_restart_blocks_work",
                    return_value=False,
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "prepare_provider_background_work_snapshot",
                    new=AsyncMock(return_value={}),
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "provider_background_work_labels_from_snapshot",
                    return_value=[],
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "server_update_is_active",
                    return_value=False,
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "working_tmux_bin",
                    return_value="/usr/bin/tmux",
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "ensure_managed_update_tmux_isolated",
                    return_value=cgroup,
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "quiesce_managed_update_service_cgroup",
                    side_effect=slow_quiesce,
                ))
                patches.enter_context(patch.object(
                    agent_server.TEAM_HUB_RUNTIME,
                    "prepare_maintenance",
                    new=AsyncMock(return_value=None),
                ))
                patches.enter_context(patch.object(
                    agent_server.TEAM_HUB_RUNTIME,
                    "capability",
                    return_value={},
                ))
                patches.enter_context(patch.object(
                    agent_server.TEAM_HUB_RUNTIME,
                    "reopen_admission_sync",
                ))
                patches.enter_context(patch.object(
                    agent_server.TEAM_HUB_RUNTIME,
                    "reopen_admission",
                    side_effect=slow_reopen,
                ))
                run_tmux = patches.enter_context(
                    patch.object(agent_server, "run_tmux")
                )
                task = asyncio.create_task(agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(version="1.1.0"),
                ))
                await asyncio.wait_for(entered.wait(), timeout=1)
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                task.cancel()
                contender = asyncio.create_task(operation_contender())
                await asyncio.sleep(0)
                self.assertFalse(contender_acquired.is_set())
                release.set()
                await asyncio.wait_for(cleanup_entered.wait(), timeout=1)
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                self.assertFalse(contender_acquired.is_set())
                release_cleanup.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                await contender
                status = agent_server.read_server_update_status()
                admission_blocker = agent_server.managed_server_update_blocker()

        self.assertEqual(status["phase"], "failed")
        self.assertIsNone(admission_blocker)
        self.assertTrue(contender_acquired.is_set())
        terminal_attachments.reopen_admission.assert_awaited_once_with()
        run_tmux.assert_not_called()

    async def test_double_cancelled_launch_failure_finishes_cleanup_under_lock(self):
        launch_entered = threading.Event()
        release_launch = threading.Event()
        cleanup_entered = asyncio.Event()
        release_cleanup = asyncio.Event()
        operation_lock = asyncio.Lock()
        contender_acquired = asyncio.Event()

        def failed_launch(_args):
            launch_entered.set()
            self.assertTrue(release_launch.wait(timeout=2))
            raise RuntimeError("tmux launch failed")

        async def slow_reopen() -> None:
            cleanup_entered.set()
            await release_cleanup.wait()

        async def operation_contender() -> None:
            async with operation_lock:
                contender_acquired.set()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            status_path = root / "status.json"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            terminal_attachments = MagicMock()
            terminal_attachments.reopen_admission = AsyncMock()
            with ExitStack() as patches:
                for target, name, value in (
                    (agent_server, "SERVER_VERSION", "1.0.0"),
                    (agent_server, "SERVER_UPDATE_STATUS_FILE", status_path),
                    (agent_server, "SERVER_UPDATE_RUNNER", runner),
                    (agent_server, "SERVER_UPDATE_PUBLIC_KEY", key),
                    (agent_server, "SERVER_UPDATE_OPERATION_LOCK", operation_lock),
                    (agent_server, "AGENT_TOKEN", ""),
                    (agent_server, "BUSY_SESSIONS", set()),
                    (agent_server, "ACTIVE", {}),
                    (agent_server, "QUEUED_TURNS", {}),
                    (agent_server, "RUN_NOW_TURNS", {}),
                    (agent_server, "SERVER_MAINTENANCE_SESSIONS", set()),
                    (agent_server, "TERMINAL_ATTACHMENTS", terminal_attachments),
                ):
                    patches.enter_context(patch.object(target, name, value))
                patches.enter_context(patch.object(
                    agent_server,
                    "managed_server_restart_blocks_work",
                    return_value=False,
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "prepare_provider_background_work_snapshot",
                    new=AsyncMock(return_value={}),
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "provider_background_work_labels_from_snapshot",
                    return_value=[],
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "server_update_is_active",
                    return_value=False,
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "working_tmux_bin",
                    return_value="/usr/bin/tmux",
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "ensure_managed_update_tmux_isolated",
                    return_value=None,
                ))
                patches.enter_context(patch.object(
                    agent_server,
                    "quiesce_managed_update_service_cgroup",
                    new=AsyncMock(),
                ))
                patches.enter_context(patch.object(
                    agent_server.TEAM_HUB_RUNTIME,
                    "prepare_maintenance",
                    new=AsyncMock(return_value=None),
                ))
                patches.enter_context(patch.object(
                    agent_server.TEAM_HUB_RUNTIME,
                    "capability",
                    return_value={},
                ))
                patches.enter_context(patch.object(
                    agent_server.TEAM_HUB_RUNTIME,
                    "reopen_admission_sync",
                ))
                patches.enter_context(patch.object(
                    agent_server.TEAM_HUB_RUNTIME,
                    "reopen_admission",
                    side_effect=slow_reopen,
                ))
                run_tmux = patches.enter_context(patch.object(
                    agent_server,
                    "run_tmux",
                    side_effect=failed_launch,
                ))
                task = asyncio.create_task(agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(version="1.1.0"),
                ))
                try:
                    self.assertTrue(
                        await asyncio.to_thread(launch_entered.wait, 1)
                    )
                    task.cancel()
                    await asyncio.sleep(0)
                    self.assertFalse(task.done())
                    task.cancel()
                    contender = asyncio.create_task(operation_contender())
                    await asyncio.sleep(0)
                    self.assertFalse(contender_acquired.is_set())
                finally:
                    release_launch.set()
                await asyncio.wait_for(cleanup_entered.wait(), timeout=1)
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                self.assertFalse(contender_acquired.is_set())
                release_cleanup.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                await contender
                status = agent_server.read_server_update_status()

        self.assertEqual(status["phase"], "failed")
        self.assertFalse(agent_server.managed_server_update_blocks_work(status))
        self.assertTrue(contender_acquired.is_set())
        terminal_attachments.reopen_admission.assert_awaited_once_with()
        run_tmux.assert_called_once()

    def test_linux_runner_environment_restores_the_user_service_bus(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            (runtime / "bus").touch()
            with patch.object(agent_server.sys, "platform", "linux"), \
                 patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime)}, clear=True):
                environment = agent_server.server_update_runner_environment()

        self.assertEqual(environment, {
            "XDG_RUNTIME_DIR": str(runtime),
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime / 'bus'}",
        })

    async def test_health_reports_missing_tmux_and_disables_managed_updates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            with patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "working_tmux_bin", return_value=None):
                response = await agent_server.health()

        capability = response["capabilities"]["tmux"]
        self.assertEqual(capability["available"], False)
        self.assertEqual(capability["required"], False)
        self.assertIn("not found", capability["message"])
        self.assertIn("Install tmux", capability["action"])
        self.assertFalse(response["managed_updates"])

    async def test_health_reports_available_tmux_and_managed_updates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            with patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"):
                response = await agent_server.health()

        capability = response["capabilities"]["tmux"]
        self.assertEqual(capability, {
            "available": True,
            "required": False,
            "message": "tmux is available.",
            "action": None,
        })
        self.assertTrue(response["managed_updates"])
        self.assertEqual(
            response["capabilities"]["server_updates"]["version"],
            10,
        )
        self.assertEqual(response["update_service_cgroup"], {
            "safe": True,
            "unknown_descendant_count": 0,
            "inspection": "not-systemd-managed",
        })
        self.assertEqual(
            response["capabilities"]["server_updates"]["tracks"],
            ["stable", "beta"],
        )
        self.assertEqual(
            response["capabilities"]["scheduled_jobs"],
            {
                "available": True,
                "required": False,
                "message": (
                    "Scheduled jobs support parent-chat and standalone "
                    "provider contexts."
                ),
                "action": None,
                "version": 6,
                "context_modes": ["chat", "standalone"],
                "default_context_mode": "chat",
                "features": {
                    "chat_references": True,
                    "team_references": True,
                    "direct_message_mentions": False,
                    "route_mentions": True,
                    "route_hint_mentions": True,
                    "next_run_reset": True,
                    "interval_next_run_reanchors": True,
                },
            },
        )

    async def test_health_reports_only_provisional_queue_as_update_blocking(self):
        queued = {
            "durable-chat": deque([{"queued_id": "kept", "_durable": True}]),
            "provisional-chat": deque([{"queued_id": "wait", "_durable": False}]),
        }
        with patch.object(agent_server, "QUEUED_TURNS", queued), \
             patch.object(agent_server, "RUN_NOW_TURNS", {}), \
             patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"):
            response = await agent_server.health()

        self.assertEqual(response["queued"], {
            "durable-chat": 1,
            "provisional-chat": 1,
        })
        self.assertEqual(response["update_blocking_queued_count"], 1)

    async def test_status_returns_live_update_target_without_persisting_it(self):
        terminal_attachments = MagicMock()
        terminal_attachments.reopen_if_update_inactive = AsyncMock(
            return_value=True
        )
        with tempfile.TemporaryDirectory() as temporary:
            status_path = Path(temporary) / "status.json"
            with patch.object(
                agent_server,
                "SERVER_UPDATE_STATUS_FILE",
                status_path,
            ), patch.object(
                agent_server,
                "server_identity",
                return_value="server-current",
            ), patch.object(
                agent_server,
                "SERVER_INSTANCE_ID",
                "instance-current",
            ), patch.object(
                agent_server,
                "TERMINAL_ATTACHMENTS",
                terminal_attachments,
            ):
                agent_server.write_server_update_status(phase="current")
                status = await agent_server.server_update_status(
                    expected_server_identity="server-current",
                    expected_server_instance_id="instance-current",
                )
                persisted = agent_server.read_server_update_status()

        self.assertEqual(status["server_identity"], "server-current")
        self.assertEqual(status["server_instance_id"], "instance-current")
        self.assertNotIn("server_identity", persisted)
        self.assertNotIn("server_instance_id", persisted)
        terminal_attachments.reopen_if_update_inactive.assert_awaited_once_with(
            status
        )

    async def test_update_endpoints_reject_stale_targets_before_state_access(self):
        state_access = MagicMock(
            side_effect=AssertionError("stale target reached update state")
        )
        restart_gate = MagicMock(
            side_effect=AssertionError("stale target reached restart reconciliation")
        )
        status_write = MagicMock(
            side_effect=AssertionError("stale target wrote update status")
        )
        abandoned_reconciliation = MagicMock(
            side_effect=AssertionError("stale target reconciled update status")
        )
        prepare_hub = AsyncMock(
            side_effect=AssertionError("stale target closed Hub admission")
        )
        calls = {
            "status identity swap": lambda: agent_server.server_update_status(
                expected_server_identity="server-stale",
                expected_server_instance_id="instance-current",
            ),
            "check instance swap": lambda: agent_server.check_server_update(
                agent_server.ServerUpdateCheckRequest(
                    expected_server_identity="server-current",
                    expected_server_instance_id="instance-stale",
                )
            ),
            "start identity swap": lambda: agent_server.start_server_update(
                agent_server.ServerUpdateRequest(
                    version="1.1.0",
                    expected_server_identity="server-stale",
                    expected_server_instance_id="instance-current",
                )
            ),
            "cancel instance swap": lambda: agent_server.cancel_server_update(
                agent_server.ServerUpdateCancelRequest(
                    schedule_id="a" * 32,
                    expected_server_identity="server-current",
                    expected_server_instance_id="instance-stale",
                )
            ),
        }
        with patch.object(
            agent_server,
            "server_identity",
            return_value="server-current",
        ), patch.object(
            agent_server,
            "SERVER_INSTANCE_ID",
            "instance-current",
        ), patch.object(
            agent_server,
            "read_server_update_status",
            state_access,
        ), patch.object(
            agent_server,
            "managed_server_restart_blocks_work",
            restart_gate,
        ), patch.object(
            agent_server,
            "write_fresh_server_update_status",
            status_write,
        ), patch.object(
            agent_server,
            "finalize_abandoned_server_update",
            abandoned_reconciliation,
        ), patch.object(
            agent_server.TEAM_HUB_RUNTIME,
            "prepare_maintenance",
            new=prepare_hub,
        ):
            for label, call in calls.items():
                with self.subTest(endpoint=label):
                    with self.assertRaises(HTTPException) as raised:
                        await call()
                    self.assertEqual(raised.exception.status_code, 409)
                    self.assertEqual(
                        raised.exception.detail["code"],
                        "server_update_target_changed",
                    )
            with self.assertRaises(HTTPException) as incomplete:
                await agent_server.server_update_status(
                    expected_server_identity="server-current",
                )

        state_access.assert_not_called()
        restart_gate.assert_not_called()
        status_write.assert_not_called()
        abandoned_reconciliation.assert_not_called()
        prepare_hub.assert_not_awaited()
        self.assertEqual(incomplete.exception.status_code, 400)
        self.assertEqual(
            incomplete.exception.detail["code"],
            "server_update_target_incomplete",
        )

    async def test_check_reports_a_signed_newer_release(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "signed_release_manifest", new=AsyncMock(return_value={"version": "1.1.0"})):
            status = await agent_server.check_server_update()

        self.assertEqual(status["phase"], "available")
        self.assertEqual(status["latest_version"], "1.1.0")
        self.assertTrue(status["update_available"])
        self.assertEqual(status["track"], "stable")
        self.assertEqual(status["server_identity"], agent_server.server_identity())
        self.assertEqual(status["server_instance_id"], agent_server.SERVER_INSTANCE_ID)

    async def test_check_beta_track_discovers_and_persists_beta_release(self):
        manifest = AsyncMock(return_value={"version": "1.1.0-beta.3"})
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "signed_release_manifest", new=manifest):
            status = await agent_server.check_server_update(
                agent_server.ServerUpdateCheckRequest(track="beta"),
            )
            persisted = agent_server.read_server_update_status()

        manifest.assert_awaited_once_with("beta")
        self.assertEqual(status["phase"], "available")
        self.assertEqual(status["track"], "beta")
        self.assertEqual(status["current_track"], "stable")
        self.assertTrue(status["channel_switch"])
        self.assertEqual(persisted["track"], "beta")

    async def test_check_without_body_infers_beta_for_legacy_status(self):
        manifest = AsyncMock(return_value={"version": "1.1.0-beta.4"})
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.1.0-beta.3"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "signed_release_manifest", new=manifest):
            status = await agent_server.check_server_update()

        manifest.assert_awaited_once_with("beta")
        self.assertEqual(status["track"], "beta")
        self.assertFalse(status["channel_switch"])

    async def test_check_stable_track_allows_beta_to_latest_stable_switch(self):
        manifest = AsyncMock(return_value={"version": "1.0.0"})
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.1.0-beta.3"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "signed_release_manifest", new=manifest):
            status = await agent_server.check_server_update(
                agent_server.ServerUpdateCheckRequest(track="stable"),
            )

        self.assertEqual(status["phase"], "available")
        self.assertTrue(status["update_available"])
        self.assertTrue(status["channel_switch"])
        self.assertIn("Switch to stable", status["message"])

    async def test_check_does_not_offer_a_signed_older_release(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.1.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "signed_release_manifest", new=AsyncMock(return_value={"version": "1.0.0"})):
            status = await agent_server.check_server_update()

        self.assertEqual(status["phase"], "current")
        self.assertFalse(status["update_available"])
        self.assertIn("current", status["message"])

    async def test_check_reports_an_unpublished_release_without_failing_ipc(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "signed_release_manifest", new=AsyncMock(side_effect=HTTPException(status_code=404, detail="No signed AgentsServer release has been published yet."))):
            status = await agent_server.check_server_update()

        self.assertEqual(status["phase"], "unavailable")
        self.assertFalse(status["update_available"])
        self.assertIn("No signed AgentsServer release", status["message"])

    async def test_fresh_check_clears_every_prior_run_field(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(
                 agent_server,
                 "signed_release_manifest",
                 new=AsyncMock(return_value={"version": "1.1.0"}),
             ):
            agent_server.write_server_update_status(
                phase="failed",
                update_id="old-update",
                target_version="0.9.0",
                heartbeat_at="old-heartbeat",
                elapsed_seconds=91,
                error_code="old_error",
                error_action="Old action.",
                retryable=True,
                team_hub_id="old-hub",
            )
            status = await agent_server.check_server_update()

        self.assertEqual(status["phase"], "available")
        for field in agent_server.SERVER_UPDATE_PER_RUN_STATUS_FIELDS:
            self.assertIsNone(status[field], field)

    async def test_status_keeps_a_just_started_update_active_while_tmux_appears(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "SERVER_UPDATE_START_GRACE_SECONDS", 45.0), \
             patch.object(agent_server, "server_update_status_age_seconds", return_value=44.9), \
             patch.object(agent_server, "working_tmux_bin", return_value=None):
            agent_server.write_server_update_status(
                update_id="new-update",
                phase="starting",
                target_version="1.1.0",
                message="Starting detached update.",
            )
            status = await agent_server.server_update_status()

        self.assertEqual(status["phase"], "starting")
        self.assertEqual(status["target_version"], "1.1.0")
        self.assertNotIn("finished_at", status)

    async def test_terminal_update_status_reconciles_terminal_admission(self):
        terminal_attachments = MagicMock()
        terminal_attachments.reopen_if_update_inactive = AsyncMock(
            return_value=True
        )
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(
                 agent_server,
                 "TERMINAL_ATTACHMENTS",
                 terminal_attachments,
             ):
            agent_server.write_server_update_status(
                update_id="late-runner-failure",
                phase="failed",
                target_version="1.1.0",
                message="Detached update failed.",
            )
            status = await agent_server.server_update_status()

        self.assertEqual(status["phase"], "failed")
        terminal_attachments.reopen_if_update_inactive.assert_awaited_once_with(
            status
        )

    async def test_status_normalizes_an_active_target_that_is_now_current(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.1.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(
                 agent_server,
                 "server_update_status_age_seconds",
                 return_value=46.0,
             ), \
             patch.object(agent_server, "working_tmux_bin", return_value=None):
            agent_server.write_server_update_status(
                update_id="completed-update",
                phase="restarting",
                target_version="1.1.0",
                update_available=True,
                message="Restarting updated server.",
            )
            status = await agent_server.server_update_status()

        self.assertEqual(status["phase"], "complete")
        self.assertFalse(status["update_available"])
        self.assertEqual(status["installed_version"], "1.1.0")
        self.assertIn("installed and healthy", status["message"])
        self.assertTrue(status["finished_at"])

    async def test_status_normalizes_a_terminal_success_with_stale_availability(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.1.0"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ):
            agent_server.write_server_update_status(
                update_id="completed-update",
                phase="complete",
                target_version="1.1.0",
                installed_version="1.1.0",
                latest_version="1.1.0",
                update_available=True,
                message="AgentsServer 1.1.0 is installed and healthy.",
            )
            status = await agent_server.server_update_status()

        self.assertEqual(status["phase"], "complete")
        self.assertFalse(status["update_available"])
        self.assertEqual(status["current_version"], "1.1.0")

    async def test_status_keeps_target_current_drained_while_updater_is_alive(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.1.0"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(
                 agent_server,
                 "server_update_is_active",
                 return_value=True,
             ), \
             patch.object(
                 agent_server,
                 "server_update_status_age_seconds",
                 return_value=120.0,
             ):
            agent_server.write_server_update_status(
                update_id="still-running",
                phase="restarting",
                target_version="1.1.0",
            )
            status = await agent_server.server_update_status()

        self.assertEqual(status["phase"], "restarting")
        self.assertTrue(agent_server.managed_server_update_blocks_work(status))

    async def test_abandoned_update_clears_its_exact_fence_before_terminal_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status_path = root / "status.json"
            hub_data = root / "hub"
            runtime = MagicMock()
            runtime.capability.return_value = {
                "available": True,
                "designated_host": True,
                "hub_id": "hub_test12345678",
                "host_server_identity": "server-test-identity",
            }
            runtime.maintenance_fence_sync.return_value = {
                "reason": "server-update",
                "operation_id": "update-exact",
                "snapshot": "snapshot_exact",
            }
            phases_at_clear: list[str] = []

            def clear(reason, operation_id, snapshot):
                phases_at_clear.append(
                    agent_server.read_server_update_status()["phase"]
                )
                self.assertEqual(reason, "server-update")
                self.assertEqual(operation_id, "update-exact")
                self.assertEqual(snapshot, hub_data / "maintenance-backups" / "snapshot_exact")
                return True

            runtime.clear_maintenance_sync.side_effect = clear
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "TEAM_HUB_DATA_DIR", hub_data), \
                 patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime), \
                 patch.object(agent_server, "server_identity", return_value="server-test-identity"), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "server_update_status_age_seconds", return_value=60.0):
                agent_server.write_server_update_status(
                    update_id="update-exact",
                    phase="downloading",
                    target_version="1.1.0",
                    team_hub_id="hub_test12345678",
                    team_hub_host_server_identity="server-test-identity",
                    team_hub_snapshot_generation="snapshot_exact",
                )
                status = await agent_server.server_update_status()

            self.assertEqual(phases_at_clear, ["downloading"])
            self.assertEqual(status["phase"], "failed")
            runtime.clear_maintenance_sync.assert_called_once()

    async def test_preinstall_orphan_recovers_when_team_hub_initialization_failed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status_path = root / "status.json"
            hub_data = root / "hub"
            runtime = MagicMock()
            runtime.capability.side_effect = RuntimeError("Hub init failed")
            runtime.maintenance_fence_sync.return_value = {
                "reason": "server-update",
                "operation_id": "update-preinstall",
                "snapshot": "snapshot_preinstall",
            }
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "TEAM_HUB_DATA_DIR", hub_data), \
                 patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "server_update_status_age_seconds", return_value=60.0):
                agent_server.write_server_update_status(
                    update_id="update-preinstall",
                    phase="downloading",
                    target_version="1.1.0",
                    team_hub_id="hub_test12345678",
                    team_hub_host_server_identity="server-test-identity",
                    team_hub_snapshot_generation="snapshot_preinstall",
                )
                status = (
                    await agent_server.reconcile_server_update_status_after_startup()
                )

            self.assertEqual(status["phase"], "failed")
            self.assertFalse(agent_server.managed_server_update_blocks_work(status))
            runtime.capability.assert_not_called()
            runtime.clear_maintenance_sync.assert_called_once_with(
                "server-update",
                "update-preinstall",
                hub_data / "maintenance-backups" / "snapshot_preinstall",
            )

    async def test_current_candidate_with_missing_hub_cannot_finalize_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            status_path = Path(temporary) / "status.json"
            runtime = MagicMock()
            runtime.capability.return_value = {
                "available": False,
                "designated_host": False,
                "hub_id": None,
                "host_server_identity": None,
            }
            with patch.object(agent_server, "SERVER_VERSION", "1.1.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "server_update_status_age_seconds", return_value=60.0):
                agent_server.write_server_update_status(
                    update_id="update-lost-hub",
                    phase="restarting",
                    target_version="1.1.0",
                    team_hub_id="hub_expected123456",
                    team_hub_host_server_identity="server-test-identity",
                    team_hub_snapshot_generation="snapshot_expected",
                )
                status = await agent_server.server_update_status()

            self.assertEqual(status["phase"], "restarting")
            runtime.clear_maintenance_sync.assert_not_called()

    async def test_abandoned_failed_host_repair_requires_exact_repaired_hub(self):
        invalid_capabilities = (
            {
                "available": False,
                "designated_host": True,
                "version": 1,
                "base_path": "/api/team-hub",
                "hub_id": None,
                "host_server_identity": "server-test-identity",
                "transport": "loopback",
                "hub_url": None,
                "routes": [{"transport": "loopback", "hub_url": None}],
            },
            {
                "available": True,
                "designated_host": True,
                "version": 1,
                "base_path": "/api/team-hub",
                "hub_id": "hub_repaired12345678",
                "host_server_identity": "server-foreign-identity",
                "transport": "loopback",
                "hub_url": None,
                "routes": [{"transport": "loopback", "hub_url": None}],
            },
        )
        for capability in invalid_capabilities:
            with self.subTest(capability=capability), tempfile.TemporaryDirectory() as temporary:
                status_path = Path(temporary) / "status.json"
                runtime = MagicMock()
                runtime.capability.return_value = capability
                runtime.maintenance_fence_sync.return_value = None
                with patch.object(agent_server, "SERVER_VERSION", "1.1.0"), \
                     patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                     patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime), \
                     patch.object(agent_server, "server_identity", return_value="server-test-identity"), \
                     patch.object(agent_server, "server_update_is_active", return_value=False), \
                     patch.object(agent_server, "server_update_status_age_seconds", return_value=60.0):
                    agent_server.write_server_update_status(
                        update_id="update-repair-orphan",
                        phase="installing",
                        target_version="1.1.0",
                        update_available=True,
                        team_hub_id=None,
                        team_hub_repair_mode="failed_start",
                        team_hub_host_server_identity="server-test-identity",
                        team_hub_snapshot_generation=None,
                        team_hub_transport="loopback",
                        team_hub_url=None,
                        team_hub_direct_ip_url="",
                        team_hub_routes=[
                            {"transport": "loopback", "hub_url": None}
                        ],
                    )
                    status = await agent_server.server_update_status()

                self.assertEqual(status["phase"], "installing")
                self.assertTrue(status["update_available"])
                runtime.clear_maintenance_sync.assert_not_called()

        valid = {
            "available": True,
            "designated_host": True,
            "version": 1,
            "base_path": "/api/team-hub",
            "hub_id": "hub_repaired12345678",
            "host_server_identity": "server-test-identity",
            "transport": "loopback",
            "hub_url": None,
            "routes": [{"transport": "loopback", "hub_url": None}],
        }
        with patch.object(agent_server, "TEAM_HUB_RUNTIME") as runtime, \
             patch.object(agent_server, "server_identity", return_value="server-test-identity"):
            runtime.capability.return_value = valid
            agent_server._verify_server_update_team_hub_identity(
                {
                    "team_hub_repair_mode": "failed_start",
                    "team_hub_host_server_identity": "server-test-identity",
                    "team_hub_transport": "loopback",
                    "team_hub_url": None,
                    "team_hub_direct_ip_url": "",
                    "team_hub_routes": [
                        {"transport": "loopback", "hub_url": None}
                    ],
                }
            )

    def test_update_identity_verification_binds_exact_team_hub_transport(self):
        runtime = MagicMock()
        runtime.capability.return_value = {
            "available": True,
            "designated_host": True,
            "hub_id": "hub_test12345678",
            "host_server_identity": "server-test-identity",
            "transport": "tailscale_serve",
            "hub_url": "https://sonic.example.ts.net:8444/api/team-hub",
        }
        status = {
            "team_hub_id": "hub_test12345678",
            "team_hub_host_server_identity": "server-test-identity",
            "team_hub_snapshot_generation": "snapshot_expected",
            "team_hub_transport": "tailscale_serve",
            "team_hub_url": "https://sonic.example.ts.net:8444/api/team-hub",
        }
        with patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime), \
             patch.object(agent_server, "server_identity", return_value="server-test-identity"):
            agent_server._verify_server_update_team_hub_identity(status)
            with self.assertRaisesRegex(RuntimeError, "lost its designated Team Hub identity"):
                agent_server._verify_server_update_team_hub_identity(
                    {
                        **status,
                        "team_hub_url": (
                            "https://other.example.ts.net:8444/api/team-hub"
                        ),
                    }
                )

    def test_update_identity_verification_binds_direct_primary_and_exact_ordered_routes(self):
        direct_url = "http://100.73.184.23:7850/api/team-hub"
        serve_url = "https://sonic.example.ts.net:8444/api/team-hub"
        routes = [
            {"transport": "direct_ip", "hub_url": direct_url},
            {"transport": "tailscale_serve", "hub_url": serve_url},
        ]
        runtime = MagicMock()
        runtime.capability.return_value = {
            "available": True,
            "designated_host": True,
            "hub_id": "hub_test12345678",
            "host_server_identity": "server-test-identity",
            "transport": "direct_ip",
            "hub_url": direct_url,
            "routes": routes,
        }
        status = {
            "team_hub_id": "hub_test12345678",
            "team_hub_host_server_identity": "server-test-identity",
            "team_hub_snapshot_generation": "snapshot_expected",
            "team_hub_transport": "direct_ip",
            "team_hub_url": direct_url,
            "team_hub_direct_ip_url": direct_url,
            "team_hub_routes": routes,
        }
        with patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime), \
             patch.object(agent_server, "server_identity", return_value="server-test-identity"):
            agent_server._verify_server_update_team_hub_identity(status)
            runtime.capability.return_value = {
                **runtime.capability.return_value,
                "routes": list(reversed(routes)),
            }
            with self.assertRaisesRegex(RuntimeError, "lost its designated Team Hub identity"):
                agent_server._verify_server_update_team_hub_identity(status)
            with self.assertRaisesRegex(RuntimeError, "route binding is invalid"):
                agent_server._verify_server_update_team_hub_identity(
                    {**status, "team_hub_direct_ip_url": ""}
                )

    async def test_startup_clears_snapshot_fence_orphaned_before_status_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status_path = root / "status.json"
            hub_data = root / "hub"
            runtime = MagicMock()
            runtime.maintenance_fence_sync.return_value = {
                "reason": "server-update",
                "operation_id": "update-pre-status",
                "snapshot": "snapshot_pre_status",
            }
            with patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "TEAM_HUB_DATA_DIR", hub_data), \
                 patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime):
                agent_server.write_server_update_status(phase="current")
                status = await agent_server.reconcile_server_update_status_after_startup()

            self.assertEqual(status["phase"], "current")
            runtime.clear_maintenance_sync.assert_called_once_with(
                "server-update",
                "update-pre-status",
                hub_data / "maintenance-backups" / "snapshot_pre_status",
            )

    async def test_startup_keeps_terminal_same_operation_fence_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            status_path = Path(temporary) / "status.json"
            runtime = MagicMock()
            runtime.maintenance_fence_sync.return_value = {
                "reason": "server-update",
                "operation_id": "update-incomplete",
                "snapshot": "snapshot_incomplete",
            }
            with patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime):
                original = agent_server.write_server_update_status(
                    update_id="update-incomplete",
                    phase="failed",
                    target_version="1.1.0",
                )
                status = await agent_server.reconcile_server_update_status_after_startup()

            self.assertEqual(status["phase"], "failed")
            self.assertEqual(status["update_id"], original["update_id"])
            runtime.clear_maintenance_sync.assert_not_called()

    async def test_check_and_start_cannot_overwrite_active_status_during_grace(self):
        manifest = AsyncMock(
            side_effect=AssertionError("active update must block release discovery")
        )
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "server_update_status_age_seconds", return_value=1.0), \
             patch.object(agent_server, "signed_release_manifest", new=manifest):
            original = agent_server.write_server_update_status(
                update_id="update-active",
                phase="starting",
                target_version="1.1.0",
            )
            with self.assertRaises(HTTPException) as check_error:
                await agent_server.check_server_update()
            with self.assertRaises(HTTPException) as start_error:
                await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(version="1.1.0")
                )
            current = agent_server.read_server_update_status()

        self.assertEqual(check_error.exception.status_code, 409)
        self.assertEqual(start_error.exception.status_code, 409)
        self.assertEqual(current["update_id"], original["update_id"])
        self.assertEqual(current["phase"], "starting")
        manifest.assert_not_awaited()

    async def test_startup_reconciliation_completes_an_installed_orphan(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.1.0"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(
                 agent_server,
                 "server_update_is_active",
                 return_value=False,
             ), \
             patch.object(
                 agent_server,
                 "server_update_status_age_seconds",
                 return_value=60.0,
             ):
            agent_server.write_server_update_status(
                update_id="orphaned-update",
                phase="restarting",
                target_version="1.1.0",
                update_available=True,
                runner_pid=424242,
                heartbeat_at="2026-09-05T00:00:00Z",
                elapsed_seconds=90,
            )
            status = (
                await agent_server.reconcile_server_update_status_after_startup()
            )

        self.assertEqual(status["phase"], "complete")
        self.assertEqual(status["installed_version"], "1.1.0")
        self.assertIsNone(status["runner_pid"])
        self.assertIsNone(status["heartbeat_at"])
        self.assertIsNone(status["elapsed_seconds"])
        self.assertFalse(agent_server.managed_server_update_blocks_work(status))

    async def test_startup_reconciliation_fails_an_uninstalled_orphan(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(
                 agent_server,
                 "server_update_is_active",
                 return_value=False,
             ), \
             patch.object(
                 agent_server,
                 "server_update_status_age_seconds",
                 return_value=60.0,
             ):
            agent_server.write_server_update_status(
                update_id="orphaned-update",
                phase="downloading",
                target_version="1.1.0",
                runner_pid=424242,
                heartbeat_at="2026-09-05T00:00:00Z",
                elapsed_seconds=90,
            )
            status = (
                await agent_server.reconcile_server_update_status_after_startup()
            )

        self.assertEqual(status["phase"], "failed")
        self.assertIn("detached updater exited", status["message"])
        self.assertIsNone(status["runner_pid"])
        self.assertIsNone(status["heartbeat_at"])
        self.assertIsNone(status["elapsed_seconds"])
        self.assertFalse(agent_server.managed_server_update_blocks_work(status))

    async def test_startup_reconciliation_keeps_a_live_update_drained(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.1.0"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(
                 agent_server,
                 "server_update_is_active",
                 return_value=True,
             ):
            original = agent_server.write_server_update_status(
                update_id="live-update",
                phase="restarting",
                target_version="1.1.0",
            )
            status = (
                await agent_server.reconcile_server_update_status_after_startup()
            )

        self.assertEqual(status["phase"], "restarting")
        self.assertEqual(status["updated_at"], original["updated_at"])
        self.assertTrue(agent_server.managed_server_update_blocks_work(status))

    async def test_start_on_current_version_does_not_require_tmux(self):
        manifest = AsyncMock(side_effect=AssertionError("/start must not perform release discovery"))
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "signed_release_manifest", new=manifest), \
             patch.object(agent_server, "working_tmux_bin", return_value=None):
            status = await agent_server.start_server_update(agent_server.ServerUpdateRequest(version="1.0.0"))

        self.assertEqual(status["phase"], "current")
        self.assertFalse(status["update_available"])
        self.assertEqual(status["server_identity"], agent_server.server_identity())
        self.assertEqual(status["server_instance_id"], agent_server.SERVER_INSTANCE_ID)
        manifest.assert_not_awaited()

    async def test_start_newer_version_without_tmux_returns_actionable_503(self):
        manifest = AsyncMock(side_effect=AssertionError("/start must not perform release discovery"))
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "signed_release_manifest", new=manifest), \
             patch.object(agent_server, "working_tmux_bin", return_value=None):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.start_server_update(agent_server.ServerUpdateRequest(version="1.1.0"))

        self.assertEqual(raised.exception.status_code, 503)
        self.assertIn("tmux", str(raised.exception.detail))
        self.assertIn("Install tmux", str(raised.exception.detail))
        manifest.assert_not_awaited()

    async def test_start_launches_a_detached_verified_update_without_manifest_discovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            manifest = AsyncMock(side_effect=AssertionError("/start must not perform release discovery"))
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "signed_release_manifest", new=manifest), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux", return_value=None) as run_tmux:
                agent_server.write_server_update_status(
                    phase="available",
                    latest_version="1.1.0",
                    update_available=True,
                    heartbeat_at="old-heartbeat",
                    elapsed_seconds=91,
                    error_code="old_error",
                    error_action="Old action.",
                    retryable=True,
                )
                status = await agent_server.start_server_update(agent_server.ServerUpdateRequest(version="1.1.0"))

        self.assertEqual(status["phase"], "starting")
        self.assertEqual(status["target_version"], "1.1.0")
        self.assertIsNone(status["heartbeat_at"])
        self.assertIsNone(status["elapsed_seconds"])
        self.assertIsNone(status["error_code"])
        self.assertIsNone(status["error_action"])
        self.assertIsNone(status["retryable"])
        manifest.assert_not_awaited()
        command = run_tmux.call_args.args[0]
        self.assertEqual(command[:3], ["new-session", "-d", "-s"])
        self.assertIn("--expected-version 1.1.0", command[-1])
        self.assertIn("--current-version 1.0.0", command[-1])
        self.assertIn("--track stable", command[-1])

    async def test_failed_team_hub_start_admits_only_identity_bound_repair_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            failed_capability = {
                "available": False,
                "designated_host": True,
                "version": 1,
                "base_path": "/api/team-hub",
                "hub_id": None,
                "host_server_identity": "server-repair-test",
                "transport": "loopback",
                "hub_url": None,
                "routes": [{"transport": "loopback", "hub_url": None}],
                "startup_failure_reason": "database unavailable",
            }
            prepare = AsyncMock(return_value=None)
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "server_identity", return_value="server-repair-test"), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server.TEAM_HUB_RUNTIME, "capability", return_value=failed_capability), \
                 patch.object(agent_server.TEAM_HUB_RUNTIME, "prepare_maintenance", new=prepare), \
                 patch.object(agent_server.TEAM_HUB_RUNTIME, "reopen_admission_sync"), \
                 patch.object(agent_server, "run_tmux", return_value=None) as run_tmux:
                status = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(version="1.1.0")
                )

        prepare.assert_awaited_once()
        self.assertEqual(prepare.await_args.args, ("server-update",))
        self.assertRegex(
            prepare.await_args.kwargs["operation_id"], r"^[0-9a-f]{32}$"
        )
        self.assertTrue(prepare.await_args.kwargs["allow_unavailable_host"])
        self.assertEqual(status["team_hub_repair_mode"], "failed_start")
        self.assertEqual(status["team_hub_host_server_identity"], "server-repair-test")
        self.assertEqual(status["team_hub_transport"], "loopback")
        command = run_tmux.call_args.args[0][-1]
        self.assertIn("--repair-failed-team-hub-host", command)
        self.assertIn("--expected-team-hub-transport loopback", command)
        self.assertIn("--expected-team-hub-url ''", command)

    async def test_start_rejects_update_while_an_agent_turn_is_active(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            quiesce = AsyncMock()
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "BUSY_SESSIONS", {"busy-chat"}), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(
                     agent_server,
                     "quiesce_managed_update_service_cgroup",
                     new=quiesce,
                 ), \
                 patch.object(agent_server, "run_tmux") as run_tmux:
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(version="1.1.0"),
                    )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("1 active agent run", str(raised.exception.detail))
        quiesce.assert_not_awaited()
        run_tmux.assert_not_called()

    async def test_when_idle_persists_exact_pending_reservation_without_drain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            quiesce = AsyncMock()
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "BUSY_SESSIONS", {"busy-chat"}), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(
                     agent_server,
                     "ensure_managed_update_tmux_isolated",
                     return_value=None,
                 ), \
                 patch.object(
                     agent_server,
                     "quiesce_managed_update_service_cgroup",
                     new=quiesce,
                 ), \
                 patch.object(agent_server, "run_tmux") as run_tmux:
                status = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="1.1.0",
                        when_idle=True,
                    ),
                )

        self.assertEqual(status["phase"], "pending")
        self.assertRegex(status["schedule_id"], r"^[0-9a-f]{32}$")
        self.assertIsNone(status["update_id"])
        self.assertEqual(status["target_version"], "1.1.0")
        self.assertEqual(status["track"], "stable")
        self.assertTrue(status["when_idle"])
        self.assertTrue(status["cancelable"])
        self.assertEqual(status["blocker_counts"], {
            "active_runs": 1,
            "queued_turns": 0,
            "provider_background_tasks": 0,
            "in_flight_server_changes": 0,
        })
        self.assertFalse(agent_server.managed_server_update_blocks_work(status))
        self.assertTrue(agent_server.managed_server_update_is_pending(status))
        quiesce.assert_not_awaited()
        run_tmux.assert_not_called()

    async def test_pending_duplicate_is_idempotent_and_conflicts_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "BUSY_SESSIONS", {"busy-chat"}), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(
                     agent_server,
                     "ensure_managed_update_tmux_isolated",
                     return_value=None,
                 ), \
                 patch.object(agent_server, "run_tmux") as run_tmux:
                first = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="1.1.0",
                        when_idle=True,
                    ),
                )
                duplicate = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="1.1.0",
                        when_idle=True,
                    ),
                )
                checked = await agent_server.check_server_update()
                with self.assertRaises(HTTPException) as different:
                    await agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(
                            version="1.2.0",
                            when_idle=True,
                        ),
                    )
                with self.assertRaises(HTTPException) as immediate:
                    await agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(version="1.1.0"),
                    )

        self.assertEqual(duplicate["schedule_id"], first["schedule_id"])
        self.assertEqual(duplicate["updated_at"], first["updated_at"])
        self.assertEqual(checked["schedule_id"], first["schedule_id"])
        self.assertEqual(different.exception.detail["code"], "server_update_pending")
        self.assertEqual(immediate.exception.detail["code"], "server_update_pending")
        run_tmux.assert_not_called()

    async def test_pending_waiter_atomically_starts_after_active_work_finishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            busy = {"busy-chat"}
            durable_queue = {
                "chat": deque([{
                    "queued_id": "durable-paused",
                    "_durable": True,
                    "_paused_after_stop": True,
                }]),
            }
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "AGENT_TOKEN", ""), \
                 patch.object(agent_server, "BUSY_SESSIONS", busy), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", durable_queue), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "active_provider_background_work_labels", return_value=[]), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(
                     agent_server,
                     "ensure_managed_update_tmux_isolated",
                     return_value=None,
                 ), \
                 patch.object(agent_server, "run_tmux", return_value=None) as run_tmux:
                pending = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="1.1.0",
                        when_idle=True,
                    ),
                )
                busy.clear()
                started = await agent_server.advance_pending_server_update_once()

        self.assertEqual(started["phase"], "starting")
        self.assertEqual(started["schedule_id"], pending["schedule_id"])
        self.assertRegex(started["update_id"], r"^[0-9a-f]{32}$")
        self.assertNotEqual(started["update_id"], pending["schedule_id"])
        self.assertFalse(started["cancelable"])
        self.assertEqual(
            list(durable_queue["chat"])[0]["queued_id"],
            "durable-paused",
        )
        run_tmux.assert_called_once()

    async def test_stale_pending_reconcile_cannot_overwrite_new_starting_row(self):
        with tempfile.TemporaryDirectory() as temporary:
            status_path = Path(temporary) / "status.json"
            reconcile_entered = threading.Event()
            release_reconcile = threading.Event()
            operation_lock = asyncio.Lock()
            contender_acquired = asyncio.Event()
            real_reconcile = (
                agent_server.reconcile_pending_server_update_after_startup
            )

            def delayed_reconcile(status):
                reconcile_entered.set()
                self.assertTrue(release_reconcile.wait(timeout=2))
                return real_reconcile(status)

            async def operation_contender() -> None:
                async with operation_lock:
                    contender_acquired.set()

            with (
                patch.object(agent_server, "SERVER_VERSION", "1.0.0"),
                patch.object(
                    agent_server,
                    "SERVER_UPDATE_STATUS_FILE",
                    status_path,
                ),
                patch.object(
                    agent_server,
                    "SERVER_UPDATE_OPERATION_LOCK",
                    operation_lock,
                ),
                patch.object(
                    agent_server,
                    "reconcile_pending_server_update_after_startup",
                    side_effect=delayed_reconcile,
                ),
            ):
                stale = agent_server.write_fresh_server_update_status(
                    phase=agent_server.SERVER_UPDATE_PENDING_PHASE,
                    schedule_id="a" * 32,
                    target_version=None,
                    latest_version="1.1.0",
                    track="stable",
                    when_idle=True,
                    cancelable=True,
                )
                advance = asyncio.create_task(
                    agent_server.advance_pending_server_update_once()
                )
                try:
                    self.assertTrue(
                        await asyncio.to_thread(reconcile_entered.wait, 1)
                    )
                    contender = asyncio.create_task(operation_contender())
                    await asyncio.sleep(0)
                    self.assertFalse(contender_acquired.is_set())

                    # Model a current updater/status owner that does not share
                    # this process's asyncio lock. The stale worker's file CAS
                    # must observe and preserve this exact replacement row.
                    starting = agent_server.write_fresh_server_update_status(
                        phase="starting",
                        schedule_id="b" * 32,
                        update_id="c" * 32,
                        target_version="1.1.0",
                        latest_version="1.1.0",
                        track="stable",
                        when_idle=True,
                        cancelable=False,
                    )
                finally:
                    release_reconcile.set()
                reconciled = await advance
                await contender
                final = agent_server.read_server_update_status()

        self.assertEqual(stale["phase"], "pending")
        self.assertEqual(reconciled["phase"], "starting")
        self.assertEqual(reconciled["update_id"], starting["update_id"])
        self.assertEqual(final["phase"], "starting")
        self.assertEqual(final["schedule_id"], "b" * 32)
        self.assertEqual(final["update_id"], "c" * 32)
        self.assertTrue(contender_acquired.is_set())

    async def test_pending_waiter_defers_for_cancelled_mutation_then_transitions(self):
        def request(path: str):
            return agent_server.Request({
                "type": "http",
                "asgi": {"version": "3.0"},
                "method": "POST",
                "scheme": "http",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "root_path": "",
                "headers": [],
                "client": ("127.0.0.1", 50000),
                "server": ("127.0.0.1", 7850),
            })

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            busy = {"busy-chat"}
            mutation_entered = asyncio.Event()
            release_mutation = asyncio.Event()

            async def slow_mutation(_request):
                mutation_entered.set()
                await release_mutation.wait()
                return agent_server.JSONResponse({"saved": True})

            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "AGENT_TOKEN", ""), \
                 patch.object(agent_server, "BUSY_SESSIONS", busy), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "UNSAFE_HTTP_MUTATION_TASKS", {}), \
                 patch.object(agent_server, "active_provider_background_work_labels", return_value=[]), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(
                     agent_server,
                     "ensure_managed_update_tmux_isolated",
                     return_value=None,
                 ), \
                 patch.object(agent_server, "run_tmux", return_value=None) as run_tmux:
                pending = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="1.1.0",
                        when_idle=True,
                    ),
                )
                busy.clear()
                mutation_task = asyncio.create_task(
                    agent_server.require_agent_token(
                        request("/api/sessions/chat/unread"),
                        slow_mutation,
                    )
                )
                await asyncio.wait_for(mutation_entered.wait(), timeout=1)
                mutation_task.cancel()
                await asyncio.sleep(0)
                mutation_task.cancel()
                await asyncio.sleep(0)
                still_pending = await agent_server.advance_pending_server_update_once()
                self.assertEqual(agent_server.unsafe_http_mutation_count_locked(), 1)
                self.assertFalse(mutation_task.done())
                run_tmux.assert_not_called()
                release_mutation.set()
                with self.assertRaises(asyncio.CancelledError):
                    await mutation_task
                started = await agent_server.advance_pending_server_update_once()
                blocked_next = AsyncMock()
                blocked_mutation = await agent_server.require_agent_token(
                    request("/api/sessions/chat/unread"),
                    blocked_next,
                )

        self.assertEqual(pending["phase"], "pending")
        self.assertEqual(still_pending["phase"], "pending")
        self.assertEqual(
            still_pending["blocker_counts"]["in_flight_server_changes"],
            1,
        )
        self.assertEqual(agent_server.unsafe_http_mutation_count_locked(), 0)
        self.assertEqual(started["phase"], "starting")
        self.assertEqual(started["schedule_id"], pending["schedule_id"])
        self.assertEqual(blocked_mutation.status_code, 409)
        self.assertIn(b"preparing a managed update", blocked_mutation.body)
        blocked_next.assert_not_awaited()
        run_tmux.assert_called_once()

    async def test_cancelled_http_mutation_holds_lease_until_thread_finishes(self):
        path = "/api/sessions/chat/unread"
        request = agent_server.Request({
            "type": "http",
            "asgi": {"version": "3.0"},
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "client": ("127.0.0.1", 50000),
            "server": ("127.0.0.1", 7850),
        })
        entered = threading.Event()
        release = threading.Event()

        def blocked_write():
            entered.set()
            release.wait()

        async def slow_mutation(_request):
            await asyncio.to_thread(blocked_write)
            return agent_server.JSONResponse({"saved": True})

        with patch.object(agent_server, "AGENT_TOKEN", ""), \
             patch.object(agent_server, "UNSAFE_HTTP_MUTATION_TASKS", {}):
            mutation = asyncio.create_task(
                agent_server.require_agent_token(request, slow_mutation)
            )
            entered_ready = await asyncio.wait_for(
                asyncio.to_thread(entered.wait, 1),
                timeout=2,
            )
            self.assertTrue(entered_ready)
            mutation.cancel()
            await asyncio.sleep(0)
            mutation.cancel()
            await asyncio.sleep(0)

            # Cancelling the asyncio wrapper does not stop its worker thread.
            # The exact lease must remain until that real mutation settles.
            self.assertFalse(mutation.done())
            self.assertEqual(agent_server.unsafe_http_mutation_count_locked(), 1)
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await mutation
            await asyncio.sleep(0)

            self.assertEqual(agent_server.unsafe_http_mutation_count_locked(), 0)

    async def test_mutation_registry_prunes_only_finished_tasks(self):
        release = asyncio.Event()
        live = asyncio.create_task(release.wait())
        completed = asyncio.create_task(asyncio.sleep(0))
        cancelled = asyncio.create_task(asyncio.sleep(60))
        await completed
        cancelled.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await cancelled

        registry = {
            "completed": completed,
            "cancelled": cancelled,
            "live": live,
        }
        with patch.object(agent_server, "UNSAFE_HTTP_MUTATION_TASKS", registry):
            self.assertEqual(
                agent_server.live_unsafe_http_mutation_ids_locked(),
                ["live"],
            )
            release.set()
            await live
            self.assertEqual(agent_server.unsafe_http_mutation_count_locked(), 0)

    async def test_pending_cancel_is_exact_and_stale_waiter_cannot_restart_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            status_path = Path(temporary) / "status.json"
            terminal_attachments = MagicMock()
            terminal_attachments.reopen_if_update_inactive = AsyncMock(
                return_value=True
            )
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "TERMINAL_ATTACHMENTS", terminal_attachments):
                schedule_id = "a" * 32
                agent_server.write_fresh_server_update_status(
                    phase="pending",
                    schedule_id=schedule_id,
                    target_version="1.1.0",
                    latest_version="1.1.0",
                    track="stable",
                    update_available=True,
                    when_idle=True,
                    cancelable=True,
                    blocker_counts={"active_runs": 1},
                )
                with self.assertRaises(HTTPException) as mismatch:
                    await agent_server.cancel_server_update(
                        agent_server.ServerUpdateCancelRequest(
                            schedule_id="b" * 32,
                        )
                    )
                cancelled = await agent_server.cancel_server_update(
                    agent_server.ServerUpdateCancelRequest(
                        schedule_id=schedule_id,
                    )
                )
                stale = await agent_server._start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="1.1.0",
                        when_idle=True,
                    ),
                    expected_schedule_id=schedule_id,
                )

        self.assertEqual(mismatch.exception.detail["code"], "server_update_changed")
        self.assertEqual(cancelled["phase"], "available")
        self.assertIsNone(cancelled["schedule_id"])
        self.assertIsNone(cancelled["update_id"])
        self.assertEqual(stale["phase"], "available")
        terminal_attachments.reopen_if_update_inactive.assert_awaited_once_with(
            cancelled
        )

    async def test_cancel_losing_pending_to_start_race_is_not_cancelable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            busy = {"busy-chat"}
            quiescing = asyncio.Event()
            release_quiesce = asyncio.Event()

            async def slow_quiesce(*, service_cgroup):
                self.assertIsNone(service_cgroup)
                quiescing.set()
                await release_quiesce.wait()

            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "AGENT_TOKEN", ""), \
                 patch.object(agent_server, "BUSY_SESSIONS", busy), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "active_provider_background_work_labels", return_value=[]), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(
                     agent_server,
                     "ensure_managed_update_tmux_isolated",
                     return_value=None,
                 ), \
                 patch.object(
                     agent_server,
                     "quiesce_managed_update_service_cgroup",
                     side_effect=slow_quiesce,
                 ), \
                 patch.object(agent_server, "run_tmux", return_value=None):
                pending = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="1.1.0",
                        when_idle=True,
                    ),
                )
                busy.clear()
                transition = asyncio.create_task(
                    agent_server.advance_pending_server_update_once()
                )
                await asyncio.wait_for(quiescing.wait(), timeout=1)
                cancel = asyncio.create_task(
                    agent_server.cancel_server_update(
                        agent_server.ServerUpdateCancelRequest(
                            schedule_id=pending["schedule_id"],
                        )
                    )
                )
                await asyncio.sleep(0)
                self.assertFalse(cancel.done())
                release_quiesce.set()
                started = await transition
                with self.assertRaises(HTTPException) as raised:
                    await cancel

        self.assertEqual(started["phase"], "starting")
        self.assertEqual(raised.exception.detail["code"], "server_update_not_cancelable")
        self.assertEqual(raised.exception.detail["schedule_id"], pending["schedule_id"])

    async def test_pending_defers_automation_but_preserves_manual_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            status_path = Path(temporary) / "status.json"
            stop_turn = AsyncMock(return_value={"stopped": True})
            resolve_codex = AsyncMock(return_value={"status": "resolved"})
            resolve_claude = AsyncMock(return_value={"status": "resolved"})
            with patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "BUSY_SESSIONS", {"active-chat"}), \
                 patch.object(agent_server, "MAX_ACTIVE_AGENT_RUNS", 0), \
                 patch.object(agent_server, "JOB_MAX_ACTIVE_RUNS", 0), \
                 patch.object(
                     agent_server,
                     "host_pressure_snapshot",
                     return_value={"available_mem_mb": 1_000_000},
                 ), \
                 patch.object(agent_server, "stop_turn", new=stop_turn), \
                 patch.object(agent_server, "resolve_codex_interaction", new=resolve_codex), \
                 patch.object(agent_server, "resolve_claude_interaction", new=resolve_claude):
                agent_server.write_fresh_server_update_status(
                    phase="pending",
                    schedule_id="c" * 32,
                    target_version="1.1.0",
                    track="stable",
                    when_idle=True,
                    cancelable=True,
                    blocker_counts={"active_runs": 1},
                )
                self.assertIsNone(agent_server.managed_server_update_blocker())
                admission = agent_server.managed_server_update_admission_blocker()
                interactive = await agent_server.turn_start_blocker()
                scheduled = await agent_server.scheduled_job_blocker("other-chat")
                manual_job = await agent_server.scheduled_job_blocker(
                    "other-chat",
                    manual=True,
                )
                stopped = await agent_server.stop_turn_endpoint("active-chat")
                codex = await agent_server.post_codex_interaction_response(
                    "active-chat",
                    "approval-1",
                    agent_server.CodexInteractionResponseRequest(
                        response={"decision": "accept"},
                    ),
                )
                claude = await agent_server.post_claude_interaction_response(
                    "active-chat",
                    "question-1",
                    agent_server.ClaudeInteractionResponseRequest(
                        response={"answer": "continue"},
                    ),
                )

        # A pending when-idle reservation remains passive for user/provider
        # controls, but unattended jobs must yield so recurring automation
        # cannot continuously refill the active-work set ahead of the updater.
        self.assertIsNone(admission)
        self.assertIsNone(interactive)
        self.assertEqual(
            scheduled,
            agent_server.MANAGED_SERVER_UPDATE_PENDING_DETAIL,
        )
        self.assertIsNone(manual_job)
        self.assertEqual(stopped, {"stopped": True})
        self.assertEqual(codex["interaction"]["status"], "resolved")
        self.assertEqual(claude["interaction"]["status"], "resolved")
        stop_turn.assert_awaited_once()
        stop_args, stop_kwargs = stop_turn.await_args
        self.assertEqual(stop_args, ("active-chat",))
        self.assertIsInstance(stop_kwargs.get("_admission_ready"), asyncio.Event)
        resolve_codex.assert_awaited_once()
        resolve_claude.assert_awaited_once()

    async def test_scheduled_job_admission_rechecks_pending_after_blocker_probe(self):
        """The turn reservation is the final fence for a scheduler race."""

        store = agent_server.JobStore()
        job_revision = "job_rev_pending_race"
        store.jobs["job_pending_race"] = {
            "id": "job_pending_race",
            "session_id": "job-chat",
            "title": "Yield to update",
            "prompt": "Do not replenish active work.",
            "enabled": True,
            "_revision": job_revision,
        }
        sessions = {
            "job-chat": {
                "id": "job-chat",
                "backend": agent_server.BACKEND_CODEX,
            },
        }

        class RuntimeProbeReached(RuntimeError):
            pass

        escaped_to_runtime = AsyncMock(side_effect=RuntimeProbeReached())

        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(agent_server, "JOBS", store), \
             patch.object(agent_server.STORE, "sessions", sessions), \
             patch.object(agent_server, "BUSY_SESSIONS", set()) as busy, \
             patch.object(agent_server, "ACTIVE", {}), \
             patch.object(agent_server, "CURRENT_TURNS", {}), \
             patch.object(agent_server, "QUEUED_TURNS", {}), \
             patch.object(agent_server, "RUN_NOW_TURNS", {}), \
             patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
             patch.object(
                 agent_server,
                 "ensure_runtime_available",
                 escaped_to_runtime,
             ):
            # Model the real TOCTOU: the scheduler's early blocker probe wins
            # just before a user reserves an idle update.
            self.assertIsNone(await agent_server.scheduled_job_blocker("job-chat"))
            agent_server.write_fresh_server_update_status(
                phase="pending",
                schedule_id="a" * 32,
                target_version="1.1.0",
                track="stable",
                when_idle=True,
                cancelable=True,
            )

            with self.assertRaises(agent_server.ManagedServerUpdatePendingError):
                await agent_server._start_turn_locked(
                    "job-chat",
                    agent_server.TurnRequest(
                        prompt="Do not replenish active work.",
                        purpose="scheduled_job",
                        job_id="job_pending_race",
                    ),
                    queue_if_busy=False,
                    scheduled_job_chat_references=True,
                    scheduled_job_revision=job_revision,
                    scheduled_job_manual_run=False,
                )
            escaped_to_runtime.assert_not_awaited()

            # Manual Run Now carries the same durable job revision, but it is
            # operator work and therefore must pass the pending-only fence.
            with self.assertRaises(RuntimeProbeReached):
                await agent_server._start_turn_locked(
                    "job-chat",
                    agent_server.TurnRequest(
                        prompt="Run this job now.",
                        purpose="scheduled_job",
                        job_id="job_pending_race",
                    ),
                    queue_if_busy=False,
                    scheduled_job_chat_references=True,
                    scheduled_job_revision=job_revision,
                    scheduled_job_manual_run=True,
                )

            # Merely claiming the scheduled-job purpose is not sufficient to
            # enter the autonomous lane. Only a revision-backed automatic
            # dispatch may be selectively fenced by a pending update.
            with self.assertRaises(RuntimeProbeReached):
                await agent_server._start_turn_locked(
                    "job-chat",
                    agent_server.TurnRequest(
                        prompt="Unowned scheduled-purpose turn.",
                        purpose="scheduled_job",
                    ),
                    queue_if_busy=False,
                )

            with self.assertRaises(RuntimeProbeReached):
                await agent_server._start_turn_locked(
                    "job-chat",
                    agent_server.TurnRequest(prompt="Ordinary user turn."),
                    queue_if_busy=False,
                )

        self.assertEqual(busy, set())
        self.assertEqual(escaped_to_runtime.await_count, 3)

    async def test_user_message_is_parked_durably_while_update_is_pending(self):
        queued = {"status": "queued", "queued_id": "queued-after-update"}
        store = MagicMock()
        store.sessions = {"chat": {"id": "chat", "backend": "codex"}}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(agent_server, "STORE", store), \
             patch.object(
                 agent_server,
                 "start_turn",
                 new=AsyncMock(
                     side_effect=agent_server.ManagedServerUpdatePendingError()
                 ),
             ), \
             patch.object(
                 agent_server,
                 "enqueue_turn",
                 new=AsyncMock(return_value=queued),
             ) as enqueue:
            agent_server.write_fresh_server_update_status(
                phase="pending",
                schedule_id="e" * 32,
                target_version="1.1.0",
                track="stable",
                when_idle=True,
                cancelable=True,
                blocker_counts={"active_runs": 1},
            )
            request = agent_server.TurnRequest(prompt="keep this message")
            result = await agent_server.post_turn("chat", request)

        self.assertEqual(result, queued)
        enqueue.assert_awaited_once_with("chat", request, store.sessions["chat"])

    async def test_generic_503_does_not_bypass_turn_admission(self):
        store = MagicMock()
        store.sessions = {"chat": {"id": "chat", "backend": "codex"}}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(agent_server, "STORE", store), \
             patch.object(
                 agent_server,
                 "start_turn",
                 new=AsyncMock(
                     side_effect=HTTPException(
                         status_code=503,
                         detail="some unrelated dependency is unavailable",
                     )
                 ),
             ), \
             patch.object(
                 agent_server,
                 "enqueue_turn",
                 new_callable=AsyncMock,
             ) as enqueue:
            agent_server.write_fresh_server_update_status(
                phase="pending",
                schedule_id="e" * 32,
                target_version="1.1.0",
                track="stable",
                when_idle=True,
                cancelable=True,
                blocker_counts={"active_runs": 1},
            )
            with self.assertRaises(HTTPException) as raised:
                await agent_server.post_turn(
                    "chat",
                    agent_server.TurnRequest(prompt="do not misclassify this"),
                )

        self.assertEqual(raised.exception.status_code, 503)
        enqueue.assert_not_awaited()

    async def test_pending_fallback_revalidates_archived_chat(self):
        store = MagicMock()
        store.sessions = {"chat": {"id": "chat", "backend": "codex"}}

        async def archive_then_report_pending(*_args, **_kwargs):
            store.sessions["chat"]["archived"] = True
            raise agent_server.ManagedServerUpdatePendingError()

        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(agent_server, "STORE", store), \
             patch.object(agent_server, "start_turn", new=archive_then_report_pending), \
             patch.object(
                 agent_server,
                 "enqueue_turn",
                 new_callable=AsyncMock,
             ) as enqueue:
            agent_server.write_fresh_server_update_status(
                phase="pending",
                schedule_id="e" * 32,
                target_version="1.1.0",
                track="stable",
                when_idle=True,
                cancelable=True,
                blocker_counts={"active_runs": 1},
            )
            with self.assertRaises(HTTPException) as raised:
                await agent_server.post_turn(
                    "chat",
                    agent_server.TurnRequest(prompt="do not queue after archive"),
                )

        self.assertEqual(raised.exception.status_code, 409)
        enqueue.assert_not_awaited()

    async def test_pending_fallback_retries_when_update_was_cancelled(self):
        store = MagicMock()
        store.sessions = {"chat": {"id": "chat", "backend": "codex"}}
        accepted = {"run_id": "run-after-cancel"}
        with tempfile.TemporaryDirectory() as temporary:
            status_path = Path(temporary) / "status.json"

            async def cancel_then_report_pending(*_args, **_kwargs):
                agent_server.write_fresh_server_update_status(
                    phase="available",
                    latest_version="1.1.0",
                    update_available=True,
                )
                raise agent_server.ManagedServerUpdatePendingError()

            calls = 0

            async def start_side_effect(*_args, **_kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return await cancel_then_report_pending()
                return accepted

            with patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "STORE", store), \
                 patch.object(agent_server, "start_turn", new=AsyncMock(side_effect=start_side_effect)) as start, \
                 patch.object(
                     agent_server,
                     "enqueue_turn",
                     new_callable=AsyncMock,
                 ) as enqueue:
                agent_server.write_fresh_server_update_status(
                    phase="pending",
                    schedule_id="e" * 32,
                    target_version="1.1.0",
                    track="stable",
                    when_idle=True,
                    cancelable=True,
                    blocker_counts={"active_runs": 1},
                )
                result = await agent_server.post_turn(
                    "chat",
                    agent_server.TurnRequest(prompt="start after cancellation"),
                )

        self.assertEqual(result, accepted)
        self.assertEqual(start.await_count, 2)
        enqueue.assert_not_awaited()

    async def test_cancel_pending_update_wakes_durable_queues_immediately(self):
        wake_queues = MagicMock(return_value=1)
        resume_jobs = AsyncMock(return_value=2)
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(
                 agent_server.TERMINAL_ATTACHMENTS,
                 "reopen_if_update_inactive",
                 new=AsyncMock(),
             ), \
             patch.object(
                 agent_server,
                 "schedule_rebuilt_queued_turns",
                 wake_queues,
             ), \
             patch.object(
                 agent_server.JOBS,
                 "resume_update_parked",
                 resume_jobs,
             ):
            pending = agent_server.write_fresh_server_update_status(
                phase="pending",
                schedule_id="c" * 32,
                target_version="1.1.0",
                latest_version="1.1.0",
                track="stable",
                when_idle=True,
                cancelable=True,
                blocker_counts={"active_runs": 1},
            )
            cancelled = await agent_server.cancel_server_update(
                agent_server.ServerUpdateCancelRequest(
                    schedule_id=pending["schedule_id"],
                )
            )

        self.assertEqual(cancelled["phase"], "available")
        self.assertEqual(cancelled["server_identity"], agent_server.server_identity())
        self.assertEqual(cancelled["server_instance_id"], agent_server.SERVER_INSTANCE_ID)
        resume_jobs.assert_awaited_once_with(pending["schedule_id"])
        wake_queues.assert_called_once_with()

    async def test_pending_allows_drain_safe_http_mutations(self):
        def request(method: str, path: str):
            return agent_server.Request({
                "type": "http",
                "asgi": {"version": "3.0"},
                "method": method,
                "scheme": "http",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "root_path": "",
                "headers": [],
                "client": ("127.0.0.1", 50000),
                "server": ("127.0.0.1", 7850),
            })

        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "AGENT_TOKEN", ""), \
             patch.object(agent_server, "UNSAFE_HTTP_MUTATION_TASKS", {}), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ):
            agent_server.write_fresh_server_update_status(
                phase="pending",
                schedule_id="f" * 32,
                target_version="1.1.0",
                track="stable",
                when_idle=True,
                cancelable=True,
                blocker_counts={"active_runs": 1},
            )
            observed: list[tuple[str, str, int]] = []

            async def mutation_next(incoming):
                observed.append((
                    incoming.method,
                    incoming.url.path,
                    agent_server.unsafe_http_mutation_count_locked(),
                ))
                return agent_server.JSONResponse({"accepted": True})

            for method, path in (
                ("POST", "/api/sessions/chat/unread"),
                ("DELETE", "/api/sessions/chat"),
            ):
                response = await agent_server.require_agent_token(
                    request(method, path),
                    mutation_next,
                )
                self.assertEqual(response.status_code, 200)
            pending = agent_server.read_server_update_status()

        self.assertEqual(
            observed,
            [
                ("POST", "/api/sessions/chat/unread", 1),
                ("DELETE", "/api/sessions/chat", 1),
            ],
        )
        self.assertEqual(agent_server.unsafe_http_mutation_count_locked(), 0)
        self.assertEqual(pending["phase"], "pending")
        self.assertEqual(pending["schedule_id"], "f" * 32)

    async def test_pending_allows_real_team_message_with_attachment_before_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            public_key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            public_key.write_text("public key\n")
            host_identity = "server-pending-team-message"
            runtime = agent_server.ManagedTeamHubHost(
                mode=agent_server.TEAM_HUB_MODE_HOST,
                data_dir=root / "hub",
                server_identity=host_identity,
                server_instance_id=agent_server.SERVER_INSTANCE_ID,
                allowed_hosts={"localhost", "127.0.0.1"},
            )
            runtime.initialize()
            self.assertIsNotNone(runtime.store)
            hub_mount = next(
                route
                for route in agent_server.app.routes
                if getattr(route, "name", None) == "team-hub"
            )
            server_mount = next(
                route
                for route in agent_server.app.routes
                if getattr(route, "name", None) == "team-hub-server-session"
            )
            original_hub_mount = hub_mount.app
            original_server_mount = server_mount.app
            hub_mount.app = runtime
            server_mount.app = runtime
            client = TestClient(
                agent_server.app,
                base_url="http://localhost",
                client=("127.0.0.1", 41000),
            )
            release_message = threading.Event()
            message_outbox_entered = threading.Event()
            message_task: asyncio.Task | None = None
            try:
                with ExitStack() as stack:
                    stack.enter_context(
                        patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime)
                    )
                    stack.enter_context(
                        patch.object(
                            agent_server,
                            "TEAM_HUB_DATA_DIR",
                            runtime.data_dir,
                        )
                    )
                    stack.enter_context(
                        patch.object(agent_server, "SERVER_VERSION", "1.0.0")
                    )
                    stack.enter_context(
                        patch.object(
                            agent_server,
                            "SERVER_UPDATE_STATUS_FILE",
                            root / "status.json",
                        )
                    )
                    stack.enter_context(
                        patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner)
                    )
                    stack.enter_context(
                        patch.object(
                            agent_server,
                            "SERVER_UPDATE_PUBLIC_KEY",
                            public_key,
                        )
                    )
                    stack.enter_context(
                        patch.object(agent_server, "AGENT_TOKEN", "test-secret")
                    )
                    stack.enter_context(
                        patch.object(
                            agent_server,
                            "server_identity",
                            return_value=host_identity,
                        )
                    )
                    for name, value in (
                        ("BUSY_SESSIONS", set()),
                        ("SERVER_MAINTENANCE_SESSIONS", set()),
                        ("ACTIVE", {}),
                        ("CURRENT_TURNS", {}),
                        ("QUEUED_TURNS", {}),
                        ("RUN_NOW_TURNS", {}),
                        ("UNSAFE_HTTP_MUTATION_TASKS", {}),
                    ):
                        stack.enter_context(patch.object(agent_server, name, value))
                    stack.enter_context(
                        patch.object(
                            agent_server,
                            "prepare_provider_background_work_snapshot",
                            new=AsyncMock(return_value={}),
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            agent_server,
                            "provider_background_work_labels_from_snapshot",
                            return_value=[],
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            agent_server,
                            "server_update_is_active",
                            return_value=False,
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            agent_server,
                            "working_tmux_bin",
                            return_value="/usr/bin/tmux",
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            agent_server,
                            "ensure_managed_update_tmux_isolated",
                            return_value=None,
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            agent_server,
                            "quiesce_managed_update_service_cgroup",
                            new=AsyncMock(return_value=None),
                        )
                    )
                    run_tmux = stack.enter_context(
                        patch.object(agent_server, "run_tmux", return_value=None)
                    )
                    proof = (
                        runtime.data_dir / "bootstrap-owner.proof"
                    ).read_text().strip()
                    bootstrap = client.post(
                        "/api/team-hub/v1/bootstrap/redeem",
                        headers={"X-Team-Hub-Bootstrap-Proof": proof},
                        json={
                            "email": "owner@example.com",
                            "display_name": "Owner",
                            "device_label": "Owner Mac",
                        },
                    )
                    self.assertEqual(bootstrap.status_code, 200, bootstrap.text)
                    headers = {"X-AgentsDock-Token": "test-secret"}
                    session = client.get(
                        "/api/team-hub-server/v1/server-session",
                        headers=headers,
                    )
                    self.assertEqual(session.status_code, 200, session.text)
                    team_id = session.json()["teams"][0]["id"]
                    pending = agent_server.write_fresh_server_update_status(
                        phase=agent_server.SERVER_UPDATE_PENDING_PHASE,
                        schedule_id="7" * 32,
                        target_version="1.1.0",
                        latest_version="1.1.0",
                        track="stable",
                        when_idle=True,
                        cancelable=True,
                        blocker_counts={"active_runs": 1},
                    )

                    attachment_bytes = b"real pending update attachment"
                    attachment = client.post(
                        f"/api/team-hub-server/v1/teams/{team_id}/network/attachments",
                        headers=headers,
                        json={
                            "file_name": "pending.txt",
                            "media_type": "text/plain",
                            "byte_size": len(attachment_bytes),
                            "sha256": hashlib.sha256(attachment_bytes).hexdigest(),
                            "idempotency_key": "pending-attachment-declare-1",
                        },
                    )
                    self.assertEqual(attachment.status_code, 200, attachment.text)
                    attachment_id = attachment.json()["attachment"]["id"]
                    uploaded = client.put(
                        f"/api/team-hub-server/v1/teams/{team_id}/network/"
                        f"attachments/{attachment_id}/content",
                        headers={
                            **headers,
                            "Content-Type": "application/octet-stream",
                            "Content-Range": (
                                f"bytes 0-{len(attachment_bytes) - 1}/"
                                f"{len(attachment_bytes)}"
                            ),
                        },
                        content=attachment_bytes,
                    )
                    self.assertEqual(uploaded.status_code, 200, uploaded.text)
                    self.assertEqual(
                        agent_server.read_server_update_status()["phase"],
                        "pending",
                    )

                    store = runtime.store
                    assert store is not None
                    original_outbox = store._outbox

                    def hold_message_transaction(*args):
                        if len(args) >= 5 and args[4] == "team.message.created":
                            message_outbox_entered.set()
                            if not release_message.wait(30):
                                raise RuntimeError("message transaction was not released")
                        return original_outbox(*args)

                    with patch.object(store, "_outbox", side_effect=hold_message_transaction):
                        message_task = asyncio.create_task(
                            asyncio.to_thread(
                                client.post,
                                f"/api/team-hub-server/v1/teams/{team_id}/network/messages",
                                headers=headers,
                                json={
                                    "kind": "message",
                                    "body": "commit before pending update starts",
                                    "body_format": "plain",
                                    "recipients": [{"kind": "all"}],
                                    "attachment_ids": [attachment_id],
                                    "idempotency_key": "pending-message-create-1",
                                },
                            )
                        )
                        entered = await asyncio.wait_for(
                            asyncio.to_thread(message_outbox_entered.wait, 2),
                            timeout=3,
                        )
                        self.assertTrue(entered)
                        self.assertEqual(
                            agent_server.unsafe_http_mutation_count_locked(),
                            1,
                        )
                        still_pending = (
                            await agent_server.advance_pending_server_update_once()
                        )
                        self.assertEqual(still_pending["phase"], "pending")
                        self.assertEqual(
                            still_pending["schedule_id"],
                            pending["schedule_id"],
                        )
                        self.assertEqual(
                            still_pending["blocker_counts"][
                                "in_flight_server_changes"
                            ],
                            1,
                        )
                        run_tmux.assert_not_called()
                        release_message.set()
                        message_response = await message_task
                    self.assertEqual(
                        message_response.status_code,
                        200,
                        message_response.text,
                    )
                    message = message_response.json()["message"]
                    self.assertEqual(
                        [item["id"] for item in message["attachments"]],
                        [attachment_id],
                    )
                    connection = store.connect()
                    try:
                        committed = connection.execute(
                            "SELECT id FROM team_messages WHERE id=? AND body=?",
                            (
                                message["id"],
                                "commit before pending update starts",
                            ),
                        ).fetchone()
                        bound = connection.execute(
                            "SELECT message_id FROM team_attachments WHERE id=?",
                            (attachment_id,),
                        ).fetchone()
                        self.assertIsNotNone(committed)
                        self.assertEqual(bound["message_id"], message["id"])
                    finally:
                        connection.close()
                    self.assertEqual(
                        agent_server.unsafe_http_mutation_count_locked(),
                        0,
                    )

                    started = await agent_server.advance_pending_server_update_once()
                    self.assertEqual(started["phase"], "starting")
                    self.assertEqual(started["schedule_id"], pending["schedule_id"])
                    run_tmux.assert_called_once()
                    snapshot = (
                        runtime.data_dir
                        / "maintenance-backups"
                        / started["team_hub_snapshot_generation"]
                        / "team-hub.sqlite3"
                    )
                    copied = sqlite3.connect(snapshot)
                    try:
                        self.assertEqual(
                            copied.execute(
                                "SELECT COUNT(*) FROM team_messages WHERE id=?",
                                (message["id"],),
                            ).fetchone()[0],
                            1,
                        )
                        self.assertEqual(
                            copied.execute(
                                "SELECT message_id FROM team_attachments WHERE id=?",
                                (attachment_id,),
                            ).fetchone()[0],
                            message["id"],
                        )
                    finally:
                        copied.close()
            finally:
                release_message.set()
                if message_task is not None and not message_task.done():
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(message_task),
                            timeout=10,
                        )
                    except BaseException:
                        pass
                client.close()
                hub_mount.app = original_hub_mount
                server_mount.app = original_server_mount
                await runtime.shutdown()

    async def test_pending_allows_terminal_reconnect(self):
        class Socket:
            pass

        registry = agent_server.TerminalAttachmentRegistry()
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ):
            agent_server.write_fresh_server_update_status(
                phase="pending",
                schedule_id="d" * 32,
                target_version="1.1.0",
                track="stable",
                when_idle=True,
                cancelable=True,
                blocker_counts={"active_runs": 1},
            )
            admitted = await registry.reserve("chat", Socket())
            agent_server.write_fresh_server_update_status(
                phase="starting",
                update_id="e" * 32,
                target_version="1.1.0",
                track="stable",
                cancelable=False,
            )
            blocked_after_transition = await registry.reserve("chat", Socket())
            snapshot = await registry.snapshot()

        self.assertTrue(admitted)
        self.assertFalse(blocked_after_transition)
        self.assertTrue(snapshot["admission_open"])
        self.assertEqual(snapshot["active_connections"], 1)

    async def test_startup_preserves_valid_pending_and_fails_malformed_schedule(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ):
            original = agent_server.write_fresh_server_update_status(
                phase="pending",
                schedule_id="e" * 32,
                target_version="1.1.0",
                latest_version="1.1.0",
                track="stable",
                when_idle=True,
                cancelable=True,
                blocker_counts={"active_runs": 1},
            )
            recovered = await agent_server.reconcile_server_update_status_after_startup()
            agent_server.write_fresh_server_update_status(
                phase="pending",
                schedule_id=None,
                target_version="1.2.0",
                track="stable",
                when_idle=True,
                cancelable=True,
            )
            malformed = await agent_server.reconcile_server_update_status_after_startup()

        self.assertEqual(recovered["phase"], "pending")
        self.assertEqual(recovered["schedule_id"], original["schedule_id"])
        self.assertEqual(recovered["updated_at"], original["updated_at"])
        self.assertEqual(malformed["phase"], "failed")
        self.assertEqual(
            malformed["error_code"],
            "server_update_schedule_invalid",
        )
        self.assertTrue(malformed["retryable"])

    async def test_start_rejects_update_while_queued_turns_are_not_durable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            queued = {
                "chat": deque(
                    [
                        {"queued_id": "one", "_durable": False},
                        {"queued_id": "two", "_durable": False},
                    ]
                )
            }
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "BUSY_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", queued), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux") as run_tmux:
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(version="1.1.0"),
                    )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("2 queued turns", str(raised.exception.detail))
        run_tmux.assert_not_called()

    async def test_start_preserves_durable_queued_turns_and_launches_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            queued = {
                "chat": deque([
                    {
                        "queued_id": "kept",
                        "prompt": "Keep this for later.",
                        "_durable": True,
                        "_paused_after_stop": True,
                    },
                ]),
            }
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "BUSY_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", queued), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "active_provider_background_work_labels", return_value=[]), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux") as run_tmux:
                status = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(version="1.1.0"),
                )

        self.assertEqual(status["phase"], "starting")
        self.assertEqual(list(queued["chat"])[0]["queued_id"], "kept")
        run_tmux.assert_called_once()

    async def test_start_rejects_update_while_a_codex_subagent_is_live(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            status_path = root / "status.json"
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "BUSY_SESSIONS", set()), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "CLAUDE_SDK_MANAGER", None), \
                 patch.object(
                     agent_server,
                     "active_codex_work_labels",
                     return_value=["Codex subagent child-thread"],
                 ), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux") as run_tmux:
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(version="1.1.0"),
                    )

            self.assertFalse(status_path.exists())
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("Codex subagent child-thread", str(raised.exception.detail))
        run_tmux.assert_not_called()

    async def test_start_rejects_loaded_claude_background_subagent(self):
        class LoadedClaudeManager:
            @staticmethod
            def is_loaded(session_id):
                return session_id == "claude-chat"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            status_path = root / "status.json"
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server.STORE, "sessions", {
                     "claude-chat": {
                         "id": "claude-chat",
                         "backend": agent_server.BACKEND_CLAUDE,
                     },
                 }), \
                 patch.object(agent_server, "BUSY_SESSIONS", set()), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "CLAUDE_SDK_MANAGER", LoadedClaudeManager()), \
                 patch.object(agent_server, "active_codex_work_labels", return_value=[]), \
                 patch.object(
                     agent_server,
                     "build_claude_subagent_snapshot",
                     return_value={"active_count": 1},
                 ), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux") as run_tmux:
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(version="1.1.0"),
                    )

            self.assertFalse(status_path.exists())
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("Claude background work in claude-chat", str(raised.exception.detail))
        run_tmux.assert_not_called()

    async def test_start_ignores_stale_claude_history_when_supervisor_is_unloaded(self):
        class UnloadedClaudeManager:
            @staticmethod
            def is_loaded(_session_id):
                return False

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            snapshot = MagicMock(return_value={"active_count": 1})
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "AGENT_TOKEN", ""), \
                 patch.object(agent_server.STORE, "sessions", {
                     "claude-chat": {
                         "id": "claude-chat",
                         "backend": agent_server.BACKEND_CLAUDE,
                     },
                 }), \
                 patch.object(agent_server, "BUSY_SESSIONS", set()), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "CLAUDE_SDK_MANAGER", UnloadedClaudeManager()), \
                 patch.object(agent_server, "active_codex_work_labels", return_value=[]), \
                 patch.object(agent_server, "build_claude_subagent_snapshot", snapshot), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux", return_value=None) as run_tmux:
                status = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(version="1.1.0"),
                )

        self.assertEqual(status["phase"], "starting")
        snapshot.assert_not_called()
        run_tmux.assert_called_once()

    async def test_start_fails_closed_when_claude_load_state_cannot_be_inspected(self):
        class BrokenClaudeManager:
            @staticmethod
            def is_loaded(_session_id):
                raise RuntimeError("supervisor registry unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            status_path = root / "status.json"
            snapshot = MagicMock(return_value={"active_count": 0})
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", status_path), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server.STORE, "sessions", {
                     "claude-chat": {
                         "id": "claude-chat",
                         "backend": agent_server.BACKEND_CLAUDE,
                     },
                 }), \
                 patch.object(agent_server, "BUSY_SESSIONS", set()), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "CLAUDE_SDK_MANAGER", BrokenClaudeManager()), \
                 patch.object(agent_server, "active_codex_work_labels", return_value=[]), \
                 patch.object(agent_server, "build_claude_subagent_snapshot", snapshot), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux") as run_tmux:
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(version="1.1.0"),
                    )

            self.assertFalse(status_path.exists())
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn(
            "Claude provider state unknown in claude-chat",
            str(raised.exception.detail),
        )
        snapshot.assert_not_called()
        run_tmux.assert_not_called()

    async def test_start_allows_loaded_claude_with_terminal_subagents(self):
        class LoadedClaudeManager:
            @staticmethod
            def is_loaded(session_id):
                return session_id == "claude-chat"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "AGENT_TOKEN", ""), \
                 patch.object(agent_server.STORE, "sessions", {
                     "claude-chat": {
                         "id": "claude-chat",
                         "backend": agent_server.BACKEND_CLAUDE,
                     },
                 }), \
                 patch.object(agent_server, "BUSY_SESSIONS", set()), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "CLAUDE_SDK_MANAGER", LoadedClaudeManager()), \
                 patch.object(agent_server, "active_codex_work_labels", return_value=[]), \
                 patch.object(
                     agent_server,
                     "build_claude_subagent_snapshot",
                     return_value={"active_count": 0},
                 ), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux", return_value=None) as run_tmux:
                status = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(version="1.1.0"),
                )

        self.assertEqual(status["phase"], "starting")
        run_tmux.assert_called_once()

    async def test_update_admission_wins_race_with_new_turn_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            updater_launched = threading.Event()
            release_updater = threading.Event()

            def blocked_tmux(_args):
                updater_launched.set()
                release_updater.wait(timeout=2)

            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "AGENT_TOKEN", ""), \
                 patch.object(agent_server.STORE, "sessions", {
                     "chat": {
                         "id": "chat",
                         "backend": agent_server.BACKEND_CODEX,
                     }
                 }), \
                 patch.object(agent_server, "BUSY_SESSIONS", set()), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "CURRENT_TURNS", {}), \
                 patch.object(agent_server, "QUEUED_TURNS", {}), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux", side_effect=blocked_tmux):
                update_task = asyncio.create_task(
                    agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(version="1.1.0"),
                    )
                )
                try:
                    self.assertTrue(
                        await asyncio.to_thread(updater_launched.wait, 1)
                    )
                    with self.assertRaises(HTTPException) as raised:
                        await agent_server._start_turn_locked(
                            "chat",
                            agent_server.TurnRequest(prompt="must not start"),
                        )
                finally:
                    release_updater.set()
                await update_task

        self.assertEqual(raised.exception.status_code, 503)
        self.assertIn("managed update", str(raised.exception.detail))

    async def test_update_rejects_while_nonreserving_control_is_loading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            control_started = asyncio.Event()
            release_control = asyncio.Event()

            async def slow_ensure(*_args, **_kwargs):
                control_started.set()
                await release_control.wait()
                return "thread", "instruction-hash"

            manager = AsyncMock()
            manager.start = AsyncMock()
            maintenance: set[str] = set()
            unpin = AsyncMock()
            with ExitStack() as patches:
                patches.enter_context(
                    patch.object(agent_server, "SERVER_VERSION", "1.0.0")
                )
                patches.enter_context(
                    patch.object(
                        agent_server,
                        "SERVER_UPDATE_STATUS_FILE",
                        root / "status.json",
                    )
                )
                patches.enter_context(
                    patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner)
                )
                patches.enter_context(
                    patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key)
                )
                patches.enter_context(
                    patch.object(
                        agent_server,
                        "CODEX_TRANSPORT",
                        agent_server.CODEX_TRANSPORT_APP_SERVER,
                    )
                )
                patches.enter_context(patch.object(agent_server.STORE, "sessions", {
                     "chat": {
                         "id": "chat",
                         "backend": agent_server.BACKEND_CODEX,
                         "codex_thread_id": "thread",
                         "cwd": "/work",
                     }
                }))
                patches.enter_context(
                    patch.object(agent_server, "BUSY_SESSIONS", set())
                )
                patches.enter_context(
                    patch.object(
                        agent_server,
                        "SERVER_MAINTENANCE_SESSIONS",
                        maintenance,
                    )
                )
                patches.enter_context(
                    patch.object(agent_server, "CURRENT_TURNS", {})
                )
                patches.enter_context(
                    patch.object(agent_server, "QUEUED_TURNS", {})
                )
                patches.enter_context(
                    patch.object(agent_server, "RUN_NOW_TURNS", {})
                )
                patches.enter_context(
                    patch.object(
                        agent_server,
                        "server_update_is_active",
                        return_value=False,
                    )
                )
                patches.enter_context(
                    patch.object(
                        agent_server,
                        "working_tmux_bin",
                        return_value="/usr/bin/tmux",
                    )
                )
                run_tmux = patches.enter_context(
                    patch.object(agent_server, "run_tmux")
                )
                patches.enter_context(
                    patch.object(
                        agent_server,
                        "codex_app_server_manager",
                        AsyncMock(return_value=manager),
                    )
                )
                patches.enter_context(
                    patch.object(
                        agent_server,
                        "ensure_codex_app_server_thread",
                        AsyncMock(side_effect=slow_ensure),
                    )
                )
                patches.enter_context(
                    patch.object(
                        agent_server,
                        "unpin_codex_app_server_thread",
                        unpin,
                    )
                )
                patches.enter_context(
                    patch.object(
                        agent_server,
                        "acquire_codex_interactive_control_lease",
                    )
                )
                patches.enter_context(
                    patch.object(
                        agent_server,
                        "release_codex_interactive_control_lease",
                    )
                )
                control_task = asyncio.create_task(
                    agent_server.acquire_codex_control_thread(
                        "chat",
                        reserve_session=False,
                    )
                )
                await asyncio.wait_for(control_started.wait(), timeout=1)
                try:
                    self.assertEqual(maintenance, {"chat"})
                    with self.assertRaises(HTTPException) as raised:
                        await agent_server.start_server_update(
                            agent_server.ServerUpdateRequest(version="1.1.0"),
                        )
                finally:
                    release_control.set()
                manager_result, thread_id, _session = await control_task
                await agent_server.release_codex_control_thread(
                    "chat",
                    manager_result,
                    thread_id,
                    schedule_queue=False,
                )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("active agent run", str(raised.exception.detail))
        self.assertEqual(maintenance, set())
        run_tmux.assert_not_called()
        unpin.assert_awaited_once_with(manager, "thread")

    async def test_tmux_launch_failure_reopens_admission_and_removes_credential(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "AGENT_TOKEN", "test-secret"), \
                 patch.object(agent_server, "BUSY_SESSIONS", set()), \
                 patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()), \
                 patch.object(agent_server, "QUEUED_TURNS", {
                     "chat": deque([{
                         "queued_id": "resume-after-launch-failure",
                         "_durable": True,
                     }]),
                 }), \
                 patch.object(agent_server, "RUN_NOW_TURNS", {}), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(
                     agent_server,
                     "schedule_rebuilt_queued_turns",
                     return_value=1,
                 ) as wake_queues, \
                 patch.object(
                     agent_server,
                     "run_tmux",
                     side_effect=RuntimeError("tmux failed"),
                 ):
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.start_server_update(
                        agent_server.ServerUpdateRequest(version="1.1.0"),
                    )
                status = agent_server.read_server_update_status()
                blocker = agent_server.managed_server_update_blocker()
                credentials = list(root.glob(".server-update-*.auth.json"))

        self.assertEqual(raised.exception.status_code, 500)
        self.assertEqual(status["phase"], "failed")
        self.assertIsNone(blocker)
        self.assertEqual(credentials, [])
        wake_queues.assert_called_once_with()

    async def test_starting_update_blocks_new_interactive_and_scheduled_work(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(agent_server, "BUSY_SESSIONS", set()):
            agent_server.write_server_update_status(
                phase="starting",
                target_version="1.1.0",
            )
            interactive = await agent_server.turn_start_blocker()
            scheduled = await agent_server.scheduled_job_blocker("chat")

        self.assertIn("managed update", str(interactive))
        self.assertIn("managed update", str(scheduled))

    def test_restarted_target_version_stays_drained_until_runner_completes(self):
        self.assertTrue(
            agent_server.managed_server_update_blocks_work(
                {
                    "phase": "restarting",
                    "target_version": agent_server.SERVER_VERSION,
                }
            )
        )

    async def test_start_passes_user_service_environment_into_detached_tmux(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "server_update_runner_environment", return_value={
                     "XDG_RUNTIME_DIR": "/run/user/123",
                     "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/123/bus",
                 }), \
                 patch.object(agent_server, "run_tmux", return_value=None) as run_tmux:
                await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(version="1.1.0"),
                )

        command = run_tmux.call_args.args[0][-1]
        self.assertIn("env XDG_RUNTIME_DIR=/run/user/123", command)
        self.assertIn(
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/123/bus",
            command,
        )
        self.assertIn("--expected-version 1.1.0", command)

    async def test_start_beta_release_passes_beta_track_to_runner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            with patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux", return_value=None) as run_tmux:
                status = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="1.1.0-beta.3",
                        track="beta",
                    )
                )

        self.assertEqual(status["track"], "beta")
        self.assertTrue(status["channel_switch"])
        self.assertIn("--track beta", run_tmux.call_args.args[0][-1])

    async def test_legacy_start_without_track_infers_installed_beta_track(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            with patch.object(agent_server, "SERVER_VERSION", "1.1.0-beta.2"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(agent_server, "run_tmux", return_value=None) as run_tmux:
                status = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(version="1.1.0-beta.3")
                )

        self.assertEqual(status["track"], "beta")
        self.assertIn("--track beta", run_tmux.call_args.args[0][-1])

    async def test_start_allows_explicit_beta_to_stable_switch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "update_runner.py"
            key = root / "release-public-key.pem"
            runner.write_text("# runner\n")
            key.write_text("public key\n")
            with patch.object(agent_server, "SERVER_VERSION", "1.1.0-beta.3"), \
                 patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", root / "status.json"), \
                 patch.object(agent_server, "SERVER_UPDATE_RUNNER", runner), \
                 patch.object(agent_server, "SERVER_UPDATE_PUBLIC_KEY", key), \
                 patch.object(agent_server, "server_update_is_active", return_value=False), \
                 patch.object(agent_server, "working_tmux_bin", return_value="/usr/bin/tmux"), \
                 patch.object(
                     agent_server,
                     "signed_release_manifest",
                     new=AsyncMock(return_value={"version": "1.0.0"}),
                 ), \
                 patch.object(agent_server, "run_tmux", return_value=None) as run_tmux:
                status = await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="1.0.0",
                        track="stable",
                    )
                )

        self.assertEqual(status["phase"], "starting")
        self.assertTrue(status["channel_switch"])
        self.assertIn("--track stable", run_tmux.call_args.args[0][-1])

    async def test_start_rejects_beta_switch_to_an_older_nonlatest_stable(self):
        latest = AsyncMock(return_value={"version": "1.0.1"})
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "9.0.0-beta.1"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(
                 agent_server,
                 "managed_server_restart_blocks_work",
                 return_value=False,
             ), \
             patch.object(
                 agent_server,
                 "signed_release_manifest",
                 new=latest,
             ), \
             patch.object(agent_server, "run_tmux") as run_tmux:
            with self.assertRaises(HTTPException) as raised:
                await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="0.1.0",
                        track="stable",
                    )
                )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(
            raised.exception.detail["code"],
            "server_update_target_superseded",
        )
        self.assertEqual(raised.exception.detail["latest_version"], "1.0.1")
        latest.assert_awaited_once_with("stable")
        run_tmux.assert_not_called()

    async def test_recovered_pending_beta_switch_revalidates_latest_stable(self):
        schedule_id = "b" * 32
        latest = AsyncMock(return_value={"version": "1.0.1"})
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "9.0.0-beta.1"), \
             patch.object(
                 agent_server,
                 "SERVER_UPDATE_STATUS_FILE",
                 Path(temporary) / "status.json",
             ), \
             patch.object(
                 agent_server,
                 "managed_server_restart_blocks_work",
                 return_value=False,
             ), \
             patch.object(
                 agent_server,
                 "signed_release_manifest",
                 new=latest,
             ), \
             patch.object(agent_server, "run_tmux") as run_tmux:
            agent_server.write_fresh_server_update_status(
                phase="pending",
                schedule_id=schedule_id,
                target_version="0.1.0",
                latest_version="0.1.0",
                track="stable",
                when_idle=True,
                cancelable=True,
            )
            with self.assertRaises(HTTPException) as raised:
                await agent_server.advance_pending_server_update_once()
            status = agent_server.fail_pending_server_update(
                schedule_id,
                raised.exception,
            )

        self.assertEqual(status["phase"], "available")
        self.assertIsNone(status["schedule_id"])
        self.assertIsNone(status["target_version"])
        self.assertEqual(status["latest_version"], "1.0.1")
        self.assertEqual(status["error_code"], "server_update_target_superseded")
        self.assertTrue(status["update_available"])
        self.assertTrue(status["checked_at"])
        latest.assert_awaited_once_with("stable")
        run_tmux.assert_not_called()

    async def test_start_rejects_version_that_does_not_match_track(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.0.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.start_server_update(
                    agent_server.ServerUpdateRequest(
                        version="1.1.0-beta.3",
                        track="stable",
                    )
                )

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("stable track", str(raised.exception.detail))

    async def test_start_refuses_stable_to_older_stable_downgrade(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.2.0"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "run_tmux") as run_tmux:
            status = await agent_server.start_server_update(
                agent_server.ServerUpdateRequest(version="1.1.0", track="stable")
            )

        self.assertEqual(status["phase"], "current")
        self.assertFalse(status["update_available"])
        run_tmux.assert_not_called()

    async def test_start_refuses_beta_to_older_beta_downgrade(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(agent_server, "SERVER_VERSION", "1.2.0-beta.4"), \
             patch.object(agent_server, "SERVER_UPDATE_STATUS_FILE", Path(temporary) / "status.json"), \
             patch.object(agent_server, "server_update_is_active", return_value=False), \
             patch.object(agent_server, "run_tmux") as run_tmux:
            status = await agent_server.start_server_update(
                agent_server.ServerUpdateRequest(
                    version="1.2.0-beta.3",
                    track="beta",
                )
            )

        self.assertEqual(status["phase"], "current")
        self.assertFalse(status["update_available"])
        run_tmux.assert_not_called()


if __name__ == "__main__":
    unittest.main()
