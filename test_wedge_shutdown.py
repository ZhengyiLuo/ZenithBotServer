"""Regression tests for the 2026-09-04 wedge, shutdown half: a cooperative
restart that never finishes, and forced kills that orphan Codex children."""

import asyncio
import json
import os
import re
import signal
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import agent_server
from codex_app_server import CodexAppServerClient
from test_codex_app_server import FakeProcessFactory
from test_server_restart_endpoints import (
    SERVER_INSTANCE_ID,
    restart_environment,
)


def fake_ps(table: dict[int, dict[str, str]]):
    """Build a ``subprocess.run`` stand-in answering ``ps -o <col>= -p <pid>``."""

    def run(args, **_kwargs):
        column = str(args[2]).rstrip("=")
        pid = int(args[4])
        stdout = table.get(pid, {}).get(column, "")
        return subprocess.CompletedProcess(args, 0, stdout=stdout + "\n", stderr="")

    return run


def provider_child_entry(
    pid: int,
    *,
    command: str = "node codex app-server --listen stdio://",
) -> dict[str, object]:
    return {
        "pid": pid,
        "pgid": pid,
        "kind": "codex-app-server",
        "boot_identity": "test-boot",
        "process_start_identity": f"start-{pid}",
        "executable_identity": "/usr/bin/node",
        "command_fingerprint": (
            agent_server.provider_child_command_fingerprint(command)
        ),
    }


class RestartWatchdogTests(unittest.TestCase):
    def test_cooperative_signal_arms_watchdog_with_graceful_delay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request_id = str(uuid.uuid4())
            watchdog = MagicMock()
            with restart_environment(root), \
                 patch.object(agent_server.time, "sleep"), \
                 patch.object(agent_server.os, "getpid", return_value=321), \
                 patch.object(agent_server.os, "kill") as kill, \
                 patch.object(agent_server.threading, "Thread", return_value=watchdog) as thread:
                agent_server.write_server_restart_status(
                    phase="accepted",
                    request_id=request_id,
                    _source_instance_id=SERVER_INSTANCE_ID,
                )
                agent_server.signal_managed_server_restart(request_id)

        thread.assert_called_once_with(
            target=agent_server.force_kill_managed_server_after_deadline,
            args=(
                request_id,
                321,
                agent_server.SERVER_RESTART_GRACEFUL_KILL_DELAY_SECONDS,
            ),
            daemon=True,
            name="agents-server-force-restart",
        )
        watchdog.start.assert_called_once_with()
        kill.assert_called_once_with(321, signal.SIGTERM)
        self.assertGreater(
            agent_server.SERVER_RESTART_GRACEFUL_KILL_DELAY_SECONDS,
            agent_server.SERVER_RESTART_FORCE_KILL_DELAY_SECONDS,
        )

    def test_watchdog_sleeps_for_requested_delay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with restart_environment(root), \
                 patch.object(agent_server.time, "sleep") as sleep, \
                 patch.object(agent_server.os, "getpid", return_value=321), \
                 patch.object(agent_server.os, "kill"):
                agent_server.force_kill_managed_server_after_deadline(
                    "req",
                    321,
                    agent_server.SERVER_RESTART_GRACEFUL_KILL_DELAY_SECONDS,
                )
                agent_server.force_kill_managed_server_after_deadline("req", 321)

        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            [
                agent_server.SERVER_RESTART_GRACEFUL_KILL_DELAY_SECONDS,
                agent_server.SERVER_RESTART_FORCE_KILL_DELAY_SECONDS,
            ],
        )

    def test_watchdog_kills_registered_codex_group_before_server(self):
        order: list[tuple[str, int, int]] = []

        def record_kill(pid, sig):
            if sig == 0:
                if pid == 4555:
                    raise ProcessLookupError(pid)
                return None
            order.append(("kill", pid, sig))

        def record_killpg(pgid, sig):
            order.append(("killpg", pgid, sig))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with restart_environment(root), \
                 patch.object(agent_server, "PROVIDER_CHILD_PROC_ROOT", root / "no-proc"), \
                 patch.object(agent_server.time, "sleep"), \
                 patch.object(agent_server.os, "getpid", return_value=321), \
                 patch.object(agent_server.os, "kill", side_effect=record_kill), \
                 patch.object(agent_server.os, "killpg", side_effect=record_killpg), \
                 patch.object(
                     agent_server,
                     "provider_host_boot_identity",
                     return_value="test-boot",
                 ), \
                 patch.object(
                     agent_server,
                     "provider_child_process_start_identity",
                     side_effect=lambda pid: f"start-{pid}",
                 ), \
                 patch.object(
                     agent_server,
                     "provider_child_executable_identity",
                     return_value="/usr/bin/node",
                 ), \
                 patch.object(
                     agent_server,
                     "process_group_for_pid",
                     side_effect=lambda pid: pid,
                 ), \
                 patch.object(
                     agent_server.subprocess,
                     "run",
                     side_effect=fake_ps({
                         4321: {"command": "node codex app-server --listen stdio://"},
                         4444: {"command": "python unrelated-daemon"},
                     }),
                 ):
                agent_server.write_provider_children_registry([
                    provider_child_entry(4321),
                    # Recycled pid now running something else: never signal.
                    provider_child_entry(4444),
                    # A dead leader cannot authenticate a surviving numeric
                    # PGID; it may have been reused after a reboot/hard kill.
                    provider_child_entry(4555),
                ])
                agent_server.force_kill_managed_server_after_deadline("req", 321)

        self.assertEqual(
            order,
            [
                ("killpg", 4321, signal.SIGKILL),
                ("kill", 321, signal.SIGKILL),
            ],
        )

    def test_watchdog_probe_failure_still_kills_server(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with restart_environment(root), \
                 patch.object(agent_server, "PROVIDER_CHILD_PROC_ROOT", root / "no-proc"), \
                 patch.object(agent_server.time, "sleep"), \
                 patch.object(agent_server.os, "getpid", return_value=321), \
                 patch.object(agent_server.os, "kill") as kill, \
                 patch.object(agent_server.os, "killpg") as killpg, \
                 patch.object(
                     agent_server.subprocess,
                     "run",
                     side_effect=subprocess.TimeoutExpired("ps", 1.0),
                 ):
                agent_server.write_provider_children_registry([
                    {"pid": 4321, "pgid": 4321, "kind": "codex-app-server"},
                ])
                agent_server.force_kill_managed_server_after_deadline("req", 321)

        killpg.assert_not_called()
        self.assertEqual(kill.call_args_list[-1].args, (321, signal.SIGKILL))


class ProviderChildRegistryTests(unittest.TestCase):
    def test_register_and_unregister_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            registry = Path(temporary) / "admin" / "provider-children.json"
            with patch.object(agent_server, "PROVIDER_CHILDREN_FILE", registry), \
                 patch.object(
                     agent_server,
                     "provider_host_boot_identity",
                     return_value="test-boot",
                 ), \
                 patch.object(
                     agent_server,
                     "provider_child_process_start_identity",
                     return_value="start-4321",
                 ), \
                 patch.object(
                     agent_server,
                     "provider_child_executable_identity",
                     return_value="/usr/bin/node",
                 ), \
                 patch.object(
                     agent_server,
                     "provider_child_command_line",
                     return_value="node codex app-server --listen stdio://",
                 ), \
                 patch.object(
                     agent_server,
                     "process_group_for_pid",
                     return_value=4321,
                 ):
                agent_server.register_provider_child(4321, 4321)
                children = agent_server.read_provider_children_registry()
                on_disk = json.loads(registry.read_text())
                agent_server.unregister_provider_child(4321)
                after_remove = agent_server.read_provider_children_registry()
                after_remove_on_disk = json.loads(registry.read_text())

        self.assertEqual(len(children), 1)
        self.assertEqual(children[0]["pid"], 4321)
        self.assertEqual(children[0]["pgid"], 4321)
        self.assertEqual(children[0]["kind"], "codex-app-server")
        self.assertEqual(children[0]["owner_pid"], os.getpid())
        self.assertTrue(children[0]["started_at"])
        self.assertEqual(children[0]["boot_identity"], "test-boot")
        self.assertEqual(children[0]["process_start_identity"], "start-4321")
        self.assertEqual(children[0]["executable_identity"], "/usr/bin/node")
        self.assertRegex(children[0]["command_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(on_disk["children"][0]["pid"], 4321)
        self.assertEqual(after_remove, [])
        self.assertEqual(after_remove_on_disk, {"children": []})

    def test_register_requires_owned_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            registry = Path(temporary) / "admin" / "provider-children.json"
            with patch.object(agent_server, "PROVIDER_CHILDREN_FILE", registry):
                agent_server.register_provider_child(4321, None)
                registered = agent_server.read_provider_children_registry()
                exists = registry.exists()

        self.assertEqual(registered, [])
        self.assertFalse(exists)

    def test_registry_drops_malformed_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            registry = Path(temporary) / "admin" / "provider-children.json"
            registry.parent.mkdir(parents=True)
            registry.write_text(json.dumps({
                "children": [
                    {"pid": 1, "pgid": "nope"},
                    {"pid": True, "pgid": 2},
                    "garbage",
                    {"pid": 7, "pgid": 7, "kind": "codex-app-server"},
                ],
            }))
            with patch.object(agent_server, "PROVIDER_CHILDREN_FILE", registry):
                children = agent_server.read_provider_children_registry()
            registry.write_text("{not json")
            with patch.object(agent_server, "PROVIDER_CHILDREN_FILE", registry):
                corrupt = agent_server.read_provider_children_registry()

        self.assertEqual([entry["pid"] for entry in children], [7])
        self.assertEqual(corrupt, [])


class ProviderChildSweepTests(unittest.TestCase):
    def test_startup_sweep_reaps_orphan_and_keeps_owned_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry = root / "admin" / "provider-children.json"
            with patch.object(agent_server, "PROVIDER_CHILDREN_FILE", registry), \
                 patch.object(agent_server, "PROVIDER_CHILD_PROC_ROOT", root / "no-proc"), \
                 patch.object(agent_server.os, "kill") as kill, \
                 patch.object(agent_server.os, "killpg") as killpg, \
                 patch.object(
                     agent_server,
                     "provider_host_boot_identity",
                     return_value="test-boot",
                 ), \
                 patch.object(
                     agent_server,
                     "provider_child_process_start_identity",
                     side_effect=lambda pid: f"start-{pid}",
                 ), \
                 patch.object(
                     agent_server,
                     "provider_child_executable_identity",
                     return_value="/usr/bin/node",
                 ), \
                 patch.object(
                     agent_server,
                     "process_group_for_pid",
                     side_effect=lambda pid: pid,
                 ), \
                 patch.object(
                     agent_server.subprocess,
                     "run",
                     side_effect=fake_ps({
                         5000: {"ppid": "1", "command": "codex app-server --listen stdio://"},
                         6000: {"ppid": str(os.getpid()), "command": "codex app-server"},
                         # Reparented but no longer Codex: leave it alone.
                         7000: {"ppid": "1", "command": "sleep 100"},
                     }),
                ), \
                 self.assertLogs(agent_server.logger, level="WARNING") as logs:
                agent_server.write_provider_children_registry([
                    provider_child_entry(
                        5000,
                        command="codex app-server --listen stdio://",
                    ),
                    provider_child_entry(6000, command="codex app-server"),
                    provider_child_entry(7000),
                ])
                reaped = agent_server.sweep_orphaned_provider_children()
                remaining = agent_server.read_provider_children_registry()

        self.assertEqual(reaped, 1)
        killpg.assert_called_once_with(5000, signal.SIGKILL)
        # Existence probes only; the sweep never SIGKILLs a bare pid.
        self.assertTrue(all(call.args[1] == 0 for call in kill.call_args_list))
        self.assertEqual([entry["pid"] for entry in remaining], [6000])
        self.assertTrue(
            any("reaped orphaned provider child" in line for line in logs.output),
            logs.output,
        )

    def test_startup_sweep_drops_dead_entries_and_tolerates_missing_file(self):
        def dead(pid, sig):
            raise ProcessLookupError(pid)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            registry = root / "admin" / "provider-children.json"
            with patch.object(agent_server, "PROVIDER_CHILDREN_FILE", registry), \
                 patch.object(agent_server.os, "kill", side_effect=dead), \
                 patch.object(agent_server.os, "killpg") as killpg:
                self.assertEqual(agent_server.sweep_orphaned_provider_children(), 0)
                self.assertFalse(registry.exists())
                agent_server.write_provider_children_registry([
                    provider_child_entry(5000),
                ])
                self.assertEqual(agent_server.sweep_orphaned_provider_children(), 0)
                remaining = agent_server.read_provider_children_registry()

        # A dead leader cannot prove the numeric group still belongs to this
        # boot/process. Dropping the stale row is safer than killpg reuse.
        killpg.assert_not_called()
        self.assertEqual(remaining, [])


class CodexProcessHookTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_reports_process_start_and_exit(self):
        started: list[tuple[int, int | None]] = []
        exited: list[tuple[int, int | None]] = []
        factory = FakeProcessFactory()
        client = CodexAppServerClient(
            "codex",
            cwd="/tmp",
            env_factory=lambda: {"PATH": "/usr/bin"},
            process_factory=factory,
            request_timeout=1,
            on_process_started=lambda pid, pgid: started.append((pid, pgid)),
            on_process_exited=lambda pid, pgid: exited.append((pid, pgid)),
        )
        await client.start()
        pid = factory.process.pid
        # An injected factory cannot prove session ownership: no group id.
        self.assertEqual(started, [(pid, None)])
        self.assertEqual(exited, [])
        await client.close()
        self.assertEqual(exited, [(pid, None)])

    async def test_hook_failure_does_not_break_start_or_close(self):
        def explode(*_args):
            raise RuntimeError("registry unavailable")

        factory = FakeProcessFactory()
        client = CodexAppServerClient(
            "codex",
            cwd="/tmp",
            env_factory=lambda: {"PATH": "/usr/bin"},
            process_factory=factory,
            request_timeout=1,
            on_process_started=explode,
            on_process_exited=explode,
        )
        await client.start()
        self.assertTrue(client.ready)
        await client.close()
        self.assertFalse(client.ready)


class BoundedShutdownPhaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_stuck_phase_times_out_and_logs(self):
        async def never() -> None:
            await asyncio.sleep(3600)

        with self.assertLogs(agent_server.logger, level="WARNING") as logs:
            completed = await agent_server.bounded_shutdown_phase(
                "stuck", never(), timeout=0.01,
            )
        self.assertFalse(completed)
        self.assertTrue(any("shutdown phase stuck" in line for line in logs.output))

    async def test_failing_phase_is_contained(self):
        async def broken() -> None:
            raise RuntimeError("boom")

        async def fine() -> str:
            return "ok"

        with self.assertLogs(agent_server.logger, level="WARNING"):
            self.assertFalse(await agent_server.bounded_shutdown_phase("broken", broken()))
        self.assertTrue(await agent_server.bounded_shutdown_phase("fine", fine()))

    async def test_phase_suppressing_cancellation_cannot_defeat_deadline(self):
        release = asyncio.Event()
        cancellation_suppressed = asyncio.Event()
        prior_stragglers = set(agent_server.SERVER_SHUTDOWN_STRAGGLERS)

        async def stubborn() -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancellation_suppressed.set()
                await release.wait()

        loop = asyncio.get_running_loop()
        started = loop.time()
        completed = await agent_server.bounded_shutdown_phase(
            "stubborn",
            stubborn(),
            timeout=0.01,
        )
        elapsed = loop.time() - started
        await asyncio.wait_for(cancellation_suppressed.wait(), timeout=1)
        retained = (
            set(agent_server.SERVER_SHUTDOWN_STRAGGLERS) - prior_stragglers
        )

        self.assertFalse(completed)
        self.assertLess(elapsed, 0.5)
        self.assertEqual(len(retained), 1)
        release.set()
        await asyncio.gather(*retained, return_exceptions=True)
        await asyncio.sleep(0)
        self.assertFalse(
            retained.intersection(agent_server.SERVER_SHUTDOWN_STRAGGLERS)
        )

    async def test_join_cancelled_tasks_swallows_cancellation(self):
        async def forever() -> None:
            await asyncio.sleep(3600)

        task = asyncio.create_task(forever())
        await asyncio.sleep(0)
        task.cancel()
        await agent_server.join_cancelled_tasks(task)
        self.assertTrue(task.cancelled())


class UvicornShutdownSettingTests(unittest.TestCase):
    def test_default_and_override(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENTSDOCK_UVICORN_GRACEFUL_SHUTDOWN_SECONDS", None)
            os.environ.pop("ZENITHBOT_UVICORN_GRACEFUL_SHUTDOWN_SECONDS", None)
            self.assertEqual(agent_server.uvicorn_graceful_shutdown_seconds(), 20)
        with patch.dict(
            os.environ,
            {"AGENTSDOCK_UVICORN_GRACEFUL_SHUTDOWN_SECONDS": "45"},
        ):
            self.assertEqual(agent_server.uvicorn_graceful_shutdown_seconds(), 45)
        with patch.dict(
            os.environ,
            {"AGENTSDOCK_UVICORN_GRACEFUL_SHUTDOWN_SECONDS": "not-a-number"},
        ):
            self.assertEqual(agent_server.uvicorn_graceful_shutdown_seconds(), 20)

    def test_override_is_finite_and_capped_to_installer_stop_budget(self):
        for configured in ("600", "inf", "nan"):
            with self.subTest(configured=configured), patch.dict(
                os.environ,
                {"AGENTSDOCK_UVICORN_GRACEFUL_SHUTDOWN_SECONDS": configured},
            ):
                value = agent_server.uvicorn_graceful_shutdown_seconds()
                self.assertGreaterEqual(value, 1)
                self.assertLessEqual(
                    value,
                    agent_server.MAX_UVICORN_GRACEFUL_SHUTDOWN_SECONDS,
                )

        installer = Path(agent_server.__file__).with_name("install.sh").read_text()
        attempts = int(
            re.search(r"^LAUNCHCTL_STOP_ATTEMPTS=(\d+)$", installer, re.MULTILINE).group(1)
        )
        delay = float(
            re.search(r"^LAUNCHCTL_STOP_DELAY=([0-9.]+)$", installer, re.MULTILINE).group(1)
        )
        watchdog_budget = (
            agent_server.MAX_UVICORN_GRACEFUL_SHUTDOWN_SECONDS
            + agent_server.SERVER_SHUTDOWN_PHASE_COUNT
            * agent_server.SERVER_SHUTDOWN_PHASE_TIMEOUT_SECONDS
            + 5.0
        )
        self.assertGreaterEqual(attempts * delay, watchdog_budget + 30.0)


if __name__ == "__main__":
    unittest.main()
