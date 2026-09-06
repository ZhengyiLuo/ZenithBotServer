import asyncio
import threading
import unittest
from unittest.mock import ANY, MagicMock, patch

import agent_server


class RecordingWebSocket:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int | None]] = []
        self.accepted_subprotocol: str | None = None
        self.headers: dict[str, str] = {}
        self.query_params: dict[str, str] = {}

    async def accept(self, *, subprotocol: str | None = None) -> None:
        self.accepted_subprotocol = subprotocol
        self.calls.append(("accept", None))

    async def close(self, code: int = 1000) -> None:
        self.calls.append(("close", code))


class ScrollDisconnectWebSocket(RecordingWebSocket):
    def __init__(self) -> None:
        super().__init__()
        self.messages = [
            {"type": "websocket.receive", "text": '{"type":"scroll","delta":-4}'},
            {"type": "websocket.disconnect"},
        ]

    async def send_json(self, _payload: dict) -> None:
        self.calls.append(("ready", None))

    async def send_bytes(self, _payload: bytes) -> None:
        self.calls.append(("data", None))

    async def receive(self) -> dict:
        return self.messages.pop(0)


class HeldTerminalWebSocket(RecordingWebSocket):
    def __init__(self) -> None:
        super().__init__()
        self.ready = asyncio.Event()

    async def send_json(self, _payload: dict) -> None:
        self.calls.append(("ready", None))
        self.ready.set()

    async def send_bytes(self, _payload: bytes) -> None:
        self.calls.append(("data", None))

    async def receive(self) -> dict:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class TerminalWebSocketRejectionTests(unittest.IsolatedAsyncioTestCase):
    def test_non_ascii_token_candidate_is_rejected_without_type_error(self) -> None:
        with patch.object(agent_server, "AGENT_TOKEN", "server-token"):
            self.assertFalse(agent_server.token_matches("not-the-token-é"))

    async def test_capable_client_gets_fixed_protocol_before_terminal_close(self) -> None:
        encoded = agent_server.base64.urlsafe_b64encode(
            b"server-token",
        ).decode("ascii").rstrip("=")
        offered = f"agentsdock-token.{encoded}"
        websocket = RecordingWebSocket()
        websocket.headers = {
            "sec-websocket-protocol": (
                f"{agent_server.TERMINAL_WEBSOCKET_PROTOCOL}, {offered}"
            ),
        }
        with patch.object(
            agent_server,
            "AGENT_TOKEN",
            "server-token",
        ), patch.dict(agent_server.STORE.sessions, {}, clear=True):
            await agent_server.session_terminal(  # type: ignore[arg-type]
                "missing-terminal",
                websocket,
            )

        self.assertEqual(
            websocket.accepted_subprotocol,
            agent_server.TERMINAL_WEBSOCKET_PROTOCOL,
        )
        self.assertEqual(websocket.calls, [
            ("accept", None),
            ("close", 4404),
        ])

    async def test_invalid_token_still_gets_fixed_protocol_before_unauthorized_close(
        self,
    ) -> None:
        encoded = agent_server.base64.urlsafe_b64encode(
            b"wrong-token",
        ).decode("ascii").rstrip("=")
        websocket = RecordingWebSocket()
        websocket.headers = {
            "sec-websocket-protocol": (
                f"{agent_server.TERMINAL_WEBSOCKET_PROTOCOL}, "
                f"agentsdock-token.{encoded}"
            ),
        }
        with patch.object(
            agent_server,
            "AGENT_TOKEN",
            "server-token",
        ), patch.dict(agent_server.STORE.sessions, {}, clear=True):
            await agent_server.session_terminal(  # type: ignore[arg-type]
                "unauthorized-terminal",
                websocket,
            )

        self.assertEqual(
            websocket.accepted_subprotocol,
            agent_server.TERMINAL_WEBSOCKET_PROTOCOL,
        )
        self.assertEqual(websocket.calls, [
            ("accept", None),
            ("close", 4401),
        ])

    async def assert_rejected_after_accept(
        self,
        session_id: str,
        expected_code: int,
        *,
        authorized: bool,
        session: dict | None = None,
    ) -> None:
        websocket = RecordingWebSocket()
        sessions = {session_id: session} if session is not None else {}
        with patch.object(agent_server, "websocket_authorized", return_value=authorized), \
             patch.dict(agent_server.STORE.sessions, sessions, clear=True):
            await agent_server.session_terminal(session_id, websocket)  # type: ignore[arg-type]

        self.assertEqual(websocket.calls, [
            ("accept", None),
            ("close", expected_code),
        ])

    async def test_unauthorized_terminal_accepts_before_custom_close(self) -> None:
        await self.assert_rejected_after_accept(
            "unauthorized-terminal",
            4401,
            authorized=False,
        )

    async def test_missing_chat_terminal_accepts_before_custom_close(self) -> None:
        await self.assert_rejected_after_accept(
            "missing-terminal",
            4404,
            authorized=True,
        )

    async def test_archived_chat_terminal_accepts_before_custom_close(self) -> None:
        await self.assert_rejected_after_accept(
            "archived-terminal",
            4409,
            authorized=True,
            session={"id": "archived-terminal", "archived": True},
        )

    async def test_unauthorized_events_accepts_before_custom_close(self) -> None:
        websocket = RecordingWebSocket()
        with patch.object(agent_server, "websocket_authorized", return_value=False), \
             patch.dict(agent_server.STORE.sessions, {}, clear=True):
            await agent_server.session_events(  # type: ignore[arg-type]
                "unauthorized-events",
                websocket,
            )
        self.assertEqual(websocket.calls, [
            ("accept", None),
            ("close", 4401),
        ])

    async def test_missing_chat_events_selects_fixed_protocol_then_4404(self) -> None:
        encoded = agent_server.base64.urlsafe_b64encode(
            b"server-token",
        ).decode("ascii").rstrip("=")
        websocket = RecordingWebSocket()
        websocket.headers = {
            "sec-websocket-protocol": (
                f"{agent_server.EVENTS_WEBSOCKET_PROTOCOL}, "
                f"agentsdock-token.{encoded}"
            ),
        }
        with patch.object(agent_server, "AGENT_TOKEN", "server-token"), \
             patch.dict(agent_server.STORE.sessions, {}, clear=True):
            await agent_server.session_events(  # type: ignore[arg-type]
                "missing-events",
                websocket,
            )
        self.assertEqual(
            websocket.accepted_subprotocol,
            agent_server.EVENTS_WEBSOCKET_PROTOCOL,
        )
        self.assertEqual(websocket.calls, [
            ("accept", None),
            ("close", 4404),
        ])

    async def test_unauthorized_emergency_accepts_fixed_protocol_then_4401(self) -> None:
        encoded = agent_server.base64.urlsafe_b64encode(
            b"wrong-token",
        ).decode("ascii").rstrip("=")
        websocket = RecordingWebSocket()
        websocket.headers = {
            "sec-websocket-protocol": (
                f"{agent_server.EMERGENCY_WEBSOCKET_PROTOCOL}, "
                f"agentsdock-token.{encoded}"
            ),
        }
        with patch.object(agent_server, "AGENT_TOKEN", "server-token"):
            await agent_server.emergency_alert_events(websocket)  # type: ignore[arg-type]

        self.assertEqual(
            websocket.accepted_subprotocol,
            agent_server.EMERGENCY_WEBSOCKET_PROTOCOL,
        )
        self.assertEqual(websocket.calls, [
            ("accept", None),
            ("close", 4401),
        ])

    async def test_emergency_missing_fixed_protocol_accepts_token_then_4406(self) -> None:
        encoded = agent_server.base64.urlsafe_b64encode(
            b"server-token",
        ).decode("ascii").rstrip("=")
        token_protocol = f"agentsdock-token.{encoded}"
        websocket = RecordingWebSocket()
        websocket.headers = {"sec-websocket-protocol": token_protocol}
        with patch.object(agent_server, "AGENT_TOKEN", "server-token"):
            await agent_server.emergency_alert_events(websocket)  # type: ignore[arg-type]

        self.assertEqual(websocket.accepted_subprotocol, token_protocol)
        self.assertEqual(websocket.calls, [
            ("accept", None),
            ("close", 4406),
        ])

    async def test_disconnect_exits_copy_mode_owned_by_terminal_scrolling(self) -> None:
        session_id = "scrolling-terminal"
        websocket = ScrollDisconnectWebSocket()

        async def wait_for_output(_fd: int) -> bytes:
            await asyncio.Event().wait()
            return b""

        with patch.object(agent_server, "websocket_authorized", return_value=True), \
             patch.dict(
                 agent_server.STORE.sessions,
                 {session_id: {"id": session_id, "archived": False, "cwd": "/workspace"}},
                 clear=True,
             ), \
             patch.object(
                 agent_server,
                 "spawn_terminal_client",
                 return_value=(object(), 91, "zd_scrolling-terminal"),
             ), \
             patch.object(agent_server, "read_terminal_output", side_effect=wait_for_output), \
             patch.object(agent_server, "scroll_terminal_history", return_value=True) as scroll, \
             patch.object(agent_server, "exit_terminal_auto_scroll") as exit_scroll, \
             patch.object(agent_server, "stop_terminal_client") as stop_client:
            await agent_server.session_terminal(session_id, websocket)  # type: ignore[arg-type]

        scroll.assert_called_once_with(session_id, -4, managed=False)
        exit_scroll.assert_called_once_with(session_id)
        stop_client.assert_called_once_with(ANY, 91)

    async def test_update_fence_drains_attachment_and_rejects_reconnect(self) -> None:
        session_id = "terminal-update-drain"
        registry = agent_server.TerminalAttachmentRegistry()
        first = HeldTerminalWebSocket()
        reconnect = RecordingWebSocket()
        process = MagicMock()

        async def wait_for_output(_fd: int) -> bytes:
            await asyncio.Event().wait()
            return b""

        with patch.object(agent_server, "TERMINAL_ATTACHMENTS", registry), \
             patch.object(agent_server, "websocket_authorized", return_value=True), \
             patch.dict(
                 agent_server.STORE.sessions,
                 {session_id: {"id": session_id, "archived": False, "cwd": "/workspace"}},
                 clear=True,
             ), \
             patch.object(
                 agent_server,
                 "spawn_terminal_client",
                 return_value=(process, 91, "zd_terminal-update-drain"),
             ) as spawn, \
             patch.object(agent_server, "read_terminal_output", side_effect=wait_for_output), \
             patch.object(agent_server, "stop_terminal_client") as stop_client, \
             patch.object(agent_server, "run_tmux") as run_tmux, \
             patch.object(
                 agent_server,
                 "managed_server_update_blocks_work",
                 side_effect=[False, True],
             ):
            owner = asyncio.create_task(
                agent_server.session_terminal(session_id, first)  # type: ignore[arg-type]
            )
            await asyncio.wait_for(first.ready.wait(), timeout=1)

            retired = await registry.close_admission_and_all()
            await asyncio.gather(owner, return_exceptions=True)
            await agent_server.session_terminal(  # type: ignore[arg-type]
                session_id,
                reconnect,
            )

        self.assertEqual(retired, 1)
        spawn.assert_called_once()
        stop_client.assert_called()
        run_tmux.assert_not_called()
        self.assertEqual(reconnect.calls, [
            ("accept", None),
            ("close", 1012),
        ])
        self.assertEqual(
            await registry.snapshot(),
            {
                "admission_open": False,
                "permanently_closed": False,
                "active_connections": 0,
                "active_sessions": 0,
            },
        )

    async def test_update_fence_reaps_cross_device_spawn_after_double_cancel(self) -> None:
        session_id = "terminal-cross-device-race"
        registry = agent_server.TerminalAttachmentRegistry()
        websocket = HeldTerminalWebSocket()
        process = MagicMock()
        spawn_entered = threading.Event()
        release_spawn = threading.Event()

        def slow_spawn(*_args):
            spawn_entered.set()
            self.assertTrue(release_spawn.wait(timeout=2))
            return process, 92, "zd_terminal-cross-device-race"

        async def wait_for_output(_fd: int) -> bytes:
            await asyncio.Event().wait()
            return b""

        with patch.object(agent_server, "TERMINAL_ATTACHMENTS", registry), \
             patch.object(agent_server, "websocket_authorized", return_value=True), \
             patch.dict(
                 agent_server.STORE.sessions,
                 {session_id: {"id": session_id, "archived": False, "cwd": "/workspace"}},
                 clear=True,
             ), \
             patch.object(agent_server, "spawn_terminal_client", side_effect=slow_spawn), \
             patch.object(agent_server, "read_terminal_output", side_effect=wait_for_output), \
             patch.object(agent_server, "stop_terminal_client") as stop_client:
            owner = asyncio.create_task(
                agent_server.session_terminal(session_id, websocket)  # type: ignore[arg-type]
            )
            self.assertTrue(
                await asyncio.to_thread(spawn_entered.wait, 1),
            )
            drain = asyncio.create_task(registry.close_admission_and_all())
            async def cleanup_task_is_owned() -> bool:
                async with registry._lock:
                    entry = registry._attachments.get(websocket)
                    return bool(
                        entry
                        and isinstance(entry.get("cleanup_task"), asyncio.Task)
                    )

            async def wait_for_cleanup_owner() -> None:
                while not await cleanup_task_is_owned():
                    await asyncio.sleep(0)

            await asyncio.wait_for(wait_for_cleanup_owner(), timeout=1)
            # Simulate a second device/lifecycle cancellation while the first
            # cancellation is already waiting for the to-thread spawn result.
            owner.cancel()
            release_spawn.set()
            await asyncio.wait_for(drain, timeout=2)
            await asyncio.gather(owner, return_exceptions=True)

        stop_client.assert_called_once_with(process, 92)
        self.assertEqual(
            (await registry.snapshot())["active_connections"],
            0,
        )

    async def test_terminal_admission_self_heals_after_update_is_terminal(self) -> None:
        registry = agent_server.TerminalAttachmentRegistry()
        websocket = RecordingWebSocket()

        with patch.object(
            agent_server,
            "managed_server_update_blocks_work",
            return_value=False,
        ), patch.object(
            agent_server,
            "managed_server_restart_blocks_work",
            return_value=False,
        ):
            await registry.close_admission_and_all()
            reserved = await registry.reserve("recovered-terminal", websocket)  # type: ignore[arg-type]

        self.assertTrue(reserved)
        self.assertTrue((await registry.snapshot())["admission_open"])
        await registry.release(websocket)  # type: ignore[arg-type]

    async def test_lifespan_terminal_shutdown_cannot_self_heal(self) -> None:
        registry = agent_server.TerminalAttachmentRegistry()
        websocket = RecordingWebSocket()

        with patch.object(
            agent_server,
            "managed_server_update_blocks_work",
            return_value=False,
        ), patch.object(
            agent_server,
            "managed_server_restart_blocks_work",
            return_value=False,
        ):
            await registry.close_admission_and_all(permanent=True)
            reserved = await registry.reserve("shutdown-terminal", websocket)  # type: ignore[arg-type]
            reopened = await registry.reopen_if_update_inactive(
                {"phase": "failed"}
            )

        self.assertFalse(reserved)
        self.assertFalse(reopened)
        self.assertEqual(
            await registry.snapshot(),
            {
                "admission_open": False,
                "permanently_closed": True,
                "active_connections": 0,
                "active_sessions": 0,
            },
        )


if __name__ == "__main__":
    unittest.main()
