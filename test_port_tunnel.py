import asyncio
import base64
import unittest
from unittest.mock import AsyncMock, patch

import agent_server


def token_protocol(token: str = "server-token") -> str:
    encoded = base64.urlsafe_b64encode(token.encode("utf-8")).decode(
        "ascii"
    ).rstrip("=")
    return f"{agent_server.PORT_TUNNEL_TOKEN_PROTOCOL_PREFIX}{encoded}"


def authenticated_protocols(
    token: str = "server-token",
) -> tuple[str, str]:
    return (
        agent_server.PORT_TUNNEL_WEBSOCKET_PROTOCOL,
        token_protocol(token),
    )


class RecordingWebSocket:
    def __init__(
        self,
        protocols: tuple[str, ...] = (),
        *,
        query_params: dict[str, str] | None = None,
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        raw_headers = (
            [
                (
                    b"sec-websocket-protocol",
                    ", ".join(protocols).encode("ascii"),
                )
            ]
            if protocols
            else []
        )
        raw_headers.extend(
            (name.encode("ascii"), value.encode("latin-1"))
            for name, value in headers
        )
        self.scope = {"headers": raw_headers}
        self.headers = {
            name.decode("ascii").lower(): value.decode("latin-1")
            for name, value in raw_headers
        }
        self.query_params = dict(query_params or {})
        self.calls: list[tuple] = []

    async def accept(self, subprotocol: str | None = None) -> None:
        self.calls.append(("accept", subprotocol))

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.calls.append(("close", code, reason))


class DuplexWebSocket(RecordingWebSocket):
    def __init__(self, outbound: bytes) -> None:
        super().__init__(authenticated_protocols())
        self.outbound = outbound
        self.receive_count = 0
        self.inbound: list[bytes] = []
        self.inbound_ready = asyncio.Event()

    async def receive(self) -> dict:
        self.receive_count += 1
        if self.receive_count == 1:
            return {"type": "websocket.receive", "bytes": self.outbound}
        await self.inbound_ready.wait()
        return {"type": "websocket.disconnect"}

    async def send_bytes(self, data: bytes) -> None:
        self.inbound.append(data)
        self.inbound_ready.set()


class TextWebSocket(RecordingWebSocket):
    async def receive(self) -> dict:
        return {"type": "websocket.receive", "text": "GET / HTTP/1.1"}

    async def send_bytes(self, _data: bytes) -> None:
        raise AssertionError("the idle reader must not produce bytes")


class IdleReader:
    async def read(self, _size: int) -> bytes:
        await asyncio.Event().wait()
        return b""


class CancellationTrackingReader:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def read(self, _size: int) -> bytes:
        self.started.set()
        try:
            await asyncio.Event().wait()
        finally:
            self.cancelled.set()
        return b""


class CancellationTrackingWebSocket(RecordingWebSocket):
    def __init__(self) -> None:
        super().__init__()
        self.receive_started = asyncio.Event()
        self.receive_cancelled = asyncio.Event()

    async def receive(self) -> dict:
        self.receive_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            self.receive_cancelled.set()
        return {"type": "websocket.disconnect"}

    async def send_bytes(self, _data: bytes) -> None:
        return None


class MemoryWriter:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class HangingCloseWebSocket(RecordingWebSocket):
    def __init__(self) -> None:
        super().__init__()
        self.close_cancelled = asyncio.Event()

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.calls.append(("close", code, reason))
        try:
            await asyncio.Event().wait()
        finally:
            self.close_cancelled.set()


class PortTunnelTests(unittest.IsolatedAsyncioTestCase):
    async def invoke(
        self,
        websocket: RecordingWebSocket,
        *,
        port: str = "7007",
        session: dict | None = None,
        token: str = "server-token",
        open_connection: AsyncMock | None = None,
    ) -> agent_server.PortTunnelRegistry:
        registry = agent_server.PortTunnelRegistry()
        sessions = {"chat-1": session} if session is not None else {}
        connection = open_connection or AsyncMock(
            side_effect=ConnectionRefusedError("not listening")
        )
        with patch.object(agent_server, "PORT_TUNNELS", registry), \
             patch.object(agent_server, "AGENT_TOKEN", token), \
             patch.dict(agent_server.STORE.sessions, sessions, clear=True), \
             patch.object(asyncio, "open_connection", connection):
            await agent_server.session_port_tunnel(
                "chat-1",
                port,
                websocket,  # type: ignore[arg-type]
            )
        return registry

    async def test_requires_configured_authentication(self) -> None:
        websocket = RecordingWebSocket(
            (agent_server.PORT_TUNNEL_WEBSOCKET_PROTOCOL,)
        )
        await self.invoke(
            websocket,
            session={"id": "chat-1", "archived": False},
            token="",
        )
        self.assertEqual(websocket.calls[0], (
            "accept",
            agent_server.PORT_TUNNEL_WEBSOCKET_PROTOCOL,
        ))
        self.assertEqual(websocket.calls[1][0:2], ("close", 4401))

    async def test_canonical_token_subprotocol_authenticates_tunnel_socket(self) -> None:
        token = "tunnel token with punctuation: /+="
        websocket = RecordingWebSocket((
            agent_server.PORT_TUNNEL_WEBSOCKET_PROTOCOL,
            token_protocol(token),
        ))

        with patch.object(agent_server, "AGENT_TOKEN", token):
            self.assertTrue(
                agent_server.port_tunnel_websocket_authorized(  # type: ignore[arg-type]
                    websocket
                )
            )

    async def test_rejects_query_token_even_with_valid_subprotocol(self) -> None:
        connection = AsyncMock()
        websocket = RecordingWebSocket(
            authenticated_protocols(),
            query_params={"token": "server-token"},
        )

        await self.invoke(
            websocket,
            session={"id": "chat-1", "archived": False},
            open_connection=connection,
        )

        self.assertEqual(websocket.calls[-1][0:2], ("close", 4401))
        connection.assert_not_awaited()

    async def test_legacy_websocket_auth_keeps_query_token_compatibility(self) -> None:
        websocket = RecordingWebSocket(
            (agent_server.PORT_TUNNEL_WEBSOCKET_PROTOCOL,),
            query_params={"token": "server-token"},
        )
        with patch.object(agent_server, "AGENT_TOKEN", "server-token"):
            self.assertTrue(
                agent_server.websocket_authorized(websocket)  # type: ignore[arg-type]
            )
            self.assertFalse(
                agent_server.port_tunnel_websocket_authorized(  # type: ignore[arg-type]
                    websocket
                )
            )

    async def test_rejects_header_and_cookie_token_alternatives(self) -> None:
        alternatives = (
            ("authorization", "Bearer server-token"),
            ("x-agentsdock-token", "server-token"),
            ("x-zenithdock-token", "server-token"),
            ("cookie", "agentsdock-token=server-token"),
        )
        for name, value in alternatives:
            with self.subTest(header=name):
                connection = AsyncMock()
                websocket = RecordingWebSocket(
                    authenticated_protocols(),
                    headers=((name, value),),
                )
                await self.invoke(
                    websocket,
                    session={"id": "chat-1", "archived": False},
                    open_connection=connection,
                )
                self.assertEqual(websocket.calls[-1][0:2], ("close", 4401))
                connection.assert_not_awaited()

    async def test_rejects_duplicate_token_subprotocols(self) -> None:
        valid = token_protocol()
        other = token_protocol("different-token")
        for offered in (
            (agent_server.PORT_TUNNEL_WEBSOCKET_PROTOCOL, valid, valid),
            (agent_server.PORT_TUNNEL_WEBSOCKET_PROTOCOL, valid, other),
        ):
            with self.subTest(offered=offered):
                connection = AsyncMock()
                websocket = RecordingWebSocket(offered)
                await self.invoke(
                    websocket,
                    session={"id": "chat-1", "archived": False},
                    open_connection=connection,
                )
                self.assertEqual(websocket.calls[-1][0:2], ("close", 4401))
                connection.assert_not_awaited()

    async def test_rejects_noncanonical_token_subprotocol(self) -> None:
        websocket = RecordingWebSocket((
            agent_server.PORT_TUNNEL_WEBSOCKET_PROTOCOL,
            f"{token_protocol()}=",
        ))
        connection = AsyncMock()
        await self.invoke(
            websocket,
            session={"id": "chat-1", "archived": False},
            open_connection=connection,
        )
        self.assertEqual(websocket.calls[-1][0:2], ("close", 4401))
        connection.assert_not_awaited()

    async def test_requires_binary_tunnel_subprotocol(self) -> None:
        websocket = RecordingWebSocket((token_protocol(),))
        await self.invoke(
            websocket,
            session={"id": "chat-1", "archived": False},
        )
        self.assertEqual(websocket.calls[0], ("accept", None))
        self.assertEqual(websocket.calls[1][0:2], ("close", 4406))

    async def test_rejects_invalid_privileged_or_ambiguous_ports(self) -> None:
        for value in ("80", "65536", "+7007", "7007.0", "localhost:7007"):
            with self.subTest(port=value):
                websocket = RecordingWebSocket(
                    authenticated_protocols()
                )
                await self.invoke(
                    websocket,
                    port=value,
                    session={"id": "chat-1", "archived": False},
                )
                self.assertEqual(websocket.calls[-1][0:2], ("close", 4400))

    async def test_rejects_missing_and_archived_sessions(self) -> None:
        missing = RecordingWebSocket(
            authenticated_protocols()
        )
        await self.invoke(missing)
        self.assertEqual(missing.calls[-1][0:2], ("close", 4404))

        archived = RecordingWebSocket(
            authenticated_protocols()
        )
        await self.invoke(
            archived,
            session={"id": "chat-1", "archived": True},
        )
        self.assertEqual(archived.calls[-1][0:2], ("close", 4409))

    async def test_connects_only_to_fixed_ipv4_loopback(self) -> None:
        websocket = RecordingWebSocket(
            authenticated_protocols()
        )
        connect = AsyncMock(side_effect=ConnectionRefusedError("no service"))
        registry = await self.invoke(
            websocket,
            port="7007",
            session={"id": "chat-1", "archived": False},
            open_connection=connect,
        )
        connect.assert_awaited_once_with(host="127.0.0.1", port=7007)
        self.assertEqual(websocket.calls[-1][0:2], ("close", 4502))
        self.assertEqual((await registry.snapshot())["active_connections"], 0)

    async def test_raw_bytes_bridge_http_and_websocket_traffic(self) -> None:
        request = (
            b"GET /viser HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            b"\x00\x01raw-websocket-payload"
        )
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            b"\x82\x04test"
        )
        received: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

        async def handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            try:
                data = await reader.readexactly(len(request))
                if not received.done():
                    received.set_result(data)
                writer.write(response)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handler, host="127.0.0.1", port=0)
        target_port = int(server.sockets[0].getsockname()[1])
        self.assertGreaterEqual(target_port, agent_server.PORT_TUNNEL_MIN_PORT)
        websocket = DuplexWebSocket(request)
        registry = agent_server.PortTunnelRegistry()
        try:
            with patch.object(agent_server, "PORT_TUNNELS", registry), \
                 patch.object(agent_server, "AGENT_TOKEN", "server-token"), \
                 patch.dict(
                     agent_server.STORE.sessions,
                     {"chat-1": {"id": "chat-1", "archived": False}},
                     clear=True,
                 ):
                await agent_server.session_port_tunnel(
                    "chat-1",
                    str(target_port),
                    websocket,  # type: ignore[arg-type]
                )
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(await received, request)
        self.assertEqual(b"".join(websocket.inbound), response)
        self.assertEqual((await registry.snapshot())["active_connections"], 0)

    async def test_bridge_rejects_text_frames_without_rewriting(self) -> None:
        websocket = TextWebSocket(
            (agent_server.PORT_TUNNEL_WEBSOCKET_PROTOCOL,)
        )
        writer = MemoryWriter()
        result = await agent_server.bridge_port_tunnel(
            websocket,  # type: ignore[arg-type]
            IdleReader(),  # type: ignore[arg-type]
            writer,  # type: ignore[arg-type]
        )
        self.assertEqual(result[0], 4406)
        self.assertEqual(writer.buffer, b"")

    async def test_bridge_rejects_oversized_binary_frames_without_rewriting(
        self,
    ) -> None:
        websocket = DuplexWebSocket(
            b"x" * (agent_server.PORT_TUNNEL_MAX_CLIENT_FRAME_BYTES + 1)
        )
        writer = MemoryWriter()
        result = await agent_server.bridge_port_tunnel(
            websocket,  # type: ignore[arg-type]
            IdleReader(),  # type: ignore[arg-type]
            writer,  # type: ignore[arg-type]
        )
        self.assertEqual(result[0], 4400)
        self.assertEqual(writer.buffer, b"")

    async def test_bridge_cancellation_joins_both_directional_pumps(self) -> None:
        websocket = CancellationTrackingWebSocket()
        reader = CancellationTrackingReader()
        bridge = asyncio.create_task(agent_server.bridge_port_tunnel(
            websocket,  # type: ignore[arg-type]
            reader,  # type: ignore[arg-type]
            MemoryWriter(),  # type: ignore[arg-type]
        ))
        await asyncio.wait_for(
            asyncio.gather(
                reader.started.wait(),
                websocket.receive_started.wait(),
            ),
            timeout=1,
        )

        bridge.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await bridge

        self.assertTrue(reader.cancelled.is_set())
        self.assertTrue(websocket.receive_cancelled.is_set())

    async def test_registry_enforces_global_and_per_session_limits(self) -> None:
        registry = agent_server.PortTunnelRegistry()
        first = RecordingWebSocket()
        second = RecordingWebSocket()
        third = RecordingWebSocket()
        with patch.object(agent_server, "PORT_TUNNEL_MAX_ACTIVE_GLOBAL", 2), \
             patch.object(agent_server, "PORT_TUNNEL_MAX_ACTIVE_PER_SESSION", 1):
            self.assertIsNone(await registry.reserve("chat-1", first))
            self.assertEqual(await registry.reserve("chat-1", second), "session")
            self.assertIsNone(await registry.reserve("chat-2", second))
            self.assertEqual(await registry.reserve("chat-3", third), "global")
        self.assertEqual((await registry.snapshot())["active_connections"], 2)

        closed = await registry.close_session(
            "chat-1",
            code=agent_server.PORT_TUNNEL_CLOSE_ARCHIVED,
            reason="Session was archived",
        )
        self.assertEqual(closed, 1)
        self.assertEqual(first.calls[-1][0:2], ("close", 4409))
        self.assertEqual((await registry.snapshot())["active_connections"], 1)

    async def test_websocket_close_is_bounded(self) -> None:
        websocket = HangingCloseWebSocket()
        with patch.object(
            agent_server,
            "PORT_TUNNEL_CLOSE_TIMEOUT_SECONDS",
            0.01,
        ):
            await asyncio.wait_for(
                agent_server.close_port_tunnel_websocket(
                    websocket, 1000, "Port tunnel closed"
                ),
                timeout=0.25,
            )

        self.assertTrue(websocket.close_cancelled.is_set())
        self.assertEqual(websocket.calls, [
            ("close", 1000, "Port tunnel closed"),
        ])

    async def test_registry_retains_and_retries_stubborn_endpoint_task(
        self,
    ) -> None:
        registry = agent_server.PortTunnelRegistry()
        websocket = HangingCloseWebSocket()
        reserved = asyncio.Event()
        finish = asyncio.Event()
        cancellations = 0

        async def endpoint() -> None:
            nonlocal cancellations
            owner_task = asyncio.current_task()
            self.assertIsNotNone(owner_task)
            self.assertIsNone(await registry.reserve(
                "chat-stubborn",
                websocket,
                owner_task=owner_task,
            ))
            reserved.set()
            try:
                while not finish.is_set():
                    try:
                        await finish.wait()
                    except asyncio.CancelledError:
                        cancellations += 1
            finally:
                await registry.release("chat-stubborn", websocket)

        endpoint_task = asyncio.create_task(endpoint())
        await asyncio.wait_for(reserved.wait(), timeout=1)
        try:
            with patch.object(
                agent_server,
                "PORT_TUNNEL_CLOSE_TIMEOUT_SECONDS",
                0.01,
            ):
                first_closed = await asyncio.wait_for(
                    registry.close_session(
                        "chat-stubborn",
                        code=agent_server.PORT_TUNNEL_CLOSE_ARCHIVED,
                        reason="Session was archived",
                    ),
                    timeout=0.25,
                )
                self.assertEqual(first_closed, 1)
                self.assertEqual(
                    (await registry.snapshot())["active_connections"],
                    1,
                )

                second_closed = await asyncio.wait_for(
                    registry.close_session(
                        "chat-stubborn",
                        code=agent_server.PORT_TUNNEL_CLOSE_ARCHIVED,
                        reason="Session was archived",
                    ),
                    timeout=0.25,
                )
                self.assertEqual(second_closed, 1)
                self.assertEqual(
                    (await registry.snapshot())["active_connections"],
                    1,
                )
        finally:
            finish.set()
            await asyncio.wait_for(endpoint_task, timeout=1)

        self.assertGreaterEqual(cancellations, 2)
        self.assertEqual(
            (await registry.snapshot())["active_connections"],
            0,
        )

    async def test_accepted_socket_is_capped_while_waiting_for_lifecycle(
        self,
    ) -> None:
        session_id = "chat-cap-before-lifecycle"
        first = RecordingWebSocket(authenticated_protocols())
        second = RecordingWebSocket(authenticated_protocols())
        registry = agent_server.PortTunnelRegistry()
        lifecycle_lock = agent_server.session_lifecycle_lock(session_id)
        connect = AsyncMock(side_effect=ConnectionRefusedError("not listening"))
        await lifecycle_lock.acquire()

        with patch.object(agent_server, "PORT_TUNNELS", registry), \
             patch.object(agent_server, "AGENT_TOKEN", "server-token"), \
             patch.object(agent_server, "PORT_TUNNEL_MAX_ACTIVE_GLOBAL", 1), \
             patch.object(agent_server, "PORT_TUNNEL_MAX_ACTIVE_PER_SESSION", 1), \
             patch.dict(
                 agent_server.STORE.sessions,
                 {session_id: {"id": session_id, "archived": False}},
                 clear=True,
             ), \
             patch.object(asyncio, "open_connection", connect):
            first_task = asyncio.create_task(agent_server.session_port_tunnel(
                session_id,
                "7007",
                first,  # type: ignore[arg-type]
            ))
            try:
                for _attempt in range(100):
                    if (
                        await registry.snapshot()
                    )["active_connections"] == 1:
                        break
                    await asyncio.sleep(0)
                self.assertEqual(
                    (await registry.snapshot())["active_connections"],
                    1,
                )

                await asyncio.wait_for(
                    agent_server.session_port_tunnel(
                        session_id,
                        "7008",
                        second,  # type: ignore[arg-type]
                    ),
                    timeout=0.25,
                )
                self.assertEqual(second.calls[-1][0:2], ("close", 4429))
                connect.assert_not_awaited()
            finally:
                lifecycle_lock.release()
                await asyncio.wait_for(first_task, timeout=1)

        connect.assert_awaited_once_with(host="127.0.0.1", port=7007)
        self.assertEqual(
            (await registry.snapshot())["active_connections"],
            0,
        )

    async def test_archiving_session_closes_lifecycle_scoped_tunnels(self) -> None:
        session_id = "archive-with-tunnel"
        active = {
            "id": session_id,
            "title": "Tunnel session",
            "backend": "codex",
            "archived": False,
        }
        archived = {**active, "archived": True}
        websocket = RecordingWebSocket()
        registry = agent_server.PortTunnelRegistry()
        self.assertIsNone(await registry.reserve(session_id, websocket))

        with patch.object(agent_server, "PORT_TUNNELS", registry), \
             patch.dict(agent_server.STORE.sessions, {session_id: active}, clear=True), \
             patch.object(
                 agent_server.STORE,
                 "update",
                 AsyncMock(return_value=archived),
             ), \
             patch.object(
                 agent_server.JOBS,
                 "pause_for_session",
                 AsyncMock(return_value=0),
             ), \
             patch.object(
                 agent_server,
                 "terminalize_archived_cross_chat_session",
                 AsyncMock(return_value=0),
             ), \
             patch.object(agent_server.asyncio, "to_thread", AsyncMock()):
            result = await agent_server.update_session(
                session_id,
                agent_server.UpdateSessionRequest(archived=True),
            )

        self.assertTrue(result["session"]["archived"])
        self.assertEqual(websocket.calls[-1][0:2], ("close", 4409))
        self.assertEqual((await registry.snapshot())["active_connections"], 0)

    async def test_archive_holds_lifecycle_lock_through_tunnel_retirement(
        self,
    ) -> None:
        session_id = "archive-tunnel-lifecycle-race"
        active = {
            "id": session_id,
            "title": "Tunnel lifecycle race",
            "backend": "codex",
            "archived": False,
        }
        old_tunnel = RecordingWebSocket()
        fresh_tunnel = RecordingWebSocket()
        close_started = asyncio.Event()
        allow_close = asyncio.Event()
        unarchive_committed = asyncio.Event()
        lifecycle_lock = agent_server.session_lifecycle_lock(session_id)
        close_lock_states: list[bool] = []

        class BlockingCloseRegistry(agent_server.PortTunnelRegistry):
            async def close_session(
                self,
                close_session_id: str,
                *,
                code: int,
                reason: str,
            ) -> int:
                close_lock_states.append(lifecycle_lock.locked())
                close_started.set()
                await allow_close.wait()
                return await super().close_session(
                    close_session_id,
                    code=code,
                    reason=reason,
                )

        registry = BlockingCloseRegistry()
        self.assertIsNone(await registry.reserve(session_id, old_tunnel))

        async def update_record(
            update_session_id: str,
            changes: dict,
        ) -> dict:
            updated = {
                **agent_server.STORE.sessions[update_session_id],
                **changes,
            }
            agent_server.STORE.sessions[update_session_id] = updated
            if changes.get("archived") is False:
                unarchive_committed.set()
            return updated

        async def unarchive_and_admit_fresh_tunnel() -> tuple[dict, str | None]:
            result = await agent_server.update_session(
                session_id,
                agent_server.UpdateSessionRequest(archived=False),
            )
            # Model the endpoint's state check and reservation under the same
            # lifecycle boundary after unarchive commits.
            async with lifecycle_lock:
                current = agent_server.STORE.sessions[session_id]
                self.assertFalse(current["archived"])
                limit = await registry.reserve(session_id, fresh_tunnel)
            return result, limit

        with patch.object(agent_server, "PORT_TUNNELS", registry), \
             patch.dict(agent_server.STORE.sessions, {session_id: active}, clear=True), \
             patch.object(
                 agent_server.STORE,
                 "update",
                 AsyncMock(side_effect=update_record),
             ), \
             patch.object(
                 agent_server.JOBS,
                 "pause_for_session",
                 AsyncMock(return_value=0),
             ), \
             patch.object(
                 agent_server,
                 "fence_secure_peer_chat_retirement",
                 AsyncMock(),
             ), \
             patch.object(
                 agent_server,
                 "terminalize_archived_cross_chat_session",
                 AsyncMock(return_value=0),
             ), \
             patch.object(agent_server.asyncio, "to_thread", AsyncMock()):
            archive_task = asyncio.create_task(agent_server.update_session(
                session_id,
                agent_server.UpdateSessionRequest(archived=True),
            ))
            await asyncio.wait_for(close_started.wait(), timeout=1)
            reopen_task = asyncio.create_task(unarchive_and_admit_fresh_tunnel())
            try:
                await asyncio.wait_for(unarchive_committed.wait(), timeout=0.05)
                unarchive_raced_close = True
            except asyncio.TimeoutError:
                unarchive_raced_close = False
            finally:
                allow_close.set()

            archived_result, reopen_result = await asyncio.gather(
                archive_task,
                reopen_task,
            )

        unarchived_result, fresh_limit = reopen_result
        self.assertEqual(close_lock_states, [True])
        self.assertFalse(unarchive_raced_close)
        self.assertTrue(archived_result["session"]["archived"])
        self.assertFalse(unarchived_result["session"]["archived"])
        self.assertIsNone(fresh_limit)
        self.assertEqual(old_tunnel.calls[-1][0:2], ("close", 4409))
        self.assertFalse(any(call[0] == "close" for call in fresh_tunnel.calls))
        self.assertEqual((await registry.snapshot())["active_connections"], 1)

    async def test_archive_cancellation_finishes_tunnel_retirement_under_lock(
        self,
    ) -> None:
        session_id = "archive-tunnel-cancel-race"
        active = {
            "id": session_id,
            "title": "Tunnel cancellation race",
            "backend": "codex",
            "archived": False,
        }
        old_tunnel = RecordingWebSocket()
        close_started = asyncio.Event()
        allow_close = asyncio.Event()
        unarchive_committed = asyncio.Event()
        lifecycle_lock = agent_server.session_lifecycle_lock(session_id)
        close_lock_states: list[bool] = []

        class BlockingCloseRegistry(agent_server.PortTunnelRegistry):
            async def close_session(
                self,
                close_session_id: str,
                *,
                code: int,
                reason: str,
            ) -> int:
                close_lock_states.append(lifecycle_lock.locked())
                close_started.set()
                await allow_close.wait()
                return await super().close_session(
                    close_session_id,
                    code=code,
                    reason=reason,
                )

        registry = BlockingCloseRegistry()
        self.assertIsNone(await registry.reserve(session_id, old_tunnel))

        async def update_record(
            update_session_id: str,
            changes: dict,
        ) -> dict:
            updated = {
                **agent_server.STORE.sessions[update_session_id],
                **changes,
            }
            agent_server.STORE.sessions[update_session_id] = updated
            if changes.get("archived") is False:
                unarchive_committed.set()
            return updated

        with patch.object(agent_server, "PORT_TUNNELS", registry), \
             patch.dict(agent_server.STORE.sessions, {session_id: active}, clear=True), \
             patch.object(
                 agent_server.STORE,
                 "update",
                 AsyncMock(side_effect=update_record),
             ), \
             patch.object(
                 agent_server.JOBS,
                 "pause_for_session",
                 AsyncMock(return_value=0),
             ), \
             patch.object(
                 agent_server,
                 "fence_secure_peer_chat_retirement",
                 AsyncMock(),
             ), \
             patch.object(
                 agent_server,
                 "terminalize_archived_cross_chat_session",
                 AsyncMock(return_value=0),
             ), \
             patch.object(agent_server.asyncio, "to_thread", AsyncMock()):
            archive_task = asyncio.create_task(agent_server.update_session(
                session_id,
                agent_server.UpdateSessionRequest(archived=True),
            ))
            await asyncio.wait_for(close_started.wait(), timeout=1)
            archive_task.cancel()
            reopen_task = asyncio.create_task(agent_server.update_session(
                session_id,
                agent_server.UpdateSessionRequest(archived=False),
            ))
            try:
                await asyncio.wait_for(
                    unarchive_committed.wait(),
                    timeout=0.05,
                )
                unarchive_raced_retirement = True
            except asyncio.TimeoutError:
                unarchive_raced_retirement = False
            finally:
                allow_close.set()

            with self.assertRaises(asyncio.CancelledError):
                await archive_task
            unarchived_result = await asyncio.wait_for(reopen_task, timeout=1)

        self.assertEqual(close_lock_states, [True])
        self.assertFalse(unarchive_raced_retirement)
        self.assertFalse(unarchived_result["session"]["archived"])
        self.assertEqual(old_tunnel.calls[-1][0:2], ("close", 4409))
        self.assertEqual((await registry.snapshot())["active_connections"], 0)

    async def test_idempotent_delete_retries_tracked_tunnel_retirement(
        self,
    ) -> None:
        session_id = "deleted-tunnel-retry"
        websocket = RecordingWebSocket()
        registry = agent_server.PortTunnelRegistry()
        self.assertIsNone(await registry.reserve(session_id, websocket))

        with patch.object(agent_server, "PORT_TUNNELS", registry), \
             patch.object(
                 agent_server,
                 "DELETED_SESSION_TOMBSTONES",
                 {session_id},
             ), \
             patch.object(
                 agent_server.JOBS,
                 "delete_for_session",
                 AsyncMock(return_value=0),
             ):
            result = await agent_server.delete_session(session_id)

        self.assertFalse(result["deleted"])
        self.assertEqual(websocket.calls[-1][0:2], ("close", 4404))
        self.assertEqual((await registry.snapshot())["active_connections"], 0)

    async def test_health_advertises_additive_tunnel_contract(self) -> None:
        registry = agent_server.PortTunnelRegistry()
        with patch.object(agent_server, "PORT_TUNNELS", registry), \
             patch.object(agent_server, "AGENT_TOKEN", "server-token"), \
             patch.object(agent_server, "working_tmux_bin", return_value=None):
            result = await agent_server.health()

        capability = result["capabilities"]["port_forwarding_v1"]
        self.assertEqual(result["api_contract_version"], 27)
        self.assertTrue(capability["available"])
        self.assertEqual(capability["version"], 1)
        self.assertEqual(
            capability["websocket_path_template"],
            "/api/sessions/{session_id}/ports/{port}/tunnel/ws",
        )
        self.assertEqual(
            capability["websocket_protocol"],
            "agentsdock-port-tunnel-v1",
        )
        self.assertEqual(capability["destination_host"], "127.0.0.1")
        self.assertEqual(capability["minimum_port"], 1024)
        self.assertEqual(capability["maximum_port"], 65535)
        self.assertEqual(
            capability["max_active_connections"],
            agent_server.PORT_TUNNEL_MAX_ACTIVE_GLOBAL,
        )
        self.assertEqual(
            capability["max_active_connections_per_session"],
            agent_server.PORT_TUNNEL_MAX_ACTIVE_PER_SESSION,
        )
        self.assertEqual(capability["max_client_frame_bytes"], 1024 * 1024)
        self.assertEqual(capability["active_connections"], 0)

    async def test_uvicorn_does_not_apply_tunnel_frame_limit_globally(self) -> None:
        with patch("sys.argv", ["agent_server.py"]), \
             patch.object(
                 agent_server,
                 "configure_server_logging",
             ) as configure_logging, \
             patch.object(agent_server.uvicorn, "run") as run:
            result = agent_server.main()

        self.assertEqual(result, 0)
        configure_logging.assert_called_once_with(agent_server.STATE_DIR)
        self.assertNotIn("ws_max_size", run.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
