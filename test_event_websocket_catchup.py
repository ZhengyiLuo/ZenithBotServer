import asyncio
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import agent_server


class FakeWebSocket:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []
        self.accepted = False
        self.accepted_subprotocol: str | None = None
        self.headers: dict[str, str] = {}
        self.query_params: dict[str, str] = {}

    async def send_json(self, event: dict[str, object]) -> None:
        self.events.append(event)

    async def accept(self, *, subprotocol: str | None = None) -> None:
        self.accepted = True
        self.accepted_subprotocol = subprotocol

    async def receive_text(self) -> str:
        raise agent_server.WebSocketDisconnect()


class EventWebSocketCatchupTests(unittest.IsolatedAsyncioTestCase):
    async def test_token_only_client_gets_its_authenticated_protocol_selected(self) -> None:
        encoded = agent_server.base64.urlsafe_b64encode(
            b"server-token",
        ).decode("ascii").rstrip("=")
        offered = f"agentsdock-token.{encoded}"
        socket = FakeWebSocket()
        socket.headers = {
            "sec-websocket-protocol": (
                f"{agent_server.EVENTS_WEBSOCKET_PROTOCOL}, {offered}"
            ),
        }
        with tempfile.TemporaryDirectory() as root, patch.object(
            agent_server,
            "AGENT_TOKEN",
            "server-token",
        ), patch.dict(
            agent_server.STORE.sessions,
            {"protocol-chat": {"id": "protocol-chat"}},
            clear=True,
        ), patch.object(
            agent_server,
            "events_path",
            return_value=Path(root) / "events.jsonl",
        ), patch.object(
            agent_server,
            "fork_internal_run_ids",
            return_value=set(),
        ):
            await agent_server.session_events(
                "protocol-chat",
                socket,  # type: ignore[arg-type]
                visible=True,
            )

        self.assertTrue(socket.accepted)
        self.assertEqual(
            socket.accepted_subprotocol,
            agent_server.EVENTS_WEBSOCKET_PROTOCOL,
        )

    async def test_unauthenticated_server_still_selects_fixed_event_protocol(self) -> None:
        socket = FakeWebSocket()
        socket.headers = {
            "sec-websocket-protocol": agent_server.EVENTS_WEBSOCKET_PROTOCOL,
        }
        with tempfile.TemporaryDirectory() as root, patch.object(
            agent_server,
            "AGENT_TOKEN",
            "",
        ), patch.dict(
            agent_server.STORE.sessions,
            {"protocol-chat": {"id": "protocol-chat"}},
            clear=True,
        ), patch.object(
            agent_server,
            "events_path",
            return_value=Path(root) / "events.jsonl",
        ), patch.object(
            agent_server,
            "fork_internal_run_ids",
            return_value=set(),
        ):
            await agent_server.session_events(
                "protocol-chat",
                socket,  # type: ignore[arg-type]
                visible=True,
            )

        self.assertEqual(
            socket.accepted_subprotocol,
            agent_server.EVENTS_WEBSOCKET_PROTOCOL,
        )

    async def test_opted_in_boundary_scans_run_off_the_event_loop(self) -> None:
        socket = FakeWebSocket()
        loop_thread = threading.get_ident()
        scan_threads: list[int] = []

        def scan(_path: Path) -> int:
            scan_threads.append(threading.get_ident())
            return 0

        with tempfile.TemporaryDirectory() as root, patch.dict(
            agent_server.STORE.sessions,
            {"off-loop-chat": {"id": "off-loop-chat"}},
            clear=True,
        ), patch.object(
            agent_server,
            "events_path",
            return_value=Path(root) / "events.jsonl",
        ), patch.object(
            agent_server,
            "last_event_seq_from_file",
            side_effect=scan,
        ), patch.object(
            agent_server,
            "fork_internal_run_ids",
            return_value=set(),
        ), patch.object(
            agent_server,
            "websocket_authorized",
            return_value=True,
        ):
            await agent_server.session_events(
                "off-loop-chat",
                socket,  # type: ignore[arg-type]
                visible=True,
            )

        self.assertEqual(len(scan_threads), 2)
        self.assertTrue(all(thread != loop_thread for thread in scan_threads))

    async def test_catchup_drains_more_than_one_page_without_raw_events(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "events.jsonl"
            with path.open("w", encoding="utf-8") as output:
                for seq in range(1, 1606):
                    event_type = "raw_event" if seq % 4 == 0 else "reasoning_summary"
                    output.write(json.dumps({
                        "seq": seq,
                        "id": f"event-{seq}",
                        "session_id": "chat",
                        "type": event_type,
                        "ts": "2026-07-28T00:00:00Z",
                        "text": f"event {seq}",
                    }) + "\n")

            socket = FakeWebSocket()
            with (
                patch.object(agent_server, "events_path", return_value=path),
                patch.object(agent_server, "fork_internal_run_ids", return_value=set()),
            ):
                cursor = await agent_server.send_event_catchup(
                    "chat",
                    socket,  # type: ignore[arg-type]
                    after=0,
                    through=1605,
                    visible=True,
                )

        self.assertEqual(cursor, 1605)
        self.assertEqual(len(socket.events), 1204)
        self.assertEqual(socket.events[0]["seq"], 1)
        self.assertEqual(socket.events[-1]["seq"], 1605)
        self.assertNotIn("raw_event", {event["type"] for event in socket.events})

    async def test_prune_replacement_between_pages_cannot_skip_surviving_tail(
        self,
    ) -> None:
        """A byte cursor from the pre-prune inode must never seek into its replacement."""

        session_id = "prune-race-chat"
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "events.jsonl"
            with path.open("w", encoding="utf-8") as output:
                for seq in range(1, 1101):
                    if seq <= 100:
                        text = f"duplicate anchor {seq}"
                        imported = False
                    elif seq <= 1000:
                        text = f"duplicate anchor {((seq - 101) % 100) + 1}"
                        imported = True
                    else:
                        text = f"surviving tail {seq}"
                        imported = False
                    output.write(json.dumps({
                        "seq": seq,
                        "id": f"event-{seq}",
                        "session_id": session_id,
                        "type": "assistant_text",
                        "ts": "2026-09-05T00:00:00Z",
                        "text": text,
                        **({"imported": True, "run_id": "import_duplicates"} if imported else {}),
                    }, separators=(",", ":")) + "\n")

            page_loaded = asyncio.Event()
            resume_send = asyncio.Event()
            registered_with: list[int] = []

            class PruningWebSocket(FakeWebSocket):
                async def send_json(self, event: dict[str, object]) -> None:
                    await super().send_json(event)
                    if event["seq"] == 1000:
                        page_loaded.set()
                        await resume_send.wait()

            socket = PruningWebSocket()

            async def register(_session_id: str, _socket: object) -> None:
                registered_with.extend(int(event["seq"]) for event in socket.events)

            agent_server.EVENT_DELIVERY_LOCKS.pop(session_id, None)
            try:
                with (
                    patch.dict(
                        agent_server.STORE.sessions,
                        {session_id: {"id": session_id}},
                        clear=True,
                    ),
                    patch.object(agent_server, "events_path", return_value=path),
                    patch.object(
                        agent_server,
                        "fork_internal_run_ids",
                        return_value=set(),
                    ),
                    patch.object(
                        agent_server,
                        "websocket_authorized",
                        return_value=True,
                    ),
                    patch.object(
                        agent_server.HUB,
                        "register_accepted",
                        side_effect=register,
                    ),
                    patch.object(
                        agent_server.HUB,
                        "unsubscribe",
                        new=AsyncMock(),
                    ),
                ):
                    catchup = asyncio.create_task(
                        agent_server.session_events(
                            session_id,
                            socket,  # type: ignore[arg-type]
                            after=0,
                            visible=True,
                        )
                    )
                    await asyncio.wait_for(page_loaded.wait(), timeout=3)
                    summary = await asyncio.to_thread(
                        agent_server.prune_duplicate_imported_history_sync,
                        session_id,
                        dry_run=False,
                    )
                    self.assertEqual(summary["removed_events"], 900)
                    resume_send.set()
                    await asyncio.wait_for(catchup, timeout=3)
            finally:
                resume_send.set()
                agent_server.EVENT_DELIVERY_LOCKS.pop(session_id, None)

        delivered = [int(event["seq"]) for event in socket.events]
        self.assertEqual(delivered[-100:], list(range(1001, 1101)))
        self.assertEqual(
            [seq for seq in delivered if 1001 <= seq <= 1100],
            list(range(1001, 1101)),
        )
        # Registration happens only after the surviving replacement tail has
        # crossed the websocket, closing the catch-up/live-delivery handoff.
        self.assertEqual(registered_with[-100:], list(range(1001, 1101)))

    async def test_omitted_visible_query_drains_complete_legacy_gap(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "events.jsonl"
            with path.open("w", encoding="utf-8") as output:
                for seq in range(1, 706):
                    output.write(json.dumps({
                        "seq": seq,
                        "id": f"event-{seq}",
                        "session_id": "legacy-chat",
                        "type": "raw_event" if seq % 2 == 0 else "reasoning_summary",
                        "ts": "2026-07-28T00:00:00Z",
                        "text": f"event {seq}",
                    }) + "\n")

            socket = FakeWebSocket()
            agent_server.EVENT_DELIVERY_LOCKS.pop("legacy-chat", None)
            with (
                patch.dict(
                    agent_server.STORE.sessions,
                    {"legacy-chat": {"id": "legacy-chat"}},
                ),
                patch.object(agent_server, "events_path", return_value=path),
                patch.object(
                    agent_server,
                    "fork_internal_run_ids",
                    return_value=set(),
                ),
                patch.object(
                    agent_server,
                    "websocket_authorized",
                    return_value=True,
                ),
            ):
                await agent_server.session_events(
                    "legacy-chat",
                    socket,  # type: ignore[arg-type]
                    after=0,
                    visible=None,
                )

        self.assertTrue(socket.accepted)
        self.assertEqual(len(socket.events), 705)
        self.assertEqual(socket.events[0]["seq"], 1)
        self.assertEqual(socket.events[-1]["seq"], 705)
        self.assertIn("raw_event", {event["type"] for event in socket.events})

    async def test_legacy_catchup_send_does_not_hold_event_delivery_lock(self) -> None:
        session_id = "legacy-slow-socket"
        send_started = asyncio.Event()
        release_send = asyncio.Event()

        class SlowWebSocket(FakeWebSocket):
            async def send_json(self, event: dict[str, object]) -> None:
                send_started.set()
                await release_send.wait()
                await super().send_json(event)

        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "events.jsonl"
            path.write_text(json.dumps({
                "seq": 1,
                "id": "event-1",
                "session_id": session_id,
                "type": "reasoning_summary",
                "ts": "2026-09-05T00:00:00Z",
                "text": "first",
            }) + "\n", encoding="utf-8")
            socket = SlowWebSocket()
            agent_server.EVENT_DELIVERY_LOCKS.pop(session_id, None)
            try:
                with (
                    patch.dict(
                        agent_server.STORE.sessions,
                        {session_id: {"id": session_id}},
                        clear=True,
                    ),
                    patch.object(agent_server, "events_path", return_value=path),
                    patch.object(
                        agent_server,
                        "fork_internal_run_ids",
                        return_value=set(),
                    ),
                    patch.object(
                        agent_server,
                        "websocket_authorized",
                        return_value=True,
                    ),
                ):
                    catchup = asyncio.create_task(
                        agent_server.session_events(
                            session_id,
                            socket,  # type: ignore[arg-type]
                            after=0,
                            visible=None,
                        )
                    )
                    await asyncio.wait_for(send_started.wait(), timeout=1)

                    async def acquire_delivery_lock() -> None:
                        async with agent_server.event_delivery_lock(session_id):
                            return

                    await asyncio.wait_for(acquire_delivery_lock(), timeout=0.1)
                    release_send.set()
                    await asyncio.wait_for(catchup, timeout=1)
            finally:
                release_send.set()
                agent_server.EVENT_DELIVERY_LOCKS.pop(session_id, None)

        self.assertEqual([event["seq"] for event in socket.events], [1])

    async def test_opted_in_handshake_delivers_racing_and_live_events_once(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "events.jsonl"
            path.write_text(json.dumps({
                "seq": 1,
                "id": "event-1",
                "session_id": "race-chat",
                "type": "reasoning_summary",
                "ts": "2026-07-28T00:00:00Z",
                "text": "first",
            }) + "\n", encoding="utf-8")

            class RacingWebSocket(FakeWebSocket):
                injected = False

                async def send_json(self, event: dict[str, object]) -> None:
                    await super().send_json(event)
                    if event["seq"] == 1 and not self.injected:
                        self.injected = True
                        await agent_server.append_event(
                            "race-chat",
                            "reasoning_summary",
                            {"text": "raced"},
                        )

                async def receive_text(self) -> str:
                    await agent_server.append_event(
                        "race-chat",
                        "reasoning_summary",
                        {"text": "live"},
                    )
                    raise agent_server.WebSocketDisconnect()

            socket = RacingWebSocket()
            agent_server.EVENT_SEQ_CACHE.pop("race-chat", None)
            agent_server.EVENT_DELIVERY_LOCKS.pop("race-chat", None)
            with (
                patch.dict(
                    agent_server.STORE.sessions,
                    {"race-chat": {"id": "race-chat"}},
                ),
                patch.object(agent_server, "ensure_dirs"),
                patch.object(agent_server, "events_path", return_value=path),
                patch.object(
                    agent_server,
                    "fork_internal_run_ids",
                    return_value=set(),
                ),
                patch.object(
                    agent_server,
                    "websocket_authorized",
                    return_value=True,
                ),
                patch.object(
                    agent_server,
                    "update_session_event_metadata",
                    new=AsyncMock(),
                ),
                patch.object(
                    agent_server,
                    "event_files_belong_to_session",
                    return_value=True,
                ),
            ):
                await agent_server.session_events(
                    "race-chat",
                    socket,  # type: ignore[arg-type]
                    after=0,
                    visible=True,
                )

        self.assertEqual(
            [event["seq"] for event in socket.events],
            [1, 2, 3],
        )

    async def test_append_event_preserves_live_sequence_order(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "events.jsonl"
            first_metadata_started = asyncio.Event()
            release_first_metadata = asyncio.Event()
            delivered: list[int] = []

            async def update_metadata(_session_id: str, event: dict[str, object]) -> None:
                if event["seq"] == 1:
                    first_metadata_started.set()
                    await release_first_metadata.wait()

            async def broadcast(_session_id: str, event: dict[str, object]) -> None:
                delivered.append(int(event["seq"]))

            agent_server.EVENT_SEQ_CACHE.pop("ordered-chat", None)
            agent_server.EVENT_DELIVERY_LOCKS.pop("ordered-chat", None)
            with (
                patch.object(agent_server, "ensure_dirs"),
                patch.object(agent_server, "events_path", return_value=path),
                patch.object(
                    agent_server,
                    "update_session_event_metadata",
                    side_effect=update_metadata,
                ),
                patch.object(
                    agent_server,
                    "event_files_belong_to_session",
                    return_value=True,
                ),
                patch.object(
                    agent_server.HUB,
                    "broadcast",
                    side_effect=broadcast,
                ),
            ):
                first = asyncio.create_task(
                    agent_server.append_event(
                        "ordered-chat",
                        "reasoning_summary",
                        {"text": "first"},
                    )
                )
                await first_metadata_started.wait()
                second = asyncio.create_task(
                    agent_server.append_event(
                        "ordered-chat",
                        "reasoning_summary",
                        {"text": "second"},
                    )
                )
                await asyncio.sleep(0)
                self.assertEqual(delivered, [])
                release_first_metadata.set()
                await asyncio.gather(first, second)

            persisted = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual([event["seq"] for event in persisted], [1, 2])
        self.assertEqual(delivered, [1, 2])

    async def test_append_event_bounds_tool_output_once_with_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "events.jsonl"
            agent_server.EVENT_SEQ_CACHE.pop("bounded-chat", None)
            agent_server.EVENT_DELIVERY_LOCKS.pop("bounded-chat", None)
            with (
                patch.object(agent_server, "ensure_dirs"),
                patch.object(agent_server, "events_path", return_value=path),
                patch.object(
                    agent_server,
                    "update_session_event_metadata",
                    new=AsyncMock(),
                ),
                patch.object(
                    agent_server,
                    "event_files_belong_to_session",
                    return_value=False,
                ),
                patch.object(
                    agent_server,
                    "CODEX_APP_SERVER_TOOL_OUTPUT_MAX_CHARS",
                    80,
                ),
            ):
                event = await agent_server.append_event(
                    "bounded-chat",
                    "tool_finished",
                    {"output": "x" * 200},
                )

            persisted = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(event["output_chars"], 200)
        self.assertTrue(event["output_truncated"])
        self.assertLessEqual(len(event["output"]), 80)
        self.assertEqual(persisted["output"], event["output"])
        self.assertTrue(
            event["output"].startswith(
                "[Earlier tool output truncated by AgentsServer]\n"
            )
        )


if __name__ == "__main__":
    unittest.main()
