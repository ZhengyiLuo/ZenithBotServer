"""Catching a chat up with provider messages added outside AgentsDock.

Importing a remote conversation used to be a one-time snapshot: continuing it
in the provider's own CLI grew the transcript, AgentsDock never noticed, and
the next AgentsDock turn resumed the thread so the model answered with full
context the timeline had never shown. Re-importing was no fix either - it had
no dedup and appended the whole conversation a second time.
"""

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import agent_server


def user(text: str) -> dict[str, str]:
    return {"kind": "user", "text": text}


def assistant(text: str) -> dict[str, str]:
    return {"kind": "assistant", "text": text}


def provider_line(backend: str, kind: str, text: str) -> str:
    if backend == agent_server.BACKEND_CLAUDE:
        record = {
            "type": kind,
            "message": {"content": [{"type": "text", "text": text}]},
        }
    elif kind == "user":
        record = {
            "type": "event_msg",
            "payload": {"type": "user_message", "message": text},
        }
    else:
        record = {
            "type": "event_msg",
            "payload": {"type": "agent_message", "message": text},
        }
    return json.dumps(record, separators=(",", ":")) + "\n"


def fake_history_timeline_scan(events: list[dict]):
    """Mirror the message-only scanner for tests with an in-memory timeline."""

    def scan(
        _session_id,
        *,
        timeline_after_seq,
        timeline_through_seq,
        tail,
        include_imported,
    ):
        selected = []
        has_messages = False
        for index, event in enumerate(events, 1):
            seq = int(event.get("seq") or index)
            if seq <= timeline_after_seq or seq > timeline_through_seq:
                continue
            event_type = event.get("type")
            if event_type == "turn_started":
                key = agent_server.history_dedup_key("user", event.get("prompt"))
            elif event_type == "assistant_text":
                key = agent_server.history_dedup_key(
                    "assistant", event.get("text")
                )
            else:
                continue
            has_messages = True
            if not include_imported and event.get("imported") is True:
                continue
            selected.append((seq, key))
        maximum = max(1, int(agent_server.HISTORY_SYNC_EVENT_SCAN_LIMIT))
        if tail:
            selected = selected[-maximum:]
        front_window_truncated = False
        if not tail and len(selected) > maximum:
            selected = selected[:maximum]
            front_window_truncated = True
        return selected, has_messages, front_window_truncated

    return scan


class UnsyncedHistoryItemsTests(unittest.TestCase):
    """Pure selection logic: what does the timeline not have yet?"""

    def select(self, events, items):
        with patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ):
            return agent_server.unsynced_history_items(
                "chat-x",
                items,
                timeline_through_seq=len(events),
            )

    def test_nothing_new_when_the_timeline_already_shows_it_all(self) -> None:
        events = [
            {"type": "turn_started", "prompt": "hello"},
            {"type": "assistant_text", "text": "hi there"},
        ]
        self.assertEqual(
            self.select(events, [user("hello"), assistant("hi there")]), []
        )

    def test_returns_only_the_tail_added_elsewhere(self) -> None:
        events = [
            {"type": "turn_started", "prompt": "hello"},
            {"type": "assistant_text", "text": "hi there"},
        ]
        fresh = self.select(
            events,
            [
                user("hello"),
                assistant("hi there"),
                user("continued in the CLI"),
                assistant("answered in the CLI"),
            ],
        )
        self.assertEqual(
            fresh, [user("continued in the CLI"), assistant("answered in the CLI")]
        )

    def test_everything_is_new_for_an_empty_timeline(self) -> None:
        self.assertEqual(
            self.select([], [user("hello"), assistant("hi")]),
            [user("hello"), assistant("hi")],
        )

    def test_whitespace_differences_still_count_as_the_same_message(self) -> None:
        # The two sides reach the timeline through different cleaning paths.
        events = [{"type": "assistant_text", "text": "hi   there\n\n"}]
        self.assertEqual(self.select(events, [assistant("hi there")]), [])

    def test_a_repeated_message_is_matched_once_per_occurrence(self) -> None:
        # "continue" sent twice must not make the second one look already
        # imported.
        events = [
            {"type": "turn_started", "prompt": "continue"},
            {"type": "assistant_text", "text": "ok"},
        ]
        fresh = self.select(
            events, [user("continue"), assistant("ok"), user("continue")]
        )
        self.assertEqual(fresh, [user("continue")])

    def test_a_complete_duplicate_exchange_appended_later_is_not_hidden(self) -> None:
        events = [
            {"type": "turn_started", "prompt": "same question"},
            {"type": "assistant_text", "text": "same answer"},
        ]
        repeated_exchange = [
            user("same question"),
            assistant("same answer"),
        ]
        self.assertEqual(
            self.select(events, repeated_exchange + repeated_exchange),
            repeated_exchange,
        )

    def test_a_mid_history_mismatch_never_splices_a_duplicate(self) -> None:
        # If an older message fails to match, the safe outcome is importing
        # nothing extra - not re-inserting it in the middle of the chat.
        events = [
            {"type": "turn_started", "prompt": "hello"},
            {"type": "assistant_text", "text": "TIMELINE VERSION"},
            {"type": "turn_started", "prompt": "second"},
            {"type": "assistant_text", "text": "second reply"},
        ]
        fresh = self.select(
            events,
            [
                user("hello"),
                assistant("TRANSCRIPT VERSION"),
                user("second"),
                assistant("second reply"),
            ],
        )
        self.assertEqual(fresh, [])

    def test_turns_run_by_agentsdock_are_not_re_imported(self) -> None:
        # The transcript also contains everything this server ran itself.
        events = [
            {"type": "turn_started", "prompt": "asked from AgentsDock"},
            {"type": "assistant_text", "text": "answered to AgentsDock"},
        ]
        self.assertEqual(
            self.select(
                events,
                [user("asked from AgentsDock"), assistant("answered to AgentsDock")],
            ),
            [],
        )

    def test_cursor_keeps_external_prefix_before_timeline_owned_suffix(self) -> None:
        events = [
            {"seq": 11, "type": "turn_started", "prompt": "local after"},
            {"seq": 12, "type": "assistant_text", "text": "local answer"},
        ]
        delta = [
            user("external before"),
            assistant("external answer"),
            user("local after"),
            assistant("local answer"),
        ]
        with patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ):
            fresh, consumed_seq = agent_server.reconcile_cursor_history_items(
                "chat-x",
                delta,
                timeline_after_seq=10,
                timeline_through_seq=12,
            )
        self.assertEqual(
            fresh,
            [user("external before"), assistant("external answer")],
        )
        self.assertEqual(consumed_seq, 12)

    def test_cursor_consumes_repeated_timeline_occurrences_only_once(self) -> None:
        events = [
            {"seq": 11, "type": "turn_started", "prompt": "same question"},
            {"seq": 12, "type": "assistant_text", "text": "same answer"},
        ]
        pair = [user("same question"), assistant("same answer")]
        with patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ):
            fresh, consumed_seq = agent_server.reconcile_cursor_history_items(
                "chat-x",
                pair + pair,
                timeline_after_seq=10,
                timeline_through_seq=12,
            )
        self.assertEqual(fresh, pair)
        self.assertEqual(consumed_seq, 12)

    def test_cursor_scan_bounds_ownership_messages_not_raw_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            event_path = Path(tempdir) / "events.jsonl"
            events = [
                {"seq": 1, "type": "raw_event"},
                {
                    "seq": 2,
                    "type": "turn_started",
                    "prompt": "external message",
                    "imported": True,
                },
                {"seq": 3, "type": "tool_started"},
                {"seq": 4, "type": "tool_finished"},
                {"seq": 5, "type": "status"},
                {"seq": 6, "type": "raw_event"},
                {"seq": 7, "type": "turn_started", "prompt": "local message"},
            ]
            event_path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            with patch.object(
                agent_server, "events_path", return_value=event_path
            ), patch.object(agent_server, "HISTORY_SYNC_EVENT_SCAN_LIMIT", 1):
                fresh, consumed_seq = agent_server.reconcile_cursor_history_items(
                    "chat-x",
                    [user("external message"), user("local message")],
                    timeline_after_seq=0,
                    timeline_through_seq=7,
                )

        self.assertEqual(fresh, [user("external message")])
        self.assertEqual(consumed_seq, 7)

    def test_cursor_ownership_credit_overflow_advances_across_front_windows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            event_path = Path(tempdir) / "events.jsonl"
            events = [
                {
                    "seq": seq,
                    "type": "turn_started",
                    "prompt": f"local-{seq}",
                }
                for seq in range(1, 4)
            ]
            event_path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            with patch.object(
                agent_server, "events_path", return_value=event_path
            ), patch.object(agent_server, "HISTORY_SYNC_EVENT_SCAN_LIMIT", 2):
                first_fresh, first_consumed_seq = (
                    agent_server.reconcile_cursor_history_items(
                        "chat-x",
                        [user("local-1"), user("local-2")],
                        timeline_after_seq=0,
                        timeline_through_seq=3,
                    )
                )
                second_fresh, second_consumed_seq = (
                    agent_server.reconcile_cursor_history_items(
                        "chat-x",
                        [user("local-3")],
                        timeline_after_seq=first_consumed_seq,
                        timeline_through_seq=3,
                    )
                )

        self.assertEqual(first_fresh, [])
        self.assertEqual(first_consumed_seq, 2)
        self.assertEqual(second_fresh, [])
        self.assertEqual(second_consumed_seq, 3)

    def test_cursor_scan_fails_closed_on_malformed_physical_event(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            event_path = Path(tempdir) / "events.jsonl"
            event_path.write_text(
                json.dumps({
                    "seq": 1,
                    "type": "turn_started",
                    "prompt": "local-1",
                })
                + "\n{malformed}\n"
                + json.dumps({
                    "seq": 3,
                    "type": "turn_started",
                    "prompt": "local-3",
                })
                + "\n",
                encoding="utf-8",
            )
            with patch.object(
                agent_server, "events_path", return_value=event_path
            ):
                with self.assertRaisesRegex(ValueError, "malformed event"):
                    agent_server.reconcile_cursor_history_items(
                        "chat-x",
                        [user("local-1"), user("local-3")],
                        timeline_after_seq=0,
                        timeline_through_seq=3,
                    )

    def test_initial_alignment_ignores_nonmessage_suffix_volume(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            event_path = Path(tempdir) / "events.jsonl"
            events = [
                {"seq": 1, "type": "turn_started", "prompt": "existing"},
                {"seq": 2, "type": "assistant_text", "text": "answer"},
                *[
                    {"seq": seq, "type": "raw_event", "payload": f"raw-{seq}"}
                    for seq in range(3, 9)
                ],
            ]
            event_path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            existing = [user("existing"), assistant("answer")]
            appended = [user("outside"), assistant("outside answer")]
            with patch.object(
                agent_server, "events_path", return_value=event_path
            ), patch.object(agent_server, "HISTORY_SYNC_EVENT_SCAN_LIMIT", 2):
                unchanged = agent_server.unsynced_history_items(
                    "chat-x",
                    existing,
                    timeline_through_seq=8,
                )
                fresh = agent_server.unsynced_history_items(
                    "chat-x",
                    existing + appended,
                    timeline_through_seq=8,
                )

        self.assertEqual(unchanged, [])
        self.assertEqual(fresh, appended)


class SyncProviderHistoryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.transcript = Path(self.tempdir.name) / "rollout.jsonl"
        self.transcript.write_text("", encoding="utf-8")
        self.sess = {
            "id": "chat-sync",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "thread-1",
        }

    async def test_appends_only_the_externally_added_tail(self) -> None:
        items = [
            user("hello"),
            assistant("hi there"),
            user("continued in the CLI"),
            assistant("answered in the CLI"),
        ]
        events = [
            {"type": "turn_started", "prompt": "hello"},
            {"type": "assistant_text", "text": "hi there"},
        ]
        appended: list[tuple[str, dict]] = []

        async def fake_append_batch(session_id, event_specs):
            appended.extend(event_specs)
            return [
                {"seq": index, "type": event_type, **payload}
                for index, (event_type, payload) in enumerate(event_specs, 1)
            ]

        with patch.object(
            agent_server,
            "load_provider_history_with_cursor",
            return_value=(self.transcript, items, None, False),
        ), patch.object(
            agent_server, "read_events", return_value=events
        ), patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ), patch.object(
            agent_server, "last_event_seq_from_file", return_value=len(events)
        ), patch.object(
            agent_server, "append_durable_event_batch", fake_append_batch
        ):
            result = await agent_server.sync_provider_history(self.sess)

        self.assertEqual(result["imported"], 2)
        prompts = [p.get("prompt") for t, p in appended if t == "turn_started"]
        texts = [p.get("text") for t, p in appended if t == "assistant_text"]
        self.assertEqual(prompts, ["continued in the CLI"])
        self.assertEqual(texts, ["answered in the CLI"])
        # The already-shown opening must not be replayed.
        self.assertNotIn("hello", prompts)
        self.assertNotIn("hi there", texts)

    async def test_up_to_date_transcript_appends_nothing_at_all(self) -> None:
        # Opening a chat repeatedly must not keep adding landmark events.
        items = [user("hello"), assistant("hi there")]
        events = [
            {"type": "turn_started", "prompt": "hello"},
            {"type": "assistant_text", "text": "hi there"},
        ]
        appended: list[str] = []

        async def fake_append(session_id, event_type, payload=None):
            appended.append(event_type)
            return {}

        with patch.object(
            agent_server,
            "load_provider_history_with_cursor",
            return_value=(self.transcript, items, None, False),
        ), patch.object(
            agent_server, "read_events", return_value=events
        ), patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ), patch.object(
            agent_server, "last_event_seq_from_file", return_value=len(events)
        ), patch.object(
            agent_server, "append_event", fake_append
        ):
            result = await agent_server.sync_provider_history(self.sess)

        self.assertEqual(result["imported"], 0)
        self.assertEqual(appended, [])

    async def test_session_without_a_provider_id_is_skipped(self) -> None:
        result = await agent_server.sync_provider_history(
            {"id": "chat-none", "backend": agent_server.BACKEND_CODEX}
        )
        self.assertEqual(result["imported"], 0)


class DurableHistoryCursorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)

    @staticmethod
    def timeline_event(seq: int, item: dict[str, str]) -> dict:
        if item["kind"] == "user":
            return {"seq": seq, "type": "turn_started", "prompt": item["text"]}
        return {"seq": seq, "type": "assistant_text", "text": item["text"]}

    @staticmethod
    def fake_read_events(events: list[dict]):
        def read(
            _session_id,
            *,
            after=0,
            before=None,
            limit=1000,
            tail=False,
            **_kwargs,
        ):
            selected = [
                event
                for event in events
                if int(event.get("seq") or 0) > int(after or 0)
                and (before is None or int(event.get("seq") or 0) < int(before))
            ]
            return selected[-limit:] if tail else selected[:limit]

        return read

    @staticmethod
    def fake_append_events(events: list[dict], batches: list[list[tuple[str, dict]]]):
        async def append(_session_id, event_specs):
            specs = list(event_specs)
            batches.append(specs)
            committed = []
            next_seq = int(events[-1]["seq"]) + 1 if events else 1
            for event_type, payload in specs:
                event = {"seq": next_seq, "type": event_type, **payload}
                events.append(event)
                committed.append(event)
                next_seq += 1
            return committed

        return append

    @staticmethod
    def last_seq(events: list[dict]):
        return lambda _path: int(events[-1]["seq"]) if events else 0

    async def test_full_window_duplicate_pair_append_survives_rollover(self) -> None:
        maximum = agent_server.normalized_history_import_limit(None)
        self.assertGreaterEqual(maximum, 4)
        repeated_pair = [
            user("same rollover question"),
            assistant("same rollover answer"),
        ]
        prefix = [
            (user if index % 2 == 0 else assistant)(f"unique-{index}")
            for index in range(maximum - len(repeated_pair))
        ]
        baseline = prefix + repeated_pair

        for backend in (agent_server.BACKEND_CLAUDE, agent_server.BACKEND_CODEX):
            with self.subTest(backend=backend):
                transcript = Path(self.tempdir.name) / f"{backend}.jsonl"
                transcript.write_text(
                    "".join(
                        provider_line(backend, item["kind"], item["text"])
                        for item in baseline
                    ),
                    encoding="utf-8",
                )
                provider_field = (
                    "claude_session_id"
                    if backend == agent_server.BACKEND_CLAUDE
                    else "codex_thread_id"
                )
                sess = {
                    "id": f"rollover-{backend}",
                    "backend": backend,
                    provider_field: f"provider-{backend}",
                }
                live = {sess["id"]: dict(sess)}
                events = [
                    self.timeline_event(index, item)
                    for index, item in enumerate(baseline, 1)
                ]
                batches: list[list[tuple[str, dict]]] = []
                save = AsyncMock()
                with patch.object(agent_server.STORE, "sessions", live), patch.object(
                    agent_server.STORE, "save", save
                ), patch.object(
                    agent_server, "provider_history_path", return_value=transcript
                ), patch.object(
                    agent_server,
                    "read_events",
                    side_effect=self.fake_read_events(events),
                ), patch.object(
                    agent_server,
                    "history_timeline_message_keys",
                    side_effect=fake_history_timeline_scan(events),
                ), patch.object(
                    agent_server,
                    "last_event_seq_from_file",
                    side_effect=self.last_seq(events),
                ), patch.object(
                    agent_server,
                    "append_durable_event_batch",
                    side_effect=self.fake_append_events(events, batches),
                ):
                    initial = await agent_server.sync_provider_history(dict(sess))
                    # Exercise the durable JSON representation rather than
                    # relying on process-local cursor identity.
                    live[sess["id"]] = json.loads(json.dumps(live[sess["id"]]))
                    with transcript.open("a", encoding="utf-8") as stream:
                        stream.write(
                            "".join(
                                provider_line(backend, item["kind"], item["text"])
                                for item in repeated_pair
                            )
                        )
                    appended = await agent_server.sync_provider_history(dict(sess))
                    unchanged = await agent_server.sync_provider_history(dict(sess))

                self.assertEqual(initial["imported"], 0)
                self.assertEqual(appended["imported"], 2)
                self.assertEqual(unchanged["imported"], 0)
                imported_messages = [
                    (
                        user(payload["prompt"])
                        if event_type == "turn_started"
                        else assistant(payload["text"])
                    )
                    for batch in batches
                    for event_type, payload in batch
                    if event_type in {"turn_started", "assistant_text"}
                ]
                self.assertEqual(imported_messages, repeated_pair)

    async def test_more_than_message_cap_drains_from_front_across_passes(self) -> None:
        maximum = agent_server.normalized_history_import_limit(None)
        transcript = Path(self.tempdir.name) / "overflow.jsonl"
        transcript.write_text("", encoding="utf-8")
        sess = {
            "id": "overflow",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "overflow-thread",
        }
        live = {sess["id"]: dict(sess)}
        events: list[dict] = []
        batches: list[list[tuple[str, dict]]] = []
        external_items = [
            (user if index % 2 == 0 else assistant)(f"overflow-{index}")
            for index in range(maximum)
        ]
        local_pair = [user("local after cap"), assistant("local answer after cap")]
        appended_items = external_items + local_pair
        with patch.object(agent_server.STORE, "sessions", live), patch.object(
            agent_server.STORE, "save", new=AsyncMock()
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ), patch.object(
            agent_server,
            "read_events",
            side_effect=self.fake_read_events(events),
        ), patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ), patch.object(
            agent_server,
            "last_event_seq_from_file",
            side_effect=self.last_seq(events),
        ), patch.object(
            agent_server,
            "append_durable_event_batch",
            side_effect=self.fake_append_events(events, batches),
        ):
            baseline = await agent_server.sync_provider_history(dict(sess))
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write(
                    "".join(
                        provider_line(
                            agent_server.BACKEND_CODEX,
                            item["kind"],
                            item["text"],
                        )
                        for item in appended_items
                    )
                )
            events.extend(
                self.timeline_event(index, item)
                for index, item in enumerate(local_pair, 1)
            )
            first = await agent_server.sync_provider_history(dict(sess))
            partial_cursor = dict(live[sess["id"]]["_history_sync_cursor"])
            second = await agent_server.sync_provider_history(dict(sess))
            third = await agent_server.sync_provider_history(dict(sess))

        self.assertEqual(baseline["imported"], 0)
        self.assertEqual(
            [first["imported"], second["imported"], third["imported"]],
            [maximum, 0, 0],
        )
        self.assertFalse(partial_cursor["timeline_pending_active"])
        self.assertEqual(partial_cursor["timeline_pending_through_seq"], 0)
        self.assertLess(partial_cursor["source_offset"], transcript.stat().st_size)
        imported_messages = [
            payload.get("prompt") if event_type == "turn_started" else payload.get("text")
            for batch in batches
            for event_type, payload in batch
            if event_type in {"turn_started", "assistant_text"}
        ]
        self.assertEqual(imported_messages, [item["text"] for item in external_items])
        self.assertFalse(
            live[sess["id"]]["_history_sync_cursor"]["timeline_pending_active"]
        )

    async def test_partial_batches_include_new_local_credits_between_passes(self) -> None:
        transcript = Path(self.tempdir.name) / "interleaved-passes.jsonl"
        transcript.write_text("", encoding="utf-8")
        sess = {
            "id": "interleaved-passes",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "interleaved-passes-thread",
        }
        live = {sess["id"]: dict(sess)}
        events: list[dict] = []
        batches: list[list[tuple[str, dict]]] = []
        external_pair = [user("outside first"), assistant("outside answer")]
        old_local_pair = [user("old local"), assistant("old local answer")]
        new_local_pair = [user("new local"), assistant("new local answer")]
        with patch.object(agent_server.STORE, "sessions", live), patch.object(
            agent_server.STORE, "save", new=AsyncMock()
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ), patch.object(
            agent_server,
            "read_events",
            side_effect=self.fake_read_events(events),
        ), patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ), patch.object(
            agent_server,
            "last_event_seq_from_file",
            side_effect=self.last_seq(events),
        ), patch.object(
            agent_server,
            "append_durable_event_batch",
            side_effect=self.fake_append_events(events, batches),
        ):
            baseline = await agent_server.sync_provider_history(dict(sess), limit=2)
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write(
                    "".join(
                        provider_line(
                            agent_server.BACKEND_CODEX,
                            item["kind"],
                            item["text"],
                        )
                        for item in external_pair + old_local_pair
                    )
                )
            events.extend(
                self.timeline_event(index, item)
                for index, item in enumerate(old_local_pair, 1)
            )
            first = await agent_server.sync_provider_history(dict(sess), limit=2)

            next_seq = int(events[-1]["seq"]) + 1
            events.extend(
                self.timeline_event(next_seq + index, item)
                for index, item in enumerate(new_local_pair)
            )
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write(
                    "".join(
                        provider_line(
                            agent_server.BACKEND_CODEX,
                            item["kind"],
                            item["text"],
                        )
                        for item in new_local_pair
                    )
                )
            second = await agent_server.sync_provider_history(dict(sess), limit=2)
            third = await agent_server.sync_provider_history(dict(sess), limit=2)
            unchanged = await agent_server.sync_provider_history(dict(sess), limit=2)

        self.assertEqual(
            [
                baseline["imported"],
                first["imported"],
                second["imported"],
                third["imported"],
                unchanged["imported"],
            ],
            [0, 2, 0, 0, 0],
        )
        imported_messages = [
            payload.get("prompt")
            if event_type == "turn_started"
            else payload.get("text")
            for batch in batches
            for event_type, payload in batch
            if event_type in {"turn_started", "assistant_text"}
        ]
        self.assertEqual(imported_messages, [item["text"] for item in external_pair])
        self.assertEqual(
            live[sess["id"]]["_history_sync_cursor"]["source_offset"],
            transcript.stat().st_size,
        )

    async def test_partial_jsonl_line_is_not_crossed_and_imports_once_when_completed(self) -> None:
        transcript = Path(self.tempdir.name) / "partial.jsonl"
        transcript.write_text("", encoding="utf-8")
        sess = {
            "id": "partial",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "partial-thread",
        }
        live = {sess["id"]: dict(sess)}
        events: list[dict] = []
        batches: list[list[tuple[str, dict]]] = []
        encoded = provider_line(
            agent_server.BACKEND_CODEX,
            "user",
            "completed later",
        ).encode("utf-8")
        with patch.object(agent_server.STORE, "sessions", live), patch.object(
            agent_server.STORE, "save", new=AsyncMock()
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ), patch.object(
            agent_server,
            "read_events",
            side_effect=self.fake_read_events(events),
        ), patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ), patch.object(
            agent_server,
            "last_event_seq_from_file",
            side_effect=self.last_seq(events),
        ), patch.object(
            agent_server,
            "append_durable_event_batch",
            side_effect=self.fake_append_events(events, batches),
        ):
            await agent_server.sync_provider_history(dict(sess))
            with transcript.open("ab") as stream:
                stream.write(encoded[:-1])
            partial = await agent_server.sync_provider_history(dict(sess))
            partial_offset = live[sess["id"]]["_history_sync_cursor"]["source_offset"]
            with transcript.open("ab") as stream:
                stream.write(b"\n")
            complete = await agent_server.sync_provider_history(dict(sess))
            unchanged = await agent_server.sync_provider_history(dict(sess))

        self.assertEqual(partial["imported"], 0)
        self.assertEqual(partial_offset, 0)
        self.assertEqual(complete["imported"], 1)
        self.assertEqual(unchanged["imported"], 0)
        self.assertEqual(len(batches), 1)

    async def test_identical_prefix_atomic_replacement_continues_cursor(self) -> None:
        transcript = Path(self.tempdir.name) / "replace.jsonl"
        original = provider_line(agent_server.BACKEND_CODEX, "user", "existing")
        transcript.write_text(original, encoding="utf-8")
        sess = {
            "id": "replace",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "replace-thread",
        }
        live = {sess["id"]: dict(sess)}
        events = [self.timeline_event(1, user("existing"))]
        batches: list[list[tuple[str, dict]]] = []
        with patch.object(agent_server.STORE, "sessions", live), patch.object(
            agent_server.STORE, "save", new=AsyncMock()
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ), patch.object(
            agent_server,
            "read_events",
            side_effect=self.fake_read_events(events),
        ), patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ), patch.object(
            agent_server,
            "last_event_seq_from_file",
            side_effect=self.last_seq(events),
        ), patch.object(
            agent_server,
            "append_durable_event_batch",
            side_effect=self.fake_append_events(events, batches),
        ):
            initial = await agent_server.sync_provider_history(dict(sess))
            original_ino = transcript.stat().st_ino
            replacement = transcript.with_suffix(".next")
            replacement.write_text(
                original
                + provider_line(
                    agent_server.BACKEND_CODEX,
                    "assistant",
                    "from replacement",
                ),
                encoding="utf-8",
            )
            os.replace(replacement, transcript)
            appended = await agent_server.sync_provider_history(dict(sess))

        self.assertEqual(initial["imported"], 0)
        self.assertNotEqual(original_ino, transcript.stat().st_ino)
        self.assertEqual(appended["imported"], 1)
        self.assertEqual(
            [
                payload["text"]
                for batch in batches
                for event_type, payload in batch
                if event_type == "assistant_text"
            ],
            ["from replacement"],
        )

    async def test_divergent_replacement_fails_closed_without_cursor_advance(self) -> None:
        transcript = Path(self.tempdir.name) / "divergent.jsonl"
        transcript.write_text(
            provider_line(agent_server.BACKEND_CODEX, "user", "existing prefix"),
            encoding="utf-8",
        )
        sess = {
            "id": "divergent",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "divergent-thread",
        }
        live = {sess["id"]: dict(sess)}
        events = [self.timeline_event(1, user("existing prefix"))]
        batches: list[list[tuple[str, dict]]] = []
        save = AsyncMock()
        with patch.object(agent_server.STORE, "sessions", live), patch.object(
            agent_server.STORE, "save", save
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ), patch.object(
            agent_server,
            "read_events",
            side_effect=self.fake_read_events(events),
        ), patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ), patch.object(
            agent_server,
            "last_event_seq_from_file",
            side_effect=self.last_seq(events),
        ), patch.object(
            agent_server,
            "append_durable_event_batch",
            side_effect=self.fake_append_events(events, batches),
        ):
            await agent_server.sync_provider_history(dict(sess))
            old_cursor = json.loads(
                json.dumps(live[sess["id"]]["_history_sync_cursor"])
            )
            replacement = transcript.with_suffix(".next")
            replacement.write_text(
                provider_line(
                    agent_server.BACKEND_CODEX,
                    "user",
                    "different prefix with enough bytes",
                ),
                encoding="utf-8",
            )
            os.replace(replacement, transcript)
            with self.assertRaisesRegex(ValueError, "no longer extends"):
                await agent_server.sync_provider_history(dict(sess))

        self.assertEqual(live[sess["id"]]["_history_sync_cursor"], old_cursor)
        self.assertEqual(save.await_count, 1)
        self.assertEqual(batches, [])

    async def test_append_between_snapshot_and_parse_does_not_advance_cursor(self) -> None:
        transcript = Path(self.tempdir.name) / "mutated.jsonl"
        transcript.write_text(
            provider_line(agent_server.BACKEND_CODEX, "user", "existing"),
            encoding="utf-8",
        )
        sess = {
            "id": "mutated",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "mutated-thread",
        }
        live = {sess["id"]: dict(sess)}
        events = [self.timeline_event(1, user("existing"))]
        save = AsyncMock()
        with patch.object(agent_server.STORE, "sessions", live), patch.object(
            agent_server.STORE, "save", save
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ), patch.object(
            agent_server,
            "read_events",
            side_effect=self.fake_read_events(events),
        ), patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ), patch.object(
            agent_server,
            "last_event_seq_from_file",
            side_effect=self.last_seq(events),
        ):
            await agent_server.sync_provider_history(dict(sess))
            old_cursor = json.loads(
                json.dumps(live[sess["id"]]["_history_sync_cursor"])
            )
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write(
                    provider_line(agent_server.BACKEND_CODEX, "assistant", "new")
                )
            original_parse = agent_server.parse_provider_history_delta

            def mutate_then_parse(*args, **kwargs):
                with transcript.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"type": "ignored"}) + "\n")
                return original_parse(*args, **kwargs)

            with patch.object(
                agent_server,
                "parse_provider_history_delta",
                side_effect=mutate_then_parse,
            ), self.assertRaisesRegex(ValueError, "changed before cursor parsing"):
                await agent_server.sync_provider_history(dict(sess))

        self.assertEqual(live[sess["id"]]["_history_sync_cursor"], old_cursor)
        self.assertEqual(save.await_count, 1)

    def test_codex_duplicate_record_format_across_cursor_is_coalesced(self) -> None:
        transcript = Path(self.tempdir.name) / "cross-format.jsonl"
        transcript.write_text(
            provider_line(agent_server.BACKEND_CODEX, "user", "same message"),
            encoding="utf-8",
        )
        sess = {
            "id": "cross-format",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "cross-format-thread",
        }
        response_item = {
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "same message"}],
            },
        }
        with patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ):
            _path, first, cursor, continued = (
                agent_server.load_provider_history_with_cursor(sess, None, None)
            )
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(response_item, separators=(",", ":")) + "\n")
            _path, second, next_cursor, continued_again = (
                agent_server.load_provider_history_with_cursor(sess, None, cursor)
            )

        self.assertEqual(first, [user("same message")])
        self.assertFalse(continued)
        self.assertEqual(second, [])
        self.assertTrue(continued_again)
        self.assertEqual(next_cursor["source_offset"], transcript.stat().st_size)

    def test_raw_checkpoint_reader_recovers_field_hidden_from_clients(self) -> None:
        transcript = Path(self.tempdir.name) / "raw-checkpoint-provider.jsonl"
        transcript.write_text(
            provider_line(agent_server.BACKEND_CODEX, "user", "committed"),
            encoding="utf-8",
        )
        event_path = Path(self.tempdir.name) / "events.jsonl"
        sess = {
            "id": "raw-checkpoint",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "raw-checkpoint-thread",
        }
        with patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ):
            _path, _items, cursor, _continued = (
                agent_server.load_provider_history_with_cursor(sess, None, None)
            )
        cursor["timeline_seq"] = 0
        cursor["checkpoint_seq"] = 0
        checkpoint = agent_server.history_sync_checkpoint(
            None,
            cursor,
            caught_up=True,
        )
        raw_events = [
            {
                "seq": 1,
                "session_id": sess["id"],
                "type": "history_imported",
                "run_id": "import_raw",
                "_history_sync_checkpoint": checkpoint,
            },
            {
                "seq": 2,
                "session_id": sess["id"],
                "type": "turn_started",
                "run_id": "import_raw",
                "imported": True,
                "prompt": "committed",
            },
            {
                "seq": 3,
                "session_id": sess["id"],
                "type": "turn_finished",
                "run_id": "import_raw",
                "imported": True,
            },
        ]
        event_path.write_text(
            "".join(json.dumps(event) + "\n" for event in raw_events),
            encoding="utf-8",
        )
        self.assertNotIn(
            "_history_sync_checkpoint",
            agent_server.client_safe_event(raw_events[0]),
        )
        with patch.object(
            agent_server, "events_path", return_value=event_path
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ):
            recovered = agent_server.committed_history_sync_checkpoint(sess, None)

        self.assertIsNotNone(recovered)
        recovered_cursor, terminal_seq = recovered
        self.assertEqual(terminal_seq, 3)
        self.assertEqual(recovered_cursor["timeline_seq"], 3)
        self.assertEqual(recovered_cursor["checkpoint_seq"], 3)

    def test_no_cursor_checkpoint_search_fails_closed_when_scan_is_truncated(self) -> None:
        sess = {
            "id": "truncated-checkpoints",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "truncated-checkpoint-thread",
        }
        events = [
            {"seq": index, "type": "assistant_text", "text": f"old-{index}"}
            for index in range(1, 5)
        ]
        with patch.object(
            agent_server,
            "MAX_LOCAL_TRANSCRIPT_SCAN_LINES",
            3,
        ), patch.object(agent_server, "read_events", return_value=events):
            with self.assertRaisesRegex(ValueError, "checkpoint search exceeded"):
                agent_server.committed_history_sync_checkpoint(sess, None)

    def test_cursor_checkpoint_is_recovered_before_later_scan_overflow(self) -> None:
        transcript = Path(self.tempdir.name) / "late-overflow-provider.jsonl"
        transcript.write_text(
            provider_line(agent_server.BACKEND_CODEX, "user", "before"),
            encoding="utf-8",
        )
        sess = {
            "id": "late-overflow",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "late-overflow-thread",
        }
        with patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ):
            _path, _items, previous, _continued = (
                agent_server.load_provider_history_with_cursor(sess, None, None)
            )
            previous["timeline_seq"] = 10
            previous["checkpoint_seq"] = 10
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write(
                    provider_line(agent_server.BACKEND_CODEX, "assistant", "after")
                )
            _path, _items, cursor, _continued = (
                agent_server.load_provider_history_with_cursor(sess, None, previous)
            )
        checkpoint = agent_server.history_sync_checkpoint(
            previous,
            cursor,
            caught_up=True,
        )
        events = [
            {
                "seq": 11,
                "type": "history_imported",
                "run_id": "import_overflow",
                "_history_sync_checkpoint": checkpoint,
            },
            {
                "seq": 12,
                "type": "turn_finished",
                "run_id": "import_overflow",
                "imported": True,
            },
            *[
                {"seq": seq, "type": "assistant_text", "text": f"later-{seq}"}
                for seq in range(13, 26)
            ],
        ]
        with patch.object(
            agent_server, "HISTORY_SYNC_EVENT_SCAN_LIMIT", 2
        ), patch.object(
            agent_server, "normalized_history_import_limit", return_value=2
        ), patch.object(
            agent_server, "read_events", return_value=events
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ):
            recovered = agent_server.committed_history_sync_checkpoint(
                sess,
                previous,
            )

        self.assertIsNotNone(recovered)
        recovered_cursor, terminal_seq = recovered
        self.assertEqual(terminal_seq, 12)
        self.assertEqual(recovered_cursor["source_offset"], transcript.stat().st_size)

    async def test_cursor_save_failure_after_batch_retries_without_duplicate(self) -> None:
        transcript = Path(self.tempdir.name) / "crash.jsonl"
        transcript.write_text(
            provider_line(agent_server.BACKEND_CODEX, "user", "existing"),
            encoding="utf-8",
        )
        sess = {
            "id": "crash",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "crash-thread",
        }
        live = {sess["id"]: dict(sess)}
        events = [self.timeline_event(1, user("existing"))]
        batches: list[list[tuple[str, dict]]] = []
        save = AsyncMock()
        with patch.object(agent_server.STORE, "sessions", live), patch.object(
            agent_server.STORE, "save", save
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ), patch.object(
            agent_server,
            "read_events",
            side_effect=self.fake_read_events(events),
        ), patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ), patch.object(
            agent_server,
            "last_event_seq_from_file",
            side_effect=self.last_seq(events),
        ), patch.object(
            agent_server,
            "append_durable_event_batch",
            side_effect=self.fake_append_events(events, batches),
        ):
            await agent_server.sync_provider_history(dict(sess))
            old_cursor = json.loads(
                json.dumps(live[sess["id"]]["_history_sync_cursor"])
            )
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write(
                    provider_line(agent_server.BACKEND_CODEX, "user", "outside")
                    + provider_line(
                        agent_server.BACKEND_CODEX,
                        "assistant",
                        "outside answer",
                    )
                )
            save.side_effect = OSError("registry unavailable")
            with self.assertRaises(OSError):
                await agent_server.sync_provider_history(dict(sess))
            self.assertEqual(live[sess["id"]]["_history_sync_cursor"], old_cursor)
            save.side_effect = None
            retry = await agent_server.sync_provider_history(dict(sess))
            unchanged = await agent_server.sync_provider_history(dict(sess))

        self.assertEqual(retry["imported"], 0)
        self.assertEqual(unchanged["imported"], 0)
        imported_message_batches = [
            [
                event_type
                for event_type, _payload in batch
                if event_type in {"turn_started", "assistant_text"}
            ]
            for batch in batches
        ]
        self.assertEqual(imported_message_batches, [["turn_started", "assistant_text"]])

    async def test_checkpoint_recovery_is_independent_of_timeline_content_order(self) -> None:
        transcript = Path(self.tempdir.name) / "ordered-crash.jsonl"
        event_path = Path(self.tempdir.name) / "ordered-crash-events.jsonl"
        transcript.write_text("", encoding="utf-8")
        sess = {
            "id": "ordered-crash",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "ordered-crash-thread",
        }
        live = {sess["id"]: dict(sess)}
        events: list[dict] = []
        batches: list[list[tuple[str, dict]]] = []
        save = AsyncMock()
        external_pair = [user("external before"), assistant("external answer")]
        local_pair = [user("local after"), assistant("local answer")]

        async def append_to_real_event_file(_session_id, event_specs):
            committed = []
            next_seq = int(events[-1]["seq"]) + 1 if events else 1
            with event_path.open("a", encoding="utf-8") as stream:
                for event_type, payload in event_specs:
                    event = {
                        "seq": next_seq,
                        "session_id": sess["id"],
                        "type": event_type,
                        **payload,
                    }
                    stream.write(json.dumps(event, separators=(",", ":")) + "\n")
                    events.append(event)
                    committed.append(event)
                    next_seq += 1
            batches.append(list(event_specs))
            return committed

        with patch.object(agent_server.STORE, "sessions", live), patch.object(
            agent_server.STORE, "save", save
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ), patch.object(
            agent_server, "events_path", return_value=event_path
        ), patch.object(
            agent_server,
            "append_durable_event_batch",
            side_effect=append_to_real_event_file,
        ):
            await agent_server.sync_provider_history(dict(sess), limit=2)
            durable_old_session = json.loads(json.dumps(live[sess["id"]]))
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write(
                    "".join(
                        provider_line(
                            agent_server.BACKEND_CODEX,
                            item["kind"],
                            item["text"],
                        )
                        for item in external_pair + local_pair
                    )
                )
            events.extend(
                self.timeline_event(index, item)
                for index, item in enumerate(local_pair, 1)
            )
            event_path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            save.side_effect = OSError("registry unavailable")
            with self.assertRaises(OSError):
                await agent_server.sync_provider_history(dict(sess), limit=2)
            # Simulate restart from the old sessions.json snapshot. The event
            # batch, including its checkpoint, is already authoritative.
            live[sess["id"]] = json.loads(json.dumps(durable_old_session))
            save.side_effect = None
            recovered = await agent_server.sync_provider_history(dict(sess), limit=2)
            drained = await agent_server.sync_provider_history(dict(sess), limit=2)
            unchanged = await agent_server.sync_provider_history(dict(sess), limit=2)

        self.assertEqual(recovered["imported"], 0)
        self.assertIn("Recovered", recovered["message"])
        self.assertEqual(drained["imported"], 0)
        self.assertEqual(unchanged["imported"], 0)
        imported_messages = [
            (
                user(payload["prompt"])
                if event_type == "turn_started"
                else assistant(payload["text"])
            )
            for batch in batches
            for event_type, payload in batch
            if event_type in {"turn_started", "assistant_text"}
        ]
        self.assertEqual(imported_messages, external_pair)
        self.assertEqual(
            live[sess["id"]]["_history_sync_cursor"]["source_offset"],
            transcript.stat().st_size,
        )

    async def test_cancelled_cursor_save_retains_committed_memory_and_retries_cleanly(self) -> None:
        transcript = Path(self.tempdir.name) / "cancel-save.jsonl"
        transcript.write_text(
            provider_line(agent_server.BACKEND_CODEX, "user", "existing"),
            encoding="utf-8",
        )
        sess = {
            "id": "cancel-save",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "cancel-save-thread",
        }
        live = {sess["id"]: dict(sess)}
        events = [self.timeline_event(1, user("existing"))]
        batches: list[list[tuple[str, dict]]] = []
        save = AsyncMock()
        disk: dict = {}
        with patch.object(agent_server.STORE, "sessions", live), patch.object(
            agent_server.STORE, "save", save
        ), patch.object(
            agent_server, "provider_history_path", return_value=transcript
        ), patch.object(
            agent_server,
            "read_events",
            side_effect=self.fake_read_events(events),
        ), patch.object(
            agent_server,
            "history_timeline_message_keys",
            side_effect=fake_history_timeline_scan(events),
        ), patch.object(
            agent_server,
            "last_event_seq_from_file",
            side_effect=self.last_seq(events),
        ), patch.object(
            agent_server,
            "append_durable_event_batch",
            side_effect=self.fake_append_events(events, batches),
        ):
            await agent_server.sync_provider_history(dict(sess))
            with transcript.open("a", encoding="utf-8") as stream:
                stream.write(
                    provider_line(agent_server.BACKEND_CODEX, "assistant", "outside")
                )

            async def commit_then_cancel(*_args, **_kwargs):
                disk.clear()
                disk.update(json.loads(json.dumps(live)))
                raise asyncio.CancelledError

            save.side_effect = commit_then_cancel
            with self.assertRaises(asyncio.CancelledError):
                await agent_server.sync_provider_history(dict(sess))
            committed_cursor = json.loads(
                json.dumps(live[sess["id"]]["_history_sync_cursor"])
            )
            self.assertEqual(
                disk[sess["id"]]["_history_sync_cursor"],
                committed_cursor,
            )
            save.side_effect = None
            retry = await agent_server.sync_provider_history(dict(sess))

        self.assertEqual(retry["imported"], 0)
        self.assertEqual(len(batches), 1)


class ScheduleProviderHistorySyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.previous_scheduled = set(agent_server.HISTORY_SYNC_SCHEDULED)
        self.previous_busy = agent_server.BUSY_SESSIONS
        self.previous_active = agent_server.ACTIVE
        agent_server.HISTORY_SYNC_SCHEDULED.clear()
        agent_server.BUSY_SESSIONS = set()
        agent_server.ACTIVE = {}

    async def asyncTearDown(self) -> None:
        agent_server.HISTORY_SYNC_SCHEDULED.clear()
        agent_server.HISTORY_SYNC_SCHEDULED.update(self.previous_scheduled)
        agent_server.BUSY_SESSIONS = self.previous_busy
        agent_server.ACTIVE = self.previous_active

    def sess(self) -> dict:
        return {
            "id": "chat-open",
            "backend": agent_server.BACKEND_CODEX,
            "codex_thread_id": "thread-1",
        }

    async def test_repeated_opens_do_not_start_overlapping_syncs(self) -> None:
        started = 0

        async def fake_run(session_id):
            nonlocal started
            started += 1
            await asyncio.sleep(0)

        with patch.object(agent_server, "run_provider_history_sync", fake_run):
            for _ in range(5):
                agent_server.schedule_provider_history_sync(self.sess())
            await asyncio.sleep(0)

        self.assertEqual(started, 1)

    async def test_busy_session_is_left_alone(self) -> None:
        # A live turn is already streaming provider output and still writing
        # its transcript.
        agent_server.BUSY_SESSIONS = {"chat-open"}
        started = False

        async def fake_run(session_id):
            nonlocal started
            started = True

        with patch.object(agent_server, "run_provider_history_sync", fake_run):
            agent_server.schedule_provider_history_sync(self.sess())
            await asyncio.sleep(0)

        self.assertFalse(started)

    async def test_session_without_provider_id_is_not_scheduled(self) -> None:
        started = False

        async def fake_run(session_id):
            nonlocal started
            started = True

        with patch.object(agent_server, "run_provider_history_sync", fake_run):
            agent_server.schedule_provider_history_sync(
                {"id": "chat-open", "backend": agent_server.BACKEND_CODEX}
            )
            await asyncio.sleep(0)

        self.assertFalse(started)

    async def test_a_failing_sync_clears_its_slot_so_a_later_open_retries(
        self,
    ) -> None:
        async def boom(sess, **kwargs):
            raise RuntimeError("transcript unreadable")

        with patch.object(agent_server.STORE, "sessions", {"chat-open": self.sess()}), \
                patch.object(agent_server, "sync_provider_history", boom):
            agent_server.HISTORY_SYNC_SCHEDULED.add("chat-open")
            await agent_server.run_provider_history_sync("chat-open")

        self.assertNotIn("chat-open", agent_server.HISTORY_SYNC_SCHEDULED)


if __name__ == "__main__":
    unittest.main()
