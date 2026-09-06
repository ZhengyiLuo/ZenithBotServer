"""Regression tests for event-loop blocking writes and unbounded logs.

Covers the coalesced sessions.json writer, the rotating server log, the
uvicorn access-log poll filter, and the repeated-message filter.
"""

import asyncio
import json
import logging
import os
import tempfile
import threading
import unittest
from contextlib import suppress
from pathlib import Path
from unittest.mock import AsyncMock, patch

import agent_server


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class CoalescedSessionSaveTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self._temp.name) / "state"
        self.sessions_file = self.state_dir / "sessions.json"
        self._patches = [
            patch.object(agent_server, "STATE_DIR", self.state_dir),
            patch.object(agent_server, "SESSIONS_FILE", self.sessions_file),
            patch.object(agent_server, "FILES_ROOT", self.state_dir / "files"),
            patch.object(agent_server, "CODE_DIFFS_ROOT", self.state_dir / "diffs"),
            patch.object(
                agent_server,
                "CROSS_CHAT_AUTHORITY_ROOT",
                self.state_dir / "authority",
            ),
        ]
        for item in self._patches:
            item.start()
        self.addCleanup(self._temp.cleanup)
        for item in reversed(self._patches):
            self.addCleanup(item.stop)

    async def asyncTearDown(self) -> None:
        # Never leave a writer task behind on the test loop.
        for store in getattr(self, "_stores", []):
            await store.flush_pending_save()

    def make_store(self) -> "agent_server.SessionStore":
        store = agent_server.SessionStore()
        self._stores = getattr(self, "_stores", [])
        self._stores.append(store)
        return store

    async def test_many_background_marks_produce_one_write_on_flush(self) -> None:
        store = self.make_store()
        for index in range(200):
            store.sessions[f"sess_{index}"] = {"id": f"sess_{index}", "n": index}
            await store.save(flush=False)
        # Nothing has hit disk yet: marks only schedule the debounced writer.
        self.assertFalse(self.sessions_file.exists())
        self.assertEqual(store.save_write_count, 0)

        await store.save()

        self.assertEqual(store.save_write_count, 1)
        self.assertEqual(json.loads(self.sessions_file.read_text()), store.sessions)

    async def test_background_marks_land_within_debounce_window(self) -> None:
        store = self.make_store()
        store.sessions["a"] = {"id": "a"}
        with (
            patch.object(agent_server, "SESSION_STORE_SAVE_DEBOUNCE_SECONDS", 0.02),
            patch.object(agent_server, "SESSION_STORE_SAVE_MAX_LATENCY_SECONDS", 0.1),
        ):
            await store.save(flush=False)
            store.sessions["b"] = {"id": "b"}
            await store.save(flush=False)
            for _ in range(50):
                if store.save_write_count:
                    break
                await asyncio.sleep(0.01)
        self.assertEqual(store.save_write_count, 1)
        self.assertEqual(
            set(json.loads(self.sessions_file.read_text())),
            {"a", "b"},
        )

    async def test_awaited_save_is_immediate_and_coalesces_concurrent_callers(self) -> None:
        store = self.make_store()
        writes: list[str] = []
        real_write = agent_server.write_sessions_json_text

        def traced_write(path: Path, text: str, *, durable: bool) -> None:
            writes.append(text)
            real_write(path, text, durable=durable)

        with patch.object(agent_server, "write_sessions_json_text", traced_write):
            async def mutate_and_save(index: int) -> None:
                store.sessions[f"s{index}"] = {"id": f"s{index}"}
                await store.save()

            await asyncio.gather(*(mutate_and_save(i) for i in range(25)))

        # At most two writes: one in flight when the burst started, one
        # covering everything marked while it ran.
        self.assertLessEqual(len(writes), 2)
        self.assertEqual(json.loads(writes[-1]), store.sessions)
        self.assertEqual(json.loads(self.sessions_file.read_text()), store.sessions)

    async def test_file_content_is_compact_and_round_trips_through_load(self) -> None:
        store = self.make_store()
        store.sessions = {
            "sess_x": {
                "id": "sess_x",
                "title": "Ünïcode ✓",
                "nested": {"a": [1, 2, {"b": None}], "flag": True},
                "sort_order": 1000,
            }
        }
        await store.save()
        raw = self.sessions_file.read_text(encoding="utf-8")
        self.assertNotIn("\n", raw)
        self.assertEqual(json.loads(raw), store.sessions)

        reloaded = agent_server.SessionStore()
        self._stores.append(reloaded)
        await reloaded.load()
        self.assertEqual(reloaded.sessions["sess_x"]["title"], "Ünïcode ✓")
        self.assertEqual(reloaded.sessions["sess_x"]["nested"], store.sessions["sess_x"]["nested"])

    async def test_unreadable_session_registry_fails_closed_without_replacement(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        original = b'{"chat":'
        self.sessions_file.write_bytes(original)
        store = self.make_store()
        store.sessions = {"in-memory": {"id": "in-memory"}}

        with self.assertRaisesRegex(RuntimeError, "unreadable sessions registry"):
            await store.load()

        self.assertEqual(self.sessions_file.read_bytes(), original)
        self.assertEqual(store.sessions, {"in-memory": {"id": "in-memory"}})

    async def test_unreadable_job_registry_fails_closed_without_replacement(self) -> None:
        jobs_file = self.state_dir / "jobs.json"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        original = b"[]"
        jobs_file.write_bytes(original)
        store = agent_server.JobStore()
        store.jobs = {"in-memory": {"id": "in-memory"}}

        with patch.object(agent_server, "JOBS_FILE", jobs_file):
            with self.assertRaisesRegex(RuntimeError, "unreadable jobs registry"):
                await store.load()

        self.assertEqual(jobs_file.read_bytes(), original)
        self.assertEqual(store.jobs, {"in-memory": {"id": "in-memory"}})

    async def test_durable_save_fsyncs_and_write_errors_propagate(self) -> None:
        store = self.make_store()
        store.sessions = {"a": {"id": "a"}}
        fsyncs: list[int] = []
        real_fsync = agent_server.os.fsync

        def traced_fsync(descriptor: int) -> None:
            fsyncs.append(descriptor)
            real_fsync(descriptor)

        with patch.object(agent_server.os, "fsync", side_effect=traced_fsync):
            await store.save(durable=True)
        self.assertEqual(len(fsyncs), 2)  # file, then directory
        self.assertEqual(json.loads(self.sessions_file.read_text()), store.sessions)

        def failing_write(path: Path, text: str, *, durable: bool) -> None:
            raise OSError("disk full")

        with patch.object(agent_server, "write_sessions_json_text", failing_write):
            with self.assertRaises(OSError):
                await store.save()

    async def test_flush_pending_save_joins_background_write(self) -> None:
        store = self.make_store()
        store.sessions = {"a": {"id": "a"}}
        await store.save(flush=False)
        self.assertFalse(self.sessions_file.exists())
        await store.flush_pending_save()
        self.assertTrue(self.sessions_file.exists())
        self.assertEqual(store.save_write_count, 1)
        self.assertIsNone(store._save_task)

    async def test_cancelled_writer_persists_pending_marks_synchronously(self) -> None:
        store = self.make_store()
        store.sessions = {"a": {"id": "a"}}
        await store.save(flush=False)
        task = store._save_task
        self.assertIsNotNone(task)
        pending = store._pending_save
        self.assertIsNotNone(pending)
        await asyncio.sleep(0)  # let the worker enter its debounce wait
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        self.assertEqual(json.loads(self.sessions_file.read_text()), store.sessions)
        self.assertIsNone(store._save_task)
        # The fallback write succeeded, so a caller awaiting it sees no error.
        self.assertTrue(pending.done.is_set())
        self.assertIsNone(pending.error)

    async def test_event_metadata_update_does_not_block_on_disk(self) -> None:
        store = self.make_store()
        store.sessions = {"chat": {"id": "chat", "backend": "claude"}}
        blocked = asyncio.Event()

        def slow_write(path: Path, text: str, *, durable: bool) -> None:
            blocked.set()
            raise OSError("never reached in this test")

        with (
            patch.object(agent_server, "STORE", store),
            patch.object(agent_server, "write_sessions_json_text", slow_write),
        ):
            event = {
                "seq": 7,
                "type": "assistant_text",
                "ts": "2026-09-04T00:00:00Z",
                "text": "hi",
            }
            await asyncio.wait_for(
                agent_server.update_session_event_metadata("chat", event),
                timeout=0.05,
            )
            self.assertEqual(store.sessions["chat"]["latest_event_seq"], 7)
            self.assertFalse(blocked.is_set())
            # Failures of the coalesced write are logged, never raised into
            # the event path.
            await store.flush_pending_save()
            self.assertTrue(blocked.is_set())


class EventLogRecoveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self._patches = [
            patch.object(agent_server, "EVENT_SEQ_CACHE", {}),
            patch.object(agent_server, "EVENT_SEQ_LOCK", asyncio.Lock()),
            patch.object(agent_server, "EVENT_SEQ_REPAIR_LOCKS", {}),
            patch.object(agent_server, "EVENT_DELIVERY_LOCKS", {}),
            patch.object(agent_server, "ensure_dirs", return_value=None),
            patch.object(
                agent_server,
                "events_path",
                side_effect=lambda session_id: self.root / f"{session_id}.jsonl",
            ),
            patch.object(
                agent_server,
                "update_session_event_metadata",
                new=AsyncMock(),
            ),
            patch.object(agent_server.HUB, "broadcast", new=AsyncMock()),
        ]
        for item in self._patches:
            item.start()
        self.addCleanup(self._temp.cleanup)
        for item in reversed(self._patches):
            self.addCleanup(item.stop)

    @staticmethod
    def write_torn_log(path: Path, *, seq: int = 1) -> None:
        path.write_bytes(
            json.dumps({"seq": seq, "type": "assistant_text"}).encode()
            + b"\n"
            + b'{"seq":'
        )

    def parsed_events(self, path: Path) -> list[dict]:
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    async def test_each_writer_repairs_a_torn_tail_before_appending(self) -> None:
        async def append_single(session_id: str) -> None:
            await agent_server.append_event(session_id, "error", {"message": "x"})

        async def append_import(session_id: str) -> None:
            written = await agent_server.append_imported_events(
                session_id,
                [("assistant_text", {"text": "x", "imported": True})],
            )
            self.assertEqual(written, 1)

        async def append_durable(session_id: str) -> None:
            await agent_server.append_durable_event_batch(
                session_id,
                [("artifact_error", {"message": "x"})],
            )

        for session_id, writer in (
            ("ordinary", append_single),
            ("imported", append_import),
            ("durable", append_durable),
        ):
            with self.subTest(writer=session_id):
                path = self.root / f"{session_id}.jsonl"
                self.write_torn_log(path)
                with patch.dict(
                    agent_server.STORE.sessions,
                    {session_id: {"id": session_id, "latest_event_seq": 1}},
                    clear=True,
                ):
                    await writer(session_id)
                events = self.parsed_events(path)
                self.assertEqual([event["seq"] for event in events], [1, 2])

    async def test_batch_write_failures_repair_tail_and_invalidate_cache(self) -> None:
        for function_name, call in (
            (
                "append_imported_events_sync",
                lambda session_id: agent_server.append_imported_events(
                    session_id,
                    [("assistant_text", {"text": "x", "imported": True})],
                ),
            ),
            (
                "append_durable_event_batch_sync",
                lambda session_id: agent_server.append_durable_event_batch(
                    session_id,
                    [("artifact_error", {"message": "x"})],
                ),
            ),
        ):
            session_id = function_name
            path = self.root / f"{session_id}.jsonl"
            path.write_text(
                json.dumps({"seq": 1, "type": "assistant_text"}) + "\n",
                encoding="utf-8",
            )

            def fail_after_fragment(*_args, **_kwargs):
                with path.open("ab") as stream:
                    stream.write(b'{"seq":2')
                raise OSError("simulated short write")

            with self.subTest(writer=function_name), patch.dict(
                agent_server.STORE.sessions,
                {session_id: {"id": session_id, "latest_event_seq": 1}},
                clear=True,
            ), patch.object(agent_server, function_name, side_effect=fail_after_fragment):
                with self.assertRaises(OSError):
                    await call(session_id)
            self.assertTrue(path.read_bytes().endswith(b"\n"))
            self.assertEqual([event["seq"] for event in self.parsed_events(path)], [1])
            self.assertEqual(agent_server.EVENT_SEQ_CACHE[session_id], 1)

    def test_invalid_json_value_without_newline_is_truncated(self) -> None:
        for suffix in (b"{}", b"[]"):
            with self.subTest(suffix=suffix):
                path = self.root / f"invalid-{len(suffix)}-{suffix[:1].hex()}.jsonl"
                path.write_bytes(
                    json.dumps({"seq": 7, "type": "assistant_text"}).encode()
                    + b"\n"
                    + suffix
                )
                self.assertEqual(agent_server.repair_event_log_tail(path), 7)
                self.assertEqual([event["seq"] for event in self.parsed_events(path)], [7])

    def test_last_event_seq_scans_across_chunks_with_only_one_line_carry(self) -> None:
        path = self.root / "reverse-scan.jsonl"
        path.write_bytes(
            json.dumps({"seq": 7, "type": "assistant_text"}).encode()
            + b"\n"
            + (b"not-json\n" * 40_000)
            + (b"x" * (300 * 1024))
        )

        self.assertEqual(agent_server.last_event_seq_from_file(path), 7)

    async def test_prune_tail_checkpoint_survives_cache_clear(self) -> None:
        session_id = "prune-restart"
        path = self.root / f"{session_id}.jsonl"
        events = [
            {"seq": 1, "type": "turn_started", "run_id": "native", "prompt": "same"},
            {"seq": 2, "type": "history_imported", "run_id": "import_tail", "imported": True},
            {"seq": 3, "type": "turn_started", "run_id": "import_tail", "prompt": "same", "imported": True},
            {"seq": 4, "type": "turn_finished", "run_id": "import_tail", "imported": True},
        ]
        path.write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )
        summary = agent_server.prune_duplicate_imported_history_sync(
            session_id,
            dry_run=False,
        )
        self.assertEqual(summary["removed_events"], 3)
        remaining = self.parsed_events(path)
        self.assertEqual(remaining[-1]["type"], "_event_sequence_checkpoint")
        self.assertEqual(remaining[-1]["seq"], 4)
        self.assertFalse(agent_server.is_client_visible_event(remaining[-1]))

        agent_server.EVENT_SEQ_CACHE.clear()  # simulate a fresh process
        with patch.dict(
            agent_server.STORE.sessions,
            {session_id: {"id": session_id, "latest_event_seq": 1}},
            clear=True,
        ):
            self.assertEqual(await agent_server.next_event_seq(session_id, path), 5)

    async def test_cancelled_prune_cannot_overwrite_concurrent_append(self) -> None:
        session_id = "cancelled-prune"
        path = self.root / f"{session_id}.jsonl"
        events = [
            {
                "seq": 1,
                "type": "turn_started",
                "run_id": "native",
                "prompt": "same question",
            },
            {
                "seq": 2,
                "type": "assistant_text",
                "run_id": "native",
                "text": "same answer",
            },
            {
                "seq": 3,
                "type": "history_imported",
                "run_id": "import_tail",
                "imported": True,
            },
            {
                "seq": 4,
                "type": "turn_started",
                "run_id": "import_tail",
                "prompt": "same question",
                "imported": True,
            },
            {
                "seq": 5,
                "type": "assistant_text",
                "run_id": "import_tail",
                "text": "same answer",
                "imported": True,
            },
            {
                "seq": 6,
                "type": "turn_finished",
                "run_id": "import_tail",
                "imported": True,
            },
        ]
        path.write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )
        store = agent_server.SessionStore()
        store.sessions = {
            session_id: {
                "id": session_id,
                "latest_event_seq": 6,
            },
        }
        replace_started = threading.Event()
        release_replace = threading.Event()
        real_replace = agent_server.os.replace

        def blocked_prune_replace(source, destination):
            if str(source).endswith(".prune-tmp"):
                replace_started.set()
                self.assertTrue(release_replace.wait(timeout=2))
            return real_replace(source, destination)

        with (
            patch.object(agent_server, "STORE", store),
            patch.object(
                agent_server,
                "SESSIONS_FILE",
                self.root / "sessions.json",
            ),
            patch.object(agent_server, "SESSION_LIFECYCLE_LOCKS", {}),
            patch.object(agent_server, "ACTIVE_LOCK", asyncio.Lock()),
            patch.object(agent_server, "ACTIVE", {}),
            patch.object(agent_server, "BUSY_SESSIONS", set()),
            patch.object(agent_server, "SERVER_MAINTENANCE_SESSIONS", set()),
            patch.object(agent_server, "SESSION_TURN_TASKS", {}),
            patch.object(
                agent_server.os,
                "replace",
                side_effect=blocked_prune_replace,
            ),
        ):
            prune_task = asyncio.create_task(
                agent_server.prune_imported_history(
                    session_id,
                    agent_server.PruneImportedHistoryRequest(dry_run=False),
                )
            )
            append_task: asyncio.Task[dict] | None = None
            try:
                self.assertTrue(
                    await asyncio.to_thread(replace_started.wait, 1)
                )
                prune_task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(prune_task.done())
                prune_task.cancel()
                append_task = asyncio.create_task(agent_server.append_event(
                    session_id,
                    "assistant_text",
                    {"text": "new answer"},
                ))
                await asyncio.sleep(0)
                self.assertFalse(append_task.done())
            finally:
                release_replace.set()
            with self.assertRaises(asyncio.CancelledError):
                await prune_task
            self.assertIsNotNone(append_task)
            appended = await asyncio.wait_for(append_task, timeout=1)
            await store.flush_pending_save()

        self.assertEqual(appended["seq"], 7)
        remaining = self.parsed_events(path)
        self.assertEqual([event["seq"] for event in remaining], [1, 2, 6, 7])
        self.assertEqual(remaining[-1]["text"], "new answer")

    async def test_durable_session_sequence_is_a_restart_floor(self) -> None:
        session_id = "registry-floor"
        path = self.root / f"{session_id}.jsonl"
        path.write_text(
            json.dumps({"seq": 2, "type": "assistant_text"}) + "\n",
            encoding="utf-8",
        )
        with patch.dict(
            agent_server.STORE.sessions,
            {session_id: {"id": session_id, "latest_event_seq": 9}},
            clear=True,
        ):
            self.assertEqual(await agent_server.next_event_seq(session_id, path), 10)

    async def test_cancelled_tail_repairs_settle_before_releasing_ownership(self) -> None:
        for operation in ("cold-seed", "failed-write"):
            with self.subTest(operation=operation):
                session_id = f"cancelled-repair-{operation}"
                path = self.root / f"{session_id}.jsonl"
                started = threading.Event()
                release = threading.Event()

                def slow_repair(_path: Path) -> int:
                    started.set()
                    self.assertTrue(release.wait(timeout=2))
                    return 7

                with patch.object(
                    agent_server,
                    "repair_event_log_tail",
                    side_effect=slow_repair,
                ), patch.dict(
                    agent_server.STORE.sessions,
                    {session_id: {"id": session_id, "latest_event_seq": 3}},
                    clear=True,
                ):
                    if operation == "cold-seed":
                        task = asyncio.create_task(
                            agent_server.next_event_seq(session_id, path)
                        )
                    else:
                        task = asyncio.create_task(
                            agent_server.reconcile_event_seq_after_failed_write(
                                session_id,
                                path,
                                consumed_high_water=5,
                            )
                        )
                    self.assertTrue(await asyncio.to_thread(started.wait, 1))
                    task.cancel()
                    await asyncio.sleep(0)
                    self.assertFalse(task.done())
                    release.set()
                    with self.assertRaises(asyncio.CancelledError):
                        await task

                if operation == "failed-write":
                    self.assertEqual(agent_server.EVENT_SEQ_CACHE[session_id], 7)

    async def test_stalled_tail_repair_does_not_block_other_sessions(self) -> None:
        stalled_session = "stalled-repair"
        healthy_session = "healthy-repair"
        stalled_path = self.root / f"{stalled_session}.jsonl"
        healthy_path = self.root / f"{healthy_session}.jsonl"
        repair_started = threading.Event()
        release_repair = threading.Event()

        def repair(path: Path) -> int:
            if path == stalled_path:
                repair_started.set()
                self.assertTrue(release_repair.wait(timeout=2))
                return 7
            self.assertEqual(path, healthy_path)
            return 4

        with patch.object(
            agent_server,
            "repair_event_log_tail",
            side_effect=repair,
        ), patch.dict(
            agent_server.STORE.sessions,
            {
                stalled_session: {"latest_event_seq": 0},
                healthy_session: {"latest_event_seq": 0},
            },
            clear=True,
        ):
            stalled = asyncio.create_task(
                agent_server.next_event_seq(stalled_session, stalled_path)
            )
            self.assertTrue(await asyncio.to_thread(repair_started.wait, 1))

            healthy_seq = await asyncio.wait_for(
                agent_server.next_event_seq(healthy_session, healthy_path),
                timeout=0.2,
            )
            self.assertEqual(healthy_seq, 5)
            self.assertFalse(stalled.done())

            release_repair.set()
            self.assertEqual(await asyncio.wait_for(stalled, timeout=1), 8)


class StableServerIdentityTests(unittest.TestCase):
    def test_first_legacy_identity_is_persisted_across_machine_name_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "server-identity"
            cache: dict[str, str] = {}
            first = "a" * 24
            changed_machine_result = "b" * 24
            with patch.object(agent_server, "SERVER_IDENTITY_FILE", path), \
                 patch.object(agent_server, "SERVER_IDENTITY_CACHE", cache), \
                 patch.object(
                     agent_server,
                     "legacy_server_identity",
                     return_value=first,
                 ) as legacy:
                self.assertEqual(agent_server.server_identity(), first)
                legacy.assert_called_once()

            cache.clear()  # simulate a process restart after hostname change
            with patch.object(agent_server, "SERVER_IDENTITY_FILE", path), \
                 patch.object(agent_server, "SERVER_IDENTITY_CACHE", cache), \
                 patch.object(
                     agent_server,
                     "legacy_server_identity",
                     return_value=changed_machine_result,
                 ) as legacy:
                self.assertEqual(agent_server.server_identity(), first)
                legacy.assert_not_called()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_corrupt_persisted_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "server-identity"
            path.write_text("not-a-valid-identity\n", encoding="ascii")
            with patch.object(agent_server, "SERVER_IDENTITY_FILE", path), \
                 patch.object(agent_server, "SERVER_IDENTITY_CACHE", {}), \
                 patch.object(agent_server, "legacy_server_identity") as legacy:
                with self.assertRaisesRegex(RuntimeError, "identity is invalid"):
                    agent_server.server_identity()
                legacy.assert_not_called()

    def test_persisted_identity_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "elsewhere"
            target.write_text("a" * 24 + "\n", encoding="ascii")
            path = root / "server-identity"
            path.symlink_to(target)
            with patch.object(agent_server, "SERVER_IDENTITY_FILE", path), \
                 patch.object(agent_server, "SERVER_IDENTITY_CACHE", {}):
                with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                    agent_server.server_identity()

    def test_persisted_identity_rejects_non_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "server-identity"
            path.mkdir()
            with patch.object(agent_server, "SERVER_IDENTITY_FILE", path), \
                 patch.object(agent_server, "SERVER_IDENTITY_CACHE", {}):
                with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                    agent_server.server_identity()

    @unittest.skipIf(os.name == "nt", "POSIX file modes are not available")
    def test_existing_identity_is_restricted_to_private_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "server-identity"
            path.write_text("a" * 24 + "\n", encoding="ascii")
            path.chmod(0o400)

            self.assertEqual(agent_server.read_server_identity_file(path), "a" * 24)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_concurrent_first_writers_do_not_replace_the_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "server-identity"
            barrier = threading.Barrier(2)
            results: list[tuple[str, bool]] = []

            def write(candidate: str) -> None:
                barrier.wait()
                results.append((
                    candidate,
                    agent_server.write_server_identity_file(path, candidate),
                ))

            threads = [
                threading.Thread(target=write, args=("a" * 24,)),
                threading.Thread(target=write, args=("b" * 24,)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)

            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(sorted(created for _value, created in results), [False, True])
            winner = next(value for value, created in results if created)
            self.assertEqual(agent_server.read_server_identity_file(path), winner)


class PollingAccessLogFilterTests(unittest.TestCase):
    def record(self, method: str, path: str, status: int, *, args: bool = True) -> logging.LogRecord:
        if args:
            return logging.LogRecord(
                "uvicorn.access",
                logging.INFO,
                __file__,
                1,
                '%s - "%s %s HTTP/%s" %d',
                ("127.0.0.1:1234", method, path, "1.1", status),
                None,
            )
        return logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            1,
            f'127.0.0.1:1234 - "{method} {path} HTTP/1.1" {status}',
            None,
            None,
        )

    def test_drops_successful_polls_and_keeps_everything_else(self) -> None:
        log_filter = agent_server.PollingAccessLogFilter()
        dropped = [
            ("GET", "/api/health", 200),
            ("GET", "/api/jobs", 200),
            ("GET", "/api/sessions?summary=true", 200),
            ("GET", "/api/sessions?summary=true&limit=50", 200),
            ("GET", "/api/sessions/sess_abc/codex/runtime", 200),
            ("GET", "/api/sessions/sess_abc/claude/runtime", 200),
            (
                "GET",
                "/api/team-hub-secure/0f7f4c8e-1111-2222-3333-444444444444/v1/teams/team-1/network/mailbox",
                200,
            ),
            (
                "GET",
                "/api/team-hub-secure/conn/v1/teams/team-1/network/mailbox?after=5",
                200,
            ),
        ]
        for method, path, status in dropped:
            with self.subTest(path=path):
                self.assertFalse(log_filter.filter(self.record(method, path, status)))
                self.assertFalse(
                    log_filter.filter(self.record(method, path, status, args=False))
                )
        kept = [
            ("GET", "/api/health", 500),
            ("GET", "/api/health", 401),
            ("GET", "/api/jobs", 503),
            ("POST", "/api/health", 200),
            ("GET", "/api/sessions", 200),
            ("GET", "/api/sessions?summary=false", 200),
            ("GET", "/api/sessions/sess_abc", 200),
            ("GET", "/api/sessions/sess_abc/events", 200),
            ("POST", "/api/sessions/sess_abc/codex/runtime", 200),
            ("GET", "/api/team-hub-secure/conn/v1/teams/team-1/network/messages", 200),
            ("POST", "/api/team-hub-secure/conn/v1/teams/team-1/network/mailbox", 200),
        ]
        for method, path, status in kept:
            with self.subTest(path=path, status=status):
                self.assertTrue(log_filter.filter(self.record(method, path, status)))
                self.assertTrue(
                    log_filter.filter(self.record(method, path, status, args=False))
                )

    def test_unrelated_records_pass_through(self) -> None:
        log_filter = agent_server.PollingAccessLogFilter()
        record = logging.LogRecord(
            "uvicorn.access", logging.INFO, __file__, 1, "startup complete", None, None
        )
        self.assertTrue(log_filter.filter(record))

    def test_redacts_websocket_query_tokens_before_logging(self) -> None:
        log_filter = agent_server.PollingAccessLogFilter()
        secret = "admin-secret-that-must-not-reach-disk"
        paths = [
            f"/api/sessions/chat/events?after=5&token={secret}&visible=true",
            f"/api/sessions/chat/events?after=5&%74o%6Ben={secret}&visible=true",
        ]
        websocket_formats = [
            ('%s - "WebSocket %s" [accepted]', ("127.0.0.1:1234",)),
            ('%s - "WebSocket %s" 403', ("127.0.0.1:1234",)),
            ('%s - "WebSocket %s" %d', ("127.0.0.1:1234", 4401)),
        ]
        for path in paths:
            for message, surrounding_args in websocket_formats:
                with self.subTest(path=path, message=message):
                    args = (
                        surrounding_args[0],
                        path,
                        *surrounding_args[1:],
                    )
                    record = logging.LogRecord(
                        "uvicorn.error",
                        logging.INFO,
                        __file__,
                        1,
                        message,
                        args,
                        None,
                    )
                    self.assertTrue(log_filter.filter(record))
                    rendered = record.getMessage()
                    self.assertNotIn(secret, rendered)
                    self.assertIn("<redacted>", rendered)
                    self.assertIn("visible=true", rendered)

        path = f"/api/sessions/chat/events?after=5&token={secret}&visible=true"
        for uses_args in (True, False):
            with self.subTest(args=uses_args):
                record = self.record("GET", path, 101, args=uses_args)
                self.assertTrue(log_filter.filter(record))
                rendered = record.getMessage()
                self.assertNotIn(secret, rendered)
                self.assertIn("token=<redacted>", rendered)
                self.assertIn("visible=true", rendered)


class RepeatedMessageFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = [1000.0]
        self.logger = logging.getLogger(f"test-repeat-{id(self)}")
        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)
        self.handler = _ListHandler()
        self.logger.addHandler(self.handler)
        self.filter = agent_server.RepeatedMessageFilter(60.0, clock=lambda: self.clock[0])
        self.logger.addFilter(self.filter)
        self.addCleanup(self.logger.removeHandler, self.handler)
        self.addCleanup(self.logger.removeFilter, self.filter)

    def messages(self) -> list[str]:
        return [record.getMessage() for record in self.handler.records]

    def test_identical_warnings_are_suppressed_then_summarized(self) -> None:
        for _ in range(5):
            self.logger.warning("codex app-server unavailable: %s", "connection refused")
            self.clock[0] += 1.0
        self.assertEqual(
            self.messages(),
            ["codex app-server unavailable: connection refused"],
        )

        self.logger.error("claude runtime probe failed")
        self.assertEqual(
            self.messages(),
            [
                "codex app-server unavailable: connection refused",
                "codex app-server unavailable: connection refused (suppressed 4 repeats)",
                "claude runtime probe failed",
            ],
        )
        self.assertEqual(self.handler.records[1].levelno, logging.WARNING)
        self.assertEqual(self.handler.records[2].levelno, logging.ERROR)

    def test_same_message_after_window_emits_again_with_summary(self) -> None:
        self.logger.warning("stuck")
        self.logger.warning("stuck")
        self.clock[0] += 61.0
        self.logger.warning("stuck")
        self.assertEqual(
            self.messages(),
            ["stuck", "stuck (suppressed 1 repeats)", "stuck"],
        )

    def test_info_and_distinct_messages_are_never_suppressed(self) -> None:
        for index in range(3):
            self.logger.info("poll %d", index)
            self.logger.info("poll %d", index)
        self.logger.warning("a")
        self.logger.warning("b")
        self.logger.warning("a")
        self.assertEqual(len(self.handler.records), 9)
        self.assertEqual(self.messages()[-3:], ["a", "b", "a"])

    def test_different_levels_with_same_text_are_distinct(self) -> None:
        self.logger.warning("same text")
        self.logger.error("same text")
        self.assertEqual(self.messages(), ["same text", "same text"])


class ConfigureServerLoggingTests(unittest.TestCase):
    def test_installs_rotating_file_and_filters_with_env_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir) / "state"
            root = logging.getLogger(f"test-root-{id(self)}")
            root.propagate = False
            access = logging.getLogger(f"test-access-{id(self)}")
            access.propagate = False
            error = logging.getLogger(f"test-error-{id(self)}")
            error.propagate = False
            server = logging.getLogger(f"test-server-{id(self)}")
            server.propagate = False
            with patch.dict(
                os.environ,
                {"AGENTSDOCK_LOG_MAX_BYTES": "65536", "AGENTSDOCK_LOG_BACKUPS": "2"},
            ):
                installed = agent_server.configure_server_logging(
                    state_dir,
                    root_logger=root,
                    access_logger=access,
                    error_logger=error,
                    server_logger=server,
                )
            try:
                self.assertIsNotNone(installed.file_handler)
                assert installed.file_handler is not None
                self.assertEqual(installed.file_handler.maxBytes, 65536)
                self.assertEqual(installed.file_handler.backupCount, 2)
                self.assertEqual(
                    Path(installed.file_handler.baseFilename),
                    state_dir / "logs" / "agents-server.log",
                )
                self.assertIn(installed.access_filter, access.filters)
                self.assertIn(installed.access_filter, error.filters)
                self.assertIn(installed.repeat_filter, server.filters)
                self.assertEqual(len(root.handlers), 2)
                self.assertIsInstance(installed.stream_handler, logging.StreamHandler)

                with patch.object(installed.stream_handler, "emit"):
                    root.warning("rotating file receives this line")
                installed.file_handler.flush()
                text = (state_dir / "logs" / "agents-server.log").read_text()
                self.assertIn("[WARNING]", text)
                self.assertIn("rotating file receives this line", text)
            finally:
                for handler in list(root.handlers):
                    root.removeHandler(handler)
                    handler.close()
                access.removeFilter(installed.access_filter)
                error.removeFilter(installed.access_filter)
                server.removeFilter(installed.repeat_filter)

    def test_rotation_settings_fall_back_on_invalid_values(self) -> None:
        with patch.dict(
            os.environ,
            {"AGENTSDOCK_LOG_MAX_BYTES": "not-a-number", "AGENTSDOCK_LOG_BACKUPS": "-4"},
        ):
            max_bytes, backups = agent_server.server_log_rotation_settings()
        self.assertEqual(max_bytes, agent_server.SERVER_LOG_DEFAULT_MAX_BYTES)
        self.assertEqual(backups, 0)

    def test_main_routes_uvicorn_logging_through_root_handlers(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(app: object, **kwargs: object) -> None:
            captured.update(kwargs)

        with (
            patch.object(agent_server, "configure_server_logging") as configure,
            patch.object(agent_server.uvicorn, "run", fake_run),
            patch.object(agent_server.sys, "argv", ["agent_server.py"]),
        ):
            self.assertEqual(agent_server.main(), 0)
        configure.assert_called_once_with(agent_server.STATE_DIR)
        self.assertIn("log_config", captured)
        self.assertIsNone(captured["log_config"])


class EventCacheInvalidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_forget_preserves_a_currently_owned_delivery_lock(self) -> None:
        session_id = "deleting-chat"
        agent_server.EVENT_DELIVERY_LOCKS.pop(session_id, None)
        lock = agent_server.event_delivery_lock(session_id)
        try:
            async with lock:
                await agent_server.forget_event_seq(session_id)
                self.assertIs(agent_server.event_delivery_lock(session_id), lock)
        finally:
            agent_server.EVENT_DELIVERY_LOCKS.pop(session_id, None)

    async def test_forget_waits_for_timeline_scan_off_event_loop(self) -> None:
        session_id = "timeline-scan-chat"
        stripe = threading.Lock()
        stripe.acquire()
        release = threading.Event()

        def release_or_timeout() -> None:
            release.wait(0.3)
            stripe.release()

        holder = threading.Thread(target=release_or_timeout)
        holder.start()
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            with patch.object(
                agent_server,
                "timeline_index_session_lock",
                return_value=stripe,
            ):
                invalidation = asyncio.create_task(
                    agent_server.forget_event_seq(session_id)
                )
                await asyncio.sleep(0.02)
                heartbeat_elapsed = loop.time() - started
                release.set()
                await asyncio.wait_for(invalidation, timeout=1)
        finally:
            release.set()
            holder.join(timeout=1)

        self.assertLess(heartbeat_elapsed, 0.1)


def _write_events(path: Path, count: int, *, session_id: str = "chat", pad: int = 0) -> None:
    with path.open("w", encoding="utf-8") as output:
        for seq in range(1, count + 1):
            event_type = "raw_event" if seq % 5 == 0 else "assistant_text"
            output.write(json.dumps({
                "seq": seq,
                "id": f"event-{seq}",
                "session_id": session_id,
                "type": event_type,
                "ts": "2026-09-04T00:00:00Z",
                "text": f"event {seq} " + ("x" * pad),
            }, separators=(",", ":")) + "\n")


def _full_scan(session_id: str, **kwargs: object) -> tuple[list[dict[str, object]], int, bool]:
    with patch.object(agent_server, "event_index_resume_offset", return_value=0):
        return agent_server.read_event_catchup_batch(session_id, **kwargs)  # type: ignore[arg-type]


class EventCatchupIndexTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.path = Path(self._temp.name) / "events.jsonl"
        self.index_path = agent_server.events_index_path(self.path)
        self.assertEqual(self.index_path.name, "events.idx")

    def line_offset(self, seq: int) -> int:
        offset = 0
        with self.path.open("rb") as source:
            for raw_line in source:
                if json.loads(raw_line)["seq"] == seq:
                    return offset
                offset += len(raw_line)
        raise AssertionError(f"seq {seq} not found")

    def test_resume_uses_indexed_offset_and_matches_full_scan(self) -> None:
        _write_events(self.path, 3000, pad=120)
        self.assertGreater(self.path.stat().st_size, agent_server.EVENT_INDEX_MIN_FILE_BYTES)
        self.assertFalse(self.index_path.exists())
        with (
            patch.object(agent_server, "events_path", return_value=self.path),
            patch.object(agent_server, "fork_internal_run_ids", return_value=set()),
        ):
            for after in (0, 1, 511, 512, 513, 1500, 2047, 2048, 2999, 3000):
                with self.subTest(after=after):
                    expected = _full_scan(
                        "chat", after=after, through=3000, limit=5000, visible=True
                    )
                    actual = agent_server.read_event_catchup_batch(
                        "chat", after=after, through=3000, limit=5000, visible=True
                    )
                    self.assertEqual(actual, expected)
            # The first miss rebuilt the index lazily from the transcript.
            self.assertTrue(self.index_path.exists())
            entries = agent_server.read_event_index(self.path)
            self.assertEqual(
                entries,
                [(seq, self.line_offset(seq)) for seq in (512, 1024, 1536, 2048, 2560)],
            )
            self.assertEqual(
                agent_server.event_index_resume_offset(self.path, 1500),
                self.line_offset(1024),
            )
            self.assertEqual(agent_server.event_index_resume_offset(self.path, 511), 0)
            self.assertEqual(agent_server.event_index_resume_offset(self.path, 0), 0)

            # Paging continues from the returned byte offset exactly as before.
            first, offset, exhausted = agent_server.read_event_catchup_batch(
                "chat", after=1500, through=3000, limit=400, visible=True
            )
            self.assertFalse(exhausted)
            rest, _, exhausted = agent_server.read_event_catchup_batch(
                "chat", after=first[-1]["seq"], through=3000, offset=offset, limit=5000, visible=True
            )
            self.assertTrue(exhausted)
            self.assertEqual(
                [event["seq"] for event in first + rest],
                [seq for seq in range(1501, 3001) if seq % 5],
            )

    def test_stale_index_falls_back_without_skipping_events(self) -> None:
        _write_events(self.path, 2000, pad=120)
        with (
            patch.object(agent_server, "events_path", return_value=self.path),
            patch.object(agent_server, "fork_internal_run_ids", return_value=set()),
        ):
            agent_server.rebuild_event_index(self.path)
            self.assertIsNotNone(agent_server.read_event_index(self.path))
            # Rewrite the transcript in place with longer lines: same inode,
            # every checkpoint now points into the middle of some other line.
            _write_events(self.path, 2000, pad=200)
            self.assertEqual(
                agent_server.read_event_catchup_batch(
                    "chat", after=1300, through=2000, limit=5000, visible=True
                ),
                _full_scan("chat", after=1300, through=2000, limit=5000, visible=True),
            )
            # ...and the index was rebuilt against the new content.
            self.assertEqual(
                agent_server.event_index_resume_offset(self.path, 1300),
                self.line_offset(1024),
            )

            # Wrong inode (transcript replaced by a copy) is rejected outright.
            replacement = self.path.with_name("replacement.jsonl")
            replacement.write_bytes(self.path.read_bytes())
            os.replace(replacement, self.path)
            self.assertIsNone(agent_server.read_event_index(self.path))
            self.assertEqual(
                agent_server.read_event_catchup_batch(
                    "chat", after=700, through=2000, limit=5000, visible=True
                ),
                _full_scan("chat", after=700, through=2000, limit=5000, visible=True),
            )

            # Corrupt index bytes are ignored, not raised.
            self.index_path.write_text("{not json", encoding="utf-8")
            self.assertIsNone(agent_server.read_event_index(self.path))
            self.assertEqual(
                agent_server.read_event_catchup_batch(
                    "chat", after=700, through=2000, limit=5000, visible=True
                ),
                _full_scan("chat", after=700, through=2000, limit=5000, visible=True),
            )

    def test_small_transcripts_are_not_indexed(self) -> None:
        _write_events(self.path, 600)
        self.assertLess(self.path.stat().st_size, agent_server.EVENT_INDEX_MIN_FILE_BYTES)
        with (
            patch.object(agent_server, "events_path", return_value=self.path),
            patch.object(agent_server, "fork_internal_run_ids", return_value=set()),
        ):
            events, _, _ = agent_server.read_event_catchup_batch(
                "chat", after=550, through=600, limit=500, visible=True
            )
        self.assertEqual(len(events), 40)
        self.assertFalse(self.index_path.exists())

    async def test_append_event_records_stride_checkpoints(self) -> None:
        session_id = "index-chat"
        agent_server.EVENT_SEQ_CACHE.pop(session_id, None)
        agent_server.EVENT_DELIVERY_LOCKS.pop(session_id, None)
        self.addCleanup(agent_server.EVENT_SEQ_CACHE.pop, session_id, None)
        self.addCleanup(agent_server.EVENT_DELIVERY_LOCKS.pop, session_id, None)
        # Pre-seed 1023 events so the very next append lands on a boundary.
        _write_events(self.path, 1023, session_id=session_id)
        expected_offset = self.path.stat().st_size
        with (
            patch.dict(agent_server.STORE.sessions, {session_id: {"id": session_id}}),
            patch.object(agent_server, "ensure_dirs"),
            patch.object(agent_server, "events_path", return_value=self.path),
            patch.object(agent_server, "update_session_event_metadata", new=AsyncMock()),
            patch.object(agent_server.HUB, "broadcast", new=AsyncMock()),
        ):
            event = await agent_server.append_event(session_id, "assistant_text", {"text": "boundary"})
            self.assertEqual(event["seq"], 1024)
            self.assertEqual(agent_server.read_event_index(self.path), [(1024, expected_offset)])
            await agent_server.append_event(session_id, "assistant_text", {"text": "after"})
            self.assertEqual(agent_server.read_event_index(self.path), [(1024, expected_offset)])
            # The last line is byte-identical to the historical text-mode writer.
            last_line = self.path.read_bytes().splitlines()[-1]
            self.assertEqual(json.loads(last_line)["seq"], 1025)
            self.assertEqual(last_line, json.dumps(json.loads(last_line), separators=(",", ":")).encode())

            with patch.object(agent_server, "fork_internal_run_ids", return_value=set()):
                self.assertEqual(
                    agent_server.read_event_catchup_batch(
                        session_id, after=1024, through=1025, limit=10, visible=True
                    )[0],
                    _full_scan(session_id, after=1024, through=1025, limit=10, visible=True)[0],
                )
                self.assertEqual(
                    agent_server.event_index_resume_offset(self.path, 1024),
                    expected_offset,
                )


if __name__ == "__main__":
    unittest.main()
