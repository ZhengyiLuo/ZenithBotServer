import json
import tempfile
import threading
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import patch

import agent_server
from fastapi import HTTPException


class FileContentTypeTests(unittest.TestCase):
    def test_generic_upload_type_falls_back_to_filename(self) -> None:
        self.assertEqual(
            agent_server.effective_content_type("screenshot.png", "application/octet-stream"),
            "image/png",
        )
        self.assertEqual(
            agent_server.effective_content_type("clip.mov", "binary/octet-stream; charset=binary"),
            "video/quicktime",
        )
        self.assertEqual(
            agent_server.effective_content_type("notes.txt", "text/plain"),
            "text/plain",
        )

    def test_legacy_file_records_are_normalized_without_rewriting_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file_root = root / "file_legacy"
            file_root.mkdir()
            metadata_path = file_root / "meta.json"
            metadata = {
                "id": "file_legacy",
                "session_id": "session-1",
                "filename": "screenshot.png",
                "path": str(file_root / "screenshot.png"),
                "content_type": "application/octet-stream",
            }
            metadata_path.write_text(json.dumps(metadata))

            with patch.object(agent_server, "FILES_ROOT", root), patch.object(
                agent_server, "iter_session_events", return_value=iter(())
            ):
                records = agent_server.list_session_file_records("session-1")

            self.assertEqual(records[0]["content_type"], "image/png")
            self.assertEqual(json.loads(metadata_path.read_text())["content_type"], "application/octet-stream")

    def test_legacy_event_record_is_normalized_for_file_listing(self) -> None:
        event = {
            "id": "event-1",
            "seq": 10,
            "type": "file_uploaded",
            "file": {
                "id": "file_event",
                "session_id": "session-1",
                "filename": "photo.jpeg",
                "content_type": "application/octet-stream",
            },
        }
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            agent_server, "FILES_ROOT", Path(temporary)
        ), patch.object(agent_server, "iter_session_events", return_value=iter((event,))):
            records = agent_server.list_session_file_records("session-1")

        self.assertEqual(records[0]["content_type"], "image/jpeg")
        self.assertEqual(records[0]["event_id"], "event-1")

    def test_file_listing_rejects_an_explicit_foreign_owner_from_fork_history(self) -> None:
        event = {
            "id": "forked-artifact",
            "seq": 10,
            "session_id": "child-session",
            "type": "artifact_created",
            "forked": True,
            "artifact": {
                "id": "parent-file",
                "session_id": "parent-session",
                "filename": "parent-output.png",
            },
        }
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            agent_server, "FILES_ROOT", Path(temporary)
        ), patch.object(agent_server, "iter_session_events", return_value=iter((event,))):
            records = agent_server.list_session_file_records("child-session")

        self.assertEqual(records, [])

    def test_transcript_read_suppresses_foreign_file_events_but_keeps_legacy_files(self) -> None:
        events = [
            {
                "id": "foreign",
                "seq": 1,
                "session_id": "child-session",
                "type": "artifact_created",
                "artifact": {
                    "id": "parent-file",
                    "session_id": "parent-session",
                    "filename": "parent.png",
                },
            },
            {
                "id": "legacy",
                "seq": 2,
                "session_id": "child-session",
                "type": "artifact_created",
                "artifact": {"id": "legacy-file", "filename": "legacy.png"},
            },
            {
                "id": "forked-legacy",
                "seq": 3,
                "session_id": "child-session",
                "type": "artifact_created",
                "forked": True,
                "original_session_id": "parent-session",
                "artifact": {"id": "parent-legacy-file", "filename": "parent.png"},
            },
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            path.write_text("".join(json.dumps(event) + "\n" for event in events))
            with patch.object(agent_server, "events_path", return_value=path):
                result = agent_server.read_events("child-session")

        self.assertEqual([event["id"] for event in result], ["legacy"])

    def test_file_listing_rejects_ownerless_fork_derived_legacy_record(self) -> None:
        event = {
            "id": "forked-legacy",
            "seq": 10,
            "session_id": "child-session",
            "type": "artifact_created",
            "forked": True,
            "original_session_id": "parent-session",
            "artifact": {
                "id": "parent-file",
                "filename": "parent-output.png",
            },
        }
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            agent_server, "FILES_ROOT", Path(temporary)
        ), patch.object(agent_server, "iter_session_events", return_value=iter((event,))):
            records = agent_server.list_session_file_records("child-session")

        self.assertEqual(records, [])


class FileContentTypeEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_file_resolutions_run_off_the_event_loop(self) -> None:
        main_thread = threading.get_ident()
        event = {"id": "event-1", "seq": 1, "type": "file_uploaded"}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "notes.txt"
            path.write_text("content")
            meta = {
                "id": "file-1",
                "session_id": "session-1",
                "filename": path.name,
                "path": str(path),
                "content_type": "text/plain",
            }

            def off_loop(value):
                self.assertNotEqual(threading.get_ident(), main_thread)
                return value

            with patch.object(
                agent_server.STORE,
                "sessions",
                {"session-1": {"id": "session-1"}},
            ), patch.object(
                agent_server,
                "list_session_file_records",
                side_effect=lambda _session_id: off_loop([meta]),
            ) as list_records, patch.object(
                agent_server,
                "resolve_session_file_event",
                side_effect=lambda _session_id, _file_id: off_loop(event),
            ) as resolve_event, patch.object(
                agent_server,
                "session_file_for_link",
                side_effect=lambda _session_id, _target: off_loop(meta),
            ) as resolve_link:
                listed = await agent_server.list_session_files(
                    "session-1",
                    limit=None,
                    offset=0,
                    content_prefix=None,
                )
                found_event = await agent_server.get_session_file_event(
                    "session-1",
                    "file-1",
                )
                linked = await agent_server.get_session_linked_file(
                    "session-1",
                    str(path),
                )

        self.assertEqual(listed["files"], [meta])
        self.assertEqual(found_event, {"event": event})
        self.assertEqual(linked.path, str(path))
        list_records.assert_called_once_with("session-1")
        resolve_event.assert_called_once_with("session-1", "file-1")
        resolve_link.assert_called_once_with("session-1", str(path))

    async def test_image_filter_includes_legacy_generic_png(self) -> None:
        event = {
            "id": "event-1",
            "seq": 10,
            "type": "file_uploaded",
            "file": {
                "id": "file_event",
                "session_id": "session-1",
                "filename": "photo.png",
                "content_type": "application/octet-stream",
            },
        }
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            agent_server, "FILES_ROOT", Path(temporary)
        ), patch.object(agent_server, "iter_session_events", return_value=iter((event,))), patch.object(
            agent_server.STORE, "sessions", {"session-1": {"id": "session-1"}}
        ):
            response = await agent_server.list_session_files(
                "session-1", limit=None, offset=0, content_prefix="image/"
            )

        self.assertEqual(response["total"], 1)
        self.assertEqual(response["files"][0]["content_type"], "image/png")

    async def test_file_event_lookup_rejects_an_explicit_foreign_owner(self) -> None:
        event = {
            "id": "forked-artifact",
            "seq": 10,
            "session_id": "child-session",
            "type": "artifact_created",
            "artifact": {
                "id": "parent-file",
                "session_id": "parent-session",
                "filename": "parent-output.png",
            },
        }
        with patch.object(
            agent_server, "iter_session_events", return_value=iter((event,))
        ), patch.object(
            agent_server.STORE, "sessions", {"child-session": {"id": "child-session"}}
        ):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.get_session_file_event("child-session", "parent-file")

        self.assertEqual(raised.exception.status_code, 404)


class SessionFileOwnershipTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def write_file(
        root: Path,
        file_id: str,
        *,
        session_id: str | None,
        filename: str = "notes.txt",
    ) -> dict:
        file_root = root / file_id
        file_root.mkdir()
        path = file_root / filename
        path.write_text("session-scoped content")
        record = {
            "id": file_id,
            "kind": "upload",
            "filename": filename,
            "path": str(path),
            "content_type": "text/plain",
        }
        if session_id is not None:
            record["session_id"] = session_id
        (file_root / "meta.json").write_text(json.dumps(record))
        return record

    def test_prompt_attachments_filter_explicit_foreign_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_file(root, "owned", session_id="session-a", filename="owned.txt")
            self.write_file(root, "foreign", session_id="session-b", filename="foreign.txt")
            with patch.object(agent_server, "FILES_ROOT", root):
                lines = agent_server.file_attachment_prompt_lines(
                    "session-a",
                    ["owned", "foreign"],
                )

        self.assertEqual(len(lines), 1)
        self.assertIn("owned.txt", lines[0])
        self.assertNotIn("foreign.txt", lines[0])

    def test_ownerless_legacy_file_requires_origin_event_in_target_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_file(root, "legacy", session_id=None)
            target_events = root / "target.jsonl"
            target_events.write_text(json.dumps({
                "id": "legacy-upload",
                "session_id": "session-a",
                "type": "file_uploaded",
                "file": {"id": "legacy", "filename": "notes.txt"},
            }) + "\n")
            other_events = root / "other.jsonl"
            other_events.write_text("")

            def event_path(session_id: str) -> Path:
                return target_events if session_id == "session-a" else other_events

            with patch.object(agent_server, "FILES_ROOT", root), patch.object(
                agent_server, "events_path", side_effect=event_path
            ):
                self.assertEqual(
                    agent_server.validate_session_file_ids("session-a", ["legacy"]),
                    ["legacy"],
                )
                with self.assertRaises(HTTPException) as raised:
                    agent_server.validate_session_file_ids("session-b", ["legacy"])

        self.assertEqual(raised.exception.status_code, 404)

    def test_turn_reference_alone_does_not_claim_ownerless_legacy_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_file(root, "legacy", session_id=None)
            events = root / "events.jsonl"
            events.write_text(json.dumps({
                "id": "turn",
                "session_id": "session-a",
                "type": "turn_started",
                "file_ids": ["legacy"],
            }) + "\n")
            with patch.object(agent_server, "FILES_ROOT", root), patch.object(
                agent_server, "events_path", return_value=events
            ):
                with self.assertRaises(HTTPException) as raised:
                    agent_server.validate_session_file_ids("session-a", ["legacy"])

        self.assertEqual(raised.exception.status_code, 404)

    def test_forked_origin_event_does_not_claim_ownerless_legacy_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_file(root, "legacy", session_id=None)
            events = root / "events.jsonl"
            events.write_text(json.dumps({
                "id": "forked-artifact",
                "session_id": "session-child",
                "type": "artifact_created",
                "forked": True,
                "original_session_id": "session-parent",
                "artifact": {"id": "legacy", "filename": "notes.txt"},
            }) + "\n")
            with patch.object(agent_server, "FILES_ROOT", root), patch.object(
                agent_server, "events_path", return_value=events
            ):
                with self.assertRaises(HTTPException) as raised:
                    agent_server.validate_session_file_ids("session-child", ["legacy"])

        self.assertEqual(raised.exception.status_code, 404)

    async def test_start_and_queue_reject_foreign_file_ids_before_mutating_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_file(root, "foreign", session_id="session-b")
            sessions = {"session-a": {"id": "session-a", "backend": "codex"}}
            queued: dict[str, deque] = {}
            with patch.object(agent_server, "FILES_ROOT", root), patch.object(
                agent_server.STORE, "sessions", sessions
            ), patch.object(agent_server, "QUEUED_TURNS", queued):
                request = agent_server.TurnRequest(prompt="inspect", file_ids=["foreign"])
                with self.assertRaises(HTTPException) as start_error:
                    await agent_server.start_turn("session-a", request)
                with self.assertRaises(HTTPException) as queue_error:
                    await agent_server.enqueue_turn("session-a", request, sessions["session-a"])

        self.assertEqual(start_error.exception.status_code, 404)
        self.assertEqual(queue_error.exception.status_code, 404)
        self.assertEqual(queued, {})

    async def test_queue_edit_rejects_foreign_file_ids_without_changing_item(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_file(root, "foreign", session_id="session-b")
            item = {"queued_id": "queued-1", "prompt": "keep", "file_ids": []}
            queued = {"session-a": deque([item])}
            with patch.object(agent_server, "FILES_ROOT", root), patch.object(
                agent_server.STORE, "sessions", {"session-a": {"id": "session-a"}}
            ), patch.object(agent_server, "QUEUED_TURNS", queued):
                with self.assertRaises(HTTPException) as raised:
                    await agent_server.update_queued_turn(
                        "session-a",
                        "queued-1",
                        agent_server.UpdateQueuedTurnRequest(file_ids=["foreign"]),
                    )

        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(item["file_ids"], [])

    async def test_download_requires_file_membership_in_path_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = self.write_file(root, "owned", session_id="session-a")
            sessions = {
                "session-a": {"id": "session-a"},
                "session-b": {"id": "session-b"},
            }
            with patch.object(agent_server, "FILES_ROOT", root), patch.object(
                agent_server.STORE, "sessions", sessions
            ):
                response = await agent_server.get_session_file("session-a", "owned")
                self.assertEqual(Path(response.path), Path(record["path"]))
                with self.assertRaises(HTTPException) as scoped_error:
                    await agent_server.get_session_file("session-b", "owned")
                with self.assertRaises(HTTPException) as alias_error:
                    await agent_server.get_file("owned", session_id="session-b")
                compatibility_response = await agent_server.get_file("owned", session_id=None)

        self.assertEqual(scoped_error.exception.status_code, 404)
        self.assertEqual(alias_error.exception.status_code, 404)
        self.assertEqual(Path(compatibility_response.path), Path(record["path"]))


if __name__ == "__main__":
    unittest.main()
