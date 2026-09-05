import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import agent_server


class ArtifactManifestContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_stable_manifest_accepts_paths_and_titled_video_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generated = root / "generated"
            generated.mkdir()
            report = generated / "report.txt"
            report.write_text("ready\n")
            video = generated / "preview.mov"
            video.write_bytes(b"preview-video")
            manifest = root / "manifests" / "current.json"
            manifest.parent.mkdir()
            manifest.write_text(json.dumps({
                "files": [
                    str(report.resolve()),
                    {
                        "path": str(video.resolve()),
                        "title": "Demo",
                        "text": "Optional note",
                    },
                ],
            }))
            with (
                patch.object(agent_server, "STATE_DIR", root / "state"),
                patch.object(agent_server, "FILES_ROOT", root / "published"),
                patch.object(agent_server, "CODE_DIFFS_ROOT", root / "code-diffs"),
                patch.object(
                    agent_server,
                    "CROSS_CHAT_AUTHORITY_ROOT",
                    root / "cross-chat-authority",
                ),
                patch.object(agent_server, "EVENT_SEQ_CACHE", {}),
                patch.object(agent_server.HUB, "broadcast", AsyncMock()),
                patch.dict(
                    agent_server.STORE.sessions,
                    {"sess-artifacts": {"id": "sess-artifacts"}},
                    clear=True,
                ),
            ):
                await agent_server.collect_manifest(
                    "sess-artifacts",
                    "run-artifacts",
                    manifest,
                    final=True,
                )

            self.assertFalse(manifest.exists())
            events_path = root / "state" / "sessions" / "sess-artifacts" / "events.jsonl"
            events = [
                json.loads(line)
                for line in events_path.read_text().splitlines()
                if line.strip()
            ]
            artifact_events = [
                event for event in events if event["type"] == "artifact_created"
            ]
            self.assertEqual(len(artifact_events), 2)
            records = {
                event["artifact"]["filename"]: event["artifact"]
                for event in artifact_events
            }
            self.assertEqual(records["report.txt"]["content_type"], "text/plain")
            self.assertEqual(records["preview.mov"]["content_type"], "video/quicktime")
            self.assertEqual(records["preview.mov"]["title"], "Demo")
            self.assertEqual(records["preview.mov"]["text"], "Optional note")
            self.assertEqual(records["preview.mov"]["source_path"], str(video.resolve()))
            self.assertTrue(Path(records["preview.mov"]["path"]).is_file())


if __name__ == "__main__":
    unittest.main()
