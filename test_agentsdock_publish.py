import asyncio
import contextlib
import hashlib
import io
import json
import tempfile
import threading
import unittest
import urllib.error
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, patch

from starlette.requests import Request

import agent_server
import agentsdock_publish


def request_for(
    host: str = "127.0.0.1",
    *,
    provider_token: str = "provider-secret",
    retry: bool = False,
) -> Request:
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": b"", "more_body": False}

    headers = [
        (b"x-agentsdock-provider-capability", provider_token.encode()),
    ]
    if retry:
        headers.append((b"x-agentsdock-publication-retry", b"1"))
    return Request({
        "type": "http",
        "method": "POST",
        "path": "/api/agent/sessions/sess/artifacts",
        "headers": headers,
        "query_string": b"",
        "scheme": "http",
        "server": ("127.0.0.1", 7850),
        "client": (host, 43210),
    }, receive=receive)


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


class FakeRawResponse(FakeResponse):
    def read(self) -> bytes:
        return bytes(self.payload)


class ArtifactPublisherCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def authority_file(self, chat_id: str) -> str:
        path = Path(self.temporary.name) / f"authority-{len(list(Path(self.temporary.name).iterdir()))}.json"
        path.write_text(json.dumps({
            "provider_capability": "provider-secret",
            "source_session_id": chat_id,
        }))
        path.chmod(0o600)
        return str(path)

    def environment(self, chat_id: str, *, url: str = "http://127.0.0.1:7850") -> dict[str, str]:
        return {
            "AGENTSDOCK_SERVER_URL": url,
            "AGENTSDOCK_CHAT_ID": chat_id,
            "AGENTSDOCK_PROVIDER_AUTHORITY_FILE": self.authority_file(chat_id),
        }

    def test_loopback_hosts_include_ipv4_mapped_ipv6(self) -> None:
        urls = (
            "http://127.0.0.1:7850",
            "http://127.12.34.56:7850",
            "http://[::1]:7850",
            "http://[::ffff:127.0.0.1]:7850",
            "http://localhost:7850",
        )
        for url in urls:
            with self.subTest(url=url), patch.dict(
                "os.environ",
                {
                    "AGENTSDOCK_SERVER_URL": url,
                },
                clear=True,
            ):
                self.assertEqual(agentsdock_publish.loopback_server_url(), url)

        for host in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"):
            with self.subTest(server_host=host):
                self.assertTrue(agent_server.network_host_is_loopback(host))

    def test_remote_server_is_rejected_before_token_is_sent(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "AGENTSDOCK_SERVER_URL": "http://10.0.0.8:7850",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(
                agentsdock_publish.PublishCLIError,
                "non-loopback",
            ):
                agentsdock_publish.loopback_server_url()

    def test_missing_authority_is_rejected(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "AGENTSDOCK_SERVER_URL": "http://127.0.0.1:7850",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(
                agentsdock_publish.PublishCLIError,
                "authority-file is required",
            ):
                agentsdock_publish.provider_authority(None)

    def test_lost_response_retries_same_publication_id_and_checks_receipts(self) -> None:
        files = ["/tmp/demo.mov"]
        payload = {
            "ok": True,
            "chat_id": "sess/demo",
            "publication_id": "pub_retry",
            "run_id": "run_1",
            "receipts": [{
                "artifact_id": "art_123",
                "event_id": "evt_123",
                "event_seq": 42,
                "run_id": "run_1",
            }],
        }
        requests = []

        def urlopen(request, timeout):
            self.assertEqual(timeout, 600)
            requests.append(request)
            if len(requests) == 1:
                raise urllib.error.URLError("response lost")
            return FakeResponse(payload)

        with (
            patch.dict(
                "os.environ",
                {
                    **self.environment("sess/demo"),
                    "HTTP_PROXY": "http://proxy.invalid:8888",
                    "NO_PROXY": "",
                },
                clear=True,
            ),
            patch.object(
                agentsdock_publish.urllib.request,
                "build_opener",
                return_value=type("Opener", (), {"open": staticmethod(urlopen)})(),
            ) as build_opener,
        ):
            result = agentsdock_publish.publish(
                "sess/demo",
                files,
                publication_id="pub_retry",
            )

        self.assertEqual(result, payload)
        self.assertEqual(len(requests), 2)
        bodies = [json.loads(request.data) for request in requests]
        self.assertEqual(bodies[0], bodies[1])
        self.assertEqual(bodies[0]["publication_id"], "pub_retry")
        self.assertIsNone(requests[0].get_header("X-agentsdock-publication-retry"))
        self.assertEqual(requests[1].get_header("X-agentsdock-publication-retry"), "1")
        self.assertIsNone(requests[0].get_header("Authorization"))
        self.assertIsNone(requests[0].get_header("X-agentsdock-publish-token"))
        self.assertEqual(
            requests[0].get_header("X-agentsdock-provider-capability"),
            "provider-secret",
        )
        handlers = build_opener.call_args.args
        self.assertIsInstance(handlers[0], urllib.request.ProxyHandler)
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], agentsdock_publish.NoRedirectHandler)

    def test_invalid_json_response_retries_same_publication(self) -> None:
        payload = {
            "ok": True,
            "chat_id": "sess",
            "publication_id": "pub_json_retry",
            "run_id": "run_json",
            "receipts": [{
                "artifact_id": "art_json",
                "event_id": "evt_json",
                "event_seq": 7,
                "run_id": "run_json",
            }],
        }
        requests = []

        def open_response(request, timeout):
            self.assertEqual(timeout, 600)
            requests.append(request)
            if len(requests) == 1:
                return FakeRawResponse(b"{truncated")
            return FakeResponse(payload)

        with (
            patch.dict(
                "os.environ",
                {
                    **self.environment("sess"),
                    "HTTP_PROXY": "http://proxy.invalid:8888",
                    "NO_PROXY": "",
                },
                clear=True,
            ),
            patch.object(
                agentsdock_publish.urllib.request,
                "build_opener",
                return_value=type("Opener", (), {"open": staticmethod(open_response)})(),
            ),
        ):
            result = agentsdock_publish.publish(
                "sess",
                ["/tmp/demo.mov"],
                publication_id="pub_json_retry",
            )

        self.assertEqual(result, payload)
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[1].get_header("X-agentsdock-publication-retry"), "1")

    def test_incomplete_receipt_exits_nonzero(self) -> None:
        with (
            patch.dict(
                "os.environ",
                self.environment("sess"),
                clear=True,
            ),
            patch.object(
                agentsdock_publish.urllib.request,
                "build_opener",
                return_value=type("Opener", (), {
                    "open": lambda _self, _request, timeout: FakeResponse({
                        "ok": True,
                        "chat_id": "sess",
                        "publication_id": "pub_bad",
                        "run_id": "run_bad",
                        "receipts": [],
                    }),
                })(),
            ),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            exit_code = agentsdock_publish.main([
                "--publication-id",
                "pub_bad",
                "/tmp/file.txt",
            ])
        self.assertEqual(exit_code, 1)
        self.assertIn("incomplete publication receipt", stderr.getvalue())


class ArtifactPublisherServerTests(unittest.IsolatedAsyncioTestCase):
    def runtime_patches(
        self,
        root: Path,
        *,
        session_id: str = "sess",
        run_id: str = "run_active",
        active: bool = True,
    ) -> ExitStack:
        stack = ExitStack()
        stack.enter_context(patch.object(agent_server, "STATE_DIR", root / "state"))
        stack.enter_context(patch.object(agent_server, "FILES_ROOT", root / "files"))
        stack.enter_context(patch.object(
            agent_server,
            "authorize_provider_action",
            AsyncMock(return_value={
                "source_session_id": session_id,
                "source_run_id": run_id,
                "actions": {"publish"},
            }),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "CROSS_CHAT_CAPABILITIES",
            {
                hashlib.sha256(b"provider-secret").hexdigest(): {
                    "source_session_id": session_id,
                    "source_run_id": run_id,
                    "actions": {"publish"},
                }
            },
        ))
        stack.enter_context(patch.object(agent_server, "EVENT_SEQ_CACHE", {}))
        stack.enter_context(patch.object(agent_server, "EVENT_DELIVERY_LOCKS", {}))
        stack.enter_context(patch.object(
            agent_server,
            "ARTIFACT_PUBLICATION_LOCK_STRIPES",
            tuple(asyncio.Lock() for _ in range(64)),
        ))
        stack.enter_context(patch.object(
            agent_server.STORE,
            "sessions",
            {session_id: {"id": session_id, "backend": "codex"}},
        ))
        stack.enter_context(patch.object(
            agent_server,
            "BUSY_SESSIONS",
            {session_id} if active else set(),
        ))
        stack.enter_context(patch.object(
            agent_server,
            "CURRENT_TURNS",
            {session_id: {"run_id": run_id}} if active else {},
        ))
        stack.enter_context(patch.object(
            agent_server,
            "ACTIVE",
            {
                session_id: {
                    "run_id": run_id,
                    "stop_requested": False,
                    "codex_native_operation": False,
                }
            } if active else {},
        ))
        stack.enter_context(patch.object(agent_server, "STOPPED_RUNS", set()))
        stack.enter_context(patch.object(agent_server, "DELETING_SESSIONS", set()))
        stack.enter_context(patch.object(agent_server, "DELETED_SESSION_TOMBSTONES", set()))
        stack.enter_context(patch.object(
            agent_server,
            "RUN_METADATA",
            {
                run_id: {
                    "purpose": "scheduled_job",
                    "job_id": "job_1",
                    "job_title": "Daily render",
                }
            },
        ))
        stack.enter_context(patch.object(
            agent_server,
            "update_session_event_metadata",
            AsyncMock(),
        ))
        stack.enter_context(patch.object(agent_server.HUB, "broadcast", AsyncMock()))
        return stack

    async def test_endpoint_persists_receipt_and_retry_survives_deleted_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "render.mov"
            source.write_bytes(b"video")
            request_model = agent_server.PublishArtifactsRequest(
                publication_id="pub_once",
                files=[{
                    "path": str(source),
                    "title": "Demo",
                    "text": "Rendered result",
                }],
            )
            with self.runtime_patches(root):
                first = await agent_server.publish_agent_artifacts(
                    request_for(),
                    "sess",
                    request_model,
                )
                source.unlink()
                agent_server.BUSY_SESSIONS.clear()
                agent_server.CURRENT_TURNS.clear()
                agent_server.ACTIVE.clear()
                second = await agent_server.publish_agent_artifacts(
                    request_for(retry=True),
                    "sess",
                    request_model,
                )

                event_lines = agent_server.events_path("sess").read_text().splitlines()
                artifact_dirs = list((root / "files").glob("art_*"))

            self.assertEqual(first, second)
            self.assertTrue(first["ok"])
            self.assertEqual(first["publication_id"], "pub_once")
            self.assertEqual(len(first["receipts"]), 1)
            self.assertGreater(first["receipts"][0]["event_seq"], 0)
            self.assertEqual(len(event_lines), 1)
            event = json.loads(event_lines[0])
            self.assertEqual(event["run_id"], "run_active")
            self.assertEqual(event["job_id"], "job_1")
            self.assertEqual(event["artifact"]["title"], "Demo")
            self.assertTrue(Path(event["artifact"]["path"]).is_file())
            self.assertEqual(len(artifact_dirs), 1)

    async def test_retry_recovers_lost_sidecar_after_source_and_turn_are_gone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "render.mp4"
            source.write_bytes(b"video")
            model = agent_server.PublishArtifactsRequest(
                publication_id="pub_tail_recovery",
                files=[str(source)],
            )
            with self.runtime_patches(root):
                first = await agent_server.publish_agent_artifacts(
                    request_for(),
                    "sess",
                    model,
                )
                agent_server.publication_receipt_path(
                    "sess",
                    "pub_tail_recovery",
                ).unlink()
                source.unlink()
                agent_server.BUSY_SESSIONS.clear()
                agent_server.CURRENT_TURNS.clear()
                agent_server.ACTIVE.clear()

                recovered = await agent_server.publish_agent_artifacts(
                    request_for(retry=True),
                    "sess",
                    model,
                )

                self.assertEqual(first, recovered)
                self.assertTrue(agent_server.publication_receipt_path(
                    "sess",
                    "pub_tail_recovery",
                ).is_file())
                self.assertEqual(
                    len(agent_server.events_path("sess").read_text().splitlines()),
                    1,
                )
                self.assertEqual(len(list((root / "files").glob("art_*"))), 1)

    async def test_publication_id_cannot_be_reused_for_changed_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_source = root / "first.txt"
            second_source = root / "second.txt"
            first_source.write_text("first")
            second_source.write_text("second")
            first_model = agent_server.PublishArtifactsRequest(
                publication_id="pub_bound",
                files=[str(first_source)],
            )
            changed_model = agent_server.PublishArtifactsRequest(
                publication_id="pub_bound",
                files=[str(second_source)],
            )
            with self.runtime_patches(root):
                await agent_server.publish_agent_artifacts(
                    request_for(),
                    "sess",
                    first_model,
                )
                with self.assertRaises(agent_server.HTTPException) as conflict:
                    await agent_server.publish_agent_artifacts(
                        request_for(),
                        "sess",
                        changed_model,
                    )

                self.assertEqual(conflict.exception.status_code, 409)
                self.assertIn("another artifact batch", conflict.exception.detail)
                self.assertEqual(
                    len(agent_server.events_path("sess").read_text().splitlines()),
                    1,
                )
                self.assertEqual(len(list((root / "files").glob("art_*"))), 1)

    async def test_endpoint_rejects_remote_wrong_token_and_inactive_chat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "report.txt"
            source.write_text("report")
            model = agent_server.PublishArtifactsRequest(
                publication_id="pub_reject",
                files=[str(source)],
            )
            async def authorize(request, *, action, session_id):
                del action, session_id
                if not agent_server.request_client_is_loopback(request):
                    raise agent_server.HTTPException(status_code=403, detail="loopback required")
                if agent_server.provider_capability_header(request) != "provider-secret":
                    raise agent_server.HTTPException(status_code=403, detail="bad provider capability")
                return {"source_session_id": "sess", "source_run_id": "run_active"}

            with self.runtime_patches(root, active=False), patch.object(
                agent_server,
                "authorize_provider_action",
                side_effect=authorize,
            ):
                with self.assertRaises(agent_server.HTTPException) as remote:
                    await agent_server.publish_agent_artifacts(
                        request_for("10.0.0.8"),
                        "sess",
                        model,
                    )
                self.assertEqual(remote.exception.status_code, 403)

                with self.assertRaises(agent_server.HTTPException) as unauthorized:
                    await agent_server.publish_agent_artifacts(
                        request_for(provider_token="wrong"),
                        "sess",
                        model,
                    )
                self.assertEqual(unauthorized.exception.status_code, 403)

                with self.assertRaises(agent_server.HTTPException) as inactive:
                    await agent_server.publish_agent_artifacts(
                        request_for(),
                        "sess",
                        model,
                    )
                self.assertEqual(inactive.exception.status_code, 409)
                self.assertIn("no active agent turn", inactive.exception.detail)

    async def test_helper_route_bypasses_admin_but_unknown_agent_route_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "secured.txt"
            source.write_text("secured")
            model = agent_server.PublishArtifactsRequest(
                publication_id="pub_middleware",
                files=[str(source)],
            )

            async def dispatch(request):
                try:
                    result = await agent_server.publish_agent_artifacts(
                        request,
                        "sess",
                        model,
                    )
                    return agent_server.JSONResponse(result)
                except agent_server.HTTPException as exc:
                    return agent_server.JSONResponse(
                        {"detail": exc.detail},
                        status_code=exc.status_code,
                    )

            with self.runtime_patches(root), patch.object(
                agent_server,
                "AGENT_TOKEN",
                "api-secret",
            ):
                accepted = await agent_server.require_agent_token(
                    request_for(),
                    dispatch,
                )
                self.assertEqual(accepted.status_code, 200)

                blocked_dispatch = AsyncMock()
                unknown = Request({
                    "type": "http",
                    "method": "POST",
                    "path": "/api/agent/future-unprotected-route",
                    "headers": [],
                    "query_string": b"",
                    "scheme": "http",
                    "server": ("127.0.0.1", 7850),
                    "client": ("127.0.0.1", 43210),
                })
                rejected = await agent_server.require_agent_token(
                    unknown,
                    blocked_dispatch,
                )
                self.assertEqual(rejected.status_code, 401)
                blocked_dispatch.assert_not_awaited()

    async def test_invalid_batch_creates_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "valid.txt"
            source.write_text("valid")
            model = agent_server.PublishArtifactsRequest(
                publication_id="pub_invalid",
                files=[str(source), "relative/missing.txt"],
            )
            with self.runtime_patches(root):
                with self.assertRaises(agent_server.HTTPException) as invalid:
                    await agent_server.publish_agent_artifacts(
                        request_for(),
                        "sess",
                        model,
                    )
                self.assertEqual(invalid.exception.status_code, 422)
                self.assertFalse((root / "files").exists())
                self.assertFalse(agent_server.events_path("sess").exists())

    async def test_copy_runs_off_event_loop_and_postcommit_failures_keep_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "large.bin"
            source.write_bytes(b"payload")
            entries = agent_server.normalize_artifact_entries([str(source)])
            caller_thread = threading.get_ident()
            copy_threads = []
            original_prepare = agent_server.prepare_artifact_records

            def observed_prepare(*args):
                copy_threads.append(threading.get_ident())
                return original_prepare(*args)

            with self.runtime_patches(root):
                with (
                    patch.object(
                        agent_server,
                        "prepare_artifact_records",
                        observed_prepare,
                    ),
                    patch.object(
                        agent_server,
                        "store_publication_events",
                        side_effect=asyncio.CancelledError,
                    ),
                    patch.object(
                        agent_server,
                        "update_session_event_metadata",
                        AsyncMock(side_effect=asyncio.CancelledError),
                    ),
                ):
                    events = await agent_server.publish_artifact_entries(
                        "sess",
                        "run_active",
                        entries,
                        publication_id="pub_postcommit",
                        publication_digest=agent_server.artifact_entries_digest(entries),
                    )

            self.assertEqual(len(events), 1)
            self.assertTrue(copy_threads)
            self.assertNotEqual(copy_threads[0], caller_thread)
            self.assertTrue(Path(events[0]["artifact"]["path"]).is_file())

    async def test_legacy_invalid_batch_is_all_or_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid = root / "valid.txt"
            valid.write_text("valid")
            missing = root / "missing.txt"
            manifest = root / "current.json"
            manifest.write_text(json.dumps({
                "files": [str(valid), str(missing)],
            }))
            with self.runtime_patches(root):
                await agent_server.collect_manifest(
                    "sess",
                    "run_active",
                    manifest,
                    final=True,
                )
                events = [
                    json.loads(line)
                    for line in agent_server.events_path("sess").read_text().splitlines()
                ]
            self.assertFalse(manifest.exists())
            self.assertEqual([event["type"] for event in events], ["artifact_error"])
            self.assertFalse(any((root / "files").glob("art_*")))

    async def test_watcher_cancellation_joins_inflight_publish_then_stops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "ready.txt"
            source.write_text("ready")
            manifest = root / "current.json"
            manifest.write_text(json.dumps({"files": [str(source)]}))
            entered = asyncio.Event()
            release = asyncio.Event()

            async def slow_publish(*_args, **_kwargs):
                entered.set()
                await release.wait()
                return [{"seq": 1, "artifact": {"id": "art_test"}}]

            with (
                patch.object(agent_server, "live_manifest_batch_ready", return_value=True),
                patch.object(agent_server, "publish_artifact_entries", slow_publish),
            ):
                task = asyncio.create_task(agent_server.watch_manifest_artifacts(
                    "sess",
                    "run_active",
                    manifest,
                    set(),
                ))
                await asyncio.wait_for(entered.wait(), timeout=1)
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=1)


if __name__ == "__main__":
    unittest.main()
