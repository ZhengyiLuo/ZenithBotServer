import asyncio
import json
import signal
import time
import unittest
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, patch

from codex_app_server import (
    CodexAppServerClient,
    CodexAppServerDisconnected,
    CodexAppServerManager,
    CodexAppServerProtocolError,
    CodexAppServerRequestError,
    CodexAppServerSubscriptionClosed,
    CodexAppServerTimeout,
)


NO_RESPONSE = object()


class FakeStdin:
    def __init__(self, process: "FakeProcess") -> None:
        self.process = process
        self.buffer = b""

    def write(self, data: bytes) -> None:
        if self.process.returncode is not None:
            raise BrokenPipeError("fake process exited")
        self.buffer += data
        while b"\n" in self.buffer:
            raw, self.buffer = self.buffer.split(b"\n", 1)
            if raw:
                self.process.receive(raw)

    async def drain(self) -> None:
        await asyncio.sleep(0)


class FakeProcess:
    _next_pid = 1000

    def __init__(self) -> None:
        FakeProcess._next_pid += 1
        self.pid = FakeProcess._next_pid
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdin = FakeStdin(self)
        self.returncode: int | None = None
        self.messages: list[dict[str, Any]] = []
        self.responders: dict[str, Callable[[dict[str, Any]], Any]] = {
            "initialize": lambda _: {
                "userAgent": "fake",
                "platformFamily": "unix",
                "platformOs": "macos",
                "codexHome": "/tmp/codex",
            }
        }
        self._exited = asyncio.Event()

    def receive(self, raw: bytes) -> None:
        message = json.loads(raw)
        self.messages.append(message)
        method = message.get("method")
        if message.get("id") is None or method not in self.responders:
            return
        result = self.responders[method](message)
        if result is not NO_RESPONSE:
            self.feed({"id": message["id"], "result": result})

    def feed(self, message: dict[str, Any]) -> None:
        self.stdout.feed_data(
            (json.dumps(message, separators=(",", ":")) + "\n").encode()
        )

    def feed_stderr(self, line: str) -> None:
        self.stderr.feed_data((line + "\n").encode())

    def crash(self, returncode: int = 17) -> None:
        if self.returncode is not None:
            return
        self.returncode = returncode
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._exited.set()

    def terminate(self) -> None:
        self.crash(-15)

    def kill(self) -> None:
        self.crash(-9)

    async def wait(self) -> int:
        await self._exited.wait()
        assert self.returncode is not None
        return self.returncode


class FakeProcessFactory:
    def __init__(self, *processes: FakeProcess) -> None:
        self.processes = list(processes) or [FakeProcess()]
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    @property
    def process(self) -> FakeProcess:
        return self.processes[0]

    async def __call__(self, *args: Any, **kwargs: Any) -> FakeProcess:
        self.calls.append((args, kwargs))
        index = len(self.calls) - 1
        if index >= len(self.processes):
            self.processes.append(FakeProcess())
        return self.processes[index]


async def wait_until(predicate: Callable[[], bool], timeout: float = 1.0) -> None:
    async def poll() -> None:
        while not predicate():
            await asyncio.sleep(0)

    await asyncio.wait_for(poll(), timeout=timeout)


class CodexAppServerClientTests(unittest.IsolatedAsyncioTestCase):
    def make_client(
        self,
        factory: FakeProcessFactory,
        **kwargs: Any,
    ) -> CodexAppServerClient:
        return CodexAppServerClient(
            "codex",
            cwd="/tmp",
            env_factory=lambda: {"PATH": "/usr/bin"},
            process_factory=factory,
            request_timeout=1,
            **kwargs,
        )

    async def test_async_notification_handler_preserves_wire_order(self) -> None:
        factory = FakeProcessFactory()
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)
        first_entered = asyncio.Event()
        release_first = asyncio.Event()
        seen: list[str] = []

        async def handler(notification: dict[str, Any]) -> None:
            method = str(notification.get("method") or "")
            seen.append(f"start:{method}")
            if method == "notification/first":
                first_entered.set()
                await release_first.wait()
            seen.append(f"finish:{method}")

        client.add_notification_handler(handler)
        client._route_notification(
            {
                "method": "notification/first",
                "params": {"threadId": "thread-a"},
            }
        )
        await asyncio.wait_for(first_entered.wait(), timeout=1)
        client._route_notification(
            {
                "method": "notification/other-thread",
                "params": {"threadId": "thread-b"},
            }
        )
        await wait_until(lambda: "finish:notification/other-thread" in seen)
        client._route_notification(
            {
                "method": "notification/second",
                "params": {"threadId": "thread-a"},
            }
        )
        await asyncio.sleep(0)
        self.assertEqual(
            seen,
            [
                "start:notification/first",
                "start:notification/other-thread",
                "finish:notification/other-thread",
            ],
        )

        release_first.set()
        await client.wait_for_notification_handler(handler, "thread-a")
        self.assertEqual(
            seen,
            [
                "start:notification/first",
                "start:notification/other-thread",
                "finish:notification/other-thread",
                "finish:notification/first",
                "start:notification/second",
                "finish:notification/second",
            ],
        )

    async def test_sync_notification_handler_runs_inline(self) -> None:
        client = self.make_client(FakeProcessFactory())
        self.addAsyncCleanup(client.close)
        seen: list[str] = []

        def handler(notification: dict[str, Any]) -> None:
            seen.append(str(notification.get("method") or ""))

        client.add_notification_handler(handler)
        client._route_notification({
            "method": "item/started",
            "params": {"threadId": "thread", "item": {"id": "approval"}},
        })
        self.assertEqual(seen, ["item/started"])

    async def test_unmatched_notification_is_recorded_not_silently_dropped(self) -> None:
        # No subscription exists for "thread-nobody-listens" - previously
        # this notification just vanished with zero trace, which is what
        # made a stalled turn look like it hung for no reason.
        client = self.make_client(FakeProcessFactory())
        self.addAsyncCleanup(client.close)

        client._route_notification({
            "method": "item/completed",
            "params": {"threadId": "thread-nobody-listens", "turnId": "turn-1"},
        })

        recorded = client.unmatched_notifications
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["method"], "item/completed")
        self.assertEqual(recorded[0]["thread_id"], "thread-nobody-listens")
        self.assertEqual(recorded[0]["turn_id"], "turn-1")

    async def test_matched_notification_is_not_recorded_as_unmatched(self) -> None:
        client = self.make_client(FakeProcessFactory())
        self.addAsyncCleanup(client.close)
        subscription = client.subscribe_thread("thread-a")
        self.addCleanup(subscription.close)

        client._route_notification({
            "method": "item/completed",
            "params": {"threadId": "thread-a"},
        })

        self.assertEqual(client.unmatched_notifications, [])
        _sequence, delivered = await asyncio.wait_for(
            subscription.next_notification_with_sequence(), timeout=1
        )
        self.assertEqual(delivered["method"], "item/completed")

    async def test_unmatched_notification_backlog_is_bounded(self) -> None:
        client = self.make_client(FakeProcessFactory())
        self.addAsyncCleanup(client.close)

        for i in range(45):
            client._route_notification({
                "method": "item/completed",
                "params": {"threadId": f"thread-{i}"},
            })

        recorded = client.unmatched_notifications
        self.assertEqual(len(recorded), 40)
        # Only the most recent 40 survive - the oldest 5 were evicted.
        self.assertEqual(recorded[0]["thread_id"], "thread-5")
        self.assertEqual(recorded[-1]["thread_id"], "thread-44")

    async def test_initialize_once_and_reuse_one_process(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.responders["thread/start"] = lambda _: {"thread": {"id": "thr_1"}}
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)

        await asyncio.gather(*(client.start() for _ in range(8)))
        await client.start()
        self.assertEqual(await client.start_thread({"cwd": "/repo"}), "thr_1")

        self.assertEqual(len(factory.calls), 1)
        args, kwargs = factory.calls[0]
        self.assertEqual(args, ("codex", "app-server", "--listen", "stdio://"))
        self.assertEqual(kwargs["cwd"], "/tmp")
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin"})
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(client.generation, 1)
        self.assertEqual(
            client.initialize_result,
            {
                "userAgent": "fake",
                "platformFamily": "unix",
                "platformOs": "macos",
                "codexHome": "/tmp/codex",
            },
        )

        initialize = process.messages[0]
        self.assertEqual(initialize["method"], "initialize")
        self.assertEqual(
            initialize["params"]["clientInfo"],
            {"name": "agents_server", "title": "AgentsServer", "version": "1"},
        )
        self.assertEqual(
            initialize["params"]["capabilities"],
            {"experimentalApi": True},
        )
        self.assertEqual(process.messages[1], {"method": "initialized"})
        self.assertEqual(
            [message.get("method") for message in process.messages].count("initialize"),
            1,
        )

    async def test_app_server_args_are_passed_before_listen(self) -> None:
        factory = FakeProcessFactory()
        client = self.make_client(
            factory,
            app_server_args=("--disable", "goals"),
        )
        self.addAsyncCleanup(client.close)

        await client.start()

        self.assertEqual(
            factory.calls[0][0],
            (
                "codex",
                "app-server",
                "--disable",
                "goals",
                "--listen",
                "stdio://",
            ),
        )

    async def test_thread_methods_track_loaded_threads_and_exact_payloads(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.responders.update(
            {
                "thread/start": lambda _: {"thread": {"id": "thr_new"}},
                "thread/resume": lambda message: {
                    "thread": {"id": message["params"]["threadId"]}
                },
                "thread/fork": lambda _: {
                    "thread": {
                        "id": "thr_fork",
                        "forkedFromId": "thr_existing",
                    }
                },
                "thread/inject_items": lambda _: {},
                "thread/read": lambda message: {
                    "thread": {
                        "id": message["params"]["threadId"],
                        "turns": [{"id": "turn_recovered"}],
                    }
                },
                "thread/turns/list": lambda _: {
                    "data": [{"id": "turn_recovered"}],
                    "nextCursor": None,
                },
                "thread/unsubscribe": lambda _: {"status": "unsubscribed"},
            }
        )
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)

        self.assertEqual(
            await client.start_thread(
                {
                    "cwd": "/repo",
                    "developerInstructions": "short stable instructions",
                }
            ),
            "thr_new",
        )
        self.assertTrue(client.is_thread_loaded("thr_new"))

        self.assertEqual(
            await client.resume_thread(
                "thr_existing",
                {"cwd": "/repo", "developerInstructions": "resume instructions"},
            ),
            "thr_existing",
        )
        self.assertTrue(client.is_thread_loaded("thr_existing"))

        self.assertEqual(
            await client.fork_thread(
                "thr_existing",
                {
                    "cwd": "/repo",
                    "developerInstructions": "fork instructions",
                    "deferGoalContinuation": True,
                },
                last_turn_id="turn_4",
            ),
            "thr_fork",
        )
        self.assertTrue(client.is_thread_loaded("thr_fork"))

        injected = [
            {
                "type": "message",
                "role": "developer",
                "content": [{"type": "input_text", "text": "migration marker"}],
            }
        ]
        await client.inject_items("thr_existing", injected)
        self.assertEqual(
            await client.read_thread("thr_existing", include_turns=True),
            {
                "id": "thr_existing",
                "turns": [{"id": "turn_recovered"}],
            },
        )
        self.assertEqual(
            await client.list_turns("thr_existing", limit=2),
            [{"id": "turn_recovered"}],
        )
        self.assertEqual(await client.unsubscribe_thread("thr_existing"), "unsubscribed")
        self.assertFalse(client.is_thread_loaded("thr_existing"))

        by_method = {
            message["method"]: message
            for message in process.messages
            if message.get("id") is not None and message.get("method") != "initialize"
        }
        self.assertEqual(
            by_method["thread/resume"]["params"],
            {
                "cwd": "/repo",
                "developerInstructions": "resume instructions",
                "threadId": "thr_existing",
                "excludeTurns": True,
            },
        )
        self.assertEqual(
            by_method["thread/fork"]["params"],
            {
                "cwd": "/repo",
                "developerInstructions": "fork instructions",
                "deferGoalContinuation": True,
                "threadId": "thr_existing",
                "lastTurnId": "turn_4",
                "excludeTurns": True,
            },
        )
        self.assertEqual(
            by_method["thread/inject_items"]["params"],
            {"threadId": "thr_existing", "items": injected},
        )
        self.assertEqual(
            by_method["thread/read"]["params"],
            {"threadId": "thr_existing", "includeTurns": True},
        )
        self.assertEqual(
            by_method["thread/turns/list"]["params"],
            {
                "threadId": "thr_existing",
                "limit": 2,
                "itemsView": "full",
                "sortDirection": "desc",
            },
        )

        fork_events = client.subscribe_thread("thr_fork")
        closed = {
            "method": "thread/closed",
            "params": {"threadId": "thr_fork"},
        }
        process.feed(closed)
        self.assertEqual(await fork_events.next_notification(timeout=1), closed)
        with self.assertRaises(CodexAppServerSubscriptionClosed):
            await fork_events.next_notification(timeout=1)
        await wait_until(lambda: not client.is_thread_loaded("thr_fork"))

    async def test_fork_accepts_distinct_child_with_matching_parent(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.responders["thread/fork"] = lambda _: {
            "thread": {
                "id": "thr_fork",
                "forkedFromId": "thr_source",
            }
        }
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)

        resolved = await client.fork_thread(
            "thr_source",
            {
                "cwd": "/repo",
                "deferGoalContinuation": True,
            },
        )

        self.assertEqual(resolved, "thr_fork")
        self.assertTrue(client.is_thread_loaded("thr_fork"))
        request = next(
            message
            for message in process.messages
            if message.get("method") == "thread/fork"
        )
        self.assertEqual(
            request["params"],
            {
                "cwd": "/repo",
                "deferGoalContinuation": True,
                "threadId": "thr_source",
                "excludeTurns": True,
            },
        )

    async def test_timed_out_fork_deletes_child_from_late_started_notification(
        self,
    ) -> None:
        factory = FakeProcessFactory()
        process = factory.process

        def fork_without_response(_message: dict[str, Any]) -> object:
            asyncio.get_running_loop().call_later(
                0.02,
                process.feed,
                {
                    "method": "thread/started",
                    "params": {
                        "thread": {
                            "id": "thr_late_child",
                            "forkedFromId": "thr_source",
                            "cwd": "/repo",
                            "createdAt": int(time.time()),
                        }
                    },
                },
            )
            return NO_RESPONSE

        process.responders["thread/fork"] = fork_without_response
        process.responders["thread/delete"] = lambda _: {}
        client = self.make_client(
            factory,
            lifecycle_timeout=0.05,
            fork_cleanup_grace=0.2,
        )
        self.addAsyncCleanup(client.close)

        with self.assertRaises(CodexAppServerTimeout) as raised:
            await client.fork_thread("thr_source", {"cwd": "/repo"})

        self.assertEqual(raised.exception.method, "thread/fork")
        self.assertFalse(
            hasattr(raised.exception, "unretired_fork_thread_ids")
        )
        self.assertEqual(
            [
                message["params"]
                for message in process.messages
                if message.get("method") == "thread/delete"
            ],
            [{"threadId": "thr_late_child"}],
        )
        self.assertFalse(client.is_thread_loaded("thr_late_child"))

    async def test_late_fork_cleanup_failure_preserves_original_timeout(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process

        def fork_without_response(_message: dict[str, Any]) -> object:
            asyncio.get_running_loop().call_later(
                0.02,
                process.feed,
                {
                    "method": "thread/started",
                    "params": {
                        "thread": {
                            "id": "thr_late_child",
                            "forkedFromId": "thr_source",
                            "cwd": "/repo",
                            "createdAt": int(time.time()),
                        }
                    },
                },
            )
            return NO_RESPONSE

        process.responders["thread/fork"] = fork_without_response
        # Hold the cleanup request open so the test proves the original timeout
        # does not escape before cleanup has either retired or handed off the
        # observed provider identity.
        process.responders["thread/delete"] = lambda _: NO_RESPONSE
        client = self.make_client(
            factory,
            lifecycle_timeout=0.05,
            fork_cleanup_grace=0.2,
        )
        self.addAsyncCleanup(client.close)

        fork_task = asyncio.create_task(
            client.fork_thread("thr_source", {"cwd": "/repo"})
        )
        await wait_until(lambda: any(
            message.get("method") == "thread/delete"
            for message in process.messages
        ))
        self.assertFalse(fork_task.done())
        delete_request = next(
            message
            for message in process.messages
            if message.get("method") == "thread/delete"
        )
        # An invalid response makes delete_thread fail after it was attempted.
        process.feed({"id": delete_request["id"], "result": None})

        with self.assertRaises(CodexAppServerTimeout) as raised:
            await fork_task

        self.assertEqual(raised.exception.method, "thread/fork")
        self.assertEqual(
            raised.exception.unretired_fork_thread_ids,
            ("thr_late_child",),
        )
        self.assertEqual(
            [
                message["params"]
                for message in process.messages
                if message.get("method") == "thread/delete"
            ],
            [{"threadId": "thr_late_child"}],
        )

    async def test_late_fork_cleanup_failure_preserves_cancellation(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.responders["thread/fork"] = lambda _: NO_RESPONSE
        process.responders["thread/delete"] = lambda _: NO_RESPONSE
        client = self.make_client(
            factory,
            lifecycle_timeout=1,
            fork_cleanup_grace=0.2,
        )
        self.addAsyncCleanup(client.close)

        fork_task = asyncio.create_task(
            client.fork_thread("thr_source", {"cwd": "/repo"})
        )
        await wait_until(lambda: any(
            message.get("method") == "thread/fork"
            for message in process.messages
        ))
        asyncio.get_running_loop().call_later(
            0.01,
            process.feed,
            {
                "method": "thread/started",
                "params": {
                    "thread": {
                        "id": "thr_late_child",
                        "forkedFromId": "thr_source",
                        "cwd": "/repo",
                        "createdAt": int(time.time()),
                    }
                },
            },
        )
        fork_task.cancel()

        await wait_until(lambda: any(
            message.get("method") == "thread/delete"
            for message in process.messages
        ))
        self.assertFalse(fork_task.done())
        delete_request = next(
            message
            for message in process.messages
            if message.get("method") == "thread/delete"
        )
        process.feed({"id": delete_request["id"], "result": None})

        with self.assertRaises(asyncio.CancelledError) as raised:
            await fork_task
        self.assertEqual(
            raised.exception.unretired_fork_thread_ids,
            ("thr_late_child",),
        )
        self.assertEqual(
            [
                message["params"]
                for message in process.messages
                if message.get("method") == "thread/delete"
            ],
            [{"threadId": "thr_late_child"}],
        )

    async def test_ambiguous_fork_does_not_delete_concurrently_resumed_child(
        self,
    ) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        fork_request_seen = asyncio.Event()

        def fork_without_response(_message: dict[str, Any]) -> object:
            fork_request_seen.set()
            return NO_RESPONSE

        process.responders["thread/fork"] = fork_without_response

        def resume_existing(_message: dict[str, Any]) -> dict[str, Any]:
            # app-server can announce an existing fork before responding to
            # thread/resume. Its ancestry alone does not make it a new child.
            process.feed({
                "method": "thread/started",
                "params": {
                    "thread": {
                        "id": "thr_existing_fork",
                        "forkedFromId": "thr_source",
                        "cwd": "/repo",
                        "createdAt": int(time.time()),
                    }
                },
            })
            return {"thread": {"id": "thr_existing_fork"}}

        process.responders["thread/resume"] = resume_existing
        process.responders["thread/unsubscribe"] = lambda _: {
            "status": "unsubscribed"
        }
        process.responders["thread/delete"] = lambda _: {}
        client = self.make_client(
            factory,
            lifecycle_timeout=1,
            fork_cleanup_grace=0.05,
        )
        self.addAsyncCleanup(client.close)

        fork_task = asyncio.create_task(
            client.fork_thread("thr_source", {"cwd": "/repo"})
        )
        await asyncio.wait_for(fork_request_seen.wait(), timeout=1)

        self.assertEqual(
            await client.resume_thread("thr_existing_fork"),
            "thr_existing_fork",
        )
        await client.unsubscribe_thread("thr_existing_fork")
        # Known identity survives unload. A delayed duplicate start notice is
        # still not eligible for destructive late-fork cleanup.
        process.feed({
            "method": "thread/started",
            "params": {
                "thread": {
                    "id": "thr_existing_fork",
                    "forkedFromId": "thr_source",
                    "cwd": "/repo",
                    "createdAt": int(time.time()),
                }
            },
        })

        fork_task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await fork_task
        self.assertFalse(any(
            message.get("method") == "thread/delete"
            for message in process.messages
        ))

    async def test_reconnect_old_fork_notification_is_never_deleted(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        fork_request_seen = asyncio.Event()

        def fork_without_response(_message: dict[str, Any]) -> object:
            fork_request_seen.set()
            return NO_RESPONSE

        process.responders["thread/fork"] = fork_without_response
        process.responders["thread/delete"] = lambda _: {}
        client = self.make_client(
            factory,
            lifecycle_timeout=1,
            fork_cleanup_grace=0.02,
        )
        self.addAsyncCleanup(client.close)

        fork_task = asyncio.create_task(
            client.fork_thread("thr_source", {"cwd": "/repo"})
        )
        await asyncio.wait_for(fork_request_seen.wait(), timeout=1)
        # Simulate a reconnect: this legitimate provider identity is not in
        # the client's process-local known set, but its creation time proves it
        # predates the current fork request.
        process.feed({
            "method": "thread/started",
            "params": {
                "thread": {
                    "id": "thr_existing_fork",
                    "forkedFromId": "thr_source",
                    "cwd": "/repo",
                    "createdAt": int(time.time()) - 3600,
                }
            },
        })
        fork_task.cancel()

        with self.assertRaises(asyncio.CancelledError):
            await fork_task
        self.assertFalse(any(
            message.get("method") == "thread/delete"
            for message in process.messages
        ))

    async def test_fork_rejects_source_thread_as_result(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.responders["thread/fork"] = lambda _: {
            "thread": {
                "id": "thr_source",
                "forkedFromId": "thr_source",
            }
        }
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)

        with self.assertRaisesRegex(
            CodexAppServerProtocolError,
            "source thread id",
        ) as raised:
            await client.fork_thread("thr_source")

        self.assertTrue(raised.exception.request_sent)
        self.assertFalse(raised.exception.safe_to_retry)
        self.assertFalse(client.is_thread_loaded("thr_source"))

    async def test_fork_rejects_result_with_wrong_parent(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.responders["thread/fork"] = lambda _: {
            "thread": {
                "id": "thr_fork",
                "forkedFromId": "thr_other",
            }
        }
        process.responders["thread/delete"] = lambda _: {}
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)

        with self.assertRaisesRegex(
            CodexAppServerProtocolError,
            "different source id",
        ) as raised:
            await client.fork_thread("thr_source")

        self.assertTrue(raised.exception.request_sent)
        self.assertFalse(raised.exception.safe_to_retry)
        self.assertFalse(client.is_thread_loaded("thr_fork"))
        delete_request = next(
            message
            for message in process.messages
            if message.get("method") == "thread/delete"
        )
        self.assertEqual(delete_request["params"], {"threadId": "thr_fork"})

    async def test_delete_thread_validates_and_unloads_exact_thread(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.responders["thread/delete"] = lambda _: {}
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)
        client._loaded_threads.add("thr_abandoned")

        await client.delete_thread("thr_abandoned")

        request = next(
            message
            for message in process.messages
            if message.get("method") == "thread/delete"
        )
        self.assertEqual(request["params"], {"threadId": "thr_abandoned"})
        self.assertFalse(client.is_thread_loaded("thr_abandoned"))
        with self.assertRaisesRegex(ValueError, "thread_id"):
            await client.delete_thread("  ")

    async def test_delete_thread_rejects_invalid_response_without_unloading(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.responders["thread/delete"] = lambda _: None
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)
        client._loaded_threads.add("thr_abandoned")

        with self.assertRaisesRegex(
            CodexAppServerProtocolError,
            "thread/delete did not return an object",
        ):
            await client.delete_thread("thr_abandoned")

        self.assertTrue(client.is_thread_loaded("thr_abandoned"))

    async def test_native_thread_controls_validate_and_send_exact_payloads(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        goal = {
            "threadId": "thr_controls",
            "objective": "Finish the integration",
            "status": "active",
            "tokenBudget": 40000,
            "tokensUsed": 123,
            "timeUsedSeconds": 9,
            "createdAt": 100,
            "updatedAt": 101,
        }

        def profiles(message: dict[str, Any]) -> dict[str, Any]:
            if message["params"].get("cursor") == "profiles-page-2":
                return {
                    "data": [
                        {
                            "id": "workspace",
                            "allowed": True,
                            "description": "Workspace access",
                        }
                    ],
                    "nextCursor": None,
                }
            return {
                "data": [
                    {
                        "id": "read-only",
                        "allowed": True,
                        "description": None,
                    }
                ],
                "nextCursor": "profiles-page-2",
            }

        def terminals(message: dict[str, Any]) -> dict[str, Any]:
            process_id = (
                "terminal-2"
                if message["params"].get("cursor") == "terminals-page-2"
                else "terminal-1"
            )
            return {
                "data": [
                    {
                        "itemId": f"item-{process_id}",
                        "processId": process_id,
                        "command": "python3 -m http.server",
                        "cwd": "/repo",
                        "osPid": 1234,
                        "cpuPercent": 1.5,
                        "rssKb": 2048,
                    }
                ],
                "nextCursor": (
                    None
                    if process_id == "terminal-2"
                    else "terminals-page-2"
                ),
            }

        process.responders.update(
            {
                "permissionProfile/list": profiles,
                "thread/goal/set": lambda _: {"goal": goal},
                "thread/goal/get": lambda _: {"goal": goal},
                "thread/goal/clear": lambda _: {"cleared": True},
                "thread/compact/start": lambda _: {},
                "thread/rollback": lambda _: {
                    "thread": {"id": "thr_controls", "turns": []}
                },
                "review/start": lambda _: {
                    "reviewThreadId": "thr_controls",
                    "turn": {
                        "id": "turn_review",
                        "status": "inProgress",
                        "items": [],
                    },
                },
                "thread/shellCommand": lambda _: {},
                "thread/backgroundTerminals/list": terminals,
                "thread/backgroundTerminals/terminate": lambda _: {
                    "terminated": True
                },
                "thread/backgroundTerminals/clean": lambda _: {},
            }
        )
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)

        self.assertEqual(
            await client.list_permission_profiles(cwd="/repo", page_size=1),
            [
                {"id": "read-only", "allowed": True, "description": None},
                {
                    "id": "workspace",
                    "allowed": True,
                    "description": "Workspace access",
                },
            ],
        )
        self.assertEqual(
            await client.set_thread_goal(
                "thr_controls",
                objective="Finish the integration",
                status="active",
                token_budget=40000,
            ),
            goal,
        )
        self.assertEqual(await client.get_thread_goal("thr_controls"), goal)
        self.assertTrue(await client.clear_thread_goal("thr_controls"))
        await client.compact_thread("thr_controls")
        self.assertEqual(
            await client.rollback_thread("thr_controls", num_turns=2),
            {"id": "thr_controls", "turns": []},
        )
        self.assertEqual(
            await client.start_review(
                "thr_controls",
                {"type": "commit", "sha": "abc123", "title": "The change"},
            ),
            {
                "reviewThreadId": "thr_controls",
                "turn": {
                    "id": "turn_review",
                    "status": "inProgress",
                    "items": [],
                },
            },
        )
        await client.run_thread_shell_command("thr_controls", "git status --short")
        self.assertEqual(
            [item["processId"] for item in await client.list_background_terminals(
                "thr_controls",
                page_size=1,
            )],
            ["terminal-1", "terminal-2"],
        )
        self.assertTrue(
            await client.terminate_background_terminal(
                "thr_controls",
                "terminal-1",
            )
        )
        await client.clean_background_terminals("thr_controls")

        requests = [
            message
            for message in process.messages
            if message.get("id") is not None and message.get("method") != "initialize"
        ]
        by_method: dict[str, list[dict[str, Any]]] = {}
        for message in requests:
            by_method.setdefault(message["method"], []).append(message)
        self.assertEqual(
            [message["params"] for message in by_method["permissionProfile/list"]],
            [
                {"cwd": "/repo", "limit": 1},
                {"cwd": "/repo", "limit": 1, "cursor": "profiles-page-2"},
            ],
        )
        self.assertEqual(
            by_method["thread/goal/set"][0]["params"],
            {
                "threadId": "thr_controls",
                "objective": "Finish the integration",
                "status": "active",
                "tokenBudget": 40000,
            },
        )
        self.assertEqual(
            by_method["thread/goal/get"][0]["params"],
            {"threadId": "thr_controls"},
        )
        self.assertEqual(
            by_method["thread/goal/clear"][0]["params"],
            {"threadId": "thr_controls"},
        )
        self.assertEqual(
            by_method["thread/rollback"][0]["params"],
            {"threadId": "thr_controls", "numTurns": 2},
        )
        self.assertEqual(
            by_method["review/start"][0]["params"],
            {
                "threadId": "thr_controls",
                "target": {
                    "type": "commit",
                    "sha": "abc123",
                    "title": "The change",
                },
                "delivery": "inline",
            },
        )
        self.assertEqual(
            by_method["thread/shellCommand"][0]["params"],
            {
                "threadId": "thr_controls",
                "command": "git status --short",
            },
        )
        self.assertEqual(
            [
                message["params"]
                for message in by_method["thread/backgroundTerminals/list"]
            ],
            [
                {"threadId": "thr_controls", "limit": 1},
                {
                    "threadId": "thr_controls",
                    "limit": 1,
                    "cursor": "terminals-page-2",
                },
            ],
        )
        self.assertEqual(
            by_method["thread/backgroundTerminals/terminate"][0]["params"],
            {"threadId": "thr_controls", "processId": "terminal-1"},
        )

    async def test_native_thread_controls_fail_closed_on_invalid_contracts(
        self,
    ) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)

        with self.assertRaises(ValueError):
            await client.set_thread_goal("thr", objective="")
        with self.assertRaises(ValueError):
            await client.set_thread_goal("thr", status="finished")
        with self.assertRaises(ValueError):
            await client.rollback_thread("thr", num_turns=0)
        with self.assertRaises(ValueError):
            await client.start_review("thr", {"type": "commit", "sha": ""})
        with self.assertRaises(ValueError):
            await client.run_thread_shell_command("thr", " ")

        process.responders["thread/goal/get"] = lambda _: {
            "goal": {
                "threadId": "different-thread",
                "objective": "Wrong",
                "status": "active",
                "tokensUsed": 0,
                "timeUsedSeconds": 0,
                "createdAt": 1,
                "updatedAt": 1,
            }
        }
        with self.assertRaises(CodexAppServerProtocolError):
            await client.get_thread_goal("thr")

        process.responders["permissionProfile/list"] = lambda _: {
            "data": [{"id": "broken", "allowed": "yes"}],
            "nextCursor": None,
        }
        with self.assertRaises(CodexAppServerProtocolError):
            await client.list_permission_profiles()

        process.responders["thread/backgroundTerminals/list"] = lambda _: {
            "data": [
                {
                    "itemId": "item",
                    "processId": "1",
                    "command": "sleep 1",
                    "cwd": "/repo",
                    "cpuPercent": "busy",
                }
            ],
            "nextCursor": None,
        }
        with self.assertRaises(CodexAppServerProtocolError):
            await client.list_background_terminals("thr")

    async def test_lists_all_subagent_descendants_with_explicit_source_filter(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process

        def list_threads(message: dict[str, Any]) -> dict[str, Any]:
            if message["params"].get("cursor") is None:
                return {
                    "data": [{"id": "child-a", "parentThreadId": "root"}],
                    "nextCursor": "page-2",
                }
            return {
                "data": [{"id": "grandchild", "parentThreadId": "child-a"}],
                "nextCursor": None,
            }

        process.responders["thread/list"] = list_threads
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)

        descendants = await client.list_descendant_threads("root", page_size=1)

        self.assertEqual([thread["id"] for thread in descendants], ["child-a", "grandchild"])
        requests = [
            message for message in process.messages
            if message.get("method") == "thread/list"
        ]
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0]["params"]["ancestorThreadId"], "root")
        self.assertTrue(requests[0]["params"]["useStateDbOnly"])
        self.assertEqual(
            requests[0]["params"]["sourceKinds"],
            [
                "subAgent",
                "subAgentReview",
                "subAgentCompact",
                "subAgentThreadSpawn",
                "subAgentOther",
            ],
        )
        self.assertEqual(requests[1]["params"]["cursor"], "page-2")

    async def test_multiplexed_turns_route_by_thread_and_turn(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process

        def start_turn(message: dict[str, Any]) -> dict[str, Any]:
            thread_id = message["params"]["threadId"]
            turn_id = f"turn_{thread_id[-1]}"
            if thread_id == "thread_a":
                # Exercise the real race where notifications can precede the
                # turn/start response.
                process.feed(
                    {
                        "method": "item/started",
                        "params": {
                            "threadId": thread_id,
                            "turnId": turn_id,
                            "item": {"id": "early"},
                        },
                    }
                )
            return {"turn": {"id": turn_id, "status": "inProgress", "items": []}}

        steer_boundary_event = {
            "method": "item/completed",
            "params": {
                "threadId": "thread_a",
                "turnId": "turn_a",
                "item": {
                    "id": "reason-before-steer-ack",
                    "type": "reasoning",
                    "summary": [{"text": "Before ack"}],
                },
            },
        }

        def steer_turn(message: dict[str, Any]) -> dict[str, Any]:
            process.feed(steer_boundary_event)
            return {"turnId": message["params"]["expectedTurnId"]}

        process.responders.update(
            {
                "turn/start": start_turn,
                "turn/steer": steer_turn,
                "turn/interrupt": lambda _: {},
            }
        )
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)
        thread_a_events = client.subscribe_thread("thread_a")
        self.addCleanup(thread_a_events.close)

        turn_a, turn_b = await asyncio.gather(
            client.start_turn(
                "thread_a",
                [{"type": "text", "text": "A"}],
                overrides={"model": "gpt-5.4", "effort": "high"},
            ),
            client.start_turn(
                "thread_b",
                [{"type": "text", "text": "B"}],
            ),
        )
        self.assertEqual(turn_a.turn_id, "turn_a")
        self.assertEqual(turn_b.turn_id, "turn_b")
        self.assertIs(client.active_turn("thread_a"), turn_a)
        self.assertIs(client.active_turn("thread_b"), turn_b)

        early = await turn_a.next_notification(timeout=1)
        self.assertEqual(early["params"]["item"]["id"], "early")
        self.assertEqual(await thread_a_events.next_notification(timeout=1), early)

        wrong_turn = {
            "method": "item/agentMessage/delta",
            "params": {
                "threadId": "thread_a",
                "turnId": "turn_other",
                "delta": "must not leak",
            },
        }
        process.feed(wrong_turn)
        self.assertEqual(await thread_a_events.next_notification(timeout=1), wrong_turn)
        with self.assertRaises(asyncio.TimeoutError):
            await turn_a.next_notification(timeout=0.01)

        turn_b_event = {
            "method": "item/agentMessage/delta",
            "params": {
                "threadId": "thread_b",
                "turnId": "turn_b",
                "delta": "B",
            },
        }
        process.feed(turn_b_event)
        self.assertEqual(await turn_b.next_notification(timeout=1), turn_b_event)

        steered_turn_id, notification_watermark = (
            await turn_a.steer_with_notification_watermark(
                [{"type": "text", "text": "steer A"}],
                client_user_message_id="message-a",
            )
        )
        self.assertEqual(steered_turn_id, "turn_a")
        boundary_sequence, boundary_notification = (
            await turn_a.next_notification_with_sequence(timeout=1)
        )
        self.assertEqual(boundary_notification, steer_boundary_event)
        self.assertEqual(boundary_sequence, notification_watermark)
        await turn_a.interrupt()

        completed = {
            "method": "turn/completed",
            "params": {
                "threadId": "thread_a",
                "turn": {"id": "turn_a", "status": "completed"},
            },
        }
        process.feed(completed)
        self.assertEqual(await turn_a.next_notification(timeout=1), completed)
        await wait_until(lambda: client.active_turn("thread_a") is None)
        with self.assertRaises(CodexAppServerSubscriptionClosed):
            await turn_a.next_notification(timeout=1)

        await turn_b.close()
        self.assertIsNone(client.active_turn("thread_b"))

        turn_starts = [
            message
            for message in process.messages
            if message.get("method") == "turn/start"
        ]
        self.assertEqual(len(turn_starts), 2)
        turn_a_start = next(
            message
            for message in turn_starts
            if message["params"]["threadId"] == "thread_a"
        )
        self.assertEqual(
            turn_a_start["params"],
            {
                "model": "gpt-5.4",
                "effort": "high",
                "threadId": "thread_a",
                "input": [{"type": "text", "text": "A"}],
            },
        )

        steer = next(
            message
            for message in process.messages
            if message.get("method") == "turn/steer"
        )
        self.assertEqual(steer["params"]["expectedTurnId"], "turn_a")
        self.assertEqual(steer["params"]["clientUserMessageId"], "message-a")
        self.assertNotIn("additionalContext", steer["params"])

    async def test_goal_continuation_retargets_active_turn_and_interrupt(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.responders.update(
            {
                "turn/start": lambda _: {
                    "turn": {
                        "id": "turn_initial",
                        "status": "inProgress",
                        "items": [],
                    }
                },
                "turn/interrupt": lambda _: {},
            }
        )
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)
        thread_events = client.subscribe_thread("thread_goal")
        other_thread_events = client.subscribe_thread("thread_other")
        self.addCleanup(thread_events.close)
        self.addCleanup(other_thread_events.close)

        turn = await client.start_turn(
            "thread_goal",
            [{"type": "text", "text": "Start goal"}],
        )
        self.assertEqual(turn.turn_id, "turn_initial")

        # An arbitrary event carrying another turn id must not retarget the
        # active handle or leak into its scoped subscription.
        wrong_turn = {
            "method": "item/agentMessage/delta",
            "params": {
                "threadId": "thread_goal",
                "turnId": "turn_wrong",
                "delta": "must not retarget",
            },
        }
        process.feed(wrong_turn)
        self.assertEqual(await thread_events.next_notification(timeout=1), wrong_turn)
        with self.assertRaises(asyncio.TimeoutError):
            await turn.next_notification(timeout=0.01)
        self.assertEqual(turn.turn_id, "turn_initial")

        # A turn started on another thread is unrelated to this active turn.
        unrelated_started = {
            "method": "turn/started",
            "params": {
                "threadId": "thread_other",
                "turn": {
                    "id": "turn_other",
                    "status": "inProgress",
                    "items": [],
                },
            },
        }
        process.feed(unrelated_started)
        self.assertEqual(
            await other_thread_events.next_notification(timeout=1),
            unrelated_started,
        )
        self.assertEqual(turn.turn_id, "turn_initial")

        # Native goals continue by starting a new turn on the same thread.
        # The existing handle must follow it before subscriptions are routed.
        continued_started = {
            "method": "turn/started",
            "params": {
                "threadId": "thread_goal",
                "turn": {
                    "id": "turn_continued",
                    "status": "inProgress",
                    "items": [],
                },
            },
        }
        process.feed(continued_started)
        self.assertEqual(
            await turn.next_notification(timeout=1),
            continued_started,
        )
        self.assertEqual(turn.turn_id, "turn_continued")

        continued_item = {
            "method": "item/agentMessage/delta",
            "params": {
                "threadId": "thread_goal",
                "turnId": "turn_continued",
                "delta": "continued output",
            },
        }
        process.feed(continued_item)
        self.assertEqual(await turn.next_notification(timeout=1), continued_item)

        await turn.interrupt()
        interrupt = next(
            message
            for message in reversed(process.messages)
            if message.get("method") == "turn/interrupt"
        )
        self.assertEqual(
            interrupt["params"],
            {"threadId": "thread_goal", "turnId": "turn_continued"},
        )

        await turn.close()

    async def test_resume_accepts_a_jsonl_response_larger_than_16_mib(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.stdout = asyncio.StreamReader(limit=32 * 1024 * 1024)
        large_value = "x" * (17 * 1024 * 1024)
        process.responders["thread/resume"] = lambda message: {
            "thread": {
                "id": message["params"]["threadId"],
                "turns": [{"id": "large-turn", "summary": large_value}],
            }
        }
        client = self.make_client(
            factory,
            process_stream_limit=32 * 1024 * 1024,
            json_parse_thread_threshold=1024,
        )
        self.addAsyncCleanup(client.close)

        self.assertEqual(await client.resume_thread("thr_large"), "thr_large")
        self.assertEqual(
            factory.calls[0][1]["limit"],
            32 * 1024 * 1024,
        )
        resume = next(
            message
            for message in process.messages
            if message.get("method") == "thread/resume"
        )
        self.assertTrue(resume["params"]["excludeTurns"])

    async def test_resume_uses_the_separate_lifecycle_timeout(self) -> None:
        factory = FakeProcessFactory()
        client = self.make_client(factory, lifecycle_timeout=123)
        request = AsyncMock(
            return_value={"thread": {"id": "thr_lifecycle"}}
        )
        with patch.object(client, "request", request):
            self.assertEqual(
                await client.resume_thread("thr_lifecycle"),
                "thr_lifecycle",
            )

        request.assert_awaited_once_with(
            "thread/resume",
            {"threadId": "thr_lifecycle", "excludeTurns": True},
            timeout=123,
        )

    async def test_notification_backlog_is_bounded_and_fails_subscription(
        self,
    ) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory, notification_queue_limit=2)
        self.addAsyncCleanup(client.close)
        await client.start()
        subscription = client.subscribe_thread("thr_backlog")

        for index in range(3):
            process.feed(
                {
                    "method": "item/agentMessage/delta",
                    "params": {
                        "threadId": "thr_backlog",
                        "turnId": "turn_backlog",
                        "itemId": "item_backlog",
                        "delta": str(index),
                    },
                }
            )

        with self.assertRaises(CodexAppServerDisconnected) as raised:
            await subscription.next_notification(timeout=1)
        self.assertIn("backlog", str(raised.exception))
        self.assertTrue(subscription._closed)

    async def test_concurrent_requests_match_out_of_order_responses(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)
        await client.start()

        first = asyncio.create_task(client.request("test/first", {"value": 1}))
        second = asyncio.create_task(client.request("test/second", {"value": 2}))
        await wait_until(lambda: len(process.messages) >= 4)
        first_message, second_message = process.messages[-2:]
        self.assertNotEqual(first_message["id"], second_message["id"])

        process.feed({"id": second_message["id"], "result": {"order": 2}})
        process.feed({"id": first_message["id"], "result": {"order": 1}})
        self.assertEqual(await first, {"order": 1})
        self.assertEqual(await second, {"order": 2})

        error_task = asyncio.create_task(client.request("test/error", {}))
        await wait_until(lambda: process.messages[-1].get("method") == "test/error")
        process.feed(
            {
                "id": process.messages[-1]["id"],
                "error": {"code": -32001, "message": "Server overloaded; retry later."},
            }
        )
        with self.assertRaises(CodexAppServerRequestError) as raised:
            await error_task
        self.assertEqual(raised.exception.code, -32001)
        self.assertTrue(raised.exception.request_sent)
        self.assertTrue(raised.exception.safe_to_retry)

    async def test_timeout_is_ambiguous_and_not_safe_to_replay(self) -> None:
        factory = FakeProcessFactory()
        client = self.make_client(factory)
        client.request_timeout = 0.01
        self.addAsyncCleanup(client.close)
        await client.start()

        with self.assertRaises(CodexAppServerTimeout) as raised:
            await client.request("turn/start", {"threadId": "thr", "input": []})
        self.assertTrue(raised.exception.request_sent)
        self.assertFalse(raised.exception.safe_to_retry)
        self.assertTrue(client.ready)
        self.assertIs(client.process, factory.process)

    async def test_cancelled_turn_start_transfers_provisional_for_cleanup(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)
        # Exercise lazy start: the transport generation is still zero when the
        # caller begins, then initialize advances it before turn/start is
        # written. Cleanup must use the generation captured at that write.
        self.assertEqual(client.generation, 0)

        start = asyncio.create_task(
            client.start_turn(
                "thr_cancelled_start",
                [{"type": "text", "text": "hello"}],
            )
        )
        await wait_until(
            lambda: any(
                message.get("method") == "turn/start"
                for message in process.messages
            )
        )
        start.cancel()
        try:
            await start
        except asyncio.CancelledError as exc:
            provisional = getattr(exc, "pending_turn", None)
        else:
            self.fail("turn/start cancellation did not propagate")

        self.assertIsNotNone(provisional)
        self.assertIs(
            client.active_turn("thr_cancelled_start"),
            provisional,
        )
        self.assertEqual(provisional.transport_generation, client.generation)
        self.assertEqual(provisional.transport_generation, 1)
        accepted_event = {
            "method": "turn/started",
            "params": {
                "threadId": "thr_cancelled_start",
                "turn": {"id": "turn_late_after_cancel"},
            },
        }
        process.feed(accepted_event)
        self.assertEqual(
            await provisional.next_notification(timeout=1),
            accepted_event,
        )
        self.assertEqual(provisional.turn_id, "turn_late_after_cancel")
        await provisional.close()
        self.assertIsNone(client.active_turn("thr_cancelled_start"))

    async def test_retire_generation_cannot_stop_a_replacement_transport(self) -> None:
        factory = FakeProcessFactory()
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)
        await client.start()

        generation = client.generation
        self.assertFalse(await client.retire_generation(generation + 1))
        self.assertTrue(client.ready)
        self.assertTrue(await client.retire_generation(generation))
        self.assertFalse(client.ready)

    async def test_request_timeout_waiting_for_write_lock_is_retry_safe(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        process.responders["test/recovered"] = lambda _: {"ok": True}
        client = self.make_client(factory)
        client.request_timeout = 0.01
        self.addAsyncCleanup(client.close)
        await client.start()

        await client._write_lock.acquire()
        try:
            with self.assertRaises(CodexAppServerTimeout) as raised:
                await client.request("test/blocked-before-write", {})
        finally:
            client._write_lock.release()

        self.assertFalse(raised.exception.request_sent)
        self.assertTrue(raised.exception.safe_to_retry)
        self.assertFalse(any(
            message.get("method") == "test/blocked-before-write"
            for message in process.messages
        ))
        self.assertTrue(client.ready)
        self.assertIs(client.process, process)
        self.assertEqual(
            await client.request("test/recovered", {}),
            {"ok": True},
        )

    async def test_blocked_drain_retires_process_and_next_request_recovers(
        self,
    ) -> None:
        first_process = FakeProcess()
        second_process = FakeProcess()
        second_process.responders["test/recovered"] = lambda _: {"ok": True}
        factory = FakeProcessFactory(first_process, second_process)
        client = self.make_client(factory)
        client.request_timeout = 0.01
        self.addAsyncCleanup(client.close)
        await client.start()

        drain_started = asyncio.Event()
        never_drain = asyncio.Event()

        async def blocked_drain() -> None:
            drain_started.set()
            await never_drain.wait()

        first_process.stdin.drain = blocked_drain
        wedged_request = asyncio.create_task(
            client.request("test/wedged-write", {})
        )
        await asyncio.wait_for(drain_started.wait(), timeout=1)
        queued_request = asyncio.create_task(
            client.request("test/queued-behind-wedge", {})
        )
        with self.assertRaises(CodexAppServerTimeout) as raised:
            await wedged_request
        with self.assertRaises(
            (CodexAppServerTimeout, CodexAppServerDisconnected)
        ):
            await asyncio.wait_for(queued_request, timeout=1)

        self.assertTrue(drain_started.is_set())
        self.assertTrue(raised.exception.request_sent)
        self.assertFalse(raised.exception.safe_to_retry)
        self.assertFalse(client._write_lock.locked())
        self.assertIsNone(client.process)
        self.assertFalse(client.ready)
        self.assertEqual(first_process.returncode, -signal.SIGTERM)

        self.assertEqual(
            await client.request("test/recovered", {}),
            {"ok": True},
        )
        self.assertIs(client.process, second_process)
        self.assertEqual(client.generation, 2)

        await client.close()
        self.assertIsNone(client.process)
        self.assertEqual(second_process.returncode, -signal.SIGTERM)

    async def test_repeated_cancellation_cannot_abandon_write_timeout_cleanup(
        self,
    ) -> None:
        process = FakeProcess()
        exit_hooks: list[tuple[int, int | None]] = []
        client = self.make_client(
            FakeProcessFactory(process),
            on_process_exited=lambda pid, group_id: exit_hooks.append(
                (pid, group_id)
            ),
        )
        client._proc = process
        client._initialized = True

        wait_started = asyncio.Event()
        release_first_wait = asyncio.Event()
        original_wait = process.wait
        original_kill = process.kill
        wait_calls = 0
        terminate_calls = 0
        kill_calls = 0

        async def stalled_wait() -> int:
            nonlocal wait_calls
            wait_calls += 1
            if wait_calls == 1:
                wait_started.set()
                await release_first_wait.wait()
                return -signal.SIGTERM
            return await original_wait()

        def stalled_terminate() -> None:
            nonlocal terminate_calls
            terminate_calls += 1

        def recording_kill() -> None:
            nonlocal kill_calls
            kill_calls += 1
            original_kill()

        process.wait = stalled_wait
        process.terminate = stalled_terminate
        process.kill = recording_kill

        owner = asyncio.create_task(
            client._discard_process_after_write_timeout(process)
        )
        await asyncio.wait_for(wait_started.wait(), timeout=1)
        owner.cancel("first cancellation")
        await asyncio.sleep(0)
        self.assertFalse(owner.done())
        owner.cancel("second cancellation")
        await asyncio.sleep(0)
        self.assertFalse(owner.done())

        release_first_wait.set()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(owner, timeout=1)

        self.assertIsNone(client.process)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual(terminate_calls, 1)
        self.assertEqual(kill_calls, 1)
        self.assertEqual(exit_hooks, [(process.pid, None)])

    async def test_response_wait_uses_remaining_end_to_end_deadline(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)
        await client.start()

        original_drain = process.stdin.drain

        async def slow_drain() -> None:
            await asyncio.sleep(0.03)
            await original_drain()

        process.stdin.drain = slow_drain
        recorded_timeouts: list[float | None] = []
        real_wait_for = asyncio.wait_for

        async def recording_wait_for(
            awaitable: Any,
            timeout: float | None,
        ) -> Any:
            recorded_timeouts.append(timeout)
            return await real_wait_for(awaitable, timeout=timeout)

        with patch("codex_app_server.asyncio.wait_for", recording_wait_for):
            with self.assertRaises(CodexAppServerTimeout):
                await client.request("test/no-response", {}, timeout=0.1)

        self.assertGreaterEqual(len(recorded_timeouts), 3)
        first_timeout = recorded_timeouts[0]
        response_timeout = recorded_timeouts[-1]
        self.assertIsNotNone(first_timeout)
        self.assertIsNotNone(response_timeout)
        assert first_timeout is not None
        assert response_timeout is not None
        self.assertLess(response_timeout, first_timeout - 0.015)
        self.assertTrue(client.ready)
        self.assertIs(client.process, process)

    async def test_blocked_server_response_drain_cleans_up_without_self_wait(
        self,
    ) -> None:
        first_process = FakeProcess()
        second_process = FakeProcess()
        second_process.responders["test/recovered"] = lambda _: {"ok": True}
        factory = FakeProcessFactory(first_process, second_process)

        async def handler(
            _request_id: Any,
            _method: str,
            _params: dict[str, Any],
        ) -> dict[str, Any]:
            return {"ok": True}

        client = self.make_client(factory, server_request_handler=handler)
        client.request_timeout = 0.01
        self.addAsyncCleanup(client.close)
        await client.start()

        never_drain = asyncio.Event()

        async def blocked_drain() -> None:
            await never_drain.wait()

        first_process.stdin.drain = blocked_drain
        first_process.feed({
            "id": "server-request",
            "method": "test/server-request",
            "params": {},
        })
        await wait_until(lambda: client.process is None)
        await wait_until(lambda: not client._server_request_tasks)

        self.assertEqual(first_process.returncode, -signal.SIGTERM)
        self.assertFalse(client._server_request_tasks)
        self.assertEqual(
            await client.request("test/recovered", {}),
            {"ok": True},
        )
        self.assertIs(client.process, second_process)

    async def test_ambiguous_turn_start_keeps_a_routed_provisional_handle(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory)
        client.request_timeout = 0.01
        self.addAsyncCleanup(client.close)

        with self.assertRaises(CodexAppServerTimeout) as raised:
            await client.start_turn(
                "thr_ambiguous",
                [{"type": "text", "text": "do not replay me"}],
            )

        pending_turn = raised.exception.pending_turn
        self.assertIsNotNone(pending_turn)
        assert pending_turn is not None
        self.assertIs(client.active_turn("thr_ambiguous"), pending_turn)
        self.assertEqual(pending_turn.turn_id, "")

        accepted_event = {
            "method": "item/started",
            "params": {
                "threadId": "thr_ambiguous",
                "turnId": "turn_late",
                "item": {"id": "proof_of_acceptance"},
            },
        }
        process.feed(accepted_event)
        self.assertEqual(
            await pending_turn.next_notification(timeout=1),
            accepted_event,
        )
        self.assertEqual(pending_turn.turn_id, "turn_late")
        await pending_turn.close()

    async def test_default_server_request_handler_declines_without_wedging(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)
        await client.start()

        requests = [
            ("command", "item/commandExecution/requestApproval", {}, {"decision": "decline"}),
            ("file", "item/fileChange/requestApproval", {}, {"decision": "decline"}),
            ("legacy_exec", "execCommandApproval", {}, {"decision": "denied"}),
            ("legacy_patch", "applyPatchApproval", {}, {"decision": "denied"}),
            (
                "input",
                "item/tool/requestUserInput",
                {"questions": [{"id": "choice"}]},
                {"answers": {}},
            ),
            ("mcp", "mcpServer/elicitation/request", {}, {"action": "decline"}),
            (
                "permissions",
                "item/permissions/requestApproval",
                {},
                {"permissions": {}, "scope": "turn", "strictAutoReview": False},
            ),
        ]
        for request_id, method, params, _expected in requests:
            process.feed({"id": request_id, "method": method, "params": params})
        process.feed({"id": "unknown", "method": "item/tool/call", "params": {}})

        await wait_until(
            lambda: len(
                [
                    message
                    for message in process.messages
                    if message.get("id") in {item[0] for item in requests} | {"unknown"}
                ]
            )
            == len(requests) + 1
        )
        responses = {
            message["id"]: message
            for message in process.messages
            if message.get("id") in {item[0] for item in requests} | {"unknown"}
        }
        for request_id, _method, _params, expected in requests:
            self.assertEqual(responses[request_id]["result"], expected)
        self.assertEqual(responses["unknown"]["error"]["code"], -32601)
        self.assertNotIn("result", responses["unknown"])

    async def test_server_request_is_cancelled_when_resolved_elsewhere(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        handler_started = asyncio.Event()
        handler_cancelled = asyncio.Event()

        async def handler(
            request_id: Any,
            method: str,
            params: dict[str, Any],
        ) -> dict[str, Any]:
            self.assertEqual(request_id, "approval_1")
            self.assertEqual(method, "item/commandExecution/requestApproval")
            self.assertEqual(params["threadId"], "thr_1")
            handler_started.set()
            try:
                await asyncio.Future()
            finally:
                handler_cancelled.set()
            return {"decision": "decline"}

        client = self.make_client(factory, server_request_handler=handler)
        self.addAsyncCleanup(client.close)
        await client.start()
        subscription = client.subscribe_thread("thr_1")
        self.addCleanup(subscription.close)

        process.feed(
            {
                "id": "approval_1",
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thr_1",
                    "turnId": "turn_1",
                    "itemId": "item_1",
                },
            }
        )
        await asyncio.wait_for(handler_started.wait(), timeout=1)

        resolved = {
            "method": "serverRequest/resolved",
            "params": {"threadId": "thr_1", "requestId": "approval_1"},
        }
        process.feed(resolved)
        await asyncio.wait_for(handler_cancelled.wait(), timeout=1)
        self.assertEqual(await subscription.next_notification(timeout=1), resolved)
        self.assertFalse(
            any(
                message.get("id") == "approval_1"
                and ("result" in message or "error" in message)
                for message in process.messages
            )
        )

    async def test_process_crash_fails_pending_requests_and_subscriptions_then_restarts(self) -> None:
        first_process = FakeProcess()
        second_process = FakeProcess()
        first_process.responders["thread/start"] = lambda _: {"thread": {"id": "thr_1"}}
        first_process.responders["turn/start"] = lambda _: {
            "turn": {"id": "turn_1", "status": "inProgress", "items": []}
        }
        second_process.responders["thread/resume"] = lambda message: {
            "thread": {"id": message["params"]["threadId"]}
        }
        factory = FakeProcessFactory(first_process, second_process)
        client = self.make_client(factory)
        self.addAsyncCleanup(client.close)

        self.assertEqual(await client.start_thread({}), "thr_1")
        turn = await client.start_turn("thr_1", [{"type": "text", "text": "go"}])
        thread_events = client.subscribe_thread("thr_1")

        pending = asyncio.create_task(client.request("test/hang", {}))
        await wait_until(
            lambda: first_process.messages[-1].get("method") == "test/hang"
        )
        first_process.crash(23)

        with self.assertRaises(CodexAppServerDisconnected) as request_failure:
            await pending
        self.assertTrue(request_failure.exception.request_sent)
        self.assertFalse(request_failure.exception.safe_to_retry)
        with self.assertRaises(CodexAppServerDisconnected):
            await turn.next_notification(timeout=1)
        with self.assertRaises(CodexAppServerDisconnected):
            await thread_events.next_notification(timeout=1)
        self.assertFalse(client.is_thread_loaded("thr_1"))
        self.assertIsNone(client.active_turn("thr_1"))

        self.assertEqual(await client.resume_thread("thr_1"), "thr_1")
        self.assertEqual(len(factory.calls), 2)
        self.assertEqual(client.generation, 2)
        self.assertTrue(client.is_thread_loaded("thr_1"))

    async def test_reader_waits_for_numeric_exit_status_after_stdout_eof(
        self,
    ) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory, process_exit_timeout=0.5)
        self.addAsyncCleanup(client.close)
        await client.start()

        pending = asyncio.create_task(client.request("test/hang", {}))
        await wait_until(
            lambda: process.messages[-1].get("method") == "test/hang"
        )
        process.stdout.feed_eof()

        async def publish_exit_status() -> None:
            await asyncio.sleep(0.01)
            process.returncode = 37
            process.stderr.feed_eof()
            process._exited.set()

        exit_task = asyncio.create_task(publish_exit_status())
        with self.assertRaises(CodexAppServerDisconnected) as raised:
            await pending
        await exit_task

        self.assertEqual(
            str(raised.exception),
            "codex app-server exited with code 37",
        )
        self.assertNotIn("None", str(raised.exception))

    async def test_reader_never_formats_missing_exit_status_as_none(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory, process_exit_timeout=0.01)
        self.addAsyncCleanup(client.close)
        await client.start()

        pending = asyncio.create_task(client.request("test/hang", {}))
        await wait_until(
            lambda: process.messages[-1].get("method") == "test/hang"
        )
        process.stdout.feed_eof()

        with self.assertRaises(CodexAppServerDisconnected) as raised:
            await pending

        self.assertIn(
            "exit status became available",
            str(raised.exception),
        )
        self.assertNotIn("code None", str(raised.exception))

    async def test_planned_close_marks_transport_disconnect_as_planned(
        self,
    ) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory)
        await client.start()

        pending = asyncio.create_task(client.request("test/hang", {}))
        await wait_until(
            lambda: process.messages[-1].get("method") == "test/hang"
        )
        await client.close()

        with self.assertRaises(CodexAppServerDisconnected) as raised:
            await pending
        self.assertTrue(raised.exception.planned)
        self.assertIn("stopped with AgentsServer", str(raised.exception))

    async def test_planned_close_terminates_the_posix_process_group(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory)
        await client.start()
        # Injected factories do not prove new-session ownership. This test
        # explicitly grants the exact group that the real launcher records.
        client._process_group_id = process.pid
        signals: list[tuple[int, int]] = []

        def kill_group(process_group_id: int, requested_signal: int) -> None:
            signals.append((process_group_id, requested_signal))
            if requested_signal == signal.SIGTERM:
                process.crash(-signal.SIGTERM)
                return
            if requested_signal == 0:
                raise ProcessLookupError

        with patch("codex_app_server.os.killpg", side_effect=kill_group), \
             patch.object(process, "terminate") as terminate:
            await client.close()

        self.assertEqual(signals, [
            (process.pid, signal.SIGTERM),
            (process.pid, 0),
        ])
        terminate.assert_not_called()

    async def test_planned_close_kills_owned_group_after_leader_exited(self) -> None:
        factory = FakeProcessFactory()
        process = factory.process
        client = self.make_client(factory)
        await client.start()
        client._process_group_id = process.pid
        # Model Node exiting before its native Codex child. The stream reader
        # is intentionally still live; close() must use stored group ownership
        # rather than the leader returncode to retire the orphan.
        process.returncode = 17
        process._exited.set()
        signals: list[tuple[int, int]] = []
        group_alive = True

        def kill_group(process_group_id: int, requested_signal: int) -> None:
            nonlocal group_alive
            signals.append((process_group_id, requested_signal))
            if requested_signal == signal.SIGTERM:
                group_alive = False
            elif requested_signal == 0 and not group_alive:
                raise ProcessLookupError

        with patch("codex_app_server.os.killpg", side_effect=kill_group), \
             patch.object(process, "terminate") as terminate:
            await client.close()

        self.assertEqual(signals, [
            (process.pid, signal.SIGTERM),
            (process.pid, 0),
        ])
        terminate.assert_not_called()

    async def test_manager_is_a_policy_agnostic_single_client_facade(self) -> None:
        factory = FakeProcessFactory()
        factory.process.responders["thread/start"] = lambda _: {
            "thread": {"id": "thr_manager"}
        }
        factory.process.responders["thread/compact/start"] = lambda _: {}
        manager = CodexAppServerManager(
            "codex",
            cwd="/tmp",
            env_factory=lambda: {"PATH": "/usr/bin"},
            process_factory=factory,
            request_timeout=1,
        )
        self.addAsyncCleanup(manager.close)

        self.assertFalse(manager.ready)
        self.assertEqual(await manager.start_thread({}), "thr_manager")
        self.assertTrue(manager.ready)
        self.assertTrue(manager.is_thread_loaded("thr_manager"))
        self.assertEqual(len(factory.calls), 1)
        await manager.compact_thread("thr_manager")
        self.assertEqual(
            factory.process.messages[-1]["method"],
            "thread/compact/start",
        )


if __name__ == "__main__":
    unittest.main()
