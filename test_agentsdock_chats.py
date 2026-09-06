import argparse
import http.client
import io
import json
import unittest
import urllib.error
from unittest.mock import Mock, patch

import agentsdock_chats


class AgentsDockChatsCLITests(unittest.TestCase):
    def test_helper_uses_only_the_canonical_provider_capability_header(self) -> None:
        self.assertEqual(
            agentsdock_chats.provider_headers("live-capability"),
            {
                "Accept": "application/json",
                "X-AgentsDock-Provider-Capability": "live-capability",
            },
        )

    def test_post_retries_only_the_native_promotion_window(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return json.dumps({"ok": True}).encode("utf-8")

        class FakeOpener:
            def __init__(self) -> None:
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                if len(self.requests) == 1:
                    raise urllib.error.HTTPError(
                        request.full_url,
                        409,
                        "Conflict",
                        {},
                        io.BytesIO(json.dumps({
                            "detail": (
                                "agent chat access is waiting for turn "
                                "promotion"
                            ),
                        }).encode("utf-8")),
                    )
                return FakeResponse()

        opener = FakeOpener()
        payload = {
            "body": "hello",
            "idempotency_key": "stable-key",
        }
        with (
            patch.object(
                agentsdock_chats,
                "environment",
                return_value="http://127.0.0.1:7850",
            ),
            patch.object(
                agentsdock_chats.urllib.request,
                "build_opener",
                return_value=opener,
            ),
            patch.object(agentsdock_chats.time, "sleep") as sleep,
        ):
            result = agentsdock_chats.post_json(
                "/api/agent/cross-chat/routes/route/handoffs",
                payload,
                "capability",
            )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(len(opener.requests), 2)
        self.assertIs(opener.requests[0][0], opener.requests[1][0])
        self.assertEqual(
            json.loads(opener.requests[0][0].data.decode("utf-8")),
            payload,
        )
        sleep.assert_called_once_with(0.05)

    def test_post_replays_identical_idempotent_request_after_lost_response(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return json.dumps({"ok": True, "accepted": True}).encode("utf-8")

        class FakeOpener:
            def __init__(self) -> None:
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                if len(self.requests) == 1:
                    raise urllib.error.URLError(TimeoutError("response lost"))
                return FakeResponse()

        opener = FakeOpener()
        payload = {
            "body": "hello",
            "idempotency_key": "stable-key",
        }
        with (
            patch.object(agentsdock_chats, "environment", return_value="http://127.0.0.1:7850"),
            patch.object(agentsdock_chats.urllib.request, "build_opener", return_value=opener),
            patch.object(agentsdock_chats.time, "sleep") as sleep,
        ):
            result = agentsdock_chats.post_json(
                "/api/agent/cross-chat/handoffs",
                payload,
                "capability",
            )

        self.assertEqual(result, {"ok": True, "accepted": True})
        self.assertEqual(len(opener.requests), 2)
        self.assertIs(opener.requests[0][0], opener.requests[1][0])
        self.assertEqual(opener.requests[0][0].data, opener.requests[1][0].data)
        sleep.assert_called_once_with(0.1)

    def test_post_replays_identical_request_after_truncated_success_body(self) -> None:
        class FakeResponse:
            def __init__(self, truncated: bool) -> None:
                self.truncated = truncated

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                if self.truncated:
                    raise http.client.IncompleteRead(b'{"ok":true')
                return json.dumps({"ok": True, "accepted": True}).encode("utf-8")

        class FakeOpener:
            def __init__(self) -> None:
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                return FakeResponse(len(self.requests) == 1)

        opener = FakeOpener()
        payload = {"body": "hello", "idempotency_key": "stable-key"}
        with (
            patch.object(agentsdock_chats, "environment", return_value="http://127.0.0.1:7850"),
            patch.object(agentsdock_chats.urllib.request, "build_opener", return_value=opener),
            patch.object(agentsdock_chats.time, "sleep") as sleep,
        ):
            result = agentsdock_chats.post_json(
                "/api/agent/cross-chat/handoffs",
                payload,
                "capability",
            )

        self.assertEqual(result, {"ok": True, "accepted": True})
        self.assertEqual(len(opener.requests), 2)
        self.assertIs(opener.requests[0][0], opener.requests[1][0])
        self.assertEqual(opener.requests[0][0].data, opener.requests[1][0].data)
        sleep.assert_called_once_with(0.1)

    def test_post_replays_identical_request_after_truncated_error_body(self) -> None:
        class TruncatedHTTPError(urllib.error.HTTPError):
            def read(self):
                raise http.client.IncompleteRead(b'{"detail":')

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return json.dumps({"ok": True, "accepted": True}).encode("utf-8")

        class FakeOpener:
            def __init__(self) -> None:
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                if len(self.requests) == 1:
                    raise TruncatedHTTPError(
                        request.full_url,
                        409,
                        "Conflict",
                        {},
                        None,
                    )
                return FakeResponse()

        opener = FakeOpener()
        payload = {"body": "hello", "idempotency_key": "stable-key"}
        with (
            patch.object(agentsdock_chats, "environment", return_value="http://127.0.0.1:7850"),
            patch.object(agentsdock_chats.urllib.request, "build_opener", return_value=opener),
            patch.object(agentsdock_chats.time, "sleep") as sleep,
        ):
            result = agentsdock_chats.post_json(
                "/api/agent/cross-chat/handoffs",
                payload,
                "capability",
            )

        self.assertEqual(result, {"ok": True, "accepted": True})
        self.assertEqual(len(opener.requests), 2)
        self.assertIs(opener.requests[0][0], opener.requests[1][0])
        sleep.assert_called_once_with(0.1)

    def test_post_reports_ambiguous_commit_without_inviting_reworded_retry(self) -> None:
        class FakeOpener:
            def open(self, _request, timeout):
                raise urllib.error.URLError(TimeoutError("response lost"))

        with (
            patch.object(agentsdock_chats, "environment", return_value="http://127.0.0.1:7850"),
            patch.object(agentsdock_chats.urllib.request, "build_opener", return_value=FakeOpener()),
            patch.object(agentsdock_chats.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                agentsdock_chats.ChatsCLIError,
                "do not resend it with different wording",
            ):
                agentsdock_chats.post_json(
                    "/api/agent/cross-chat/handoffs",
                    {"body": "hello", "idempotency_key": "stable-key"},
                    "capability",
                )

    def test_get_replays_identical_live_lease_after_lost_response(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return json.dumps({"ok": True, "body": "answer"}).encode("utf-8")

        class FakeOpener:
            def __init__(self) -> None:
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                if len(self.requests) == 1:
                    raise urllib.error.URLError(ConnectionResetError("response lost"))
                return FakeResponse()

        opener = FakeOpener()
        with (
            patch.object(agentsdock_chats, "environment", return_value="http://127.0.0.1:7850"),
            patch.object(agentsdock_chats.urllib.request, "build_opener", return_value=opener),
            patch.object(agentsdock_chats.time, "sleep") as sleep,
        ):
            result = agentsdock_chats.get_json(
                "/api/agent/cross-chat/exchanges/ex/legs/leg/live-response?lease_id=lease",
                "capability",
                timeout=90,
            )

        self.assertEqual(result, {"ok": True, "body": "answer"})
        self.assertEqual(len(opener.requests), 2)
        self.assertIs(opener.requests[0][0], opener.requests[1][0])
        self.assertEqual(opener.requests[0][0].full_url, opener.requests[1][0].full_url)
        sleep.assert_called_once_with(0.1)

    def test_get_replays_identical_live_lease_after_truncated_json(self) -> None:
        class FakeResponse:
            def __init__(self, body: bytes) -> None:
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return self.body

        class FakeOpener:
            def __init__(self) -> None:
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                if len(self.requests) == 1:
                    return FakeResponse(b'{"ok":true')
                return FakeResponse(json.dumps({
                    "ok": True,
                    "body": "answer",
                }).encode("utf-8"))

        opener = FakeOpener()
        with (
            patch.object(agentsdock_chats, "environment", return_value="http://127.0.0.1:7850"),
            patch.object(agentsdock_chats.urllib.request, "build_opener", return_value=opener),
            patch.object(agentsdock_chats.time, "sleep") as sleep,
        ):
            result = agentsdock_chats.get_json(
                "/api/agent/cross-chat/exchanges/ex/legs/leg/live-response?lease_id=lease",
                "capability",
                timeout=90,
            )

        self.assertEqual(result, {"ok": True, "body": "answer"})
        self.assertEqual(len(opener.requests), 2)
        self.assertIs(opener.requests[0][0], opener.requests[1][0])
        sleep.assert_called_once_with(0.1)

    def test_get_replays_identical_live_lease_after_truncated_error_body(self) -> None:
        class TruncatedHTTPError(urllib.error.HTTPError):
            def read(self):
                raise http.client.IncompleteRead(b'{"detail":')

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return json.dumps({"ok": True, "body": "answer"}).encode("utf-8")

        class FakeOpener:
            def __init__(self) -> None:
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                if len(self.requests) == 1:
                    raise TruncatedHTTPError(
                        request.full_url,
                        409,
                        "Conflict",
                        {},
                        None,
                    )
                return FakeResponse()

        opener = FakeOpener()
        with (
            patch.object(agentsdock_chats, "environment", return_value="http://127.0.0.1:7850"),
            patch.object(agentsdock_chats.urllib.request, "build_opener", return_value=opener),
            patch.object(agentsdock_chats.time, "sleep") as sleep,
        ):
            result = agentsdock_chats.get_json(
                "/api/agent/cross-chat/exchanges/ex/legs/leg/live-response?lease_id=lease",
                "capability",
                timeout=90,
            )

        self.assertEqual(result, {"ok": True, "body": "answer"})
        self.assertEqual(len(opener.requests), 2)
        self.assertIs(opener.requests[0][0], opener.requests[1][0])
        sleep.assert_called_once_with(0.1)

    def test_live_post_returns_lease_on_bounded_transport_timeout(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return json.dumps({"ok": True}).encode("utf-8")

        class FakeOpener:
            timeout = None

            def open(self, _request, timeout):
                self.timeout = timeout
                return FakeResponse()

        opener = FakeOpener()
        with (
            patch.object(agentsdock_chats, "environment", return_value="http://127.0.0.1:7850"),
            patch.object(agentsdock_chats.urllib.request, "build_opener", return_value=opener),
        ):
            agentsdock_chats.post_json(
                "/api/agent/cross-chat/handoffs",
                {
                    "wait_for_response": True,
                    "response_timeout_seconds": 120,
                },
                "capability",
            )
        self.assertEqual(opener.timeout, 30)

    def test_ask_posts_then_long_polls_exact_live_lease(self) -> None:
        post = Mock(return_value={
            "ok": True,
            "action": "request_reply",
            "accepted": True,
            "exchange_id": "exchange_live",
            "inbound_leg_id": "leg_question",
            "live_response_lease_id": "lease_" + "a" * 32,
        })
        get = Mock(return_value={
            "ok": True,
            "exchange_id": "exchange_live",
            "inbound_leg_id": "leg_answer",
            "body": "Peer answer",
            "request_response": False,
        })
        args = argparse.Namespace(
            authority_file="authority.json",
            route=None,
            target="grant_" + "b" * 64,
            message="Question",
            idempotency_key=None,
            timeout_seconds=75,
        )
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", post),
            patch.object(agentsdock_chats, "get_json", get),
        ):
            result = agentsdock_chats.ask(args)
        self.assertEqual(result["body"], "Peer answer")
        self.assertEqual(result["inbound_leg_id"], "leg_answer")
        wait_path = get.call_args.args[0]
        self.assertIn("exchange_live/legs/leg_question/live-response?", wait_path)
        self.assertIn("lease_id=lease_", wait_path)
        self.assertEqual(get.call_args.kwargs["timeout"], 75)
        self.assertTrue(get.call_args.kwargs["retry_forever"])
        self.assertIn("timeout_seconds=60", wait_path)

    def test_route_ask_waits_on_the_exact_live_lease(self) -> None:
        route = "route_" + "a" * 32
        receipt = {
            "ok": True,
            "route_id": route,
            "action": "request_reply",
            "accepted": True,
            "exchange_id": "exchange_route_live",
            "inbound_leg_id": "leg_route_question",
            "live_response_lease_id": "lease_" + "b" * 32,
        }
        post = Mock(return_value=receipt)
        get = Mock(return_value={
            "ok": True,
            "exchange_id": "exchange_route_live",
            "inbound_leg_id": "leg_route_answer",
            "body": "Route answer",
            "request_response": False,
        })
        args = argparse.Namespace(
            authority_file="authority.json",
            route=route,
            target=None,
            message="Slow question",
            idempotency_key=None,
            timeout_seconds=75,
            async_response=False,
        )
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", post),
            patch.object(agentsdock_chats, "get_json", get),
        ):
            result = agentsdock_chats.ask(args)

        self.assertEqual(result["body"], "Route answer")
        payload = post.call_args.args[1]
        self.assertTrue(payload["wait_for_response"])
        self.assertEqual(payload["response_timeout_seconds"], 75)
        get.assert_called_once()

    def test_route_ask_accepts_minimal_receipt_only_in_explicit_async_mode(self) -> None:
        args = argparse.Namespace(
            authority_file="authority.json",
            route="route_" + "a" * 32,
            target=None,
            message="Question",
            idempotency_key=None,
            timeout_seconds=75,
            async_response=True,
        )
        receipt = {
            "ok": True,
            "route_id": args.route,
            "action": "request_reply",
            "accepted": True,
        }
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(
                agentsdock_chats,
                "post_json",
                return_value=receipt,
            ),
        ):
            self.assertEqual(agentsdock_chats.ask(args), receipt)

    def test_live_wait_repeats_pending_heartbeats_until_the_answer(self) -> None:
        receipt = {
            "exchange_id": "exchange_heartbeat",
            "inbound_leg_id": "leg_question",
            "live_response_lease_id": "lease_" + "d" * 32,
        }
        pending = {
            "ok": True,
            "exchange_id": "exchange_heartbeat",
            "inbound_leg_id": "leg_question",
            "pending": True,
        }
        answer = {
            "ok": True,
            "exchange_id": "exchange_heartbeat",
            "inbound_leg_id": "leg_answer",
            "body": "Eventually answered",
            "request_response": False,
        }
        # Four complete 20-second heartbeat windows model a response arriving
        # after the old 75-second semantic timeout without making the unit
        # test sleep in real time.
        get = Mock(side_effect=[pending, pending, pending, pending, answer])
        with patch.object(agentsdock_chats, "get_json", get):
            result = agentsdock_chats.await_live_response(
                receipt,
                "capability",
                20,
            )

        self.assertEqual(result, answer)
        self.assertEqual(get.call_count, 5)
        self.assertEqual({call.args[0] for call in get.call_args_list}, {
            get.call_args_list[0].args[0],
        })
        self.assertTrue(all(
            call.kwargs["retry_forever"] for call in get.call_args_list
        ))

    def test_cli_timeout_one_waits_past_old_limit_until_eventual_answer(self) -> None:
        route = "route_" + "e" * 32
        post = Mock(return_value={
            "ok": True,
            "route_id": route,
            "action": "request_reply",
            "accepted": True,
            "exchange_id": "exchange_cli_heartbeat",
            "inbound_leg_id": "leg_cli_question",
            "live_response_lease_id": "lease_" + "f" * 32,
        })
        pending = {
            "ok": True,
            "exchange_id": "exchange_cli_heartbeat",
            "inbound_leg_id": "leg_cli_question",
            "pending": True,
        }
        answer = {
            "ok": True,
            "exchange_id": "exchange_cli_heartbeat",
            "inbound_leg_id": "leg_cli_answer",
            "body": "Answer after more than the old timeout",
            "request_response": False,
        }
        # The legacy value is now a one-second heartbeat request, not a total
        # deadline. Seventy-six pending responses cross the old 75-second
        # semantic cap before the same lease eventually returns its answer.
        get = Mock(side_effect=[pending] * 76 + [answer])
        stdout = io.StringIO()
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", post),
            patch.object(agentsdock_chats, "get_json", get),
            patch.object(agentsdock_chats.sys, "stdout", stdout),
        ):
            exit_code = agentsdock_chats.main([
                "--authority-file",
                "authority.json",
                "ask",
                "--route",
                route,
                "--message",
                "Wait as long as necessary",
                "--timeout-seconds",
                "1",
            ])

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["body"], answer["body"])
        self.assertEqual(post.call_args.args[1]["response_timeout_seconds"], 1)
        self.assertEqual(get.call_count, 77)
        self.assertEqual(
            {call.args[0] for call in get.call_args_list},
            {get.call_args_list[0].args[0]},
        )
        self.assertTrue(all(
            "timeout_seconds=1" in call.args[0]
            and call.kwargs["timeout"] == 16
            and call.kwargs["retry_forever"] is True
            for call in get.call_args_list
        ))

    def test_cli_explicit_410_cancel_is_terminal(self) -> None:
        route = "route_" + "a" * 32
        post = Mock(return_value={
            "ok": True,
            "route_id": route,
            "action": "request_reply",
            "accepted": True,
            "exchange_id": "exchange_cli_cancel",
            "inbound_leg_id": "leg_cli_cancel",
            "live_response_lease_id": "lease_" + "b" * 32,
        })
        get = Mock(side_effect=agentsdock_chats.ChatsCLIError(
            "server rejected request (410): cancelled_by_user"
        ))
        stderr = io.StringIO()
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", post),
            patch.object(agentsdock_chats, "get_json", get),
            patch.object(agentsdock_chats.sys, "stderr", stderr),
        ):
            exit_code = agentsdock_chats.main([
                "--authority-file",
                "authority.json",
                "ask",
                "--route",
                route,
                "--message",
                "Wait until cancel",
                "--timeout-seconds",
                "1",
            ])

        self.assertEqual(exit_code, 2)
        self.assertIn("cancelled_by_user", stderr.getvalue())
        get.assert_called_once()

    def test_live_get_retries_transport_gateway_and_disconnect_failures(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return json.dumps({"ok": True, "pending": True}).encode("utf-8")

        class FakeOpener:
            def __init__(self) -> None:
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                if len(self.requests) == 1:
                    raise urllib.error.URLError(
                        ConnectionResetError("proxy reset")
                    )
                if len(self.requests) == 2:
                    raise urllib.error.HTTPError(
                        request.full_url,
                        503,
                        "Service Unavailable",
                        {},
                        io.BytesIO(b'{"detail":"restarting"}'),
                    )
                if len(self.requests) == 3:
                    raise urllib.error.HTTPError(
                        request.full_url,
                        499,
                        "Client Closed Request",
                        {},
                        io.BytesIO(b'{"detail":"observer disconnected"}'),
                    )
                return FakeResponse()

        opener = FakeOpener()
        with (
            patch.object(
                agentsdock_chats,
                "environment",
                return_value="http://127.0.0.1:7850",
            ),
            patch.object(
                agentsdock_chats.urllib.request,
                "build_opener",
                return_value=opener,
            ),
            patch.object(agentsdock_chats.time, "sleep") as sleep,
        ):
            result = agentsdock_chats.get_json(
                "/api/agent/cross-chat/exchanges/ex/legs/leg/live-response",
                "capability",
                retry_forever=True,
            )

        self.assertEqual(result, {"ok": True, "pending": True})
        self.assertEqual(len(opener.requests), 4)
        self.assertIs(opener.requests[0][0], opener.requests[1][0])
        self.assertIs(opener.requests[1][0], opener.requests[2][0])
        self.assertIs(opener.requests[2][0], opener.requests[3][0])
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            [0.1, 0.2, 0.4],
        )

    def test_live_get_treats_explicit_cancel_as_terminal(self) -> None:
        class FakeOpener:
            def __init__(self) -> None:
                self.calls = 0

            def open(self, request, timeout):
                self.calls += 1
                raise urllib.error.HTTPError(
                    request.full_url,
                    410,
                    "Gone",
                    {},
                    io.BytesIO(b'{"detail":"cancelled_by_user"}'),
                )

        opener = FakeOpener()
        with (
            patch.object(
                agentsdock_chats,
                "environment",
                return_value="http://127.0.0.1:7850",
            ),
            patch.object(
                agentsdock_chats.urllib.request,
                "build_opener",
                return_value=opener,
            ),
            patch.object(agentsdock_chats.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                agentsdock_chats.ChatsCLIError,
                r"\(410\): cancelled_by_user",
            ):
                agentsdock_chats.get_json(
                    "/api/agent/cross-chat/exchanges/ex/legs/leg/live-response",
                    "capability",
                    retry_forever=True,
                )

        self.assertEqual(opener.calls, 1)
        sleep.assert_not_called()

    def test_live_get_does_not_retry_malformed_success_forever(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return b'{"ok":'

        class FakeOpener:
            def __init__(self) -> None:
                self.calls = 0

            def open(self, _request, timeout):
                self.calls += 1
                return FakeResponse()

        opener = FakeOpener()
        with (
            patch.object(
                agentsdock_chats,
                "environment",
                return_value="http://127.0.0.1:7850",
            ),
            patch.object(
                agentsdock_chats.urllib.request,
                "build_opener",
                return_value=opener,
            ),
            patch.object(agentsdock_chats.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                agentsdock_chats.ChatsCLIError,
                "invalid live-response body",
            ):
                agentsdock_chats.get_json(
                    "/api/agent/cross-chat/exchanges/ex/legs/leg/live-response",
                    "capability",
                    retry_forever=True,
                )

        self.assertEqual(opener.calls, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_secure_peer_ask_can_explicitly_use_async_response_delivery(self) -> None:
        args = argparse.Namespace(
            authority_file="authority.json",
            route=None,
            target="route_" + "a" * 32,
            message="Question for peer server",
            idempotency_key=None,
            timeout_seconds=75,
            async_response=True,
        )
        receipt = {
            "ok": True,
            "action": "request_reply",
            "accepted": True,
        }
        post = Mock(return_value=receipt)
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", post),
        ):
            self.assertEqual(agentsdock_chats.ask(args), receipt)
        payload = post.call_args.args[1]
        self.assertNotIn("wait_for_response", payload)
        self.assertNotIn("response_timeout_seconds", payload)

    def test_list_uses_capability_scoped_route_endpoint(self) -> None:
        args = argparse.Namespace(authority_file="authority.json")
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(
                agentsdock_chats,
                "get_json",
                return_value={"routes": [], "max_handoffs_per_run": 4},
            ) as get,
        ):
            result = agentsdock_chats.list_routes(args)
        self.assertEqual(result["routes"], [])
        get.assert_called_once_with(
            "/api/agent/cross-chat/routes",
            "capability",
        )

    def test_ask_uses_request_reply_wire_and_stable_retry_key(self) -> None:
        handle = "grant_" + "a" * 64
        args = argparse.Namespace(
            authority_file="authority.json",
            target=handle,
            message="  investigate this  ",
            idempotency_key=None,
        )
        calls = []

        def post(path, payload, capability):
            calls.append((path, payload, capability))
            return {
                "ok": True,
                "action": "request_reply",
                "accepted": True,
                "exchange_id": "exchange_live",
                "inbound_leg_id": "leg_live_answer",
                "body": "Investigation complete",
                "request_response": False,
            }

        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", side_effect=post),
        ):
            first = agentsdock_chats.ask(args)
            second = agentsdock_chats.ask(args)
        self.assertEqual(first, second)
        self.assertEqual(calls[0][0], "/api/agent/cross-chat/handoffs")
        self.assertEqual(calls[0][1]["action"], "request_reply")
        self.assertEqual(calls[0][1]["body"], "investigate this")
        self.assertEqual(calls[0][1]["target_session_id"], handle)
        self.assertTrue(calls[0][1]["wait_for_response"])
        self.assertEqual(calls[0][1]["response_timeout_seconds"], 20)
        self.assertEqual(calls[0][1]["idempotency_key"], calls[1][1]["idempotency_key"])

    def test_direct_send_rejects_receipt_with_internal_identifiers(self) -> None:
        args = argparse.Namespace(
            authority_file="authority.json",
            target="grant_" + "b" * 64,
            message="check",
            idempotency_key=None,
        )
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(
                agentsdock_chats,
                "post_json",
                return_value={
                    "ok": True,
                    "action": "instruction",
                    "accepted": True,
                    "target_session_id": "must-not-leak",
                },
            ),
        ):
            with self.assertRaises(agentsdock_chats.ChatsCLIError):
                agentsdock_chats.send(args)

    def test_respond_has_no_target_and_request_response_changes_stable_key(self) -> None:
        base = dict(
            authority_file="authority.json",
            exchange="exchange_one",
            inbound_leg="leg_one",
            message="answer",
            idempotency_key=None,
        )
        payloads = []

        def post(_path, payload, _capability):
            payloads.append(payload)
            receipt = {"ok": True, "action": "response", "accepted": True}
            if payload["request_response"]:
                receipt.update({
                    "exchange_id": "exchange_one",
                    "inbound_leg_id": "leg_two",
                    "body": "follow-up answer",
                    "request_response": False,
                })
            return receipt

        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", side_effect=post),
        ):
            agentsdock_chats.respond(argparse.Namespace(**base, request_response=False))
            agentsdock_chats.respond(argparse.Namespace(**base, request_response=True))
        self.assertNotIn("target_session_id", payloads[0])
        self.assertEqual(payloads[0]["inbound_leg_id"], "leg_one")
        self.assertFalse(payloads[0]["request_response"])
        self.assertTrue(payloads[1]["request_response"])
        self.assertTrue(payloads[1]["wait_for_response"])
        self.assertEqual(payloads[1]["response_timeout_seconds"], 20)
        self.assertNotEqual(payloads[0]["idempotency_key"], payloads[1]["idempotency_key"])

    def test_respond_accepts_only_strict_configured_route_receipt(self) -> None:
        args = argparse.Namespace(
            authority_file="authority.json",
            exchange="exchange_private",
            inbound_leg="leg_private",
            message="answer",
            request_response=False,
            idempotency_key="configured-response-key",
        )
        receipt = {"ok": True, "action": "response", "accepted": True}
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", return_value=receipt),
        ):
            self.assertEqual(agentsdock_chats.respond(args), receipt)

        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(
                agentsdock_chats,
                "post_json",
                return_value={**receipt, "exchange": {"id": "must-not-leak"}},
            ),
        ):
            with self.assertRaises(agentsdock_chats.ChatsCLIError):
                agentsdock_chats.respond(args)

    def test_followup_accepts_legacy_async_recovery_receipt(self) -> None:
        args = argparse.Namespace(
            authority_file="authority.json",
            exchange="exchange_deferred",
            inbound_leg="leg_answer",
            message="One more question",
            request_response=True,
            async_response=False,
            idempotency_key=None,
            timeout_seconds=75,
        )
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(
                agentsdock_chats,
                "post_json",
                return_value={
                    "ok": True,
                    "action": "response",
                    "accepted": True,
                    "exchange_id": "exchange_deferred",
                    "inbound_leg_id": "leg_followup",
                    "live_response_lease_id": "lease_" + "c" * 32,
                },
            ),
            patch.object(
                agentsdock_chats,
                "get_json",
                return_value={
                    "ok": True,
                    "exchange_id": "exchange_deferred",
                    "inbound_leg_id": "leg_followup",
                    "deferred": True,
                    "delivery": "asynchronous",
                    "message": "The answer will be delivered asynchronously.",
                },
            ),
        ):
            result = agentsdock_chats.respond(args)

        self.assertTrue(result["accepted"])
        self.assertTrue(result["deferred"])
        self.assertEqual(result["delivery"], "asynchronous")

    def test_secure_peer_followup_can_explicitly_remain_async(self) -> None:
        args = argparse.Namespace(
            authority_file="authority.json",
            exchange="exchange_peer",
            inbound_leg="envelope_peer",
            message="Question back to peer",
            request_response=True,
            async_response=True,
            idempotency_key=None,
            timeout_seconds=75,
        )
        receipt = {"ok": True, "action": "response", "accepted": True}
        post = Mock(return_value=receipt)
        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", post),
        ):
            self.assertEqual(agentsdock_chats.respond(args), receipt)
        payload = post.call_args.args[1]
        self.assertTrue(payload["request_response"])
        self.assertNotIn("wait_for_response", payload)
        self.assertNotIn("response_timeout_seconds", payload)

    def test_live_and_async_followups_use_distinct_retry_keys(self) -> None:
        base = dict(
            authority_file="authority.json",
            exchange="exchange_peer",
            inbound_leg="envelope_peer",
            message="Question back to peer",
            request_response=True,
            idempotency_key=None,
            timeout_seconds=75,
        )
        payloads = []

        def post(_path, payload, _capability):
            payloads.append(payload)
            if payload.get("wait_for_response"):
                return {
                    "ok": True,
                    "action": "response",
                    "accepted": True,
                    "exchange_id": "exchange_peer",
                    "inbound_leg_id": "envelope_reply",
                    "body": "Peer reply",
                    "request_response": False,
                }
            return {"ok": True, "action": "response", "accepted": True}

        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", side_effect=post),
        ):
            agentsdock_chats.respond(
                argparse.Namespace(**base, async_response=False)
            )
            agentsdock_chats.respond(
                argparse.Namespace(**base, async_response=True)
            )
        self.assertNotEqual(
            payloads[0]["idempotency_key"],
            payloads[1]["idempotency_key"],
        )

    def test_route_send_uses_opaque_route_path_and_no_target(self) -> None:
        args = argparse.Namespace(
            authority_file="authority.json",
            route="route_0123456789abcdef0123456789abcdef",
            target=None,
            message="update mobile",
            idempotency_key=None,
        )
        calls = []

        def post(path, payload, capability):
            calls.append((path, payload, capability))
            return {
                "ok": True,
                "route_id": args.route,
                "action": "instruction",
                "accepted": True,
            }

        with (
            patch.object(agentsdock_chats, "authority", return_value="capability"),
            patch.object(agentsdock_chats, "post_json", side_effect=post),
        ):
            result = agentsdock_chats.send(args)
        self.assertTrue(result["accepted"])
        self.assertEqual(
            calls[0][0],
            f"/api/agent/cross-chat/routes/{args.route}/handoffs",
        )
        self.assertNotIn("target_session_id", calls[0][1])

    def test_send_parser_requires_exactly_one_route_or_target(self) -> None:
        cli = agentsdock_chats.parser()
        with self.assertRaises(SystemExit):
            cli.parse_args([
                "--authority-file", "authority.json", "send",
                "--message", "hello",
            ])
        with self.assertRaises(SystemExit):
            cli.parse_args([
                "--authority-file", "authority.json", "send",
                "--route", "route_one", "--target", "sess_one",
                "--message", "hello",
            ])

    def test_ask_and_respond_reject_whitespace_messages(self) -> None:
        for handler, args in (
            (
                agentsdock_chats.ask,
                argparse.Namespace(
                    authority_file="authority.json", target="target",
                    message="  ", idempotency_key=None,
                ),
            ),
            (
                agentsdock_chats.respond,
                argparse.Namespace(
                    authority_file="authority.json", exchange="exchange",
                    inbound_leg="leg", message="\n", request_response=False,
                    idempotency_key=None,
                ),
            ),
        ):
            with patch.object(agentsdock_chats, "authority", return_value="capability"):
                with self.assertRaises(agentsdock_chats.ChatsCLIError):
                    handler(args)


if __name__ == "__main__":
    unittest.main()
