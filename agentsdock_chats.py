#!/usr/bin/env python3
"""Capability-scoped same-server chat contact CLI for AgentsDock agents."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# Keep the default below provider shell-tool deadlines (Claude's default is
# commonly 120 seconds). The server still enforces its own configurable cap.
LIVE_RESPONSE_TIMEOUT_SECONDS = 75
LIVE_RESPONSE_SOCKET_GRACE_SECONDS = 15
IDEMPOTENT_POST_RETRY_DELAYS_SECONDS = (0.1, 0.5)
IDEMPOTENT_GET_RETRY_DELAYS_SECONDS = (0.1, 0.5)


class ChatsCLIError(RuntimeError):
    pass


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def host_is_loopback(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() == "localhost"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_loopback


def environment() -> str:
    server_url = os.environ.get("AGENTSDOCK_SERVER_URL", "").strip().rstrip("/")
    if not server_url:
        raise ChatsCLIError("missing AgentsDock agent environment")
    parsed = urllib.parse.urlsplit(server_url)
    if parsed.scheme != "http" or not parsed.hostname or not host_is_loopback(parsed.hostname):
        raise ChatsCLIError("AGENTSDOCK_SERVER_URL must be a loopback HTTP URL")
    return server_url


def authority(path: str) -> str:
    authority_path = Path(path).expanduser()
    try:
        mode = authority_path.stat().st_mode & 0o777
        if mode & 0o077:
            raise ChatsCLIError("authority file permissions are unsafe")
        payload = json.loads(authority_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ChatsCLIError(f"could not read authority file: {exc}") from exc
    token = str(payload.get("provider_capability") or payload.get("capability") or "")
    if not token:
        raise ChatsCLIError("authority file is invalid")
    return token


def provider_headers(capability: str) -> dict[str, str]:
    """Return the one canonical header accepted by agent-helper routes.

    The retired cross-chat-specific header is intentionally omitted.  The
    server rejects requests that mix legacy and current authority names so a
    browser or stale helper cannot smuggle ambiguous credentials.
    """

    return {
        "Accept": "application/json",
        "X-AgentsDock-Provider-Capability": capability,
    }


def post_json(
    path: str,
    payload: dict[str, Any],
    capability: str,
) -> dict[str, Any]:
    server_url = environment()
    body = json.dumps(payload).encode("utf-8")
    headers = {
        **provider_headers(capability),
        "Content-Type": "application/json",
    }
    request = urllib.request.Request(
        f"{server_url}{path}",
        data=body,
        headers=headers,
        method="POST",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirectHandler(),
    )
    promotion_deadline = time.monotonic() + 10.0
    transport_retry = 0
    while True:
        try:
            socket_timeout = (
                float(payload.get("response_timeout_seconds") or 0)
                + LIVE_RESPONSE_SOCKET_GRACE_SECONDS
                if payload.get("wait_for_response") is True
                else 30
            )
            with opener.open(request, timeout=socket_timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read().decode("utf-8", errors="replace")
            except (OSError, http.client.IncompleteRead) as read_exc:
                retryable = bool(payload.get("idempotency_key"))
                if (
                    retryable
                    and transport_retry
                    < len(IDEMPOTENT_POST_RETRY_DELAYS_SECONDS)
                ):
                    delay = IDEMPOTENT_POST_RETRY_DELAYS_SECONDS[
                        transport_retry
                    ]
                    transport_retry += 1
                    time.sleep(delay)
                    continue
                raise ChatsCLIError(
                    "could not confirm whether AgentsServer accepted the "
                    "request because its error response was truncated; do "
                    "not resend it with different wording"
                ) from read_exc
            try:
                detail = json.loads(raw).get("detail") or raw
            except json.JSONDecodeError:
                detail = raw
            if (
                exc.code == 409
                and detail == "agent chat access is waiting for turn promotion"
                and time.monotonic() < promotion_deadline
            ):
                # The body and idempotency key are identical on every attempt.
                # Promotion has made no durable target effect yet.
                time.sleep(0.05)
                continue
            raise ChatsCLIError(
                f"server rejected handoff ({exc.code}): {detail or exc.reason}"
            ) from exc
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            http.client.IncompleteRead,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            retryable = bool(payload.get("idempotency_key"))
            if (
                retryable
                and transport_retry < len(IDEMPOTENT_POST_RETRY_DELAYS_SECONDS)
            ):
                delay = IDEMPOTENT_POST_RETRY_DELAYS_SECONDS[transport_retry]
                transport_retry += 1
                # Reuse the byte-identical request and idempotency key. The
                # prior server attempt may still commit after its socket dies.
                time.sleep(delay)
                continue
            detail = getattr(exc, "reason", exc)
            if retryable:
                raise ChatsCLIError(
                    "could not confirm whether AgentsServer accepted the "
                    "request after retrying the same idempotency key; do not "
                    f"resend it with different wording: {detail}"
                ) from exc
            raise ChatsCLIError(
                f"could not reach AgentsServer: {detail}"
            ) from exc
    if not isinstance(result, dict):
        raise ChatsCLIError("AgentsServer returned an invalid response")
    return result


def get_json(
    path: str,
    capability: str,
    *,
    timeout: float = 30,
) -> dict[str, Any]:
    server_url = environment()
    request = urllib.request.Request(
        f"{server_url}{path}",
        headers=provider_headers(capability),
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirectHandler(),
    )
    transport_retry = 0
    while True:
        try:
            with opener.open(request, timeout=timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read().decode("utf-8", errors="replace")
            except (OSError, http.client.IncompleteRead) as read_exc:
                if transport_retry < len(IDEMPOTENT_GET_RETRY_DELAYS_SECONDS):
                    delay = IDEMPOTENT_GET_RETRY_DELAYS_SECONDS[
                        transport_retry
                    ]
                    transport_retry += 1
                    time.sleep(delay)
                    continue
                raise ChatsCLIError(
                    "AgentsServer returned a truncated error response after "
                    "retrying the exact live-response lease"
                ) from read_exc
            try:
                detail = json.loads(raw).get("detail") or raw
            except json.JSONDecodeError:
                detail = raw
            raise ChatsCLIError(
                f"server rejected request ({exc.code}): {detail or exc.reason}"
            ) from exc
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            http.client.IncompleteRead,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            if transport_retry < len(IDEMPOTENT_GET_RETRY_DELAYS_SECONDS):
                delay = IDEMPOTENT_GET_RETRY_DELAYS_SECONDS[transport_retry]
                transport_retry += 1
                # GET is side-effect free and the live-response URL contains
                # the same exact lease on every attempt. The server retains a
                # completed result briefly for this replay window.
                time.sleep(delay)
                continue
            raise ChatsCLIError(
                f"could not reach AgentsServer: {getattr(exc, 'reason', exc)}"
            ) from exc
    if not isinstance(result, dict):
        raise ChatsCLIError("AgentsServer returned an invalid response")
    return result


def await_live_response(
    receipt: dict[str, Any],
    capability: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    exchange_id = str(receipt.get("exchange_id") or "")
    inbound_leg_id = str(receipt.get("inbound_leg_id") or "")
    lease_id = str(receipt.get("live_response_lease_id") or "")
    query = urllib.parse.urlencode({
        "lease_id": lease_id,
        "timeout_seconds": timeout_seconds,
    })
    result = get_json(
        "/api/agent/cross-chat/exchanges/"
        f"{urllib.parse.quote(exchange_id, safe='')}/legs/"
        f"{urllib.parse.quote(inbound_leg_id, safe='')}/live-response?{query}",
        capability,
        timeout=timeout_seconds + LIVE_RESPONSE_SOCKET_GRACE_SECONDS,
    )
    answer_keys = {
        "ok", "exchange_id", "inbound_leg_id", "body", "request_response",
    }
    deferred_keys = {
        "ok", "exchange_id", "inbound_leg_id", "deferred", "delivery",
        "message",
    }
    valid_answer = (
        set(result) == answer_keys
        and isinstance(result.get("body"), str)
        and isinstance(result.get("request_response"), bool)
    )
    valid_deferred = (
        set(result) == deferred_keys
        and result.get("deferred") is True
        and result.get("delivery") == "asynchronous"
        and isinstance(result.get("message"), str)
    )
    if (
        not (valid_answer or valid_deferred)
        or result.get("ok") is not True
        or result.get("exchange_id") != exchange_id
        or not isinstance(result.get("inbound_leg_id"), str)
    ):
        raise ChatsCLIError("AgentsServer returned an invalid live response")
    return result


def list_routes(args: argparse.Namespace) -> dict[str, Any]:
    capability = authority(args.authority_file)
    result = get_json("/api/agent/cross-chat/routes", capability)
    routes = result.get("routes")
    if not isinstance(routes, list) or any(
        not isinstance(route, dict) for route in routes
    ):
        raise ChatsCLIError("AgentsServer returned an invalid route list")
    return result


def send_action(args: argparse.Namespace, action: str) -> dict[str, Any]:
    capability = authority(args.authority_file)
    message = str(args.message or "").strip()
    if not message:
        raise ChatsCLIError("--message must not be empty")
    route = str(getattr(args, "route", None) or "")
    target = str(getattr(args, "target", None) or "")
    if bool(route) == bool(target):
        raise ChatsCLIError("provide exactly one of --route or --target")
    destination = route if route else target
    live_wait = (
        action == "request_reply"
        and not bool(getattr(args, "async_response", False))
    )
    stable_key = "cli_" + hashlib.sha256(
        (
            f"{capability}\0{action}\0"
            f"{'route' if route else 'target'}\0{destination}\0"
            f"{int(live_wait)}\0{message}"
        ).encode("utf-8")
    ).hexdigest()
    payload: dict[str, Any] = {
        "action": action,
        "body": message,
        "idempotency_key": args.idempotency_key or stable_key,
        "artifact_grants": [],
    }
    if live_wait:
        payload["wait_for_response"] = True
        payload["response_timeout_seconds"] = int(
            getattr(args, "timeout_seconds", LIVE_RESPONSE_TIMEOUT_SECONDS)
        )
    if route:
        path = (
            "/api/agent/cross-chat/routes/"
            f"{urllib.parse.quote(route, safe='')}/handoffs"
        )
    else:
        path = "/api/agent/cross-chat/handoffs"
        payload["target_session_id"] = target
    result = post_json(path, payload, capability)
    minimal_expected = {"ok", "action", "accepted"}
    if route:
        minimal_expected.add("route_id")
    expected = set(minimal_expected)
    deferred_expected = set(minimal_expected)
    wait_expected = set(minimal_expected)
    if live_wait:
        expected.update({
            "exchange_id",
            "inbound_leg_id",
            "body",
            "request_response",
        })
        wait_expected.update({
            "exchange_id",
            "inbound_leg_id",
            "live_response_lease_id",
        })
        deferred_expected.update({
            "exchange_id",
            "inbound_leg_id",
            "deferred",
            "delivery",
            "message",
        })
        if frozenset(result) == frozenset(wait_expected):
            live_result = await_live_response(
                result,
                capability,
                int(payload["response_timeout_seconds"]),
            )
            result = {
                **{key: result[key] for key in minimal_expected},
                **live_result,
            }
        elif frozenset(result) == frozenset(minimal_expected):
            raise ChatsCLIError(
                "AgentsServer does not support a live response for this route"
            )
    has_live_response = live_wait and frozenset(result) == frozenset(expected)
    has_deferred_response = (
        live_wait and frozenset(result) == frozenset(deferred_expected)
    )
    if route:
        if (
            frozenset(result) not in {
                frozenset(minimal_expected),
                frozenset(expected),
                frozenset(deferred_expected),
            }
            or result.get("ok") is not True
            or result.get("route_id") != route
            or result.get("action") != action
            or result.get("accepted") is not True
            or (has_live_response and not isinstance(result.get("body"), str))
            or (
                has_deferred_response
                and (
                    result.get("deferred") is not True
                    or result.get("delivery") != "asynchronous"
                )
            )
        ):
            raise ChatsCLIError("AgentsServer returned an invalid route handoff response")
    else:
        if (
            frozenset(result) not in {
                frozenset(minimal_expected),
                frozenset(expected),
                frozenset(deferred_expected),
            }
            or result.get("ok") is not True
            or result.get("action") != action
            or result.get("accepted") is not True
            or (has_live_response and not isinstance(result.get("body"), str))
            or (
                has_deferred_response
                and (
                    result.get("deferred") is not True
                    or result.get("delivery") != "asynchronous"
                )
            )
        ):
            raise ChatsCLIError("AgentsServer returned an invalid direct handoff response")
    return result


def send(args: argparse.Namespace) -> dict[str, Any]:
    return send_action(args, "instruction")


def ask(args: argparse.Namespace) -> dict[str, Any]:
    return send_action(args, "request_reply")


def respond(args: argparse.Namespace) -> dict[str, Any]:
    capability = authority(args.authority_file)
    message = str(args.message or "").strip()
    if not message:
        raise ChatsCLIError("--message must not be empty")
    request_response = bool(args.request_response)
    async_response = bool(getattr(args, "async_response", False))
    if async_response and not request_response:
        raise ChatsCLIError("--async-response requires --request-response")
    live_wait = request_response and not async_response
    stable_key = "cli_" + hashlib.sha256(
        (
            f"{capability}\0respond\0{args.exchange}\0{args.inbound_leg}\0"
            f"{int(request_response)}\0{int(live_wait)}\0{message}"
        ).encode("utf-8")
    ).hexdigest()
    payload = {
        "inbound_leg_id": args.inbound_leg,
        "body": message,
        "request_response": request_response,
        "idempotency_key": args.idempotency_key or stable_key,
        "artifact_grants": [],
    }
    if live_wait:
        payload["wait_for_response"] = True
        payload["response_timeout_seconds"] = int(
            getattr(args, "timeout_seconds", LIVE_RESPONSE_TIMEOUT_SECONDS)
        )
    result = post_json(
        f"/api/agent/cross-chat/exchanges/{urllib.parse.quote(args.exchange, safe='')}/responses",
        payload,
        capability,
    )
    minimal_expected = {"ok", "action", "accepted"}
    expected = set(minimal_expected)
    deferred_expected = set(minimal_expected)
    wait_expected = set(minimal_expected)
    if live_wait:
        expected.update({
            "exchange_id",
            "inbound_leg_id",
            "body",
            "request_response",
        })
        wait_expected.update({
            "exchange_id",
            "inbound_leg_id",
            "live_response_lease_id",
        })
        deferred_expected.update({
            "exchange_id",
            "inbound_leg_id",
            "deferred",
            "delivery",
            "message",
        })
        if frozenset(result) == frozenset(wait_expected):
            live_result = await_live_response(
                result,
                capability,
                int(payload["response_timeout_seconds"]),
            )
            result = {**result, **live_result}
            result.pop("live_response_lease_id", None)
        elif frozenset(result) == frozenset(minimal_expected):
            raise ChatsCLIError(
                "AgentsServer does not support a live follow-up response"
            )
    has_live_response = live_wait and frozenset(result) == frozenset(expected)
    has_deferred_response = (
        live_wait and frozenset(result) == frozenset(deferred_expected)
    )
    if (
        frozenset(result) not in {
            frozenset(minimal_expected),
            frozenset(expected),
            frozenset(deferred_expected),
        }
        or result.get("ok") is not True
        or result.get("action") != "response"
        or result.get("accepted") is not True
        or (has_live_response and not isinstance(result.get("body"), str))
        or (
            has_deferred_response
            and (
                result.get("deferred") is not True
                or result.get("delivery") != "asynchronous"
            )
        )
    ):
        raise ChatsCLIError(
            "AgentsServer returned an invalid cross-chat response"
        )
    return result


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Contact an eligible chat on this AgentsDock server."
    )
    root.add_argument("--authority-file", required=True)
    commands = root.add_subparsers(dest="command", required=True)
    list_command = commands.add_parser(
        "list",
        help="list eligible same-server chats for this live run",
    )
    list_command.set_defaults(handler=list_routes)
    command = commands.add_parser("send", help="send one authorized instruction")
    send_destination = command.add_mutually_exclusive_group(required=True)
    send_destination.add_argument("--route")
    send_destination.add_argument("--target")
    command.add_argument("--message", required=True)
    command.add_argument("--idempotency-key")
    command.set_defaults(handler=send)
    ask_command = commands.add_parser("ask", help="start one bounded request/reply exchange")
    ask_destination = ask_command.add_mutually_exclusive_group(required=True)
    ask_destination.add_argument("--route")
    ask_destination.add_argument("--target")
    ask_command.add_argument("--message", required=True)
    ask_command.add_argument("--idempotency-key")
    ask_command.add_argument(
        "--async-response",
        action="store_true",
        help=(
            "return after durable send and receive the peer reply in a later "
            "turn (required for secure-peer routes)"
        ),
    )
    ask_command.add_argument(
        "--timeout-seconds",
        type=int,
        choices=range(1, 3601),
        default=LIVE_RESPONSE_TIMEOUT_SECONDS,
    )
    ask_command.set_defaults(handler=ask)
    response_command = commands.add_parser("respond", help="respond to the exact inbound exchange leg")
    response_command.add_argument("--exchange", required=True)
    response_command.add_argument("--inbound-leg", required=True)
    response_command.add_argument("--message", required=True)
    response_command.add_argument("--request-response", action="store_true")
    response_command.add_argument(
        "--async-response",
        action="store_true",
        help=(
            "with --request-response, receive the peer reply in a later turn "
            "instead of waiting on this provider call"
        ),
    )
    response_command.add_argument("--idempotency-key")
    response_command.add_argument(
        "--timeout-seconds",
        type=int,
        choices=range(1, 3601),
        default=LIVE_RESPONSE_TIMEOUT_SECONDS,
    )
    response_command.set_defaults(handler=respond)
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        print(json.dumps(args.handler(args), ensure_ascii=False))
        return 0
    except ChatsCLIError as exc:
        print(f"agentsdock-chats: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
