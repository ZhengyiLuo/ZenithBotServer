import argparse
import asyncio
import io
import json
import logging
import tempfile
import threading
import unittest
import urllib.error
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from starlette.requests import Request

import agent_server
import agentsdock_mail
from agentsdock_team_hub.store import HubError, HubStore


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class AgentsDockMailCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def authority(self, mode: int = 0o600) -> str:
        path = self.root / "authority.json"
        path.write_text(json.dumps({
            "provider_capability": "provider-secret",
            "source_session_id": "source",
        }))
        path.chmod(mode)
        return str(path)

    def test_list_stays_loopback_and_disables_proxy_and_redirects(self) -> None:
        requests = []

        class Opener:
            def open(self, request, timeout):
                requests.append((request, timeout))
                return FakeResponse({"routes": [], "max_sends_per_run": 20})

        with (
            patch.dict("os.environ", {
                "AGENTSDOCK_SERVER_URL": "http://127.0.0.1:7850",
                "HTTP_PROXY": "http://proxy.invalid:8080",
            }, clear=True),
            patch.object(
                agentsdock_mail.urllib.request,
                "build_opener",
                return_value=Opener(),
            ) as build_opener,
        ):
            result = agentsdock_mail.list_routes(argparse.Namespace(
                authority_file=self.authority(),
            ))
        self.assertEqual(result["routes"], [])
        self.assertEqual(requests[0][1], 30)
        self.assertEqual(
            requests[0][0].full_url,
            "http://127.0.0.1:7850/api/agent/team-mail/routes",
        )
        handlers = build_opener.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], agentsdock_mail.NoRedirectHandler)

    def test_remote_url_and_unsafe_authority_are_rejected(self) -> None:
        with patch.dict("os.environ", {
            "AGENTSDOCK_SERVER_URL": "http://10.0.0.8:7850",
        }, clear=True):
            with self.assertRaises(agentsdock_mail.MailCLIError):
                agentsdock_mail.list_routes(argparse.Namespace(
                    authority_file=self.authority(),
                ))
        with patch.dict("os.environ", {
            "AGENTSDOCK_SERVER_URL": "http://127.0.0.1:7850",
        }, clear=True):
            with self.assertRaises(agentsdock_mail.MailCLIError):
                agentsdock_mail.list_routes(argparse.Namespace(
                    authority_file=self.authority(0o644),
                ))

    def test_send_uses_opaque_route_and_strict_receipt(self) -> None:
        route_id = "mail_" + "a" * 32
        calls = []

        def request(method, path, capability, payload=None):
            calls.append((method, path, capability, payload))
            return {
                "ok": True,
                "route_id": route_id,
                "kind": "message",
                "accepted": True,
                "duplicate": False,
            }

        args = argparse.Namespace(
            authority_file=self.authority(),
            route=route_id,
            kind="message",
            idempotency_key=None,
        )
        with (
            patch.object(agentsdock_mail, "_request_json", side_effect=request),
            patch.object(agentsdock_mail.sys, "stdin", io.StringIO(
                "  Please report status  "
            )),
        ):
            first = agentsdock_mail.send(args)
        with (
            patch.object(agentsdock_mail, "_request_json", side_effect=request),
            patch.object(agentsdock_mail.sys, "stdin", io.StringIO(
                "  Please report status  "
            )),
        ):
            second = agentsdock_mail.send(args)
        self.assertTrue(first["accepted"])
        self.assertEqual(calls[0][1], f"/api/agent/team-mail/routes/{route_id}")
        self.assertEqual(calls[0][3]["message"], "Please report status")
        self.assertEqual(
            calls[0][3]["idempotency_key"],
            calls[1][3]["idempotency_key"],
        )

    def test_send_rejects_request_kind_even_when_called_without_parser(self) -> None:
        with patch.object(agentsdock_mail.sys, "stdin", io.StringIO("body")):
            with self.assertRaises(agentsdock_mail.MailCLIError):
                agentsdock_mail.send(argparse.Namespace(
                    authority_file=self.authority(),
                    route="mail_" + "a" * 32,
                    kind="request",
                    idempotency_key=None,
                ))

    def test_send_rejects_tty_invalid_utf8_and_oversize_stdin(self) -> None:
        route_id = "mail_" + "a" * 32
        args = argparse.Namespace(
            authority_file=self.authority(),
            route=route_id,
            kind="message",
            idempotency_key=None,
        )

        class TTY(io.StringIO):
            def isatty(self) -> bool:
                return True

        with patch.object(agentsdock_mail.sys, "stdin", TTY("secret")):
            with self.assertRaises(agentsdock_mail.MailCLIError):
                agentsdock_mail.send(args)
        with patch.object(
            agentsdock_mail.sys,
            "stdin",
            io.TextIOWrapper(io.BytesIO(b"\xff"), encoding="utf-8"),
        ):
            with self.assertRaises(agentsdock_mail.MailCLIError):
                agentsdock_mail.send(args)
        with patch.object(
            agentsdock_mail.sys,
            "stdin",
            io.StringIO("x" * (agentsdock_mail.MAIL_BODY_MAX_BYTES + 1)),
        ):
            with self.assertRaises(agentsdock_mail.MailCLIError):
                agentsdock_mail.send(args)


class ProviderTeamMailTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous_sessions = agent_server.STORE.sessions
        self.previous_current = agent_server.CURRENT_TURNS
        self.previous_active = agent_server.ACTIVE
        self.previous_busy = agent_server.BUSY_SESSIONS
        self.previous_capabilities = agent_server.CROSS_CHAT_CAPABILITIES
        self.previous_authority_root = agent_server.CROSS_CHAT_AUTHORITY_ROOT
        self.previous_agent_token = agent_server.AGENT_TOKEN
        agent_server.STORE.sessions = {
            "source": {"id": "source", "backend": "codex"},
        }
        agent_server.CURRENT_TURNS = {"source": {"run_id": "run_mail"}}
        agent_server.ACTIVE = {"source": {"run_id": "run_mail"}}
        agent_server.BUSY_SESSIONS = {"source"}
        agent_server.CROSS_CHAT_CAPABILITIES = {}
        agent_server.CROSS_CHAT_AUTHORITY_ROOT = self.root / "authority"
        agent_server.AGENT_TOKEN = "test-agent-token"
        path = await agent_server.issue_cross_chat_capability(
            "source",
            "run_mail",
            [],
            actions={"team_mail"},
            team_mail_enabled=True,
        )
        payload = json.loads(path.read_text())
        self.token = payload["provider_capability"]
        self.token_hash = agent_server.hashlib.sha256(
            self.token.encode()
        ).hexdigest()

    async def asyncTearDown(self) -> None:
        agent_server.STORE.sessions = self.previous_sessions
        agent_server.CURRENT_TURNS = self.previous_current
        agent_server.ACTIVE = self.previous_active
        agent_server.BUSY_SESSIONS = self.previous_busy
        agent_server.CROSS_CHAT_CAPABILITIES = self.previous_capabilities
        agent_server.CROSS_CHAT_AUTHORITY_ROOT = self.previous_authority_root
        agent_server.AGENT_TOKEN = self.previous_agent_token
        self.temporary.cleanup()

    def request(self, method: str = "GET", path: str = "/api/agent/team-mail/routes") -> Request:
        return Request({
            "type": "http",
            "method": method,
            "path": path,
            "headers": [(b"x-agentsdock-provider-capability", self.token.encode())],
            "query_string": b"",
            "scheme": "http",
            "server": ("127.0.0.1", 7850),
            "client": ("127.0.0.1", 41000),
        })

    async def activate_strict_command(self, prompt: str) -> Path:
        command = agent_server.provider_team_mail_strict_command(None, prompt)
        self.assertIsNotNone(command)
        path = await agent_server.issue_cross_chat_capability(
            "source",
            "run_mail",
            [],
            actions={"team_mail"},
            team_mail_enabled=True,
            team_mail_command=command,
        )
        payload = json.loads(path.read_text())
        self.token = payload["provider_capability"]
        self.token_hash = agent_server.hashlib.sha256(
            self.token.encode()
        ).hexdigest()
        return path

    @staticmethod
    def profile() -> dict:
        return {
            "realm": "secure_peer",
            "connection_id": str(uuid.uuid4()),
            "team_id": "team_private",
            "hub_id": "hub_private",
            "host_server_identity": "host_private",
            "certificate_fingerprint": "fingerprint_private",
            "destination_kind": "server",
            "destination_id": "node_private",
            "display_name": "Remote server",
            "backend": None,
        }

    async def routes(self) -> tuple[str, dict]:
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[self.profile()],
        ) as snapshot:
            listed = await agent_server.list_provider_team_mail_routes(self.request())
        snapshot.assert_called_once_with()
        self.assertEqual(len(listed["routes"]), 1)
        route = listed["routes"][0]
        self.assertNotIn("destination_id", route)
        self.assertNotIn("connection_id", route)
        self.assertNotIn("hub_id", route)
        return route["route_id"], route

    async def test_routes_are_lazy_frozen_and_live_run_scoped(self) -> None:
        route_id, _route = await self.routes()
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            side_effect=AssertionError("snapshot must be frozen"),
        ):
            listed = await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(listed["routes"][0]["route_id"], route_id)
        agent_server.CURRENT_TURNS["source"]["run_id"] = "run_other"
        with self.assertRaises(HTTPException) as raised:
            await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(raised.exception.status_code, 403)

    async def test_routes_filter_legacy_agent_profiles_and_project_server_only(self) -> None:
        server = self.profile()
        agent = {
            **self.profile(),
            "destination_kind": "agent",
            "destination_id": "agent_private",
            "display_name": "Remote agent",
            "backend": "codex",
        }
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[agent, server],
        ):
            listed = await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(len(listed["routes"]), 1)
        self.assertEqual(listed["routes"][0]["kind"], "server")
        self.assertIsNone(listed["routes"][0]["backend"])

        capability = agent_server.CROSS_CHAT_CAPABILITIES[self.token_hash]
        frozen = capability["team_mail_routes"]
        self.assertTrue(frozen)
        self.assertTrue(
            all(
                profile["destination_kind"] == "server"
                for profile in frozen.values()
            )
        )
        frozen["mail_" + ("f" * 32)] = agent
        relisted = await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(len(relisted["routes"]), 1)
        self.assertEqual(relisted["routes"][0]["kind"], "server")

        forged_projection = agent_server.provider_team_mail_route_projection(
            "mail_" + ("a" * 32),
            agent,
        )
        self.assertEqual(forged_projection["kind"], "server")
        self.assertIsNone(forged_projection["backend"])

    async def test_route_list_rejects_missing_capability_and_non_loopback_client(self) -> None:
        missing = Request({
            "type": "http",
            "method": "GET",
            "path": "/api/agent/team-mail/routes",
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("127.0.0.1", 7850),
            "client": ("127.0.0.1", 41000),
        })
        with self.assertRaises(HTTPException) as no_capability:
            await agent_server.list_provider_team_mail_routes(missing)
        self.assertEqual(no_capability.exception.status_code, 403)

        remote = Request({
            "type": "http",
            "method": "GET",
            "path": "/api/agent/team-mail/routes",
            "headers": [
                (b"x-agentsdock-provider-capability", self.token.encode())
            ],
            "query_string": b"",
            "scheme": "http",
            "server": ("127.0.0.1", 7850),
            "client": ("192.0.2.20", 41000),
        })
        with self.assertRaises(HTTPException) as not_loopback:
            await agent_server.list_provider_team_mail_routes(remote)
        self.assertEqual(not_loopback.exception.status_code, 403)

    async def test_route_snapshot_fails_closed_above_bound(self) -> None:
        profiles = [self.profile(), self.profile()]
        with (
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "agent_mail_route_profiles",
                return_value=profiles,
            ),
            patch.object(agent_server, "PROVIDER_TEAM_MAIL_ROUTE_LIMIT", 1),
        ):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(raised.exception.status_code, 409)
        capability = agent_server.CROSS_CHAT_CAPABILITIES[self.token_hash]
        self.assertIsNone(capability["team_mail_routes"])

    async def test_duplicate_destination_names_are_disambiguated_by_network(self) -> None:
        first = {**self.profile(), "display_name": "MBA", "network_display_name": "Alpha"}
        second = {**self.profile(), "display_name": "MBA", "network_display_name": "Beta"}
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[first, second],
        ):
            listed = await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(
            {(route["display_name"], route["network_display_name"]) for route in listed["routes"]},
            {("MBA", "Alpha"), ("MBA", "Beta")},
        )
        self.assertEqual(len({route["route_id"] for route in listed["routes"]}), 2)

    async def test_strict_server_command_matches_one_exact_case_sensitive_server(self) -> None:
        authority_path = await self.activate_strict_command(
            "/mail server MBA exact private body"
        )
        self.assertNotIn("MBA", authority_path.read_text())
        self.assertNotIn("exact private body", authority_path.read_text())
        server = {
            **self.profile(),
            "display_name": "MBA",
            "network_display_name": "Alpha",
        }
        agent = {
            **self.profile(),
            "destination_kind": "agent",
            "destination_id": "agent_private",
            "display_name": "MBA",
            "backend": "codex",
        }
        wrong_case = {
            **self.profile(),
            "destination_id": "node_wrong_case",
            "display_name": "mba",
            "network_display_name": "Beta",
        }
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[agent, wrong_case, server],
        ):
            listed = await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(len(listed["routes"]), 1)
        self.assertEqual(listed["routes"][0]["kind"], "server")
        self.assertEqual(listed["routes"][0]["display_name"], "MBA")
        self.assertEqual(listed["routes"][0]["network_display_name"], "Alpha")

    async def test_strict_server_command_fails_closed_on_zero_or_duplicate_matches(self) -> None:
        await self.activate_strict_command("/mail server MBA exact body")
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[{**self.profile(), "display_name": "mba"}],
        ):
            with self.assertRaises(HTTPException) as missing:
                await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(missing.exception.status_code, 404)
        capability = agent_server.CROSS_CHAT_CAPABILITIES[self.token_hash]
        self.assertEqual(capability["team_mail_routes"], {})

        await self.activate_strict_command("/mail server MBA exact body")
        first = {
            **self.profile(),
            "destination_id": "node_alpha",
            "display_name": "MBA",
            "network_display_name": "Alpha",
        }
        second = {
            **self.profile(),
            "destination_id": "node_beta",
            "display_name": "MBA",
            "network_display_name": "Beta",
        }
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[first, second],
        ):
            with self.assertRaises(HTTPException) as ambiguous:
                await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(ambiguous.exception.status_code, 409)
        with self.assertRaises(HTTPException) as frozen_ambiguous:
            await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(frozen_ambiguous.exception.status_code, 409)

    async def test_strict_server_command_enforces_body_kind_and_one_effect(self) -> None:
        await self.activate_strict_command("/mail server MBA exact body")
        profile = {**self.profile(), "display_name": "MBA"}
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[profile],
        ):
            listed = await agent_server.list_provider_team_mail_routes(self.request())
        route_id = listed["routes"][0]["route_id"]
        request = self.request("POST", f"/api/agent/team-mail/routes/{route_id}")

        with self.assertRaises(HTTPException) as wrong_kind:
            await agent_server.send_provider_team_mail(
                route_id,
                agent_server.AgentTeamMailRequest.model_construct(
                    kind="request",
                    message="exact body",
                    idempotency_key="strict.kind.0001",
                ),
                request,
            )
        self.assertEqual(wrong_kind.exception.status_code, 422)
        with self.assertRaises(HTTPException) as wrong_body:
            await agent_server.send_provider_team_mail(
                route_id,
                agent_server.AgentTeamMailRequest(
                    kind="message",
                    message="rewritten body",
                    idempotency_key="strict.body.0001",
                ),
                request,
            )
        self.assertEqual(wrong_body.exception.status_code, 422)

        exact = agent_server.AgentTeamMailRequest(
            kind="message",
            message="exact body",
            idempotency_key="strict.send.0001",
        )
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "send_agent_mail",
            return_value={"item": {"id": "private_item"}},
        ) as send:
            accepted = await agent_server.send_provider_team_mail(
                route_id, exact, request
            )
            replay = await agent_server.send_provider_team_mail(
                route_id, exact, request
            )
            with self.assertRaises(HTTPException) as second_send:
                await agent_server.send_provider_team_mail(
                    route_id,
                    agent_server.AgentTeamMailRequest(
                        kind="message",
                        message="exact body",
                        idempotency_key="strict.send.0002",
                    ),
                    request,
                )
        self.assertTrue(accepted["accepted"])
        self.assertFalse(accepted["duplicate"])
        self.assertTrue(replay["duplicate"])
        self.assertEqual(second_send.exception.status_code, 429)
        send.assert_called_once()

    async def test_send_rejects_authority_expiring_after_route_snapshot(self) -> None:
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[self.profile()],
        ):
            snapshot = await agent_server.provider_team_mail_routes(self.request())
        route_id = next(iter(snapshot[2]))
        request = self.request("POST", f"/api/agent/team-mail/routes/{route_id}")

        async def expire_in_gap(_request):
            capability = agent_server.CROSS_CHAT_CAPABILITIES[self.token_hash]
            capability["expires_at"] = 0
            return snapshot

        with (
            patch.object(
                agent_server,
                "provider_team_mail_routes",
                side_effect=expire_in_gap,
            ),
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "send_agent_mail",
            ) as send,
        ):
            with self.assertRaises(HTTPException) as expired:
                await agent_server.send_provider_team_mail(
                    route_id,
                    agent_server.AgentTeamMailRequest(
                        message="must not send",
                        idempotency_key="expired.gap.0001",
                    ),
                    request,
                )
        self.assertEqual(expired.exception.status_code, 403)
        send.assert_not_called()
        capability = agent_server.CROSS_CHAT_CAPABILITIES[self.token_hash]
        self.assertNotIn("team_mail", capability["actions"])
        self.assertEqual(capability["team_mail_routes"], {})

    async def test_send_rejects_forged_agent_profile_before_reservation(self) -> None:
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[self.profile()],
        ):
            snapshot = await agent_server.provider_team_mail_routes(self.request())
        route_id = next(iter(snapshot[2]))
        forged = {
            **snapshot[2][route_id],
            "destination_kind": "agent",
            "destination_id": "agent_private",
            "backend": "codex",
        }
        capability = agent_server.CROSS_CHAT_CAPABILITIES[self.token_hash]
        capability["team_mail_routes"] = {route_id: forged}
        forged_snapshot = (
            snapshot[0],
            snapshot[1],
            {route_id: forged},
            snapshot[3],
            snapshot[4],
        )
        with (
            patch.object(
                agent_server,
                "provider_team_mail_routes",
                return_value=forged_snapshot,
            ),
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "send_agent_mail",
            ) as send,
        ):
            with self.assertRaises(HTTPException) as rejected:
                await agent_server.send_provider_team_mail(
                    route_id,
                    agent_server.AgentTeamMailRequest(
                        message="must not target an agent",
                        idempotency_key="forged.agent.0001",
                    ),
                    self.request("POST", f"/api/agent/team-mail/routes/{route_id}"),
                )
        self.assertEqual(rejected.exception.status_code, 409)
        send.assert_not_called()
        self.assertEqual(int(capability.get("team_mail_send_count") or 0), 0)
        self.assertFalse(capability.get("team_mail_consumed"))

    async def test_send_rejects_route_generation_or_strict_binding_relaxation(self) -> None:
        await self.activate_strict_command("/mail server MBA exact body")
        profile = {**self.profile(), "display_name": "MBA"}
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[profile],
        ):
            snapshot = await agent_server.provider_team_mail_routes(self.request())
        route_id = next(iter(snapshot[2]))
        request = self.request("POST", f"/api/agent/team-mail/routes/{route_id}")

        async def relax_strict_binding(_request):
            capability = agent_server.CROSS_CHAT_CAPABILITIES[self.token_hash]
            capability["team_mail_command"] = None
            return snapshot

        with (
            patch.object(
                agent_server,
                "provider_team_mail_routes",
                side_effect=relax_strict_binding,
            ),
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "send_agent_mail",
            ) as send,
        ):
            with self.assertRaises(HTTPException) as relaxed:
                await agent_server.send_provider_team_mail(
                    route_id,
                    agent_server.AgentTeamMailRequest(
                        message="rewritten body",
                        idempotency_key="strict.relax.0001",
                    ),
                    request,
                )
        self.assertEqual(relaxed.exception.status_code, 409)
        send.assert_not_called()

        await self.activate_strict_command("/mail server MBA exact body")
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "agent_mail_route_profiles",
            return_value=[profile],
        ):
            snapshot = await agent_server.provider_team_mail_routes(self.request())
        route_id = next(iter(snapshot[2]))
        request = self.request("POST", f"/api/agent/team-mail/routes/{route_id}")

        async def replace_generation(_request):
            capability = agent_server.CROSS_CHAT_CAPABILITIES[self.token_hash]
            capability["team_mail_profile_generation"] = "replacement"
            return snapshot

        with (
            patch.object(
                agent_server,
                "provider_team_mail_routes",
                side_effect=replace_generation,
            ),
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "send_agent_mail",
            ) as send,
        ):
            with self.assertRaises(HTTPException) as changed:
                await agent_server.send_provider_team_mail(
                    route_id,
                    agent_server.AgentTeamMailRequest(
                        message="exact body",
                        idempotency_key="generation.gap.0001",
                    ),
                    request,
                )
        self.assertEqual(changed.exception.status_code, 409)
        send.assert_not_called()

    async def test_expiry_revokes_frozen_routes_and_action(self) -> None:
        await self.routes()
        capability = agent_server.CROSS_CHAT_CAPABILITIES[self.token_hash]
        capability["expires_at"] = 0
        with self.assertRaises(HTTPException) as raised:
            await agent_server.list_provider_team_mail_routes(self.request())
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(capability["team_mail_routes"], {})
        self.assertNotIn("team_mail", capability["actions"])

    async def test_send_deduplicates_and_conflicts_without_exposing_payload(self) -> None:
        route_id, _route = await self.routes()
        sent = []

        def send(profile, **kwargs):
            sent.append((profile, kwargs))
            return {"item": {"id": "private_item"}, "delivery": {"id": "private_delivery"}}

        request = self.request("POST", f"/api/agent/team-mail/routes/{route_id}")
        first_req = agent_server.AgentTeamMailRequest(
            kind="message",
            message="private body",
            idempotency_key="request.same.0001",
        )
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "send_agent_mail",
            side_effect=send,
        ):
            first = await agent_server.send_provider_team_mail(
                route_id, first_req, request
            )
            duplicate = await agent_server.send_provider_team_mail(
                route_id, first_req, request
            )
        self.assertFalse(first["duplicate"])
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(len(sent), 1)
        with self.assertRaises(HTTPException) as raised:
            await agent_server.send_provider_team_mail(
                route_id,
                agent_server.AgentTeamMailRequest(
                    kind="message",
                    message="different private body",
                    idempotency_key="request.same.0001",
                ),
                request,
            )
        self.assertEqual(raised.exception.status_code, 409)
        self.assertNotIn("private", str(raised.exception.detail))

    async def test_legacy_provider_harness_rejects_request_kind(self) -> None:
        route_id, _route = await self.routes()
        request = self.request("POST", f"/api/agent/team-mail/routes/{route_id}")
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "send_agent_mail",
        ) as send:
            with self.assertRaises(HTTPException) as rejected:
                await agent_server.send_provider_team_mail(
                    route_id,
                    agent_server.AgentTeamMailRequest.model_construct(
                        kind="request",
                        message="legacy request",
                        idempotency_key="legacy.request.0001",
                    ),
                    request,
                )
        self.assertEqual(rejected.exception.status_code, 422)
        send.assert_not_called()

    async def test_concurrent_same_key_has_one_effect_and_duplicate_receipt(self) -> None:
        route_id, _route = await self.routes()
        entered = threading.Event()
        release = threading.Event()
        calls = 0

        def send(_profile, **_kwargs):
            nonlocal calls
            calls += 1
            entered.set()
            release.wait(timeout=5)
            return {"item": {"id": "private_item"}}

        req = agent_server.AgentTeamMailRequest(
            message="one effect",
            idempotency_key="request.concurrent.0001",
        )
        request = self.request("POST", f"/api/agent/team-mail/routes/{route_id}")
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "send_agent_mail",
            side_effect=send,
        ):
            first = asyncio.create_task(
                agent_server.send_provider_team_mail(route_id, req, request)
            )
            await asyncio.to_thread(entered.wait, 5)
            second = asyncio.create_task(
                agent_server.send_provider_team_mail(route_id, req, request)
            )
            await asyncio.sleep(0)
            release.set()
            receipts = await asyncio.gather(first, second)
        self.assertEqual(calls, 1)
        self.assertEqual(sorted(item["duplicate"] for item in receipts), [False, True])

    async def test_failing_concurrent_leader_releases_same_key_waiter(self) -> None:
        route_id, _route = await self.routes()
        entered = threading.Event()
        release = threading.Event()
        calls = 0

        def fail(_profile, **_kwargs):
            nonlocal calls
            calls += 1
            entered.set()
            release.wait(timeout=5)
            raise ValueError("private unexpected failure")

        req = agent_server.AgentTeamMailRequest(
            message="one failing effect",
            idempotency_key="request.concurrent.failure.0001",
        )
        request = self.request("POST", f"/api/agent/team-mail/routes/{route_id}")
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "send_agent_mail",
            side_effect=fail,
        ):
            first = asyncio.create_task(
                agent_server.send_provider_team_mail(route_id, req, request)
            )
            await asyncio.to_thread(entered.wait, 5)
            second = asyncio.create_task(
                agent_server.send_provider_team_mail(route_id, req, request)
            )
            await asyncio.sleep(0)
            release.set()
            results = await asyncio.wait_for(
                asyncio.gather(first, second, return_exceptions=True),
                timeout=5,
            )
        self.assertEqual(calls, 1)
        self.assertTrue(all(isinstance(item, HTTPException) for item in results))
        self.assertEqual(
            sorted(item.status_code for item in results),
            [409, 500],
        )
        self.assertNotIn("private", " ".join(str(item.detail) for item in results))

    async def test_utf8_limit_send_cap_and_failure_log_omit_body_and_credentials(self) -> None:
        route_id, _route = await self.routes()
        request = self.request("POST", f"/api/agent/team-mail/routes/{route_id}")
        with self.assertRaises(HTTPException) as too_large:
            await agent_server.send_provider_team_mail(
                route_id,
                agent_server.AgentTeamMailRequest(
                    message="é" * 4_097,
                    idempotency_key="request.bytes.0001",
                ),
                request,
            )
        self.assertEqual(too_large.exception.status_code, 413)

        capability = agent_server.CROSS_CHAT_CAPABILITIES[self.token_hash]
        capability["team_mail_send_count"] = agent_server.PROVIDER_TEAM_MAIL_SEND_LIMIT
        with self.assertRaises(HTTPException) as capped:
            await agent_server.send_provider_team_mail(
                route_id,
                agent_server.AgentTeamMailRequest(
                    message="cap test",
                    idempotency_key="request.cap.0001",
                ),
                request,
            )
        self.assertEqual(capped.exception.status_code, 429)

        capability["team_mail_send_count"] = 0
        secret = "body-secret certificate-secret"
        with (
            self.assertLogs("agents-server", logging.INFO) as logs,
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "send_agent_mail",
                side_effect=HubError("gone", secret, 409),
            ),
        ):
            with self.assertRaises(HTTPException) as rejected:
                await agent_server.send_provider_team_mail(
                    route_id,
                    agent_server.AgentTeamMailRequest(
                        message=secret,
                        idempotency_key="request.log.0001",
                    ),
                    request,
                )
        self.assertNotIn(secret, "\n".join(logs.output))
        self.assertNotIn(secret, str(rejected.exception.detail))

    async def test_committed_send_returns_success_when_turn_stops_during_io(self) -> None:
        route_id, _route = await self.routes()

        def commit_then_stop(_profile, **_kwargs):
            agent_server.CROSS_CHAT_CAPABILITIES.pop(self.token_hash, None)
            agent_server.CURRENT_TURNS["source"]["run_id"] = "run_stopped"
            return {"item": {"id": "private_item"}}

        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "send_agent_mail",
            side_effect=commit_then_stop,
        ):
            result = await agent_server.send_provider_team_mail(
                route_id,
                agent_server.AgentTeamMailRequest(
                    message="commit before stop",
                    idempotency_key="request.stop.0001",
                ),
                self.request("POST", f"/api/agent/team-mail/routes/{route_id}"),
            )
        self.assertTrue(result["accepted"])
        self.assertFalse(result["duplicate"])

    def test_provider_mail_requires_exact_leading_command_on_ordinary_turn(self) -> None:
        self.assertTrue(
            agent_server.provider_turn_may_send_team_mail(None, "/mail")
        )
        self.assertTrue(
            agent_server.provider_turn_may_send_team_mail(
                "", "  /mail send a prepared update"
            )
        )
        strict = agent_server.provider_team_mail_strict_command(
            None,
            "  /mail server MBA preserve   internal spacing  ",
        )
        self.assertEqual(strict, {
            "destination_kind": "server",
            "display_name": "MBA",
            "message": "preserve   internal spacing",
        })
        self.assertTrue(
            agent_server.provider_turn_may_send_team_mail(
                None,
                "/mail server MBA exact body",
            )
        )
        for malformed in (
            "/mail server",
            "/mail server MBA",
            "/mail server MBA   ",
            "/mail server " + ("x" * 161) + " body",
            "/mail server MBA " + ("é" * 4_097),
        ):
            self.assertIsNone(
                agent_server.provider_team_mail_strict_command(None, malformed)
            )
            self.assertFalse(
                agent_server.provider_turn_may_send_team_mail(None, malformed)
            )
        for prompt in (
            "ordinary prompt",
            "/mailbox",
            "please /mail later",
            "",
            None,
        ):
            self.assertFalse(
                agent_server.provider_turn_may_send_team_mail(None, prompt)
            )
        for purpose in (
            "scheduled_job",
            "cross_chat_handoff_delivery",
            "secure_peer_handoff_delivery",
            "handoff_digest",
            "handoff_digest_delivery",
        ):
            self.assertFalse(
                agent_server.provider_turn_may_send_team_mail(
                    purpose, "/mail should remain denied"
                )
            )

    async def test_health_advertises_explicit_bounded_mail_contract(self) -> None:
        with patch.object(agent_server, "AGENT_TOKEN", "configured"):
            health = await agent_server.health()
        self.assertEqual(health["api_contract_version"], 27)
        self.assertEqual(health["capabilities"]["cursor_backend"]["version"], 2)
        capability = health["capabilities"]["agent_team_mail_v1"]
        self.assertTrue(capability["available"])
        self.assertEqual(capability["version"], 1)
        self.assertEqual(capability["explicit_command"], "/mail")
        self.assertEqual(
            capability["command_syntax"],
            "/mail server <name> <message>",
        )
        self.assertTrue(
            capability["features"]["deterministic_server_message_command"]
        )
        self.assertTrue(
            capability["features"]["exact_case_sensitive_server_name"]
        )
        self.assertTrue(capability["features"]["single_committed_send"])
        self.assertTrue(capability["features"]["message_only"])
        self.assertEqual(capability["max_sends_per_run"], 4)
        self.assertEqual(capability["max_body_bytes"], 8_192)

    async def test_native_steer_gate_uses_new_exact_prompt_not_stale_queue_prompt(self) -> None:
        base = {
            "purpose": None,
            "chat_references": [],
            "cross_chat_obligation_ids": [],
            "cross_chat_exchange_ids": [],
            "provider_cross_chat_route_snapshot": [],
            "secure_peer_route_snapshots": [],
        }
        _prompt, denied_path = await agent_server.issue_native_steer_provider_authority(
            "source",
            "run_native_denied",
            {**base, "prompt": "/mail stale queued prompt"},
            "ordinary new prompt",
            "nonce-denied",
        )
        denied_payload = json.loads(denied_path.read_text())
        denied_hash = agent_server.hashlib.sha256(
            denied_payload["provider_capability"].encode()
        ).hexdigest()
        self.assertNotIn(
            "team_mail",
            agent_server.CROSS_CHAT_CAPABILITIES[denied_hash]["actions"],
        )

        provider_prompt, allowed_path = (
            await agent_server.issue_native_steer_provider_authority(
                "source",
                "run_native_allowed",
                {**base, "prompt": "ordinary stale queued prompt"},
                "/mail server MBA exact body",
                "nonce-allowed",
            )
        )
        allowed_payload = json.loads(allowed_path.read_text())
        allowed_hash = agent_server.hashlib.sha256(
            allowed_payload["provider_capability"].encode()
        ).hexdigest()
        self.assertIn(
            "team_mail",
            agent_server.CROSS_CHAT_CAPABILITIES[allowed_hash]["actions"],
        )
        self.assertEqual(
            agent_server.CROSS_CHAT_CAPABILITIES[allowed_hash][
                "team_mail_command"
            ],
            {
                "destination_kind": "server",
                "display_name": "MBA",
                "message": "exact body",
            },
        )
        self.assertNotIn("MBA", allowed_path.read_text())
        self.assertNotIn("exact body", allowed_path.read_text())
        # The per-turn block is compact: it names the pre-bound mail grant,
        # while the usage rules live once in the thread-level instructions.
        self.assertIn("team_mail=prebound", provider_prompt)
        self.assertIn("/mail server MBA exact body", provider_prompt)
        self.assertIn(
            "pre-bound",
            agent_server.PROVIDER_AUTHORITY_USAGE_INSTRUCTIONS,
        )


class LocalAgentMailClaimsTests(unittest.TestCase):
    def test_local_agent_mail_is_host_scoped_and_agent_authorship_is_retired(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = HubStore(
                Path(temporary),
                managed_host_identity="host_server_identity",
                managed_server_instance_id="host_instance",
            )
            proof = (Path(temporary) / "bootstrap-owner.proof").read_text().strip()
            bootstrap = store.bootstrap(
                proof,
                "owner@example.test",
                "Owner",
                "Host",
            )
            owner = store.verify_access(bootstrap["access_token"])
            team_id = bootstrap["teams"][0]["id"]
            peer_id = str(uuid.uuid4())
            store.ensure_secure_peer_service(
                peer_id=peer_id,
                peer_server_identity="peer_server_identity",
                team_id=team_id,
                display_name="Peer",
            )
            store.record_secure_peer_heartbeat(peer_id, team_id)
            projection = store.get_network(owner, team_id, limit=100)
            host = next(item for item in projection["servers"] if item["is_host"])
            peer = next(item for item in projection["servers"] if not item["is_host"])
            host_agent = store.register_network_agent(owner, team_id, {
                "external_agent_id": "host-chat",
                "backend": "codex",
                "display_name": "Host agent",
                "idempotency_key": "host-agent-register-0001",
            })["agent"]
            claims = store.local_agent_mail_claims(team_id)
            with patch.object(store, "_charge_rate_bucket") as charge:
                store._charge_network_peer_write(
                    MagicMock(), claims, team_id, 17, 12345
                )
            self.assertEqual(charge.call_count, 2)
            for call in charge.call_args_list:
                self.assertEqual(
                    call.kwargs["subject_key"],
                    "local-agent-mail:service_local_control",
                )
            local_projection = store.get_network(claims, team_id, limit=100)
            owned = [item["id"] for item in local_projection["servers"] if item["owned_by_caller"]]
            self.assertEqual(owned, [host["id"]])
            sent = store.create_network_mailbox_item(claims, team_id, {
                "to": {"kind": "server", "id": peer["id"]},
                "from_agent_id": None,
                "body": "Passive host mail",
                "body_format": "plain",
                "idempotency_key": "local-host-mail-0001",
            })
            self.assertEqual(sent["item"]["from"]["kind"], "server")
            self.assertEqual(sent["item"]["from"]["id"], host["id"])
            with self.assertRaises(HubError) as retired_agent_author:
                store.create_network_mailbox_item(claims, team_id, {
                    "to": {"kind": "server", "id": peer["id"]},
                    "from_agent_id": host_agent["id"],
                    "body": "Owned host agent mail",
                    "body_format": "plain",
                    "idempotency_key": "local-host-mail-0002",
                })
            self.assertEqual(retired_agent_author.exception.code, "invalid_request")
