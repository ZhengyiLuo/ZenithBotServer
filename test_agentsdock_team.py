"""Team Messages V2 agent side: references, gating, helper CLI, endpoints."""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

import agent_server
import agentsdock_team
from agentsdock_team_hub.secure_peer import SecurePeerError
from secure_peer_runtime import SecurePeerRuntime


def _server_reference(**overrides) -> agent_server.TeamReference:
    fields = {
        "kind": "recipient",
        "recipient_kind": "server",
        "team_id": "team_alpha_0001",
        "target_id": "node_sonic_0001",
        "display_name_snapshot": "SONIC",
        "source_text_start": 5,
        "source_text_end": 12,
    }
    fields.update(overrides)
    return agent_server.TeamReference(**fields)


def _all_reference() -> agent_server.TeamReference:
    return agent_server.TeamReference(
        kind="recipient",
        recipient_kind="all",
        team_id="team_alpha_0001",
        target_id="all",
        display_name_snapshot="all",
        source_text_start=17,
        source_text_end=22,
    )


def _skill_reference() -> agent_server.TeamReference:
    return agent_server.TeamReference(
        kind="skill",
        team_id="team_alpha_0001",
        target_id="tskill_deploy_0001",
        display_name_snapshot="deploy-sonic",
        source_text_start=4,
        source_text_end=18,
    )


class TeamReferenceModelTests(unittest.TestCase):
    def test_recipient_shapes_are_validated(self) -> None:
        self.assertEqual(_server_reference().recipient_kind, "server")
        with self.assertRaises(ValidationError):
            agent_server.TeamReference(
                kind="recipient", team_id="team_alpha_0001", target_id="node_x"
            )
        with self.assertRaises(ValidationError):
            _server_reference(recipient_kind="all", target_id="node_sonic_0001")
        with self.assertRaises(ValidationError):
            _server_reference(
                recipient_kind="all",
                target_id="all",
                display_name_snapshot="SONIC",
            )
        with self.assertRaises(ValidationError):
            agent_server.TeamReference(
                kind="skill",
                recipient_kind="server",
                team_id="team_alpha_0001",
                target_id="tskill_1",
            )
        with self.assertRaises(ValidationError):
            _server_reference(source_text_start=9, source_text_end=3)
        with self.assertRaises(ValidationError):
            _server_reference(grant_intent=False)

    def test_turn_request_keeps_team_references_apart_from_chat_references(self) -> None:
        request = agent_server.TurnRequest(
            prompt="Tell @@SONIC the build is green",
            team_references=[_server_reference().model_dump()],
        )
        self.assertEqual(request.chat_references, [])
        self.assertEqual(request.team_references[0].target_id, "node_sonic_0001")
        self.assertEqual(
            agent_server.team_reference_dicts(request.team_references)[0]["kind"],
            "recipient",
        )

    def test_routed_turn_cannot_hide_a_different_visible_prompt(self) -> None:
        with self.assertRaisesRegex(ValidationError, "display_prompt"):
            agent_server.TurnRequest(
                prompt="Tell @@SONIC the build is green",
                display_prompt="Tell the team the build is green",
                team_references=[_server_reference().model_dump()],
            )
        with self.assertRaisesRegex(ValidationError, "display_prompt"):
            agent_server.TurnRequest(
                prompt="Tell @Chat the build is green",
                display_prompt="Tell the team the build is green",
                chat_references=[
                    agent_server.ChatReference(
                        session_id="target",
                        display_title_snapshot="Chat",
                        source_text_start=5,
                        source_text_end=10,
                        action="route",
                    )
                ],
            )
        # Internal display projections remain valid when no authority-bearing
        # reference is present.
        request = agent_server.TurnRequest(
            prompt="private wrapper",
            display_prompt="Visible delivery",
        )
        self.assertEqual(request.display_prompt, "Visible delivery")


class TeamPurposeGatingTests(unittest.TestCase):
    def test_ordinary_turns_and_jobs_may_read_but_deliveries_may_not(self) -> None:
        for purpose in (None, "", "scheduled_job"):
            self.assertTrue(agent_server.provider_turn_may_read_team(purpose))
            self.assertTrue(agent_server.provider_turn_may_send_team(purpose))
        for purpose in (
            "cross_chat_handoff_delivery",
            "secure_peer_handoff_delivery",
            "handoff_digest",
            "handoff_digest_delivery",
        ):
            self.assertFalse(agent_server.provider_turn_may_read_team(purpose))
            self.assertFalse(agent_server.provider_turn_may_send_team(purpose))

    def test_skill_publish_requires_all_or_skill_reference(self) -> None:
        self.assertFalse(
            agent_server.team_reference_requests_skill_publish([_server_reference()])
        )
        self.assertTrue(agent_server.team_reference_requests_skill_publish([_all_reference()]))
        self.assertTrue(
            agent_server.team_reference_requests_skill_publish([
                agent_server.TeamReference(
                    kind="skill",
                    team_id="team_alpha_0001",
                    target_id="tskill_1",
                    display_name_snapshot="deploy-runbook",
                    source_text_start=4,
                    source_text_end=21,
                )
            ])
        )

    def test_exact_visible_utf16_team_mentions_are_required(self) -> None:
        prompt = "😀 Tell @@SONIC now"
        start = len("😀 Tell ".encode("utf-16-le")) // 2
        reference = _server_reference(
            source_text_start=start,
            source_text_end=start + len("@@SONIC"),
        )
        self.assertEqual(
            agent_server.validate_team_references(prompt, [reference]),
            [reference],
        )

        unicode_prompt = "Send @@李😀 now"
        unicode_marker = "@@李😀"
        unicode_reference = _server_reference(
            display_name_snapshot="李😀",
            source_text_start=5,
            source_text_end=5 + agent_server.utf16_length(unicode_marker),
        )
        self.assertEqual(
            agent_server.validate_team_references(
                unicode_prompt,
                [unicode_reference],
            ),
            [unicode_reference],
        )

        for rejected in (
            _server_reference(source_text_start=0, source_text_end=7),
            _server_reference(source_text_start=start + 1, source_text_end=start + 8),
            _server_reference(source_text_start=start, source_text_end=10_000),
            _server_reference(display_name_snapshot="DPark"),
            _server_reference(source_text_start=1, source_text_end=8),
        ):
            with self.subTest(reference=rejected.model_dump()):
                with self.assertRaises(HTTPException):
                    agent_server.validate_team_references(prompt, [rejected])

    def test_team_mentions_reject_duplicates_bad_boundaries_and_chat_overlap(self) -> None:
        with self.assertRaisesRegex(HTTPException, "delimited"):
            agent_server.validate_team_references(
                "x@@SONIC now",
                [_server_reference(source_text_start=1, source_text_end=8)],
            )
        with self.assertRaisesRegex(HTTPException, "duplicate"):
            agent_server.validate_team_references(
                "@@SONIC then @@SONIC",
                [
                    _server_reference(source_text_start=0, source_text_end=7),
                    _server_reference(source_text_start=13, source_text_end=20),
                ],
            )

        legacy_chat_reference = agent_server.ChatReference(
            session_id="target-private-id",
            display_title_snapshot="SONIC",
            source_text_start=0,
            source_text_end=7,
            action="route",
        )
        with self.assertRaisesRegex(HTTPException, "overlap"):
            agent_server.validate_team_references(
                "@@SONIC now",
                [_server_reference(source_text_start=0, source_text_end=7)],
                chat_references=[legacy_chat_reference],
            )

    def test_hidden_team_reference_cannot_mint_provider_authority(self) -> None:
        async def exercise() -> None:
            with (
                tempfile.TemporaryDirectory() as temporary,
                patch.object(agent_server, "AGENT_TOKEN", "test-agent-token"),
                patch.object(
                    agent_server,
                    "CROSS_CHAT_AUTHORITY_ROOT",
                    Path(temporary) / "authority",
                ),
            ):
                with self.assertRaisesRegex(HTTPException, "visible @@"):
                    await agent_server.issue_cross_chat_capability(
                        "source",
                        "run_hidden_team_reference",
                        [],
                        source_user_instruction="Do the work today",
                        actions={"team_send"},
                        team_references=[_server_reference()],
                    )
                self.assertFalse((Path(temporary) / "authority").exists())

        asyncio.run(exercise())

    def test_changed_authoritative_target_cannot_mint_provider_authority(self) -> None:
        async def exercise() -> None:
            with (
                tempfile.TemporaryDirectory() as temporary,
                patch.object(agent_server, "AGENT_TOKEN", "test-agent-token"),
                patch.object(
                    agent_server,
                    "CROSS_CHAT_AUTHORITY_ROOT",
                    Path(temporary) / "authority",
                ),
                patch.object(
                    agent_server.SECURE_PEER_RUNTIME,
                    "resolve_team_references",
                    side_effect=SecurePeerError(
                        "team_reference_invalid", "renamed", 409
                    ),
                ),
            ):
                with self.assertRaises(
                    agent_server.TeamReferenceTargetRepairRequired
                ):
                    await agent_server.issue_cross_chat_capability(
                        "source",
                        "run_changed_team_reference",
                        [],
                        source_user_instruction="Tell @@SONIC now",
                        actions={"team_send"},
                        team_references=[_server_reference()],
                    )
                self.assertFalse((Path(temporary) / "authority").exists())

        asyncio.run(exercise())


class TeamReferenceAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_ordinary_turn_rejects_a_stale_team_reference_before_launch(self) -> None:
        sessions = {
            "source": {
                "id": "source",
                "title": "Source",
                "backend": agent_server.BACKEND_CODEX,
            }
        }
        request = agent_server.TurnRequest(
            prompt="Mention was removed",
            team_references=[_server_reference()],
        )
        with patch.object(agent_server.STORE, "sessions", sessions):
            with self.assertRaisesRegex(HTTPException, "visible @@"):
                await agent_server._start_turn_locked(
                    "source",
                    request,
                    queue_if_busy=False,
                    provider_context_mode="chat",
                    admission_backend=agent_server.BACKEND_CODEX,
                )


class TeamReferenceResolutionTests(unittest.TestCase):
    def runtime(
        self,
        *,
        team_ids=("team_alpha_0001",),
        servers=None,
        members=None,
        skills=None,
    ) -> tuple[SecurePeerRuntime, list]:
        runtime = object.__new__(SecurePeerRuntime)
        realms = [
            {
                "realm": "secure_peer",
                "team_id": team_id,
                "connection_id": f"connection-{team_id}",
                "can_write": True,
            }
            for team_id in team_ids
        ]
        server_map = servers or {}
        member_map = members or {}
        skill_map = skills or {}

        def get(realm, path, _query, *, preserve_not_found=False):
            team_id = realm["team_id"]
            team_path = quote(team_id, safe="")
            server_prefix = f"/v1/teams/{team_path}/network/servers/"
            member_prefix = f"/v1/teams/{team_path}/members/"
            if path.startswith(server_prefix):
                self.assertTrue(preserve_not_found)
                for server in server_map.get(team_id, []):
                    server_id = str(server.get("id") or "")
                    if (
                        path == server_prefix + quote(server_id, safe="")
                        and server.get("status") != "revoked"
                    ):
                        return {"server": dict(server)}
                raise SecurePeerError("not_found", "Resource not found", 404)
            if path.startswith(member_prefix):
                self.assertTrue(preserve_not_found)
                for member in member_map.get(team_id, []):
                    principal_id = str(member.get("principal_id") or "")
                    if (
                        path == member_prefix + quote(principal_id, safe="")
                        and member.get("status") == "active"
                        and member.get("role") != "automation"
                    ):
                        return {"member": dict(member)}
                raise SecurePeerError("not_found", "Resource not found", 404)
            raise AssertionError(path)

        runtime.team_realms = lambda: list(realms)
        runtime._team_hub_get = get
        runtime.team_list_skills = lambda *, include_archived, team_id: {
            "skills": list(skill_map.get(team_id, [])),
            "team_id": team_id,
        }
        return runtime, realms

    def test_reference_resolves_only_to_one_authoritative_visible_target(self) -> None:
        runtime, _realms = self.runtime(
            servers={
                "team_alpha_0001": [
                    {
                        "id": "node_sonic_0001",
                        "display_name": "SONIC",
                        "status": "active",
                    }
                ]
            }
        )
        resolved = runtime.resolve_team_references(
            [_server_reference().model_dump()]
        )
        self.assertEqual(resolved[0]["target_id"], "node_sonic_0001")

    def test_renamed_or_replaced_server_reference_is_rejected(self) -> None:
        runtime, _realms = self.runtime(
            servers={
                "team_alpha_0001": [
                    {
                        "id": "node_sonic_0001",
                        "display_name": "SONIC Renamed",
                        "status": "active",
                    }
                ]
            }
        )
        with self.assertRaisesRegex(SecurePeerError, "changed"):
            runtime.resolve_team_references([_server_reference().model_dump()])

    def test_structured_team_id_disambiguates_all_across_multiple_teams(self) -> None:
        runtime, _realms = self.runtime(
            team_ids=("team_alpha_0001", "team_beta_0001")
        )
        resolved = runtime.resolve_team_references([_all_reference().model_dump()])
        self.assertEqual(resolved[0]["team_id"], "team_alpha_0001")

    def test_hidden_automation_member_is_not_a_human_recipient(self) -> None:
        runtime, _realms = self.runtime(
            members={
                "team_alpha_0001": [
                    {
                        "principal_id": "service_1",
                        "display_name": "Automation",
                        "status": "active",
                        "role": "automation",
                    }
                ]
            }
        )
        reference = agent_server.TeamReference(
            kind="recipient",
            recipient_kind="human",
            team_id="team_alpha_0001",
            target_id="service_1",
            display_name_snapshot="Automation",
            source_text_start=0,
            source_text_end=12,
        )
        with self.assertRaisesRegex(SecurePeerError, "unavailable"):
            runtime.resolve_team_references([reference.model_dump()])

    def test_active_human_member_resolves(self) -> None:
        runtime, _realms = self.runtime(
            members={
                "team_alpha_0001": [
                    {
                        "principal_id": "human_dpark",
                        "display_name": "DPark",
                        "status": "active",
                        "role": "member",
                    }
                ]
            }
        )
        reference = agent_server.TeamReference(
            kind="recipient",
            recipient_kind="human",
            team_id="team_alpha_0001",
            target_id="human_dpark",
            display_name_snapshot="DPark",
            source_text_start=0,
            source_text_end=7,
        )
        resolved = runtime.resolve_team_references([reference.model_dump()])
        self.assertEqual(resolved[0]["target_id"], "human_dpark")

    def test_skill_resolution_freezes_the_authorized_slug(self) -> None:
        runtime, _realms = self.runtime(
            skills={
                "team_alpha_0001": [
                    {
                        "id": "tskill_deploy_0001",
                        "slug": "deploy-sonic",
                        "title": "Deploy SONIC",
                        "archived": False,
                    }
                ]
            }
        )
        resolved = runtime.resolve_team_references([_skill_reference().model_dump()])
        self.assertEqual(resolved[0]["authorized_skill_slug"], "deploy-sonic")


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class AgentsDockTeamCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def authority(self, mode: int = 0o600) -> str:
        path = self.root / "authority.json"
        path.write_text(json.dumps({
            "provider_capability": "provider-secret",
            "source_session_id": "source",
        }))
        path.chmod(mode)
        return str(path)

    def test_reads_stay_loopback_and_carry_the_capability_header(self) -> None:
        requests = []

        class Opener:
            def open(self, request, timeout):
                requests.append((request, timeout))
                return FakeResponse({"messages": [], "has_more": False, "team_id": "team_alpha_0001"})

        with (
            patch.dict(agentsdock_team.os.environ, {"AGENTSDOCK_SERVER_URL": "http://127.0.0.1:7850"}),
            patch.object(agentsdock_team.urllib.request, "build_opener", return_value=Opener()),
        ):
            result = agentsdock_team.main([
                "--authority-file", self.authority(), "inbox", "--unread", "--limit", "5",
            ])
        self.assertEqual(result, 0)
        request, _timeout = requests[0]
        self.assertTrue(request.full_url.startswith("http://127.0.0.1:7850/api/agent/team/messages?"))
        self.assertIn("box=inbox", request.full_url)
        self.assertIn("unread=1", request.full_url)
        self.assertIn("limit=5", request.full_url)
        self.assertEqual(request.get_header("X-agentsdock-provider-capability"), "provider-secret")

    def test_remote_url_and_unsafe_authority_are_rejected(self) -> None:
        with patch.dict(agentsdock_team.os.environ, {"AGENTSDOCK_SERVER_URL": "http://example.com"}):
            self.assertEqual(
                agentsdock_team.main(["--authority-file", self.authority(), "skills"]), 2
            )
        with patch.dict(agentsdock_team.os.environ, {"AGENTSDOCK_SERVER_URL": "http://127.0.0.1:7850"}):
            self.assertEqual(
                agentsdock_team.main(["--authority-file", self.authority(0o644), "skills"]), 2
            )

    def test_send_reads_body_from_stdin_and_validates_attachments(self) -> None:
        attachment = self.root / "runbook.md"
        attachment.write_text("# Runbook\n")
        captured = []

        class Opener:
            def open(self, request, timeout):
                captured.append(json.loads(request.data.decode("utf-8")))
                return FakeResponse({
                    "ok": True,
                    "route_id": "team_" + "a" * 32,
                    "message_id": "tmsg_1",
                    "kind": "message",
                    "accepted": True,
                    "duplicate": False,
                    "attachments": 1,
                })

        stdin = io.StringIO("Build is **green**.\n")
        with (
            patch.dict(agentsdock_team.os.environ, {"AGENTSDOCK_SERVER_URL": "http://127.0.0.1:7850"}),
            patch.object(agentsdock_team.urllib.request, "build_opener", return_value=Opener()),
            patch.object(agentsdock_team.sys, "stdin", stdin),
        ):
            result = agentsdock_team.main([
                "--authority-file", self.authority(), "send",
                "--route", "team_" + "a" * 32,
                "--attach", str(attachment),
            ])
        self.assertEqual(result, 0)
        payload = captured[0]
        self.assertEqual(payload["body"], "Build is **green**.")
        self.assertEqual(payload["kind"], "message")
        self.assertEqual(payload["attachments"], [str(attachment.resolve())])
        self.assertTrue(payload["idempotency_key"].startswith("team_cli_"))

        with (
            patch.dict(agentsdock_team.os.environ, {"AGENTSDOCK_SERVER_URL": "http://127.0.0.1:7850"}),
            patch.object(agentsdock_team.sys, "stdin", io.StringIO("body")),
        ):
            self.assertEqual(
                agentsdock_team.main([
                    "--authority-file", self.authority(), "send",
                    "--route", "team_" + "a" * 32, "--attach", "relative/path.md",
                ]),
                2,
            )
            self.assertEqual(
                agentsdock_team.main([
                    "--authority-file", self.authority(), "send",
                    "--route", "team_" + "a" * 32, "--attach", str(self.root / "missing.md"),
                ]),
                2,
            )
            self.assertEqual(
                agentsdock_team.main([
                    "--authority-file", self.authority(), "send",
                    "--route", "team_" + "a" * 32, "--kind", "skill", "--title", "T",
                ]),
                2,
                "skill sends require --skill-slug",
            )

    def test_send_rejects_tty_stdin(self) -> None:
        class TTY(io.StringIO):
            def isatty(self) -> bool:
                return True

        with (
            patch.dict(agentsdock_team.os.environ, {"AGENTSDOCK_SERVER_URL": "http://127.0.0.1:7850"}),
            patch.object(agentsdock_team.sys, "stdin", TTY("x")),
        ):
            self.assertEqual(
                agentsdock_team.main([
                    "--authority-file", self.authority(), "send", "--route", "team_" + "b" * 32,
                ]),
                2,
            )

    def test_send_rejects_title_for_plain_message(self) -> None:
        with (
            patch.dict(agentsdock_team.os.environ, {"AGENTSDOCK_SERVER_URL": "http://127.0.0.1:7850"}),
            patch.object(agentsdock_team.sys, "stdin", io.StringIO("body")),
            patch.object(agentsdock_team.urllib.request, "build_opener") as opener,
        ):
            self.assertEqual(
                agentsdock_team.main([
                    "--authority-file", self.authority(), "send",
                    "--route", "team_" + "b" * 32, "--title", "Unexpected",
                ]),
                2,
            )
        opener.assert_not_called()


class ProviderTeamEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous = {
            name: getattr(agent_server, name)
            for name in (
                "CURRENT_TURNS",
                "ACTIVE",
                "BUSY_SESSIONS",
                "CROSS_CHAT_CAPABILITIES",
                "CROSS_CHAT_AUTHORITY_ROOT",
                "AGENT_TOKEN",
            )
        }
        self.previous_sessions = agent_server.STORE.sessions
        agent_server.STORE.sessions = {"source": {"id": "source", "backend": "codex"}}
        agent_server.CURRENT_TURNS = {"source": {"run_id": "run_team"}}
        agent_server.ACTIVE = {"source": {"run_id": "run_team"}}
        agent_server.BUSY_SESSIONS = {"source"}
        agent_server.CROSS_CHAT_CAPABILITIES = {}
        agent_server.CROSS_CHAT_AUTHORITY_ROOT = self.root / "authority"
        agent_server.AGENT_TOKEN = "test-agent-token"
        self.references = [_server_reference(), _all_reference()]
        await self.issue({"team_read", "team_send", "team_skill_publish"}, self.references)

    async def asyncTearDown(self) -> None:
        agent_server.STORE.sessions = self.previous_sessions
        for name, value in self.previous.items():
            setattr(agent_server, name, value)
        self.temporary.cleanup()

    async def issue(
        self,
        actions: set[str],
        references,
        *,
        source_prompt: str = "Tell @@SONIC and @@all",
    ) -> None:
        def resolved(items):
            return [
                {
                    **item,
                    **(
                        {"authorized_skill_slug": item["display_name_snapshot"]}
                        if item.get("kind") == "skill"
                        else {}
                    ),
                }
                for item in items
            ]

        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "resolve_team_references",
            side_effect=resolved,
        ):
            path = await agent_server.issue_cross_chat_capability(
                "source",
                "run_team",
                [],
                source_user_instruction=source_prompt,
                actions=set(actions),
                team_references=list(references) if references else None,
                team_read_enabled="team_read" in actions,
            )
        self.authority_path = path
        payload = json.loads(path.read_text())
        self.token = payload["provider_capability"]
        self.assertNotIn("node_sonic_0001", path.read_text())

    def request(self, method: str = "GET", path: str = "/api/agent/team/routes") -> Request:
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

    async def routes(self) -> dict[str, dict]:
        listed = await agent_server.list_provider_team_routes(self.request())
        return {route["display_name"]: route for route in listed["routes"]}

    async def test_routes_are_opaque_and_never_expose_hub_identities(self) -> None:
        listed = await agent_server.list_provider_team_routes(self.request())
        self.assertEqual(len(listed["routes"]), 2)
        self.assertTrue(listed["skill_publish"])
        for route in listed["routes"]:
            self.assertRegex(route["route_id"], r"^team_[0-9a-f]{32}$")
            self.assertNotIn("target_id", route)
            self.assertNotIn("team_id", route)
        by_name = {route["display_name"]: route for route in listed["routes"]}
        self.assertFalse(by_name["SONIC"]["allows_skill"])
        self.assertEqual(by_name["SONIC"]["recipient_kind"], "server")
        self.assertTrue(by_name["Team"]["allows_skill"])
        self.assertEqual(by_name["Team"]["recipient_kind"], "all")

    async def test_read_endpoints_delegate_to_the_runtime_and_mark_content_untrusted(self) -> None:
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "team_list_messages",
            return_value={"messages": [], "has_more": False, "team_id": "team_alpha_0001"},
        ) as listed:
            result = await agent_server.list_provider_team_messages(
                self.request(), box="inbox", unread=True, limit=500
            )
        listed.assert_called_once_with(
            box="inbox", team_id=None, unread=True, since=None, after_sequence=0, limit=100
        )
        self.assertIn("team-authored", result["notice"])
        with self.assertRaises(HTTPException) as raised:
            await agent_server.list_provider_team_messages(self.request(), box="drafts")
        self.assertEqual(raised.exception.status_code, 422)
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "team_get_skill",
            return_value={"skill": {"slug": "deploy-sonic", "attachments": []}, "team_id": "t"},
        ) as skill:
            result = await agent_server.get_provider_team_skill(" Deploy-SONIC ", self.request())
        skill.assert_called_once_with("deploy-sonic", version=None, team_id=None)
        self.assertEqual(result["skill"]["slug"], "deploy-sonic")
        with self.assertRaises(HTTPException) as bad_slug:
            await agent_server.get_provider_team_skill("bad slug!", self.request())
        self.assertEqual(bad_slug.exception.status_code, 422)
        with patch.object(
            agent_server.SECURE_PEER_RUNTIME,
            "team_get_message",
            side_effect=SecurePeerError("team_unavailable", "no network", 409),
        ):
            with self.assertRaises(HTTPException) as unavailable:
                await agent_server.get_provider_team_message("tmsg_1", self.request())
        self.assertEqual(unavailable.exception.status_code, 409)
        self.assertTrue(str(unavailable.exception.detail).startswith("team_unavailable"))

    async def test_read_requires_the_team_read_action(self) -> None:
        agent_server.CROSS_CHAT_CAPABILITIES = {}
        await self.issue({"publish"}, None)
        with self.assertRaises(HTTPException) as raised:
            await agent_server.list_provider_team_skills(self.request())
        self.assertEqual(raised.exception.status_code, 403)
        with self.assertRaises(HTTPException) as routes:
            await agent_server.list_provider_team_routes(self.request())
        self.assertEqual(routes.exception.status_code, 403)

    async def test_send_is_once_per_route_gated_for_skills_and_idempotent(self) -> None:
        routes = await self.routes()
        attachment = self.root / "notes.md"
        attachment.write_text("# notes\n")

        def fake_send(reference, *, payload, attachment_paths, idempotency_key, provenance):
            self.assertEqual(provenance["via"], "agent")
            self.assertEqual(provenance["chat_id"], "source")
            self.assertEqual(provenance["backend"], "codex")
            self.assertTrue(idempotency_key.startswith("agent_team_"))
            skill = payload.get("skill") if payload.get("kind") == "skill" else None
            return {
                "message": {
                    "id": "tmsg_" + reference["target_id"],
                    "title": payload.get("title"),
                    "attachments": [{"id": f"tatt_{index}"} for index, _ in enumerate(attachment_paths)],
                    "recipients": [{"kind": reference.get("recipient_kind"), "display_name": "x"}],
                    "skill": {"slug": skill["slug"], "version": 1} if skill else None,
                }
            }

        recorded = AsyncMock()
        with (
            patch.object(agent_server.SECURE_PEER_RUNTIME, "team_send_message", side_effect=fake_send) as send,
            patch.object(agent_server, "record_team_message_sent_event", recorded),
        ):
            receipt = await agent_server.send_provider_team_message(
                routes["SONIC"]["route_id"],
                agent_server.AgentTeamSendRequest(
                    body="Build is green.",
                    attachments=[str(attachment)],
                    idempotency_key="send-0001-key",
                ),
                self.request("POST"),
            )
            self.assertEqual(receipt["ok"], True)
            self.assertEqual(receipt["message_id"], "tmsg_node_sonic_0001")

            self.assertEqual(receipt["attachments"], 1)
            self.assertFalse(receipt["duplicate"])
            self.assertEqual(send.call_args.kwargs["attachment_paths"], [str(attachment.resolve())])
            recorded.assert_awaited_once()

            replay = await agent_server.send_provider_team_message(
                routes["SONIC"]["route_id"],
                agent_server.AgentTeamSendRequest(
                    body="Build is green.",
                    attachments=[str(attachment)],
                    idempotency_key="send-0001-key",
                ),
                self.request("POST"),
            )
            self.assertTrue(replay["duplicate"])
            self.assertEqual(send.call_count, 1)

            with self.assertRaises(HTTPException) as reused:
                await agent_server.send_provider_team_message(
                    routes["SONIC"]["route_id"],
                    agent_server.AgentTeamSendRequest(body="Again", idempotency_key="send-0002-key"),
                    self.request("POST"),
                )
            self.assertEqual(reused.exception.status_code, 409)

            with self.assertRaises(HTTPException) as wrong_target:
                await agent_server.send_provider_team_message(
                    routes["SONIC"]["route_id"],
                    agent_server.AgentTeamSendRequest(
                        kind="skill", title="Deploy", body="# steps",
                        skill={"slug": "deploy-sonic"}, idempotency_key="send-0003-key",
                    ),
                    self.request("POST"),
                )
            self.assertEqual(wrong_target.exception.status_code, 409)

            skill_receipt = await agent_server.send_provider_team_message(
                routes["Team"]["route_id"],
                agent_server.AgentTeamSendRequest(
                    kind="skill", title="Deploy SONIC", body="# steps",
                    skill={"slug": "deploy-sonic", "summary": "how"}, idempotency_key="send-0004-key",
                ),
                self.request("POST"),
            )
            self.assertEqual(skill_receipt["skill_slug"], "deploy-sonic")
            self.assertEqual(skill_receipt["skill_version"], 1)
            self.assertEqual(send.call_count, 2)

    async def test_send_from_legacy_session_uses_default_backend_provenance(self) -> None:
        agent_server.STORE.sessions["source"].pop("backend")
        routes = await self.routes()
        message = {
            "id": "tmsg_node_sonic_0001",
            "title": None,
            "attachments": [],
            "recipients": [{"kind": "server", "display_name": "SONIC"}],
            "skill": None,
        }
        with (
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "team_send_message",
                return_value={"message": message},
            ) as send,
            patch.object(agent_server, "record_team_message_sent_event", AsyncMock()),
        ):
            await agent_server.send_provider_team_message(
                routes["SONIC"]["route_id"],
                agent_server.AgentTeamSendRequest(
                    body="Legacy session send.",
                    idempotency_key="legacy-session-send-key",
                ),
                self.request("POST"),
            )
        self.assertEqual(
            send.call_args.kwargs["provenance"]["backend"],
            agent_server.DEFAULT_BACKEND,
        )

    async def test_skill_sends_need_the_publish_action_and_an_all_route(self) -> None:
        agent_server.CROSS_CHAT_CAPABILITIES = {}
        await self.issue({"team_read", "team_send"}, self.references)
        routes = await self.routes()
        with patch.object(agent_server.SECURE_PEER_RUNTIME, "team_send_message") as send:
            with self.assertRaises(HTTPException) as denied:
                await agent_server.send_provider_team_message(
                    routes["Team"]["route_id"],
                    agent_server.AgentTeamSendRequest(
                        kind="skill", title="T", body="# x", skill={"slug": "x-skill"},
                        idempotency_key="send-0005-key",
                    ),
                    self.request("POST"),
                )
            self.assertEqual(denied.exception.status_code, 403)
            with self.assertRaises(HTTPException) as no_slug:
                await agent_server.send_provider_team_message(
                    routes["Team"]["route_id"],
                    agent_server.AgentTeamSendRequest(
                        kind="skill", title="T", body="# x", idempotency_key="send-0006-key",
                    ),
                    self.request("POST"),
                )
            self.assertEqual(no_slug.exception.status_code, 422)
        send.assert_not_called()

    async def test_skill_route_cannot_broadcast_or_mutate_another_skill(self) -> None:
        agent_server.CROSS_CHAT_CAPABILITIES = {}
        await self.issue(
            {"team_read", "team_send", "team_skill_publish"},
            [_skill_reference()],
            source_prompt="Use @@deploy-sonic",
        )
        routes = await self.routes()
        route_id = routes["deploy-sonic"]["route_id"]
        with (
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "team_send_message",
                return_value={
                    "message": {
                        "id": "tmsg_skill_exact",
                        "attachments": [],
                        "recipients": [{"kind": "all"}],
                        "skill": {"slug": "deploy-sonic", "version": 2},
                        "title": "Deploy SONIC",
                    }
                },
            ) as send,
            patch.object(
                agent_server,
                "record_team_message_sent_event",
                new_callable=AsyncMock,
            ),
        ):
            with self.assertRaises(HTTPException) as general:
                await agent_server.send_provider_team_message(
                    route_id,
                    agent_server.AgentTeamSendRequest(
                        body="broadcast",
                        idempotency_key="skill-route-message",
                    ),
                    self.request("POST"),
                )
            self.assertEqual(general.exception.status_code, 409)

            with self.assertRaises(HTTPException) as wrong_skill:
                await agent_server.send_provider_team_message(
                    route_id,
                    agent_server.AgentTeamSendRequest(
                        kind="skill",
                        title="Wrong",
                        body="# wrong",
                        skill={"slug": "another-skill"},
                        idempotency_key="skill-route-wrong-slug",
                    ),
                    self.request("POST"),
                )
            self.assertEqual(wrong_skill.exception.status_code, 409)
            send.assert_not_called()

            receipt = await agent_server.send_provider_team_message(
                route_id,
                agent_server.AgentTeamSendRequest(
                    kind="skill",
                    title="Deploy SONIC",
                    body="# exact",
                    skill={"slug": "deploy-sonic"},
                    idempotency_key="skill-route-exact-slug",
                ),
                self.request("POST"),
            )
            self.assertEqual(receipt["message_id"], "tmsg_skill_exact")
            self.assertEqual(receipt["skill_version"], 2)
            send.assert_called_once()

    async def test_send_rejects_protected_or_missing_attachments(self) -> None:
        routes = await self.routes()
        for path, status in (
            (str(self.authority_path), 403),
            ("relative.md", 422),
            (str(self.root / "missing.md"), 422),
        ):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.send_provider_team_message(
                    routes["SONIC"]["route_id"],
                    agent_server.AgentTeamSendRequest(
                        body="x", attachments=[path], idempotency_key="send-0007-key",
                    ),
                    self.request("POST"),
                )
            self.assertEqual(raised.exception.status_code, status, path)

    async def test_failed_send_releases_the_route_for_a_retry(self) -> None:
        routes = await self.routes()
        recorded = AsyncMock()
        with (
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "team_send_message",
                side_effect=SecurePeerError("team_unavailable", "hub offline", 409),
            ),
            patch.object(agent_server, "record_team_message_sent_event", recorded),
        ):
            with self.assertRaises(HTTPException) as raised:
                await agent_server.send_provider_team_message(
                    routes["SONIC"]["route_id"],
                    agent_server.AgentTeamSendRequest(body="x", idempotency_key="send-0008-key"),
                    self.request("POST"),
                )
        self.assertEqual(raised.exception.status_code, 409)
        recorded.assert_not_awaited()
        with (
            patch.object(
                agent_server.SECURE_PEER_RUNTIME,
                "team_send_message",
                return_value={"message": {"id": "tmsg_ok", "attachments": [], "recipients": [], "skill": None, "title": None}},
            ),
            patch.object(agent_server, "record_team_message_sent_event", AsyncMock()),
        ):
            receipt = await agent_server.send_provider_team_message(
                routes["SONIC"]["route_id"],
                agent_server.AgentTeamSendRequest(body="x", idempotency_key="send-0008-key"),
                self.request("POST"),
            )
        self.assertEqual(receipt["message_id"], "tmsg_ok")

    async def test_authority_block_advertises_the_team_helper(self) -> None:
        block = agent_server.cross_chat_provider_authority_block(
            [],
            self.authority_path,
            "source",
            {"team_read", "team_send", "team_skill_publish"},
            team_references=self.references,
        )
        self.assertIn("$AGENTSDOCK_TEAM_CLI", block)
        self.assertIn("inbox", block)
        self.assertIn("routes`", block)
        self.assertIn("--kind message [--attach", block)
        self.assertIn("--kind skill --skill-slug SLUG --title T", block)
        self.assertNotIn("--kind message|skill", block)
        self.assertNotIn("--kind message [--title", block)
        self.assertIn("a server, the whole team", block)
        self.assertNotIn("node_sonic_0001", block)
        durable = agent_server.PROVIDER_AUTHORITY_USAGE_INSTRUCTIONS
        self.assertIn("--kind message [--attach", durable)
        self.assertIn("--kind skill --skill-slug SLUG --title T", durable)
        self.assertNotIn("--kind message|skill", durable)
        self.assertNotIn("--kind message [--title", durable)
        read_only = agent_server.cross_chat_provider_authority_block(
            [], self.authority_path, "source", {"team_read"}
        )
        self.assertIn("read-only", read_only)
        self.assertNotIn("send --route", read_only)


if __name__ == "__main__":
    unittest.main()
