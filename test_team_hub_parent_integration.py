import asyncio
from contextlib import suppress
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import agent_server
from fastapi.testclient import TestClient

from team_hub_host import TEAM_HUB_MODE_HOST, ManagedTeamHubHost
from secure_peer_runtime import SecurePeerRuntime


HOST_ID = "server-parent-integration-12345678"
TAILNET_HOST = "sonic.example.ts.net"
TAILNET_HUB_URL = f"https://{TAILNET_HOST}:8444/api/team-hub"
TAILNET_HEADERS = {
    "X-Forwarded-Host": f"{TAILNET_HOST}:8444",
    "X-Forwarded-Proto": "https",
    "Tailscale-Headers-Info": "https://tailscale.com/s/serve-headers",
    "Tailscale-User-Login": "owner@example.com",
    "Tailscale-User-Name": "Owner",
}


class TeamHubParentIntegrationTests(unittest.TestCase):
    def test_parent_bootstrap_grant_is_serve_only_and_never_returns_hub_auth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = ManagedTeamHubHost(
                mode=TEAM_HUB_MODE_HOST,
                data_dir=Path(temporary) / "hub",
                server_identity=HOST_ID,
                server_instance_id=agent_server.SERVER_INSTANCE_ID,
                allowed_hosts={"localhost", "127.0.0.1", TAILNET_HOST},
                transport="tailscale_serve",
                hub_url=TAILNET_HUB_URL,
            )
            runtime.initialize()
            mount = next(
                route
                for route in agent_server.app.routes
                if getattr(route, "name", None) == "team-hub"
            )
            original_mount = mount.app
            mount.app = runtime
            payload = {
                "request_id": "58c9470a-9443-42f2-973c-b35d3f4ec768",
                "expected_server_identity": HOST_ID,
                "expected_server_instance_id": agent_server.SERVER_INSTANCE_ID,
                "expected_hub_id": runtime.capability()["hub_id"],
                "expected_hub_url": TAILNET_HUB_URL,
                "confirmed": True,
                "recipient_email": "owner@example.com",
                "display_name": "Owner",
                "device_label": "Owner Mac",
            }
            try:
                with patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime), \
                     patch.object(agent_server, "AGENT_TOKEN", "agents-server-token"):
                    serve = TestClient(
                        agent_server.app,
                        base_url=f"http://{TAILNET_HOST}:8444",
                        client=("127.0.0.1", 41000),
                    )
                    grant_headers = {
                        **TAILNET_HEADERS,
                        "Authorization": "Bearer agents-server-token",
                        "Sec-Fetch-Mode": "cors",
                    }

                    local_proof = (runtime.data_dir / "bootstrap-owner.proof").read_text().strip()
                    local_over_serve = serve.post(
                        "/api/team-hub/v1/bootstrap/redeem",
                        headers={
                            **TAILNET_HEADERS,
                            "X-Team-Hub-Bootstrap-Proof": local_proof,
                            "X-Team-Hub-Bootstrap-Request-Id": payload["request_id"],
                        },
                        json={
                            "email": "owner@example.com",
                            "display_name": "Owner",
                            "device_label": "Owner Mac",
                        },
                    )
                    self.assertEqual(local_over_serve.status_code, 403)

                    for headers, params, expected in (
                        (
                            {**TAILNET_HEADERS, "X-AgentsDock-Token": "agents-server-token"},
                            None,
                            401,
                        ),
                        (
                            {
                                **grant_headers,
                                "X-ZenithDock-Token": "agents-server-token",
                            },
                            None,
                            401,
                        ),
                        (grant_headers, {"token": "agents-server-token"}, 401),
                        ({**grant_headers, "Origin": "https://evil.test"}, None, 403),
                        ({**grant_headers, "Sec-Fetch-Site": "none"}, None, 403),
                        ({**grant_headers, "Sec-Fetch-Mode": "navigate"}, None, 403),
                        ({**grant_headers, "Cookie": "session=ambient"}, None, 403),
                        (
                            {
                                **grant_headers,
                                "Tailscale-Funnel-Request": "?1",
                            },
                            None,
                            403,
                        ),
                    ):
                        denied = serve.post(
                            "/api/admin/team-hub/bootstrap-proof",
                            headers=headers,
                            params=params,
                            json=payload,
                        )
                        self.assertEqual(denied.status_code, expected, denied.text)

                    duplicate = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=[
                            *TAILNET_HEADERS.items(),
                            ("Authorization", "Bearer agents-server-token"),
                            ("Authorization", "Bearer agents-server-token"),
                        ],
                        json=payload,
                    )
                    self.assertEqual(duplicate.status_code, 401, duplicate.text)
                    duplicate_mode = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=[
                            *grant_headers.items(),
                            ("Sec-Fetch-Mode", "cors"),
                        ],
                        json=payload,
                    )
                    self.assertEqual(duplicate_mode.status_code, 403, duplicate_mode.text)

                    for missing in (
                        "X-Forwarded-Host",
                        "X-Forwarded-Proto",
                        "Tailscale-Headers-Info",
                        "Tailscale-User-Login",
                        "Tailscale-User-Name",
                    ):
                        denied = serve.post(
                            "/api/admin/team-hub/bootstrap-proof",
                            headers={
                                key: value
                                for key, value in grant_headers.items()
                                if key != missing
                            },
                            json=payload,
                        )
                        self.assertEqual(denied.status_code, 403, missing)
                    for changed_headers in (
                        {**grant_headers, "Host": "evil.example.ts.net:8444"},
                        {**grant_headers, "X-Forwarded-Host": "evil.example.ts.net:8444"},
                        {**grant_headers, "X-Forwarded-Proto": "http"},
                        {**grant_headers, "Tailscale-Headers-Info": "https://evil.test"},
                        {**grant_headers, "Forwarded": "host=localhost"},
                    ):
                        denied = serve.post(
                            "/api/admin/team-hub/bootstrap-proof",
                            headers=changed_headers,
                            json=payload,
                        )
                        self.assertEqual(denied.status_code, 403, denied.text)

                    options = serve.options(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=grant_headers,
                    )
                    self.assertEqual(options.status_code, 403, options.text)
                    local_direct = TestClient(
                        agent_server.app,
                        base_url="http://localhost:7850",
                        client=("127.0.0.1", 41004),
                    ).post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers={"Authorization": "Bearer agents-server-token"},
                        json=payload,
                    )
                    self.assertEqual(local_direct.status_code, 403, local_direct.text)

                    wrong_content_type = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers={**grant_headers, "Content-Type": "text/plain"},
                        content=b"{}",
                    )
                    self.assertEqual(wrong_content_type.status_code, 415)
                    transfer_encoding = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers={
                            **grant_headers,
                            "Content-Type": "application/json",
                            "Transfer-Encoding": "chunked",
                        },
                        content=b"{}",
                    )
                    self.assertEqual(transfer_encoding.status_code, 400)
                    duplicate_length = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=[
                            *grant_headers.items(),
                            ("Content-Type", "application/json"),
                            ("Content-Length", "2"),
                            ("Content-Length", "2"),
                        ],
                        content=b"{}",
                    )
                    self.assertEqual(duplicate_length.status_code, 400)
                    oversized = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers={
                            **grant_headers,
                            "Content-Type": "application/json",
                        },
                        content=b"{" + b" " * 5000 + b"}",
                    )
                    self.assertEqual(oversized.status_code, 413)

                    non_v4 = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=grant_headers,
                        json={
                            **payload,
                            "request_id": "00000000-0000-1000-8000-000000000000",
                        },
                    )
                    self.assertEqual(non_v4.status_code, 422, non_v4.text)
                    false_confirmation = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=grant_headers,
                        json={**payload, "confirmed": False},
                    )
                    self.assertEqual(false_confirmation.status_code, 422)
                    extra_body = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=grant_headers,
                        json={**payload, "unexpected": "authority"},
                    )
                    self.assertEqual(extra_body.status_code, 422)
                    for field, value in (
                        ("expected_server_identity", "server-other-identity"),
                        ("expected_server_instance_id", "server-instance-other"),
                        ("expected_hub_id", "hub_other12345678"),
                        (
                            "expected_hub_url",
                            "https://other.example.ts.net:8444/api/team-hub",
                        ),
                    ):
                        changed = serve.post(
                            "/api/admin/team-hub/bootstrap-proof",
                            headers=grant_headers,
                            json={**payload, field: value},
                        )
                        self.assertEqual(changed.status_code, 409, field)

                    direct = TestClient(
                        agent_server.app,
                        base_url=f"http://{TAILNET_HOST}:7850",
                        client=("100.73.184.23", 41001),
                    ).post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers={
                            **grant_headers,
                            "Host": f"{TAILNET_HOST}:8444",
                        },
                        json=payload,
                    )
                    self.assertEqual(direct.status_code, 403, direct.text)

                    wrong_identity_headers = {
                        **grant_headers,
                        "Tailscale-User-Login": "attacker@example.com",
                    }
                    wrong_identity = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=wrong_identity_headers,
                        json=payload,
                    )
                    self.assertEqual(wrong_identity.status_code, 403, wrong_identity.text)
                    wrong_recipient = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=grant_headers,
                        json={**payload, "recipient_email": "other@example.com"},
                    )
                    self.assertEqual(wrong_recipient.status_code, 403, wrong_recipient.text)

                    grant = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=grant_headers,
                        json=payload,
                    )
                    self.assertEqual(grant.status_code, 200, grant.text)
                    self.assertEqual(
                        set(grant.json()),
                        {
                            "request_id",
                            "server_identity",
                            "server_instance_id",
                            "hub_id",
                            "tailnet_login",
                            "expires_at",
                            "bootstrap_proof",
                        },
                    )
                    self.assertEqual(grant.headers["cache-control"], "no-store")
                    self.assertNotIn("access_token", grant.json())
                    self.assertNotIn("refresh_token", grant.json())
                    self.assertRegex(
                        grant.json()["bootstrap_proof"],
                        r"^bootstrap_remote\.[A-Za-z0-9_-]{43}$",
                    )
                    repeated = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=grant_headers,
                        json=payload,
                    )
                    self.assertEqual(repeated.status_code, 200, repeated.text)
                    self.assertEqual(repeated.json(), grant.json())

                    conflict_payload = {**payload, "device_label": "Another Mac"}
                    conflict = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=grant_headers,
                        json=conflict_payload,
                    )
                    self.assertEqual(conflict.status_code, 409, conflict.text)

                    redeemed = serve.post(
                        "/api/team-hub/v1/bootstrap/redeem",
                        headers={
                            **TAILNET_HEADERS,
                            "X-Team-Hub-Bootstrap-Proof": grant.json()["bootstrap_proof"],
                            "X-Team-Hub-Bootstrap-Request-Id": payload["request_id"],
                        },
                        json={
                            "email": payload["recipient_email"],
                            "display_name": payload["display_name"],
                            "device_label": payload["device_label"],
                        },
                    )
                    self.assertEqual(redeemed.status_code, 200, redeemed.text)
                    self.assertIn("access_token", redeemed.json())
                    self.assertIn("refresh_token", redeemed.json())
                    replay = serve.post(
                        "/api/team-hub/v1/bootstrap/redeem",
                        headers={
                            **TAILNET_HEADERS,
                            "X-Team-Hub-Bootstrap-Proof": grant.json()["bootstrap_proof"],
                            "X-Team-Hub-Bootstrap-Request-Id": payload["request_id"],
                        },
                        json={
                            "email": payload["recipient_email"],
                            "display_name": payload["display_name"],
                            "device_label": payload["device_label"],
                        },
                    )
                    self.assertEqual(replay.status_code, 409, replay.text)
                    hub_token_at_parent = serve.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers={
                            **TAILNET_HEADERS,
                            "Authorization": (
                                f"Bearer {redeemed.json()['access_token']}"
                            ),
                        },
                        json=payload,
                    )
                    self.assertEqual(hub_token_at_parent.status_code, 401)
                    serve.close()
            finally:
                mount.app = original_mount
                asyncio.run(runtime.shutdown())

    def test_parent_bootstrap_grant_supports_only_explicit_exact_direct_ip(self) -> None:
        direct_ip = "100.73.184.23"
        direct_url = f"http://{direct_ip}:7850/api/team-hub"
        with tempfile.TemporaryDirectory() as temporary:
            runtime = ManagedTeamHubHost(
                mode=TEAM_HUB_MODE_HOST,
                data_dir=Path(temporary) / "hub",
                server_identity=HOST_ID,
                server_instance_id=agent_server.SERVER_INSTANCE_ID,
                allowed_hosts={"localhost", "127.0.0.1", TAILNET_HOST, direct_ip},
                transport="tailscale_serve",
                hub_url=TAILNET_HUB_URL,
                routes={
                    "tailscale_serve": TAILNET_HUB_URL,
                    "direct_ip": direct_url,
                },
            )
            runtime.initialize()
            self.assertEqual(runtime.capability()["transport"], "tailscale_serve")
            mount = next(
                route
                for route in agent_server.app.routes
                if getattr(route, "name", None) == "team-hub"
            )
            original_mount = mount.app
            mount.app = runtime
            payload = {
                "request_id": "fc34af4d-5f89-47cd-93df-b48d08256e41",
                "expected_server_identity": HOST_ID,
                "expected_server_instance_id": agent_server.SERVER_INSTANCE_ID,
                "expected_hub_id": runtime.capability()["hub_id"],
                "expected_hub_url": direct_url,
                "expected_transport": "direct_ip",
                "confirmed": True,
                "unsafe_direct_ip_confirmed": True,
                "recipient_email": "owner@example.com",
                "display_name": "Owner",
                "device_label": "Owner Mac",
            }
            try:
                with patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime), \
                     patch.object(agent_server, "AGENT_TOKEN", "agents-server-token"):
                    direct = TestClient(
                        agent_server.app,
                        base_url=f"http://{direct_ip}:7850",
                        client=("192.0.2.50", 41000),
                    )
                    headers = {"Authorization": "Bearer agents-server-token"}
                    missing_confirmation = direct.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=headers,
                        json={
                            key: value
                            for key, value in payload.items()
                            if key != "unsafe_direct_ip_confirmed"
                        },
                    )
                    self.assertEqual(missing_confirmation.status_code, 409)
                    for changed_headers in (
                        {**headers, "Forwarded": "for=192.0.2.50"},
                        {**headers, "X-Forwarded-For": "192.0.2.50"},
                        {**headers, "Tailscale-Funnel-Request": "?1"},
                        {**headers, "Origin": "https://evil.test"},
                    ):
                        denied = direct.post(
                            "/api/admin/team-hub/bootstrap-proof",
                            headers=changed_headers,
                            json=payload,
                        )
                        self.assertEqual(denied.status_code, 403, denied.text)
                    grant = direct.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers=headers,
                        json=payload,
                    )
                    self.assertEqual(grant.status_code, 200, grant.text)
                    self.assertNotIn("access_token", grant.json())
                    redeemed = direct.post(
                        "/api/team-hub/v1/bootstrap/redeem",
                        headers={
                            "X-Team-Hub-Bootstrap-Proof": grant.json()["bootstrap_proof"],
                            "X-Team-Hub-Bootstrap-Request-Id": payload["request_id"],
                        },
                        json={
                            "email": payload["recipient_email"],
                            "display_name": payload["display_name"],
                            "device_label": payload["device_label"],
                        },
                    )
                    self.assertEqual(redeemed.status_code, 200, redeemed.text)
                    parent_with_hub_token = direct.post(
                        "/api/admin/team-hub/bootstrap-proof",
                        headers={
                            "Authorization": f"Bearer {redeemed.json()['access_token']}"
                        },
                        json=payload,
                    )
                    self.assertEqual(parent_with_hub_token.status_code, 401)
                    direct.close()
            finally:
                mount.app = original_mount
                asyncio.run(runtime.shutdown())

    def test_parent_listener_preserves_hub_transport_and_credential_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = ManagedTeamHubHost(
                mode=TEAM_HUB_MODE_HOST,
                data_dir=Path(temporary) / "hub",
                server_identity=HOST_ID,
                allowed_hosts={"localhost", "127.0.0.1"},
            )
            runtime.initialize()
            mount = next(
                route
                for route in agent_server.app.routes
                if getattr(route, "name", None) == "team-hub"
            )
            original_mount = mount.app
            mount.app = runtime
            try:
                with patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime), \
                     patch.object(agent_server, "AGENT_TOKEN", "agents-server-token"):
                    local = TestClient(
                        agent_server.app,
                        base_url="http://localhost",
                        client=("127.0.0.1", 41000),
                    )
                    bare = local.get(
                        "/api/team-hub",
                        headers={"Host": "evil.test"},
                        follow_redirects=False,
                    )
                    self.assertEqual(bare.status_code, 404)
                    self.assertNotIn("location", bare.headers)
                    self.assertNotIn("evil.test", bare.text)
                    for method in ("post", "options"):
                        response = getattr(local, method)(
                            "/api/team-hub",
                            headers={"Host": "evil.test"},
                        )
                        self.assertEqual(response.status_code, 404)
                        self.assertNotIn("location", response.headers)

                    health = local.get("/api/team-hub/v1/health")
                    self.assertEqual(health.status_code, 200, health.text)
                    self.assertEqual(health.json()["hub_id"], runtime.capability()["hub_id"])

                    proof = (runtime.data_dir / "bootstrap-owner.proof").read_text().strip()
                    bootstrap = local.post(
                        "/api/team-hub/v1/bootstrap/redeem",
                        headers={"X-Team-Hub-Bootstrap-Proof": proof},
                        json={
                            "email": "owner@example.com",
                            "display_name": "Owner",
                            "device_label": "Local Mac",
                        },
                    )
                    self.assertEqual(bootstrap.status_code, 200, bootstrap.text)
                    bundle = bootstrap.json()

                    hub_session = "/api/team-hub/v1/session"
                    for kwargs in (
                        {"headers": {"Authorization": "Bearer agents-server-token"}},
                        {"headers": {"X-AgentsDock-Token": "agents-server-token"}},
                        {"headers": {"X-ZenithDock-Token": "agents-server-token"}},
                        {"params": {"token": "agents-server-token"}},
                    ):
                        denied = local.get(hub_session, **kwargs)
                        self.assertEqual(denied.status_code, 401, denied.text)

                    for kwargs in (
                        {"headers": {"Authorization": f"Bearer {bundle['access_token']}"}},
                        {"params": {"token": bundle["refresh_token"]}},
                    ):
                        denied = local.get("/api/health", **kwargs)
                        self.assertEqual(denied.status_code, 401, denied.text)

                    hostile_origin = local.get(
                        "/api/team-hub/v1/health",
                        headers={"Origin": "https://evil.test"},
                    )
                    self.assertEqual(hostile_origin.status_code, 403)
                    self.assertNotIn("access-control-allow-origin", hostile_origin.headers)
                    preflight = local.options(
                        "/api/team-hub/v1/session",
                        headers={
                            "Origin": "https://evil.test",
                            "Access-Control-Request-Method": "GET",
                        },
                    )
                    self.assertEqual(preflight.status_code, 403)
                    self.assertNotIn("access-control-allow-origin", preflight.headers)

                    remote = TestClient(
                        agent_server.app,
                        base_url="http://localhost",
                        client=("192.0.2.20", 41000),
                    )
                    remote_health = remote.get(
                        "/api/team-hub/v1/health",
                        headers={"Host": "localhost"},
                    )
                    self.assertEqual(remote_health.status_code, 403)

                    with patch.object(
                        agent_server,
                        "managed_server_update_blocks_work",
                        return_value=True,
                    ):
                        maintenance = local.post(
                            "/api/team-hub/v1/sessions/refresh",
                            json={"refresh_token": bundle["refresh_token"]},
                        )
                    self.assertEqual(maintenance.status_code, 503)
                    self.assertEqual(
                        maintenance.json()["error"]["code"],
                        "hub_maintenance",
                    )

                    # Mounted path normalization must keep bootstrap in its
                    # sensitive 8/minute bucket instead of generic POST limits.
                    attempts = [
                        local.post(
                            "/api/team-hub/v1/bootstrap/redeem",
                            headers={
                                "X-Team-Hub-Bootstrap-Proof":
                                    "invalid-proof-that-is-long-enough"
                            },
                            json={
                                "email": "second@example.com",
                                "display_name": "Second",
                                "device_label": "Local Mac",
                            },
                        )
                        for _ in range(9)
                    ]
                    self.assertEqual(attempts[-1].status_code, 429)
                    self.assertEqual(attempts[-1].json()["error"]["code"], "rate_limited")
                    local.close()
                    remote.close()
            finally:
                mount.app = original_mount
                asyncio.run(runtime.shutdown())

    def test_server_scoped_session_is_shared_through_the_authenticated_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = ManagedTeamHubHost(
                mode=TEAM_HUB_MODE_HOST,
                data_dir=Path(temporary) / "hub",
                server_identity=HOST_ID,
                allowed_hosts={"localhost", "127.0.0.1"},
            )
            runtime.initialize()
            hub_mount = next(
                route
                for route in agent_server.app.routes
                if getattr(route, "name", None) == "team-hub"
            )
            server_mount = next(
                route
                for route in agent_server.app.routes
                if getattr(route, "name", None) == "team-hub-server-session"
            )
            original_hub_mount = hub_mount.app
            original_server_mount = server_mount.app
            hub_mount.app = runtime
            server_mount.app = runtime
            try:
                with patch.object(agent_server, "TEAM_HUB_RUNTIME", runtime), \
                     patch.object(agent_server, "AGENT_TOKEN", "agents-server-token"):
                    client = TestClient(
                        agent_server.app,
                        base_url="http://localhost",
                        client=("127.0.0.1", 41000),
                    )
                    proof = (
                        runtime.data_dir / "bootstrap-owner.proof"
                    ).read_text().strip()
                    bootstrap = client.post(
                        "/api/team-hub/v1/bootstrap/redeem",
                        headers={"X-Team-Hub-Bootstrap-Proof": proof},
                        json={
                            "email": "owner@example.com",
                            "display_name": "Owner",
                            "device_label": "Studio",
                        },
                    )
                    self.assertEqual(bootstrap.status_code, 200, bootstrap.text)

                    headers = {"X-AgentsDock-Token": "agents-server-token"}
                    health = client.get(
                        "/api/team-hub-server/v1/health",
                        headers=headers,
                    )
                    self.assertEqual(health.status_code, 200, health.text)
                    self.assertTrue(health.json()["server_session_available"])
                    first = client.get(
                        "/api/team-hub-server/v1/server-session",
                        headers=headers,
                    )
                    second = client.get(
                        "/api/team-hub-server/v1/server-session",
                        headers=headers,
                    )
                    self.assertEqual(first.status_code, 200, first.text)
                    self.assertEqual(second.status_code, 200, second.text)
                    self.assertEqual(
                        first.json()["principal"]["id"],
                        second.json()["principal"]["id"],
                    )
                    self.assertEqual(
                        first.json()["teams"][0]["id"],
                        second.json()["teams"][0]["id"],
                    )

                    team_id = first.json()["teams"][0]["id"]
                    message = client.post(
                        f"/api/team-hub-server/v1/teams/{team_id}/network/messages",
                        headers=headers,
                        json={
                            "kind": "message",
                            "body": "server-session deletion",
                            "body_format": "plain",
                            "recipients": [{"kind": "all"}],
                            "idempotency_key": "server-session-message-create-1",
                        },
                    )
                    self.assertEqual(message.status_code, 200, message.text)
                    message_id = message.json()["message"]["id"]
                    deleted_message = client.request(
                        "DELETE",
                        f"/api/team-hub-server/v1/teams/{team_id}/network/messages/{message_id}",
                        headers=headers,
                        json={"idempotency_key": "server-session-message-delete-1"},
                    )
                    self.assertEqual(
                        deleted_message.status_code,
                        200,
                        deleted_message.text,
                    )
                    self.assertEqual(
                        deleted_message.json(),
                        {"deleted": True, "message_id": message_id},
                    )
                    bulletin = client.post(
                        f"/api/team-hub-server/v1/teams/{team_id}/network/bulletin",
                        headers=headers,
                        json={
                            "body": "server-session bulletin deletion",
                            "body_format": "plain",
                            "idempotency_key": "server-session-bulletin-create-1",
                        },
                    )
                    self.assertEqual(bulletin.status_code, 200, bulletin.text)
                    post_id = bulletin.json()["post"]["id"]
                    deleted_bulletin = client.request(
                        "DELETE",
                        f"/api/team-hub-server/v1/teams/{team_id}/network/bulletin/{post_id}",
                        headers=headers,
                        json={"idempotency_key": "server-session-bulletin-delete-1"},
                    )
                    self.assertEqual(
                        deleted_bulletin.status_code,
                        200,
                        deleted_bulletin.text,
                    )
                    self.assertEqual(
                        deleted_bulletin.json(),
                        {"deleted": True, "post_id": post_id},
                    )
                    journal = client.get(
                        f"/api/team-hub-server/v1/teams/{team_id}/network/deletions"
                        "?after_sequence=0&limit=10",
                        headers=headers,
                    )
                    self.assertEqual(journal.status_code, 200, journal.text)
                    self.assertEqual(
                        [(item["kind"], item["id"]) for item in journal.json()["deletions"]],
                        [("message", message_id), ("bulletin", post_id)],
                    )
                    disallowed_delete = client.request(
                        "DELETE",
                        f"/api/team-hub-server/v1/teams/{team_id}/network/messages",
                        headers=headers,
                        json={"idempotency_key": "server-session-wrong-route-1"},
                    )
                    self.assertEqual(
                        disallowed_delete.status_code,
                        404,
                        disallowed_delete.text,
                    )

                    attachment_bytes = b"server-session attachment"
                    attachment = client.post(
                        f"/api/team-hub-server/v1/teams/{team_id}/network/attachments",
                        headers=headers,
                        json={
                            "file_name": "proof.bin",
                            "media_type": "application/octet-stream",
                            "byte_size": len(attachment_bytes),
                            "sha256": hashlib.sha256(attachment_bytes).hexdigest(),
                            "idempotency_key": "server-session-attachment-1",
                        },
                    )
                    self.assertEqual(attachment.status_code, 200, attachment.text)
                    attachment_id = attachment.json()["attachment"]["id"]
                    content_path = (
                        f"/api/team-hub-server/v1/teams/{team_id}/network/"
                        f"attachments/{attachment_id}/content"
                    )
                    uploaded = client.put(
                        content_path,
                        headers={
                            **headers,
                            "Content-Type": "application/octet-stream",
                            "Content-Range": (
                                f"bytes 0-{len(attachment_bytes) - 1}/"
                                f"{len(attachment_bytes)}"
                            ),
                        },
                        content=attachment_bytes,
                    )
                    self.assertEqual(uploaded.status_code, 200, uploaded.text)
                    downloaded = client.get(content_path, headers=headers)
                    self.assertEqual(downloaded.status_code, 200, downloaded.text)
                    self.assertEqual(downloaded.content, attachment_bytes)
                    ranged = client.get(
                        content_path,
                        headers={**headers, "Range": "bytes=1-5"},
                    )
                    self.assertEqual(ranged.status_code, 206, ranged.text)
                    self.assertEqual(ranged.content, attachment_bytes[1:6])
                    headed = client.head(content_path, headers=headers)
                    self.assertEqual(headed.status_code, 200, headed.text)
                    self.assertEqual(headed.content, b"")
                    query_rejected = client.get(
                        content_path + "?download=1",
                        headers=headers,
                    )
                    self.assertEqual(query_rejected.status_code, 422)
                    malformed_upload = client.put(
                        content_path,
                        headers={**headers, "Content-Type": "application/json"},
                        content=b"{}",
                    )
                    self.assertEqual(malformed_upload.status_code, 415)

                    for request_headers, expected in (
                        ({}, 401),
                        ({"X-AgentsDock-Token": "wrong"}, 401),
                        ({**headers, "Origin": "https://evil.test"}, 403),
                        ({**headers, "Cookie": "ambient=yes"}, 403),
                        ({**headers, "Sec-Fetch-Site": "cross-site"}, 403),
                    ):
                        denied = client.get(
                            "/api/team-hub-server/v1/server-session",
                            headers=request_headers,
                        )
                        self.assertEqual(denied.status_code, expected, denied.text)

                    proxied = client.get(
                        "/api/team-hub-server/v1/server-session",
                        headers={
                            **headers,
                            "Forwarded": "for=192.0.2.50;proto=https",
                            "Via": "1.1 edge.example.test",
                            "X-Forwarded-For": "192.0.2.50",
                            "X-Forwarded-Host": "dock.example.test",
                            "X-Forwarded-Proto": "https",
                            "X-Real-IP": "192.0.2.50",
                        },
                    )
                    self.assertEqual(proxied.status_code, 200, proxied.text)
                    self.assertEqual(
                        proxied.json()["principal"]["id"],
                        first.json()["principal"]["id"],
                    )

                    bare = client.get(
                        "/api/team-hub-server",
                        headers=headers,
                        follow_redirects=False,
                    )
                    self.assertEqual(bare.status_code, 404, bare.text)
                    forbidden = client.post(
                        "/api/team-hub-server/v1/sessions/refresh",
                        headers=headers,
                        json={"refresh_token": "not-a-device-credential"},
                    )
                    self.assertEqual(forbidden.status_code, 404, forbidden.text)
                    direct = client.get("/api/team-hub/v1/server-session")
                    self.assertEqual(direct.status_code, 404, direct.text)

                    # A fresh client reaches this parent through the selected
                    # AgentsServer address, which need not also be configured
                    # as a direct Team Hub transport host. The authenticated
                    # process-local mount accepts that authority while the
                    # ordinary Hub mount keeps its strict Host allowlist.
                    remote = TestClient(
                        agent_server.app,
                        base_url="http://100.73.184.23:7850",
                        client=("100.73.184.24", 41001),
                    )
                    try:
                        remote_session = remote.get(
                            "/api/team-hub-server/v1/server-session",
                            headers=headers,
                        )
                        self.assertEqual(
                            remote_session.status_code,
                            200,
                            remote_session.text,
                        )
                        self.assertEqual(
                            remote_session.json()["principal"]["id"],
                            first.json()["principal"]["id"],
                        )
                        direct_remote = remote.get("/api/team-hub/v1/health")
                        self.assertEqual(
                            direct_remote.status_code,
                            400,
                            direct_remote.text,
                        )
                        self.assertEqual(
                            direct_remote.json()["error"]["message"],
                            "Invalid Host header",
                        )
                    finally:
                        remote.close()

                    capability = agent_server.current_team_hub_capability()
                    self.assertEqual(
                        capability["server_session_base_path"],
                        "/api/team-hub-server",
                    )
                    client.close()
            finally:
                hub_mount.app = original_hub_mount
                server_mount.app = original_server_mount
                asyncio.run(runtime.shutdown())


class TeamHubHealthResponsivenessTests(unittest.IsolatedAsyncioTestCase):
    async def test_sqlite_lock_does_not_block_health_capability_heartbeat(self) -> None:
        class DisabledHost:
            designated_host = False

            @staticmethod
            def capability() -> dict[str, object]:
                return {
                    "available": False,
                    "designated_host": False,
                    "version": 1,
                    "base_path": None,
                    "transport": None,
                    "hub_url": None,
                    "routes": [],
                    "hub_id": None,
                    "host_server_identity": None,
                    "message": "This server is not the designated host.",
                    "action": None,
                }

        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="health-source-server",
                server_instance_id="health-source-instance",
                display_name="Health source",
            )
            blocker = sqlite3.connect(
                runtime.client.db_path,
                timeout=1,
                isolation_level=None,
            )
            blocker.execute("PRAGMA journal_mode=DELETE")
            blocker.execute("BEGIN EXCLUSIVE")
            state: dict[str, object | None] = {"loop": None, "task": None}
            loop = asyncio.get_running_loop()
            started = loop.time()
            try:
                with (
                    patch.object(agent_server, "TEAM_HUB_RUNTIME", DisabledHost()),
                    patch.object(agent_server, "SECURE_PEER_RUNTIME", runtime),
                    patch.object(
                        agent_server,
                        "TEAM_HUB_HEALTH_CAPABILITY_STATE",
                        state,
                    ),
                    patch.object(
                        agent_server,
                        "HEALTH_TEAM_HUB_CAPABILITY_TIMEOUT_SECONDS",
                        0.02,
                    ),
                ):
                    heartbeat = asyncio.create_task(asyncio.sleep(0.01))
                    capability = await agent_server.team_hub_capability_for_health()
                    await asyncio.wait_for(heartbeat, timeout=0.05)
                    elapsed = loop.time() - started
                    self.assertFalse(capability["available"])
                    self.assertLess(elapsed, 0.1)

                    worker = state.get("task")
                    self.assertIsInstance(worker, asyncio.Task)
                    blocker.rollback()
                    blocker.close()
                    await asyncio.wait_for(worker, timeout=1)  # type: ignore[arg-type]
            finally:
                with suppress(sqlite3.Error):
                    blocker.rollback()
                blocker.close()


if __name__ == "__main__":
    unittest.main()
