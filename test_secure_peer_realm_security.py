"""Regression coverage for the secure-peer control and Hub auth realms."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

import agent_server


def secure_peer_request(
    path: str,
    *,
    headers: list[tuple[bytes, bytes]],
    query_string: bytes = b"",
) -> agent_server.Request:
    return agent_server.Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": query_string,
            "root_path": "",
            "headers": headers,
            "client": ("127.0.0.1", 50000),
            "server": ("127.0.0.1", 7850),
        }
    )


class SecurePeerRealmSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_admin_control_requires_one_exact_header_only_core_token(self) -> None:
        path = "/api/admin/secure-peers/v1/status"
        core_token = b"core-control-secret"

        async def guarded_downstream(request: agent_server.Request):
            # Endpoints repeat the same real guard for direct-invocation safety.
            agent_server.require_secure_peer_control(request)
            return agent_server.JSONResponse({"ok": True})

        with patch.object(agent_server, "AGENT_TOKEN", core_token.decode("ascii")):
            accepted = await agent_server.require_agent_token(
                secure_peer_request(
                    path,
                    headers=[(b"x-agentsdock-token", core_token)],
                ),
                guarded_downstream,
            )
            self.assertEqual(accepted.status_code, 200)

            rejected_cases = {
                "missing": ([], b""),
                "bearer_only": (
                    [(b"authorization", b"Bearer core-control-secret")],
                    b"",
                ),
                "wrong": (
                    [(b"x-agentsdock-token", b"wrong-core-secret")],
                    b"",
                ),
                "duplicate": (
                    [
                        (b"x-agentsdock-token", core_token),
                        (b"x-agentsdock-token", core_token),
                    ],
                    b"",
                ),
                "query_only": ([], b"token=core-control-secret"),
                "legacy_alongside_exact": (
                    [
                        (b"x-agentsdock-token", core_token),
                        (b"x-zenithdock-token", core_token),
                    ],
                    b"",
                ),
            }
            for label, (headers, query_string) in rejected_cases.items():
                with self.subTest(case=label):
                    downstream = AsyncMock()
                    response = await agent_server.require_agent_token(
                        secure_peer_request(
                            path,
                            headers=headers,
                            query_string=query_string,
                        ),
                        downstream,
                    )
                    self.assertEqual(response.status_code, 401)
                    downstream.assert_not_awaited()

    async def test_proxy_preserves_hub_authorization_and_rejects_browser_metadata(
        self,
    ) -> None:
        path = (
            "/api/team-hub-secure/"
            "123e4567-e89b-42d3-a456-426614174000/"
            "v1/teams/team-alpha/network/mailbox"
        )
        core_token = b"core-control-secret"
        hub_authorization = b"Bearer hub-session-secret"
        observed_authorization: list[str | None] = []

        async def guarded_hub_downstream(request: agent_server.Request):
            agent_server.require_secure_peer_control(request)
            observed_authorization.append(request.headers.get("authorization"))
            return agent_server.JSONResponse({"ok": True})

        base_headers = [
            (b"x-agentsdock-token", core_token),
            (b"authorization", hub_authorization),
        ]
        with patch.object(agent_server, "AGENT_TOKEN", core_token.decode("ascii")):
            accepted = await agent_server.require_agent_token(
                secure_peer_request(path, headers=base_headers),
                guarded_hub_downstream,
            )
            self.assertEqual(accepted.status_code, 200)
            self.assertEqual(
                observed_authorization,
                [hub_authorization.decode("ascii")],
            )

            forbidden_metadata = (
                (b"origin", b"https://attacker.example"),
                (b"sec-fetch-site", b"cross-site"),
                (b"forwarded", b"for=192.0.2.10;proto=https"),
                (b"x-forwarded-for", b"192.0.2.10"),
            )
            for name, value in forbidden_metadata:
                with self.subTest(header=name.decode("ascii")):
                    downstream = AsyncMock()
                    response = await agent_server.require_agent_token(
                        secure_peer_request(
                            path,
                            headers=[*base_headers, (name, value)],
                        ),
                        downstream,
                    )
                    self.assertEqual(response.status_code, 403)
                    downstream.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
