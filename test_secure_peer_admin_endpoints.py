import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

from agentsdock_team_hub.secure_peer import SecurePeerStore, build_pairing_request
from agentsdock_team_hub.store import MANAGED_SERVER_PRINCIPAL_ID
import agent_server


class _StoreBackedRevokeRuntime:
    """Exercise the endpoint against the real secure-peer storage contract."""

    def __init__(self, store: SecurePeerStore) -> None:
        self.store = store

    def revoke_peer(self, **values):
        return {"peer": self.store.revoke_peer(**values)}


class SecurePeerHostAdminEndpointTests(unittest.IsolatedAsyncioTestCase):
    def test_public_pairing_models_accept_only_teamspace_scopes(self) -> None:
        self.assertEqual(
            agent_server.canonical_secure_peer_scopes(
                ["teamspace.write", "teamspace.read"]
            ),
            ["teamspace.read", "teamspace.write"],
        )
        with self.assertRaisesRegex(ValueError, "supported subset"):
            agent_server.canonical_secure_peer_scopes(
                ["teamspace.read", "cross_chat.instruction"]
            )

    async def test_chat_route_publication_is_retired_before_runtime_lookup(
        self,
    ) -> None:
        runtime = Mock()
        request = Mock()
        body = agent_server.SecurePeerRouteCreateRequest(
            request_id="42e7bb2e-3b47-4be7-89fc-2cecd90f4434",
            expected_server_identity="server-current",
            expected_server_instance_id="instance-current",
            confirmed=True,
            connection_id="22e7bb2e-3b47-4be7-89fc-2cecd90f4434",
            chat_id="chat-current",
            alias="remote",
            display_title="Remote chat",
            actions=["instruction"],
        )
        with (
            patch.object(agent_server, "SECURE_PEER_RUNTIME", runtime),
            patch.object(agent_server, "SERVER_INSTANCE_ID", "instance-current"),
            patch.object(agent_server, "server_identity", return_value="server-current"),
            patch.object(agent_server, "require_secure_peer_control") as require_control,
            patch.object(agent_server, "SECURE_PEER_AGENT_RELAY_ENABLED", False),
            self.assertRaises(HTTPException) as raised,
        ):
            await agent_server.secure_peer_route_publish_endpoint(
                body,
                request,
            )
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("Team Network Inbox", str(raised.exception.detail))
        require_control.assert_called_once_with(request)
        runtime.publish_route.assert_not_called()

    async def test_lists_only_the_exact_team_under_the_current_server_instance(self) -> None:
        runtime = Mock()
        runtime.list_peers.return_value = {"peers": []}
        request = Mock()

        with (
            patch.object(agent_server, "SECURE_PEER_RUNTIME", runtime),
            patch.object(agent_server, "SERVER_INSTANCE_ID", "instance-current"),
            patch.object(agent_server, "server_identity", return_value="server-current"),
            patch.object(agent_server, "require_secure_peer_control") as require_control,
        ):
            response = await agent_server.secure_peer_host_peers_endpoint(
                request,
                expected_server_identity="server-current",
                expected_server_instance_id="instance-current",
                team_id="team-studio",
            )

            require_control.assert_called_once_with(request)
            runtime.list_peers.assert_called_once_with(team_id="team-studio")
            self.assertEqual(json.loads(response.body), {"peers": []})
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertEqual(response.headers["pragma"], "no-cache")

            with self.assertRaises(HTTPException) as changed:
                await agent_server.secure_peer_host_peers_endpoint(
                    request,
                    expected_server_identity="server-current",
                    expected_server_instance_id="instance-stale",
                    team_id="team-studio",
                )
            self.assertEqual(changed.exception.status_code, 409)
            self.assertEqual(runtime.list_peers.call_count, 1)

    async def test_revokes_one_exact_team_peer_with_certificate_cas(self) -> None:
        peer_id = "22e7bb2e-3b47-4be7-89fc-2cecd90f4434"
        request_id = "42e7bb2e-3b47-4be7-89fc-2cecd90f4434"
        certificate = "sha256:" + "b" * 64
        runtime = Mock()
        runtime.revoke_peer.return_value = {"peer": {"connection_id": peer_id}}
        request = Mock()
        body = agent_server.SecurePeerHostPeerRevokeRequest(
            request_id=request_id,
            expected_server_identity="server-current",
            expected_server_instance_id="instance-current",
            team_id="team-studio",
            expected_certificate_fingerprint=certificate,
            confirmed=True,
        )

        with (
            patch.object(agent_server, "SECURE_PEER_RUNTIME", runtime),
            patch.object(agent_server, "SERVER_INSTANCE_ID", "instance-current"),
            patch.object(agent_server, "server_identity", return_value="server-current"),
            patch.object(agent_server, "require_secure_peer_control") as require_control,
        ):
            response = await agent_server.secure_peer_host_peer_revoke_endpoint(
                peer_id,
                body,
                request,
            )

        require_control.assert_called_once_with(request)
        runtime.revoke_peer.assert_called_once_with(
            peer_id=peer_id,
            team_id="team-studio",
            expected_certificate_fingerprint=certificate,
            idempotency_key=request_id,
            revoked_by=MANAGED_SERVER_PRINCIPAL_ID,
        )
        self.assertEqual(json.loads(response.body), {"peer": {"connection_id": peer_id}})
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["pragma"], "no-cache")

    async def test_revoke_endpoint_satisfies_the_real_store_audit_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = SecurePeerStore(
                Path(temporary) / "host",
                "host-server-001",
                "team-hub-001",
            )
            peer_key = Ed25519PrivateKey.generate()
            pairing_request = build_pairing_request(
                peer_key,
                server_identity="peer-server-001",
                display_name="Peer server",
                host_ca_fingerprint=store.ca_fingerprint,
                requested_scopes=["teamspace.read"],
            )
            submitted = store.submit_pairing(
                pairing_request,
                source_ip="192.0.2.10",
                source_port=45123,
            )
            approved = store.approve_pairing(
                submitted["pairing_id"],
                "team-studio",
                ["teamspace.read"],
                "owner-admin",
                expected_peer_server_identity="peer-server-001",
                expected_transcript_hash=submitted["transcript_hash"],
                idempotency_key=str(uuid.uuid4()),
            )
            request_id = str(uuid.uuid4())
            body = agent_server.SecurePeerHostPeerRevokeRequest(
                request_id=request_id,
                expected_server_identity="server-current",
                expected_server_instance_id="instance-current",
                team_id="team-studio",
                expected_certificate_fingerprint=approved[
                    "certificate_fingerprint"
                ],
                confirmed=True,
            )

            with (
                patch.object(
                    agent_server,
                    "SECURE_PEER_RUNTIME",
                    _StoreBackedRevokeRuntime(store),
                ),
                patch.object(agent_server, "SERVER_INSTANCE_ID", "instance-current"),
                patch.object(
                    agent_server,
                    "server_identity",
                    return_value="server-current",
                ),
                patch.object(agent_server, "require_secure_peer_control"),
            ):
                response = await agent_server.secure_peer_host_peer_revoke_endpoint(
                    approved["peer_id"],
                    body,
                    Mock(),
                )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                json.loads(response.body)["peer"]["status"],
                "revoked",
            )
            connection = store._connect()
            try:
                peer = connection.execute(
                    "SELECT status,revoked_by FROM peers WHERE id=?",
                    (approved["peer_id"],),
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual(peer["status"], "revoked")
            self.assertEqual(peer["revoked_by"], MANAGED_SERVER_PRINCIPAL_ID)


if __name__ == "__main__":
    unittest.main()
