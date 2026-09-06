import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
from urllib.parse import parse_qs, urlsplit
import uuid

from agentsdock_team_hub.secure_peer import SecurePeerError, canonical_peer_ipv4
from agentsdock_team_hub.store import HubError, HubStore
from secure_peer_runtime import SecurePeerRuntime


TEAMSPACE_SCOPES = ["teamspace.read", "teamspace.write"]
PAIRING_SCOPES = list(TEAMSPACE_SCOPES)
HOST_SERVER_IDENTITY = "team_network_host_server"
MEMBER_SERVER_IDENTITY = "team_network_member_server"


def _uuid() -> str:
    return str(uuid.uuid4())


def _nonloopback_ipv4() -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        candidate = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    try:
        return canonical_peer_ipv4(candidate)
    except ValueError:
        return None


def _free_port(host: str) -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind((host, 0))
        return int(listener.getsockname()[1])
    finally:
        listener.close()


class TeamNetworkHarness:
    """Two real server runtimes sharing only the secure peer network."""

    def __init__(self, case: unittest.TestCase, root: Path, host_ip: str) -> None:
        self.case = case
        self.root = root
        self.host_ip = host_ip
        self.port = _free_port(host_ip)

        self.hub = HubStore(
            root / "host-hub",
            managed_host_identity=HOST_SERVER_IDENTITY,
            managed_server_instance_id="team_network_host_instance",
            managed_host_display_name="Sonic",
        )
        proof = (root / "host-hub" / "bootstrap-owner.proof").read_text().strip()
        bootstrap = self.hub.bootstrap(
            proof,
            "owner@example.test",
            "Network owner",
            "Host server",
        )
        self.owner = self.hub.verify_access(bootstrap["access_token"])
        self.team_id = bootstrap["teams"][0]["id"]
        self.host = SecurePeerRuntime(
            root / "host-runtime",
            server_identity=HOST_SERVER_IDENTITY,
            server_instance_id="team_network_host_instance",
            display_name="Host server",
        )
        self.member = SecurePeerRuntime(
            root / "member-runtime",
            server_identity=MEMBER_SERVER_IDENTITY,
            server_instance_id="team_network_member_instance",
            display_name="Member server",
        )
        case.addCleanup(self.shutdown)
        # Team Network writes are passive store operations. Any cross-chat
        # delivery admission would mean a provider/agent turn escaped this
        # contract, so retain an observable tripwire on both real runtimes.
        self.delivery_checks: list[tuple[str, str]] = []

        def delivery_tripwire(chat_id: str, _route=None) -> bool:
            self.delivery_checks.append(("delivery", chat_id))
            return True

        self.member.set_delivery_target_validator(delivery_tripwire)
        self.host.set_delivery_target_validator(delivery_tripwire)
        self.host.attach_host_hub(
            hub_id=self.hub.hub_id,
            hub_data_dir=root / "host-hub",
            hub_store=self.hub,
        )
        self.host_status = self.host.configure_host(
            enabled=True,
            advertised_host=host_ip,
            listen_port=self.port,
        )

        self.pairing_id = ""
        self.connection_id = ""
        self.peer_id = ""
        self.peer_server_identity = ""
        self.certificate_fingerprint = ""

    def shutdown(self) -> None:
        self.member.shutdown()
        self.host.shutdown()

    def invite_target(self) -> tuple[str, int, str]:
        link = self.host_status["host"]["pairing_link"]
        self.case.assertIsInstance(link, str)
        parsed = urlsplit(link)
        self.case.assertEqual(
            (parsed.scheme, parsed.hostname, parsed.path),
            ("agentsdock", "secure-peer", "/join"),
        )
        query = parse_qs(parsed.query, strict_parsing=True)
        self.case.assertEqual(set(query), {"host", "port", "fingerprint"})
        self.case.assertTrue(all(len(values) == 1 for values in query.values()))
        host = query["host"][0]
        port = int(query["port"][0])
        fingerprint = query["fingerprint"][0]
        self.case.assertEqual(
            (host, port, fingerprint),
            (
                self.host_ip,
                self.port,
                self.host_status["host"]["ca_fingerprint"],
            ),
        )
        return host, port, fingerprint

    def pair_approve_and_activate(self) -> None:
        host, port, fingerprint = self.invite_target()
        outgoing = self.member.begin_pairing(
            host=host,
            port=port,
            expected_ca_fingerprint=fingerprint,
            request_id=_uuid(),
            display_name="Member server",
            requested_scopes=list(PAIRING_SCOPES),
        )
        pending = self.host.list_pairings(
            team_id=None,
            status="pending_approval",
        )["pairings"]
        self.case.assertEqual(len(pending), 1)
        incoming = pending[0]
        self.case.assertEqual(incoming["id"], outgoing["id"])
        self.case.assertEqual(
            incoming["peer_server_identity"],
            MEMBER_SERVER_IDENTITY,
        )
        self.case.assertEqual(incoming["transcript_hash"], outgoing["transcript_hash"])
        self.case.assertEqual(incoming["sas_words"], outgoing["sas_words"])
        self.case.assertEqual(incoming["requested_scopes"], PAIRING_SCOPES)
        self.case.assertGreaterEqual(len(incoming["sas_words"]), 4)

        approved = self.host.approve_pairing(
            pairing_id=incoming["id"],
            team_id=self.team_id,
            scopes=list(PAIRING_SCOPES),
            approved_by=self.owner.principal_id,
            expected_peer_server_identity=incoming["peer_server_identity"],
            expected_transcript_hash=incoming["transcript_hash"],
            idempotency_key=_uuid(),
        )["pairing"]
        self.case.assertEqual(approved["granted_scopes"], PAIRING_SCOPES)
        self.case.assertTrue(set(TEAMSPACE_SCOPES).issubset(approved["granted_scopes"]))

        paired = self.member.poll_pairing(outgoing["id"])
        self.case.assertEqual(paired["status"], "approved")
        self.case.assertEqual(paired["transcript_hash"], incoming["transcript_hash"])
        self.case.assertEqual(paired["sas_words"], incoming["sas_words"])
        activated = self.member.activate_pairing(
            paired["id"],
            expected_connection_id=paired["connection_id"],
            expected_host_server_identity=paired["host_server_identity"],
            expected_hub_id=paired["hub_id"],
        )
        self.case.assertEqual(
            activated["active_connection_id"],
            paired["connection_id"],
        )

        self.pairing_id = paired["id"]
        self.connection_id = paired["connection_id"]
        self.peer_id = approved["connection_id"]
        self.peer_server_identity = incoming["peer_server_identity"]
        self.certificate_fingerprint = approved["certificate_fingerprint"]

    def peer_proxy_json(
        self,
        method: str,
        path: str,
        *,
        body: dict | None = None,
        query: str = "",
        expected_status: int = 200,
    ) -> dict:
        response = self.member.proxy(
            self.connection_id,
            method,
            path,
            query=query,
            headers={"content-type": "application/json"} if body is not None else None,
            body=None if body is None else json.dumps(body).encode("utf-8"),
        )
        self.case.assertEqual(response.status, expected_status, response.body)
        value = json.loads(response.body)
        self.case.assertIsInstance(value, dict)
        return value

    def peer_post_bulletin(self, body: str) -> dict:
        return self.peer_proxy_json(
            "POST",
            f"/v1/teams/{self.team_id}/network/bulletin",
            body={
                "body": body,
                "body_format": "plain",
                "idempotency_key": _uuid(),
            },
        )["post"]

    def peer_bulletin(self) -> list[dict]:
        return self.peer_proxy_json(
            "GET",
            f"/v1/teams/{self.team_id}/network/bulletin",
            query="after_sequence=0&limit=100",
        )["posts"]

    def revoke_from_host(self) -> None:
        revoked = self.host.revoke_peer(
            peer_id=self.peer_id,
            team_id=self.team_id,
            revoked_by=self.owner.principal_id,
            expected_certificate_fingerprint=self.certificate_fingerprint,
            idempotency_key=_uuid(),
        )["peer"]
        self.case.assertEqual(revoked["status"], "revoked")


class TeamNetworkE2EAcceptanceTests(unittest.TestCase):
    def test_offline_forget_preserves_credential_until_remote_revocation_ack(self) -> None:
        host_ip = _nonloopback_ipv4()
        if host_ip is None:
            self.skipTest("no non-loopback IPv4 address is available")

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        network = TeamNetworkHarness(self, Path(temporary.name), host_ip)
        network.pair_approve_and_activate()
        connection = next(
            item
            for item in network.member.status()["pairings"]
            if item["connection_id"] == network.connection_id
        )
        network.host.configure_host(
            enabled=False,
            advertised_host=None,
            listen_port=network.port,
        )
        with self.assertRaises(SecurePeerError) as offline:
            network.member.forget_connection(
                network.connection_id,
                expected_host_server_identity=connection["host_server_identity"],
                expected_hub_id=connection["hub_id"],
                expected_certificate_fingerprint=connection[
                    "certificate_fingerprint"
                ],
            )
        self.assertEqual(offline.exception.code, "transport_failed")
        preserved = network.member.client.get_connection(network.connection_id)
        self.assertEqual(preserved["certificate_fingerprint"], connection["certificate_fingerprint"])

        network.host.configure_host(
            enabled=True,
            advertised_host=host_ip,
            listen_port=network.port,
        )
        forgotten = network.member.forget_connection(
            network.connection_id,
            expected_host_server_identity=connection["host_server_identity"],
            expected_hub_id=connection["hub_id"],
            expected_certificate_fingerprint=connection[
                "certificate_fingerprint"
            ],
        )
        self.assertFalse(
            any(
                item.get("connection_id") == network.connection_id
                for item in forgotten["pairings"]
            )
        )

    def test_disconnect_reconnect_forget_and_repair_have_one_logical_peer(self) -> None:
        host_ip = _nonloopback_ipv4()
        if host_ip is None:
            self.skipTest("no non-loopback IPv4 address is available")

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        network = TeamNetworkHarness(self, Path(temporary.name), host_ip)
        network.pair_approve_and_activate()

        online = next(
            item
            for item in network.member.status()["pairings"]
            if item["connection_id"] == network.connection_id
        )
        self.assertEqual(online["trust_state"], "approved")
        self.assertEqual(online["transport_state"], "online")
        incoming = next(
            item
            for item in network.host.status()["pairings"]
            if item.get("peer_server_identity") == MEMBER_SERVER_IDENTITY
            and item.get("trust_state") == "approved"
        )
        self.assertEqual(incoming["transport_state"], "online")
        self.assertIsNotNone(incoming["last_seen_at"])

        # Presence expires independently of certificate trust, then the next
        # pinned health heartbeat reactivates the same logical node.
        self.assertEqual(
            network.hub.expire_secure_peer_leases(int(time.time()) + 1),
            1,
        )
        member_node = next(
            server
            for server in network.hub.get_network(
                network.owner, network.team_id
            )["servers"]
            if server["server_identity"] == MEMBER_SERVER_IDENTITY
        )
        self.assertEqual(member_node["status"], "offline")
        heartbeat = network.member.maintenance_once()
        self.assertTrue(heartbeat["healthy"])
        member_node = next(
            server
            for server in network.hub.get_network(
                network.owner, network.team_id
            )["servers"]
            if server["server_identity"] == MEMBER_SERVER_IDENTITY
        )
        self.assertEqual(member_node["status"], "active")

        disconnected = network.member.deactivate_connection(
            network.connection_id,
            expected_host_server_identity=online["host_server_identity"],
            expected_hub_id=online["hub_id"],
        )
        inactive = next(
            item
            for item in disconnected["pairings"]
            if item["connection_id"] == network.connection_id
        )
        self.assertEqual(inactive["trust_state"], "approved")
        self.assertEqual(inactive["transport_state"], "disconnected")

        reconnected = network.member.activate_pairing(
            inactive["id"],
            expected_connection_id=network.connection_id,
            expected_host_server_identity=inactive["host_server_identity"],
            expected_hub_id=inactive["hub_id"],
        )
        restored = next(
            item
            for item in reconnected["pairings"]
            if item["connection_id"] == network.connection_id
        )
        self.assertEqual(restored["transport_state"], "online")

        forgotten = network.member.forget_connection(
            network.connection_id,
            expected_host_server_identity=restored["host_server_identity"],
            expected_hub_id=restored["hub_id"],
            expected_certificate_fingerprint=restored["certificate_fingerprint"],
        )
        self.assertFalse(
            any(
                item.get("connection_id") == network.connection_id
                for item in forgotten["pairings"]
            )
        )
        host_peer = next(
            item
            for item in network.host.list_peers(team_id=network.team_id)["peers"]
            if item["connection_id"] == network.peer_id
        )
        self.assertEqual(host_peer["trust_state"], "revoked")

        # Re-pairing the same stable server identity creates one successor,
        # never a second simultaneously active logical binding.
        network.pair_approve_and_activate()
        active_peers = [
            item
            for item in network.host.list_peers(team_id=network.team_id)["peers"]
            if item["peer_server_identity"] == MEMBER_SERVER_IDENTITY
            and item["trust_state"] == "approved"
        ]
        self.assertEqual(len(active_peers), 1)
        connection = network.hub.connect()
        try:
            active_bindings = connection.execute(
                """SELECT COUNT(*) AS count FROM network_peer_bindings
                WHERE team_id=? AND peer_server_identity=? AND status='active'""",
                (network.team_id, MEMBER_SERVER_IDENTITY),
            ).fetchone()["count"]
        finally:
            connection.close()
        self.assertEqual(int(active_bindings), 1)

    def test_two_servers_use_passive_team_network_and_converge_after_revocation(self) -> None:
        host_ip = _nonloopback_ipv4()
        if host_ip is None:
            self.skipTest("no non-loopback IPv4 address is available")

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        network = TeamNetworkHarness(self, Path(temporary.name), host_ip)
        network.pair_approve_and_activate()

        health = network.peer_proxy_json("GET", "/v1/health")
        capability = health["capabilities"]["team_network_v1"]
        self.assertEqual(
            capability,
            {
                "available": True,
                "version": 1,
                "logical_servers": True,
                "agent_registry": True,
                "bulletin": True,
                "mailbox": True,
                "delivery_receipts": ["delivered", "read"],
                "passive_requests": True,
                "server_invites": False,
                "skill_attachments": False,
                "dispatch": False,
                "max_agents_per_server": 256,
                "max_page_items": 100,
                "max_body_bytes": 8_192,
            },
        )

        host_projection = network.hub.get_network(network.owner, network.team_id)
        peer_projection = network.peer_proxy_json(
            "GET",
            f"/v1/teams/{network.team_id}/network",
        )
        self.assertEqual(host_projection["network"], peer_projection["network"])
        self.assertEqual(host_projection["network"]["hub_id"], network.hub.hub_id)
        self.assertEqual(len(host_projection["servers"]), 2)
        host_servers = {
            server["server_identity"]: server
            for server in host_projection["servers"]
        }
        peer_servers = {
            server["server_identity"]: server
            for server in peer_projection["servers"]
        }
        self.assertEqual(set(host_servers), {HOST_SERVER_IDENTITY, MEMBER_SERVER_IDENTITY})
        self.assertEqual(set(peer_servers), set(host_servers))
        host_node_id = host_servers[HOST_SERVER_IDENTITY]["id"]
        member_node_id = host_servers[MEMBER_SERVER_IDENTITY]["id"]
        self.assertTrue(host_servers[HOST_SERVER_IDENTITY]["is_host"])
        self.assertEqual(host_servers[HOST_SERVER_IDENTITY]["display_name"], "Sonic")
        self.assertEqual(peer_servers[HOST_SERVER_IDENTITY]["display_name"], "Sonic")
        self.assertTrue(host_servers[HOST_SERVER_IDENTITY]["owned_by_caller"])
        self.assertFalse(host_servers[MEMBER_SERVER_IDENTITY]["owned_by_caller"])
        self.assertTrue(peer_servers[MEMBER_SERVER_IDENTITY]["owned_by_caller"])
        self.assertFalse(peer_servers[HOST_SERVER_IDENTITY]["owned_by_caller"])
        self.assertTrue(all(server["status"] == "active" for server in host_servers.values()))

        host_reference = {
            "team_id": network.team_id,
            "recipient_kind": "server",
            "target_id": host_node_id,
            "display_name_snapshot": "Sonic",
        }
        self.assertEqual(
            network.member.resolve_team_references([host_reference]),
            [host_reference],
        )
        with self.assertRaises(SecurePeerError) as stale_alias:
            network.member.resolve_team_references([
                {
                    **host_reference,
                    "display_name_snapshot": "Host server",
                }
            ])
        self.assertEqual(stale_alias.exception.code, "team_reference_invalid")
        remote_routes = network.member.agent_mail_route_profiles()
        self.assertIn(
            (host_node_id, "Sonic"),
            {
                (route["destination_id"], route["display_name"])
                for route in remote_routes
            },
        )

        host_agent = network.hub.register_network_agent(
            network.owner,
            network.team_id,
            {
                "external_agent_id": "host-agent-chat",
                "backend": "codex",
                "display_name": "Host agent",
                "idempotency_key": _uuid(),
            },
        )["agent"]
        member_agent = network.peer_proxy_json(
            "POST",
            f"/v1/teams/{network.team_id}/network/agents",
            body={
                "external_agent_id": "member-agent-chat",
                "backend": "claude",
                "display_name": "Member agent",
                "idempotency_key": _uuid(),
            },
        )["agent"]
        self.assertEqual(host_agent["server_id"], host_node_id)
        self.assertEqual(member_agent["server_id"], member_node_id)
        self.assertEqual(host_agent["status"], "active")
        self.assertEqual(member_agent["status"], "active")
        projected_agents = {
            agent["id"]: agent
            for agent in network.peer_proxy_json(
                "GET", f"/v1/teams/{network.team_id}/network"
            )["agents"]
        }
        self.assertEqual(set(projected_agents), {host_agent["id"], member_agent["id"]})
        self.assertEqual(projected_agents[member_agent["id"]]["server_id"], member_node_id)

        self.assertEqual(network.peer_bulletin(), [])
        peer_message = network.peer_post_bulletin("Update from the member server")
        self.assertEqual(peer_message["author"]["kind"], "server")
        self.assertEqual(peer_message["author"]["id"], member_node_id)
        owner_view = network.hub.list_network_bulletin(
            network.owner,
            network.team_id,
            after_sequence=0,
            limit=100,
        )["posts"]
        self.assertEqual([post["id"] for post in owner_view], [peer_message["id"]])
        self.assertEqual(owner_view[0]["body"], "Update from the member server")

        owner_message = network.hub.create_network_bulletin_post(
            network.owner,
            network.team_id,
            {
                "body": "Reply from the host owner",
                "body_format": "plain",
                "reply_to_post_id": None,
                "idempotency_key": _uuid(),
            },
        )["post"]
        self.assertEqual(owner_message["author"]["kind"], "human")
        self.assertEqual(owner_message["author"]["id"], network.owner.principal_id)
        peer_view = network.peer_bulletin()
        self.assertEqual(
            [post["id"] for post in peer_view],
            [peer_message["id"], owner_message["id"]],
        )
        self.assertEqual(peer_view[-1]["body"], "Reply from the host owner")
        empty_member_mailbox = network.peer_proxy_json(
            "GET",
            f"/v1/teams/{network.team_id}/network/mailbox",
            query=(
                f"address_kind=server&address_id={member_node_id}"
                "&after_sequence=0&limit=100"
            ),
        )
        self.assertEqual(empty_member_mailbox["items"], [])

        host_to_peer = network.hub.create_network_mailbox_item(
            network.owner,
            network.team_id,
            {
                "to": {"kind": "server", "id": member_node_id},
                "from_agent_id": None,
                "body": "Host mailbox item",
                "body_format": "plain",
                "idempotency_key": _uuid(),
            },
        )
        self.assertEqual(host_to_peer["item"]["from"]["kind"], "human")
        self.assertEqual(host_to_peer["item"]["to"]["id"], member_node_id)
        member_mailbox = network.peer_proxy_json(
            "GET",
            f"/v1/teams/{network.team_id}/network/mailbox",
            query=(
                f"address_kind=server&address_id={member_node_id}"
                "&after_sequence=0&limit=100"
            ),
        )
        self.assertEqual(
            [entry["item"]["id"] for entry in member_mailbox["items"]],
            [host_to_peer["item"]["id"]],
        )
        bulletin_after_mail = network.peer_bulletin()
        self.assertEqual(
            [post["id"] for post in bulletin_after_mail],
            [peer_message["id"], owner_message["id"]],
        )
        self.assertNotIn(
            host_to_peer["item"]["id"],
            {post["id"] for post in bulletin_after_mail},
        )
        host_delivery_id = host_to_peer["delivery"]["id"]
        delivered = network.peer_proxy_json(
            "POST",
            (
                f"/v1/teams/{network.team_id}/network/deliveries/"
                f"{host_delivery_id}/receipts"
            ),
            body={"state": "delivered", "idempotency_key": _uuid()},
        )["delivery"]
        self.assertEqual(delivered["state"], "delivered")
        self.assertIsNotNone(delivered["delivered_at"])
        read = network.peer_proxy_json(
            "POST",
            (
                f"/v1/teams/{network.team_id}/network/deliveries/"
                f"{host_delivery_id}/receipts"
            ),
            body={"state": "read", "idempotency_key": _uuid()},
        )["delivery"]
        self.assertEqual(read["state"], "read")
        self.assertIsNotNone(read["read_at"])
        self.assertEqual(
            network.hub.get_network_item(
                network.owner, network.team_id, host_to_peer["item"]["id"]
            )["delivery"]["state"],
            "read",
        )

        peer_to_host = network.peer_proxy_json(
            "POST",
            f"/v1/teams/{network.team_id}/network/mailbox",
            body={
                "to": {"kind": "server", "id": host_node_id},
                "from_agent_id": None,
                "body": "Peer mailbox item",
                "body_format": "markdown",
                "idempotency_key": _uuid(),
            },
        )
        self.assertEqual(peer_to_host["item"]["from"]["kind"], "server")
        self.assertEqual(peer_to_host["item"]["from"]["id"], member_node_id)
        host_mailbox = network.hub.list_network_mailbox(
            network.owner,
            network.team_id,
            address_kind="server",
            address_id=host_node_id,
            after_sequence=0,
            limit=100,
        )
        self.assertEqual(
            [entry["item"]["id"] for entry in host_mailbox["items"]],
            [peer_to_host["item"]["id"]],
        )
        peer_delivery_id = peer_to_host["delivery"]["id"]
        for state in ("delivered", "read"):
            receipt = network.hub.record_network_delivery_receipt(
                network.owner,
                network.team_id,
                peer_delivery_id,
                {"state": state, "idempotency_key": _uuid()},
            )["delivery"]
            self.assertEqual(receipt["state"], state)
        peer_item = network.peer_proxy_json(
            "GET",
            (
                f"/v1/teams/{network.team_id}/network/items/"
                f"{peer_to_host['item']['id']}"
            ),
        )
        self.assertEqual(peer_item["delivery"]["state"], "read")

        passive_request = network.hub.create_network_request(
            network.owner,
            network.team_id,
            {
                "to": {"kind": "server", "id": member_node_id},
                "from_agent_id": None,
                "body": "Please acknowledge this passive request",
                "body_format": "plain",
                "expires_in_seconds": 3_600,
                "idempotency_key": _uuid(),
            },
        )
        request_id = passive_request["request"]["id"]
        self.assertEqual(request_id, passive_request["item"]["id"])
        self.assertEqual(passive_request["request"]["status"], "open")
        member_request_mailbox = network.peer_proxy_json(
            "GET",
            f"/v1/teams/{network.team_id}/network/mailbox",
            query=(
                f"address_kind=server&address_id={member_node_id}"
                f"&after_sequence={host_to_peer['item']['sequence']}&limit=100"
            ),
        )
        self.assertEqual(
            [entry["item"]["id"] for entry in member_request_mailbox["items"]],
            [request_id],
        )
        request_before_reply = network.peer_proxy_json(
            "GET",
            f"/v1/teams/{network.team_id}/network/requests/{request_id}",
        )
        self.assertEqual(request_before_reply["request"]["status"], "open")
        self.assertIsNone(request_before_reply["reply"])
        self.assertEqual(network.delivery_checks, [])

        reply = network.peer_proxy_json(
            "POST",
            f"/v1/teams/{network.team_id}/network/requests/{request_id}/replies",
            body={
                "from_agent_id": None,
                "body": "Acknowledged",
                "body_format": "plain",
                "idempotency_key": _uuid(),
            },
        )
        self.assertEqual(reply["item"]["kind"], "reply")
        self.assertEqual(reply["item"]["from"]["kind"], "server")
        self.assertEqual(reply["item"]["from"]["id"], member_node_id)
        self.assertEqual(reply["item"]["to"]["id"], network.owner.principal_id)
        self.assertEqual(reply["request"]["status"], "replied")
        self.assertEqual(reply["request"]["reply_item_id"], reply["item"]["id"])
        with self.assertRaises(SecurePeerError) as peer_human_mailbox:
            network.peer_proxy_json(
                "GET",
                f"/v1/teams/{network.team_id}/network/mailbox",
                query=(
                    "address_kind=human&address_id="
                    f"{network.owner.principal_id}&after_sequence=0&limit=100"
                ),
            )
        self.assertEqual(peer_human_mailbox.exception.code, "invalid_request")
        reopened_hub = HubStore(
            network.root / "host-hub",
            managed_host_identity=HOST_SERVER_IDENTITY,
            managed_server_instance_id="team_network_host_instance",
        )
        owner_human_mailbox = reopened_hub.list_network_mailbox(
            network.owner,
            network.team_id,
            address_kind="human",
            address_id=network.owner.principal_id,
            after_sequence=0,
            limit=100,
        )
        self.assertEqual(
            [entry["item"]["id"] for entry in owner_human_mailbox["items"]],
            [reply["item"]["id"]],
        )
        reply_delivery_id = reply["delivery"]["id"]
        for state in ("delivered", "read"):
            reply_receipt = reopened_hub.record_network_delivery_receipt(
                network.owner,
                network.team_id,
                reply_delivery_id,
                {"state": state, "idempotency_key": _uuid()},
            )["delivery"]
            self.assertEqual(reply_receipt["state"], state)
        peer_reply_item = network.peer_proxy_json(
            "GET",
            f"/v1/teams/{network.team_id}/network/items/{reply['item']['id']}",
        )
        self.assertEqual(peer_reply_item["delivery"]["state"], "read")
        owner_request = network.hub.get_network_request(
            network.owner, network.team_id, request_id
        )
        self.assertEqual(owner_request["reply"]["item"]["id"], reply["item"]["id"])
        self.assertEqual(owner_request["reply"]["item"]["body"], "Acknowledged")
        second_reply = network.peer_proxy_json(
            "POST",
            f"/v1/teams/{network.team_id}/network/requests/{request_id}/replies",
            body={
                "from_agent_id": None,
                "body": "A duplicate reply",
                "body_format": "plain",
                "idempotency_key": _uuid(),
            },
            expected_status=409,
        )
        self.assertEqual(second_reply["error"]["code"], "request_unavailable")

        no_dispatch = network.peer_proxy_json(
            "POST",
            f"/v1/teams/{network.team_id}/network/dispatch",
            body={"agent_id": member_agent["id"], "idempotency_key": _uuid()},
            expected_status=403,
        )
        self.assertEqual(no_dispatch["error"]["code"], "route_forbidden")
        self.assertEqual(network.delivery_checks, [])
        self.assertEqual(
            network.member.client.list_published_routes(),
            [],
        )

        network.revoke_from_host()
        with self.assertRaises(SecurePeerError) as revoked_request:
            network.member.proxy(
                network.connection_id,
                "GET",
                f"/v1/teams/{network.team_id}/network",
                query="",
                headers=None,
                body=None,
            )
        self.assertEqual(revoked_request.exception.code, "peer_revoked")
        self.assertEqual(revoked_request.exception.status_code, 401)

        member_status = network.member.status()
        self.assertIsNone(member_status["active_connection_id"])
        connection = next(
            item
            for item in member_status["pairings"]
            if item["connection_id"] == network.connection_id
        )
        self.assertEqual(connection["status"], "revoked")
        self.assertFalse(
            any(
                item["status"] in {"requesting", "pending_approval", "approved", "connected"}
                for item in member_status["pairings"]
                if item["id"] == network.pairing_id
            )
        )
        host_peer = network.host.list_peers(team_id=network.team_id)["peers"][0]
        self.assertEqual(host_peer["status"], "revoked")
        peer_claims = network.hub.secure_peer_claims(
            peer_id=network.peer_id,
            peer_server_identity=network.peer_server_identity,
            team_id=network.team_id,
            scopes=frozenset(PAIRING_SCOPES),
            expires_at=int(time.time()) + 300,
            display_name="Member server",
        )
        with self.assertRaises(HubError) as revoked_service:
            network.hub.session_snapshot(peer_claims)
        self.assertEqual(revoked_service.exception.code, "authentication_required")
        self.assertEqual(revoked_service.exception.status_code, 401)

        with self.assertRaises(SecurePeerError) as local_rejection:
            network.member.proxy(
                network.connection_id,
                "GET",
                f"/v1/teams/{network.team_id}/network",
                query="",
                headers=None,
                body=None,
            )
        self.assertEqual(local_rejection.exception.code, "connection_unavailable")
        self.assertEqual(network.delivery_checks, [])


if __name__ == "__main__":
    unittest.main()
