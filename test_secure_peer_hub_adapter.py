import json
from collections import deque
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
import uuid
from unittest import mock

from agentsdock_team_hub.secure_peer import (
    MAX_RESPONSE_BODY_BYTES,
    PeerAuthorization,
    ProxyRequest,
)
from agentsdock_team_hub.secure_peer_hub import SecurePeerHubAdapter
from agentsdock_team_hub.store import (
    MAX_NETWORK_BODY_BYTES,
    MAX_NETWORK_PAGE_RESPONSE_BYTES,
    MAX_SECURE_PEER_BINDING_LOOKUP_IDS,
    HubError,
    HubStore,
)


class SecurePeerHubAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = HubStore(self.root)
        proof = (self.root / "bootstrap-owner.proof").read_text().strip()
        bootstrap = self.store.bootstrap(
            proof,
            "owner@example.com",
            "Owner",
            "Owner Mac",
        )
        self.team_id = bootstrap["teams"][0]["id"]
        owner = self.store.verify_access(bootstrap["access_token"])
        self.owner = owner
        channel = self.store.create_channel(
            owner,
            self.team_id,
            {
                "kind": "board",
                "visibility": "team",
                "slug": "shared",
                "display_name": "Shared",
                "participant_principal_ids": [],
                "idempotency_key": "channel-create-1",
            },
        )["channel"]
        self.channel_id = channel["id"]
        self.peer_id = str(uuid.uuid4())
        self.peer = PeerAuthorization(
            self.peer_id,
            str(uuid.uuid4()),
            "peer-server-identity",
            self.team_id,
            frozenset({"teamspace.read", "teamspace.write"}),
            "sha256:" + "a" * 64,
            int(time.time()) + 600,
            "Paired server",
        )
        self.adapter = SecurePeerHubAdapter(self.store)
        self.adapter.provision_peer(
            {
                "peer_id": self.peer_id,
                "peer_server_identity": self.peer.peer_server_identity,
                "team_id": self.team_id,
            },
            display_name=self.peer.peer_display_name,
        )
        # Direct adapter tests bypass the gateway callback that records an
        # authenticated heartbeat before forwarding each request.
        self.adapter.record_peer_heartbeat(self.peer_id, self.team_id)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        query: str = "",
        body: dict | None = None,
    ):
        return self.adapter.forward(
            ProxyRequest(
                method,
                path,
                query,
                (),
                b"" if body is None else json.dumps(body).encode(),
                self.peer,
            )
        )

    def test_peer_session_and_team_are_service_scoped(self) -> None:
        session = self.request("GET", "/v1/peer-session")
        self.assertEqual(session.status, 200)
        value = json.loads(session.body)
        self.assertEqual(value["principal"]["id"], "service_secure_peer_" + self.peer_id.replace("-", ""))
        self.assertIsNone(value["principal"]["email"])
        self.assertEqual(value["principal"]["kind"], "service")
        self.assertEqual(len(value["teams"]), 1)
        self.assertEqual(value["teams"][0]["id"], self.team_id)
        self.assertEqual(value["teams"][0]["role"], "automation")
        self.assertEqual(value["teams"][0]["status"], "active")

    def test_member_projection_pages_past_fifty_without_truncation(self) -> None:
        timestamp = int(time.time())
        connection = self.store.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for index in range(55):
                principal_id = f"principal_page_member_{index:04d}"
                connection.execute(
                    """
                    INSERT INTO principals(
                        id,kind,scope_team_id,display_name,status,created_at,updated_at
                    ) VALUES (?, 'human', NULL, ?, 'active', ?, ?)
                    """,
                    (principal_id, f"Member {index:04d}", timestamp, timestamp),
                )
                connection.execute(
                    "INSERT INTO human_accounts(principal_id,email_normalized,created_at) "
                    "VALUES (?,?,?)",
                    (principal_id, f"member-{index:04d}@example.test", timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO memberships(
                        id,team_id,principal_id,role,status,invited_by_principal_id,
                        created_at,updated_at
                    ) VALUES (?,?,?,'member','active',?,?,?)
                    """,
                    (
                        f"membership_page_member_{index:04d}",
                        self.team_id,
                        principal_id,
                        self.owner.principal_id,
                        timestamp,
                        timestamp,
                    ),
                )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

        first = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/members",
            query="limit=50",
        )
        self.assertEqual(first.status, 200, first.body)
        first_value = json.loads(first.body)
        self.assertEqual(len(first_value["members"]), 50)
        self.assertTrue(first_value["has_more"])
        self.assertIsInstance(first_value["next_cursor"], str)
        second = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/members",
            query="limit=50&cursor=" + first_value["next_cursor"],
        )
        self.assertEqual(second.status, 200, second.body)
        second_value = json.loads(second.body)
        self.assertFalse(second_value["has_more"])
        projected = first_value["members"] + second_value["members"]
        projected_ids = {item["principal_id"] for item in projected}
        self.assertEqual(len(projected_ids), len(projected))
        self.assertTrue(
            {f"principal_page_member_{index:04d}" for index in range(55)}
            .issubset(projected_ids)
        )

    def test_message_round_trip_uses_no_bearer_and_rejects_extra_fields(self) -> None:
        created = self.request(
            "POST",
            f"/v1/channels/{self.channel_id}/messages",
            body={
                "body": "hello over mTLS",
                "body_format": "plain",
                "kind": "post",
                "idempotency_key": "message-request-1",
            },
        )
        self.assertEqual(created.status, 200, created.body)
        listed = self.request(
            "GET",
            f"/v1/channels/{self.channel_id}/messages",
            query="limit=20",
        )
        self.assertEqual(listed.status, 200, listed.body)
        self.assertEqual(json.loads(listed.body)["messages"][0]["body"], "hello over mTLS")

        malformed = self.request(
            "POST",
            f"/v1/channels/{self.channel_id}/messages",
            body={
                "body": "not accepted",
                "idempotency_key": "message-request-2",
                "refresh_token": "must-never-cross-this-boundary",
            },
        )
        self.assertEqual(malformed.status, 422)

    def test_server_author_can_delete_through_adapter_but_unrelated_peer_cannot(self) -> None:
        created = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/messages",
            body={
                "kind": "message",
                "body": "server-authored deletion",
                "body_format": "plain",
                "recipients": [{"kind": "all"}],
                "idempotency_key": "adapter-message-create-001",
            },
        )
        self.assertEqual(created.status, 200, created.body)
        message = json.loads(created.body)["message"]
        self.assertEqual(message["sender"]["kind"], "server")

        malformed = self.request(
            "DELETE",
            f"/v1/teams/{self.team_id}/network/messages/{message['id']}",
            body={
                "idempotency_key": "adapter-message-delete-bad",
                "force": True,
            },
        )
        self.assertEqual(malformed.status, 422, malformed.body)

        deleted = self.request(
            "DELETE",
            f"/v1/teams/{self.team_id}/network/messages/{message['id']}",
            body={"idempotency_key": "adapter-message-delete-001"},
        )
        self.assertEqual(deleted.status, 200, deleted.body)
        self.assertEqual(
            json.loads(deleted.body),
            {"deleted": True, "message_id": message["id"]},
        )
        detail = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network/messages/{message['id']}",
        )
        self.assertEqual(detail.status, 404, detail.body)

        bulletin = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/bulletin",
            body={
                "body": "server-authored bulletin deletion",
                "body_format": "plain",
                "idempotency_key": "adapter-bulletin-create-001",
            },
        )
        self.assertEqual(bulletin.status, 200, bulletin.body)
        post_id = json.loads(bulletin.body)["post"]["id"]
        deleted_bulletin = self.request(
            "DELETE",
            f"/v1/teams/{self.team_id}/network/bulletin/{post_id}",
            body={"idempotency_key": "adapter-bulletin-delete-001"},
        )
        self.assertEqual(deleted_bulletin.status, 200, deleted_bulletin.body)
        self.assertEqual(
            json.loads(deleted_bulletin.body),
            {"deleted": True, "post_id": post_id},
        )

        journal = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network/deletions",
            query="after_sequence=0&limit=10",
        )
        self.assertEqual(journal.status, 200, journal.body)
        journal_value = json.loads(journal.body)
        self.assertEqual(
            set(journal_value),
            {"deletions", "next_after_sequence", "has_more"},
        )
        self.assertEqual(
            [(item["kind"], item["id"]) for item in journal_value["deletions"]],
            [("message", message["id"]), ("bulletin", post_id)],
        )

        owner_message = self.store.create_team_message(
            self.owner,
            self.team_id,
            {
                "kind": "message",
                "body": "human-owned message",
                "body_format": "plain",
                "recipients": [{"kind": "all"}],
                "idempotency_key": "adapter-owner-message-001",
            },
        )["message"]
        forbidden = self.request(
            "DELETE",
            f"/v1/teams/{self.team_id}/network/messages/{owner_message['id']}",
            body={"idempotency_key": "adapter-owner-delete-denied"},
        )
        self.assertEqual(forbidden.status, 403, forbidden.body)
        self.assertEqual(json.loads(forbidden.body)["error"]["code"], "forbidden")

    def test_repaired_peer_can_delete_message_authored_by_same_server_node(self) -> None:
        created = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/messages",
            body={
                "kind": "message",
                "body": "survives peer credential rotation",
                "body_format": "plain",
                "recipients": [{"kind": "all"}],
                "idempotency_key": "adapter-before-repair-create-1",
            },
        )
        self.assertEqual(created.status, 200, created.body)
        message = json.loads(created.body)["message"]
        connection = self.store.connect()
        try:
            source = connection.execute(
                "SELECT * FROM team_messages WHERE id=?",
                (message["id"],),
            ).fetchone()
            self.assertIsNotNone(source)
            source_before = dict(source)
            old_principal_id = str(source["sender_principal_id"])
            authoritative_node_id = str(source["sender_node_id"])
        finally:
            connection.close()

        # A human member can address/read the managed host's Inbox, but that
        # convenience must never turn into server authorship for deletion.
        issued = self.store.issue_invite(
            self.owner,
            self.team_id,
            "managed-address-member@example.com",
            "member",
            3_600,
        )
        human_bundle = self.store.redeem_invite(
            issued["token"],
            "managed-address-member@example.com",
            "Managed address member",
            "Member Mac",
        )
        human_claims = self.store.verify_access(human_bundle["access_token"])
        self.store.managed_host_identity = self.peer.peer_server_identity
        connection = self.store.connect()
        try:
            self.assertIn(
                ("server", authoritative_node_id),
                self.store._team_owned_addresses(
                    connection,
                    human_claims,
                    self.team_id,
                    "member",
                ),
            )
        finally:
            connection.close()
        with self.assertRaises(HubError) as human_denied:
            self.store.delete_team_message(
                human_claims,
                self.team_id,
                message["id"],
                {"idempotency_key": "human-managed-node-delete-denied"},
            )
        self.assertEqual(human_denied.exception.code, "forbidden")

        # Another valid peer binding controls a different authoritative node
        # and cannot claim this source. Swapping its signed identity snapshot
        # to the source identity fails the exact binding check as well.
        other_peer_id = str(uuid.uuid4())
        other_peer = PeerAuthorization(
            other_peer_id,
            str(uuid.uuid4()),
            "different-peer-server-identity",
            self.team_id,
            frozenset({"teamspace.read", "teamspace.write"}),
            "sha256:" + "d" * 64,
            int(time.time()) + 600,
            "Different paired server",
        )
        self.adapter.provision_peer(
            {
                "peer_id": other_peer_id,
                "peer_server_identity": other_peer.peer_server_identity,
                "team_id": self.team_id,
            },
            display_name=other_peer.peer_display_name,
        )
        self.adapter.record_peer_heartbeat(other_peer_id, self.team_id)
        other_denied = self.adapter.forward(
            ProxyRequest(
                "DELETE",
                f"/v1/teams/{self.team_id}/network/messages/{message['id']}",
                "",
                (),
                b'{"idempotency_key":"other-node-delete-denied"}',
                other_peer,
            )
        )
        self.assertEqual(other_denied.status, 403, other_denied.body)
        forged_peer = PeerAuthorization(
            other_peer.peer_id,
            other_peer.pairing_id,
            self.peer.peer_server_identity,
            other_peer.team_id,
            other_peer.scopes,
            other_peer.certificate_fingerprint,
            other_peer.certificate_expires_at,
            other_peer.peer_display_name,
        )
        forged_denied = self.adapter.forward(
            ProxyRequest(
                "DELETE",
                f"/v1/teams/{self.team_id}/network/messages/{message['id']}",
                "",
                (),
                b'{"idempotency_key":"forged-node-delete-denied"}',
                forged_peer,
            )
        )
        self.assertEqual(forged_denied.status, 403, forged_denied.body)
        self.assertEqual(
            json.loads(forged_denied.body)["error"]["code"],
            "forbidden",
        )

        self.adapter.revoke_peer(peer_id=self.peer_id, team_id=self.team_id)
        repaired_peer_id = str(uuid.uuid4())
        repaired_peer = PeerAuthorization(
            repaired_peer_id,
            str(uuid.uuid4()),
            self.peer.peer_server_identity,
            self.team_id,
            frozenset({"teamspace.read", "teamspace.write"}),
            "sha256:" + "c" * 64,
            int(time.time()) + 600,
            "Repaired paired server",
        )
        repaired_principal_id = self.adapter.provision_peer(
            {
                "peer_id": repaired_peer_id,
                "peer_server_identity": repaired_peer.peer_server_identity,
                "team_id": self.team_id,
            },
            display_name=repaired_peer.peer_display_name,
        )
        self.adapter.record_peer_heartbeat(repaired_peer_id, self.team_id)
        self.assertNotEqual(repaired_principal_id, old_principal_id)
        connection = self.store.connect()
        try:
            rebound = connection.execute(
                "SELECT node_id,service_principal_id FROM network_peer_bindings "
                "WHERE peer_id=? AND status='active'",
                (repaired_peer_id,),
            ).fetchone()
            self.assertIsNotNone(rebound)
            self.assertEqual(rebound["node_id"], authoritative_node_id)
            self.assertEqual(rebound["service_principal_id"], repaired_principal_id)
        finally:
            connection.close()

        deleted = self.adapter.forward(
            ProxyRequest(
                "DELETE",
                f"/v1/teams/{self.team_id}/network/messages/{message['id']}",
                "",
                (),
                json.dumps(
                    {"idempotency_key": "adapter-after-repair-delete-1"}
                ).encode(),
                repaired_peer,
            )
        )
        self.assertEqual(deleted.status, 200, deleted.body)
        self.assertEqual(
            json.loads(deleted.body),
            {"deleted": True, "message_id": message["id"]},
        )
        replay = self.adapter.forward(
            ProxyRequest(
                "DELETE",
                f"/v1/teams/{self.team_id}/network/messages/{message['id']}",
                "",
                (),
                json.dumps(
                    {"idempotency_key": "adapter-after-repair-delete-1"}
                ).encode(),
                repaired_peer,
            )
        )
        self.assertEqual(replay.status, 200, replay.body)
        self.assertEqual(replay.body, deleted.body)
        connection = self.store.connect()
        try:
            self.assertEqual(
                dict(
                    connection.execute(
                        "SELECT * FROM team_messages WHERE id=?",
                        (message["id"],),
                    ).fetchone()
                ),
                source_before,
            )
            tombstone = connection.execute(
                "SELECT deleted_by_principal_id FROM network_content_deletions "
                "WHERE resource_kind='message' AND resource_id=?",
                (message["id"],),
            ).fetchall()
            self.assertEqual(len(tombstone), 1)
            self.assertEqual(
                tombstone[0]["deleted_by_principal_id"],
                repaired_principal_id,
            )
        finally:
            connection.close()

    def test_revocation_is_checked_again_for_every_request(self) -> None:
        self.adapter.revoke_peer(peer_id=self.peer_id, team_id=self.team_id)
        denied = self.request("GET", "/v1/teams")
        self.assertEqual(denied.status, 401)
        self.assertEqual(json.loads(denied.body)["error"]["code"], "authentication_required")

    def test_active_binding_lookup_is_exact_bounded_and_presence_independent(self) -> None:
        unknown_peer_id = str(uuid.uuid4())
        self.assertEqual(
            self.adapter.active_binding_peer_ids(
                [unknown_peer_id, self.peer_id, self.peer_id],
                self.peer.peer_server_identity,
            ),
            {self.peer_id},
        )
        self.assertEqual(
            self.adapter.active_binding_peer_ids(
                [self.peer_id],
                "different-peer-server-identity",
            ),
            set(),
        )

        connection = self.store.connect()
        try:
            connection.execute(
                """
                UPDATE nodes SET status='offline'
                WHERE id=(
                    SELECT node_id FROM network_peer_bindings WHERE peer_id=?
                )
                """,
                (self.peer_id,),
            )
        finally:
            connection.close()
        self.assertEqual(
            self.adapter.active_binding_peer_ids(
                [self.peer_id],
                self.peer.peer_server_identity,
            ),
            {self.peer_id},
        )

        with self.assertRaises(ValueError):
            self.adapter.active_binding_peer_ids(
                [self.peer_id] * (MAX_SECURE_PEER_BINDING_LOOKUP_IDS + 1),
                self.peer.peer_server_identity,
            )
        with self.assertRaises(HubError):
            self.adapter.active_binding_peer_ids(
                ["not-a-peer-id"],
                self.peer.peer_server_identity,
            )

        self.adapter.revoke_peer(peer_id=self.peer_id, team_id=self.team_id)
        self.assertEqual(
            self.adapter.active_binding_peer_ids(
                [self.peer_id],
                self.peer.peer_server_identity,
            ),
            set(),
        )
        with self.assertRaises(HubError) as raised:
            self.adapter.record_peer_heartbeat(self.peer_id, self.team_id)
        self.assertEqual(raised.exception.code, "peer_unavailable")

    def test_peer_heartbeat_reactivates_only_exact_live_binding(self) -> None:
        connection = self.store.connect()
        try:
            row = connection.execute(
                """
                SELECT n.id,n.enrolled_at,n.last_seen_at
                FROM nodes AS n JOIN network_peer_bindings AS b
                  ON b.team_id=n.team_id AND b.node_id=n.id
                WHERE b.peer_id=? AND b.team_id=?
                """,
                (self.peer_id, self.team_id),
            ).fetchone()
            assert row is not None
            heartbeat_at = max(int(row["enrolled_at"]), int(row["last_seen_at"] or 0)) + 60
            connection.execute(
                "UPDATE nodes SET status='offline' WHERE id=?",
                (row["id"],),
            )
        finally:
            connection.close()

        with mock.patch(
            "agentsdock_team_hub.store._now",
            return_value=heartbeat_at,
        ):
            self.adapter.record_peer_heartbeat(self.peer_id, self.team_id)
            self.adapter.record_peer_heartbeat(self.peer_id, self.team_id)
        connection = self.store.connect()
        try:
            current = connection.execute(
                """
                SELECT n.status,n.last_seen_at,b.status AS binding_status
                FROM nodes AS n JOIN network_peer_bindings AS b
                  ON b.team_id=n.team_id AND b.node_id=n.id
                WHERE b.peer_id=? AND b.team_id=?
                """,
                (self.peer_id, self.team_id),
            ).fetchone()
            assert current is not None
            self.assertEqual(current["status"], "active")
            self.assertEqual(current["last_seen_at"], heartbeat_at)
            self.assertEqual(current["binding_status"], "active")
            connection.execute(
                """
                UPDATE nodes SET status='suspended'
                WHERE id=(
                    SELECT node_id FROM network_peer_bindings WHERE peer_id=?
                )
                """,
                (self.peer_id,),
            )
        finally:
            connection.close()

        with self.assertRaises(HubError) as raised:
            self.adapter.record_peer_heartbeat(self.peer_id, self.team_id)
        self.assertEqual(raised.exception.code, "peer_unavailable")
        connection = self.store.connect()
        try:
            status = connection.execute(
                """
                SELECT status FROM nodes WHERE id=(
                    SELECT node_id FROM network_peer_bindings WHERE peer_id=?
                )
                """,
                (self.peer_id,),
            ).fetchone()
            assert status is not None
            self.assertEqual(status["status"], "suspended")
        finally:
            connection.close()

    def test_provisioning_does_not_claim_transport_presence(self) -> None:
        peer_id = str(uuid.uuid4())
        self.store.ensure_secure_peer_service(
            peer_id=peer_id,
            peer_server_identity="provisioned-offline-peer",
            team_id=self.team_id,
            display_name="Provisioned offline peer",
        )
        # Replaying startup projection is also not a heartbeat.
        self.store.ensure_secure_peer_service(
            peer_id=peer_id,
            peer_server_identity="provisioned-offline-peer",
            team_id=self.team_id,
            display_name="Provisioned offline peer",
        )
        connection = self.store.connect()
        try:
            row = connection.execute(
                """
                SELECT n.status,n.last_seen_at,n.display_name
                FROM nodes AS n JOIN network_peer_bindings AS b
                  ON b.team_id=n.team_id AND b.node_id=n.id
                WHERE b.peer_id=?
                """,
                (peer_id,),
            ).fetchone()
            assert row is not None
            self.assertEqual(row["status"], "offline")
            self.assertIsNone(row["last_seen_at"])
            self.assertEqual(row["display_name"], "Provisioned offline peer")
        finally:
            connection.close()

        self.adapter.record_peer_heartbeat(peer_id, self.team_id)
        connection = self.store.connect()
        try:
            row = connection.execute(
                """
                SELECT n.status,n.last_seen_at
                FROM nodes AS n JOIN network_peer_bindings AS b
                  ON b.team_id=n.team_id AND b.node_id=n.id
                WHERE b.peer_id=?
                """,
                (peer_id,),
            ).fetchone()
            assert row is not None
            self.assertEqual(row["status"], "active")
            self.assertIsInstance(row["last_seen_at"], int)
        finally:
            connection.close()

    def test_expire_peer_leases_is_idempotent_and_preserves_trust(self) -> None:
        fresh_peer_id = str(uuid.uuid4())
        self.store.ensure_secure_peer_service(
            peer_id=fresh_peer_id,
            peer_server_identity="fresh-peer-server-identity",
            team_id=self.team_id,
            display_name="Fresh paired server",
        )
        connection = self.store.connect()
        try:
            rows = connection.execute(
                """
                SELECT b.peer_id,n.id,n.enrolled_at
                FROM network_peer_bindings AS b JOIN nodes AS n
                  ON n.team_id=b.team_id AND n.id=b.node_id
                WHERE b.peer_id IN (?,?)
                """,
                (self.peer_id, fresh_peer_id),
            ).fetchall()
            by_peer = {str(row["peer_id"]): row for row in rows}
            base = max(int(row["enrolled_at"]) for row in rows)
            cutoff = base + 100
            connection.execute(
                "UPDATE nodes SET status='active',last_seen_at=? WHERE id=?",
                (cutoff - 1, by_peer[self.peer_id]["id"]),
            )
            connection.execute(
                "UPDATE nodes SET status='active',last_seen_at=? WHERE id=?",
                (cutoff, by_peer[fresh_peer_id]["id"]),
            )
        finally:
            connection.close()

        self.assertEqual(self.adapter.expire_peer_leases(cutoff), 1)
        self.assertEqual(self.adapter.expire_peer_leases(cutoff), 0)
        connection = self.store.connect()
        try:
            rows = connection.execute(
                """
                SELECT b.peer_id,b.status AS binding_status,n.status AS node_status
                FROM network_peer_bindings AS b JOIN nodes AS n
                  ON n.team_id=b.team_id AND n.id=b.node_id
                WHERE b.peer_id IN (?,?)
                """,
                (self.peer_id, fresh_peer_id),
            ).fetchall()
            by_peer = {str(row["peer_id"]): row for row in rows}
            self.assertEqual(by_peer[self.peer_id]["node_status"], "offline")
            self.assertEqual(by_peer[fresh_peer_id]["node_status"], "active")
            self.assertEqual(by_peer[self.peer_id]["binding_status"], "active")
            self.assertEqual(by_peer[fresh_peer_id]["binding_status"], "active")
        finally:
            connection.close()

        for invalid in (-1, True, 1.5, "100"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.adapter.expire_peer_leases(invalid)  # type: ignore[arg-type]

    def test_team_network_mailbox_receipts_and_passive_reply(self) -> None:
        network = self.request("GET", f"/v1/teams/{self.team_id}/network")
        self.assertEqual(network.status, 200, network.body)
        network_value = json.loads(network.body)
        self.assertEqual(len(network_value["servers"]), 1)
        server_id = network_value["servers"][0]["id"]
        self.assertTrue(network_value["servers"][0]["owned_by_caller"])

        registered = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/agents",
            body={
                "external_agent_id": "agent-local-1",
                "backend": "codex",
                "display_name": "Planner",
                "idempotency_key": "network-agent-register-1",
            },
        )
        self.assertEqual(registered.status, 200, registered.body)
        agent_id = json.loads(registered.body)["agent"]["id"]
        registered_replay = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/agents",
            body={
                "external_agent_id": "agent-local-1",
                "backend": "codex",
                "display_name": "Planner",
                "idempotency_key": "network-agent-register-1",
            },
        )
        self.assertEqual(registered_replay.body, registered.body)
        registered_conflict = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/agents",
            body={
                "external_agent_id": "agent-local-2",
                "backend": "codex",
                "display_name": "Planner",
                "idempotency_key": "network-agent-register-1",
            },
        )
        self.assertEqual(registered_conflict.status, 409)

        bulletin = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/bulletin",
            body={
                "body": "Team update",
                "body_format": "plain",
                "idempotency_key": "network-bulletin-post-1",
            },
        )
        self.assertEqual(bulletin.status, 200, bulletin.body)
        self.assertNotIn("channel_id", json.loads(bulletin.body)["post"])
        listed_bulletin = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network/bulletin",
            query="after_sequence=0&limit=10",
        )
        self.assertEqual(listed_bulletin.status, 200, listed_bulletin.body)
        self.assertEqual(json.loads(listed_bulletin.body)["posts"][0]["body"], "Team update")

        sent = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/mailbox",
            body={
                "to": {"kind": "server", "id": server_id},
                "from_agent_id": None,
                "body": "Passive mail",
                "body_format": "plain",
                "idempotency_key": "network-mail-send-1",
            },
        )
        self.assertEqual(sent.status, 200, sent.body)
        sent_value = json.loads(sent.body)
        self.assertEqual(sent_value["item"]["from"]["kind"], "server")
        self.assertEqual(sent_value["item"]["from"]["id"], server_id)
        delivery_id = sent_value["delivery"]["id"]
        inbox = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network/mailbox",
            query=f"address_kind=server&address_id={server_id}&after_sequence=0&limit=10",
        )
        self.assertEqual(inbox.status, 200, inbox.body)
        self.assertEqual(json.loads(inbox.body)["items"][0]["item"]["body"], "Passive mail")
        malformed_query = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network/mailbox",
            query=(
                f"address_kind=server&address_id={server_id}"
                "&after_sequence=9223372036854775808"
            ),
        )
        self.assertEqual(malformed_query.status, 422)

        delivered = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
            body={
                "state": "delivered",
                "idempotency_key": "network-receipt-delivered-1",
            },
        )
        self.assertEqual(delivered.status, 200, delivered.body)
        read = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
            body={
                "state": "read",
                "idempotency_key": "network-receipt-read-1",
            },
        )
        self.assertEqual(read.status, 200, read.body)
        self.assertEqual(json.loads(read.body)["delivery"]["state"], "read")

        passive = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/requests",
            body={
                "to": {"kind": "server", "id": server_id},
                "body": "Can you inspect this?",
                "idempotency_key": "network-request-create-1",
            },
        )
        self.assertEqual(passive.status, 200, passive.body)
        passive_value = json.loads(passive.body)
        request_id = passive_value["request"]["id"]
        before_reply = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network/requests/{request_id}",
        )
        self.assertEqual(before_reply.status, 200, before_reply.body)
        before_reply_value = json.loads(before_reply.body)
        self.assertEqual(before_reply_value["request"]["id"], request_id)
        self.assertEqual(before_reply_value["request"]["status"], "open")
        self.assertIsNone(before_reply_value["reply"])
        replied = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/requests/{request_id}/replies",
            body={
                "from_agent_id": None,
                "body": "Reviewed; no turn was started.",
                "idempotency_key": "network-request-reply-1",
            },
        )
        self.assertEqual(replied.status, 200, replied.body)
        replied_value = json.loads(replied.body)
        self.assertEqual(replied_value["request"]["status"], "replied")
        after_reply = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network/requests/{request_id}",
        )
        self.assertEqual(after_reply.status, 200, after_reply.body)
        after_reply_value = json.loads(after_reply.body)
        self.assertEqual(after_reply_value["request"]["status"], "replied")
        self.assertEqual(
            after_reply_value["request"]["reply_item_id"],
            replied_value["item"]["id"],
        )
        self.assertEqual(
            after_reply_value["reply"]["item"]["id"],
            replied_value["item"]["id"],
        )
        second_reply = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/requests/{request_id}/replies",
            body={
                "from_agent_id": None,
                "body": "A second reply is forbidden.",
                "idempotency_key": "network-request-reply-2",
            },
        )
        self.assertEqual(second_reply.status, 409)
        connection = self.store.connect()
        try:
            self.assertEqual(
                int(connection.execute("SELECT COUNT(*) FROM dispatch_requests").fetchone()[0]),
                0,
            )
        finally:
            connection.close()

        attachment_rejected = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/mailbox",
            body={
                "to": {"kind": "server", "id": server_id},
                "body": "not accepted",
                "idempotency_key": "network-mail-send-2",
                "attachments": ["skill-1"],
            },
        )
        self.assertEqual(attachment_rejected.status, 422)

    def test_legacy_peer_mail_rejects_agent_targeting_and_impersonation(self) -> None:
        network = json.loads(
            self.request("GET", f"/v1/teams/{self.team_id}/network").body
        )
        server_id = network["servers"][0]["id"]
        registered = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/agents",
            body={
                "external_agent_id": "legacy-boundary-agent",
                "backend": "codex",
                "display_name": "Legacy boundary agent",
                "idempotency_key": "legacy-boundary-register-1",
            },
        )
        agent_id = json.loads(registered.body)["agent"]["id"]

        denied_bodies = (
            (
                "mailbox",
                {
                    "to": {"kind": "agent", "id": agent_id},
                    "body": "Agent target is retired",
                    "idempotency_key": "legacy-agent-target-mail-1",
                },
            ),
            (
                "mailbox",
                {
                    "to": {"kind": "server", "id": server_id},
                    "from_agent_id": agent_id,
                    "body": "Agent authorship is retired",
                    "idempotency_key": "legacy-agent-author-mail-1",
                },
            ),
            (
                "requests",
                {
                    "to": {"kind": "agent", "id": agent_id},
                    "body": "Agent request target is retired",
                    "idempotency_key": "legacy-agent-target-request-1",
                },
            ),
            (
                "requests",
                {
                    "to": {"kind": "server", "id": server_id},
                    "from_agent_id": agent_id,
                    "body": "Agent request authorship is retired",
                    "idempotency_key": "legacy-agent-author-request-1",
                },
            ),
        )
        for route, body in denied_bodies:
            with self.subTest(route=route, body=body["body"]):
                denied = self.request(
                    "POST",
                    f"/v1/teams/{self.team_id}/network/{route}",
                    body=body,
                )
                self.assertEqual(denied.status, 422, denied.body)
                self.assertEqual(
                    json.loads(denied.body)["error"]["code"],
                    "invalid_request",
                )

        agent_mailbox = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network/mailbox",
            query=(
                f"address_kind=agent&address_id={agent_id}"
                "&after_sequence=0&limit=10"
            ),
        )
        self.assertEqual(agent_mailbox.status, 422, agent_mailbox.body)
        self.assertEqual(
            json.loads(agent_mailbox.body)["error"]["code"],
            "invalid_request",
        )

        created = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/requests",
            body={
                "to": {"kind": "server", "id": server_id},
                "from_agent_id": None,
                "body": "Server-level passive request",
                "idempotency_key": "legacy-server-request-1",
            },
        )
        self.assertEqual(created.status, 200, created.body)
        request_id = json.loads(created.body)["request"]["id"]
        forged_reply = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/requests/{request_id}/replies",
            body={
                "from_agent_id": agent_id,
                "body": "Forged agent reply",
                "idempotency_key": "legacy-agent-reply-1",
            },
        )
        self.assertEqual(forged_reply.status, 422, forged_reply.body)
        self.assertEqual(
            json.loads(forged_reply.body)["error"]["code"],
            "invalid_request",
        )
        unchanged = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network/requests/{request_id}",
        )
        self.assertEqual(json.loads(unchanged.body)["request"]["status"], "open")
        self.assertIsNone(json.loads(unchanged.body)["reply"])

    def test_authenticated_peer_rate_and_concurrency_limits_fail_closed(self) -> None:
        now = time.monotonic()
        self.adapter._rate_events[(self.peer_id, "all")] = deque([now] * 240)
        limited = self.request("GET", "/v1/teams")
        self.assertEqual(limited.status, 429)
        self.adapter._rate_events.clear()
        self.adapter._in_flight[self.peer_id] = 4
        concurrent = self.request("GET", "/v1/teams")
        self.assertEqual(concurrent.status, 429)

    def test_network_body_and_page_caps_fit_the_secure_transport(self) -> None:
        network = json.loads(
            self.request("GET", f"/v1/teams/{self.team_id}/network").body
        )
        server_id = network["servers"][0]["id"]
        body = "\x01" * MAX_NETWORK_BODY_BYTES
        for index in range(40):
            sent = self.request(
                "POST",
                f"/v1/teams/{self.team_id}/network/mailbox",
                body={
                    "to": {"kind": "server", "id": server_id},
                    "body": body,
                    "body_format": "plain",
                    "idempotency_key": f"network-page-body-{index:03d}",
                },
            )
            self.assertEqual(sent.status, 200, sent.body[:200])
        oversized = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/mailbox",
            body={
                "to": {"kind": "server", "id": server_id},
                "body": body + "x",
                "body_format": "plain",
                "idempotency_key": "network-page-body-oversized",
            },
        )
        self.assertEqual(oversized.status, 422, oversized.body)

        after = 0
        seen = 0
        while True:
            page = self.request(
                "GET",
                f"/v1/teams/{self.team_id}/network/mailbox",
                query=(
                    f"address_kind=server&address_id={server_id}"
                    f"&after_sequence={after}&limit=100"
                ),
            )
            self.assertEqual(page.status, 200, page.body[:200])
            self.assertLessEqual(len(page.body), MAX_NETWORK_PAGE_RESPONSE_BYTES)
            self.assertLess(len(page.body), MAX_RESPONSE_BODY_BYTES)
            value = json.loads(page.body)
            self.assertGreater(len(value["items"]), 0)
            seen += len(value["items"])
            after = value["next_after_sequence"]
            if not value["has_more"]:
                break
        self.assertEqual(seen, 40)

    def test_network_projection_cursor_survives_server_revocation(self) -> None:
        extra_peer_ids: list[str] = []
        for index in range(3):
            peer_id = str(uuid.uuid4())
            extra_peer_ids.append(peer_id)
            self.store.ensure_secure_peer_service(
                peer_id=peer_id,
                peer_server_identity=f"projection-revoke-peer-{index:02d}",
                team_id=self.team_id,
                display_name=f"Projection peer {index}",
            )
        connection = self.store.connect()
        try:
            rows = connection.execute(
                """
                SELECT n.id,b.peer_id FROM nodes AS n
                JOIN network_peer_bindings AS b
                  ON b.team_id=n.team_id AND b.node_id=n.id
                WHERE n.team_id=? ORDER BY n.id
                """,
                (self.team_id,),
            ).fetchall()
        finally:
            connection.close()
        target_index = next(
            index
            for index, row in enumerate(rows)
            if str(row["peer_id"]) != self.peer_id
        )
        first = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network",
            query=f"limit={target_index + 1}",
        )
        self.assertEqual(first.status, 200, first.body)
        first_value = json.loads(first.body)
        cursor = str(rows[target_index]["id"])
        self.assertEqual(first_value["next_after_server_id"], cursor)
        self.assertTrue(first_value["has_more"])
        self.assertEqual(
            [server["id"] for server in first_value["servers"]],
            [str(row["id"]) for row in rows[: target_index + 1]],
        )

        connection = self.store.connect()
        try:
            connection.execute(
                "UPDATE nodes SET status='revoked' WHERE team_id=? AND id=?",
                (self.team_id, cursor),
            )
        finally:
            connection.close()
        second = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network",
            query=f"after_server_id={cursor}&limit=100",
        )
        self.assertEqual(second.status, 200, second.body)
        second_value = json.loads(second.body)
        self.assertEqual(
            [server["id"] for server in second_value["servers"]],
            [str(row["id"]) for row in rows[target_index + 1 :]],
        )
        self.assertTrue(
            set(server["id"] for server in first_value["servers"]).isdisjoint(
                server["id"] for server in second_value["servers"]
            )
        )

    def test_network_projection_requires_live_authority_before_pagination(self) -> None:
        for index in range(4):
            self.store.ensure_secure_peer_service(
                peer_id=str(uuid.uuid4()),
                peer_server_identity=f"projection-lifecycle-peer-{index:02d}",
                team_id=self.team_id,
                display_name=f"Projection lifecycle peer {index}",
            )
        connection = self.store.connect()
        try:
            rows = connection.execute(
                """
                SELECT n.id,n.server_identity,n.status,b.peer_id,b.status AS binding_status
                FROM nodes AS n
                JOIN network_peer_bindings AS b
                  ON b.team_id=n.team_id AND b.node_id=n.id
                WHERE n.team_id=? ORDER BY n.id
                """,
                (self.team_id,),
            ).fetchall()
            self.assertGreaterEqual(len(rows), 5)
            # Model the peer-side Forget completion independently from the
            # host-side adapter callback below. Both converge on this durable
            # Team Hub retirement operation.
            forgotten = rows[0]
            revoked = rows[1]
            offline_live = rows[2]
            connection.execute(
                "UPDATE nodes SET status='offline' WHERE team_id=? AND id=?",
                (self.team_id, offline_live["id"]),
            )
        finally:
            connection.close()

        self.store.revoke_secure_peer_service(
            peer_id=str(forgotten["peer_id"]),
            team_id=self.team_id,
        )
        self.adapter.revoke_peer(
            peer_id=str(revoked["peer_id"]),
            team_id=self.team_id,
        )

        expected_visible = [str(row["id"]) for row in rows[2:]]
        first_page = self.store.get_network(self.owner, self.team_id, limit=1)
        self.assertEqual(
            [server["id"] for server in first_page["servers"]],
            expected_visible[:1],
        )
        self.assertTrue(first_page["has_more"])

        projection = self.store.get_network(self.owner, self.team_id, limit=50)
        projected = {server["id"]: server for server in projection["servers"]}
        self.assertNotIn(str(forgotten["id"]), projected)
        self.assertNotIn(str(revoked["id"]), projected)
        self.assertEqual(projected[str(offline_live["id"])]["status"], "offline")

        repaired_peer_id = str(uuid.uuid4())
        self.store.ensure_secure_peer_service(
            peer_id=repaired_peer_id,
            peer_server_identity=str(forgotten["server_identity"]),
            team_id=self.team_id,
            display_name="Re-paired lifecycle peer",
        )
        repaired = self.store.get_network(self.owner, self.team_id, limit=50)
        repaired_servers = [
            server
            for server in repaired["servers"]
            if server["server_identity"] == forgotten["server_identity"]
        ]
        self.assertEqual(len(repaired_servers), 1)
        self.assertEqual(repaired_servers[0]["id"], forgotten["id"])

    def test_network_projection_retains_managed_host_and_legacy_node(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = HubStore(
                Path(directory),
                managed_host_identity="projection-managed-host-identity",
            )
            proof = (Path(directory) / "bootstrap-owner.proof").read_text().strip()
            bootstrap = store.bootstrap(
                proof,
                "host-owner@example.com",
                "Host Owner",
                "Host Mac",
            )
            team_id = bootstrap["teams"][0]["id"]
            owner = store.verify_access(bootstrap["access_token"])
            timestamp = int(time.time())
            principal_id = "node_principal_" + uuid.uuid4().hex
            node_id = "node_" + uuid.uuid4().hex
            connection = store.connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO principals(
                        id,kind,scope_team_id,display_name,status,created_at,updated_at
                    ) VALUES (?,'node',?,'Legacy server','active',?,?)
                    """,
                    (principal_id, team_id, timestamp, timestamp),
                )
                connection.execute(
                    """
                    INSERT INTO nodes(
                        id,team_id,principal_id,server_identity,display_name,status,
                        enrolled_at,last_seen_at
                    ) VALUES (?,?,?,?,?,'offline',?,NULL)
                    """,
                    (
                        node_id,
                        team_id,
                        principal_id,
                        "projection-legacy-server-identity",
                        "Legacy server",
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO legacy_server_bindings(
                        id,team_id,server_identity,node_id,created_at
                    ) VALUES (?,?,?,?,?)
                    """,
                    (
                        "legacy_binding_" + uuid.uuid4().hex,
                        team_id,
                        "projection-legacy-server-identity",
                        node_id,
                        timestamp,
                    ),
                )
                connection.execute("COMMIT")
            finally:
                connection.close()

            projection = store.get_network(owner, team_id, limit=50)
            by_identity = {
                server["server_identity"]: server
                for server in projection["servers"]
            }
            self.assertTrue(
                by_identity["projection-managed-host-identity"]["is_host"]
            )
            self.assertEqual(
                by_identity["projection-legacy-server-identity"]["status"],
                "offline",
            )

    def test_network_projection_is_group_paged_below_transport_cap(self) -> None:
        for index in range(3):
            self.store.ensure_secure_peer_service(
                peer_id=str(uuid.uuid4()),
                peer_server_identity=(
                    f"projection-max-peer-{index:02d}-"
                    + "x" * (240 - len(f"projection-max-peer-{index:02d}-"))
                ),
                team_id=self.team_id,
                display_name="\x01" * 160,
            )
        connection = self.store.connect()
        try:
            server_ids = [
                str(row["id"])
                for row in connection.execute(
                    "SELECT id FROM nodes WHERE team_id=? ORDER BY id",
                    (self.team_id,),
                )
            ]
            timestamp = int(time.time())
            connection.execute("BEGIN IMMEDIATE")
            for server_index, server_id in enumerate(server_ids):
                for agent_index in range(256):
                    principal_id = (
                        f"agent_principal_projection_{server_index:03d}_{agent_index:03d}"
                    )
                    agent_id = f"agent_projection_{server_index:03d}_{agent_index:03d}"
                    external_prefix = f"{server_index:03d}-{agent_index:03d}-"
                    external_id = external_prefix + "\x01" * (
                        240 - len(external_prefix)
                    )
                    connection.execute(
                        """
                        INSERT INTO principals(
                            id,kind,scope_team_id,display_name,status,
                            created_at,updated_at
                        ) VALUES (?,'agent',?,?,'active',?,?)
                        """,
                        (
                            principal_id,
                            self.team_id,
                            "\x01" * 160,
                            timestamp,
                            timestamp,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO agents(
                            id,team_id,principal_id,node_id,external_agent_id,
                            backend,display_name,status,created_at,updated_at
                        ) VALUES (?,?,?,?,?,'other',?,'active',?,?)
                        """,
                        (
                            agent_id,
                            self.team_id,
                            principal_id,
                            server_id,
                            external_id,
                            "\x01" * 160,
                            timestamp,
                            timestamp,
                        ),
                    )
            connection.execute("COMMIT")
        finally:
            connection.close()

        materialized_server_ids: set[str] = set()
        render_agent = self.store._agent_public

        def track_agent(row):
            materialized_server_ids.add(str(row["node_id"]))
            return render_agent(row)

        with mock.patch.object(
            self.store, "_agent_public", side_effect=track_agent
        ):
            first = self.request(
                "GET",
                f"/v1/teams/{self.team_id}/network",
                query="limit=100",
            )
        self.assertEqual(first.status, 200, first.body[:200])
        self.assertLessEqual(len(first.body), MAX_NETWORK_PAGE_RESPONSE_BYTES)
        self.assertLess(len(first.body), MAX_RESPONSE_BODY_BYTES)
        first_value = json.loads(first.body)
        first_server_ids = {
            str(server["id"]) for server in first_value["servers"]
        }
        self.assertTrue(first_value["has_more"])
        self.assertLess(len(first_server_ids), len(server_ids))
        self.assertTrue(
            set(server_ids) - first_server_ids - materialized_server_ids,
            "later server groups were materialized after the byte cutoff",
        )

        seen_servers: list[str] = []
        seen_agents: list[str] = []
        cursor: str | None = None
        while True:
            page = (
                first
                if cursor is None
                else self.request(
                    "GET",
                    f"/v1/teams/{self.team_id}/network",
                    query=f"after_server_id={cursor}&limit=100",
                )
            )
            self.assertEqual(page.status, 200, page.body[:200])
            self.assertLessEqual(len(page.body), MAX_NETWORK_PAGE_RESPONSE_BYTES)
            self.assertLess(len(page.body), MAX_RESPONSE_BODY_BYTES)
            value = json.loads(page.body)
            page_server_ids = [str(server["id"]) for server in value["servers"]]
            self.assertEqual(page_server_ids, sorted(page_server_ids))
            self.assertTrue(page_server_ids)
            self.assertEqual(value["next_after_server_id"], page_server_ids[-1])
            self.assertTrue(
                all(agent["server_id"] in page_server_ids for agent in value["agents"])
            )
            seen_servers.extend(page_server_ids)
            seen_agents.extend(str(agent["id"]) for agent in value["agents"])
            cursor = value["next_after_server_id"]
            if not value["has_more"]:
                break
        self.assertEqual(seen_servers, server_ids)
        self.assertEqual(len(seen_servers), len(set(seen_servers)))
        self.assertEqual(len(seen_agents), 4 * 256)
        self.assertEqual(len(seen_agents), len(set(seen_agents)))

        empty = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network",
            query="after_server_id=zzzzzzzz&limit=100",
        )
        self.assertEqual(empty.status, 200, empty.body)
        empty_value = json.loads(empty.body)
        self.assertEqual(empty_value["servers"], [])
        self.assertEqual(empty_value["agents"], [])
        self.assertIsNone(empty_value["next_after_server_id"])
        self.assertFalse(empty_value["has_more"])

    def test_receipts_are_charged_to_the_durable_peer_write_quota(self) -> None:
        network = json.loads(
            self.request("GET", f"/v1/teams/{self.team_id}/network").body
        )
        server_id = network["servers"][0]["id"]
        sent = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/mailbox",
            body={
                "to": {"kind": "server", "id": server_id},
                "body": "Receipt quota",
                "idempotency_key": "receipt-quota-message-1",
            },
        )
        delivery_id = json.loads(sent.body)["delivery"]["id"]
        delivered = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
            body={
                "state": "delivered",
                "idempotency_key": "receipt-quota-delivered-1",
            },
        )
        self.assertEqual(delivered.status, 200, delivered.body)
        connection = self.store.connect()
        try:
            connection.execute(
                """
                UPDATE rate_limit_buckets
                SET window_started_at=?,count=60,updated_at=?
                WHERE team_id=? AND subject_key=?
                  AND action='network.mailbox.count.minute'
                """,
                (
                    int(time.time()),
                    int(time.time()),
                    self.team_id,
                    f"secure-peer:{self.peer_id}",
                ),
            )
        finally:
            connection.close()
        denied = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
            body={
                "state": "read",
                "idempotency_key": "receipt-quota-read-1",
            },
        )
        self.assertEqual(denied.status, 429, denied.body)
        self.assertEqual(json.loads(denied.body)["error"]["code"], "rate_limited")

    def test_satisfied_receipts_do_not_grow_durable_state(self) -> None:
        network = json.loads(
            self.request("GET", f"/v1/teams/{self.team_id}/network").body
        )
        server_id = network["servers"][0]["id"]
        sent = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/mailbox",
            body={
                "to": {"kind": "server", "id": server_id},
                "body": "Bound receipt replay growth",
                "idempotency_key": "receipt-growth-message-1",
            },
        )
        delivery_id = json.loads(sent.body)["delivery"]["id"]

        def durable_state() -> tuple[int, int, int, int]:
            connection = self.store.connect()
            try:
                return (
                    int(
                        connection.execute(
                            """
                            SELECT COUNT(*) FROM request_idempotency
                            WHERE team_id=? AND principal_id=?
                              AND operation='network.delivery.receipt'
                            """,
                            (
                                self.team_id,
                                "service_secure_peer_" + self.peer_id.replace("-", ""),
                            ),
                        ).fetchone()[0]
                    ),
                    int(
                        connection.execute(
                            """
                            SELECT COUNT(*) FROM audit_events
                            WHERE team_id=? AND action='network.delivery.receipt'
                              AND resource_id=?
                            """,
                            (self.team_id, delivery_id),
                        ).fetchone()[0]
                    ),
                    int(
                        connection.execute(
                            """
                            SELECT COUNT(*) FROM outbox_events
                            WHERE team_id=? AND aggregate_type='network_delivery'
                              AND aggregate_id=?
                            """,
                            (self.team_id, delivery_id),
                        ).fetchone()[0]
                    ),
                    int(
                        connection.execute(
                            """
                            SELECT COALESCE(MAX(count),0) FROM rate_limit_buckets
                            WHERE team_id=? AND subject_key=?
                              AND action='network.mailbox.count.minute'
                            """,
                            (self.team_id, f"secure-peer:{self.peer_id}"),
                        ).fetchone()[0]
                    ),
                )
            finally:
                connection.close()

        available_state = durable_state()
        premature = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
            body={
                "state": "read",
                "idempotency_key": "receipt-growth-premature-read",
            },
        )
        self.assertEqual(premature.status, 409, premature.body)
        self.assertEqual(
            json.loads(premature.body)["error"]["code"], "receipt_conflict"
        )
        self.assertEqual(durable_state(), available_state)

        delivered = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
            body={
                "state": "delivered",
                "idempotency_key": "receipt-growth-delivered-transition",
            },
        )
        self.assertEqual(delivered.status, 200, delivered.body)
        delivered_value = json.loads(delivered.body)["delivery"]
        after_delivered = durable_state()
        for index in range(10):
            replay = self.request(
                "POST",
                f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
                body={
                    "state": "delivered",
                    "idempotency_key": f"receipt-growth-delivered-noop-{index}",
                },
            )
            self.assertEqual(replay.status, 200, replay.body)
            self.assertEqual(json.loads(replay.body)["delivery"], delivered_value)
        self.assertEqual(durable_state(), after_delivered)

        read = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
            body={
                "state": "read",
                "idempotency_key": "receipt-growth-read-transition",
            },
        )
        self.assertEqual(read.status, 200, read.body)
        read_value = json.loads(read.body)["delivery"]
        after_read = durable_state()
        for index in range(10):
            for state in ("read", "delivered"):
                replay = self.request(
                    "POST",
                    f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
                    body={
                        "state": state,
                        "idempotency_key": f"receipt-growth-{state}-noop-{index}",
                    },
                )
                self.assertEqual(replay.status, 200, replay.body)
                self.assertEqual(json.loads(replay.body)["delivery"], read_value)
        self.assertEqual(durable_state(), after_read)

        cached_transition = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
            body={
                "state": "delivered",
                "idempotency_key": "receipt-growth-delivered-transition",
            },
        )
        self.assertEqual(cached_transition.status, 200, cached_transition.body)
        self.assertEqual(
            json.loads(cached_transition.body)["delivery"], delivered_value
        )
        self.assertEqual(durable_state(), after_read)

    def test_satisfied_receipt_still_requires_address_authority(self) -> None:
        other_peer_id = str(uuid.uuid4())
        self.store.ensure_secure_peer_service(
            peer_id=other_peer_id,
            peer_server_identity="other-peer-server-identity",
            team_id=self.team_id,
            display_name="Other paired server",
        )
        self.adapter.record_peer_heartbeat(other_peer_id, self.team_id)
        other_claims = self.store.secure_peer_claims(
            peer_id=other_peer_id,
            peer_server_identity="other-peer-server-identity",
            team_id=self.team_id,
            scopes=frozenset({"teamspace.read", "teamspace.write"}),
            expires_at=int(time.time()) + 600,
            display_name="Other paired server",
        )
        network = self.store.get_network(other_claims, self.team_id)
        other_server_id = next(
            server["id"]
            for server in network["servers"]
            if server["owned_by_caller"]
        )
        sent = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/mailbox",
            body={
                "to": {"kind": "server", "id": other_server_id},
                "body": "Recipient-only receipt",
                "idempotency_key": "receipt-authority-message-1",
            },
        )
        delivery_id = json.loads(sent.body)["delivery"]["id"]
        delivered = self.store.record_network_delivery_receipt(
            other_claims,
            self.team_id,
            delivery_id,
            {
                "state": "delivered",
                "idempotency_key": "receipt-authority-delivered-1",
            },
        )
        self.assertEqual(delivered["delivery"]["state"], "delivered")

        denied = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/deliveries/{delivery_id}/receipts",
            body={
                "state": "delivered",
                "idempotency_key": "receipt-authority-noop-denied",
            },
        )
        self.assertEqual(denied.status, 404, denied.body)

    def test_legacy_agent_request_is_readable_but_peer_reply_is_retired(self) -> None:
        network = json.loads(
            self.request("GET", f"/v1/teams/{self.team_id}/network").body
        )
        server_id = network["servers"][0]["id"]
        registered = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/agents",
            body={
                "external_agent_id": "inactive-requester-runtime",
                "backend": "codex",
                "display_name": "Inactive requester",
                "idempotency_key": "inactive-requester-agent-1",
            },
        )
        agent_id = json.loads(registered.body)["agent"]["id"]
        # Seed through the retained Hub compatibility API.  The secure-peer
        # adapter no longer permits a peer to claim this agent authorship, but
        # pre-existing agent-authored requests must remain safely readable.
        claims = self.store.secure_peer_claims(
            peer_id=self.peer.peer_id,
            peer_server_identity=self.peer.peer_server_identity,
            team_id=self.peer.team_id,
            scopes=self.peer.scopes,
            expires_at=self.peer.certificate_expires_at,
            display_name=self.peer.peer_display_name,
        )
        with mock.patch.object(
            self.store,
            "_require_server_inbox_write",
        ):
            created = self.store.create_network_request(
                claims,
                self.team_id,
                {
                    "to": {"kind": "server", "id": server_id},
                    "from_agent_id": agent_id,
                    "body": "Reply after I go offline",
                    "body_format": "markdown",
                    "idempotency_key": "inactive-requester-request-1",
                },
            )
        request_id = created["request"]["id"]
        readable = self.request(
            "GET",
            f"/v1/teams/{self.team_id}/network/requests/{request_id}",
        )
        self.assertEqual(readable.status, 200, readable.body)
        self.assertEqual(json.loads(readable.body)["request"]["status"], "open")
        reply = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/requests/{request_id}/replies",
            body={
                "body": "Controlled failure",
                "idempotency_key": "inactive-requester-reply-1",
            },
        )
        self.assertEqual(reply.status, 422, reply.body)
        self.assertEqual(
            json.loads(reply.body)["error"]["code"], "invalid_request"
        )
        unchanged = self.store.get_network_request(
            claims,
            self.team_id,
            request_id,
        )
        self.assertEqual(unchanged["request"]["status"], "open")
        self.assertIsNone(unchanged["reply"])

    def test_network_agent_registry_has_durable_server_boundary(self) -> None:
        network = self.request("GET", f"/v1/teams/{self.team_id}/network")
        self.assertEqual(network.status, 200, network.body)
        server_id = json.loads(network.body)["servers"][0]["id"]
        timestamp = int(time.time())
        connection = self.store.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for index in range(255):
                principal_id = f"agent_principal_seed_{index}"
                connection.execute(
                    """
                    INSERT INTO principals(
                        id,kind,scope_team_id,display_name,status,created_at,updated_at
                    ) VALUES (?,'agent',?,?,'active',?,?)
                    """,
                    (
                        principal_id,
                        self.team_id,
                        f"Seed agent {index}",
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO agents(
                        id,team_id,principal_id,node_id,external_agent_id,
                        backend,display_name,status,created_at,updated_at
                    ) VALUES (?,?,?,?,?,'other',?,'active',?,?)
                    """,
                    (
                        f"agent_seed_{index}",
                        self.team_id,
                        principal_id,
                        server_id,
                        f"external-seed-{index}",
                        f"Seed agent {index}",
                        timestamp,
                        timestamp,
                    ),
                )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

        boundary_body = {
            "external_agent_id": "boundary-agent-256",
            "backend": "codex",
            "display_name": "Boundary agent",
            "idempotency_key": "network-agent-boundary-256",
        }
        boundary = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/agents",
            body=boundary_body,
        )
        self.assertEqual(boundary.status, 200, boundary.body)
        replay = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/agents",
            body=boundary_body,
        )
        self.assertEqual(replay.status, 200, replay.body)
        self.assertEqual(replay.body, boundary.body)

        overflow = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/agents",
            body={
                "external_agent_id": "overflow-agent-257",
                "backend": "claude",
                "display_name": "Overflow agent",
                "idempotency_key": "network-agent-overflow-257",
            },
        )
        self.assertEqual(overflow.status, 409, overflow.body)
        self.assertEqual(json.loads(overflow.body)["error"]["code"], "agent_limit_reached")

        connection = self.store.connect()
        try:
            self.assertEqual(
                int(
                    connection.execute(
                        "SELECT COUNT(*) FROM agents WHERE node_id=?", (server_id,)
                    ).fetchone()[0]
                ),
                256,
            )
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO principals(
                    id,kind,scope_team_id,display_name,status,created_at,updated_at
                ) VALUES ('agent_principal_raw_overflow','agent',?,'Raw overflow','active',?,?)
                """,
                (self.team_id, timestamp, timestamp),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "network server agent limit exceeded"
            ):
                connection.execute(
                    """
                    INSERT INTO agents(
                        id,team_id,principal_id,node_id,external_agent_id,
                        backend,display_name,status,created_at,updated_at
                    ) VALUES (
                        'agent_raw_overflow',?,'agent_principal_raw_overflow',?,
                        'external-raw-overflow','other','Raw overflow','active',?,?
                    )
                    """,
                    (self.team_id, server_id, timestamp, timestamp),
                )
            connection.execute("ROLLBACK")
        finally:
            connection.close()

    def test_secure_peer_message_quota_is_durable(self) -> None:
        connection = self.store.connect()
        try:
            connection.execute(
                """
                INSERT INTO rate_limit_buckets(
                    team_id,subject_key,action,window_started_at,count,updated_at
                ) VALUES (?,?,?,?,?,?)
                """,
                (
                    self.team_id,
                    f"secure-peer:{self.peer_id}",
                    "peer.message.count.minute",
                    int(time.time()),
                    60,
                    int(time.time()),
                ),
            )
        finally:
            connection.close()
        denied = self.request(
            "POST",
            f"/v1/channels/{self.channel_id}/messages",
            body={"body": "bounded", "idempotency_key": "message-quota-1"},
        )
        self.assertEqual(denied.status, 429, denied.body)
        self.assertEqual(json.loads(denied.body)["error"]["code"], "rate_limited")

    def test_secure_peer_bulletin_quota_is_durable(self) -> None:
        connection = self.store.connect()
        try:
            connection.execute(
                """
                INSERT INTO rate_limit_buckets(
                    team_id,subject_key,action,window_started_at,count,updated_at
                ) VALUES (?,?,?,?,?,?)
                """,
                (
                    self.team_id,
                    f"secure-peer:{self.peer_id}",
                    "network.mailbox.count.minute",
                    int(time.time()),
                    60,
                    int(time.time()),
                ),
            )
        finally:
            connection.close()
        denied = self.request(
            "POST",
            f"/v1/teams/{self.team_id}/network/bulletin",
            body={
                "body": "bounded Bulletin write",
                "body_format": "plain",
                "idempotency_key": "network-bulletin-quota-1",
            },
        )
        self.assertEqual(denied.status, 429, denied.body)
        self.assertEqual(json.loads(denied.body)["error"]["code"], "rate_limited")


if __name__ == "__main__":
    unittest.main()
