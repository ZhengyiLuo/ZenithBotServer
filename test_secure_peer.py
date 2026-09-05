import base64
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentsdock_team_hub.secure_peer import (
    ACTIVATED_RENEWAL_HISTORY_LIMIT,
    MAX_RELAY_LEGS,
    PAIRING_ATTEMPT_RETENTION_SECONDS,
    PAIRING_STATUS_LIMIT,
    PAIRING_TTL_SECONDS,
    PEER_HEARTBEAT_COALESCE_SECONDS,
    PEER_HEARTBEAT_LEASE_SECONDS,
    PEER_BINDING_OID,
    RENEWAL_REQUEST_TTL_SECONDS,
    RETIRED_RENEWAL_MATERIAL_LIMIT,
    PeerAuthorization,
    ProxyResponse,
    SecurePeerClient,
    SecurePeerError,
    SecurePeerGateway,
    SecurePeerStore,
    build_pairing_request,
    canonical_peer_ipv4,
    sanitize_proxy_request,
    sanitize_proxy_response,
    sas_words,
)
from agentsdock_team_hub.security import canonical_json


def _uuid() -> str:
    return str(uuid.uuid4())


def _key_fingerprint(key: Ed25519PrivateKey) -> str:
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


class _Clock:
    def __init__(self) -> None:
        self.value = int(time.time())

    def __call__(self) -> float:
        return float(self.value)


class SecurePeerStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.clock = _Clock()
        self.store = SecurePeerStore(
            self.root / "host",
            "host-server-001",
            "team-hub-001",
            clock=self.clock,
            cross_chat_enabled=True,
        )
        self.requested_scopes = [
            "teamspace.read",
            "teamspace.write",
            "cross_chat.instruction",
            "cross_chat.request_reply",
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(
        self,
        key: Ed25519PrivateKey | None = None,
        *,
        request_id: str | None = None,
        created_at: int | None = None,
        scopes: list[str] | None = None,
        nonce: bytes | None = None,
        server_identity: str = "peer-server-001",
        display_name: str = "Peer server",
    ) -> tuple[Ed25519PrivateKey, dict]:
        key = key or Ed25519PrivateKey.generate()
        return key, build_pairing_request(
            key,
            server_identity=server_identity,
            display_name=display_name,
            host_ca_fingerprint=self.store.ca_fingerprint,
            request_id=request_id,
            created_at=self.clock.value if created_at is None else created_at,
            nonce=nonce,
            requested_scopes=scopes or self.requested_scopes,
        )

    def approve_peer(
        self,
        *,
        scopes: list[str] | None = None,
        source_ip: str = "10.0.0.9",
        server_identity: str = "peer-server-001",
        display_name: str = "Peer server",
    ) -> tuple[Ed25519PrivateKey, dict, dict, PeerAuthorization]:
        key, request = self.request(
            server_identity=server_identity,
            display_name=display_name,
        )
        submitted = self.store.submit_pairing(
            request, source_ip=source_ip, source_port=45123
        )
        approved = self.store.approve_pairing(
            submitted["pairing_id"],
            "team-alpha",
            scopes or self.requested_scopes,
            "owner-admin",
            expected_peer_server_identity=server_identity,
            expected_transcript_hash=submitted["transcript_hash"],
            idempotency_key=_uuid(),
        )
        polled = self.store.poll_pairing(
            submitted["pairing_id"], submitted["poll_token"]
        )
        certificate = x509.load_pem_x509_certificate(
            polled["client_certificate_pem"].encode("ascii")
        )
        peer = self.store.authenticate_peer(
            certificate.public_bytes(serialization.Encoding.DER)
        )
        return key, submitted, approved, peer

    def test_signed_transcript_sas_idempotency_and_scope_tamper(self) -> None:
        request_id = _uuid()
        key, request = self.request(request_id=request_id, nonce=b"n" * 32)
        submitted = self.store.submit_pairing(
            request, source_ip="10.0.0.7", source_port=41000
        )
        repeated = self.store.submit_pairing(
            request, source_ip="10.0.0.7", source_port=41001
        )
        self.assertEqual(repeated["pairing_id"], submitted["pairing_id"])
        self.assertEqual(repeated["poll_token"], submitted["poll_token"])
        self.assertEqual(submitted["sas_words"], list(sas_words(submitted["transcript_hash"])))
        self.assertEqual(submitted["peer_public_key_fingerprint"], _key_fingerprint(key))
        self.assertEqual(submitted["requested_scopes"], self.requested_scopes)

        _unused, changed = self.request(
            key,
            request_id=request_id,
            nonce=b"x" * 32,
        )
        with self.assertRaisesRegex(SecurePeerError, "different content") as conflict:
            self.store.submit_pairing(changed)
        self.assertEqual(conflict.exception.code, "idempotency_conflict")

        tampered = copy.deepcopy(request)
        tampered["requested_scopes"] = ["teamspace.read"]
        with self.assertRaises(SecurePeerError) as invalid_signature:
            self.store.submit_pairing(tampered)
        self.assertEqual(invalid_signature.exception.code, "signature_invalid")

        controlled = copy.deepcopy(request)
        controlled["request_id"] = _uuid()
        controlled["peer_display_name"] = "Peer\nname"
        unsigned = {
            name: value for name, value in controlled.items() if name != "signature"
        }
        controlled["signature"] = base64.b64encode(
            key.sign(canonical_json(unsigned))
        ).decode("ascii")
        with self.assertRaises(SecurePeerError) as invalid_label:
            self.store.submit_pairing(controlled)
        self.assertEqual(invalid_label.exception.code, "invalid_request")

        with self.assertRaises(SecurePeerError) as invalid_title:
            self.store.publish_local_route(
                "team-alpha",
                _uuid(),
                "chat-invalid-title",
                "valid-alias",
                "Remote\x7ftitle",
                ["instruction"],
                idempotency_key=_uuid(),
                published_by="owner-admin",
            )
        self.assertEqual(invalid_title.exception.code, "invalid_request")

        _unused, low_port_request = self.request(request_id=_uuid())
        with self.assertRaises(SecurePeerError) as low_source_port:
            self.store.submit_pairing(
                low_port_request,
                source_ip="192.0.2.10",
                source_port=443,
            )
        self.assertEqual(low_source_port.exception.code, "invalid_request")

    def test_pairing_expiry_csr_mismatch_and_scope_escalation(self) -> None:
        _key, expired = self.request(created_at=self.clock.value - 301)
        with self.assertRaises(SecurePeerError) as stale:
            self.store.submit_pairing(expired)
        self.assertEqual(stale.exception.code, "pairing_expired")

        key, request = self.request(scopes=["teamspace.read"])
        other = Ed25519PrivateKey.generate()
        other_request = build_pairing_request(
            other,
            server_identity="peer-server-001",
            display_name="Peer server",
            host_ca_fingerprint=self.store.ca_fingerprint,
            created_at=self.clock.value,
            requested_scopes=["teamspace.read"],
        )
        mismatch = copy.deepcopy(request)
        mismatch["csr_pem"] = other_request["csr_pem"]
        unsigned = {name: value for name, value in mismatch.items() if name != "signature"}
        mismatch["signature"] = base64.b64encode(
            key.sign(canonical_json(unsigned))
        ).decode("ascii")
        with self.assertRaises(SecurePeerError) as bad_csr:
            self.store.submit_pairing(mismatch)
        self.assertEqual(bad_csr.exception.code, "key_mismatch")

        _key, limited = self.request(scopes=["teamspace.read"])
        pending = self.store.submit_pairing(limited)
        with self.assertRaises(SecurePeerError) as escalation:
            self.store.approve_pairing(
                pending["pairing_id"],
                "team-alpha",
                ["teamspace.read", "teamspace.write"],
                "owner-admin",
                expected_peer_server_identity="peer-server-001",
                expected_transcript_hash=pending["transcript_hash"],
                idempotency_key=_uuid(),
            )
        self.assertEqual(escalation.exception.code, "scope_escalation")

        self.clock.value += PAIRING_TTL_SECONDS + 1
        expired_poll = self.store.poll_pairing(
            pending["pairing_id"], pending["poll_token"]
        )
        self.assertEqual(expired_poll["status"], "expired")

    def test_listing_and_host_decisions_persist_due_pairing_expiry(self) -> None:
        submitted: list[dict] = []
        for index in range(3):
            _key, request = self.request(
                request_id=_uuid(),
                server_identity=f"peer-server-{index + 10:03d}",
            )
            submitted.append(self.store.submit_pairing(request))

        self.clock.value += PAIRING_TTL_SECONDS + 1
        with self.assertRaises(SecurePeerError) as approve_expired:
            self.store.approve_pairing(
                submitted[0]["pairing_id"],
                "team-alpha",
                self.requested_scopes,
                "owner-admin",
                expected_peer_server_identity="peer-server-010",
                expected_transcript_hash=submitted[0]["transcript_hash"],
                idempotency_key=_uuid(),
            )
        self.assertEqual(approve_expired.exception.code, "pairing_not_pending")
        with self.assertRaises(SecurePeerError) as reject_expired:
            self.store.reject_pairing(
                submitted[1]["pairing_id"],
                "owner-admin",
                "No longer needed",
                expected_peer_server_identity="peer-server-011",
                expected_transcript_hash=submitted[1]["transcript_hash"],
                idempotency_key=_uuid(),
            )
        self.assertEqual(reject_expired.exception.code, "pairing_not_pending")

        # Decision failures must commit their exact expiry before raising, and
        # listing must expire any remaining due row before applying filters.
        connection = sqlite3.connect(self.store.db_path)
        try:
            statuses = {
                row[0]: row[1]
                for row in connection.execute(
                    "SELECT id,status FROM pairing_requests"
                ).fetchall()
            }
        finally:
            connection.close()
        self.assertEqual(statuses[submitted[0]["pairing_id"]], "expired")
        self.assertEqual(statuses[submitted[1]["pairing_id"]], "expired")
        self.assertEqual(statuses[submitted[2]["pairing_id"]], "pending")
        self.assertEqual(self.store.list_pairings(status="pending"), [])
        self.assertEqual(
            {row["pairing_id"] for row in self.store.list_pairings(status="expired")},
            {row["pairing_id"] for row in submitted},
        )

    def test_cross_chat_grant_requires_explicit_store_enablement(self) -> None:
        disabled = SecurePeerStore(
            self.root / "disabled-host",
            "disabled-host-001",
            "disabled-hub-001",
            clock=self.clock,
        )
        key = Ed25519PrivateKey.generate()
        request = build_pairing_request(
            key,
            server_identity="peer-server-002",
            display_name="Second peer",
            host_ca_fingerprint=disabled.ca_fingerprint,
            created_at=self.clock.value,
            requested_scopes=["teamspace.read", "cross_chat.instruction"],
        )
        pending = disabled.submit_pairing(request)
        with self.assertRaises(SecurePeerError) as unavailable:
            disabled.approve_pairing(
                pending["pairing_id"],
                "team-alpha",
                ["teamspace.read", "cross_chat.instruction"],
                "owner-admin",
                expected_peer_server_identity="peer-server-002",
                expected_transcript_hash=pending["transcript_hash"],
                idempotency_key=_uuid(),
            )
        self.assertEqual(unavailable.exception.code, "cross_chat_unavailable")

    def test_certificate_binding_authentication_and_immediate_revocation(self) -> None:
        _key, submitted, approved, peer = self.approve_peer()
        self.assertEqual(peer.peer_id, approved["peer_id"])
        self.assertEqual(peer.pairing_id, submitted["pairing_id"])
        self.assertEqual(peer.certificate_fingerprint, approved["certificate_fingerprint"])
        self.assertGreater(peer.certificate_expires_at, self.clock.value)
        certificate = x509.load_pem_x509_certificate(
            self.store.poll_pairing(
                submitted["pairing_id"], submitted["poll_token"]
            )["client_certificate_pem"].encode("ascii")
        )
        binding = json.loads(
            certificate.extensions.get_extension_for_oid(PEER_BINDING_OID).value.value
        )
        self.assertEqual(binding["scopes"], self.requested_scopes)
        local_route = self.store.publish_local_route(
            peer.team_id,
            peer.peer_id,
            "chat-revocation-001",
            "revoke",
            "Revocation chat",
            ["instruction"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        revoked = self.store.revoke_peer(
            peer.peer_id,
            peer.team_id,
            peer.certificate_fingerprint,
            _uuid(),
            "owner-admin",
        )
        self.assertEqual(revoked["status"], "revoked")
        with self.assertRaises(SecurePeerError) as denied:
            self.store.authenticate_peer(
                certificate.public_bytes(serialization.Encoding.DER)
            )
        self.assertEqual(denied.exception.code, "peer_revoked")
        routes = self.store.list_local_routes(peer.peer_id)
        self.assertEqual(routes[0]["route_id"], local_route["route_id"])
        self.assertEqual(routes[0]["status"], "revoked")

    def test_publish_rechecks_authenticated_peer_after_revoke_commits(self) -> None:
        _key, _submitted, _approved, authenticated_peer = self.approve_peer()
        route_id = _uuid()
        original_require_cross_chat = self.store._require_cross_chat
        revoke_results: list[dict] = []

        def revoke_after_preflight(
            peer: PeerAuthorization | None = None,
            *,
            connection=None,
        ) -> int:
            epoch = original_require_cross_chat(peer, connection=connection)
            if (
                peer is authenticated_peer
                and connection is None
                and not revoke_results
            ):
                revoke_results.append(
                    self.store.revoke_peer(
                        authenticated_peer.peer_id,
                        authenticated_peer.team_id,
                        authenticated_peer.certificate_fingerprint,
                        _uuid(),
                        "owner-admin",
                    )
                )
            return epoch

        with mock.patch.object(
            self.store,
            "_require_cross_chat",
            side_effect=revoke_after_preflight,
        ):
            with self.assertRaises(SecurePeerError) as denied:
                self.store.publish_peer_route(
                    authenticated_peer,
                    {
                        "route_id": route_id,
                        "revision": "rev_" + uuid.uuid4().hex,
                        "alias": "revoked-race",
                        "display_title": "Revoked race",
                        "actions": ["instruction"],
                    },
                )

        self.assertEqual(revoke_results[0]["status"], "revoked")
        self.assertEqual(denied.exception.code, "peer_revoked")
        connection = self.store._connect()
        try:
            active = connection.execute(
                """SELECT COUNT(*) AS count FROM peer_routes
                WHERE peer_id=? AND status='active'""",
                (authenticated_peer.peer_id,),
            ).fetchone()
            route = connection.execute(
                "SELECT id FROM peer_routes WHERE id=?", (route_id,)
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(int(active["count"]), 0)
        self.assertIsNone(route)

    def test_reapproval_atomically_supersedes_all_old_peer_authority(self) -> None:
        _key, submitted, approved, peer = self.approve_peer()
        certificate = x509.load_pem_x509_certificate(
            self.store.poll_pairing(
                submitted["pairing_id"], submitted["poll_token"]
            )["client_certificate_pem"].encode("ascii")
        )
        local_route = self.store.publish_local_route(
            peer.team_id,
            peer.peer_id,
            "chat-reapproval-001",
            "reapproval-local",
            "Reapproval local",
            ["instruction"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        remote_route = self.store.publish_peer_route(
            peer,
            {
                "route_id": _uuid(),
                "revision": "rev_" + uuid.uuid4().hex,
                "alias": "reapproval-remote",
                "display_title": "Reapproval remote",
                "actions": ["instruction"],
            },
        )
        queued = self.store.submit_local_envelope(
            peer.team_id,
            local_route["route_id"],
            {
                "request_id": _uuid(),
                "source_route_id": local_route["route_id"],
                "target_route_id": remote_route["route_id"],
                "target_route_revision": remote_route["revision"],
                "kind": "instruction",
                "exchange_id": None,
                "parent_envelope_id": None,
                "expires_at": self.clock.value + 600,
                "body": {"message": "must not survive reapproval"},
            },
        )

        self.clock.value += 1
        _new_key, _new_submitted, replacement, replacement_peer = (
            self.approve_peer()
        )
        self.assertEqual(
            replacement["superseded_peer_ids"], [approved["peer_id"]]
        )
        self.assertNotEqual(replacement_peer.peer_id, peer.peer_id)
        with self.assertRaises(SecurePeerError) as retired:
            self.store.authenticate_peer(
                certificate.public_bytes(serialization.Encoding.DER)
            )
        self.assertEqual(retired.exception.code, "peer_revoked")

        connection = self.store._connect()
        try:
            old_peer = connection.execute(
                "SELECT * FROM peers WHERE id=?", (peer.peer_id,)
            ).fetchone()
            certificate_states = connection.execute(
                """SELECT revoked_at,valid_until FROM peer_certificates
                WHERE peer_id=?""",
                (peer.peer_id,),
            ).fetchall()
            route_states = connection.execute(
                """SELECT status FROM peer_routes
                WHERE peer_id=? OR audience_peer_id=?""",
                (peer.peer_id, peer.peer_id),
            ).fetchall()
            envelope = connection.execute(
                "SELECT status FROM relay_envelopes WHERE id=?",
                (queued["envelope_id"],),
            ).fetchone()
            audit = connection.execute(
                """SELECT detail_json FROM audit_events
                WHERE action='peer.supersede' AND object_id=?""",
                (peer.peer_id,),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(old_peer["status"], "revoked")
        self.assertEqual(old_peer["revoked_by"], "owner-admin")
        self.assertTrue(certificate_states)
        self.assertTrue(
            all(
                row["revoked_at"] == self.clock.value
                and row["valid_until"] <= self.clock.value
                for row in certificate_states
            )
        )
        self.assertTrue(route_states)
        self.assertTrue(all(row["status"] == "revoked" for row in route_states))
        self.assertEqual(envelope["status"], "expired")
        self.assertEqual(
            json.loads(audit["detail_json"])["successor_peer_id"],
            replacement_peer.peer_id,
        )

    def test_startup_reconciliation_prefers_hub_binding_then_is_idempotent(self) -> None:
        _key, _submitted, first, _peer = self.approve_peer(
            server_identity="duplicate-peer-001"
        )
        connection = self.store._connect()
        try:
            connection.execute(
                "UPDATE peers SET status='revoked' WHERE id=?", (first["peer_id"],)
            )
        finally:
            connection.close()
        self.clock.value += 1
        _key, _submitted, preferred, _peer = self.approve_peer(
            server_identity="duplicate-peer-001"
        )
        connection = self.store._connect()
        try:
            connection.execute(
                "UPDATE peers SET status='active',revoked_at=NULL,revoked_by=NULL WHERE id=?",
                (first["peer_id"],),
            )
        finally:
            connection.close()

        self.clock.value += 1
        _key, _submitted, oldest, _peer = self.approve_peer(
            server_identity="fallback-peer-001"
        )
        connection = self.store._connect()
        try:
            connection.execute(
                "UPDATE peers SET status='revoked' WHERE id=?", (oldest["peer_id"],)
            )
        finally:
            connection.close()
        self.clock.value += 1
        _key, _submitted, newest, _peer = self.approve_peer(
            server_identity="fallback-peer-001"
        )
        connection = self.store._connect()
        try:
            connection.execute(
                "UPDATE peers SET status='active',revoked_at=NULL,revoked_by=NULL WHERE id=?",
                (oldest["peer_id"],),
            )
        finally:
            connection.close()

        reconciled = self.store.reconcile_active_logical_peers(
            {preferred["peer_id"]}
        )
        self.assertEqual(
            set(reconciled["superseded_peer_ids"]),
            {first["peer_id"], newest["peer_id"]},
        )
        self.assertIn(preferred["peer_id"], reconciled["retained_peer_ids"])
        self.assertIn(oldest["peer_id"], reconciled["retained_peer_ids"])

        connection = self.store._connect()
        try:
            audit_count = connection.execute(
                """SELECT COUNT(*) AS count FROM audit_events
                WHERE action='peer.supersede'
                AND object_id IN (?,?)""",
                (first["peer_id"], newest["peer_id"]),
            ).fetchone()["count"]
        finally:
            connection.close()
        repeated = self.store.reconcile_active_logical_peers(
            {preferred["peer_id"]}
        )
        self.assertEqual(repeated["superseded_peer_ids"], [])
        connection = self.store._connect()
        try:
            self.assertEqual(
                connection.execute(
                    """SELECT COUNT(*) AS count FROM audit_events
                    WHERE action='peer.supersede'
                    AND object_id IN (?,?)""",
                    (first["peer_id"], newest["peer_id"]),
                ).fetchone()["count"],
                audit_count,
            )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE peers SET status='active' WHERE id=?",
                    (first["peer_id"],),
                )
        finally:
            connection.close()

    def test_peer_heartbeat_is_coalesced_and_exposed(self) -> None:
        _key, _submitted, _approved, peer = self.approve_peer()
        listed = self.store.list_peers(team_id=peer.team_id)
        self.assertIsNone(listed[0]["last_seen_at"])
        self.assertIsNone(listed[0]["lease_expires_at"])

        first = self.store.record_peer_heartbeat(peer.peer_id)
        self.assertTrue(first["recorded"])
        self.assertEqual(first["last_seen_at"], self.clock.value)
        self.assertEqual(
            first["lease_expires_at"],
            self.clock.value + PEER_HEARTBEAT_LEASE_SECONDS,
        )
        coalesced = self.store.record_peer_heartbeat(peer.peer_id)
        self.assertFalse(coalesced["recorded"])
        self.assertEqual(coalesced, {**first, "recorded": False})

        self.clock.value += PEER_HEARTBEAT_COALESCE_SECONDS
        extended = self.store.record_peer_heartbeat(peer.peer_id)
        self.assertTrue(extended["recorded"])
        self.assertEqual(extended["last_seen_at"], self.clock.value)
        listed = self.store.list_peers(team_id=peer.team_id)
        self.assertEqual(listed[0]["last_seen_at"], extended["last_seen_at"])
        self.assertEqual(
            listed[0]["lease_expires_at"], extended["lease_expires_at"]
        )

    def test_proxy_allowlist_team_scope_and_header_stripping(self) -> None:
        peer = PeerAuthorization(
            _uuid(),
            _uuid(),
            "peer-server-001",
            "team-alpha",
            frozenset({"teamspace.read", "teamspace.write"}),
            "sha256:" + "a" * 64,
            self.clock.value + 600,
            "Peer server",
        )
        request = sanitize_proxy_request(
            peer,
            "POST",
            "/v1/channels/channel-alpha/messages",
            "",
            (
                ("Authorization", "Bearer renderer-secret"),
                ("X-AgentsDock-Token", "local-proof"),
                ("X-Team-Hub-Bootstrap-Proof", "bootstrap-proof"),
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
            ),
            b'{"body":"hello"}',
            resource_team_resolver=lambda kind, resource: (
                "team-alpha" if (kind, resource) == ("channel", "channel-alpha") else None
            ),
        )
        self.assertEqual(
            request.headers,
            (("content-type", "application/json"), ("accept", "application/json")),
        )
        network = sanitize_proxy_request(
            peer,
            "GET",
            "/v1/teams/team-alpha/network",
            "after_server_id=node_12345678&limit=100",
            (),
            b"",
        )
        self.assertEqual(network.path, "/v1/teams/team-alpha/network")
        self.assertEqual(
            network.query, "after_server_id=node_12345678&limit=100"
        )
        members = sanitize_proxy_request(
            peer,
            "GET",
            "/v1/teams/team-alpha/members",
            "limit=100&cursor=v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            (),
            b"",
        )
        self.assertEqual(
            members.query,
            "limit=100&cursor=v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        mailbox = sanitize_proxy_request(
            peer,
            "GET",
            "/v1/teams/team-alpha/network/mailbox",
            "address_kind=server&address_id=node_12345678&after_sequence=0&limit=100",
            (),
            b"",
        )
        self.assertEqual(
            mailbox.query,
            "address_kind=server&address_id=node_12345678&after_sequence=0&limit=100",
        )
        registration = sanitize_proxy_request(
            peer,
            "POST",
            "/v1/teams/team-alpha/network/agents",
            "",
            (("Content-Type", "application/json"),),
            b'{"external_agent_id":"agent-runtime","backend":"codex","display_name":"Agent","idempotency_key":"agent-register-001"}',
        )
        self.assertEqual(registration.method, "POST")
        skills = sanitize_proxy_request(
            peer,
            "GET",
            "/v1/teams/team-alpha/network/skills",
            "include_archived=false&slug=deploy-sonic",
            (),
            b"",
        )
        self.assertEqual(
            skills.query,
            "include_archived=false&slug=deploy-sonic",
        )
        for path in (
            "/v1/sessions/refresh",
            "/v1/invitations/redeem",
            "/v1/bootstrap/redeem",
            "/v1/teams/team-alpha/channels/new",
            "/v1/teams/team-other/members",
            "/v1/teams/team-other/network",
            "/v1/teams/team-alpha/network/invites",
        ):
            with self.subTest(path=path), self.assertRaises(SecurePeerError):
                sanitize_proxy_request(peer, "GET", path, "", (), b"")
        for query in (
            "address_kind=server",
            "address_kind=server&address_id=node_12345678&limit=101",
            "address_kind=server&address_id=node_12345678&after_sequence=01",
            "address_kind=server&address_id=node_12345678&after_sequence=9223372036854775808",
            "address_kind=server&address_id=node_12345678&limit=1&limit=2",
            "address_kind=human&address_id=node_12345678",
        ):
            with self.subTest(query=query), self.assertRaises(SecurePeerError):
                sanitize_proxy_request(
                    peer,
                    "GET",
                    "/v1/teams/team-alpha/network/mailbox",
                    query,
                    (),
                    b"",
                )
        for query in (
            "limit=101",
            "cursor=invalid",
            "cursor=v1.short",
            "cursor=v2.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "limit=1&limit=2",
            "unknown=value",
        ):
            with self.subTest(member_query=query), self.assertRaises(
                SecurePeerError
            ):
                sanitize_proxy_request(
                    peer,
                    "GET",
                    "/v1/teams/team-alpha/members",
                    query,
                    (),
                    b"",
                )
        for query in (
            "after_server_id=short",
            "after_server_id=node_12345678&limit=0",
            "after_server_id=node_12345678&limit=101",
            "after_server_id=node_12345678&limit=01",
            "after_server_id=node_12345678&after_server_id=node_87654321",
            "unknown=value",
        ):
            with self.subTest(network_query=query), self.assertRaises(
                SecurePeerError
            ):
                sanitize_proxy_request(
                    peer,
                    "GET",
                    "/v1/teams/team-alpha/network",
                    query,
                    (),
                    b"",
                )
        read_only_peer = PeerAuthorization(
            peer.peer_id,
            peer.pairing_id,
            peer.peer_server_identity,
            peer.team_id,
            frozenset({"teamspace.read"}),
            peer.certificate_fingerprint,
            peer.certificate_expires_at,
            peer.peer_display_name,
        )
        with self.assertRaises(SecurePeerError):
            sanitize_proxy_request(
                read_only_peer,
                "POST",
                "/v1/teams/team-alpha/network/mailbox",
                "",
                (("Content-Type", "application/json"),),
                b'{"to":{"kind":"server","id":"node_12345678"},"body":"no","idempotency_key":"mail-denied-001"}',
            )

    def test_proxy_response_is_bounded_and_strips_peer_control_headers(self) -> None:
        sanitized = sanitize_proxy_response(
            ProxyResponse(
                200,
                (
                    ("Content-Type", "application/json"),
                    ("Cache-Control", "no-store"),
                    ("ETag", '"current"'),
                    ("Location", "https://attacker.invalid/steal"),
                    ("Set-Cookie", "session=peer-controlled"),
                    ("Content-Encoding", "gzip"),
                    ("Transfer-Encoding", "chunked"),
                ),
                b'{"ok":true}',
            )
        )
        self.assertEqual(sanitized.status, 200)
        self.assertEqual(
            sanitized.headers,
            (
                ("content-type", "application/json"),
                ("cache-control", "no-store"),
                ("etag", '"current"'),
            ),
        )

        invalid_responses = (
            ProxyResponse(99, (), b""),
            ProxyResponse(302, (("Location", "https://attacker.invalid/steal"),), b""),
            ProxyResponse(200, (("Content-Type", "application/json"), ("content-type", "text/plain")), b""),
            ProxyResponse(200, (), b"x" * (2 * 1024 * 1024 + 1)),
        )
        for response in invalid_responses:
            with self.subTest(response=response), self.assertRaises(SecurePeerError) as invalid:
                sanitize_proxy_response(response)
            self.assertEqual(invalid.exception.code, "upstream_invalid")

        with self.assertRaises(SecurePeerError) as invalid_remote_error:
            SecurePeerClient._decode_json_response(
                409,
                [("content-type", "application/json")],
                b'{"error":{"code":"route_changed","message":"evil\\nmessage"}}',
            )
        self.assertEqual(invalid_remote_error.exception.code, "remote_invalid")

    def test_client_proxy_surfaces_only_structured_peer_revocation(self) -> None:
        client = SecurePeerClient(
            self.root / "proxy-client",
            "proxy-peer-001",
            "Proxy peer",
            clock=self.clock,
        )
        connection_id = _uuid()
        revoked = ProxyResponse(
            401,
            (("content-type", "application/json"),),
            b'{"error":{"code":"peer_revoked","message":"Peer authentication is unavailable"}}',
        )
        with (
            mock.patch.object(
                client,
                "_require_active_connection_locked",
            ),
            mock.patch.object(
                client,
                "_proxy_locked",
                return_value=revoked,
            ),
            self.assertRaises(SecurePeerError) as terminal,
        ):
            client.proxy(connection_id, "GET", "/v1/teams")
        self.assertEqual(terminal.exception.code, "peer_revoked")
        self.assertEqual(terminal.exception.status_code, 401)

        passthrough = (
            ProxyResponse(
                401,
                (("content-type", "application/json"),),
                b'{"error":{"code":"authorization_failed","message":"Denied"}}',
            ),
            ProxyResponse(
                503,
                (("content-type", "application/json"),),
                b'{"error":{"code":"peer_revoked","message":"Retry later"}}',
            ),
            ProxyResponse(
                401,
                (("content-type", "text/plain"),),
                b'{"error":{"code":"peer_revoked","message":"Untrusted shape"}}',
            ),
        )
        for response in passthrough:
            with (
                self.subTest(response=response),
                mock.patch.object(
                    client,
                    "_require_active_connection_locked",
                ),
                mock.patch.object(
                    client,
                    "_proxy_locked",
                    return_value=response,
                ),
            ):
                self.assertIs(
                    client.proxy(connection_id, "GET", "/v1/teams"),
                    response,
                )

    def test_pairing_capacity_is_transactional_and_prunes_old_terminal_rows(self) -> None:
        _key, request = self.request()
        template = self.store.submit_pairing(request)
        connection = self.store._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            original = connection.execute(
                "SELECT * FROM pairing_requests WHERE id=?", (template["pairing_id"],)
            ).fetchone()
            assert original is not None
            columns = [row["name"] for row in connection.execute("PRAGMA table_info(pairing_requests)")]
            values = [original[name] for name in columns]
            for _index in range(511):
                clone = list(values)
                clone[columns.index("id")] = _uuid()
                clone[columns.index("request_id")] = _uuid()
                clone[columns.index("source_ip")] = None
                clone[columns.index("source_endpoint")] = None
                placeholders = ",".join("?" for _ in columns)
                connection.execute(
                    f"INSERT INTO pairing_requests({','.join(columns)}) VALUES ({placeholders})",
                    clone,
                )
            connection.execute("COMMIT")
        finally:
            connection.close()
        _key, next_request = self.request()
        with self.assertRaises(SecurePeerError) as full:
            self.store.submit_pairing(next_request)
        self.assertEqual(full.exception.code, "pairing_capacity")

        connection = self.store._connect()
        try:
            connection.execute(
                """UPDATE pairing_requests SET status='rejected',decided_at=?
                WHERE id IN (SELECT id FROM pairing_requests LIMIT 20)""",
                (self.clock.value - 8 * 24 * 60 * 60,),
            )
        finally:
            connection.close()
        accepted = self.store.submit_pairing(next_request)
        self.assertEqual(accepted["status"], "pending")

    def test_recent_terminal_pairing_history_cannot_exhaust_admission(self) -> None:
        _key, request = self.request()
        template = self.store.submit_pairing(request)
        connection = self.store._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE pairing_requests SET status='rejected',decided_at=? WHERE id=?",
                (self.clock.value, template["pairing_id"]),
            )
            original = connection.execute(
                "SELECT * FROM pairing_requests WHERE id=?",
                (template["pairing_id"],),
            ).fetchone()
            assert original is not None
            columns = [
                row["name"]
                for row in connection.execute("PRAGMA table_info(pairing_requests)")
            ]
            values = [original[name] for name in columns]
            for _index in range(4):
                clone = list(values)
                clone[columns.index("id")] = _uuid()
                clone[columns.index("request_id")] = _uuid()
                placeholders = ",".join("?" for _ in columns)
                connection.execute(
                    f"INSERT INTO pairing_requests({','.join(columns)}) "
                    f"VALUES ({placeholders})",
                    clone,
                )
            connection.execute("COMMIT")
        finally:
            connection.close()

        _key, next_request = self.request()
        with mock.patch(
            "agentsdock_team_hub.secure_peer.PAIRING_TERMINAL_RETAINED_LIMIT",
            2,
        ):
            accepted = self.store.submit_pairing(next_request)
        self.assertEqual(accepted["status"], "pending")
        connection = self.store._connect()
        try:
            terminal_count = connection.execute(
                """SELECT COUNT(*) AS count FROM pairing_requests
                WHERE status IN ('expired','rejected','cancelled')"""
            ).fetchone()["count"]
        finally:
            connection.close()
        self.assertEqual(terminal_count, 2)

    def test_pairing_capacity_reserves_outgoing_actionable_slots(self) -> None:
        self.store._external_actionable_pairing_count = lambda: 1
        _key, request = self.request()
        template = self.store.submit_pairing(request)
        connection = self.store._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            original = connection.execute(
                "SELECT * FROM pairing_requests WHERE id=?",
                (template["pairing_id"],),
            ).fetchone()
            assert original is not None
            columns = [
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(pairing_requests)"
                )
            ]
            values = [original[name] for name in columns]
            for _index in range(PAIRING_STATUS_LIMIT - 2):
                clone = list(values)
                clone[columns.index("id")] = _uuid()
                clone[columns.index("request_id")] = _uuid()
                placeholders = ",".join("?" for _ in columns)
                connection.execute(
                    f"INSERT INTO pairing_requests({','.join(columns)}) "
                    f"VALUES ({placeholders})",
                    clone,
                )
            connection.execute("COMMIT")
        finally:
            connection.close()
        self.assertEqual(
            self.store.actionable_pairing_count(),
            PAIRING_STATUS_LIMIT - 1,
        )

        _key, overflow = self.request()
        with self.assertRaises(SecurePeerError) as full:
            self.store.submit_pairing(overflow)
        self.assertEqual(full.exception.code, "pairing_capacity")

    def test_client_pairing_admission_fails_closed_at_combined_capacity(self) -> None:
        client = SecurePeerClient(
            self.root / "capacity-client",
            "client-server-001",
            "Capacity client",
            external_actionable_pairing_count=lambda: PAIRING_STATUS_LIMIT,
        )
        fingerprint = "sha256:" + "d" * 64
        health = {
            "protocol_version": 1,
            "host_server_identity": "host-server-remote",
            "hub_id": "team-hub-remote",
            "host_ca_fingerprint": fingerprint,
        }
        with (
            mock.patch.object(
                client,
                "_request",
                return_value=(200, [], b"{}", b"unparsed-leaf"),
            ),
            mock.patch.object(
                client,
                "_decode_json_response",
                return_value=health,
            ),
            self.assertRaises(SecurePeerError) as full,
        ):
            client.begin_pairing(
                "192.0.2.20",
                requested_scopes=["teamspace.read"],
            )
        self.assertEqual(full.exception.code, "pairing_capacity")
        self.assertEqual(client.actionable_pairing_count(), 0)

    def test_route_bound_relay_uses_immutable_revisions_and_host_leg_ledger(self) -> None:
        _key, _submitted, _approved, peer = self.approve_peer()
        local_route = self.store.publish_local_route(
            peer.team_id,
            peer.peer_id,
            "chat-local-001",
            "local",
            "Local chat",
            ["instruction", "request_reply"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        peer_route = self.store.publish_peer_route(
            peer,
            {
                "route_id": _uuid(),
                "revision": "rev_" + uuid.uuid4().hex,
                "alias": "remote",
                "display_title": "Remote chat",
                "actions": ["instruction", "request_reply"],
            },
        )
        local_projection = self.store.list_local_routes(peer.peer_id)
        self.assertEqual(local_projection[0]["chat_id"], "chat-local-001")
        self.assertEqual(local_projection[0]["audience_peer_id"], peer.peer_id)
        remote_projection = self.store.list_remote_routes_for_peer(peer.peer_id)
        self.assertEqual(remote_projection[0]["route_id"], peer_route["route_id"])
        self.assertNotIn("chat_id", remote_projection[0])
        expires_at = self.clock.value + 3600
        first_payload = {
            "request_id": _uuid(),
            "source_route_id": local_route["route_id"],
            "target_route_id": peer_route["route_id"],
            "target_route_revision": peer_route["revision"],
            "kind": "request_reply",
            "exchange_id": None,
            "parent_envelope_id": None,
            "expires_at": expires_at,
            "body": {"message": "Please inspect this"},
        }
        first = self.store.submit_local_envelope(
            peer.team_id, local_route["route_id"], first_payload
        )
        repeated = self.store.submit_local_envelope(
            peer.team_id, local_route["route_id"], first_payload
        )
        self.assertEqual(first, repeated)
        changed = copy.deepcopy(first_payload)
        changed["body"] = {"message": "Changed"}
        with self.assertRaises(SecurePeerError) as conflict:
            self.store.submit_local_envelope(
                peer.team_id, local_route["route_id"], changed
            )
        self.assertEqual(conflict.exception.code, "idempotency_conflict")

        claim = self.store.claim_inbox(peer, "remote-worker")
        self.assertEqual(len(claim["envelopes"]), 1)
        envelope = claim["envelopes"][0]
        self.assertEqual(envelope["source_route_id"], local_route["route_id"])
        self.assertEqual(envelope["source_route_revision"], local_route["revision"])
        self.assertEqual(envelope["target_route_id"], peer_route["route_id"])
        self.assertEqual(envelope["target_route_revision"], peer_route["revision"])
        self.assertEqual(envelope["action"], "request_reply")
        self.store.receipt_envelope(
            peer,
            first["envelope_id"],
            claim["lease_token"],
            "delivered",
        )

        response = self.store.submit_envelope(
            peer,
            {
                "request_id": _uuid(),
                "source_route_id": peer_route["route_id"],
                "target_route_id": local_route["route_id"],
                "target_route_revision": local_route["revision"],
                "kind": "response",
                "exchange_id": first["exchange_id"],
                "parent_envelope_id": first["envelope_id"],
                "expires_at": expires_at,
                "body": {"message": "done"},
            },
        )
        self.assertEqual(response["used_legs"], 2)
        local_claim = self.store.claim_local_route_inbox(
            peer.team_id, local_route["route_id"], "local-worker"
        )
        self.assertEqual(local_claim["envelopes"][0]["body"], {"message": "done"})
        self.assertEqual(
            local_claim["envelopes"][0]["target_chat_id"], "chat-local-001"
        )

        with self.assertRaises(SecurePeerError) as replay:
            self.store.submit_envelope(
                peer,
                {
                    "request_id": _uuid(),
                    "source_route_id": peer_route["route_id"],
                    "target_route_id": local_route["route_id"],
                    "target_route_revision": local_route["revision"],
                    "kind": "response",
                    "exchange_id": first["exchange_id"],
                    "parent_envelope_id": first["envelope_id"],
                    "expires_at": expires_at,
                    "body": {"message": "replay"},
                },
            )
        self.assertEqual(replay.exception.code, "exchange_changed")

    def test_source_and_target_action_grants_are_both_required(self) -> None:
        _key, _submitted, _approved, peer = self.approve_peer()
        source = self.store.publish_local_route(
            peer.team_id,
            peer.peer_id,
            "chat-local-002",
            "local2",
            "Local two",
            ["instruction"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        target = self.store.publish_peer_route(
            peer,
            {
                "route_id": _uuid(),
                "revision": "rev_" + uuid.uuid4().hex,
                "alias": "remote2",
                "display_title": "Remote two",
                "actions": ["request_reply"],
            },
        )
        with self.assertRaises(SecurePeerError) as denied:
            self.store.submit_local_envelope(
                peer.team_id,
                source["route_id"],
                {
                    "request_id": _uuid(),
                    "source_route_id": source["route_id"],
                    "target_route_id": target["route_id"],
                    "target_route_revision": target["revision"],
                    "kind": "request_reply",
                    "exchange_id": None,
                    "parent_envelope_id": None,
                    "expires_at": self.clock.value + 60,
                    "body": {"message": "action check"},
                },
            )
        self.assertEqual(denied.exception.code, "route_action_forbidden")

    def test_receipt_cannot_accept_a_claim_after_exchange_expiry(self) -> None:
        _key, _submitted, _approved, peer = self.approve_peer()
        local_route = self.store.publish_local_route(
            peer.team_id,
            peer.peer_id,
            "chat-expiry-local",
            "expiry-local",
            "Expiry local",
            ["instruction"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        peer_route = self.store.publish_peer_route(
            peer,
            {
                "route_id": _uuid(),
                "revision": "rev_" + uuid.uuid4().hex,
                "alias": "expiry-peer",
                "display_title": "Expiry peer",
                "actions": ["instruction"],
            },
        )
        expires_at = self.clock.value + 1
        queued = self.store.submit_local_envelope(
            peer.team_id,
            local_route["route_id"],
            {
                "request_id": _uuid(),
                "source_route_id": local_route["route_id"],
                "target_route_id": peer_route["route_id"],
                "target_route_revision": peer_route["revision"],
                "kind": "instruction",
                "exchange_id": None,
                "parent_envelope_id": None,
                "expires_at": expires_at,
                "body": {"message": "must expire"},
            },
        )
        claim = self.store.claim_inbox(peer, "expiry-worker")
        self.assertEqual(len(claim["envelopes"]), 1)
        self.clock.value = expires_at + 1
        with self.assertRaises(SecurePeerError) as hidden:
            self.store.receipt_envelope(
                peer,
                queued["envelope_id"],
                "not-the-real-lease-token-but-long-enough",
                "delivered",
            )
        self.assertEqual(hidden.exception.code, "lease_unavailable")
        with self.assertRaises(SecurePeerError) as expired:
            self.store.receipt_envelope(
                peer,
                queued["envelope_id"],
                claim["lease_token"],
                "delivered",
            )
        self.assertEqual(expired.exception.code, "exchange_expired")
        self.assertEqual(expired.exception.status_code, 410)
        self.assertEqual(
            self.store.claim_inbox(peer, "expiry-worker-2")["envelopes"],
            [],
        )

    def test_persisted_consent_epoch_rejects_legacy_and_invalidates_old_grants(self) -> None:
        _key, _submitted, _approved, peer = self.approve_peer()
        self.assertEqual(peer.cross_chat_grant_epoch, 1)
        legacy = PeerAuthorization(
            peer.peer_id,
            peer.pairing_id,
            peer.peer_server_identity,
            peer.team_id,
            peer.scopes,
            peer.certificate_fingerprint,
            peer.certificate_expires_at,
            peer.peer_display_name,
            None,
        )
        descriptor = {
            "route_id": _uuid(),
            "revision": "rev_" + uuid.uuid4().hex,
            "alias": "legacy",
            "display_title": "Legacy route",
            "actions": ["instruction"],
        }
        with self.assertRaises(SecurePeerError) as legacy_denied:
            self.store.publish_peer_route(legacy, descriptor)
        self.assertEqual(
            legacy_denied.exception.code, "cross_chat_reapproval_required"
        )
        accepted = self.store.publish_peer_route(peer, descriptor)
        self.assertEqual(accepted["status"], "active")
        rotated = self.store.activate_cross_chat_consent(
            expected_epoch=1,
            idempotency_key=_uuid(),
            activated_by="owner-admin",
        )
        self.assertEqual(rotated["consent_epoch"], 2)
        with self.assertRaises(SecurePeerError) as old_denied:
            self.store.publish_peer_route(
                peer,
                {
                    **descriptor,
                    "route_id": _uuid(),
                    "revision": "rev_" + uuid.uuid4().hex,
                    "alias": "oldgrant",
                },
            )
        self.assertEqual(old_denied.exception.code, "cross_chat_reapproval_required")
        self.assertEqual(
            self.store.list_remote_routes_for_peer(peer.peer_id)[0]["status"],
            "revoked",
        )

    def test_route_and_relay_quotas_fail_before_unbounded_growth(self) -> None:
        _key, _submitted, _approved, peer = self.approve_peer()
        first_remote = self.store.publish_peer_route(
            peer,
            {
                "route_id": _uuid(),
                "revision": "rev_" + uuid.uuid4().hex,
                "alias": "quotaone",
                "display_title": "Quota one",
                "actions": ["instruction", "request_reply"],
            },
        )
        with mock.patch(
            "agentsdock_team_hub.secure_peer.ROUTE_ACTIVE_PER_PEER_LIMIT", 1
        ):
            with self.assertRaises(SecurePeerError) as route_full:
                self.store.publish_peer_route(
                    peer,
                    {
                        "route_id": _uuid(),
                        "revision": "rev_" + uuid.uuid4().hex,
                        "alias": "quotatwo",
                        "display_title": "Quota two",
                        "actions": ["instruction"],
                    },
                )
        self.assertEqual(route_full.exception.code, "route_capacity")

        local = self.store.publish_local_route(
            peer.team_id,
            peer.peer_id,
            "chat-quota-001",
            "quota",
            "Quota local",
            ["instruction", "request_reply"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        payload = {
            "request_id": _uuid(),
            "source_route_id": local["route_id"],
            "target_route_id": first_remote["route_id"],
            "target_route_revision": first_remote["revision"],
            "kind": "request_reply",
            "exchange_id": None,
            "parent_envelope_id": None,
            "expires_at": self.clock.value + 300,
            "body": {"message": "one"},
        }
        with mock.patch(
            "agentsdock_team_hub.secure_peer.RELAY_ACTIVE_GLOBAL_LIMIT", 1
        ):
            first = self.store.submit_local_envelope(
                peer.team_id, local["route_id"], payload
            )
            self.assertEqual(
                self.store.submit_local_envelope(
                    peer.team_id, local["route_id"], payload
                ),
                first,
            )
            changed = {**payload, "request_id": _uuid(), "body": {"message": "two"}}
            with self.assertRaises(SecurePeerError) as relay_full:
                self.store.submit_local_envelope(
                    peer.team_id, local["route_id"], changed
                )
        self.assertEqual(relay_full.exception.code, "relay_capacity")
        revoked = self.store.revoke_peer_route(
            peer,
            first_remote["route_id"],
            first_remote["revision"],
            _uuid(),
        )
        self.assertEqual(revoked["status"], "revoked")
        connection = self.store._connect()
        try:
            envelope = connection.execute(
                "SELECT status FROM relay_envelopes WHERE id=?",
                (first["envelope_id"],),
            ).fetchone()
            exchange = connection.execute(
                "SELECT status FROM relay_exchanges WHERE id=?",
                (first["exchange_id"],),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(envelope["status"], "expired")
        self.assertEqual(exchange["status"], "expired")

    def test_relay_usage_budget_is_durable_and_isolated_per_peer(self) -> None:
        _key, _submitted, _approved, first_peer = self.approve_peer()
        _key, _submitted, _approved, second_peer = self.approve_peer(
            source_ip="10.0.0.10",
            server_identity="peer-server-002",
            display_name="Second peer",
        )

        def paired_routes(peer: PeerAuthorization, suffix: str) -> tuple[dict, dict]:
            local = self.store.publish_local_route(
                peer.team_id,
                peer.peer_id,
                f"chat-budget-{suffix}",
                f"local{suffix}",
                f"Local {suffix}",
                ["instruction"],
                idempotency_key=_uuid(),
                published_by="owner-admin",
            )
            remote = self.store.publish_peer_route(
                peer,
                {
                    "route_id": _uuid(),
                    "revision": "rev_" + uuid.uuid4().hex,
                    "alias": f"remote{suffix}",
                    "display_title": f"Remote {suffix}",
                    "actions": ["instruction"],
                },
            )
            return remote, local

        first_source, first_target = paired_routes(first_peer, "one")
        second_source, second_target = paired_routes(second_peer, "two")

        def payload(source: dict, target: dict, message: str) -> dict:
            return {
                "request_id": _uuid(),
                "source_route_id": source["route_id"],
                "target_route_id": target["route_id"],
                "target_route_revision": target["revision"],
                "kind": "instruction",
                "exchange_id": None,
                "parent_envelope_id": None,
                "expires_at": self.clock.value + 600,
                "body": {"message": message},
            }

        first_payload = payload(first_source, first_target, "one")
        with mock.patch(
            "agentsdock_team_hub.secure_peer.RELAY_SUBMISSIONS_PER_PEER_WINDOW_LIMIT",
            1,
        ):
            accepted = self.store.submit_envelope(first_peer, first_payload)
            self.assertEqual(
                self.store.submit_envelope(first_peer, first_payload), accepted
            )
            with self.assertRaises(SecurePeerError) as first_limited:
                self.store.submit_envelope(
                    first_peer,
                    payload(first_source, first_target, "two"),
                )
            self.assertEqual(first_limited.exception.code, "rate_limited")

            reopened = SecurePeerStore(
                self.root / "host",
                "host-server-001",
                "team-hub-001",
                clock=self.clock,
                cross_chat_enabled=True,
            )
            with self.assertRaises(SecurePeerError) as still_limited:
                reopened.submit_envelope(
                    first_peer,
                    payload(first_source, first_target, "three"),
                )
            self.assertEqual(still_limited.exception.code, "rate_limited")

            other_accepted = self.store.submit_envelope(
                second_peer,
                payload(second_source, second_target, "other peer"),
            )
            self.assertEqual(other_accepted["status"], "queued")

    def test_local_routes_are_unique_per_audience_chat_and_alias(self) -> None:
        _key, _submitted, _approved, peer = self.approve_peer()
        self.store.publish_local_route(
            peer.team_id,
            peer.peer_id,
            "chat-unique-001",
            "unique",
            "Unique chat",
            ["instruction"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        for chat_id, alias in (
            ("chat-unique-001", "different"),
            ("chat-unique-002", "unique"),
        ):
            with self.subTest(chat_id=chat_id, alias=alias):
                with self.assertRaises(SecurePeerError) as conflict:
                    self.store.publish_local_route(
                        peer.team_id,
                        peer.peer_id,
                        chat_id,
                        alias,
                        "Conflicting route",
                        ["instruction"],
                        idempotency_key=_uuid(),
                        published_by="owner-admin",
                    )
                self.assertEqual(conflict.exception.code, "route_conflict")

    def test_request_reply_reserves_the_sixth_leg_for_terminal_response(self) -> None:
        _key, _submitted, _approved, peer = self.approve_peer()
        local = self.store.publish_local_route(
            peer.team_id,
            peer.peer_id,
            "chat-budget-001",
            "budgetlocal",
            "Budget local",
            ["request_reply"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        remote = self.store.publish_peer_route(
            peer,
            {
                "route_id": _uuid(),
                "revision": "rev_" + uuid.uuid4().hex,
                "alias": "budgetremote",
                "display_title": "Budget remote",
                "actions": ["request_reply"],
            },
        )
        expires_at = self.clock.value + 600

        def payload(source, target, kind, exchange, parent):
            return {
                "request_id": _uuid(),
                "source_route_id": source["route_id"],
                "target_route_id": target["route_id"],
                "target_route_revision": target["revision"],
                "kind": kind,
                "exchange_id": exchange,
                "parent_envelope_id": parent,
                "expires_at": expires_at,
                "body": {"message": kind},
            }

        current = self.store.submit_local_envelope(
            peer.team_id,
            local["route_id"],
            payload(local, remote, "request_reply", None, None),
        )
        exchange = current["exchange_id"]
        for leg in range(2, 6):
            if leg % 2 == 0:
                current = self.store.submit_envelope(
                    peer,
                    payload(
                        remote,
                        local,
                        "request_reply",
                        exchange,
                        current["envelope_id"],
                    ),
                )
            else:
                current = self.store.submit_local_envelope(
                    peer.team_id,
                    local["route_id"],
                    payload(
                        local,
                        remote,
                        "request_reply",
                        exchange,
                        current["envelope_id"],
                    ),
                )
            self.assertEqual(current["used_legs"], leg)
        sixth_request = payload(
            remote,
            local,
            "request_reply",
            exchange,
            current["envelope_id"],
        )
        with self.assertRaises(SecurePeerError) as exhausted:
            self.store.submit_envelope(peer, sixth_request)
        self.assertEqual(exhausted.exception.code, "leg_budget_exhausted")
        sixth_request["request_id"] = _uuid()
        sixth_request["kind"] = "response"
        terminal = self.store.submit_envelope(peer, sixth_request)
        self.assertEqual(terminal["used_legs"], MAX_RELAY_LEGS)

    def test_identity_first_create_recovers_and_client_state_is_identity_bound(self) -> None:
        incomplete = self.root / "incomplete-host"
        incomplete.mkdir(mode=0o700)
        partial = incomplete / "host-ca-key.pem"
        partial.write_bytes(b"not-a-committed-key" * 4)
        partial.chmod(0o600)
        recovered = SecurePeerStore(
            incomplete,
            "recovered-host-001",
            "recovered-hub-001",
        )
        self.assertRegex(recovered.ca_fingerprint, r"^sha256:[0-9a-f]{64}$")
        client_root = self.root / "bound-client"
        SecurePeerClient(client_root, "bound-peer-001", "Bound peer")
        with self.assertRaisesRegex(PermissionError, "quarantined"):
            SecurePeerClient(client_root, "other-peer-001", "Other peer")

    def test_remote_revocation_retires_exact_connection_and_routes_atomically(self) -> None:
        client = SecurePeerClient(
            self.root / "revoked-client",
            "revoked-peer-001",
            "Revoked peer",
            clock=self.clock,
        )
        connection_id = _uuid()
        certificate_fingerprint = "sha256:" + "d" * 64
        key_path = client.keys_dir / f"{connection_id}.key.pem"
        certificate_path = client.keys_dir / f"{connection_id}.certificate.pem"
        key_path.write_bytes(b"preserved-private-key")
        certificate_path.write_bytes(b"preserved-certificate")
        key_path.chmod(0o600)
        certificate_path.chmod(0o600)
        active_route = _uuid()
        pending_route = _uuid()
        database = client._connect()
        try:
            database.execute(
                """INSERT INTO client_connections(
                connection_id,host_ip,port,status,pairing_id,pairing_request_id,
                poll_token,pairing_request_json,pairing_request_digest,peer_id,
                team_id,scopes_json,host_server_identity,hub_id,
                host_ca_certificate_pem,host_ca_fingerprint,transcript_hash,
                sas_json,requested_scopes_json,peer_public_key_fingerprint,
                key_path,certificate_path,certificate_fingerprint,
                certificate_expires_at,relay_available,created_at,updated_at,
                last_validated_at
                ) VALUES (
                :connection_id,'192.0.2.20',7851,'connected',:pairing_id,
                :request_id,'poll-token','{}',:request_digest,:peer_id,
                'team-alpha','["teamspace.read"]','host-server-001',
                'team-hub-001',:ca_pem,:ca_fingerprint,:transcript_hash,
                '["amber","beacon","cedar","delta","ember","forest"]',
                '["teamspace.read"]',:public_key_fingerprint,:key_path,
                :certificate_path,:certificate_fingerprint,:certificate_expires_at,
                1,:created_at,:created_at,:created_at
                )""",
                {
                    "connection_id": connection_id,
                    "pairing_id": _uuid(),
                    "request_id": _uuid(),
                    "request_digest": b"pairing-digest",
                    "peer_id": _uuid(),
                    "ca_pem": self.store.ca_certificate_pem,
                    "ca_fingerprint": self.store.ca_fingerprint,
                    "transcript_hash": "a" * 64,
                    "public_key_fingerprint": "sha256:" + "b" * 64,
                    "key_path": str(key_path),
                    "certificate_path": str(certificate_path),
                    "certificate_fingerprint": certificate_fingerprint,
                    "certificate_expires_at": self.clock.value + 3_600,
                    "created_at": self.clock.value,
                },
            )
            database.execute(
                "UPDATE client_meta SET value=? WHERE key='active_connection_id'",
                (connection_id,),
            )
            for route_id, status, pending in (
                (active_route, "active", 0),
                (pending_route, "revoked", 1),
            ):
                database.execute(
                    """INSERT INTO client_routes(
                    route_id,connection_id,revision,alias,display_title,
                    actions_json,chat_id,status,revoke_pending,
                    revoke_expected_revision,revoke_idempotency_key,
                    created_at,updated_at
                    ) VALUES (?,?,?,'route','Route','["instruction"]',?,?,?,?,?,?,?)""",
                    (
                        route_id,
                        connection_id,
                        "rev_" + "e" * 32,
                        f"chat-{route_id}",
                        status,
                        pending,
                        "rev_" + "e" * 32 if pending else None,
                        _uuid() if pending else None,
                        self.clock.value,
                        self.clock.value,
                    ),
                )
            database.execute(
                """INSERT INTO client_renewals(
                request_id,connection_id,old_certificate_fingerprint,
                request_json,key_path,status,created_at,updated_at
                ) VALUES (?,?,?,'{}',?,'pending',?,?)""",
                (
                    _uuid(),
                    connection_id,
                    certificate_fingerprint,
                    str(key_path),
                    self.clock.value,
                    self.clock.value,
                ),
            )
        finally:
            database.close()

        with self.assertRaises(SecurePeerError) as changed:
            client.retire_remote_revoked_connection(
                connection_id,
                expected_host_server_identity="host-server-001",
                expected_hub_id="team-hub-001",
                expected_certificate_fingerprint="sha256:" + "f" * 64,
            )
        self.assertEqual(changed.exception.code, "connection_changed")
        self.assertTrue(client.get_connection(connection_id)["active"])
        self.assertEqual(
            {route["status"] for route in client.list_published_routes()},
            {"active", "revoked"},
        )

        retired = client.retire_remote_revoked_connection(
            connection_id,
            expected_host_server_identity="host-server-001",
            expected_hub_id="team-hub-001",
            expected_certificate_fingerprint=certificate_fingerprint,
        )
        self.assertEqual(retired["status"], "revoked")
        self.assertFalse(retired["active"])
        self.assertFalse(retired["remote_route_delivery_available"])
        self.assertEqual(key_path.read_bytes(), b"preserved-private-key")
        self.assertEqual(
            certificate_path.read_bytes(),
            b"preserved-certificate",
        )
        database = client._connect()
        try:
            routes = database.execute(
                """SELECT status,revoke_pending,revoke_expected_revision,
                revoke_idempotency_key FROM client_routes
                WHERE connection_id=? ORDER BY route_id""",
                (connection_id,),
            ).fetchall()
            renewals = database.execute(
                "SELECT COUNT(*) AS count FROM client_renewals WHERE connection_id=?",
                (connection_id,),
            ).fetchone()
        finally:
            database.close()
        self.assertEqual(len(routes), 2)
        self.assertTrue(all(route["status"] == "revoked" for route in routes))
        self.assertTrue(all(int(route["revoke_pending"]) == 0 for route in routes))
        self.assertTrue(all(route["revoke_expected_revision"] is None for route in routes))
        self.assertTrue(all(route["revoke_idempotency_key"] is None for route in routes))
        self.assertEqual(int(renewals["count"]), 0)

        repeated = client.retire_remote_revoked_connection(
            connection_id,
            expected_host_server_identity="host-server-001",
            expected_hub_id="team-hub-001",
            expected_certificate_fingerprint=certificate_fingerprint,
        )
        self.assertEqual(repeated["status"], "revoked")
        self.assertFalse(repeated["active"])

    def test_expired_unanswered_pairing_attempt_retires_all_key_material(self) -> None:
        client = SecurePeerClient(
            self.root / "attempt-client",
            "attempt-peer-001",
            "Attempt peer",
            clock=self.clock,
        )
        request_id = _uuid()
        connection_id = _uuid()
        key = Ed25519PrivateKey.generate()
        request = build_pairing_request(
            key,
            server_identity=client.server_identity,
            display_name=client.display_name,
            host_ca_fingerprint=self.store.ca_fingerprint,
            request_id=request_id,
            created_at=self.clock.value,
            requested_scopes=["teamspace.read"],
        )
        key_path = client.keys_dir / f"{connection_id}.key.pem"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        ca_path = client.keys_dir / f"{connection_id}.ca.pem"
        ca_path.write_bytes(b"persisted pairing CA")
        ca_path.chmod(0o600)
        database = client._connect()
        try:
            database.execute(
                """INSERT INTO client_pairing_attempts(
                request_id,connection_id,host_ip,port,observed_ca_fingerprint,
                health_leaf_fingerprint,host_server_identity,hub_id,request_json,
                key_path,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    request_id,
                    connection_id,
                    "192.0.2.30",
                    7851,
                    self.store.ca_fingerprint,
                    "sha256:" + "1" * 64,
                    self.store.host_server_identity,
                    self.store.hub_id,
                    canonical_json(request).decode("utf-8"),
                    str(key_path),
                    self.clock.value,
                ),
            )
        finally:
            database.close()
        self.clock.value += PAIRING_ATTEMPT_RETENTION_SECONDS + 1
        recovery = client.recover_pairing_attempts()
        self.assertEqual(recovery["retired"], 1)
        self.assertEqual(recovery["remaining"], 0)
        self.assertFalse(key_path.exists())
        self.assertFalse(ca_path.exists())
        self.assertEqual(list(client.keys_dir.iterdir()), [])

    def test_pairing_database_open_failure_retires_unpersisted_private_key(self) -> None:
        client = SecurePeerClient(
            self.root / "connect-failure-client",
            "connect-failure-peer-001",
            "Connect failure peer",
            clock=self.clock,
        )
        health = {
            "protocol_version": 1,
            "host_server_identity": self.store.host_server_identity,
            "hub_id": self.store.hub_id,
            "host_ca_fingerprint": self.store.ca_fingerprint,
        }
        real_connect = client._connect
        connect_calls = 0

        def fail_after_key_creation():
            nonlocal connect_calls
            connect_calls += 1
            if connect_calls == 2:
                raise OSError("injected database-open failure")
            return real_connect()

        with (
            mock.patch.object(
                client,
                "_request",
                return_value=(
                    200,
                    [("Content-Type", "application/json")],
                    canonical_json(health),
                    b"stable discovery leaf",
                ),
            ),
            mock.patch.object(client, "_connect", side_effect=fail_after_key_creation),
            self.assertRaisesRegex(OSError, "injected database-open failure"),
        ):
            client.begin_pairing(
                "192.0.2.30",
                requested_scopes=["teamspace.read"],
            )

        self.assertEqual(connect_calls, 2)
        self.assertEqual(client.actionable_pairing_count(), 0)
        self.assertEqual(list(client.keys_dir.iterdir()), [])

    def test_untrusted_discovery_identity_cannot_create_actionable_client_state(self) -> None:
        client = SecurePeerClient(
            self.root / "malicious-discovery-client",
            "discovery-peer-001",
            "Discovery peer",
            clock=self.clock,
        )
        health = {
            "protocol_version": 1,
            "host_server_identity": "evil\nhost",
            "hub_id": "team-hub-001",
            "host_ca_fingerprint": self.store.ca_fingerprint,
        }
        with (
            mock.patch.object(
                client,
                "_request",
                return_value=(
                    200,
                    [("Content-Type", "application/json")],
                    canonical_json(health),
                    b"unused-leaf",
                ),
            ),
            self.assertRaises(SecurePeerError) as rejected,
        ):
            client.begin_pairing(
                "192.0.2.30",
                requested_scopes=["teamspace.read"],
            )
        self.assertEqual(rejected.exception.code, "host_identity_mismatch")
        self.assertEqual(client.actionable_pairing_count(), 0)
        self.assertEqual(list(client.keys_dir.iterdir()), [])

    def test_host_compatibility_migration_rolls_back_schema_and_purge_together(self) -> None:
        legacy_dir = self.root / "atomic-migration-host"
        original = SecurePeerStore(
            legacy_dir,
            "atomic-host-001",
            "atomic-hub-001",
            clock=self.clock,
        )
        database = original._connect()
        try:
            database.execute(
                "ALTER TABLE relay_envelopes DROP COLUMN source_route_revision"
            )
        finally:
            database.close()

        class FailingConnection:
            def __init__(self, inner):
                self.inner = inner

            def execute(self, sql, parameters=()):
                if sql.strip().startswith("DELETE FROM relay_receipts"):
                    raise RuntimeError("simulated migration interruption")
                return self.inner.execute(sql, parameters)

            def __getattr__(self, name):
                return getattr(self.inner, name)

        class FailingStore(SecurePeerStore):
            def _connect(self):
                return FailingConnection(super()._connect())

        with self.assertRaisesRegex(RuntimeError, "migration interruption"):
            FailingStore(
                legacy_dir,
                "atomic-host-001",
                "atomic-hub-001",
                clock=self.clock,
            )
        database = sqlite3.connect(legacy_dir / "secure-peer.sqlite3")
        try:
            columns_after_failure = {
                row[1]
                for row in database.execute(
                    "PRAGMA table_info(relay_envelopes)"
                ).fetchall()
            }
        finally:
            database.close()
        self.assertNotIn("source_route_revision", columns_after_failure)

        repaired = SecurePeerStore(
            legacy_dir,
            "atomic-host-001",
            "atomic-hub-001",
            clock=self.clock,
        )
        database = repaired._connect()
        try:
            columns_after_retry = {
                row["name"]
                for row in database.execute(
                    "PRAGMA table_info(relay_envelopes)"
                ).fetchall()
            }
        finally:
            database.close()
        self.assertIn("source_route_revision", columns_after_retry)

    def test_attachment_download_releases_route_guard_while_body_streams(self) -> None:
        client = SecurePeerClient(
            self.root / "download-lock-client",
            "download-peer-001",
            "Download peer",
            clock=self.clock,
        )
        entered = threading.Event()
        release = threading.Event()

        class Response:
            status = 200

            @staticmethod
            def getheaders():
                return [
                    ("Content-Length", "4"),
                    ("ETag", '"etag"'),
                    ("Content-Type", "text/plain"),
                    ("Accept-Ranges", "bytes"),
                ]

            def __init__(self):
                self.sent = False

            def read(self, _amount):
                if self.sent:
                    return b""
                self.sent = True
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("test download was not released")
                return b"data"

        class Connection:
            def __init__(self, *_args, **_kwargs):
                self.response = Response()

            @staticmethod
            def request(*_args, **_kwargs):
                return None

            def getresponse(self):
                return self.response

            @staticmethod
            def close():
                return None

        destination = self.root / "downloaded.txt"
        errors: list[BaseException] = []
        with (
            mock.patch.object(
                client, "_require_active_connection_locked", return_value=None
            ),
            mock.patch.object(
                client,
                "_connection_row",
                return_value={"host_ip": "192.0.2.20", "port": 7851},
            ),
            mock.patch.object(client, "_pinned_context", return_value=object()),
            mock.patch(
                "agentsdock_team_hub.secure_peer.http.client.HTTPSConnection",
                Connection,
            ),
        ):
            worker = threading.Thread(
                target=lambda: self._capture_thread_error(
                    errors,
                    lambda: client.download_attachment_to(
                        str(uuid.uuid4()),
                        "/v1/teams/team-1/network/attachments/attachment-1/content",
                        destination,
                        expected_size=4,
                    ),
                )
            )
            worker.start()
            self.assertTrue(entered.wait(5))
            self.assertTrue(client._route_guard.acquire(timeout=1))
            client._route_guard.release()
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(destination.read_bytes(), b"data")

    @staticmethod
    def _capture_thread_error(
        errors: list[BaseException], operation
    ) -> None:
        try:
            operation()
        except BaseException as exc:
            errors.append(exc)


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


class SecurePeerLiveTLSTests(unittest.TestCase):
    def setUp(self) -> None:
        self.host_ip = _nonloopback_ipv4()
        if self.host_ip is None:
            self.skipTest("no non-loopback IPv4 address is available")
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.store = SecurePeerStore(
            root / "host",
            "host-server-live",
            "team-hub-live",
            cross_chat_enabled=True,
        )
        self.port = _free_port(self.host_ip)
        self.gateway = SecurePeerGateway(self.store, self.host_ip, self.port)
        self.gateway.start()
        self.client = SecurePeerClient(
            root / "client", "peer-server-live", "Live peer", timeout_seconds=5
        )

    def tearDown(self) -> None:
        if hasattr(self, "gateway"):
            self.gateway.stop()
        if hasattr(self, "temporary"):
            self.temporary.cleanup()

    def pair_and_approve(self) -> dict:
        connection = self.client.begin_pairing(
            self.host_ip,
            self.port,
            expected_ca_fingerprint=self.store.ca_fingerprint,
            requested_scopes=[
                "teamspace.read",
                "cross_chat.instruction",
                "cross_chat.request_reply",
            ],
        )
        self.assertRegex(connection["peer_public_key_fingerprint"], r"^sha256:[0-9a-f]{64}$")
        pending = self.store.list_pairings(status="pending")[0]
        self.store.approve_pairing(
            pending["pairing_id"],
            "team-alpha",
            pending["requested_scopes"],
            "owner-admin",
            expected_peer_server_identity=pending["peer_server_identity"],
            expected_transcript_hash=pending["transcript_hash"],
            idempotency_key=_uuid(),
        )
        return self.client.poll_pairing(connection["connection_id"])

    def test_cancel_pairing_is_locally_terminal_and_response_loss_idempotent(self) -> None:
        pending = self.client.begin_pairing(
            self.host_ip,
            self.port,
            expected_ca_fingerprint=self.store.ca_fingerprint,
            requested_scopes=["teamspace.read"],
        )
        original_abandon = self.client._abandon_uncredentialed_connection
        abandon_calls = 0

        def lose_first_local_response(row):
            nonlocal abandon_calls
            result = original_abandon(row)
            abandon_calls += 1
            if abandon_calls == 1:
                raise RuntimeError("simulated lost local cancel response")
            return result

        operation_id = _uuid()
        with mock.patch.object(
            self.client,
            "_abandon_uncredentialed_connection",
            side_effect=lose_first_local_response,
        ):
            with self.assertRaisesRegex(RuntimeError, "lost local cancel response"):
                self.client.cancel_pairing(
                    pending["connection_id"], operation_id
                )
        repeated = self.client.cancel_pairing(
            pending["connection_id"], operation_id
        )
        self.assertEqual(repeated["status"], "cancelled")
        self.assertFalse(repeated["active"])
        self.assertEqual(self.client.actionable_pairing_count(), 0)
        self.assertEqual(list(self.client.keys_dir.iterdir()), [])
        self.assertTrue(any((self.client.data_dir / "retired").iterdir()))

    def test_cancel_pairing_is_locally_terminal_when_remote_is_unavailable(
        self,
    ) -> None:
        remote_failures = {
            "transport": SecurePeerError(
                "transport_failed",
                "Secure peer host is unavailable",
                502,
            ),
            "not_found": (
                404,
                [("Content-Type", "application/json")],
                canonical_json(
                    {
                        "error": {
                            "code": "pairing_not_found",
                            "message": "Pairing request was not found",
                        }
                    }
                ),
                b"pinned-host-leaf",
            ),
        }

        for label, failure in remote_failures.items():
            with self.subTest(failure=label):
                pending = self.client.begin_pairing(
                    self.host_ip,
                    self.port,
                    expected_ca_fingerprint=self.store.ca_fingerprint,
                    requested_scopes=["teamspace.read"],
                )
                operation_id = _uuid()
                request_patch = (
                    mock.patch.object(self.client, "_request", side_effect=failure)
                    if isinstance(failure, BaseException)
                    else mock.patch.object(
                        self.client,
                        "_request",
                        return_value=failure,
                    )
                )
                with request_patch as remote_request:
                    cancelled = self.client.cancel_pairing(
                        pending["connection_id"], operation_id
                    )

                remote_request.assert_called_once()
                self.assertEqual(cancelled["status"], "cancelled")
                self.assertFalse(cancelled["active"])
                self.assertEqual(self.client.actionable_pairing_count(), 0)
                self.assertEqual(list(self.client.keys_dir.iterdir()), [])

                # The local terminal tombstone makes retries independent of the
                # remote host, including after a lost first response.
                with mock.patch.object(self.client, "_request") as retry_request:
                    repeated = self.client.cancel_pairing(
                        pending["connection_id"], operation_id
                    )
                retry_request.assert_not_called()
                self.assertEqual(repeated["status"], "cancelled")
                self.assertFalse(repeated["active"])

    def test_cancel_winning_during_approved_poll_cannot_resurrect_pairing(self) -> None:
        pending = self.client.begin_pairing(
            self.host_ip,
            self.port,
            expected_ca_fingerprint=self.store.ca_fingerprint,
            requested_scopes=["teamspace.read"],
        )
        incoming = self.store.list_pairings(status="pending")[0]
        self.store.approve_pairing(
            incoming["pairing_id"],
            "team-alpha",
            incoming["requested_scopes"],
            "owner-admin",
            expected_peer_server_identity=incoming["peer_server_identity"],
            expected_transcript_hash=incoming["transcript_hash"],
            idempotency_key=_uuid(),
        )
        competing = SecurePeerClient(
            self.client.data_dir,
            self.client.server_identity,
            self.client.display_name,
            timeout_seconds=5,
        )
        validated = threading.Event()
        release = threading.Event()
        results: list[dict] = []
        errors: list[BaseException] = []
        original_validate = self.client._validate_issued_client_certificate

        def pause_after_validation(*args, **kwargs):
            result = original_validate(*args, **kwargs)
            validated.set()
            if not release.wait(5):
                raise TimeoutError("test did not release pairing poll")
            return result

        def poll() -> None:
            try:
                results.append(self.client.poll_pairing(pending["connection_id"]))
            except BaseException as exc:
                errors.append(exc)

        with mock.patch.object(
            self.client,
            "_validate_issued_client_certificate",
            side_effect=pause_after_validation,
        ):
            worker = threading.Thread(target=poll)
            worker.start()
            self.assertTrue(validated.wait(5))
            cancelled = competing.cancel_pairing(
                pending["connection_id"], _uuid()
            )
            self.assertEqual(cancelled["status"], "cancelled")
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual([item["status"] for item in results], ["cancelled"])
        self.assertEqual(
            self.client.get_connection(pending["connection_id"])["status"],
            "cancelled",
        )
        self.assertEqual(list(self.client.keys_dir.iterdir()), [])

    def test_stale_pending_poll_cannot_downgrade_approved_pairing(self) -> None:
        pending = self.client.begin_pairing(
            self.host_ip,
            self.port,
            expected_ca_fingerprint=self.store.ca_fingerprint,
            requested_scopes=["teamspace.read"],
        )
        competing = SecurePeerClient(
            self.client.data_dir,
            self.client.server_identity,
            self.client.display_name,
            timeout_seconds=5,
        )
        decoded_pending = threading.Event()
        release = threading.Event()
        results: list[dict] = []
        errors: list[BaseException] = []
        original_decode = competing._decode_json_response

        def pause_pending_decode(*args, **kwargs):
            response = original_decode(*args, **kwargs)
            if response.get("status") == "pending":
                decoded_pending.set()
                if not release.wait(5):
                    raise TimeoutError("test did not release stale pairing poll")
            return response

        def stale_poll() -> None:
            try:
                results.append(competing.poll_pairing(pending["connection_id"]))
            except BaseException as exc:
                errors.append(exc)

        with mock.patch.object(
            competing,
            "_decode_json_response",
            side_effect=pause_pending_decode,
        ):
            worker = threading.Thread(target=stale_poll)
            worker.start()
            self.assertTrue(decoded_pending.wait(5))
            incoming = self.store.list_pairings(status="pending")[0]
            self.store.approve_pairing(
                incoming["pairing_id"],
                "team-alpha",
                incoming["requested_scopes"],
                "owner-admin",
                expected_peer_server_identity=incoming["peer_server_identity"],
                expected_transcript_hash=incoming["transcript_hash"],
                idempotency_key=_uuid(),
            )
            approved = self.client.poll_pairing(pending["connection_id"])
            self.assertEqual(approved["status"], "approved")
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual([item["status"] for item in results], ["approved"])
        self.assertEqual(
            self.client.get_connection(pending["connection_id"])["status"],
            "approved",
        )

    def test_winning_terminal_polls_retire_client_key_and_pinned_ca(self) -> None:
        for terminal_status in ("rejected", "cancelled", "expired"):
            with self.subTest(status=terminal_status):
                pending = self.client.begin_pairing(
                    self.host_ip,
                    self.port,
                    expected_ca_fingerprint=self.store.ca_fingerprint,
                    requested_scopes=["teamspace.read"],
                )
                incoming = self.store.list_pairings(status="pending")[0]
                material = [
                    path
                    for path in self.client.keys_dir.iterdir()
                    if path.name.startswith(pending["connection_id"] + ".")
                ]
                self.assertEqual(
                    {path.suffixes[-2] for path in material}, {".key", ".ca"}
                )
                if terminal_status == "rejected":
                    self.store.reject_pairing(
                        incoming["pairing_id"],
                        "owner-admin",
                        "Not this peer",
                        expected_peer_server_identity=incoming[
                            "peer_server_identity"
                        ],
                        expected_transcript_hash=incoming["transcript_hash"],
                        idempotency_key=_uuid(),
                    )
                elif terminal_status == "cancelled":
                    row = self.client._connection_row(pending["connection_id"])
                    self.store.cancel_pairing(
                        incoming["pairing_id"], row["poll_token"], _uuid()
                    )
                else:
                    database = self.store._connect()
                    try:
                        database.execute(
                            "UPDATE pairing_requests SET expires_at=? WHERE id=?",
                            (int(time.time()) - 1, incoming["pairing_id"]),
                        )
                    finally:
                        database.close()

                result = self.client.poll_pairing(pending["connection_id"])
                self.assertEqual(result["status"], terminal_status)
                self.assertEqual(
                    [
                        path
                        for path in self.client.keys_dir.iterdir()
                        if path.name.startswith(pending["connection_id"])
                    ],
                    [],
                )

    def test_restart_poll_self_heals_terminal_commit_before_file_retirement(self) -> None:
        pending = self.client.begin_pairing(
            self.host_ip,
            self.port,
            expected_ca_fingerprint=self.store.ca_fingerprint,
            requested_scopes=["teamspace.read"],
        )
        database = self.client._connect()
        try:
            database.execute(
                "UPDATE client_connections SET status='expired' WHERE connection_id=?",
                (pending["connection_id"],),
            )
        finally:
            database.close()
        self.assertTrue(
            any(
                path.name.startswith(pending["connection_id"])
                for path in self.client.keys_dir.iterdir()
            )
        )

        restarted = SecurePeerClient(
            self.client.data_dir,
            self.client.server_identity,
            self.client.display_name,
            timeout_seconds=5,
        )
        result = restarted.poll_pairing(pending["connection_id"])
        self.assertEqual(result["status"], "expired")
        self.assertEqual(
            [
                path
                for path in restarted.keys_dir.iterdir()
                if path.name.startswith(pending["connection_id"])
            ],
            [],
        )

    def test_expired_saved_renewal_is_retired_and_retried_once(self) -> None:
        paired = self.pair_and_approve()
        now = int(time.time())
        host_db = self.store._connect()
        try:
            host_db.execute(
                "UPDATE peer_certificates SET expires_at=? WHERE fingerprint=?",
                (now + 60, paired["certificate_fingerprint"]),
            )
        finally:
            host_db.close()
        client_db = self.client._connect()
        try:
            client_db.execute(
                "UPDATE client_connections SET certificate_expires_at=? WHERE connection_id=?",
                (now + 60, paired["connection_id"]),
            )
        finally:
            client_db.close()

        original_request = self.client._request
        activation_attempts = 0

        def lose_first_activation(*args, **kwargs):
            nonlocal activation_attempts
            path = args[3]
            if "/v1/renewals/" in path and path.endswith("/activate"):
                activation_attempts += 1
                if activation_attempts == 1:
                    raise RuntimeError("simulated pre-activation interruption")
            return original_request(*args, **kwargs)

        with mock.patch.object(
            self.client, "_request", side_effect=lose_first_activation
        ):
            with self.assertRaisesRegex(RuntimeError, "pre-activation interruption"):
                self.client.renew_if_due(paired["connection_id"])
        client_db = self.client._connect()
        try:
            stale = client_db.execute(
                """SELECT * FROM client_renewals WHERE connection_id=?
                AND status='certificate_saved'""",
                (paired["connection_id"],),
            ).fetchone()
        finally:
            client_db.close()
        self.assertIsNotNone(stale)
        stale_request_id = stale["request_id"]
        host_db = self.store._connect()
        try:
            host_db.execute(
                "UPDATE renewal_requests SET expires_at=? WHERE request_id=?",
                (now - 1, stale_request_id),
            )
        finally:
            host_db.close()
        client_db = self.client._connect()
        try:
            client_db.execute(
                "UPDATE client_renewals SET created_at=? WHERE request_id=?",
                (
                    now - RENEWAL_REQUEST_TTL_SECONDS - 1,
                    stale_request_id,
                ),
            )
        finally:
            client_db.close()

        renewed = self.client.renew_if_due(paired["connection_id"])
        self.assertTrue(renewed["renewed"])
        self.assertNotEqual(
            renewed["connection"]["certificate_fingerprint"],
            paired["certificate_fingerprint"],
        )
        client_db = self.client._connect()
        try:
            self.assertIsNone(
                client_db.execute(
                    "SELECT 1 FROM client_renewals WHERE request_id=?",
                    (stale_request_id,),
                ).fetchone()
            )
        finally:
            client_db.close()
        retired_names = {
            path.name
            for path in (self.client.data_dir / "retired").rglob("*")
            if path.is_file()
        }
        self.assertTrue(any(stale_request_id in name for name in retired_names))

    def test_missing_saved_renewal_is_retired_and_retried_once(self) -> None:
        paired = self.pair_and_approve()
        now = int(time.time())
        host_db = self.store._connect()
        try:
            host_db.execute(
                "UPDATE peer_certificates SET expires_at=? WHERE fingerprint=?",
                (now + 60, paired["certificate_fingerprint"]),
            )
        finally:
            host_db.close()
        client_db = self.client._connect()
        try:
            client_db.execute(
                "UPDATE client_connections SET certificate_expires_at=? WHERE connection_id=?",
                (now + 60, paired["connection_id"]),
            )
        finally:
            client_db.close()

        original_request = self.client._request
        activation_attempts = 0

        def lose_first_activation(*args, **kwargs):
            nonlocal activation_attempts
            path = args[3]
            if "/v1/renewals/" in path and path.endswith("/activate"):
                activation_attempts += 1
                if activation_attempts == 1:
                    raise RuntimeError("simulated pre-activation interruption")
            return original_request(*args, **kwargs)

        with mock.patch.object(
            self.client, "_request", side_effect=lose_first_activation
        ):
            with self.assertRaisesRegex(RuntimeError, "pre-activation interruption"):
                self.client.renew_if_due(paired["connection_id"])
        client_db = self.client._connect()
        try:
            stale = client_db.execute(
                "SELECT * FROM client_renewals WHERE connection_id=? "
                "AND status='certificate_saved'",
                (paired["connection_id"],),
            ).fetchone()
        finally:
            client_db.close()
        self.assertIsNotNone(stale)
        stale_request_id = stale["request_id"]
        host_db = self.store._connect()
        try:
            host_db.execute(
                "DELETE FROM renewal_requests WHERE request_id=?",
                (stale_request_id,),
            )
        finally:
            host_db.close()

        renewed = self.client.renew_if_due(paired["connection_id"])
        self.assertTrue(renewed["renewed"])
        self.assertNotEqual(
            renewed["connection"]["certificate_fingerprint"],
            paired["certificate_fingerprint"],
        )
        client_db = self.client._connect()
        try:
            self.assertIsNone(
                client_db.execute(
                    "SELECT 1 FROM client_renewals WHERE request_id=?",
                    (stale_request_id,),
                ).fetchone()
            )
        finally:
            client_db.close()
        retired_names = {
            path.name
            for path in (self.client.data_dir / "retired").rglob("*")
            if path.is_file()
        }
        self.assertTrue(any(stale_request_id in name for name in retired_names))

    def test_fresh_host_expired_renewal_does_not_rotate_key_per_retry(self) -> None:
        paired = self.pair_and_approve()
        client_db = self.client._connect()
        try:
            client_db.execute(
                "UPDATE client_connections SET certificate_expires_at=? "
                "WHERE connection_id=?",
                (int(time.time()) + 60, paired["connection_id"]),
            )
        finally:
            client_db.close()

        expired = SecurePeerError(
            "renewal_expired", "host rejected fresh renewal", 410
        )
        with mock.patch.object(
            self.client, "_mutual_json", side_effect=expired
        ) as request:
            for _attempt in range(2):
                with self.assertRaises(SecurePeerError) as raised:
                    self.client.renew_if_due(paired["connection_id"])
                self.assertEqual(raised.exception.code, "renewal_expired")

        client_db = self.client._connect()
        try:
            renewals = client_db.execute(
                "SELECT request_id,key_path,created_at FROM client_renewals "
                "WHERE connection_id=?",
                (paired["connection_id"],),
            ).fetchall()
        finally:
            client_db.close()
        self.assertEqual(request.call_count, 2)
        self.assertEqual(len(renewals), 1)
        self.assertTrue(Path(renewals[0]["key_path"]).is_file())
        retired_renewals = self.client.data_dir / "retired" / "renewals"
        self.assertEqual(
            [path for path in retired_renewals.rglob("*") if path.is_file()]
            if retired_renewals.exists()
            else [],
            [],
        )

    def test_renewal_creation_db_failures_retire_unpersisted_keys(self) -> None:
        paired = self.pair_and_approve()
        connection_id = paired["connection_id"]
        client_db = self.client._connect()
        try:
            client_db.execute(
                """UPDATE client_connections SET certificate_expires_at=?
                WHERE connection_id=?""",
                (int(time.time()) + 60, connection_id),
            )
        finally:
            client_db.close()
        original_live_files = {
            path.name: path.read_bytes() for path in self.client.keys_dir.iterdir()
        }
        real_connect = self.client._connect

        for failure_point in ("insert", "commit"):
            with self.subTest(failure_point=failure_point):
                injected = False

                class ConnectionProxy:
                    def __init__(self, wrapped):
                        self.wrapped = wrapped

                    @property
                    def in_transaction(self):
                        return self.wrapped.in_transaction

                    def execute(self, statement, *args):
                        nonlocal injected
                        normalized = " ".join(statement.split()).upper()
                        should_fail = (
                            failure_point == "insert"
                            and normalized.startswith("INSERT INTO CLIENT_RENEWALS")
                            or failure_point == "commit"
                            and normalized == "COMMIT"
                        )
                        if should_fail and not injected:
                            injected = True
                            raise sqlite3.OperationalError(
                                f"injected renewal {failure_point} failure"
                            )
                        return self.wrapped.execute(statement, *args)

                    def __getattr__(self, name):
                        return getattr(self.wrapped, name)

                with (
                    mock.patch.object(
                        self.client,
                        "_connect",
                        side_effect=lambda: ConnectionProxy(real_connect()),
                    ),
                    self.assertRaisesRegex(
                        sqlite3.OperationalError,
                        f"renewal {failure_point} failure",
                    ),
                ):
                    self.client.renew_if_due(connection_id)
                self.assertTrue(injected)
                client_db = real_connect()
                try:
                    count = client_db.execute(
                        """SELECT COUNT(*) AS count FROM client_renewals
                        WHERE connection_id=?""",
                        (connection_id,),
                    ).fetchone()["count"]
                finally:
                    client_db.close()
                self.assertEqual(int(count), 0)
                self.assertEqual(
                    {
                        path.name: path.read_bytes()
                        for path in self.client.keys_dir.iterdir()
                    },
                    original_live_files,
                )

    def test_repeated_real_renewals_bound_live_material_and_history(self) -> None:
        paired = self.pair_and_approve()
        connection_id = paired["connection_id"]
        current = paired
        latest_request_id = ""
        for _rotation in range(ACTIVATED_RENEWAL_HISTORY_LIMIT + 2):
            timestamp = int(time.time())
            with self.gateway._rate_guard:
                self.gateway._pairing_rate.clear()
            host_db = self.store._connect()
            try:
                host_db.execute(
                    """UPDATE peer_certificates SET expires_at=?
                    WHERE fingerprint=?""",
                    (timestamp + 60, current["certificate_fingerprint"]),
                )
            finally:
                host_db.close()
            client_db = self.client._connect()
            try:
                client_db.execute(
                    """UPDATE client_connections SET certificate_expires_at=?
                    WHERE connection_id=?""",
                    (timestamp + 60, connection_id),
                )
            finally:
                client_db.close()
            renewed = self.client.renew_if_due(connection_id)
            self.assertTrue(renewed["renewed"])
            current = renewed["connection"]

            stored = self.client._connection_row(connection_id)
            expected_live = {
                Path(stored["key_path"]),
                Path(stored["certificate_path"]),
                self.client.keys_dir / f"{connection_id}.ca.pem",
            }
            self.assertEqual(set(self.client.keys_dir.iterdir()), expected_live)
            latest_request_id = Path(stored["key_path"]).name[
                len(connection_id) + 1 : -len(".key.pem")
            ]

        client_db = self.client._connect()
        try:
            client_history = client_db.execute(
                """SELECT request_id FROM client_renewals
                WHERE connection_id=? AND status='activated'
                ORDER BY updated_at DESC,request_id DESC""",
                (connection_id,),
            ).fetchall()
        finally:
            client_db.close()
        host_db = self.store._connect()
        try:
            host_history = host_db.execute(
                """SELECT request_id FROM renewal_requests
                WHERE peer_id=? AND status='activated'
                ORDER BY activated_at DESC,request_id DESC""",
                (paired["peer_id"],),
            ).fetchall()
        finally:
            host_db.close()
        self.assertEqual(
            len(client_history), ACTIVATED_RENEWAL_HISTORY_LIMIT
        )
        self.assertEqual(len(host_history), ACTIVATED_RENEWAL_HISTORY_LIMIT)
        self.assertIn(
            latest_request_id,
            {row["request_id"] for row in client_history},
        )
        self.assertIn(
            latest_request_id,
            {row["request_id"] for row in host_history},
        )
        stored = self.client._connection_row(connection_id)
        status, headers, raw, _leaf = self.client._request(
            stored["host_ip"],
            int(stored["port"]),
            "POST",
            f"/v1/renewals/{latest_request_id}/activate",
            body={"request_id": latest_request_id},
            context=self.client._pinned_context(stored, mutual_tls=True),
        )
        replay = self.client._decode_json_response(status, headers, raw)
        self.assertTrue(replay["activated"])
        self.assertEqual(replay["request_id"], latest_request_id)
        retired = (
            self.client.data_dir / "retired" / "renewals" / connection_id
        )
        self.assertLessEqual(
            len([path for path in retired.iterdir() if path.is_file()]),
            RETIRED_RENEWAL_MATERIAL_LIMIT,
        )

    def test_retired_renewal_material_is_pruned_to_bound(self) -> None:
        connection_id = _uuid()
        for _attempt in range(RETIRED_RENEWAL_MATERIAL_LIMIT + 3):
            request_id = _uuid()
            for suffix in ("key.pem", "certificate.pem"):
                material = (
                    self.client.keys_dir
                    / f"{connection_id}-{request_id}.{suffix}"
                )
                material.write_bytes(b"retired material")
                material.chmod(0o600)
            self.client._retire_client_key_material(
                connection_id, renewal_request_id=request_id
            )

        retired = (
            self.client.data_dir / "retired" / "renewals" / connection_id
        )
        self.assertLessEqual(
            len([path for path in retired.iterdir() if path.is_file()]),
            RETIRED_RENEWAL_MATERIAL_LIMIT,
        )

    def test_live_pair_mtls_health_activation_and_pin(self) -> None:
        with self.assertRaises(SecurePeerError) as bad_pin:
            self.client.begin_pairing(
                self.host_ip,
                self.port,
                expected_ca_fingerprint="sha256:" + "0" * 64,
                requested_scopes=["teamspace.read"],
            )
        self.assertEqual(bad_pin.exception.code, "host_identity_mismatch")
        paired = self.pair_and_approve()
        health = self.client.peer_health(paired["connection_id"])
        self.assertEqual(health["certificate_fingerprint"], paired["certificate_fingerprint"])
        validated = self.client.get_connection(paired["connection_id"])
        self.assertIsNotNone(validated["last_validated_at"])
        active = self.client.set_active_connection(
            paired["connection_id"], expected_current=None
        )
        self.assertEqual(active["status"], "connected")
        self.assertTrue(active["active"])
        self.assertFalse(active["remote_route_delivery_available"])
        self.gateway.relay_enabled = True
        self.client.peer_health(paired["connection_id"])
        self.assertTrue(
            self.client.get_connection(paired["connection_id"])[
                "remote_route_delivery_available"
            ]
        )
        deactivated = self.client.deactivate_connection(
            paired["connection_id"],
            expected_host_server_identity=paired["host_server_identity"],
            expected_hub_id=paired["hub_id"],
        )
        self.assertEqual(deactivated["status"], "deactivated")
        self.assertFalse(deactivated["active"])

    def test_lowercase_forwarded_accept_header_is_not_duplicated(self) -> None:
        status, _headers, _raw, _leaf = self.client._request(
            self.host_ip,
            self.port,
            "GET",
            "/v1/health",
            headers={"accept": "application/json"},
            context=SecurePeerClient._unverified_context(),
            no_sni=True,
        )
        self.assertEqual(status, 200)

    def test_route_and_relay_network_endpoints_are_hard_gated_by_default(self) -> None:
        context = SecurePeerClient._unverified_context()
        for method, path, body in (
            ("GET", "/v1/routes", None),
            ("POST", "/v1/routes", {"malformed": True}),
            ("POST", "/v1/relay/envelopes", {"malformed": True}),
            ("POST", "/v1/relay/inbox/claim", {"malformed": True}),
            ("POST", f"/v1/relay/envelopes/{_uuid()}/receipt", {"malformed": True}),
        ):
            with self.subTest(method=method, path=path):
                status, headers, raw, _leaf = self.client._request(
                    self.host_ip,
                    self.port,
                    method,
                    path,
                    body=body,
                    context=context,
                    no_sni=True,
                )
                self.assertEqual(status, 404)
                value = self.client._decode_json_response
                with self.assertRaises(SecurePeerError) as unavailable:
                    value(status, headers, raw)
                self.assertEqual(unavailable.exception.code, "not_found")

    def test_pairing_post_commit_crash_retries_exact_persisted_request(self) -> None:
        request_id = _uuid()
        original_decode = self.client._decode_json_response
        calls = 0

        def fail_after_pair(status, headers, body):
            nonlocal calls
            value = original_decode(status, headers, body)
            calls += 1
            if calls == 2:
                raise RuntimeError("simulated crash after host pairing commit")
            return value

        with mock.patch.object(self.client, "_decode_json_response", side_effect=fail_after_pair):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                self.client.begin_pairing(
                    self.host_ip,
                    self.port,
                    request_id=request_id,
                    requested_scopes=["teamspace.read"],
                )
        self.assertEqual(len(self.store.list_pairings()), 1)
        recovering_client = SecurePeerClient(
            self.client.data_dir,
            self.client.server_identity,
            self.client.display_name,
            timeout_seconds=5,
        )
        recovery = recovering_client.recover_pairing_attempts()
        self.assertEqual(len(recovery["recovered"]), 1)
        recovered = recovering_client.get_connection(recovery["recovered"][0])
        self.assertEqual(len(self.store.list_pairings()), 1)
        self.assertEqual(recovered["status"], "pending")
        with self.assertRaises(SecurePeerError) as changed:
            recovering_client.begin_pairing(
                self.host_ip,
                self.port,
                request_id=request_id,
                requested_scopes=["teamspace.read", "teamspace.write"],
                display_name="Changed display",
            )
        self.assertEqual(changed.exception.code, "idempotency_conflict")

    def test_malformed_poll_capability_is_rejected_without_local_state_leak(self) -> None:
        original_decode = self.client._decode_json_response
        calls = 0

        def poison_poll_token(status, headers, body):
            nonlocal calls
            value = original_decode(status, headers, body)
            calls += 1
            if calls == 2:
                value["poll_token"] = "pairpoll.bad\r\nInjected: value"
            return value

        with mock.patch.object(
            self.client,
            "_decode_json_response",
            side_effect=poison_poll_token,
        ):
            with self.assertRaises(SecurePeerError) as rejected:
                self.client.begin_pairing(
                    self.host_ip,
                    self.port,
                    requested_scopes=["teamspace.read"],
                )
        self.assertEqual(rejected.exception.code, "transcript_mismatch")
        self.assertEqual(self.client.actionable_pairing_count(), 0)
        self.assertEqual(list(self.client.keys_dir.iterdir()), [])

    def test_two_phase_renewal_recovers_after_remote_activation_commit(self) -> None:
        paired = self.pair_and_approve()
        now = int(time.time())
        host_db = self.store._connect()
        try:
            host_db.execute(
                "UPDATE peer_certificates SET expires_at=? WHERE fingerprint=?",
                (now + 60, paired["certificate_fingerprint"]),
            )
        finally:
            host_db.close()
        client_db = self.client._connect()
        try:
            client_db.execute(
                "UPDATE client_connections SET certificate_expires_at=? WHERE connection_id=?",
                (now + 60, paired["connection_id"]),
            )
        finally:
            client_db.close()

        original_decode = self.client._decode_json_response
        calls = 0

        def fail_after_activation(status, headers, body):
            nonlocal calls
            value = original_decode(status, headers, body)
            calls += 1
            if calls == 2:
                raise RuntimeError("simulated crash after activation commit")
            return value

        with mock.patch.object(self.client, "_decode_json_response", side_effect=fail_after_activation):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                self.client.renew_if_due(paired["connection_id"])
        recovered = self.client.renew_if_due(paired["connection_id"])
        self.assertTrue(recovered["renewed"])
        self.assertNotEqual(
            recovered["connection"]["certificate_fingerprint"],
            paired["certificate_fingerprint"],
        )
        self.client.peer_health(paired["connection_id"])

    def test_superseded_certificate_can_revoke_forget_and_cleanly_repair(self) -> None:
        paired = self.pair_and_approve()
        connection_id = paired["connection_id"]
        self.gateway.relay_enabled = True
        self.gateway.peer_revoker = self.store.revoke_peer_for_self
        self.client.peer_health(connection_id)
        self.client.set_active_connection(connection_id, expected_current=None)
        route = self.client.publish_route(
            connection_id,
            "chat-to-forget",
            "forgetme",
            "Forget me",
            ["instruction"],
        )

        # Simulate the exact response-loss boundary: the host activated the new
        # certificate, while the client still has the old certificate selected.
        now = int(time.time())
        host_db = self.store._connect()
        try:
            host_db.execute(
                "UPDATE peer_certificates SET expires_at=? WHERE fingerprint=?",
                (now + 60, paired["certificate_fingerprint"]),
            )
        finally:
            host_db.close()
        client_db = self.client._connect()
        try:
            client_db.execute(
                "UPDATE client_connections SET certificate_expires_at=? WHERE connection_id=?",
                (now + 60, connection_id),
            )
        finally:
            client_db.close()

        original_decode = self.client._decode_json_response
        calls = 0

        def lose_activation_response(status, headers, body):
            nonlocal calls
            value = original_decode(status, headers, body)
            calls += 1
            if calls == 2:
                raise RuntimeError("activation response lost")
            return value

        with mock.patch.object(
            self.client,
            "_decode_json_response",
            side_effect=lose_activation_response,
        ):
            with self.assertRaisesRegex(RuntimeError, "activation response lost"):
                self.client.renew_if_due(connection_id)

        self.assertEqual(
            self.client.remote_revocation_status(connection_id)["status"],
            "active",
        )
        operation_id = _uuid()
        first = self.client.revoke_remote_connection(
            connection_id,
            idempotency_key=operation_id,
        )
        repeated = self.client.revoke_remote_connection(
            connection_id,
            idempotency_key=operation_id,
        )
        self.assertEqual(first, repeated)
        self.assertTrue(first["acknowledged"])
        self.assertEqual(
            first["presented_certificate_fingerprint"],
            paired["certificate_fingerprint"],
        )
        self.assertEqual(
            self.client.remote_revocation_status(connection_id)["status"],
            "revoked",
        )
        host_routes = self.store.list_remote_routes_for_peer(paired["peer_id"])
        self.assertEqual(len(host_routes), 1)
        self.assertEqual(host_routes[0]["route_id"], route["route_id"])
        self.assertEqual(host_routes[0]["status"], "revoked")

        self.client.retire_remote_revoked_connection(
            connection_id,
            expected_host_server_identity=paired["host_server_identity"],
            expected_hub_id=paired["hub_id"],
            expected_certificate_fingerprint=paired["certificate_fingerprint"],
        )
        forgotten = self.client.forget_connection(
            connection_id,
            expected_host_server_identity=paired["host_server_identity"],
            expected_hub_id=paired["hub_id"],
            expected_certificate_fingerprint=paired["certificate_fingerprint"],
        )
        self.assertEqual(forgotten["status"], "forgotten")
        self.assertEqual(self.client.list_connections(), [])

    def test_generic_revoked_error_is_not_a_self_revoke_acknowledgment(self) -> None:
        paired = self.pair_and_approve()
        failure = SecurePeerError(
            "peer_revoked",
            "Peer authentication is unavailable",
            401,
        )
        with mock.patch.object(
            self.client,
            "_mutual_json",
            side_effect=failure,
        ):
            with self.assertRaises(SecurePeerError) as raised:
                self.client.revoke_remote_connection(
                    paired["connection_id"],
                    idempotency_key=_uuid(),
                )
        self.assertIs(raised.exception, failure)
        self.assertEqual(
            self.client.get_connection(paired["connection_id"])["status"],
            "approved",
        )

    def test_live_route_relay_claim_resolves_only_local_chat_ledger(self) -> None:
        paired = self.pair_and_approve()
        self.gateway.relay_enabled = True
        self.client.peer_health(paired["connection_id"])
        self.client.set_active_connection(
            paired["connection_id"], expected_current=None
        )
        published = self.client.publish_route(
            paired["connection_id"],
            "chat-client-001",
            "clientchat",
            "Client chat",
            ["instruction"],
        )
        source = self.store.publish_local_route(
            paired["team_id"],
            paired["peer_id"],
            "chat-host-001",
            "hostchat",
            "Host chat",
            ["instruction"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        queued = self.store.submit_local_envelope(
            paired["team_id"],
            source["route_id"],
            {
                "request_id": _uuid(),
                "source_route_id": source["route_id"],
                "target_route_id": published["route_id"],
                "target_route_revision": published["revision"],
                "kind": "instruction",
                "exchange_id": None,
                "parent_envelope_id": None,
                "expires_at": int(time.time()) + 300,
                "body": {"message": "network relay"},
            },
        )
        claimed = self.client.claim_inbox(
            paired["connection_id"], lease_owner="client-worker", limit=5
        )
        self.assertEqual(len(claimed["envelopes"]), 1)
        self.assertEqual(
            claimed["envelopes"][0]["target_chat_id"], "chat-client-001"
        )
        receipt = self.client.receipt_envelope(
            paired["connection_id"],
            queued["envelope_id"],
            lease_token=claimed["lease_token"],
            outcome="delivered",
        )
        self.assertEqual(receipt["status"], "delivered")

    def test_stale_local_route_does_not_poison_claimed_batch(self) -> None:
        paired = self.pair_and_approve()
        self.gateway.relay_enabled = True
        self.client.peer_health(paired["connection_id"])
        self.client.set_active_connection(
            paired["connection_id"], expected_current=None
        )
        stale_target = self.client.publish_route(
            paired["connection_id"],
            "chat-client-stale",
            "client-stale",
            "Client stale",
            ["instruction"],
        )
        valid_target = self.client.publish_route(
            paired["connection_id"],
            "chat-client-valid",
            "client-valid",
            "Client valid",
            ["instruction"],
        )
        source = self.store.publish_local_route(
            paired["team_id"],
            paired["peer_id"],
            "chat-host-batch",
            "host-batch",
            "Host batch",
            ["instruction"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        queued = []
        for target in (stale_target, valid_target):
            queued.append(
                self.store.submit_local_envelope(
                    paired["team_id"],
                    source["route_id"],
                    {
                        "request_id": _uuid(),
                        "source_route_id": source["route_id"],
                        "target_route_id": target["route_id"],
                        "target_route_revision": target["revision"],
                        "kind": "instruction",
                        "exchange_id": None,
                        "parent_envelope_id": None,
                        "expires_at": int(time.time()) + 300,
                        "body": {"message": target["display_title"]},
                    },
                )
            )
        client_db = self.client._connect()
        try:
            client_db.execute(
                "UPDATE client_routes SET status='publishing' WHERE route_id=?",
                (stale_target["route_id"],),
            )
        finally:
            client_db.close()

        claimed = self.client.claim_inbox(
            paired["connection_id"], lease_owner="batch-worker", limit=5
        )
        self.assertEqual(
            [item["envelope_id"] for item in claimed["envelopes"]],
            [queued[1]["envelope_id"]],
        )
        self.assertEqual(
            claimed["envelopes"][0]["target_chat_id"], "chat-client-valid"
        )
        host_db = self.store._connect()
        try:
            stale_status = host_db.execute(
                "SELECT status FROM relay_envelopes WHERE id=?",
                (queued[0]["envelope_id"],),
            ).fetchone()["status"]
        finally:
            host_db.close()
        self.assertEqual(stale_status, "failed")

    def test_route_retirement_is_local_first_retryable_and_republish_rotates_id(self) -> None:
        paired = self.pair_and_approve()
        self.gateway.relay_enabled = True
        route = self.client.publish_route(
            paired["connection_id"],
            "chat-retire-001",
            "retire",
            "Retire chat",
            ["instruction"],
        )
        original = self.client._mutual_json

        def offline_revoke(connection_id, method, path, body=None, **kwargs):
            if path.endswith("/revoke"):
                raise SecurePeerError(
                    "transport_failed", "peer is offline", 503
                )
            return original(connection_id, method, path, body, **kwargs)

        with mock.patch.object(
            self.client, "_mutual_json", side_effect=offline_revoke
        ):
            with self.assertRaises(SecurePeerError):
                self.client.revoke_published_route(
                    paired["connection_id"],
                    route["route_id"],
                    route["revision"],
                    _uuid(),
                )
        local = next(
            item
            for item in self.client.list_published_routes()
            if item["chat_id"] == "chat-retire-001"
        )
        self.assertEqual(local["status"], "revoked")
        with self.assertRaises(SecurePeerError) as forget_pending:
            self.client.forget_connection(
                paired["connection_id"],
                expected_host_server_identity=paired["host_server_identity"],
                expected_hub_id=paired["hub_id"],
                expected_certificate_fingerprint=paired[
                    "certificate_fingerprint"
                ],
            )
        self.assertEqual(
            forget_pending.exception.code,
            "connection_retirement_pending",
        )
        with self.assertRaises(SecurePeerError) as pending:
            self.client.publish_route(
                paired["connection_id"],
                "chat-retire-001",
                "retire",
                "Retire chat",
                ["instruction"],
            )
        self.assertEqual(pending.exception.code, "route_retirement_pending")
        self.assertEqual(
            self.client.flush_pending_route_revocations_for_connection(
                paired["connection_id"]
            ),
            1,
        )
        replacement = self.client.publish_route(
            paired["connection_id"],
            "chat-retire-001",
            "retire",
            "Retire chat",
            ["instruction"],
        )
        self.assertNotEqual(replacement["route_id"], route["route_id"])

    def test_route_publish_recovers_exactly_after_remote_commit_ack_loss(self) -> None:
        paired = self.pair_and_approve()
        self.gateway.relay_enabled = True
        self.client.peer_health(paired["connection_id"])
        self.client.set_active_connection(
            paired["connection_id"], expected_current=None
        )
        original = self.client._mutual_json
        committed: dict[str, str] = {}

        def lose_first_ack(connection_id, method, path, body=None, **kwargs):
            response = original(connection_id, method, path, body, **kwargs)
            if method == "POST" and path == "/v1/routes" and not committed:
                committed.update(
                    route_id=str(response["route_id"]),
                    revision=str(response["revision"]),
                )
                raise SecurePeerError(
                    "transport_failed", "route acknowledgement was lost", 502
                )
            return response

        with mock.patch.object(
            self.client, "_mutual_json", side_effect=lose_first_ack
        ):
            with self.assertRaises(SecurePeerError) as ambiguous:
                self.client.publish_route(
                    paired["connection_id"],
                    "chat-publish-retry-001",
                    "publish-retry",
                    "Publish retry",
                    ["instruction"],
                )
        self.assertEqual(ambiguous.exception.code, "transport_failed")
        pending = next(
            item
            for item in self.client.list_published_routes()
            if item["chat_id"] == "chat-publish-retry-001"
        )
        self.assertEqual(pending["status"], "publishing")
        self.assertEqual(pending["route_id"], committed["route_id"])
        self.assertEqual(pending["revision"], committed["revision"])

        recovered = self.client.publish_route(
            paired["connection_id"],
            "chat-publish-retry-001",
            "publish-retry",
            "Publish retry",
            ["instruction"],
        )
        self.assertEqual(recovered["status"], "active")
        self.assertEqual(recovered["route_id"], committed["route_id"])
        self.assertEqual(recovered["revision"], committed["revision"])

    def test_route_revoke_linearizes_after_inflight_submission(self) -> None:
        paired = self.pair_and_approve()
        self.gateway.relay_enabled = True
        self.client.peer_health(paired["connection_id"])
        self.client.set_active_connection(
            paired["connection_id"], expected_current=None
        )
        route = self.client.publish_route(
            paired["connection_id"],
            "chat-linear-001",
            "linear",
            "Linear chat",
            ["instruction"],
        )
        entered = threading.Event()
        release = threading.Event()
        sent: list[dict] = []
        revoked: list[dict] = []
        expires_at = int(time.time()) + 300

        def blocked_submit(_connection_id, _payload):
            entered.set()
            self.assertTrue(release.wait(5))
            return {
                "envelope_id": _uuid(),
                "exchange_id": _uuid(),
                "status": "queued",
                "used_legs": 1,
                "max_legs": 6,
                "expires_at": expires_at,
            }

        payload = {
            "request_id": _uuid(),
            "source_route_id": route["route_id"],
            "target_route_id": _uuid(),
            "target_route_revision": "rev_" + "a" * 32,
            "kind": "instruction",
            "exchange_id": None,
            "parent_envelope_id": None,
            "expires_at": expires_at,
            "body": {"message": "linearized"},
        }
        with mock.patch.object(
            self.client, "submit_envelope", side_effect=blocked_submit
        ):
            sender = threading.Thread(
                target=lambda: sent.append(
                    self.client.submit_envelope_from_published_route(
                        paired["connection_id"],
                        source_route_id=route["route_id"],
                        source_route_revision=route["revision"],
                        source_chat_id="chat-linear-001",
                        action="instruction",
                        payload=payload,
                    )
                )
            )
            sender.start()
            self.assertTrue(entered.wait(5))
            reverter = threading.Thread(
                target=lambda: revoked.append(
                    self.client.revoke_published_route(
                        paired["connection_id"],
                        route["route_id"],
                        route["revision"],
                        _uuid(),
                    )
                )
            )
            reverter.start()
            time.sleep(0.05)
            self.assertFalse(revoked)
            release.set()
            sender.join(5)
            reverter.join(5)
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(revoked), 1)
        with self.assertRaises(SecurePeerError) as denied:
            self.client.submit_envelope_from_published_route(
                paired["connection_id"],
                source_route_id=route["route_id"],
                source_route_revision=route["revision"],
                source_chat_id="chat-linear-001",
                action="instruction",
                payload=payload,
            )
        self.assertEqual(denied.exception.code, "route_changed")

    def test_connection_deactivate_linearizes_after_inflight_submission(self) -> None:
        paired = self.pair_and_approve()
        self.gateway.relay_enabled = True
        self.client.peer_health(paired["connection_id"])
        self.client.set_active_connection(
            paired["connection_id"], expected_current=None
        )
        route = self.client.publish_route(
            paired["connection_id"],
            "chat-deactivate-001",
            "deactivate",
            "Deactivate chat",
            ["instruction"],
        )
        entered = threading.Event()
        release = threading.Event()
        sent: list[dict] = []
        deactivated: list[dict] = []
        expires_at = int(time.time()) + 300

        def blocked_submit(_connection_id, _payload):
            entered.set()
            self.assertTrue(release.wait(5))
            return {
                "envelope_id": _uuid(),
                "exchange_id": _uuid(),
                "status": "queued",
                "used_legs": 1,
                "max_legs": 6,
                "expires_at": expires_at,
            }

        payload = {
            "request_id": _uuid(),
            "source_route_id": route["route_id"],
            "target_route_id": _uuid(),
            "target_route_revision": "rev_" + "a" * 32,
            "kind": "instruction",
            "exchange_id": None,
            "parent_envelope_id": None,
            "expires_at": expires_at,
            "body": {"message": "linearized"},
        }
        with mock.patch.object(
            self.client, "submit_envelope", side_effect=blocked_submit
        ):
            sender = threading.Thread(
                target=lambda: sent.append(
                    self.client.submit_envelope_from_published_route(
                        paired["connection_id"],
                        source_route_id=route["route_id"],
                        source_route_revision=route["revision"],
                        source_chat_id="chat-deactivate-001",
                        action="instruction",
                        payload=payload,
                    )
                )
            )
            sender.start()
            self.assertTrue(entered.wait(5))
            stopper = threading.Thread(
                target=lambda: deactivated.append(
                    self.client.deactivate_connection(
                        paired["connection_id"],
                        expected_host_server_identity=paired[
                            "host_server_identity"
                        ],
                        expected_hub_id=paired["hub_id"],
                    )
                )
            )
            stopper.start()
            time.sleep(0.05)
            self.assertFalse(deactivated)
            release.set()
            sender.join(5)
            stopper.join(5)
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(deactivated), 1)
        with self.assertRaises(SecurePeerError) as denied:
            self.client.submit_envelope_from_published_route(
                paired["connection_id"],
                source_route_id=route["route_id"],
                source_route_revision=route["revision"],
                source_chat_id="chat-deactivate-001",
                action="instruction",
                payload=payload,
            )
        self.assertEqual(denied.exception.code, "route_changed")

    def test_prepared_receipt_cannot_cross_local_route_tombstone(self) -> None:
        paired = self.pair_and_approve()
        self.gateway.relay_enabled = True
        self.client.peer_health(paired["connection_id"])
        self.client.set_active_connection(
            paired["connection_id"], expected_current=None
        )
        target = self.client.publish_route(
            paired["connection_id"],
            "chat-receipt-race",
            "receipt-race",
            "Receipt race",
            ["instruction"],
        )
        source = self.store.publish_local_route(
            paired["team_id"],
            paired["peer_id"],
            "chat-host-receipt-race",
            "host-receipt-race",
            "Host receipt race",
            ["instruction"],
            idempotency_key=_uuid(),
            published_by="owner-admin",
        )
        queued = self.store.submit_local_envelope(
            paired["team_id"],
            source["route_id"],
            {
                "request_id": _uuid(),
                "source_route_id": source["route_id"],
                "target_route_id": target["route_id"],
                "target_route_revision": target["revision"],
                "kind": "instruction",
                "exchange_id": None,
                "parent_envelope_id": None,
                "expires_at": int(time.time()) + 300,
                "body": {"message": "do not accept after revoke"},
            },
        )
        claim = self.client.claim_inbox(
            paired["connection_id"], lease_owner="receipt-race-worker"
        )
        self.assertEqual(len(claim["envelopes"]), 1)
        original = self.client._mutual_json

        def offline_revoke(connection_id, method, path, body=None, **kwargs):
            if path.endswith("/revoke"):
                raise SecurePeerError(
                    "transport_failed", "peer is offline", 503
                )
            return original(connection_id, method, path, body, **kwargs)

        with mock.patch.object(
            self.client, "_mutual_json", side_effect=offline_revoke
        ):
            with self.assertRaises(SecurePeerError):
                self.client.revoke_published_route(
                    paired["connection_id"],
                    target["route_id"],
                    target["revision"],
                    _uuid(),
                )
        with self.assertRaises(SecurePeerError) as denied:
            self.client.receipt_envelope_for_published_route(
                paired["connection_id"],
                queued["envelope_id"],
                target_route_id=target["route_id"],
                target_route_revision=target["revision"],
                lease_token=claim["lease_token"],
                outcome="delivered",
            )
        self.assertEqual(denied.exception.code, "route_changed")

    def test_stalled_client_hello_does_not_block_health_and_is_closed(self) -> None:
        stalled = socket.create_connection((self.host_ip, self.port), timeout=2)
        stalled.settimeout(5)
        stalled.sendall(b"\x16")
        started = time.monotonic()
        context = SecurePeerClient._unverified_context()
        status, headers, body, _leaf = self.client._request(
            self.host_ip,
            self.port,
            "GET",
            "/v1/health",
            context=context,
            no_sni=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["protocol_version"], 1)
        self.assertLess(time.monotonic() - started, 2.5)
        try:
            closed = stalled.recv(1)
        except (ConnectionResetError, OSError):
            closed = b""
        finally:
            stalled.close()
        self.assertEqual(closed, b"")

    def test_rate_limits_cover_health_poll_and_pairing(self) -> None:
        for action, allowed in (("health", 60), ("poll", 120), ("pair", 8)):
            source = "10.1.2.3-" + action
            for _index in range(allowed):
                self.assertTrue(self.gateway._allow_request(source, action))
            self.assertFalse(self.gateway._allow_request(source, action))
        peer = PeerAuthorization(
            _uuid(),
            _uuid(),
            "rated-peer-001",
            "team-alpha",
            frozenset({"cross_chat.instruction"}),
            "sha256:" + "b" * 64,
            int(time.time()) + 600,
            "Rated peer",
            1,
        )
        for _index in range(120):
            self.assertTrue(self.gateway._allow_peer_request(peer, "relay_claim"))
        self.assertFalse(self.gateway._allow_peer_request(peer, "relay_claim"))

    def test_local_rate_rejections_do_not_poison_shared_buckets(self) -> None:
        attacker = "10.1.2.3"
        for _index in range(8):
            self.assertTrue(self.gateway._allow_request(attacker, "pair"))
        for _index in range(500):
            self.assertFalse(self.gateway._allow_request(attacker, "pair"))
        self.assertTrue(self.gateway._allow_request("10.1.2.4", "pair"))
        self.assertEqual(self.gateway._pairing_rate["pair:*"][1], 9)

        attacker_peer = PeerAuthorization(
            _uuid(),
            _uuid(),
            "rate-attacker-peer",
            "team-alpha",
            frozenset({"cross_chat.instruction"}),
            "sha256:" + "c" * 64,
            int(time.time()) + 600,
            "Rate attacker",
            1,
        )
        other_peer = PeerAuthorization(
            _uuid(),
            _uuid(),
            "rate-other-peer",
            "team-alpha",
            frozenset({"cross_chat.instruction"}),
            "sha256:" + "d" * 64,
            int(time.time()) + 600,
            "Rate other",
            1,
        )
        for _index in range(120):
            self.assertTrue(
                self.gateway._allow_peer_request(attacker_peer, "relay_submit")
            )
        for _index in range(500):
            self.assertFalse(
                self.gateway._allow_peer_request(attacker_peer, "relay_submit")
            )
        self.assertTrue(
            self.gateway._allow_peer_request(other_peer, "relay_submit")
        )
        self.assertEqual(self.gateway._pairing_rate["peer:*:relay_submit"][1], 121)


if __name__ == "__main__":
    unittest.main()
