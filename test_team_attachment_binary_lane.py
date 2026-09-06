"""Compact end-to-end checks for Team Messages V2's secure binary lane."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agentsdock_team_hub.secure_peer import (
    PeerAuthorization,
    SecurePeerError,
    canonical_peer_ipv4,
    sanitize_attachment_proxy_request,
    sanitize_proxy_request,
)
from test_team_network_e2e import TeamNetworkHarness


def _host_ip() -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        return canonical_peer_ipv4(probe.getsockname()[0])
    except (OSError, ValueError):
        return None
    finally:
        probe.close()


class TeamAttachmentBinaryLaneTests(unittest.TestCase):
    def setUp(self) -> None:
        host_ip = _host_ip()
        if host_ip is None:
            self.skipTest("no non-loopback IPv4 address is available")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.network = TeamNetworkHarness(self, self.root, host_ip)
        self.network.pair_approve_and_activate()

    def declare(self, payload: bytes, name: str) -> dict:
        return self.network.peer_proxy_json(
            "POST",
            f"/v1/teams/{self.network.team_id}/network/attachments",
            body={
                "file_name": name,
                "media_type": "application/octet-stream",
                "byte_size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "idempotency_key": "binary_" + uuid.uuid4().hex,
            },
        )["attachment"]

    def upload(self, attachment_id: str, payload: bytes) -> None:
        midpoint = max(1, len(payload) // 2)
        first = payload[:midpoint]
        first_range = f"bytes 0-{len(first) - 1}/{len(payload)}"
        response = self.network.member.proxy_team_attachment_chunk(
            self.network.connection_id,
            self.network.team_id,
            attachment_id,
            content_range=first_range,
            body=first,
        )
        self.assertEqual(response.status, 200)
        # An ambiguous network retry of an already committed chunk is safe.
        replay = self.network.member.proxy_team_attachment_chunk(
            self.network.connection_id,
            self.network.team_id,
            attachment_id,
            content_range=first_range,
            body=first,
        )
        self.assertEqual(replay.status, 200)
        if midpoint < len(payload):
            response = self.network.member.proxy_team_attachment_chunk(
                self.network.connection_id,
                self.network.team_id,
                attachment_id,
                content_range=f"bytes {midpoint}-{len(payload) - 1}/{len(payload)}",
                body=payload[midpoint:],
            )
            self.assertEqual(response.status, 200)

    def test_mtls_upload_head_range_and_verified_cache(self) -> None:
        payload = (b"0123456789abcdef" * 513) + b"tail"
        attachment = self.declare(payload, "sample.bin")
        self.upload(attachment["id"], payload)
        content_path = self.network.member._team_attachment_path(
            self.network.team_id, attachment["id"]
        )

        head = self.network.member.proxy_team_attachment_head(
            self.network.connection_id, self.network.team_id, attachment["id"]
        )
        self.assertEqual(head.status, 200)
        self.assertEqual(dict(head.headers)["content-length"], str(len(payload)))
        part = self.network.member.client.read_attachment_range(
            self.network.connection_id, content_path, "bytes=7-31"
        )
        self.assertEqual(part.status, 206)
        self.assertEqual(part.body, payload[7:32])
        self.assertEqual(
            dict(part.headers)["content-range"], f"bytes 7-31/{len(payload)}"
        )

        public, cached = self.network.member.cache_team_attachment(
            self.network.connection_id, self.network.team_id, attachment["id"]
        )
        self.assertEqual(public["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(cached.read_bytes(), payload)
        cached.write_bytes(b"x" * len(payload))
        _public, repaired = self.network.member.cache_team_attachment(
            self.network.connection_id, self.network.team_id, attachment["id"]
        )
        self.assertEqual(repaired.read_bytes(), payload)

    def test_host_receiver_opens_peer_uploaded_message_attachment(self) -> None:
        """Mirror Studio peer -> Sonic host attachment receipt end to end."""

        payload = b"peer-authored image bytes"
        attachment = self.declare(payload, "studio-image.png")
        self.upload(attachment["id"], payload)
        projection = self.network.hub.get_network(
            self.network.owner,
            self.network.team_id,
        )
        host_node = next(server for server in projection["servers"] if server["is_host"])
        message = self.network.peer_proxy_json(
            "POST",
            f"/v1/teams/{self.network.team_id}/network/messages",
            body={
                "kind": "message",
                "title": None,
                "body": "Studio attachment for Sonic",
                "body_format": "plain",
                "recipients": [{"kind": "server", "id": host_node["id"]}],
                "attachment_ids": [attachment["id"]],
                "in_reply_to_message_id": None,
                "skill": None,
                "provenance": {},
                "idempotency_key": "receiver_" + uuid.uuid4().hex,
            },
        )["message"]

        host_claims = self.network.hub.managed_server_claims()
        inbox = self.network.hub.list_team_messages(
            host_claims,
            self.network.team_id,
            box="inbox",
            after_sequence=0,
            limit=50,
        )
        self.assertIn(message["id"], {item["id"] for item in inbox["messages"]})
        public, lease = self.network.hub.open_team_attachment(
            host_claims,
            self.network.team_id,
            attachment["id"],
        )
        try:
            self.assertEqual(public["message_id"], message["id"])
            self.assertEqual(os.read(lease.descriptor, len(payload) + 1), payload)
        finally:
            lease.close()

    def test_cache_is_lru_bounded_and_requires_live_connection(self) -> None:
        first_payload, second_payload = b"a" * 5_001, b"b" * 5_003
        first = self.declare(first_payload, "first.bin")
        self.upload(first["id"], first_payload)
        _meta, first_path = self.network.member.cache_team_attachment(
            self.network.connection_id, self.network.team_id, first["id"]
        )
        _meta, first_lease = self.network.member.open_cached_team_attachment(
            self.network.connection_id, self.network.team_id, first["id"]
        )
        self.network.member.team_cache_max_bytes = len(second_payload) + 4_096 + 20
        second = self.declare(second_payload, "second.bin")
        self.upload(second["id"], second_payload)
        with self.assertRaises(SecurePeerError) as pinned:
            self.network.member.cache_team_attachment(
                self.network.connection_id, self.network.team_id, second["id"]
            )
        self.assertEqual(pinned.exception.code, "cache_unavailable")
        first_lease.close()
        _meta, second_path = self.network.member.cache_team_attachment(
            self.network.connection_id, self.network.team_id, second["id"]
        )
        self.assertFalse(first_path.exists())
        self.assertEqual(second_path.read_bytes(), second_payload)
        self.assertLessEqual(
            sum(
                item.stat().st_size
                for item in self.network.member.team_cache_dir.rglob("*")
                if item.is_file()
            ),
            self.network.member.team_cache_max_bytes,
        )

        self.network.host.configure_host(
            enabled=False,
            advertised_host=None,
            listen_port=self.network.port,
        )
        with self.assertRaises(SecurePeerError):
            self.network.member.cache_team_attachment(
                self.network.connection_id, self.network.team_id, second["id"]
            )
        self.network.host.configure_host(
            enabled=True,
            advertised_host=self.network.host_ip,
            listen_port=self.network.port,
        )
        self.network.member.client.peer_health(self.network.connection_id)
        _meta, reconnected = self.network.member.cache_team_attachment(
            self.network.connection_id, self.network.team_id, second["id"]
        )
        self.assertEqual(reconnected.read_bytes(), second_payload)

        self.network.revoke_from_host()
        with self.assertRaises(SecurePeerError):
            self.network.member.cache_team_attachment(
                self.network.connection_id, self.network.team_id, second["id"]
            )
        self.assertIsNone(self.network.member.status()["active_connection_id"])

    def test_binary_allowlist_rejects_wrong_team_and_missing_scope(self) -> None:
        peer = PeerAuthorization(
            peer_id=str(uuid.uuid4()),
            pairing_id=str(uuid.uuid4()),
            peer_server_identity="peer-server-test",
            team_id="team-alpha",
            scopes=frozenset({"teamspace.read"}),
            certificate_fingerprint="sha256:" + "1" * 64,
            certificate_expires_at=2_000_000_000,
            peer_display_name="Peer",
        )
        path = "/v1/teams/team-alpha/network/attachments/tatt_12345678/content"
        request = sanitize_attachment_proxy_request(
            peer, "GET", path, "", (("range", "bytes=0-9"),), b""
        )
        self.assertEqual((request.method, dict(request.headers)["range"]), ("GET", "bytes=0-9"))
        with self.assertRaises(SecurePeerError) as wrong_team:
            sanitize_attachment_proxy_request(
                peer,
                "GET",
                path.replace("team-alpha", "team-bravo"),
                "",
                (),
                b"",
            )
        self.assertEqual(wrong_team.exception.code, "route_forbidden")
        with self.assertRaises(SecurePeerError) as no_write:
            sanitize_attachment_proxy_request(
                peer,
                "PUT",
                path,
                "",
                (
                    ("content-type", "application/octet-stream"),
                    ("content-range", "bytes 0-0/1"),
                ),
                b"x",
            )
        self.assertEqual(no_write.exception.code, "forbidden")

        version = sanitize_proxy_request(
            peer,
            "GET",
            "/v1/teams/team-alpha/network/skills/skill_12345678/versions/1",
            "",
            (),
            b"",
        )
        self.assertEqual(version.method, "GET")

    def test_cache_handles_control_like_and_long_utf8_file_names(self) -> None:
        for index, name in enumerate((".download.notes", ("界" * 100) + ".md")):
            payload = f"payload-{index}".encode()
            attachment = self.declare(payload, name)
            self.upload(attachment["id"], payload)
            public, cached = self.network.member.cache_team_attachment(
                self.network.connection_id, self.network.team_id, attachment["id"]
            )
            self.assertEqual(public["file_name"], name)
            self.assertEqual(cached.read_bytes(), payload)

    def test_upload_retry_resumes_from_live_attachment_state(self) -> None:
        source = self.root.resolve() / "ambiguous-final.bin"
        source.write_bytes(b"committed-before-the-response-was-lost")
        realm = self.network.member.team_realm(self.network.team_id)
        original = self.network.member.proxy_team_attachment_chunk

        alias = self.root.resolve() / "attachment-alias.bin"
        alias.symlink_to(source)
        with self.assertRaises(SecurePeerError):
            self.network.member._team_upload_attachment(
                realm, alias, idempotency_key="symlink-must-not-upload"
            )

        def commit_then_disconnect(*args, **kwargs):
            original(*args, **kwargs)
            raise SecurePeerError("transport_failed", "connection closed", 502)

        with patch.object(
            self.network.member,
            "proxy_team_attachment_chunk",
            side_effect=commit_then_disconnect,
        ):
            with self.assertRaises(SecurePeerError):
                self.network.member._team_upload_attachment(
                    realm, source, idempotency_key="ambiguous-final-upload"
                )
        with patch.object(
            self.network.member,
            "proxy_team_attachment_chunk",
            wraps=original,
        ) as retried_chunk:
            attachment_id = self.network.member._team_upload_attachment(
                realm, source, idempotency_key="ambiguous-final-upload"
            )
        self.assertTrue(attachment_id)
        retried_chunk.assert_not_called()


if __name__ == "__main__":
    unittest.main()
