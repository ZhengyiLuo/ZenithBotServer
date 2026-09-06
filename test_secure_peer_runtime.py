from pathlib import Path
import hashlib
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

from agentsdock_team_hub.secure_peer import (
    AttachmentFileLease,
    PAIRING_STATUS_LIMIT,
    ProxyResponse,
    SecurePeerError,
    SecurePeerStore,
)
from agentsdock_team_hub.store import HubError, HubStore
from secure_peer_runtime import SecurePeerRuntime


class SecurePeerRuntimeTests(unittest.TestCase):
    def test_team_deletion_wrappers_cover_host_remote_and_read_only_realms(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="source_server",
                server_instance_id="source_instance",
                display_name="Source",
            )
            host_calls: list[tuple] = []

            class HostStore:
                hub_id = "hub_host_delete"

                @staticmethod
                def local_agent_mail_claims(team_id):
                    host_calls.append(("claims", team_id))
                    return "host-claims"

                @staticmethod
                def delete_team_message(claims, team_id, message_id, body):
                    host_calls.append(
                        ("message", claims, team_id, message_id, dict(body))
                    )
                    return {"deleted": True, "message_id": message_id}

                @staticmethod
                def delete_network_bulletin_post(claims, team_id, post_id, body):
                    host_calls.append(
                        ("bulletin", claims, team_id, post_id, dict(body))
                    )
                    return {"deleted": True, "post_id": post_id}

                @staticmethod
                def list_network_content_deletions(
                    claims,
                    team_id,
                    *,
                    after_sequence,
                    limit,
                ):
                    host_calls.append(
                        ("journal", claims, team_id, after_sequence, limit)
                    )
                    return {
                        "deletions": [
                            {
                                "sequence": 8,
                                "kind": "message",
                                "id": "tmsg_host_delete_001",
                                "deleted_at": "2026-09-05T12:00:00Z",
                            }
                        ],
                        "next_after_sequence": 8,
                        "has_more": False,
                    }

            host_realm = {
                "realm": "host",
                "team_id": "team_host_delete",
                "hub_id": HostStore.hub_id,
                "can_write": True,
            }
            runtime._hub_store = HostStore()
            try:
                with mock.patch.object(
                    runtime,
                    "team_realm",
                    return_value=host_realm,
                ):
                    self.assertEqual(
                        runtime.team_delete_message(
                            "tmsg_host_delete_001",
                            "host-message-delete-key",
                            team_id="team_host_delete",
                        ),
                        {
                            "deleted": True,
                            "message_id": "tmsg_host_delete_001",
                        },
                    )
                    self.assertEqual(
                        runtime.team_delete_bulletin_post(
                            "message_host_delete_001",
                            "host-bulletin-delete-key",
                            team_id="team_host_delete",
                        ),
                        {
                            "deleted": True,
                            "post_id": "message_host_delete_001",
                        },
                    )
                    host_journal = runtime.team_list_deletions(
                        team_id="team_host_delete",
                        after_sequence=7,
                        limit=2,
                    )
                self.assertEqual(host_journal["team_id"], "team_host_delete")
                self.assertEqual(
                    host_calls,
                    [
                        ("claims", "team_host_delete"),
                        (
                            "message",
                            "host-claims",
                            "team_host_delete",
                            "tmsg_host_delete_001",
                            {"idempotency_key": "host-message-delete-key"},
                        ),
                        ("claims", "team_host_delete"),
                        (
                            "bulletin",
                            "host-claims",
                            "team_host_delete",
                            "message_host_delete_001",
                            {"idempotency_key": "host-bulletin-delete-key"},
                        ),
                        ("claims", "team_host_delete"),
                        ("journal", "host-claims", "team_host_delete", 7, 2),
                    ],
                )

                remote_realm = {
                    "realm": "secure_peer",
                    "team_id": "team_remote_delete",
                    "hub_id": "hub_remote_delete",
                    "connection_id": "connection_remote_delete",
                    "can_write": True,
                }
                responses = (
                    ProxyResponse(
                        200,
                        (("content-type", "application/json"),),
                        b'{"deleted":true,"message_id":"tmsg_remote_delete_001"}',
                    ),
                    ProxyResponse(
                        200,
                        (("content-type", "application/json"),),
                        b'{"deleted":true,"post_id":"message_remote_delete_001"}',
                    ),
                    ProxyResponse(
                        200,
                        (("content-type", "application/json"),),
                        b'{"deletions":[],"next_after_sequence":9,"has_more":false}',
                    ),
                )
                with mock.patch.object(
                    runtime,
                    "team_realm",
                    return_value=remote_realm,
                ), mock.patch.object(
                    runtime,
                    "proxy",
                    side_effect=responses,
                ) as proxy:
                    self.assertEqual(
                        runtime.team_delete_message(
                            "tmsg_remote_delete_001",
                            "remote-message-delete-key",
                            team_id="team_remote_delete",
                        )["message_id"],
                        "tmsg_remote_delete_001",
                    )
                    self.assertEqual(
                        runtime.team_delete_bulletin_post(
                            "message_remote_delete_001",
                            "remote-bulletin-delete-key",
                            team_id="team_remote_delete",
                        )["post_id"],
                        "message_remote_delete_001",
                    )
                    remote_journal = runtime.team_list_deletions(
                        team_id="team_remote_delete",
                        after_sequence=9,
                        limit=3,
                    )
                self.assertEqual(remote_journal["team_id"], "team_remote_delete")
                self.assertEqual(
                    proxy.call_args_list,
                    [
                        mock.call(
                            "connection_remote_delete",
                            "DELETE",
                            "/v1/teams/team_remote_delete/network/messages/"
                            "tmsg_remote_delete_001",
                            query="",
                            headers={
                                "accept": "application/json",
                                "content-type": "application/json",
                            },
                            body=b'{"idempotency_key":"remote-message-delete-key"}',
                        ),
                        mock.call(
                            "connection_remote_delete",
                            "DELETE",
                            "/v1/teams/team_remote_delete/network/bulletin/"
                            "message_remote_delete_001",
                            query="",
                            headers={
                                "accept": "application/json",
                                "content-type": "application/json",
                            },
                            body=b'{"idempotency_key":"remote-bulletin-delete-key"}',
                        ),
                        mock.call(
                            "connection_remote_delete",
                            "GET",
                            "/v1/teams/team_remote_delete/network/deletions",
                            query="after_sequence=9&limit=3",
                            headers={"accept": "application/json"},
                            body=None,
                        ),
                    ],
                )

                read_only = {**remote_realm, "can_write": False}
                with mock.patch.object(
                    runtime,
                    "team_realm",
                    return_value=read_only,
                ), mock.patch.object(runtime, "proxy") as proxy:
                    for operation in (
                        lambda: runtime.team_delete_message(
                            "tmsg_remote_delete_001",
                            "read-only-message-key",
                            team_id="team_remote_delete",
                        ),
                        lambda: runtime.team_delete_bulletin_post(
                            "message_remote_delete_001",
                            "read-only-bulletin-key",
                            team_id="team_remote_delete",
                        ),
                    ):
                        with self.assertRaises(SecurePeerError) as denied:
                            operation()
                        self.assertEqual(denied.exception.code, "forbidden")
                    proxy.assert_not_called()
            finally:
                runtime.shutdown()

    def test_human_mention_uses_exact_lookup_beyond_inventory_scale_locally_and_remotely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="source_server",
                server_instance_id="source_instance",
                display_name="Source",
            )
            target_id = "principal_target_12345678"
            exact_member = {
                "member": {
                    "principal_id": target_id,
                    "display_name": "Target Member",
                    "status": "active",
                    "role": "member",
                }
            }

            class FakeHostStore:
                hub_id = "hub_1"

                @staticmethod
                def local_agent_mail_claims(team_id):
                    return {"team_id": team_id}

                @staticmethod
                def list_members(*_args, **_kwargs):
                    raise AssertionError(
                        "mention resolution must not enumerate a >10k inventory"
                    )

                @staticmethod
                def get_member(_claims, team_id, principal_id):
                    if (team_id, principal_id) != ("team_1", target_id):
                        raise AssertionError("exact member identity changed")
                    return exact_member

            reference = {
                "team_id": "team_1",
                "recipient_kind": "human",
                "target_id": target_id,
                "display_name_snapshot": "Target Member",
            }
            try:
                runtime._hub_store = FakeHostStore()
                with mock.patch.object(
                    runtime,
                    "team_realms",
                    return_value=[
                        {"realm": "host", "team_id": "team_1", "hub_id": "hub_1"}
                    ],
                ):
                    self.assertEqual(
                        runtime.resolve_team_references([reference])[0]["target_id"],
                        target_id,
                    )

                def remote_get(_realm, path, query, *, preserve_not_found=False):
                    self.assertTrue(preserve_not_found)
                    self.assertEqual(
                        path,
                        f"/v1/teams/team_1/members/{target_id}",
                    )
                    self.assertEqual(query, {})
                    return exact_member

                with mock.patch.object(
                    runtime,
                    "team_realms",
                    return_value=[
                        {
                            "realm": "secure_peer",
                            "team_id": "team_1",
                            "hub_id": "hub_1",
                            "connection_id": "connection_12345678",
                        }
                    ],
                ), mock.patch.object(
                    runtime, "_team_hub_get", side_effect=remote_get
                ) as remote:
                    self.assertEqual(
                        runtime.resolve_team_references([reference])[0]["target_id"],
                        target_id,
                    )
                    self.assertEqual(remote.call_count, 1)
            finally:
                runtime.shutdown()

    def test_human_mention_rejects_mismatched_exact_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="source_server",
                server_instance_id="source_instance",
                display_name="Source",
            )
            realm = {
                "realm": "secure_peer",
                "team_id": "team_1",
                "hub_id": "hub_1",
                "connection_id": "connection_12345678",
            }
            mismatched = {
                "member": {
                    "principal_id": "principal_other_12345678",
                    "display_name": "Target Member",
                    "status": "active",
                    "role": "member",
                },
            }
            try:
                with mock.patch.object(
                    runtime, "team_realms", return_value=[realm]
                ), mock.patch.object(
                    runtime, "_team_hub_get", return_value=mismatched
                ):
                    with self.assertRaises(SecurePeerError) as denied:
                        runtime.resolve_team_references(
                            [
                                {
                                    "team_id": "team_1",
                                    "recipient_kind": "human",
                                    "target_id": "principal_target_12345678",
                                    "display_name_snapshot": "Target Member",
                                }
                            ]
                        )
                self.assertEqual(denied.exception.code, "team_reference_invalid")
            finally:
                runtime.shutdown()

    def test_server_mention_requires_authoritative_display_name_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="source_server",
                server_instance_id="source_instance",
                display_name="Source",
            )
            realm = {
                "realm": "secure_peer",
                "team_id": "team_1",
                "hub_id": "hub_1",
                "connection_id": "connection_12345678",
            }
            target_id = "node_sonic_12345678"
            canonical = {
                "server": {
                    "id": target_id,
                    "server_identity": "sonic_server_identity",
                    "display_name": "Sonic",
                    "status": "active",
                    "is_host": True,
                    "owned_by_caller": False,
                }
            }

            def remote_get(_realm, path, query, *, preserve_not_found=False):
                self.assertEqual(_realm, realm)
                self.assertEqual(
                    path,
                    f"/v1/teams/team_1/network/servers/{target_id}",
                )
                self.assertEqual(query, {})
                self.assertTrue(preserve_not_found)
                return canonical

            reference = {
                "team_id": "team_1",
                "recipient_kind": "server",
                "target_id": target_id,
                "display_name_snapshot": "Sonic",
            }
            try:
                with mock.patch.object(
                    runtime, "team_realms", return_value=[realm]
                ), mock.patch.object(
                    runtime, "_team_hub_get", side_effect=remote_get
                ):
                    self.assertEqual(
                        runtime.resolve_team_references([reference]),
                        [reference],
                    )
                    with self.assertRaises(SecurePeerError) as stale:
                        runtime.resolve_team_references([
                            {
                                **reference,
                                "display_name_snapshot": "Visible local alias",
                            }
                        ])
                self.assertEqual(stale.exception.code, "team_reference_invalid")
            finally:
                runtime.shutdown()

    def test_agent_mail_receipt_rejects_remote_mismatch(self) -> None:
        valid = {
            "item": {
                "id": "item_1",
                "kind": "message",
                "body": "prepared body",
                "body_format": "markdown",
                "to": {"kind": "server", "id": "node_1"},
            },
            "delivery": {"id": "delivery_1", "state": "available"},
        }
        accepted = SecurePeerRuntime._validated_agent_mail_receipt(
            valid,
            kind="message",
            target_kind="server",
            target_id="node_1",
            message="prepared body",
        )
        self.assertEqual(accepted["item"]["id"], "item_1")
        for mismatch in (
            {},
            {**valid, "delivery": {}},
            {
                **valid,
                "item": {
                    **valid["item"],
                    "to": {"kind": "server", "id": "wrong_node"},
                },
            },
            {**valid, "item": {**valid["item"], "body": "wrong body"}},
        ):
            with self.assertRaises(SecurePeerError):
                SecurePeerRuntime._validated_agent_mail_receipt(
                    mismatch,
                    kind="message",
                    target_kind="server",
                    target_id="node_1",
                    message="prepared body",
                )

    def test_agent_mail_destinations_project_active_remote_servers_only(self) -> None:
        destinations = SecurePeerRuntime._agent_mail_destinations(
            {
                "network": {"display_name": "Private Team"},
                "servers": [
                    {
                        "id": "node_owned_12345678",
                        "display_name": "Owned",
                        "status": "active",
                        "owned_by_caller": True,
                    },
                    {
                        "id": "node_remote_12345678",
                        "display_name": "Remote",
                        "status": "active",
                        "owned_by_caller": False,
                        "server_identity": "remote_identity",
                        "is_host": False,
                    },
                    {
                        "id": "node_host_12345678",
                        "display_name": "Sonic",
                        "status": "active",
                        "owned_by_caller": False,
                        "server_identity": "host_identity",
                        "is_host": True,
                    },
                    {
                        "id": "node_current_malformed_12345678",
                        "display_name": "Current duplicate",
                        "status": "active",
                        "owned_by_caller": False,
                        "server_identity": "current_identity",
                        "is_host": False,
                    },
                    {
                        "id": "node_offline_12345678",
                        "display_name": "Offline",
                        "status": "offline",
                        "owned_by_caller": False,
                    },
                    {
                        "id": "node_ownership_missing_12345678",
                        "display_name": "Malformed",
                        "status": "active",
                    },
                ],
                "agents": [
                    {
                        "id": "agent_remote_12345678",
                        "server_id": "node_remote_12345678",
                        "display_name": "Remote agent",
                        "backend": "codex",
                        "status": "active",
                    }
                ],
            },
            realm={"realm": "secure_peer", "team_id": "team_1"},
            current_server_identity="current_identity",
        )
        self.assertEqual(
            [
                (
                    item["destination_kind"],
                    item["destination_id"],
                    item["display_name"],
                    item["backend"],
                )
                for item in destinations
            ],
            [
                ("server", "node_remote_12345678", "Remote", None),
                ("server", "node_host_12345678", "Sonic", None),
            ],
        )
        self.assertNotIn(
            "agent_remote_12345678",
            {item["destination_id"] for item in destinations},
        )
        self.assertNotIn(
            "node_current_malformed_12345678",
            {item["destination_id"] for item in destinations},
        )

    def test_agent_mail_send_rejects_agent_profile_without_network_io(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="source_server",
                server_instance_id="source_instance",
                display_name="Source",
            )
            try:
                with (
                    mock.patch.object(runtime, "proxy") as proxy,
                    mock.patch.object(runtime.client, "list_connections") as listed,
                ):
                    with self.assertRaises(SecurePeerError) as rejected:
                        runtime.send_agent_mail(
                            {
                                "realm": "secure_peer",
                                "team_id": "team_1",
                                "destination_kind": "agent",
                                "destination_id": "agent_remote_12345678",
                            },
                            kind="message",
                            message="must remain passive",
                            idempotency_key="server-only-mail-1",
                        )
                self.assertEqual(rejected.exception.code, "team_mail_route_changed")
                self.assertEqual(rejected.exception.status_code, 409)
                listed.assert_not_called()
                proxy.assert_not_called()
            finally:
                runtime.shutdown()

    def test_agent_mail_send_rejects_stale_connection_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="source_server",
                server_instance_id="source_instance",
                display_name="Source",
            )
            connection_id = str(uuid.uuid4())
            profile = {
                "realm": "secure_peer",
                "connection_id": connection_id,
                "team_id": "team_1",
                "hub_id": "hub_1",
                "host_server_identity": "host_1",
                "certificate_fingerprint": "sha256:" + "a" * 64,
                "destination_kind": "server",
                "destination_id": "node_1",
            }
            active = {
                "active": True,
                "status": "connected",
                "connection_id": connection_id,
                "team_id": "team_1",
                "hub_id": "hub_1",
                "host_server_identity": "host_1",
                "certificate_fingerprint": "sha256:" + "b" * 64,
                "scopes": ["teamspace.read", "teamspace.write"],
            }
            with (
                mock.patch.object(
                    runtime.client, "list_connections", return_value=[active]
                ),
                mock.patch.object(runtime, "proxy") as proxy,
            ):
                with self.assertRaises(SecurePeerError):
                    runtime.send_agent_mail(
                        profile,
                        kind="message",
                        message="prepared body",
                        idempotency_key="mail_stale_1",
                    )
            proxy.assert_not_called()
            runtime.shutdown()

    def test_agent_mail_host_listing_fails_closed_on_one_team_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="source_server",
                server_instance_id="source_instance",
                display_name="Source",
            )

            class FailingHost:
                hub_id = "hub_1"

                @staticmethod
                def local_agent_mail_team_ids():
                    return ["team_1", "team_2"]

                @staticmethod
                def local_agent_mail_claims(team_id):
                    return {"team_id": team_id}

                @staticmethod
                def get_network(*_args, **_kwargs):
                    raise HubError("unavailable", "private host detail", 409)

            runtime._hub_store = FailingHost()
            with mock.patch.object(runtime.client, "list_connections", return_value=[]):
                with self.assertRaises(HubError):
                    runtime.agent_mail_route_profiles()
            runtime.shutdown()

    @staticmethod
    def incoming_pairing(status: str, created_at: int) -> dict:
        return {
            "pairing_id": str(uuid.uuid4()),
            "peer_server_identity": f"peer_{created_at}",
            "peer_display_name": f"Peer {created_at}",
            "transcript_hash": f"transcript-{created_at}",
            "sas_words": ["amber", "beacon", "cedar", "delta"],
            "status": status,
            "created_at": created_at,
            "expires_at": 2_000_000_000,
            "team_id": None,
            "scopes": [],
            "requested_scopes": ["teamspace.read"],
            "source_ip": "192.0.2.10",
            "source_endpoint": "192.0.2.10:50000",
            "peer_public_key_fingerprint": "sha256:" + "b" * 64,
        }

    @staticmethod
    def outgoing_pairing(created_at: int) -> dict:
        return {
            "connection_id": str(uuid.uuid4()),
            "pairing_id": str(uuid.uuid4()),
            "host_ip": "192.0.2.20",
            "port": 7851,
            "status": "connected",
            "active": True,
            "host_server_identity": "remote_server",
            "host_display_name": "Remote server",
            "host_ca_fingerprint": "sha256:" + "c" * 64,
            "transcript_hash": "outgoing-transcript",
            "sas_words": ["echo", "forest", "globe", "harbor"],
            "requested_scopes": ["teamspace.read"],
            "scopes": ["teamspace.read"],
            "created_at": created_at,
            "updated_at": created_at,
        }

    def test_disabled_host_status_does_not_advertise_live_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )

            class DormantHost:
                ca_fingerprint = "sha256:" + "a" * 64
                server_certificate_expires_at = 2_000_000_000

                @staticmethod
                def list_pairings(*, team_id=None, status=None):
                    del team_id, status
                    return []

                @staticmethod
                def list_peers(*, team_id=None):
                    del team_id
                    return []

            runtime._host_store = DormantHost()
            runtime._config = {
                **runtime._config,
                "enabled": False,
                "advertised_host": None,
            }
            with mock.patch.object(
                runtime, "remote_route_delivery_available", return_value=False
            ):
                status = runtime.status()

            self.assertTrue(status["host"]["available"])
            self.assertFalse(status["host"]["enabled"])
            self.assertIsNone(status["host"]["pairing_link"])
            self.assertIsNone(status["host"]["certificate_expires_at"])
            runtime.mark_host_unavailable("Peer\nerror\x7fdetail")
            projected = runtime.status()["host"]["error"]
            self.assertNotIn("\n", projected)
            self.assertNotIn("\x7f", projected)
            self.assertEqual(
                runtime.status()["host"]["error_code"],
                "secure_peer_host_unavailable",
            )
            self.assertTrue(runtime.status()["host"]["action"])
            runtime.shutdown()

    def test_default_inbox_only_runtime_attaches_team_hub_without_relay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = SecurePeerRuntime(
                root / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            hub_store = HubStore(root / "hub")
            try:
                runtime.attach_host_hub(
                    hub_id=hub_store.hub_id,
                    hub_data_dir=root / "hub",
                    hub_store=hub_store,
                )
                status = runtime.status()
                self.assertTrue(status["host"]["available"])
                self.assertFalse(status["remote_route_delivery_available"])
                self.assertEqual(status["remote_routes"], [])
                self.assertEqual(status["published_routes"], [])
                self.assertEqual(
                    runtime._host_store.cross_chat_consent_status()[
                        "consent_epoch"
                    ],
                    0,
                )
            finally:
                runtime.shutdown()

    def test_default_inbox_only_runtime_synchronously_retires_client_routes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "secure-peers"
            legacy = SecurePeerRuntime(
                data_dir,
                server_identity="server_identity_test",
                server_instance_id="server_instance_legacy",
                display_name="Test server",
                agent_relay_enabled=True,
            )
            active_route_id = str(uuid.uuid4())
            pending_route_id = str(uuid.uuid4())
            connection = legacy.client._connect()
            try:
                for route_id, status, pending in (
                    (active_route_id, "active", 0),
                    (pending_route_id, "revoked", 1),
                ):
                    connection.execute(
                        """INSERT INTO client_routes(
                        route_id,connection_id,revision,alias,display_title,
                        actions_json,chat_id,status,revoke_pending,
                        revoke_expected_revision,revoke_idempotency_key,
                        created_at,updated_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            route_id,
                            str(uuid.uuid4()),
                            "rev_" + "a" * 32,
                            f"route-{route_id[-8:]}",
                            "Legacy route",
                            '["instruction"]',
                            f"chat-{route_id}",
                            status,
                            pending,
                            "rev_" + "a" * 32 if pending else None,
                            str(uuid.uuid4()) if pending else None,
                            123,
                            123,
                        ),
                    )
            finally:
                connection.close()
                legacy.shutdown()

            runtime = SecurePeerRuntime(
                data_dir,
                server_identity="server_identity_test",
                server_instance_id="server_instance_current",
                display_name="Test server",
            )
            try:
                connection = runtime.client._connect()
                try:
                    rows = connection.execute(
                        """SELECT status,revoke_pending,
                        revoke_expected_revision,revoke_idempotency_key
                        FROM client_routes ORDER BY route_id"""
                    ).fetchall()
                finally:
                    connection.close()
                self.assertEqual(len(rows), 2)
                self.assertTrue(all(row["status"] == "revoked" for row in rows))
                self.assertTrue(all(int(row["revoke_pending"]) == 0 for row in rows))
                self.assertTrue(
                    all(row["revoke_expected_revision"] is None for row in rows)
                )
                self.assertTrue(
                    all(row["revoke_idempotency_key"] is None for row in rows)
                )
            finally:
                runtime.shutdown()

    def test_inbox_only_status_hides_legacy_cross_chat_scopes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            legacy_scopes = [
                "teamspace.read",
                "teamspace.write",
                "cross_chat.instruction",
                "cross_chat.request_reply",
            ]
            try:
                incoming = runtime._incoming_pairing(
                    {
                        **self.incoming_pairing("active", 123),
                        "requested_scopes": legacy_scopes,
                        "scopes": legacy_scopes,
                    }
                )
                outgoing = runtime._outgoing_pairing(
                    {
                        **self.outgoing_pairing(123),
                        "requested_scopes": legacy_scopes,
                        "scopes": legacy_scopes,
                    }
                )
                for projection in (incoming, outgoing):
                    self.assertEqual(
                        projection["requested_scopes"],
                        ["teamspace.read", "teamspace.write"],
                    )
                    self.assertEqual(
                        projection["granted_scopes"],
                        ["teamspace.read", "teamspace.write"],
                    )
            finally:
                runtime.shutdown()

    def test_inbox_only_route_retirement_never_calls_the_peer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            self.assertEqual(
                runtime.client._pairing_capabilities,
                ("cert_renewal", "teamspace"),
            )
            with (
                mock.patch.object(
                    runtime.client,
                    "revoke_published_route",
                ) as remote_revoke,
                mock.patch.object(
                    runtime,
                    "_require_route_outbound_quiescent",
                    side_effect=AssertionError(
                        "disabled relay must not enter remote CAS fencing"
                    ),
                ) as outbound_fence,
            ):
                self.assertEqual(
                    runtime.revoke_routes_for_chat("chat-local"),
                    0,
                )
                with self.assertRaises(SecurePeerError) as retired:
                    runtime.revoke_route(
                        route_id=str(uuid.uuid4()),
                        expected_connection_id=str(uuid.uuid4()),
                        expected_revision="rev_" + "a" * 32,
                        idempotency_key=str(uuid.uuid4()),
                    )
            self.assertEqual(
                retired.exception.code,
                "remote_route_delivery_unavailable",
            )
            remote_revoke.assert_not_called()
            outbound_fence.assert_not_called()
            runtime.shutdown()

    def test_failed_host_attachment_is_retried_without_service_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = SecurePeerRuntime(
                root / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            hub_store = HubStore(root / "hub")
            attempts = 0

            def construct(*args, **kwargs):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise OSError("transient database open failure")
                return SecurePeerStore(*args, **kwargs)

            with mock.patch(
                "secure_peer_runtime.SecurePeerStore",
                side_effect=construct,
            ):
                with self.assertRaises(OSError):
                    runtime.attach_host_hub(
                        hub_id=hub_store.hub_id,
                        hub_data_dir=root / "hub",
                        hub_store=hub_store,
                    )
                runtime.mark_host_unavailable(
                    "The secure peer host could not finish recovery.",
                    error_code="secure_peer_host_recovery_failed",
                )
                self.assertFalse(runtime.status()["host"]["available"])
                self.assertTrue(runtime.retry_host_attachment())

            self.assertEqual(attempts, 2)
            self.assertIsNone(runtime._pending_host_attachment)
            self.assertTrue(runtime.status()["host"]["available"])
            self.assertIsNone(runtime.status()["host"]["error"])
            runtime.shutdown()

    def test_failed_agent_mail_provision_preserves_host_attachment_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = SecurePeerRuntime(
                root / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            hub_store = HubStore(root / "hub")
            provision = hub_store.provision_local_agent_mail
            attempts = 0

            def fail_once():
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise OSError("transient Agent Mail projection failure")
                return provision()

            with mock.patch.object(
                hub_store,
                "provision_local_agent_mail",
                side_effect=fail_once,
            ):
                with self.assertRaisesRegex(OSError, "projection failure"):
                    runtime.attach_host_hub(
                        hub_id=hub_store.hub_id,
                        hub_data_dir=root / "hub",
                        hub_store=hub_store,
                    )
                self.assertIsNotNone(runtime._pending_host_attachment)
                runtime.mark_host_unavailable(
                    "The secure peer host could not finish recovery.",
                    error_code="secure_peer_host_recovery_failed",
                )
                self.assertTrue(runtime.retry_host_attachment())

            self.assertEqual(attempts, 2)
            self.assertIsNone(runtime._pending_host_attachment)
            self.assertTrue(runtime.status()["host"]["available"])
            runtime.shutdown()

    def test_gateway_thread_start_failure_releases_listener_for_attach_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = SecurePeerRuntime(
                root / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            hub_store = HubStore(root / "hub")
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind(("127.0.0.1", 0))
                port = int(probe.getsockname()[1])
            finally:
                probe.close()
            runtime._config = {
                **runtime._config,
                "enabled": True,
                "advertised_host": "127.0.0.1",
                "listen_port": port,
            }
            real_start = threading.Thread.start
            starts = 0

            def fail_once(thread):
                nonlocal starts
                if thread.name != "agentsdock-secure-peer-gateway":
                    return real_start(thread)
                starts += 1
                if starts == 1:
                    raise RuntimeError("injected gateway thread start failure")
                return real_start(thread)

            try:
                with (
                    mock.patch(
                        "agentsdock_team_hub.secure_peer.canonical_peer_ipv4",
                        side_effect=lambda value: value,
                    ),
                    mock.patch.object(
                        threading.Thread,
                        "start",
                        autospec=True,
                        side_effect=fail_once,
                    ),
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "gateway thread start failure"
                    ):
                        runtime.attach_host_hub(
                            hub_id=hub_store.hub_id,
                            hub_data_dir=root / "hub",
                            hub_store=hub_store,
                        )
                    self.assertIsNone(runtime._gateway)
                    self.assertIsNotNone(runtime._pending_host_attachment)
                    # Rebinding the same port proves the failed gateway did
                    # not leak its already-activated listening socket. Retry
                    # directly so enabled hosting cannot be mistaken for an
                    # already-complete attachment when no gateway is live.
                    self.assertTrue(runtime.retry_host_attachment())
                    self.assertIsNotNone(runtime._gateway)
                    self.assertIsNone(runtime._pending_host_attachment)
                    self.assertEqual(starts, 2)
                # Probe only after restoring Thread.start: accepting this
                # connection creates a separate worker thread, whose timing
                # must not be confused with gateway listener startup.
                connection = socket.create_connection(
                    ("127.0.0.1", port), timeout=1
                )
                connection.close()
            finally:
                runtime.shutdown()

    def test_status_separates_durable_trust_from_transport_presence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            online = {
                **self.outgoing_pairing(123),
                "last_validated_at": 1_000,
            }

            class Client:
                @staticmethod
                def list_connections():
                    return [online]

            runtime.client = Client()
            with (
                mock.patch("secure_peer_runtime.time.time", return_value=1_040),
                mock.patch.object(
                    runtime, "remote_route_delivery_available", return_value=False
                ),
            ):
                projected = runtime.status()["pairings"][0]
            self.assertEqual(projected["trust_state"], "approved")
            self.assertEqual(projected["transport_state"], "online")

            runtime._client_failure_counts[online["connection_id"]] = 1
            with (
                mock.patch("secure_peer_runtime.time.time", return_value=1_040),
                mock.patch.object(
                    runtime, "remote_route_delivery_available", return_value=False
                ),
            ):
                reconnecting = runtime.status()["pairings"][0]
            self.assertEqual(reconnecting["trust_state"], "approved")
            self.assertEqual(reconnecting["transport_state"], "reconnecting")

            runtime._client_failure_counts[online["connection_id"]] = 3
            with (
                mock.patch("secure_peer_runtime.time.time", return_value=1_100),
                mock.patch.object(
                    runtime, "remote_route_delivery_available", return_value=False
                ),
            ):
                offline = runtime.status()["pairings"][0]
            self.assertEqual(offline["trust_state"], "approved")
            self.assertEqual(offline["transport_state"], "offline")
            runtime.shutdown()

    def test_unknown_trust_state_fails_closed(self) -> None:
        self.assertEqual(SecurePeerRuntime._trust_state("unexpected"), "error")
        self.assertEqual(SecurePeerRuntime._trust_state(None), "error")

    def test_status_preserves_511_pending_plus_one_outgoing_connection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            pending = [
                self.incoming_pairing("pending", index + 1)
                for index in range(PAIRING_STATUS_LIMIT - 1)
            ]
            outgoing = self.outgoing_pairing(PAIRING_STATUS_LIMIT + 1)

            class Host:
                ca_fingerprint = "sha256:" + "a" * 64
                server_certificate_expires_at = 2_000_000_000
                hub_id = "team-hub-test"

                @staticmethod
                def list_pairings(*, team_id=None, status=None):
                    del team_id, status
                    return pending

                @staticmethod
                def list_peers(*, team_id=None):
                    del team_id
                    return []

            class Client:
                @staticmethod
                def list_connections():
                    return [outgoing]

            runtime._host_store = Host()
            runtime.client = Client()
            with mock.patch.object(
                runtime, "remote_route_delivery_available", return_value=False
            ):
                status = runtime.status()
            self.assertEqual(len(status["pairings"]), PAIRING_STATUS_LIMIT)
            self.assertEqual(
                sum(
                    item["status"] == "pending_approval"
                    for item in status["pairings"]
                ),
                PAIRING_STATUS_LIMIT - 1,
            )
            self.assertIn(
                outgoing["pairing_id"],
                {item["id"] for item in status["pairings"]},
            )
            runtime.shutdown()

    def test_status_caps_terminal_history_after_preserving_actionable_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            pending = self.incoming_pairing("pending", 10_000)
            terminal = [
                self.incoming_pairing("rejected", index + 1)
                for index in range(PAIRING_STATUS_LIMIT + 88)
            ]
            outgoing = self.outgoing_pairing(10_001)

            class Host:
                ca_fingerprint = "sha256:" + "a" * 64
                server_certificate_expires_at = 2_000_000_000
                hub_id = "team-hub-test"

                @staticmethod
                def list_pairings(*, team_id=None, status=None):
                    del team_id, status
                    return [pending, *terminal]

                @staticmethod
                def list_peers(*, team_id=None):
                    del team_id
                    return []

            class Client:
                @staticmethod
                def list_connections():
                    return [outgoing]

            runtime._host_store = Host()
            runtime.client = Client()
            with mock.patch.object(
                runtime, "remote_route_delivery_available", return_value=False
            ):
                status = runtime.status()
            pairing_ids = {item["id"] for item in status["pairings"]}
            self.assertEqual(len(status["pairings"]), PAIRING_STATUS_LIMIT)
            self.assertIn(pending["pairing_id"], pairing_ids)
            self.assertIn(outgoing["pairing_id"], pairing_ids)
            self.assertIn(terminal[-1]["pairing_id"], pairing_ids)
            self.assertNotIn(terminal[0]["pairing_id"], pairing_ids)
            runtime.shutdown()

    def test_maintenance_retires_only_exact_authenticated_peer_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            active = {
                **self.outgoing_pairing(123),
                "hub_id": "hub-remote",
                "certificate_fingerprint": "sha256:" + "d" * 64,
            }
            renewed = {
                **active,
                "certificate_fingerprint": "sha256:" + "e" * 64,
            }
            connection_id = active["connection_id"]
            runtime._remote_routes_cache[connection_id] = [{"route_id": "stale"}]
            runtime._remote_routes_refreshed_at[connection_id] = 123
            with (
                mock.patch.object(
                    runtime.client,
                    "recover_pairing_attempts",
                    return_value={"remaining": 0},
                ),
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    side_effect=[[active], [renewed]],
                ),
                mock.patch.object(
                    runtime.client,
                    "flush_pending_route_revocations_for_connection",
                    return_value=0,
                ) as flush_routes,
                mock.patch.object(
                    runtime.client,
                    "renew_if_due",
                    return_value={"renewed": True, "connection": renewed},
                ),
                mock.patch.object(
                    runtime.client,
                    "peer_health",
                    side_effect=SecurePeerError(
                        "peer_revoked",
                        "Peer authentication is unavailable",
                        401,
                    ),
                ),
                mock.patch.object(
                    runtime.client,
                    "remote_revocation_status",
                    return_value={"status": "revoked"},
                ),
                mock.patch.object(
                    runtime.client,
                    "retire_remote_revoked_connection",
                    return_value={"status": "revoked", "active": False},
                ) as retire,
            ):
                result = runtime.maintenance_once()
            flush_routes.assert_not_called()
            retire.assert_called_once_with(
                connection_id,
                expected_host_server_identity="remote_server",
                expected_hub_id="hub-remote",
                expected_certificate_fingerprint="sha256:" + "e" * 64,
            )
            self.assertEqual(
                result,
                {
                    "active": False,
                    "renewed": False,
                    "healthy": False,
                    "revoked": True,
                    "revoked_connection_id": connection_id,
                    "error": "peer_revoked",
                    "pairing_recovery": {"remaining": 0},
                },
            )
            self.assertNotIn(connection_id, runtime._remote_routes_cache)
            self.assertNotIn(connection_id, runtime._remote_routes_refreshed_at)
            self.assertIsNone(runtime._client_error)
            runtime.shutdown()

    def test_maintenance_never_retires_transient_or_unpinned_errors(self) -> None:
        failures = (
            SecurePeerError("peer_revoked", "untrusted status", 503),
            SecurePeerError("transport_failed", "peer is offline", 503),
            SecurePeerError("rate_limited", "retry later", 429),
            SecurePeerError("remote_invalid", "invalid response", 502),
            TimeoutError("timed out"),
        )
        for failure in failures:
            with self.subTest(failure=repr(failure)), tempfile.TemporaryDirectory() as temporary:
                runtime = SecurePeerRuntime(
                    Path(temporary) / "secure-peers",
                    server_identity="server_identity_test",
                    server_instance_id="server_instance_test",
                    display_name="Test server",
                )
                active = {
                    **self.outgoing_pairing(123),
                    "hub_id": "hub-remote",
                    "certificate_fingerprint": "sha256:" + "d" * 64,
                }
                with (
                    mock.patch.object(
                        runtime.client,
                        "recover_pairing_attempts",
                        return_value={"remaining": 0},
                    ),
                    mock.patch.object(
                        runtime.client,
                        "list_connections",
                        return_value=[active],
                    ),
                    mock.patch.object(
                        runtime.client,
                        "flush_pending_route_revocations_for_connection",
                        return_value=0,
                    ),
                    mock.patch.object(
                        runtime.client,
                        "renew_if_due",
                        return_value={"renewed": False},
                    ),
                    mock.patch.object(
                        runtime.client,
                        "peer_health",
                        side_effect=failure,
                    ),
                    mock.patch.object(
                        runtime.client,
                        "retire_remote_revoked_connection",
                    ) as retire,
                ):
                    result = runtime.maintenance_once()
                self.assertTrue(result["active"])
                self.assertFalse(result["healthy"])
                self.assertEqual(
                    result["error"],
                    failure.code
                    if isinstance(failure, SecurePeerError)
                    else "secure_peer_maintenance_failed",
                )
                retire.assert_not_called()
                self.assertIsNotNone(runtime._client_error)
                runtime.shutdown()

    def test_maintenance_does_not_retire_superseded_credential_as_peer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            active = {
                **self.outgoing_pairing(123),
                "hub_id": "hub-remote",
                "certificate_fingerprint": "sha256:" + "d" * 64,
            }
            terminal = SecurePeerError(
                "peer_revoked",
                "Peer authentication is unavailable",
                401,
            )
            with (
                mock.patch.object(
                    runtime.client,
                    "recover_pairing_attempts",
                    return_value={"remaining": 0},
                ),
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[active],
                ),
                mock.patch.object(
                    runtime.client,
                    "renew_if_due",
                    return_value={"renewed": False},
                ),
                mock.patch.object(
                    runtime.client,
                    "peer_health",
                    side_effect=terminal,
                ),
                mock.patch.object(
                    runtime.client,
                    "remote_revocation_status",
                    return_value={"status": "active"},
                ) as status,
                mock.patch.object(
                    runtime.client,
                    "retire_remote_revoked_connection",
                ) as retire,
            ):
                result = runtime.maintenance_once()

            status.assert_called_once_with(active["connection_id"])
            retire.assert_not_called()
            self.assertTrue(result["active"])
            self.assertFalse(result["healthy"])
            self.assertEqual(result["error"], "peer_revoked")
            runtime.shutdown()

    def test_ancillary_failures_do_not_suppress_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                agent_relay_enabled=True,
            )
            active = {
                **self.outgoing_pairing(123),
                "scopes": ["teamspace.read", "cross_chat.instruction"],
                "certificate_expires_at": int(time.time()) + 3600,
                "last_validated_at": int(time.time()),
            }
            connection_id = active["connection_id"]
            calls: list[str] = []

            def fail_renew(_connection_id):
                calls.append("renew")
                raise TimeoutError("renewal unavailable")

            def heartbeat(_connection_id):
                calls.append("heartbeat")
                return {"hub_id": "hub-remote"}

            def fail_flush(_connection_id, *, limit):
                del limit
                calls.append("flush")
                raise SecurePeerError("route_retry", "route unavailable", 503)

            def routes(_connection_id):
                calls.append("routes")
                return [{"route_id": "remote-route"}]

            with (
                mock.patch.object(
                    runtime.client,
                    "recover_pairing_attempts",
                    return_value={"remaining": 0},
                ),
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[active],
                ),
                mock.patch.object(
                    runtime.client,
                    "renew_if_due",
                    side_effect=fail_renew,
                ),
                mock.patch.object(
                    runtime.client,
                    "peer_health",
                    side_effect=heartbeat,
                ),
                mock.patch.object(
                    runtime.client,
                    "flush_pending_route_revocations_for_connection",
                    side_effect=fail_flush,
                ),
                mock.patch.object(
                    runtime.client,
                    "list_remote_routes",
                    side_effect=routes,
                ),
            ):
                result = runtime.maintenance_once()

            self.assertEqual(calls, ["renew", "heartbeat", "flush", "routes"])
            self.assertTrue(result["healthy"])
            self.assertEqual(result["error"], "secure_peer_maintenance_degraded")
            self.assertNotIn(connection_id, runtime._client_failure_counts)
            self.assertEqual(
                runtime._remote_routes_cache[connection_id],
                [{"route_id": "remote-route"}],
            )
            self.assertIsNone(runtime._client_error)
            with mock.patch.object(
                runtime.client, "list_connections", return_value=[active]
            ):
                self.assertIsNotNone(runtime.team_hub_capability())
            runtime.shutdown()

    def test_relay_claim_failure_does_not_suppress_fresh_team_hub_capability(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            connection_id = str(uuid.uuid4())
            active = {
                **self.outgoing_pairing(int(time.time())),
                "connection_id": connection_id,
                "hub_id": "hub-remote",
                "certificate_expires_at": int(time.time()) + 3_600,
                "last_validated_at": int(time.time()),
                "remote_route_delivery_available": True,
            }
            with (
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[active],
                ),
                mock.patch.object(
                    runtime,
                    "remote_route_delivery_available",
                    return_value=True,
                ),
                mock.patch.object(
                    runtime.client,
                    "claim_inbox",
                    side_effect=SecurePeerError(
                        "relay_unavailable",
                        "relay inbox is unavailable",
                        503,
                    ),
                ),
            ):
                self.assertIsNotNone(runtime.team_hub_capability())
                self.assertEqual(runtime.claim_deliveries_once(limit=1), [])
                self.assertIsNone(runtime._client_error)
                self.assertEqual(
                    runtime._delivery_error,
                    "relay inbox is unavailable",
                )
                self.assertEqual(
                    runtime.status()["delivery_error"],
                    "relay inbox is unavailable",
                )
                self.assertIsNotNone(runtime.team_hub_capability())

                runtime._client_error = "authenticated heartbeat failed"
                self.assertIsNone(runtime.team_hub_capability())
            runtime.shutdown()

    def test_expired_connection_forget_uses_local_exact_retirement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            connection_id = str(uuid.uuid4())
            fingerprint = "sha256:" + "a" * 64
            expired = {
                **self.outgoing_pairing(123),
                "connection_id": connection_id,
                "hub_id": "hub-remote",
                "host_server_identity": "server_remote",
                "certificate_fingerprint": fingerprint,
                "certificate_expires_at": int(time.time()) - 1,
            }
            with (
                mock.patch.object(
                    runtime.client, "list_connections", return_value=[expired]
                ),
                mock.patch.object(
                    runtime.client, "forget_expired_connection"
                ) as local_forget,
                mock.patch.object(
                    runtime.client, "revoke_remote_connection"
                ) as remote_revoke,
                mock.patch.object(runtime, "status", return_value={"ok": True}),
            ):
                result = runtime.forget_connection(
                    connection_id,
                    expected_host_server_identity="server_remote",
                    expected_hub_id="hub-remote",
                    expected_certificate_fingerprint=fingerprint,
                )
            self.assertEqual(result, {"ok": True})
            local_forget.assert_called_once_with(
                connection_id,
                expected_host_server_identity="server_remote",
                expected_hub_id="hub-remote",
                expected_certificate_fingerprint=fingerprint,
            )
            remote_revoke.assert_not_called()
            runtime.shutdown()

    def test_attachment_download_releases_global_locks_and_deduplicates_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=32 * 1024,
            )
            connection_id = str(uuid.uuid4())
            payload = b"attachment bytes"
            attachment_id = "attachment-1"
            team_id = "team-1"
            active = {
                "connection_id": connection_id,
                "active": True,
                "status": "connected",
                "team_id": team_id,
                "hub_id": "hub-1",
            }
            attachment = {
                "id": attachment_id,
                "message_id": "message-1",
                "file_name": "example.txt",
                "media_type": "text/plain",
                "byte_size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "state": "ready",
                "received_bytes": len(payload),
            }
            entered = threading.Event()
            release = threading.Event()
            calls = 0
            results: list[Path] = []
            errors: list[BaseException] = []

            def download(_connection_id, _path, destination, *, expected_size):
                nonlocal calls
                calls += 1
                self.assertEqual(expected_size, len(payload))
                entered.set()
                self.assertTrue(release.wait(5))
                destination.write_bytes(payload)
                return (
                    ("etag", f'"{attachment["sha256"]}"'),
                    ("content-type", "text/plain"),
                    ("accept-ranges", "bytes"),
                )

            def cache() -> None:
                try:
                    results.append(
                        runtime.cache_team_attachment(
                            connection_id, team_id, attachment_id
                        )[1]
                    )
                except BaseException as exc:
                    errors.append(exc)

            with (
                mock.patch.object(
                    runtime,
                    "_team_attachment_metadata",
                    return_value=(active, attachment),
                ),
                mock.patch.object(
                    runtime.client, "list_connections", return_value=[active]
                ),
                mock.patch.object(
                    runtime.client,
                    "download_attachment_to",
                    side_effect=download,
                ),
            ):
                first = threading.Thread(target=cache)
                second = threading.Thread(target=cache)
                first.start()
                self.assertTrue(entered.wait(5))
                second.start()
                time.sleep(0.05)
                self.assertEqual(calls, 1)
                self.assertTrue(runtime._team_cache_guard.acquire(timeout=1))
                runtime._team_cache_guard.release()
                self.assertTrue(runtime._outbound_guard.acquire(timeout=1))
                runtime._outbound_guard.release()
                with runtime._team_cache_guard:
                    self.assertEqual(len(runtime._team_cache_reservations), 1)
                release.set()
                first.join(5)
                second.join(5)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(calls, 1)
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0], results[1])
            self.assertEqual(results[0].read_bytes(), payload)
            self.assertEqual(runtime._team_cache_reservations, {})
            self.assertEqual(runtime._team_cache_entry_locks, {})
            runtime.shutdown()

    def test_host_attachment_local_path_is_a_verified_cache_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = SecurePeerRuntime(
                root / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            canonical = root / "hub" / "blobs" / "canonical"
            canonical.parent.mkdir(parents=True)
            payload = b"canonical hub bytes"
            canonical.write_bytes(payload)
            attachment_id = "attachment-1"
            team_id = "team-1"
            public = {
                "id": attachment_id,
                "message_id": "message-1",
                "file_name": "canonical.txt",
                "media_type": "text/plain",
                "byte_size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "state": "ready",
                "received_bytes": len(payload),
            }

            class HostStore:
                hub_id = "hub-1"

                @staticmethod
                def local_agent_mail_claims(_team_id):
                    return object()

                @staticmethod
                def open_team_attachment(_claims, _team_id, _attachment_id):
                    descriptor = os.open(canonical, os.O_RDONLY)
                    return dict(public), AttachmentFileLease(
                        descriptor, lambda: os.close(descriptor)
                    )

            runtime._hub_store = HostStore()
            with mock.patch.object(
                runtime,
                "team_realm",
                return_value={"realm": "host", "team_id": team_id},
            ):
                first = runtime.team_attachment_local_paths(
                    [{"id": attachment_id}], team_id=team_id
                )[0]
                exported = Path(first["local_path"])
                self.assertNotEqual(exported.resolve(), canonical.resolve())
                self.assertNotIn(canonical.parent, exported.resolve().parents)
                original = exported.stat()
                exported.write_bytes(b"x" * len(payload))
                os.utime(
                    exported,
                    ns=(original.st_atime_ns, original.st_mtime_ns),
                )
                self.assertEqual(exported.stat().st_size, original.st_size)
                self.assertEqual(exported.stat().st_mtime_ns, original.st_mtime_ns)
                second = runtime.team_attachment_local_paths(
                    [{"id": attachment_id}], team_id=team_id
                )[0]
            self.assertEqual(canonical.read_bytes(), payload)
            self.assertEqual(Path(second["local_path"]).read_bytes(), payload)
            runtime.shutdown()

    def test_cache_reuse_hashes_outside_global_lock_and_cas_rechecks_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=32 * 1024,
            )
            connection_id = str(uuid.uuid4())
            team_id = "team-1"
            attachment_id = "attachment-1"
            payload = b"verified attachment bytes"
            active = {
                "connection_id": connection_id,
                "active": True,
                "status": "connected",
                "team_id": team_id,
                "hub_id": "hub-1",
            }
            attachment = {
                "id": attachment_id,
                "message_id": "message-1",
                "file_name": "verified.txt",
                "media_type": "text/plain",
                "byte_size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "state": "ready",
                "received_bytes": len(payload),
            }
            downloads = 0

            def download(_connection_id, _path, destination, *, expected_size):
                nonlocal downloads
                downloads += 1
                self.assertEqual(expected_size, len(payload))
                destination.write_bytes(payload)
                return (
                    ("etag", f'"{attachment["sha256"]}"'),
                    ("content-type", "text/plain"),
                    ("accept-ranges", "bytes"),
                )

            common_patches = (
                mock.patch.object(
                    runtime,
                    "_team_attachment_metadata",
                    return_value=(active, attachment),
                ),
                mock.patch.object(
                    runtime.client, "list_connections", return_value=[active]
                ),
                mock.patch.object(
                    runtime.client,
                    "download_attachment_to",
                    side_effect=download,
                ),
            )
            with common_patches[0], common_patches[1], common_patches[2]:
                _public, cached = runtime.cache_team_attachment(
                    connection_id, team_id, attachment_id
                )
                original = cached.stat()
                hashed = threading.Event()
                release = threading.Event()
                errors: list[BaseException] = []
                results: list[Path] = []
                descriptor_sha256 = runtime._team_descriptor_sha256

                def pause_after_hash(descriptor, size):
                    digest = descriptor_sha256(descriptor, size)
                    hashed.set()
                    if not release.wait(5):
                        raise TimeoutError("test did not release cache hash")
                    return digest

                def reuse() -> None:
                    try:
                        results.append(
                            runtime.cache_team_attachment(
                                connection_id, team_id, attachment_id
                            )[1]
                        )
                    except BaseException as exc:
                        errors.append(exc)

                with mock.patch.object(
                    runtime,
                    "_team_descriptor_sha256",
                    side_effect=pause_after_hash,
                ):
                    worker = threading.Thread(target=reuse)
                    worker.start()
                    self.assertTrue(hashed.wait(5))
                    self.assertTrue(runtime._team_cache_guard.acquire(timeout=1))
                    runtime._team_cache_guard.release()
                    cached.write_bytes(b"z" * len(payload))
                    os.utime(
                        cached,
                        ns=(original.st_atime_ns, original.st_mtime_ns),
                    )
                    release.set()
                    worker.join(5)

            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(downloads, 2)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].read_bytes(), payload)
            runtime.shutdown()

    def test_attachment_path_batch_pins_earlier_entries_or_fails_whole_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payloads = {
                "attachment-1": b"a" * 128,
                "attachment-2": b"b" * 128,
            }
            runtime = SecurePeerRuntime(
                root / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=4096 + 128,
            )
            team_id = "team-1"

            class HostStore:
                hub_id = "hub-1"

                @staticmethod
                def local_agent_mail_claims(_team_id):
                    return object()

                @staticmethod
                def open_team_attachment(_claims, _team_id, attachment_id):
                    payload = payloads[attachment_id]
                    source = root / f"{attachment_id}.source"
                    source.write_bytes(payload)
                    descriptor = os.open(source, os.O_RDONLY)
                    public = {
                        "id": attachment_id,
                        "message_id": "message-1",
                        "file_name": f"{attachment_id}.txt",
                        "media_type": "text/plain",
                        "byte_size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "state": "ready",
                        "received_bytes": len(payload),
                    }
                    return public, AttachmentFileLease(
                        descriptor, lambda: os.close(descriptor)
                    )

            runtime._hub_store = HostStore()
            with mock.patch.object(
                runtime,
                "team_realm",
                return_value={"realm": "host", "team_id": team_id},
            ):
                with self.assertRaises(SecurePeerError) as too_small:
                    runtime.team_attachment_local_paths(
                        [{"id": "attachment-1"}, {"id": "attachment-2"}],
                        team_id=team_id,
                    )
                self.assertEqual(too_small.exception.code, "cache_unavailable")

                runtime.team_cache_max_bytes = 32 * 1024
                resolved = runtime.team_attachment_local_paths(
                    [{"id": "attachment-1"}, {"id": "attachment-2"}],
                    team_id=team_id,
                )

            self.assertEqual(len(resolved), 2)
            for item in resolved:
                path = Path(item["local_path"])
                self.assertTrue(path.is_file())
                self.assertEqual(path.read_bytes(), payloads[item["id"]])
            runtime.shutdown()

    def test_returned_attachment_export_survives_concurrent_cache_eviction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payloads = {
                "attachment-1": b"a" * 128,
                "attachment-2": b"b" * 128,
            }
            runtime = SecurePeerRuntime(
                root / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=4096 + 128,
            )
            team_id = "team-1"

            class HostStore:
                hub_id = "hub-1"

                @staticmethod
                def local_agent_mail_claims(_team_id):
                    return object()

                @staticmethod
                def open_team_attachment(_claims, _team_id, attachment_id):
                    payload = payloads[attachment_id]
                    source = root / f"{attachment_id}.source"
                    source.write_bytes(payload)
                    descriptor = os.open(source, os.O_RDONLY)
                    public = {
                        "id": attachment_id,
                        "message_id": "message-1",
                        "file_name": f"{attachment_id}.txt",
                        "media_type": "text/plain",
                        "byte_size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "state": "ready",
                        "received_bytes": len(payload),
                    }
                    return public, AttachmentFileLease(
                        descriptor, lambda: os.close(descriptor)
                    )

            runtime._hub_store = HostStore()
            with mock.patch.object(
                runtime,
                "team_realm",
                return_value={"realm": "host", "team_id": team_id},
            ):
                held = runtime.team_attachment_local_paths(
                    [{"id": "attachment-1"}], team_id=team_id
                )
                response_body = json.dumps({"attachments": held})
                held_path = Path(
                    json.loads(response_body)["attachments"][0]["local_path"]
                )
                del held
                first_cache, _sidecar = runtime._team_cache_paths(
                    {"hub_id": "hub-1"},
                    team_id,
                    "attachment-1",
                    "attachment-1.txt",
                )
                errors: list[BaseException] = []
                replacements: list[list[dict]] = []

                def competing_fill() -> None:
                    try:
                        replacements.append(
                            runtime.team_attachment_local_paths(
                                [{"id": "attachment-2"}], team_id=team_id
                            )
                        )
                    except BaseException as exc:
                        errors.append(exc)

                worker = threading.Thread(target=competing_fill)
                worker.start()
                worker.join(5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(len(replacements), 1)
                self.assertFalse(first_cache.exists())
                self.assertTrue(held_path.is_file())
                self.assertEqual(held_path.read_bytes(), payloads["attachment-1"])
                replacement_path = Path(replacements[0][0]["local_path"])
                self.assertEqual(
                    replacement_path.read_bytes(), payloads["attachment-2"]
                )
            runtime.shutdown()

    def test_fresh_download_staging_inode_is_cas_checked_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=32 * 1024,
            )
            connection_id = str(uuid.uuid4())
            team_id = "team-1"
            attachment_id = "attachment-1"
            payload = b"fresh verified attachment"
            active = {
                "connection_id": connection_id,
                "active": True,
                "status": "connected",
                "team_id": team_id,
                "hub_id": "hub-1",
            }
            attachment = {
                "id": attachment_id,
                "message_id": "message-1",
                "file_name": "fresh.txt",
                "media_type": "text/plain",
                "byte_size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "state": "ready",
                "received_bytes": len(payload),
            }
            downloads = 0

            def download(_connection_id, _path, destination, *, expected_size):
                nonlocal downloads
                downloads += 1
                self.assertEqual(expected_size, len(payload))
                destination.write_bytes(payload)
                return (
                    ("etag", f'"{attachment["sha256"]}"'),
                    ("content-type", "text/plain"),
                    ("accept-ranges", "bytes"),
                )

            hashed = threading.Event()
            release = threading.Event()
            errors: list[BaseException] = []
            descriptor_sha256 = runtime._team_descriptor_sha256

            def pause_after_first_hash(descriptor, size):
                digest = descriptor_sha256(descriptor, size)
                if not hashed.is_set():
                    hashed.set()
                    if not release.wait(5):
                        raise TimeoutError("test did not release staging hash")
                return digest

            def first_fill() -> None:
                try:
                    runtime.cache_team_attachment(
                        connection_id, team_id, attachment_id
                    )
                except BaseException as exc:
                    errors.append(exc)

            with (
                mock.patch.object(
                    runtime,
                    "_team_attachment_metadata",
                    return_value=(active, attachment),
                ),
                mock.patch.object(
                    runtime.client, "list_connections", return_value=[active]
                ),
                mock.patch.object(
                    runtime.client,
                    "download_attachment_to",
                    side_effect=download,
                ),
            ):
                with mock.patch.object(
                    runtime,
                    "_team_descriptor_sha256",
                    side_effect=pause_after_first_hash,
                ):
                    worker = threading.Thread(target=first_fill)
                    worker.start()
                    self.assertTrue(hashed.wait(5))
                    staging = next(
                        runtime.team_cache_dir.rglob(".download.*")
                    )
                    original = staging.stat()
                    staging.write_bytes(b"z" * len(payload))
                    os.utime(
                        staging,
                        ns=(original.st_atime_ns, original.st_mtime_ns),
                    )
                    self.assertEqual(staging.stat().st_size, original.st_size)
                    self.assertEqual(
                        staging.stat().st_mtime_ns, original.st_mtime_ns
                    )
                    release.set()
                    worker.join(5)

                self.assertFalse(worker.is_alive())
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], SecurePeerError)
                self.assertEqual(errors[0].code, "attachment_hash_mismatch")
                self.assertEqual(runtime._team_cache_reservations, {})
                self.assertEqual(runtime._team_cache_pins, {})
                self.assertEqual(
                    list(runtime.team_cache_dir.rglob(".download.*")), []
                )
                target, sidecar = runtime._team_cache_paths(
                    active,
                    team_id,
                    attachment_id,
                    attachment["file_name"],
                )
                self.assertFalse(target.exists())
                self.assertFalse(sidecar.exists())

                _public, recovered = runtime.cache_team_attachment(
                    connection_id, team_id, attachment_id
                )
                self.assertEqual(recovered.read_bytes(), payload)

            self.assertEqual(downloads, 2)
            runtime.shutdown()

    def test_failed_distinct_cache_ids_prune_empty_directories_boundedly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=4096 + 8,
            )
            connection_id = str(uuid.uuid4())
            team_id = "team-1"
            active = {
                "connection_id": connection_id,
                "active": True,
                "status": "connected",
                "team_id": team_id,
                "hub_id": "hub-1",
            }

            def metadata(_connection_id, _team_id, attachment_id):
                payload = b"12345678"
                return active, {
                    "id": attachment_id,
                    "message_id": "message-1",
                    "file_name": f"{attachment_id}.txt",
                    "media_type": "text/plain",
                    "byte_size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "state": "ready",
                    "received_bytes": len(payload),
                }

            with (
                mock.patch.object(
                    runtime,
                    "_team_attachment_metadata",
                    side_effect=metadata,
                ),
                mock.patch.object(
                    runtime.client, "list_connections", return_value=[active]
                ),
                mock.patch.object(
                    runtime.client,
                    "download_attachment_to",
                    side_effect=SecurePeerError(
                        "attachment_unavailable", "synthetic download failure", 502
                    ),
                ),
            ):
                for index in range(200):
                    with self.assertRaises(SecurePeerError):
                        runtime.cache_team_attachment(
                            connection_id,
                            team_id,
                            f"attachment-{index}",
                        )

            self.assertEqual(
                [path for path in runtime.team_cache_dir.rglob("*")], []
            )
            runtime.shutdown()

    def test_empty_cache_pruning_never_traverses_symlink_or_nonempty_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = SecurePeerRuntime(
                root / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            external = root / "external"
            external.mkdir()
            marker = external / "marker.txt"
            marker.write_text("preserve")
            runtime.team_cache_dir.mkdir(mode=0o700)
            linked = runtime.team_cache_dir / "linked"
            linked.symlink_to(external, target_is_directory=True)
            nonempty = runtime.team_cache_dir / "owned" / "nonempty"
            nonempty.mkdir(parents=True)
            protected = nonempty / "marker.txt"
            protected.write_text("preserve")
            empty = runtime.team_cache_dir / "empty" / "nested"
            empty.mkdir(parents=True)

            with runtime._team_cache_guard:
                runtime._prune_empty_team_cache_directories_locked()

            self.assertTrue(linked.is_symlink())
            self.assertEqual(marker.read_text(), "preserve")
            self.assertEqual(protected.read_text(), "preserve")
            self.assertFalse(empty.exists())
            runtime.shutdown()

    def test_cache_directory_creation_is_atomic_with_concurrent_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=32 * 1024,
            )
            connection_id = str(uuid.uuid4())
            team_id = "team-1"
            attachment_id = "attachment-1"
            payload = b"atomic cache hierarchy"
            active = {
                "connection_id": connection_id,
                "active": True,
                "status": "connected",
                "team_id": team_id,
                "hub_id": "hub-1",
            }
            attachment = {
                "id": attachment_id,
                "message_id": "message-1",
                "file_name": "atomic.txt",
                "media_type": "text/plain",
                "byte_size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "state": "ready",
                "received_bytes": len(payload),
            }
            created = threading.Event()
            release = threading.Event()
            prune_done = threading.Event()
            results: list[Path] = []
            errors: list[BaseException] = []
            original_paths = runtime._team_cache_paths_locked

            def gated_paths(*args, **kwargs):
                result = original_paths(*args, **kwargs)
                created.set()
                if not release.wait(5):
                    raise TimeoutError("test did not release cache hierarchy")
                return result

            def download(_connection_id, _path, destination, *, expected_size):
                self.assertTrue(destination.parent.is_dir())
                self.assertEqual(expected_size, len(payload))
                destination.write_bytes(payload)
                return (
                    ("etag", f'"{attachment["sha256"]}"'),
                    ("content-type", "text/plain"),
                    ("accept-ranges", "bytes"),
                )

            def materialize() -> None:
                try:
                    results.append(
                        runtime.cache_team_attachment(
                            connection_id, team_id, attachment_id
                        )[1]
                    )
                except BaseException as exc:
                    errors.append(exc)

            def prune() -> None:
                with runtime._team_cache_guard:
                    runtime._prune_empty_team_cache_directories_locked()
                prune_done.set()

            with (
                mock.patch.object(
                    runtime,
                    "_team_attachment_metadata",
                    return_value=(active, attachment),
                ),
                mock.patch.object(
                    runtime.client, "list_connections", return_value=[active]
                ),
                mock.patch.object(
                    runtime.client,
                    "download_attachment_to",
                    side_effect=download,
                ),
                mock.patch.object(
                    runtime,
                    "_team_cache_paths_locked",
                    side_effect=gated_paths,
                ),
            ):
                worker = threading.Thread(target=materialize)
                worker.start()
                self.assertTrue(created.wait(5))
                pruner = threading.Thread(target=prune)
                pruner.start()
                time.sleep(0.05)
                self.assertFalse(prune_done.is_set())
                release.set()
                worker.join(5)
                pruner.join(5)

            self.assertFalse(worker.is_alive())
            self.assertFalse(pruner.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].read_bytes(), payload)
            runtime.shutdown()

    def test_cache_scan_tolerates_active_writer_directory_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=32 * 1024,
            )
            target, sidecar = runtime._team_cache_paths(
                {"hub_id": "hub-1"},
                "team-1",
                "attachment-1",
                "attachment.txt",
            )
            staging = sidecar.parent / f".download.{uuid.uuid4().hex}"
            staging.write_bytes(b"x")
            hub_directory = runtime.team_cache_dir / "hub-1"
            real_open = os.open
            mutated = False

            def mutate_before_open(path, *args, **kwargs):
                nonlocal mutated
                if (
                    path == "hub-1"
                    and kwargs.get("dir_fd") is not None
                    and not mutated
                ):
                    mutated = True
                    transient = hub_directory / "concurrent-writer"
                    transient.mkdir()
                    transient.rmdir()
                return real_open(path, *args, **kwargs)

            try:
                with runtime._team_cache_guard:
                    runtime._team_cache_reservations[staging] = 1
                with mock.patch(
                    "secure_peer_runtime.os.open",
                    side_effect=mutate_before_open,
                ):
                    with runtime._team_cache_guard:
                        # This is the capacity reservation made by a second
                        # download while the first staging writer is active.
                        runtime._evict_team_cache(
                            reserve_bytes=1,
                            prune_empty=False,
                        )
                self.assertTrue(mutated)
            finally:
                with runtime._team_cache_guard:
                    runtime._team_cache_reservations.pop(staging, None)
                staging.unlink(missing_ok=True)
                runtime.shutdown()

    def test_legacy_cache_count_overflow_is_recovered_in_bounded_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=32 * 1024,
            )
            for index in range(10):
                target, sidecar = runtime._team_cache_paths(
                    {"hub_id": "hub-1"},
                    "team-1",
                    f"legacy-{index}",
                    f"legacy-{index}.txt",
                )
                target.write_bytes(bytes([index]) * 64)
                sidecar.write_text("{}")

            with mock.patch(
                "secure_peer_runtime._TEAM_CACHE_DIRECTORY_SCAN_LIMIT", 12
            ):
                with runtime._team_cache_guard:
                    runtime._evict_team_cache(
                        reserve_bytes=runtime.team_cache_max_bytes
                    )
                    regular, scan_status = (
                        runtime._bounded_team_cache_regular_files_locked()
                    )
            self.assertEqual(scan_status, "complete")
            self.assertEqual(sum(item.st_size for item in regular.values()), 0)
            self.assertLessEqual(
                runtime.team_cache_max_bytes
                + sum(item.st_size for item in regular.values()),
                runtime.team_cache_max_bytes,
            )
            runtime.shutdown()

    def test_unsafe_cache_scan_never_admits_reserved_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=32 * 1024,
            )
            target, _sidecar = runtime._team_cache_paths(
                {"hub_id": "hub-1"},
                "team-1",
                "attachment-1",
                "attachment.txt",
            )
            target.write_bytes(b"must not be undercounted")
            partial = {target: target.stat()}
            with (
                mock.patch.object(
                    runtime,
                    "_bounded_team_cache_regular_files_locked",
                    return_value=(partial, "unsafe"),
                ),
                runtime._team_cache_guard,
                self.assertRaises(SecurePeerError) as unavailable,
            ):
                runtime._evict_team_cache(
                    reserve_bytes=runtime.team_cache_max_bytes
                )
            self.assertEqual(unavailable.exception.code, "cache_unavailable")
            self.assertEqual(target.read_bytes(), b"must not be undercounted")
            runtime.shutdown()

    def test_export_reservation_skips_active_writer_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                team_cache_max_bytes=32 * 1024,
            )
            reservations: list[tuple[int, int, str, Path]] = []
            try:
                with runtime._team_cache_guard:
                    first = runtime._reserve_team_export_locked(8)
                reservations.append(first)
                first_root, first_directory, first_name, _first_path = first
                first_identity = runtime._team_directory_identity(
                    os.fstat(first_directory)
                )
                real_open = os.open
                real_scandir = os.scandir
                mutated = False

                def mutate_before_open(path, *args, **kwargs):
                    nonlocal mutated
                    if (
                        path == first_name
                        and kwargs.get("dir_fd") is not None
                        and not mutated
                    ):
                        mutated = True
                        output = real_open(
                            "in-flight",
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                            dir_fd=first_directory,
                        )
                        try:
                            os.write(output, b"12345678")
                        finally:
                            os.close(output)
                    return real_open(path, *args, **kwargs)

                def reject_active_child_scan(path):
                    if isinstance(path, int):
                        try:
                            identity = runtime._team_directory_identity(
                                os.fstat(path)
                            )
                        except OSError:
                            identity = None
                        if identity == first_identity:
                            raise AssertionError(
                                "active export directory must not be enumerated"
                            )
                    return real_scandir(path)

                with (
                    mock.patch(
                        "secure_peer_runtime.os.open",
                        side_effect=mutate_before_open,
                    ),
                    mock.patch(
                        "secure_peer_runtime.os.scandir",
                        side_effect=reject_active_child_scan,
                    ),
                ):
                    with runtime._team_cache_guard:
                        second = runtime._reserve_team_export_locked(8)
                reservations.append(second)
                self.assertTrue(mutated)
            finally:
                with runtime._team_cache_guard:
                    for root_descriptor, directory_descriptor, name, path in reversed(
                        reservations
                    ):
                        runtime._team_export_reservations.pop(path, None)
                        runtime._remove_team_export_directory_fd(
                            root_descriptor,
                            name,
                            directory_descriptor,
                        )
                        os.close(directory_descriptor)
                        os.close(root_descriptor)
                runtime.shutdown()

    def test_cache_prune_rejects_component_swapped_to_external_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = SecurePeerRuntime(
                root / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            runtime.team_cache_dir.mkdir(mode=0o700)
            victim = runtime.team_cache_dir / "victim"
            (victim / "nested").mkdir(parents=True)
            external = root / "external"
            outside_empty = external / "must-survive"
            outside_empty.mkdir(parents=True)
            parked = runtime.team_cache_dir / "parked"
            real_open = os.open
            swapped = False

            def swap_before_child_open(path, *args, **kwargs):
                nonlocal swapped
                if path == "victim" and kwargs.get("dir_fd") is not None and not swapped:
                    swapped = True
                    victim.rename(parked)
                    victim.symlink_to(external, target_is_directory=True)
                return real_open(path, *args, **kwargs)

            with mock.patch(
                "secure_peer_runtime.os.open",
                side_effect=swap_before_child_open,
            ):
                with runtime._team_cache_guard:
                    runtime._prune_empty_team_cache_directories_locked()

            self.assertTrue(swapped)
            self.assertTrue(victim.is_symlink())
            self.assertTrue(outside_empty.is_dir())
            self.assertTrue(parked.is_dir())
            runtime.shutdown()

    def test_cache_eviction_cannot_follow_swapped_root_or_component(self) -> None:
        for swap_root in (True, False):
            with self.subTest(scope="root" if swap_root else "component"):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    runtime = SecurePeerRuntime(
                        root / "secure-peers",
                        server_identity="server_identity_test",
                        server_instance_id="server_instance_test",
                        display_name="Test server",
                        team_cache_max_bytes=32 * 1024,
                    )
                    connection_id = str(uuid.uuid4())
                    team_id = "team-1"
                    attachment_id = "attachment-1"
                    payload = b"eviction swap payload"
                    active = {
                        "connection_id": connection_id,
                        "active": True,
                        "status": "connected",
                        "team_id": team_id,
                        "hub_id": "hub-1",
                    }
                    attachment = {
                        "id": attachment_id,
                        "message_id": "message-1",
                        "file_name": "swap.txt",
                        "media_type": "text/plain",
                        "byte_size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "state": "ready",
                        "received_bytes": len(payload),
                    }

                    def download(
                        _connection_id, _path, destination, *, expected_size
                    ):
                        self.assertEqual(expected_size, len(payload))
                        destination.write_bytes(payload)
                        return (
                            ("etag", f'"{attachment["sha256"]}"'),
                            ("content-type", "text/plain"),
                            ("accept-ranges", "bytes"),
                        )

                    with (
                        mock.patch.object(
                            runtime,
                            "_team_attachment_metadata",
                            return_value=(active, attachment),
                        ),
                        mock.patch.object(
                            runtime.client,
                            "list_connections",
                            return_value=[active],
                        ),
                        mock.patch.object(
                            runtime.client,
                            "download_attachment_to",
                            side_effect=download,
                        ),
                    ):
                        runtime.cache_team_attachment(
                            connection_id, team_id, attachment_id
                        )

                    external = root / "outside-cache"
                    relative = (
                        Path("hub-1") / "team-1" / "attachment-1" / "payload"
                        if swap_root
                        else Path("team-1") / "attachment-1" / "payload"
                    )
                    outside_payload = external / relative / "swap.txt"
                    outside_payload.parent.mkdir(parents=True)
                    outside_payload.write_bytes(b"outside must survive")
                    original_parent = (
                        runtime.team_cache_dir
                        if swap_root
                        else runtime.team_cache_dir / "hub-1"
                    )
                    parked = original_parent.with_name(
                        original_parent.name + "-parked"
                    )
                    original_open_parent = (
                        runtime._open_team_cache_parent_descriptor_locked
                    )
                    swapped = False

                    def swap_before_delete(candidate):
                        nonlocal swapped
                        if not swapped:
                            swapped = True
                            original_parent.rename(parked)
                            original_parent.symlink_to(
                                external, target_is_directory=True
                            )
                        return original_open_parent(candidate)

                    with (
                        mock.patch.object(
                            runtime,
                            "_open_team_cache_parent_descriptor_locked",
                            side_effect=swap_before_delete,
                        ),
                        runtime._team_cache_guard,
                        self.assertRaises(SecurePeerError) as unavailable,
                    ):
                        runtime._evict_team_cache(
                            reserve_bytes=runtime.team_cache_max_bytes
                        )
                    self.assertEqual(unavailable.exception.code, "cache_unavailable")
                    self.assertTrue(swapped)
                    self.assertEqual(
                        outside_payload.read_bytes(), b"outside must survive"
                    )
                    self.assertTrue(original_parent.is_symlink())
                    self.assertTrue(parked.is_dir())
                    runtime.shutdown()

    def test_revocation_replay_failure_does_not_block_other_peers_or_leases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            first_peer = str(uuid.uuid4())
            second_peer = str(uuid.uuid4())
            host_store = mock.Mock()
            host_store.list_peers.return_value = [
                {
                    "peer_id": first_peer,
                    "team_id": "team-test",
                    "peer_server_identity": "peer-first",
                    "status": "revoked",
                },
                {
                    "peer_id": second_peer,
                    "team_id": "team-test",
                    "peer_server_identity": "peer-second",
                    "status": "revoked",
                },
            ]
            adapter = mock.Mock()
            adapter.active_binding_peer_ids.side_effect = [
                RuntimeError("corrupt first tombstone"),
                {second_peer},
            ]
            runtime._host_store = host_store
            runtime._adapter = adapter
            with (
                mock.patch.object(
                    runtime.client,
                    "recover_pairing_attempts",
                    return_value={"remaining": 0},
                ),
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[],
                ),
            ):
                result = runtime.maintenance_once()

            adapter.revoke_peer.assert_called_once_with(
                peer_id=second_peer,
                team_id="team-test",
            )
            adapter.expire_peer_leases.assert_called_once()
            self.assertFalse(result["active"])
            runtime.shutdown()

    def test_inbox_only_connection_makes_no_route_maintenance_rpc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            active = self.outgoing_pairing(123)
            connection_id = active["connection_id"]
            with (
                mock.patch.object(
                    runtime.client,
                    "recover_pairing_attempts",
                    return_value={"remaining": 0},
                ),
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[active],
                ),
                mock.patch.object(
                    runtime.client,
                    "flush_pending_route_revocations_for_connection",
                ) as flush_route_revocations,
                mock.patch.object(
                    runtime.client,
                    "renew_if_due",
                    return_value={"renewed": False},
                ),
                mock.patch.object(
                    runtime.client,
                    "peer_health",
                    return_value={"hub_id": "hub-remote"},
                ),
                mock.patch.object(
                    runtime.client,
                    "list_remote_routes",
                ) as list_remote_routes,
            ):
                result = runtime.maintenance_once()
            flush_route_revocations.assert_not_called()
            list_remote_routes.assert_not_called()
            self.assertTrue(result["healthy"])
            self.assertEqual(runtime._remote_routes_cache[connection_id], [])
            self.assertIsNone(runtime._client_error)
            runtime.shutdown()

    def test_cross_chat_connection_still_refreshes_remote_routes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                agent_relay_enabled=True,
            )
            active = {
                **self.outgoing_pairing(123),
                "scopes": ["teamspace.read", "cross_chat.instruction"],
            }
            connection_id = active["connection_id"]
            routes = [{"route_id": "remote-route"}]
            with (
                mock.patch.object(
                    runtime.client,
                    "recover_pairing_attempts",
                    return_value={"remaining": 0},
                ),
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[active],
                ),
                mock.patch.object(
                    runtime.client,
                    "flush_pending_route_revocations_for_connection",
                    return_value=0,
                ),
                mock.patch.object(
                    runtime.client,
                    "renew_if_due",
                    return_value={"renewed": False},
                ),
                mock.patch.object(
                    runtime.client,
                    "peer_health",
                    return_value={"hub_id": "hub-remote"},
                ),
                mock.patch.object(
                    runtime.client,
                    "list_remote_routes",
                    return_value=routes,
                ) as list_remote_routes,
            ):
                result = runtime.maintenance_once()
            list_remote_routes.assert_called_once_with(connection_id)
            self.assertTrue(result["healthy"])
            self.assertEqual(runtime._remote_routes_cache[connection_id], routes)
            self.assertIsNone(runtime._client_error)
            runtime.shutdown()

    def test_revocation_retires_exact_deactivated_connection_not_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            observed = {
                **self.outgoing_pairing(123),
                "hub_id": "hub-remote",
                "certificate_fingerprint": "sha256:" + "d" * 64,
            }
            deactivated = {
                **observed,
                "status": "deactivated",
                "active": False,
                "certificate_fingerprint": "sha256:" + "f" * 64,
            }
            replacement = {
                **self.outgoing_pairing(124),
                "hub_id": "hub-other",
                "certificate_fingerprint": "sha256:" + "e" * 64,
            }
            with (
                mock.patch.object(
                    runtime.client,
                    "recover_pairing_attempts",
                    return_value={"remaining": 0},
                ),
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    side_effect=[[observed], [replacement, deactivated]],
                ),
                mock.patch.object(
                    runtime.client,
                    "flush_pending_route_revocations_for_connection",
                    return_value=0,
                ),
                mock.patch.object(
                    runtime.client,
                    "renew_if_due",
                    return_value={"renewed": False},
                ),
                mock.patch.object(
                    runtime.client,
                    "peer_health",
                    side_effect=SecurePeerError(
                        "peer_revoked",
                        "Peer authentication is unavailable",
                        401,
                    ),
                ),
                mock.patch.object(
                    runtime.client,
                    "remote_revocation_status",
                    return_value={"status": "revoked"},
                ),
                mock.patch.object(
                    runtime.client,
                    "retire_remote_revoked_connection",
                    return_value={"status": "revoked", "active": False},
                ) as retire,
            ):
                result = runtime.maintenance_once()
            self.assertEqual(result["error"], "peer_revoked")
            self.assertTrue(result["active"])
            retire.assert_called_once_with(
                observed["connection_id"],
                expected_host_server_identity="remote_server",
                expected_hub_id="hub-remote",
                expected_certificate_fingerprint="sha256:" + "f" * 64,
            )
            self.assertNotEqual(
                retire.call_args.args[0],
                replacement["connection_id"],
            )
            runtime.shutdown()

    def test_revocation_treats_forgotten_connection_as_terminal_noop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            observed = {
                **self.outgoing_pairing(123),
                "hub_id": "hub-remote",
                "certificate_fingerprint": "sha256:" + "d" * 64,
            }
            replacement = {
                **self.outgoing_pairing(124),
                "hub_id": "hub-other",
                "certificate_fingerprint": "sha256:" + "e" * 64,
            }
            with (
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[replacement],
                ),
                mock.patch.object(
                    runtime.client,
                    "retire_remote_revoked_connection",
                ) as retire,
            ):
                result = runtime._retire_remote_revoked_active_connection(
                    observed,
                    {"remaining": 0},
                )
            self.assertTrue(result["active"])
            self.assertTrue(result["revoked"])
            self.assertEqual(
                result["revoked_connection_id"],
                observed["connection_id"],
            )
            retire.assert_not_called()
            runtime.shutdown()

    def test_proxy_retires_exact_authenticated_revocation_before_propagating(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            active = {
                **self.outgoing_pairing(123),
                "hub_id": "hub-remote",
                "certificate_fingerprint": "sha256:" + "d" * 64,
            }
            renewed = {
                **active,
                "certificate_fingerprint": "sha256:" + "e" * 64,
            }
            connection_id = active["connection_id"]
            terminal = SecurePeerError(
                "peer_revoked",
                "Peer authentication is unavailable",
                401,
            )
            runtime._remote_routes_cache[connection_id] = [{"route_id": "stale"}]
            runtime._remote_routes_refreshed_at[connection_id] = 123
            with (
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    side_effect=[[active], [renewed]],
                ),
                mock.patch.object(
                    runtime.client,
                    "proxy",
                    side_effect=terminal,
                ),
                mock.patch.object(
                    runtime.client,
                    "remote_revocation_status",
                    return_value={"status": "revoked"},
                ),
                mock.patch.object(
                    runtime.client,
                    "retire_remote_revoked_connection",
                    return_value={"status": "revoked", "active": False},
                ) as retire,
                self.assertRaises(SecurePeerError) as propagated,
            ):
                runtime.proxy(
                    connection_id,
                    "GET",
                    "/v1/teams",
                    query="",
                    headers=None,
                    body=None,
                )
            self.assertIs(propagated.exception, terminal)
            retire.assert_called_once_with(
                connection_id,
                expected_host_server_identity="remote_server",
                expected_hub_id="hub-remote",
                expected_certificate_fingerprint="sha256:" + "e" * 64,
            )
            self.assertNotIn(connection_id, runtime._remote_routes_cache)
            self.assertNotIn(connection_id, runtime._remote_routes_refreshed_at)
            self.assertIsNone(runtime._client_error)
            runtime.shutdown()

    def test_proxy_never_retires_transient_or_other_unauthorized_errors(self) -> None:
        failures = (
            SecurePeerError("peer_revoked", "untrusted status", 503),
            SecurePeerError("authorization_failed", "Denied", 401),
            SecurePeerError("transport_failed", "Peer is offline", 502),
        )
        for failure in failures:
            with self.subTest(failure=repr(failure)), tempfile.TemporaryDirectory() as temporary:
                runtime = SecurePeerRuntime(
                    Path(temporary) / "secure-peers",
                    server_identity="server_identity_test",
                    server_instance_id="server_instance_test",
                    display_name="Test server",
                )
                active = {
                    **self.outgoing_pairing(123),
                    "hub_id": "hub-remote",
                    "certificate_fingerprint": "sha256:" + "d" * 64,
                }
                with (
                    mock.patch.object(
                        runtime.client,
                        "list_connections",
                        return_value=[active],
                    ),
                    mock.patch.object(
                        runtime.client,
                        "proxy",
                        side_effect=failure,
                    ),
                    mock.patch.object(
                        runtime.client,
                        "retire_remote_revoked_connection",
                    ) as retire,
                    self.assertRaises(SecurePeerError) as propagated,
                ):
                    runtime.proxy(
                        active["connection_id"],
                        "GET",
                        "/v1/teams",
                        query="",
                        headers=None,
                        body=None,
                    )
                self.assertIs(propagated.exception, failure)
                retire.assert_not_called()
                runtime.shutdown()

    def test_inbox_only_proxy_rejects_agent_addresses_before_peer_io(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            connection_id = str(uuid.uuid4())
            attempts = (
                (
                    "POST",
                    "/v1/teams/team-1/network/mailbox",
                    "",
                    {"to": {"kind": "agent", "id": "agent-1"}},
                ),
                (
                    "POST",
                    "/v1/teams/team-1/network/requests",
                    "",
                    {
                        "to": {"kind": "server", "id": "server-2"},
                        "from_agent_id": "agent-1",
                    },
                ),
                (
                    "POST",
                    "/v1/teams/team-1/network/requests/request-1/replies",
                    "",
                    {"from_agent_id": "agent-1"},
                ),
                (
                    "POST",
                    "/v1/teams/team-1/network/messages",
                    "",
                    {"recipients": [{"kind": "agent", "id": "agent-1"}]},
                ),
                (
                    "GET",
                    "/v1/teams/team-1/network/mailbox",
                    "address_kind=agent&address_id=agent-1",
                    None,
                ),
            )
            for method, path, query, value in attempts:
                body = (
                    json.dumps(value).encode("utf-8")
                    if value is not None
                    else None
                )
                with (
                    self.subTest(method=method, path=path, body=value),
                    mock.patch.object(runtime.client, "list_connections") as listed,
                    mock.patch.object(runtime.client, "proxy") as peer_proxy,
                    self.assertRaises(SecurePeerError) as rejected,
                ):
                    runtime.proxy(
                        connection_id,
                        method,
                        path,
                        query=query,
                        headers={"content-type": "application/json"},
                        body=body,
                    )
                self.assertEqual(rejected.exception.code, "invalid_request")
                self.assertEqual(rejected.exception.status_code, 422)
                listed.assert_not_called()
                peer_proxy.assert_not_called()
            runtime.shutdown()

    def test_inbox_only_proxy_preflights_legacy_request_before_reply(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            active = self.outgoing_pairing(123)
            connection_id = active["connection_id"]
            legacy_parent = ProxyResponse(
                200,
                (("content-type", "application/json"),),
                json.dumps(
                    {
                        "item": {
                            "from": {"kind": "agent", "id": "agent-1"},
                            "to": {"kind": "server", "id": "server-2"},
                        }
                    }
                ).encode("utf-8"),
            )
            with (
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[active],
                ),
                mock.patch.object(
                    runtime.client,
                    "proxy",
                    return_value=legacy_parent,
                ) as peer_proxy,
                self.assertRaises(SecurePeerError) as rejected,
            ):
                runtime.proxy(
                    connection_id,
                    "POST",
                    "/v1/teams/team-1/network/requests/request-1/replies",
                    query="",
                    headers={"content-type": "application/json"},
                    body=json.dumps(
                        {
                            "body": "reply",
                            "idempotency_key": "reply-legacy-agent-1",
                        }
                    ).encode("utf-8"),
                )
            self.assertEqual(rejected.exception.code, "invalid_request")
            peer_proxy.assert_called_once_with(
                connection_id,
                "GET",
                "/v1/teams/team-1/network/requests/request-1",
                query="",
                headers={"accept": "application/json"},
                body=None,
            )
            runtime.shutdown()

    def test_proxy_keeps_local_trust_when_status_says_peer_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            active = {
                **self.outgoing_pairing(123),
                "hub_id": "hub-remote",
                "certificate_fingerprint": "sha256:" + "d" * 64,
            }
            failure = SecurePeerError(
                "peer_revoked",
                "Peer authentication is unavailable",
                401,
            )
            with (
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[active],
                ),
                mock.patch.object(
                    runtime.client,
                    "proxy",
                    side_effect=failure,
                ),
                mock.patch.object(
                    runtime.client,
                    "remote_revocation_status",
                    return_value={"status": "active"},
                ) as status,
                mock.patch.object(
                    runtime.client,
                    "retire_remote_revoked_connection",
                ) as retire,
                self.assertRaises(SecurePeerError) as propagated,
            ):
                runtime.proxy(
                    active["connection_id"],
                    "GET",
                    "/v1/teams",
                    query="",
                    headers=None,
                    body=None,
                )

            self.assertIs(propagated.exception, failure)
            status.assert_called_once_with(active["connection_id"])
            retire.assert_not_called()
            runtime.shutdown()

    def test_client_submit_uses_atomic_local_route_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            self.assertTrue(runtime.state_available())
            self.assertIsNone(runtime.state_error_code())
            connection_id = str(uuid.uuid4())
            source_route_id = str(uuid.uuid4())
            target_route_id = str(uuid.uuid4())
            request_id = str(uuid.uuid4())
            revision = "rev_" + "a" * 32
            expires_at = 2_000_000_000
            calls: list[dict] = []

            class Client:
                def submit_envelope(self, *_args, **_kwargs):
                    raise AssertionError("raw relay submit must not be used")

                def submit_envelope_from_published_route(
                    self, connection, **kwargs
                ):
                    calls.append({"connection": connection, **kwargs})
                    return {
                        "envelope_id": str(uuid.uuid4()),
                        "exchange_id": str(uuid.uuid4()),
                        "status": "queued",
                        "used_legs": 1,
                        "max_legs": 6,
                        "expires_at": expires_at,
                    }

            runtime.client = Client()
            snapshot = {
                "role": "client",
                "connection_id": connection_id,
                "source_server_identity": "server_identity_test",
                "source_chat_id": "chat-source",
                "source_route_id": source_route_id,
                "source_route_revision": revision,
                "target_server_identity": "server_remote",
                "target_route_id": target_route_id,
                "target_route_revision": "rev_" + "b" * 32,
                "action": "instruction",
            }
            published = {
                "connection_id": connection_id,
                "chat_id": "chat-source",
                "route_id": source_route_id,
                "revision": revision,
                "status": "active",
                "actions": ["instruction"],
            }
            with (
                mock.patch.object(
                    runtime, "remote_route_delivery_available", return_value=True
                ),
                mock.patch.object(runtime, "_client_delivery_ready", return_value=True),
                mock.patch.object(
                    runtime,
                    "_client_connection",
                    return_value={"connection_id": connection_id},
                ),
                mock.patch.object(
                    runtime, "_published_routes", return_value=[published]
                ),
            ):
                response = runtime.submit_remote_handoff(
                    snapshot,
                    body="hello",
                    action="instruction",
                    request_id=request_id,
                    expires_at=expires_at,
                    expected_used_legs=1,
                )
            self.assertEqual(response["used_legs"], 1)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["connection"], connection_id)
            self.assertEqual(calls[0]["source_route_id"], source_route_id)
            self.assertEqual(calls[0]["source_route_revision"], revision)
            self.assertEqual(calls[0]["source_chat_id"], "chat-source")
            self.assertEqual(calls[0]["action"], "instruction")
            runtime.shutdown()

    def test_corrupt_optional_state_is_quarantined_without_blocking_server(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "secure-peers"
            root.mkdir(mode=0o700)
            config = root / "host-config.json"
            config.write_text("not-json", encoding="utf-8")
            os.chmod(config, 0o600)

            runtime = SecurePeerRuntime(
                root,
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            status = runtime.status()
            self.assertFalse(runtime.state_available())
            self.assertEqual(
                runtime.state_error_code(), "secure_peer_state_unavailable"
            )
            self.assertFalse(status["host"]["available"])
            self.assertFalse(status["host"]["enabled"])
            self.assertIsNone(status["active_connection_id"])
            self.assertIn("safety validation", status["host"]["error"])
            self.assertFalse(runtime.remote_route_delivery_available())
            self.assertEqual(runtime.revoke_routes_for_chat("chat-local"), 0)
            with self.assertRaises(SecurePeerError) as raised:
                runtime.begin_pairing(
                    host="192.0.2.10",
                    port=7851,
                    expected_ca_fingerprint=None,
                    request_id="52e36f23-50ff-42c7-aec8-269e0419cb06",
                    display_name="Peer",
                    requested_scopes=["teamspace.read"],
                )
            self.assertEqual(raised.exception.code, "secure_peer_state_unavailable")
            runtime.shutdown()

    def test_pending_outbound_fences_route_chat_and_connection_retirement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
                agent_relay_enabled=True,
            )
            connection_id = str(uuid.uuid4())
            route_id = str(uuid.uuid4())
            revision = "rev_" + "a" * 32
            snapshot = {
                "version": 1,
                "role": "client",
                "connection_id": connection_id,
                "source_server_identity": "server_identity_test",
                "source_chat_id": "chat-source",
                "source_route_id": route_id,
                "source_route_revision": revision,
                "target_server_identity": "server_remote",
                "target_route_id": str(uuid.uuid4()),
                "target_route_revision": "rev_" + "b" * 32,
                "action": "instruction",
            }
            route = {
                "connection_id": connection_id,
                "chat_id": "chat-source",
                "route_id": route_id,
                "revision": revision,
                "status": "active",
                "actions": ["instruction"],
            }
            with mock.patch.object(runtime, "_published_routes", return_value=[route]):
                runtime.prepare_outbound_handoff(
                    request_id=str(uuid.uuid4()),
                    source_session_id="chat-source",
                    source_run_id="run-source",
                    snapshot=snapshot,
                    body="deliver me",
                    action="instruction",
                    expires_at=2_000_000_000,
                )
            with self.assertRaises(SecurePeerError) as chat_blocked:
                runtime.revoke_routes_for_chat("chat-source")
            self.assertEqual(chat_blocked.exception.code, "outbound_handoff_pending")
            with self.assertRaises(SecurePeerError) as route_blocked:
                runtime.revoke_route(
                    route_id=route_id,
                    expected_connection_id=connection_id,
                    expected_revision=revision,
                    idempotency_key=str(uuid.uuid4()),
                )
            self.assertEqual(route_blocked.exception.code, "outbound_handoff_pending")
            with self.assertRaises(SecurePeerError) as connection_blocked:
                runtime.deactivate_connection(
                    connection_id,
                    expected_host_server_identity="server_remote",
                    expected_hub_id="hub_remote",
                )
            self.assertEqual(
                connection_blocked.exception.code,
                "connection_delivery_pending",
            )
            replacement_id = str(uuid.uuid4())
            with (
                mock.patch.object(
                    runtime,
                    "_outgoing_for_pairing",
                    return_value={
                        "connection_id": replacement_id,
                        "host_server_identity": "server-replacement",
                        "hub_id": "hub-replacement",
                    },
                ),
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[
                        {"connection_id": connection_id, "active": True}
                    ],
                ),
                mock.patch.object(
                    runtime.client,
                    "set_active_connection",
                ) as set_active,
            ):
                with self.assertRaises(SecurePeerError) as switch_blocked:
                    runtime.activate_pairing(
                        str(uuid.uuid4()),
                        expected_connection_id=replacement_id,
                        expected_host_server_identity="server-replacement",
                        expected_hub_id="hub-replacement",
                    )
                self.assertEqual(
                    switch_blocked.exception.code,
                    "active_connection_conflict",
                )
                set_active.assert_not_called()
            runtime.shutdown()

    def test_begin_pairing_resumes_matching_persisted_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            outgoing = self.outgoing_pairing(123)
            with mock.patch.object(
                runtime.client,
                "begin_pairing",
                return_value=outgoing,
            ) as begin:
                result = runtime.begin_pairing(
                    host="192.0.2.20",
                    port=7851,
                    expected_ca_fingerprint=None,
                    request_id=str(uuid.uuid4()),
                    display_name="Test server",
                    requested_scopes=["teamspace.read"],
                )
            self.assertEqual(result["connection_id"], outgoing["connection_id"])
            self.assertTrue(begin.call_args.kwargs["resume_matching"])
            runtime.shutdown()

    def test_publishing_route_can_be_resolved_for_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            connection_id = str(uuid.uuid4())
            route_id = str(uuid.uuid4())
            revision = "rev_" + "8" * 32
            with mock.patch.object(
                runtime,
                "_published_routes",
                return_value=[{
                    "route_id": route_id,
                    "connection_id": connection_id,
                    "revision": revision,
                    "chat_id": "chat-publishing",
                    "status": "publishing",
                }],
            ):
                self.assertEqual(
                    runtime.route_local_chat(
                        route_id=route_id,
                        expected_connection_id=connection_id,
                        expected_revision=revision,
                    ),
                    "chat-publishing",
                )
            runtime.shutdown()

    def test_client_claim_prepare_linearizes_deactivate_and_forget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            connection_id = str(uuid.uuid4())
            entered = threading.Event()
            release = threading.Event()
            envelope = {
                "envelope_id": str(uuid.uuid4()),
                "request_id": str(uuid.uuid4()),
                "team_id": str(uuid.uuid4()),
                "source_peer_id": str(uuid.uuid4()),
                "source_server_identity": "server_remote",
                "source_route_id": str(uuid.uuid4()),
                "source_route_revision": "rev_" + "1" * 32,
                "target_peer_id": None,
                "target_server_identity": "server_identity_test",
                "target_route_id": str(uuid.uuid4()),
                "target_route_revision": "rev_" + "2" * 32,
                "action": "instruction",
                "kind": "instruction",
                "exchange_id": str(uuid.uuid4()),
                "parent_envelope_id": None,
                "parent_leg": None,
                "used_legs": 1,
                "max_legs": 6,
                "expires_at": 2_000_000_000,
                "body": {"message": "deliver"},
            }

            def claim(*_args, **_kwargs):
                entered.set()
                self.assertTrue(release.wait(5))
                return {"lease_token": "lease-token", "envelopes": [envelope]}

            claim_result: list[dict] = []
            retirement_errors: list[BaseException] = []
            with (
                mock.patch.object(
                    runtime, "remote_route_delivery_available", return_value=True
                ),
                mock.patch.object(
                    runtime.client,
                    "list_connections",
                    return_value=[{"connection_id": connection_id, "active": True}],
                ),
                mock.patch.object(runtime.client, "claim_inbox", side_effect=claim),
                mock.patch.object(
                    runtime,
                    "_resolve_claim_target",
                    return_value=("target-chat", envelope["team_id"]),
                ),
            ):
                claim_thread = threading.Thread(
                    target=lambda: claim_result.extend(
                        runtime.claim_deliveries_once(limit=1)
                    )
                )

                def deactivate() -> None:
                    try:
                        runtime.deactivate_connection(
                            connection_id,
                            expected_host_server_identity="server_remote",
                            expected_hub_id="hub_remote",
                        )
                    except BaseException as exc:
                        retirement_errors.append(exc)

                retirement_thread = threading.Thread(target=deactivate)
                claim_thread.start()
                self.assertTrue(entered.wait(5))
                retirement_thread.start()
                self.assertTrue(retirement_thread.is_alive())
                release.set()
                claim_thread.join(5)
                retirement_thread.join(5)

            self.assertEqual(len(claim_result), 1)
            self.assertEqual(len(retirement_errors), 1)
            self.assertIsInstance(retirement_errors[0], SecurePeerError)
            self.assertEqual(
                retirement_errors[0].code,
                "connection_delivery_pending",
            )
            with self.assertRaises(SecurePeerError) as forgetting:
                runtime.forget_connection(
                    connection_id,
                    expected_host_server_identity="server_remote",
                    expected_hub_id="hub_remote",
                    expected_certificate_fingerprint="sha256:" + "f" * 64,
                )
            self.assertEqual(forgetting.exception.code, "connection_delivery_pending")
            runtime.shutdown()

    def test_expired_prepared_delivery_is_terminalized_without_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = SecurePeerRuntime(
                Path(temporary) / "secure-peers",
                server_identity="server_identity_test",
                server_instance_id="server_instance_test",
                display_name="Test server",
            )
            envelope_id = "env_expired_prepared"
            runtime.delivery_ledger.prepare(
                {
                    "envelope_id": envelope_id,
                    "request_id": str(uuid.uuid4()),
                    "team_id": "team-test",
                    "source_peer_id": str(uuid.uuid4()),
                    "source_server_identity": "server-source",
                    "source_route_id": str(uuid.uuid4()),
                    "source_route_revision": "rev_" + "1" * 32,
                    "target_peer_id": None,
                    "target_server_identity": "server_identity_test",
                    "target_route_id": str(uuid.uuid4()),
                    "target_route_revision": "rev_" + "2" * 32,
                    "action": "instruction",
                    "kind": "instruction",
                    "exchange_id": str(uuid.uuid4()),
                    "parent_envelope_id": None,
                    "parent_leg": None,
                    "used_legs": 1,
                    "max_legs": 6,
                    "expires_at": 1,
                    "body": {"message": "expired"},
                },
                transport_role="client",
                connection_id=str(uuid.uuid4()),
                lease_token="lease." + "a" * 43,
                target_chat_id="chat-target",
            )
            self.assertEqual(runtime.recover_prepared_deliveries(), [])
            self.assertEqual(runtime.delivery(envelope_id)["state"], "failed")
            runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
