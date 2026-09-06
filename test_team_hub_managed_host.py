from __future__ import annotations

from dataclasses import replace
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from fastapi.testclient import TestClient

import agentsdock_team_hub.cli as team_hub_cli
from agentsdock_team_hub.cli import main as cli_main
from agentsdock_team_hub.database import MIGRATIONS, _statements
from agentsdock_team_hub.service import (
    MANAGED_SERVER_SESSION_SCOPE_KEY,
    create_app,
)
from agentsdock_team_hub.store import HubError, HubStore


HOST_A = "server-host-a-12345678"
HOST_B = "server-host-b-12345678"


class ManagedHostTests(unittest.TestCase):
    @staticmethod
    def run_rebase_until_crash(
        data_dir: Path,
        snapshot: Path,
        *,
        hub_id: str,
        operation_id: str,
        crash_point: str,
    ) -> subprocess.CompletedProcess[str]:
        script = r"""
import os
from pathlib import Path
import sys
from unittest import mock

from agentsdock_team_hub.store import HubStore

root = Path(sys.argv[1])
target = Path(sys.argv[2])
crash_point = sys.argv[5]
original_replace = os.replace

def replace_then_crash(source, destination):
    original_replace(source, destination)
    source_path = Path(source)
    destination_path = Path(destination)
    if (
        crash_point == "retired"
        and destination_path.name.startswith(".snapshot-rebase-")
    ):
        os._exit(81)
    if (
        crash_point == "published"
        and destination_path == target
        and source_path.name.startswith("snapshot_")
    ):
        os._exit(82)

with mock.patch("agentsdock_team_hub.store.os.replace", side_effect=replace_then_crash):
    HubStore.rebase_maintenance_snapshot(
        root,
        target,
        expected_host_identity=sys.argv[6],
        expected_hub_id=sys.argv[3],
        expected_operation_id=sys.argv[4],
    )
sys.exit(10)
"""
        return subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(data_dir),
                str(snapshot),
                hub_id,
                operation_id,
                crash_point,
                HOST_A,
            ],
            cwd=Path(__file__).parent,
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def run_restore_until_crash(
        data_dir: Path,
        snapshot: Path,
        *,
        hub_id: str,
        operation_id: str,
        crash_point: str,
    ) -> subprocess.CompletedProcess[str]:
        script = r"""
import os
from pathlib import Path
import sys
from unittest import mock

from agentsdock_team_hub.store import HubStore

data_dir = Path(sys.argv[1])
snapshot = Path(sys.argv[2])
hub_id = sys.argv[3]
operation_id = sys.argv[4]
crash_point = sys.argv[5]
original_replace = os.replace
original_write_journal = HubStore._write_restore_transaction_journal

def replace_then_crash(source, target):
    original_replace(source, target)
    source_path = Path(source)
    target_path = Path(target)
    if (
        crash_point == "retire"
        and target_path.parent.name == "previous"
        and target_path.name == "team-hub.sqlite3"
    ):
        os._exit(71)
    if (
        crash_point == "install"
        and target_path.parent == data_dir
        and target_path.name == "access-token-signing.key"
        and source_path.parent.name.startswith(".restore-")
    ):
        os._exit(72)

def write_journal_then_crash(root, journal):
    if crash_point == "prejournal" and journal["state"] == "prepared":
        os._exit(75)
    original_write_journal(root, journal)
    if crash_point == "commit" and journal["state"] == "committed":
        os._exit(73)

with mock.patch(
    "agentsdock_team_hub.store.os.replace", side_effect=replace_then_crash
), mock.patch.object(
    HubStore,
    "_write_restore_transaction_journal",
    side_effect=write_journal_then_crash,
):
    HubStore.restore_maintenance_snapshot(
        data_dir,
        snapshot,
        expected_host_identity=sys.argv[6],
        expected_hub_id=hub_id,
        expected_operation_id=operation_id,
    )
sys.exit(10)
"""
        return subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(data_dir),
                str(snapshot),
                hub_id,
                operation_id,
                crash_point,
                HOST_A,
            ],
            cwd=Path(__file__).parent,
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def run_restore_cleanup_until_crash(
        data_dir: Path,
        *,
        target_name: str,
    ) -> subprocess.CompletedProcess[str]:
        script = r"""
import os
from pathlib import Path
import sys
from unittest import mock

from agentsdock_team_hub.store import HubStore

data_dir = Path(sys.argv[1])
target_name = sys.argv[2]
original_unlink = Path.unlink

def unlink_then_crash(path, *args, **kwargs):
    result = original_unlink(path, *args, **kwargs)
    if path.parent == data_dir and path.name == target_name:
        os._exit(76 if target_name == ".restore-transaction.json" else 77)
    return result

with mock.patch.object(Path, "unlink", side_effect=unlink_then_crash, autospec=True):
    with HubStore.maintenance_control_lock(data_dir):
        pass
raise SystemExit(10)
"""
        return subprocess.run(
            [sys.executable, "-c", script, str(data_dir), target_name],
            cwd=Path(__file__).parent,
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def run_recovery_until_crash(data_dir: Path) -> subprocess.CompletedProcess[str]:
        script = r"""
import os
from pathlib import Path
import sys
from unittest import mock

from agentsdock_team_hub.store import HubStore

data_dir = Path(sys.argv[1])
original_replace = os.replace

def replace_then_crash(source, target):
    original_replace(source, target)
    source_path = Path(source)
    target_path = Path(target)
    if (
        source_path.parent.name == "previous"
        and target_path.parent == data_dir
        and target_path.name == "team-hub.sqlite3"
    ):
        os._exit(74)

with mock.patch(
    "agentsdock_team_hub.store.os.replace", side_effect=replace_then_crash
):
    HubStore(data_dir, managed_host_identity=sys.argv[2])
sys.exit(10)
"""
        return subprocess.run(
            [sys.executable, "-c", script, str(data_dir), HOST_A],
            cwd=Path(__file__).parent,
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def run_reactivation_restore_until_fence_crash(
        data_dir: Path,
        snapshot: Path,
        *,
        hub_id: str,
        operation_id: str,
    ) -> subprocess.CompletedProcess[str]:
        script = r"""
import os
from pathlib import Path
import sys
from unittest import mock

from agentsdock_team_hub.store import HubStore

data_dir = Path(sys.argv[1])

def crash_before_journal(*_args, **_kwargs):
    os._exit(76)

with mock.patch.object(
    HubStore,
    "_write_restore_transaction_journal",
    side_effect=crash_before_journal,
):
    HubStore.restore_host_reactivation_snapshot(
        data_dir,
        Path(sys.argv[2]),
        expected_host_identity=sys.argv[4],
        expected_hub_id=sys.argv[3],
        expected_operation_id=sys.argv[5],
    )
sys.exit(10)
"""
        return subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(data_dir),
                str(snapshot),
                hub_id,
                HOST_A,
                operation_id,
            ],
            cwd=Path(__file__).parent,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_managed_server_mount_health_requires_issuable_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            application = create_app(
                Path(temporary) / "hub",
                managed_host_identity=HOST_A,
                managed_server_instance_id="managed-instance-a",
            )

            async def managed_server_mount(scope, receive, send):
                scoped = dict(scope)
                scoped[MANAGED_SERVER_SESSION_SCOPE_KEY] = True
                await application(scoped, receive, send)

            store = application.state.store
            with TestClient(managed_server_mount, base_url="http://localhost") as client:
                health = client.get("/v1/health")
                self.assertEqual(health.status_code, 200, health.text)
                self.assertFalse(health.json()["server_session_available"])

                proof = store.bootstrap_proof_path.read_text().strip()
                store.bootstrap(
                    proof,
                    "owner@example.com",
                    "Owner",
                    "Owner Mac",
                )
                health = client.get("/v1/health")
                self.assertEqual(health.status_code, 200, health.text)
                self.assertTrue(health.json()["server_session_available"])

                connection = store.connect()
                try:
                    connection.execute(
                        """
                        UPDATE memberships SET status='suspended'
                        WHERE principal_id='service_managed_server'
                        """
                    )
                finally:
                    connection.close()
                self.assertTrue(store.health()["bootstrapped"])
                with self.assertRaises(HubError):
                    store.managed_server_claims()

                health = client.get("/v1/health")
                self.assertEqual(health.status_code, 200, health.text)
                self.assertFalse(health.json()["server_session_available"])

    def test_managed_host_display_name_migrates_node_and_principal_idempotently(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            legacy = HubStore(
                data_dir,
                managed_host_identity=HOST_A,
                managed_server_instance_id="managed-instance-a",
            )
            proof = legacy.bootstrap_proof_path.read_text().strip()
            bundle = legacy.bootstrap(
                proof,
                "owner@example.com",
                "Owner",
                "Owner Mac",
            )
            team_id = bundle["teams"][0]["id"]

            connection = legacy.connect()
            try:
                original = connection.execute(
                    """
                    SELECT n.id,n.principal_id,n.display_name,n.last_seen_at,
                           p.display_name AS principal_display_name,p.updated_at
                    FROM nodes AS n
                    JOIN principals AS p ON p.id=n.principal_id
                    WHERE n.server_identity=?
                    """,
                    (HOST_A,),
                ).fetchone()
            finally:
                connection.close()
            self.assertIsNotNone(original)
            self.assertEqual(original["display_name"], "Team Hub host")
            self.assertEqual(original["principal_display_name"], "Team Hub host")

            migration_timestamp = 2_000_000_000
            migrated = HubStore(
                data_dir,
                now=migration_timestamp,
                managed_host_identity=HOST_A,
                managed_server_instance_id="managed-instance-a",
                managed_host_display_name="  Sonic  ",
            )
            claims = migrated.managed_server_claims()
            projection = migrated.get_network(claims, team_id)
            host = next(server for server in projection["servers"] if server["is_host"])
            self.assertEqual(host["display_name"], "Sonic")
            self.assertEqual(
                migrated.get_network_server(claims, team_id, host["id"])["server"],
                host,
            )

            connection = migrated.connect()
            try:
                first = connection.execute(
                    """
                    SELECT n.id,n.principal_id,n.display_name,n.last_seen_at,
                           p.display_name AS principal_display_name,p.updated_at
                    FROM nodes AS n
                    JOIN principals AS p ON p.id=n.principal_id
                    WHERE n.server_identity=?
                    """,
                    (HOST_A,),
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual(first["id"], original["id"])
            self.assertEqual(first["principal_id"], original["principal_id"])
            self.assertEqual(first["display_name"], "Sonic")
            self.assertEqual(first["principal_display_name"], "Sonic")
            self.assertEqual(first["last_seen_at"], migration_timestamp)
            self.assertEqual(first["updated_at"], migration_timestamp)

            HubStore(
                data_dir,
                now=migration_timestamp + 1,
                managed_host_identity=HOST_A,
                managed_server_instance_id="managed-instance-a",
                managed_host_display_name="Sonic",
            )
            connection = migrated.connect()
            try:
                second = connection.execute(
                    """
                    SELECT n.display_name,n.last_seen_at,
                           p.display_name AS principal_display_name,p.updated_at
                    FROM nodes AS n
                    JOIN principals AS p ON p.id=n.principal_id
                    WHERE n.server_identity=?
                    """,
                    (HOST_A,),
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual(dict(second), {
                "display_name": "Sonic",
                "last_seen_at": migration_timestamp,
                "principal_display_name": "Sonic",
                "updated_at": migration_timestamp,
            })

    def test_managed_server_session_is_distinct_host_bound_and_write_capable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(
                data_dir,
                managed_host_identity=HOST_A,
                managed_server_instance_id="managed-instance-a",
            )
            with self.assertRaises(HubError) as unavailable:
                store.managed_server_claims()
            self.assertEqual(unavailable.exception.code, "server_session_unavailable")

            proof = store.bootstrap_proof_path.read_text().strip()
            owner_bundle = store.bootstrap(
                proof,
                "owner@example.com",
                "Owner",
                "Owner Mac",
            )
            team_id = owner_bundle["teams"][0]["id"]
            claims = store.managed_server_claims()
            local_mail_claims = store.local_agent_mail_claims(team_id)

            self.assertEqual(claims.principal_id, "service_managed_server")
            self.assertEqual(claims.auth_kind, "managed_server")
            self.assertEqual(claims.team_id, team_id)
            self.assertEqual(
                claims.scopes,
                frozenset({"teamspace.read", "teamspace.write"}),
            )
            self.assertNotEqual(claims.principal_id, local_mail_claims.principal_id)
            self.assertNotEqual(claims.auth_kind, local_mail_claims.auth_kind)

            session = store.session_snapshot(claims)
            self.assertEqual(session["principal"]["id"], "service_managed_server")
            self.assertEqual(session["principal"]["kind"], "service")
            self.assertIsNone(session["principal"]["email"])
            self.assertEqual(session["teams"][0]["role"], "automation")

            network = store.get_network(claims, team_id)
            host = next(server for server in network["servers"] if server["is_host"])
            self.assertTrue(host["owned_by_caller"])
            agent = store.register_network_agent(
                claims,
                team_id,
                {
                    "external_agent_id": "managed-server-agent",
                    "backend": "codex",
                    "display_name": "Managed server agent",
                    "idempotency_key": "managed-server-agent-register-0001",
                },
            )["agent"]
            with self.assertRaises(HubError) as retired_agent_author:
                store.create_network_mailbox_item(
                    claims,
                    team_id,
                    {
                        "to": {"kind": "server", "id": host["id"]},
                        "from_agent_id": agent["id"],
                        "body": "Managed server mailbox write",
                        "body_format": "plain",
                        "idempotency_key": "managed-server-mailbox-0001",
                    },
                )
            self.assertEqual(retired_agent_author.exception.code, "invalid_request")

            bulletin = store.create_network_bulletin_post(
                claims,
                team_id,
                {
                    "body": "Managed server bulletin",
                    "body_format": "plain",
                    "reply_to_post_id": None,
                    "idempotency_key": "managed-server-bulletin-0001",
                },
            )["post"]
            self.assertEqual(bulletin["author"]["kind"], "server")
            self.assertEqual(bulletin["author"]["id"], host["id"])

            connection = store.connect()
            try:
                board_id = connection.execute(
                    "SELECT channel_id FROM network_boards WHERE team_id=?",
                    (team_id,),
                ).fetchone()["channel_id"]
                actor_rows = connection.execute(
                    """
                    SELECT p.kind,s.service_identifier,m.role,m.status
                    FROM principals AS p
                    JOIN service_accounts AS s ON s.principal_id=p.id
                    JOIN memberships AS m ON m.principal_id=p.id
                    WHERE p.id=? AND m.team_id=?
                    """,
                    (claims.principal_id, team_id),
                ).fetchall()
                self.assertEqual(
                    [tuple(row) for row in actor_rows],
                    [
                        (
                            "service",
                            "agentsdock.team-hub.managed-server",
                            "automation",
                            "active",
                        )
                    ],
                )
                rate_subjects = {
                    row["subject_key"]
                    for row in connection.execute(
                        "SELECT subject_key FROM rate_limit_buckets WHERE team_id=?",
                        (team_id,),
                    )
                }
                self.assertEqual(
                    rate_subjects,
                    {"managed-server:service_managed_server"},
                )
                host_principal_id = connection.execute(
                    "SELECT principal_id FROM nodes WHERE id=?",
                    (host["id"],),
                ).fetchone()["principal_id"]
                connection.execute(
                    """
                    INSERT INTO principals(
                        id,kind,scope_team_id,display_name,status,
                        created_at,updated_at
                    ) VALUES (?,'service',NULL,?,'active',?,?)
                    """,
                    ("service_spoof_actor", "Spoof actor", 1_800_000_000, 1_800_000_000),
                )
                connection.execute(
                    """
                    INSERT INTO service_accounts(
                        principal_id,service_identifier,created_at
                    ) VALUES (?,?,?)
                    """,
                    ("service_spoof_actor", "agentsdock.test.spoof", 1_800_000_000),
                )
                connection.execute(
                    """
                    INSERT INTO memberships(
                        id,team_id,principal_id,role,status,
                        invited_by_principal_id,created_at,updated_at
                    ) VALUES (?,?,?,'automation','active',NULL,?,?)
                    """,
                    (
                        "membership_spoof_actor",
                        team_id,
                        "service_spoof_actor",
                        1_800_000_000,
                        1_800_000_000,
                    ),
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "network mailbox sender is not authorized",
                ):
                    connection.execute(
                        """
                        INSERT INTO network_mailbox_items(
                            id,team_id,kind,sender_kind,sender_principal_id,
                            sender_node_id,sender_agent_id,
                            recipient_kind,recipient_principal_id,
                            recipient_node_id,recipient_agent_id,
                            root_request_item_id,body_format,body,
                            idempotency_key,created_at,expires_at
                        ) VALUES (?,?,'message','server',?,?,NULL,
                                  'server',?,?,NULL,NULL,'plain',?,?,?,NULL)
                        """,
                        (
                            "network_item_spoof_actor",
                            team_id,
                            "service_spoof_actor",
                            host["id"],
                            host_principal_id,
                            host["id"],
                            "spoof",
                            hashlib.sha256(b"spoof").digest(),
                            1_800_000_000,
                        ),
                    )
            finally:
                connection.close()

            store.create_message(
                claims,
                str(board_id),
                {
                    "kind": "post",
                    "body": "Managed server generic channel write",
                    "body_format": "plain",
                    "thread_root_message_id": None,
                    "parent_message_id": None,
                    "idempotency_key": "managed-server-channel-0001",
                },
            )

            invalid_claims = (
                replace(claims, principal_id="service_local_control"),
                replace(claims, session_id="managed_server_session_wrong"),
                replace(claims, jti="managed_server_wrong"),
                replace(claims, scopes=frozenset({"teamspace.read"})),
                replace(claims, peer_id="00000000-0000-4000-8000-000000000000"),
                replace(claims, expires_at=0),
                replace(claims, team_id="team_wrong"),
            )
            for invalid in invalid_claims:
                with self.subTest(invalid=invalid):
                    with self.assertRaises(HubError) as denied:
                        store.session_snapshot(invalid)
                    self.assertEqual(denied.exception.code, "authentication_required")

            connection = store.connect()
            try:
                connection.execute(
                    "UPDATE nodes SET status='offline' WHERE id=?",
                    (host["id"],),
                )
            finally:
                connection.close()
            with self.assertRaises(HubError) as offline:
                store.session_snapshot(claims)
            self.assertEqual(offline.exception.code, "authentication_required")

            reopened = HubStore(
                data_dir,
                managed_host_identity=HOST_A,
                managed_server_instance_id="managed-instance-b",
            )
            self.assertEqual(
                reopened.managed_server_claims().principal_id,
                "service_managed_server",
            )

    @staticmethod
    def downgrade_database_to_schema5(database_path: Path) -> None:
        connection = sqlite3.connect(database_path, isolation_level=None)
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("BEGIN IMMEDIATE")
            for trigger in (
                "network_agents_limit_per_server",
                "network_bulletin_body_limit_on_insert",
                "network_bulletin_body_limit_on_update",
                "human_admin_page_device_session_insert",
                "human_admin_page_invitation_insert",
                "human_admin_page_membership_insert",
                "human_admin_page_entries_immutable",
                "human_admin_page_entries_cannot_be_deleted",
            ):
                connection.execute(f"DROP TRIGGER {trigger}")
            for index in (
                "device_sessions_human_created_id_idx",
                "invitations_pending_team_created_id_idx",
                "memberships_active_team_created_principal_idx",
                "memberships_manageable_team_created_principal_idx",
            ):
                connection.execute(f"DROP INDEX {index}")
            for table in (
                "network_content_deletions",
                "human_admin_page_entries",
                "team_attachment_cleanup_queue",
                "team_skill_versions",
                "team_attachments",
                "team_message_recipients",
                "team_messages",
                "team_skills",
                "network_passive_requests",
                "network_deliveries",
                "network_mailbox_items",
                "network_boards",
                "network_peer_bindings",
            ):
                connection.execute(f"DROP TABLE {table}")
            connection.execute("DELETE FROM schema_migrations WHERE version > 5")
            connection.execute("PRAGMA user_version = 5")
            connection.execute("COMMIT")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            connection.close()

    @staticmethod
    def downgrade_database_to_schema4(
        database_path: Path,
        *,
        update_version_ledger: bool = True,
    ) -> None:
        connection = sqlite3.connect(database_path, isolation_level=None)
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DROP TRIGGER network_agents_limit_per_server")
            connection.execute("DROP TRIGGER network_bulletin_body_limit_on_insert")
            connection.execute("DROP TRIGGER network_bulletin_body_limit_on_update")
            for trigger in (
                "human_admin_page_device_session_insert",
                "human_admin_page_invitation_insert",
                "human_admin_page_membership_insert",
                "human_admin_page_entries_immutable",
                "human_admin_page_entries_cannot_be_deleted",
            ):
                connection.execute(f"DROP TRIGGER {trigger}")
            for index in (
                "device_sessions_human_created_id_idx",
                "invitations_pending_team_created_id_idx",
                "memberships_active_team_created_principal_idx",
                "memberships_manageable_team_created_principal_idx",
            ):
                connection.execute(f"DROP INDEX {index}")
            for table in (
                "network_content_deletions",
                "human_admin_page_entries",
                "team_attachment_cleanup_queue",
                "team_skill_versions",
                "team_attachments",
                "team_message_recipients",
                "team_messages",
                "team_skills",
                "network_passive_requests",
                "network_deliveries",
                "network_mailbox_items",
                "network_boards",
                "network_peer_bindings",
            ):
                connection.execute(f"DROP TABLE {table}")
            for trigger in (
                "bootstrap_delegation_is_immutable",
                "bootstrap_delegations_cannot_be_deleted",
                "bootstrap_delegation_matches_claim_expiry",
                "bootstrap_delegation_matches_hub",
            ):
                connection.execute(f"DROP TRIGGER {trigger}")
            connection.execute("DROP TABLE bootstrap_delegations")
            if update_version_ledger:
                connection.execute("DELETE FROM schema_migrations WHERE version > 4")
                connection.execute("PRAGMA user_version = 4")
            connection.execute("COMMIT")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            connection.close()

    @classmethod
    def make_schema4_snapshot(
        cls,
        store: HubStore,
        *,
        operation_id: str,
    ) -> Path:
        snapshot = store.maintenance_snapshot_and_fence(
            "server-update",
            operation_id=operation_id,
        )
        snapshot_database = snapshot / "team-hub.sqlite3"
        cls.downgrade_database_to_schema4(snapshot_database)
        manifest_path = snapshot / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["schema_version"] = 4
        manifest["database_sha256"] = hashlib.sha256(
            snapshot_database.read_bytes()
        ).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        )
        cls.rebind_snapshot_fence_digest(store, snapshot)
        cls.downgrade_database_to_schema4(store.database_path)
        return snapshot

    @staticmethod
    def rebind_snapshot_fence_digest(store: HubStore, snapshot: Path) -> None:
        """Keep an intentionally rewritten fixture bound to its test fence."""

        marker = json.loads(store.maintenance_fence_path.read_text())
        marker["snapshot_manifest_sha256"] = hashlib.sha256(
            (snapshot / "manifest.json").read_bytes()
        ).hexdigest()
        store.maintenance_fence_path.write_text(
            json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n"
        )
        store.maintenance_fence_path.chmod(0o600)

    def test_concurrent_first_bind_has_one_winner_and_foreign_copy_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"

            def bind(identity: str) -> tuple[str, str]:
                try:
                    store = HubStore(data_dir, managed_host_identity=identity)
                    return "accepted", store.hub_id
                except RuntimeError:
                    return "rejected", ""

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(bind, (HOST_A, HOST_B)))
            self.assertEqual(sorted(result[0] for result in results), ["accepted", "rejected"])
            winner = HOST_A if results[0][0] == "accepted" else HOST_B
            winner_store = HubStore(data_dir, managed_host_identity=winner)

            connection = winner_store.connect()
            try:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                binding = connection.execute(
                    "SELECT hub_id, server_identity FROM managed_host_bindings"
                ).fetchone()
                self.assertEqual(binding["hub_id"], winner_store.hub_id)
                self.assertEqual(binding["server_identity"], winner)
            finally:
                connection.close()

            copied = Path(temporary) / "copied-hub"
            shutil.copytree(data_dir, copied)
            before = {
                path.relative_to(copied).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in copied.rglob("*")
                if path.is_file()
            }
            foreign = HOST_B if winner == HOST_A else HOST_A
            with self.assertRaisesRegex(RuntimeError, "different AgentsServer"):
                HubStore(copied, managed_host_identity=foreign)
            after = {
                path.relative_to(copied).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in copied.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)

            with self.assertRaisesRegex(RuntimeError, "cannot be served standalone"):
                create_app(data_dir)
            control = HubStore(data_dir, allow_bound_control=True)
            self.assertEqual(control.hub_id, winner_store.hub_id)

    def test_snapshot_is_verified_bounded_and_preserves_active_proofs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            bootstrap_proof = store.bootstrap_proof_path.read_bytes()
            signing_key = store.signing_key_path.read_bytes()

            first = store.maintenance_snapshot("pre-update", keep=3)
            manifest = json.loads((first / "manifest.json").read_text())
            self.assertEqual(manifest["hub_id"], store.hub_id)
            self.assertEqual(manifest["host_server_identity"], HOST_A)
            self.assertEqual(
                (first / "access-token-signing.key").read_bytes(), signing_key
            )
            self.assertEqual(
                (first / "proofs" / "bootstrap-owner.proof").read_bytes(),
                bootstrap_proof,
            )
            backup = sqlite3.connect(first / "team-hub.sqlite3")
            try:
                self.assertEqual(backup.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(
                    backup.execute(
                        "SELECT server_identity FROM managed_host_bindings"
                    ).fetchone()[0],
                    HOST_A,
                )
            finally:
                backup.close()
            self.assertEqual(store.bootstrap_proof_path.read_bytes(), bootstrap_proof)

            proof = bootstrap_proof.decode("ascii").strip()
            store.bootstrap(proof, "owner@example.com", "Owner", "Owner Mac")
            recovery_path = store.issue_device_recovery(
                "owner@example.com", "Recovered Mac"
            )
            recovery_bytes = recovery_path.read_bytes()
            latest = store.maintenance_snapshot("pre-restart", keep=3)
            self.assertEqual(
                (latest / "proofs" / recovery_path.name).read_bytes(),
                recovery_bytes,
            )
            for index in range(3):
                store.maintenance_snapshot(f"bounded-{index}", keep=3)
            generations = list((data_dir / "maintenance-backups").glob("snapshot_*"))
            self.assertEqual(len(generations), 3)

    def test_snapshot_preserves_fenced_generation_and_cleans_abandoned_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            fenced = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id="update-protected",
                keep=3,
            )
            backups = data_dir / "maintenance-backups"
            abandoned = backups / ".snapshot_00000000000000000001_0123456789abcdef.tmp"
            abandoned.mkdir(mode=0o700)
            orphan = abandoned / "orphan.bin"
            orphan.write_bytes(b"unfinished")
            orphan.chmod(0o600)
            unrelated = backups / ".snapshot_not_a_generation.tmp"
            unrelated.mkdir(mode=0o700)

            for index in range(4):
                store.maintenance_snapshot(f"forced-restart-{index}", keep=3)

            self.assertTrue(fenced.is_dir())
            self.assertFalse(abandoned.exists())
            self.assertTrue(unrelated.is_dir())
            generations = list(backups.glob("snapshot_*"))
            self.assertEqual(len(generations), 4)
            self.assertIn(fenced, generations)

    def test_snapshot_restores_ready_and_resumable_attachment_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            proof = store.bootstrap_proof_path.read_text().strip()
            bundle = store.bootstrap(
                proof,
                "owner@example.com",
                "Owner",
                "Owner Mac",
            )
            claims = store.verify_access(bundle["access_token"])
            team_id = bundle["teams"][0]["id"]

            ready_bytes = b"ready attachment generation"
            ready_digest = hashlib.sha256(ready_bytes).hexdigest()
            ready = store.declare_team_attachment(
                claims,
                team_id,
                {
                    "file_name": "ready.txt",
                    "media_type": "text/plain",
                    "byte_size": len(ready_bytes),
                    "sha256": ready_digest,
                    "idempotency_key": "snapshot-ready-attachment",
                },
            )["attachment"]
            store.write_team_attachment_chunk(
                claims,
                team_id,
                ready["id"],
                offset=0,
                total=len(ready_bytes),
                data=ready_bytes,
            )

            pending_bytes = b"resumable attachment generation"
            pending_digest = hashlib.sha256(pending_bytes).hexdigest()
            pending = store.declare_team_attachment(
                claims,
                team_id,
                {
                    "file_name": "pending.txt",
                    "media_type": "text/plain",
                    "byte_size": len(pending_bytes),
                    "sha256": pending_digest,
                    "idempotency_key": "snapshot-pending-attachment",
                },
            )["attachment"]
            prefix = pending_bytes[:11]
            store.write_team_attachment_chunk(
                claims,
                team_id,
                pending["id"],
                offset=0,
                total=len(pending_bytes),
                data=prefix,
            )

            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id="update-attachments",
            )
            manifest = json.loads((snapshot / "manifest.json").read_text())
            self.assertEqual(manifest["format"], 2)
            self.assertEqual(manifest["attachments"]["file_count"], 2)
            self.assertEqual(
                manifest["attachments"]["byte_size"],
                len(ready_bytes) + len(prefix),
            )
            snapshot_ready = snapshot / "attachments" / ready_digest[:2] / ready_digest
            snapshot_pending = (
                snapshot / "attachments" / "uploads" / f"{pending['id']}.part"
            )
            self.assertEqual(snapshot_ready.read_bytes(), ready_bytes)
            self.assertEqual(snapshot_pending.read_bytes(), prefix)
            HubStore.verify_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=store.hub_id,
                expected_operation_id="update-attachments",
            )

            live_ready = data_dir / "attachments" / ready_digest[:2] / ready_digest
            live_pending = data_dir / "attachments" / "uploads" / f"{pending['id']}.part"
            replacement_ready = live_ready.with_name(f".{live_ready.name}.replacement")
            replacement_ready.write_bytes(b"x" * len(ready_bytes))
            replacement_ready.chmod(0o600)
            os.replace(replacement_ready, live_ready)
            live_pending.write_bytes(b"y" * len(prefix))
            extra = data_dir / "attachments" / "uploads" / "newer.part"
            extra.write_bytes(b"newer generation")
            extra.chmod(0o600)

            HubStore.restore_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=store.hub_id,
                expected_operation_id="update-attachments",
            )
            self.assertEqual(live_ready.read_bytes(), ready_bytes)
            self.assertEqual(live_pending.read_bytes(), prefix)
            self.assertFalse(extra.exists())
            connection = sqlite3.connect(data_dir / "team-hub.sqlite3")
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT state,received_bytes FROM team_attachments WHERE id=?",
                        (ready["id"],),
                    ).fetchone(),
                    ("ready", len(ready_bytes)),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT state,received_bytes FROM team_attachments WHERE id=?",
                        (pending["id"],),
                    ).fetchone(),
                    ("uploading", len(prefix)),
                )
            finally:
                connection.close()

    def test_snapshot_rejects_missing_attachment_before_live_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            proof = store.bootstrap_proof_path.read_text().strip()
            bundle = store.bootstrap(
                proof,
                "owner@example.com",
                "Owner",
                "Owner Mac",
            )
            claims = store.verify_access(bundle["access_token"])
            team_id = bundle["teams"][0]["id"]
            payload = b"must remain available"
            digest = hashlib.sha256(payload).hexdigest()
            attachment = store.declare_team_attachment(
                claims,
                team_id,
                {
                    "file_name": "required.txt",
                    "media_type": "text/plain",
                    "byte_size": len(payload),
                    "sha256": digest,
                    "idempotency_key": "snapshot-required-attachment",
                },
            )["attachment"]
            store.write_team_attachment_chunk(
                claims,
                team_id,
                attachment["id"],
                offset=0,
                total=len(payload),
                data=payload,
            )
            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id="update-missing-attachment",
            )
            live_path = data_dir / "attachments" / digest[:2] / digest
            live_before = {
                "database": store.database_path.read_bytes(),
                "key": store.signing_key_path.read_bytes(),
                "fence": store.maintenance_fence_path.read_bytes(),
                "attachment": live_path.read_bytes(),
            }
            (snapshot / "attachments" / digest[:2] / digest).unlink()

            with self.assertRaisesRegex(RuntimeError, "attachment tree"):
                HubStore.verify_maintenance_snapshot(
                    data_dir,
                    snapshot,
                    expected_host_identity=HOST_A,
                    expected_hub_id=store.hub_id,
                    expected_operation_id="update-missing-attachment",
                )
            self.assertEqual(store.database_path.read_bytes(), live_before["database"])
            self.assertEqual(store.signing_key_path.read_bytes(), live_before["key"])
            self.assertEqual(store.maintenance_fence_path.read_bytes(), live_before["fence"])
            self.assertEqual(live_path.read_bytes(), live_before["attachment"])

    def test_attachment_directory_rolls_back_after_restore_install_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            proof = store.bootstrap_proof_path.read_text().strip()
            bundle = store.bootstrap(
                proof,
                "owner@example.com",
                "Owner",
                "Owner Mac",
            )
            claims = store.verify_access(bundle["access_token"])
            team_id = bundle["teams"][0]["id"]
            payload = b"snapshot attachment"
            digest = hashlib.sha256(payload).hexdigest()
            attachment = store.declare_team_attachment(
                claims,
                team_id,
                {
                    "file_name": "rollback.txt",
                    "media_type": "text/plain",
                    "byte_size": len(payload),
                    "sha256": digest,
                    "idempotency_key": "snapshot-rollback-attachment",
                },
            )["attachment"]
            store.write_team_attachment_chunk(
                claims,
                team_id,
                attachment["id"],
                offset=0,
                total=len(payload),
                data=payload,
            )
            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id="update-attachment-rollback",
            )
            live_path = data_dir / "attachments" / digest[:2] / digest
            changed = b"changed attachment!"
            self.assertEqual(len(changed), len(payload))
            replacement = live_path.with_name(f".{live_path.name}.candidate")
            replacement.write_bytes(changed)
            replacement.chmod(0o600)
            os.replace(replacement, live_path)
            live_before = {
                "database": store.database_path.read_bytes(),
                "key": store.signing_key_path.read_bytes(),
                "fence": store.maintenance_fence_path.read_bytes(),
                "attachment": live_path.read_bytes(),
            }
            original_write_journal = HubStore._write_restore_transaction_journal

            def fail_commit(path: Path, journal: dict[str, object]) -> None:
                if journal["state"] == "committed":
                    raise OSError("forced restore commit failure")
                original_write_journal(path, journal)

            with mock.patch.object(
                HubStore,
                "_write_restore_transaction_journal",
                side_effect=fail_commit,
            ):
                with self.assertRaisesRegex(OSError, "forced restore commit failure"):
                    HubStore.restore_maintenance_snapshot(
                        data_dir,
                        snapshot,
                        expected_host_identity=HOST_A,
                        expected_hub_id=store.hub_id,
                        expected_operation_id="update-attachment-rollback",
                    )
            self.assertEqual(store.database_path.read_bytes(), live_before["database"])
            self.assertEqual(store.signing_key_path.read_bytes(), live_before["key"])
            self.assertEqual(store.maintenance_fence_path.read_bytes(), live_before["fence"])
            self.assertEqual(live_path.read_bytes(), live_before["attachment"])
            self.assertEqual(list(data_dir.glob(".restore-*")), [])

    def test_ready_snapshot_uses_hardlink_but_partial_upload_is_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            proof = store.bootstrap_proof_path.read_text().strip()
            bundle = store.bootstrap(
                proof,
                "owner@example.com",
                "Owner",
                "Owner Mac",
            )
            claims = store.verify_access(bundle["access_token"])
            team_id = bundle["teams"][0]["id"]

            ready_bytes = b"immutable ready attachment"
            ready_digest = hashlib.sha256(ready_bytes).hexdigest()
            ready = store.declare_team_attachment(
                claims,
                team_id,
                {
                    "file_name": "ready.txt",
                    "media_type": "text/plain",
                    "byte_size": len(ready_bytes),
                    "sha256": ready_digest,
                    "idempotency_key": "hardlink-ready-attachment",
                },
            )["attachment"]
            store.write_team_attachment_chunk(
                claims,
                team_id,
                ready["id"],
                offset=0,
                total=len(ready_bytes),
                data=ready_bytes,
            )

            intended_partial = b"mutable partial upload that is not complete"
            received_partial = intended_partial[:13]
            partial_digest = hashlib.sha256(intended_partial).hexdigest()
            partial = store.declare_team_attachment(
                claims,
                team_id,
                {
                    "file_name": "partial.txt",
                    "media_type": "text/plain",
                    "byte_size": len(intended_partial),
                    "sha256": partial_digest,
                    "idempotency_key": "copied-partial-attachment",
                },
            )["attachment"]
            store.write_team_attachment_chunk(
                claims,
                team_id,
                partial["id"],
                offset=0,
                total=len(intended_partial),
                data=received_partial,
            )

            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id="update-hardlink-attachments",
            )
            live_ready = data_dir / "attachments" / ready_digest[:2] / ready_digest
            saved_ready = snapshot / "attachments" / ready_digest[:2] / ready_digest
            live_partial = data_dir / "attachments" / "uploads" / f"{partial['id']}.part"
            saved_partial = snapshot / "attachments" / "uploads" / f"{partial['id']}.part"

            self.assertEqual(
                (live_ready.stat().st_dev, live_ready.stat().st_ino),
                (saved_ready.stat().st_dev, saved_ready.stat().st_ino),
            )
            self.assertGreaterEqual(live_ready.stat().st_nlink, 2)
            self.assertNotEqual(
                (live_partial.stat().st_dev, live_partial.stat().st_ino),
                (saved_partial.stat().st_dev, saved_partial.stat().st_ino),
            )

            # Reclaiming the live content name only decrements the link count;
            # the rollback generation remains complete and can recreate it.
            store._unlink_team_attachment_cleanup_path("content", ready_digest)
            self.assertFalse(live_ready.exists())
            self.assertEqual(saved_ready.read_bytes(), ready_bytes)
            HubStore.restore_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=store.hub_id,
                expected_operation_id="update-hardlink-attachments",
            )
            self.assertEqual(live_ready.read_bytes(), ready_bytes)
            self.assertEqual(
                (live_ready.stat().st_dev, live_ready.stat().st_ino),
                (saved_ready.stat().st_dev, saved_ready.stat().st_ino),
            )
            self.assertEqual(live_partial.read_bytes(), received_partial)
            self.assertNotEqual(
                (live_partial.stat().st_dev, live_partial.stat().st_ino),
                (saved_partial.stat().st_dev, saved_partial.stat().st_ino),
            )

    def test_ready_snapshot_falls_back_to_copy_when_hardlinks_are_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            proof = store.bootstrap_proof_path.read_text().strip()
            bundle = store.bootstrap(
                proof,
                "owner@example.com",
                "Owner",
                "Owner Mac",
            )
            claims = store.verify_access(bundle["access_token"])
            team_id = bundle["teams"][0]["id"]
            payload = b"copy fallback attachment"
            digest = hashlib.sha256(payload).hexdigest()
            attachment = store.declare_team_attachment(
                claims,
                team_id,
                {
                    "file_name": "fallback.txt",
                    "media_type": "text/plain",
                    "byte_size": len(payload),
                    "sha256": digest,
                    "idempotency_key": "hardlink-fallback-attachment",
                },
            )["attachment"]
            store.write_team_attachment_chunk(
                claims,
                team_id,
                attachment["id"],
                offset=0,
                total=len(payload),
                data=payload,
            )

            with mock.patch(
                "agentsdock_team_hub.store.os.link",
                side_effect=OSError(errno.EXDEV, "cross-device link"),
            ):
                snapshot = store.maintenance_snapshot("hardlink-fallback")

            live = data_dir / "attachments" / digest[:2] / digest
            saved = snapshot / "attachments" / digest[:2] / digest
            self.assertEqual(saved.read_bytes(), payload)
            self.assertNotEqual(
                (live.stat().st_dev, live.stat().st_ino),
                (saved.stat().st_dev, saved.stat().st_ino),
            )

    def test_restore_crash_recovery_rolls_back_or_commits_one_exact_generation(self) -> None:
        expected_exit = {"retire": 71, "install": 72, "commit": 73}
        for crash_point in expected_exit:
            with self.subTest(crash_point=crash_point), tempfile.TemporaryDirectory() as temporary:
                data_dir = Path(temporary) / "hub"
                store = HubStore(data_dir, managed_host_identity=HOST_A)
                proof = store.bootstrap_proof_path.read_text().strip()
                bundle = store.bootstrap(
                    proof,
                    "owner@example.com",
                    "Owner",
                    "Owner Mac",
                )
                claims = store.verify_access(bundle["access_token"])
                team_id = bundle["teams"][0]["id"]

                snapshot_bytes = b"snapshot generation attachment"
                snapshot_digest = hashlib.sha256(snapshot_bytes).hexdigest()
                snapshot_attachment = store.declare_team_attachment(
                    claims,
                    team_id,
                    {
                        "file_name": "snapshot.txt",
                        "media_type": "text/plain",
                        "byte_size": len(snapshot_bytes),
                        "sha256": snapshot_digest,
                        "idempotency_key": f"restore-crash-snapshot-{crash_point}",
                    },
                )["attachment"]
                store.write_team_attachment_chunk(
                    claims,
                    team_id,
                    snapshot_attachment["id"],
                    offset=0,
                    total=len(snapshot_bytes),
                    data=snapshot_bytes,
                )
                operation_id = f"restore-crash-{crash_point}"
                snapshot = store.maintenance_snapshot_and_fence(
                    "server-update",
                    operation_id=operation_id,
                )
                fence_bytes = store.maintenance_fence_path.read_bytes()
                self.assertTrue(
                    store.clear_maintenance_fence(
                        expected_reason="server-update",
                        expected_operation_id=operation_id,
                        expected_snapshot=snapshot,
                    )
                )

                candidate_bytes = b"candidate generation attachment"
                candidate_digest = hashlib.sha256(candidate_bytes).hexdigest()
                candidate_attachment = store.declare_team_attachment(
                    claims,
                    team_id,
                    {
                        "file_name": "candidate.txt",
                        "media_type": "text/plain",
                        "byte_size": len(candidate_bytes),
                        "sha256": candidate_digest,
                        "idempotency_key": f"restore-crash-candidate-{crash_point}",
                    },
                )["attachment"]
                store.write_team_attachment_chunk(
                    claims,
                    team_id,
                    candidate_attachment["id"],
                    offset=0,
                    total=len(candidate_bytes),
                    data=candidate_bytes,
                )
                store.maintenance_fence_path.write_bytes(fence_bytes)
                store.maintenance_fence_path.chmod(0o600)

                crashed = self.run_restore_until_crash(
                    data_dir,
                    snapshot,
                    hub_id=store.hub_id,
                    operation_id=operation_id,
                    crash_point=crash_point,
                )
                self.assertEqual(
                    crashed.returncode,
                    expected_exit[crash_point],
                    crashed.stderr,
                )
                self.assertTrue(
                    (data_dir / ".restore-transaction.json").exists()
                )

                if crash_point == "install":
                    recovery_crashed = self.run_recovery_until_crash(data_dir)
                    self.assertEqual(
                        recovery_crashed.returncode,
                        74,
                        recovery_crashed.stderr,
                    )
                    self.assertTrue(
                        (data_dir / ".restore-transaction.json").exists()
                    )

                with HubStore.maintenance_control_lock(data_dir):
                    pass
                marker_path = data_dir / "maintenance-fence.json"
                if marker_path.exists():
                    marker = json.loads(marker_path.read_text())
                    recovered = HubStore(
                        data_dir,
                        managed_host_identity=HOST_A,
                        managed_update_hub_id=store.hub_id,
                        managed_update_operation_id=operation_id,
                        managed_update_snapshot=snapshot,
                    )
                else:
                    with self.assertRaisesRegex(
                        RuntimeError, "rollback settlement is pending"
                    ):
                        HubStore(data_dir, managed_host_identity=HOST_A)
                    HubStore.confirm_restored_maintenance_snapshot(
                        data_dir,
                        snapshot,
                        expected_host_identity=HOST_A,
                        expected_hub_id=store.hub_id,
                        expected_operation_id=operation_id,
                    )
                    HubStore.acknowledge_restored_maintenance_snapshot(
                        data_dir,
                        snapshot,
                        expected_host_identity=HOST_A,
                        expected_hub_id=store.hub_id,
                        expected_operation_id=operation_id,
                    )
                    recovered = HubStore(data_dir, managed_host_identity=HOST_A)
                connection = recovered.connect()
                try:
                    attachment_ids = {
                        str(row["id"])
                        for row in connection.execute(
                            "SELECT id FROM team_attachments"
                        )
                    }
                finally:
                    connection.close()
                snapshot_path = (
                    data_dir / "attachments" / snapshot_digest[:2] / snapshot_digest
                )
                candidate_path = (
                    data_dir / "attachments" / candidate_digest[:2] / candidate_digest
                )
                if crash_point == "commit":
                    self.assertEqual(attachment_ids, {snapshot_attachment["id"]})
                    self.assertFalse(candidate_path.exists())
                    self.assertIsNone(recovered.maintenance_fence())
                else:
                    self.assertEqual(
                        attachment_ids,
                        {snapshot_attachment["id"], candidate_attachment["id"]},
                    )
                    self.assertEqual(candidate_path.read_bytes(), candidate_bytes)
                    self.assertIsNotNone(recovered.maintenance_fence())
                self.assertEqual(snapshot_path.read_bytes(), snapshot_bytes)
                self.assertFalse(
                    (data_dir / ".restore-transaction.json").exists()
                )
                self.assertEqual(list(data_dir.glob(".restore-[0-9]*-*")), [])

                # Recovery is a no-op after completion and cannot flip the
                # chosen generation on a later open.
                if marker_path.exists():
                    reopened = HubStore(
                        data_dir,
                        managed_host_identity=HOST_A,
                        managed_update_hub_id=store.hub_id,
                        managed_update_operation_id=operation_id,
                        managed_update_snapshot=snapshot,
                    )
                else:
                    reopened = HubStore(data_dir, managed_host_identity=HOST_A)
                self.assertEqual(
                    reopened.maintenance_fence() is None,
                    crash_point == "commit",
                )

    def test_prepared_restore_cleanup_retires_journal_before_receipt(self) -> None:
        cuts = {
            ".restore-transaction.json": 76,
            ".restore-completion.json": 77,
        }
        for target_name, expected_exit in cuts.items():
            with self.subTest(target=target_name), tempfile.TemporaryDirectory() as temporary:
                data_dir = Path(temporary) / "hub"
                store = HubStore(data_dir, managed_host_identity=HOST_A)
                operation_id = f"restore-cleanup-{expected_exit}"
                snapshot = store.maintenance_snapshot_and_fence(
                    "server-update",
                    operation_id=operation_id,
                )
                crashed_restore = self.run_restore_until_crash(
                    data_dir,
                    snapshot,
                    hub_id=store.hub_id,
                    operation_id=operation_id,
                    crash_point="retire",
                )
                self.assertEqual(crashed_restore.returncode, 71, crashed_restore.stderr)

                crashed_cleanup = self.run_restore_cleanup_until_crash(
                    data_dir,
                    target_name=target_name,
                )
                self.assertEqual(
                    crashed_cleanup.returncode,
                    expected_exit,
                    crashed_cleanup.stderr,
                )
                self.assertFalse(
                    (data_dir / ".restore-transaction.json").exists()
                )
                self.assertEqual(
                    (data_dir / ".restore-completion.json").exists(),
                    target_name == ".restore-transaction.json",
                )
                self.assertTrue((data_dir / "maintenance-fence.json").exists())

                # The exact retry either adopts the surviving prepared receipt
                # or starts clean after both controls were durably retired.
                HubStore.restore_maintenance_snapshot(
                    data_dir,
                    snapshot,
                    expected_host_identity=HOST_A,
                    expected_hub_id=store.hub_id,
                    expected_operation_id=operation_id,
                )
                HubStore.confirm_restored_maintenance_snapshot(
                    data_dir,
                    snapshot,
                    expected_host_identity=HOST_A,
                    expected_hub_id=store.hub_id,
                    expected_operation_id=operation_id,
                )
                HubStore.acknowledge_restored_maintenance_snapshot(
                    data_dir,
                    snapshot,
                    expected_host_identity=HOST_A,
                    expected_hub_id=store.hub_id,
                    expected_operation_id=operation_id,
                )
                self.assertEqual(
                    HubStore(data_dir, managed_host_identity=HOST_A).hub_id,
                    store.hub_id,
                )

    def test_invalid_restore_journal_fails_closed_before_database_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            database_before = store.database_path.read_bytes()
            journal = data_dir / ".restore-transaction.json"
            journal.write_text("{}\n", encoding="utf-8")
            journal.chmod(0o600)

            with mock.patch.object(
                HubStore,
                "_preflight_managed_host_binding",
            ) as preflight:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "restore transaction journal is invalid",
                ):
                    HubStore(data_dir, managed_host_identity=HOST_A)
            preflight.assert_not_called()
            self.assertEqual(store.database_path.read_bytes(), database_before)

    def test_prejournal_restore_crash_is_cleaned_before_database_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            hub_id = store.hub_id
            operation_id = "restore-crash-prejournal"
            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id=operation_id,
            )
            live_before = {
                "database": store.database_path.read_bytes(),
                "key": store.signing_key_path.read_bytes(),
                "proof": store.bootstrap_proof_path.read_bytes(),
                "fence": store.maintenance_fence_path.read_bytes(),
            }

            crashed = self.run_restore_until_crash(
                data_dir,
                snapshot,
                hub_id=hub_id,
                operation_id=operation_id,
                crash_point="prejournal",
            )
            self.assertEqual(crashed.returncode, 75, crashed.stderr)
            self.assertFalse((data_dir / ".restore-transaction.json").exists())
            self.assertEqual(len(list(data_dir.glob(".restore-[0-9]*-*"))), 1)
            self.assertEqual(store.database_path.read_bytes(), live_before["database"])
            self.assertEqual(store.signing_key_path.read_bytes(), live_before["key"])
            self.assertEqual(store.bootstrap_proof_path.read_bytes(), live_before["proof"])
            self.assertEqual(store.maintenance_fence_path.read_bytes(), live_before["fence"])

            with self.assertRaisesRegex(
                RuntimeError, "rollback settlement is pending"
            ):
                HubStore(
                    data_dir,
                    managed_host_identity=HOST_A,
                    managed_update_hub_id=hub_id,
                    managed_update_operation_id=operation_id,
                    managed_update_snapshot=snapshot,
                )
            HubStore.restore_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
            )
            HubStore.confirm_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
            )
            HubStore.acknowledge_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
            )
            recovered = HubStore(data_dir, managed_host_identity=HOST_A)
            self.assertEqual(recovered.hub_id, hub_id)
            manifest = json.loads((snapshot / "manifest.json").read_text())
            self.assertEqual(
                hashlib.sha256(store.database_path.read_bytes()).hexdigest(),
                manifest["database_sha256"],
            )
            self.assertEqual(store.signing_key_path.read_bytes(), live_before["key"])
            self.assertEqual(store.bootstrap_proof_path.read_bytes(), live_before["proof"])
            self.assertFalse(store.maintenance_fence_path.exists())
            self.assertEqual(list(data_dir.glob(".restore-[0-9]*-*")), [])

            reopened = HubStore(data_dir, managed_host_identity=HOST_A)
            self.assertEqual(reopened.hub_id, hub_id)
            self.assertEqual(list(data_dir.glob(".restore-[0-9]*-*")), [])

    def test_unsafe_orphan_restore_generation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            database_before = store.database_path.read_bytes()
            outside = root / "outside"
            outside.mkdir()
            marker = outside / "keep.txt"
            marker.write_text("do not delete", encoding="utf-8")
            orphan = data_dir / ".restore-999-0123456789abcdef"
            orphan.symlink_to(outside, target_is_directory=True)

            with mock.patch.object(
                HubStore,
                "_preflight_managed_host_binding",
            ) as preflight:
                with self.assertRaisesRegex(
                    PermissionError,
                    "restore transaction target is unsafe",
                ):
                    HubStore(data_dir, managed_host_identity=HOST_A)
            preflight.assert_not_called()
            self.assertTrue(orphan.is_symlink())
            self.assertEqual(marker.read_text(encoding="utf-8"), "do not delete")
            self.assertEqual(store.database_path.read_bytes(), database_before)

    def test_offline_restore_verifies_identity_and_restores_db_key_and_proofs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            hub_id = store.hub_id
            proof_bytes = store.bootstrap_proof_path.read_bytes()
            key_bytes = store.signing_key_path.read_bytes()
            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id="update-restore",
            )
            snapshot_database = (snapshot / "team-hub.sqlite3").read_bytes()
            live_before_verify = {
                path.name: path.read_bytes()
                for path in (
                    store.database_path,
                    store.signing_key_path,
                    store.bootstrap_proof_path,
                    store.maintenance_fence_path,
                )
            }
            HubStore.verify_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id="update-restore",
            )
            with mock.patch("sys.stdout"):
                self.assertEqual(
                    cli_main(
                        [
                            "verify-snapshot",
                            "--data-dir",
                            str(data_dir),
                            "--snapshot",
                            str(snapshot),
                            "--expected-host-identity",
                            HOST_A,
                            "--expected-hub-id",
                            hub_id,
                            "--expected-operation-id",
                            "update-restore",
                        ]
                    ),
                    0,
                )
            self.assertEqual(
                {
                    path.name: path.read_bytes()
                    for path in (
                        store.database_path,
                        store.signing_key_path,
                        store.bootstrap_proof_path,
                        store.maintenance_fence_path,
                    )
                },
                live_before_verify,
            )

            store.bootstrap(
                proof_bytes.decode("ascii").strip(),
                "owner@example.com",
                "Owner",
                "Original device",
            )
            self.assertFalse(store.bootstrap_proof_path.exists())
            live_before_rejected_restore = (data_dir / "team-hub.sqlite3").read_bytes()
            marker_before_rejected_restore = store.maintenance_fence_path.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                HubStore.restore_maintenance_snapshot(
                    data_dir,
                    snapshot,
                    expected_host_identity=HOST_A,
                    expected_hub_id=hub_id,
                    expected_operation_id="update-stale",
                )
            self.assertEqual(
                (data_dir / "team-hub.sqlite3").read_bytes(),
                live_before_rejected_restore,
            )
            self.assertEqual(
                store.maintenance_fence_path.read_bytes(),
                marker_before_rejected_restore,
            )
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                HubStore.restore_maintenance_snapshot(
                    data_dir,
                    snapshot,
                    expected_host_identity=HOST_A,
                    expected_hub_id="hub_wrongidentity123456",
                    expected_operation_id="update-restore",
                )
            self.assertEqual(
                (data_dir / "team-hub.sqlite3").read_bytes(),
                live_before_rejected_restore,
            )

            HubStore.restore_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id="update-restore",
            )
            self.assertEqual((data_dir / "team-hub.sqlite3").read_bytes(), snapshot_database)
            self.assertEqual(store.signing_key_path.read_bytes(), key_bytes)
            self.assertEqual(store.bootstrap_proof_path.read_bytes(), proof_bytes)
            self.assertFalse((data_dir / "team-hub.sqlite3-wal").exists())
            self.assertFalse((data_dir / "team-hub.sqlite3-shm").exists())
            self.assertFalse(store.maintenance_fence_path.exists())
            with self.assertRaisesRegex(
                RuntimeError, "rollback settlement is pending"
            ):
                HubStore(data_dir, managed_host_identity=HOST_A)
            HubStore.confirm_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id="update-restore",
            )
            HubStore.acknowledge_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id="update-restore",
            )
            restored = HubStore(data_dir, managed_host_identity=HOST_A)
            self.assertEqual(restored.hub_id, hub_id)
            self.assertTrue(restored.health()["bootstrap_required"])

    def test_restore_receipt_is_exact_generation_bound_and_idempotently_acknowledged(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            operation_id = "update-receipt-exact"
            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id=operation_id,
            )
            HubStore.restore_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=store.hub_id,
                expected_operation_id=operation_id,
            )
            receipt_path = data_dir / ".restore-completion.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["state"], "committed")
            self.assertEqual(receipt["operation_id"], operation_id)
            self.assertEqual(receipt["snapshot"], snapshot.name)
            self.assertEqual(
                receipt["snapshot_manifest_sha256"],
                hashlib.sha256((snapshot / "manifest.json").read_bytes()).hexdigest(),
            )
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                HubStore.confirm_restored_maintenance_snapshot(
                    data_dir,
                    snapshot,
                    expected_host_identity=HOST_A,
                    expected_hub_id=store.hub_id,
                    expected_operation_id="update-receipt-foreign",
                )
            self.assertTrue(receipt_path.exists())
            HubStore.confirm_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=store.hub_id,
                expected_operation_id=operation_id,
            )
            HubStore.acknowledge_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=store.hub_id,
                expected_operation_id=operation_id,
            )
            self.assertFalse(receipt_path.exists())
            HubStore.acknowledge_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=store.hub_id,
                expected_operation_id=operation_id,
                allow_missing=True,
            )
            self.assertEqual(
                HubStore(data_dir, managed_host_identity=HOST_A).hub_id,
                store.hub_id,
            )

    def test_schema4_snapshot_verifies_restores_exactly_then_migrates_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            hub_id = store.hub_id
            operation_id = "update-schema4-restore"
            snapshot = self.make_schema4_snapshot(
                store,
                operation_id=operation_id,
            )
            expected_database = (snapshot / "team-hub.sqlite3").read_bytes()
            expected_key = (snapshot / "access-token-signing.key").read_bytes()
            expected_proof = (
                snapshot / "proofs" / "bootstrap-owner.proof"
            ).read_bytes()

            HubStore.verify_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
            )
            store.database_path.write_bytes(b"candidate-mutated database\n")
            store.signing_key_path.write_bytes(b"candidate-mutated signing key\n")
            store.bootstrap_proof_path.write_bytes(b"candidate-mutated proof\n")

            HubStore.restore_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
            )
            self.assertEqual(store.database_path.read_bytes(), expected_database)
            self.assertEqual(store.signing_key_path.read_bytes(), expected_key)
            self.assertEqual(store.bootstrap_proof_path.read_bytes(), expected_proof)
            self.assertFalse(store.maintenance_fence_path.exists())

            legacy = sqlite3.connect(
                f"file:{store.database_path}?mode=ro&immutable=1",
                uri=True,
            )
            try:
                self.assertEqual(legacy.execute("PRAGMA user_version").fetchone()[0], 4)
                self.assertEqual(
                    legacy.execute(
                        "SELECT hub_id, server_identity FROM managed_host_bindings"
                    ).fetchone(),
                    (hub_id, HOST_A),
                )
                self.assertIsNone(
                    legacy.execute(
                        "SELECT 1 FROM sqlite_master "
                        "WHERE type = 'table' AND name = 'bootstrap_delegations'"
                    ).fetchone()
                )
            finally:
                legacy.close()

            HubStore.confirm_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
            )
            HubStore.acknowledge_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
            )
            migrated = HubStore(data_dir, managed_host_identity=HOST_A)
            self.assertEqual(migrated.hub_id, hub_id)
            self.assertEqual(migrated.signing_key_path.read_bytes(), expected_key)
            self.assertEqual(migrated.bootstrap_proof_path.read_bytes(), expected_proof)
            connection = migrated.connect()
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 12)
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM bootstrap_delegations"
                    ).fetchone()[0],
                    0,
                )
                self.assertIsNotNone(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master "
                        "WHERE type = 'table' AND name = 'network_mailbox_items'"
                    ).fetchone()
                )
            finally:
                connection.close()

    def test_schema5_bulletin_slug_collisions_upgrade_without_hijacking(self) -> None:
        collisions = {
            "live-shared": {
                "kind": "board",
                "visibility": "team",
                "archived": False,
            },
            "archived": {"kind": "board", "visibility": "team", "archived": True},
            "private": {"kind": "board", "visibility": "private", "archived": False},
            "wrong-kind": {
                "kind": "announcements",
                "visibility": "team",
                "archived": False,
            },
        }
        for label, collision in collisions.items():
            with self.subTest(collision=label), tempfile.TemporaryDirectory() as temporary:
                data_dir = Path(temporary) / "hub"
                store = HubStore(data_dir, managed_host_identity=HOST_A)
                proof = store.bootstrap_proof_path.read_text().strip()
                bootstrap = store.bootstrap(
                    proof,
                    f"owner-{label}@example.com",
                    "Owner",
                    "Owner Mac",
                )
                owner = store.verify_access(bootstrap["access_token"])
                team_id = bootstrap["teams"][0]["id"]
                preserved_post = store.create_network_bulletin_post(
                    owner,
                    team_id,
                    {
                        "body": f"preserve pre-V6 {label}",
                        "body_format": "plain",
                        "reply_to_post_id": None,
                        "idempotency_key": f"preserve-pre-v6-{label}",
                    },
                )["post"]
                connection = store.connect()
                try:
                    old_board = connection.execute(
                        """
                        SELECT c.* FROM network_boards AS b
                        JOIN channels AS c
                          ON c.team_id=b.team_id AND c.id=b.channel_id
                        WHERE b.team_id=?
                        """,
                        (team_id,),
                    ).fetchone()
                    assert old_board is not None
                    archived_at = (
                        int(old_board["created_at"])
                        if collision["archived"]
                        else None
                    )
                    connection.execute(
                        """
                        UPDATE channels
                        SET kind=?,visibility=?,archived_at=?,updated_at=updated_at+1
                        WHERE id=?
                        """,
                        (
                            collision["kind"],
                            collision["visibility"],
                            archived_at,
                            old_board["id"],
                        ),
                    )
                    old_board_id = str(old_board["id"])
                finally:
                    connection.close()

                self.downgrade_database_to_schema5(store.database_path)
                migrated = HubStore(data_dir, managed_host_identity=HOST_A)
                connection = migrated.connect()
                try:
                    self.assertEqual(
                        connection.execute("PRAGMA user_version").fetchone()[0],
                        12,
                    )
                    preserved = connection.execute(
                        "SELECT * FROM channels WHERE id=?", (old_board_id,)
                    ).fetchone()
                    self.assertIsNotNone(preserved)
                    assert preserved is not None
                    self.assertEqual(preserved["slug"], "agentsdock-bulletin")
                    self.assertEqual(preserved["kind"], collision["kind"])
                    self.assertEqual(preserved["visibility"], collision["visibility"])
                    self.assertEqual(
                        preserved["archived_at"] is not None,
                        collision["archived"],
                    )
                    replacement = connection.execute(
                        """
                        SELECT c.* FROM network_boards AS b
                        JOIN channels AS c
                          ON c.team_id=b.team_id AND c.id=b.channel_id
                        WHERE b.team_id=?
                        """,
                        (team_id,),
                    ).fetchone()
                    self.assertIsNotNone(replacement)
                    assert replacement is not None
                    self.assertNotEqual(replacement["id"], old_board_id)
                    self.assertEqual(replacement["slug"], "agentsdock-bulletin-v1")
                    self.assertEqual(replacement["kind"], "board")
                    self.assertEqual(replacement["visibility"], "team")
                    self.assertIsNone(replacement["archived_at"])
                    self.assertIsNotNone(
                        connection.execute(
                            "SELECT 1 FROM messages WHERE id=? AND channel_id=?",
                            (preserved_post["id"], old_board_id),
                        ).fetchone()
                    )
                finally:
                    connection.close()
                bulletin = migrated.list_network_bulletin(
                    owner,
                    team_id,
                    after_sequence=0,
                    limit=100,
                )
                self.assertEqual(bulletin["posts"], [])

    def test_unavailable_bulletin_binding_is_repaired_without_hijacking(self) -> None:
        for mode in ("archived", "missing"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                data_dir = Path(temporary) / "hub"
                store = HubStore(data_dir, managed_host_identity=HOST_A)
                proof = store.bootstrap_proof_path.read_text().strip()
                bootstrap = store.bootstrap(
                    proof,
                    f"owner-{mode}@example.com",
                    "Owner",
                    "Owner Mac",
                )
                owner = store.verify_access(bootstrap["access_token"])
                team_id = bootstrap["teams"][0]["id"]
                occupied_fallback = store.create_channel(
                    owner,
                    team_id,
                    {
                        "kind": "board",
                        "visibility": "team",
                        "slug": "agentsdock-bulletin-v1",
                        "display_name": "User fallback board",
                        "participant_principal_ids": [],
                        "idempotency_key": f"fallback-board-{mode}",
                    },
                )["channel"]
                connection = store.connect()
                try:
                    old_board = connection.execute(
                        """
                        SELECT c.* FROM network_boards AS b
                        JOIN channels AS c
                          ON c.team_id=b.team_id AND c.id=b.channel_id
                        WHERE b.team_id=?
                        """,
                        (team_id,),
                    ).fetchone()
                    assert old_board is not None
                    old_board_id = str(old_board["id"])
                    if mode == "archived":
                        connection.execute(
                            "UPDATE channels SET archived_at=?,updated_at=updated_at+1 "
                            "WHERE id=?",
                            (int(old_board["created_at"]), old_board_id),
                        )
                finally:
                    connection.close()
                if mode == "missing":
                    connection = sqlite3.connect(
                        store.database_path, isolation_level=None
                    )
                    try:
                        connection.execute("PRAGMA foreign_keys=OFF")
                        connection.execute("BEGIN IMMEDIATE")
                        connection.execute(
                            "DELETE FROM channel_acl_entries WHERE channel_id=?",
                            (old_board_id,),
                        )
                        connection.execute(
                            "DELETE FROM messages WHERE channel_id=?",
                            (old_board_id,),
                        )
                        connection.execute(
                            "DELETE FROM channels WHERE id=?", (old_board_id,)
                        )
                        connection.execute("COMMIT")
                    finally:
                        connection.close()

                repaired = HubStore(data_dir, managed_host_identity=HOST_A)
                connection = repaired.connect()
                try:
                    replacement = connection.execute(
                        """
                        SELECT c.* FROM network_boards AS b
                        JOIN channels AS c
                          ON c.team_id=b.team_id AND c.id=b.channel_id
                        WHERE b.team_id=?
                        """,
                        (team_id,),
                    ).fetchone()
                    self.assertIsNotNone(replacement)
                    assert replacement is not None
                    self.assertNotEqual(replacement["id"], old_board_id)
                    self.assertEqual(
                        replacement["slug"],
                        (
                            "agentsdock-bulletin-v1-2"
                            if mode == "archived"
                            else "agentsdock-bulletin"
                        ),
                    )
                    self.assertEqual(replacement["kind"], "board")
                    self.assertEqual(replacement["visibility"], "team")
                    self.assertIsNone(replacement["archived_at"])
                    self.assertIsNotNone(
                        connection.execute(
                            "SELECT 1 FROM channels WHERE id=? AND slug=?",
                            (
                                occupied_fallback["id"],
                                "agentsdock-bulletin-v1",
                            ),
                        ).fetchone()
                    )
                    if mode == "archived":
                        archived = connection.execute(
                            "SELECT archived_at FROM channels WHERE id=?",
                            (old_board_id,),
                        ).fetchone()
                        self.assertIsNotNone(archived)
                        assert archived is not None
                        self.assertIsNotNone(archived["archived_at"])
                    else:
                        self.assertIsNone(
                            connection.execute(
                                "SELECT 1 FROM channels WHERE id=?",
                                (old_board_id,),
                            ).fetchone()
                        )
                    self.assertEqual(
                        connection.execute("PRAGMA foreign_key_check").fetchall(),
                        [],
                    )
                finally:
                    connection.close()

    def test_schema5_snapshot_does_not_fall_back_when_delegation_schema_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            operation_id = "update-schema5-strict"
            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id=operation_id,
            )
            snapshot_database = snapshot / "team-hub.sqlite3"
            self.downgrade_database_to_schema4(
                snapshot_database,
                update_version_ledger=False,
            )
            manifest_path = snapshot / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["database_sha256"] = hashlib.sha256(
                snapshot_database.read_bytes()
            ).hexdigest()
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
            )
            self.rebind_snapshot_fence_digest(store, snapshot)

            with self.assertRaisesRegex(
                RuntimeError,
                "snapshot bootstrap proof schema is invalid",
            ):
                HubStore.verify_maintenance_snapshot(
                    data_dir,
                    snapshot,
                    expected_host_identity=HOST_A,
                    expected_hub_id=store.hub_id,
                    expected_operation_id=operation_id,
                )

    def test_preflight_sees_a_binding_present_only_in_live_wal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            standalone = HubStore(data_dir)
            keeper = standalone.connect()
            try:
                keeper.execute("PRAGMA wal_autocheckpoint = 0")
                keeper.execute(
                    """
                    INSERT INTO managed_host_bindings(
                        singleton, hub_id, server_identity, created_at
                    ) VALUES (1, ?, ?, 1)
                    """,
                    (standalone.hub_id, HOST_A),
                )
                wal = data_dir / "team-hub.sqlite3-wal"
                self.assertTrue(wal.is_file())
                immutable = sqlite3.connect(
                    f"file:{standalone.database_path}?mode=ro&immutable=1",
                    uri=True,
                )
                try:
                    self.assertIsNone(
                        immutable.execute(
                            "SELECT server_identity FROM managed_host_bindings"
                        ).fetchone()
                    )
                finally:
                    immutable.close()
                with self.assertRaisesRegex(RuntimeError, "different AgentsServer"):
                    HubStore(data_dir, managed_host_identity=HOST_B)
            finally:
                keeper.close()

    def test_snapshot_verification_fails_before_live_state_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id="update-verify",
            )
            live_before = {
                path.name: path.read_bytes()
                for path in (
                    store.database_path,
                    store.signing_key_path,
                    store.bootstrap_proof_path,
                    store.maintenance_fence_path,
                )
            }
            snapshot_database = snapshot / "team-hub.sqlite3"
            snapshot_database.write_bytes(snapshot_database.read_bytes() + b"tampered")
            with self.assertRaisesRegex(RuntimeError, "digest is invalid"):
                HubStore.verify_maintenance_snapshot(
                    data_dir,
                    snapshot,
                    expected_host_identity=HOST_A,
                    expected_hub_id=store.hub_id,
                    expected_operation_id="update-verify",
                )
            self.assertEqual(
                {
                    path.name: path.read_bytes()
                    for path in (
                        store.database_path,
                        store.signing_key_path,
                        store.bootstrap_proof_path,
                        store.maintenance_fence_path,
                    )
                },
                live_before,
            )

    def test_update_fence_blocks_local_recovery_until_exact_clear(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            proof = store.bootstrap_proof_path.read_text().strip()
            store.bootstrap(
                proof,
                "owner@example.com",
                "Owner",
                "Owner Mac",
            )
            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id="update-one",
            )
            with mock.patch("sys.stderr"):
                denied = cli_main(
                    [
                        "device-recovery",
                        "--data-dir",
                        str(data_dir),
                        "--email",
                        "owner@example.com",
                        "--device-label",
                        "Replacement Mac",
                    ]
                )
            self.assertEqual(denied, 2)
            connection = store.connect()
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM owner_recovery_claims"
                    ).fetchone()[0],
                    0,
                )
            finally:
                connection.close()
            self.assertTrue(
                store.clear_maintenance_fence(
                    expected_reason="server-update",
                    expected_operation_id="update-one",
                    expected_snapshot=snapshot,
                )
            )
            with mock.patch("sys.stdout"):
                allowed = cli_main(
                    [
                        "device-recovery",
                        "--data-dir",
                        str(data_dir),
                        "--email",
                        "owner@example.com",
                        "--device-label",
                        "Replacement Mac",
                    ]
                )
            self.assertEqual(allowed, 0)

    def test_schema4_reactivation_and_failed_start_repair_snapshot_without_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            hub_id = store.hub_id
            expected_key = store.signing_key_path.read_bytes()
            expected_proof = store.bootstrap_proof_path.read_bytes()
            self.downgrade_database_to_schema4(store.database_path)
            expected_database = store.database_path.read_bytes()

            (
                prepared_hub_id,
                snapshot,
                operation_id,
                _fence_device,
                _fence_inode,
            ) = HubStore.prepare_managed_host_reactivation(
                data_dir,
                expected_host_identity=HOST_A,
            )
            HubStore.adopt_prepared_host_reactivation(
                data_dir,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
                expected_snapshot=snapshot,
                expected_device=_fence_device,
                expected_inode=_fence_inode,
            )

            self.assertEqual(prepared_hub_id, hub_id)
            self.assertEqual(store.database_path.read_bytes(), expected_database)
            self.assertEqual(store.signing_key_path.read_bytes(), expected_key)
            self.assertEqual(store.bootstrap_proof_path.read_bytes(), expected_proof)
            manifest = json.loads((snapshot / "manifest.json").read_text())
            self.assertEqual(manifest["schema_version"], 4)
            self.assertEqual(manifest["reason"], "host-reactivation")
            self.assertEqual(
                (snapshot / "proofs" / "bootstrap-owner.proof").read_bytes(),
                expected_proof,
            )
            snapshot_database = sqlite3.connect(
                f"file:{snapshot / 'team-hub.sqlite3'}?mode=ro&immutable=1",
                uri=True,
            )
            try:
                self.assertEqual(
                    snapshot_database.execute("PRAGMA user_version").fetchone()[0],
                    4,
                )
                self.assertIsNone(
                    snapshot_database.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='bootstrap_delegations'"
                    ).fetchone()
                )
            finally:
                snapshot_database.close()
            HubStore.verify_host_reactivation_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
            )

    def test_rejected_reactivation_never_publishes_or_prunes_backup_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            for index in range(3):
                store.maintenance_snapshot(f"known-good-{index}", keep=3)
            backups = data_dir / "maintenance-backups"
            before = {
                path.relative_to(backups).as_posix(): path.read_bytes()
                for path in backups.rglob("*")
                if path.is_file()
            }
            self.assertEqual(
                len({name.split("/", 1)[0] for name in before}),
                3,
            )
            connection = sqlite3.connect(store.database_path, isolation_level=None)
            try:
                connection.execute(
                    "UPDATE schema_migrations SET sha256=? WHERE version=4",
                    ("0" * 64,),
                )
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                connection.close()

            for _attempt in range(5):
                with self.assertRaisesRegex(
                    RuntimeError, "snapshot migration ledger is invalid"
                ):
                    HubStore.prepare_managed_host_reactivation(
                        data_dir,
                        expected_host_identity=HOST_A,
                    )
                self.assertEqual(
                    {
                        path.relative_to(backups).as_posix(): path.read_bytes()
                        for path in backups.rglob("*")
                        if path.is_file()
                    },
                    before,
                )
                self.assertFalse(
                    any(path.name.startswith(".snapshot_") for path in backups.iterdir())
                )

    def test_explicit_host_reactivation_verifies_binding_and_snapshots_first(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            identity = "a" * 24
            identity_path = state_dir / "server-identity"
            identity_path.write_text(identity + "\n")
            identity_path.chmod(0o600)
            data_dir = state_dir / "team-hub"
            store = HubStore(data_dir, managed_host_identity=identity)

            output = io.StringIO()
            with mock.patch("sys.stdout", output):
                result = cli_main(
                    [
                        "prepare-host-reactivation",
                        "--data-dir",
                        str(data_dir),
                        "--server-state-dir",
                        str(state_dir),
                    ]
                )
            self.assertEqual(result, 0)
            lines = output.getvalue().splitlines()
            self.assertEqual(lines[0], identity)
            self.assertEqual(lines[1], store.hub_id)
            operation_id = lines[2]
            self.assertRegex(operation_id, r"^host-reactivation-[0-9a-f]{24}$")
            snapshot = Path(lines[3])
            self.assertTrue(snapshot.is_dir())
            manifest = json.loads((snapshot / "manifest.json").read_text())
            self.assertEqual(manifest["reason"], "host-reactivation")
            self.assertEqual(manifest["host_server_identity"], identity)
            marker = store.maintenance_fence()
            self.assertIsNotNone(marker)
            self.assertEqual(marker["reason"], "host-reactivation")
            self.assertEqual(marker["operation_id"], operation_id)
            self.assertEqual(marker["snapshot"], snapshot.name)

            # The snapshot and its source generation are one fenced unit.
            # A supported local-control mutation after preflight must not mint
            # state that a later rollback could silently erase/resurrect.
            database_before_control = store.database_path.read_bytes()
            proof_before_control = store.bootstrap_proof_path.read_bytes()
            with mock.patch("sys.stderr"):
                control_denied = cli_main(
                    [
                        "bootstrap-proof",
                        "--data-dir",
                        str(data_dir),
                    ]
                )
            self.assertEqual(control_denied, 2)
            self.assertEqual(store.database_path.read_bytes(), database_before_control)
            self.assertEqual(store.bootstrap_proof_path.read_bytes(), proof_before_control)

            foreign_dir = root / "foreign-hub"
            foreign = HubStore(
                foreign_dir,
                managed_host_identity="b" * 24,
            )
            database_before = foreign.database_path.read_bytes()
            generations_before = list(
                (foreign_dir / "maintenance-backups").glob("snapshot_*")
            ) if (foreign_dir / "maintenance-backups").exists() else []
            with mock.patch("sys.stderr"):
                denied = cli_main(
                    [
                        "prepare-host-reactivation",
                        "--data-dir",
                        str(foreign_dir),
                        "--server-state-dir",
                        str(state_dir),
                    ]
                )
            self.assertEqual(denied, 2)
            self.assertEqual(foreign.database_path.read_bytes(), database_before)
            generations_after = list(
                (foreign_dir / "maintenance-backups").glob("snapshot_*")
            ) if (foreign_dir / "maintenance-backups").exists() else []
            self.assertEqual(generations_after, generations_before)

    def test_reactivation_preflight_failure_never_leaks_an_unowned_fence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            identity = "c" * 24
            identity_path = state_dir / "server-identity"
            identity_path.write_text(identity + "\n")
            identity_path.chmod(0o600)
            data_dir = state_dir / "team-hub"
            HubStore(data_dir, managed_host_identity=identity)

            original_fsync = HubStore._fsync_directory
            injected = False

            def fail_first_marker_fsync(path):
                nonlocal injected
                candidate = Path(path)
                if (
                    not injected
                    and candidate == data_dir
                    and (data_dir / "maintenance-fence.json").exists()
                ):
                    injected = True
                    raise OSError("injected marker directory fsync failure")
                return original_fsync(path)

            with mock.patch.object(
                HubStore,
                "_fsync_directory",
                side_effect=fail_first_marker_fsync,
            ):
                with self.assertRaisesRegex(OSError, "marker directory fsync"):
                    HubStore.prepare_managed_host_reactivation(
                        data_dir,
                        expected_host_identity=identity,
                    )
            self.assertTrue(injected)
            self.assertFalse((data_dir / "maintenance-fence.json").exists())

            with mock.patch.object(
                HubStore,
                "_maintenance_fence_control_unlocked",
                side_effect=RuntimeError("injected marker verification failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "marker verification"):
                    HubStore.prepare_managed_host_reactivation(
                        data_dir,
                        expected_host_identity=identity,
                    )
            self.assertFalse((data_dir / "maintenance-fence.json").exists())

            with (
                mock.patch.object(
                    team_hub_cli,
                    "_persist_server_identity",
                    side_effect=RuntimeError("injected identity persistence failure"),
                ),
                mock.patch("sys.stderr"),
            ):
                self.assertEqual(
                    cli_main(
                        [
                            "prepare-host-reactivation",
                            "--data-dir",
                            str(data_dir),
                            "--server-state-dir",
                            str(state_dir),
                        ]
                    ),
                    2,
                )
            self.assertFalse((data_dir / "maintenance-fence.json").exists())

    def test_host_reactivation_seeds_the_matching_legacy_server_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            state_dir.mkdir(mode=0o700)
            identity = team_hub_cli._legacy_server_identity(state_dir)
            data_dir = state_dir / "team-hub"
            HubStore(data_dir, managed_host_identity=identity)

            with mock.patch("sys.stdout", io.StringIO()):
                result = cli_main(
                    [
                        "prepare-host-reactivation",
                        "--data-dir",
                        str(data_dir),
                        "--server-state-dir",
                        str(state_dir),
                    ]
                )
            self.assertEqual(result, 0)
            identity_path = state_dir / "server-identity"
            self.assertEqual(identity_path.read_text().strip(), identity)
            self.assertEqual(stat.S_IMODE(identity_path.stat().st_mode), 0o600)

    def test_server_identity_persistence_overrides_restrictive_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            state_dir.mkdir(mode=0o700)
            identity_path = state_dir / "server-identity"
            identity = "a" * 24
            prior_umask = os.umask(0o777)
            try:
                persisted = team_hub_cli._persist_server_identity(
                    identity_path,
                    identity,
                )
            finally:
                os.umask(prior_umask)

            self.assertEqual(persisted, identity)
            self.assertEqual(identity_path.read_text().strip(), identity)
            self.assertEqual(stat.S_IMODE(identity_path.stat().st_mode), 0o600)

            failed_path = state_dir / "failed-server-identity"
            with mock.patch.object(
                team_hub_cli,
                "_read_server_identity_file",
                side_effect=PermissionError("forced validation failure"),
            ):
                with self.assertRaisesRegex(
                    PermissionError,
                    "forced validation failure",
                ):
                    team_hub_cli._persist_server_identity(
                        failed_path,
                        "b" * 24,
                    )
            self.assertFalse(failed_path.exists())
            self.assertEqual(list(state_dir.glob(".failed-server-identity.*.tmp")), [])

    def test_host_reactivation_snapshots_legacy_wal_without_migrating_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            state_dir.mkdir(mode=0o700)
            identity = "c" * 24
            identity_path = state_dir / "server-identity"
            identity_path.write_text(identity + "\n")
            identity_path.chmod(0o600)
            data_dir = state_dir / "team-hub"
            data_dir.mkdir(mode=0o700)
            database = data_dir / "team-hub.sqlite3"
            connection = sqlite3.connect(database, isolation_level=None)
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA wal_autocheckpoint = 0")
                connection.execute(
                    """
                    CREATE TABLE schema_migrations (
                        version INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
                        applied_at INTEGER NOT NULL
                    )
                    """
                )
                connection.execute("BEGIN IMMEDIATE")
                for migration in MIGRATIONS[:5]:
                    for statement in _statements(migration.source):
                        connection.execute(statement)
                    connection.execute(
                        """
                        INSERT INTO schema_migrations(version,name,sha256,applied_at)
                        VALUES (?,?,?,1)
                        """,
                        (migration.version, migration.name, migration.sha256),
                    )
                    connection.execute(f"PRAGMA user_version = {migration.version}")
                hub_id = "hub_legacy_reactivation_12345678"
                connection.execute(
                    "INSERT INTO hub_metadata(singleton,hub_id,created_at) VALUES (1,?,1)",
                    (hub_id,),
                )
                connection.execute(
                    """
                    INSERT INTO managed_host_bindings(
                        singleton,hub_id,server_identity,created_at
                    ) VALUES (1,?,?,1)
                    """,
                    (hub_id, identity),
                )
                connection.execute("COMMIT")
                database.chmod(0o600)
                wal = data_dir / "team-hub.sqlite3-wal"
                wal.chmod(0o600)
                key = data_dir / "access-token-signing.key"
                key.write_bytes(os.urandom(32))
                key.chmod(0o600)
                database_before = database.read_bytes()
                wal_before = wal.read_bytes()

                with self.assertRaisesRegex(RuntimeError, "different AgentsServer"):
                    HubStore.prepare_managed_host_reactivation(
                        data_dir,
                        expected_host_identity="d" * 24,
                    )
                self.assertEqual(database.read_bytes(), database_before)
                self.assertEqual(wal.read_bytes(), wal_before)

                output = io.StringIO()
                with mock.patch("sys.stdout", output):
                    result = cli_main(
                        [
                            "prepare-host-reactivation",
                            "--data-dir",
                            str(data_dir),
                            "--server-state-dir",
                            str(state_dir),
                        ]
                    )
                self.assertEqual(result, 0)
                (
                    result_identity,
                    result_hub,
                    operation_id,
                    raw_snapshot,
                    raw_fence_device,
                    raw_fence_inode,
                ) = output.getvalue().splitlines()
                self.assertEqual(result_identity, identity)
                self.assertEqual(result_hub, hub_id)
                self.assertEqual(database.read_bytes(), database_before)
                self.assertEqual(wal.read_bytes(), wal_before)
                snapshot = Path(raw_snapshot)
                self.assertGreaterEqual(int(raw_fence_device), 0)
                self.assertGreater(int(raw_fence_inode), 0)
                manifest = json.loads((snapshot / "manifest.json").read_text())
                self.assertEqual(manifest["schema_version"], 5)
                self.assertEqual(manifest["reason"], "host-reactivation")
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0],
                    5,
                )
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE name='team_messages'"
                    ).fetchone()
                )
            finally:
                connection.close()

    def test_host_reactivation_snapshot_restores_candidate_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            state_dir.mkdir(mode=0o700)
            identity = "e" * 24
            data_dir = state_dir / "team-hub"
            store = HubStore(data_dir, managed_host_identity=identity)
            (
                hub_id,
                snapshot,
                operation_id,
                _fence_device,
                _fence_inode,
            ) = HubStore.prepare_managed_host_reactivation(
                data_dir,
                expected_host_identity=identity,
            )
            HubStore.adopt_prepared_host_reactivation(
                data_dir,
                expected_host_identity=identity,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
                expected_snapshot=snapshot,
                expected_device=_fence_device,
                expected_inode=_fence_inode,
            )
            for _ in range(5):
                store.maintenance_snapshot("server-shutdown")
            self.assertTrue(snapshot.is_dir())
            connection = store.connect()
            try:
                connection.execute("CREATE TABLE candidate_only(value TEXT)")
            finally:
                connection.close()

            HubStore.restore_host_reactivation_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=identity,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
            )

            connection = store.connect()
            try:
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE name='candidate_only'"
                    ).fetchone()
                )
            finally:
                connection.close()
            self.assertFalse((data_dir / "maintenance-fence.json").exists())

    def test_host_reactivation_restore_fence_crash_recovers_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            (
                hub_id,
                snapshot,
                operation_id,
                _fence_device,
                _fence_inode,
            ) = HubStore.prepare_managed_host_reactivation(
                data_dir,
                expected_host_identity=HOST_A,
            )
            HubStore.adopt_prepared_host_reactivation(
                data_dir,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
                expected_snapshot=snapshot,
                expected_device=_fence_device,
                expected_inode=_fence_inode,
            )
            database_before = store.database_path.read_bytes()
            key_before = store.signing_key_path.read_bytes()

            crashed = self.run_reactivation_restore_until_fence_crash(
                data_dir,
                snapshot,
                hub_id=hub_id,
                operation_id=operation_id,
            )
            self.assertEqual(crashed.returncode, 76, crashed.stderr)
            marker = json.loads(store.maintenance_fence_path.read_text())
            self.assertEqual(marker["format"], 1)
            self.assertEqual(marker["reason"], "host-reactivation")
            self.assertEqual(marker["operation_id"], operation_id)
            self.assertFalse((data_dir / ".restore-transaction.json").exists())
            self.assertEqual(len(list(data_dir.glob(".restore-[0-9]*-*"))), 1)
            self.assertEqual(store.database_path.read_bytes(), database_before)
            self.assertEqual(store.signing_key_path.read_bytes(), key_before)

            with self.assertRaisesRegex(
                RuntimeError, "rollback settlement is pending"
            ):
                HubStore(data_dir, managed_host_identity=HOST_A)
            HubStore.restore_host_reactivation_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
            )
            HubStore.confirm_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
                expected_reason="host-reactivation",
            )
            HubStore.acknowledge_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_A,
                expected_hub_id=hub_id,
                expected_operation_id=operation_id,
                expected_reason="host-reactivation",
            )
            recovered = HubStore(data_dir, managed_host_identity=HOST_A)
            self.assertIsNone(recovered.maintenance_fence())

            # Ordinary durable update fences use format 1 and must never be
            # mistaken for an abandoned private restore owner.
            update_snapshot = recovered.maintenance_snapshot_and_fence(
                "server-update",
                operation_id="update-after-reactivation-crash",
            )
            fence_before = recovered.maintenance_fence_path.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "startup authority"):
                HubStore(data_dir, managed_host_identity=HOST_A)
            reopened = HubStore(
                data_dir,
                managed_host_identity=HOST_A,
                managed_update_hub_id=hub_id,
                managed_update_operation_id="update-after-reactivation-crash",
                managed_update_snapshot=update_snapshot,
            )
            self.assertEqual(reopened.maintenance_fence_path.read_bytes(), fence_before)
            self.assertEqual(reopened.maintenance_fence()["reason"], "server-update")
            self.assertTrue(
                reopened.clear_maintenance_fence(
                    expected_reason="server-update",
                    expected_operation_id="update-after-reactivation-crash",
                    expected_snapshot=update_snapshot,
                )
            )

    def test_maintenance_fence_clear_is_bound_to_operation_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_A)
            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id="update-new",
            )
            marker_before = store.maintenance_fence()
            with self.assertRaisesRegex(RuntimeError, "operation does not match"):
                store.clear_maintenance_fence(
                    expected_reason="server-update",
                    expected_operation_id="update-old",
                    expected_snapshot=snapshot,
                )
            self.assertEqual(store.maintenance_fence(), marker_before)
            with self.assertRaisesRegex(RuntimeError, "snapshot does not match"):
                store.clear_maintenance_fence(
                    expected_reason="server-update",
                    expected_operation_id="update-new",
                    expected_snapshot=snapshot.with_name("snapshot_wrong"),
                )
            self.assertEqual(store.maintenance_fence(), marker_before)
            self.assertTrue(
                store.clear_maintenance_fence(
                    expected_reason="server-update",
                    expected_operation_id="update-new",
                    expected_snapshot=snapshot,
                )
            )

    def test_standalone_listener_and_embedded_host_share_one_runtime_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            lease = HubStore.acquire_managed_runtime_lease(data_dir)
            try:
                with mock.patch("sys.stderr"):
                    self.assertEqual(
                        cli_main(["serve", "--data-dir", str(data_dir)]),
                        2,
                    )
            finally:
                HubStore.release_managed_runtime_lease(lease)

            embedded_result: list[str] = []

            def try_embedded(*_args, **_kwargs) -> None:
                try:
                    lease_fd = HubStore.acquire_managed_runtime_lease(data_dir)
                except RuntimeError:
                    embedded_result.append("rejected")
                else:
                    embedded_result.append("accepted")
                    HubStore.release_managed_runtime_lease(lease_fd)

            with mock.patch("agentsdock_team_hub.cli.uvicorn.run", side_effect=try_embedded), \
                 mock.patch("sys.stdout"):
                self.assertEqual(
                    cli_main(["serve", "--data-dir", str(data_dir)]),
                    0,
                )
            self.assertEqual(embedded_result, ["rejected"])


if __name__ == "__main__":
    unittest.main()
