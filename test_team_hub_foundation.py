from __future__ import annotations

import base64
import hashlib
import inspect
import os
from pathlib import Path
import sqlite3
import stat
import struct
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from agentsdock_team_hub import (
    AuthenticationError,
    AuthorizationError,
    LATEST_SCHEMA_VERSION,
    apply_migrations,
    bootstrap_personal_team,
    issue_invitation,
    issue_node_enrollment,
    open_database,
    record_legacy_server_binding,
    redeem_invitation,
    redeem_node_enrollment,
)
from agentsdock_team_hub.database import MIGRATIONS, MigrationError


NOW = 1_800_000_000


def ed25519_public(fill: int, comment: str = "") -> str:
    algorithm = b"ssh-ed25519"
    key = bytes([fill]) * 32
    wire = (
        struct.pack(">I", len(algorithm))
        + algorithm
        + struct.pack(">I", len(key))
        + key
    )
    suffix = f" {comment}" if comment else ""
    return f"ssh-ed25519 {base64.b64encode(wire).decode('ascii')}{suffix}"


class DatabaseTests(unittest.TestCase):
    def test_migrations_are_complete_idempotent_and_foreign_keys_are_sound(self) -> None:
        connection = open_database()
        self.addCleanup(connection.close)

        self.assertEqual(LATEST_SCHEMA_VERSION, 11)
        self.assertEqual(
            connection.execute("PRAGMA user_version").fetchone()[0],
            LATEST_SCHEMA_VERSION,
        )
        self.assertEqual(apply_migrations(connection), LATEST_SCHEMA_VERSION)
        self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
            )
        }
        self.assertTrue(
            {
                "principals",
                "teams",
                "memberships",
                "invitations",
                "device_sessions",
                "nodes",
                "agents",
                "chats",
                "runs",
                "turn_capabilities",
                "channels",
                "messages",
                "message_recipients",
                "dispatch_requests",
                "artifacts",
                "library_versions",
                "audit_events",
                "outbox_events",
                "bootstrap_claims",
                "bootstrap_delegations",
                "network_peer_bindings",
                "network_boards",
                "network_mailbox_items",
                "network_deliveries",
                "network_passive_requests",
                "team_attachment_cleanup_queue",
            }.issubset(table_names)
        )

    def test_attachment_reclamation_schema_has_bounded_query_plans(self) -> None:
        connection = open_database()
        self.addCleanup(connection.close)
        objects = {
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type IN ('table','index')
                """
            )
        }
        self.assertTrue(
            {
                "team_attachment_cleanup_queue",
                "team_attachment_cleanup_queue_oldest",
                "team_attachments_reclaim_expired_by_team",
                "team_attachments_reclaim_expired_global",
            }.issubset(objects)
        )

        team_plan = " ".join(
            str(row[3])
            for row in connection.execute(
                """
                EXPLAIN QUERY PLAN
                SELECT id,storage_key,state FROM team_attachments
                WHERE message_id IS NULL AND expires_at<=? AND team_id=?
                ORDER BY expires_at,id LIMIT ?
                """,
                (NOW, "team_example", 128),
            )
        )
        global_plan = " ".join(
            str(row[3])
            for row in connection.execute(
                """
                EXPLAIN QUERY PLAN
                SELECT id,storage_key,state FROM team_attachments
                WHERE message_id IS NULL AND expires_at<=?
                ORDER BY expires_at,id LIMIT ?
                """,
                (NOW, 128),
            )
        )
        cleanup_plan = " ".join(
            str(row[3])
            for row in connection.execute(
                """
                EXPLAIN QUERY PLAN
                SELECT path_kind,path_key FROM team_attachment_cleanup_queue
                ORDER BY attempt_count,created_at,path_kind,path_key LIMIT ?
                """,
                (256,),
            )
        )
        self.assertIn("team_attachments_reclaim_expired_by_team", team_plan)
        self.assertIn("team_attachments_reclaim_expired_global", global_plan)
        self.assertIn("team_attachment_cleanup_queue_oldest", cleanup_plan)
        self.assertNotIn("TEMP B-TREE", team_plan)
        self.assertNotIn("TEMP B-TREE", global_plan)
        self.assertNotIn("TEMP B-TREE", cleanup_plan)

        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO team_attachment_cleanup_queue(path_kind,path_key,created_at)
                VALUES ('content','../../outside',?)
                """,
                (NOW,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO team_attachment_cleanup_queue(path_kind,path_key,created_at)
                VALUES ('staging','tatt_not-hex',?)
                """,
                (NOW,),
            )

    def test_version_five_database_upgrades_to_network_schema(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        connection.execute("PRAGMA foreign_keys = ON")
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
        for migration in MIGRATIONS[:5]:
            connection.executescript(migration.source)
            connection.execute(
                """
                INSERT INTO schema_migrations(version,name,sha256,applied_at)
                VALUES (?,?,?,?)
                """,
                (migration.version, migration.name, migration.sha256, NOW),
            )
            connection.execute(f"PRAGMA user_version = {migration.version}")

        self.assertEqual(apply_migrations(connection), LATEST_SCHEMA_VERSION)
        self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        objects = {
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type IN ('table','trigger','index')
                """
            )
        }
        self.assertTrue(
            {
                "network_peer_bindings",
                "network_boards",
                "network_mailbox_items",
                "network_deliveries",
                "network_passive_requests",
                "network_agents_limit_per_server",
                "network_bulletin_body_limit_on_insert",
                "network_bulletin_body_limit_on_update",
                "network_mailbox_sender_is_authorized",
                "network_delivery_state_is_monotonic",
                "network_request_state_is_forward_only",
            }.issubset(objects)
        )

    def test_tailnet_bootstrap_delegation_is_bound_and_immutable(self) -> None:
        connection = open_database()
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO hub_metadata(singleton, hub_id, created_at) VALUES (1, ?, ?)",
            ("hub_test12345678", NOW),
        )
        connection.execute(
            """
            INSERT INTO bootstrap_claims(id, token_hash, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            ("bootstrap_claim_test", b"a" * 32, NOW, NOW + 300),
        )
        values = (
            "bootstrap_claim_test",
            "58c9470a-9443-42f2-973c-b35d3f4ec768",
            b"b" * 32,
            "server-test-identity",
            "server-instance-test",
            "hub_test12345678",
            "https://sonic.example.ts.net:8444/api/team-hub",
            "owner@example.com",
            "owner@example.com",
            "Owner",
            "Owner Mac",
            NOW,
            NOW + 300,
        )
        connection.execute(
            """
            INSERT INTO bootstrap_delegations(
                bootstrap_claim_id, request_id, request_fingerprint,
                server_identity, server_instance_id, hub_id, hub_url,
                tailnet_login_normalized, recipient_email_normalized,
                display_name, device_label, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            connection.execute(
                "UPDATE bootstrap_delegations SET device_label = 'Other'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
            connection.execute("DELETE FROM bootstrap_delegations")
        connection.execute(
            """
            INSERT INTO bootstrap_claims(id, token_hash, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            ("bootstrap_claim_bad", b"c" * 32, NOW, NOW + 301),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "match its claim lifetime"):
            connection.execute(
                """
                INSERT INTO bootstrap_delegations(
                    bootstrap_claim_id, request_id, request_fingerprint,
                    server_identity, server_instance_id, hub_id, hub_url,
                    tailnet_login_normalized, recipient_email_normalized,
                    display_name, device_label, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "bootstrap_claim_bad",
                    "9aacde87-018a-4e1f-84b9-951ac6a75a7d",
                    b"d" * 32,
                    *values[3:-2],
                    NOW,
                    NOW + 300,
                ),
            )

    def test_changed_migration_checksum_is_rejected(self) -> None:
        connection = open_database()
        self.addCleanup(connection.close)
        connection.execute(
            "UPDATE schema_migrations SET sha256 = ? WHERE version = 1", ("0" * 64,)
        )
        with self.assertRaisesRegex(MigrationError, "checksum changed"):
            apply_migrations(connection)

    def test_database_from_a_newer_build_is_rejected(self) -> None:
        connection = open_database()
        self.addCleanup(connection.close)
        future_version = LATEST_SCHEMA_VERSION + 1
        connection.execute(
            """
            INSERT INTO schema_migrations(version, name, sha256, applied_at)
            VALUES (?, 'future', ?, ?)
            """,
            (future_version, "f" * 64, NOW),
        )
        connection.execute(f"PRAGMA user_version = {future_version}")
        with self.assertRaisesRegex(MigrationError, "newer"):
            apply_migrations(connection)

    def test_database_file_is_owner_only(self) -> None:
        test_root = Path(__file__).parent / ".tmp"
        test_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as directory:
            database_path = Path(directory) / "hub.sqlite3"
            connection = open_database(database_path)
            connection.close()
            self.assertEqual(stat.S_IMODE(os.stat(database_path).st_mode), 0o600)

    def test_database_permissions_override_hostile_umask_and_fail_closed(self) -> None:
        test_root = Path(__file__).parent / ".tmp"
        test_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as directory:
            database_path = Path(directory) / "umask.sqlite3"
            prior_umask = os.umask(0)
            try:
                connection = open_database(database_path)
                connection.close()
            finally:
                os.umask(prior_umask)
            self.assertEqual(stat.S_IMODE(os.stat(database_path).st_mode), 0o600)

            denied_path = Path(directory) / "denied.sqlite3"
            with mock.patch(
                "agentsdock_team_hub.database.os.fchmod",
                side_effect=PermissionError("denied"),
            ):
                with self.assertRaises(PermissionError):
                    open_database(denied_path)

    def test_two_connections_can_migrate_one_fresh_database(self) -> None:
        test_root = Path(__file__).parent / ".tmp"
        test_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as directory:
            database_path = Path(directory) / "concurrent-migration.sqlite3"
            barrier = threading.Barrier(2)

            def migrate() -> tuple[int, str]:
                barrier.wait(timeout=5)
                connection = open_database(database_path)
                try:
                    return (
                        connection.execute("PRAGMA user_version").fetchone()[0],
                        connection.execute("PRAGMA integrity_check").fetchone()[0],
                    )
                finally:
                    connection.close()

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: migrate(), range(2)))
            self.assertEqual(results, [(LATEST_SCHEMA_VERSION, "ok")] * 2)


class AuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = open_database()
        self.owner = bootstrap_personal_team(
            self.connection, "OWNER@Example.com", "Owner", now=NOW
        )

    def tearDown(self) -> None:
        self.connection.close()

    def add_human(self, number: int):
        return bootstrap_personal_team(
            self.connection,
            f"person{number}@example.com",
            f"Person {number}",
            now=NOW,
        )

    def test_personal_bootstrap_is_idempotent_and_has_one_owner(self) -> None:
        repeated = bootstrap_personal_team(
            self.connection, " owner@example.com ", "Different Label", now=NOW + 1
        )
        self.assertFalse(repeated.created)
        self.assertEqual(repeated.team_id, self.owner.team_id)
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM teams").fetchone()[0], 1
        )

        other = self.add_human(1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO memberships(
                    id, team_id, principal_id, role, status, created_at, updated_at
                ) VALUES ('second-owner', ?, ?, 'owner', 'active', ?, ?)
                """,
                (self.owner.team_id, other.human_principal_id, NOW, NOW),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                "UPDATE teams SET personal_owner_principal_id = ? WHERE id = ?",
                (other.human_principal_id, self.owner.team_id),
            )

        self.connection.execute(
            """
            INSERT INTO principals(id, kind, display_name, created_at, updated_at)
            VALUES ('service-principal', 'service', 'Service', ?, ?)
            """,
            (NOW, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO service_accounts(principal_id, service_identifier, created_at)
            VALUES ('service-principal', 'service.test', ?)
            """,
            (NOW,),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                """
                UPDATE human_accounts SET principal_id = 'service-principal'
                WHERE principal_id = ?
                """,
                (self.owner.human_principal_id,),
            )

    def test_invitation_is_hashed_email_bound_short_lived_and_one_time(self) -> None:
        invited = self.add_human(2)
        issued = issue_invitation(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            "member",
            invitee_email="person2@example.com",
            ttl_seconds=60,
            now=NOW,
        )
        stored = self.connection.execute(
            "SELECT token_hash FROM invitations WHERE id = ?", (issued.id,)
        ).fetchone()[0]
        self.assertEqual(stored, hashlib.sha256(issued.token.encode()).digest())
        self.assertNotEqual(stored, issued.token.encode())
        self.assertNotIn(issued.token, repr(issued))

        membership_id = redeem_invitation(
            self.connection, issued.token, invited.human_principal_id, now=NOW + 1
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT role FROM memberships WHERE id = ?", (membership_id,)
            ).fetchone()[0],
            "member",
        )
        with self.assertRaises(AuthenticationError):
            redeem_invitation(
                self.connection, issued.token, invited.human_principal_id, now=NOW + 2
            )

    def test_invitation_fails_closed_for_email_expiry_and_role(self) -> None:
        invited = self.add_human(3)
        wrong_human = self.add_human(4)
        email_bound = issue_invitation(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            "guest",
            invitee_email="person3@example.com",
            ttl_seconds=30,
            now=NOW,
        )
        with self.assertRaises(AuthenticationError):
            redeem_invitation(
                self.connection,
                email_bound.token,
                wrong_human.human_principal_id,
                now=NOW + 1,
            )
        with self.assertRaises(AuthenticationError):
            redeem_invitation(
                self.connection,
                email_bound.token,
                invited.human_principal_id,
                now=NOW + 30,
            )

        member_invite = issue_invitation(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            "member",
            invitee_email="person3@example.com",
            ttl_seconds=60,
            now=NOW,
        )
        redeem_invitation(
            self.connection,
            member_invite.token,
            invited.human_principal_id,
            now=NOW + 1,
        )
        with self.assertRaises(AuthorizationError):
            issue_invitation(
                self.connection,
                self.owner.team_id,
                invited.human_principal_id,
                "guest",
                invitee_email="nobody@example.com",
                now=NOW + 2,
            )

    def test_node_enrollment_is_distinct_atomic_and_one_time(self) -> None:
        record_legacy_server_binding(
            self.connection,
            self.owner.team_id,
            "server:0123456789abcdef",
            self.owner.human_principal_id,
            now=NOW,
        )
        grant = issue_node_enrollment(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            ttl_seconds=60,
            now=NOW,
        )
        enrolled = redeem_node_enrollment(
            self.connection,
            grant.token,
            "server:0123456789abcdef",
            "Primary node",
            "ed25519",
            ed25519_public(1, "first-node-comment"),
            now=NOW + 1,
        )
        self.assertEqual(enrolled.team_id, self.owner.team_id)
        self.assertEqual(
            self.connection.execute(
                "SELECT public_material FROM node_credentials WHERE id = ?",
                (enrolled.credential_id,),
            ).fetchone()[0],
            ed25519_public(1),
        )
        self.assertEqual(
            self.connection.execute(
                """
                SELECT node_id FROM legacy_server_bindings
                WHERE server_identity = 'server:0123456789abcdef'
                """
            ).fetchone()[0],
            enrolled.node_id,
        )
        with self.assertRaises(AuthenticationError):
            redeem_node_enrollment(
                self.connection,
                grant.token,
                "server:fedcba9876543210",
                "Replay node",
                "ed25519",
                ed25519_public(2),
                now=NOW + 2,
            )

        second = issue_node_enrollment(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            now=NOW + 2,
        )
        with self.assertRaises(AuthorizationError):
            redeem_node_enrollment(
                self.connection,
                second.token,
                "server:0123456789abcdef",
                "Duplicate node",
                "ed25519",
                ed25519_public(3),
                now=NOW + 3,
            )
        self.assertIsNone(
            self.connection.execute(
                "SELECT consumed_at FROM node_enrollment_grants WHERE id = ?", (second.id,)
            ).fetchone()[0]
        )

    def test_revoked_principals_and_demoted_issuers_fail_closed(self) -> None:
        invited_principal_id = "unowned-person-6"
        self.connection.execute(
            """
            INSERT INTO principals(id, kind, display_name, created_at, updated_at)
            VALUES (?, 'human', 'Person 6', ?, ?)
            """,
            (invited_principal_id, NOW, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO human_accounts(principal_id, email_normalized, created_at)
            VALUES (?, 'person6@example.com', ?)
            """,
            (invited_principal_id, NOW),
        )
        invitation = issue_invitation(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            "member",
            invitee_email="person6@example.com",
            now=NOW,
        )
        self.connection.execute(
            "UPDATE principals SET status = 'revoked', updated_at = ? WHERE id = ?",
            (NOW + 1, invited_principal_id),
        )
        with self.assertRaises(AuthenticationError):
            redeem_invitation(
                self.connection,
                invitation.token,
                invited_principal_id,
                now=NOW + 2,
            )
        with self.assertRaises(AuthenticationError):
            bootstrap_personal_team(
                self.connection, "person6@example.com", "Revoked", now=NOW + 2
            )

        other = self.add_human(7)
        administrator = issue_invitation(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            "admin",
            invitee_email="person7@example.com",
            now=NOW,
        )
        administrator_membership_id = redeem_invitation(
            self.connection,
            administrator.token,
            other.human_principal_id,
            now=NOW + 1,
        )
        target = self.add_human(8)
        outstanding = issue_invitation(
            self.connection,
            self.owner.team_id,
            other.human_principal_id,
            "guest",
            invitee_email="person8@example.com",
            now=NOW,
        )
        self.connection.execute(
            "UPDATE memberships SET role = 'member', updated_at = ? WHERE id = ?",
            (NOW + 1, administrator_membership_id),
        )
        with self.assertRaises(AuthenticationError):
            redeem_invitation(
                self.connection,
                outstanding.token,
                target.human_principal_id,
                now=NOW + 2,
            )
        with self.assertRaises(AuthorizationError):
            issue_node_enrollment(
                self.connection,
                self.owner.team_id,
                other.human_principal_id,
                now=NOW + 2,
            )

    def test_consumed_and_revoked_credentials_cannot_be_reopened(self) -> None:
        invited = self.add_human(9)
        invitation = issue_invitation(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            "member",
            invitee_email="person9@example.com",
            now=NOW,
        )
        redeem_invitation(
            self.connection,
            invitation.token,
            invited.human_principal_id,
            now=NOW + 1,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "one-way"):
            self.connection.execute(
                """
                UPDATE invitations
                SET redeemed_at = NULL, redeemed_by_principal_id = NULL
                WHERE id = ?
                """,
                (invitation.id,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
            self.connection.execute(
                "DELETE FROM invitations WHERE id = ?", (invitation.id,)
            )

        grant = issue_node_enrollment(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            now=NOW,
        )
        node = redeem_node_enrollment(
            self.connection,
            grant.token,
            "server:immutable-credential",
            "Immutable node",
            "ed25519",
            ed25519_public(10),
            now=NOW + 1,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "one-way"):
            self.connection.execute(
                """
                UPDATE node_enrollment_grants
                SET consumed_at = NULL, consumed_by_node_id = NULL
                WHERE id = ?
                """,
                (grant.id,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                "UPDATE node_credentials SET public_material = ? WHERE id = ?",
                (ed25519_public(11), node.credential_id),
            )

        private_material_grant = issue_node_enrollment(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            now=NOW + 4,
        )
        with self.assertRaisesRegex(ValueError, "private key"):
            redeem_node_enrollment(
                self.connection,
                private_material_grant.token,
                "server:must-not-store-private-key",
                "Unsafe node",
                "ed25519",
                "-----BEGIN PRIVATE KEY-----\nnot-public\n-----END PRIVATE KEY-----",
                now=NOW + 5,
            )
        self.assertIsNone(
            self.connection.execute(
                "SELECT consumed_at FROM node_enrollment_grants WHERE id = ?",
                (private_material_grant.id,),
            ).fetchone()[0]
        )

    def test_session_rotation_and_revocation_ledgers_are_one_way(self) -> None:
        other = self.add_human(12)
        for session_id, principal_id in (
            ("device-owner", self.owner.human_principal_id),
            ("device-other", other.human_principal_id),
        ):
            self.connection.execute(
                """
                INSERT INTO device_sessions(
                    id, human_principal_id, device_label, refresh_generation,
                    created_at, last_seen_at, expires_at
                ) VALUES (?, ?, 'Test device', 0, ?, ?, ?)
                """,
                (session_id, principal_id, NOW, NOW, NOW + 3600),
            )
        for token_id, session_id, generation, fill in (
            ("refresh-old", "device-owner", 0, b"a"),
            ("refresh-next", "device-owner", 1, b"b"),
            ("refresh-other", "device-other", 1, b"c"),
        ):
            self.connection.execute(
                """
                INSERT INTO refresh_tokens(
                    id, device_session_id, token_hash, generation,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token_id, session_id, fill * 32, generation, NOW, NOW + 3600),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                UPDATE refresh_tokens
                SET consumed_at = ?, replaced_by_token_id = 'refresh-other'
                WHERE id = 'refresh-old'
                """,
                (NOW + 1,),
            )
        self.connection.execute(
            """
            UPDATE refresh_tokens
            SET consumed_at = ?, replaced_by_token_id = 'refresh-next'
            WHERE id = 'refresh-old'
            """,
            (NOW + 1,),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "one-way"):
            self.connection.execute(
                """
                UPDATE refresh_tokens
                SET consumed_at = NULL, replaced_by_token_id = NULL
                WHERE id = 'refresh-old'
                """
            )

        self.connection.execute(
            """
            INSERT INTO access_token_revocations(
                jti_hash, device_session_id, expires_at, revoked_at, reason
            ) VALUES (?, 'device-owner', ?, ?, 'test revocation')
            """,
            (b"j" * 32, NOW + 60, NOW),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                "DELETE FROM access_token_revocations WHERE jti_hash = ?", (b"j" * 32,)
            )

        self.connection.execute(
            "UPDATE device_sessions SET revoked_at = ? WHERE id = 'device-owner'",
            (NOW + 2,),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "monotonic"):
            self.connection.execute(
                "UPDATE device_sessions SET revoked_at = NULL WHERE id = 'device-owner'"
            )

    def test_legacy_binding_never_accepts_or_stores_server_bearer(self) -> None:
        signature = inspect.signature(record_legacy_server_binding)
        self.assertNotIn("token", signature.parameters)
        self.assertNotIn("bearer", signature.parameters)
        binding_id = record_legacy_server_binding(
            self.connection,
            self.owner.team_id,
            "legacy:0123456789abcdef",
            self.owner.human_principal_id,
            now=NOW,
        )
        self.assertEqual(
            binding_id,
            record_legacy_server_binding(
                self.connection,
                self.owner.team_id,
                "legacy:0123456789abcdef",
                self.owner.human_principal_id,
                now=NOW + 1,
            ),
        )
        columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(legacy_server_bindings)")
        }
        self.assertTrue(columns.isdisjoint({"token", "token_hash", "bearer", "secret"}))
        outsider = self.add_human(8)
        with self.assertRaises(AuthorizationError):
            record_legacy_server_binding(
                self.connection,
                self.owner.team_id,
                "legacy:unauthorized-server",
                outsider.human_principal_id,
                now=NOW + 2,
            )

    def test_invitation_redemption_is_atomic_across_connections(self) -> None:
        test_root = Path(__file__).parent / ".tmp"
        test_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as directory:
            database_path = Path(directory) / "concurrent.sqlite3"
            connection = open_database(database_path)
            owner = bootstrap_personal_team(
                connection, "concurrent-owner@example.com", "Owner", now=NOW
            )
            invited = bootstrap_personal_team(
                connection, "concurrent-member@example.com", "Member", now=NOW
            )
            issued = issue_invitation(
                connection,
                owner.team_id,
                owner.human_principal_id,
                "member",
                invitee_email="concurrent-member@example.com",
                ttl_seconds=60,
                now=NOW,
            )
            connection.close()
            barrier = threading.Barrier(2)

            def redeem() -> str:
                worker = open_database(database_path)
                try:
                    barrier.wait(timeout=5)
                    redeem_invitation(
                        worker, issued.token, invited.human_principal_id, now=NOW + 1
                    )
                    return "accepted"
                except AuthenticationError:
                    return "rejected"
                finally:
                    worker.close()

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = sorted(executor.map(lambda _: redeem(), range(2)))
            self.assertEqual(results, ["accepted", "rejected"])


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = open_database()
        self.owner = bootstrap_personal_team(
            self.connection, "ledger@example.com", "Ledger Owner", now=NOW
        )
        grant = issue_node_enrollment(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            now=NOW,
        )
        self.node = redeem_node_enrollment(
            self.connection,
            grant.token,
            "server:ledger-primary",
            "Ledger node",
            "ed25519",
            ed25519_public(4),
            now=NOW + 1,
        )
        self.agent_principal_id = "agent-principal"
        self.agent_id = "agent-1"
        self.chat_principal_id = "chat-principal"
        self.chat_id = "chat-1"
        self.run_id = "run-1"
        self.channel_id = "channel-1"
        self.connection.execute(
            """
            INSERT INTO principals(
                id, kind, scope_team_id, display_name, created_at, updated_at
            ) VALUES (?, 'agent', ?, 'Agent', ?, ?)
            """,
            (self.agent_principal_id, self.owner.team_id, NOW, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO agents(
                id, team_id, principal_id, node_id, external_agent_id,
                backend, display_name, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'provider-agent-1', 'codex', 'Agent', ?, ?)
            """,
            (
                self.agent_id,
                self.owner.team_id,
                self.agent_principal_id,
                self.node.node_id,
                NOW,
                NOW,
            ),
        )
        self.connection.execute(
            """
            INSERT INTO principals(
                id, kind, scope_team_id, display_name, created_at, updated_at
            ) VALUES (?, 'chat', ?, 'Chat', ?, ?)
            """,
            (self.chat_principal_id, self.owner.team_id, NOW, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO chats(
                id, team_id, principal_id, node_id, agent_id, external_chat_id,
                display_name, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'provider-chat-1', 'Chat', ?, ?)
            """,
            (
                self.chat_id,
                self.owner.team_id,
                self.chat_principal_id,
                self.node.node_id,
                self.agent_id,
                NOW,
                NOW,
            ),
        )
        self.connection.execute(
            """
            INSERT INTO runs(
                id, team_id, node_id, agent_id, chat_id,
                acting_human_principal_id, external_run_id, status, started_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'provider-run-1', 'running', ?)
            """,
            (
                self.run_id,
                self.owner.team_id,
                self.node.node_id,
                self.agent_id,
                self.chat_id,
                self.owner.human_principal_id,
                NOW,
            ),
        )
        self.connection.execute(
            """
            INSERT INTO channels(
                id, team_id, kind, visibility, slug, display_name,
                created_by_principal_id, created_at, updated_at
            ) VALUES (?, ?, 'board', 'team', 'general', 'General', ?, ?, ?)
            """,
            (
                self.channel_id,
                self.owner.team_id,
                self.owner.human_principal_id,
                NOW,
                NOW,
            ),
        )

    def tearDown(self) -> None:
        self.connection.close()

    def add_message(self, message_id: str, body: str, sequence: int) -> None:
        self.connection.execute(
            """
            INSERT INTO messages(
                id, team_id, channel_id, channel_sequence, kind,
                author_principal_id, body, idempotency_key, created_at
            ) VALUES (?, ?, ?, ?, 'post', ?, ?, ?, ?)
            """,
            (
                message_id,
                self.owner.team_id,
                self.channel_id,
                sequence,
                self.owner.human_principal_id,
                body,
                hashlib.sha256(message_id.encode()).digest(),
                NOW,
            ),
        )

    def test_message_kinds_cannot_encode_dispatch(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO messages(
                    id, team_id, channel_id, channel_sequence, kind,
                    author_principal_id, body, idempotency_key, created_at
                ) VALUES ('bad', ?, ?, 1, 'dispatch', ?, 'wake everyone', ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.channel_id,
                    self.owner.human_principal_id,
                    b"x" * 32,
                    NOW,
                ),
            )

    def test_dispatch_fifo_causation_and_delegation_records_are_bounded(self) -> None:
        self.add_message("dispatch-source", "Explicit source", 1)
        self.connection.execute(
            """
            INSERT INTO dispatch_requests(
                id, team_id, requested_by_human_principal_id, source_message_id,
                target_kind, target_node_id, target_agent_id, request_text,
                idempotency_key, created_at, updated_at, expires_at
            ) VALUES ('dispatch-root', ?, ?, 'dispatch-source', 'agent', ?, ?,
                      'Root request', ?, ?, ?, ?)
            """,
            (
                self.owner.team_id,
                self.owner.human_principal_id,
                self.node.node_id,
                self.agent_id,
                b"1" * 32,
                NOW,
                NOW,
                NOW + 300,
            ),
        )
        self.connection.execute(
            """
            INSERT INTO turn_capabilities(
                id, team_id, issued_to_run_id, issued_by_principal_id,
                token_hash, action, resource_type, resource_id, nonce_hash,
                max_uses, created_at, expires_at
            ) VALUES ('dispatch-capability', ?, ?, ?, ?, 'dispatch', 'agent', ?, ?,
                      1, ?, ?)
            """,
            (
                self.owner.team_id,
                self.run_id,
                self.owner.human_principal_id,
                b"t" * 32,
                self.agent_id,
                b"n" * 32,
                NOW,
                NOW + 60,
            ),
        )
        self.connection.execute(
            """
            INSERT INTO dispatch_requests(
                id, team_id, requested_by_human_principal_id, target_kind,
                target_node_id, target_agent_id, request_text, idempotency_key,
                created_at, updated_at, expires_at
            ) VALUES ('unbound-parent', ?, ?, 'agent', ?, ?, 'Not admitted', ?, ?, ?, ?)
            """,
            (
                self.owner.team_id,
                self.owner.human_principal_id,
                self.node.node_id,
                self.agent_id,
                b"u" * 32,
                NOW,
                NOW,
                NOW + 300,
            ),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "bounded"):
            self.connection.execute(
                """
                INSERT INTO dispatch_requests(
                    id, team_id, requester_kind, requested_by_human_principal_id,
                    requesting_node_id, requesting_agent_id, requesting_chat_id,
                    requesting_run_id, authorization_capability_id,
                    target_kind, target_node_id, target_agent_id, request_text,
                    idempotency_key, causation_dispatch_id, root_dispatch_id,
                    hop_count, created_at, updated_at, expires_at
                ) VALUES ('wrong-parent-run', ?, 'agent', ?, ?, ?, ?, ?,
                          'dispatch-capability', 'agent', ?, ?, 'Wrong parent', ?,
                          'unbound-parent', 'unbound-parent', 1, ?, ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.owner.human_principal_id,
                    self.node.node_id,
                    self.agent_id,
                    self.chat_id,
                    self.run_id,
                    self.node.node_id,
                    self.agent_id,
                    b"v" * 32,
                    NOW + 1,
                    NOW + 1,
                    NOW + 300,
                ),
            )
        self.connection.execute(
            "UPDATE dispatch_requests SET target_run_id = ? WHERE id = 'dispatch-root'",
            (self.run_id,),
        )
        self.connection.execute(
            """
            INSERT INTO dispatch_requests(
                id, team_id, requester_kind, requested_by_human_principal_id,
                requesting_node_id, requesting_agent_id, requesting_chat_id,
                requesting_run_id, authorization_capability_id,
                target_kind, target_node_id, target_agent_id, request_text,
                idempotency_key, causation_dispatch_id, root_dispatch_id,
                hop_count, created_at, updated_at, expires_at
            ) VALUES ('dispatch-child', ?, 'agent', ?, ?, ?, ?, ?,
                      'dispatch-capability', 'agent', ?, ?, 'Bounded child', ?,
                      'dispatch-root', 'dispatch-root', 1, ?, ?, ?)
            """,
            (
                self.owner.team_id,
                self.owner.human_principal_id,
                self.node.node_id,
                self.agent_id,
                self.chat_id,
                self.run_id,
                self.node.node_id,
                self.agent_id,
                b"2" * 32,
                NOW + 1,
                NOW + 1,
                NOW + 300,
            ),
        )
        ordinals = [
            row[0]
            for row in self.connection.execute(
                """
                SELECT queue_ordinal FROM dispatch_requests
                WHERE id IN ('dispatch-root', 'dispatch-child')
                ORDER BY queue_ordinal
                """
            )
        ]
        self.assertEqual(len(ordinals), 2)
        self.assertLess(ordinals[0], ordinals[1])

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO dispatch_requests(
                    id, team_id, requester_kind,
                    requested_by_human_principal_id, requesting_node_id,
                    requesting_agent_id, requesting_chat_id, requesting_run_id,
                    authorization_capability_id, target_kind, target_node_id,
                    target_agent_id, request_text, idempotency_key,
                    created_at, updated_at, expires_at
                ) VALUES ('agent-new-root', ?, 'agent', ?, ?, ?, ?, ?,
                          'dispatch-capability', 'agent', ?, ?, 'No root reset', ?,
                          ?, ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.owner.human_principal_id,
                    self.node.node_id,
                    self.agent_id,
                    self.chat_id,
                    self.run_id,
                    self.node.node_id,
                    self.agent_id,
                    b"3" * 32,
                    NOW + 2,
                    NOW + 2,
                    NOW + 300,
                ),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "bounded"):
            self.connection.execute(
                """
                INSERT INTO dispatch_requests(
                    id, team_id, requested_by_human_principal_id,
                    target_kind, target_node_id, target_agent_id, request_text,
                    idempotency_key, causation_dispatch_id, root_dispatch_id,
                    hop_count, created_at, updated_at, expires_at
                ) VALUES ('bad-hop', ?, ?, 'agent', ?, ?, 'Bad hop', ?,
                          'dispatch-root', 'dispatch-root', 2, ?, ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.owner.human_principal_id,
                    self.node.node_id,
                    self.agent_id,
                    b"4" * 32,
                    NOW + 2,
                    NOW + 2,
                    NOW + 300,
                ),
            )

        self.connection.execute(
            "UPDATE turn_capabilities SET used_count = 1 WHERE id = 'dispatch-capability'"
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "monotonic"):
            self.connection.execute(
                "UPDATE turn_capabilities SET used_count = 0 WHERE id = 'dispatch-capability'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
            self.connection.execute(
                "DELETE FROM turn_capabilities WHERE id = 'dispatch-capability'"
            )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "one-way"):
            self.connection.execute(
                "UPDATE dispatch_requests SET target_run_id = NULL WHERE id = 'dispatch-root'"
            )

    def test_direct_records_cannot_claim_delegated_human_provenance(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO messages(
                    id, team_id, channel_id, channel_sequence, kind,
                    author_principal_id, acting_human_principal_id,
                    body, idempotency_key, created_at
                ) VALUES ('false-direct-message', ?, ?, 1, 'post', ?, ?,
                          'False delegation', ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.channel_id,
                    self.owner.human_principal_id,
                    self.owner.human_principal_id,
                    b"z" * 32,
                    NOW,
                ),
            )

        self.connection.execute(
            """
            INSERT INTO artifacts(
                id, team_id, kind, display_name, created_by_principal_id, created_at
            ) VALUES ('artifact-direct', ?, 'runbook', 'Runbook', ?, ?)
            """,
            (self.owner.team_id, self.owner.human_principal_id, NOW),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO artifact_versions(
                    id, team_id, artifact_id, version, media_type, byte_size,
                    sha256, storage_key, created_by_principal_id,
                    acting_human_principal_id, created_at
                ) VALUES ('artifact-version-bad', ?, 'artifact-direct', 1,
                          'text/markdown', 4, ?, 'objects/artifact-bad', ?, ?, ?)
                """,
                (
                    self.owner.team_id,
                    b"a" * 32,
                    self.owner.human_principal_id,
                    self.owner.human_principal_id,
                    NOW,
                ),
            )
        self.connection.execute(
            """
            INSERT INTO artifact_versions(
                id, team_id, artifact_id, version, media_type, byte_size,
                sha256, storage_key, created_by_principal_id, created_at
            ) VALUES ('artifact-version-good', ?, 'artifact-direct', 1,
                      'text/markdown', 4, ?, 'objects/artifact-good', ?, ?)
            """,
            (
                self.owner.team_id,
                b"b" * 32,
                self.owner.human_principal_id,
                NOW,
            ),
        )
        self.connection.execute(
            """
            INSERT INTO library_items(
                id, team_id, kind, slug, display_name,
                created_by_principal_id, created_at, updated_at
            ) VALUES ('library-direct', ?, 'runbook', 'direct-runbook',
                      'Direct runbook', ?, ?, ?)
            """,
            (
                self.owner.team_id,
                self.owner.human_principal_id,
                NOW,
                NOW,
            ),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO library_versions(
                    id, team_id, library_item_id, version, artifact_version_id,
                    permissions_json, acting_human_principal_id,
                    published_by_principal_id, created_at
                ) VALUES ('library-version-bad', ?, 'library-direct', 1,
                          'artifact-version-good', '{}', ?, ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.owner.human_principal_id,
                    self.owner.human_principal_id,
                    NOW,
                ),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO subscriptions(
                    id, team_id, subscriber_principal_id, channel_id,
                    level, delivery_mode, wake_mode, created_at, updated_at
                ) VALUES ('wake-sub', ?, ?, ?, 'all', 'inbox', 'dispatch', ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.agent_principal_id,
                    self.channel_id,
                    NOW,
                    NOW,
                ),
            )

        self.add_message("source-message", "Please investigate", 2)
        self.connection.execute(
            """
            INSERT INTO dispatch_requests(
                id, team_id, requested_by_human_principal_id, source_message_id,
                target_kind, target_node_id, target_agent_id, request_text,
                idempotency_key, created_at, updated_at, expires_at
            ) VALUES ('dispatch-1', ?, ?, 'source-message', 'agent', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.owner.team_id,
                self.owner.human_principal_id,
                self.node.node_id,
                self.agent_id,
                "Explicitly investigate this post",
                b"d" * 32,
                NOW,
                NOW,
                NOW + 300,
            ),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT status FROM dispatch_requests WHERE id = 'dispatch-1'"
            ).fetchone()[0],
            "registered",
        )

        second_grant = issue_node_enrollment(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            now=NOW + 2,
        )
        second_node = redeem_node_enrollment(
            self.connection,
            second_grant.token,
            "server:ledger-secondary",
            "Secondary node",
            "ed25519",
            ed25519_public(5),
            now=NOW + 3,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO dispatch_requests(
                    id, team_id, requested_by_human_principal_id,
                    target_kind, target_node_id, target_agent_id, request_text,
                    idempotency_key, created_at, updated_at, expires_at
                ) VALUES ('wrong-node', ?, ?, 'agent', ?, ?, 'Wrong node', ?, ?, ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.owner.human_principal_id,
                    second_node.node_id,
                    self.agent_id,
                    b"w" * 32,
                    NOW,
                    NOW,
                    NOW + 300,
                ),
            )

    def test_agent_authorship_requires_exact_complete_provenance(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO messages(
                    id, team_id, channel_id, channel_sequence, kind,
                    author_principal_id, body, idempotency_key, created_at
                ) VALUES ('agent-bad', ?, ?, 1, 'post', ?, 'No provenance', ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.channel_id,
                    self.agent_principal_id,
                    b"a" * 32,
                    NOW,
                ),
            )
        other_human = bootstrap_personal_team(
            self.connection, "other-actor@example.com", "Other Actor", now=NOW
        )
        actor_invite = issue_invitation(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            "member",
            invitee_email="other-actor@example.com",
            now=NOW,
        )
        redeem_invitation(
            self.connection,
            actor_invite.token,
            other_human.human_principal_id,
            now=NOW + 1,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "exact"):
            self.connection.execute(
                """
                INSERT INTO messages(
                    id, team_id, channel_id, channel_sequence, kind,
                    author_principal_id, acting_human_principal_id,
                    provenance_node_id, provenance_agent_id, provenance_chat_id,
                    provenance_run_id, body, idempotency_key, created_at
                ) VALUES ('wrong-actor', ?, ?, 1, 'post', ?, ?, ?, ?, ?, ?,
                          'Wrong actor', ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.channel_id,
                    self.agent_principal_id,
                    other_human.human_principal_id,
                    self.node.node_id,
                    self.agent_id,
                    self.chat_id,
                    self.run_id,
                    b"r" * 32,
                    NOW,
                ),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "only an agent"):
            self.connection.execute(
                """
                INSERT INTO messages(
                    id, team_id, channel_id, channel_sequence, kind,
                    author_principal_id, acting_human_principal_id,
                    provenance_node_id, provenance_agent_id, provenance_chat_id,
                    provenance_run_id, body, idempotency_key, created_at
                ) VALUES ('human-false-provenance', ?, ?, 2, 'post', ?, ?, ?, ?, ?, ?,
                          'False claim', ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.channel_id,
                    self.owner.human_principal_id,
                    self.owner.human_principal_id,
                    self.node.node_id,
                    self.agent_id,
                    self.chat_id,
                    self.run_id,
                    b"f" * 32,
                    NOW,
                ),
            )
        self.connection.execute(
            """
            INSERT INTO messages(
                id, team_id, channel_id, channel_sequence, kind,
                author_principal_id, acting_human_principal_id,
                provenance_node_id, provenance_agent_id, provenance_chat_id,
                provenance_run_id, body, idempotency_key, created_at
            ) VALUES ('agent-good', ?, ?, 1, 'post', ?, ?, ?, ?, ?, ?, 'Verified', ?, ?)
            """,
            (
                self.owner.team_id,
                self.channel_id,
                self.agent_principal_id,
                self.owner.human_principal_id,
                self.node.node_id,
                self.agent_id,
                self.chat_id,
                self.run_id,
                b"p" * 32,
                NOW,
            ),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                """
                UPDATE messages SET acting_human_principal_id = ?
                WHERE id = 'agent-good'
                """,
                (other_human.human_principal_id,),
            )

    def test_message_search_and_soft_delete_are_consistent(self) -> None:
        self.add_message("searchable", "A narwhal runbook", 1)
        self.assertEqual(
            self.connection.execute(
                "SELECT id FROM message_search WHERE message_search MATCH 'narwhal'"
            ).fetchone()[0],
            "searchable",
        )
        self.connection.execute(
            "UPDATE messages SET deleted_at = ? WHERE id = 'searchable'", (NOW + 1,)
        )
        self.assertIsNone(
            self.connection.execute(
                "SELECT id FROM message_search WHERE message_search MATCH 'narwhal'"
            ).fetchone()
        )

    def test_audit_is_immutable_and_outbox_is_idempotent(self) -> None:
        self.connection.execute(
            """
            INSERT INTO audit_events(
                id, team_id, actor_principal_id, action, resource_type,
                resource_id, outcome, event_hash, created_at
            ) VALUES ('audit-1', ?, ?, 'team.created', 'team', ?, 'succeeded', ?, ?)
            """,
            (
                self.owner.team_id,
                self.owner.human_principal_id,
                self.owner.team_id,
                b"h" * 32,
                NOW,
            ),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                "UPDATE audit_events SET outcome = 'failed' WHERE id = 'audit-1'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute("DELETE FROM audit_events WHERE id = 'audit-1'")

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO audit_events(
                    id, team_id, actor_principal_id, acting_human_principal_id,
                    action, resource_type, resource_id, outcome, event_hash, created_at
                ) VALUES ('audit-false-delegation', ?, ?, ?, 'team.read', 'team', ?,
                          'denied', ?, ?)
                """,
                (
                    self.owner.team_id,
                    self.owner.human_principal_id,
                    self.owner.human_principal_id,
                    self.owner.team_id,
                    b"f" * 32,
                    NOW,
                ),
            )

        revoked_principal_id = "revoked-auditor"
        self.connection.execute(
            """
            INSERT INTO principals(id, kind, display_name, created_at, updated_at)
            VALUES (?, 'human', 'Revoked Auditor', ?, ?)
            """,
            (revoked_principal_id, NOW, NOW),
        )
        self.connection.execute(
            """
            INSERT INTO human_accounts(principal_id, email_normalized, created_at)
            VALUES (?, 'revoked-auditor@example.com', ?)
            """,
            (revoked_principal_id, NOW),
        )
        revoked_invite = issue_invitation(
            self.connection,
            self.owner.team_id,
            self.owner.human_principal_id,
            "member",
            invitee_email="revoked-auditor@example.com",
            now=NOW,
        )
        redeem_invitation(
            self.connection,
            revoked_invite.token,
            revoked_principal_id,
            now=NOW + 1,
        )
        self.connection.execute(
            "UPDATE principals SET status = 'revoked', updated_at = ? WHERE id = ?",
            (NOW + 2, revoked_principal_id),
        )
        self.connection.execute(
            """
            INSERT INTO audit_events(
                id, team_id, actor_principal_id, action, resource_type,
                resource_id, outcome, event_hash, created_at
            ) VALUES ('audit-denied-revoked', ?, ?, 'team.read', 'team', ?,
                      'denied', ?, ?)
            """,
            (
                self.owner.team_id,
                revoked_principal_id,
                self.owner.team_id,
                b"r" * 32,
                NOW + 2,
            ),
        )

        values = (
            "outbox-1",
            self.owner.team_id,
            "message",
            "m-1",
            "message.created",
            "{}",
            b"o" * 32,
            NOW,
            NOW,
        )
        self.connection.execute(
            """
            INSERT INTO outbox_events(
                id, team_id, aggregate_type, aggregate_id, event_type,
                metadata_json, idempotency_key, available_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                "UPDATE outbox_events SET metadata_json = '{\"changed\":true}' "
                "WHERE id = 'outbox-1'"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO outbox_events(
                    id, team_id, aggregate_type, aggregate_id, event_type,
                    metadata_json, idempotency_key, available_at, created_at
                ) VALUES ('outbox-2', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values[1:],
            )

    def test_acl_entries_cannot_duplicate_nullable_subjects(self) -> None:
        values = (
            self.owner.team_id,
            self.channel_id,
            self.owner.human_principal_id,
            NOW,
        )
        self.connection.execute(
            """
            INSERT INTO channel_acl_entries(
                id, team_id, channel_id, subject_kind, subject_principal_id,
                can_read, can_post, can_manage, can_dispatch, created_at
            ) VALUES ('acl-1', ?, ?, 'principal', ?, 1, 1, 0, 0, ?)
            """,
            values,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO channel_acl_entries(
                    id, team_id, channel_id, subject_kind, subject_principal_id,
                    can_read, can_post, can_manage, can_dispatch, created_at
                ) VALUES ('acl-2', ?, ?, 'principal', ?, 1, 0, 0, 0, ?)
                """,
                values,
            )

    def test_cross_team_principals_are_rejected_from_channel_metadata(self) -> None:
        outsider = bootstrap_personal_team(
            self.connection, "outsider@example.com", "Outsider", now=NOW
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "does not belong"):
            self.connection.execute(
                """
                INSERT INTO channel_acl_entries(
                    id, team_id, channel_id, subject_kind, subject_principal_id,
                    can_read, can_post, can_manage, can_dispatch, created_at
                ) VALUES ('outsider-acl', ?, ?, 'principal', ?, 1, 0, 0, 0, ?)
                """,
                (
                    self.owner.team_id,
                    self.channel_id,
                    outsider.human_principal_id,
                    NOW,
                ),
            )
        self.add_message("mention-source", "No cross-team mention", 1)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "does not belong"):
            self.connection.execute(
                """
                INSERT INTO message_mentions(
                    team_id, message_id, principal_id, start_offset, end_offset
                ) VALUES (?, 'mention-source', ?, 0, 4)
                """,
                (self.owner.team_id, outsider.human_principal_id),
            )
        self.connection.execute(
            """
            INSERT INTO channel_acl_entries(
                id, team_id, channel_id, subject_kind, subject_principal_id,
                can_read, can_post, can_manage, can_dispatch, created_at
            ) VALUES ('owner-acl', ?, ?, 'principal', ?, 1, 1, 1, 1, ?)
            """,
            (
                self.owner.team_id,
                self.channel_id,
                self.owner.human_principal_id,
                NOW,
            ),
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.connection.execute(
                """
                UPDATE channel_acl_entries SET subject_principal_id = ?
                WHERE id = 'owner-acl'
                """,
                (outsider.human_principal_id,),
            )


if __name__ == "__main__":
    unittest.main()
