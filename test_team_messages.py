"""Team Messages V2 service tests: messages, receipts, attachments, skills."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

from fastapi.testclient import TestClient

from agentsdock_team_hub.service import create_app
from agentsdock_team_hub.store import (
    HubError,
    MAX_TEAM_MESSAGE_BODY_BYTES,
    TEAM_ATTACHMENT_CHUNK_BYTES,
)


def _key() -> str:
    return "key_" + uuid.uuid4().hex


class TeamMessagesServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.data_dir = Path(self.temporary.name)
        self.app = create_app(self.data_dir, allowed_hosts={"testserver", "localhost"})
        self.client = TestClient(
            self.app,
            base_url="http://localhost",
            client=("127.0.0.1", 41000),
        )
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.owner = self.bootstrap()
        self.team_id = self.owner["teams"][0]["id"]
        self.member = self.invite_and_redeem(self.owner, "member@example.com", "member")
        self.guest = self.invite_and_redeem(self.owner, "guest@example.com", "guest")
        self.base = f"/v1/teams/{self.team_id}/network"

    # -- helpers ------------------------------------------------------------

    def bootstrap(self) -> dict:
        proof = (self.data_dir / "bootstrap-owner.proof").read_text().strip()
        response = self.client.post(
            "/v1/bootstrap/redeem",
            headers={"X-Team-Hub-Bootstrap-Proof": proof},
            json={
                "email": "owner@example.com",
                "display_name": "Owner",
                "device_label": "Owner Mac",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    @staticmethod
    def auth(bundle: dict) -> dict[str, str]:
        return {"Authorization": f"Bearer {bundle['access_token']}"}

    def invite_and_redeem(self, owner: dict, email: str, role: str) -> dict:
        issued = self.client.post(
            f"/v1/teams/{self.team_id if hasattr(self, 'team_id') else owner['teams'][0]['id']}/invitations",
            headers=self.auth(owner),
            json={"invitee_email": email, "role": role},
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        redeemed = self.client.post(
            "/v1/invitations/redeem",
            json={
                "token": issued.json()["token"],
                "email": email,
                "display_name": email.split("@", 1)[0].title(),
                "device_label": f"{role} device",
            },
        )
        self.assertEqual(redeemed.status_code, 200, redeemed.text)
        return redeemed.json()

    def post(self, bundle: dict, path: str, body: dict, expected: int = 200) -> dict:
        response = self.client.post(path, headers=self.auth(bundle), json=body)
        self.assertEqual(response.status_code, expected, response.text)
        return response.json()

    def get(self, bundle: dict, path: str, expected: int = 200) -> dict:
        response = self.client.get(path, headers=self.auth(bundle))
        self.assertEqual(response.status_code, expected, response.text)
        return response.json()

    def delete(self, bundle: dict, path: str, body: dict, expected: int = 200) -> dict:
        response = self.client.request(
            "DELETE",
            path,
            headers=self.auth(bundle),
            json=body,
        )
        self.assertEqual(response.status_code, expected, response.text)
        return response.json()

    def send(self, bundle: dict, recipients: list[dict], body: str = "Hello team", **extra) -> dict:
        payload = {
            "kind": "message",
            "body": body,
            "body_format": "markdown",
            "recipients": recipients,
            "idempotency_key": _key(),
        }
        payload.update(extra)
        return self.post(bundle, f"{self.base}/messages", payload)["message"]

    def put_chunk(self, bundle: dict, attachment_id: str, payload: bytes, start: int, end: int):
        return self.client.put(
            f"{self.base}/attachments/{attachment_id}/content",
            headers={
                **self.auth(bundle),
                "Content-Type": "application/octet-stream",
                "Content-Range": f"bytes {start}-{end}/{len(payload)}",
            },
            content=payload[start : end + 1],
        )

    def declare(self, bundle: dict, payload: bytes, *, name: str = "demo.bin", digest: str | None = None) -> dict:
        return self.post(
            bundle,
            f"{self.base}/attachments",
            {
                "file_name": name,
                "media_type": "application/octet-stream",
                "byte_size": len(payload),
                "sha256": digest or hashlib.sha256(payload).hexdigest(),
                "idempotency_key": _key(),
            },
        )

    def upload(self, bundle: dict, payload: bytes, *, name: str = "demo.bin") -> dict:
        attachment = self.declare(bundle, payload, name=name)["attachment"]
        response = self.put_chunk(bundle, attachment["id"], payload, 0, len(payload) - 1)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["attachment"]

    # -- health -------------------------------------------------------------

    def test_health_advertises_team_messages_as_sibling_capability(self) -> None:
        health = self.client.get("/v1/health").json()
        capabilities = health["capabilities"]
        self.assertEqual(set(capabilities["team_network_v1"]), {
            "available", "version", "logical_servers", "agent_registry", "bulletin",
            "mailbox", "delivery_receipts", "passive_requests", "server_invites",
            "skill_attachments", "dispatch", "max_agents_per_server", "max_page_items",
            "max_body_bytes",
        })
        messages = capabilities["team_messages_v1"]
        self.assertTrue(messages["available"])
        self.assertEqual(messages["kinds"], ["message", "skill"])
        self.assertEqual(messages["recipient_kinds"], ["server", "human", "all"])
        self.assertEqual(messages["max_body_bytes"], MAX_TEAM_MESSAGE_BODY_BYTES)
        self.assertEqual(messages["attachments"]["chunk_bytes"], TEAM_ATTACHMENT_CHUNK_BYTES)
        self.assertTrue(messages["attachments"]["range_downloads"])

    # -- feed ---------------------------------------------------------------

    def test_feed_post_is_visible_to_all_and_guest_is_read_only(self) -> None:
        created = self.send(self.owner, [{"kind": "all"}], body="Hello **team**")
        self.assertEqual(created["kind"], "message")
        self.assertEqual(created["body"], "Hello **team**")
        self.assertEqual(created["recipients"][0]["kind"], "all")
        self.assertEqual(created["sender"], {
            "kind": "human",
            "id": self.owner["principal"]["id"],
            "display_name": "Owner",
        })
        self.assertEqual(created["attachments"], [])
        self.assertIsNone(created["skill"])

        for bundle in (self.owner, self.member, self.guest):
            feed = self.get(bundle, f"{self.base}/messages?box=feed")
            self.assertEqual([item["id"] for item in feed["messages"]], [created["id"]])
            self.assertEqual(feed["messages"][0]["preview"], "Hello **team**")
            self.assertNotIn("body", feed["messages"][0])
            self.assertFalse(feed["has_more"])
            self.assertEqual(feed["next_after_sequence"], created["sequence"])
            detail = self.get(bundle, f"{self.base}/messages/{created['id']}")["message"]
            self.assertEqual(detail["body"], "Hello **team**")

        # Guests may read but cannot post.
        response = self.client.post(
            f"{self.base}/messages",
            headers=self.auth(self.guest),
            json={
                "kind": "message",
                "body": "nope",
                "recipients": [{"kind": "all"}],
                "idempotency_key": _key(),
            },
        )
        self.assertEqual(response.status_code, 404, response.text)

        # Paging cursor excludes already-seen items.
        second = self.send(self.member, [{"kind": "all"}], body="Second")
        page = self.get(
            self.owner, f"{self.base}/messages?box=feed&after_sequence={created['sequence']}"
        )
        self.assertEqual([item["id"] for item in page["messages"]], [second["id"]])

    def test_bulletin_edits_are_poster_only_and_versioned(self) -> None:
        created = self.send(
            self.member,
            [{"kind": "all"}],
            body="Original bulletin",
        )
        message_id = created["id"]

        legacy = self.get(self.member, f"{self.base}/messages/{message_id}")["message"]
        self.assertNotIn("revision", legacy)
        current = self.get(
            self.member,
            f"{self.base}/messages/{message_id}?include_revision=true",
        )["message"]
        self.assertEqual(current["revision"], {
            "version": 1,
            "versions_count": 1,
            "edited_at": None,
        })

        key = _key()
        request = {
            "body": "Edited bulletin",
            "body_format": "markdown",
            "expected_version": 1,
            "idempotency_key": key,
        }
        edited = self.post(
            self.member,
            f"{self.base}/messages/{message_id}/revisions",
            request,
        )["message"]
        self.assertEqual(edited["body"], "Edited bulletin")
        self.assertEqual(edited["revision"]["version"], 2)

        replay = self.post(
            self.member,
            f"{self.base}/messages/{message_id}/revisions",
            request,
        )["message"]
        self.assertEqual(replay, edited)

        history = self.get(
            self.owner,
            f"{self.base}/messages/{message_id}/revisions",
        )
        self.assertEqual([item["version"] for item in history["versions"]], [2, 1])
        self.assertEqual(history["versions"][0]["preview"], "Edited bulletin")
        self.assertEqual(history["versions"][1]["preview"], "Original bulletin")

        self.post(
            self.owner,
            f"{self.base}/messages/{message_id}/revisions",
            {
                **request,
                "body": "Owner overwrite",
                "idempotency_key": _key(),
                "expected_version": 2,
            },
            expected=403,
        )
        self.post(
            self.member,
            f"{self.base}/messages/{message_id}/revisions",
            {
                **request,
                "body": "Stale edit",
                "idempotency_key": _key(),
            },
            expected=409,
        )

        database = sqlite3.connect(self.data_dir / "team-hub.sqlite3")
        try:
            original = database.execute(
                "SELECT body FROM team_messages WHERE id=?",
                (message_id,),
            ).fetchone()
            self.assertEqual(original, ("Original bulletin",))
            revisions = database.execute(
                "SELECT version,body FROM team_message_revisions WHERE message_id=?",
                (message_id,),
            ).fetchall()
            self.assertEqual(revisions, [(2, "Edited bulletin")])
        finally:
            database.close()

    def test_idempotent_replay_returns_same_message_and_conflicts_on_changed_body(self) -> None:
        key = _key()
        payload = {
            "kind": "message",
            "body": "once",
            "recipients": [{"kind": "all"}],
            "idempotency_key": key,
        }
        first = self.post(self.owner, f"{self.base}/messages", payload)["message"]
        replay = self.post(self.owner, f"{self.base}/messages", payload)["message"]
        self.assertEqual(first["id"], replay["id"])
        changed = self.post(
            self.owner, f"{self.base}/messages", {**payload, "body": "twice"}, expected=409
        )
        self.assertEqual(changed["error"]["code"], "idempotency_conflict")
        feed = self.get(self.owner, f"{self.base}/messages?box=feed")
        self.assertEqual(len(feed["messages"]), 1)

    def test_plain_message_rejects_title_and_legacy_title_is_sanitized(self) -> None:
        rejected = self.post(
            self.owner,
            f"{self.base}/messages",
            {
                "kind": "message",
                "title": "Unexpected",
                "body": "plain",
                "recipients": [{"kind": "all"}],
                "idempotency_key": _key(),
            },
            expected=422,
        )
        self.assertEqual(rejected["error"]["code"], "invalid_request")

        sent = self.send(self.owner, [{"kind": "all"}], body="legacy")
        store = self.app.state.store
        connection = store.connect()
        try:
            # Simulate a row written before the immutable V2 trigger and
            # strict kind/title contract were installed.
            connection.execute("DROP TRIGGER team_messages_are_immutable")
            connection.execute(
                "UPDATE team_messages SET title=? WHERE id=?",
                ("legacy title", sent["id"]),
            )
            connection.commit()
        finally:
            connection.close()

        detail = self.get(
            self.owner, f"{self.base}/messages/{sent['id']}"
        )["message"]
        self.assertIsNone(detail["title"])
        feed = self.get(self.owner, f"{self.base}/messages?box=feed")
        self.assertIsNone(feed["messages"][0]["title"])

    def test_provenance_round_trips_and_rejects_unknown_or_invalid_fields(self) -> None:
        provenance = {
            "via": "agent",
            "backend": None,
            "chat_id": "chat-1",
            "run_id": None,
        }
        sent = self.send(
            self.owner,
            [{"kind": "all"}],
            body="provenance",
            provenance=provenance,
        )
        self.assertEqual(sent["provenance"], provenance)
        detail = self.get(
            self.owner, f"{self.base}/messages/{sent['id']}"
        )["message"]
        self.assertEqual(detail["provenance"], provenance)

        for rejected_provenance in (
            {"source": "foreign"},
            {"backend": 7},
            {"backend": "codex\nspoofed"},
            {"backend": " codex"},
            {"via": "foreign"},
        ):
            rejected = self.post(
                self.owner,
                f"{self.base}/messages",
                {
                    "kind": "message",
                    "body": "invalid provenance",
                    "recipients": [{"kind": "all"}],
                    "provenance": rejected_provenance,
                    "idempotency_key": _key(),
                },
                expected=422,
            )
            self.assertEqual(rejected["error"]["code"], "invalid_request")

    def test_legacy_provenance_is_sanitized_from_detail_and_feed(self) -> None:
        sent = self.send(self.owner, [{"kind": "all"}], body="legacy provenance")
        stored = {
            "via": "desktop",
            "backend": None,
            "chat_id": "chat-legacy",
            "run_id": None,
            "foreign": "must not escape",
        }
        store = self.app.state.store
        connection = store.connect()
        try:
            connection.execute("DROP TRIGGER team_messages_are_immutable")
            connection.execute(
                "UPDATE team_messages SET provenance_json=? WHERE id=?",
                (json.dumps(stored), sent["id"]),
            )
            connection.commit()
        finally:
            connection.close()

        expected = {
            "via": "desktop",
            "backend": None,
            "chat_id": "chat-legacy",
            "run_id": None,
        }
        detail = self.get(
            self.owner, f"{self.base}/messages/{sent['id']}"
        )["message"]
        self.assertEqual(detail["provenance"], expected)
        feed = self.get(self.owner, f"{self.base}/messages?box=feed")
        self.assertEqual(feed["messages"][0]["provenance"], expected)

    # -- direct mail --------------------------------------------------------

    def test_direct_message_inbox_receipts_sent_and_visibility(self) -> None:
        member_id = self.member["principal"]["id"]
        sent = self.send(self.owner, [{"kind": "human", "id": member_id}], body="For you")
        self.assertEqual(sent["recipients"][0]["id"], member_id)
        self.assertEqual(sent["recipients"][0]["state"], "available")

        inbox = self.get(self.member, f"{self.base}/messages?box=inbox")
        self.assertEqual(inbox["address"], {"kind": "human", "id": member_id})
        self.assertEqual([item["id"] for item in inbox["messages"]], [sent["id"]])
        self.assertEqual(inbox["messages"][0]["delivery"]["state"], "available")

        self.assertEqual(self.get(self.owner, f"{self.base}/messages?box=inbox")["messages"], [])
        owner_sent = self.get(self.owner, f"{self.base}/messages?box=sent")
        self.assertEqual([item["id"] for item in owner_sent["messages"]], [sent["id"]])
        self.assertEqual(self.get(self.member, f"{self.base}/messages?box=sent")["messages"], [])

        unread = self.get(self.member, f"{self.base}/messages?box=inbox&unread=1")
        self.assertEqual(len(unread["messages"]), 1)

        delivered = self.post(
            self.member,
            f"{self.base}/messages/{sent['id']}/receipts",
            {"state": "delivered", "idempotency_key": _key()},
        )
        self.assertEqual(delivered["recipients"][0]["state"], "delivered")
        read = self.post(
            self.member,
            f"{self.base}/messages/{sent['id']}/receipts",
            {"state": "read", "idempotency_key": _key()},
        )
        self.assertEqual(read["recipients"][0]["state"], "read")
        self.assertIsNotNone(read["recipients"][0]["delivered_at"])
        self.assertEqual(
            self.get(self.member, f"{self.base}/messages?box=inbox&unread=1")["messages"], []
        )
        # Receipts are monotonic: going back to delivered is a no-op.
        again = self.post(
            self.member,
            f"{self.base}/messages/{sent['id']}/receipts",
            {"state": "delivered", "idempotency_key": _key()},
        )
        self.assertEqual(again["recipients"][0]["state"], "read")

        # The sender sees the recipient state; a third party sees nothing.
        detail = self.get(self.owner, f"{self.base}/messages/{sent['id']}")["message"]
        self.assertEqual(detail["recipients"][0]["state"], "read")
        self.get(self.guest, f"{self.base}/messages/{sent['id']}", expected=404)
        denied = self.post(
            self.guest,
            f"{self.base}/messages/{sent['id']}/receipts",
            {"state": "read", "idempotency_key": _key()},
            expected=403,
        )
        self.assertEqual(denied["error"]["code"], "forbidden")

        # Only owned mailboxes can be listed.
        other = self.client.get(
            f"{self.base}/messages?box=inbox&address_kind=human&address_id={self.owner['principal']['id']}",
            headers=self.auth(self.member),
        )
        self.assertEqual(other.status_code, 403, other.text)

        # Unknown or non-member recipients fail closed.
        missing = self.post(
            self.owner,
            f"{self.base}/messages",
            {
                "kind": "message",
                "body": "?",
                "recipients": [{"kind": "human", "id": "principal_missing"}],
                "idempotency_key": _key(),
            },
            expected=404,
        )
        self.assertEqual(missing["error"]["code"], "recipient_unavailable")

        # Sender filter and since filter.
        filtered = self.get(
            self.member,
            f"{self.base}/messages?box=inbox&from_kind=human&from_id={self.owner['principal']['id']}",
        )
        self.assertEqual(len(filtered["messages"]), 1)
        future = self.get(self.member, f"{self.base}/messages?box=inbox&since=2999-01-01T00:00:00Z")
        self.assertEqual(future["messages"], [])

    def test_receipt_outbox_is_atomic_per_recipient_and_idempotent(self) -> None:
        member_id = self.member["principal"]["id"]
        sent = self.send(self.owner, [{"kind": "human", "id": member_id}])
        store = self.app.state.store
        connection = store.connect()
        try:
            recipient_id = str(
                connection.execute(
                    "SELECT id FROM team_message_recipients WHERE message_id=?",
                    (sent["id"],),
                ).fetchone()[0]
            )
        finally:
            connection.close()

        delivered_key = _key()
        delivered_request = {
            "state": "delivered",
            "idempotency_key": delivered_key,
        }
        with mock.patch.object(
            store,
            "_outbox",
            side_effect=RuntimeError("forced receipt outbox failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "forced receipt outbox failure"):
                self.client.post(
                    f"{self.base}/messages/{sent['id']}/receipts",
                    headers=self.auth(self.member),
                    json=delivered_request,
                )

        connection = store.connect()
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM team_message_recipients WHERE id=?",
                    (recipient_id,),
                ).fetchone()[0],
                "available",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE action='team.message.receipt'"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM request_idempotency "
                    "WHERE operation='team.message.receipt'"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM outbox_events "
                    "WHERE aggregate_type='team_message_recipient' AND aggregate_id=?",
                    (recipient_id,),
                ).fetchone()[0],
                0,
            )
        finally:
            connection.close()

        first = self.post(
            self.member,
            f"{self.base}/messages/{sent['id']}/receipts",
            delivered_request,
        )
        replay = self.post(
            self.member,
            f"{self.base}/messages/{sent['id']}/receipts",
            delivered_request,
        )
        self.assertEqual(first, replay)
        read_key = _key()
        read_request = {"state": "read", "idempotency_key": read_key}
        self.post(
            self.member,
            f"{self.base}/messages/{sent['id']}/receipts",
            read_request,
        )
        self.post(
            self.member,
            f"{self.base}/messages/{sent['id']}/receipts",
            read_request,
        )
        # A monotonic no-op under a distinct request key is audited but does
        # not claim another state-change effect in the outbox.
        self.post(
            self.member,
            f"{self.base}/messages/{sent['id']}/receipts",
            {"state": "delivered", "idempotency_key": _key()},
        )

        connection = store.connect()
        try:
            events = connection.execute(
                """
                SELECT aggregate_type,aggregate_id,event_type,state
                FROM outbox_events
                WHERE aggregate_type='team_message_recipient' AND aggregate_id=?
                ORDER BY created_at,event_type
                """,
                (recipient_id,),
            ).fetchall()
            self.assertEqual(
                [tuple(row) for row in events],
                [
                    (
                        "team_message_recipient",
                        recipient_id,
                        "team.message.delivered",
                        "pending",
                    ),
                    (
                        "team_message_recipient",
                        recipient_id,
                        "team.message.read",
                        "pending",
                    ),
                ],
            )
        finally:
            connection.close()

    def test_inbox_delivery_matches_the_requested_owned_address(self) -> None:
        member_id = self.member["principal"]["id"]
        guest_id = self.guest["principal"]["id"]
        sent = self.send(
            self.owner,
            [
                {"kind": "human", "id": member_id},
                {"kind": "human", "id": guest_id},
            ],
            body="Address-specific delivery",
        )

        store = self.app.state.store
        original_owned_addresses = store._team_owned_addresses
        store._team_owned_addresses = lambda *_args, **_kwargs: [
            ("human", member_id),
            ("human", guest_id),
        ]
        self.addCleanup(setattr, store, "_team_owned_addresses", original_owned_addresses)

        inbox = self.get(
            self.member,
            f"{self.base}/messages?box=inbox&address_kind=human&address_id={guest_id}",
        )
        self.assertEqual([item["id"] for item in inbox["messages"]], [sent["id"]])
        self.assertEqual(inbox["messages"][0]["delivery"]["id"], guest_id)

    def test_reply_links_to_an_existing_message_only(self) -> None:
        root = self.send(self.owner, [{"kind": "all"}], body="root")
        reply = self.send(
            self.member, [{"kind": "all"}], body="reply", in_reply_to_message_id=root["id"]
        )
        self.assertEqual(reply["in_reply_to_message_id"], root["id"])
        self.post(
            self.member,
            f"{self.base}/messages",
            {
                "kind": "message",
                "body": "orphan",
                "recipients": [{"kind": "all"}],
                "in_reply_to_message_id": "tmsg_doesnotexist0000",
                "idempotency_key": _key(),
            },
            expected=422,
        )

        private = self.send(
            self.owner,
            [{"kind": "human", "id": self.member["principal"]["id"]}],
            body="private reply parent",
        )
        unrelated = self.invite_and_redeem(
            self.owner,
            "reply-oracle@example.com",
            "member",
        )
        guessed = self.post(
            unrelated,
            f"{self.base}/messages",
            {
                "kind": "message",
                "body": "guessed a real but private parent",
                "recipients": [{"kind": "all"}],
                "in_reply_to_message_id": private["id"],
                "idempotency_key": _key(),
            },
            expected=422,
        )
        self.assertEqual(guessed["error"]["code"], "invalid_request")
        self.assertIn("unavailable", guessed["error"]["message"].lower())
        recipient_reply = self.send(
            self.member,
            [{"kind": "all"}],
            body="recipient may reply",
            in_reply_to_message_id=private["id"],
        )
        sender_reply = self.send(
            self.owner,
            [{"kind": "all"}],
            body="sender may reply",
            in_reply_to_message_id=private["id"],
        )
        self.assertEqual(recipient_reply["in_reply_to_message_id"], private["id"])
        self.assertEqual(sender_reply["in_reply_to_message_id"], private["id"])

    # -- deletion journal -------------------------------------------------

    def test_message_delete_is_strict_authorized_idempotent_and_additive(self) -> None:
        other = self.invite_and_redeem(
            self.owner,
            "other-member@example.com",
            "member",
        )
        admin = self.invite_and_redeem(
            self.owner,
            "message-admin@example.com",
            "admin",
        )
        message = self.send(
            self.member,
            [{"kind": "human", "id": self.owner["principal"]["id"]}],
            body="immutable delete source",
        )
        path = f"{self.base}/messages/{message['id']}"
        store = self.app.state.store
        connection = store.connect()
        try:
            source_before = dict(
                connection.execute(
                    "SELECT * FROM team_messages WHERE team_id=? AND id=?",
                    (self.team_id, message["id"]),
                ).fetchone()
            )
            recipients_before = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM team_message_recipients "
                    "WHERE team_id=? AND message_id=? ORDER BY id",
                    (self.team_id, message["id"]),
                )
            ]
        finally:
            connection.close()

        for invalid in (
            {},
            {"idempotency_key": "1234567"},
            {"idempotency_key": "x" * 241},
            {"idempotency_key": _key(), "message_id": message["id"]},
        ):
            with self.subTest(invalid=invalid):
                rejected = self.delete(self.member, path, invalid, expected=422)
                self.assertEqual(rejected["error"]["code"], "invalid_request")

        forbidden = self.delete(other, path, {"idempotency_key": _key()}, expected=403)
        self.assertEqual(forbidden["error"]["code"], "forbidden")

        first_key = _key()
        expected = {"deleted": True, "message_id": message["id"]}
        self.assertEqual(
            self.delete(self.member, path, {"idempotency_key": first_key}),
            expected,
        )
        self.assertEqual(
            self.delete(self.member, path, {"idempotency_key": first_key}),
            expected,
        )
        self.assertEqual(
            self.delete(self.member, path, {"idempotency_key": _key()}),
            expected,
        )

        connection = store.connect()
        try:
            self.assertEqual(
                dict(
                    connection.execute(
                        "SELECT * FROM team_messages WHERE team_id=? AND id=?",
                        (self.team_id, message["id"]),
                    ).fetchone()
                ),
                source_before,
            )
            self.assertEqual(
                [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM team_message_recipients "
                        "WHERE team_id=? AND message_id=? ORDER BY id",
                        (self.team_id, message["id"]),
                    )
                ],
                recipients_before,
            )
            deletion = connection.execute(
                "SELECT * FROM network_content_deletions "
                "WHERE team_id=? AND resource_kind='message' AND resource_id=?",
                (self.team_id, message["id"]),
            ).fetchone()
            self.assertIsNotNone(deletion)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM network_content_deletions "
                    "WHERE team_id=? AND resource_kind='message' AND resource_id=?",
                    (self.team_id, message["id"]),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_events "
                    "WHERE action='team.message.delete' AND resource_id=?",
                    (message["id"],),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM outbox_events "
                    "WHERE aggregate_type='team_message' AND aggregate_id=? "
                    "AND event_type='team.message.deleted'",
                    (message["id"],),
                ).fetchone()[0],
                1,
            )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE network_content_deletions SET deleted_at=deleted_at+1 "
                    "WHERE id=?",
                    (deletion["id"],),
                )
            connection.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "DELETE FROM network_content_deletions WHERE id=?",
                    (deletion["id"],),
                )
            connection.rollback()
        finally:
            connection.close()

        owner_target = self.send(
            self.member,
            [{"kind": "human", "id": other["principal"]["id"]}],
            body="owner may remove",
        )
        self.assertEqual(
            self.delete(
                self.owner,
                f"{self.base}/messages/{owner_target['id']}",
                {"idempotency_key": _key()},
            ),
            {"deleted": True, "message_id": owner_target["id"]},
        )
        admin_target = self.send(
            self.member,
            [{"kind": "human", "id": other["principal"]["id"]}],
            body="admin may remove",
        )
        self.assertEqual(
            self.delete(
                admin,
                f"{self.base}/messages/{admin_target['id']}",
                {"idempotency_key": _key()},
            ),
            {"deleted": True, "message_id": admin_target["id"]},
        )

    def test_deleted_message_is_absent_from_every_content_surface(self) -> None:
        payload = b"deletion must retain these immutable bytes"
        attachment = self.upload(self.owner, payload, name="retained.bin")
        member_id = self.member["principal"]["id"]
        message = self.send(
            self.owner,
            [{"kind": "all"}, {"kind": "human", "id": member_id}],
            body="delete all projections",
            attachment_ids=[attachment["id"]],
        )
        self.post(
            self.member,
            f"{self.base}/messages/{message['id']}/receipts",
            {"state": "delivered", "idempotency_key": _key()},
        )
        store = self.app.state.store
        blob = (
            self.data_dir
            / "attachments"
            / attachment["sha256"][:2]
            / attachment["sha256"]
        )
        connection = store.connect()
        try:
            source_before = dict(
                connection.execute(
                    "SELECT * FROM team_messages WHERE id=?",
                    (message["id"],),
                ).fetchone()
            )
            recipient_rows_before = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM team_message_recipients "
                    "WHERE message_id=? ORDER BY id",
                    (message["id"],),
                )
            ]
            attachment_before = dict(
                connection.execute(
                    "SELECT * FROM team_attachments WHERE id=?",
                    (attachment["id"],),
                ).fetchone()
            )
        finally:
            connection.close()

        self.delete(
            self.owner,
            f"{self.base}/messages/{message['id']}",
            {"idempotency_key": _key()},
        )
        surfaces = (
            (self.owner, f"{self.base}/messages?box=sent"),
            (self.member, f"{self.base}/messages?box=feed"),
            (
                self.member,
                f"{self.base}/messages?box=inbox&address_kind=human&address_id={member_id}",
            ),
        )
        for bundle, path in surfaces:
            with self.subTest(path=path):
                listed = self.get(bundle, path)
                self.assertNotIn(
                    message["id"],
                    [item["id"] for item in listed["messages"]],
                )
        for bundle in (self.owner, self.member):
            self.get(bundle, f"{self.base}/messages/{message['id']}", expected=404)
        receipt = self.post(
            self.member,
            f"{self.base}/messages/{message['id']}/receipts",
            {"state": "read", "idempotency_key": _key()},
            expected=404,
        )
        self.assertEqual(receipt["error"]["code"], "not_found")
        reply = self.post(
            self.member,
            f"{self.base}/messages",
            {
                "kind": "message",
                "body": "must not reply to a tombstone",
                "recipients": [{"kind": "all"}],
                "in_reply_to_message_id": message["id"],
                "idempotency_key": _key(),
            },
            expected=422,
        )
        self.assertEqual(reply["error"]["code"], "invalid_request")

        metadata_path = f"{self.base}/attachments/{attachment['id']}"
        content_path = metadata_path + "/content"
        self.get(self.member, metadata_path, expected=404)
        for method, headers in (
            ("GET", self.auth(self.member)),
            ("HEAD", self.auth(self.member)),
            ("GET", {**self.auth(self.member), "Range": "bytes=0-3"}),
        ):
            with self.subTest(method=method, range=headers.get("Range")):
                denied = self.client.request(method, content_path, headers=headers)
                self.assertEqual(denied.status_code, 404, denied.text)

        member_claims = store.verify_access(self.member["access_token"])
        for operation in (
            lambda: store.get_team_attachment(
                member_claims,
                self.team_id,
                attachment["id"],
            ),
            lambda: store.open_team_attachment(
                member_claims,
                self.team_id,
                attachment["id"],
            ),
            lambda: store.bound_team_attachment_local_path(
                member_claims,
                self.team_id,
                attachment["id"],
            ),
        ):
            with self.assertRaises(HubError) as unavailable:
                operation()
            self.assertEqual(unavailable.exception.code, "not_found")

        connection = store.connect()
        try:
            self.assertEqual(
                dict(connection.execute("SELECT * FROM team_messages WHERE id=?", (message["id"],)).fetchone()),
                source_before,
            )
            self.assertEqual(
                [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM team_message_recipients "
                        "WHERE message_id=? ORDER BY id",
                        (message["id"],),
                    )
                ],
                recipient_rows_before,
            )
            self.assertEqual(
                dict(connection.execute("SELECT * FROM team_attachments WHERE id=?", (attachment["id"],)).fetchone()),
                attachment_before,
            )
        finally:
            connection.close()
        self.assertEqual(blob.read_bytes(), payload)

    def test_skill_message_delete_requires_library_archive(self) -> None:
        skill_message = self.skill_post(
            self.owner,
            "delete-via-archive",
            "Delete via archive",
            "# Keep immutable versions",
        )["message"]
        rejected = self.delete(
            self.owner,
            f"{self.base}/messages/{skill_message['id']}",
            {"idempotency_key": _key()},
            expected=409,
        )
        self.assertEqual(rejected["error"]["code"], "skill_archive_required")
        self.assertIn("Archive", rejected["error"]["message"])
        self.assertIn("Skills library", rejected["error"]["message"])
        connection = self.app.state.store.connect()
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM network_content_deletions WHERE resource_id=?",
                    (skill_message["id"],),
                ).fetchone()[0],
                0,
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "team message deletion source is unavailable",
            ):
                connection.execute(
                    "INSERT INTO network_content_deletions("
                    "id,team_id,resource_kind,resource_id,"
                    "deleted_by_principal_id,deleted_at"
                    ") VALUES (?,?,?,?,?,?)",
                    (
                        "deletion_skill_insert_must_fail",
                        self.team_id,
                        "message",
                        skill_message["id"],
                        self.owner["principal"]["id"],
                        int(time.time()),
                    ),
                )
            connection.rollback()
        finally:
            connection.close()
        self.assertEqual(
            self.get(
                self.owner,
                f"{self.base}/messages/{skill_message['id']}",
            )["message"]["id"],
            skill_message["id"],
        )

    def test_bulletin_delete_is_global_additive_and_blocks_new_replies(self) -> None:
        root = self.post(
            self.member,
            f"{self.base}/bulletin",
            {
                "body": "legacy bulletin root",
                "body_format": "plain",
                "idempotency_key": _key(),
            },
        )["post"]
        child = self.post(
            self.owner,
            f"{self.base}/bulletin",
            {
                "body": "existing child remains an independent immutable row",
                "body_format": "plain",
                "reply_to_post_id": root["id"],
                "idempotency_key": _key(),
            },
        )["post"]
        store = self.app.state.store
        connection = store.connect()
        try:
            source_before = dict(
                connection.execute(
                    "SELECT * FROM messages WHERE team_id=? AND id=?",
                    (self.team_id, root["id"]),
                ).fetchone()
            )
            channel_id = connection.execute(
                "SELECT channel_id FROM network_boards WHERE team_id=?",
                (self.team_id,),
            ).fetchone()["channel_id"]
        finally:
            connection.close()

        key = _key()
        path = f"{self.base}/bulletin/{root['id']}"
        expected = {"deleted": True, "post_id": root["id"]}
        self.assertEqual(self.delete(self.owner, path, {"idempotency_key": key}), expected)
        self.assertEqual(self.delete(self.owner, path, {"idempotency_key": key}), expected)
        self.assertEqual(self.delete(self.owner, path, {"idempotency_key": _key()}), expected)

        bulletin = self.get(self.member, f"{self.base}/bulletin")
        self.assertNotIn(root["id"], [post["id"] for post in bulletin["posts"]])
        self.assertIn(child["id"], [post["id"] for post in bulletin["posts"]])
        generic = self.get(self.member, f"/v1/channels/{channel_id}/messages")
        self.assertNotIn(root["id"], [item["id"] for item in generic["messages"]])
        self.assertIn(child["id"], [item["id"] for item in generic["messages"]])
        reply = self.post(
            self.member,
            f"{self.base}/bulletin",
            {
                "body": "cannot extend a deleted parent",
                "body_format": "plain",
                "reply_to_post_id": root["id"],
                "idempotency_key": _key(),
            },
            expected=422,
        )
        self.assertEqual(reply["error"]["code"], "invalid_request")

        connection = store.connect()
        try:
            self.assertEqual(
                dict(
                    connection.execute(
                        "SELECT * FROM messages WHERE team_id=? AND id=?",
                        (self.team_id, root["id"]),
                    ).fetchone()
                ),
                source_before,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM network_content_deletions "
                    "WHERE team_id=? AND resource_kind='bulletin' AND resource_id=?",
                    (self.team_id, root["id"]),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_events "
                    "WHERE action='network.bulletin.delete' AND resource_id=?",
                    (root["id"],),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM outbox_events "
                    "WHERE aggregate_type='network_bulletin_post' AND aggregate_id=? "
                    "AND event_type='network.bulletin.deleted'",
                    (root["id"],),
                ).fetchone()[0],
                1,
            )
        finally:
            connection.close()

    def test_deletion_journal_is_bounded_paginated_and_visibility_filtered(self) -> None:
        member_id = self.member["principal"]["id"]
        guest_id = self.guest["principal"]["id"]
        other = self.invite_and_redeem(
            self.owner,
            "journal-author@example.com",
            "member",
        )
        admin = self.invite_and_redeem(
            self.owner,
            "journal-admin@example.com",
            "admin",
        )
        hidden_before = self.send(
            other,
            [{"kind": "human", "id": guest_id}],
            body="private before visible deletion",
        )
        visible_first = self.send(
            other,
            [{"kind": "human", "id": member_id}],
            body="first private deletion visible to member",
        )
        hidden_between = self.send(
            other,
            [{"kind": "human", "id": guest_id}],
            body="private between visible deletions",
        )
        public = self.send(other, [{"kind": "all"}], body="public deletion")
        bulletin = self.post(
            other,
            f"{self.base}/bulletin",
            {
                "body": "public bulletin deletion",
                "body_format": "plain",
                "idempotency_key": _key(),
            },
        )["post"]
        hidden_after = self.send(
            other,
            [{"kind": "human", "id": guest_id}],
            body="private after visible deletions",
        )
        base_time = int(time.time())
        first_deletions = (
            (1, "messages", hidden_before["id"]),
            (2, "messages", visible_first["id"]),
            (3, "messages", hidden_between["id"]),
        )
        for offset, kind, resource_id in first_deletions:
            with mock.patch(
                "agentsdock_team_hub.store._now",
                return_value=base_time + offset,
            ):
                self.delete(
                    other,
                    f"{self.base}/{kind}/{resource_id}",
                    {"idempotency_key": _key()},
                )

        # Invisible rows on either side of the sole visible row are excluded
        # by the journal query itself: they neither consume the page nor leak
        # through its cursor/has-more metadata.
        member_midpoint = self.client.get(
            f"{self.base}/deletions?after_sequence=0&limit=1",
            headers=self.auth(self.member),
        )
        self.assertEqual(member_midpoint.status_code, 200, member_midpoint.text)
        member_midpoint_value = member_midpoint.json()
        self.assertEqual(
            [item["id"] for item in member_midpoint_value["deletions"]],
            [visible_first["id"]],
        )
        self.assertEqual(
            member_midpoint_value["next_after_sequence"],
            member_midpoint_value["deletions"][0]["sequence"],
        )
        self.assertFalse(member_midpoint_value["has_more"])
        for hidden in (hidden_before, hidden_between):
            self.assertNotIn(hidden["id"], member_midpoint.text)

        for bundle in (self.owner, admin):
            with self.subTest(privileged=bundle["principal"]["id"]):
                private_page = self.get(
                    bundle,
                    f"{self.base}/deletions?after_sequence=0&limit=1",
                )
                self.assertEqual(
                    private_page,
                    {
                        "deletions": [],
                        "next_after_sequence": 0,
                        "has_more": False,
                    },
                )

        for offset, kind, resource_id in (
            (4, "messages", public["id"]),
            (5, "bulletin", bulletin["id"]),
            (6, "messages", hidden_after["id"]),
        ):
            with mock.patch(
                "agentsdock_team_hub.store._now",
                return_value=base_time + offset,
            ):
                self.delete(
                    other,
                    f"{self.base}/{kind}/{resource_id}",
                    {"idempotency_key": _key()},
                )

        author_page = self.client.get(
            f"{self.base}/deletions?after_sequence=0&limit=100",
            headers=self.auth(other),
        )
        self.assertEqual(author_page.status_code, 200, author_page.text)
        author_value = author_page.json()
        self.assertEqual(
            set(author_value),
            {"deletions", "next_after_sequence", "has_more"},
        )
        self.assertEqual(
            [(item["kind"], item["id"]) for item in author_value["deletions"]],
            [
                ("message", hidden_before["id"]),
                ("message", visible_first["id"]),
                ("message", hidden_between["id"]),
                ("message", public["id"]),
                ("bulletin", bulletin["id"]),
                ("message", hidden_after["id"]),
            ],
        )
        for item in author_value["deletions"]:
            self.assertEqual(
                set(item),
                {"sequence", "kind", "id", "deleted_at"},
            )
        deleted_at_by_id = {
            item["id"]: item["deleted_at"] for item in author_value["deletions"]
        }

        def collect(bundle: dict) -> tuple[list[dict], str, dict]:
            cursor = 0
            found: list[dict] = []
            raw_pages: list[str] = []
            for _ in range(10):
                response = self.client.get(
                    f"{self.base}/deletions?after_sequence={cursor}&limit=1",
                    headers=self.auth(bundle),
                )
                self.assertEqual(response.status_code, 200, response.text)
                value = response.json()
                self.assertEqual(
                    set(value),
                    {"deletions", "next_after_sequence", "has_more"},
                )
                for item in value["deletions"]:
                    self.assertEqual(
                        set(item),
                        {"sequence", "kind", "id", "deleted_at"},
                    )
                found.extend(value["deletions"])
                raw_pages.append(response.text)
                next_cursor = value["next_after_sequence"]
                self.assertGreaterEqual(next_cursor, cursor)
                if not value["has_more"]:
                    break
                self.assertGreater(next_cursor, cursor)
                cursor = next_cursor
            else:
                self.fail("deletion pagination did not terminate")
            return found, "\n".join(raw_pages), value

        member_rows, member_raw, member_last_page = collect(self.member)
        self.assertEqual(
            [item["id"] for item in member_rows],
            [visible_first["id"], public["id"], bulletin["id"]],
        )
        self.assertEqual(
            member_last_page["next_after_sequence"],
            member_rows[-1]["sequence"],
        )
        self.assertFalse(member_last_page["has_more"])
        for hidden in (hidden_before, hidden_between, hidden_after):
            self.assertNotIn(hidden["id"], member_raw)
            self.assertNotIn(deleted_at_by_id[hidden["id"]], member_raw)

        for bundle in (self.owner, admin):
            privileged_rows, privileged_raw, privileged_last_page = collect(bundle)
            self.assertEqual(
                [item["id"] for item in privileged_rows],
                [public["id"], bulletin["id"]],
            )
            self.assertEqual(
                privileged_last_page["next_after_sequence"],
                privileged_rows[-1]["sequence"],
            )
            self.assertFalse(privileged_last_page["has_more"])
            for private in (
                hidden_before,
                visible_first,
                hidden_between,
                hidden_after,
            ):
                self.assertNotIn(private["id"], privileged_raw)
                self.assertNotIn(deleted_at_by_id[private["id"]], privileged_raw)

        guest_rows, guest_raw, _guest_last_page = collect(self.guest)
        self.assertEqual(
            [item["id"] for item in guest_rows],
            [
                hidden_before["id"],
                hidden_between["id"],
                public["id"],
                bulletin["id"],
                hidden_after["id"],
            ],
        )
        self.assertNotIn(visible_first["id"], guest_raw)
        self.assertNotIn(deleted_at_by_id[visible_first["id"]], guest_raw)

        for query in ("limit=0", "limit=101", "after_sequence=-1"):
            with self.subTest(query=query):
                response = self.client.get(
                    f"{self.base}/deletions?{query}",
                    headers=self.auth(self.member),
                )
                self.assertEqual(response.status_code, 422, response.text)

    # -- skills -------------------------------------------------------------

    def skill_post(self, bundle: dict, slug: str, title: str, body: str, expected: int = 200, **skill) -> dict:
        return self.post(
            bundle,
            f"{self.base}/messages",
            {
                "kind": "skill",
                "title": title,
                "body": body,
                "recipients": [{"kind": "all"}],
                "skill": {"slug": slug, **skill},
                "idempotency_key": _key(),
            },
            expected=expected,
        )

    def test_skill_lifecycle_create_update_cas_pin_archive_restore(self) -> None:
        first = self.skill_post(
            self.owner,
            "deploy-sonic",
            "Deploy SONIC",
            "# Steps\n1. build\n2. ship",
            summary="How we deploy SONIC",
            tags=["Sonic", "deploy", "sonic"],
        )["message"]
        self.assertEqual(first["kind"], "skill")
        self.assertEqual(first["skill"]["slug"], "deploy-sonic")
        self.assertEqual(first["skill"]["version"], 1)
        skill_id = first["skill"]["id"]

        listed = self.get(self.member, f"{self.base}/skills")["skills"]
        self.assertEqual(len(listed), 1)
        skill = listed[0]
        self.assertEqual(skill["slug"], "deploy-sonic")
        self.assertEqual(skill["tags"], ["sonic", "deploy"])
        self.assertEqual(skill["version"], 1)
        self.assertEqual(skill["versions_count"], 1)
        self.assertFalse(skill["pinned"])
        self.assertTrue(skill["permissions"]["edit"])
        self.assertNotIn("body", skill)
        guest_view = self.get(self.guest, f"{self.base}/skills")["skills"][0]
        self.assertFalse(guest_view["permissions"]["edit"])
        by_slug = self.get(self.guest, f"{self.base}/skills?slug=deploy-sonic")["skills"]
        self.assertEqual([item["id"] for item in by_slug], [skill_id])

        # Updating requires the current version.
        conflict = self.skill_post(
            self.member, "deploy-sonic", "Deploy SONIC", "# v2", expected=409
        )
        self.assertEqual(conflict["error"]["code"], "skill_version_conflict")
        stale = self.skill_post(
            self.member, "deploy-sonic", "Deploy SONIC", "# v2", expected=409, expected_version=5
        )
        self.assertEqual(stale["error"]["code"], "skill_version_conflict")
        second = self.skill_post(
            self.member,
            "deploy-sonic",
            "Deploy SONIC v2",
            "# v2 steps",
            expected_version=1,
            change_note="Added rollback",
        )["message"]
        self.assertEqual(second["skill"]["version"], 2)
        self.assertEqual(second["skill"]["id"], skill_id)

        detail = self.get(self.guest, f"{self.base}/skills/{skill_id}")["skill"]
        self.assertEqual(detail["version"], 2)
        self.assertEqual(detail["title"], "Deploy SONIC v2")
        self.assertEqual(detail["body"], "# v2 steps")
        self.assertEqual(detail["author"]["display_name"], "Member")
        self.assertEqual(detail["current"]["change_note"], "Added rollback")
        self.assertEqual(detail["attachments"], [])

        versions = self.get(self.guest, f"{self.base}/skills/{skill_id}/versions")["versions"]
        self.assertEqual([item["version"] for item in versions], [2, 1])
        self.assertNotIn("body", versions[0])
        version_one = self.get(self.guest, f"{self.base}/skills/{skill_id}/versions/1")["version"]
        self.assertEqual(version_one["body"], "# Steps\n1. build\n2. ship")
        self.get(self.guest, f"{self.base}/skills/{skill_id}/versions/9", expected=404)

        # Feed shows both skill posts.
        feed = self.get(self.guest, f"{self.base}/messages?box=feed")["messages"]
        self.assertEqual([item["kind"] for item in feed], ["skill", "skill"])

        # Pinning orders the library; another skill stays below.
        other = self.skill_post(self.owner, "run-groot", "Run GR00T", "# groot")["message"]
        pinned = self.post(
            self.member,
            f"{self.base}/skills/{skill_id}/pin",
            {"pinned": True, "idempotency_key": _key()},
        )["skill"]
        self.assertTrue(pinned["pinned"])
        order = [item["slug"] for item in self.get(self.guest, f"{self.base}/skills")["skills"]]
        self.assertEqual(order, ["deploy-sonic", "run-groot"])
        self.assertEqual(other["skill"]["version"], 1)

        # Guests cannot pin.
        self.post(
            self.guest,
            f"{self.base}/skills/{skill_id}/pin",
            {"pinned": False, "idempotency_key": _key()},
            expected=404,
        )

        # Archiving unpins and hides; edits and pins are blocked until restore.
        archived = self.post(
            self.owner,
            f"{self.base}/skills/{skill_id}/archive",
            {"archived": True, "idempotency_key": _key()},
        )["skill"]
        self.assertTrue(archived["archived"])
        self.assertFalse(archived["pinned"])
        self.assertFalse(archived["permissions"]["edit"])
        visible = [item["slug"] for item in self.get(self.guest, f"{self.base}/skills")["skills"]]
        self.assertEqual(visible, ["run-groot"])
        everything = [
            item["slug"]
            for item in self.get(self.guest, f"{self.base}/skills?include_archived=1")["skills"]
        ]
        self.assertEqual(sorted(everything), ["deploy-sonic", "run-groot"])
        blocked = self.skill_post(
            self.owner, "deploy-sonic", "Deploy SONIC v3", "# v3", expected=409, expected_version=2
        )
        self.assertEqual(blocked["error"]["code"], "skill_archived")
        repin = self.post(
            self.owner,
            f"{self.base}/skills/{skill_id}/pin",
            {"pinned": True, "idempotency_key": _key()},
            expected=409,
        )
        self.assertEqual(repin["error"]["code"], "skill_archived")
        restored = self.post(
            self.owner,
            f"{self.base}/skills/{skill_id}/archive",
            {"archived": False, "idempotency_key": _key()},
        )["skill"]
        self.assertFalse(restored["archived"])
        third = self.skill_post(
            self.owner, "deploy-sonic", "Deploy SONIC v3", "# v3", expected_version=2
        )["message"]
        self.assertEqual(third["skill"]["version"], 3)

    def test_skill_posts_require_title_all_recipient_and_skill_details(self) -> None:
        base = {
            "kind": "skill",
            "body": "# x",
            "recipients": [{"kind": "all"}],
            "skill": {"slug": "needs-title"},
            "idempotency_key": _key(),
        }
        self.post(self.owner, f"{self.base}/messages", base, expected=422)
        self.post(
            self.owner,
            f"{self.base}/messages",
            {
                **base,
                "title": "T",
                "recipients": [{"kind": "human", "id": self.member["principal"]["id"]}],
                "idempotency_key": _key(),
            },
            expected=422,
        )
        self.post(
            self.owner,
            f"{self.base}/messages",
            {**base, "title": "T", "skill": {"slug": "Bad Slug!"}, "idempotency_key": _key()},
            expected=422,
        )
        self.post(
            self.owner,
            f"{self.base}/messages",
            {
                "kind": "message",
                "body": "plain",
                "recipients": [{"kind": "all"}],
                "skill": {"slug": "not-allowed"},
                "idempotency_key": _key(),
            },
            expected=422,
        )

    # -- attachments --------------------------------------------------------

    def test_attachment_chunked_upload_range_download_and_binding(self) -> None:
        payload = bytes(range(256)) * 40  # 10 240 bytes, two chunks in this test
        declared = self.declare(self.owner, payload)
        attachment = declared["attachment"]
        self.assertEqual(declared["chunk_bytes"], TEAM_ATTACHMENT_CHUNK_BYTES)
        self.assertEqual(attachment["state"], "uploading")
        self.assertEqual(attachment["received_bytes"], 0)
        self.assertIsNone(attachment["message_id"])
        url = f"{self.base}/attachments/{attachment['id']}/content"

        # Nothing to download yet, and other members cannot see an unbound upload.
        self.assertEqual(
            self.client.get(url, headers=self.auth(self.owner)).status_code, 409
        )
        self.assertEqual(
            self.client.get(
                f"{self.base}/attachments/{attachment['id']}", headers=self.auth(self.member)
            ).status_code,
            404,
        )

        first = self.put_chunk(self.owner, attachment["id"], payload, 0, 4095)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["attachment"]["received_bytes"], 4096)
        self.assertEqual(first.json()["attachment"]["state"], "uploading")

        gap = self.put_chunk(self.owner, attachment["id"], payload, 8192, len(payload) - 1)
        self.assertEqual(gap.status_code, 409, gap.text)

        replay = self.put_chunk(self.owner, attachment["id"], payload, 0, 4095)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["attachment"]["received_bytes"], 4096)

        stranger = self.put_chunk(self.member, attachment["id"], payload, 4096, len(payload) - 1)
        self.assertEqual(stranger.status_code, 404, stranger.text)

        final = self.put_chunk(self.owner, attachment["id"], payload, 4096, len(payload) - 1)
        self.assertEqual(final.status_code, 200, final.text)
        ready = final.json()["attachment"]
        self.assertEqual(ready["state"], "ready")
        self.assertEqual(ready["received_bytes"], len(payload))
        self.assertIsNotNone(ready["ready_at"])
        stored = self.data_dir / "attachments" / ready["sha256"][:2] / ready["sha256"]
        self.assertEqual(stored.read_bytes(), payload)
        self.assertFalse((self.data_dir / "attachments" / "uploads" / f"{attachment['id']}.part").exists())

        # Full download, range, suffix range, invalid range, HEAD.
        full = self.client.get(url, headers=self.auth(self.owner))
        self.assertEqual(full.status_code, 200, full.text)
        self.assertEqual(full.content, payload)
        self.assertEqual(full.headers["accept-ranges"], "bytes")
        self.assertEqual(full.headers["content-type"], "application/octet-stream")
        self.assertEqual(full.headers["content-length"], str(len(payload)))
        self.assertIn(ready["sha256"], full.headers["etag"])
        part = self.client.get(url, headers={**self.auth(self.owner), "Range": "bytes=5-9"})
        self.assertEqual(part.status_code, 206, part.text)
        self.assertEqual(part.content, payload[5:10])
        self.assertEqual(part.headers["content-range"], f"bytes 5-9/{len(payload)}")
        tail = self.client.get(url, headers={**self.auth(self.owner), "Range": "bytes=-4"})
        self.assertEqual(tail.status_code, 206)
        self.assertEqual(tail.content, payload[-4:])
        open_ended = self.client.get(
            url, headers={**self.auth(self.owner), "Range": f"bytes={len(payload) - 3}-"}
        )
        self.assertEqual(open_ended.status_code, 206)
        self.assertEqual(open_ended.content, payload[-3:])
        bad = self.client.get(url, headers={**self.auth(self.owner), "Range": "bytes=999999-"})
        self.assertEqual(bad.status_code, 416)
        self.assertEqual(bad.headers["content-range"], f"bytes */{len(payload)}")
        head = self.client.head(url, headers=self.auth(self.owner))
        self.assertEqual(head.status_code, 200, head.text)
        self.assertEqual(head.headers["content-length"], str(len(payload)))
        self.assertEqual(head.content, b"")

        # Binding to a message makes it visible to recipients, and single-use.
        member_id = self.member["principal"]["id"]
        message = self.send(
            self.owner,
            [{"kind": "human", "id": member_id}],
            body="see attached",
            attachment_ids=[attachment["id"]],
        )
        self.assertEqual([item["id"] for item in message["attachments"]], [attachment["id"]])
        self.assertEqual(message["attachments"][0]["message_id"], message["id"])
        reused = self.post(
            self.owner,
            f"{self.base}/messages",
            {
                "kind": "message",
                "body": "again",
                "recipients": [{"kind": "all"}],
                "attachment_ids": [attachment["id"]],
                "idempotency_key": _key(),
            },
            expected=409,
        )
        self.assertEqual(reused["error"]["code"], "attachment_unavailable")
        self.assertEqual(self.client.get(url, headers=self.auth(self.member)).status_code, 200)
        self.assertEqual(self.client.get(url, headers=self.auth(self.guest)).status_code, 404)
        metadata = self.get(self.member, f"{self.base}/attachments/{attachment['id']}")
        self.assertEqual(metadata["attachment"]["file_name"], "demo.bin")

        # Same bytes declared again are ready immediately.
        duplicate = self.declare(self.owner, payload, name="copy.bin")["attachment"]
        self.assertEqual(duplicate["state"], "ready")
        self.assertEqual(duplicate["received_bytes"], len(payload))

    def test_attachment_declaration_outbox_is_atomic_and_idempotent(self) -> None:
        payload = b"declaration outbox"
        request = {
            "file_name": "outbox.txt",
            "media_type": "text/plain",
            "byte_size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "idempotency_key": _key(),
        }
        store = self.app.state.store
        with mock.patch.object(
            store,
            "_outbox",
            side_effect=RuntimeError("forced declaration outbox failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "forced declaration outbox failure"):
                self.client.post(
                    f"{self.base}/attachments",
                    headers=self.auth(self.owner),
                    json=request,
                )

        connection = store.connect()
        try:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM team_attachments").fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_events "
                    "WHERE action='team.attachment.declare'"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM request_idempotency "
                    "WHERE operation='team.attachment.declare'"
                ).fetchone()[0],
                0,
            )
        finally:
            connection.close()

        first = self.post(self.owner, f"{self.base}/attachments", request)
        replay = self.post(self.owner, f"{self.base}/attachments", request)
        self.assertEqual(first, replay)
        attachment_id = first["attachment"]["id"]
        connection = store.connect()
        try:
            events = connection.execute(
                """
                SELECT aggregate_type,aggregate_id,event_type,state
                FROM outbox_events
                WHERE aggregate_type='team_attachment' AND aggregate_id=?
                  AND event_type='team.attachment.declared'
                """,
                (attachment_id,),
            ).fetchall()
            self.assertEqual(
                [tuple(row) for row in events],
                [
                    (
                        "team_attachment",
                        attachment_id,
                        "team.attachment.declared",
                        "pending",
                    )
                ],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_events "
                    "WHERE action='team.attachment.declare' AND resource_id=?",
                    (attachment_id,),
                ).fetchone()[0],
                1,
            )
        finally:
            connection.close()

    def test_failed_skill_cas_keeps_ready_attachment_bindable_for_retry(self) -> None:
        first = self.skill_post(
            self.owner,
            "attachment-retry",
            "Attachment retry",
            "# v1",
        )["message"]
        payload = b"retry after a stale skill edit"
        attachment = self.upload(self.owner, payload, name="retry.md")
        request = {
            "kind": "skill",
            "title": "Attachment retry v2",
            "body": "# v2",
            "recipients": [{"kind": "all"}],
            "attachment_ids": [attachment["id"]],
            "skill": {
                "slug": "attachment-retry",
                "expected_version": 99,
            },
            "idempotency_key": _key(),
        }

        conflict = self.post(self.owner, f"{self.base}/messages", request, expected=409)
        self.assertEqual(conflict["error"]["code"], "skill_version_conflict")
        still_ready = self.get(
            self.owner, f"{self.base}/attachments/{attachment['id']}"
        )["attachment"]
        self.assertEqual(still_ready["state"], "ready")
        self.assertIsNone(still_ready["message_id"])

        retried = self.post(
            self.owner,
            f"{self.base}/messages",
            {
                **request,
                "skill": {
                    "slug": "attachment-retry",
                    "expected_version": first["skill"]["version"],
                },
                "idempotency_key": _key(),
            },
        )["message"]
        self.assertEqual(retried["skill"]["version"], 2)
        self.assertEqual(retried["attachments"][0]["id"], attachment["id"])
        self.assertEqual(retried["attachments"][0]["message_id"], retried["id"])

    def test_failed_message_request_keeps_ready_attachment_bindable_for_retry(self) -> None:
        payload = b"retry after an unavailable recipient"
        attachment = self.upload(self.owner, payload, name="request-retry.txt")
        failed = self.post(
            self.owner,
            f"{self.base}/messages",
            {
                "kind": "message",
                "body": "first attempt",
                "recipients": [{"kind": "server", "id": "node_missing0000"}],
                "attachment_ids": [attachment["id"]],
                "idempotency_key": _key(),
            },
            expected=404,
        )
        self.assertEqual(failed["error"]["code"], "recipient_unavailable")
        still_ready = self.get(
            self.owner, f"{self.base}/attachments/{attachment['id']}"
        )["attachment"]
        self.assertIsNone(still_ready["message_id"])

        retried = self.send(
            self.owner,
            [{"kind": "all"}],
            body="second attempt",
            attachment_ids=[attachment["id"]],
        )
        self.assertEqual(retried["attachments"][0]["id"], attachment["id"])
        self.assertEqual(retried["attachments"][0]["message_id"], retried["id"])

    def test_attachment_hash_mismatch_fails_closed(self) -> None:
        payload = b"x" * 3000
        wrong = hashlib.sha256(b"different").hexdigest()
        declared = self.declare(self.owner, payload, digest=wrong)["attachment"]
        response = self.put_chunk(self.owner, declared["id"], payload, 0, len(payload) - 1)
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json()["error"]["code"], "attachment_hash_mismatch")
        metadata = self.get(self.owner, f"{self.base}/attachments/{declared['id']}")["attachment"]
        self.assertEqual(metadata["state"], "failed")
        self.assertFalse((self.data_dir / "attachments" / wrong[:2] / wrong).exists())
        # A failed upload cannot be attached.
        denied = self.post(
            self.owner,
            f"{self.base}/messages",
            {
                "kind": "message",
                "body": "broken",
                "recipients": [{"kind": "all"}],
                "attachment_ids": [declared["id"]],
                "idempotency_key": _key(),
            },
            expected=409,
        )
        self.assertEqual(denied["error"]["code"], "attachment_unavailable")

    def test_corrupt_digest_named_blob_is_not_deduplicated_and_is_repaired(self) -> None:
        payload = b"verified staging must replace same-sized corrupt final bytes"
        original = self.upload(self.owner, payload, name="original.bin")
        blob = (
            self.data_dir
            / "attachments"
            / original["sha256"][:2]
            / original["sha256"]
        )
        corrupt = b"!" * len(payload)
        self.assertNotEqual(hashlib.sha256(corrupt).hexdigest(), original["sha256"])
        blob.write_bytes(corrupt)

        unavailable = self.client.get(
            f"{self.base}/attachments/{original['id']}/content",
            headers=self.auth(self.owner),
        )
        self.assertEqual(unavailable.status_code, 404, unavailable.text)
        self.assertEqual(
            unavailable.json()["error"]["code"], "attachment_unavailable"
        )

        replacement = self.declare(
            self.owner,
            payload,
            name="replacement.bin",
        )["attachment"]
        self.assertEqual(replacement["state"], "uploading")
        completed = self.put_chunk(
            self.owner,
            replacement["id"],
            payload,
            0,
            len(payload) - 1,
        )
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertEqual(completed.json()["attachment"]["state"], "ready")
        self.assertEqual(blob.read_bytes(), payload)
        repaired = self.client.get(
            f"{self.base}/attachments/{original['id']}/content",
            headers=self.auth(self.owner),
        )
        self.assertEqual(repaired.status_code, 200, repaired.text)
        self.assertEqual(repaired.content, payload)

    def test_final_chunk_retry_reconciles_publish_before_sqlite_commit_crash(self) -> None:
        payload = b"published final bytes survive a pre-commit process death"
        declared = self.declare(
            self.owner,
            payload,
            name="publish-crash.bin",
        )["attachment"]
        store = self.app.state.store
        claims = store.verify_access(self.owner["access_token"])
        original_outbox = store._outbox

        def fail_ready_outbox(*args, **kwargs):
            if len(args) >= 5 and args[4] == "team.attachment.ready":
                raise RuntimeError("simulated death after durable blob publication")
            return original_outbox(*args, **kwargs)

        with mock.patch.object(store, "_outbox", side_effect=fail_ready_outbox):
            with self.assertRaisesRegex(
                RuntimeError, "simulated death after durable blob publication"
            ):
                store.write_team_attachment_chunk(
                    claims,
                    self.team_id,
                    declared["id"],
                    offset=0,
                    total=len(payload),
                    data=payload,
                )

        blob = (
            self.data_dir
            / "attachments"
            / declared["sha256"][:2]
            / declared["sha256"]
        )
        staging = store._team_attachment_staging_path(declared["id"])
        self.assertEqual(blob.read_bytes(), payload)
        self.assertFalse(staging.exists())
        rolled_back = self.get(
            self.owner, f"{self.base}/attachments/{declared['id']}"
        )["attachment"]
        self.assertEqual(rolled_back["state"], "uploading")
        self.assertEqual(rolled_back["received_bytes"], 0)

        reconciled = store.write_team_attachment_chunk(
            claims,
            self.team_id,
            declared["id"],
            offset=0,
            total=len(payload),
            data=payload,
        )["attachment"]
        self.assertEqual(reconciled["state"], "ready")
        self.assertEqual(reconciled["received_bytes"], len(payload))
        connection = store.connect()
        try:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT count(*) FROM outbox_events
                    WHERE aggregate_type='team_attachment' AND aggregate_id=?
                      AND event_type='team.attachment.ready'
                    """,
                    (declared["id"],),
                ).fetchone()[0],
                1,
            )
        finally:
            connection.close()

    def test_expiry_reclaims_blob_published_before_sqlite_commit_crash(self) -> None:
        payload = b"expired crash-window upload must not strand final bytes"
        declared = self.declare(
            self.owner,
            payload,
            name="publish-crash-expiry.bin",
        )["attachment"]
        store = self.app.state.store
        claims = store.verify_access(self.owner["access_token"])
        original_outbox = store._outbox

        def fail_ready_outbox(*args, **kwargs):
            if len(args) >= 5 and args[4] == "team.attachment.ready":
                raise RuntimeError("simulated pre-commit death before expiry")
            return original_outbox(*args, **kwargs)

        with mock.patch.object(store, "_outbox", side_effect=fail_ready_outbox):
            with self.assertRaisesRegex(
                RuntimeError, "simulated pre-commit death before expiry"
            ):
                store.write_team_attachment_chunk(
                    claims,
                    self.team_id,
                    declared["id"],
                    offset=0,
                    total=len(payload),
                    data=payload,
                )

        blob = (
            self.data_dir
            / "attachments"
            / declared["sha256"][:2]
            / declared["sha256"]
        )
        self.assertEqual(blob.read_bytes(), payload)
        connection = store.connect()
        try:
            row = connection.execute(
                "SELECT created_at,state FROM team_attachments WHERE id=?",
                (declared["id"],),
            ).fetchone()
            assert row is not None
            self.assertEqual(row["state"], "uploading")
            expired_at = int(row["created_at"]) + 1
            connection.execute(
                "UPDATE team_attachments SET expires_at=? WHERE id=?",
                (expired_at, declared["id"]),
            )
        finally:
            connection.close()

        self.assertEqual(store.purge_expired_team_attachments(expired_at + 1), 1)
        self.get(
            self.owner,
            f"{self.base}/attachments/{declared['id']}",
            expected=404,
        )
        self.assertFalse(blob.exists())
        connection = store.connect()
        try:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT count(*) FROM team_attachment_cleanup_queue
                    WHERE path_kind='content' AND path_key=?
                    """,
                    (declared["sha256"],),
                ).fetchone()[0],
                0,
            )
        finally:
            connection.close()

    def test_first_chunk_rejects_precreated_hardlink_and_fifo_without_touching_them(self) -> None:
        payload = b"first chunk must create its staging inode exclusively"
        store = self.app.state.store
        for path_kind in ("hardlink", "fifo"):
            with self.subTest(path_kind=path_kind):
                declared = self.declare(
                    self.owner,
                    payload,
                    name=f"first-{path_kind}.bin",
                )["attachment"]
                staging = store._team_attachment_staging_path(declared["id"])
                victim: Path | None = None
                if path_kind == "hardlink":
                    victim = self.data_dir / f"first-{path_kind}-victim.bin"
                    victim.write_bytes(b"victim bytes must never be truncated")
                    os.chmod(victim, 0o600)
                    os.link(victim, staging)
                    before = victim.read_bytes()
                else:
                    os.mkfifo(staging, 0o600)

                rejected = self.put_chunk(
                    self.owner,
                    declared["id"],
                    payload,
                    0,
                    len(payload) - 1,
                )
                self.assertEqual(rejected.status_code, 409, rejected.text)
                self.assertEqual(
                    rejected.json()["error"]["code"], "attachment_unavailable"
                )
                metadata = self.get(
                    self.owner, f"{self.base}/attachments/{declared['id']}"
                )["attachment"]
                self.assertEqual(metadata["state"], "failed")
                if victim is not None:
                    self.assertEqual(victim.read_bytes(), before)
                    self.assertEqual(victim.stat().st_nlink, 2)
                else:
                    # Cleanup inspection is nonblocking too; the unsafe FIFO
                    # remains for explicit operator repair rather than hanging
                    # an opportunistic reclamation pass.
                    with self.assertRaises(PermissionError):
                        store._unlink_team_attachment_cleanup_path(
                            "staging", declared["id"]
                        )

    def test_resume_rejects_replaced_staging_hardlink_and_fifo_without_mutation(self) -> None:
        payload = b"resume must stay bound to one private regular staging inode"
        first_end = 8
        store = self.app.state.store
        for path_kind in ("hardlink", "fifo"):
            with self.subTest(path_kind=path_kind):
                declared = self.declare(
                    self.owner,
                    payload,
                    name=f"resume-{path_kind}.bin",
                )["attachment"]
                first = self.put_chunk(
                    self.owner,
                    declared["id"],
                    payload,
                    0,
                    first_end,
                )
                self.assertEqual(first.status_code, 200, first.text)
                staging = store._team_attachment_staging_path(declared["id"])
                staging.unlink()
                victim: Path | None = None
                if path_kind == "hardlink":
                    victim = self.data_dir / f"resume-{path_kind}-victim.bin"
                    victim.write_bytes(b"long victim bytes must remain exactly intact")
                    os.chmod(victim, 0o600)
                    os.link(victim, staging)
                    before = victim.read_bytes()
                else:
                    os.mkfifo(staging, 0o600)

                rejected = self.put_chunk(
                    self.owner,
                    declared["id"],
                    payload,
                    first_end + 1,
                    len(payload) - 1,
                )
                self.assertEqual(rejected.status_code, 409, rejected.text)
                self.assertEqual(
                    rejected.json()["error"]["code"], "attachment_unavailable"
                )
                if victim is not None:
                    self.assertEqual(victim.read_bytes(), before)
                    self.assertEqual(victim.stat().st_nlink, 2)

    def test_attachment_declaration_and_chunk_validation(self) -> None:
        payload = b"y" * 10
        digest = hashlib.sha256(payload).hexdigest()
        for bad in (
            {"file_name": "../evil", "media_type": "text/plain", "byte_size": 10, "sha256": digest},
            {"file_name": "a/b", "media_type": "text/plain", "byte_size": 10, "sha256": digest},
            {"file_name": "ok.txt", "media_type": "not a type", "byte_size": 10, "sha256": digest},
            {"file_name": "ok.txt", "media_type": "text/plain", "byte_size": 10, "sha256": "zz"},
        ):
            self.post(
                self.owner,
                f"{self.base}/attachments",
                {**bad, "idempotency_key": _key()},
                expected=422,
            )
        declared = self.declare(self.owner, payload, name="ok.txt")["attachment"]
        url = f"{self.base}/attachments/{declared['id']}/content"
        wrong_type = self.client.put(
            url,
            headers={
                **self.auth(self.owner),
                "Content-Type": "application/json",
                "Content-Range": "bytes 0-9/10",
            },
            content=payload,
        )
        self.assertEqual(wrong_type.status_code, 415, wrong_type.text)
        no_range = self.client.put(
            url,
            headers={**self.auth(self.owner), "Content-Type": "application/octet-stream"},
            content=payload,
        )
        self.assertEqual(no_range.status_code, 400, no_range.text)
        mismatch = self.client.put(
            url,
            headers={
                **self.auth(self.owner),
                "Content-Type": "application/octet-stream",
                "Content-Range": "bytes 0-4/10",
            },
            content=payload,
        )
        self.assertEqual(mismatch.status_code, 422, mismatch.text)
        wrong_total = self.client.put(
            url,
            headers={
                **self.auth(self.owner),
                "Content-Type": "application/octet-stream",
                "Content-Range": "bytes 0-9/11",
            },
            content=payload,
        )
        self.assertEqual(wrong_total.status_code, 422, wrong_total.text)
        guest = self.declare  # guests cannot declare uploads (write scope)
        response = self.client.post(
            f"{self.base}/attachments",
            headers=self.auth(self.guest),
            json={
                "file_name": "g.txt",
                "media_type": "text/plain",
                "byte_size": 10,
                "sha256": digest,
                "idempotency_key": _key(),
            },
        )
        self.assertEqual(response.status_code, 404, response.text)
        del guest

    def test_expired_unbound_uploads_are_purged_in_bounded_batches(self) -> None:
        store = self.app.state.store
        payload = b"z" * 100
        stale = self.declare(self.owner, payload, name="stale.bin")["attachment"]
        self.put_chunk(self.owner, stale["id"], payload, 0, 49)
        orphan = self.upload(self.owner, b"q" * 20, name="orphan.bin")
        survivor = self.upload(self.owner, b"s" * 20, name="bound.bin")
        message = self.send(
            self.owner,
            [{"kind": "all"}],
            body="durable attachment",
            attachment_ids=[survivor["id"]],
        )
        far_future = 10**10
        self.assertEqual(store.purge_expired_team_attachments(far_future, limit=1), 1)
        self.assertEqual(store.purge_expired_team_attachments(far_future, limit=1), 1)
        self.assertEqual(store.purge_expired_team_attachments(far_future, limit=1), 0)
        self.get(self.owner, f"{self.base}/attachments/{stale['id']}", expected=404)
        self.get(self.owner, f"{self.base}/attachments/{orphan['id']}", expected=404)
        self.assertEqual(
            self.get(self.owner, f"{self.base}/attachments/{survivor['id']}")["attachment"][
                "message_id"
            ],
            message["id"],
        )
        self.assertEqual(
            self.get(self.owner, f"{self.base}/attachments/{survivor['id']}")["attachment"][
                "state"
            ],
            "ready",
        )

    def test_expired_ready_orphan_does_not_permanently_consume_quota(self) -> None:
        store = self.app.state.store
        payload = b"o" * 32
        orphan = self.upload(self.owner, payload, name="quota-orphan.bin")
        orphan_path = self.data_dir / "attachments" / orphan["sha256"][:2] / orphan["sha256"]
        self.assertTrue(orphan_path.is_file())

        connection = store.connect()
        try:
            row = connection.execute(
                "SELECT created_at FROM team_attachments WHERE id=?", (orphan["id"],)
            ).fetchone()
            assert row is not None
            expired_at = int(row["created_at"]) + 1
            connection.execute(
                "UPDATE team_attachments SET expires_at=? WHERE id=?",
                (expired_at, orphan["id"]),
            )
        finally:
            connection.close()

        store.team_attachment_quota_bytes = len(payload)
        replacement_payload = b"n" * len(payload)
        with (
            mock.patch.object(store, "purge_expired_team_attachments", return_value=0),
            mock.patch("agentsdock_team_hub.store._now", return_value=expired_at + 1),
        ):
            replacement = self.declare(
                self.owner,
                replacement_payload,
                name="replacement.bin",
            )["attachment"]
        self.assertEqual(replacement["state"], "uploading")
        # Quota admission excludes expired unbound rows even if a bounded
        # opportunistic sweep has not reached them yet.
        self.assertTrue(orphan_path.exists())
        self.assertEqual(store.purge_expired_team_attachments(expired_at + 1), 1)
        self.get(self.owner, f"{self.base}/attachments/{orphan['id']}", expected=404)
        self.assertFalse(orphan_path.exists())

    def test_expired_declaration_replay_requires_a_fresh_idempotency_key(self) -> None:
        store = self.app.state.store
        payload = b"expired idempotency response"
        request = {
            "file_name": "expired-replay.bin",
            "media_type": "application/octet-stream",
            "byte_size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "idempotency_key": _key(),
        }
        attachment = self.post(
            self.owner, f"{self.base}/attachments", request
        )["attachment"]
        response = self.put_chunk(
            self.owner, attachment["id"], payload, 0, len(payload) - 1
        )
        self.assertEqual(response.status_code, 200, response.text)

        connection = store.connect()
        try:
            row = connection.execute(
                "SELECT created_at FROM team_attachments WHERE id=?", (attachment["id"],)
            ).fetchone()
            assert row is not None
            expired_at = int(row["created_at"]) + 1
            connection.execute(
                "UPDATE team_attachments SET expires_at=? WHERE id=?",
                (expired_at, attachment["id"]),
            )
        finally:
            connection.close()
        self.assertEqual(store.purge_expired_team_attachments(expired_at + 1), 1)

        with mock.patch("agentsdock_team_hub.store._now", return_value=expired_at + 1):
            replay = self.post(
                self.owner, f"{self.base}/attachments", request, expected=409
            )
            fresh = self.post(
                self.owner,
                f"{self.base}/attachments",
                {**request, "idempotency_key": _key()},
            )["attachment"]
        self.assertEqual(replay["error"]["code"], "attachment_unavailable")
        self.assertEqual(fresh["state"], "uploading")

    def test_reclaiming_ready_duplicates_preserves_shared_and_bound_blob(self) -> None:
        store = self.app.state.store
        payload = b"content addressed shared bytes"
        bound = self.upload(self.owner, payload, name="bound-copy.bin")
        message = self.send(
            self.owner,
            [{"kind": "all"}],
            body="owns shared bytes",
            attachment_ids=[bound["id"]],
        )
        expired = self.declare(self.owner, payload, name="expired-copy.bin")["attachment"]
        live = self.declare(self.owner, payload, name="live-copy.bin")["attachment"]
        self.assertEqual(expired["state"], "ready")
        self.assertEqual(live["state"], "ready")
        shared_path = self.data_dir / "attachments" / bound["sha256"][:2] / bound["sha256"]

        connection = store.connect()
        try:
            row = connection.execute(
                "SELECT created_at FROM team_attachments WHERE id=?", (expired["id"],)
            ).fetchone()
            assert row is not None
            expired_at = int(row["created_at"]) + 1
            connection.execute(
                "UPDATE team_attachments SET expires_at=? WHERE id=?",
                (expired_at, expired["id"]),
            )
        finally:
            connection.close()

        self.assertEqual(store.purge_expired_team_attachments(expired_at + 1), 1)
        self.assertTrue(shared_path.is_file())
        self.get(self.owner, f"{self.base}/attachments/{expired['id']}", expected=404)
        self.assertEqual(
            self.get(self.owner, f"{self.base}/attachments/{live['id']}")["attachment"][
                "state"
            ],
            "ready",
        )

        # Once the other unbound reference expires, the message-bound reference
        # still protects the physical blob indefinitely.
        self.assertEqual(store.purge_expired_team_attachments(10**10), 1)
        self.assertTrue(shared_path.is_file())
        download = self.client.get(
            f"{self.base}/attachments/{bound['id']}/content",
            headers=self.auth(self.owner),
        )
        self.assertEqual(download.status_code, 200, download.text)
        self.assertEqual(download.content, payload)
        self.assertEqual(
            self.get(self.owner, f"{self.base}/attachments/{bound['id']}")["attachment"][
                "message_id"
            ],
            message["id"],
        )

    def test_attachment_cleanup_failures_remain_durably_retryable(self) -> None:
        store = self.app.state.store
        ready_payload = b"ready orphan pending durable cleanup"
        ready = self.upload(self.owner, ready_payload, name="cleanup-ready.bin")
        partial_payload = b"partial orphan pending durable cleanup"
        partial = self.declare(
            self.owner, partial_payload, name="cleanup-partial.bin"
        )["attachment"]
        response = self.put_chunk(
            self.owner,
            partial["id"],
            partial_payload,
            0,
            len(partial_payload) // 2,
        )
        self.assertEqual(response.status_code, 200, response.text)

        ready_path = (
            self.data_dir
            / "attachments"
            / ready["sha256"][:2]
            / ready["sha256"]
        )
        partial_path = (
            self.data_dir / "attachments" / "uploads" / f"{partial['id']}.part"
        )
        self.assertTrue(ready_path.is_file())
        self.assertTrue(partial_path.is_file())

        with mock.patch.object(
            store,
            "_unlink_team_attachment_cleanup_path",
            side_effect=OSError("filesystem temporarily busy"),
        ):
            self.assertEqual(store.purge_expired_team_attachments(10**10), 2)

        connection = store.connect()
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM team_attachments WHERE id IN (?,?)",
                    (ready["id"], partial["id"]),
                ).fetchone()[0],
                0,
            )
            queued = {
                (str(row["path_kind"]), str(row["path_key"]))
                for row in connection.execute(
                    """
                    SELECT path_kind,path_key FROM team_attachment_cleanup_queue
                    ORDER BY path_kind,path_key
                    """
                )
            }
        finally:
            connection.close()
        self.assertEqual(
            queued,
            {
                ("content", ready["sha256"]),
                # Uploading rows also queue their final digest name: normally
                # it is absent, but a crash after publication and before the
                # ready transaction may have left verified final bytes there.
                ("content", partial["sha256"]),
                ("staging", ready["id"]),
                ("staging", partial["id"]),
            },
        )
        self.assertTrue(ready_path.is_file())
        self.assertTrue(partial_path.is_file())

        # There are no new stale rows, but a later pass still drains the
        # committed tombstones and treats already-missing paths as success.
        self.assertEqual(store.purge_expired_team_attachments(10**10), 0)
        self.assertFalse(ready_path.exists())
        self.assertFalse(partial_path.exists())
        connection = store.connect()
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM team_attachment_cleanup_queue"
                ).fetchone()[0],
                0,
            )
        finally:
            connection.close()

    def test_cleanup_tombstone_rechecks_a_reused_ready_blob(self) -> None:
        store = self.app.state.store
        payload = b"reused bytes must survive cleanup retry"
        orphan = self.upload(self.owner, payload, name="cleanup-orphan.bin")
        blob = (
            self.data_dir
            / "attachments"
            / orphan["sha256"][:2]
            / orphan["sha256"]
        )
        original_unlink = store._unlink_team_attachment_cleanup_path

        def fail_content(path_kind: str, path_key: str) -> None:
            if path_kind == "content":
                raise OSError("filesystem temporarily busy")
            original_unlink(path_kind, path_key)

        with mock.patch.object(
            store,
            "_unlink_team_attachment_cleanup_path",
            side_effect=fail_content,
        ):
            self.assertEqual(store.purge_expired_team_attachments(10**10), 1)
            replacement = self.declare(
                self.owner, payload, name="cleanup-replacement.bin"
            )["attachment"]
        self.assertEqual(replacement["state"], "uploading")
        response = self.put_chunk(
            self.owner, replacement["id"], payload, 0, len(payload) - 1
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["attachment"]["state"], "ready")

        # The pending content tombstone now observes the new ready metadata
        # reference and retires itself without unlinking the shared blob.
        self.assertEqual(store.purge_expired_team_attachments(), 0)
        self.assertTrue(blob.is_file())
        download = self.client.get(
            f"{self.base}/attachments/{replacement['id']}/content",
            headers=self.auth(self.owner),
        )
        self.assertEqual(download.status_code, 200, download.text)
        self.assertEqual(download.content, payload)
        connection = store.connect()
        try:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT count(*) FROM team_attachment_cleanup_queue
                    WHERE path_kind='content' AND path_key=?
                    """,
                    (orphan["sha256"],),
                ).fetchone()[0],
                0,
            )
        finally:
            connection.close()

    def test_authorized_stream_survives_orphan_reclamation(self) -> None:
        store = self.app.state.store
        payload = b"pinned stream survives unlink"
        orphan = self.upload(self.owner, payload, name="stream-orphan.bin")
        claims = store.verify_access(self.owner["access_token"])
        with self.assertRaises(HubError):
            store.bound_team_attachment_local_path(
                claims, self.team_id, orphan["id"]
            )
        public, source = store.open_team_attachment(
            claims, self.team_id, orphan["id"]
        )
        self.assertEqual(public["byte_size"], len(payload))

        connection = store.connect()
        try:
            created_at = int(
                connection.execute(
                    "SELECT created_at FROM team_attachments WHERE id=?",
                    (orphan["id"],),
                ).fetchone()[0]
            )
            connection.execute(
                "UPDATE team_attachments SET expires_at=? WHERE id=?",
                (created_at + 1, orphan["id"]),
            )
        finally:
            connection.close()

        try:
            self.assertEqual(
                store.purge_expired_team_attachments(created_at + 2), 1
            )
            self.assertEqual(os.pread(source.descriptor, len(payload), 0), payload)
        finally:
            source.close()

    def test_declaration_waits_for_reclaimer_before_deciding_blob_is_ready(self) -> None:
        store = self.app.state.store
        payload = b"serialize ready deduplication with physical reclamation"
        orphan = self.upload(self.owner, payload, name="race-orphan.bin")
        connection = store.connect()
        try:
            row = connection.execute(
                "SELECT created_at FROM team_attachments WHERE id=?", (orphan["id"],)
            ).fetchone()
            assert row is not None
            expired_at = int(row["created_at"]) + 1
            connection.execute(
                "UPDATE team_attachments SET expires_at=? WHERE id=?",
                (expired_at, orphan["id"]),
            )
        finally:
            connection.close()

        claims = store.verify_access(self.owner["access_token"])
        original_purge = store.purge_expired_team_attachments
        original_cleanup_unlink = store._unlink_team_attachment_cleanup_path
        collector_at_unlink = threading.Event()
        allow_unlink = threading.Event()
        declaration_done = threading.Event()
        outcomes: dict[str, object] = {}

        def controlled_cleanup_unlink(path_kind: str, path_key: str) -> None:
            if (
                threading.current_thread().name == "attachment-reclaimer"
                and path_kind == "content"
            ):
                collector_at_unlink.set()
                if not allow_unlink.wait(2):
                    raise RuntimeError("test did not release attachment reclaimer")
            original_cleanup_unlink(path_kind, path_key)

        def controlled_purge(*args, **kwargs) -> int:
            if threading.current_thread().name == "attachment-declarer":
                return 0
            return original_purge(*args, **kwargs)

        def reclaim() -> None:
            try:
                outcomes["removed"] = store.purge_expired_team_attachments(expired_at + 1)
            except BaseException as exc:  # pragma: no cover - asserted below
                outcomes["reclaim_error"] = exc

        def declare_replacement() -> None:
            try:
                outcomes["declared"] = store.declare_team_attachment(
                    claims,
                    self.team_id,
                    {
                        "file_name": "race-replacement.bin",
                        "media_type": "application/octet-stream",
                        "byte_size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "idempotency_key": _key(),
                    },
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                outcomes["declare_error"] = exc
            finally:
                declaration_done.set()

        with (
            mock.patch.object(
                store,
                "_unlink_team_attachment_cleanup_path",
                side_effect=controlled_cleanup_unlink,
            ),
            mock.patch.object(
                store, "purge_expired_team_attachments", side_effect=controlled_purge
            ),
        ):
            collector = threading.Thread(target=reclaim, name="attachment-reclaimer")
            declarer = threading.Thread(target=declare_replacement, name="attachment-declarer")
            declarer_started = False
            collector.start()
            try:
                self.assertTrue(collector_at_unlink.wait(2))
                declarer.start()
                declarer_started = True
                self.assertFalse(declaration_done.wait(0.1))
            finally:
                allow_unlink.set()
            collector.join(2)
            if declarer_started:
                declarer.join(2)

        self.assertFalse(collector.is_alive())
        self.assertTrue(declarer_started)
        self.assertFalse(declarer.is_alive())
        self.assertNotIn("reclaim_error", outcomes)
        self.assertNotIn("declare_error", outcomes)
        self.assertEqual(outcomes["removed"], 1)
        declared = outcomes["declared"]
        assert isinstance(declared, dict)
        self.assertEqual(declared["attachment"]["state"], "uploading")


if __name__ == "__main__":
    unittest.main()
