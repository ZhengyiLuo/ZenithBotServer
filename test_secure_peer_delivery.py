from pathlib import Path
import tempfile
import unittest

from secure_peer_delivery import SecurePeerDeliveryLedger


def envelope(**changes):
    value = {
        "envelope_id": "env_1234567890abcdef",
        "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "team_id": "team-test",
        "source_peer_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "source_server_identity": "server-source",
        "source_route_id": "11111111-1111-4111-8111-111111111111",
        "source_route_revision": "rev_" + "1" * 32,
        "target_peer_id": None,
        "target_server_identity": "server-target",
        "target_route_id": "22222222-2222-4222-8222-222222222222",
        "target_route_revision": "rev_" + "2" * 32,
        "action": "request_reply",
        "kind": "request_reply",
        "exchange_id": "33333333-3333-4333-8333-333333333333",
        "parent_envelope_id": None,
        "parent_leg": None,
        "used_legs": 1,
        "max_legs": 6,
        "expires_at": 4_000_000_000,
        "body": {"message": "hello"},
    }
    value.update(changes)
    return value


class SecurePeerDeliveryLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = SecurePeerDeliveryLedger(
            Path(self.temp.name) / "secure" / "deliveries.sqlite3"
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_prepare_is_exactly_idempotent_and_survives_reopen(self):
        first, created = self.ledger.prepare(
            envelope(),
            transport_role="client",
            connection_id="44444444-4444-4444-8444-444444444444",
            lease_token="lease." + "a" * 43,
            target_chat_id="chat-target",
        )
        self.assertTrue(created)
        self.assertEqual(first["state"], "prepared")
        reopened = SecurePeerDeliveryLedger(self.ledger.path)
        second, created = reopened.prepare(
            envelope(),
            transport_role="client",
            connection_id="44444444-4444-4444-8444-444444444444",
            lease_token="lease." + "a" * 43,
            target_chat_id="chat-target",
        )
        self.assertFalse(created)
        self.assertEqual(second["claim_digest"], first["claim_digest"])
        redelivered, created = reopened.prepare(
            envelope(),
            transport_role="client",
            connection_id="44444444-4444-4444-8444-444444444444",
            lease_token="lease." + "c" * 43,
            target_chat_id="chat-target",
        )
        self.assertFalse(created)
        self.assertEqual(redelivered["claim_digest"], first["claim_digest"])
        self.assertEqual(redelivered["lease_token"], "lease." + "c" * 43)
        with self.assertRaisesRegex(RuntimeError, "identity changed"):
            reopened.prepare(
                envelope(body={"message": "changed"}),
                transport_role="client",
                connection_id="44444444-4444-4444-8444-444444444444",
                lease_token="lease." + "a" * 43,
                target_chat_id="chat-target",
            )

    def test_authorize_bind_response_and_finish_are_monotonic(self):
        self.ledger.prepare(
            envelope(),
            transport_role="host",
            connection_id="55555555-5555-4555-8555-555555555555",
            lease_token="lease." + "b" * 43,
            target_chat_id="chat-target",
        )
        authorized = self.ledger.authorize("env_1234567890abcdef")
        self.assertEqual(authorized["state"], "authorized")
        queued = self.ledger.bind_owner(
            "env_1234567890abcdef", queued_id="queued_1", run_id=None
        )
        self.assertEqual(queued["state"], "queued")
        running = self.ledger.bind_owner(
            "env_1234567890abcdef", queued_id="queued_1", run_id="run_1"
        )
        self.assertEqual(running["state"], "running")
        self.assertIsNone(self.ledger.bind_owner(
            "env_1234567890abcdef", queued_id="queued_2", run_id=None
        ))
        replay = self.ledger.bind_owner(
            "env_1234567890abcdef", queued_id="queued_1", run_id="run_1"
        )
        self.assertEqual(replay["state"], "running")
        intent = self.ledger.prepare_response(
            "env_1234567890abcdef",
            request_id="66666666-6666-4666-8666-666666666666",
            body="answer",
            request_response=False,
        )
        self.assertEqual(intent["response_body"], "answer")
        with self.assertRaisesRegex(RuntimeError, "intent changed"):
            self.ledger.prepare_response(
                "env_1234567890abcdef",
                request_id="77777777-7777-4777-8777-777777777777",
                body="different",
                request_response=False,
            )
        response = self.ledger.mark_response_committed(
            "env_1234567890abcdef",
            request_id="66666666-6666-4666-8666-666666666666",
        )
        self.assertEqual(response["response_committed"], 1)
        finished = self.ledger.finish(
            "env_1234567890abcdef", succeeded=True, result_text="answer"
        )
        self.assertEqual(finished["state"], "completed")
        self.assertIsNone(self.ledger.bind_owner(
            "env_1234567890abcdef", queued_id="queued_2", run_id=None
        ))

    def test_ownerless_authorized_failure_cas_preserves_a_racing_owner(self):
        self.ledger.prepare(
            envelope(),
            transport_role="client",
            connection_id="44444444-4444-4444-8444-444444444444",
            lease_token="lease." + "a" * 43,
            target_chat_id="chat-target",
        )
        self.ledger.authorize("env_1234567890abcdef")
        failed = self.ledger.fail_ownerless_authorized(
            "env_1234567890abcdef",
            error="target unavailable",
        )
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(self.ledger.pending_admissions(), [])
        self.assertEqual(self.ledger.nonterminal_for_chat("chat-target"), [])

        second = envelope(
            envelope_id="env_fedcba0987654321",
            request_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        )
        self.ledger.prepare(
            second,
            transport_role="client",
            connection_id="44444444-4444-4444-8444-444444444444",
            lease_token="lease." + "b" * 43,
            target_chat_id="chat-target",
        )
        self.ledger.authorize(second["envelope_id"])
        self.ledger.bind_owner(
            second["envelope_id"],
            queued_id="queued-owner",
            run_id=None,
        )
        retained = self.ledger.fail_ownerless_authorized(
            second["envelope_id"],
            error="stale unavailable decision",
        )
        self.assertEqual(retained["state"], "queued")
        self.assertEqual(retained["queued_id"], "queued-owner")

    def test_invalid_budget_and_cross_envelope_collision_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "leg budget"):
            self.ledger.prepare(
                envelope(max_legs=7),
                transport_role="client",
                connection_id="44444444-4444-4444-8444-444444444444",
                lease_token="lease." + "a" * 43,
                target_chat_id="chat-target",
            )
        self.ledger.prepare(
            envelope(),
            transport_role="client",
            connection_id="44444444-4444-4444-8444-444444444444",
            lease_token="lease." + "a" * 43,
            target_chat_id="chat-target",
        )
        with self.assertRaisesRegex(RuntimeError, "identity changed"):
            self.ledger.prepare(
                envelope(target_route_revision="rev_" + "3" * 32),
                transport_role="client",
                connection_id="44444444-4444-4444-8444-444444444444",
                lease_token="lease." + "a" * 43,
                target_chat_id="chat-target",
            )


    def test_pending_outbound_is_indexed_by_chat_route_and_connection(self):
        snapshot = {
            "version": 1,
            "role": "client",
            "connection_id": "44444444-4444-4444-8444-444444444444",
            "source_server_identity": "server-source",
            "source_chat_id": "chat-source",
            "source_route_id": "11111111-1111-4111-8111-111111111111",
            "source_route_revision": "rev_" + "1" * 32,
            "target_server_identity": "server-target",
            "target_route_id": "22222222-2222-4222-8222-222222222222",
            "target_route_revision": "rev_" + "2" * 32,
            "action": "instruction",
        }
        intent, created = self.ledger.prepare_outbound(
            request_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            source_session_id="chat-source",
            source_run_id="run-source",
            snapshot=snapshot,
            body="deliver me",
            action="instruction",
            expires_at=4_000_000_000,
        )
        self.assertTrue(created)
        self.assertEqual(intent["connection_id"], snapshot["connection_id"])
        self.assertEqual(
            [
                item["request_id"]
                for item in self.ledger.pending_outbound_for_chat("chat-source")
            ],
            ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        )
        self.assertEqual(
            len(
                self.ledger.pending_outbound_for_route(
                    snapshot["connection_id"],
                    snapshot["source_route_id"],
                    snapshot["source_route_revision"],
                )
            ),
            1,
        )
        self.assertEqual(
            len(
                self.ledger.pending_outbound_for_connection(
                    snapshot["connection_id"]
                )
            ),
            1,
        )
        self.ledger.fail_outbound(intent["request_id"], "retired")
        self.assertEqual(
            self.ledger.pending_outbound_for_chat("chat-source"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
