from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from agentsdock_team_hub.service import _RateLimiter, create_app
from agentsdock_team_hub.store import HubError


class TeamHubServiceTests(unittest.TestCase):
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
        team_id = owner["teams"][0]["id"]
        issued = self.client.post(
            f"/v1/teams/{team_id}/invitations",
            headers=self.auth(owner),
            json={"invitee_email": email, "role": role},
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        redeemed = self.client.post(
            "/v1/invitations/redeem",
            json={
                "token": issued.json()["token"],
                "email": email,
                "display_name": email.split("@", 1)[0],
                "device_label": f"{role} device",
            },
        )
        self.assertEqual(redeemed.status_code, 200, redeemed.text)
        return redeemed.json()

    def test_health_has_stable_hub_identity_and_no_bootstrap_secret(self) -> None:
        first = self.client.get("/v1/health").json()
        self.assertTrue(first["bootstrap_required"])
        self.assertNotIn("proof", " ".join(first.keys()).lower())
        second_app = create_app(self.data_dir, allowed_hosts={"testserver"})
        second = TestClient(second_app).get("/v1/health").json()
        self.assertEqual(second["hub_id"], first["hub_id"])
        self.assertNotEqual(second["instance_id"], first["instance_id"])
        with tempfile.TemporaryDirectory() as other:
            other_app = create_app(other, allowed_hosts={"testserver"})
            other_health = TestClient(other_app).get("/v1/health").json()
        self.assertNotEqual(other_health["hub_id"], first["hub_id"])

    def test_bootstrap_requires_actual_loopback_and_one_exact_proof_header(self) -> None:
        proof = (self.data_dir / "bootstrap-owner.proof").read_text().strip()
        remote = TestClient(self.app, client=("192.0.2.8", 41000))
        denied = remote.post(
            "/v1/bootstrap/redeem",
            headers={
                "Host": "localhost",
                "X-Forwarded-For": "127.0.0.1",
                "X-Team-Hub-Bootstrap-Proof": proof,
            },
            json={"email": "owner@example.com", "display_name": "Owner", "device_label": "Mac"},
        )
        self.assertEqual(denied.status_code, 403)
        proxied_app = create_app(
            Path(self.temporary.name) / "proxied",
            allowed_hosts={"localhost", "hub.example.test"},
        )
        proxied_proof = (
            Path(self.temporary.name) / "proxied" / "bootstrap-owner.proof"
        ).read_text().strip()
        proxied = TestClient(
            proxied_app,
            base_url="http://hub.example.test",
            client=("127.0.0.1", 41001),
        ).post(
            "/v1/bootstrap/redeem",
            headers={"X-Team-Hub-Bootstrap-Proof": proxied_proof},
            json={"email": "owner@example.com", "display_name": "Owner", "device_label": "Mac"},
        )
        self.assertEqual(proxied.status_code, 403)
        malformed = self.client.post(
            "/v1/bootstrap/redeem",
            headers={"X-Team-Hub-Bootstrap-Proof": "short"},
            json={
                "email": "owner@example.com",
                "display_name": "Owner",
                "device_label": "Mac",
            },
        )
        self.assertEqual(malformed.status_code, 403)
        self.assertEqual(
            malformed.json()["error"]["code"],
            "bootstrap_unavailable",
        )
        duplicate = self.client.post(
            "/v1/bootstrap/redeem",
            headers=[
                ("X-Team-Hub-Bootstrap-Proof", proof),
                ("X-Team-Hub-Bootstrap-Proof", proof),
            ],
            json={"email": "owner@example.com", "display_name": "Owner", "device_label": "Mac"},
        )
        self.assertEqual(duplicate.status_code, 403)
        malformed_host = self.client.get("/v1/health", headers={"Host": "[::1]evil"})
        self.assertEqual(malformed_host.status_code, 400)

    def test_unknown_post_paths_share_a_bounded_rate_bucket(self) -> None:
        last = None
        for index in range(121):
            last = self.client.post(f"/unknown/{index}", json={})
        assert last is not None
        self.assertEqual(last.status_code, 429)
        limiter = self.app.state.rate_limiter
        for index in range(5000):
            limiter.allow(f"peer-{index}", f"action-{index}", 1)
        self.assertLessEqual(len(limiter._buckets), 4096)

    def test_rate_limit_does_not_reset_at_a_wall_window_boundary(self) -> None:
        now = [59.999]
        limiter = _RateLimiter(clock=lambda: now[0])
        for _index in range(8):
            self.assertTrue(limiter.allow("peer", "bootstrap", 8))

        now[0] = 60.001
        self.assertFalse(limiter.allow("peer", "bootstrap", 8))

        now[0] = 120.001
        self.assertTrue(limiter.allow("peer", "bootstrap", 8))

    def test_rate_limit_samples_clock_in_serialized_admission_order(self) -> None:
        class ReverseEntryLock:
            def __init__(self) -> None:
                self.mutex = threading.Lock()
                self.first_waiting = threading.Event()
                self.second_finished = threading.Event()

            def __enter__(self) -> "ReverseEntryLock":
                if threading.current_thread().name == "rate-first":
                    self.first_waiting.set()
                    if not self.second_finished.wait(timeout=2):
                        raise TimeoutError("second limiter call did not finish")
                elif not self.first_waiting.wait(timeout=2):
                    raise TimeoutError("first limiter call did not reach the lock")
                self.mutex.acquire()
                return self

            def __exit__(self, *_args: object) -> None:
                self.mutex.release()
                if threading.current_thread().name == "rate-second":
                    self.second_finished.set()

        clock_values = iter((100.25, 101.25))
        clock_lock = threading.Lock()

        def clock() -> float:
            with clock_lock:
                return next(clock_values)

        limiter = _RateLimiter(clock=clock)
        reverse_lock = ReverseEntryLock()
        limiter._lock = reverse_lock  # type: ignore[assignment]
        failures: list[BaseException] = []

        def admit() -> None:
            try:
                self.assertTrue(limiter.allow("peer", "action", 10))
            except BaseException as exc:
                failures.append(exc)

        first = threading.Thread(target=admit, name="rate-first")
        second = threading.Thread(target=admit, name="rate-second")
        first.start()
        self.assertTrue(reverse_lock.first_waiting.wait(timeout=2))
        second.start()
        first.join(timeout=3)
        second.join(timeout=3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        if failures:
            raise failures[0]

        bucket = limiter._buckets[("peer", "action")]
        self.assertEqual(list(bucket.bins), [(100, 1), (101, 1)])
        self.assertEqual(bucket.count, 2)
        self.assertEqual(bucket.last_seen, 101.25)

    def test_patch_is_cors_advertised_maintenance_fenced_and_rate_limited(self) -> None:
        origin = "https://desktop.example.test"
        origin_app = create_app(
            self.data_dir,
            allowed_hosts={"testserver", "localhost"},
            allowed_origins={origin},
        )
        with TestClient(
            origin_app,
            base_url="http://localhost",
            client=("127.0.0.1", 41002),
        ) as client:
            preflight = client.options(
                "/v1/teams/team_valid_12345678/members/principal_valid_12345678",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "PATCH",
                    "Access-Control-Request-Headers": "authorization, content-type",
                },
            )
            self.assertEqual(preflight.status_code, 204, preflight.text)
            self.assertEqual(
                preflight.headers["access-control-allow-methods"],
                "GET, POST, PUT, PATCH",
            )

            attachment_preflight = client.options(
                "/v1/teams/team_valid_12345678/network/attachments/attachment_valid_12345678/content",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": (
                        "authorization, content-type, content-range"
                    ),
                },
            )
            self.assertEqual(
                attachment_preflight.status_code,
                204,
                attachment_preflight.text,
            )
            self.assertEqual(
                attachment_preflight.headers["access-control-allow-methods"],
                "GET, POST, PUT, PATCH",
            )
            self.assertEqual(
                attachment_preflight.headers["access-control-allow-headers"],
                "authorization, content-type, content-range",
            )

            with mock.patch.object(
                origin_app.state.store,
                "maintenance_fence",
                return_value={"reason": "server-update"},
            ), mock.patch.object(
                origin_app.state.store,
                "update_human_membership",
            ) as update:
                fenced = client.patch(
                    "/v1/teams/team_valid_12345678/members/principal_valid_12345678",
                    headers={"Origin": origin, "Authorization": "Bearer invalid"},
                    json={"status": "suspended"},
                )
            self.assertEqual(fenced.status_code, 503, fenced.text)
            self.assertEqual(fenced.json()["error"]["code"], "hub_maintenance")
            self.assertEqual(fenced.headers["access-control-allow-origin"], origin)
            self.assertEqual(fenced.headers["vary"], "Origin")
            update.assert_not_called()

            with mock.patch.object(
                origin_app.state.store,
                "maintenance_fence",
                return_value=None,
            ), mock.patch.object(
                origin_app.state.rate_limiter,
                "allow",
                return_value=False,
            ) as allow:
                limited = client.patch(
                    "/v1/teams/team_valid_12345678/members/principal_valid_12345678",
                    headers={"Origin": origin, "Authorization": "Bearer invalid"},
                    json={"status": "suspended"},
                )
            self.assertEqual(limited.status_code, 429, limited.text)
            self.assertEqual(limited.json()["error"]["code"], "rate_limited")
            self.assertEqual(limited.headers["access-control-allow-origin"], origin)
            self.assertEqual(limited.headers["vary"], "Origin")
            self.assertEqual(allow.call_args.args[1], "other_patch")

            malformed = client.request(
                "PATCH",
                "/v1/teams/team_valid_12345678/members/principal_valid_12345678",
                headers={
                    "Origin": origin,
                    "Authorization": "Bearer invalid",
                    "Content-Type": "application/json",
                },
                content=b"{",
            )
            self.assertEqual(malformed.status_code, 413, malformed.text)
            self.assertEqual(
                malformed.headers["access-control-allow-origin"], origin
            )
            self.assertEqual(malformed.headers["vary"], "Origin")

    def test_refresh_rotation_replay_revokes_entire_session(self) -> None:
        owner = self.bootstrap()
        rotated = self.client.post(
            "/v1/sessions/refresh", json={"refresh_token": owner["refresh_token"]}
        )
        self.assertEqual(rotated.status_code, 200, rotated.text)
        replay = self.client.post(
            "/v1/sessions/refresh", json={"refresh_token": owner["refresh_token"]}
        )
        self.assertEqual(replay.status_code, 401)
        rejected = self.client.get("/v1/session", headers=self.auth(rotated.json()))
        self.assertEqual(rejected.status_code, 401)
        connection = self.app.state.store.connect()
        try:
            row = connection.execute(
                "SELECT revoked_at FROM device_sessions WHERE id = ?",
                (owner["session"]["id"],),
            ).fetchone()
            self.assertIsNotNone(row["revoked_at"])
        finally:
            connection.close()

    def test_existing_email_invite_cannot_mint_session_and_authenticated_accepts(self) -> None:
        owner = self.bootstrap()
        member = self.invite_and_redeem(owner, "member@example.com", "member")
        team_id = owner["teams"][0]["id"]
        issued = self.client.post(
            f"/v1/teams/{team_id}/invitations",
            headers=self.auth(owner),
            json={"invitee_email": "member@example.com", "role": "member"},
        ).json()
        before = self.app.state.store.connect()
        try:
            session_count = before.execute("SELECT count(*) FROM device_sessions").fetchone()[0]
        finally:
            before.close()
        impersonation = self.client.post(
            "/v1/invitations/redeem",
            json={
                "token": issued["token"],
                "email": "member@example.com",
                "display_name": "Attacker",
                "device_label": "Attacker device",
            },
        )
        self.assertEqual(impersonation.status_code, 409)
        accepted = self.client.post(
            "/v1/invitations/accept",
            headers=self.auth(member),
            json={"token": issued["token"]},
        )
        self.assertEqual(accepted.status_code, 200, accepted.text)
        after = self.app.state.store.connect()
        try:
            self.assertEqual(
                after.execute("SELECT count(*) FROM device_sessions").fetchone()[0],
                session_count,
            )
        finally:
            after.close()

    def test_owner_lists_and_revokes_only_pending_invitation_metadata(self) -> None:
        owner = self.bootstrap()
        team_id = owner["teams"][0]["id"]
        issued = self.client.post(
            f"/v1/teams/{team_id}/invitations",
            headers=self.auth(owner),
            json={"invitee_email": "pending@example.com", "role": "member"},
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        invitation = issued.json()["invitation"]
        second = self.client.post(
            f"/v1/teams/{team_id}/invitations",
            headers=self.auth(owner),
            json={"invitee_email": "second@example.com", "role": "guest"},
        )
        self.assertEqual(second.status_code, 200, second.text)

        listed = self.client.get(
            f"/v1/teams/{team_id}/invitations",
            headers=self.auth(owner),
            params={"limit": 1},
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        invitations = listed.json()["invitations"]
        self.assertEqual(len(invitations), 1)
        self.assertTrue(listed.json()["has_more"])
        self.assertIsInstance(listed.json()["next_cursor"], str)
        next_page = self.client.get(
            f"/v1/teams/{team_id}/invitations",
            headers=self.auth(owner),
            params={"limit": 1, "cursor": listed.json()["next_cursor"]},
        )
        self.assertEqual(next_page.status_code, 200, next_page.text)
        all_invitations = invitations + next_page.json()["invitations"]
        by_id = {item["id"]: item for item in all_invitations}
        self.assertEqual(
            set(by_id), {invitation["id"], second.json()["invitation"]["id"]}
        )
        pending = by_id[invitation["id"]]
        self.assertEqual(pending["invitee_email"], "pending@example.com")
        self.assertEqual(pending["role"], "member")
        self.assertEqual(
            pending["issued_by_principal_id"], owner["principal"]["id"]
        )
        self.assertEqual(pending["expires_at"], invitation["expires_at"])
        self.assertIsInstance(pending["created_at"], str)
        serialized = json.dumps(listed.json()).lower()
        self.assertNotIn("token", serialized)
        self.assertNotIn("hash", serialized)

        admin = self.invite_and_redeem(owner, "admin@example.com", "admin")
        denied = self.client.get(
            f"/v1/teams/{team_id}/invitations",
            headers=self.auth(admin),
        )
        self.assertEqual(denied.status_code, 403)
        hidden_team = self.client.get(
            "/v1/teams/team_missing_12345678/invitations",
            headers=self.auth(owner),
        )
        self.assertEqual(hidden_team.status_code, 404)
        oversized_team = self.client.get(
            f"/v1/teams/{'t' * 241}/invitations",
            headers=self.auth(owner),
        )
        self.assertEqual(oversized_team.status_code, 404)
        invalid_cursor = self.client.get(
            f"/v1/teams/{team_id}/invitations",
            headers=self.auth(owner),
            params={"cursor": "99999999999999999999:invite_valid_12345678"},
        )
        self.assertEqual(invalid_cursor.status_code, 422)

        revoked = self.client.post(
            f"/v1/teams/{team_id}/invitations/{invitation['id']}/revoke",
            headers=self.auth(owner),
            json={},
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.json(), {"revoked": True})
        replay = self.client.post(
            f"/v1/teams/{team_id}/invitations/{invitation['id']}/revoke",
            headers=self.auth(owner),
            json={},
        )
        missing = self.client.post(
            f"/v1/teams/{team_id}/invitations/invite_missing_12345678/revoke",
            headers=self.auth(owner),
            json={},
        )
        self.assertEqual(replay.status_code, 404)
        self.assertEqual(missing.status_code, 404)
        redeem = self.client.post(
            "/v1/invitations/redeem",
            json={
                "token": issued.json()["token"],
                "email": "pending@example.com",
                "display_name": "Pending",
                "device_label": "Pending Mac",
            },
        )
        self.assertEqual(redeem.status_code, 403)
        connection = self.app.state.store.connect()
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM audit_events WHERE action='invitation.revoke' "
                    "AND resource_id=?",
                    (invitation["id"],),
                ).fetchone()[0],
                1,
            )
        finally:
            connection.close()

    def test_owner_membership_admin_enforces_transitions_and_hidden_targets(self) -> None:
        owner = self.bootstrap()
        team_id = owner["teams"][0]["id"]
        admin = self.invite_and_redeem(owner, "admin@example.com", "admin")
        member = self.invite_and_redeem(owner, "member@example.com", "member")
        observer = self.invite_and_redeem(
            owner, "observer@example.com", "member"
        )
        member_id = member["principal"]["id"]

        denied = self.client.patch(
            f"/v1/teams/{team_id}/members/{member_id}",
            headers=self.auth(admin),
            json={"status": "suspended"},
        )
        self.assertEqual(denied.status_code, 403)
        self_target = self.client.patch(
            f"/v1/teams/{team_id}/members/{owner['principal']['id']}",
            headers=self.auth(owner),
            json={"status": "suspended"},
        )
        missing = self.client.patch(
            f"/v1/teams/{team_id}/members/principal_missing_12345678",
            headers=self.auth(owner),
            json={"status": "suspended"},
        )
        self.assertEqual(self_target.status_code, 404)
        self.assertEqual(missing.status_code, 404)
        invalid_shapes = (
            {},
            {"role": "member", "status": "active"},
            {"role": "owner"},
            {"status": "unknown"},
        )
        for body in invalid_shapes:
            with self.subTest(body=body):
                response = self.client.patch(
                    f"/v1/teams/{team_id}/members/{member_id}",
                    headers=self.auth(owner),
                    json=body,
                )
                self.assertEqual(response.status_code, 422, response.text)

        suspended = self.client.patch(
            f"/v1/teams/{team_id}/members/{member_id}",
            headers=self.auth(owner),
            json={"status": "suspended"},
        )
        self.assertEqual(suspended.status_code, 200, suspended.text)
        self.assertEqual(suspended.json()["member"]["status"], "suspended")
        inactive_role = self.client.patch(
            f"/v1/teams/{team_id}/members/{member_id}",
            headers=self.auth(owner),
            json={"role": "guest"},
        )
        self.assertEqual(inactive_role.status_code, 409)
        denied_team = self.client.get(
            f"/v1/teams/{team_id}", headers=self.auth(member)
        )
        self.assertEqual(denied_team.status_code, 404)

        reloaded_app = create_app(
            self.data_dir, allowed_hosts={"testserver", "localhost"}
        )
        with TestClient(
            reloaded_app,
            base_url="http://localhost",
            client=("127.0.0.1", 41001),
        ) as reloaded:
            owner_view = reloaded.get(
                f"/v1/teams/{team_id}/members", headers=self.auth(owner)
            )
            admin_view = reloaded.get(
                f"/v1/teams/{team_id}/members", headers=self.auth(admin)
            )
            ordinary_view = reloaded.get(
                f"/v1/teams/{team_id}/members", headers=self.auth(observer)
            )
            self.assertEqual(owner_view.status_code, 200, owner_view.text)
            self.assertEqual(admin_view.status_code, 200, admin_view.text)
            self.assertEqual(ordinary_view.status_code, 200, ordinary_view.text)
            self.assertEqual(
                next(
                    item
                    for item in owner_view.json()["members"]
                    if item["principal_id"] == member_id
                )["status"],
                "suspended",
            )
            self.assertIn(
                member_id,
                {item["principal_id"] for item in admin_view.json()["members"]},
            )
            self.assertNotIn(
                member_id,
                {
                    item["principal_id"]
                    for item in ordinary_view.json()["members"]
                },
            )
            page_ids: list[str] = []
            cursor = None
            while True:
                page = reloaded.get(
                    f"/v1/teams/{team_id}/members",
                    headers=self.auth(owner),
                    params={"limit": 1, **({"cursor": cursor} if cursor else {})},
                )
                self.assertEqual(page.status_code, 200, page.text)
                page_ids.extend(
                    item["principal_id"] for item in page.json()["members"]
                )
                if not page.json()["has_more"]:
                    self.assertIsNone(page.json()["next_cursor"])
                    break
                cursor = page.json()["next_cursor"]
                self.assertIsInstance(cursor, str)
            self.assertEqual(
                set(page_ids),
                {
                    owner["principal"]["id"],
                    admin["principal"]["id"],
                    member_id,
                    observer["principal"]["id"],
                },
            )
            self.assertEqual(len(page_ids), len(set(page_ids)))
            reactivated = reloaded.patch(
                f"/v1/teams/{team_id}/members/{member_id}",
                headers=self.auth(owner),
                json={"status": "active"},
            )
        self.assertEqual(reactivated.status_code, 200, reactivated.text)
        changed_role = self.client.patch(
            f"/v1/teams/{team_id}/members/{member_id}",
            headers=self.auth(owner),
            json={"role": "guest"},
        )
        self.assertEqual(changed_role.status_code, 200, changed_role.text)
        self.assertEqual(changed_role.json()["member"]["role"], "guest")
        revoked = self.client.patch(
            f"/v1/teams/{team_id}/members/{member_id}",
            headers=self.auth(owner),
            json={"status": "revoked"},
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        terminal = self.client.patch(
            f"/v1/teams/{team_id}/members/{member_id}",
            headers=self.auth(owner),
            json={"status": "active"},
        )
        self.assertEqual(terminal.status_code, 409)
        self.assertEqual(terminal.json()["error"]["code"], "membership_terminal")
        connection = self.app.state.store.connect()
        try:
            actions = [
                row[0]
                for row in connection.execute(
                    "SELECT action FROM audit_events WHERE resource_id=?",
                    (member_id,),
                )
            ]
            self.assertEqual(actions.count("membership.status_change"), 3)
            self.assertEqual(actions.count("membership.role_change"), 1)
        finally:
            connection.close()

    def test_device_session_self_service_is_principal_scoped_and_immediate(self) -> None:
        owner = self.bootstrap()
        member = self.invite_and_redeem(owner, "member@example.com", "member")
        owner_session_id = owner["session"]["id"]
        timestamp = int(time.time())
        connection = self.app.state.store.connect()
        try:
            connection.execute(
                """
                INSERT INTO device_sessions(
                    id,human_principal_id,device_label,refresh_generation,
                    created_at,last_seen_at,expires_at
                ) VALUES (?,?,?,0,?,?,?)
                """,
                (
                    "device_secondary_12345678",
                    owner["principal"]["id"],
                    "Secondary",
                    timestamp,
                    timestamp,
                    timestamp + 3600,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        listed = self.client.get(
            "/v1/sessions",
            headers=self.auth(owner),
            params={"limit": 1},
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(len(listed.json()["sessions"]), 1)
        self.assertTrue(listed.json()["has_more"])
        page_cursor = listed.json()["next_cursor"]
        self.assertTrue(page_cursor.startswith("v1."))
        encrypted_cursor = base64.urlsafe_b64decode(
            page_cursor[3:] + "=" * (-len(page_cursor[3:]) % 4)
        )
        self.assertNotIn(
            owner["principal"]["id"].encode("utf-8"), encrypted_cursor
        )
        tampered_cursor = list(page_cursor)
        tampered_cursor[10] = "A" if tampered_cursor[10] != "A" else "B"
        tampered = self.client.get(
            "/v1/sessions",
            headers=self.auth(owner),
            params={"limit": 1, "cursor": "".join(tampered_cursor)},
        )
        cross_principal = self.client.get(
            "/v1/sessions",
            headers=self.auth(member),
            params={"limit": 1, "cursor": page_cursor},
        )
        self.assertEqual(tampered.status_code, 422, tampered.text)
        self.assertEqual(cross_principal.status_code, 422, cross_principal.text)
        connection = self.app.state.store.connect()
        try:
            connection.execute(
                """
                INSERT INTO device_sessions(
                    id,human_principal_id,device_label,refresh_generation,
                    created_at,last_seen_at,expires_at
                ) VALUES (?,?,?,0,?,?,?)
                """,
                (
                    "00000000",
                    owner["principal"]["id"],
                    "Inserted after traversal began",
                    timestamp,
                    timestamp,
                    timestamp + 3600,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        next_page = self.client.get(
            "/v1/sessions",
            headers=self.auth(owner),
            params={"limit": 1, "cursor": listed.json()["next_cursor"]},
        )
        self.assertEqual(next_page.status_code, 200, next_page.text)
        sessions = listed.json()["sessions"] + next_page.json()["sessions"]
        self.assertNotIn(
            "00000000",
            {item["id"] for item in sessions},
        )
        public = next(item for item in sessions if item["id"] == owner_session_id)
        self.assertEqual(public["id"], owner_session_id)
        self.assertTrue(public["current"])
        self.assertEqual(
            set(public),
            {
                "id",
                "device_label",
                "created_at",
                "last_seen_at",
                "expires_at",
                "revoked_at",
                "current",
            },
        )
        hidden = self.client.post(
            f"/v1/sessions/{owner_session_id}/revoke",
            headers=self.auth(member),
            json={},
        )
        missing = self.client.post(
            "/v1/sessions/device_missing_12345678/revoke",
            headers=self.auth(member),
            json={},
        )
        oversized = self.client.post(
            f"/v1/sessions/{'s' * 241}/revoke",
            headers=self.auth(member),
            json={},
        )
        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(oversized.status_code, 404)
        invalid_cursor = self.client.get(
            "/v1/sessions",
            headers=self.auth(owner),
            params={"cursor": "99999999999999999999:device_valid_12345678"},
        )
        self.assertEqual(invalid_cursor.status_code, 422)

        revoked = self.client.post(
            f"/v1/sessions/{owner_session_id}/revoke",
            headers=self.auth(owner),
            json={},
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(
            self.client.get("/v1/session", headers=self.auth(owner)).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/v1/sessions/refresh",
                json={"refresh_token": owner["refresh_token"]},
            ).status_code,
            401,
        )
        connection = self.app.state.store.connect()
        try:
            session = connection.execute(
                "SELECT revoked_at FROM device_sessions WHERE id=?",
                (owner_session_id,),
            ).fetchone()
            active_refreshes = connection.execute(
                "SELECT count(*) FROM refresh_tokens WHERE device_session_id=? "
                "AND consumed_at IS NULL AND revoked_at IS NULL",
                (owner_session_id,),
            ).fetchone()[0]
            self.assertIsNotNone(session["revoked_at"])
            self.assertEqual(active_refreshes, 0)
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM audit_events WHERE action='session.device_revoke' "
                    "AND resource_id=?",
                    (owner_session_id,),
                ).fetchone()[0],
                1,
            )
        finally:
            connection.close()

    def test_human_admin_pages_use_keyset_order_indexes(self) -> None:
        owner = self.bootstrap()
        team_id = owner["teams"][0]["id"]
        timestamp = int(time.time())
        maximal_cursor = self.app.state.store._encode_human_admin_page_cursor(
            resource_kind="membership",
            scope_id="s" * 240,
            viewer_id="v" * 240,
            visibility="manageable",
            highwater=9_223_372_036_854_775_807,
            timestamp=9_223_372_036_854_775_807,
            resource_id="i" * 240,
        )
        self.assertLessEqual(len(maximal_cursor), 512)
        self.assertEqual(
            self.app.state.store._human_admin_page_cursor(
                maximal_cursor,
                resource_kind="membership",
                scope_id="s" * 240,
                viewer_id="v" * 240,
                visibility="manageable",
            ),
            (
                9_223_372_036_854_775_807,
                9_223_372_036_854_775_807,
                "i" * 240,
            ),
        )
        connection = self.app.state.store.connect()
        try:
            device_plan = " ".join(
                str(row["detail"])
                for row in connection.execute(
                    """
                    EXPLAIN QUERY PLAN
                    SELECT s.id,s.device_label,s.created_at,s.last_seen_at,
                           s.expires_at,s.revoked_at
                    FROM device_sessions AS s
                    JOIN human_admin_page_entries AS page
                      ON page.resource_kind='device_session'
                     AND page.resource_id=s.id
                    WHERE s.human_principal_id=? AND page.sequence<=?
                      AND (s.created_at<? OR (s.created_at=? AND s.id<?))
                    ORDER BY s.created_at DESC,s.id DESC LIMIT ?
                    """,
                    (
                        owner["principal"]["id"],
                        9_223_372_036_854_775_807,
                        timestamp,
                        timestamp,
                        "device_cursor_12345678",
                        51,
                    ),
                )
            )
            invitation_plan = " ".join(
                str(row["detail"])
                for row in connection.execute(
                    """
                    EXPLAIN QUERY PLAN
                    SELECT i.id,i.invitee_email_normalized,i.role,
                           i.issued_by_principal_id,i.created_at,i.expires_at
                    FROM invitations AS i
                    JOIN human_admin_page_entries AS page
                      ON page.resource_kind='invitation'
                     AND page.resource_id=i.id
                    WHERE i.team_id=? AND i.redeemed_at IS NULL
                      AND i.revoked_at IS NULL AND i.expires_at>?
                      AND i.created_at>? AND page.sequence<=?
                      AND (i.created_at<? OR (i.created_at=? AND i.id<?))
                    ORDER BY i.created_at DESC,i.id DESC LIMIT ?
                    """,
                    (
                        team_id,
                        timestamp,
                        timestamp - 86_400,
                        9_223_372_036_854_775_807,
                        timestamp,
                        timestamp,
                        "invite_cursor_12345678",
                        51,
                    ),
                )
            )
            member_plan = " ".join(
                str(row["detail"])
                for row in connection.execute(
                    """
                    EXPLAIN QUERY PLAN
                    SELECT m.principal_id,h.email_normalized,p.display_name,
                           m.role,m.status,m.created_at
                    FROM memberships AS m
                    JOIN human_admin_page_entries AS page
                      ON page.resource_kind='membership'
                     AND page.resource_id=m.id
                    JOIN principals AS p ON p.id=m.principal_id
                    LEFT JOIN human_accounts AS h ON h.principal_id=m.principal_id
                    WHERE m.team_id=? AND page.sequence<=?
                      AND m.status IN ('active','suspended')
                      AND p.status='active' AND p.kind='human'
                      AND (m.created_at<? OR (m.created_at=? AND m.principal_id<?))
                    ORDER BY m.created_at DESC,m.principal_id DESC LIMIT ?
                    """,
                    (
                        team_id,
                        9_223_372_036_854_775_807,
                        timestamp,
                        timestamp,
                        "principal_cursor_12345678",
                        51,
                    ),
                )
            )
            ordinary_member_plan = " ".join(
                str(row["detail"])
                for row in connection.execute(
                    """
                    EXPLAIN QUERY PLAN
                    SELECT m.principal_id,p.display_name,m.role,m.status,m.created_at
                    FROM memberships AS m
                    JOIN human_admin_page_entries AS page
                      ON page.resource_kind='membership'
                     AND page.resource_id=m.id
                    JOIN principals AS p ON p.id=m.principal_id
                    WHERE m.team_id=? AND page.sequence<=? AND m.status='active'
                      AND p.status='active' AND p.kind='human'
                      AND (m.created_at<? OR (m.created_at=? AND m.principal_id<?))
                    ORDER BY m.created_at DESC,m.principal_id DESC LIMIT ?
                    """,
                    (
                        team_id,
                        9_223_372_036_854_775_807,
                        timestamp,
                        timestamp,
                        "principal_cursor_12345678",
                        51,
                    ),
                )
            )
            highwater_plan = " ".join(
                str(row["detail"])
                for row in connection.execute(
                    "EXPLAIN QUERY PLAN SELECT COALESCE(MAX(sequence),0) "
                    "FROM human_admin_page_entries"
                )
            )
        finally:
            connection.close()

        self.assertIn("device_sessions_human_created_id_idx", device_plan)
        self.assertIn("invitations_pending_team_created_id_idx", invitation_plan)
        self.assertIn("memberships_manageable_team_created_principal_idx", member_plan)
        self.assertIn(
            "memberships_active_team_created_principal_idx", ordinary_member_plan
        )
        self.assertNotIn("USE TEMP B-TREE", device_plan)
        self.assertNotIn("USE TEMP B-TREE", invitation_plan)
        self.assertNotIn("USE TEMP B-TREE", member_plan)
        self.assertNotIn("USE TEMP B-TREE", ordinary_member_plan)
        self.assertIn("SEARCH human_admin_page_entries", highwater_plan)
        self.assertNotIn("SCAN human_admin_page_entries", highwater_plan)

    def test_local_owner_recovery_restores_same_principal_after_logout(self) -> None:
        owner = self.bootstrap()
        revoked = self.client.post(
            "/v1/sessions/revoke",
            headers=self.auth(owner),
            json={"refresh_token": owner["refresh_token"]},
        )
        self.assertEqual(revoked.status_code, 200)
        proof_path = self.app.state.store.issue_owner_recovery(
            "owner@example.com", "Recovered Mac"
        )
        recovery = self.client.post(
            "/v1/owner-recovery/redeem",
            headers={"X-Team-Hub-Owner-Recovery-Proof": proof_path.read_text().strip()},
            json={"device_label": "Recovered Mac"},
        )
        self.assertEqual(recovery.status_code, 200, recovery.text)
        recovered = recovery.json()
        self.assertEqual(recovered["principal"]["id"], owner["principal"]["id"])
        self.assertEqual(recovered["teams"], owner["teams"])
        replay = self.client.post(
            "/v1/owner-recovery/redeem",
            headers={"X-Team-Hub-Owner-Recovery-Proof": "owner-recovery.invalid-invalid"},
            json={"device_label": "Recovered Mac"},
        )
        self.assertEqual(replay.status_code, 403)

    def test_member_device_recovery_allows_loopback_or_direct_https_only(self) -> None:
        owner = self.bootstrap()
        member = self.invite_and_redeem(owner, "member@example.com", "member")
        self.assertEqual(
            self.client.get("/v1/session", headers=self.auth(member)).status_code,
            200,
        )
        proof_path = self.app.state.store.issue_device_recovery(
            "member@example.com", "Replacement Mac"
        )
        proof = proof_path.read_text().strip()
        # Issuance is the host operator's lost-device action. It invalidates
        # existing access and refresh authority before the proof is delivered.
        self.assertEqual(
            self.client.get("/v1/session", headers=self.auth(member)).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/v1/sessions/refresh",
                json={"refresh_token": member["refresh_token"]},
            ).status_code,
            401,
        )
        remote_http = TestClient(
            self.app, base_url="http://testserver", client=("192.0.2.9", 41000)
        )
        forwarded = remote_http.post(
            "/v1/device-recovery/redeem",
            headers={
                "X-Team-Hub-Device-Recovery-Proof": proof,
                "X-Forwarded-Proto": "https",
            },
            json={"device_label": "Replacement Mac"},
        )
        self.assertEqual(forwarded.status_code, 403)
        wrong_label = self.client.post(
            "/v1/device-recovery/redeem",
            headers={"X-Team-Hub-Device-Recovery-Proof": proof},
            json={"device_label": "Wrong Mac"},
        )
        self.assertEqual(wrong_label.status_code, 403)
        remote_https = TestClient(
            self.app, base_url="https://testserver", client=("192.0.2.9", 41000)
        )
        recovered = remote_https.post(
            "/v1/device-recovery/redeem",
            headers={"X-Team-Hub-Device-Recovery-Proof": proof},
            json={"device_label": "Replacement Mac"},
        )
        self.assertEqual(recovered.status_code, 200, recovered.text)
        replacement = recovered.json()
        self.assertEqual(replacement["principal"]["id"], member["principal"]["id"])
        self.assertEqual(replacement["teams"], member["teams"])
        self.assertEqual(
            self.client.get("/v1/session", headers=self.auth(member)).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                "/v1/sessions/refresh",
                json={"refresh_token": member["refresh_token"]},
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.get("/v1/session", headers=self.auth(replacement)).status_code,
            200,
        )
        replay = remote_https.post(
            "/v1/device-recovery/redeem",
            headers={"X-Team-Hub-Device-Recovery-Proof": proof},
            json={"device_label": "Replacement Mac"},
        )
        self.assertEqual(replay.status_code, 403)

        connection = self.app.state.store.connect()
        try:
            events = connection.execute(
                """
                SELECT actor_principal_id, action, metadata_json
                FROM audit_events
                WHERE action IN ('device_recovery.issue', 'device_recovery.redeem')
                ORDER BY created_at, id
                """
            ).fetchall()
            self.assertEqual(len(events), 2)
            self.assertTrue(
                all(row["actor_principal_id"] == "service_local_control" for row in events)
            )
            self.assertTrue(
                all(
                    member["principal"]["id"] in row["metadata_json"]
                    for row in events
                )
            )
            issue_event = next(row for row in events if row["action"] == "device_recovery.issue")
            issue_metadata = json.loads(issue_event["metadata_json"])
            self.assertEqual(issue_metadata["revoked_session_count"], 1)
            self.assertEqual(
                connection.execute(
                    """
                    SELECT count(*) FROM device_sessions
                    WHERE human_principal_id = ? AND revoked_at IS NULL
                    """,
                    (member["principal"]["id"],),
                ).fetchone()[0],
                1,
            )
        finally:
            connection.close()

    def test_device_recovery_issue_failure_rolls_back_revocation(self) -> None:
        owner = self.bootstrap()
        member = self.invite_and_redeem(owner, "member@example.com", "member")
        store = self.app.state.store
        proof_files_before = set(self.data_dir.glob("owner_recovery_*.proof"))

        with mock.patch.object(store, "_audit", side_effect=OSError("audit unavailable")):
            with self.assertRaisesRegex(OSError, "audit unavailable"):
                store.issue_device_recovery("member@example.com", "Replacement Mac")

        self.assertEqual(
            self.client.get("/v1/session", headers=self.auth(member)).status_code,
            200,
        )
        refreshed = self.client.post(
            "/v1/sessions/refresh",
            json={"refresh_token": member["refresh_token"]},
        )
        self.assertEqual(refreshed.status_code, 200, refreshed.text)
        self.assertEqual(
            set(self.data_dir.glob("owner_recovery_*.proof")),
            proof_files_before,
        )

    def test_device_recovery_expiry_suspension_and_concurrent_consumption(self) -> None:
        owner = self.bootstrap()
        member = self.invite_and_redeem(owner, "member@example.com", "member")
        store = self.app.state.store
        proof_path = store.issue_device_recovery("member@example.com", "Concurrent Mac")
        proof = proof_path.read_text().strip()

        def redeem(_: int) -> str:
            try:
                store.redeem_device_recovery(proof, "Concurrent Mac")
                return "accepted"
            except HubError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sorted(executor.map(redeem, range(2))), ["accepted", "rejected"])

        expired_path = store.issue_device_recovery("member@example.com", "Expired Mac")
        expired = expired_path.read_text().strip()
        with mock.patch(
            "agentsdock_team_hub.store._now", return_value=int(time.time()) + 601
        ):
            with self.assertRaises(HubError):
                store.redeem_device_recovery(expired, "Expired Mac")

        connection = store.connect()
        try:
            connection.execute(
                """
                UPDATE memberships SET status = 'suspended', updated_at = updated_at + 1
                WHERE principal_id = ?
                """,
                (member["principal"]["id"],),
            )
        finally:
            connection.close()
        with self.assertRaises(HubError):
            store.issue_device_recovery("member@example.com", "Suspended Mac")

    def test_node_enrollment_requires_bound_key_pop_and_is_one_time(self) -> None:
        owner = self.bootstrap()
        team_id = owner["teams"][0]["id"]
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        ).decode("ascii")
        wrong_key = Ed25519PrivateKey.generate()
        wrong_public = wrong_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        ).decode("ascii")
        issued = self.client.post(
            f"/v1/teams/{team_id}/node-enrollments",
            headers=self.auth(owner),
            json={
                "server_identity": "server:1234567890abcdef",
                "display_name": "Primary node",
                "public_key": public_key,
            },
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        token = issued.json()["token"]
        wrong = self.client.post(
            "/v1/node-enrollments/challenge",
            json={
                "token": token,
                "server_identity": "server:1234567890abcdef",
                "display_name": "Primary node",
                "public_key": wrong_public,
            },
        )
        self.assertEqual(wrong.status_code, 403)
        challenge = self.client.post(
            "/v1/node-enrollments/challenge",
            json={
                "token": token,
                "server_identity": "server:1234567890abcdef",
                "display_name": "Primary node",
                "public_key": public_key,
            },
        ).json()
        bad_signature = base64.b64encode(wrong_key.sign(challenge["signing_payload"].encode())).decode()
        denied = self.client.post(
            "/v1/node-enrollments/redeem",
            json={"challenge_id": challenge["challenge_id"], "signature": bad_signature},
        )
        self.assertEqual(denied.status_code, 403)
        signature = base64.b64encode(
            private_key.sign(challenge["signing_payload"].encode())
        ).decode()
        enrolled = self.client.post(
            "/v1/node-enrollments/redeem",
            json={"challenge_id": challenge["challenge_id"], "signature": signature},
        )
        self.assertEqual(enrolled.status_code, 200, enrolled.text)
        replay = self.client.post(
            "/v1/node-enrollments/redeem",
            json={"challenge_id": challenge["challenge_id"], "signature": signature},
        )
        self.assertEqual(replay.status_code, 403)

    def test_channel_acl_direct_privacy_passive_messages_and_idempotency(self) -> None:
        owner = self.bootstrap()
        member = self.invite_and_redeem(owner, "member@example.com", "member")
        admin = self.invite_and_redeem(owner, "admin@example.com", "admin")
        guest = self.invite_and_redeem(owner, "guest@example.com", "guest")
        team_id = owner["teams"][0]["id"]
        board_request = {
            "kind": "board",
            "visibility": "team",
            "slug": "general",
            "display_name": "General",
            "participant_principal_ids": [],
            "idempotency_key": "channel-general-1",
        }
        board = self.client.post(
            f"/v1/teams/{team_id}/channels", headers=self.auth(owner), json=board_request
        )
        self.assertEqual(board.status_code, 200, board.text)
        repeated = self.client.post(
            f"/v1/teams/{team_id}/channels", headers=self.auth(owner), json=board_request
        )
        self.assertEqual(repeated.json(), board.json())
        conflict_request = {**board_request, "display_name": "Changed"}
        conflict = self.client.post(
            f"/v1/teams/{team_id}/channels",
            headers=self.auth(owner),
            json=conflict_request,
        )
        self.assertEqual(conflict.status_code, 409)
        guest_channels = self.client.get(
            f"/v1/teams/{team_id}/channels", headers=self.auth(guest)
        ).json()["channels"]
        self.assertFalse(guest_channels[0]["permissions"]["post"])
        board_id = board.json()["channel"]["id"]
        guest_post = self.client.post(
            f"/v1/channels/{board_id}/messages",
            headers=self.auth(guest),
            json={"body": "blocked", "idempotency_key": "guest-message-1"},
        )
        self.assertEqual(guest_post.status_code, 404)
        direct = self.client.post(
            f"/v1/teams/{team_id}/channels",
            headers=self.auth(owner),
            json={
                "kind": "direct",
                "visibility": "private",
                "participant_principal_ids": [
                    owner["principal"]["id"],
                    member["principal"]["id"],
                ],
                "idempotency_key": "direct-owner-member",
            },
        )
        self.assertEqual(direct.status_code, 200, direct.text)
        direct_id = direct.json()["channel"]["id"]
        hidden = self.client.get(
            f"/v1/channels/{direct_id}/messages", headers=self.auth(admin)
        )
        self.assertEqual(hidden.status_code, 404)
        message_request = {"body": "Passive only", "idempotency_key": "message-passive-1"}
        message = self.client.post(
            f"/v1/channels/{direct_id}/messages",
            headers=self.auth(owner),
            json=message_request,
        )
        self.assertEqual(message.status_code, 200, message.text)
        same = self.client.post(
            f"/v1/channels/{direct_id}/messages",
            headers=self.auth(owner),
            json=message_request,
        )
        self.assertEqual(same.json(), message.json())
        changed = self.client.post(
            f"/v1/channels/{direct_id}/messages",
            headers=self.auth(owner),
            json={**message_request, "body": "Different"},
        )
        self.assertEqual(changed.status_code, 409)
        dispatch = self.client.post("/v1/dispatches", headers=self.auth(owner), json={})
        self.assertEqual(dispatch.status_code, 501)
        connection = self.app.state.store.connect()
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM dispatch_requests").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM messages").fetchone()[0], 1)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
