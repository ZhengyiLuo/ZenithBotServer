"""Durable local admission ledger for secure-peer chat deliveries.

The authoritative exchange and six-leg counter live on the designated Hub.
This ledger bridges that remote transaction to one local durable chat turn.  A
delivery is never acknowledged remotely until its exact target route has been
resolved to a private local chat and this intent has been fsynced.  If the
process dies between the remote CAS and local queue admission, startup resumes
the saved intent instead of re-running or losing it.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from typing import Any, Iterator, Mapping

from agentsdock_team_hub.security import canonical_json, ensure_private_directory


DELIVERY_STATES = frozenset({
    "prepared",
    "authorized",
    "queued",
    "running",
    "completed",
    "failed",
})
TERMINAL_DELIVERY_STATES = frozenset({"completed", "failed"})
MAX_NONTERMINAL_DELIVERIES = 2_048


class SecurePeerDeliveryLedger:
    """Owner-private, crash-safe mapping from a relay envelope to one turn."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        ensure_private_directory(self.path.parent)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self.path.is_symlink():
            raise PermissionError("secure peer delivery ledger must not be a symlink")
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        os.chmod(self.path, 0o600)
        info = os.stat(self.path, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            connection.close()
            raise PermissionError("secure peer delivery ledger is unsafe")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()

    def _initialize(self) -> None:
        with self._lock:
            connection = self._connect()
            try:
                connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS secure_peer_deliveries (
                    envelope_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    claim_digest TEXT NOT NULL,
                    transport_role TEXT NOT NULL CHECK(transport_role IN ('host','client')),
                    connection_id TEXT NOT NULL,
                    lease_token TEXT NOT NULL,
                    team_id TEXT NOT NULL,
                    source_peer_id TEXT,
                    source_server_identity TEXT NOT NULL,
                    source_route_id TEXT NOT NULL,
                    source_route_revision TEXT NOT NULL,
                    target_peer_id TEXT,
                    target_server_identity TEXT NOT NULL,
                    target_route_id TEXT NOT NULL,
                    target_route_revision TEXT NOT NULL,
                    target_chat_id TEXT NOT NULL,
                    action TEXT NOT NULL CHECK(action IN ('instruction','request_reply')),
                    kind TEXT NOT NULL CHECK(kind IN ('instruction','request_reply','response')),
                    exchange_id TEXT NOT NULL,
                    parent_envelope_id TEXT,
                    parent_leg INTEGER,
                    used_legs INTEGER NOT NULL CHECK(used_legs BETWEEN 1 AND 6),
                    max_legs INTEGER NOT NULL CHECK(max_legs=6),
                    expires_at INTEGER NOT NULL,
                    body_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'prepared','authorized','queued','running','completed','failed'
                    )),
                    queued_id TEXT,
                    run_id TEXT,
                    admission_retry_at INTEGER,
                    admission_attempts INTEGER NOT NULL DEFAULT 0,
                    admission_last_error TEXT,
                    response_committed INTEGER NOT NULL DEFAULT 0
                        CHECK(response_committed IN (0,1)),
                    response_request_id TEXT,
                    response_request_digest TEXT,
                    response_body TEXT,
                    response_request_response INTEGER CHECK(
                        response_request_response IS NULL
                        OR response_request_response IN (0,1)
                    ),
                    response_retry_at INTEGER,
                    response_attempts INTEGER NOT NULL DEFAULT 0,
                    response_last_error TEXT,
                    result_hash TEXT,
                    error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS secure_peer_delivery_state
                    ON secure_peer_deliveries(state,updated_at);
                CREATE INDEX IF NOT EXISTS secure_peer_delivery_run
                    ON secure_peer_deliveries(run_id,state);
                CREATE UNIQUE INDEX IF NOT EXISTS secure_peer_delivery_queued_owner
                    ON secure_peer_deliveries(queued_id) WHERE queued_id IS NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS secure_peer_delivery_run_owner
                    ON secure_peer_deliveries(run_id) WHERE run_id IS NOT NULL;
                CREATE TABLE IF NOT EXISTS secure_peer_outbound_intents (
                    request_id TEXT PRIMARY KEY,
                    intent_digest TEXT NOT NULL,
                    source_session_id TEXT NOT NULL,
                    source_run_id TEXT NOT NULL,
                    connection_id TEXT NOT NULL,
                    source_route_id TEXT NOT NULL,
                    source_route_revision TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    body TEXT NOT NULL,
                    action TEXT NOT NULL CHECK(action IN ('instruction','request_reply')),
                    expires_at INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','committed','failed')),
                    response_json TEXT,
                    retry_at INTEGER,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS secure_peer_outbound_pending
                    ON secure_peer_outbound_intents(state,retry_at,created_at);
                """
                )
                # Development snapshots created before the full immutable
                # claim landed are upgraded additively. No released build has
                # written these rows, but keeping the migration safe avoids a
                # local optional-feature boot failure while iterating.
                columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(secure_peer_deliveries)"
                    ).fetchall()
                }
                for name, declaration in (
                    ("request_id", "TEXT"),
                    ("lease_token", "TEXT"),
                    ("team_id", "TEXT"),
                    ("source_peer_id", "TEXT"),
                    ("target_peer_id", "TEXT"),
                    ("parent_leg", "INTEGER"),
                    ("response_request_id", "TEXT"),
                    ("response_request_digest", "TEXT"),
                    ("response_body", "TEXT"),
                    ("response_request_response", "INTEGER"),
                    ("response_retry_at", "INTEGER"),
                    ("response_attempts", "INTEGER NOT NULL DEFAULT 0"),
                    ("response_last_error", "TEXT"),
                    ("admission_retry_at", "INTEGER"),
                    ("admission_attempts", "INTEGER NOT NULL DEFAULT 0"),
                    ("admission_last_error", "TEXT"),
                ):
                    if name not in columns:
                        connection.execute(
                            f"ALTER TABLE secure_peer_deliveries ADD COLUMN {name} {declaration}"
                        )
                outbound_columns = {
                    str(row["name"])
                    for row in connection.execute(
                        "PRAGMA table_info(secure_peer_outbound_intents)"
                    ).fetchall()
                }
                for name in (
                    "connection_id",
                    "source_route_id",
                    "source_route_revision",
                ):
                    if name not in outbound_columns:
                        connection.execute(
                            f"ALTER TABLE secure_peer_outbound_intents ADD COLUMN {name} TEXT"
                        )
                # Unreleased development ledgers predate the indexed route
                # projection. Recover it only from the already-digested
                # immutable snapshot; malformed rows fail closed.
                legacy_rows = connection.execute(
                    """SELECT request_id,snapshot_json FROM secure_peer_outbound_intents
                    WHERE connection_id IS NULL OR source_route_id IS NULL
                    OR source_route_revision IS NULL"""
                ).fetchall()
                for row in legacy_rows:
                    try:
                        snapshot = json.loads(row["snapshot_json"])
                        connection_id = str(snapshot.get("connection_id") or "")
                        source_route_id = str(snapshot.get("source_route_id") or "")
                        source_route_revision = str(
                            snapshot.get("source_route_revision") or ""
                        )
                        if not all(
                            (connection_id, source_route_id, source_route_revision)
                        ):
                            raise ValueError("missing outbound route identity")
                    except Exception:
                        connection.execute(
                            """UPDATE secure_peer_outbound_intents SET
                            state='failed',retry_at=NULL,
                            last_error='invalid legacy secure peer route snapshot',
                            connection_id='',source_route_id='',source_route_revision=''
                            WHERE request_id=?""",
                            (row["request_id"],),
                        )
                    else:
                        connection.execute(
                            """UPDATE secure_peer_outbound_intents SET
                            connection_id=?,source_route_id=?,source_route_revision=?
                            WHERE request_id=?""",
                            (
                                connection_id,
                                source_route_id,
                                source_route_revision,
                                row["request_id"],
                            ),
                        )
                connection.execute(
                    """CREATE INDEX IF NOT EXISTS secure_peer_outbound_source
                    ON secure_peer_outbound_intents(state,source_session_id,created_at)"""
                )
                connection.execute(
                    """CREATE INDEX IF NOT EXISTS secure_peer_outbound_connection
                    ON secure_peer_outbound_intents(state,connection_id,created_at)"""
                )
            finally:
                connection.close()

    @staticmethod
    def _public(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        item["body"] = json.loads(item.pop("body_json"))
        return item

    @staticmethod
    def _claim(
        envelope: Mapping[str, Any],
        *,
        transport_role: str,
        connection_id: str,
        lease_token: str,
        target_chat_id: str,
    ) -> tuple[dict[str, Any], str]:
        if transport_role not in {"host", "client"}:
            raise ValueError("secure peer delivery role is invalid")
        action = str(envelope.get("action") or "")
        kind = str(envelope.get("kind") or "")
        if action not in {"instruction", "request_reply"}:
            raise ValueError("secure peer delivery action is invalid")
        if kind not in {"instruction", "request_reply", "response"}:
            raise ValueError("secure peer delivery kind is invalid")
        body = envelope.get("body")
        if (
            not isinstance(body, dict)
            or set(body) != {"message"}
            or not isinstance(body.get("message"), str)
            or not body["message"].strip()
            or len(body["message"]) > 100_000
        ):
            raise ValueError("secure peer delivery body is invalid")
        exact = {
            "envelope_id": str(envelope.get("envelope_id") or ""),
            "request_id": str(envelope.get("request_id") or ""),
            "transport_role": transport_role,
            "connection_id": str(connection_id),
            "lease_token": str(lease_token),
            "team_id": str(envelope.get("team_id") or ""),
            "source_peer_id": (
                str(envelope.get("source_peer_id"))
                if envelope.get("source_peer_id") is not None
                else None
            ),
            "source_server_identity": str(envelope.get("source_server_identity") or ""),
            "source_route_id": str(envelope.get("source_route_id") or ""),
            "source_route_revision": str(envelope.get("source_route_revision") or ""),
            "target_peer_id": (
                str(envelope.get("target_peer_id"))
                if envelope.get("target_peer_id") is not None
                else None
            ),
            "target_server_identity": str(envelope.get("target_server_identity") or ""),
            "target_route_id": str(envelope.get("target_route_id") or ""),
            "target_route_revision": str(envelope.get("target_route_revision") or ""),
            "target_chat_id": str(target_chat_id),
            "action": action,
            "kind": kind,
            "exchange_id": str(envelope.get("exchange_id") or ""),
            "parent_envelope_id": (
                str(envelope.get("parent_envelope_id"))
                if envelope.get("parent_envelope_id") is not None
                else None
            ),
            "parent_leg": (
                int(envelope.get("parent_leg"))
                if envelope.get("parent_leg") is not None
                else None
            ),
            "used_legs": int(envelope.get("used_legs") or 0),
            "max_legs": int(envelope.get("max_legs") or 0),
            "expires_at": int(envelope.get("expires_at") or 0),
            "body": body,
        }
        required = (
            "envelope_id",
            "request_id",
            "connection_id",
            "lease_token",
            "team_id",
            "source_server_identity",
            "source_route_id",
            "source_route_revision",
            "target_server_identity",
            "target_route_id",
            "target_route_revision",
            "target_chat_id",
            "exchange_id",
        )
        if any(not exact[key] for key in required):
            raise ValueError("secure peer delivery identity is incomplete")
        if exact["max_legs"] != 6 or not 1 <= exact["used_legs"] <= 6:
            raise ValueError("secure peer delivery leg budget is invalid")
        # The lease token belongs to a delivery *claim*, not the immutable
        # envelope. A crash past the lease deadline legitimately redelivers
        # the same envelope with a new token.
        immutable = {
            key: value for key, value in exact.items() if key != "lease_token"
        }
        digest = hashlib.sha256(canonical_json(immutable)).hexdigest()
        return exact, digest

    def prepare(
        self,
        envelope: Mapping[str, Any],
        *,
        transport_role: str,
        connection_id: str,
        lease_token: str,
        target_chat_id: str,
    ) -> tuple[dict[str, Any], bool]:
        exact, digest = self._claim(
            envelope,
            transport_role=transport_role,
            connection_id=connection_id,
            lease_token=lease_token,
            target_chat_id=target_chat_id,
        )
        timestamp = int(time.time())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (exact["envelope_id"],),
            ).fetchone()
            if row is not None:
                if row["claim_digest"] != digest:
                    raise RuntimeError("secure peer envelope identity changed")
                if (
                    str(row["state"]) == "prepared"
                    and str(row["lease_token"] or "") != exact["lease_token"]
                ):
                    connection.execute(
                        """UPDATE secure_peer_deliveries
                        SET lease_token=?,updated_at=?
                        WHERE envelope_id=? AND state='prepared' AND claim_digest=?""",
                        (
                            exact["lease_token"],
                            timestamp,
                            exact["envelope_id"],
                            digest,
                        ),
                    )
                    row = connection.execute(
                        "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                        (exact["envelope_id"],),
                    ).fetchone()
                public = self._public(row)
                assert public is not None
                return public, False
            connection.execute(
                """UPDATE secure_peer_deliveries SET state='failed',
                error='secure peer exchange expired',updated_at=?
                WHERE state='prepared' AND expires_at<=?""",
                (timestamp, timestamp),
            )
            nonterminal_count = int(
                connection.execute(
                    """SELECT COUNT(*) AS count FROM secure_peer_deliveries
                    WHERE state IN ('prepared','authorized','queued','running')"""
                ).fetchone()["count"]
            )
            if nonterminal_count >= MAX_NONTERMINAL_DELIVERIES:
                raise RuntimeError("secure peer delivery capacity is full")
            connection.execute(
                """INSERT INTO secure_peer_deliveries(
                envelope_id,request_id,claim_digest,transport_role,connection_id,lease_token,
                team_id,source_peer_id,
                source_server_identity,source_route_id,source_route_revision,
                target_peer_id,
                target_server_identity,target_route_id,target_route_revision,
                target_chat_id,action,kind,exchange_id,parent_envelope_id,parent_leg,
                used_legs,max_legs,expires_at,body_json,state,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'prepared',?,?)""",
                (
                    exact["envelope_id"],
                    exact["request_id"],
                    digest,
                    exact["transport_role"],
                    exact["connection_id"],
                    exact["lease_token"],
                    exact["team_id"],
                    exact["source_peer_id"],
                    exact["source_server_identity"],
                    exact["source_route_id"],
                    exact["source_route_revision"],
                    exact["target_peer_id"],
                    exact["target_server_identity"],
                    exact["target_route_id"],
                    exact["target_route_revision"],
                    exact["target_chat_id"],
                    exact["action"],
                    exact["kind"],
                    exact["exchange_id"],
                    exact["parent_envelope_id"],
                    exact["parent_leg"],
                    exact["used_legs"],
                    exact["max_legs"],
                    exact["expires_at"],
                    canonical_json(exact["body"]).decode("utf-8"),
                    timestamp,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (exact["envelope_id"],),
            ).fetchone()
            public = self._public(row)
            assert public is not None
            return public, True

    def get(self, envelope_id: str) -> dict[str, Any] | None:
        with self._lock:
            connection = self._connect()
            try:
                return self._public(connection.execute(
                    "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                    (envelope_id,),
                ).fetchone())
            finally:
                connection.close()

    def _transition(
        self,
        envelope_id: str,
        *,
        expected: set[str],
        state: str,
        **values: Any,
    ) -> dict[str, Any] | None:
        if state not in DELIVERY_STATES:
            raise ValueError("secure peer delivery state is invalid")
        allowed = {"queued_id", "run_id", "result_hash", "error"}
        patch = {key: value for key, value in values.items() if key in allowed}
        patch.update({"state": state, "updated_at": int(time.time())})
        assignments = ",".join(f"{key}=?" for key in patch)
        placeholders = ",".join("?" for _ in expected)
        arguments = [*patch.values(), envelope_id, *sorted(expected)]
        with self._transaction() as connection:
            changed = connection.execute(
                f"UPDATE secure_peer_deliveries SET {assignments} "
                f"WHERE envelope_id=? AND state IN ({placeholders})",
                arguments,
            ).rowcount
            if changed != 1:
                return None
            return self._public(connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone())

    def authorize(self, envelope_id: str) -> dict[str, Any] | None:
        return self._transition(
            envelope_id,
            expected={"prepared", "authorized"},
            state="authorized",
        )

    def fail_ownerless_authorized(
        self,
        envelope_id: str,
        *,
        error: str,
    ) -> dict[str, Any] | None:
        """Fail only a receipt-accepted delivery that has no queued/run owner."""

        timestamp = int(time.time())
        with self._transaction() as connection:
            connection.execute(
                """UPDATE secure_peer_deliveries SET
                state='failed',error=?,admission_retry_at=NULL,
                admission_last_error=NULL,updated_at=?
                WHERE envelope_id=? AND state='authorized'
                AND queued_id IS NULL AND run_id IS NULL""",
                (str(error)[:400], timestamp, envelope_id),
            )
            return self._public(connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone())

    def bind_owner(
        self,
        envelope_id: str,
        *,
        queued_id: str | None,
        run_id: str | None,
    ) -> dict[str, Any] | None:
        if queued_id is None and run_id is None:
            raise ValueError("secure peer delivery owner is empty")
        timestamp = int(time.time())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone()
            if row is None:
                return None
            state = str(row["state"])
            current_queued = row["queued_id"]
            current_run = row["run_id"]
            if state == "authorized":
                next_state = "running" if run_id is not None else "queued"
                connection.execute(
                    """UPDATE secure_peer_deliveries
                    SET state=?,queued_id=?,run_id=?,admission_retry_at=NULL,
                    admission_last_error=NULL,updated_at=?
                    WHERE envelope_id=? AND state='authorized'
                    AND queued_id IS NULL AND run_id IS NULL""",
                    (next_state, queued_id, run_id, timestamp, envelope_id),
                )
            elif state == "queued" and run_id is not None:
                if current_queued != queued_id or current_run is not None:
                    return None
                connection.execute(
                    """UPDATE secure_peer_deliveries SET state='running',run_id=?,
                    admission_retry_at=NULL,admission_last_error=NULL,updated_at=?
                    WHERE envelope_id=? AND state='queued' AND queued_id=? AND run_id IS NULL""",
                    (run_id, timestamp, envelope_id, queued_id),
                )
            elif state == "queued":
                if current_queued != queued_id or current_run is not None:
                    return None
            elif state == "running":
                if current_queued != queued_id or current_run != run_id:
                    return None
            else:
                return None
            return self._public(connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone())

    def defer_admission(
        self,
        envelope_id: str,
        *,
        error: str,
    ) -> dict[str, Any] | None:
        now = int(time.time())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone()
            if (
                row is None
                or row["state"] != "authorized"
                or row["queued_id"] is not None
                or row["run_id"] is not None
            ):
                return self._public(row)
            attempts = int(row["admission_attempts"] or 0) + 1
            delay = min(300, 2 ** min(attempts, 8))
            connection.execute(
                """UPDATE secure_peer_deliveries SET
                admission_attempts=?,admission_retry_at=?,admission_last_error=?,updated_at=?
                WHERE envelope_id=? AND state='authorized'
                AND queued_id IS NULL AND run_id IS NULL""",
                (attempts, now + delay, str(error)[:400], now, envelope_id),
            )
            return self._public(connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone())

    def pending_admissions(
        self,
        *,
        limit: int = 20,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("secure peer admission retry limit is invalid")
        timestamp = int(time.time()) if now is None else int(now)
        with self._lock:
            connection = self._connect()
            try:
                rows = connection.execute(
                    """SELECT * FROM secure_peer_deliveries
                    WHERE state='authorized' AND queued_id IS NULL AND run_id IS NULL
                    AND COALESCE(admission_retry_at,0)<=?
                    ORDER BY COALESCE(admission_retry_at,0),created_at,envelope_id
                    LIMIT ?""",
                    (timestamp, limit),
                ).fetchall()
                return [self._public(row) for row in rows if row is not None]
            finally:
                connection.close()

    def nonterminal_for_chat(self, chat_id: str) -> list[dict[str, Any]]:
        with self._lock:
            connection = self._connect()
            try:
                rows = connection.execute(
                    """SELECT * FROM secure_peer_deliveries
                    WHERE target_chat_id=?
                    AND state IN ('prepared','authorized','queued','running')
                    ORDER BY created_at,envelope_id""",
                    (chat_id,),
                ).fetchall()
                return [self._public(row) for row in rows if row is not None]
            finally:
                connection.close()

    def finish(
        self,
        envelope_id: str,
        *,
        succeeded: bool,
        result_text: str = "",
        error: str | None = None,
    ) -> dict[str, Any] | None:
        return self._transition(
            envelope_id,
            expected=(
                {"authorized", "queued", "running"}
                if succeeded
                else {"prepared", "authorized", "queued", "running"}
            ),
            state="completed" if succeeded else "failed",
            result_hash=(
                hashlib.sha256(result_text.encode("utf-8")).hexdigest()
                if result_text
                else None
            ),
            error=error,
        )

    def prepare_response(
        self,
        envelope_id: str,
        *,
        request_id: str,
        body: str,
        request_response: bool,
    ) -> dict[str, Any] | None:
        if (
            not request_id
            or not isinstance(body, str)
            or not body.strip()
            or len(body) > 100_000
            or type(request_response) is not bool
        ):
            raise ValueError("secure peer response intent is invalid")
        intent = {
            "request_id": request_id,
            "body": body,
            "request_response": request_response,
        }
        digest = hashlib.sha256(canonical_json(intent)).hexdigest()
        timestamp = int(time.time())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone()
            if (
                row is None
                or row["state"] not in {"authorized", "queued", "running"}
                or row["kind"] == "instruction"
            ):
                return None
            existing = row["response_request_digest"]
            if existing is not None:
                if existing != digest:
                    raise RuntimeError("secure peer response intent changed")
                return self._public(row)
            connection.execute(
                """UPDATE secure_peer_deliveries SET
                response_request_id=?,response_request_digest=?,response_body=?,
                response_request_response=?,response_retry_at=?,
                response_attempts=0,response_last_error=NULL,updated_at=?
                WHERE envelope_id=? AND response_request_digest IS NULL
                AND response_committed=0
                AND state IN ('authorized','queued','running')""",
                (
                    request_id,
                    digest,
                    body,
                    int(request_response),
                    timestamp,
                    timestamp,
                    envelope_id,
                ),
            )
            return self._public(connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone())

    def mark_response_committed(
        self,
        envelope_id: str,
        *,
        request_id: str | None = None,
    ) -> dict[str, Any] | None:
        with self._transaction() as connection:
            changed = connection.execute(
                """UPDATE secure_peer_deliveries
                SET response_committed=1,response_retry_at=NULL,
                response_last_error=NULL,updated_at=?
                WHERE envelope_id=? AND state IN ('authorized','queued','running')
                AND response_committed=0
                AND (? IS NULL OR response_request_id=?)""",
                (int(time.time()), envelope_id, request_id, request_id),
            ).rowcount
            if changed not in {0, 1}:
                raise RuntimeError("secure peer response state is ambiguous")
            return self._public(connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone())

    def clear_response_intent(
        self,
        envelope_id: str,
        *,
        request_id: str,
    ) -> dict[str, Any] | None:
        with self._transaction() as connection:
            connection.execute(
                """UPDATE secure_peer_deliveries SET
                response_request_id=NULL,response_request_digest=NULL,
                response_body=NULL,response_request_response=NULL,
                response_retry_at=NULL,response_attempts=0,
                response_last_error=NULL,updated_at=?
                WHERE envelope_id=? AND response_request_id=?
                AND response_committed=0
                AND state IN ('authorized','queued','running')""",
                (int(time.time()), envelope_id, request_id),
            )
            return self._public(connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone())

    def defer_response(
        self,
        envelope_id: str,
        *,
        request_id: str,
        error: str,
    ) -> dict[str, Any] | None:
        """Persist bounded exponential retry state for one response intent."""

        now = int(time.time())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone()
            if (
                row is None
                or row["state"] not in {"authorized", "queued", "running"}
                or row["response_request_id"] != request_id
                or int(row["response_committed"] or 0) != 0
            ):
                return self._public(row)
            attempts = int(row["response_attempts"] or 0) + 1
            delay = min(300, 2 ** min(attempts, 8))
            connection.execute(
                """UPDATE secure_peer_deliveries SET
                response_attempts=?,response_retry_at=?,response_last_error=?,updated_at=?
                WHERE envelope_id=? AND response_request_id=?
                AND response_committed=0
                AND state IN ('authorized','queued','running')""",
                (
                    attempts,
                    now + delay,
                    str(error)[:400],
                    now,
                    envelope_id,
                    request_id,
                ),
            )
            return self._public(connection.execute(
                "SELECT * FROM secure_peer_deliveries WHERE envelope_id=?",
                (envelope_id,),
            ).fetchone())

    def pending_responses(
        self,
        *,
        limit: int = 8,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        if (
            type(limit) is not int
            or not 1 <= limit <= MAX_NONTERMINAL_DELIVERIES
        ):
            raise ValueError("secure peer response retry limit is invalid")
        timestamp = int(time.time()) if now is None else int(now)
        with self._lock:
            connection = self._connect()
            try:
                rows = connection.execute(
                    """SELECT * FROM secure_peer_deliveries
                    WHERE state IN ('authorized','queued','running')
                    AND response_request_id IS NOT NULL
                    AND response_committed=0
                    AND COALESCE(response_retry_at,0)<=?
                    ORDER BY COALESCE(response_retry_at,0),created_at,envelope_id
                    LIMIT ?""",
                    (timestamp, limit),
                ).fetchall()
                return [self._public(row) for row in rows if row is not None]
            finally:
                connection.close()

    def recoverable(self) -> list[dict[str, Any]]:
        with self._lock:
            connection = self._connect()
            try:
                rows = connection.execute(
                    """SELECT * FROM secure_peer_deliveries
                    WHERE state IN ('prepared','authorized','queued','running')
                    ORDER BY created_at,envelope_id"""
                ).fetchall()
                return [self._public(row) for row in rows if row is not None]
            finally:
                connection.close()

    def for_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            connection = self._connect()
            try:
                return self._public(connection.execute(
                    "SELECT * FROM secure_peer_deliveries WHERE run_id=?",
                    (run_id,),
                ).fetchone())
            finally:
                connection.close()

    @staticmethod
    def _public_outbound(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        item["snapshot"] = json.loads(item.pop("snapshot_json"))
        response = item.pop("response_json")
        item["response"] = json.loads(response) if response else None
        return item

    def prepare_outbound(
        self,
        *,
        request_id: str,
        source_session_id: str,
        source_run_id: str,
        snapshot: Mapping[str, Any],
        body: str,
        action: str,
        expires_at: int,
    ) -> tuple[dict[str, Any], bool]:
        connection_id = str(snapshot.get("connection_id") or "")
        source_route_id = str(snapshot.get("source_route_id") or "")
        source_route_revision = str(snapshot.get("source_route_revision") or "")
        if (
            not request_id
            or not source_session_id
            or not source_run_id
            or not connection_id
            or not source_route_id
            or not source_route_revision
            or str(snapshot.get("source_chat_id") or "") != source_session_id
            or str(snapshot.get("action") or "") != action
            or action not in {"instruction", "request_reply"}
            or not isinstance(body, str)
            or not body.strip()
            or len(body) > 100_000
            or not isinstance(snapshot, Mapping)
        ):
            raise ValueError("secure peer outbound intent is invalid")
        exact = {
            "request_id": request_id,
            "source_session_id": source_session_id,
            "source_run_id": source_run_id,
            "snapshot": dict(snapshot),
            "body": body,
            "action": action,
            "expires_at": int(expires_at),
        }
        digest = hashlib.sha256(canonical_json(exact)).hexdigest()
        now = int(time.time())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM secure_peer_outbound_intents WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is not None:
                if row["intent_digest"] != digest:
                    raise RuntimeError("secure peer outbound intent changed")
                public = self._public_outbound(row)
                assert public is not None
                return public, False
            connection.execute(
                """INSERT INTO secure_peer_outbound_intents(
                request_id,intent_digest,source_session_id,source_run_id,
                connection_id,source_route_id,source_route_revision,
                snapshot_json,body,action,expires_at,state,retry_at,
                created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,?)""",
                (
                    request_id,
                    digest,
                    source_session_id,
                    source_run_id,
                    connection_id,
                    source_route_id,
                    source_route_revision,
                    canonical_json(dict(snapshot)).decode("utf-8"),
                    body,
                    action,
                    int(expires_at),
                    now,
                    now,
                    now,
                ),
            )
            public = self._public_outbound(connection.execute(
                "SELECT * FROM secure_peer_outbound_intents WHERE request_id=?",
                (request_id,),
            ).fetchone())
            assert public is not None
            return public, True

    @staticmethod
    def _expire_pending_outbound(
        connection: sqlite3.Connection,
        timestamp: int,
    ) -> None:
        connection.execute(
            """UPDATE secure_peer_outbound_intents SET
            state='failed',retry_at=NULL,last_error='secure peer exchange expired',
            updated_at=? WHERE state='pending' AND expires_at<=?""",
            (timestamp, timestamp),
        )

    def pending_outbound_for_chat(
        self,
        source_session_id: str,
        *,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        timestamp = int(time.time()) if now is None else int(now)
        with self._transaction() as connection:
            self._expire_pending_outbound(connection, timestamp)
            rows = connection.execute(
                """SELECT * FROM secure_peer_outbound_intents
                WHERE state='pending' AND source_session_id=?
                ORDER BY created_at,request_id""",
                (str(source_session_id),),
            ).fetchall()
            return [
                item
                for row in rows
                if (item := self._public_outbound(row)) is not None
            ]

    def pending_outbound_for_route(
        self,
        connection_id: str,
        source_route_id: str,
        source_route_revision: str,
        *,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        timestamp = int(time.time()) if now is None else int(now)
        with self._transaction() as connection:
            self._expire_pending_outbound(connection, timestamp)
            rows = connection.execute(
                """SELECT * FROM secure_peer_outbound_intents
                WHERE state='pending' AND connection_id=? AND source_route_id=?
                AND source_route_revision=? ORDER BY created_at,request_id""",
                (connection_id, source_route_id, source_route_revision),
            ).fetchall()
            return [
                item
                for row in rows
                if (item := self._public_outbound(row)) is not None
            ]

    def pending_outbound_for_connection(
        self,
        connection_id: str,
        *,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        timestamp = int(time.time()) if now is None else int(now)
        with self._transaction() as connection:
            self._expire_pending_outbound(connection, timestamp)
            rows = connection.execute(
                """SELECT * FROM secure_peer_outbound_intents
                WHERE state='pending' AND connection_id=?
                ORDER BY created_at,request_id""",
                (connection_id,),
            ).fetchall()
            return [
                item
                for row in rows
                if (item := self._public_outbound(row)) is not None
            ]

    def nonterminal_for_connection(
        self,
        connection_id: str,
    ) -> list[dict[str, Any]]:
        with self._lock:
            connection = self._connect()
            try:
                rows = connection.execute(
                    """SELECT * FROM secure_peer_deliveries
                    WHERE connection_id=?
                    AND state IN ('prepared','authorized','queued','running')
                    ORDER BY created_at,envelope_id""",
                    (connection_id,),
                ).fetchall()
                return [
                    item
                    for row in rows
                    if (item := self._public(row)) is not None
                ]
            finally:
                connection.close()

    def outbound(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            connection = self._connect()
            try:
                return self._public_outbound(connection.execute(
                    "SELECT * FROM secure_peer_outbound_intents WHERE request_id=?",
                    (request_id,),
                ).fetchone())
            finally:
                connection.close()

    def commit_outbound(
        self,
        request_id: str,
        response: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        response_text = canonical_json(dict(response)).decode("utf-8")
        now = int(time.time())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM secure_peer_outbound_intents WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                return None
            if row["state"] == "committed":
                if str(row["response_json"] or "") != response_text:
                    raise RuntimeError("secure peer outbound result changed")
                return self._public_outbound(row)
            if row["state"] != "pending":
                return self._public_outbound(row)
            connection.execute(
                """UPDATE secure_peer_outbound_intents SET
                state='committed',response_json=?,retry_at=NULL,last_error=NULL,updated_at=?
                WHERE request_id=? AND state='pending'""",
                (response_text, now, request_id),
            )
            return self._public_outbound(connection.execute(
                "SELECT * FROM secure_peer_outbound_intents WHERE request_id=?",
                (request_id,),
            ).fetchone())

    def defer_outbound(self, request_id: str, error: str) -> dict[str, Any] | None:
        now = int(time.time())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM secure_peer_outbound_intents WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None or row["state"] != "pending":
                return self._public_outbound(row)
            attempts = int(row["attempts"] or 0) + 1
            delay = min(300, 2 ** min(attempts, 8))
            connection.execute(
                """UPDATE secure_peer_outbound_intents SET
                attempts=?,retry_at=?,last_error=?,updated_at=?
                WHERE request_id=? AND state='pending'""",
                (attempts, now + delay, str(error)[:400], now, request_id),
            )
            return self._public_outbound(connection.execute(
                "SELECT * FROM secure_peer_outbound_intents WHERE request_id=?",
                (request_id,),
            ).fetchone())

    def fail_outbound(self, request_id: str, error: str) -> dict[str, Any] | None:
        now = int(time.time())
        with self._transaction() as connection:
            connection.execute(
                """UPDATE secure_peer_outbound_intents SET
                state='failed',retry_at=NULL,last_error=?,updated_at=?
                WHERE request_id=? AND state='pending'""",
                (str(error)[:400], now, request_id),
            )
            return self._public_outbound(connection.execute(
                "SELECT * FROM secure_peer_outbound_intents WHERE request_id=?",
                (request_id,),
            ).fetchone())

    def pending_outbound(
        self,
        *,
        limit: int = 8,
        now: int | None = None,
    ) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("secure peer outbound retry limit is invalid")
        timestamp = int(time.time()) if now is None else int(now)
        with self._lock:
            connection = self._connect()
            try:
                rows = connection.execute(
                    """SELECT * FROM secure_peer_outbound_intents
                    WHERE state='pending' AND COALESCE(retry_at,0)<=?
                    ORDER BY COALESCE(retry_at,0),created_at,request_id LIMIT ?""",
                    (timestamp, limit),
                ).fetchall()
                return [
                    self._public_outbound(row)
                    for row in rows
                    if row is not None
                ]
            finally:
                connection.close()

    def prune(self, *, retain_seconds: int = 30 * 24 * 60 * 60) -> int:
        cutoff = int(time.time()) - retain_seconds
        with self._transaction() as connection:
            deleted = int(connection.execute(
                "DELETE FROM secure_peer_deliveries WHERE state IN ('completed','failed') AND updated_at<?",
                (cutoff,),
            ).rowcount or 0)
            deleted += int(connection.execute(
                "DELETE FROM secure_peer_outbound_intents WHERE state IN ('committed','failed') AND updated_at<?",
                (cutoff,),
            ).rowcount or 0)
            return deleted
