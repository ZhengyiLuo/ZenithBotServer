-- Bound owner/self-service administration scans to their keyset order.
-- The append-only AUTOINCREMENT ledger gives a traversal a stable high-water:
-- SQLite table rowids can otherwise be reused after deletion.
CREATE TABLE human_admin_page_entries (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_kind TEXT NOT NULL
        CHECK(resource_kind IN ('device_session', 'invitation', 'membership')),
    resource_id TEXT NOT NULL,
    UNIQUE(resource_kind, resource_id)
);

INSERT INTO human_admin_page_entries(resource_kind, resource_id)
SELECT 'device_session', id FROM device_sessions ORDER BY rowid;
INSERT INTO human_admin_page_entries(resource_kind, resource_id)
SELECT 'invitation', id FROM invitations ORDER BY rowid;
INSERT INTO human_admin_page_entries(resource_kind, resource_id)
SELECT 'membership', id FROM memberships ORDER BY rowid;

CREATE TRIGGER human_admin_page_device_session_insert
AFTER INSERT ON device_sessions
BEGIN
    INSERT INTO human_admin_page_entries(resource_kind, resource_id)
    VALUES ('device_session', NEW.id);
END;

CREATE TRIGGER human_admin_page_invitation_insert
AFTER INSERT ON invitations
BEGIN
    INSERT INTO human_admin_page_entries(resource_kind, resource_id)
    VALUES ('invitation', NEW.id);
END;

CREATE TRIGGER human_admin_page_membership_insert
AFTER INSERT ON memberships
BEGIN
    INSERT INTO human_admin_page_entries(resource_kind, resource_id)
    VALUES ('membership', NEW.id);
END;

CREATE TRIGGER human_admin_page_entries_immutable
BEFORE UPDATE ON human_admin_page_entries
BEGIN
    SELECT RAISE(ABORT, 'human administration page sequence is immutable');
END;

CREATE TRIGGER human_admin_page_entries_cannot_be_deleted
BEFORE DELETE ON human_admin_page_entries
BEGIN
    SELECT RAISE(ABORT, 'human administration page sequence cannot be deleted');
END;

CREATE INDEX device_sessions_human_created_id_idx
ON device_sessions(human_principal_id, created_at DESC, id DESC);

CREATE INDEX invitations_pending_team_created_id_idx
ON invitations(team_id, created_at DESC, id DESC)
WHERE redeemed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX memberships_active_team_created_principal_idx
ON memberships(team_id, created_at DESC, principal_id DESC)
WHERE status = 'active';

CREATE INDEX memberships_manageable_team_created_principal_idx
ON memberships(team_id, created_at DESC, principal_id DESC)
WHERE status IN ('active', 'suspended');
