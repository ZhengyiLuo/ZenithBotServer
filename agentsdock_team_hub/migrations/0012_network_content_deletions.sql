-- Immutable soft-deletion journal for Team Messages V2 and the legacy Team
-- Network bulletin. Source records and bound attachment blobs remain
-- immutable; readers suppress content through this additive ledger.

CREATE TABLE network_content_deletions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
    resource_kind TEXT NOT NULL CHECK(resource_kind IN ('message', 'bulletin')),
    resource_id TEXT NOT NULL,
    deleted_by_principal_id TEXT NOT NULL
        REFERENCES principals(id) ON DELETE RESTRICT,
    deleted_at INTEGER NOT NULL CHECK(deleted_at >= 0),
    UNIQUE(team_id, resource_kind, resource_id)
);

CREATE INDEX network_content_deletions_team_sequence
ON network_content_deletions(team_id, sequence);

CREATE TRIGGER network_content_deletions_require_message
BEFORE INSERT ON network_content_deletions
FOR EACH ROW WHEN NEW.resource_kind = 'message' AND NOT EXISTS (
    SELECT 1 FROM team_messages AS m
    WHERE m.team_id = NEW.team_id AND m.id = NEW.resource_id
      AND m.kind = 'message'
)
BEGIN
    SELECT RAISE(ABORT, 'team message deletion source is unavailable');
END;

CREATE TRIGGER network_content_deletions_require_bulletin
BEFORE INSERT ON network_content_deletions
FOR EACH ROW WHEN NEW.resource_kind = 'bulletin' AND NOT EXISTS (
    SELECT 1
    FROM messages AS m
    JOIN network_boards AS b
      ON b.team_id = m.team_id AND b.channel_id = m.channel_id
    WHERE m.team_id = NEW.team_id AND m.id = NEW.resource_id
)
BEGIN
    SELECT RAISE(ABORT, 'bulletin deletion source is unavailable');
END;

CREATE TRIGGER network_content_deletions_require_team_actor
BEFORE INSERT ON network_content_deletions
FOR EACH ROW WHEN NOT EXISTS (
    SELECT 1
    FROM principals AS p
    JOIN memberships AS m
      ON m.team_id = NEW.team_id AND m.principal_id = p.id
    WHERE p.id = NEW.deleted_by_principal_id
      AND p.status = 'active'
      AND m.status = 'active'
)
BEGIN
    SELECT RAISE(ABORT, 'deletion actor does not belong to this team');
END;

CREATE TRIGGER network_content_deletions_are_immutable
BEFORE UPDATE ON network_content_deletions
BEGIN
    SELECT RAISE(ABORT, 'network content deletions are immutable');
END;

CREATE TRIGGER network_content_deletions_cannot_be_deleted
BEFORE DELETE ON network_content_deletions
BEGIN
    SELECT RAISE(ABORT, 'network content deletions cannot be deleted');
END;
