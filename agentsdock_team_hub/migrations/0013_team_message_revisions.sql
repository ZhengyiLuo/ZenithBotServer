-- Immutable, author-only revisions for ordinary Team Messages. The original
-- team_messages row remains version 1; every edit appends a new body revision.

CREATE TABLE team_message_revisions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    team_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 2),
    body_format TEXT NOT NULL CHECK(body_format IN ('plain', 'markdown')),
    body TEXT NOT NULL CHECK(length(CAST(body AS BLOB)) BETWEEN 1 AND 49152),
    body_sha256 BLOB NOT NULL
        CHECK(typeof(body_sha256) = 'blob' AND length(body_sha256) = 32),
    editor_kind TEXT NOT NULL CHECK(editor_kind IN ('human', 'server')),
    edited_by_principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
    editor_node_id TEXT,
    idempotency_key BLOB NOT NULL
        CHECK(typeof(idempotency_key) = 'blob' AND length(idempotency_key) = 32),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    FOREIGN KEY(team_id, message_id)
        REFERENCES team_messages(team_id, id) ON DELETE RESTRICT,
    FOREIGN KEY(team_id, editor_node_id)
        REFERENCES nodes(team_id, id) ON DELETE RESTRICT,
    UNIQUE(team_id, message_id, version),
    UNIQUE(team_id, message_id, idempotency_key),
    CHECK(
        (editor_kind = 'human' AND editor_node_id IS NULL)
        OR (editor_kind = 'server' AND editor_node_id IS NOT NULL)
    )
);

CREATE INDEX team_message_revisions_by_message
ON team_message_revisions(team_id, message_id, version DESC);

CREATE INDEX team_message_revisions_by_team
ON team_message_revisions(team_id, sequence);

CREATE TRIGGER team_message_revisions_are_immutable
BEFORE UPDATE ON team_message_revisions
BEGIN
    SELECT RAISE(ABORT, 'team message revisions are immutable');
END;

CREATE TRIGGER team_message_revisions_cannot_be_deleted
BEFORE DELETE ON team_message_revisions
BEGIN
    SELECT RAISE(ABORT, 'team message revisions cannot be deleted');
END;
