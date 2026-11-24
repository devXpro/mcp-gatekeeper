package sqlitestore

import (
	"context"
	"fmt"
)

// Schema components: the gatekeeper's own tables and the application's. Each has its own version line in
// gk_schema_migrations, so the application's steps never collide with the gatekeeper's.
const (
	componentGatekeeper = "gatekeeper"
	componentApp        = "app"
)

// Migration is one step of a schema. Steps are applied in Version order, each in its own transaction, and a step that
// was applied is never run again. A step is final once released: change a schema by adding a step, never by editing
// one.
type Migration struct {
	// Version is a positive number, unique and increasing inside its list.
	Version int
	// Name describes the step ("add plugin tables"); it is recorded, not interpreted.
	Name string
	// SQL is one or more statements.
	SQL string
}

// gatekeeperMigrations is the gatekeeper's schema. Appended to, never edited.
var gatekeeperMigrations = []Migration{
	{Version: 1, Name: "initial schema", SQL: `
CREATE TABLE gk_accounts (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE gk_people (
	id          TEXT PRIMARY KEY,
	account_id  TEXT NOT NULL,
	name        TEXT NOT NULL,
	role        TEXT NOT NULL,
	superadmin  INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL,
	disabled_at INTEGER
) STRICT;
CREATE INDEX gk_people_account ON gk_people (account_id, created_at, id);

CREATE TABLE gk_passkeys (
	id            TEXT PRIMARY KEY,
	person_id     TEXT NOT NULL,
	credential_id BLOB NOT NULL UNIQUE,
	data          BLOB NOT NULL,
	name          TEXT NOT NULL DEFAULT '',
	created_at    INTEGER NOT NULL,
	last_used_at  INTEGER
) STRICT;
CREATE INDEX gk_passkeys_person ON gk_passkeys (person_id, created_at, id);

CREATE TABLE gk_sessions (
	id_hash       BLOB PRIMARY KEY,
	person_id     TEXT NOT NULL,
	created_at    INTEGER NOT NULL,
	last_seen_at  INTEGER NOT NULL,
	expires_at    INTEGER NOT NULL,
	step_up_until INTEGER,
	user_agent    TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX gk_sessions_person ON gk_sessions (person_id);
CREATE INDEX gk_sessions_expires ON gk_sessions (expires_at);

CREATE TABLE gk_invites (
	id         TEXT PRIMARY KEY,
	token_hash BLOB NOT NULL UNIQUE,
	kind       TEXT NOT NULL,
	account_id TEXT NOT NULL DEFAULT '',
	name       TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at    INTEGER,
	revoked_at INTEGER
) STRICT;
CREATE INDEX gk_invites_account ON gk_invites (account_id, created_at, id);

CREATE TABLE gk_oauth_clients (
	id            TEXT PRIMARY KEY,
	kind          TEXT NOT NULL,
	assistant     TEXT NOT NULL,
	name          TEXT NOT NULL DEFAULT '',
	redirect_uris TEXT NOT NULL DEFAULT '[]',
	auth_method   TEXT NOT NULL,
	secret_hash   BLOB,
	fetched_at    INTEGER NOT NULL,
	created_at    INTEGER NOT NULL,
	last_used_at  INTEGER
) STRICT;

CREATE TABLE gk_oauth_codes (
	code_hash      BLOB PRIMARY KEY,
	grant_id       TEXT NOT NULL,
	client_id      TEXT NOT NULL,
	redirect_uri   TEXT NOT NULL DEFAULT '',
	resource       TEXT NOT NULL DEFAULT '',
	scope          TEXT NOT NULL DEFAULT '',
	code_challenge TEXT NOT NULL DEFAULT '',
	created_at     INTEGER NOT NULL,
	expires_at     INTEGER NOT NULL
) STRICT;
CREATE INDEX gk_oauth_codes_grant ON gk_oauth_codes (grant_id);

CREATE TABLE gk_oauth_grants (
	id           TEXT PRIMARY KEY,
	person_id    TEXT NOT NULL,
	account_id   TEXT NOT NULL,
	client_id    TEXT NOT NULL,
	resource_id  TEXT NOT NULL,
	scope        TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER,
	revoked_at   INTEGER
) STRICT;
-- One active grant per (person, client, resource); a revoked grant leaves the key.
CREATE UNIQUE INDEX gk_oauth_grants_active ON gk_oauth_grants (person_id, client_id, resource_id) WHERE revoked_at IS NULL;
CREATE INDEX gk_oauth_grants_account ON gk_oauth_grants (account_id, created_at, id);
CREATE INDEX gk_oauth_grants_client ON gk_oauth_grants (client_id);
CREATE INDEX gk_oauth_grants_resource ON gk_oauth_grants (resource_id);

CREATE TABLE gk_oauth_tokens (
	hash       BLOB PRIMARY KEY,
	grant_id   TEXT NOT NULL,
	kind       TEXT NOT NULL,
	family     TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used_at    INTEGER,
	revoked_at INTEGER
) STRICT;
CREATE INDEX gk_oauth_tokens_grant ON gk_oauth_tokens (grant_id);
CREATE INDEX gk_oauth_tokens_family ON gk_oauth_tokens (family);
CREATE INDEX gk_oauth_tokens_expires ON gk_oauth_tokens (expires_at);

-- The audit id is 24 hex characters that sort by time (see audit.go); an entry without an account is a system event.
CREATE TABLE gk_audit (
	id         TEXT PRIMARY KEY,
	at         INTEGER NOT NULL,
	account_id TEXT,
	actor      TEXT NOT NULL DEFAULT '',
	action     TEXT NOT NULL,
	target     TEXT NOT NULL DEFAULT '',
	detail     TEXT,
	ip         TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX gk_audit_account ON gk_audit (account_id, id);
`},
}

// validateMigrations checks an application's list.
func validateMigrations(list []Migration) error {
	last := 0
	for _, m := range list {
		switch {
		case m.Version <= last:
			return fmt.Errorf("sqlitestore: migration versions must be positive and increasing: %d after %d", m.Version, last)
		case m.SQL == "":
			return fmt.Errorf("sqlitestore: migration %d has no SQL", m.Version)
		}
		last = m.Version
	}
	return nil
}

// migrate applies the gatekeeper's and then the application's pending steps.
func (s *Store) migrate(ctx context.Context, app []Migration) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS gk_schema_migrations (
		component  TEXT NOT NULL,
		version    INTEGER NOT NULL,
		name       TEXT NOT NULL,
		applied_at INTEGER NOT NULL,
		PRIMARY KEY (component, version)
	) STRICT`); err != nil {
		return fmt.Errorf("sqlitestore: create the migration table: %w", err)
	}
	if err := s.applyAll(ctx, componentGatekeeper, gatekeeperMigrations); err != nil {
		return err
	}
	if len(app) == 0 {
		return nil
	}
	return s.applyAll(ctx, componentApp, app)
}

// applyAll applies the steps of one component that are newer than the database and refuses a database that is ahead
// of the build.
func (s *Store) applyAll(ctx context.Context, component string, list []Migration) error {
	for _, m := range list {
		if err := s.applyOne(ctx, component, m); err != nil {
			return err
		}
	}
	var newest int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM gk_schema_migrations WHERE component = ?`,
		component).Scan(&newest); err != nil {
		return fmt.Errorf("sqlitestore: read the %s schema version: %w", component, err)
	}
	known := 0
	if len(list) > 0 {
		known = list[len(list)-1].Version
	}
	if newest > known {
		return fmt.Errorf("sqlitestore: the %s schema of the database is at version %d, newer than this build supports (%d); upgrade the program",
			component, newest, known)
	}
	return nil
}

// applyOne runs one step in its own immediate transaction that re-reads whether the step was applied, so two
// processes opening the same file cannot apply it twice.
func (s *Store) applyOne(ctx context.Context, component string, m Migration) error {
	label := fmt.Sprintf("%s migration %d (%s)", component, m.Version, m.Name)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlitestore: %s: %w", label, err)
	}
	defer func() { _ = tx.Rollback() }()
	var applied int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM gk_schema_migrations WHERE component = ? AND version = ?`,
		component, m.Version).Scan(&applied); err != nil {
		return fmt.Errorf("sqlitestore: %s: %w", label, err)
	}
	if applied > 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("sqlitestore: %s: %w", label, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO gk_schema_migrations (component, version, name, applied_at) VALUES (?, ?, ?, ?)`,
		component, m.Version, m.Name, ms(s.clock())); err != nil {
		return fmt.Errorf("sqlitestore: %s: %w", label, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlitestore: %s: %w", label, err)
	}
	s.log.InfoContext(ctx, "sqlitestore: migration applied", "component", component, "version", m.Version, "name", m.Name)
	return nil
}
