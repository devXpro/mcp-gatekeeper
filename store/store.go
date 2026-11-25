// Package store defines the gatekeeper's persistence. Adapters: package mongostore (MongoDB, Family Hub) and package
// sqlitestore (SQLite, Homie); package storetest is the one conformance suite both must pass.
//
// It is frozen (docs/PLAN.md §4.1). Agents never edit it.
//
// An application picks the adapter at build time by importing it; the other driver never gets into its binary.
//
// Transactions travel in the context: Tx calls fn with a context bound to one transaction, and every store method
// called with that context joins it. An application's own collections or tables join the same transaction through
// the adapter's helpers (mongostore: the context carries the session; sqlitestore: Conn(ctx)).
package store

import (
	"context"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// Store is the gatekeeper's persistence.
type Store interface {
	Accounts() AccountStore
	People() PersonStore
	Passkeys() PasskeyStore
	Sessions() SessionStore
	Invites() InviteStore
	OAuth() OAuthStore
	Audit() AuditStore
	// Tx runs fn in one transaction; every store call made with the context passed to fn joins it, and an error
	// from fn rolls it back. A Tx inside a Tx joins the outer one.
	Tx(ctx context.Context, fn func(ctx context.Context) error) error
	Close() error
}

// Cascade lets an application delete its own rows when the gatekeeper deletes an account or a person. The adapters
// call every registered Cascade inside the same transaction as their own deletes. A transaction may be retried after
// a transient error (MongoDB), so a Cascade may run more than once: keep its effects inside the transaction.
type Cascade interface {
	DeleteAccount(ctx context.Context, a core.AccountID) error
	DeletePerson(ctx context.Context, p core.PersonID) error
}

// AccountStore keeps accounts.
type AccountStore interface {
	Create(ctx context.Context, a core.Account) error
	Get(ctx context.Context, id core.AccountID) (core.Account, error)
	List(ctx context.Context) ([]core.Account, error)
	Rename(ctx context.Context, id core.AccountID, name string) error
	// Delete removes the account and, by cascade, its people, passkeys, sessions, invites, grants, codes and tokens.
	// The registered Cascades run with it: DeletePerson for every person of the account first, then DeleteAccount.
	// Audit entries stay.
	Delete(ctx context.Context, id core.AccountID) error
}

// PersonStore keeps people.
type PersonStore interface {
	Create(ctx context.Context, p core.Person) error
	Get(ctx context.Context, id core.PersonID) (core.Person, error)
	ListByAccount(ctx context.Context, a core.AccountID) ([]core.Person, error)
	CountSuperadmins(ctx context.Context) (int, error)
	Rename(ctx context.Context, id core.PersonID, name string) error
	Disable(ctx context.Context, id core.PersonID, at time.Time) error
	// SetAccess replaces a person's term and permissions (core.Person.AccessUntil and Permissions; nil clears each).
	SetAccess(ctx context.Context, id core.PersonID, until *time.Time, perms []string) error
	// Delete removes the person with their passkeys, sessions, grants and tokens, then runs the registered Cascades.
	Delete(ctx context.Context, id core.PersonID) error
}

// Purger is implemented by an adapter whose database cannot expire rows by itself (sqlitestore; MongoDB has TTL
// indexes, so mongostore does not need it). The application's sweeper calls it, e.g. hourly.
type Purger interface {
	// Purge deletes what has expired at now under the adapter's retention: tokens and codes past their end, invites
	// some days after theirs, audit entries past the retention, and DCR clients without a grant.
	Purge(ctx context.Context, now time.Time) (PurgeStats, error)
}

// PurgeStats counts what one Purge deleted.
type PurgeStats struct {
	Tokens  int
	Codes   int
	Invites int
	Audit   int
	Clients int
}

// PasskeyStore keeps passkeys.
type PasskeyStore interface {
	Add(ctx context.Context, k core.Passkey) error
	Get(ctx context.Context, id string) (core.Passkey, error)
	GetByCredentialID(ctx context.Context, credentialID []byte) (core.Passkey, error)
	ListByPerson(ctx context.Context, p core.PersonID) ([]core.Passkey, error)
	// Update stores new credential data (sign counter, flags) and the time of use.
	Update(ctx context.Context, id string, data []byte, lastUsed time.Time) error
	Rename(ctx context.Context, id, name string) error
	Delete(ctx context.Context, id string) error
	DeleteByPerson(ctx context.Context, p core.PersonID) error
}

// SessionStore keeps browser sessions by the sha256 of the cookie.
type SessionStore interface {
	Create(ctx context.Context, s core.Session) error
	Get(ctx context.Context, idHash []byte) (core.Session, error)
	Touch(ctx context.Context, idHash []byte, at time.Time) error
	SetStepUp(ctx context.Context, idHash []byte, until time.Time) error
	Delete(ctx context.Context, idHash []byte) error
	DeleteByPerson(ctx context.Context, p core.PersonID) error
	// DeleteExpired removes sessions past their absolute end or idle for longer than idle.
	DeleteExpired(ctx context.Context, now time.Time, idle time.Duration) (int, error)
}

// InviteStore keeps one-time links by the sha256 of the token.
type InviteStore interface {
	Create(ctx context.Context, inv core.Invite) error
	// Peek returns a live invite without using it; otherwise ErrNotFound, ErrExpired or ErrUsed.
	Peek(ctx context.Context, tokenHash []byte, now time.Time) (core.Invite, error)
	// Consume marks a live invite used, atomically: of two concurrent calls one wins and the other gets ErrUsed.
	Consume(ctx context.Context, tokenHash []byte, now time.Time) (core.Invite, error)
	ListByAccount(ctx context.Context, a core.AccountID) ([]core.Invite, error)
	Revoke(ctx context.Context, id string, at time.Time) error
	// RevokeKind revokes every live invite of a kind (a new setup link revokes the older ones).
	RevokeKind(ctx context.Context, kind core.InviteKind, at time.Time) error
}

// OAuthStore keeps clients, codes, grants and tokens.
type OAuthStore interface {
	// PutClient inserts or replaces a client (CIMD clients are refreshed).
	PutClient(ctx context.Context, c core.OAuthClient) error
	GetClient(ctx context.Context, id core.ClientID) (core.OAuthClient, error)
	TouchClient(ctx context.Context, id core.ClientID, at time.Time) error
	// DeleteIdleClients removes DCR clients created before cutoff that have no grant.
	DeleteIdleClients(ctx context.Context, cutoff time.Time) (int, error)

	PutCode(ctx context.Context, c core.AuthCode) error
	// ConsumeCode returns and deletes a live code, atomically; otherwise ErrNotFound or ErrExpired.
	ConsumeCode(ctx context.Context, codeHash []byte, now time.Time) (core.AuthCode, error)

	PutGrant(ctx context.Context, g core.Grant) error
	GetGrant(ctx context.Context, id core.GrantID) (core.Grant, error)
	// FindGrant returns the active grant of (person, client, resource), or ErrNotFound.
	FindGrant(ctx context.Context, p core.PersonID, c core.ClientID, r core.ResourceID) (core.Grant, error)
	ListGrantsByAccount(ctx context.Context, a core.AccountID) ([]core.Grant, error)
	TouchGrant(ctx context.Context, id core.GrantID, at time.Time) error
	// RevokeGrant revokes the grant and every token of it.
	RevokeGrant(ctx context.Context, id core.GrantID, at time.Time) error
	// RevokeGrantsByResource revokes every grant of a resource and their tokens (the resource was removed).
	RevokeGrantsByResource(ctx context.Context, r core.ResourceID, at time.Time) error

	PutToken(ctx context.Context, t core.Token) error
	GetToken(ctx context.Context, hash []byte) (core.Token, error)
	// UseRefresh marks a live refresh token used, atomically: of two concurrent calls one wins and the other gets
	// ErrUsed.
	UseRefresh(ctx context.Context, hash []byte, at time.Time) (core.Token, error)
	RevokeToken(ctx context.Context, hash []byte, at time.Time) error
	RevokeFamily(ctx context.Context, family string, at time.Time) error
	DeleteExpiredTokens(ctx context.Context, now time.Time) (int, error)
}

// AuditStore appends and lists audit entries, newest first.
type AuditStore interface {
	Append(ctx context.Context, e core.AuditEntry) error
	// ListByAccount returns at most limit entries of account a older than the entry with ID before ("" starts from
	// the newest).
	ListByAccount(ctx context.Context, a core.AccountID, before string, limit int) ([]core.AuditEntry, error)
	// ListSystem returns entries without an account, paged the same way.
	ListSystem(ctx context.Context, before string, limit int) ([]core.AuditEntry, error)
}
