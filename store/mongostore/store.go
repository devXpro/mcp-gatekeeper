// Package mongostore implements store.Store on MongoDB. It is Family Hub's internal/store moved here, and it reads
// and writes Family Hub's live database unchanged: the same collections, documents, _id forms, indexes and TTLs
// (docs/PLAN.md §4.2.1).
//
// The store assumes a replica set, so Tx and the delete cascades run in real transactions. Mongo keeps times with
// millisecond precision, so a time read back is the time written, truncated to the millisecond and in UTC.
//
// Transactions travel in the context: inside Tx the context carries the *mongo.Session (mongo.NewSessionContext),
// so any collection call an application makes with that context, on the same client, joins the transaction. An
// application keeps its own collections in the same database (Database) and creates them with EnsureCollection.
//
// Conventions shared by every sub-store:
//   - a write to one entity that does not exist returns core.ErrNotFound, except deletes of sessions and the bulk
//     operations (DeleteByPerson, RevokeFamily, ...), which are idempotent;
//   - inserting an id that exists returns core.ErrConflict, except the Put methods, which replace;
//   - Revoke* methods are idempotent: the first revocation time wins.
package mongostore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// Collection names. They are Family Hub's and must never change.
const (
	colAccounts     = "accounts"
	colPeople       = "people"
	colPasskeys     = "passkeys"
	colSessions     = "sessions"
	colInvites      = "invites"
	colOAuthClients = "oauth_clients"
	colOAuthCodes   = "oauth_codes"
	colOAuthGrants  = "oauth_grants"
	colOAuthTokens  = "oauth_tokens" //nolint:gosec // a collection name, not a credential
	colAudit        = "audit"
	colMigrations   = "schema_migrations"
)

// Defaults of Options.
const (
	defaultAppName        = "mcp-gatekeeper"
	defaultConnectTimeout = 10 * time.Second
	defaultOpTimeout      = 30 * time.Second
)

// Options configures a Store. Give either URI and Database, or DB.
type Options struct {
	// URI is the connection string. It carries credentials, so it is never logged and never part of an error.
	URI string
	// Database is the database name inside Mongo; required with URI.
	Database string
	// DB is an existing database whose client the application owns and shares (Family Hub). Close leaves that
	// client connected, and AppName, ConnectTimeout and OpTimeout do not apply: the client's own settings do.
	DB *mongo.Database
	// AppName is the client name the server logs; default "mcp-gatekeeper".
	AppName string
	// ConnectTimeout bounds finding the server, both at start and for every operation that waits for one; default 10s.
	ConnectTimeout time.Duration
	// OpTimeout bounds one operation, or one whole transaction, whose context has no deadline of its own; default 30s.
	OpTimeout time.Duration
	// Cascades run inside the transaction of an account or person delete, after the store's own deletes.
	Cascades []store.Cascade
	// Logger receives the migration log; nil discards it.
	Logger *slog.Logger
}

// Store is store.Store on MongoDB.
type Store struct {
	client     *mongo.Client
	db         *mongo.Database
	ownsClient bool
	cascades   []store.Cascade
	log        *slog.Logger
}

var _ store.Store = (*Store)(nil)

// New prepares a Store without contacting the server; call Init before use.
func New(o Options) (*Store, error) {
	log := o.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	for i, c := range o.Cascades {
		if c == nil {
			return nil, fmt.Errorf("mongostore: cascade %d is nil", i)
		}
	}
	s := &Store{cascades: append([]store.Cascade(nil), o.Cascades...), log: log}
	switch {
	case o.DB != nil && o.URI != "":
		return nil, errors.New("mongostore: give either a URI or a DB, not both")
	case o.DB != nil:
		s.client, s.db = o.DB.Client(), o.DB
		return s, nil
	case o.URI == "":
		return nil, errors.New("mongostore: a URI or a DB is required")
	case o.Database == "":
		return nil, errors.New("mongostore: a database name is required with a URI")
	}
	appName, connect, op := o.AppName, o.ConnectTimeout, o.OpTimeout
	if appName == "" {
		appName = defaultAppName
	}
	if connect <= 0 {
		connect = defaultConnectTimeout
	}
	if op <= 0 {
		op = defaultOpTimeout
	}
	client, err := mongo.Connect(options.Client().
		ApplyURI(o.URI).
		SetAppName(appName).
		SetServerSelectionTimeout(connect).
		SetTimeout(op))
	if err != nil {
		return nil, fmt.Errorf("mongostore: connect: %w", redactURI(err, o.URI))
	}
	s.client, s.db, s.ownsClient = client, client.Database(o.Database), true
	return s, nil
}

// Init checks the server answers and applies the migrations.
func (s *Store) Init(ctx context.Context) error {
	if err := s.client.Ping(ctx, readpref.Primary()); err != nil {
		return fmt.Errorf("mongostore: ping: %w", err)
	}
	return migrate(ctx, s.db, s.log)
}

// Open is New followed by Init; on an Init error the client New made is closed.
func Open(ctx context.Context, o Options) (*Store, error) {
	s, err := New(o)
	if err != nil {
		return nil, err
	}
	if err := s.Init(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Database returns the database the store works in, for an application's own collections. Calls made on it with a
// context from Tx join the transaction.
func (s *Store) Database() *mongo.Database { return s.db }

// Accounts returns the account store.
func (s *Store) Accounts() store.AccountStore { return accountStore{s} }

// People returns the person store.
func (s *Store) People() store.PersonStore { return personStore{s} }

// Passkeys returns the passkey store.
func (s *Store) Passkeys() store.PasskeyStore { return passkeyStore{s} }

// Sessions returns the session store.
func (s *Store) Sessions() store.SessionStore { return sessionStore{s} }

// Invites returns the invite store.
func (s *Store) Invites() store.InviteStore { return inviteStore{s} }

// OAuth returns the OAuth store.
func (s *Store) OAuth() store.OAuthStore { return oauthStore{s} }

// Audit returns the audit store.
func (s *Store) Audit() store.AuditStore { return auditStore{s} }

// Tx runs fn in one transaction; an error from fn rolls it back and is returned. The context fn gets carries the
// session. When ctx already carries a running transaction of this store's client, fn joins it (there are no
// savepoints: an error a nested fn returns fails the outer transaction only if the outer fn returns it too).
//
// The driver may run fn again after a transient transaction error (a write conflict, a primary change), so fn and
// every Cascade must keep their side effects inside the transaction.
func (s *Store) Tx(ctx context.Context, fn func(ctx context.Context) error) error {
	if InTx(ctx) && mongo.SessionFromContext(ctx).Client() == s.client {
		return fn(ctx)
	}
	sess, err := s.client.StartSession()
	if err != nil {
		return fmt.Errorf("mongostore: start session: %w", err)
	}
	defer sess.EndSession(context.WithoutCancel(ctx))
	_, err = sess.WithTransaction(ctx, func(ctx context.Context) (any, error) {
		return nil, fn(ctx)
	})
	return err
}

// InTx reports whether ctx carries a session with a running transaction, as the context inside Tx does.
func InTx(ctx context.Context) bool {
	sess := mongo.SessionFromContext(ctx)
	return sess != nil && sess.TransactionRunning()
}

// Close disconnects from Mongo when New made the client; a shared client (Options.DB) stays connected.
func (s *Store) Close() error {
	if !s.ownsClient {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.client.Disconnect(ctx)
}

// cascadeAccount runs every Cascade for a deleted account: DeletePerson for each of its people, then DeleteAccount.
func (s *Store) cascadeAccount(ctx context.Context, a core.AccountID, people []string) error {
	for _, p := range people {
		if err := s.cascadePerson(ctx, core.PersonID(p)); err != nil {
			return err
		}
	}
	for _, c := range s.cascades {
		if err := c.DeleteAccount(ctx, a); err != nil {
			return fmt.Errorf("mongostore: cascade account delete: %w", err)
		}
	}
	return nil
}

// cascadePerson runs every Cascade for a deleted person.
func (s *Store) cascadePerson(ctx context.Context, p core.PersonID) error {
	for _, c := range s.cascades {
		if err := c.DeletePerson(ctx, p); err != nil {
			return fmt.Errorf("mongostore: cascade person delete: %w", err)
		}
	}
	return nil
}

// redactURI hides the connection string, which may carry a password, if the driver echoes it in an error.
func redactURI(err error, uri string) error {
	if !strings.Contains(err.Error(), uri) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), uri, "<uri>"))
}
