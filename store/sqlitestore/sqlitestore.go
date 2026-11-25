// Package sqlitestore implements store.Store on SQLite (modernc.org/sqlite, no cgo). It is the adapter of Homie, an
// application with one household and one file; Family Hub uses package mongostore. Both pass the one conformance suite,
// package storetest.
//
// The database file is opened in WAL mode with full synchronous commits (a commit that returned survives a power
// cut), foreign keys on and a busy timeout. The file, its -wal and -shm are 0600 and their directory 0700; Open
// tightens looser modes and logs a warning when it had to. It tightens a directory only when it is the database's own
// (Open created it, or it is the process user's and holds nothing but the database's files) and refuses to open in
// any other directory that is not 0700. Every gatekeeper table is named
// gk_*, so an application's own tables can live in the same file without a clash; times are INTEGER Unix
// milliseconds in UTC (the precision every adapter keeps), secrets and tokens only as sha256 BLOBs.
//
// # Transactions
//
// Transactions travel in the context: Tx binds one transaction to the context passed to its function, every store
// method called with that context joins it, and a Tx inside a Tx joins the outer one. An application puts its own
// tables in the same transaction through Conn:
//
//	err := st.Tx(ctx, func(ctx context.Context) error {
//		if err := st.People().Create(ctx, p); err != nil {
//			return err
//		}
//		_, err := st.Conn(ctx).ExecContext(ctx, `INSERT INTO plugin_settings (person_id) VALUES (?)`, p.ID)
//		return err
//	})
//
// # Concurrency
//
// SQLite has one writer. The store serializes write transactions in the process: a Tx (and every store method that
// writes outside a Tx) first takes a one-slot lock, then opens the transaction with BEGIN IMMEDIATE. So callers never
// see SQLITE_BUSY from each other and never deadlock on a read-then-write upgrade; waiting for the lock honours the
// context. The busy timeout only covers a second process (or a second Store) writing the same file. Readers never
// wait: outside a Tx they use another pooled connection, and WAL gives them the last committed state.
//
// The lock is held for the whole Tx function, so the function must not wait for another Tx started with a context
// that does not carry this one (it would wait for itself): inside the function pass the context it received.
//
// An application's own writes outside a Tx (Conn on a context without a transaction) skip the in-process lock and
// rely on the busy timeout; write inside Tx instead.
package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// Defaults of Options.
const (
	defaultBusyTimeout = 10 * time.Second
	defaultMaxConns    = 8
)

// Options configures a Store.
type Options struct {
	// Path is the database file; it is created (mode 0600, its directory 0700) when missing, and an existing file,
	// -wal or -shm with other modes is set to those (with a warning). Use a directory of its own: an existing directory
	// that is not 0700 is tightened only when it belongs to the process user and holds nothing but the database's
	// files, and Open fails otherwise (it never chmods a shared directory). Required.
	Path string
	// Cascades run inside the transaction of an account or person delete, after the store's own deletes.
	Cascades []store.Cascade
	// Migrations are the application's own schema steps, applied after the gatekeeper's and tracked apart from them
	// (see Migration).
	Migrations []Migration
	// Clock is the time source for audit ids and migration stamps; default time.Now.
	Clock core.Clock
	// Logger receives the migration log; nil discards it.
	Logger *slog.Logger
	// BusyTimeout is how long SQLite waits for a lock another process holds; default 10s.
	BusyTimeout time.Duration
	// MaxConns bounds the pooled connections (one writer, the rest readers); default 8.
	MaxConns int
}

// Conn is what an application needs to run its own SQL: a *sql.DB or a *sql.Tx.
type Conn interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store is store.Store on SQLite.
type Store struct {
	db       *sql.DB
	cascades []store.Cascade
	clock    core.Clock
	log      *slog.Logger
	writer   chan struct{} // one slot: the in-process write lock
	audit    auditIDs
}

var _ store.Store = (*Store)(nil)

// Open opens (creating it when missing) the database, applies the migrations and returns the store. It refuses a
// database whose schema is newer than this build knows.
func Open(ctx context.Context, o Options) (*Store, error) {
	if o.Path == "" {
		return nil, errors.New("sqlitestore: a database path is required")
	}
	for i, c := range o.Cascades {
		if c == nil {
			return nil, fmt.Errorf("sqlitestore: cascade %d is nil", i)
		}
	}
	if err := validateMigrations(o.Migrations); err != nil {
		return nil, err
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	busy := o.BusyTimeout
	if busy <= 0 {
		busy = defaultBusyTimeout
	}
	maxConns := o.MaxConns
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}

	path, err := prepareFile(o.Path, log)
	if err != nil {
		return nil, err
	}
	// _txlock=immediate makes every transaction take the write lock at BEGIN, so a read-then-write transaction waits
	// instead of failing with SQLITE_BUSY halfway.
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busy.Milliseconds()))
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Set("_txlock", "immediate")
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlitestore: open database: %w", err)
	}
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlitestore: open database: %w", err)
	}
	s := &Store{
		db: db, cascades: append([]store.Cascade(nil), o.Cascades...), clock: clock, log: log,
		writer: make(chan struct{}, 1),
	}
	if err := s.migrate(ctx, o.Migrations); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.audit.seed(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	// The -wal and -shm files exist now (they may also be left over from a process that crashed).
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := restrict(path+suffix, 0o600, log); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = db.Close()
			return nil, err
		}
	}
	return s, nil
}

// prepareFile creates the directory and the file with restrictive modes and tightens the modes of ones that exist
// (SQLite gives -wal and -shm the main file's mode). It returns the absolute path.
func prepareFile(path string, log *slog.Logger) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("sqlitestore: database path: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return "", fmt.Errorf("sqlitestore: create data dir: %w", err)
	}
	err = os.Mkdir(dir, 0o700)
	created := err == nil
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("sqlitestore: create data dir: %w", err)
	}
	if err := restrictDir(dir, filepath.Base(path), created, log); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // the operator's own database path
	if err != nil {
		return "", fmt.Errorf("sqlitestore: create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("sqlitestore: create database file: %w", err)
	}
	if err := restrict(path, 0o600, log); err != nil {
		return "", err
	}
	return path, nil
}

// restrictDir makes the database's directory 0700, but only when it is the database's own (review R-8): one Open has
// just created, or one of the process user that holds nothing but this database's files. A shared directory with
// another mode (/tmp, a home directory, a volume root) is refused, never chmodded; a 0700 one is fine as it is.
func restrictDir(dir, base string, created bool, log *slog.Logger) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("sqlitestore: stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("sqlitestore: %s is not a directory", dir)
	}
	if info.Mode().Perm() == 0o700 {
		return nil
	}
	if !created {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("sqlitestore: read %s: %w", dir, err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if problem := sharedDir(info, names, base); problem != "" {
			return fmt.Errorf("sqlitestore: the database's directory %s has mode %s, not 0700, and %s, so Open will "+
				"not change it: use a directory of its own for the database", dir, info.Mode().Perm(), problem)
		}
	}
	return restrict(dir, 0o700, log)
}

// sharedDir says why a directory holding names is not the database's own to chmod, or "" when it is: it belongs to
// the process user and holds only the database file base and its -wal, -shm and -journal.
func sharedDir(info fs.FileInfo, names []string, base string) string {
	if !ownedByProcessUser(info) {
		return "it belongs to another user"
	}
	for _, n := range names {
		switch n {
		case base, base + "-wal", base + "-shm", base + "-journal":
		default:
			return fmt.Sprintf("it holds other files (%s)", n)
		}
	}
	return ""
}

// restrict sets the mode of path to want when it is anything else, and says so in a warning: the data was readable
// by others (or unusable by its owner) until now. A path that does not exist is os.ErrNotExist.
func restrict(path string, want os.FileMode, log *slog.Logger) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("sqlitestore: stat %s: %w", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		if err := os.Chmod(path, want); err != nil {
			return fmt.Errorf("sqlitestore: set the mode of %s: %w", path, err)
		}
		log.Warn("sqlitestore: file mode corrected", "path", path, "was", got.String(), "now", want.String())
	}
	return nil
}

// Accounts implements store.Store.
func (s *Store) Accounts() store.AccountStore { return accounts{s} }

// People implements store.Store.
func (s *Store) People() store.PersonStore { return people{s} }

// Passkeys implements store.Store.
func (s *Store) Passkeys() store.PasskeyStore { return passkeys{s} }

// Sessions implements store.Store.
func (s *Store) Sessions() store.SessionStore { return sessions{s} }

// Invites implements store.Store.
func (s *Store) Invites() store.InviteStore { return invites{s} }

// OAuth implements store.Store.
func (s *Store) OAuth() store.OAuthStore { return oauth{s} }

// Audit implements store.Store.
func (s *Store) Audit() store.AuditStore { return audit{s} }

// Close closes the database. Open transactions are rolled back.
func (s *Store) Close() error { return s.db.Close() }

// txKey keys the transaction in a context. It holds the Store, so a transaction of one store is never mistaken for
// another's.
type txKey struct{ s *Store }

// Tx implements store.Store: it runs fn in one write transaction (BEGIN IMMEDIATE, serialized with the store's other
// write transactions) and commits when fn returns nil; any error, or a panic, rolls it back. Inside fn, pass the
// context fn received to every store method and to Conn. A Tx inside a Tx joins the outer one.
func (s *Store) Tx(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if _, ok := s.txFrom(ctx); ok {
		return fn(ctx)
	}
	select {
	case s.writer <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("sqlitestore: wait for the write lock: %w", ctx.Err())
	}
	defer func() { <-s.writer }()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlitestore: begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback() // after a failed fn or a panic; ErrTxDone when the context already ended it
		}
	}()
	if err := fn(context.WithValue(ctx, txKey{s}, tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlitestore: commit: %w", err)
	}
	committed = true
	return nil
}

func (s *Store) txFrom(ctx context.Context) (*sql.Tx, bool) {
	tx, ok := ctx.Value(txKey{s}).(*sql.Tx)
	return tx, ok
}

// Conn returns the transaction ctx carries (from Tx) or, without one, the database. An application runs its own SQL
// through it so its tables join the gatekeeper's transactions. Without a transaction use it for reads and write
// through Tx (see the package comment).
func (s *Store) Conn(ctx context.Context) Conn {
	if tx, ok := s.txFrom(ctx); ok {
		return tx
	}
	return s.db
}

// write runs fn in a write transaction: the one ctx carries, or a new one. fn gets the context to pass on (it carries
// the transaction, so a cascade or a nested store call joins) and the connection.
func (s *Store) write(ctx context.Context, fn func(ctx context.Context, q Conn) error) error {
	return s.Tx(ctx, func(ctx context.Context) error { return fn(ctx, s.Conn(ctx)) })
}

// exec runs one write statement and returns the number of rows it touched.
func (s *Store) exec(ctx context.Context, op, query string, args ...any) (int64, error) {
	var n int64
	err := s.write(ctx, func(ctx context.Context, q Conn) error {
		res, err := q.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n, wrap(op, err)
}

// execOne runs one write statement that must touch a row; none is core.ErrNotFound.
func (s *Store) execOne(ctx context.Context, op, query string, args ...any) error {
	n, err := s.exec(ctx, op, query, args...)
	if err != nil {
		return err
	}
	if n == 0 {
		return wrap(op, sql.ErrNoRows)
	}
	return nil
}

// wrap names the operation and maps the driver's errors to the core sentinels, keeping the original in the chain.
func wrap(op string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("sqlitestore: %s: %w", op, core.ErrNotFound)
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return fmt.Errorf("sqlitestore: %s: %w (%w)", op, core.ErrConflict, err)
		}
	}
	return fmt.Errorf("sqlitestore: %s: %w", op, err)
}

// scanner is *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

// queryAll runs a query and scans every row with scan.
func queryAll[T any](ctx context.Context, q Conn, scan func(scanner) (T, error), query string, args ...any) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ms converts a time to stored Unix milliseconds.
func ms(t time.Time) int64 { return t.UnixMilli() }

// fromMS is the inverse of ms; the result is in UTC.
func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

// optMS stores an optional time: nil is NULL.
func optMS(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixMilli()
}

// zeroMS stores a time that is zero when unset: the zero time is NULL.
func zeroMS(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixMilli()
}

// optTime reads a nullable time column.
func optTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMS(v.Int64)
	return &t
}

// zeroTime reads a nullable time column into a time that is zero when unset.
func zeroTime(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return fromMS(v.Int64)
}

// blob stores bytes for a NOT NULL column: nil becomes empty.
func blob(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// optBlob stores bytes for a nullable column: empty is NULL.
func optBlob(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// encodePermissions stores a list of permission ids as a JSON array; none (nil or empty) is NULL, so both read back
// as nil, as in the MongoDB adapter.
func encodePermissions(perms []string) (any, error) {
	if len(perms) == 0 {
		return nil, nil //nolint:nilnil // NULL is the stored form of "none"
	}
	raw, err := json.Marshal(perms)
	if err != nil {
		return nil, err
	}
	return string(raw), nil
}

// decodePermissions is the inverse of encodePermissions.
func decodePermissions(v sql.NullString) ([]string, error) {
	if !v.Valid {
		return nil, nil
	}
	var perms []string
	if err := json.Unmarshal([]byte(v.String), &perms); err != nil {
		return nil, err
	}
	if len(perms) == 0 {
		return nil, nil
	}
	return perms, nil
}
