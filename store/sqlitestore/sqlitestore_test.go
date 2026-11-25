package sqlitestore_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/internal/testlog"
	"github.com/devXpro/mcp-gatekeeper/store"
	"github.com/devXpro/mcp-gatekeeper/store/sqlitestore"
	"github.com/devXpro/mcp-gatekeeper/store/storetest"
)

var errBoom = errors.New("boom")

func dbPath(t *testing.T) string { return filepath.Join(t.TempDir(), "data", "gatekeeper.db") }

// scalar runs a query that returns one value through the store's own connection.
func scalar[T any](t *testing.T, s *sqlitestore.Store, query string, args ...any) T {
	t.Helper()
	var v T
	require.NoError(t, s.Conn(t.Context()).QueryRowContext(t.Context(), query, args...).Scan(&v))
	return v
}

func TestOpenSettings(t *testing.T) {
	path := dbPath(t)
	s := open(t, sqlitestore.Options{Path: path})

	assert.Equal(t, "wal", scalar[string](t, s, `PRAGMA journal_mode`))
	assert.Equal(t, 1, scalar[int](t, s, `PRAGMA foreign_keys`))
	assert.Equal(t, 10000, scalar[int](t, s, `PRAGMA busy_timeout`))
	assert.Equal(t, 2, scalar[int](t, s, `PRAGMA synchronous`), "2 is FULL")

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dir, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dir.Mode().Perm())

	custom := open(t, sqlitestore.Options{BusyTimeout: 2 * time.Second})
	assert.Equal(t, 2000, scalar[int](t, custom, `PRAGMA busy_timeout`))
}

func TestOpenRejectsBadOptions(t *testing.T) {
	ctx := t.Context()
	_, err := sqlitestore.Open(ctx, sqlitestore.Options{})
	require.Error(t, err, "a path is required")
	_, err = sqlitestore.Open(ctx, sqlitestore.Options{Path: dbPath(t), Cascades: []store.Cascade{nil}})
	require.Error(t, err, "a nil cascade")
	_, err = sqlitestore.Open(ctx, sqlitestore.Options{Path: dbPath(t), Migrations: []sqlitestore.Migration{
		{Version: 2, Name: "b", SQL: "SELECT 1"}, {Version: 1, Name: "a", SQL: "SELECT 1"},
	}})
	require.Error(t, err, "versions must increase")
	_, err = sqlitestore.Open(ctx, sqlitestore.Options{Path: dbPath(t), Migrations: []sqlitestore.Migration{{Version: 0, SQL: "SELECT 1"}}})
	require.Error(t, err, "versions must be positive")
	_, err = sqlitestore.Open(ctx, sqlitestore.Options{Path: dbPath(t), Migrations: []sqlitestore.Migration{{Version: 1}}})
	require.Error(t, err, "a step needs SQL")
}

func TestMigrations(t *testing.T) {
	ctx := t.Context()
	path := dbPath(t)
	log, rec := testlog.New()
	versions := func(s *sqlitestore.Store, component string) []int {
		rows, err := s.Conn(ctx).QueryContext(ctx, `SELECT version FROM gk_schema_migrations WHERE component = ? ORDER BY version`, component)
		require.NoError(t, err)
		defer func() { _ = rows.Close() }()
		var out []int
		for rows.Next() {
			var v int
			require.NoError(t, rows.Scan(&v))
			out = append(out, v)
		}
		require.NoError(t, rows.Err())
		return out
	}
	app1 := sqlitestore.Migration{Version: 1, Name: "notes", SQL: `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL) STRICT;`}
	app2 := sqlitestore.Migration{Version: 2, Name: "notes author", SQL: `
		ALTER TABLE notes ADD COLUMN author TEXT NOT NULL DEFAULT '';
		CREATE INDEX notes_author ON notes (author);`}

	// A fresh file gets the gatekeeper's schema and the application's first step.
	s, err := sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Migrations: []sqlitestore.Migration{app1}, Logger: log})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2}, versions(s, "gatekeeper"))
	assert.Equal(t, []int{1}, versions(s, "app"))
	assert.Len(t, rec.Records(), 3, "one log line per applied step")
	require.NoError(t, s.Accounts().Create(ctx, core.Account{ID: "acc_1", Name: "A", CreatedAt: time.Now()}))
	_, err = s.Conn(ctx).ExecContext(ctx, `INSERT INTO notes (body) VALUES ('kept')`)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	// Reopening applies nothing again and keeps the data.
	rec2log, rec2 := testlog.New()
	s, err = sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Migrations: []sqlitestore.Migration{app1}, Logger: rec2log})
	require.NoError(t, err)
	assert.Empty(t, rec2.Records())
	assert.Equal(t, 1, scalar[int](t, s, `SELECT COUNT(*) FROM notes`))
	_, err = s.Accounts().Get(ctx, "acc_1")
	require.NoError(t, err)
	require.NoError(t, s.Close())

	// A newer build adds a step: only that one runs, on the existing data.
	s, err = sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Migrations: []sqlitestore.Migration{app1, app2}})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2}, versions(s, "app"))
	assert.Equal(t, "kept", scalar[string](t, s, `SELECT body FROM notes`))
	require.NoError(t, s.Close())

	// An older build refuses the database its successor migrated.
	_, err = sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Migrations: []sqlitestore.Migration{app1}})
	require.ErrorContains(t, err, "newer than this build supports")

	// A build that knows no application steps does not look at the application's version line.
	s, err = sqlitestore.Open(ctx, sqlitestore.Options{Path: path})
	require.NoError(t, err)
	require.NoError(t, s.Close())
}

func TestMigrationIsAtomic(t *testing.T) {
	ctx := t.Context()
	path := dbPath(t)
	bad := sqlitestore.Migration{Version: 1, Name: "half", SQL: `CREATE TABLE half (id INTEGER); INSERT INTO nowhere VALUES (1);`}
	_, err := sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Migrations: []sqlitestore.Migration{bad}})
	require.ErrorContains(t, err, "app migration 1 (half)")

	// The failed step left nothing behind: the fixed step applies cleanly.
	good := sqlitestore.Migration{Version: 1, Name: "whole", SQL: `CREATE TABLE half (id INTEGER);`}
	s, err := sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Migrations: []sqlitestore.Migration{good}})
	require.NoError(t, err)
	require.NoError(t, s.Close())
}

func TestDatabaseFromTheFutureIsRefused(t *testing.T) {
	ctx := t.Context()
	path := dbPath(t)
	s := open(t, sqlitestore.Options{Path: path})
	_, err := s.Conn(ctx).ExecContext(ctx, `INSERT INTO gk_schema_migrations (component, version, name, applied_at) VALUES ('gatekeeper', 99, 'later', 0)`)
	require.NoError(t, err)
	require.NoError(t, s.Close())
	_, err = sqlitestore.Open(ctx, sqlitestore.Options{Path: path})
	require.ErrorContains(t, err, "gatekeeper schema of the database is at version 99")
}

// notesStore opens a store with an application table next to the gatekeeper's.
func notesStore(t *testing.T, cascades ...store.Cascade) *sqlitestore.Store {
	t.Helper()
	return open(t, sqlitestore.Options{Cascades: cascades, Migrations: []sqlitestore.Migration{{
		Version: 1, Name: "notes",
		SQL: `CREATE TABLE notes (id INTEGER PRIMARY KEY, account_id TEXT NOT NULL, body TEXT NOT NULL) STRICT;
		      CREATE TABLE note_tags (note_id INTEGER NOT NULL REFERENCES notes (id), tag TEXT NOT NULL) STRICT;`,
	}}})
}

func countNotes(ctx context.Context, t *testing.T, s *sqlitestore.Store) int {
	t.Helper()
	var n int
	require.NoError(t, s.Conn(ctx).QueryRowContext(ctx, `SELECT COUNT(*) FROM notes`).Scan(&n))
	return n
}

func TestConnJoinsTransaction(t *testing.T) {
	ctx := t.Context()
	s := notesStore(t)
	acc := core.Account{ID: "acc_1", Name: "A", CreatedAt: time.Now().UTC().Truncate(time.Millisecond)}

	// Commit: the gatekeeper's row and the application's land together, and the transaction sees both.
	require.NoError(t, s.Tx(ctx, func(ctx context.Context) error {
		if err := s.Accounts().Create(ctx, acc); err != nil {
			return err
		}
		if _, err := s.Conn(ctx).ExecContext(ctx, `INSERT INTO notes (account_id, body) VALUES (?, 'hello')`, acc.ID); err != nil {
			return err
		}
		return s.Tx(ctx, func(ctx context.Context) error { // a nested Tx joins
			if got := countNotes(ctx, t, s); got != 1 {
				return fmt.Errorf("the transaction sees %d notes, want 1", got)
			}
			_, err := s.Conn(ctx).ExecContext(ctx, `INSERT INTO notes (account_id, body) VALUES (?, 'second')`, acc.ID)
			return err
		})
	}))
	assert.Equal(t, 2, countNotes(ctx, t, s))

	// Rollback: an error after the application's write undoes it and the gatekeeper's write.
	err := s.Tx(ctx, func(ctx context.Context) error {
		if err := s.Accounts().Create(ctx, core.Account{ID: "acc_2", Name: "B", CreatedAt: acc.CreatedAt}); err != nil {
			return err
		}
		if _, err := s.Conn(ctx).ExecContext(ctx, `INSERT INTO notes (account_id, body) VALUES ('acc_2', 'lost')`); err != nil {
			return err
		}
		return errBoom
	})
	require.ErrorIs(t, err, errBoom)
	assert.Equal(t, 2, countNotes(ctx, t, s))
	_, err = s.Accounts().Get(ctx, "acc_2")
	assert.ErrorIs(t, err, core.ErrNotFound)

	// An uncommitted note is invisible outside the transaction, and Conn without a transaction reads the database.
	inside, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.Tx(ctx, func(ctx context.Context) error {
			if _, err := s.Conn(ctx).ExecContext(ctx, `INSERT INTO notes (account_id, body) VALUES ('acc_1', 'pending')`); err != nil {
				return err
			}
			close(inside)
			<-release
			return nil
		})
	}()
	<-inside
	assert.Equal(t, 2, countNotes(ctx, t, s), "a reader outside the transaction sees the last commit and does not wait")
	close(release)
	require.NoError(t, <-done)
	assert.Equal(t, 3, countNotes(ctx, t, s))

	// Foreign keys are on for the application's tables.
	_, err = s.Conn(ctx).ExecContext(ctx, `INSERT INTO note_tags (note_id, tag) VALUES (999, 'orphan')`)
	require.ErrorContains(t, err, "FOREIGN KEY")
}

// notesCascade deletes the application's notes of an account from inside the store's delete transaction.
type notesCascade struct {
	s    *sqlitestore.Store
	fail error
}

func (c *notesCascade) DeleteAccount(ctx context.Context, a core.AccountID) error {
	if _, err := c.s.Conn(ctx).ExecContext(ctx, `DELETE FROM notes WHERE account_id = ?`, a); err != nil {
		return err
	}
	return c.fail
}

func (*notesCascade) DeletePerson(context.Context, core.PersonID) error { return nil }

func TestCascadeUsesTheDeleteTransaction(t *testing.T) {
	ctx := t.Context()
	cascade := &notesCascade{}
	s := notesStore(t, cascade)
	cascade.s = s
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, id := range []core.AccountID{"acc_1", "acc_2"} {
		require.NoError(t, s.Accounts().Create(ctx, core.Account{ID: id, Name: string(id), CreatedAt: now}))
		_, err := s.Conn(ctx).ExecContext(ctx, `INSERT INTO notes (account_id, body) VALUES (?, 'x')`, id)
		require.NoError(t, err)
	}

	cascade.fail = errBoom
	require.ErrorIs(t, s.Accounts().Delete(ctx, "acc_1"), errBoom)
	assert.Equal(t, 2, countNotes(ctx, t, s), "the cascade's own delete rolled back with the account")
	_, err := s.Accounts().Get(ctx, "acc_1")
	require.NoError(t, err)

	cascade.fail = nil
	require.NoError(t, s.Accounts().Delete(ctx, "acc_1"))
	assert.Equal(t, 1, countNotes(ctx, t, s))
}

func TestWriteTransactionsAreSerialized(t *testing.T) {
	ctx := t.Context()
	s := notesStore(t)
	_, err := s.Conn(ctx).ExecContext(ctx, `CREATE TABLE counter (n INTEGER NOT NULL)`)
	require.NoError(t, err)
	_, err = s.Conn(ctx).ExecContext(ctx, `INSERT INTO counter VALUES (0)`)
	require.NoError(t, err)

	// A read-then-write transaction loses no update and never sees SQLITE_BUSY.
	const n = 40
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			errs[i] = s.Tx(ctx, func(ctx context.Context) error {
				var cur int
				if err := s.Conn(ctx).QueryRowContext(ctx, `SELECT n FROM counter`).Scan(&cur); err != nil {
					return err
				}
				_, err := s.Conn(ctx).ExecContext(ctx, `UPDATE counter SET n = ?`, cur+1)
				return err
			})
		})
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, n, scalar[int](t, s, `SELECT n FROM counter`))
}

func TestTwoStoresOnOneFile(t *testing.T) {
	ctx := t.Context()
	path := dbPath(t)
	a := open(t, sqlitestore.Options{Path: path})
	b := open(t, sqlitestore.Options{Path: path})
	const each = 25
	var wg sync.WaitGroup
	errs := make([]error, 2*each)
	for i := range each {
		for j, s := range []*sqlitestore.Store{a, b} {
			wg.Go(func() {
				errs[2*i+j] = s.Accounts().Create(ctx, core.Account{ID: core.AccountID(fmt.Sprint("acc_", i, "_", j)), Name: "x",
					CreatedAt: time.Now()})
			})
		}
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err, "the busy timeout covers a writer in another store")
	}
	list, err := a.Accounts().List(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 2*each)
}

func TestWaitingForTheWriteLockHonoursTheContext(t *testing.T) {
	ctx := t.Context()
	s := open(t, sqlitestore.Options{})
	inside, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.Tx(ctx, func(context.Context) error {
			close(inside)
			<-release
			return nil
		})
	}()
	<-inside
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	err := s.Tx(waitCtx, func(context.Context) error { return errors.New("must not run") })
	require.ErrorIs(t, err, context.DeadlineExceeded)
	err = s.Accounts().Create(waitCtx, core.Account{ID: "acc_x", CreatedAt: time.Now()})
	require.ErrorIs(t, err, context.DeadlineExceeded, "a store write waits the same way")
	close(release)
	require.NoError(t, <-done)
	require.NoError(t, s.Tx(ctx, func(context.Context) error { return nil }), "the lock is free again")
}

func TestPanicInTxRollsBackAndReleasesTheLock(t *testing.T) {
	ctx := t.Context()
	s := open(t, sqlitestore.Options{})
	require.PanicsWithValue(t, "oops", func() {
		_ = s.Tx(ctx, func(ctx context.Context) error {
			if err := s.Accounts().Create(ctx, core.Account{ID: "acc_p", CreatedAt: time.Now()}); err != nil {
				return err
			}
			panic("oops")
		})
	})
	_, err := s.Accounts().Get(ctx, "acc_p")
	require.ErrorIs(t, err, core.ErrNotFound)
	require.NoError(t, s.Accounts().Create(ctx, core.Account{ID: "acc_p", CreatedAt: time.Now()}))
}

func TestATransactionOfAnotherStoreIsNotJoined(t *testing.T) {
	ctx := t.Context()
	a, b := open(t, sqlitestore.Options{}), open(t, sqlitestore.Options{})
	require.NoError(t, a.Tx(ctx, func(ctxA context.Context) error {
		// b gets a's context but does not mistake a's transaction for its own: it opens its own.
		return b.Accounts().Create(ctxA, core.Account{ID: "acc_b", CreatedAt: time.Now()})
	}))
	_, err := b.Accounts().Get(ctx, "acc_b")
	require.NoError(t, err)
}

func TestErrorsAreWrapped(t *testing.T) {
	ctx := t.Context()
	s := open(t, sqlitestore.Options{})
	acc := core.Account{ID: "acc_1", Name: "A", CreatedAt: time.Now()}
	require.NoError(t, s.Accounts().Create(ctx, acc))
	err := s.Accounts().Create(ctx, acc)
	require.ErrorIs(t, err, core.ErrConflict)
	assert.Contains(t, err.Error(), "sqlitestore: create account")
	_, err = s.Accounts().Get(ctx, "acc_none")
	require.ErrorIs(t, err, core.ErrNotFound)
	assert.NotErrorIs(t, err, core.ErrConflict)
}

func TestTimesComeBackInUTC(t *testing.T) {
	ctx := t.Context()
	s := open(t, sqlitestore.Options{})
	at := time.Date(2026, 11, 24, 12, 30, 15, 123_456_789, time.FixedZone("X", 3*3600))
	require.NoError(t, s.Accounts().Create(ctx, core.Account{ID: "acc_1", CreatedAt: at}))
	got, err := s.Accounts().Get(ctx, "acc_1")
	require.NoError(t, err)
	assert.Equal(t, time.UTC, got.CreatedAt.Location())
	assert.Equal(t, at.Truncate(time.Millisecond).UTC(), got.CreatedAt)
}

var auditIDPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)

func TestAuditIDsSortByTime(t *testing.T) {
	ctx := t.Context()
	// A clock that stands still, then steps back: ids must still rise.
	var (
		mu  sync.Mutex
		now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	s := open(t, sqlitestore.Options{Clock: clock})
	const n = 300
	for i := range n {
		if i == 100 {
			mu.Lock()
			now = now.Add(time.Second)
			mu.Unlock()
		}
		if i == 200 {
			mu.Lock()
			now = now.Add(-time.Hour)
			mu.Unlock()
		}
		require.NoError(t, s.Audit().Append(ctx, core.AuditEntry{At: now, Action: fmt.Sprint("n", i)}))
	}
	list, err := s.Audit().ListSystem(ctx, "", 1000)
	require.NoError(t, err)
	require.Len(t, list, n)
	for i, e := range list {
		assert.Regexp(t, auditIDPattern, e.ID)
		assert.Equal(t, fmt.Sprint("n", n-1-i), e.Action, "newest first, in append order")
		if i > 0 {
			assert.Greater(t, list[i-1].ID, e.ID)
		}
	}
	// The first eight bytes hold the milliseconds of the clock at the time of the append.
	assert.Equal(t, fmt.Sprintf("%016x", uint64(time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC).UnixMilli())<<16), list[n-1].ID[:16])

	// A cursor in upper case is the same id; one of the wrong length or alphabet is an error.
	page, err := s.Audit().ListSystem(ctx, upper(list[10].ID), 2)
	require.NoError(t, err)
	require.Len(t, page, 2)
	assert.Equal(t, list[11].ID, page[0].ID)
	for _, bad := range []string{"abc", list[0].ID + "00", "zzzzzzzzzzzzzzzzzzzzzzzz"} {
		_, err := s.Audit().ListSystem(ctx, bad, 2)
		require.Error(t, err, bad)
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// TestConformanceOnAFileWithApplicationTables runs the suite on stores that carry an application's schema, to be sure
// the extra tables and migration lines change nothing.
func TestConformanceOnAFileWithApplicationTables(t *testing.T) {
	storetest.Run(t, func(t *testing.T, cascades ...store.Cascade) store.Store {
		return notesStore(t, cascades...)
	})
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Mode().Perm()
}

func modeWarnings(rec *testlog.Recorder) []testlog.Record {
	var out []testlog.Record
	for _, r := range rec.Records() {
		if r.Level == slog.LevelWarn && r.Message == modeMessage {
			out = append(out, r)
		}
	}
	return out
}

const modeMessage = "sqlitestore: file mode corrected"

// A database that is already there with loose modes is tightened, and Open says so; a file that is right is left alone
// and silent (GK-8).
func TestOpenTightensModes(t *testing.T) {
	ctx := t.Context()
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "gatekeeper.db")
	require.NoError(t, os.Mkdir(dir, 0o755))           //nolint:gosec // a loose directory is the point of the test
	require.NoError(t, os.WriteFile(path, nil, 0o644)) //nolint:gosec // so is a loose file
	require.NoError(t, os.Chmod(dir, 0o755))           //nolint:gosec // the umask may have narrowed it

	log, rec := testlog.New()
	s, err := sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Logger: log})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	assert.Equal(t, os.FileMode(0o700), modeOf(t, dir))
	assert.Equal(t, os.FileMode(0o600), modeOf(t, path))
	warned := modeWarnings(rec)
	require.Len(t, warned, 2, "the directory and the file")
	assert.Equal(t, dir, warned[0].Attrs["path"])
	assert.Equal(t, "-rwxr-xr-x", warned[0].Attrs["was"])
	assert.Equal(t, path, warned[1].Attrs["path"])

	// The -wal and -shm of a database that is open are tightened by the next Open on the file, and those it creates
	// itself are 0600 from the start.
	for _, suffix := range []string{"-wal", "-shm"} {
		assert.Equal(t, os.FileMode(0o600), modeOf(t, path+suffix), suffix)
		require.NoError(t, os.Chmod(path+suffix, 0o666)) //nolint:gosec // loosened on purpose
	}
	log2, rec2 := testlog.New()
	second, err := sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Logger: log2})
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Close() })
	for _, suffix := range []string{"-wal", "-shm"} {
		assert.Equal(t, os.FileMode(0o600), modeOf(t, path+suffix), suffix)
	}
	assert.Len(t, modeWarnings(rec2), 2, "the -wal and the -shm")

	// Nothing to correct, nothing said.
	log3, rec3 := testlog.New()
	third, err := sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Logger: log3})
	require.NoError(t, err)
	t.Cleanup(func() { _ = third.Close() })
	assert.Empty(t, modeWarnings(rec3))
}

// A shared directory with another mode (a home directory, /tmp, a volume root) is never chmodded: Open refuses it and
// says why (review R-8). A directory Open creates inside one is the database's own; a 0700 one is used as it is.
func TestOpenLeavesASharedDirectoryAlone(t *testing.T) {
	ctx := t.Context()
	shared := filepath.Join(t.TempDir(), "shared")
	require.NoError(t, os.Mkdir(shared, 0o755)) //nolint:gosec // a shared directory is the point of the test
	require.NoError(t, os.Chmod(shared, 0o755)) //nolint:gosec // the umask may have narrowed it
	require.NoError(t, os.WriteFile(filepath.Join(shared, "notes.txt"), []byte("x"), 0o600))

	log, rec := testlog.New()
	_, err := sqlitestore.Open(ctx, sqlitestore.Options{Path: filepath.Join(shared, "gatekeeper.db"), Logger: log})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "the database's directory "+shared+" has mode -rwxr-xr-x, not 0700, and it holds "+
		"other files (notes.txt), so Open will not change it: use a directory of its own for the database")
	assert.Equal(t, os.FileMode(0o755), modeOf(t, shared))
	assert.NoFileExists(t, filepath.Join(shared, "gatekeeper.db"), "nothing is created there")
	assert.Empty(t, modeWarnings(rec))

	// A directory of its own inside the shared one: created 0700, the shared one untouched.
	path := filepath.Join(shared, "app", "data", "gatekeeper.db")
	open(t, sqlitestore.Options{Path: path, Logger: log})
	assert.Equal(t, os.FileMode(0o700), modeOf(t, filepath.Dir(path)))
	assert.Equal(t, os.FileMode(0o755), modeOf(t, shared))
	assert.Empty(t, modeWarnings(rec))

	// A 0700 directory that also holds the application's own files is fine as it is.
	own := filepath.Join(t.TempDir(), "own")
	require.NoError(t, os.Mkdir(own, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(own, "app.yaml"), []byte("x"), 0o600))
	open(t, sqlitestore.Options{Path: filepath.Join(own, "gatekeeper.db"), Logger: log})
	assert.Equal(t, os.FileMode(0o700), modeOf(t, own))
	assert.Empty(t, modeWarnings(rec))
}

// The database's own loose directory, empty or holding only its files (a leftover -wal, -shm or -journal included),
// is tightened with a warning.
func TestOpenTightensItsOwnDirectory(t *testing.T) {
	for name, files := range map[string][]string{
		"empty":         nil,
		"its own files": {"gatekeeper.db", "gatekeeper.db-wal", "gatekeeper.db-shm", "gatekeeper.db-journal"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			require.NoError(t, os.Mkdir(dir, 0o755)) //nolint:gosec // a loose directory is the point of the test
			require.NoError(t, os.Chmod(dir, 0o755)) //nolint:gosec // the umask may have narrowed it
			for _, f := range files {
				require.NoError(t, os.WriteFile(filepath.Join(dir, f), nil, 0o600))
			}
			log, rec := testlog.New()
			open(t, sqlitestore.Options{Path: filepath.Join(dir, "gatekeeper.db"), Logger: log})
			assert.Equal(t, os.FileMode(0o700), modeOf(t, dir))
			warned := modeWarnings(rec)
			require.NotEmpty(t, warned)
			assert.Equal(t, dir, warned[0].Attrs["path"])
		})
	}
}

// A new database is created with the right modes and nothing to warn about.
func TestOpenCreatesWithModes(t *testing.T) {
	log, rec := testlog.New()
	path := dbPath(t)
	open(t, sqlitestore.Options{Path: path, Logger: log})
	assert.Equal(t, os.FileMode(0o700), modeOf(t, filepath.Dir(path)))
	assert.Equal(t, os.FileMode(0o600), modeOf(t, path))
	assert.Empty(t, modeWarnings(rec))
}

// The audit ids keep rising across a restart, even when the clock is behind the ids already stored (GK-9).
func TestAuditIDsContinueAfterReopen(t *testing.T) {
	ctx := t.Context()
	path := dbPath(t)
	ahead := time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	first, err := sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Clock: func() time.Time { return ahead }})
	require.NoError(t, err)
	for i := range 3 {
		require.NoError(t, first.Audit().Append(ctx, core.AuditEntry{At: ahead, Action: fmt.Sprint("before", i)}))
	}
	require.NoError(t, first.Close())

	behind := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	second := open(t, sqlitestore.Options{Path: path, Clock: func() time.Time { return behind }})
	for i := range 3 {
		require.NoError(t, second.Audit().Append(ctx, core.AuditEntry{At: behind, Action: fmt.Sprint("after", i)}))
	}
	list, err := second.Audit().ListSystem(ctx, "", 10)
	require.NoError(t, err)
	var actions []string
	for _, e := range list {
		actions = append(actions, e.Action)
	}
	assert.Equal(t, []string{"after2", "after1", "after0", "before2", "before1", "before0"}, actions,
		"newest first: what was appended after the restart is newer")
}

// An empty audit table, or one with an id that is not ours, does not stop Open.
func TestAuditSeedIgnoresForeignIDs(t *testing.T) {
	ctx := t.Context()
	path := dbPath(t)
	s := open(t, sqlitestore.Options{Path: path})
	_, err := s.Conn(ctx).ExecContext(ctx, `INSERT INTO gk_audit (id, at, action) VALUES ('zzz', 0, 'foreign')`)
	require.NoError(t, err)
	require.NoError(t, s.Close())
	again := open(t, sqlitestore.Options{Path: path})
	require.NoError(t, again.Audit().Append(ctx, core.AuditEntry{At: time.Now(), Action: "mine"}))
}

// A database written by the first schema is upgraded in place: the rows stay, read as people and invites without a
// term or permissions, and the new columns work.
func TestMigrationToTheAccessColumns(t *testing.T) {
	ctx := t.Context()
	path := dbPath(t)
	s := open(t, sqlitestore.Options{Path: path})
	now := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, s.Accounts().Create(ctx, core.Account{ID: "acc_1", Name: "Home", CreatedAt: now}))
	require.NoError(t, s.People().Create(ctx, core.Person{ID: "per_1", AccountID: "acc_1", Name: "Alice", Role: core.RoleOwner, CreatedAt: now}))
	require.NoError(t, s.Invites().Create(ctx, core.Invite{ID: "inv_1", TokenHash: []byte("tok"), Kind: core.InviteMember,
		AccountID: "acc_1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
	// Put the file back to what the first build left: no access columns, no audit index, version 2 not recorded.
	for _, stmt := range []string{
		`DROP INDEX gk_audit_at`,
		`ALTER TABLE gk_people DROP COLUMN access_until`, `ALTER TABLE gk_people DROP COLUMN permissions`,
		`ALTER TABLE gk_invites DROP COLUMN access_until`, `ALTER TABLE gk_invites DROP COLUMN permissions`,
		`DELETE FROM gk_schema_migrations WHERE component = 'gatekeeper' AND version = 2`,
	} {
		_, err := s.Conn(ctx).ExecContext(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	require.NoError(t, s.Close())

	log, rec := testlog.New()
	up, err := sqlitestore.Open(ctx, sqlitestore.Options{Path: path, Logger: log})
	require.NoError(t, err)
	t.Cleanup(func() { _ = up.Close() })
	require.Len(t, rec.Records(), 1, "only the second step runs")
	assert.Equal(t, "2", rec.Records()[0].Attrs["version"])

	p, err := up.People().Get(ctx, "per_1")
	require.NoError(t, err)
	assert.Equal(t, core.Person{ID: "per_1", AccountID: "acc_1", Name: "Alice", Role: core.RoleOwner, CreatedAt: now}, p)
	inv, err := up.Invites().Peek(ctx, []byte("tok"), now)
	require.NoError(t, err)
	assert.Nil(t, inv.AccessUntil)
	assert.Nil(t, inv.Permissions)
	until := now.Add(time.Hour)
	require.NoError(t, up.People().SetAccess(ctx, "per_1", &until, []string{core.PermissionAll}))
	p, err = up.People().Get(ctx, "per_1")
	require.NoError(t, err)
	assert.Equal(t, []string{core.PermissionAll}, p.Permissions)
}

// Purge runs in one transaction with the caller's context and rolls back with it.
func TestPurgeJoinsTheTransaction(t *testing.T) {
	ctx := t.Context()
	s := open(t, sqlitestore.Options{})
	now := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, s.OAuth().PutToken(ctx, core.Token{Hash: []byte("t"), GrantID: "g", Kind: core.TokenAccess, CreatedAt: now,
		ExpiresAt: now.Add(-time.Hour)}))
	err := s.Tx(ctx, func(ctx context.Context) error {
		st, err := s.Purge(ctx, now)
		require.NoError(t, err)
		assert.Equal(t, 1, st.Tokens)
		return errBoom
	})
	require.ErrorIs(t, err, errBoom)
	_, err = s.OAuth().GetToken(ctx, []byte("t"))
	require.NoError(t, err, "the rollback brought the token back")
	st, err := s.Purge(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, store.PurgeStats{Tokens: 1}, st)
}
