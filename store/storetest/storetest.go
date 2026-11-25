// Package storetest is the one conformance suite of store.Store. Every adapter (mongostore, sqlitestore) runs it from
// its own tests:
//
//	func TestConformance(t *testing.T) {
//		storetest.Run(t, func(t *testing.T, cascades ...store.Cascade) store.Store { ... })
//	}
//
// The suite pins the semantics of Family Hub's MongoDB store (docs/PLAN.md §4.2), so the adapters are interchangeable:
//   - times are kept at least to the millisecond and come back in UTC (the suite truncates to the millisecond);
//   - a write to one entity that does not exist returns core.ErrNotFound, except deleting a session and the bulk
//     operations (DeleteByPerson, RevokeKind, RevokeGrantsByResource, RevokeFamily, Delete*Expired*), which are
//     idempotent;
//   - inserting an id or another unique key that exists returns core.ErrConflict, except the Put methods, which
//     replace; a second active grant of the same (person, client, resource) is core.ErrConflict too;
//   - Revoke* methods are idempotent: the first revocation time wins;
//   - an expiry is reached when ExpiresAt <= now; a session is idle when LastSeenAt < now - idle;
//   - lists are oldest first (by creation time, then id); the audit is newest first, by its store-assigned id, and a
//     cursor that is not an audit id is an error; a limit <= 0 means 50 and a limit above 1000 means 1000;
//   - AccountStore.Delete runs Cascade.DeletePerson for every person of the account, then Cascade.DeleteAccount;
//     PersonStore.Delete runs Cascade.DeletePerson. Every Cascade runs inside the delete's transaction, and an error
//     from one rolls the whole delete back;
//   - a person and an invite keep an access term (AccessUntil) and permission ids; no permissions (nil or empty) read
//     back as nil, and SetAccess replaces both, clearing what it is given nothing for;
//   - an adapter that implements store.Purger (it has no TTL indexes) deletes with Purge what the TTL indexes of the
//     MongoDB adapter would: see the Purge test for the retention. Adapters without a Purger skip that test;
//   - Tx: commit, rollback on an error from fn, a Tx inside a Tx joins the outer one, and a write inside an open
//     transaction is invisible to a reader outside it until the commit (a reader outside never waits for it).
//
// Each test opens its own store, and the tests run in parallel.
package storetest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// Open returns a new, empty store with cascades registered. It arranges (with t.Cleanup) for the store to be closed
// and its data removed when the test ends.
type Open func(t *testing.T, cascades ...store.Cascade) store.Store

// Run runs the whole suite against the stores open makes.
func Run(t *testing.T, open Open) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(t *testing.T, open Open)
	}{
		{"Accounts", testAccounts},
		{"People", testPeople},
		{"PersonAccess", testPersonAccess},
		{"Passkeys", testPasskeys},
		{"Sessions", testSessions},
		{"Invites", testInvites},
		{"InviteAccess", testInviteAccess},
		{"InviteConsumeConcurrent", testInviteConsumeConcurrent},
		{"OAuthClients", testOAuthClients},
		{"OAuthCodes", testOAuthCodes},
		{"ConsumeCodeConcurrent", testConsumeCodeConcurrent},
		{"OAuthGrantsAndTokens", testOAuthGrantsAndTokens},
		{"RevokeGrantsByResource", testRevokeGrantsByResource},
		{"UseRefresh", testUseRefresh},
		{"UseRefreshConcurrent", testUseRefreshConcurrent},
		{"Purge", testPurge},
		{"Audit", testAudit},
		{"AuditLimits", testAuditLimits},
		{"Tx", testTx},
		{"TxIsolation", testTxIsolation},
		{"TxConflicts", testTxConflicts},
		{"DeleteCascades", testDeleteCascades},
		{"CascadeHooks", testCascadeHooks},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.fn(t, open)
		})
	}
}

// Call is one call of a Cascade: Account is set for DeleteAccount, Person for DeletePerson.
type Call struct {
	Account core.AccountID
	Person  core.PersonID
}

// Recorder is a store.Cascade that records every call and runs an optional hook with the call's context, so a test
// can write through the store inside the delete's transaction or make the cascade fail.
type Recorder struct {
	mu    sync.Mutex
	calls []Call
	hook  func(ctx context.Context, c Call) error
}

var _ store.Cascade = (*Recorder)(nil)

// DeleteAccount implements store.Cascade.
func (r *Recorder) DeleteAccount(ctx context.Context, a core.AccountID) error {
	return r.record(ctx, Call{Account: a})
}

// DeletePerson implements store.Cascade.
func (r *Recorder) DeletePerson(ctx context.Context, p core.PersonID) error {
	return r.record(ctx, Call{Person: p})
}

func (r *Recorder) record(ctx context.Context, c Call) error {
	r.mu.Lock()
	r.calls = append(r.calls, c)
	hook := r.hook
	r.mu.Unlock()
	if hook == nil {
		return nil
	}
	return hook(ctx, c)
}

// SetHook sets the function every later call runs (nil: none).
func (r *Recorder) SetHook(fn func(ctx context.Context, c Call) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hook = fn
}

// Calls returns the distinct calls so far, in the order of their first appearance. A store may run a transaction
// again after a transient error, so a call may happen more than once.
func (r *Recorder) Calls() []Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Call
	for _, c := range r.calls {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// Reset forgets the recorded calls.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = nil
}

// ms returns now in UTC at the precision every adapter keeps.
func ms() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// hash makes a fake sha256 for a name.
func hash(s string) []byte { return []byte("hash-" + s) }

func seedAccount(t *testing.T, s store.Store, name string) core.Account {
	t.Helper()
	a := core.Account{ID: core.AccountID(core.NewID(core.PrefixAccount)), Name: name, CreatedAt: ms()}
	require.NoError(t, s.Accounts().Create(t.Context(), a))
	return a
}

func seedPerson(t *testing.T, s store.Store, a core.AccountID, name string) core.Person {
	t.Helper()
	p := core.Person{
		ID: core.PersonID(core.NewID(core.PrefixPerson)), AccountID: a, Name: name, Role: core.RoleOwner,
		CreatedAt: ms(),
	}
	require.NoError(t, s.People().Create(t.Context(), p))
	return p
}

// race runs fn n times at once and returns the n results.
func race(n int, fn func(i int) error) []error {
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make([]error, n)
	)
	for i := range n {
		wg.Go(func() {
			<-start
			errs[i] = fn(i)
		})
	}
	close(start)
	wg.Wait()
	return errs
}

// assertOneWinner checks that exactly one call succeeded and every other one failed with loser.
func assertOneWinner(t *testing.T, errs []error, loser error) {
	t.Helper()
	var wins int
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, loser):
			t.Errorf("a losing call failed with %v, want %v", err, loser)
		}
	}
	assert.Equal(t, 1, wins, "exactly one concurrent call must win")
}

// gone reports whether err is core.ErrNotFound, failing the test on any other error.
func gone(t *testing.T, err error) bool {
	t.Helper()
	if errors.Is(err, core.ErrNotFound) {
		return true
	}
	require.NoError(t, err)
	return false
}
