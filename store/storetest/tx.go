package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

var errBoom = errors.New("boom")

func testTx(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)

	// Commit: both writes land, the transaction sees its own writes, and a nested Tx joins the outer one.
	a := core.Account{ID: "acc_tx1", Name: "One", CreatedAt: ms()}
	require.NoError(t, s.Tx(ctx, func(ctx context.Context) error {
		if err := s.Accounts().Create(ctx, a); err != nil {
			return err
		}
		if _, err := s.Accounts().Get(ctx, a.ID); err != nil {
			return err
		}
		return s.Tx(ctx, func(ctx context.Context) error {
			return s.Accounts().Rename(ctx, a.ID, "One!")
		})
	}))
	got, err := s.Accounts().Get(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, "One!", got.Name)

	// Rollback: an error from fn undoes everything, and is returned.
	err = s.Tx(ctx, func(ctx context.Context) error {
		if err := s.Accounts().Create(ctx, core.Account{ID: "acc_tx2", Name: "Two", CreatedAt: ms()}); err != nil {
			return err
		}
		if err := s.Audit().Append(ctx, core.AuditEntry{At: ms(), Action: "tx.test"}); err != nil {
			return err
		}
		return errBoom
	})
	require.ErrorIs(t, err, errBoom)
	_, err = s.Accounts().Get(ctx, "acc_tx2")
	assert.ErrorIs(t, err, core.ErrNotFound)
	sys, err := s.Audit().ListSystem(ctx, "", 10)
	require.NoError(t, err)
	assert.Empty(t, sys)

	// An error from a nested Tx, returned by the outer fn, rolls back the outer writes too.
	err = s.Tx(ctx, func(ctx context.Context) error {
		if err := s.Accounts().Create(ctx, core.Account{ID: "acc_tx4", Name: "Four", CreatedAt: ms()}); err != nil {
			return err
		}
		return s.Tx(ctx, func(ctx context.Context) error {
			if err := s.Accounts().Rename(ctx, a.ID, "changed"); err != nil {
				return err
			}
			return errBoom
		})
	})
	require.ErrorIs(t, err, errBoom)
	_, err = s.Accounts().Get(ctx, "acc_tx4")
	assert.ErrorIs(t, err, core.ErrNotFound)
	got, err = s.Accounts().Get(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, "One!", got.Name)

	// A store method that runs its own transaction joins the caller's one.
	p := seedPerson(t, s, a.ID, "Owner")
	err = s.Tx(ctx, func(ctx context.Context) error {
		if err := s.Accounts().Delete(ctx, a.ID); err != nil {
			return err
		}
		return errBoom
	})
	require.ErrorIs(t, err, errBoom)
	_, err = s.Accounts().Get(ctx, a.ID)
	require.NoError(t, err)
	_, err = s.People().Get(ctx, p.ID)
	require.NoError(t, err)

	// A store error inside Tx comes out wrapped as it was.
	err = s.Tx(ctx, func(ctx context.Context) error { return s.Accounts().Rename(ctx, "acc_missing", "x") })
	assert.ErrorIs(t, err, core.ErrNotFound)
}

// testTxIsolation checks that a write inside an open transaction is invisible outside until it commits, and that a
// reader outside does not wait for the transaction.
func testTxIsolation(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	inside, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		var once bool
		done <- s.Tx(ctx, func(ctx context.Context) error {
			if err := s.Accounts().Create(ctx, core.Account{ID: "acc_tx3", Name: "Three", CreatedAt: ms()}); err != nil {
				return err
			}
			if !once { // a store may run fn again after a transient error
				once = true
				close(inside)
			}
			<-release
			return nil
		})
	}()
	<-inside
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := s.Accounts().Get(readCtx, "acc_tx3")
	assert.ErrorIs(t, err, core.ErrNotFound)
	list, err := s.Accounts().List(readCtx)
	require.NoError(t, err)
	assert.Empty(t, list)
	close(release)
	require.NoError(t, <-done)
	_, err = s.Accounts().Get(ctx, "acc_tx3")
	assert.NoError(t, err)
}

// testTxConflicts runs many transactions that write the same row at once: every one of them must land (the store
// retries or serializes them).
func testTxConflicts(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	a := seedAccount(t, s, "start")
	const n = 12
	errs := race(n, func(i int) error {
		return s.Tx(ctx, func(ctx context.Context) error {
			return s.Accounts().Rename(ctx, a.ID, fmt.Sprint("name-", i))
		})
	})
	for _, err := range errs {
		assert.NoError(t, err)
	}
}

// testDeleteCascades builds two accounts with everything attached and checks that deleting one removes all of its
// rows and none of the other's, and that the registered Cascade hears of every person and the account.
func testDeleteCascades(t *testing.T, open Open) {
	ctx := t.Context()
	rec := &Recorder{}
	s := open(t, rec)
	now := ms()

	type fixture struct {
		acc    core.Account
		people []core.Person
	}
	build := func(name string) fixture {
		acc := seedAccount(t, s, name)
		f := fixture{acc: acc}
		for i := range 2 {
			p := seedPerson(t, s, acc.ID, fmt.Sprint(name, i))
			f.people = append(f.people, p)
			key := fmt.Sprint(name, i)
			require.NoError(t, s.Passkeys().Add(ctx, core.Passkey{ID: "pk_" + key, PersonID: p.ID, CredentialID: []byte(key),
				Data: []byte("{}"), CreatedAt: now}))
			require.NoError(t, s.Sessions().Create(ctx, core.Session{IDHash: hash("sess" + key), PersonID: p.ID, CreatedAt: now,
				LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}))
			g := core.Grant{ID: core.GrantID("grt_" + key), PersonID: p.ID, AccountID: acc.ID, ClientID: "cli_a",
				ResourceID: "notes", CreatedAt: now}
			require.NoError(t, s.OAuth().PutGrant(ctx, g))
			require.NoError(t, s.OAuth().PutToken(ctx, core.Token{Hash: hash("tok" + key), GrantID: g.ID, Kind: core.TokenAccess,
				Family: "f" + key, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
			require.NoError(t, s.OAuth().PutCode(ctx, core.AuthCode{CodeHash: hash("code" + key), GrantID: g.ID, ClientID: "cli_a",
				CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
		}
		require.NoError(t, s.Invites().Create(ctx, core.Invite{ID: "inv_" + name, TokenHash: hash("inv" + name),
			Kind: core.InviteMember, AccountID: acc.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
		require.NoError(t, s.Audit().Append(ctx, core.AuditEntry{At: now, AccountID: acc.ID, Actor: f.people[0].ID, Action: "test.seed"}))
		return f
	}
	doomed, kept := build("Doomed"), build("Kept")

	// present reports which rows of the fixture are left. Codes are checked by consuming them, so only at the end.
	present := func(name string, f fixture, withCodes bool) map[string]bool {
		out := map[string]bool{}
		_, err := s.Accounts().Get(ctx, f.acc.ID)
		out["account"] = !gone(t, err)
		inv, err := s.Invites().ListByAccount(ctx, f.acc.ID)
		require.NoError(t, err)
		out["invite"] = len(inv) > 0
		grants, err := s.OAuth().ListGrantsByAccount(ctx, f.acc.ID)
		require.NoError(t, err)
		out["grants of the account"] = len(grants) > 0
		for i, p := range f.people {
			key := fmt.Sprint(name, i)
			_, err = s.People().Get(ctx, p.ID)
			out["person "+key] = !gone(t, err)
			pk, err := s.Passkeys().ListByPerson(ctx, p.ID)
			require.NoError(t, err)
			out["passkey "+key] = len(pk) > 0
			_, err = s.Sessions().Get(ctx, hash("sess"+key))
			out["session "+key] = !gone(t, err)
			_, err = s.OAuth().GetGrant(ctx, core.GrantID("grt_"+key))
			out["grant "+key] = !gone(t, err)
			_, err = s.OAuth().GetToken(ctx, hash("tok"+key))
			out["token "+key] = !gone(t, err)
			if withCodes {
				_, err = s.OAuth().ConsumeCode(ctx, hash("code"+key), now)
				out["code "+key] = !gone(t, err)
			}
		}
		return out
	}
	for k, v := range present("Doomed", doomed, false) {
		require.True(t, v, "fixture %s", k)
	}

	require.NoError(t, s.Accounts().Delete(ctx, doomed.acc.ID))
	for k, v := range present("Doomed", doomed, true) {
		assert.False(t, v, "%s of the deleted account must be gone", k)
	}
	audit, err := s.Audit().ListByAccount(ctx, doomed.acc.ID, "", 10)
	require.NoError(t, err)
	assert.Len(t, audit, 1, "audit entries stay")

	calls := rec.Calls()
	require.Len(t, calls, 3)
	assert.ElementsMatch(t, []Call{{Person: doomed.people[0].ID}, {Person: doomed.people[1].ID}}, calls[:2],
		"DeletePerson for every person of the account")
	assert.Equal(t, Call{Account: doomed.acc.ID}, calls[2], "then DeleteAccount")

	// Deleting one person removes only their own rows.
	rec.Reset()
	second := kept.people[1]
	require.NoError(t, s.People().Delete(ctx, second.ID))
	assert.Equal(t, []Call{{Person: second.ID}}, rec.Calls())
	_, err = s.People().Get(ctx, second.ID)
	assert.ErrorIs(t, err, core.ErrNotFound)
	pk, err := s.Passkeys().ListByPerson(ctx, second.ID)
	require.NoError(t, err)
	assert.Empty(t, pk)
	_, err = s.Sessions().Get(ctx, hash("sessKept1"))
	assert.ErrorIs(t, err, core.ErrNotFound)
	_, err = s.OAuth().GetGrant(ctx, "grt_Kept1")
	assert.ErrorIs(t, err, core.ErrNotFound)
	_, err = s.OAuth().GetToken(ctx, hash("tokKept1"))
	assert.ErrorIs(t, err, core.ErrNotFound)
	_, err = s.OAuth().ConsumeCode(ctx, hash("codeKept1"), now)
	assert.ErrorIs(t, err, core.ErrNotFound)

	left := present("Kept", fixture{acc: kept.acc, people: kept.people[:1]}, true)
	for k, v := range left {
		assert.True(t, v, "%s of the other account must stay", k)
	}
}

// testCascadeHooks checks that every Cascade runs inside the delete's transaction: what it writes through the store
// with its context lands with the delete, and its error rolls back the delete and its own writes.
func testCascadeHooks(t *testing.T, open Open) {
	ctx := t.Context()
	rec := &Recorder{}
	s := open(t, rec)
	a := seedAccount(t, s, "A")
	p := seedPerson(t, s, a.ID, "P")

	marker := func(c Call) core.AccountID {
		return core.AccountID("acc_marker_" + string(c.Account) + string(c.Person))
	}
	write := func(ctx context.Context, c Call) error {
		return s.Accounts().Create(ctx, core.Account{ID: marker(c), Name: "marker", CreatedAt: ms()})
	}
	markers := func() []core.AccountID {
		list, err := s.Accounts().List(ctx)
		require.NoError(t, err)
		var out []core.AccountID
		for _, acc := range list {
			if acc.Name == "marker" {
				out = append(out, acc.ID)
			}
		}
		return out
	}

	// A failing cascade: its write and the whole delete roll back, and its error comes out.
	rec.SetHook(func(ctx context.Context, c Call) error {
		if err := write(ctx, c); err != nil {
			return err
		}
		return errBoom
	})
	require.ErrorIs(t, s.Accounts().Delete(ctx, a.ID), errBoom)
	require.ErrorIs(t, s.People().Delete(ctx, p.ID), errBoom)
	_, err := s.Accounts().Get(ctx, a.ID)
	require.NoError(t, err)
	_, err = s.People().Get(ctx, p.ID)
	require.NoError(t, err)
	assert.Empty(t, markers())

	// A failing DeleteAccount after a successful DeletePerson rolls back the person too.
	rec.SetHook(func(ctx context.Context, c Call) error {
		if err := write(ctx, c); err != nil {
			return err
		}
		if c.Account != "" {
			return errBoom
		}
		return nil
	})
	require.ErrorIs(t, s.Accounts().Delete(ctx, a.ID), errBoom)
	_, err = s.People().Get(ctx, p.ID)
	require.NoError(t, err)
	assert.Empty(t, markers())

	// A successful cascade: its writes land with the delete.
	rec.SetHook(write)
	require.NoError(t, s.People().Delete(ctx, p.ID))
	assert.Equal(t, []core.AccountID{marker(Call{Person: p.ID})}, markers())
	require.NoError(t, s.Accounts().Delete(ctx, a.ID))
	assert.ElementsMatch(t, []core.AccountID{marker(Call{Person: p.ID}), marker(Call{Account: a.ID})}, markers())

	// A delete inside a Tx that fails later rolls back with its cascades.
	b := seedAccount(t, s, "B")
	q := seedPerson(t, s, b.ID, "Q")
	err = s.Tx(ctx, func(ctx context.Context) error {
		if err := s.Accounts().Delete(ctx, b.ID); err != nil {
			return err
		}
		return errBoom
	})
	require.ErrorIs(t, err, errBoom)
	_, err = s.People().Get(ctx, q.ID)
	require.NoError(t, err)
	assert.Len(t, markers(), 2)
}
