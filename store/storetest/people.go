package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func testAccounts(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	a := core.Account{ID: "acc_a", Name: "Kowalski", CreatedAt: ms()}
	require.NoError(t, s.Accounts().Create(ctx, a))

	got, err := s.Accounts().Get(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, a, got)

	assert.ErrorIs(t, s.Accounts().Create(ctx, a), core.ErrConflict)
	_, err = s.Accounts().Get(ctx, "acc_missing")
	assert.ErrorIs(t, err, core.ErrNotFound)

	b := core.Account{ID: "acc_b", Name: "Nowak", CreatedAt: a.CreatedAt.Add(-time.Hour)}
	require.NoError(t, s.Accounts().Create(ctx, b))
	list, err := s.Accounts().List(ctx)
	require.NoError(t, err)
	assert.Equal(t, []core.Account{b, a}, list, "oldest first")

	require.NoError(t, s.Accounts().Rename(ctx, a.ID, "Kowalscy"))
	got, err = s.Accounts().Get(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, "Kowalscy", got.Name)
	assert.ErrorIs(t, s.Accounts().Rename(ctx, "acc_missing", "x"), core.ErrNotFound)
	assert.ErrorIs(t, s.Accounts().Delete(ctx, "acc_missing"), core.ErrNotFound)

	require.NoError(t, s.Accounts().Delete(ctx, b.ID))
	_, err = s.Accounts().Get(ctx, b.ID)
	assert.ErrorIs(t, err, core.ErrNotFound)
	list, err = s.Accounts().List(ctx)
	require.NoError(t, err)
	assert.Equal(t, []core.Account{{ID: a.ID, Name: "Kowalscy", CreatedAt: a.CreatedAt}}, list)

	// A time written in another zone comes back as the same instant in UTC.
	at := ms()
	z := core.Account{ID: "acc_z", Name: "Zone", CreatedAt: at.In(time.FixedZone("X", 3*3600))}
	require.NoError(t, s.Accounts().Create(ctx, z))
	got, err = s.Accounts().Get(ctx, z.ID)
	require.NoError(t, err)
	assert.Equal(t, time.UTC, got.CreatedAt.Location())
	assert.True(t, at.Equal(got.CreatedAt))
}

func testPeople(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	a := seedAccount(t, s, "Family")
	now := ms()
	root := core.Person{ID: "per_root", AccountID: a.ID, Name: "Alice", Role: core.RoleOwner, Superadmin: true, CreatedAt: now}
	member := core.Person{ID: "per_member", AccountID: a.ID, Name: "Bella", Role: core.RoleMember, CreatedAt: now.Add(-time.Minute)}
	require.NoError(t, s.People().Create(ctx, root))
	require.NoError(t, s.People().Create(ctx, member))

	got, err := s.People().Get(ctx, root.ID)
	require.NoError(t, err)
	assert.Equal(t, root, got)
	assert.Nil(t, got.DisabledAt)
	assert.ErrorIs(t, s.People().Create(ctx, root), core.ErrConflict)
	_, err = s.People().Get(ctx, "per_missing")
	assert.ErrorIs(t, err, core.ErrNotFound)

	list, err := s.People().ListByAccount(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, []core.Person{member, root}, list, "oldest first")
	empty, err := s.People().ListByAccount(ctx, "acc_other")
	require.NoError(t, err)
	assert.Empty(t, empty)

	n, err := s.People().CountSuperadmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	require.NoError(t, s.People().Rename(ctx, member.ID, "Tania"))
	at := ms()
	require.NoError(t, s.People().Disable(ctx, member.ID, at))
	got, err = s.People().Get(ctx, member.ID)
	require.NoError(t, err)
	assert.Equal(t, "Tania", got.Name)
	require.NotNil(t, got.DisabledAt)
	assert.True(t, at.Equal(*got.DisabledAt))
	assert.ErrorIs(t, s.People().Rename(ctx, "per_missing", "x"), core.ErrNotFound)
	assert.ErrorIs(t, s.People().Disable(ctx, "per_missing", at), core.ErrNotFound)
	assert.ErrorIs(t, s.People().Delete(ctx, "per_missing"), core.ErrNotFound)

	// A disabled superadmin still counts: the setup link must not replace them.
	require.NoError(t, s.People().Disable(ctx, root.ID, at))
	n, err = s.People().CountSuperadmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	// A person created disabled keeps the time.
	off := core.Person{ID: "per_off", AccountID: a.ID, Name: "Off", Role: core.RoleMember, CreatedAt: now, DisabledAt: &at}
	require.NoError(t, s.People().Create(ctx, off))
	got, err = s.People().Get(ctx, off.ID)
	require.NoError(t, err)
	assert.Equal(t, off, got)

	require.NoError(t, s.People().Delete(ctx, member.ID))
	_, err = s.People().Get(ctx, member.ID)
	assert.ErrorIs(t, err, core.ErrNotFound)
}

func testPersonAccess(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	a := seedAccount(t, s, "Family")
	now := ms()
	until := now.Add(48 * time.Hour)

	// A person created with a term and permissions reads back with both, in the order given, as UTC.
	guest := core.Person{ID: "per_guest", AccountID: a.ID, Name: "Carol", Role: core.RoleMember, CreatedAt: now,
		AccessUntil: &until, Permissions: []string{"plugin:tv", "plugin:lights"}}
	require.NoError(t, s.People().Create(ctx, guest))
	got, err := s.People().Get(ctx, guest.ID)
	require.NoError(t, err)
	assert.Equal(t, guest, got)
	require.NotNil(t, got.AccessUntil)
	assert.Equal(t, time.UTC, got.AccessUntil.Location())
	list, err := s.People().ListByAccount(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, []core.Person{guest}, list)

	// No permissions, whether nil or empty, is nil.
	plain := core.Person{ID: "per_plain", AccountID: a.ID, Name: "Bob", Role: core.RoleMember, CreatedAt: now.Add(time.Second),
		Permissions: []string{}}
	require.NoError(t, s.People().Create(ctx, plain))
	got, err = s.People().Get(ctx, plain.ID)
	require.NoError(t, err)
	assert.Nil(t, got.Permissions)
	assert.Nil(t, got.AccessUntil)

	// SetAccess replaces the term and the permissions together.
	later := until.Add(24 * time.Hour).In(time.FixedZone("X", 3*3600))
	require.NoError(t, s.People().SetAccess(ctx, guest.ID, &later, []string{PermissionTV}))
	got, err = s.People().Get(ctx, guest.ID)
	require.NoError(t, err)
	require.NotNil(t, got.AccessUntil)
	assert.True(t, later.Equal(*got.AccessUntil))
	assert.Equal(t, time.UTC, got.AccessUntil.Location())
	assert.Equal(t, []string{PermissionTV}, got.Permissions)
	assert.Equal(t, "Carol", got.Name, "nothing else changes")
	assert.Nil(t, got.DisabledAt)

	// nil clears the term, nil or no permissions clear the permissions: each on its own.
	require.NoError(t, s.People().SetAccess(ctx, guest.ID, nil, []string{PermissionTV, core.PermissionAll}))
	got, err = s.People().Get(ctx, guest.ID)
	require.NoError(t, err)
	assert.Nil(t, got.AccessUntil)
	assert.Equal(t, []string{PermissionTV, core.PermissionAll}, got.Permissions)
	require.NoError(t, s.People().SetAccess(ctx, guest.ID, &until, []string{}))
	got, err = s.People().Get(ctx, guest.ID)
	require.NoError(t, err)
	require.NotNil(t, got.AccessUntil)
	assert.True(t, until.Equal(*got.AccessUntil))
	assert.Nil(t, got.Permissions)
	require.NoError(t, s.People().SetAccess(ctx, guest.ID, nil, nil))
	got, err = s.People().Get(ctx, guest.ID)
	require.NoError(t, err)
	assert.Equal(t, core.Person{ID: guest.ID, AccountID: a.ID, Name: "Carol", Role: core.RoleMember, CreatedAt: now}, got,
		"clearing both leaves a person as if they never had a term")
	require.NoError(t, s.People().SetAccess(ctx, guest.ID, nil, nil), "clearing twice is fine")

	// Active follows the term and the disabled mark, with the person as stored.
	require.NoError(t, s.People().SetAccess(ctx, guest.ID, &until, nil))
	got, err = s.People().Get(ctx, guest.ID)
	require.NoError(t, err)
	assert.True(t, got.Active(until.Add(-time.Millisecond)))
	assert.False(t, got.Active(until), "the term ends at AccessUntil")

	assert.ErrorIs(t, s.People().SetAccess(ctx, "per_missing", &until, nil), core.ErrNotFound)
	assert.ErrorIs(t, s.People().SetAccess(ctx, "per_missing", nil, nil), core.ErrNotFound)

	// It joins the transaction of its context: a rollback undoes it.
	errRollBack := errors.New("roll back")
	err = s.Tx(ctx, func(ctx context.Context) error {
		if err := s.People().SetAccess(ctx, guest.ID, nil, []string{"x"}); err != nil {
			return err
		}
		return errRollBack
	})
	require.ErrorIs(t, err, errRollBack)
	got, err = s.People().Get(ctx, guest.ID)
	require.NoError(t, err)
	assert.Nil(t, got.Permissions)
}

// PermissionTV is a permission id the tests use; the gatekeeper never interprets ids.
const PermissionTV = "plugin:tv"

func testPasskeys(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	pid := core.PersonID("per_x")
	k := core.Passkey{ID: core.NewID(core.PrefixPasskey), PersonID: pid, CredentialID: []byte{1, 2, 3}, Data: []byte(`{"a":1}`),
		Name: "iPhone", CreatedAt: ms()}
	require.NoError(t, s.Passkeys().Add(ctx, k))

	got, err := s.Passkeys().Get(ctx, k.ID)
	require.NoError(t, err)
	assert.Equal(t, k, got)
	got, err = s.Passkeys().GetByCredentialID(ctx, []byte{1, 2, 3})
	require.NoError(t, err)
	assert.Equal(t, k, got)
	_, err = s.Passkeys().GetByCredentialID(ctx, []byte{1, 2})
	assert.ErrorIs(t, err, core.ErrNotFound)
	_, err = s.Passkeys().Get(ctx, "pk_missing")
	assert.ErrorIs(t, err, core.ErrNotFound)

	dup := k
	dup.ID = core.NewID(core.PrefixPasskey)
	assert.ErrorIs(t, s.Passkeys().Add(ctx, dup), core.ErrConflict, "the credential id is unique")
	assert.ErrorIs(t, s.Passkeys().Add(ctx, k), core.ErrConflict)

	used := ms()
	require.NoError(t, s.Passkeys().Update(ctx, k.ID, []byte(`{"a":2}`), used))
	require.NoError(t, s.Passkeys().Rename(ctx, k.ID, "Mac"))
	got, err = s.Passkeys().Get(ctx, k.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"a":2}`), got.Data)
	assert.Equal(t, "Mac", got.Name)
	require.NotNil(t, got.LastUsedAt)
	assert.True(t, used.Equal(*got.LastUsedAt))
	assert.ErrorIs(t, s.Passkeys().Rename(ctx, "pk_missing", "x"), core.ErrNotFound)

	k2 := core.Passkey{ID: core.NewID(core.PrefixPasskey), PersonID: pid, CredentialID: []byte{9}, Data: []byte("{}"), Name: "Key",
		CreatedAt: k.CreatedAt.Add(time.Second)}
	require.NoError(t, s.Passkeys().Add(ctx, k2))
	other := core.Passkey{ID: core.NewID(core.PrefixPasskey), PersonID: "per_y", CredentialID: []byte{7}, Data: []byte("{}"),
		CreatedAt: k.CreatedAt}
	require.NoError(t, s.Passkeys().Add(ctx, other))
	list, err := s.Passkeys().ListByPerson(ctx, pid)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, []string{k.ID, k2.ID}, []string{list[0].ID, list[1].ID}, "oldest first")

	require.NoError(t, s.Passkeys().Delete(ctx, k.ID))
	assert.ErrorIs(t, s.Passkeys().Delete(ctx, k.ID), core.ErrNotFound)
	assert.ErrorIs(t, s.Passkeys().Update(ctx, k.ID, nil, used), core.ErrNotFound)
	require.NoError(t, s.Passkeys().DeleteByPerson(ctx, pid))
	require.NoError(t, s.Passkeys().DeleteByPerson(ctx, pid), "bulk delete is idempotent")
	list, err = s.Passkeys().ListByPerson(ctx, pid)
	require.NoError(t, err)
	assert.Empty(t, list)
	_, err = s.Passkeys().Get(ctx, other.ID)
	assert.NoError(t, err, "another person's passkey stays")
}

func testSessions(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	mk := func(id string, person core.PersonID, seen, expires time.Time) core.Session {
		return core.Session{IDHash: hash(id), PersonID: person, CreatedAt: now, LastSeenAt: seen, ExpiresAt: expires, UserAgent: "ua"}
	}
	fresh := mk("fresh", "per_a", now, now.Add(7*24*time.Hour))
	require.NoError(t, s.Sessions().Create(ctx, fresh))
	got, err := s.Sessions().Get(ctx, fresh.IDHash)
	require.NoError(t, err)
	assert.Equal(t, fresh, got)
	assert.True(t, got.StepUpUntil.IsZero())
	assert.ErrorIs(t, s.Sessions().Create(ctx, fresh), core.ErrConflict)

	later := now.Add(time.Minute)
	require.NoError(t, s.Sessions().Touch(ctx, fresh.IDHash, later))
	until := now.Add(5 * time.Minute)
	require.NoError(t, s.Sessions().SetStepUp(ctx, fresh.IDHash, until))
	got, err = s.Sessions().Get(ctx, fresh.IDHash)
	require.NoError(t, err)
	assert.True(t, later.Equal(got.LastSeenAt))
	assert.True(t, until.Equal(got.StepUpUntil))
	assert.ErrorIs(t, s.Sessions().Touch(ctx, hash("none"), later), core.ErrNotFound)
	assert.ErrorIs(t, s.Sessions().SetStepUp(ctx, hash("none"), later), core.ErrNotFound)
	_, err = s.Sessions().Get(ctx, hash("none"))
	assert.ErrorIs(t, err, core.ErrNotFound)

	// A session created with a step-up keeps it.
	stepped := mk("stepped", "per_c", now, now.Add(time.Hour))
	stepped.StepUpUntil = until
	stepped.UserAgent = ""
	require.NoError(t, s.Sessions().Create(ctx, stepped))
	got, err = s.Sessions().Get(ctx, stepped.IDHash)
	require.NoError(t, err)
	assert.Equal(t, stepped, got)

	// Expired: the absolute end reached (<= now) or idle for longer than idle (last seen < now - idle).
	const idle = 12 * time.Hour
	require.NoError(t, s.Sessions().Create(ctx, mk("ended", "per_a", now, now.Add(-time.Hour))))
	require.NoError(t, s.Sessions().Create(ctx, mk("ends-now", "per_a", now, now)))
	require.NoError(t, s.Sessions().Create(ctx, mk("idle", "per_b", now.Add(-13*time.Hour), now.Add(time.Hour))))
	require.NoError(t, s.Sessions().Create(ctx, mk("idle-edge", "per_b", now.Add(-idle), now.Add(time.Hour))))
	n, err := s.Sessions().DeleteExpired(ctx, now, idle)
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	for _, id := range []string{"fresh", "stepped", "idle-edge"} {
		_, err = s.Sessions().Get(ctx, hash(id))
		require.NoError(t, err, id)
	}
	n, err = s.Sessions().DeleteExpired(ctx, now, idle)
	require.NoError(t, err)
	assert.Zero(t, n)

	require.NoError(t, s.Sessions().Create(ctx, mk("second", "per_a", now, now.Add(time.Hour))))
	require.NoError(t, s.Sessions().DeleteByPerson(ctx, "per_a"))
	require.NoError(t, s.Sessions().DeleteByPerson(ctx, "per_a"), "bulk delete is idempotent")
	_, err = s.Sessions().Get(ctx, hash("second"))
	assert.ErrorIs(t, err, core.ErrNotFound)
	_, err = s.Sessions().Get(ctx, hash("fresh"))
	assert.ErrorIs(t, err, core.ErrNotFound)
	_, err = s.Sessions().Get(ctx, hash("idle-edge"))
	assert.NoError(t, err, "another person's session stays")

	require.NoError(t, s.Sessions().Delete(ctx, hash("idle-edge")))
	_, err = s.Sessions().Get(ctx, hash("idle-edge"))
	assert.ErrorIs(t, err, core.ErrNotFound)
	require.NoError(t, s.Sessions().Delete(ctx, hash("idle-edge")), "deleting a missing session is fine")
}
