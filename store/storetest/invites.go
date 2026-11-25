package storetest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func testInvites(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	a := seedAccount(t, s, "Family")
	mk := func(id string, kind core.InviteKind, expires time.Time) core.Invite {
		return core.Invite{ID: "inv_" + id, TokenHash: hash(id), Kind: kind, AccountID: a.ID, Name: "Name " + id,
			CreatedBy: "per_x", CreatedAt: now, ExpiresAt: expires}
	}
	live := mk("live", core.InviteMember, now.Add(time.Hour))
	require.NoError(t, s.Invites().Create(ctx, live))
	assert.ErrorIs(t, s.Invites().Create(ctx, live), core.ErrConflict)
	sameToken := mk("other", core.InviteMember, now.Add(time.Hour))
	sameToken.TokenHash = live.TokenHash
	assert.ErrorIs(t, s.Invites().Create(ctx, sameToken), core.ErrConflict, "the token hash is unique")

	got, err := s.Invites().Peek(ctx, live.TokenHash, now)
	require.NoError(t, err)
	assert.Equal(t, live, got)
	_, err = s.Invites().Peek(ctx, hash("unknown"), now)
	assert.ErrorIs(t, err, core.ErrNotFound)
	_, err = s.Invites().Peek(ctx, live.TokenHash, now.Add(2*time.Hour))
	assert.ErrorIs(t, err, core.ErrExpired)
	_, err = s.Invites().Peek(ctx, live.TokenHash, live.ExpiresAt)
	assert.ErrorIs(t, err, core.ErrExpired, "an invite expires at ExpiresAt")

	older := mk("older", core.InviteMember, now.Add(time.Hour))
	older.CreatedAt = now.Add(-time.Minute)
	require.NoError(t, s.Invites().Create(ctx, older))
	list, err := s.Invites().ListByAccount(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, []core.Invite{older, live}, list, "oldest first")

	used, err := s.Invites().Consume(ctx, live.TokenHash, now)
	require.NoError(t, err)
	require.NotNil(t, used.UsedAt)
	assert.True(t, now.Equal(*used.UsedAt))
	used.UsedAt = nil
	assert.Equal(t, live, used, "Consume returns the invite")
	_, err = s.Invites().Consume(ctx, live.TokenHash, now)
	assert.ErrorIs(t, err, core.ErrUsed)
	_, err = s.Invites().Peek(ctx, live.TokenHash, now)
	assert.ErrorIs(t, err, core.ErrUsed)
	_, err = s.Invites().Peek(ctx, live.TokenHash, now.Add(2*time.Hour))
	assert.ErrorIs(t, err, core.ErrUsed, "used wins over expired")
	list, err = s.Invites().ListByAccount(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, []core.Invite{older}, list, "a used invite is not pending")

	old := mk("old", core.InviteMember, now.Add(-time.Minute))
	require.NoError(t, s.Invites().Create(ctx, old))
	_, err = s.Invites().Consume(ctx, old.TokenHash, now)
	assert.ErrorIs(t, err, core.ErrExpired)
	_, err = s.Invites().Consume(ctx, hash("unknown"), now)
	assert.ErrorIs(t, err, core.ErrNotFound)
	list, err = s.Invites().ListByAccount(ctx, a.ID)
	require.NoError(t, err)
	assert.Len(t, list, 2, "ListByAccount does not look at the expiry")

	rev := mk("rev", core.InviteOwner, now.Add(time.Hour))
	require.NoError(t, s.Invites().Create(ctx, rev))
	require.NoError(t, s.Invites().Revoke(ctx, rev.ID, now))
	require.NoError(t, s.Invites().Revoke(ctx, rev.ID, now.Add(time.Second)), "revoking twice is fine")
	assert.ErrorIs(t, s.Invites().Revoke(ctx, "inv_missing", now), core.ErrNotFound)
	_, err = s.Invites().Consume(ctx, rev.TokenHash, now)
	assert.ErrorIs(t, err, core.ErrNotFound, "a revoked invite is gone")
	_, err = s.Invites().Peek(ctx, rev.TokenHash, now.Add(2*time.Hour))
	assert.ErrorIs(t, err, core.ErrNotFound, "revoked wins over expired")
	require.NoError(t, s.Invites().Revoke(ctx, live.ID, now), "a used invite can be revoked")
	_, err = s.Invites().Peek(ctx, live.TokenHash, now)
	assert.ErrorIs(t, err, core.ErrNotFound, "revoked wins over used")

	// RevokeKind touches only its kind and only live invites.
	setup1 := core.Invite{ID: "inv_s1", TokenHash: hash("s1"), Kind: core.InviteSetup, CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	setup2 := setup1
	setup2.ID, setup2.TokenHash = "inv_s2", hash("s2")
	require.NoError(t, s.Invites().Create(ctx, setup1))
	got, err = s.Invites().Peek(ctx, setup1.TokenHash, now)
	require.NoError(t, err)
	assert.Equal(t, setup1, got, "a setup invite has no account and no creator")
	usedOwner := mk("used-owner", core.InviteOwner, now.Add(time.Hour))
	require.NoError(t, s.Invites().Create(ctx, usedOwner))
	_, err = s.Invites().Consume(ctx, usedOwner.TokenHash, now)
	require.NoError(t, err)
	require.NoError(t, s.Invites().RevokeKind(ctx, core.InviteSetup, now))
	require.NoError(t, s.Invites().RevokeKind(ctx, core.InviteSetup, now), "RevokeKind is idempotent")
	require.NoError(t, s.Invites().Create(ctx, setup2))
	_, err = s.Invites().Peek(ctx, setup1.TokenHash, now)
	assert.ErrorIs(t, err, core.ErrNotFound)
	_, err = s.Invites().Peek(ctx, setup2.TokenHash, now)
	assert.NoError(t, err)
	_, err = s.Invites().Peek(ctx, older.TokenHash, now)
	assert.NoError(t, err, "another kind stays")
	require.NoError(t, s.Invites().RevokeKind(ctx, core.InviteOwner, now))
	_, err = s.Invites().Peek(ctx, usedOwner.TokenHash, now)
	assert.ErrorIs(t, err, core.ErrUsed, "a used invite is not revoked by RevokeKind")
}

func testInviteAccess(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	a := seedAccount(t, s, "Family")
	until := now.Add(72 * time.Hour)
	guest := core.Invite{ID: "inv_guest", TokenHash: hash("guest"), Kind: core.InviteMember, AccountID: a.ID, Name: "Carol",
		CreatedBy: "per_x", CreatedAt: now, ExpiresAt: now.Add(time.Hour), AccessUntil: &until,
		Permissions: []string{PermissionTV, "plugin:lights"}}
	require.NoError(t, s.Invites().Create(ctx, guest))
	plain := core.Invite{ID: "inv_plain", TokenHash: hash("plain"), Kind: core.InviteMember, AccountID: a.ID, Name: "Bob",
		CreatedBy: "per_x", CreatedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour), Permissions: []string{}}
	require.NoError(t, s.Invites().Create(ctx, plain))

	got, err := s.Invites().Peek(ctx, guest.TokenHash, now)
	require.NoError(t, err)
	assert.Equal(t, guest, got)
	require.NotNil(t, got.AccessUntil)
	assert.Equal(t, time.UTC, got.AccessUntil.Location())

	got, err = s.Invites().Peek(ctx, plain.TokenHash, now)
	require.NoError(t, err)
	assert.Nil(t, got.Permissions, "no permissions, nil or empty, is nil")
	assert.Nil(t, got.AccessUntil)

	list, err := s.Invites().ListByAccount(ctx, a.ID)
	require.NoError(t, err)
	plain.Permissions = nil
	assert.Equal(t, []core.Invite{guest, plain}, list)

	// Consume hands both over, so the redeemer can copy them to the person in the same transaction.
	used, err := s.Invites().Consume(ctx, guest.TokenHash, now)
	require.NoError(t, err)
	assert.True(t, until.Equal(*used.AccessUntil))
	assert.Equal(t, guest.Permissions, used.Permissions)
}

func testInviteConsumeConcurrent(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	inv := core.Invite{ID: "inv_c", TokenHash: hash("c"), Kind: core.InviteOwner, AccountID: "acc_x", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	require.NoError(t, s.Invites().Create(ctx, inv))

	errs := race(32, func(int) error {
		_, err := s.Invites().Consume(ctx, inv.TokenHash, now)
		return err
	})
	assertOneWinner(t, errs, core.ErrUsed)
}
