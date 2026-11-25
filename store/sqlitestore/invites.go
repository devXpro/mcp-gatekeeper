package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

const inviteCols = `id, token_hash, kind, account_id, name, created_by, created_at, expires_at, used_at, revoked_at, access_until, permissions`

func scanInvite(r scanner) (core.Invite, error) {
	var (
		inv                    core.Invite
		kind, account, creator string
		created, expires       int64
		used, revoked, until   sql.NullInt64
		perms                  sql.NullString
	)
	if err := r.Scan(&inv.ID, &inv.TokenHash, &kind, &account, &inv.Name, &creator, &created, &expires, &used, &revoked,
		&until, &perms); err != nil {
		return core.Invite{}, err
	}
	inv.Kind, inv.AccountID, inv.CreatedBy = core.InviteKind(kind), core.AccountID(account), core.PersonID(creator)
	inv.CreatedAt, inv.ExpiresAt, inv.UsedAt, inv.RevokedAt = fromMS(created), fromMS(expires), optTime(used), optTime(revoked)
	inv.AccessUntil = optTime(until)
	var err error
	if inv.Permissions, err = decodePermissions(perms); err != nil {
		return core.Invite{}, fmt.Errorf("permissions of invite %q: %w", inv.ID, err)
	}
	return inv, nil
}

type invites struct{ s *Store }

func (i invites) Create(ctx context.Context, inv core.Invite) error {
	perms, err := encodePermissions(inv.Permissions)
	if err != nil {
		return wrap("create invite", err)
	}
	_, err = i.s.exec(ctx, "create invite", `INSERT INTO gk_invites (`+inviteCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		inv.ID, blob(inv.TokenHash), string(inv.Kind), string(inv.AccountID), inv.Name, string(inv.CreatedBy),
		ms(inv.CreatedAt), ms(inv.ExpiresAt), optMS(inv.UsedAt), optMS(inv.RevokedAt), optMS(inv.AccessUntil), perms)
	return err
}

// Peek returns a live invite. A revoked invite is core.ErrNotFound (it was withdrawn), a used one core.ErrUsed and an
// expired one core.ErrExpired.
func (i invites) Peek(ctx context.Context, tokenHash []byte, now time.Time) (core.Invite, error) {
	inv, err := peekInvite(ctx, i.s.Conn(ctx), tokenHash, now)
	return inv, wrap("peek invite", err)
}

func peekInvite(ctx context.Context, q Conn, tokenHash []byte, now time.Time) (core.Invite, error) {
	inv, err := scanInvite(q.QueryRowContext(ctx, `SELECT `+inviteCols+` FROM gk_invites WHERE token_hash = ?`, blob(tokenHash)))
	switch {
	case err != nil:
		return core.Invite{}, err
	case inv.RevokedAt != nil:
		return core.Invite{}, sql.ErrNoRows
	case inv.UsedAt != nil:
		return core.Invite{}, core.ErrUsed
	case !inv.ExpiresAt.After(now):
		return core.Invite{}, core.ErrExpired
	}
	return inv, nil
}

// Consume marks a live invite used with one conditional UPDATE ... RETURNING inside a write transaction, so of two
// concurrent calls one wins and the other finds the invite used.
func (i invites) Consume(ctx context.Context, tokenHash []byte, now time.Time) (core.Invite, error) {
	var (
		inv   core.Invite
		cause error // the answer for a call that lost, kept out of the transaction so the lookup is not rolled back
	)
	err := i.s.write(ctx, func(ctx context.Context, q Conn) error {
		var err error
		inv, err = scanInvite(q.QueryRowContext(ctx, `UPDATE gk_invites SET used_at = ?
			WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?
			RETURNING `+inviteCols, ms(now), blob(tokenHash), ms(now)))
		if err == nil || !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := peekInvite(ctx, q, tokenHash, now); err != nil {
			cause = err
			return nil
		}
		cause = core.ErrUsed // live when we looked again: another call took it
		return nil
	})
	if err == nil && cause != nil {
		err = cause
	}
	return inv, wrap("consume invite", err)
}

// ListByAccount returns the invites of an account that are neither used nor revoked, oldest first. It does not look
// at the expiry: the caller has the clock.
func (i invites) ListByAccount(ctx context.Context, a core.AccountID) ([]core.Invite, error) {
	list, err := queryAll(ctx, i.s.Conn(ctx), scanInvite, `SELECT `+inviteCols+` FROM gk_invites
		WHERE account_id = ? AND used_at IS NULL AND revoked_at IS NULL ORDER BY created_at, id`, string(a))
	return list, wrap("list invites", err)
}

// Revoke withdraws an invite; the first revocation time wins.
func (i invites) Revoke(ctx context.Context, id string, at time.Time) error {
	return i.s.execOne(ctx, "revoke invite", `UPDATE gk_invites SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, ms(at), id)
}

// RevokeKind revokes every invite of a kind that is not used, revoked or expired.
func (i invites) RevokeKind(ctx context.Context, kind core.InviteKind, at time.Time) error {
	_, err := i.s.exec(ctx, "revoke invites", `UPDATE gk_invites SET revoked_at = ?
		WHERE kind = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, ms(at), string(kind), ms(at))
	return err
}
