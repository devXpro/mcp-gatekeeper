package mongostore

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/devXpro/mcp-gatekeeper/core"
)

type inviteDoc struct {
	ID        string     `bson:"_id"`
	TokenHash []byte     `bson:"token_hash"`
	Kind      string     `bson:"kind"`
	AccountID string     `bson:"account_id,omitempty"`
	Name      string     `bson:"name"`
	CreatedBy string     `bson:"created_by,omitempty"`
	CreatedAt time.Time  `bson:"created_at"`
	ExpiresAt time.Time  `bson:"expires_at"`
	UsedAt    *time.Time `bson:"used_at,omitempty"`
	RevokedAt *time.Time `bson:"revoked_at,omitempty"`
	// Absent on an invite that offers neither, like Family Hub's own documents.
	AccessUntil *time.Time `bson:"access_until,omitempty"`
	Permissions []string   `bson:"permissions,omitempty"`
}

func (d inviteDoc) toCore() core.Invite {
	return core.Invite{
		ID: d.ID, TokenHash: d.TokenHash, Kind: core.InviteKind(d.Kind), AccountID: core.AccountID(d.AccountID),
		Name: d.Name, CreatedBy: core.PersonID(d.CreatedBy), CreatedAt: utc(d.CreatedAt), ExpiresAt: utc(d.ExpiresAt),
		UsedAt: optTime(d.UsedAt), RevokedAt: optTime(d.RevokedAt),
		AccessUntil: optTime(d.AccessUntil), Permissions: d.Permissions,
	}
}

type inviteStore struct{ s *Store }

func (i inviteStore) Create(ctx context.Context, inv core.Invite) error {
	return i.s.c(colInvites).insert(ctx, inviteDoc{
		ID: inv.ID, TokenHash: inv.TokenHash, Kind: string(inv.Kind), AccountID: string(inv.AccountID), Name: inv.Name,
		CreatedBy: string(inv.CreatedBy), CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt,
		UsedAt: optTime(inv.UsedAt), RevokedAt: optTime(inv.RevokedAt),
		AccessUntil: optTime(inv.AccessUntil), Permissions: inv.Permissions,
	})
}

// Peek returns a live invite. A revoked invite is core.ErrNotFound (it was withdrawn), a used one core.ErrUsed and
// an expired one core.ErrExpired.
func (i inviteStore) Peek(ctx context.Context, tokenHash []byte, now time.Time) (core.Invite, error) {
	d, err := findOne[inviteDoc](ctx, i.s.c(colInvites), kv("token_hash", tokenHash))
	if err != nil {
		return core.Invite{}, err
	}
	switch {
	case d.RevokedAt != nil:
		return core.Invite{}, i.s.c(colInvites).notFound("peek revoked invite")
	case d.UsedAt != nil:
		return core.Invite{}, i.s.c(colInvites).wrap("peek", core.ErrUsed)
	case !d.ExpiresAt.After(now):
		return core.Invite{}, i.s.c(colInvites).wrap("peek", core.ErrExpired)
	}
	return d.toCore(), nil
}

// Consume marks a live invite used with one findOneAndUpdate, so of two concurrent calls one wins.
func (i inviteStore) Consume(ctx context.Context, tokenHash []byte, now time.Time) (core.Invite, error) {
	c := i.s.c(colInvites)
	d, err := findAndUpdate[inviteDoc](ctx, c, bson.D{
		{Key: "token_hash", Value: tokenHash},
		{Key: "used_at", Value: nil},
		{Key: "revoked_at", Value: nil},
		{Key: "expires_at", Value: kv("$gt", now)},
	}, set(kv("used_at", now)))
	if err == nil {
		return d.toCore(), nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return core.Invite{}, c.wrap("consume", err)
	}
	if _, err := i.Peek(ctx, tokenHash, now); err != nil {
		return core.Invite{}, err
	}
	// Live when we looked again: someone else's call changed it in between. It is theirs.
	return core.Invite{}, c.wrap("consume", core.ErrUsed)
}

// ListByAccount returns the invites of an account that are neither used nor revoked, oldest first. It does not
// look at the expiry: the caller has the clock.
func (i inviteStore) ListByAccount(ctx context.Context, a core.AccountID) ([]core.Invite, error) {
	docs, err := findAll[inviteDoc](ctx, i.s.c(colInvites), bson.D{
		{Key: "account_id", Value: string(a)},
		{Key: "used_at", Value: nil},
		{Key: "revoked_at", Value: nil},
	}, bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, 0)
	if err != nil {
		return nil, err
	}
	out := make([]core.Invite, len(docs))
	for n, d := range docs {
		out[n] = d.toCore()
	}
	return out, nil
}

func (i inviteStore) Revoke(ctx context.Context, id string, at time.Time) error {
	return i.s.c(colInvites).markOnce(ctx, idIs(id), "revoked_at", at)
}

// RevokeKind revokes every invite of a kind that is not used, revoked or expired.
func (i inviteStore) RevokeKind(ctx context.Context, kind core.InviteKind, at time.Time) error {
	err := i.s.c(colInvites).updateMany(ctx, bson.D{
		{Key: "kind", Value: string(kind)},
		{Key: "used_at", Value: nil},
		{Key: "revoked_at", Value: nil},
		{Key: "expires_at", Value: kv("$gt", at)},
	}, set(kv("revoked_at", at)))
	return err
}
