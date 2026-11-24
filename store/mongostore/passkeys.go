package mongostore

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/devXpro/mcp-gatekeeper/core"
)

type passkeyDoc struct {
	ID           string     `bson:"_id"`
	PersonID     string     `bson:"person_id"`
	CredentialID []byte     `bson:"credential_id"`
	Data         []byte     `bson:"data"`
	Name         string     `bson:"name"`
	CreatedAt    time.Time  `bson:"created_at"`
	LastUsedAt   *time.Time `bson:"last_used_at,omitempty"`
}

func (d passkeyDoc) toCore() core.Passkey {
	return core.Passkey{
		ID: d.ID, PersonID: core.PersonID(d.PersonID), CredentialID: d.CredentialID, Data: d.Data, Name: d.Name,
		CreatedAt: utc(d.CreatedAt), LastUsedAt: optTime(d.LastUsedAt),
	}
}

type passkeyStore struct{ s *Store }

// Add stores a passkey; a repeated id or credential id is core.ErrConflict.
func (p passkeyStore) Add(ctx context.Context, k core.Passkey) error {
	return p.s.c(colPasskeys).insert(ctx, passkeyDoc{
		ID: k.ID, PersonID: string(k.PersonID), CredentialID: k.CredentialID, Data: k.Data, Name: k.Name,
		CreatedAt: k.CreatedAt, LastUsedAt: optTime(k.LastUsedAt),
	})
}

func (p passkeyStore) Get(ctx context.Context, id string) (core.Passkey, error) {
	d, err := findOne[passkeyDoc](ctx, p.s.c(colPasskeys), idIs(id))
	if err != nil {
		return core.Passkey{}, err
	}
	return d.toCore(), nil
}

func (p passkeyStore) GetByCredentialID(ctx context.Context, credentialID []byte) (core.Passkey, error) {
	d, err := findOne[passkeyDoc](ctx, p.s.c(colPasskeys), kv("credential_id", credentialID))
	if err != nil {
		return core.Passkey{}, err
	}
	return d.toCore(), nil
}

func (p passkeyStore) ListByPerson(ctx context.Context, person core.PersonID) ([]core.Passkey, error) {
	docs, err := findAll[passkeyDoc](ctx, p.s.c(colPasskeys), kv("person_id", string(person)),
		bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, 0)
	if err != nil {
		return nil, err
	}
	out := make([]core.Passkey, len(docs))
	for i, d := range docs {
		out[i] = d.toCore()
	}
	return out, nil
}

func (p passkeyStore) Update(ctx context.Context, id string, data []byte, lastUsed time.Time) error {
	return p.s.c(colPasskeys).update(ctx, idIs(id), set(bson.D{{Key: "data", Value: data}, {Key: "last_used_at", Value: lastUsed}}))
}

func (p passkeyStore) Rename(ctx context.Context, id, name string) error {
	return p.s.c(colPasskeys).update(ctx, idIs(id), set(kv("name", name)))
}

func (p passkeyStore) Delete(ctx context.Context, id string) error {
	return p.s.c(colPasskeys).deleteOne(ctx, idIs(id))
}

func (p passkeyStore) DeleteByPerson(ctx context.Context, person core.PersonID) error {
	_, err := p.s.c(colPasskeys).deleteMany(ctx, kv("person_id", string(person)))
	return err
}
