package sqlitestore

import (
	"context"
	"database/sql"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

const passkeyCols = `id, person_id, credential_id, data, name, created_at, last_used_at` //nolint:gosec // column names, not a credential

func scanPasskey(r scanner) (core.Passkey, error) {
	var (
		k       core.Passkey
		person  string
		created int64
		used    sql.NullInt64
	)
	if err := r.Scan(&k.ID, &person, &k.CredentialID, &k.Data, &k.Name, &created, &used); err != nil {
		return core.Passkey{}, err
	}
	k.PersonID, k.CreatedAt, k.LastUsedAt = core.PersonID(person), fromMS(created), optTime(used)
	return k, nil
}

type passkeys struct{ s *Store }

// Add inserts a passkey; its id and its credential id are unique.
func (p passkeys) Add(ctx context.Context, k core.Passkey) error {
	_, err := p.s.exec(ctx, "add passkey", `INSERT INTO gk_passkeys (`+passkeyCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		k.ID, string(k.PersonID), blob(k.CredentialID), blob(k.Data), k.Name, ms(k.CreatedAt), optMS(k.LastUsedAt))
	return err
}

func (p passkeys) Get(ctx context.Context, id string) (core.Passkey, error) {
	k, err := scanPasskey(p.s.Conn(ctx).QueryRowContext(ctx, `SELECT `+passkeyCols+` FROM gk_passkeys WHERE id = ?`, id))
	return k, wrap("get passkey", err)
}

func (p passkeys) GetByCredentialID(ctx context.Context, credentialID []byte) (core.Passkey, error) {
	k, err := scanPasskey(p.s.Conn(ctx).QueryRowContext(ctx,
		`SELECT `+passkeyCols+` FROM gk_passkeys WHERE credential_id = ?`, blob(credentialID)))
	return k, wrap("get passkey by credential", err)
}

func (p passkeys) ListByPerson(ctx context.Context, person core.PersonID) ([]core.Passkey, error) {
	list, err := queryAll(ctx, p.s.Conn(ctx), scanPasskey,
		`SELECT `+passkeyCols+` FROM gk_passkeys WHERE person_id = ? ORDER BY created_at, id`, string(person))
	return list, wrap("list passkeys", err)
}

func (p passkeys) Update(ctx context.Context, id string, data []byte, lastUsed time.Time) error {
	return p.s.execOne(ctx, "update passkey", `UPDATE gk_passkeys SET data = ?, last_used_at = ? WHERE id = ?`,
		blob(data), ms(lastUsed), id)
}

func (p passkeys) Rename(ctx context.Context, id, name string) error {
	return p.s.execOne(ctx, "rename passkey", `UPDATE gk_passkeys SET name = ? WHERE id = ?`, name, id)
}

func (p passkeys) Delete(ctx context.Context, id string) error {
	return p.s.execOne(ctx, "delete passkey", `DELETE FROM gk_passkeys WHERE id = ?`, id)
}

func (p passkeys) DeleteByPerson(ctx context.Context, person core.PersonID) error {
	_, err := p.s.exec(ctx, "delete passkeys", `DELETE FROM gk_passkeys WHERE person_id = ?`, string(person))
	return err
}
