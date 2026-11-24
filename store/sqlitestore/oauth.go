package sqlitestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

const (
	clientCols = `id, kind, assistant, name, redirect_uris, auth_method, secret_hash, fetched_at, created_at, last_used_at`
	codeCols   = `code_hash, grant_id, client_id, redirect_uri, resource, scope, code_challenge, created_at, expires_at`
	grantCols  = `id, person_id, account_id, client_id, resource_id, scope, created_at, last_used_at, revoked_at`
	tokenCols  = `hash, grant_id, kind, family, created_at, expires_at, used_at, revoked_at` //nolint:gosec // column names, not a credential
)

func scanClient(r scanner) (core.OAuthClient, error) {
	var (
		c                         core.OAuthClient
		id, kind, assistant, uris string
		fetched, created          int64
		used                      sql.NullInt64
	)
	if err := r.Scan(&id, &kind, &assistant, &c.Name, &uris, &c.AuthMethod, &c.SecretHash, &fetched, &created, &used); err != nil {
		return core.OAuthClient{}, err
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		return core.OAuthClient{}, fmt.Errorf("redirect uris of client %q: %w", id, err)
	}
	c.ID, c.Kind, c.Assistant = core.ClientID(id), core.ClientKind(kind), core.Assistant(assistant)
	c.FetchedAt, c.CreatedAt, c.LastUsedAt = fromMS(fetched), fromMS(created), optTime(used)
	return c, nil
}

func scanCode(r scanner) (core.AuthCode, error) {
	var (
		c                core.AuthCode
		grant, client    string
		created, expires int64
	)
	if err := r.Scan(&c.CodeHash, &grant, &client, &c.RedirectURI, &c.Resource, &c.Scope, &c.CodeChallenge, &created, &expires); err != nil {
		return core.AuthCode{}, err
	}
	c.GrantID, c.ClientID, c.CreatedAt, c.ExpiresAt = core.GrantID(grant), core.ClientID(client), fromMS(created), fromMS(expires)
	return c, nil
}

func scanGrant(r scanner) (core.Grant, error) {
	var (
		g                                     core.Grant
		id, person, account, client, resource string
		created                               int64
		used, revoked                         sql.NullInt64
	)
	if err := r.Scan(&id, &person, &account, &client, &resource, &g.Scope, &created, &used, &revoked); err != nil {
		return core.Grant{}, err
	}
	g.ID, g.PersonID, g.AccountID = core.GrantID(id), core.PersonID(person), core.AccountID(account)
	g.ClientID, g.ResourceID = core.ClientID(client), core.ResourceID(resource)
	g.CreatedAt, g.LastUsedAt, g.RevokedAt = fromMS(created), optTime(used), optTime(revoked)
	return g, nil
}

func scanToken(r scanner) (core.Token, error) {
	var (
		t                core.Token
		grant, kind      string
		created, expires int64
		used, revoked    sql.NullInt64
	)
	if err := r.Scan(&t.Hash, &grant, &kind, &t.Family, &created, &expires, &used, &revoked); err != nil {
		return core.Token{}, err
	}
	t.GrantID, t.Kind = core.GrantID(grant), core.TokenKind(kind)
	t.CreatedAt, t.ExpiresAt, t.UsedAt, t.RevokedAt = fromMS(created), fromMS(expires), optTime(used), optTime(revoked)
	return t, nil
}

// The grants a delete reaches, as SQL conditions; constants, so the delete statements below are fixed text.
const (
	grantsOfPerson  = `person_id = ?`
	grantsOfAccount = `account_id = ?`
)

// deleteGrants removes the grants matching where (one of the constants above, with one argument) together with their
// tokens and codes. The caller is inside a transaction.
func deleteGrants(ctx context.Context, q Conn, where, arg string) error {
	var stmts [3]string
	switch where {
	case grantsOfPerson:
		stmts = [3]string{
			`DELETE FROM gk_oauth_tokens WHERE grant_id IN (SELECT id FROM gk_oauth_grants WHERE ` + grantsOfPerson + `)`,
			`DELETE FROM gk_oauth_codes WHERE grant_id IN (SELECT id FROM gk_oauth_grants WHERE ` + grantsOfPerson + `)`,
			`DELETE FROM gk_oauth_grants WHERE ` + grantsOfPerson,
		}
	case grantsOfAccount:
		stmts = [3]string{
			`DELETE FROM gk_oauth_tokens WHERE grant_id IN (SELECT id FROM gk_oauth_grants WHERE ` + grantsOfAccount + `)`,
			`DELETE FROM gk_oauth_codes WHERE grant_id IN (SELECT id FROM gk_oauth_grants WHERE ` + grantsOfAccount + `)`,
			`DELETE FROM gk_oauth_grants WHERE ` + grantsOfAccount,
		}
	default:
		return fmt.Errorf("unknown grant filter %q", where)
	}
	for _, stmt := range stmts {
		if _, err := q.ExecContext(ctx, stmt, arg); err != nil {
			return err
		}
	}
	return nil
}

type oauth struct{ s *Store }

// PutClient inserts the client or replaces the one with the same id.
func (o oauth) PutClient(ctx context.Context, c core.OAuthClient) error {
	uris := c.RedirectURIs
	if uris == nil {
		uris = []string{}
	}
	raw, err := json.Marshal(uris)
	if err != nil {
		return wrap("put client", err)
	}
	_, err = o.s.exec(ctx, "put client", `INSERT INTO gk_oauth_clients (`+clientCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET kind = excluded.kind, assistant = excluded.assistant, name = excluded.name,
			redirect_uris = excluded.redirect_uris, auth_method = excluded.auth_method, secret_hash = excluded.secret_hash,
			fetched_at = excluded.fetched_at, created_at = excluded.created_at, last_used_at = excluded.last_used_at`,
		string(c.ID), string(c.Kind), string(c.Assistant), c.Name, string(raw), c.AuthMethod, optBlob(c.SecretHash),
		ms(c.FetchedAt), ms(c.CreatedAt), optMS(c.LastUsedAt))
	return err
}

func (o oauth) GetClient(ctx context.Context, id core.ClientID) (core.OAuthClient, error) {
	c, err := scanClient(o.s.Conn(ctx).QueryRowContext(ctx, `SELECT `+clientCols+` FROM gk_oauth_clients WHERE id = ?`, string(id)))
	return c, wrap("get client", err)
}

func (o oauth) TouchClient(ctx context.Context, id core.ClientID, at time.Time) error {
	return o.s.execOne(ctx, "touch client", `UPDATE gk_oauth_clients SET last_used_at = ? WHERE id = ?`, ms(at), string(id))
}

// DeleteIdleClients removes DCR clients created before cutoff that no grant, revoked ones included, points at.
func (o oauth) DeleteIdleClients(ctx context.Context, cutoff time.Time) (int, error) {
	n, err := o.s.exec(ctx, "delete idle clients", `DELETE FROM gk_oauth_clients
		WHERE kind = ? AND created_at < ? AND id NOT IN (SELECT client_id FROM gk_oauth_grants)`, string(core.ClientDCR), ms(cutoff))
	return int(n), err
}

func (o oauth) PutCode(ctx context.Context, c core.AuthCode) error {
	_, err := o.s.exec(ctx, "put code", `INSERT INTO gk_oauth_codes (`+codeCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		blob(c.CodeHash), string(c.GrantID), string(c.ClientID), c.RedirectURI, c.Resource, c.Scope, c.CodeChallenge,
		ms(c.CreatedAt), ms(c.ExpiresAt))
	return err
}

// ConsumeCode deletes the code with one DELETE ... RETURNING inside a write transaction, so of two concurrent calls
// one wins. A code found past its end is deleted too and answered with core.ErrExpired.
func (o oauth) ConsumeCode(ctx context.Context, codeHash []byte, now time.Time) (core.AuthCode, error) {
	var c core.AuthCode
	err := o.s.write(ctx, func(ctx context.Context, q Conn) error {
		var err error
		c, err = scanCode(q.QueryRowContext(ctx, `DELETE FROM gk_oauth_codes WHERE code_hash = ? RETURNING `+codeCols, blob(codeHash)))
		return err
	})
	if err == nil && !c.ExpiresAt.After(now) {
		return core.AuthCode{}, wrap("consume code", core.ErrExpired)
	}
	if err != nil {
		return core.AuthCode{}, wrap("consume code", err)
	}
	return c, nil
}

// PutGrant inserts the grant or replaces the one with the same id. A second active grant for the same (person,
// client, resource) is core.ErrConflict.
func (o oauth) PutGrant(ctx context.Context, g core.Grant) error {
	_, err := o.s.exec(ctx, "put grant", `INSERT INTO gk_oauth_grants (`+grantCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET person_id = excluded.person_id, account_id = excluded.account_id,
			client_id = excluded.client_id, resource_id = excluded.resource_id, scope = excluded.scope,
			created_at = excluded.created_at, last_used_at = excluded.last_used_at, revoked_at = excluded.revoked_at`,
		string(g.ID), string(g.PersonID), string(g.AccountID), string(g.ClientID), string(g.ResourceID), g.Scope,
		ms(g.CreatedAt), optMS(g.LastUsedAt), optMS(g.RevokedAt))
	return err
}

// GetGrant returns a grant, revoked or not.
func (o oauth) GetGrant(ctx context.Context, id core.GrantID) (core.Grant, error) {
	g, err := scanGrant(o.s.Conn(ctx).QueryRowContext(ctx, `SELECT `+grantCols+` FROM gk_oauth_grants WHERE id = ?`, string(id)))
	return g, wrap("get grant", err)
}

func (o oauth) FindGrant(ctx context.Context, p core.PersonID, c core.ClientID, r core.ResourceID) (core.Grant, error) {
	g, err := scanGrant(o.s.Conn(ctx).QueryRowContext(ctx, `SELECT `+grantCols+` FROM gk_oauth_grants
		WHERE person_id = ? AND client_id = ? AND resource_id = ? AND revoked_at IS NULL`, string(p), string(c), string(r)))
	return g, wrap("find grant", err)
}

// ListGrantsByAccount returns the active grants of an account, oldest first.
func (o oauth) ListGrantsByAccount(ctx context.Context, a core.AccountID) ([]core.Grant, error) {
	list, err := queryAll(ctx, o.s.Conn(ctx), scanGrant, `SELECT `+grantCols+` FROM gk_oauth_grants
		WHERE account_id = ? AND revoked_at IS NULL ORDER BY created_at, id`, string(a))
	return list, wrap("list grants", err)
}

func (o oauth) TouchGrant(ctx context.Context, id core.GrantID, at time.Time) error {
	return o.s.execOne(ctx, "touch grant", `UPDATE gk_oauth_grants SET last_used_at = ? WHERE id = ?`, ms(at), string(id))
}

// RevokeGrant revokes the grant and every token of it in one transaction; the first revocation time wins.
func (o oauth) RevokeGrant(ctx context.Context, id core.GrantID, at time.Time) error {
	return wrap("revoke grant", o.s.write(ctx, func(ctx context.Context, q Conn) error {
		res, err := q.ExecContext(ctx, `UPDATE gk_oauth_grants SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, ms(at), string(id))
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			if err != nil {
				return err
			}
			return sql.ErrNoRows
		}
		_, err = q.ExecContext(ctx, `UPDATE gk_oauth_tokens SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL`, ms(at), string(id))
		return err
	}))
}

// RevokeGrantsByResource revokes every grant of a resource and their tokens in one transaction.
func (o oauth) RevokeGrantsByResource(ctx context.Context, r core.ResourceID, at time.Time) error {
	return wrap("revoke grants", o.s.write(ctx, func(ctx context.Context, q Conn) error {
		if _, err := q.ExecContext(ctx, `UPDATE gk_oauth_tokens SET revoked_at = ? WHERE revoked_at IS NULL
			AND grant_id IN (SELECT id FROM gk_oauth_grants WHERE resource_id = ?)`, ms(at), string(r)); err != nil {
			return err
		}
		_, err := q.ExecContext(ctx, `UPDATE gk_oauth_grants SET revoked_at = ? WHERE resource_id = ? AND revoked_at IS NULL`,
			ms(at), string(r))
		return err
	}))
}

func (o oauth) PutToken(ctx context.Context, t core.Token) error {
	_, err := o.s.exec(ctx, "put token", `INSERT INTO gk_oauth_tokens (`+tokenCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		blob(t.Hash), string(t.GrantID), string(t.Kind), t.Family, ms(t.CreatedAt), ms(t.ExpiresAt), optMS(t.UsedAt), optMS(t.RevokedAt))
	return err
}

// GetToken returns a token as stored, expired or revoked or not: the validator decides.
func (o oauth) GetToken(ctx context.Context, hash []byte) (core.Token, error) {
	t, err := scanToken(o.s.Conn(ctx).QueryRowContext(ctx, `SELECT `+tokenCols+` FROM gk_oauth_tokens WHERE hash = ?`, blob(hash)))
	return t, wrap("get token", err)
}

// UseRefresh marks a live refresh token used with one conditional UPDATE ... RETURNING inside a write transaction, so
// of two concurrent calls one wins. An already rotated token is core.ErrUsed (the caller revokes its family); a
// revoked or unknown one, or an access token, is core.ErrNotFound; an expired one is core.ErrExpired.
func (o oauth) UseRefresh(ctx context.Context, hash []byte, at time.Time) (core.Token, error) {
	var (
		t     core.Token
		cause error
	)
	err := o.s.write(ctx, func(ctx context.Context, q Conn) error {
		var err error
		t, err = scanToken(q.QueryRowContext(ctx, `UPDATE gk_oauth_tokens SET used_at = ?
			WHERE hash = ? AND kind = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?
			RETURNING `+tokenCols, ms(at), blob(hash), string(core.TokenRefresh), ms(at)))
		if err == nil || !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		cur, err := scanToken(q.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM gk_oauth_tokens WHERE hash = ?`, blob(hash)))
		if err != nil {
			return err // unknown: sql.ErrNoRows
		}
		switch {
		case cur.Kind != core.TokenRefresh:
			cause = sql.ErrNoRows // an access token is no refresh token
		case cur.UsedAt != nil:
			cause = core.ErrUsed
		case cur.RevokedAt != nil:
			cause = sql.ErrNoRows
		case !cur.ExpiresAt.After(at):
			cause = core.ErrExpired
		default:
			cause = core.ErrUsed // live when we looked again: another call took it
		}
		return nil
	})
	if err == nil && cause != nil {
		err = cause
	}
	if err != nil {
		return core.Token{}, wrap("use refresh", err)
	}
	return t, nil
}

// RevokeToken revokes one token; the first revocation time wins.
func (o oauth) RevokeToken(ctx context.Context, hash []byte, at time.Time) error {
	return o.s.execOne(ctx, "revoke token", `UPDATE gk_oauth_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE hash = ?`, ms(at), blob(hash))
}

func (o oauth) RevokeFamily(ctx context.Context, family string, at time.Time) error {
	_, err := o.s.exec(ctx, "revoke family", `UPDATE gk_oauth_tokens SET revoked_at = ? WHERE family = ? AND revoked_at IS NULL`, ms(at), family)
	return err
}

func (o oauth) DeleteExpiredTokens(ctx context.Context, now time.Time) (int, error) {
	n, err := o.s.exec(ctx, "delete expired tokens", `DELETE FROM gk_oauth_tokens WHERE expires_at <= ?`, ms(now))
	return int(n), err
}
