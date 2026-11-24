package mongostore

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/devXpro/mcp-gatekeeper/core"
)

type clientDoc struct {
	ID           string     `bson:"_id"`
	Kind         string     `bson:"kind"`
	Assistant    string     `bson:"assistant"`
	Name         string     `bson:"name"`
	RedirectURIs []string   `bson:"redirect_uris"`
	AuthMethod   string     `bson:"auth_method"`
	SecretHash   []byte     `bson:"secret_hash,omitempty"`
	FetchedAt    time.Time  `bson:"fetched_at"`
	CreatedAt    time.Time  `bson:"created_at"`
	LastUsedAt   *time.Time `bson:"last_used_at,omitempty"`
}

func (d clientDoc) toCore() core.OAuthClient {
	return core.OAuthClient{
		ID: core.ClientID(d.ID), Kind: core.ClientKind(d.Kind), Assistant: core.Assistant(d.Assistant), Name: d.Name,
		RedirectURIs: d.RedirectURIs, AuthMethod: d.AuthMethod, SecretHash: d.SecretHash, FetchedAt: utc(d.FetchedAt),
		CreatedAt: utc(d.CreatedAt), LastUsedAt: optTime(d.LastUsedAt),
	}
}

type codeDoc struct {
	CodeHash      []byte    `bson:"_id"`
	GrantID       string    `bson:"grant_id"`
	ClientID      string    `bson:"client_id"`
	RedirectURI   string    `bson:"redirect_uri"`
	Resource      string    `bson:"resource"`
	Scope         string    `bson:"scope"`
	CodeChallenge string    `bson:"code_challenge"`
	CreatedAt     time.Time `bson:"created_at"`
	ExpiresAt     time.Time `bson:"expires_at"`
}

func (d codeDoc) toCore() core.AuthCode {
	return core.AuthCode{
		CodeHash: d.CodeHash, GrantID: core.GrantID(d.GrantID), ClientID: core.ClientID(d.ClientID),
		RedirectURI: d.RedirectURI, Resource: d.Resource, Scope: d.Scope, CodeChallenge: d.CodeChallenge,
		CreatedAt: utc(d.CreatedAt), ExpiresAt: utc(d.ExpiresAt),
	}
}

type grantDoc struct {
	ID         string     `bson:"_id"`
	PersonID   string     `bson:"person_id"`
	AccountID  string     `bson:"account_id"`
	ClientID   string     `bson:"client_id"`
	ResourceID string     `bson:"module_id"` // Family Hub's name for the resource; the live database keeps it
	Scope      string     `bson:"scope"`
	CreatedAt  time.Time  `bson:"created_at"`
	LastUsedAt *time.Time `bson:"last_used_at,omitempty"`
	RevokedAt  *time.Time `bson:"revoked_at"` // stored as null while the grant is active: the unique index relies on it
}

func (d grantDoc) toCore() core.Grant {
	return core.Grant{
		ID: core.GrantID(d.ID), PersonID: core.PersonID(d.PersonID), AccountID: core.AccountID(d.AccountID),
		ClientID: core.ClientID(d.ClientID), ResourceID: core.ResourceID(d.ResourceID), Scope: d.Scope,
		CreatedAt: utc(d.CreatedAt), LastUsedAt: optTime(d.LastUsedAt), RevokedAt: optTime(d.RevokedAt),
	}
}

type tokenDoc struct {
	Hash      []byte     `bson:"_id"`
	GrantID   string     `bson:"grant_id"`
	Kind      string     `bson:"kind"`
	Family    string     `bson:"family"`
	CreatedAt time.Time  `bson:"created_at"`
	ExpiresAt time.Time  `bson:"expires_at"`
	UsedAt    *time.Time `bson:"used_at,omitempty"`
	RevokedAt *time.Time `bson:"revoked_at,omitempty"`
}

func (d tokenDoc) toCore() core.Token {
	return core.Token{
		Hash: d.Hash, GrantID: core.GrantID(d.GrantID), Kind: core.TokenKind(d.Kind), Family: d.Family,
		CreatedAt: utc(d.CreatedAt), ExpiresAt: utc(d.ExpiresAt), UsedAt: optTime(d.UsedAt), RevokedAt: optTime(d.RevokedAt),
	}
}

type oauthStore struct{ s *Store }

func (o oauthStore) PutClient(ctx context.Context, c core.OAuthClient) error {
	uris := c.RedirectURIs
	if uris == nil {
		uris = []string{}
	}
	return o.s.c(colOAuthClients).upsert(ctx, string(c.ID), clientDoc{
		ID: string(c.ID), Kind: string(c.Kind), Assistant: string(c.Assistant), Name: c.Name, RedirectURIs: uris,
		AuthMethod: c.AuthMethod, SecretHash: c.SecretHash, FetchedAt: c.FetchedAt, CreatedAt: c.CreatedAt,
		LastUsedAt: optTime(c.LastUsedAt),
	})
}

func (o oauthStore) GetClient(ctx context.Context, id core.ClientID) (core.OAuthClient, error) {
	d, err := findOne[clientDoc](ctx, o.s.c(colOAuthClients), idIs(string(id)))
	if err != nil {
		return core.OAuthClient{}, err
	}
	return d.toCore(), nil
}

func (o oauthStore) TouchClient(ctx context.Context, id core.ClientID, at time.Time) error {
	return o.s.c(colOAuthClients).update(ctx, idIs(string(id)), set(kv("last_used_at", at)))
}

// DeleteIdleClients removes DCR clients created before cutoff that no grant, revoked ones included, points at.
func (o oauthStore) DeleteIdleClients(ctx context.Context, cutoff time.Time) (int, error) {
	var n int
	err := o.s.Tx(ctx, func(ctx context.Context) error {
		ids, err := stringIDs(ctx, o.s.c(colOAuthClients), bson.D{
			{Key: "kind", Value: string(core.ClientDCR)},
			{Key: "created_at", Value: kv("$lt", cutoff)},
		})
		if err != nil || len(ids) == 0 {
			return err
		}
		grants, err := findAll[grantDoc](ctx, o.s.c(colOAuthGrants), kv("client_id", kv("$in", ids)), nil, 0)
		if err != nil {
			return err
		}
		usedIDs := make([]string, len(grants))
		for i, g := range grants {
			usedIDs[i] = g.ClientID
		}
		inUse := make(map[string]bool, len(usedIDs))
		for _, id := range usedIDs {
			inUse[id] = true
		}
		var idle []string
		for _, id := range ids {
			if !inUse[id] {
				idle = append(idle, id)
			}
		}
		if len(idle) == 0 {
			return nil
		}
		n, err = o.s.c(colOAuthClients).deleteMany(ctx, idIs(kv("$in", idle)))
		return err
	})
	return n, err
}

func (o oauthStore) PutCode(ctx context.Context, c core.AuthCode) error {
	return o.s.c(colOAuthCodes).insert(ctx, codeDoc{
		CodeHash: c.CodeHash, GrantID: string(c.GrantID), ClientID: string(c.ClientID), RedirectURI: c.RedirectURI,
		Resource: c.Resource, Scope: c.Scope, CodeChallenge: c.CodeChallenge, CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt,
	})
}

// ConsumeCode deletes the code with one findOneAndDelete, so of two concurrent calls one wins. A code found past its
// end is deleted too and answered with core.ErrExpired.
func (o oauthStore) ConsumeCode(ctx context.Context, codeHash []byte, now time.Time) (core.AuthCode, error) {
	c := o.s.c(colOAuthCodes)
	var d codeDoc
	err := c.c.FindOneAndDelete(ctx, idIs(codeHash)).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return core.AuthCode{}, c.notFound("consume")
	}
	if err != nil {
		return core.AuthCode{}, c.wrap("consume", err)
	}
	if !d.ExpiresAt.After(now) {
		return core.AuthCode{}, c.wrap("consume", core.ErrExpired)
	}
	return d.toCore(), nil
}

// PutGrant inserts the grant or replaces the one with the same id. A second active grant for the same (person,
// client, resource) is core.ErrConflict.
func (o oauthStore) PutGrant(ctx context.Context, g core.Grant) error {
	return o.s.c(colOAuthGrants).upsert(ctx, string(g.ID), grantDoc{
		ID: string(g.ID), PersonID: string(g.PersonID), AccountID: string(g.AccountID), ClientID: string(g.ClientID),
		ResourceID: string(g.ResourceID), Scope: g.Scope, CreatedAt: g.CreatedAt, LastUsedAt: optTime(g.LastUsedAt),
		RevokedAt: optTime(g.RevokedAt),
	})
}

// GetGrant returns a grant, revoked or not.
func (o oauthStore) GetGrant(ctx context.Context, id core.GrantID) (core.Grant, error) {
	d, err := findOne[grantDoc](ctx, o.s.c(colOAuthGrants), idIs(string(id)))
	if err != nil {
		return core.Grant{}, err
	}
	return d.toCore(), nil
}

func (o oauthStore) FindGrant(ctx context.Context, p core.PersonID, c core.ClientID, r core.ResourceID) (core.Grant, error) {
	d, err := findOne[grantDoc](ctx, o.s.c(colOAuthGrants), bson.D{
		{Key: "person_id", Value: string(p)},
		{Key: "client_id", Value: string(c)},
		{Key: "module_id", Value: string(r)},
		{Key: "revoked_at", Value: nil},
	})
	if err != nil {
		return core.Grant{}, err
	}
	return d.toCore(), nil
}

// ListGrantsByAccount returns the active grants of an account, oldest first.
func (o oauthStore) ListGrantsByAccount(ctx context.Context, a core.AccountID) ([]core.Grant, error) {
	docs, err := findAll[grantDoc](ctx, o.s.c(colOAuthGrants), bson.D{
		{Key: "account_id", Value: string(a)},
		{Key: "revoked_at", Value: nil},
	}, bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}, 0)
	if err != nil {
		return nil, err
	}
	out := make([]core.Grant, len(docs))
	for i, d := range docs {
		out[i] = d.toCore()
	}
	return out, nil
}

func (o oauthStore) TouchGrant(ctx context.Context, id core.GrantID, at time.Time) error {
	return o.s.c(colOAuthGrants).update(ctx, idIs(string(id)), set(kv("last_used_at", at)))
}

// RevokeGrant revokes the grant and every token of it in one transaction.
func (o oauthStore) RevokeGrant(ctx context.Context, id core.GrantID, at time.Time) error {
	return o.s.Tx(ctx, func(ctx context.Context) error {
		if err := o.s.c(colOAuthGrants).markOnce(ctx, idIs(string(id)), "revoked_at", at); err != nil {
			return err
		}
		err := o.s.c(colOAuthTokens).updateMany(ctx, bson.D{
			{Key: "grant_id", Value: string(id)}, {Key: "revoked_at", Value: nil},
		}, set(kv("revoked_at", at)))
		return err
	})
}

// RevokeGrantsByResource revokes every grant of a resource and their tokens in one transaction.
func (o oauthStore) RevokeGrantsByResource(ctx context.Context, r core.ResourceID, at time.Time) error {
	return o.s.Tx(ctx, func(ctx context.Context) error {
		ids, err := stringIDs(ctx, o.s.c(colOAuthGrants), kv("module_id", string(r)))
		if err != nil || len(ids) == 0 {
			return err
		}
		if err := o.s.c(colOAuthGrants).updateMany(ctx, bson.D{
			{Key: "module_id", Value: string(r)}, {Key: "revoked_at", Value: nil},
		}, set(kv("revoked_at", at))); err != nil {
			return err
		}
		err = o.s.c(colOAuthTokens).updateMany(ctx, bson.D{
			{Key: "grant_id", Value: kv("$in", ids)}, {Key: "revoked_at", Value: nil},
		}, set(kv("revoked_at", at)))
		return err
	})
}

func (o oauthStore) PutToken(ctx context.Context, t core.Token) error {
	return o.s.c(colOAuthTokens).insert(ctx, tokenDoc{
		Hash: t.Hash, GrantID: string(t.GrantID), Kind: string(t.Kind), Family: t.Family, CreatedAt: t.CreatedAt,
		ExpiresAt: t.ExpiresAt, UsedAt: optTime(t.UsedAt), RevokedAt: optTime(t.RevokedAt),
	})
}

// GetToken returns a token as stored, expired or revoked or not: the validator decides.
func (o oauthStore) GetToken(ctx context.Context, hash []byte) (core.Token, error) {
	d, err := findOne[tokenDoc](ctx, o.s.c(colOAuthTokens), idIs(hash))
	if err != nil {
		return core.Token{}, err
	}
	return d.toCore(), nil
}

// UseRefresh marks a live refresh token used with one findOneAndUpdate, so of two concurrent calls one wins. An
// already rotated token is core.ErrUsed (the caller revokes its family); a revoked or unknown one, or an access
// token, is core.ErrNotFound; an expired one is core.ErrExpired.
func (o oauthStore) UseRefresh(ctx context.Context, hash []byte, at time.Time) (core.Token, error) {
	c := o.s.c(colOAuthTokens)
	d, err := findAndUpdate[tokenDoc](ctx, c, bson.D{
		{Key: "_id", Value: hash},
		{Key: "kind", Value: string(core.TokenRefresh)},
		{Key: "used_at", Value: nil},
		{Key: "revoked_at", Value: nil},
		{Key: "expires_at", Value: kv("$gt", at)},
	}, set(kv("used_at", at)))
	if err == nil {
		return d.toCore(), nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return core.Token{}, c.wrap("use refresh", err)
	}
	cur, err := findOne[tokenDoc](ctx, c, idIs(hash))
	if err != nil {
		return core.Token{}, err
	}
	switch {
	case cur.Kind != string(core.TokenRefresh):
		return core.Token{}, c.notFound("use refresh of an access token")
	case cur.UsedAt != nil:
		return core.Token{}, c.wrap("use refresh", core.ErrUsed)
	case cur.RevokedAt != nil:
		return core.Token{}, c.notFound("use revoked refresh token")
	case !cur.ExpiresAt.After(at):
		return core.Token{}, c.wrap("use refresh", core.ErrExpired)
	}
	return core.Token{}, c.wrap("use refresh", core.ErrUsed) // live a moment ago: another call took it
}

func (o oauthStore) RevokeToken(ctx context.Context, hash []byte, at time.Time) error {
	return o.s.c(colOAuthTokens).markOnce(ctx, idIs(hash), "revoked_at", at)
}

func (o oauthStore) RevokeFamily(ctx context.Context, family string, at time.Time) error {
	err := o.s.c(colOAuthTokens).updateMany(ctx, bson.D{
		{Key: "family", Value: family}, {Key: "revoked_at", Value: nil},
	}, set(kv("revoked_at", at)))
	return err
}

func (o oauthStore) DeleteExpiredTokens(ctx context.Context, now time.Time) (int, error) {
	return o.s.c(colOAuthTokens).deleteMany(ctx, kv("expires_at", kv("$lte", now)))
}
