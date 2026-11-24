package storetest

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func testOAuthClients(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	c := core.OAuthClient{ID: "cli_a", Kind: core.ClientDCR, Assistant: core.AssistantChatGPT, Name: "ChatGPT",
		RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"}, AuthMethod: "client_secret_post",
		SecretHash: hash("sec"), FetchedAt: now, CreatedAt: now.Add(-48 * time.Hour)}
	require.NoError(t, s.OAuth().PutClient(ctx, c))
	got, err := s.OAuth().GetClient(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, c, got)

	c.Name = "ChatGPT 2"
	c.RedirectURIs = append(c.RedirectURIs, "https://chatgpt.com/other")
	require.NoError(t, s.OAuth().PutClient(ctx, c), "Put replaces")
	got, err = s.OAuth().GetClient(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, c, got)

	require.NoError(t, s.OAuth().TouchClient(ctx, c.ID, now))
	got, err = s.OAuth().GetClient(ctx, c.ID)
	require.NoError(t, err)
	require.NotNil(t, got.LastUsedAt)
	assert.True(t, now.Equal(*got.LastUsedAt))
	assert.ErrorIs(t, s.OAuth().TouchClient(ctx, "cli_missing", now), core.ErrNotFound)
	_, err = s.OAuth().GetClient(ctx, "cli_missing")
	assert.ErrorIs(t, err, core.ErrNotFound)

	// A public client: no secret, and a CIMD id is a URL.
	cimd := core.OAuthClient{ID: "https://claude.ai/oauth/client.json", Kind: core.ClientCIMD, Assistant: core.AssistantClaude,
		Name: "Claude", RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"}, AuthMethod: "none",
		FetchedAt: now, CreatedAt: now.Add(-48 * time.Hour)}
	require.NoError(t, s.OAuth().PutClient(ctx, cimd))
	got, err = s.OAuth().GetClient(ctx, cimd.ID)
	require.NoError(t, err)
	assert.Equal(t, cimd, got)
	assert.Empty(t, got.SecretHash)

	// Idle clients: old DCR without grants go (revoked grants count as grants); DCR with a grant, young DCR and CIMD
	// stay.
	mk := func(id string, created time.Time) {
		require.NoError(t, s.OAuth().PutClient(ctx, core.OAuthClient{ID: core.ClientID(id), Kind: core.ClientDCR,
			Assistant: core.AssistantClaude, AuthMethod: "none", RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"},
			FetchedAt: created, CreatedAt: created}))
	}
	mk("cli_old_idle", now.Add(-48*time.Hour))
	mk("cli_old_used", now.Add(-48*time.Hour))
	mk("cli_old_revoked", now.Add(-48*time.Hour))
	mk("cli_young", now.Add(-time.Hour))
	require.NoError(t, s.OAuth().PutGrant(ctx, core.Grant{ID: "grt_1", PersonID: "per_a", AccountID: "acc_a",
		ClientID: "cli_old_used", ResourceID: "notes", CreatedAt: now}))
	require.NoError(t, s.OAuth().PutGrant(ctx, core.Grant{ID: "grt_2", PersonID: "per_a", AccountID: "acc_a",
		ClientID: "cli_old_revoked", ResourceID: "notes", CreatedAt: now, RevokedAt: &now}))
	n, err := s.OAuth().DeleteIdleClients(ctx, now.Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 2, n, "cli_a (no grant) and cli_old_idle")
	for _, id := range []core.ClientID{"cli_old_used", "cli_old_revoked", "cli_young", cimd.ID} {
		_, err := s.OAuth().GetClient(ctx, id)
		assert.NoError(t, err, id)
	}
	for _, id := range []core.ClientID{"cli_a", "cli_old_idle"} {
		_, err = s.OAuth().GetClient(ctx, id)
		assert.ErrorIs(t, err, core.ErrNotFound, id)
	}
	n, err = s.OAuth().DeleteIdleClients(ctx, now.Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Zero(t, n)
}

func testOAuthCodes(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	c := core.AuthCode{CodeHash: hash("code"), GrantID: "grt_1", ClientID: "cli_a", RedirectURI: "https://x/cb",
		Resource: "https://hub/mcp/notes", Scope: "mcp", CodeChallenge: "chal", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	require.NoError(t, s.OAuth().PutCode(ctx, c))
	assert.ErrorIs(t, s.OAuth().PutCode(ctx, c), core.ErrConflict)

	got, err := s.OAuth().ConsumeCode(ctx, c.CodeHash, now)
	require.NoError(t, err)
	assert.Equal(t, c, got)
	_, err = s.OAuth().ConsumeCode(ctx, c.CodeHash, now)
	assert.ErrorIs(t, err, core.ErrNotFound, "a code works once")
	_, err = s.OAuth().ConsumeCode(ctx, hash("unknown"), now)
	assert.ErrorIs(t, err, core.ErrNotFound)

	stale := c
	stale.CodeHash = hash("stale")
	require.NoError(t, s.OAuth().PutCode(ctx, stale))
	_, err = s.OAuth().ConsumeCode(ctx, stale.CodeHash, now.Add(10*time.Minute))
	assert.ErrorIs(t, err, core.ErrExpired)
	_, err = s.OAuth().ConsumeCode(ctx, stale.CodeHash, now)
	assert.ErrorIs(t, err, core.ErrNotFound, "an expired code is removed by the attempt")

	edge := c
	edge.CodeHash = hash("edge")
	require.NoError(t, s.OAuth().PutCode(ctx, edge))
	_, err = s.OAuth().ConsumeCode(ctx, edge.CodeHash, edge.ExpiresAt)
	assert.ErrorIs(t, err, core.ErrExpired, "a code expires at ExpiresAt")
}

func testConsumeCodeConcurrent(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	c := core.AuthCode{CodeHash: hash("race"), GrantID: "grt_1", ClientID: "cli_a", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	require.NoError(t, s.OAuth().PutCode(ctx, c))
	errs := race(32, func(int) error {
		_, err := s.OAuth().ConsumeCode(ctx, c.CodeHash, now)
		return err
	})
	assertOneWinner(t, errs, core.ErrNotFound)
}

func testOAuthGrantsAndTokens(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	g := core.Grant{ID: "grt_1", PersonID: "per_a", AccountID: "acc_a", ClientID: "cli_a", ResourceID: "notes", Scope: "mcp", CreatedAt: now}
	require.NoError(t, s.OAuth().PutGrant(ctx, g))
	got, err := s.OAuth().GetGrant(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, g, got)
	_, err = s.OAuth().GetGrant(ctx, "grt_missing")
	assert.ErrorIs(t, err, core.ErrNotFound)
	found, err := s.OAuth().FindGrant(ctx, "per_a", "cli_a", "notes")
	require.NoError(t, err)
	assert.Equal(t, g, found)
	_, err = s.OAuth().FindGrant(ctx, "per_a", "cli_a", "photos")
	assert.ErrorIs(t, err, core.ErrNotFound)
	_, err = s.OAuth().FindGrant(ctx, "per_b", "cli_a", "notes")
	assert.ErrorIs(t, err, core.ErrNotFound)
	_, err = s.OAuth().FindGrant(ctx, "per_a", "cli_b", "notes")
	assert.ErrorIs(t, err, core.ErrNotFound)

	// A second active grant for the same triple is refused; Put with the same id replaces.
	twin := g
	twin.ID = "grt_2"
	assert.ErrorIs(t, s.OAuth().PutGrant(ctx, twin), core.ErrConflict)
	g.Scope = "mcp offline_access"
	require.NoError(t, s.OAuth().PutGrant(ctx, g))
	got, err = s.OAuth().GetGrant(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, "mcp offline_access", got.Scope)

	require.NoError(t, s.OAuth().TouchGrant(ctx, g.ID, now))
	got, err = s.OAuth().GetGrant(ctx, g.ID)
	require.NoError(t, err)
	require.NotNil(t, got.LastUsedAt)
	assert.True(t, now.Equal(*got.LastUsedAt))
	assert.ErrorIs(t, s.OAuth().TouchGrant(ctx, "grt_missing", now), core.ErrNotFound)

	access := core.Token{Hash: hash("acc"), GrantID: g.ID, Kind: core.TokenAccess, Family: "fam1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	refresh := core.Token{Hash: hash("ref"), GrantID: g.ID, Kind: core.TokenRefresh, Family: "fam1", CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour)}
	require.NoError(t, s.OAuth().PutToken(ctx, access))
	require.NoError(t, s.OAuth().PutToken(ctx, refresh))
	assert.ErrorIs(t, s.OAuth().PutToken(ctx, access), core.ErrConflict)
	gt, err := s.OAuth().GetToken(ctx, access.Hash)
	require.NoError(t, err)
	assert.Equal(t, access, gt)
	_, err = s.OAuth().GetToken(ctx, hash("unknown"))
	assert.ErrorIs(t, err, core.ErrNotFound)
	earlyRevoked := core.Token{Hash: hash("early"), GrantID: g.ID, Kind: core.TokenAccess, Family: "fam0", CreatedAt: now,
		ExpiresAt: now.Add(time.Hour), RevokedAt: new(now.Add(-time.Minute))}
	require.NoError(t, s.OAuth().PutToken(ctx, earlyRevoked))

	// The account's active grants, oldest first; another account's stay out.
	older := core.Grant{ID: "grt_0", PersonID: "per_b", AccountID: "acc_a", ClientID: "cli_a", ResourceID: "notes", CreatedAt: now.Add(-time.Hour)}
	require.NoError(t, s.OAuth().PutGrant(ctx, older))
	require.NoError(t, s.OAuth().PutGrant(ctx, core.Grant{ID: "grt_9", PersonID: "per_z", AccountID: "acc_z", ClientID: "cli_a",
		ResourceID: "notes", CreatedAt: now}))
	list, err := s.OAuth().ListGrantsByAccount(ctx, "acc_a")
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, []core.GrantID{older.ID, g.ID}, []core.GrantID{list[0].ID, list[1].ID})

	// Revoking the grant revokes its tokens and frees the triple for a new grant.
	require.NoError(t, s.OAuth().RevokeGrant(ctx, g.ID, now))
	require.NoError(t, s.OAuth().RevokeGrant(ctx, g.ID, now.Add(time.Hour)), "revoking twice is fine")
	assert.ErrorIs(t, s.OAuth().RevokeGrant(ctx, "grt_missing", now), core.ErrNotFound)
	got, err = s.OAuth().GetGrant(ctx, g.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RevokedAt)
	assert.True(t, now.Equal(*got.RevokedAt), "the first revocation time wins")
	for _, h := range [][]byte{access.Hash, refresh.Hash} {
		tk, err := s.OAuth().GetToken(ctx, h)
		require.NoError(t, err)
		require.NotNil(t, tk.RevokedAt)
		assert.True(t, now.Equal(*tk.RevokedAt))
	}
	tk, err := s.OAuth().GetToken(ctx, earlyRevoked.Hash)
	require.NoError(t, err)
	assert.Equal(t, earlyRevoked, tk, "a token revoked before keeps its time")
	_, err = s.OAuth().FindGrant(ctx, "per_a", "cli_a", "notes")
	assert.ErrorIs(t, err, core.ErrNotFound)
	list, err = s.OAuth().ListGrantsByAccount(ctx, "acc_a")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, older.ID, list[0].ID)
	require.NoError(t, s.OAuth().PutGrant(ctx, twin), "a revoked grant leaves the unique key")
	found, err = s.OAuth().FindGrant(ctx, "per_a", "cli_a", "notes")
	require.NoError(t, err)
	assert.Equal(t, twin.ID, found.ID)
}

func testRevokeGrantsByResource(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	for i, r := range []core.ResourceID{"notes", "notes", "photos"} {
		g := core.Grant{ID: core.GrantID(fmt.Sprintf("grt_%d", i)), PersonID: core.PersonID(fmt.Sprintf("per_%d", i)),
			AccountID: "acc_a", ClientID: "cli_a", ResourceID: r, CreatedAt: now}
		require.NoError(t, s.OAuth().PutGrant(ctx, g))
		require.NoError(t, s.OAuth().PutToken(ctx, core.Token{Hash: hash(fmt.Sprint("t", i)), GrantID: g.ID, Kind: core.TokenAccess,
			Family: "f", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}))
	}
	require.NoError(t, s.OAuth().RevokeGrantsByResource(ctx, "notes", now))
	require.NoError(t, s.OAuth().RevokeGrantsByResource(ctx, "notes", now.Add(time.Hour)), "revoking twice is fine")
	for i, wantRevoked := range []bool{true, true, false} {
		g, err := s.OAuth().GetGrant(ctx, core.GrantID(fmt.Sprintf("grt_%d", i)))
		require.NoError(t, err)
		require.Equal(t, wantRevoked, g.RevokedAt != nil, "grant %d", i)
		tk, err := s.OAuth().GetToken(ctx, hash(fmt.Sprint("t", i)))
		require.NoError(t, err)
		require.Equal(t, wantRevoked, tk.RevokedAt != nil, "token %d", i)
		if wantRevoked {
			assert.True(t, now.Equal(*g.RevokedAt), "the first revocation time wins")
			assert.True(t, now.Equal(*tk.RevokedAt))
		}
	}
	require.NoError(t, s.OAuth().RevokeGrantsByResource(ctx, "none", now), "a resource without grants is fine")
}

func testUseRefresh(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	mk := func(id string, kind core.TokenKind, expires time.Time) core.Token {
		tk := core.Token{Hash: hash(id), GrantID: "grt_1", Kind: kind, Family: "fam", CreatedAt: now, ExpiresAt: expires}
		require.NoError(t, s.OAuth().PutToken(ctx, tk))
		return tk
	}
	live := mk("live", core.TokenRefresh, now.Add(time.Hour))
	got, err := s.OAuth().UseRefresh(ctx, live.Hash, now)
	require.NoError(t, err)
	require.NotNil(t, got.UsedAt)
	assert.True(t, now.Equal(*got.UsedAt))
	got.UsedAt = nil
	assert.Equal(t, live, got, "UseRefresh returns the token")
	_, err = s.OAuth().UseRefresh(ctx, live.Hash, now)
	assert.ErrorIs(t, err, core.ErrUsed, "reuse of a rotated token")
	_, err = s.OAuth().UseRefresh(ctx, live.Hash, now.Add(2*time.Hour))
	assert.ErrorIs(t, err, core.ErrUsed, "reuse is reported even after the expiry")

	exp := mk("exp", core.TokenRefresh, now.Add(-time.Minute))
	_, err = s.OAuth().UseRefresh(ctx, exp.Hash, now)
	assert.ErrorIs(t, err, core.ErrExpired)
	edge := mk("edge", core.TokenRefresh, now)
	_, err = s.OAuth().UseRefresh(ctx, edge.Hash, now)
	assert.ErrorIs(t, err, core.ErrExpired, "a token expires at ExpiresAt")

	acc := mk("acc", core.TokenAccess, now.Add(time.Hour))
	_, err = s.OAuth().UseRefresh(ctx, acc.Hash, now)
	assert.ErrorIs(t, err, core.ErrNotFound, "an access token is no refresh token")
	_, err = s.OAuth().UseRefresh(ctx, hash("unknown"), now)
	assert.ErrorIs(t, err, core.ErrNotFound)

	other := mk("other", core.TokenRefresh, now.Add(time.Hour))
	require.NoError(t, s.OAuth().RevokeToken(ctx, other.Hash, now))
	require.NoError(t, s.OAuth().RevokeToken(ctx, other.Hash, now.Add(time.Minute)), "revoking twice is fine")
	tk, err := s.OAuth().GetToken(ctx, other.Hash)
	require.NoError(t, err)
	require.NotNil(t, tk.RevokedAt)
	assert.True(t, now.Equal(*tk.RevokedAt), "the first revocation time wins")
	_, err = s.OAuth().UseRefresh(ctx, other.Hash, now)
	assert.ErrorIs(t, err, core.ErrNotFound, "a revoked token is dead")
	assert.ErrorIs(t, s.OAuth().RevokeToken(ctx, hash("unknown"), now), core.ErrNotFound)

	// The family revoke after a reuse reaches every token of the family and no other.
	stranger := core.Token{Hash: hash("stranger"), GrantID: "grt_9", Kind: core.TokenRefresh, Family: "other-fam", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	require.NoError(t, s.OAuth().PutToken(ctx, stranger))
	require.NoError(t, s.OAuth().RevokeFamily(ctx, "fam", now.Add(time.Second)))
	require.NoError(t, s.OAuth().RevokeFamily(ctx, "no-such-family", now))
	for _, h := range [][]byte{live.Hash, acc.Hash, exp.Hash, edge.Hash} {
		tk, err := s.OAuth().GetToken(ctx, h)
		require.NoError(t, err)
		require.NotNil(t, tk.RevokedAt)
		assert.True(t, now.Add(time.Second).Equal(*tk.RevokedAt))
	}
	tk, err = s.OAuth().GetToken(ctx, other.Hash)
	require.NoError(t, err)
	assert.True(t, now.Equal(*tk.RevokedAt), "a revoked token keeps its first time")
	tk, err = s.OAuth().GetToken(ctx, stranger.Hash)
	require.NoError(t, err)
	assert.Nil(t, tk.RevokedAt)

	n, err := s.OAuth().DeleteExpiredTokens(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "the expired one and the one that expires now")
	for _, h := range [][]byte{exp.Hash, edge.Hash} {
		_, err = s.OAuth().GetToken(ctx, h)
		assert.ErrorIs(t, err, core.ErrNotFound)
	}
	_, err = s.OAuth().GetToken(ctx, live.Hash)
	assert.NoError(t, err)
}

func testUseRefreshConcurrent(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	now := ms()
	tk := core.Token{Hash: hash("race"), GrantID: "grt_1", Kind: core.TokenRefresh, Family: "f", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	require.NoError(t, s.OAuth().PutToken(ctx, tk))
	errs := race(32, func(int) error {
		_, err := s.OAuth().UseRefresh(ctx, tk.Hash, now)
		return err
	})
	assertOneWinner(t, errs, core.ErrUsed)
}
