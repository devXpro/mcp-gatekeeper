package storetest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// testPurge pins the retention of store.Purger, which an adapter without TTL indexes implements to keep what the
// MongoDB adapter's TTL indexes keep:
//   - tokens and codes are removed when their end is reached (ExpiresAt <= now);
//   - invites 7 days after their expiry, used or not;
//   - audit entries older than 400 days;
//   - DCR clients older than an hour that no grant, revoked ones included, points at.
//
// Whatever is inside the retention stays, and a second Purge finds nothing. The test is skipped for an adapter that
// is not a store.Purger.
func testPurge(t *testing.T, open Open) {
	ctx := t.Context()
	s := open(t)
	purger, ok := s.(store.Purger)
	if !ok {
		t.Skip("the adapter expires data by itself (TTL indexes) and has no Purger")
	}
	now := ms()
	day := 24 * time.Hour

	// Tokens: reached or past the end go; a token without an end yet stays, used and revoked ones too until then.
	put := func(name string, expires time.Time) {
		require.NoError(t, s.OAuth().PutToken(ctx, core.Token{Hash: hash(name), GrantID: "grt_1", Kind: core.TokenAccess,
			Family: "fam", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: expires}))
		require.NoError(t, s.OAuth().PutCode(ctx, core.AuthCode{CodeHash: hash(name), GrantID: "grt_1", ClientID: "cli_x",
			CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: expires}))
	}
	put("old", now.Add(-time.Hour))
	put("edge", now)
	put("live", now.Add(time.Millisecond))
	put("later", now.Add(time.Hour))

	// Invites: kept 7 days past the expiry, so Peek can say "used" rather than "unknown".
	invite := func(name string, expires time.Time) {
		require.NoError(t, s.Invites().Create(ctx, core.Invite{ID: "inv_" + name, TokenHash: hash("inv-" + name),
			Kind: core.InviteMember, AccountID: "acc_x", CreatedBy: "per_x", CreatedAt: expires.Add(-time.Hour), ExpiresAt: expires,
			UsedAt: &now}))
	}
	invite("ancient", now.Add(-8*day))
	invite("week", now.Add(-6*day-23*time.Hour))
	invite("fresh", now.Add(-time.Hour))
	invite("future", now.Add(2*day))

	// Audit: 400 days.
	for name, at := range map[string]time.Time{"audit.ancient": now.Add(-401 * day), "audit.year": now.Add(-399 * day),
		"audit.now": now} {
		require.NoError(t, s.Audit().Append(ctx, core.AuditEntry{At: at, Action: name}))
	}

	// Clients: DCR without a grant for more than an hour go; CIMD clients and ones with a grant stay.
	client := func(id string, kind core.ClientKind, age time.Duration) {
		require.NoError(t, s.OAuth().PutClient(ctx, core.OAuthClient{ID: core.ClientID(id), Kind: kind,
			Assistant: core.AssistantClaude, AuthMethod: "none", RedirectURIs: []string{"https://claude.ai/cb"},
			FetchedAt: now.Add(-age), CreatedAt: now.Add(-age)}))
	}
	client("cli_idle", core.ClientDCR, 2*time.Hour)
	client("cli_young", core.ClientDCR, 30*time.Minute)
	client("cli_used", core.ClientDCR, 2*time.Hour)
	client("cli_revoked", core.ClientDCR, 2*time.Hour)
	client("https://example.com/client.json", core.ClientCIMD, 100*day)
	require.NoError(t, s.OAuth().PutGrant(ctx, core.Grant{ID: "grt_1", PersonID: "per_a", AccountID: "acc_a", ClientID: "cli_used",
		ResourceID: "res-a", CreatedAt: now}))
	require.NoError(t, s.OAuth().PutGrant(ctx, core.Grant{ID: "grt_2", PersonID: "per_a", AccountID: "acc_a", ClientID: "cli_revoked",
		ResourceID: "res-a", CreatedAt: now, RevokedAt: &now}))

	st, err := purger.Purge(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, store.PurgeStats{Tokens: 2, Codes: 2, Invites: 1, Audit: 1, Clients: 1}, st)

	long := now.Add(-time.Hour) // a clock behind the expiries, to read a row without its expiry deciding the answer
	for _, name := range []string{"old", "edge"} {
		_, err := s.OAuth().GetToken(ctx, hash(name))
		assert.ErrorIs(t, err, core.ErrNotFound, "token "+name)
		_, err = s.OAuth().ConsumeCode(ctx, hash(name), long.Add(-day))
		assert.ErrorIs(t, err, core.ErrNotFound, "code "+name)
	}
	for _, name := range []string{"live", "later"} {
		_, err := s.OAuth().GetToken(ctx, hash(name))
		assert.NoError(t, err, "token "+name)
		_, err = s.OAuth().ConsumeCode(ctx, hash(name), long)
		assert.NoError(t, err, "code "+name)
	}

	_, err = s.Invites().Peek(ctx, hash("inv-ancient"), now)
	assert.ErrorIs(t, err, core.ErrNotFound)
	for _, name := range []string{"week", "fresh", "future"} {
		_, err := s.Invites().Peek(ctx, hash("inv-"+name), now)
		assert.NotErrorIs(t, err, core.ErrNotFound, "invite "+name)
	}

	entries, err := s.Audit().ListSystem(ctx, "", 10)
	require.NoError(t, err)
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	assert.ElementsMatch(t, []string{"audit.year", "audit.now"}, actions)

	for _, id := range []core.ClientID{"cli_idle"} {
		_, err := s.OAuth().GetClient(ctx, id)
		assert.ErrorIs(t, err, core.ErrNotFound, string(id))
	}
	for _, id := range []core.ClientID{"cli_young", "cli_used", "cli_revoked", "https://example.com/client.json"} {
		_, err := s.OAuth().GetClient(ctx, id)
		assert.NoError(t, err, string(id))
	}

	st, err = purger.Purge(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, store.PurgeStats{}, st, "a second purge finds nothing")

	// Time passes: what was inside the retention goes at its time.
	st, err = purger.Purge(ctx, now.Add(8*day))
	require.NoError(t, err)
	assert.Equal(t, store.PurgeStats{Tokens: 2, Invites: 2, Audit: 1, Clients: 1}, st,
		"the tokens, the invites past 7 days (week, fresh), the audit entry now over 400 days old and the young client (now over an hour old); the codes were consumed above")
}
