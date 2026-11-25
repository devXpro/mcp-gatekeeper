package oauth

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestValidateAccess(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authPost)
	tk := h.connect(tc, "alice", "notes")
	info, err := h.srv.ValidateAccess(t.Context(), tk.AccessToken, "notes")
	require.NoError(t, err)
	g := h.store.grantList()[0]
	assert.Equal(t, core.AccessInfo{
		GrantID: g.ID, PersonID: alice.Person.ID, AccountID: millers.ID, ResourceID: "notes",
		ClientID: core.ClientID(tc.id), Assistant: core.AssistantChatGPT, Scope: "mcp offline_access",
		ExpiresAt: h.clock.now().Add(time.Hour),
	}, info)

	theirs := h.connect(tc, "bob", "notes")
	info, err = h.srv.ValidateAccess(t.Context(), theirs.AccessToken, "notes")
	require.NoError(t, err)
	assert.Equal(t, bob.Person.ID, info.PersonID, "a token stands for the person who consented")
	assert.NotEqual(t, g.ID, info.GrantID)

	photos := h.connect(tc, "alice", "photos")
	info, err = h.srv.ValidateAccess(t.Context(), photos.AccessToken, "photos")
	require.NoError(t, err)
	assert.Equal(t, core.ResourceID("photos"), info.ResourceID, "one client, another resource: another grant")
	assert.NotEqual(t, g.ID, info.GrantID)
	assert.False(t, h.valid(photos.AccessToken, "notes"))
}

// TestValidateAccessRefusals: every refusal is core.ErrInvalidToken; one of a token the server knows that has ended
// is core.ErrExpired too (review GK-12), so the MCP access check charges no failure to the client's address for it.
func TestValidateAccessRefusals(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, h *harness, tk tokens) (token, resource string)
		ended   bool // a known token that has ended
	}{
		{"a token of another resource", func(_ *testing.T, _ *harness, tk tokens) (string, string) {
			return tk.AccessToken, "photos"
		}, false},
		{"a refresh token", func(_ *testing.T, _ *harness, tk tokens) (string, string) {
			return tk.RefreshToken, "notes"
		}, false},
		{"an unknown token", func(*testing.T, *harness, tokens) (string, string) { return randomToken(), "notes" }, false},
		{"a malformed token", func(*testing.T, *harness, tokens) (string, string) { return "Bearer x", "notes" }, false},
		{"no token", func(*testing.T, *harness, tokens) (string, string) { return "", "notes" }, false},
		{"an expired token", func(_ *testing.T, h *harness, tk tokens) (string, string) {
			h.clock.advance(time.Hour)
			return tk.AccessToken, "notes"
		}, true},
		{"an expired token of another resource", func(_ *testing.T, h *harness, tk tokens) (string, string) {
			h.clock.advance(time.Hour)
			return tk.AccessToken, "photos"
		}, true},
		{"a revoked token", func(t *testing.T, h *harness, tk tokens) (string, string) {
			require.NoError(t, h.store.OAuth().RevokeToken(t.Context(), hashOf(tk.AccessToken), h.clock.now()))
			return tk.AccessToken, "notes"
		}, true},
		{"a token of a revoked grant", func(t *testing.T, h *harness, tk tokens) (string, string) {
			g := h.store.grantList()[0]
			require.NoError(t, h.store.OAuth().RevokeGrant(t.Context(), g.ID, h.clock.now()))
			return tk.AccessToken, "notes"
		}, true},
		{"a token in its hour of a grant past its 180 days", func(t *testing.T, h *harness, tk tokens) (string, string) {
			g := h.store.grantList()[0]
			g.CreatedAt = h.clock.now().Add(-grantTTL)
			require.NoError(t, h.store.OAuth().PutGrant(t.Context(), g))
			return tk.AccessToken, "notes"
		}, true},
		{"a token of a gone client", func(_ *testing.T, h *harness, tk tokens) (string, string) {
			h.store.deleteClient(string(h.store.grantList()[0].ClientID))
			return tk.AccessToken, "notes"
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tk := h.connect(h.registerDCR(claudeCallback, authNone), "alice", "notes")
			token, resource := tt.prepare(t, h, tk)
			_, err := h.srv.ValidateAccess(t.Context(), token, core.ResourceID(resource))
			assert.ErrorIs(t, err, core.ErrInvalidToken)
			assert.Equal(t, tt.ended, errors.Is(err, core.ErrExpired), err)
			if !tt.ended {
				assert.Same(t, core.ErrInvalidToken, err, "bare, as before")
			}
		})
	}
}

func TestValidateAccessStoreFailure(t *testing.T) {
	h := newHarness(t)
	tk := h.connect(h.registerDCR(claudeCallback, authNone), "alice", "notes")
	h.store.failWith("GetToken", errors.New("store down"), true)
	_, err := h.srv.ValidateAccess(t.Context(), tk.AccessToken, "notes")
	require.Error(t, err)
	assert.NotErrorIs(t, err, core.ErrInvalidToken, "a store failure must not send the assistant to sign in")

	h.store.failWith("GetToken", errors.New("store down"), false)
	_, err = h.srv.ValidateAccess(t.Context(), "junk", "notes")
	assert.ErrorIs(t, err, core.ErrInvalidToken, "junk is refused before the store is asked")
}

func TestValidateAccessRecordsUse(t *testing.T) {
	h := newHarness(t)
	tk := h.connect(h.registerDCR(claudeCallback, authNone), "alice", "notes")
	g := h.store.grantList()[0]
	assert.Nil(t, g.LastUsedAt)

	start := h.clock.now()
	require.True(t, h.valid(tk.AccessToken, "notes"))
	require.NotNil(t, h.store.grant(g.ID).LastUsedAt)
	assert.Equal(t, start, *h.store.grant(g.ID).LastUsedAt)

	h.clock.advance(30 * time.Second)
	require.True(t, h.valid(tk.AccessToken, "notes"))
	assert.Equal(t, start, *h.store.grant(g.ID).LastUsedAt, "written at most once a minute")

	h.clock.advance(31 * time.Second)
	require.True(t, h.valid(tk.AccessToken, "notes"))
	assert.Equal(t, h.clock.now(), *h.store.grant(g.ID).LastUsedAt)

	h.clock.advance(time.Minute)
	h.store.failWith("TouchGrant", errors.New("store down"), true)
	assert.True(t, h.valid(tk.AccessToken, "notes"), "a failed write does not fail the call")
}
