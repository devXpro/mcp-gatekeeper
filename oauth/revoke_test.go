package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestRevoke(t *testing.T) {
	tests := []struct {
		name        string
		token       func(tk tokens) string
		hint        string
		other       bool // another client sends the request
		accessAlive bool
		refreshOK   bool // the refresh token still works afterwards
	}{
		{"an access token", func(tk tokens) string { return tk.AccessToken }, "", false, false, true},
		{"an access token with the wrong hint", func(tk tokens) string { return tk.AccessToken }, "refresh_token",
			false, false, true},
		{"a refresh token revokes its family", func(tk tokens) string { return tk.RefreshToken }, "refresh_token",
			false, false, false},
		{"an unknown token", func(tokens) string { return randomToken() }, "", false, true, true},
		{"a malformed token", func(tokens) string { return "not-a-token" }, "", false, true, true},
		{"another client's token", func(tk tokens) string { return tk.RefreshToken }, "", true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tc := h.registerDCR(chatgptCallback, authBasic)
			tk := h.connect(tc, "alice", "notes")
			from := tc
			if tt.other {
				from = h.registerDCR(chatgptCallback, authPost)
			}
			form := url.Values{"token": {tt.token(tk)}}
			if tt.hint != "" {
				form.Set("token_type_hint", tt.hint)
			}
			w := h.clientPost("/oauth/revoke", from, form)
			assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.Empty(t, w.Body.String())
			assert.Empty(t, w.Header().Get("Content-Type"), "an empty 200, as before")
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.Equal(t, tt.accessAlive, h.valid(tk.AccessToken, "notes"))
			want := http.StatusBadRequest
			if tt.refreshOK {
				want = http.StatusOK
			}
			assert.Equal(t, want, h.refresh(tc, tk.RefreshToken).Code)
		})
	}
}

func TestRevokeRefusals(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authPost)
	tk := h.connect(tc, "alice", "notes")

	w := h.clientPost("/oauth/revoke", tc, url.Values{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_request", errorOf(t, w), "no token")

	wrong := tc
	wrong.secret = "wrong"
	w = h.clientPost("/oauth/revoke", wrong, url.Values{"token": {tk.AccessToken}})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "invalid_client", errorOf(t, w))
	assert.True(t, h.valid(tk.AccessToken, "notes"), "an unauthenticated revoke does nothing")

	h.store.failWith("GetToken", errors.New("store down"), true)
	w = h.clientPost("/oauth/revoke", tc, url.Values{"token": {tk.AccessToken}})
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "server_error", errorOf(t, w))
}

func TestRevokeGrant(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	first := h.connect(tc, "alice", "notes")
	second := h.connect(tc, "alice", "notes")
	g := h.store.grantList()[0]

	require.NoError(t, h.srv.RevokeGrant(t.Context(), g.ID, alice.Person.ID, "198.51.100.7"))
	assert.False(t, h.valid(first.AccessToken, "notes"))
	assert.False(t, h.valid(second.AccessToken, "notes"), "every token of the grant")
	assert.Equal(t, http.StatusBadRequest, h.refresh(tc, second.RefreshToken).Code)
	assert.NotNil(t, h.store.grant(g.ID).RevokedAt)

	entries := h.store.auditEntries()
	last := entries[len(entries)-1]
	assert.Equal(t, core.AuditEntry{
		ID: last.ID, At: h.clock.now(), AccountID: millers.ID, Actor: alice.Person.ID, Action: "oauth.grant.revoke",
		Target: string(g.ID), IP: "198.51.100.7", Detail: map[string]string{"module": "notes"},
	}, last)

	require.NoError(t, h.srv.RevokeGrant(t.Context(), g.ID, alice.Person.ID, ""), "a revoked grant is left alone")
	assert.Equal(t, 1, h.store.auditActions()["oauth.grant.revoke"])

	err := h.srv.RevokeGrant(t.Context(), "grt_unknown", alice.Person.ID, "")
	assert.ErrorIs(t, err, core.ErrNotFound)

	again := h.connect(tc, "alice", "notes")
	assert.True(t, h.valid(again.AccessToken, "notes"), "a new consent makes a new grant")
	assert.Len(t, h.store.grantList(), 2)
}
