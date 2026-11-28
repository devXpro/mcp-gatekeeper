package oauth

// A person's access term (core.Person.AccessUntil) and the other reasons a person may not act (core.Person.Active):
// the consent API, the code exchange and the refresh refuse them, and an access token never outlives the term.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// setTerm makes person's term end at end (nil: no term), as package people's member update does.
func (h *harness) setTerm(person core.PersonID, end *time.Time) {
	h.t.Helper()
	require.NoError(h.t, h.store.People().SetAccess(h.t.Context(), person, end, nil))
}

func refreshForm(refreshToken string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
}

// TestGuestTermFullFlow walks the connector of a guest whose term ends in an hour, at T, over real HTTP as ChatGPT's
// backend and the SPA do: the access token issued at T-10 min expires at T, the refresh at T+1 s is invalid_grant, a
// code issued before T is refused after it, and so is the consent. Nothing is spent or revoked meanwhile, so when the
// owner extends the term, the same refresh token, code and transaction work. Alice, without a term, gets today's
// answers at the same moment.
func TestGuestTermFullFlow(t *testing.T) {
	h := newHarness(t)
	srv := httptest.NewServer(h.mux)
	t.Cleanup(srv.Close)
	c := &flowClient{t: t, base: srv.URL, jar: newBrowser(), http: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	var secrets []string
	end := h.clock.now().Add(time.Hour) // T
	h.setTerm(bob.Person.ID, &end)

	// T-1 h: ChatGPT registers, and Bob connects the notes.
	var reg registered
	c.postJSON("/oauth/register", map[string]any{
		"redirect_uris": []string{chatgptCallback}, "token_endpoint_auth_method": "client_secret_post",
	}, http.StatusCreated, &reg)
	chatgpt := testClient{id: reg.ClientID, secret: reg.ClientSecret, redirect: chatgptCallback}
	verifier, challenge := newPKCE()
	code := c.approve(c.authorize(authorizeParams(chatgpt, "notes", challenge)), "bob").Query().Get("code")
	tk := c.token(chatgpt, exchangeForm(chatgpt, code, verifier), http.StatusOK)
	assert.Equal(t, int64(3600), tk.ExpiresIn, "an hour of the term is left")
	secrets = append(secrets, chatgpt.secret, verifier, code, tk.AccessToken, tk.RefreshToken)

	// T-10 min: the refresh gives an access token that expires at T.
	h.clock.advance(50 * time.Minute)
	tk = c.token(chatgpt, refreshForm(tk.RefreshToken), http.StatusOK)
	secrets = append(secrets, tk.AccessToken, tk.RefreshToken)
	assert.Equal(t, int64(600), tk.ExpiresIn)
	access, ok := h.store.token(tk.AccessToken)
	require.True(t, ok)
	assert.Equal(t, end, access.ExpiresAt, "the token ends with the term")
	refresh, ok := h.store.token(tk.RefreshToken)
	require.True(t, ok)
	assert.Equal(t, h.clock.now().Add(refreshTTL), refresh.ExpiresAt, "the refresh token keeps its 30 days")
	info, err := h.srv.ValidateAccess(t.Context(), tk.AccessToken, "notes")
	require.NoError(t, err)
	assert.Equal(t, end, info.ExpiresAt)

	// T-2 min: Bob also starts connecting the photos; the code waits for its exchange.
	h.clock.advance(8 * time.Minute)
	verifier2, challenge2 := newPKCE()
	code2 := c.approve(c.authorize(authorizeParams(chatgpt, "photos", challenge2)), "bob").Query().Get("code")
	secrets = append(secrets, verifier2, code2)

	// T: the access token has ended, and the validator says it knows the token (GK-12), so the MCP access check does
	// not count it as a guess.
	h.clock.advance(2*time.Minute - time.Nanosecond)
	require.True(t, h.valid(tk.AccessToken, "notes"), "until the last instant before T")
	h.clock.advance(time.Nanosecond)
	_, err = h.srv.ValidateAccess(t.Context(), tk.AccessToken, "notes")
	assert.ErrorIs(t, err, core.ErrInvalidToken)
	assert.ErrorIs(t, err, core.ErrExpired)

	// T+1 s: the refresh and the exchange are invalid_grant, with the bytes of any dead grant.
	h.clock.advance(time.Second)
	var body json.RawMessage
	c.post("/oauth/token", chatgpt, refreshForm(tk.RefreshToken), http.StatusBadRequest, &body)
	assert.Equal(t, `{"error":"invalid_grant"}`, string(body))
	c.post("/oauth/token", chatgpt, exchangeForm(chatgpt, code2, verifier2), http.StatusBadRequest, &body)
	assert.Equal(t, `{"error":"invalid_grant"}`, string(body))

	// The consent: authorize still sends the browser to the screen (it knows no person), which refuses Bob.
	_, challenge3 := newPKCE()
	txnID := c.authorize(authorizeParams(chatgpt, "notes", challenge3))
	var refused struct{ Error, Message string }
	c.getJSON("/api/oauth/txn/"+txnID, "bob", http.StatusUnauthorized, &refused)
	assert.Equal(t, "no_session", refused.Error)
	assert.Equal(t, "your access has ended", refused.Message)
	c.send(c.consentRequest(txnID, "approve"), "bob", http.StatusUnauthorized, &refused)
	assert.Equal(t, "no_session", refused.Error)

	// Nothing was spent, revoked or audited for Bob meanwhile.
	spent, _ := h.store.token(tk.RefreshToken)
	assert.Nil(t, spent.UsedAt, "the refused refresh rolled back")
	_, ok = h.store.code(code2)
	assert.True(t, ok, "the refused exchange left the code")
	for _, g := range h.store.grantList() {
		assert.Nil(t, g.RevokedAt, "a term that ends revokes no grant")
	}
	assert.Equal(t, map[string]int{"oauth.client.register": 1, "oauth.grant.create": 2}, h.store.auditActions())

	// Alice, without a term, connects at the same moment and gets today's hour.
	verifier4, challenge4 := newPKCE()
	code4 := c.approve(c.authorize(authorizeParams(chatgpt, "notes", challenge4)), "alice").Query().Get("code")
	alices := c.token(chatgpt, exchangeForm(chatgpt, code4, verifier4), http.StatusOK)
	assert.Equal(t, int64(3600), alices.ExpiresIn)
	secrets = append(secrets, verifier4, code4, alices.AccessToken, alices.RefreshToken)

	// The owner extends Bob's term by a day: the same refresh token, code and transaction work again.
	extended := end.Add(24 * time.Hour)
	h.setTerm(bob.Person.ID, &extended)
	tk = c.token(chatgpt, refreshForm(tk.RefreshToken), http.StatusOK)
	assert.Equal(t, int64(3600), tk.ExpiresIn)
	photos := c.token(chatgpt, exchangeForm(chatgpt, code2, verifier2), http.StatusOK)
	assert.True(t, h.valid(photos.AccessToken, "photos"))
	assert.Equal(t, "st-notes", c.approve(txnID, "bob").Query().Get("state"))
	secrets = append(secrets, tk.AccessToken, tk.RefreshToken, photos.AccessToken, photos.RefreshToken)
	assertNoSecrets(t, h, secrets)
}

// consentRequest is the SPA's POST of approve or deny for txnID.
func (c *flowClient) consentRequest(txnID, answer string) *http.Request {
	r := c.request(http.MethodPost, "/api/oauth/txn/"+txnID+"/"+answer, nil)
	r.Header.Set(testBrand.CSRFHeader, "1")
	r.Header.Set("Origin", hubURL)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

// TestAccessTokenEndsWithTheTerm: an access token never outlives its person's term, and expires_in says how long it
// lives in whole seconds, never more; without a term, or with one past the hour, it is today's 3600.
func TestAccessTokenEndsWithTheTerm(t *testing.T) {
	tests := []struct {
		name string
		left time.Duration // until the end of Bob's term; 0: no term
		want int64
	}{
		{"no term", 0, 3600},
		{"a term past the hour", 2 * time.Hour, 3600},
		{"a term of exactly the hour", time.Hour, 3600},
		{"10 minutes", 10 * time.Minute, 600},
		{"1.9 seconds", 1900 * time.Millisecond, 1},
		{"half a second", 500 * time.Millisecond, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tc := h.registerDCR(claudeCallback, authNone)
			code, verifier := h.codeFor(tc, "bob", "notes")
			now := h.clock.now()
			accessEnd := now.Add(time.Hour)
			if tt.left > 0 {
				end := now.Add(tt.left)
				h.setTerm(bob.Person.ID, &end)
				accessEnd = earlier(accessEnd, end)
			}
			w := h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			var tk tokens
			decode(t, w, &tk)
			assert.Equal(t, `{"access_token":"`+tk.AccessToken+`","token_type":"Bearer","expires_in":`+
				strconv.FormatInt(tt.want, 10)+`,"refresh_token":"`+tk.RefreshToken+`","scope":"mcp offline_access"}`,
				w.Body.String())
			access, _ := h.store.token(tk.AccessToken)
			assert.Equal(t, accessEnd, access.ExpiresAt)
			refresh, _ := h.store.token(tk.RefreshToken)
			assert.Equal(t, now.Add(refreshTTL), refresh.ExpiresAt)
		})
	}
}

// TestTokenRefusesAPersonWhoMayNotAct: a person who is past their term, disabled, gone or in another account than the
// grant can neither exchange a code nor refresh. Both are invalid_grant, after the checks of the token itself, and
// roll back: the code and the refresh token are left, no grant is revoked and nothing is audited.
func TestTokenRefusesAPersonWhoMayNotAct(t *testing.T) {
	tests := []struct {
		name string
		stop func(t *testing.T, h *harness) // makes Bob unable to act
	}{
		{"past the end of the term", func(_ *testing.T, h *harness) {
			end := h.clock.now()
			h.setTerm(bob.Person.ID, &end)
		}},
		{"disabled", func(t *testing.T, h *harness) {
			require.NoError(t, h.store.People().Disable(t.Context(), bob.Person.ID, h.clock.now()))
		}},
		{"gone", func(_ *testing.T, h *harness) {
			h.store.failWith("GetPerson", fakeNotFound("person"), false)
		}},
		{"in another account", func(t *testing.T, h *harness) {
			require.NoError(t, fakePeople{h.store}.update(t.Context(), bob.Person.ID,
				func(p *core.Person) { p.AccountID = friends.ID }))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tc := h.registerDCR(chatgptCallback, authNone)
			tk := h.connect(tc, "bob", "notes")
			code, verifier := h.codeFor(tc, "bob", "photos")
			audited := h.store.auditActions()
			tt.stop(t, h)

			w := h.refresh(tc, tk.RefreshToken)
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, `{"error":"invalid_grant"}`, w.Body.String())
			w = h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, `{"error":"invalid_grant"}`, w.Body.String())

			spent, _ := h.store.token(tk.RefreshToken)
			assert.Nil(t, spent.UsedAt, "the refresh token is left")
			_, ok := h.store.code(code)
			assert.True(t, ok, "the code is left")
			for _, g := range h.store.grantList() {
				assert.Nil(t, g.RevokedAt)
			}
			assert.Equal(t, audited, h.store.auditActions())
			assert.True(t, h.valid(tk.AccessToken, "notes"),
				"the token check reads no person: the MCP access check refuses the person (package mcpguard)")
		})
	}
}

// TestTokenRefusalOfAPersonKeepsReuseDetection: the person is checked after the refresh token is spent, so a spent
// token coming back still revokes its family and is audited, also while its person may not act.
func TestTokenRefusalOfAPersonKeepsReuseDetection(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authNone)
	first := h.connect(tc, "bob", "notes")
	w := h.refresh(tc, first.RefreshToken)
	require.Equal(t, http.StatusOK, w.Code)
	var next tokens
	decode(t, w, &next)
	end := h.clock.now()
	h.setTerm(bob.Person.ID, &end)

	h.clock.advance(refreshGrace + time.Second)
	assert.Equal(t, http.StatusBadRequest, h.refresh(tc, first.RefreshToken).Code)
	assert.Equal(t, 1, h.store.auditActions()["oauth.refresh.reuse"])
	assert.False(t, h.valid(next.AccessToken, "notes"), "the family is revoked")
}

// TestTokenPersonLookupFailure: a store failure while reading the person is server_error, and the code or refresh
// token stays for the retry.
func TestTokenPersonLookupFailure(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	code, verifier := h.codeFor(tc, "bob", "notes")
	h.store.failWith("GetPerson", errors.New("store down"), true)
	w := h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, `{"error":"server_error"}`, w.Body.String())
	tk := h.exchange(tc, code, verifier)

	h.store.failWith("GetPerson", errors.New("store down"), true)
	w = h.refresh(tc, tk.RefreshToken)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, http.StatusOK, h.refresh(tc, tk.RefreshToken).Code, "a retry after a store failure is no reuse")
	assert.Zero(t, h.store.auditActions()["oauth.refresh.reuse"])
}

// TestConsentRefusesAPersonWhoMayNotAct: the consent screen and Allow answer 401 no_session to a person past their term
// or disabled, as package auth refuses their session (this covers any other core.Sessions, and a term that ends while
// a call runs). A refusal consumes nothing: once the term is extended, the same transaction is approved. Deny stays
// open to them, since it grants nothing.
func TestConsentRefusesAPersonWhoMayNotAct(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	end := h.clock.now()
	h.setTerm(bob.Person.ID, &end)

	for _, w := range []*httptest.ResponseRecorder{
		h.get("/api/oauth/txn/"+txnID, "bob"),
		h.consentPost("/api/oauth/txn/"+txnID+"/approve", "bob"),
	} {
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `{"error":"no_session","message":"your access has ended"}`, w.Body.String())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	}
	assert.Empty(t, h.store.grantList())
	assert.Zero(t, h.store.codeCount())
	assert.Equal(t, http.StatusOK, h.get("/api/oauth/txn/"+txnID, "alice").Code, "the check is the person's")

	later := end.Add(time.Hour)
	h.setTerm(bob.Person.ID, &later)
	h.approveTxn(txnID, "bob")
	require.Len(t, h.store.grantList(), 1)

	other, _ := h.startTxn(tc, "photos")
	require.NoError(t, h.store.People().Disable(t.Context(), bob.Person.ID, h.clock.now()))
	assert.Equal(t, http.StatusUnauthorized, h.get("/api/oauth/txn/"+other, "bob").Code)
	w := h.consentPost("/api/oauth/txn/"+other+"/deny", "bob")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "access_denied", redirectOf(t, w).Query().Get("error"))
}
