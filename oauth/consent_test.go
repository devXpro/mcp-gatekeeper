package oauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestTxnInfo(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authPost)
	txnID, _ := h.startTxn(tc, "notes")
	w := h.get("/api/oauth/txn/"+txnID, "alice")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.JSONEq(t, `{
		"assistant": "chatgpt",
		"client_name": "Test",
		"client_kind": "dcr",
		"redirect_host": "chatgpt.com",
		"started_from": "unknown",
		"resource": {
			"id": "notes",
			"name": "Notes",
			"description": "Школьный дневник",
			"tools": [
				{"name": "messages_list", "title": "Сообщения", "access": "read"},
				{"name": "message_send", "title": "Отправить сообщение", "access": "write"}
			]
		},
		"account": {"id": "acc_millers", "name": "Millers"},
		"already_granted": false
	}`, w.Body.String())

	h.approveTxn(txnID, "alice")
	again, _ := h.startTxn(tc, "notes")
	assert.True(t, alreadyGranted(t, h.get("/api/oauth/txn/"+again, "alice")),
		"the second connection of a client only asks for a click")
	assert.False(t, alreadyGranted(t, h.get("/api/oauth/txn/"+again, "bob")), "a grant is the person's own")
	other, _ := h.startTxn(tc, "photos")
	assert.False(t, alreadyGranted(t, h.get("/api/oauth/txn/"+other, "alice")), "and the resource's own")
}

func TestTxnInfoWithoutTools(t *testing.T) {
	h := newHarness(t)
	h.catalog.add(core.ResourceInfo{ID: "bare", Name: "Bare"}, true, millers.ID)
	txnID, _ := h.startTxn(h.registerDCR(claudeCallback, authNone), "bare")
	w := h.get("/api/oauth/txn/"+txnID, "alice")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"resource":{"id":"bare","name":"Bare","description":"","tools":[]}`,
		"tools is a list even when empty")
}

func alreadyGranted(t *testing.T, w *httptest.ResponseRecorder) bool {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var v struct {
		AlreadyGranted *bool `json:"already_granted"`
	}
	decode(t, w, &v)
	require.NotNil(t, v.AlreadyGranted)
	return *v.AlreadyGranted
}

func TestTxnInfoRefusals(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	notes, _ := h.startTxn(tc, "notes")
	secret, _ := h.startTxn(tc, "secret")

	tests := []struct {
		name, txn, person string
		status            int
		code              string
	}{
		{"no session", notes, "", http.StatusUnauthorized, "no_session"},
		{"an unknown transaction", "txn_aaaaaaaaaaaaaaaa", "alice", http.StatusNotFound, "not_found"},
		{"a resource that is off for the account", secret, "alice", http.StatusForbidden, "forbidden"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := h.get("/api/oauth/txn/"+tt.txn, tt.person)
			assert.Equal(t, tt.status, w.Code)
			assert.Equal(t, tt.code, errorOf(t, w))
		})
	}
	assert.Equal(t, http.StatusOK, h.get("/api/oauth/txn/"+secret, "carol").Code, "it is on for the Friends")

	h.catalog.setError(errors.New("catalog down"))
	w := h.get("/api/oauth/txn/"+notes, "alice")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "internal", errorOf(t, w))
	h.catalog.setError(nil)

	h.catalog.setAvailableError(errors.New("switches down"))
	w = h.get("/api/oauth/txn/"+notes, "alice")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, `{"error":"internal","message":"the module registry failed"}`, w.Body.String())
	assert.Len(t, h.logged("oauth: reading whether a resource is available failed"), 1)
	h.catalog.setAvailableError(nil)

	h.catalog.setLive("notes", false)
	assert.Equal(t, http.StatusNotFound, h.get("/api/oauth/txn/"+notes, "alice").Code, "the resource went away")
	h.catalog.setLive("notes", true)

	h.clock.advance(txnTTL)
	assert.Equal(t, http.StatusNotFound, h.get("/api/oauth/txn/"+notes, "alice").Code, "it expired")
}

func TestApprove(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authPost)
	txnID, _ := h.startTxn(tc, "notes")
	w := h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	back := redirectOf(t, w)
	assert.Equal(t, chatgptCallback, back.Scheme+"://"+back.Host+back.Path)
	q := back.Query()
	assert.Regexp(t, `^[A-Za-z0-9_-]{43}$`, q.Get("code"))
	assert.Equal(t, "st-notes", q.Get("state"))
	assert.Equal(t, hubURL, q.Get("iss"))
	assert.Len(t, q, 3)
	amp := `\` + `u0026` // how json.Marshal writes "&"
	assert.Equal(t, `{"redirect_url":"`+chatgptCallback+`?code=`+q.Get("code")+amp+`iss=`+
		`https%3A%2F%2Fhub.example.com`+amp+`state=st-notes"}`, w.Body.String(),
		"json.Marshal's bytes, as Gin wrote them: & escaped, no newline")

	grants := h.store.grantList()
	require.Len(t, grants, 1)
	g := grants[0]
	assert.Equal(t, core.Grant{
		ID: g.ID, PersonID: alice.Person.ID, AccountID: millers.ID, ClientID: core.ClientID(tc.id), ResourceID: "notes",
		Scope: "mcp offline_access", CreatedAt: h.clock.now(),
	}, g)
	code, ok := h.store.code(q.Get("code"))
	require.True(t, ok, "the code is stored by its sha256")
	assert.Equal(t, g.ID, code.GrantID)
	assert.Equal(t, core.ClientID(tc.id), code.ClientID)
	assert.Equal(t, chatgptCallback, code.RedirectURI)
	assert.Equal(t, hubURL+"/mcp/notes", code.Resource)
	assert.Equal(t, "mcp offline_access", code.Scope)
	assert.Equal(t, h.clock.now().Add(5*time.Minute), code.ExpiresAt)

	entries := h.store.auditEntries()
	last := entries[len(entries)-1]
	assert.Equal(t, core.AuditEntry{
		ID: last.ID, At: h.clock.now(), AccountID: millers.ID, Actor: alice.Person.ID, Action: "oauth.grant.create",
		Target: string(g.ID), IP: "192.0.2.1",
		Detail: map[string]string{"module": "notes", "assistant": "chatgpt", "client": tc.id},
	}, last, "the audit keeps Family Hub's detail keys")

	assert.Equal(t, http.StatusNotFound, h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice").Code, "used once")
	assert.Equal(t, http.StatusNotFound, h.consentPost("/api/oauth/txn/"+txnID+"/deny", "alice").Code)

	second, _ := h.startTxn(tc, "notes")
	other := h.approveTxn(second, "alice").Query().Get("code")
	c, _ := h.store.code(other)
	assert.Equal(t, g.ID, c.GrantID, "the active grant is reused")
	assert.Len(t, h.store.grantList(), 1)
	assert.Equal(t, 1, h.store.auditActions()["oauth.grant.create"])

	third, _ := h.startTxn(tc, "notes")
	h.approveTxn(third, "bob")
	assert.Len(t, h.store.grantList(), 2, "Bob's consent is his own grant")
}

// TestApproveRefusals checks that approve sits behind core.Sessions.RequireViewer, whose CSRF checks and session are
// package auth's, and that a refused call leaves the transaction.
func TestApproveRefusals(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	post := func(headers map[string]string, person string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/oauth/txn/"+txnID+"/approve", nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		signIn(r, person)
		return h.do(r)
	}
	tests := []struct {
		name    string
		headers map[string]string
		person  string
		status  int
		code    string
	}{
		{"a cross-site write", map[string]string{"Origin": "https://evil.example"}, "alice",
			http.StatusForbidden, "forbidden"},
		{"no session", map[string]string{"X-Family-Hub": "1"}, "", http.StatusUnauthorized, "no_session"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := post(tt.headers, tt.person)
			assert.Equal(t, tt.status, w.Code)
			assert.Equal(t, tt.code, errorOf(t, w))
		})
	}
	assert.Zero(t, h.store.codeCount())
	assert.Equal(t, http.StatusOK, post(map[string]string{"X-Family-Hub": "1"}, "alice").Code,
		"the refusals left the transaction, and headers the browser does not send are not needed")
}

func TestApproveOfAResourceThatIsOff(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	txnID, _ := h.startTxn(tc, "secret")
	w := h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice")
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "forbidden", errorOf(t, w))
	assert.Empty(t, h.store.grantList())
	assert.Equal(t, http.StatusOK, h.consentPost("/api/oauth/txn/"+txnID+"/deny", "alice").Code,
		"the transaction is still there to deny")
}

func TestApproveOfAGoneClient(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	h.store.deleteClient(tc.id)
	w := h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "not_found", errorOf(t, w))
}

func TestApproveStoreFailure(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	h.store.failWith("PutCode", errors.New("disk full"), true)
	w := h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "internal", errorOf(t, w))
	assert.Empty(t, h.store.grantList(), "the grant rolled back with the code")
	assert.Zero(t, h.store.auditActions()["oauth.grant.create"])
}

func TestApproveRetriesAGrantConflict(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	h.store.failWith("PutGrant", core.ErrConflict, true) // another approval won the unique index
	h.approveTxn(txnID, "alice")
	assert.Len(t, h.store.grantList(), 1)
	assert.Equal(t, 1, h.store.codeCount())
}

func TestApproveRace(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	const n = 10
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { codes[i] = h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice").Code })
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		} else {
			assert.Equal(t, http.StatusNotFound, c)
		}
	}
	assert.Equal(t, 1, ok, "a transaction is used once")
	assert.Equal(t, 1, h.store.codeCount())
}

func TestDeny(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	r := httptest.NewRequest(http.MethodPost, "/api/oauth/txn/"+txnID+"/deny", nil)
	signIn(r, "alice")
	assert.Equal(t, http.StatusForbidden, h.do(r).Code, "deny sits behind RequireViewer too")

	w := h.consentPost("/api/oauth/txn/"+txnID+"/deny", "alice")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	back := redirectOf(t, w)
	assert.Equal(t, claudeCallback, back.Scheme+"://"+back.Host+back.Path)
	assert.Equal(t, "access_denied", back.Query().Get("error"))
	assert.Equal(t, "st-notes", back.Query().Get("state"))
	assert.Equal(t, hubURL, back.Query().Get("iss"))
	assert.Empty(t, back.Query().Get("code"))
	assert.Empty(t, h.store.grantList())
	assert.Zero(t, h.store.codeCount())
	assert.Equal(t, http.StatusNotFound, h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice").Code)
}

// consentIn sends a consent API call out of browser b as person: GET for the view, or POST approve or deny as the
// SPA does.
func (h *harness) consentIn(b *browser, method, target, person string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	if method == http.MethodPost {
		r.Header.Set(testBrand.CSRFHeader, "1")
		r.Header.Set("Origin", hubURL)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	signIn(r, person)
	return h.doIn(b, r)
}

func TestConsentNeedsTheBrowserThatStarted(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	stranger := newBrowser()
	stranger.cookies[testBrand.TxnCookie] = randomToken() // another browser that once started a connector of its own
	calls := []struct{ method, path string }{
		{http.MethodGet, "/api/oauth/txn/" + txnID},
		{http.MethodPost, "/api/oauth/txn/" + txnID + "/approve"},
		{http.MethodPost, "/api/oauth/txn/" + txnID + "/deny"},
	}
	for _, b := range []*browser{newBrowser(), stranger} {
		for _, call := range calls {
			w := h.consentIn(b, call.method, call.path, "alice")
			assert.Equal(t, http.StatusForbidden, w.Code, call.path)
			assert.Equal(t, "other_browser", errorOf(t, w), call.path)
			assert.Contains(t, w.Body.String(), "start connecting from the assistant again")
		}
	}
	assert.Empty(t, h.store.grantList())
	assert.Zero(t, h.store.codeCount())
	refused := h.logged("oauth: a consent call from another browser than the one that started it was refused")
	require.Len(t, refused, 2*len(calls))
	assert.Equal(t, map[string]string{"person": "per_alice", "client": tc.id, "resource": "notes"}, refused[0].Attrs)

	// The browser that started it still can: the refusals left the transaction.
	assert.Equal(t, http.StatusOK, h.get("/api/oauth/txn/"+txnID, "alice").Code)
	h.approveTxn(txnID, "alice")

	// A resource that is off stays 403 forbidden.
	secret, _ := h.startTxn(tc, "secret")
	w := h.get("/api/oauth/txn/"+secret, "alice")
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "forbidden", errorOf(t, w))
}

func TestConsentWithoutBinding(t *testing.T) {
	h := newHarnessWith(t, func(o *Options) { o.TxnBindingOff = true })
	tc := h.registerDCR(claudeCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	other := newBrowser()
	assert.Equal(t, http.StatusOK, h.consentIn(other, http.MethodGet, "/api/oauth/txn/"+txnID, "alice").Code)
	assert.Equal(t, http.StatusOK,
		h.consentIn(other, http.MethodPost, "/api/oauth/txn/"+txnID+"/approve", "alice").Code)
}

func TestApproveOfANewGrantNeedsAFreshStepUp(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	h.sessions.setStale("alice", true) // signed in longer than 5 minutes ago, no step-up since

	w := h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice")
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "step_up_required", errorOf(t, w))
	assert.Empty(t, h.store.grantList())
	assert.Zero(t, h.store.codeCount())
	assert.Zero(t, h.store.auditActions()["oauth.grant.create"])

	// The SPA steps up and approves again: the transaction is still there.
	h.sessions.setStale("alice", false)
	h.approveTxn(txnID, "alice")
	require.Len(t, h.store.grantList(), 1)

	// Reconnecting the same client to the same resource reuses the grant: one click, no step-up.
	h.sessions.setStale("alice", true)
	again, _ := h.startTxn(tc, "notes")
	assert.True(t, alreadyGranted(t, h.get("/api/oauth/txn/"+again, "alice")))
	h.approveTxn(again, "alice")
	assert.Len(t, h.store.grantList(), 1)

	// Another resource is another grant, and needs one again.
	other, _ := h.startTxn(tc, "photos")
	assert.Equal(t, http.StatusForbidden, h.consentPost("/api/oauth/txn/"+other+"/approve", "alice").Code)
	assert.Equal(t, http.StatusOK, h.consentPost("/api/oauth/txn/"+other+"/deny", "alice").Code,
		"deny needs no step-up")
}

func TestApproveWithStepUpOff(t *testing.T) {
	h := newHarnessWith(t, func(o *Options) { o.ConsentStepUpOff = true })
	tc := h.registerDCR(chatgptCallback, authNone)
	txnID, _ := h.startTxn(tc, "notes")
	h.sessions.setStale("alice", true)
	h.approveTxn(txnID, "alice")
	assert.Len(t, h.store.grantList(), 1, "one click, always")
}

// lifetime walks a connection of tc for Alice to notes up to just before its grant ends, refreshing as an
// assistant does, and returns the last tokens.
func (h *harness) lifetime(tc testClient) tokens {
	h.t.Helper()
	tk := h.connect(tc, "alice", "notes")
	for range 6 {
		h.clock.advance(29 * 24 * time.Hour)
		w := h.refresh(tc, tk.RefreshToken)
		require.Equal(h.t, http.StatusOK, w.Code, w.Body.String())
		decode(h.t, w, &tk)
	}
	h.clock.advance(6*24*time.Hour - 30*time.Minute) // 30 minutes before the 180 days are up
	w := h.refresh(tc, tk.RefreshToken)
	require.Equal(h.t, http.StatusOK, w.Code, "refreshing works to the end", w.Body.String())
	decode(h.t, w, &tk)
	return tk
}

func TestAGrantEndsAfter180Days(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	created := h.clock.now()
	tk := h.lifetime(tc)
	g := h.store.grantList()[0]
	info, err := h.srv.ValidateAccess(t.Context(), tk.AccessToken, "notes")
	require.NoError(t, err)
	assert.Equal(t, created.Add(180*24*time.Hour), info.ExpiresAt, "the access ends with its grant")

	h.clock.advance(30 * time.Minute)
	assert.False(t, h.valid(tk.AccessToken, "notes"), "the grant is over, though the token's hour is not")
	w := h.refresh(tc, tk.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_grant", errorOf(t, w))
	assert.NotNil(t, h.store.grant(g.ID).RevokedAt, "the outlived grant is revoked, so it leaves the connections list")
	entries := h.store.auditEntries()
	last := entries[len(entries)-1]
	assert.Equal(t, core.AuditEntry{
		ID: last.ID, At: h.clock.now(), AccountID: millers.ID, Action: "oauth.grant.revoke", Target: string(g.ID),
		Detail: map[string]string{"module": "notes", "reason": "expired"},
	}, last)
	assert.Zero(t, h.store.auditActions()["oauth.refresh.reuse"])

	// Connecting again is a new grant, under the step-up policy.
	txnID, _ := h.startTxn(tc, "notes")
	assert.False(t, alreadyGranted(t, h.get("/api/oauth/txn/"+txnID, "alice")))
	h.sessions.setStale("alice", true)
	assert.Equal(t, http.StatusForbidden, h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice").Code)
	h.sessions.setStale("alice", false)
	tk = h.connect(tc, "alice", "notes")
	assert.True(t, h.valid(tk.AccessToken, "notes"))
	assert.Len(t, h.store.grantList(), 2)
}

func TestApproveReplacesAnOutlivedGrant(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	h.connect(tc, "alice", "notes")
	old := h.store.grantList()[0]
	h.clock.advance(180 * 24 * time.Hour) // nobody refreshed: the grant is still marked active

	txnID, _ := h.startTxn(tc, "notes")
	assert.False(t, alreadyGranted(t, h.get("/api/oauth/txn/"+txnID, "alice")), "an outlived grant is no grant")
	c, ok := h.store.code(h.approveTxn(txnID, "alice").Query().Get("code"))
	require.True(t, ok)
	assert.NotEqual(t, old.ID, c.GrantID, "the code is of a new grant")
	assert.NotNil(t, h.store.grant(old.ID).RevokedAt, "the outlived one is revoked")
	assert.Equal(t, 1, h.store.auditActions()["oauth.grant.revoke"])
	assert.Equal(t, 2, h.store.auditActions()["oauth.grant.create"])
}

func TestCodeOfAGrantThatEndsBeforeTheExchange(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	h.connect(tc, "alice", "notes")
	h.clock.advance(180*24*time.Hour - time.Minute)
	code, verifier := h.codeFor(tc, "alice", "notes") // reuses the grant in its last minute
	h.clock.advance(2 * time.Minute)
	w := h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_grant", errorOf(t, w))
}

func TestAnOutlivedGrantIsRefusedWhenItsRevocationFails(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	tk := h.connect(tc, "alice", "notes")
	g := h.store.grantList()[0]
	h.clock.advance(grantTTL)

	h.store.failWith("Append", errors.New("disk full"), true)
	w := h.refresh(tc, tk.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_grant", errorOf(t, w))
	assert.Nil(t, h.store.grant(g.ID).RevokedAt, "the revocation rolled back with its audit entry")
	assert.Len(t, h.logged("oauth: revoking an expired grant failed"), 1)

	assert.Equal(t, http.StatusBadRequest, h.refresh(tc, tk.RefreshToken).Code)
	assert.NotNil(t, h.store.grant(g.ID).RevokedAt, "the next try revokes it")
}
