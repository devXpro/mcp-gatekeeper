package oauth

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestAuthorizePages(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	_, challenge := newPKCE()
	tests := []struct {
		name string
		edit func(q url.Values)
		text pageText
	}{
		{"no client_id", func(q url.Values) { q.Del("client_id") }, pageBadRequest},
		{"a repeated client_id", func(q url.Values) { q.Add("client_id", tc.id) }, pageBadRequest},
		{"an unknown client", func(q url.Values) { q.Set("client_id", "cli_aaaaaaaaaaaaaaaa") }, pageUnknownClient},
		{"a junk client_id", func(q url.Values) { q.Set("client_id", "<script>alert(1)</script>") }, pageUnknownClient},
		{"no redirect_uri", func(q url.Values) { q.Del("redirect_uri") }, pageBadRequest},
		{"a repeated redirect_uri", func(q url.Values) { q.Add("redirect_uri", claudeCallback) }, pageBadRequest},
		{"a callback the client did not register", func(q url.Values) {
			q.Set("redirect_uri", "https://claude.com/api/mcp/auth_callback")
		}, pageBadRedirect},
		{"an attacker's redirect_uri", func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") }, pageBadRedirect},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := authorizeParams(tc, "notes", challenge)
			tt.edit(q)
			assertPage(t, h.authorize(q), http.StatusBadRequest, tt.text)
		})
	}
	t.Run("a malformed query", func(t *testing.T) {
		assertPage(t, h.get("/oauth/authorize?client_id=%zz", ""), http.StatusBadRequest, pageBadRequest)
	})
	assert.Zero(t, h.srv.txns.count(), "no error keeps a transaction")
}

func assertPage(t *testing.T, w *httptest.ResponseRecorder, status int, text pageText) {
	t.Helper()
	assert.Equal(t, status, w.Code)
	assert.Empty(t, w.Header().Get("Location"), "an error page is never a redirect")
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, pageCSP, w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Body.String(), "<title>Family Hub</title>", "the title is the brand's product")
	assert.Contains(t, w.Body.String(), template.HTMLEscapeString(text.EN))
	assert.Contains(t, w.Body.String(), template.HTMLEscapeString(text.RU))
	assert.NotContains(t, w.Body.String(), "<script")
}

func TestAuthorizeRedirectsErrors(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	_, challenge := newPKCE()
	set := func(k, v string) func(url.Values) { return func(q url.Values) { q.Set(k, v) } }
	del := func(k string) func(url.Values) { return func(q url.Values) { q.Del(k) } }
	add := func(k, v string) func(url.Values) { return func(q url.Values) { q.Add(k, v) } }
	noResource := func(scope string) func(url.Values) {
		return func(q url.Values) { q.Del("resource"); q.Set("scope", scope) }
	}
	tests := []struct {
		name        string
		edit        func(url.Values)
		code        string
		description string // the error_description Family Hub sent, word for word
		withState   bool
	}{
		{"no response_type", del("response_type"), "invalid_request", "response_type is required", true},
		{"response_type token", set("response_type", "token"), "unsupported_response_type",
			"response_type must be code", true},
		{"a repeated response_type", add("response_type", "code"), "invalid_request", "response_type is repeated", true},
		{"no code_challenge", del("code_challenge"), "invalid_request",
			"PKCE is required: code_challenge with code_challenge_method=S256", true},
		{"a short code_challenge", set("code_challenge", "abc"), "invalid_request",
			"PKCE is required: code_challenge with code_challenge_method=S256", true},
		{"a repeated code_challenge", add("code_challenge", challenge), "invalid_request",
			"code_challenge is repeated", true},
		{"plain PKCE", set("code_challenge_method", "plain"), "invalid_request",
			"PKCE is required: code_challenge with code_challenge_method=S256", true},
		{"no code_challenge_method", del("code_challenge_method"), "invalid_request",
			"PKCE is required: code_challenge with code_challenge_method=S256", true},
		{"a repeated state", add("state", "other"), "invalid_request", "state is repeated or over 1024 bytes", false},
		{"a state over 1024 bytes", set("state", strings.Repeat("s", maxStateLen+1)), "invalid_request",
			"state is repeated or over 1024 bytes", false},
		{"no resource and no resource scope", noResource("mcp offline_access"), "invalid_target",
			"resource is required", true},
		{"two resources", add("resource", hubURL+"/mcp/photos"), "invalid_target",
			"one resource is expected", true},
		{"a resource of another server", set("resource", "https://evil.example/mcp/notes"), "invalid_target",
			"the resource is not a module of this hub", true},
		{"a resource with a trailing slash", set("resource", hubURL+"/mcp/notes/"), "invalid_target",
			"the resource is not a module of this hub", true},
		{"a resource of a path below a resource", set("resource", hubURL+"/mcp/notes/x"), "invalid_target",
			"the resource is not a module of this hub", true},
		{"a resource with a query", set("resource", hubURL+"/mcp/notes?x=1"), "invalid_target",
			"the resource is not a module of this hub", true},
		{"a resource of a longer host", set("resource", hubURL+".evil/mcp/notes"), "invalid_target",
			"the resource is not a module of this hub", true},
		{"a resource with an upper-case id", set("resource", hubURL+"/mcp/Notes"), "invalid_target",
			"the resource is not a module of this hub", true},
		{"the root as resource", set("resource", hubURL), "invalid_target",
			"the resource is not a module of this hub", true},
		{"a resource that cannot be connected", set("resource", hubURL+"/mcp/old"), "invalid_target",
			"no such module is running", true},
		{"a resource of an unknown id", set("resource", hubURL+"/mcp/nobody"), "invalid_target",
			"no such module is running", true},
		{"a scope naming another resource than the resource", set("scope", "mcp mcp:photos"), "invalid_scope",
			"the scope names another module than the resource", true},
		{"a resource scope of an unknown id", noResource("mcp:nobody"), "invalid_scope",
			"no such module is running", true},
		{"a resource scope of a resource that cannot be connected", noResource("mcp:old"), "invalid_scope",
			"no such module is running", true},
		{"a resource scope of two resources", noResource("mcp:notes mcp:photos"), "invalid_scope",
			"the scope names more than one module", true},
		{"a resource scope with a bad id", noResource("mcp:Notes"), "invalid_scope",
			"the scope names no module of this hub", true},
		{"a scope over 1024 bytes", set("scope", strings.Repeat("a", maxScopeLen+1)), "invalid_scope",
			"scope is over 1024 bytes", true},
		{"a repeated scope", add("scope", "mcp"), "invalid_request", "scope is repeated", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.clock.advance(time.Minute) // a fresh rate-limit bucket for every case
			q := authorizeParams(tc, "notes", challenge)
			tt.edit(q)
			w := h.authorize(q)
			require.Equal(t, http.StatusFound, w.Code, w.Body.String())
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
			back := location(t, w)
			assert.Equal(t, claudeCallback, back.Scheme+"://"+back.Host+back.Path)
			assert.Equal(t, tt.code, back.Query().Get("error"))
			assert.Equal(t, tt.description, back.Query().Get("error_description"))
			assert.Equal(t, hubURL, back.Query().Get("iss"))
			assert.Empty(t, back.Query().Get("code"))
			if tt.withState {
				assert.Equal(t, "st-notes", back.Query().Get("state"))
			} else {
				assert.NotContains(t, back.Query(), "state")
			}
		})
	}
	assert.Zero(t, h.srv.txns.count(), "no error keeps a transaction")
}

func location(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	return u
}

func TestAuthorizeKeepsATransaction(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authPost)
	_, challenge := newPKCE()
	w := h.authorize(authorizeParams(tc, "notes", challenge))
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	id, ok := strings.CutPrefix(w.Header().Get("Location"), "/consent?txn=")
	require.True(t, ok)
	assert.Regexp(t, `^txn_[a-z2-7]{16}$`, id)
	got, ok := h.srv.txns.get(id, h.clock.now())
	require.True(t, ok)
	binding := h.jar.binding()
	require.Regexp(t, `^[A-Za-z0-9_-]{43}$`, binding, "authorize binds the transaction to the browser")
	assert.Equal(t, txn{
		clientID: core.ClientID(tc.id), clientKind: core.ClientDCR, assistant: core.AssistantChatGPT,
		clientName: "Test", redirectURI: chatgptCallback, state: "st-notes", challenge: challenge,
		scope: "mcp offline_access", resource: "notes", resourceURL: hubURL + "/mcp/notes",
		startedFrom: startedUnknown, group: "192.0.2.1", binding: hashOf(binding),
		expiresAt: h.clock.now().Add(10 * time.Minute), seq: 1,
	}, got, "the binding is kept as its sha256")

	h.clock.advance(10 * time.Minute)
	_, ok = h.srv.txns.get(id, h.clock.now())
	assert.False(t, ok, "a transaction lives 10 minutes")
}

func TestAuthorizeSetsTheBindingCookie(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	_, challenge := newPKCE()
	w := h.authorize(authorizeParams(tc, "notes", challenge))
	require.Equal(t, http.StatusFound, w.Code)
	cookies := (&http.Response{Header: w.Header()}).Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, "__Host-fh_txn", c.Name, "the name is the brand's TxnCookie")
	assert.Equal(t, "/", c.Path)
	assert.Empty(t, c.Domain, "a __Host- cookie has no Domain")
	assert.True(t, c.Secure)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite, "Lax comes along on the assistant's cross-site navigation")
	assert.Equal(t, 600, c.MaxAge, "as long as the transaction")
	assert.Equal(t, "__Host-fh_txn="+c.Value+"; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax",
		w.Header().Get("Set-Cookie"), "the header Family Hub sent")

	// The browser's value is kept for its next connector; a malformed one is replaced.
	h.authorize(authorizeParams(tc, "photos", challenge))
	assert.Equal(t, c.Value, h.jar.binding(), "one value per browser")
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeParams(tc, "notes", challenge).Encode(), nil)
	addCookie(r, testBrand.TxnCookie, "made-up")
	other := newBrowser()
	require.Equal(t, http.StatusFound, h.doIn(other, r).Code)
	assert.Regexp(t, `^[A-Za-z0-9_-]{43}$`, other.binding())
	assert.NotEqual(t, c.Value, other.binding())

	// Without binding, no cookie.
	off := newHarnessWith(t, func(o *Options) { o.TxnBindingOff = true })
	tc = off.registerDCR(claudeCallback, authNone)
	w = off.authorize(authorizeParams(tc, "notes", challenge))
	require.Equal(t, http.StatusFound, w.Code)
	assert.Empty(t, w.Header().Values("Set-Cookie"))
}

func TestAuthorizeStartedFrom(t *testing.T) {
	tests := []struct {
		name         string
		redirect     string
		referer, sfs string // the Referer and Sec-Fetch-Site of the navigation
		want         string
	}{
		{"from ChatGPT", chatgptCallback, "https://chatgpt.com/", "cross-site", startedAssistant},
		{"from ChatGPT's other host", chatgptCallback, "https://chat.openai.com/g/x", "cross-site", startedAssistant},
		{"from Claude", claudeCallback, "https://claude.ai/new", "cross-site", startedAssistant},
		{"from claude.com", claudeCallback, "https://claude.com/", "cross-site", startedAssistant},
		{"Claude's client from ChatGPT", claudeCallback, "https://chatgpt.com/", "cross-site", startedElsewhere},
		{"from a webmail", chatgptCallback, "https://mail.example.com/inbox", "cross-site", startedElsewhere},
		{"from the server itself", chatgptCallback, hubURL + "/account", "same-origin", startedElsewhere},
		{"an assistant host over http", chatgptCallback, "http://chatgpt.com/", "cross-site", startedElsewhere},
		{"opened directly, e.g. from a messenger", chatgptCallback, "", "none", startedElsewhere},
		{"cross-site without a Referer", chatgptCallback, "", "cross-site", startedUnknown},
		{"no headers at all", chatgptCallback, "", "", startedUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tc := h.registerDCR(tt.redirect, authNone)
			_, challenge := newPKCE()
			r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeParams(tc, "notes", challenge).Encode(), nil)
			if tt.referer != "" {
				r.Header.Set("Referer", tt.referer)
			}
			if tt.sfs != "" {
				r.Header.Set("Sec-Fetch-Site", tt.sfs)
			}
			w := h.do(r)
			require.Equal(t, http.StatusFound, w.Code)
			id, _ := strings.CutPrefix(w.Header().Get("Location"), "/consent?txn=")
			var view txnView
			v := h.get("/api/oauth/txn/"+id, "alice")
			require.Equal(t, http.StatusOK, v.Code, v.Body.String())
			decode(t, v, &view)
			assert.Equal(t, tt.want, view.StartedFrom)
		})
	}
}

func TestAuthorizeRefusesPerConnectorCallbacksWhenTold(t *testing.T) {
	// A client registered with a per-connector callback while they were allowed cannot use it once they are not.
	allowed := newHarness(t)
	tc := allowed.registerDCR(chatgptConnectors, authNone)
	stored, ok := allowed.store.client(tc.id)
	require.True(t, ok)

	h := newHarnessWith(t, func(o *Options) { o.RefuseConnectorCallback = true })
	require.NoError(t, h.store.OAuth().PutClient(t.Context(), stored))
	_, challenge := newPKCE()
	assertPage(t, h.authorize(authorizeParams(tc, "notes", challenge)), http.StatusBadRequest, pageBadRedirect)
	assert.Zero(t, h.srv.txns.count())
}

func TestAuthorizeScope(t *testing.T) {
	tests := []struct {
		name, resource, scope, want, granted string
	}{
		{"resource and offline_access", hubURL + "/mcp/notes", "mcp offline_access", "notes", "mcp offline_access"},
		{"resource without a scope", hubURL + "/mcp/notes", "", "notes", "mcp"},
		{"the resource named by the scope", "", "mcp:photos", "photos", "mcp"},
		{"the resource scope with offline_access", "", "offline_access mcp:photos", "photos",
			"mcp offline_access"},
		{"unknown scopes are ignored", hubURL + "/mcp/notes", "openid profile mcp", "notes", "mcp"},
		{"a resource scope agreeing with the resource", hubURL + "/mcp/notes", "mcp:notes mcp:notes", "notes", "mcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tc := h.registerDCR(claudeCallback, authNone)
			_, challenge := newPKCE()
			q := authorizeParams(tc, "notes", challenge)
			q.Set("resource", tt.resource) // an empty resource counts as none
			q.Set("scope", tt.scope)
			w := h.authorize(q)
			require.Equal(t, http.StatusFound, w.Code, w.Header().Get("Location"))
			id, _ := strings.CutPrefix(w.Header().Get("Location"), "/consent?txn=")
			got, ok := h.srv.txns.get(id, h.clock.now())
			require.True(t, ok)
			assert.Equal(t, core.ResourceID(tt.want), got.resource)
			assert.Equal(t, hubURL+"/mcp/"+tt.want, got.resourceURL, "the resource is the canonical one either way")
			assert.Equal(t, tt.granted, got.scope)
		})
	}
}

// authorizeFrom sends tc's authorization request for resource from the client address addr, out of a browser of
// its own, and returns the transaction.
func (h *harness) authorizeFrom(addr string, tc testClient, resource string) string {
	h.t.Helper()
	_, challenge := newPKCE()
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeParams(tc, resource, challenge).Encode(), nil)
	r.RemoteAddr = addr
	w := h.doIn(newBrowser(), r)
	require.Equal(h.t, http.StatusFound, w.Code, w.Body.String())
	id, ok := strings.CutPrefix(w.Header().Get("Location"), "/consent?txn=")
	require.True(h.t, ok, w.Header().Get("Location"))
	return id
}

// live reports which of the transactions ids are still kept.
func (h *harness) live(ids ...string) []bool {
	out := make([]bool, len(ids))
	for i, id := range ids {
		_, out[i] = h.srv.txns.get(id, h.clock.now())
	}
	return out
}

func TestAuthorizeWhenFull(t *testing.T) {
	h := newHarness(t)
	h.srv.txns.max = 4
	tc := h.registerDCR(claudeCallback, authNone)
	a1 := h.authorizeFrom("198.51.100.1:1", tc, "notes")
	b1 := h.authorizeFrom("198.51.100.2:1", tc, "notes")
	b2 := h.authorizeFrom("198.51.100.2:2", tc, "notes")
	b3 := h.authorizeFrom("198.51.100.2:3", tc, "notes")
	require.Equal(t, 4, h.srv.txns.count())

	// Full: a new one gets in, and the oldest of the address group holding the most goes, not the oldest of all.
	c1 := h.authorizeFrom("198.51.100.3:1", tc, "notes")
	assert.Equal(t, []bool{true, false, true, true, true}, h.live(a1, b1, b2, b3, c1))

	// Of groups holding as many, the one with the oldest transaction gives way.
	c2 := h.authorizeFrom("198.51.100.3:2", tc, "notes") // B holds the most: b2 goes
	d1 := h.authorizeFrom("198.51.100.4:1", tc, "notes") // C holds the most: c1 goes
	d2 := h.authorizeFrom("198.51.100.4:2", tc, "notes") // every group holds one: A's is the oldest
	assert.Equal(t, []bool{false, false, true, false, true, true, true}, h.live(a1, b2, b3, c1, c2, d1, d2))
	assert.Equal(t, 4, h.srv.txns.count())

	h.clock.advance(txnTTL)
	h.authorizeFrom("198.51.100.9:1", tc, "notes")
	assert.Equal(t, 1, h.srv.txns.count(), "expired ones are dropped first")
}

func TestAuthorizeCapsAnAddressGroup(t *testing.T) {
	h := newHarness(t)
	h.srv.txns.perGroup = 3
	tc := h.registerDCR(claudeCallback, authNone)
	other := h.authorizeFrom("[2001:db8:9::1]:1", tc, "notes")
	ids := make([]string, 5)
	for i := range ids {
		ids[i] = h.authorizeFrom(fmt.Sprintf("[2001:db8:1:2::%x]:443", i+1), tc, "notes") // one /64
	}
	assert.Equal(t, []bool{false, false, true, true, true}, h.live(ids...), "a group keeps its newest 3")
	assert.Equal(t, []bool{true}, h.live(other), "another group is untouched")
}

func TestAuthorizeCapsADCRClient(t *testing.T) {
	h := newHarness(t)
	h.srv.txns.perClient = 2
	flood := h.registerDCR(claudeCallback, authNone)
	ids := make([]string, 3)
	for i := range ids {
		ids[i] = h.authorizeFrom(fmt.Sprintf("198.51.100.%d:1", i+1), flood, "notes")
	}
	assert.Equal(t, []bool{false, true, true}, h.live(ids...), "a DCR client keeps its newest 2")

	// A CIMD client id is shared by every user of its assistant, so it has no cap.
	shared := h.cimdClient(chatgptDocument, chatgptCallback)
	ids = make([]string, 3)
	for i := range ids {
		ids[i] = h.authorizeFrom(fmt.Sprintf("203.0.113.%d:1", i+1), shared, "notes")
	}
	assert.Equal(t, []bool{true, true, true}, h.live(ids...))
}

func TestAuthorizeRateLimit(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	_, challenge := newPKCE()
	target := "/oauth/authorize?" + authorizeParams(tc, "notes", challenge).Encode()
	from := func(addr string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.RemoteAddr = addr + ":4444"
		return h.do(r)
	}
	for i := range limitPerAddress {
		require.Equal(t, http.StatusFound, from("203.0.113.5").Code, i)
	}
	w := from("203.0.113.5")
	assertPage(t, w, http.StatusTooManyRequests, pageRateLimited)
	assert.Equal(t, "3", w.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusFound, from("203.0.113.6").Code, "another address has its own bucket")
}

func TestAuthorizeServerErrors(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	_, challenge := newPKCE()

	h.catalog.setError(errors.New("catalog down"))
	w := h.authorize(authorizeParams(tc, "notes", challenge))
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "server_error", location(t, w).Query().Get("error"), "the redirect URI is valid by then")
	assert.Equal(t, "the hub failed; try again", location(t, w).Query().Get("error_description"))
	h.catalog.setError(nil)

	h.store.failWith("GetClient", errors.New("store down"), true)
	assertPage(t, h.authorize(authorizeParams(tc, "notes", challenge)), http.StatusInternalServerError, pageServerError)
}

// TestAuthorizeWrongMethods: the routes answer only their own methods; the mux answers the others.
func TestAuthorizeWrongMethods(t *testing.T) {
	h := newHarness(t)
	for _, tt := range []struct{ method, path string }{
		{http.MethodPost, "/oauth/authorize"},
		{http.MethodGet, "/oauth/token"},
		{http.MethodGet, "/oauth/revoke"},
		{http.MethodGet, "/oauth/register"},
		{http.MethodPost, "/.well-known/oauth-authorization-server"},
		{http.MethodGet, "/api/oauth/txn/txn_aaaaaaaaaaaaaaaa/approve"},
		{http.MethodPost, "/api/oauth/txn/txn_aaaaaaaaaaaaaaaa"},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := h.do(httptest.NewRequest(tt.method, tt.path, nil))
			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		})
	}
}
