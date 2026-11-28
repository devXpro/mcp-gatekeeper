package oauth

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// deskScheme is the private-use URI scheme of the desk app in these tests, and schemeRedirect its callback.
const (
	deskScheme     = "com.example.desk"
	schemeRedirect = deskScheme + ":/oauth/callback"
)

// newSchemeHarness declares the desk app with deskScheme, and another app with a scheme of its own.
func newSchemeHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, func(o *Options) {
		o.NativeApps = []NativeApp{
			{ID: deskApp.ID, Name: deskApp.Name, Ports: []int{8742}, Schemes: []string{deskScheme}},
			{ID: "other", Name: "Other", Schemes: []string{"org.example.other"}},
		}
	})
}

// registerScheme registers a desk client with uris and returns it with redirect as its redirect URI.
func (h *harness) registerScheme(redirect string, uris ...string) testClient {
	h.t.Helper()
	w := h.registerJSON(map[string]any{
		"redirect_uris": uris, "token_endpoint_auth_method": "none", "client_name": "Phone", "software_id": "desk",
	})
	require.Equal(h.t, http.StatusCreated, w.Code, w.Body.String())
	var resp registered
	decode(h.t, w, &resp)
	return testClient{id: resp.ClientID, redirect: redirect}
}

func TestSchemeCallback(t *testing.T) {
	for _, uri := range []string{schemeRedirect, "org.example.other:/oauth/callback", "a.b:/oauth/callback",
		"com.example-x.desk2:/oauth/callback"} {
		scheme, ok := schemeCallback(uri)
		assert.True(t, ok, uri)
		assert.Equal(t, strings.TrimSuffix(uri, ":/oauth/callback"), scheme)
	}
	for _, uri := range []string{
		"com.example.desk://oauth/callback",             // the authority form
		"com.example.desk:///oauth/callback",            // an empty authority
		"com.example.desk://host/oauth/callback",        // a host
		"com.example.desk:oauth/callback",               // no slash
		"com.example.desk:/oauth/callback/",             // another path
		"com.example.desk:/oauth/cb",                    // another path
		"com.example.desk:/OAUTH/callback",              // another path
		"com.example.desk:/oauth/%63allback",            // an escape
		"com.example.desk:/oauth/callback?x=1",          // a query
		"com.example.desk:/oauth/callback?",             // an empty query
		"com.example.desk:/oauth/callback#x",            // a fragment
		"com.example.desk:/oauth/callback\n",            // a line break
		"Com.Example.Desk:/oauth/callback",              // capitals
		"desk:/oauth/callback",                          // no dot
		"com.example.desk.:/oauth/callback",             // an empty label
		"com..desk:/oauth/callback",                     // an empty label
		"com.-example.desk:/oauth/callback",             // a label starting with a hyphen
		"1com.example.desk:/oauth/callback",             // a digit first
		"com.example_desk:/oauth/callback",              // an underscore
		"com.example+desk:/oauth/callback",              // a plus
		"http:/oauth/callback", "https:/oauth/callback", // web schemes have no dot
		"https://com.example.desk/oauth/callback", "http://com.example.desk/oauth/callback",
		nativeCallback, claudeCallback, ":/oauth/callback", "",
		strings.Repeat("a.", 64) + "a:/oauth/callback", // over maxSchemeLen
	} {
		_, ok := schemeCallback(uri)
		assert.False(t, ok, uri)
	}
}

func TestNewRefusesBadSchemes(t *testing.T) {
	for name, apps := range map[string][]NativeApp{
		"no dot":             {{ID: "desk", Name: "Desk", Schemes: []string{"desk"}}},
		"capitals":           {{ID: "desk", Name: "Desk", Schemes: []string{"com.Example.desk"}}},
		"https":              {{ID: "desk", Name: "Desk", Schemes: []string{"https"}}},
		"with a colon":       {{ID: "desk", Name: "Desk", Schemes: []string{"com.example.desk:"}}},
		"a whole URI":        {{ID: "desk", Name: "Desk", Schemes: []string{schemeRedirect}}},
		"a trailing dot":     {{ID: "desk", Name: "Desk", Schemes: []string{"com.example."}}},
		"empty":              {{ID: "desk", Name: "Desk", Schemes: []string{""}}},
		"an underscore":      {{ID: "desk", Name: "Desk", Schemes: []string{"com.example_desk"}}},
		"over 128":           {{ID: "desk", Name: "Desk", Schemes: []string{strings.Repeat("a.", 64) + "a"}}},
		"twice in one app":   {{ID: "desk", Name: "Desk", Schemes: []string{deskScheme, deskScheme}}},
		"twice in two apps":  {{ID: "desk", Name: "Desk", Schemes: []string{deskScheme}}, {ID: "other", Name: "Other", Schemes: []string{deskScheme}}},
		"a digit first":      {{ID: "desk", Name: "Desk", Schemes: []string{"1com.example"}}},
		"a hyphen at an end": {{ID: "desk", Name: "Desk", Schemes: []string{"com.example-"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := nativeApps(apps)
			assert.Error(t, err)
		})
	}
	apps, err := nativeApps([]NativeApp{{ID: "desk", Name: "Desk", Schemes: []string{deskScheme, "net.example.desk-2"}}})
	require.NoError(t, err)
	assert.Equal(t, []string{deskScheme, "net.example.desk-2"}, apps["desk"].Schemes)
}

func TestRegisterSchemeCallback(t *testing.T) {
	tests := []struct {
		name string
		body map[string]any
		code string // the OAuth error, "" on success
		uris []string
	}{
		{"the scheme callback", map[string]any{"redirect_uris": []string{schemeRedirect}, "software_id": "desk"}, "",
			[]string{schemeRedirect}},
		{"next to the loopback ones", map[string]any{
			"redirect_uris": []string{nativeCallback, schemeRedirect, schemeRedirect}, "software_id": "desk",
		}, "", []string{nativeCallback, schemeRedirect}},

		{"an undeclared scheme", map[string]any{"redirect_uris": []string{"com.example.evil:/oauth/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil},
		{"another app's scheme", map[string]any{"redirect_uris": []string{"org.example.other:/oauth/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil},
		{"https with the scheme's name", map[string]any{"redirect_uris": []string{"https://com.example.desk/oauth/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil},
		{"http with the scheme's name", map[string]any{"redirect_uris": []string{"http://com.example.desk/oauth/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil},
		{"the authority form", map[string]any{"redirect_uris": []string{"com.example.desk://oauth/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil},
		{"another path", map[string]any{"redirect_uris": []string{"com.example.desk:/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil},
		{"a query", map[string]any{"redirect_uris": []string{schemeRedirect + "?x=1"},
			"software_id": "desk"}, "invalid_redirect_uri", nil},
		{"capitals", map[string]any{"redirect_uris": []string{"COM.EXAMPLE.DESK:/oauth/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil},
		{"next to an assistant's callback", map[string]any{"redirect_uris": []string{schemeRedirect, claudeCallback},
			"software_id": "desk"}, "invalid_redirect_uri", nil},
		{"no software_id", map[string]any{"redirect_uris": []string{schemeRedirect}}, "invalid_client_metadata", nil},
		{"the other app's software_id", map[string]any{"redirect_uris": []string{schemeRedirect},
			"software_id": "other"}, "invalid_redirect_uri", nil},
		{"a secret", map[string]any{"redirect_uris": []string{schemeRedirect}, "software_id": "desk",
			"token_endpoint_auth_method": "client_secret_post"}, "invalid_client_metadata", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newSchemeHarness(t)
			w := h.registerJSON(tt.body)
			if tt.code != "" {
				require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
				assert.Equal(t, tt.code, errorOf(t, w))
				assert.Zero(t, h.store.clientCount())
				return
			}
			require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
			var resp registered
			decode(t, w, &resp)
			assert.Equal(t, "desk", resp.SoftwareID)
			assert.Equal(t, authNone, resp.TokenEndpointAuthMethod)
			assert.Equal(t, tt.uris, resp.RedirectURIs)
			c, ok := h.store.client(resp.ClientID)
			require.True(t, ok)
			assert.Equal(t, core.Assistant("app:desk"), c.Assistant)
			assert.Equal(t, tt.uris, c.RedirectURIs)
		})
	}

	// An app without Schemes cannot register a scheme callback, not even one another app declares.
	h := newHarnessWith(t, func(o *Options) {
		o.NativeApps = []NativeApp{deskApp, {ID: "other", Name: "Other", Schemes: []string{deskScheme}}}
	})
	w := h.registerJSON(map[string]any{"redirect_uris": []string{schemeRedirect}, "software_id": "desk"})
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, `{"error":"invalid_redirect_uri","error_description":"the scheme com.example.desk is not one of `+
		`the native app desk's"}`, w.Body.String())
	w = newNativeHarness(t).registerJSON(map[string]any{"redirect_uris": []string{schemeRedirect}, "software_id": "desk"})
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_redirect_uri", errorOf(t, w), "no app declares a scheme")
	w = newHarness(t).registerJSON(map[string]any{"redirect_uris": []string{schemeRedirect}, "software_id": "desk"})
	assert.Equal(t, `{"error":"invalid_redirect_uri",`+
		`"error_description":"only ChatGPT's or Claude's callbacks are accepted, 1 to 10 of one assistant"}`,
		w.Body.String(), "without native apps, v0.2.0's bytes")
}

// TestRegisterSchemeBytes pins the answer of a scheme registration and the refusal's wording with a scheme declared.
func TestRegisterSchemeBytes(t *testing.T) {
	h := newSchemeHarness(t)
	w := h.registerJSON(map[string]any{"redirect_uris": []string{"https://evil.example/cb"}})
	assert.Equal(t, `{"error":"invalid_redirect_uri","error_description":"only ChatGPT's or Claude's callbacks, `+
		`1 to 10 of one assistant, or a native app's http://127.0.0.1/oauth/callback or its own scheme's `+
		`scheme:/oauth/callback are accepted"}`, w.Body.String())

	w = h.registerJSON(map[string]any{"redirect_uris": []string{schemeRedirect}, "software_id": "desk",
		"client_name": "Phone"})
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"client_name":"Phone","redirect_uris":["com.example.desk:/oauth/callback"],`)
	assert.Contains(t, w.Body.String(), `"software_id":"desk"}`)
}

// TestSchemeFlow walks a phone app through registration, authorize with its scheme callback from the system
// browser, the consent view, approve, the code exchange and a refresh.
func TestSchemeFlow(t *testing.T) {
	h := newSchemeHarness(t)
	tc := h.registerScheme(schemeRedirect, nativeCallback, schemeRedirect)
	txnID, verifier := h.startAppTxn(tc)

	w := h.get("/api/oauth/txn/"+txnID, "alice")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var view map[string]any
	decode(t, w, &view)
	assert.Equal(t, "app", view["started_from"])
	assert.Equal(t, "", view["redirect_host"], "a scheme callback has no host")
	assert.Equal(t, map[string]any{"id": "desk", "name": "Desk", "scheme": deskScheme}, view["app"])

	back := h.approveTxn(txnID, "alice")
	assert.Equal(t, deskScheme, back.Scheme)
	assert.Empty(t, back.Host)
	assert.Equal(t, "/oauth/callback", back.Path)
	assert.Equal(t, "st-notes", back.Query().Get("state"))
	assert.Equal(t, hubURL, back.Query().Get("iss"))
	assert.True(t, strings.HasPrefix(back.String(), schemeRedirect+"?"), back.String())

	tk := h.exchange(tc, back.Query().Get("code"), verifier)
	info, err := h.srv.ValidateAccess(t.Context(), tk.AccessToken, "notes")
	require.NoError(t, err)
	assert.Equal(t, core.Assistant("app:desk"), info.Assistant)
	w = h.refresh(tc, tk.RefreshToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// The same client still uses its loopback callback on the app's port; the view has no scheme then.
	tc.redirect = nativeAt(8742)
	txnID, _ = h.startAppTxn(tc)
	w = h.get("/api/oauth/txn/"+txnID, "alice")
	decode(t, w, &view)
	assert.Equal(t, map[string]any{"id": "desk", "name": "Desk"}, view["app"])
	assert.Equal(t, "127.0.0.1:8742", view["redirect_host"])
}

func TestAuthorizeSchemeRedirects(t *testing.T) {
	h := newSchemeHarness(t)
	tc := h.registerScheme("", schemeRedirect)
	loopbackOnly := h.registerScheme("", nativeCallback)
	for _, c := range []struct {
		tc       testClient
		redirect string
	}{
		{tc, "com.example.desk://oauth/callback"},
		{tc, "com.example.desk:///oauth/callback"},
		{tc, "com.example.desk:/oauth/callback/"},
		{tc, "com.example.desk:/oauth/other"},
		{tc, schemeRedirect + "?x=1"},
		{tc, schemeRedirect + "#x"},
		{tc, "COM.EXAMPLE.DESK:/oauth/callback"},
		{tc, "https://com.example.desk/oauth/callback"},
		{tc, "org.example.other:/oauth/callback"},
		{tc, nativeAt(8742)}, // not among this client's callbacks
		{loopbackOnly, schemeRedirect},
	} {
		t.Run(c.redirect, func(t *testing.T) {
			_, challenge := newPKCE()
			params := authorizeParams(testClient{id: c.tc.id, redirect: c.redirect}, "notes", challenge)
			assertPage(t, h.authorizeFromApp(params), http.StatusBadRequest, pageBadRedirect)
		})
	}
	assert.Zero(t, h.srv.txns.count())

	// PKCE is required, and the error goes back to the scheme callback.
	_, challenge := newPKCE()
	params := authorizeParams(testClient{id: tc.id, redirect: schemeRedirect}, "notes", challenge)
	params.Del("code_challenge")
	w := h.authorizeFromApp(params)
	require.Equal(t, http.StatusFound, w.Code)
	loc := location(t, w)
	assert.Equal(t, deskScheme, loc.Scheme)
	assert.Equal(t, "invalid_request", loc.Query().Get("error"))

	// An assistant's client cannot use a scheme callback.
	claude := h.registerDCR(claudeCallback, authNone)
	claude.redirect = schemeRedirect
	assertPage(t, h.authorize(authorizeParams(claude, "notes", challenge)), http.StatusBadRequest, pageBadRedirect)

	// A cross-site request for a scheme callback warns, as for loopback ones.
	tc.redirect = schemeRedirect
	assert.Equal(t, startedElsewhere, h.txnStartedFrom(tc, "https://evil.example/", "cross-site"))
	assert.Equal(t, startedApp, h.txnStartedFrom(tc, "", "none"))
}

func TestAuthorizeRefusesAnUndeclaredScheme(t *testing.T) {
	declared := newSchemeHarness(t)
	tc := declared.registerScheme(schemeRedirect, schemeRedirect, nativeCallback)
	stored, ok := declared.store.client(tc.id)
	require.True(t, ok)

	// The app is still declared, without the scheme: the scheme callback is refused, the loopback one still works.
	h := newHarnessWith(t, func(o *Options) { o.NativeApps = []NativeApp{deskApp} })
	require.NoError(t, h.store.OAuth().PutClient(t.Context(), stored))
	_, challenge := newPKCE()
	assertPage(t, h.authorizeFromApp(authorizeParams(tc, "notes", challenge)), http.StatusBadRequest, pageBadRedirect)
	assert.Zero(t, h.srv.txns.count())
	h.startAppTxn(testClient{id: tc.id, redirect: nativeAt(53211)})
}
