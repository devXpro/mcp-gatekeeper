package oauth

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// deskApp is the native app of these tests; nativeCallback is its registered callback, and nativeAt one with the
// port the app listens on for one request.
var deskApp = NativeApp{ID: "desk", Name: "Desk"}

const (
	nativeCallback   = "http://127.0.0.1/oauth/callback"
	nativeCallbackV6 = "http://[::1]/oauth/callback"
)

func nativeAt(port int) string { return fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", port) }

// newNativeHarness is newHarness with deskApp declared.
func newNativeHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, func(o *Options) { o.NativeApps = []NativeApp{deskApp} })
}

// registerNative registers a client of deskApp named name and returns it with redirect as its redirect URI.
func (h *harness) registerNative(name, redirect string) testClient {
	h.t.Helper()
	w := h.registerJSON(map[string]any{
		"redirect_uris": []string{nativeCallback}, "token_endpoint_auth_method": "none", "client_name": name,
		"software_id": deskApp.ID,
	})
	require.Equal(h.t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		ClientID string `json:"client_id"`
	}
	decode(h.t, w, &resp)
	return testClient{id: resp.ClientID, redirect: redirect}
}

func TestLoopbackCallback(t *testing.T) {
	tests := []struct {
		uri, want string
	}{
		{"http://127.0.0.1/oauth/callback", nativeCallback},
		{"http://127.0.0.1:53211/oauth/callback", nativeCallback},
		{"http://127.0.0.1:1/oauth/callback", nativeCallback},
		{"http://127.0.0.1:65535/oauth/callback", nativeCallback},
		{"http://[::1]/oauth/callback", nativeCallbackV6},
		{"http://[::1]:8080/oauth/callback", nativeCallbackV6},

		{"http://localhost/oauth/callback", ""},
		{"http://localhost:53211/oauth/callback", ""},
		{"https://127.0.0.1/oauth/callback", ""},
		{"https://127.0.0.1:53211/oauth/callback", ""},
		{"http://127.0.0.2/oauth/callback", ""},
		{"http://127.1/oauth/callback", ""},
		{"http://[0:0::1]/oauth/callback", ""},
		{"http://[::ffff:127.0.0.1]/oauth/callback", ""},
		{"http://[::1%25lo0]/oauth/callback", ""},
		{"http://0.0.0.0/oauth/callback", ""},
		{"http://evil.example/oauth/callback", ""},
		{"http://127.0.0.1.evil.example/oauth/callback", ""},
		{"http://127.0.0.1:/oauth/callback", ""},
		{"http://127.0.0.1:0/oauth/callback", ""},
		{"http://127.0.0.1:65536/oauth/callback", ""},
		{"http://127.0.0.1:053211/oauth/callback", ""},
		{"http://127.0.0.1:+80/oauth/callback", ""},
		{"http://127.0.0.1/oauth/callback/", ""},
		{"http://127.0.0.1/oauth/cb", ""},
		{"http://127.0.0.1/", ""},
		{"http://127.0.0.1", ""},
		{"http://127.0.0.1/oauth/%63allback", ""},
		{"http://127.0.0.1/OAUTH/callback", ""},
		{"HTTP://127.0.0.1/oauth/callback", ""},
		{"http://me@127.0.0.1/oauth/callback", ""},
		{"http://127.0.0.1/oauth/callback?x=1", ""},
		{"http://127.0.0.1/oauth/callback?", ""},
		{"http://127.0.0.1/oauth/callback#x", ""},
		{"http://127.0.0.1/oauth/callback\n", ""},
		{"//127.0.0.1/oauth/callback", ""},
		{claudeCallback, ""},
		{"http://127.0.0.1:53211/oauth/callback" + strings.Repeat("a", maxURLLen), ""},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			got, ok := loopbackCallback(tt.uri)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.want != "", ok)
		})
	}
}

func TestNativeSet(t *testing.T) {
	got, ok := nativeSet([]string{nativeCallback, nativeCallbackV6, nativeCallback})
	assert.True(t, ok)
	assert.Equal(t, []string{nativeCallback, nativeCallbackV6}, got, "without repeats")

	eleven := make([]string, 11)
	for i := range eleven {
		eleven[i] = nativeCallback
	}
	for name, uris := range map[string][]string{
		"none":                    nil,
		"eleven":                  eleven,
		"with a port":             {nativeAt(53211)},
		"localhost":               {"http://localhost/oauth/callback"},
		"an assistant's callback": {nativeCallback, claudeCallback},
	} {
		_, ok := nativeSet(uris)
		assert.False(t, ok, name)
	}
}

func TestNativeAppID(t *testing.T) {
	id, ok := NativeAppID("app:desk")
	assert.True(t, ok)
	assert.Equal(t, "desk", id)
	for _, a := range []core.Assistant{core.AssistantChatGPT, core.AssistantClaude, "app:", "app:Desk", "desk", ""} {
		_, ok := NativeAppID(a)
		assert.False(t, ok, a)
	}
}

func TestNewRefusesBadNativeApps(t *testing.T) {
	for name, apps := range map[string][]NativeApp{
		"an id with a capital":  {{ID: "Desk", Name: "Desk"}},
		"a one-letter id":       {{ID: "d", Name: "Desk"}},
		"an id with a colon":    {{ID: "desk:x", Name: "Desk"}},
		"an id twice":           {deskApp, deskApp},
		"no name":               {{ID: "desk"}},
		"a blank name":          {{ID: "desk", Name: "  "}},
		"a name with spaces":    {{ID: "desk", Name: " Desk"}},
		"an invisible name":     {{ID: "desk", Name: bidiOverride + "Desk"}},
		"a name over 64 runes":  {{ID: "desk", Name: strings.Repeat("я", 65)}},
		"a name with a newline": {{ID: "desk", Name: "De\nsk"}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			o := Options{
				Site:  core.Site{PublicURL: hubURL, RPID: "hub.example.com", ClientIP: core.ClientIPRemote},
				Brand: testBrand, Store: h.store, Sessions: h.sessions, Catalog: h.catalog,
				Paths: core.PerResource{Prefix: "/mcp/"}, NativeApps: apps,
			}
			_, err := New(o)
			assert.Error(t, err)
		})
	}
}

func TestRegisterNativeApp(t *testing.T) {
	tests := []struct {
		name       string
		body       map[string]any
		code       string // the OAuth error, "" on success
		uris       []string
		clientName string
	}{
		{"the loopback callback", map[string]any{"redirect_uris": []string{nativeCallback}, "software_id": "desk",
			"token_endpoint_auth_method": "none", "client_name": "Work laptop"}, "",
			[]string{nativeCallback}, "Work laptop"},
		{"both loopback addresses, the method by default", map[string]any{
			"redirect_uris": []string{nativeCallbackV6, nativeCallback, nativeCallbackV6}, "software_id": "desk",
			"client_name": "Work laptop",
		}, "", []string{nativeCallbackV6, nativeCallback}, "Work laptop"},
		{"no name takes the app's", map[string]any{"redirect_uris": []string{nativeCallback}, "software_id": "desk"},
			"", []string{nativeCallback}, "Desk"},
		{"the name is cleaned", map[string]any{"redirect_uris": []string{nativeCallback}, "software_id": "desk",
			"client_name": bidiOverride + zeroWidth}, "", []string{nativeCallback}, "Desk"},

		{"localhost", map[string]any{"redirect_uris": []string{"http://localhost/oauth/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil, ""},
		{"a foreign host", map[string]any{"redirect_uris": []string{"http://evil.example/oauth/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil, ""},
		{"another path", map[string]any{"redirect_uris": []string{"http://127.0.0.1/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil, ""},
		{"https on loopback", map[string]any{"redirect_uris": []string{"https://127.0.0.1/oauth/callback"},
			"software_id": "desk"}, "invalid_redirect_uri", nil, ""},
		{"a port at registration", map[string]any{"redirect_uris": []string{nativeAt(53211)},
			"software_id": "desk"}, "invalid_redirect_uri", nil, ""},
		{"loopback next to an assistant's callback", map[string]any{
			"redirect_uris": []string{nativeCallback, claudeCallback}, "software_id": "desk",
		}, "invalid_redirect_uri", nil, ""},
		{"no software_id", map[string]any{"redirect_uris": []string{nativeCallback}}, "invalid_client_metadata", nil, ""},
		{"an undeclared software_id", map[string]any{"redirect_uris": []string{nativeCallback},
			"software_id": "other"}, "invalid_client_metadata", nil, ""},
		{"software_id of another type", map[string]any{"redirect_uris": []string{nativeCallback},
			"software_id": 1}, "invalid_client_metadata", nil, ""},
		{"a secret", map[string]any{"redirect_uris": []string{nativeCallback}, "software_id": "desk",
			"token_endpoint_auth_method": "client_secret_post"}, "invalid_client_metadata", nil, ""},
		{"basic", map[string]any{"redirect_uris": []string{nativeCallback}, "software_id": "desk",
			"token_endpoint_auth_method": "client_secret_basic"}, "invalid_client_metadata", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newNativeHarness(t)
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
			assert.Empty(t, resp.ClientSecret)
			assert.Equal(t, tt.uris, resp.RedirectURIs)
			c, ok := h.store.client(resp.ClientID)
			require.True(t, ok)
			assert.Equal(t, core.ClientDCR, c.Kind)
			assert.Equal(t, core.Assistant("app:desk"), c.Assistant)
			assert.Equal(t, tt.uris, c.RedirectURIs)
			assert.Equal(t, tt.clientName, c.Name)
			assert.Nil(t, c.SecretHash)
		})
	}
}

// TestRegisterNativeAppBytes pins a native app's registration answer and the refusals' wording.
func TestRegisterNativeAppBytes(t *testing.T) {
	h := newNativeHarness(t)
	w := h.registerJSON(map[string]any{"redirect_uris": []string{nativeCallback}, "software_id": "desk",
		"client_name": "Work laptop"})
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp registered
	decode(t, w, &resp)
	assert.Equal(t, `{"client_id":"`+resp.ClientID+`","client_id_issued_at":`+fmt.Sprint(h.clock.now().Unix())+
		`,"client_name":"Work laptop","redirect_uris":["http://127.0.0.1/oauth/callback"],`+
		`"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],`+
		`"response_types":["code"],"scope":"mcp offline_access","software_id":"desk"}`, w.Body.String())
	assert.Equal(t, map[string]string{"kind": "dcr", "assistant": "app:desk", "auth_method": "none"},
		h.store.auditEntries()[0].Detail)

	w = h.registerJSON(map[string]any{"redirect_uris": []string{"https://evil.example/cb"}})
	assert.Equal(t, `{"error":"invalid_redirect_uri","error_description":"only ChatGPT's or Claude's callbacks, `+
		`1 to 10 of one assistant, or a native app's http://127.0.0.1/oauth/callback are accepted"}`, w.Body.String())
	w = h.registerJSON(map[string]any{"redirect_uris": []string{nativeCallback}})
	assert.Equal(t, `{"error":"invalid_client_metadata","error_description":"software_id must name a native app of `+
		`this hub"}`, w.Body.String())
	w = h.registerJSON(map[string]any{"redirect_uris": []string{nativeCallback}, "software_id": "desk",
		"token_endpoint_auth_method": "client_secret_post"})
	assert.Equal(t, `{"error":"invalid_client_metadata","error_description":"a native app is a public client: `+
		`token_endpoint_auth_method must be none"}`, w.Body.String())
}

// TestRegisterLoopbackWithoutNativeApps: with none declared, a loopback callback is refused with v0.2.0's bytes, and
// a software_id changes nothing for an assistant.
func TestRegisterLoopbackWithoutNativeApps(t *testing.T) {
	h := newHarness(t)
	w := h.registerJSON(map[string]any{"redirect_uris": []string{nativeCallback}, "software_id": "desk"})
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, `{"error":"invalid_redirect_uri",`+
		`"error_description":"only ChatGPT's or Claude's callbacks are accepted, 1 to 10 of one assistant"}`,
		w.Body.String())
	assert.Zero(t, h.store.clientCount())

	for _, h := range []*harness{newHarness(t), newNativeHarness(t)} {
		w := h.registerJSON(map[string]any{"redirect_uris": []string{claudeCallback}, "software_id": "desk"})
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		assert.NotContains(t, w.Body.String(), "software_id")
		var resp registered
		decode(t, w, &resp)
		c, _ := h.store.client(resp.ClientID)
		assert.Equal(t, core.AssistantClaude, c.Assistant, "an assistant's callback tells the assistant")
	}
}

// TestNativeAppFlow walks a native app through registration, authorize on a port of its own, the consent screen,
// approve, the code exchange, the access check and a refresh.
func TestNativeAppFlow(t *testing.T) {
	h := newNativeHarness(t)
	tc := h.registerNative("Work laptop", nativeAt(53211))
	txnID, verifier := h.startTxn(tc, "notes")

	w := h.get("/api/oauth/txn/"+txnID, "alice")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{
		"assistant": "app:desk",
		"client_name": "Work laptop",
		"client_kind": "dcr",
		"redirect_host": "127.0.0.1:53211",
		"started_from": "app",
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
		"already_granted": false,
		"app": {"id": "desk", "name": "Desk"}
	}`, w.Body.String())

	back := h.approveTxn(txnID, "alice")
	assert.Equal(t, "http://127.0.0.1:53211/oauth/callback", back.Scheme+"://"+back.Host+back.Path,
		"the code goes to the port of the request")
	assert.Equal(t, "st-notes", back.Query().Get("state"))
	assert.Equal(t, hubURL, back.Query().Get("iss"))
	code := back.Query().Get("code")

	other := tc
	other.redirect = nativeAt(40000)
	w = h.clientPost("/oauth/token", other, exchangeForm(other, code, verifier))
	assert.Equal(t, http.StatusBadRequest, w.Code, "the exchange names the port of the authorization request")
	assert.Equal(t, "invalid_grant", errorOf(t, w))

	code, verifier = h.codeFor(tc, "alice", "notes")
	tk := h.exchange(tc, code, verifier)
	info, err := h.srv.ValidateAccess(t.Context(), tk.AccessToken, "notes")
	require.NoError(t, err)
	assert.Equal(t, core.Assistant("app:desk"), info.Assistant)
	assert.Equal(t, core.ResourceID("notes"), info.ResourceID)
	assert.False(t, h.valid(tk.AccessToken, "photos"))

	w = h.refresh(tc, tk.RefreshToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// The next connection listens on another port; that is the same client.
	tc.redirect = nativeAt(61000)
	h.startTxn(tc, "notes")
	assert.Equal(t, map[string]int{"oauth.client.register": 1, "oauth.grant.create": 1}, h.store.auditActions())
}

func TestAuthorizeNativeRedirects(t *testing.T) {
	h := newNativeHarness(t)
	tc := h.registerNative("Work laptop", "")
	for _, uri := range []string{nativeCallback, nativeAt(1), nativeAt(53211), nativeAt(65535)} {
		tc.redirect = uri
		h.startTxn(tc, "notes")
	}
	for _, uri := range []string{
		"http://localhost:53211/oauth/callback", "https://127.0.0.1:53211/oauth/callback",
		"http://127.0.0.1:53211/oauth/other", "http://127.0.0.1:53211/oauth/callback?x=1",
		"http://127.0.0.1:0/oauth/callback", "http://127.0.0.1:65536/oauth/callback",
		"http://127.0.0.1:/oauth/callback", "http://evil.example:53211/oauth/callback",
		"http://[::1]:53211/oauth/callback", // [::1] is not among this client's callbacks
		claudeCallback,
	} {
		tc.redirect = uri
		_, challenge := newPKCE()
		assertPage(t, h.authorize(authorizeParams(tc, "notes", challenge)), http.StatusBadRequest, pageBadRedirect)
	}

	_, challenge := newPKCE()
	params := authorizeParams(testClient{id: tc.id, redirect: nativeAt(53211)}, "notes", challenge)
	params.Del("code_challenge")
	w := h.authorize(params)
	require.Equal(t, http.StatusFound, w.Code)
	loc := location(t, w)
	assert.Equal(t, "127.0.0.1:53211", loc.Host)
	assert.Equal(t, "invalid_request", loc.Query().Get("error"), "PKCE is required, as for everyone")

	// An assistant's client cannot use a loopback callback.
	claude := h.registerDCR(claudeCallback, authNone)
	claude.redirect = nativeAt(53211)
	assertPage(t, h.authorize(authorizeParams(claude, "notes", challenge)), http.StatusBadRequest, pageBadRedirect)
}

func TestAuthorizeRefusesAnUndeclaredNativeApp(t *testing.T) {
	// A client of an app that is no longer declared cannot start a connection.
	declared := newNativeHarness(t)
	tc := declared.registerNative("Work laptop", nativeAt(53211))
	stored, ok := declared.store.client(tc.id)
	require.True(t, ok)

	for _, h := range []*harness{
		newHarness(t),
		newHarnessWith(t, func(o *Options) { o.NativeApps = []NativeApp{{ID: "other", Name: "Other"}} }),
	} {
		require.NoError(t, h.store.OAuth().PutClient(t.Context(), stored))
		_, challenge := newPKCE()
		assertPage(t, h.authorize(authorizeParams(tc, "notes", challenge)), http.StatusBadRequest, pageBadRedirect)
		assert.Zero(t, h.srv.txns.count())
	}
}

// randomParts are the values that differ from run to run: client, transaction and grant ids, codes and tokens.
var randomParts = regexp.MustCompile(`cli_[a-z2-7]{16}|txn_[A-Za-z0-9_-]+|[A-Za-z0-9_-]{43}`)

// TestAssistantsUnchangedByNativeApps: ChatGPT's and Claude's registration, authorize, consent view, approve, token
// and refresh answers are byte for byte the same whether native apps are declared or not.
func TestAssistantsUnchangedByNativeApps(t *testing.T) {
	run := func(h *harness) []string {
		var out []string
		// keep notes the status, every header and body of an answer.
		keep := func(w *httptest.ResponseRecorder, body string) {
			var b strings.Builder
			fmt.Fprintln(&b, w.Code)
			for _, k := range slices.Sorted(maps.Keys(w.Header())) {
				fmt.Fprintln(&b, k+": "+strings.Join(w.Header()[k], ", "))
			}
			b.WriteString(body)
			out = append(out, b.String())
		}
		for _, redirect := range []string{chatgptCallback, claudeCallback} {
			w := h.registerJSON(map[string]any{"redirect_uris": []string{redirect}, "client_name": "Test"})
			keep(w, w.Body.String())
			var reg registered
			decode(t, w, &reg)
			tc := testClient{id: reg.ClientID, redirect: redirect}
			verifier, challenge := newPKCE()
			w = h.authorize(authorizeParams(tc, "notes", challenge))
			keep(w, w.Body.String())
			txnID := strings.TrimPrefix(w.Header().Get("Location"), "/consent?txn=")
			w = h.get("/api/oauth/txn/"+txnID, "alice")
			keep(w, w.Body.String())
			w = h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice")
			keep(w, w.Body.String())
			code := redirectOf(t, w).Query().Get("code")
			w = h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
			keep(w, w.Body.String())
			var tk tokens
			decode(t, w, &tk)
			w = h.refresh(tc, tk.RefreshToken)
			keep(w, w.Body.String())

			bad := tc
			bad.redirect = nativeAt(53211)
			w = h.authorize(authorizeParams(bad, "notes", challenge))
			keep(w, w.Body.String())
		}
		w := h.registerJSON(map[string]any{"redirect_uris": []string{"https://evil.example/cb"}})
		keep(w, "") // its wording differs by design when native apps are declared (TestRegisterNativeAppBytes)
		for i, s := range out {
			out[i] = randomParts.ReplaceAllString(s, "<random>")
		}
		return out
	}
	without, with := run(newHarness(t)), run(newNativeHarness(t))
	require.Len(t, without, 15)
	assert.Equal(t, without, with)
	assert.Contains(t, without[2], `"started_from":"unknown"`)
	assert.NotContains(t, strings.Join(without, "\n"), `"app"`)
	assert.NotContains(t, strings.Join(without, "\n"), "software_id")
}
