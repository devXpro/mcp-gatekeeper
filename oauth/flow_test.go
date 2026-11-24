package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// TestFullFlow walks two connectors the way ChatGPT's and Claude's backends and the SPA do, over real HTTP: the
// 401 discovery, DCR for ChatGPT and CIMD for Claude, authorize, the consent API with a session, the code exchange,
// tokens bound to their resources, a refresh, a reused refresh, and a revoke. No secret may reach the logs or the
// audit.
func TestFullFlow(t *testing.T) {
	h := newHarness(t)
	srv := httptest.NewServer(h.mux)
	t.Cleanup(srv.Close)
	c := &flowClient{t: t, base: srv.URL, jar: newBrowser(), http: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	var secrets []string

	// Discovery: the 401 of the MCP access check names the protected-resource metadata, which names the issuer.
	var prm resourceMetadataDoc
	metadataURL := ResourceMetadataURL(hubURL, core.PerResource{Prefix: "/mcp/"}, "notes")
	c.getJSON(strings.TrimPrefix(metadataURL, hubURL), "", http.StatusOK, &prm)
	assert.Equal(t, hubURL+"/mcp/notes", prm.Resource)
	var as serverMetadataDoc
	c.getJSON("/.well-known/oauth-authorization-server", "", http.StatusOK, &as)
	assert.Equal(t, prm.AuthorizationServers, []string{as.Issuer})
	assert.True(t, as.ClientIDMetadataDocumentSupported)

	// ChatGPT registers with a secret.
	var reg registered
	c.postJSON(strings.TrimPrefix(as.RegistrationEndpoint, hubURL), map[string]any{
		"redirect_uris": []string{chatgptCallback}, "token_endpoint_auth_method": "client_secret_post",
		"client_name": "ChatGPT",
	}, http.StatusCreated, &reg)
	chatgpt := testClient{id: reg.ClientID, secret: reg.ClientSecret, redirect: chatgptCallback}
	secrets = append(secrets, chatgpt.secret)

	// Authorize, then the SPA: no session first, then Alice's.
	verifier, challenge := newPKCE()
	secrets = append(secrets, verifier)
	txnID := c.authorize(authorizeParams(chatgpt, "notes", challenge))
	binding := c.jar.binding()
	require.NotEmpty(t, binding, "authorize binds the transaction to this browser")
	secrets = append(secrets, binding)
	c.getJSON("/api/oauth/txn/"+txnID, "", http.StatusUnauthorized, nil)
	var view txnView
	c.getJSON("/api/oauth/txn/"+txnID, "alice", http.StatusOK, &view)
	assert.Equal(t, "chatgpt", string(view.Assistant))
	assert.Equal(t, "Notes", view.Resource.Name)
	assert.Equal(t, "dcr", string(view.ClientKind))
	assert.False(t, view.AlreadyGranted)
	back := c.approve(txnID, "alice")
	assert.Equal(t, "st-notes", back.Query().Get("state"))
	assert.Equal(t, hubURL, back.Query().Get("iss"))
	code := back.Query().Get("code")
	secrets = append(secrets, code)

	// The exchange gives tokens bound to Notes.
	chatgptTokens := c.token(chatgpt, exchangeForm(chatgpt, code, verifier), http.StatusOK)
	secrets = append(secrets, chatgptTokens.AccessToken, chatgptTokens.RefreshToken)
	assert.True(t, h.valid(chatgptTokens.AccessToken, "notes"))
	assert.False(t, h.valid(chatgptTokens.AccessToken, "photos"), "a token of A is refused on B")

	// A second connector, Claude with CIMD for the photos: the session is there, so only the consent click.
	claude := h.cimdClient(claudeDocument, claudeCallback)
	verifier2, challenge2 := newPKCE()
	secrets = append(secrets, verifier2)
	txn2 := c.authorize(authorizeParams(claude, "photos", challenge2))
	assert.Equal(t, binding, c.jar.binding(), "one binding per browser")
	c.getJSON("/api/oauth/txn/"+txn2, "alice", http.StatusOK, &view)
	assert.Equal(t, "claude", string(view.Assistant))
	assert.Equal(t, "claude.ai", view.RedirectHost)
	assert.Equal(t, "cimd", string(view.ClientKind))
	code2 := c.approve(txn2, "alice").Query().Get("code")
	secrets = append(secrets, code2)
	claudeTokens := c.token(claude, exchangeForm(claude, code2, verifier2), http.StatusOK)
	secrets = append(secrets, claudeTokens.AccessToken, claudeTokens.RefreshToken)
	assert.True(t, h.valid(claudeTokens.AccessToken, "photos"))
	assert.False(t, h.valid(claudeTokens.AccessToken, "notes"))

	// ChatGPT refreshes; its old refresh token coming back revokes the family.
	refreshed := c.token(chatgpt, url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {chatgptTokens.RefreshToken}}, http.StatusOK)
	secrets = append(secrets, refreshed.AccessToken, refreshed.RefreshToken)
	assert.True(t, h.valid(refreshed.AccessToken, "notes"))
	c.token(chatgpt, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {chatgptTokens.RefreshToken}},
		http.StatusBadRequest)
	assert.False(t, h.valid(refreshed.AccessToken, "notes"))
	assert.True(t, h.valid(claudeTokens.AccessToken, "photos"), "the other connector is untouched")

	// Claude revokes its refresh token, and with it its access token.
	c.post("/oauth/revoke", claude, url.Values{"token": {claudeTokens.RefreshToken}}, http.StatusOK, nil)
	assert.False(t, h.valid(claudeTokens.AccessToken, "photos"))

	assert.Equal(t, map[string]int{
		"oauth.client.register": 2, "oauth.grant.create": 2, "oauth.refresh.reuse": 1,
	}, h.store.auditActions())
	assertNoSecrets(t, h, secrets)
}

// assertNoSecrets checks that no log line and no audit entry holds any of secrets.
func assertNoSecrets(t *testing.T, h *harness, secrets []string) {
	t.Helper()
	require.NotEmpty(t, h.logs.Records(), "the flow logs something")
	var seen strings.Builder
	for _, r := range h.logs.Records() {
		seen.WriteString(r.Message)
		for k, v := range r.Attrs {
			fmt.Fprintf(&seen, " %s=%v", k, v)
		}
		seen.WriteString("\n")
	}
	for _, e := range h.store.auditEntries() {
		b, err := json.Marshal(e)
		require.NoError(t, err)
		seen.Write(b)
	}
	for _, s := range secrets {
		require.NotEmpty(t, s)
		assert.NotContains(t, seen.String(), s)
		assert.False(t, h.logs.Contains(s))
	}
}

// flowClient talks to the server over HTTP like an assistant's backend or the SPA, with the server's cookies of one
// browser in jar.
type flowClient struct {
	t    *testing.T
	base string
	http *http.Client
	jar  *browser
}

// send makes the request as person, requires status, decodes the body into out unless it is nil, and returns the
// answer's headers.
func (c *flowClient) send(r *http.Request, person string, status int, out any) http.Header {
	c.t.Helper()
	signIn(r, person)
	c.jar.attach(r)
	resp, err := c.http.Do(r)
	require.NoError(c.t, err)
	defer func() { _ = resp.Body.Close() }()
	c.jar.keep(resp.Header)
	body, err := io.ReadAll(resp.Body)
	require.NoError(c.t, err)
	require.Equal(c.t, status, resp.StatusCode, string(body))
	if out != nil {
		require.NoError(c.t, json.Unmarshal(body, out), string(body))
	}
	return resp.Header
}

func (c *flowClient) request(method, path string, body io.Reader) *http.Request {
	c.t.Helper()
	r, err := http.NewRequestWithContext(c.t.Context(), method, c.base+path, body)
	require.NoError(c.t, err)
	return r
}

func (c *flowClient) getJSON(path, person string, status int, out any) {
	c.t.Helper()
	c.send(c.request(http.MethodGet, path, nil), person, status, out)
}

func (c *flowClient) postJSON(path string, in any, status int, out any) {
	c.t.Helper()
	b, err := json.Marshal(in)
	require.NoError(c.t, err)
	r := c.request(http.MethodPost, path, strings.NewReader(string(b)))
	r.Header.Set("Content-Type", "application/json")
	c.send(r, "", status, out)
}

// authorize sends the browser to /oauth/authorize and returns the transaction of the consent redirect.
func (c *flowClient) authorize(params url.Values) string {
	c.t.Helper()
	header := c.send(c.request(http.MethodGet, "/oauth/authorize?"+params.Encode(), nil), "", http.StatusFound, nil)
	id, ok := strings.CutPrefix(header.Get("Location"), "/consent?txn=")
	require.True(c.t, ok, header.Get("Location"))
	return id
}

// approve presses Allow on the consent screen and returns where the SPA sends the browser.
func (c *flowClient) approve(txnID, person string) *url.URL {
	c.t.Helper()
	r := c.request(http.MethodPost, "/api/oauth/txn/"+txnID+"/approve", nil)
	r.Header.Set(testBrand.CSRFHeader, "1")
	r.Header.Set("Origin", hubURL)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	var resp struct {
		RedirectURL string `json:"redirect_url"`
	}
	c.send(r, person, http.StatusOK, &resp)
	u, err := url.Parse(resp.RedirectURL)
	require.NoError(c.t, err)
	return u
}

// post sends a form to path, authenticated as tc in the form, and decodes the answer into out unless it is nil.
func (c *flowClient) post(path string, tc testClient, form url.Values, status int, out any) {
	c.t.Helper()
	form = cloneValues(form)
	form.Set("client_id", tc.id)
	if tc.secret != "" {
		form.Set("client_secret", tc.secret)
	}
	r := c.request(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.send(r, "", status, out)
}

// token sends a token request; the tokens are decoded from a 200.
func (c *flowClient) token(tc testClient, form url.Values, status int) tokens {
	c.t.Helper()
	var tk tokens
	var out any
	if status == http.StatusOK {
		out = &tk
	}
	c.post("/oauth/token", tc, form, status, out)
	return tk
}
