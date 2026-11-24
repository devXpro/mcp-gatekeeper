package oauth

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestCIMDClient(t *testing.T) {
	h := newHarness(t)
	tc := h.cimdClient(claudeDocument, claudeCallback)
	h.startTxn(tc, "notes")

	c, ok := h.store.client(claudeDocument)
	require.True(t, ok)
	assert.Equal(t, core.OAuthClient{
		ID: claudeDocument, Kind: core.ClientCIMD, Assistant: core.AssistantClaude, Name: "Claude",
		RedirectURIs: []string{claudeCallback}, AuthMethod: authNone, FetchedAt: h.clock.now(), CreatedAt: h.clock.now(),
	}, c)
	assert.Equal(t, 1, h.fetcher.count(claudeDocument))
	assert.WithinDuration(t, time.Now().Add(cimdTimeout), h.fetcher.deadline(claudeDocument), time.Second,
		"the fetch has 5 s")
	assert.Equal(t, map[string]int{"oauth.client.register": 1}, h.store.auditActions())
	entry := h.store.auditEntries()[0]
	assert.Equal(t, claudeDocument, entry.Target)
	assert.Equal(t, map[string]string{"kind": "cimd", "assistant": "claude"}, entry.Detail)

	h.clock.advance(23 * time.Hour)
	h.startTxn(tc, "photos")
	assert.Equal(t, 1, h.fetcher.count(claudeDocument), "a document is reused for a day")

	created := h.clock.now().Add(-23 * time.Hour)
	h.clock.advance(2 * time.Hour)
	h.fetcher.set(claudeDocument, metadataDoc(claudeDocument, claudeCallback, "https://claude.com/api/mcp/auth_callback"))
	h.startTxn(tc, "notes")
	assert.Equal(t, 2, h.fetcher.count(claudeDocument), "and fetched again after it")
	c, _ = h.store.client(claudeDocument)
	assert.Equal(t, h.clock.now(), c.FetchedAt)
	assert.Equal(t, created, c.CreatedAt)
	assert.Len(t, c.RedirectURIs, 2, "the new document counts")
	assert.Equal(t, map[string]int{"oauth.client.register": 1}, h.store.auditActions(), "a refetch is no registration")
}

// chatgptRealDocument is https://chatgpt.com/oauth/client.json as ChatGPT served it on 2026-11-21, when the first
// live connect was refused: its own method is private_key_jwt, and it lists none among the methods it supports.
const chatgptRealDocument = `{
  "client_id": "https://chatgpt.com/oauth/client.json",
  "client_uri": "https://chatgpt.com/",
  "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
  "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
  "response_types": ["code"],
  "client_name": "ChatGPT",
  "logo_uri": "https://persistent.oaistatic.com/sonic/misc/openai-logo.png",
  "token_endpoint_auth_signing_alg": "RS256",
  "jwks_uri": "https://chatgpt.com/oauth/jwks.json"
}`

// TestCIMDChatGPTDocument: ChatGPT's real document connects as a public client. The server does not offer
// private_key_jwt, so the token request carries client_id and the PKCE verifier only, and refresh works the same way.
func TestCIMDChatGPTDocument(t *testing.T) {
	h := newHarness(t)
	h.fetcher.set(chatgptDocument, chatgptRealDocument)
	tc := testClient{id: chatgptDocument, redirect: chatgptCallback}

	tk := h.connect(tc, "alice", "notes")
	assert.True(t, h.valid(tk.AccessToken, "notes"))
	c, ok := h.store.client(chatgptDocument)
	require.True(t, ok)
	assert.Equal(t, core.ClientCIMD, c.Kind)
	assert.Equal(t, core.AssistantChatGPT, c.Assistant)
	assert.Equal(t, "ChatGPT", c.Name)
	assert.Equal(t, authNone, c.AuthMethod, "it authenticates with none here")
	assert.Equal(t, []string{chatgptCallback}, c.RedirectURIs)

	w := h.refresh(tc, tk.RefreshToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestCIMDDocumentRefused(t *testing.T) {
	doc := func(fields string) string {
		return `{"client_id":"` + claudeDocument + `","redirect_uris":["` + claudeCallback + `"]` + fields + `}`
	}
	tests := []struct{ name, doc string }{
		{"not JSON", "<!doctype html>"},
		{"a JSON array", "[]"},
		{"client_id is another URL", metadataDoc("https://claude.ai/oauth/other", claudeCallback)},
		{"no client_id", `{"redirect_uris":["` + claudeCallback + `"]}`},
		{"callbacks of the other assistant", metadataDoc(claudeDocument, chatgptCallback)},
		{"a foreign callback", metadataDoc(claudeDocument, "https://evil.example/cb")},
		{"no callbacks", metadataDoc(claudeDocument)},
		{"a secret auth method", doc(`,"token_endpoint_auth_method":"client_secret_basic"`)},
		{"private_key_jwt", doc(`,"token_endpoint_auth_method":"private_key_jwt"`)},
		{"private_key_jwt that offers only itself",
			doc(`,"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_methods_supported":["private_key_jwt"]`)},
		{"none offered but a secret carried",
			doc(`,"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_methods_supported":["none"],"client_secret":"s"`)},
		{"it carries a secret", doc(`,"client_secret":"s3cr3t"`)},
		{"it carries a null secret", doc(`,"client_secret":null`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.fetcher.set(claudeDocument, tt.doc)
			_, challenge := newPKCE()
			w := h.authorize(authorizeParams(testClient{id: claudeDocument, redirect: claudeCallback}, "notes", challenge))
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), template.HTMLEscapeString(pageMetadataInvalid.EN))
			assert.Empty(t, w.Header().Get("Location"), "never redirected")
			assert.Zero(t, h.store.clientCount())
		})
	}
}

func TestCIMDFetchFailure(t *testing.T) {
	h := newHarness(t)
	h.fetcher.fail(claudeDocument, errors.New("connection refused"))
	_, challenge := newPKCE()
	tc := testClient{id: claudeDocument, redirect: claudeCallback}
	w := h.authorize(authorizeParams(tc, "notes", challenge))
	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), template.HTMLEscapeString(pageMetadataFetch.EN))
	assert.Zero(t, h.store.clientCount())

	// The failure is remembered for 5 minutes: asking again fetches nothing.
	h.fetcher.set(claudeDocument, metadataDoc(claudeDocument, claudeCallback))
	h.clock.advance(cimdFailureTTL - time.Second)
	assert.Equal(t, http.StatusBadGateway, h.authorize(authorizeParams(tc, "notes", challenge)).Code)
	assert.Equal(t, 1, h.fetcher.count(claudeDocument))

	h.clock.advance(time.Second)
	h.startTxn(tc, "notes")
	assert.Equal(t, 2, h.fetcher.count(claudeDocument))
}

func TestCIMDRefusedDocumentIsRemembered(t *testing.T) {
	h := newHarness(t)
	h.fetcher.set(claudeDocument, `{"client_id":"`+claudeDocument+`","redirect_uris":["`+claudeCallback+`"],`+
		`"token_endpoint_auth_method":"client_secret_basic"}`)
	_, challenge := newPKCE()
	tc := testClient{id: claudeDocument, redirect: claudeCallback}
	for range 2 {
		w := h.authorize(authorizeParams(tc, "notes", challenge))
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), template.HTMLEscapeString(pageMetadataInvalid.EN))
	}
	assert.Equal(t, 1, h.fetcher.count(claudeDocument), "a refused document is not fetched again for 5 minutes")
	refused := h.logged("oauth: client metadata document refused")
	require.Len(t, refused, 1)
	assert.Contains(t, refused[0].Attrs["error"], `"client_secret_basic"`, "the log names the auth method")
}

func TestCIMDFetchLimit(t *testing.T) {
	h := newHarness(t)
	from := func(addr, docURL string) *httptest.ResponseRecorder {
		_, challenge := newPKCE()
		q := authorizeParams(testClient{id: docURL, redirect: claudeCallback}, "notes", challenge)
		r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		r.RemoteAddr = addr
		return h.doIn(newBrowser(), r)
	}
	for i := range limitFetches {
		w := from("[2001:db8:7:7::1]:1", fmt.Sprintf("https://claude.ai/random/%d", i))
		require.Equal(t, http.StatusBadGateway, w.Code, "fetched, and not there")
	}
	w := from("[2001:db8:7:7::2]:1", "https://claude.ai/random/next") // the same /64
	assertPage(t, w, http.StatusTooManyRequests, pageRateLimited)
	assert.Equal(t, "12", w.Header().Get("Retry-After"), "5 a minute: one every 12 s")
	assert.Zero(t, h.fetcher.count("https://claude.ai/random/next"), "refused before any fetch")

	// Another address group still fetches, and a stored document needs no fetch at all.
	h.cimdClient(claudeDocument, claudeCallback)
	assert.Equal(t, http.StatusFound, from("198.51.100.20:1", claudeDocument).Code)
	h.clock.advance(time.Second)
	assert.Equal(t, http.StatusFound, from("[2001:db8:7:7::3]:1", claudeDocument).Code,
		"the spent group uses the stored copy")
}

func TestCIMDPerConnectorCallbacksWhenRefused(t *testing.T) {
	h := newHarnessWith(t, func(o *Options) { o.RefuseConnectorCallback = true })
	perConnector := "https://chatgpt.com/oauth/cb_42/client.json" // ChatGPT's per-connector document
	h.fetcher.set(perConnector, metadataDoc(perConnector, chatgptConnectors))
	_, challenge := newPKCE()
	w := h.authorize(authorizeParams(testClient{id: perConnector, redirect: chatgptConnectors}, "notes", challenge))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), template.HTMLEscapeString(pageMetadataInvalid.EN))
	assert.Zero(t, h.store.clientCount())

	h.startTxn(h.cimdClient(chatgptDocument, chatgptCallback), "notes") // the shared document is fine
}

func TestCIMDStaleDocumentIsNotUsed(t *testing.T) {
	h := newHarness(t)
	tc := h.cimdClient(claudeDocument, claudeCallback)
	h.startTxn(tc, "notes")
	h.clock.advance(cimdCacheTTL)
	h.fetcher.fail(claudeDocument, errors.New("timeout"))
	_, challenge := newPKCE()
	assert.Equal(t, http.StatusBadGateway, h.authorize(authorizeParams(tc, "notes", challenge)).Code)
}

func TestCIMDClientIDRules(t *testing.T) {
	for _, id := range []string{
		"https://evil.example/oauth/client.json",
		"https://chat.openai.com/oauth/client.json",
		"https://chatgpt.com/",
		"https://chatgpt.com/oauth/client.json?x=1",
		"http://chatgpt.com/oauth/client.json",
	} {
		t.Run(id, func(t *testing.T) {
			h := newHarness(t)
			h.fetcher.set(id, metadataDoc(id, chatgptCallback))
			_, challenge := newPKCE()
			w := h.authorize(authorizeParams(testClient{id: id, redirect: chatgptCallback}, "notes", challenge))
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), template.HTMLEscapeString(pageUnknownClient.EN))
			assert.Zero(t, h.fetcher.count(id), "nothing is fetched")
		})
	}
}

func TestCIMDRedirectMustBeInTheDocument(t *testing.T) {
	h := newHarness(t)
	h.cimdClient(chatgptDocument, chatgptCallback)
	_, challenge := newPKCE()
	w := h.authorize(authorizeParams(testClient{id: chatgptDocument, redirect: chatgptConnectors}, "notes", challenge))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), template.HTMLEscapeString(pageBadRedirect.EN))
}

func TestHTTPFetcher(t *testing.T) {
	exact := strings.Repeat("x", cimdMaxBytes)
	release := make(chan struct{})
	accept := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/doc", func(w http.ResponseWriter, r *http.Request) {
		accept <- r.Header.Get("Accept")
		_, _ = io.WriteString(w, `{"client_id":"x"}`)
	})
	mux.HandleFunc("/exact", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, exact) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, exact+"x") })
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/doc", http.StatusFound) })
	mux.HandleFunc("/missing", http.NotFound)
	mux.HandleFunc("/slow", func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	f := newHTTPFetcher(200*time.Millisecond, cimdMaxBytes)
	f.client.Transport = srv.Client().Transport

	body, err := f.Fetch(t.Context(), srv.URL+"/doc")
	require.NoError(t, err)
	assert.JSONEq(t, `{"client_id":"x"}`, string(body))
	assert.Equal(t, "application/json", <-accept)

	body, err = f.Fetch(t.Context(), srv.URL+"/exact")
	require.NoError(t, err)
	assert.Len(t, body, cimdMaxBytes, "64 KiB is allowed")

	for _, path := range []string{"/big", "/moved", "/missing", "/slow"} {
		_, err := f.Fetch(t.Context(), srv.URL+path)
		assert.Error(t, err, path)
	}
}

func TestFetchFailuresBound(t *testing.T) {
	f := newFetchFailures()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	f.add(claudeDocument, errMetadataFetch, now)
	require.ErrorIs(t, f.get(claudeDocument, now.Add(cimdFailureTTL-time.Second)), errMetadataFetch)
	require.NoError(t, f.get(claudeDocument, now.Add(cimdFailureTTL)), "forgotten after 5 minutes")
	for i := range 3 * maxKeys {
		f.add(fmt.Sprintf("https://claude.ai/doc/%d", i), errMetadataInvalid, now)
	}
	assert.LessOrEqual(t, len(f.items), maxKeys)
}
