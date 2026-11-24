package oauth

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestRegister(t *testing.T) {
	tenClaude := `"` + strings.Repeat(claudeCallback+`","`, 10) + claudeCallback + `"`
	tests := []struct {
		name       string
		body       string
		status     int
		code       string // the OAuth error, "" on success
		method     string
		assistant  core.Assistant
		clientName string
	}{
		{"public claude", `{"redirect_uris":["` + claudeCallback + `"],"token_endpoint_auth_method":"none",` +
			`"client_name":"Claude"}`, http.StatusCreated, "", authNone, core.AssistantClaude, "Claude"},
		{"the method defaults to none", `{"redirect_uris":["` + claudeCallback + `"]}`,
			http.StatusCreated, "", authNone, core.AssistantClaude, "Claude"},
		{"chatgpt with client_secret_post", `{"redirect_uris":["` + chatgptCallback + `"],` +
			`"token_endpoint_auth_method":"client_secret_post","client_name":"ChatGPT"}`,
			http.StatusCreated, "", authPost, core.AssistantChatGPT, "ChatGPT"},
		{"client_secret_basic", `{"redirect_uris":["` + chatgptConnectors + `"],` +
			`"token_endpoint_auth_method":"client_secret_basic"}`,
			http.StatusCreated, "", authBasic, core.AssistantChatGPT, "ChatGPT"},
		{"the name is cleaned", `{"redirect_uris":["` + claudeCallback + `"],"client_name":"` + bidiOverride + `Your bank"}`,
			http.StatusCreated, "", authNone, core.AssistantClaude, "Your bank"},
		{"unknown fields are ignored", `{"redirect_uris":["` + claudeCallback + `"],"grant_types":["client_credentials"],` +
			`"logo_uri":"https://evil.example/x.png"}`, http.StatusCreated, "", authNone, core.AssistantClaude, "Claude"},

		{"a foreign callback", `{"redirect_uris":["https://evil.example/cb"]}`,
			http.StatusBadRequest, "invalid_redirect_uri", "", "", ""},
		{"callbacks of two assistants", `{"redirect_uris":["` + claudeCallback + `","` + chatgptCallback + `"]}`,
			http.StatusBadRequest, "invalid_redirect_uri", "", "", ""},
		{"no redirect_uris", `{}`, http.StatusBadRequest, "invalid_redirect_uri", "", "", ""},
		{"null", `null`, http.StatusBadRequest, "invalid_redirect_uri", "", "", ""},
		{"eleven callbacks", `{"redirect_uris":[` + tenClaude + `]}`,
			http.StatusBadRequest, "invalid_redirect_uri", "", "", ""},
		{"a redirect URI that is no string", `{"redirect_uris":[1]}`,
			http.StatusBadRequest, "invalid_client_metadata", "", "", ""},
		{"not JSON", `redirect_uris=x`, http.StatusBadRequest, "invalid_client_metadata", "", "", ""},
		{"a JSON array", `[]`, http.StatusBadRequest, "invalid_client_metadata", "", "", ""},
		{"an unsupported auth method", `{"redirect_uris":["` + claudeCallback + `"],` +
			`"token_endpoint_auth_method":"private_key_jwt"}`,
			http.StatusBadRequest, "invalid_client_metadata", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", "application/json")
			w := h.do(r)
			require.Equal(t, tt.status, w.Code, w.Body.String())
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			if tt.code != "" {
				assert.Equal(t, tt.code, errorOf(t, w))
				assert.Zero(t, h.store.clientCount())
				return
			}
			var resp map[string]any
			decode(t, w, &resp)
			id, _ := resp["client_id"].(string)
			assert.Regexp(t, `^cli_[a-z2-7]{16}$`, id)
			assert.InDelta(t, h.clock.now().Unix(), resp["client_id_issued_at"], 0)
			assert.Equal(t, tt.method, resp["token_endpoint_auth_method"])
			assert.Equal(t, tt.clientName, resp["client_name"])
			assert.Equal(t, []any{"authorization_code", "refresh_token"}, resp["grant_types"])
			assert.Equal(t, []any{"code"}, resp["response_types"])
			assert.Equal(t, "mcp offline_access", resp["scope"])

			c, ok := h.store.client(id)
			require.True(t, ok)
			assert.Equal(t, core.ClientDCR, c.Kind)
			assert.Equal(t, tt.assistant, c.Assistant)
			assert.Equal(t, tt.method, c.AuthMethod)
			assert.Equal(t, tt.clientName, c.Name)
			assert.Equal(t, h.clock.now(), c.CreatedAt)
			secret, hasSecret := resp["client_secret"].(string)
			if tt.method == authNone {
				assert.False(t, hasSecret)
				assert.NotContains(t, resp, "client_secret_expires_at")
				assert.Nil(t, c.SecretHash)
				return
			}
			assert.Regexp(t, `^[A-Za-z0-9_-]{43}$`, secret)
			assert.InDelta(t, 0, resp["client_secret_expires_at"], 0)
			assert.Equal(t, hashOf(secret), c.SecretHash, "the secret is stored only as its sha256")
		})
	}
}

// TestRegisterBytes pins the registration answer to the bytes Family Hub sent.
func TestRegisterBytes(t *testing.T) {
	h := newHarness(t)
	w := h.registerJSON(map[string]any{"redirect_uris": []string{claudeCallback}})
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		ClientID string `json:"client_id"`
	}
	decode(t, w, &resp)
	assert.Equal(t, `{"client_id":"`+resp.ClientID+`","client_id_issued_at":`+fmt.Sprint(h.clock.now().Unix())+
		`,"client_name":"Claude",`+
		`"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"none",`+
		`"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":"mcp offline_access"}`,
		w.Body.String())

	w = h.registerJSON(map[string]any{"redirect_uris": []string{"https://evil.example/cb"}})
	assert.Equal(t, `{"error":"invalid_redirect_uri",`+
		`"error_description":"only ChatGPT's or Claude's callbacks are accepted, 1 to 10 of one assistant"}`,
		w.Body.String())
}

func TestRegisterAudits(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	entries := h.store.auditEntries()
	require.Len(t, entries, 1)
	assert.Equal(t, core.AuditEntry{
		ID: entries[0].ID, At: h.clock.now(), Action: "oauth.client.register", Target: tc.id, IP: "192.0.2.1",
		Detail: map[string]string{"kind": "dcr", "assistant": "claude", "auth_method": "none"},
	}, entries[0])
}

func TestRegisterDeletesIdleClients(t *testing.T) {
	h := newHarness(t)
	idle := h.registerDCR(claudeCallback, authNone)
	used := h.registerDCR(claudeCallback, authNone)
	h.connect(used, "alice", "notes")
	h.clock.advance(59 * time.Minute)
	young := h.registerDCR(claudeCallback, authNone)
	_, ok := h.store.client(idle.id)
	assert.True(t, ok, "an hour has not passed yet")

	h.clock.advance(2 * time.Minute)
	fresh := h.registerDCR(claudeCallback, authNone)
	for id, want := range map[string]bool{idle.id: false, used.id: true, young.id: true, fresh.id: true} {
		_, ok := h.store.client(id)
		assert.Equal(t, want, ok, id)
	}
}

func TestRegisterAuditsOncePerAddressAMinute(t *testing.T) {
	h := newHarness(t)
	register := func(addr string) string {
		r := httptest.NewRequest(http.MethodPost, "/oauth/register",
			strings.NewReader(`{"redirect_uris":["`+claudeCallback+`"]}`))
		r.RemoteAddr = addr
		w := h.do(r)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		var resp struct {
			ClientID string `json:"client_id"`
		}
		decode(t, w, &resp)
		return resp.ClientID
	}
	first := register("[2001:db8:1:2::1]:443")
	register("[2001:db8:1:2::2]:443") // the same /64 within the minute: stored, logged, not audited
	other := register("198.51.100.4:443")
	h.clock.advance(time.Minute)
	later := register("[2001:db8:1:2::3]:443")

	var targets []string
	for _, e := range h.store.auditEntries() {
		require.Equal(t, "oauth.client.register", e.Action)
		targets = append(targets, e.Target)
	}
	assert.Equal(t, []string{first, other, later}, targets)
	assert.Equal(t, 4, h.store.clientCount(), "every client is stored")
	assert.Len(t, h.logged("oauth: client registered"), 4, "and logged")
}

func TestRegisterPerConnectorCallbacks(t *testing.T) {
	body := `{"redirect_uris":["` + chatgptConnectors + `"]}`
	for _, tt := range []struct {
		refuse bool
		status int
	}{{false, http.StatusCreated}, {true, http.StatusBadRequest}} {
		t.Run(fmt.Sprintf("RefuseConnectorCallback=%v", tt.refuse), func(t *testing.T) {
			h := newHarnessWith(t, func(o *Options) { o.RefuseConnectorCallback = tt.refuse })
			r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
			w := h.do(r)
			assert.Equal(t, tt.status, w.Code, w.Body.String())
			if tt.status != http.StatusCreated {
				assert.Equal(t, "invalid_redirect_uri", errorOf(t, w))
			}
			h.registerDCR(chatgptCallback, authNone) // ChatGPT's callback for servers with iss stays
		})
	}
}

func TestRegisterTooLarge(t *testing.T) {
	h := newHarness(t)
	body := `{"redirect_uris":["` + claudeCallback + `"],"client_name":"` + strings.Repeat("x", maxRegisterBody) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader([]byte(body)))
	w := h.do(r)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Equal(t, "invalid_client_metadata", errorOf(t, w))
}

func TestRegisterStoreFailure(t *testing.T) {
	h := newHarness(t)
	h.store.failWith("PutClient", fmt.Errorf("disk full"), true)
	w := h.registerJSON(map[string]any{"redirect_uris": []string{claudeCallback}})
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "server_error", errorOf(t, w))
	assert.Empty(t, h.store.auditEntries())
}

func TestRegisterRateLimit(t *testing.T) {
	h := newHarness(t)
	register := func(addr string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/oauth/register",
			strings.NewReader(`{"redirect_uris":["`+claudeCallback+`"]}`))
		r.RemoteAddr = addr + ":5555"
		return h.do(r)
	}
	for i := range limitPerAddress {
		require.Equal(t, http.StatusCreated, register("198.51.100.1").Code, i)
	}
	w := register("198.51.100.1")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "temporarily_unavailable", errorOf(t, w))
	assert.Equal(t, "3", w.Header().Get("Retry-After"), "20 a minute: one every 3 s")

	// Every address together gets 60 a minute: registration keeps a shared bucket, which bounds how fast the client
	// store grows (token and revoke have none).
	for i := range 2 * limitPerAddress {
		require.Equal(t, http.StatusCreated, register(fmt.Sprintf("198.51.100.%d", 2+i/limitPerAddress)).Code, i)
	}
	assert.Equal(t, http.StatusTooManyRequests, register("198.51.100.9").Code, "the total is spent")

	h.clock.advance(time.Minute)
	assert.Equal(t, http.StatusCreated, register("198.51.100.1").Code)

	// The addresses of one IPv6 /64 share a bucket.
	h.clock.advance(time.Minute)
	for i := range limitPerAddress {
		require.Equal(t, http.StatusCreated, register(fmt.Sprintf("[2001:db8:5:6::%x]", i+1)).Code, i)
	}
	assert.Equal(t, http.StatusTooManyRequests, register("[2001:db8:5:6::ffff]").Code)
	assert.Equal(t, http.StatusCreated, register("[2001:db8:5:7::1]").Code, "the next /64 has its own")
}
