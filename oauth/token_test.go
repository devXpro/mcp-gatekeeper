package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

func TestExchangeCode(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authPost)
	code, verifier := h.codeFor(tc, "alice", "notes")
	w := h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	var tk tokens
	decode(t, w, &tk)
	assert.Regexp(t, `^[A-Za-z0-9_-]{43}$`, tk.AccessToken)
	assert.Regexp(t, `^[A-Za-z0-9_-]{43}$`, tk.RefreshToken)
	assert.Equal(t, "Bearer", tk.TokenType)
	assert.Equal(t, int64(3600), tk.ExpiresIn)
	assert.Equal(t, "mcp offline_access", tk.Scope)
	assert.Equal(t, `{"access_token":"`+tk.AccessToken+`","token_type":"Bearer","expires_in":3600,"refresh_token":"`+
		tk.RefreshToken+`","scope":"mcp offline_access"}`, w.Body.String(), "the bytes Family Hub sent")

	access, ok := h.store.token(tk.AccessToken)
	require.True(t, ok, "tokens are stored by their sha256")
	refresh, ok := h.store.token(tk.RefreshToken)
	require.True(t, ok)
	assert.Equal(t, core.TokenAccess, access.Kind)
	assert.Equal(t, core.TokenRefresh, refresh.Kind)
	assert.Equal(t, h.clock.now().Add(time.Hour), access.ExpiresAt)
	assert.Equal(t, h.clock.now().Add(30*24*time.Hour), refresh.ExpiresAt)
	assert.Equal(t, access.Family, refresh.Family)
	assert.Equal(t, access.GrantID, refresh.GrantID)
	assert.Regexp(t, `^fam_`, access.Family)
	assert.True(t, h.valid(tk.AccessToken, "notes"))
	assert.Zero(t, h.store.codeCount(), "the code is spent")
}

func TestExchangeCodeRefusals(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(form url.Values)
		other  bool // the request comes from another client
		status int
		code   string
	}{
		{"a wrong verifier", func(f url.Values) { f.Set("code_verifier", randomToken()) }, false,
			http.StatusBadRequest, "invalid_grant"},
		{"no verifier", func(f url.Values) { f.Del("code_verifier") }, false, http.StatusBadRequest, "invalid_grant"},
		{"a short verifier", func(f url.Values) { f.Set("code_verifier", "short") }, false,
			http.StatusBadRequest, "invalid_grant"},
		{"another redirect_uri", func(f url.Values) { f.Set("redirect_uri", chatgptConnectors) }, false,
			http.StatusBadRequest, "invalid_grant"},
		{"no redirect_uri", func(f url.Values) { f.Del("redirect_uri") }, false, http.StatusBadRequest, "invalid_grant"},
		{"another resource", func(f url.Values) { f.Set("resource", hubURL+"/mcp/photos") }, false,
			http.StatusBadRequest, "invalid_target"},
		{"two resources", func(f url.Values) {
			f["resource"] = []string{hubURL + "/mcp/notes", hubURL + "/mcp/photos"}
		}, false, http.StatusBadRequest, "invalid_target"},
		{"an unknown code", func(f url.Values) { f.Set("code", randomToken()) }, false,
			http.StatusBadRequest, "invalid_grant"},
		{"a malformed code", func(f url.Values) { f.Set("code", "abc") }, false, http.StatusBadRequest, "invalid_grant"},
		{"no code", func(f url.Values) { f.Del("code") }, false, http.StatusBadRequest, "invalid_request"},
		{"a repeated code", func(f url.Values) { f.Add("code", "x") }, false, http.StatusBadRequest, "invalid_request"},
		{"another client's code", func(url.Values) {}, true, http.StatusBadRequest, "invalid_grant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tc := h.registerDCR(chatgptCallback, authPost)
			code, verifier := h.codeFor(tc, "alice", "notes")
			form := exchangeForm(tc, code, verifier)
			tt.edit(form)
			from := tc
			if tt.other {
				from = h.registerDCR(chatgptCallback, authPost)
			}
			w := h.clientPost("/oauth/token", from, form)
			assert.Equal(t, tt.status, w.Code, w.Body.String())
			assert.Equal(t, tt.code, errorOf(t, w))

			w = h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
			assert.Equal(t, http.StatusOK, w.Code, "a refused exchange leaves the code to its own client")
		})
	}
}

func TestExchangeCodeWithItsResource(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	code, verifier := h.codeFor(tc, "alice", "notes")
	form := exchangeForm(tc, code, verifier)
	form.Set("resource", hubURL+"/mcp/notes")
	assert.Equal(t, http.StatusOK, h.clientPost("/oauth/token", tc, form).Code)
}

func TestCodeExpires(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	code, verifier := h.codeFor(tc, "alice", "notes")
	h.clock.advance(5 * time.Minute)
	w := h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_grant", errorOf(t, w))
}

func TestCodeReuseRevokesItsTokens(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	code, verifier := h.codeFor(tc, "alice", "notes")
	first := h.exchange(tc, code, verifier)
	other := h.connect(tc, "alice", "notes") // another sign-in of the same grant

	w := h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_grant", errorOf(t, w))
	assert.Equal(t, `{"error":"invalid_grant","error_description":"the code is unknown, used or expired"}`,
		w.Body.String(), "the bytes Family Hub sent")
	assert.False(t, h.valid(first.AccessToken, "notes"), "the tokens the code got are revoked")
	assert.Equal(t, http.StatusBadRequest, h.refresh(tc, first.RefreshToken).Code)
	assert.True(t, h.valid(other.AccessToken, "notes"), "another sign-in stays")
}

func TestCodeOfARevokedGrant(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	code, verifier := h.codeFor(tc, "alice", "notes")
	require.NoError(t, h.srv.RevokeGrant(t.Context(), h.store.grantList()[0].ID, alice.Person.ID, "192.0.2.9"))
	w := h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_grant", errorOf(t, w))
}

func TestExchangeStoreFailureKeepsTheCode(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	code, verifier := h.codeFor(tc, "alice", "notes")
	h.store.failWith("PutToken", errors.New("disk full"), true)
	w := h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "server_error", errorOf(t, w))
	assert.Equal(t, `{"error":"server_error"}`, w.Body.String(), "no description, as Family Hub sent it")
	assert.Equal(t, http.StatusOK, h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier)).Code,
		"the transaction rolled back, so a retry works")
}

func TestClientAuthentication(t *testing.T) {
	formID := func(tc testClient) url.Values { return url.Values{"client_id": {tc.id}} }
	tests := []struct {
		name      string
		method    string                         // the method the client registered with
		send      func(tc testClient) testClient // how it authenticates this time
		extra     func(tc testClient) url.Values // more form fields
		status    int
		code      string
		challenge bool // the answer carries WWW-Authenticate: Basic
	}{
		{"a public client with client_id", authNone, same, nil, http.StatusOK, "", false},
		{"a public client with Basic and no secret", authNone, viaBasic, nil, http.StatusOK, "", false},
		{"client_secret_post", authPost, same, nil, http.StatusOK, "", false},
		{"client_secret_basic", authBasic, same, nil, http.StatusOK, "", false},
		{"a post client using Basic", authPost, viaBasic, nil, http.StatusOK, "", false},
		{"a basic client using the form", authBasic, viaForm, nil, http.StatusOK, "", false},
		{"no secret", authPost, func(tc testClient) testClient { tc.secret = ""; return tc }, nil,
			http.StatusUnauthorized, "invalid_client", false},
		{"a wrong secret", authPost, func(tc testClient) testClient { tc.secret = randomToken(); return tc }, nil,
			http.StatusUnauthorized, "invalid_client", false},
		{"a wrong Basic secret", authBasic, func(tc testClient) testClient { tc.secret = "nope"; return tc }, nil,
			http.StatusUnauthorized, "invalid_client", true},
		{"no client_id", authNone, func(tc testClient) testClient { tc.id = ""; return tc }, nil,
			http.StatusUnauthorized, "invalid_client", false},
		{"an unknown client_id", authNone, func(tc testClient) testClient { tc.id = "cli_aaaaaaaaaaaaaaaa"; return tc },
			nil, http.StatusUnauthorized, "invalid_client", false},
		{"an unknown Basic client", authBasic, func(tc testClient) testClient { tc.id = "cli_bbbbbbbbbbbbbbbb"; return tc },
			nil, http.StatusUnauthorized, "invalid_client", true},
		{"Basic and a form secret", authBasic, same,
			func(testClient) url.Values { return url.Values{"client_secret": {"x"}} },
			http.StatusBadRequest, "invalid_request", false},
		{"Basic and another form client_id", authBasic, same,
			func(testClient) url.Values { return url.Values{"client_id": {"cli_cccccccccccccccc"}} },
			http.StatusBadRequest, "invalid_request", false},
		{"Basic and the same form client_id", authBasic, same, formID, http.StatusOK, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tc := h.registerDCR(chatgptCallback, tt.method)
			code, verifier := h.codeFor(tc, "alice", "notes")
			form := exchangeForm(tc, code, verifier)
			if tt.extra != nil {
				for k, v := range tt.extra(tc) {
					form[k] = v
				}
			}
			w := h.clientPost("/oauth/token", tt.send(tc), form)
			assert.Equal(t, tt.status, w.Code, w.Body.String())
			if tt.code != "" {
				assert.Equal(t, tt.code, errorOf(t, w))
			}
			if tt.challenge {
				assert.Equal(t, `Basic realm="family-hub"`, w.Header().Get("WWW-Authenticate"),
					"the realm Family Hub sent, from the brand's product")
			} else {
				assert.Empty(t, w.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func same(tc testClient) testClient     { return tc }
func viaBasic(tc testClient) testClient { tc.basic = true; return tc }
func viaForm(tc testClient) testClient  { tc.basic = false; return tc }

func TestClientAuthenticationBadBasicEscape(t *testing.T) {
	h := newHarness(t)
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=authorization_code"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("cli_%zz", "x")
	w := h.do(r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "invalid_client", errorOf(t, w))
}

func TestTokenRequestFormat(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	send := func(contentType, body, query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/oauth/token"+query, strings.NewReader(body))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		return h.do(r)
	}
	form := func(fields string) string { return "client_id=" + tc.id + "&" + fields }
	tests := []struct {
		name, contentType, body, query, code string
	}{
		{"a JSON body", "application/json", `{"grant_type":"authorization_code","client_id":"` + tc.id + `"}`, "",
			"invalid_request"},
		{"no content type", "", form("grant_type=authorization_code"), "", "invalid_request"},
		{"a repeated grant_type", "application/x-www-form-urlencoded",
			form("grant_type=refresh_token&grant_type=refresh_token"), "", "invalid_request"},
		{"no grant_type", "application/x-www-form-urlencoded", form("code=x"), "", "invalid_request"},
		{"the grant_type only in the query", "application/x-www-form-urlencoded", form("code=x"),
			"?grant_type=authorization_code", "invalid_request"},
		{"the password grant", "application/x-www-form-urlencoded", form("grant_type=password"), "",
			"unsupported_grant_type"},
		{"client_credentials", "application/x-www-form-urlencoded; charset=utf-8", form("grant_type=client_credentials"),
			"", "unsupported_grant_type"},
		{"a body over 16 KiB", "application/x-www-form-urlencoded",
			form("grant_type=authorization_code&code=" + strings.Repeat("x", maxFormBody)), "", "invalid_request"},
		{"no refresh_token", "application/x-www-form-urlencoded", form("grant_type=refresh_token"), "",
			"invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := send(tt.contentType, tt.body, tt.query)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, tt.code, errorOf(t, w))
		})
	}
}

func TestTokenRateLimit(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	for i := range limitPerAddress {
		require.Equal(t, http.StatusBadRequest, h.refresh(tc, randomToken()).Code, i)
	}
	w := h.refresh(tc, randomToken())
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "temporarily_unavailable", errorOf(t, w))
	assert.Equal(t, "3", w.Header().Get("Retry-After"))
	assert.Equal(t, `{"error":"temporarily_unavailable","error_description":"too many requests; try again later"}`,
		w.Body.String())
}

func TestRefreshRotates(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authPost)
	first := h.connect(tc, "alice", "notes")
	h.clock.advance(time.Minute)
	w := h.refresh(tc, first.RefreshToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var next tokens
	decode(t, w, &next)
	assert.NotEqual(t, first.AccessToken, next.AccessToken)
	assert.NotEqual(t, first.RefreshToken, next.RefreshToken)
	assert.Equal(t, "mcp offline_access", next.Scope)
	assert.Equal(t, int64(3600), next.ExpiresIn)

	old, _ := h.store.token(first.RefreshToken)
	require.NotNil(t, old.UsedAt, "the old refresh token is spent")
	fresh, _ := h.store.token(next.RefreshToken)
	assert.Equal(t, old.Family, fresh.Family, "the family stays")
	assert.Equal(t, h.clock.now().Add(30*24*time.Hour), fresh.ExpiresAt)
	assert.True(t, h.valid(next.AccessToken, "notes"))
	assert.True(t, h.valid(first.AccessToken, "notes"), "the old access token lives out its hour")
}

func TestRefreshReuseRevokesTheFamily(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(chatgptCallback, authPost)
	first := h.connect(tc, "alice", "notes")
	other := h.connect(tc, "alice", "notes") // another sign-in of the same grant
	w := h.refresh(tc, first.RefreshToken)
	require.Equal(t, http.StatusOK, w.Code)
	var next tokens
	decode(t, w, &next)

	w = h.refresh(tc, first.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_grant", errorOf(t, w))
	assert.False(t, h.valid(next.AccessToken, "notes"), "the whole family is revoked")
	assert.False(t, h.valid(first.AccessToken, "notes"))
	assert.Equal(t, http.StatusBadRequest, h.refresh(tc, next.RefreshToken).Code)
	assert.True(t, h.valid(other.AccessToken, "notes"), "another family stays")

	var reuse []core.AuditEntry
	for _, e := range h.store.auditEntries() {
		if e.Action == "oauth.refresh.reuse" {
			reuse = append(reuse, e)
		}
	}
	require.Len(t, reuse, 1)
	g := h.store.grantList()[0]
	assert.Equal(t, core.AuditEntry{
		ID: reuse[0].ID, At: h.clock.now(), AccountID: millers.ID, Action: "oauth.refresh.reuse", Target: string(g.ID),
		IP: "192.0.2.1", Detail: map[string]string{"module": "notes", "assistant": "chatgpt"},
	}, reuse[0])
	assert.Len(t, h.logged("oauth: a spent refresh token came back; its family is revoked"), 1)
}

func TestRefreshReuseIsHandledWhenTheClientHangsUp(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	tk := h.connect(tc, "alice", "notes")
	w := h.refresh(tc, tk.RefreshToken)
	require.Equal(t, http.StatusOK, w.Code)
	var next tokens
	decode(t, w, &next)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken}, "client_id": {tc.id}}
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.do(r)
	assert.False(t, h.valid(next.AccessToken, "notes"), "the family is revoked though the client is gone")
	assert.Equal(t, 1, h.store.auditActions()["oauth.refresh.reuse"])
}

func TestRefreshRefusals(t *testing.T) {
	type prepare func(t *testing.T, h *harness, tc testClient, tk tokens) (testClient, string)
	tests := []struct {
		name    string
		prepare prepare
		code    string
		alive   bool // the refresh token still works afterwards
	}{
		{"an access token", func(_ *testing.T, _ *harness, tc testClient, tk tokens) (testClient, string) {
			return tc, tk.AccessToken
		}, "invalid_grant", true},
		{"an unknown token", func(_ *testing.T, _ *harness, tc testClient, _ tokens) (testClient, string) {
			return tc, randomToken()
		}, "invalid_grant", true},
		{"a malformed token", func(_ *testing.T, _ *harness, tc testClient, _ tokens) (testClient, string) {
			return tc, "x.y.z"
		}, "invalid_grant", true},
		{"another client's token", func(_ *testing.T, h *harness, _ testClient, tk tokens) (testClient, string) {
			return h.registerDCR(claudeCallback, authNone), tk.RefreshToken
		}, "invalid_grant", true},
		{"an expired token", func(_ *testing.T, h *harness, tc testClient, tk tokens) (testClient, string) {
			h.clock.advance(30 * 24 * time.Hour)
			return tc, tk.RefreshToken
		}, "invalid_grant", false},
		{"a token of a revoked grant", func(t *testing.T, h *harness, tc testClient, tk tokens) (testClient, string) {
			require.NoError(t, h.srv.RevokeGrant(t.Context(), h.store.grantList()[0].ID, alice.Person.ID, ""))
			return tc, tk.RefreshToken
		}, "invalid_grant", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			tc := h.registerDCR(claudeCallback, authNone)
			tk := h.connect(tc, "alice", "notes")
			from, rt := tt.prepare(t, h, tc, tk)
			w := h.refresh(from, rt)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, tt.code, errorOf(t, w))
			assert.Zero(t, h.store.auditActions()["oauth.refresh.reuse"], "a dead token is no reuse")
			want := http.StatusBadRequest
			if tt.alive {
				want = http.StatusOK
			}
			assert.Equal(t, want, h.refresh(tc, tk.RefreshToken).Code)
		})
	}
}

func TestRefreshResource(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	tk := h.connect(tc, "alice", "notes")
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken},
		"resource": {hubURL + "/mcp/photos"}}
	w := h.clientPost("/oauth/token", tc, form)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_target", errorOf(t, w))

	form.Set("resource", hubURL+"/mcp/notes")
	assert.Equal(t, http.StatusOK, h.clientPost("/oauth/token", tc, form).Code,
		"the refused try did not spend the token")
}

func TestRefreshStoreFailureKeepsTheToken(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	tk := h.connect(tc, "alice", "notes")
	h.store.failWith("PutToken", errors.New("disk full"), true)
	w := h.refresh(tc, tk.RefreshToken)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "server_error", errorOf(t, w))
	assert.Equal(t, http.StatusOK, h.refresh(tc, tk.RefreshToken).Code, "a retry after a store failure is no reuse")
	assert.Zero(t, h.store.auditActions()["oauth.refresh.reuse"])
}

func TestRefreshRace(t *testing.T) {
	h := newHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	tk := h.connect(tc, "alice", "notes")
	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { codes[i] = h.refresh(tc, tk.RefreshToken).Code })
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	assert.Equal(t, 1, ok, "of concurrent refreshes one wins")
	assert.Equal(t, n-1, h.store.auditActions()["oauth.refresh.reuse"], "the others are reuse")
}
