package mcpguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

const helloPRM = `resource_metadata="https://hub.example.com/.well-known/oauth-protected-resource/mcp/hello", scope="mcp"`

func TestNewChecksItsOptions(t *testing.T) {
	ok := func() Options {
		return Options{
			Site: core.Site{PublicURL: hubURL}, Paths: core.PerResource{Prefix: "/mcp/"}, Tokens: &fakeTokens{},
			People: &fakePeople{}, Resources: &fakeResources{},
		}
	}
	g, err := New(ok())
	require.NoError(t, err)
	assert.Equal(t, defaultPingInterval, g.ping)
	assert.NotNil(t, g.log)
	assert.NotNil(t, g.now)

	for name, change := range map[string]func(*Options){
		"no public URL":       func(o *Options) { o.Site.PublicURL = "" },
		"no paths":            func(o *Options) { o.Paths = nil },
		"no tokens":           func(o *Options) { o.Tokens = nil },
		"no people":           func(o *Options) { o.People = nil },
		"no resources":        func(o *Options) { o.Resources = nil },
		"a negative interval": func(o *Options) { o.PingInterval = -1 },
	} {
		o := ok()
		change(&o)
		_, err := New(o)
		assert.Error(t, err, name)
	}
}

func TestGuardLetsAValidCallThroughWithItsCaller(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	tests := []struct {
		method, path, auth string
		person             core.PersonID
		assistant          core.Assistant
	}{
		{http.MethodPost, "/mcp/hello", "Bearer tok-alice", "per_alice", core.AssistantChatGPT},
		{http.MethodPost, "/mcp/hello/messages/a-1", "bearer tok-alice", "per_alice", core.AssistantChatGPT},
		{http.MethodGet, "/mcp/hello/", "BEARER tok-bella", "per_bella", core.AssistantClaude},
		{http.MethodDelete, "/mcp/hello?x=1", "Bearer  tok-bella ", "per_bella", core.AssistantClaude},
	}
	for i, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			a := h.do(t, h.request(t, tt.method, tt.path, tt.auth, strings.NewReader(`{}`)))
			require.Equal(t, http.StatusOK, a.status, "body %s", a.body)
			assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			assert.Equal(t, guardCSP, a.header.Get("Content-Security-Policy"))
			assert.Equal(t, "nosniff", a.header.Get("X-Content-Type-Options"))
			got := h.passed()
			require.Len(t, got, i+1)
			c := got[i]
			assert.Equal(t, core.ResourceID("hello"), c.access.ResourceID)
			assert.Equal(t, tt.person, c.access.PersonID)
			assert.Equal(t, core.AccountID("acc_a"), c.access.AccountID)
			assert.Equal(t, tt.assistant, c.access.Assistant)
			assert.Equal(t, core.GrantID("grt_"+tt.person), c.access.GrantID)
			assert.Equal(t, tt.person, c.person.ID)
			assert.Equal(t, core.AccountID("acc_a"), c.person.AccountID)
		})
	}
}

func TestGuardRefusals(t *testing.T) {
	tests := []struct {
		name, method, path, auth string
		status                   int
		code                     string
		wwwAuth                  string
	}{
		{"no token", http.MethodPost, "/mcp/hello", "", 401, httpsec.CodeUnauthorized, "Bearer " + helloPRM},
		{"another scheme", http.MethodPost, "/mcp/hello", "Basic dXNlcjpwYXNz", 401, httpsec.CodeUnauthorized,
			"Bearer " + helloPRM},
		{"an empty bearer", http.MethodGet, "/mcp/hello", "Bearer ", 401, httpsec.CodeUnauthorized, "Bearer " + helloPRM},
		{"a bearer with spaces", http.MethodGet, "/mcp/hello", "Bearer tok alice", 401, httpsec.CodeUnauthorized,
			"Bearer " + helloPRM},
		{"a bearer with a tab", http.MethodGet, "/mcp/hello", "Bearer tok\talice", 401, httpsec.CodeUnauthorized,
			"Bearer " + helloPRM},
		{"an unknown token", http.MethodPost, "/mcp/hello", "Bearer tok-nope", 401, httpsec.CodeInvalidToken,
			`Bearer error="invalid_token", ` + helloPRM},
		{"a token of another resource", http.MethodPost, "/mcp/hello", "Bearer tok-other", 401,
			httpsec.CodeInvalidToken, `Bearer error="invalid_token", ` + helloPRM},
		{"a disabled person", http.MethodPost, "/mcp/hello", "Bearer tok-off", 401, httpsec.CodeInvalidToken,
			`Bearer error="invalid_token", ` + helloPRM},
		{"a person who is gone", http.MethodPost, "/mcp/hello", "Bearer tok-ghost", 401, httpsec.CodeInvalidToken,
			`Bearer error="invalid_token", ` + helloPRM},
		{"a person of another account", http.MethodPost, "/mcp/hello", "Bearer tok-moved", 401,
			httpsec.CodeInvalidToken, `Bearer error="invalid_token", ` + helloPRM},
		{"the resource is off for the account", http.MethodPost, "/mcp/hello", "Bearer tok-bob", 403,
			httpsec.CodeForbidden, ""},
		{"a path outside the resources", http.MethodPost, "/api/hello", "Bearer tok-alice", 404, httpsec.CodeNotFound,
			""},
		{"the bare prefix", http.MethodPost, "/mcp/", "Bearer tok-alice", 404, httpsec.CodeNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{})
			a := h.do(t, h.request(t, tt.method, tt.path, tt.auth, strings.NewReader(`{}`)))
			require.Equal(t, tt.status, a.status, "body %s", a.body)
			assert.Equal(t, tt.code, a.errorCode(t))
			assert.Equal(t, tt.wwwAuth, a.header.Get("WWW-Authenticate"))
			assert.Equal(t, guardCSP, a.header.Get("Content-Security-Policy"))
			assert.Equal(t, "nosniff", a.header.Get("X-Content-Type-Options"))
			assert.Equal(t, []string{"no-store"}, a.header.Values("Cache-Control"))
			assert.Empty(t, h.passed(), "nothing reaches the application's handler")
			assert.Empty(t, h.upstream.requests())
			h.requireNoSecrets(t, "tok-alice", "tok-other", "tok-nope", "dXNlcjpwYXNz")
		})
	}
}

// TestGuardAnswersAsFamilyHubDoes pins the exact answers assistants see today: the header, the status and the JSON
// error form, byte for byte (httpsec.WriteError writes json.Marshal's bytes, as Gin did).
func TestGuardAnswersAsFamilyHubDoes(t *testing.T) {
	tests := []struct {
		name, auth string
		status     int
		wwwAuth    string
		body       string
	}{
		{"no token", "", 401, `Bearer ` + helloPRM,
			`{"error":"unauthorized","message":"a bearer access token is required"}`},
		{"an invalid token", "Bearer tok-nope", 401, `Bearer error="invalid_token", ` + helloPRM,
			`{"error":"invalid_token","message":"the access token is invalid, expired or for another module"}`},
		{"the switch is off", "Bearer tok-bob", 403, "",
			`{"error":"forbidden","message":"the module is not on for this account"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{})
			a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", tt.auth, strings.NewReader(`{}`)))
			require.Equal(t, tt.status, a.status)
			assert.Equal(t, tt.wwwAuth, a.header.Get("WWW-Authenticate"))
			assert.Equal(t, "application/json; charset=utf-8", a.header.Get("Content-Type"))
			assert.Equal(t, tt.body, string(a.body))
		})
	}
}

func TestGuardChecksTheTokensResourceItself(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.tokens.set(func(f *fakeTokens) { f.lenient = true }) // a validator that forgets the resource
	a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-other", strings.NewReader(`{}`)))
	require.Equal(t, http.StatusUnauthorized, a.status)
	assert.Equal(t, httpsec.CodeInvalidToken, a.errorCode(t))
	assert.Empty(t, h.passed())
}

func TestGuardRefusesEveryKindOfDeadToken(t *testing.T) {
	for _, err := range []error{core.ErrInvalidToken, core.ErrNotFound, core.ErrExpired, core.ErrUsed} {
		h := newHarness(t, harnessOptions{})
		h.tokens.set(func(f *fakeTokens) { f.err = errors.Join(errors.New("store"), err) })
		a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", strings.NewReader(`{}`)))
		require.Equal(t, http.StatusUnauthorized, a.status, "%v", err)
		assert.Equal(t, httpsec.CodeInvalidToken, a.errorCode(t))
		assert.Empty(t, h.logs.Records(), "a refusal is no failure of the application")
	}
}

func TestGuardFailuresOfTheApplicationsServices(t *testing.T) {
	boom := errors.New("mongo is down")
	tests := []struct {
		name string
		fail func(h *harness)
	}{
		{"the token check", func(h *harness) { h.tokens.set(func(f *fakeTokens) { f.err = boom }) }},
		{"the people", func(h *harness) { h.people.fail(boom) }},
		{"the resource switch", func(h *harness) { h.resources.fail(boom) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{})
			tt.fail(h)
			a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", strings.NewReader(`{}`)))
			require.Equal(t, http.StatusInternalServerError, a.status)
			assert.Equal(t, httpsec.CodeInternal, a.errorCode(t))
			assert.NotContains(t, string(a.body), "mongo", "no detail in the answer")
			assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			assert.Empty(t, h.passed())
			recs := h.logs.Records()
			require.Len(t, recs, 1, "the cause is logged once")
			assert.True(t, strings.HasPrefix(recs[0].Message, "mcpguard: "), recs[0].Message)
			assert.Equal(t, "hello", recs[0].Attrs["resource"])
			assert.Contains(t, recs[0].Attrs["err"], "mongo is down")
			h.requireNoSecrets(t, "tok-alice")
		})
	}
}

// TestGuardOnASingleResource is Homie's shape: one resource at one path.
func TestGuardOnASingleResource(t *testing.T) {
	h := newHarness(t, harnessOptions{paths: core.SingleResource{At: "/mcp", ID: "home"}})
	for _, path := range []string{"/mcp", "/mcp/", "/mcp/messages"} {
		a := h.do(t, h.request(t, http.MethodPost, path, "Bearer tok-home", strings.NewReader(`{}`)))
		require.Equal(t, http.StatusOK, a.status, "%s: %s", path, a.body)
	}
	for _, c := range h.passed() {
		assert.Equal(t, core.ResourceID("home"), c.access.ResourceID)
	}

	const prm = `resource_metadata="https://hub.example.com/.well-known/oauth-protected-resource/mcp", scope="mcp"`
	a := h.do(t, h.request(t, http.MethodPost, "/mcp", "", nil))
	require.Equal(t, http.StatusUnauthorized, a.status)
	assert.Equal(t, "Bearer "+prm, a.header.Get("WWW-Authenticate"))
	a = h.do(t, h.request(t, http.MethodPost, "/mcp", "Bearer tok-alice", nil)) // a token of another resource
	require.Equal(t, http.StatusUnauthorized, a.status)
	assert.Equal(t, `Bearer error="invalid_token", `+prm, a.header.Get("WWW-Authenticate"))

	for _, path := range []string{"/mcpx", "/", "/mc"} {
		a = h.do(t, h.request(t, http.MethodPost, path, "Bearer tok-home", nil))
		assert.Equal(t, http.StatusNotFound, a.status, path)
	}
}

// TestGuardEscapesTheResourceInTheHeader: the resource of a path is whatever the caller put there, and it must not
// end the quoted resource_metadata value.
func TestGuardEscapesTheResourceInTheHeader(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	a := h.do(t, h.request(t, http.MethodGet, `/mcp/a%22,%20scope=%22admin`, "", nil))
	require.Equal(t, http.StatusUnauthorized, a.status)
	assert.Equal(t, `Bearer resource_metadata="https://hub.example.com/.well-known/oauth-protected-resource/mcp/`+
		`a%22%2C%20scope=%22admin", scope="mcp"`, a.header.Get("WWW-Authenticate"))
}

func TestTheContextAccessors(t *testing.T) {
	_, ok := AccessFrom(context.Background())
	assert.False(t, ok)
	_, ok = PersonFrom(context.Background())
	assert.False(t, ok)

	// The middleware run on its own, without a server.
	h := newHarness(t, harnessOptions{})
	var got core.AccessInfo
	var who core.Person
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = AccessFrom(r.Context())
		who, _ = PersonFrom(r.Context())
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp/hello", nil)
	req.Header.Set("Authorization", "Bearer tok-alice")
	rec := httptest.NewRecorder()
	h.guard.Middleware(next).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, core.PersonID("per_alice"), got.PersonID)
	assert.Equal(t, "Alice", who.Name)
}
