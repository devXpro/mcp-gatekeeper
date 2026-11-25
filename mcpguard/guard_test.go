package mcpguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

const helloPRM = `resource_metadata="https://hub.example.com/.well-known/oauth-protected-resource/mcp/hello", scope="mcp"`

func TestNewChecksItsOptions(t *testing.T) {
	ok := func() Options {
		return Options{
			Site:  core.Site{PublicURL: hubURL, ClientIP: core.ClientIPCloudflare},
			Paths: core.PerResource{Prefix: "/mcp/"}, Tokens: &fakeTokens{}, People: &fakePeople{},
			Resources: &fakeResources{},
		}
	}
	g, err := New(ok())
	require.NoError(t, err)
	assert.Equal(t, defaultPingInterval, g.ping)
	assert.Equal(t, "module", g.noun)
	assert.Equal(t, inFlightPerResource, g.inFlight.limit)
	assert.False(t, g.perPerson)
	assert.InDelta(t, float64(failuresPerAddress), g.failures.rate, 0)
	assert.NotNil(t, g.log)
	assert.NotNil(t, g.now)

	o := ok()
	o.Brand, o.InFlightPerResource, o.InFlightKey, o.FailuresPerAddress = core.Brand{ResourceNoun: "home"}, 8, PerPerson, 5
	g, err = New(o)
	require.NoError(t, err)
	assert.Equal(t, "home", g.noun)
	assert.Equal(t, 8, g.inFlight.limit)
	assert.True(t, g.perPerson)
	assert.InDelta(t, 5.0, g.failures.rate, 0)

	for name, change := range map[string]func(*Options){
		"no public URL":             func(o *Options) { o.Site.PublicURL = "" },
		"a public URL over http":    func(o *Options) { o.Site.PublicURL = "http://hub.example.com" },
		"no client address mode":    func(o *Options) { o.Site.ClientIP = "" },
		"an unknown mode":           func(o *Options) { o.Site.ClientIP = "cloudflare" },
		"no paths":                  func(o *Options) { o.Paths = nil },
		"no tokens":                 func(o *Options) { o.Tokens = nil },
		"no people":                 func(o *Options) { o.People = nil },
		"no resources":              func(o *Options) { o.Resources = nil },
		"a negative interval":       func(o *Options) { o.PingInterval = -1 },
		"a negative in-flight cap":  func(o *Options) { o.InFlightPerResource = -1 },
		"a negative failure budget": func(o *Options) { o.FailuresPerAddress = -1 },
		"an unknown in-flight key":  func(o *Options) { o.InFlightKey = PerPerson + 1 },
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
		{"a guest past their term", http.MethodPost, "/mcp/hello", "Bearer tok-erin", 401,
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

// TestGuardAnswersAsFamilyHubDoes pins the exact answers assistants see today, with the default options: the header,
// the status and the JSON error form, byte for byte (httpsec.WriteError writes json.Marshal's bytes, as Gin did). A
// person past their term gets the bytes of a disabled one.
func TestGuardAnswersAsFamilyHubDoes(t *testing.T) {
	const invalid = `{"error":"invalid_token","message":"the access token is invalid, expired or for another module"}`
	tests := []struct {
		name, path, auth string
		status           int
		wwwAuth          string
		body             string
	}{
		{"no token", "/mcp/hello", "", 401, `Bearer ` + helloPRM,
			`{"error":"unauthorized","message":"a bearer access token is required"}`},
		{"an invalid token", "/mcp/hello", "Bearer tok-nope", 401, `Bearer error="invalid_token", ` + helloPRM, invalid},
		{"a disabled person", "/mcp/hello", "Bearer tok-off", 401, `Bearer error="invalid_token", ` + helloPRM, invalid},
		{"a guest past their term", "/mcp/hello", "Bearer tok-erin", 401, `Bearer error="invalid_token", ` + helloPRM,
			invalid},
		{"the switch is off", "/mcp/hello", "Bearer tok-bob", 403, "",
			`{"error":"forbidden","message":"the module is not on for this account"}`},
		{"no such resource", "/api/hello", "Bearer tok-alice", 404, "",
			`{"error":"not_found","message":"no such resource"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{})
			a := h.do(t, h.request(t, http.MethodPost, tt.path, tt.auth, strings.NewReader(`{}`)))
			require.Equal(t, tt.status, a.status)
			assert.Equal(t, tt.wwwAuth, a.header.Get("WWW-Authenticate"))
			assert.Equal(t, "application/json; charset=utf-8", a.header.Get("Content-Type"))
			assert.Equal(t, tt.body, string(a.body))
		})
	}
}

// TestGuardSpeaksTheApplicationsWords: the brand's noun replaces "module" in the answers people and assistants read
// (review GK-18); the codes and the header stay.
func TestGuardSpeaksTheApplicationsWords(t *testing.T) {
	h := newHarness(t, harnessOptions{brand: core.Brand{ResourceNoun: "home", AppNoun: "Homie"}, inFlight: 1})
	a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-nope", nil))
	require.Equal(t, http.StatusUnauthorized, a.status)
	assert.Equal(t, `Bearer error="invalid_token", `+helloPRM, a.header.Get("WWW-Authenticate"))
	assert.Equal(t, `{"error":"invalid_token","message":"the access token is invalid, expired or for another home"}`,
		string(a.body))
	a = h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-bob", nil))
	assert.Equal(t, `{"error":"forbidden","message":"the home is not on for this account"}`, string(a.body))

	release, ok := h.guard.Admit(httptest.NewRecorder(), "acc_a", "hello")
	require.True(t, ok)
	defer release()
	rec := httptest.NewRecorder()
	_, ok = h.guard.Admit(rec, "acc_a", "hello")
	require.False(t, ok)
	assert.Equal(t, `{"error":"rate_limited","message":"too many calls to this home at once; try again shortly"}`,
		rec.Body.String())
}

// TestGuardEndsAGuestsAccessAtTheirTerm: a guest's token works until the end of their term, and from that instant
// gets the 401 of a disabled person (review GK-13, plan §4.4).
func TestGuardEndsAGuestsAccessAtTheirTerm(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-carol", strings.NewReader(`{}`)))
	require.Equal(t, http.StatusOK, a.status, "body %s", a.body)
	got := h.passed()
	require.Len(t, got, 1)
	assert.Equal(t, []string{"plugin:tv"}, got[0].person.Permissions, "the application reads the permissions")
	require.NotNil(t, got[0].person.AccessUntil)

	h.clock.Set(start.Add(time.Hour - time.Nanosecond))
	a = h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-carol", strings.NewReader(`{}`)))
	require.Equal(t, http.StatusOK, a.status, "the last instant of the term")

	h.clock.Set(start.Add(time.Hour))
	a = h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-carol", strings.NewReader(`{}`)))
	require.Equal(t, http.StatusUnauthorized, a.status)
	assert.Equal(t, `Bearer error="invalid_token", `+helloPRM, a.header.Get("WWW-Authenticate"))
	assert.Equal(t, `{"error":"invalid_token","message":"the access token is invalid, expired or for another module"}`,
		string(a.body))
	assert.Len(t, h.passed(), 2, "nothing more reached the application")
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

// cleaningRouter is an application's router that routes /mcp/<id> on the cleaned path, as routers that remove dot
// segments and repeated slashes do, and hands the request on as it came. routed records the resource it chose.
func cleaningRouter(serve func(id core.ResourceID) http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := core.PerResource{Prefix: "/mcp/"}.FromPath(path.Clean(r.URL.Path))
		if !ok {
			httpsec.NotFound(w, r)
			return
		}
		serve(id).ServeHTTP(w, r)
	})
}

// TestMiddlewareForKeepsATokenToItsResource is the probe of review GK-1: behind a router that cleans paths,
// Middleware lets a token for one resource reach another, and MiddlewareFor does not.
func TestMiddlewareForKeepsATokenToItsResource(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	type reached struct{ routed, access core.ResourceID }
	var got []reached
	handler := func(id core.ResourceID) http.Handler {
		return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			info, _ := AccessFrom(r.Context())
			got = append(got, reached{routed: id, access: info.ResourceID})
		})
	}
	send := func(app http.Handler, target, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(`{}`))
		req.Header.Set("Authorization", auth)
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		return rec
	}
	const smuggled = "/mcp/other/../hello" // the guard reads "other", the router cleans it to "hello"

	t.Run("Middleware behind a cleaning router: the documented hole", func(t *testing.T) {
		got = nil
		app := cleaningRouter(func(id core.ResourceID) http.Handler { return h.guard.Middleware(handler(id)) })
		rec := send(app, smuggled, "Bearer tok-other")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, []reached{{routed: "hello", access: "other"}}, got,
			"the application must compare AccessFrom(ctx).ResourceID with its route")
	})
	t.Run("MiddlewareFor behind the same router", func(t *testing.T) {
		got = nil
		app := cleaningRouter(func(id core.ResourceID) http.Handler { return h.guard.MiddlewareFor(id)(handler(id)) })
		for _, tok := range []string{"Bearer tok-other", "Bearer tok-alice"} {
			rec := send(app, smuggled, tok)
			require.Equal(t, http.StatusNotFound, rec.Code, tok)
			assert.JSONEq(t, `{"error":"not_found","message":"no such resource"}`, rec.Body.String())
			assert.Equal(t, guardCSP, rec.Header().Get("Content-Security-Policy"))
		}
		assert.Empty(t, got, "nothing reaches a resource through a path that names another")

		rec := send(app, "/mcp/hello/messages", "Bearer tok-alice")
		require.Equal(t, http.StatusOK, rec.Code)
		rec = send(app, "/mcp/hello", "Bearer tok-other")
		require.Equal(t, http.StatusUnauthorized, rec.Code, "the token must be for the stated resource")
		assert.Equal(t, `Bearer error="invalid_token", `+helloPRM, rec.Header().Get("WWW-Authenticate"))
		assert.Equal(t, []reached{{routed: "hello", access: "hello"}}, got)
	})
}

// TestMiddlewareForOnASingleResource is Homie's mount: exactly /mcp, MiddlewareFor("home").
func TestMiddlewareForOnASingleResource(t *testing.T) {
	h := newHarness(t, harnessOptions{paths: core.SingleResource{At: "/mcp", ID: "home"}})
	var who []core.Person
	app := h.guard.MiddlewareFor("home")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		p, ok := PersonFrom(r.Context())
		require.True(t, ok)
		who = append(who, p)
	}))
	send := func(target, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		return rec
	}
	require.Equal(t, http.StatusOK, send("/mcp", "Bearer tok-home").Code)
	require.Len(t, who, 1)
	assert.Equal(t, core.PersonID("per_alice"), who[0].ID)

	const prm = `resource_metadata="https://hub.example.com/.well-known/oauth-protected-resource/mcp", scope="mcp"`
	rec := send("/mcp", "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "Bearer "+prm, rec.Header().Get("WWW-Authenticate"))
	rec = send("/mcp", "Bearer tok-alice")
	require.Equal(t, http.StatusUnauthorized, rec.Code, "a token of another resource")
	assert.Equal(t, `Bearer error="invalid_token", `+prm, rec.Header().Get("WWW-Authenticate"))
	for _, p := range []string{"/mcpx", "/", "/api/mcp"} {
		assert.Equal(t, http.StatusNotFound, send(p, "Bearer tok-home").Code, p)
	}
	assert.Len(t, who, 1)
}

func TestMiddlewareForRefusesAResourceThePathsCannotServe(t *testing.T) {
	single := newHarness(t, harnessOptions{paths: core.SingleResource{At: "/mcp", ID: "home"}}).guard
	assert.Panics(t, func() { single.MiddlewareFor("other") })
	assert.NotPanics(t, func() { single.MiddlewareFor("home") })
	per := newHarness(t, harnessOptions{}).guard
	for _, id := range []core.ResourceID{"", "a/b"} {
		assert.Panics(t, func() { per.MiddlewareFor(id) }, "%q", id)
	}
	assert.NotPanics(t, func() { per.MiddlewareFor("hello") })
}
