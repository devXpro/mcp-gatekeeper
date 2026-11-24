package mcpguard

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
	"github.com/devXpro/mcp-gatekeeper/internal/testlog"
)

const hubURL = "https://hub.example.com"

// failsafe bounds every wait of a test on a channel; reaching it is a failure, never a pass.
const failsafe = 10 * time.Second

const guardCSP = "default-src 'none'; frame-ancestors 'none'; sandbox"

// fakeTokens is core.TokenValidator over a map of tokens.
type fakeTokens struct {
	mu      sync.Mutex
	tokens  map[string]core.AccessInfo
	err     error // returned for every token when set
	lenient bool  // hand out a token whatever resource it is for (to test the guard's own check)
}

func (f *fakeTokens) ValidateAccess(_ context.Context, token string, r core.ResourceID) (core.AccessInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return core.AccessInfo{}, f.err
	}
	info, ok := f.tokens[token]
	if !ok || (!f.lenient && info.ResourceID != r) {
		return core.AccessInfo{}, core.ErrInvalidToken
	}
	return info, nil
}

func (f *fakeTokens) set(fn func(*fakeTokens)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// fakePeople is People over a map.
type fakePeople struct {
	mu     sync.Mutex
	people map[core.PersonID]core.Person
	err    error
}

func (f *fakePeople) Get(_ context.Context, id core.PersonID) (core.Person, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return core.Person{}, f.err
	}
	p, ok := f.people[id]
	if !ok {
		return core.Person{}, core.ErrNotFound
	}
	return p, nil
}

func (f *fakePeople) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// fakeResources is core.ResourceCatalog over a map of switches.
type fakeResources struct {
	mu  sync.Mutex
	on  map[core.AccountID][]core.ResourceID
	err error
}

func (f *fakeResources) Resource(context.Context, core.ResourceID) (core.ResourceInfo, error) {
	panic("the guard never asks for a resource's description")
}

func (f *fakeResources) Available(_ context.Context, a core.AccountID, id core.ResourceID) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	return slices.Contains(f.on[a], id), nil
}

func (f *fakeResources) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// upstreamRequest is one request the fake MCP server got.
type upstreamRequest struct {
	method string
	uri    string
	header http.Header
	body   []byte
}

// fakeUpstream is an MCP server behind the application: it records every request and answers with its handler.
type fakeUpstream struct {
	srv *httptest.Server

	mu      sync.Mutex
	handler http.HandlerFunc
	got     []upstreamRequest
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{handler: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.got = append(u.got, upstreamRequest{method: r.Method, uri: r.RequestURI, header: r.Header.Clone(), body: body})
		h := u.handler
		u.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *fakeUpstream) handle(h http.HandlerFunc) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.handler = h
}

func (u *fakeUpstream) requests() []upstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.got)
}

func (u *fakeUpstream) only(t *testing.T) upstreamRequest {
	t.Helper()
	got := u.requests()
	require.Len(t, got, 1)
	return got[0]
}

// passed is what the guard handed the application's handler.
type passed struct {
	access core.AccessInfo
	person core.Person
}

// harness is an application with one MCP endpoint per resource under /mcp/ (or the paths it is given), whose handler
// is a small proxy to a fake MCP server built from the package's helpers, the way an application's proxy uses them.
type harness struct {
	guard     *Guard
	tokens    *fakeTokens
	people    *fakePeople
	resources *fakeResources
	upstream  *fakeUpstream
	app       *httptest.Server
	client    *http.Client // the assistant's
	proxied   *http.Client // the application's, to the MCP server
	logs      *testlog.Recorder

	mu    sync.Mutex
	calls []passed
}

// harnessOptions change a harness.
type harnessOptions struct {
	paths    core.ResourcePaths // nil: core.PerResource{Prefix: "/mcp/"}
	clientIP core.ClientIPMode
	ping     time.Duration
}

func newHarness(t *testing.T, o harnessOptions) *harness {
	t.Helper()
	if o.paths == nil {
		o.paths = core.PerResource{Prefix: "/mcp/"}
	}
	disabled := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	h := &harness{
		people: &fakePeople{people: map[core.PersonID]core.Person{
			"per_alice": {ID: "per_alice", AccountID: "acc_a", Name: "Alice", Role: core.RoleOwner},
			"per_bella": {ID: "per_bella", AccountID: "acc_a", Name: "Bella", Role: core.RoleMember},
			"per_off":   {ID: "per_off", AccountID: "acc_a", Name: "Gone Away", Role: core.RoleMember, DisabledAt: &disabled},
			"per_bob":   {ID: "per_bob", AccountID: "acc_b", Name: "Bob", Role: core.RoleOwner},
		}},
		resources: &fakeResources{on: map[core.AccountID][]core.ResourceID{
			"acc_a": {"hello", "other", "home"},
			"acc_b": {"other"},
		}},
		upstream: newFakeUpstream(t),
	}
	access := func(p core.PersonID, a core.AccountID, r core.ResourceID, as core.Assistant) core.AccessInfo {
		return core.AccessInfo{GrantID: "grt_" + core.GrantID(p), PersonID: p, AccountID: a, ResourceID: r,
			ClientID: "cli_" + core.ClientID(as), Assistant: as, Scope: Scope}
	}
	h.tokens = &fakeTokens{tokens: map[string]core.AccessInfo{
		"tok-alice":     access("per_alice", "acc_a", "hello", core.AssistantChatGPT),
		"tok-bella":     access("per_bella", "acc_a", "hello", core.AssistantClaude),
		"tok-other":     access("per_alice", "acc_a", "other", core.AssistantChatGPT),
		"tok-off":       access("per_off", "acc_a", "hello", core.AssistantChatGPT),
		"tok-ghost":     access("per_ghost", "acc_a", "hello", core.AssistantChatGPT),
		"tok-moved":     access("per_alice", "acc_b", "hello", core.AssistantChatGPT),
		"tok-bob":       access("per_bob", "acc_b", "hello", core.AssistantChatGPT),
		"tok-bob-other": access("per_bob", "acc_b", "other", core.AssistantChatGPT),
		"tok-home":      access("per_alice", "acc_a", "home", core.AssistantClaude),
	}}
	log, rec := testlog.New()
	h.logs = rec
	g, err := New(Options{
		Site:  core.Site{PublicURL: hubURL, ClientIP: o.clientIP},
		Paths: o.paths, Tokens: h.tokens, People: h.people, Resources: h.resources,
		PingInterval: o.ping, Log: log,
	})
	require.NoError(t, err)
	h.guard = g

	mux := http.NewServeMux()
	mux.Handle("/", g.Middleware(http.HandlerFunc(h.proxy)))
	h.app = httptest.NewServer(mux)
	t.Cleanup(h.app.Close)
	h.client = &http.Client{Transport: &http.Transport{}}
	t.Cleanup(h.client.CloseIdleConnections)
	tr := &http.Transport{Proxy: nil, DisableCompression: true}
	h.proxied = &http.Client{Transport: tr}
	t.Cleanup(tr.CloseIdleConnections)
	return h
}

// proxy is the application's MCP handler behind the guard: it admits the call, reads the body, passes the allowed
// headers both ways and relays the answer.
func (h *harness) proxy(w http.ResponseWriter, r *http.Request) {
	info, okA := AccessFrom(r.Context())
	person, okP := PersonFrom(r.Context())
	if !okA || !okP {
		http.Error(w, "no caller in the context", http.StatusTeapot)
		return
	}
	h.mu.Lock()
	h.calls = append(h.calls, passed{access: info, person: person})
	h.mu.Unlock()
	release, ok := h.guard.Admit(w, info.AccountID, info.ResourceID)
	if !ok {
		return
	}
	defer release()
	body, ok := ReadBody(w, r)
	if !ok {
		return
	}
	u := h.upstream.srv.URL + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		u += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u, bytes.NewReader(body)) //nolint:gosec // G704: the test's own fake server
	if err != nil {
		httpsec.WriteError(w, http.StatusInternalServerError, httpsec.CodeInternal, "internal error")
		return
	}
	RequestHeaders(req.Header, r.Header)
	req.Header.Set("User-Agent", "") // only the allowed headers reach the server
	resp, err := h.proxied.Do(req)   //nolint:gosec // G704: the test's own fake server
	if err != nil {
		if r.Context().Err() == nil {
			httpsec.WriteError(w, http.StatusBadGateway, httpsec.CodeUpstream, "the module cannot be reached")
		}
		return
	}
	defer resp.Body.Close()
	ResponseHeaders(w.Header(), resp.Header)
	_ = h.guard.Relay(r.Context(), w, resp.StatusCode, resp.Body)
}

func (h *harness) passed() []passed {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.calls)
}

// request builds a request to the application; a non-empty auth becomes the Authorization header as it is.
func (h *harness) request(t *testing.T, method, path, auth string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, h.app.URL+path, body)
	require.NoError(t, err)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return req
}

// answer is a whole response of the application.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func (h *harness) do(t *testing.T, req *http.Request) answer {
	t.Helper()
	resp, err := h.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return answer{status: resp.StatusCode, header: resp.Header, body: b}
}

// errorCode is the "error" of a JSON error answer.
func (a answer) errorCode(t *testing.T) string {
	t.Helper()
	var e httpsec.ErrorBody
	require.NoError(t, json.Unmarshal(a.body, &e), "body %q", a.body)
	return e.Error
}

// requireNoSecrets fails if any log record holds one of secrets.
func (h *harness) requireNoSecrets(t *testing.T, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		require.False(t, h.logs.Contains(s), "a log record holds %q", s)
	}
}

// wait receives from ch, failing the test after failsafe.
func wait[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(failsafe):
		require.FailNow(t, "timed out waiting for "+what)
	}
	var zero T
	return zero
}

func headerNames(h http.Header) []string {
	var names []string
	for k := range h {
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}
