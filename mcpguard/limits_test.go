package mcpguard

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

func TestAdmitCapsTheCallsPerAccountAndResource(t *testing.T) {
	g := newHarness(t, harnessOptions{}).guard
	var releases []func()
	for i := range inFlightPerResource {
		release, ok := g.Admit(httptest.NewRecorder(), "acc_a", "hello")
		require.True(t, ok, "call %d", i+1)
		releases = append(releases, release)
	}
	rec := httptest.NewRecorder()
	release, ok := g.Admit(rec, "acc_a", "hello")
	require.False(t, ok)
	assert.Nil(t, release)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
	assert.Equal(t, `{"error":"rate_limited","message":"too many calls to this module at once; try again shortly"}`,
		rec.Body.String())

	for _, k := range []placeKey{{account: "acc_b", resource: "hello"}, {account: "acc_a", resource: "other"}} {
		release, ok := g.Admit(httptest.NewRecorder(), k.account, k.resource)
		assert.True(t, ok, "%+v has its own places", k)
		release()
	}

	releases[0]()
	releases[0]() // a second release gives nothing back
	release, ok = g.Admit(httptest.NewRecorder(), "acc_a", "hello")
	require.True(t, ok, "the place comes back")
	_, ok = g.Admit(httptest.NewRecorder(), "acc_a", "hello")
	require.False(t, ok, "only one place came back")

	release()
	for _, r := range releases[1:] {
		r()
	}
	g.inFlight.mu.Lock()
	assert.Empty(t, g.inFlight.calls, "no counter outlives its calls")
	g.inFlight.mu.Unlock()
}

func TestAdmitThroughTheApplication(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	arrived := make(chan struct{}, inFlightPerResource)
	release := make(chan struct{})
	h.upstream.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp/hello/hold" {
			arrived <- struct{}{}
			select {
			case <-release:
			case <-time.After(failsafe):
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	})

	var wg sync.WaitGroup
	statuses := make(chan int, inFlightPerResource)
	for range inFlightPerResource {
		req := h.request(t, http.MethodPost, "/mcp/hello/hold", "Bearer tok-alice", strings.NewReader(`{}`))
		wg.Go(func() {
			resp, err := h.client.Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			_ = resp.Body.Close()
			statuses <- resp.StatusCode
		})
	}
	for range inFlightPerResource {
		wait(t, arrived, "a held call to reach the server")
	}

	a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-bella", strings.NewReader(`{}`)))
	require.Equal(t, http.StatusTooManyRequests, a.status, "the account's next call")
	assert.Equal(t, httpsec.CodeRateLimited, a.errorCode(t))
	assert.Equal(t, "1", a.header.Get("Retry-After"))
	a = h.do(t, h.request(t, http.MethodPost, "/mcp/other", "Bearer tok-other", strings.NewReader(`{}`)))
	assert.Equal(t, http.StatusOK, a.status, "the same account in another resource")
	a = h.do(t, h.request(t, http.MethodPost, "/mcp/other", "Bearer tok-bob-other", strings.NewReader(`{}`)))
	assert.Equal(t, http.StatusOK, a.status, "another account")

	close(release)
	wg.Wait()
	close(statuses)
	for s := range statuses {
		assert.Equal(t, http.StatusOK, s)
	}
	a = h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-bella", strings.NewReader(`{}`)))
	assert.Equal(t, http.StatusOK, a.status, "the places come back")
	h.guard.inFlight.mu.Lock()
	assert.Empty(t, h.guard.inFlight.calls, "no counter outlives its calls")
	h.guard.inFlight.mu.Unlock()
}

func TestFailureLimitPerAddress(t *testing.T) {
	h := newHarness(t, harnessOptions{clientIP: core.ClientIPCloudflare})
	from := func(addr, auth string) answer {
		req := h.request(t, http.MethodPost, "/mcp/hello", auth, strings.NewReader(`{}`))
		req.Header.Set("CF-Connecting-IP", addr)
		return h.do(t, req)
	}
	// otherDoor is a door of the application that takes another credential (Family Hub: the legacy REST door) and
	// refuses it through the same limit.
	otherDoor := func(addr string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/legacy/hello/x", nil)
		req.Header.Set("CF-Connecting-IP", addr)
		rec := httptest.NewRecorder()
		h.guard.Refuse(rec, req, func() {
			httpsec.WriteError(rec, http.StatusUnauthorized, httpsec.CodeInvalidToken, "the key is not valid")
		})
		return rec
	}
	const attacker = "2001:db8:1:2::1"
	// The failures of every kind and of every door count together.
	junk := []string{
		"Bearer tok-nope",
		"Bearer tok-other", // a token of another resource
		"Bearer tok-moved", // a person of another account
		"",                 // the other door
	}
	for i := range failuresPerAddress {
		if j := junk[i%len(junk)]; j != "" {
			require.Equal(t, http.StatusUnauthorized, from(attacker, j).status, "failure %d", i+1)
		} else {
			require.Equal(t, http.StatusUnauthorized, otherDoor(attacker).Code, "failure %d", i+1)
		}
	}
	const sameNet = "2001:db8:1:2:ffff::9" // the same /64
	for _, j := range junk[:3] {
		a := from(sameNet, j)
		require.Equal(t, http.StatusTooManyRequests, a.status, j)
		assert.Equal(t, httpsec.CodeRateLimited, a.errorCode(t))
		assert.Equal(t, "2", a.header.Get("Retry-After"), "one failure refills in 2 s")
		assert.Empty(t, a.header.Get("WWW-Authenticate"))
	}
	rec := otherDoor(sameNet)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "the other door")
	assert.Equal(t, `{"error":"rate_limited","message":"too many invalid credentials; try again later"}`,
		rec.Body.String())

	t.Run("no credential is no failure", func(t *testing.T) {
		a := from(attacker, "")
		assert.Equal(t, http.StatusUnauthorized, a.status)
		assert.Equal(t, httpsec.CodeUnauthorized, a.errorCode(t))
	})
	t.Run("a valid credential from a spent address passes", func(t *testing.T) {
		before := len(h.upstream.requests())
		assert.Equal(t, http.StatusOK, from(attacker, "Bearer tok-alice").status)
		assert.Len(t, h.upstream.requests(), before+1)
	})
	t.Run("other addresses are not touched", func(t *testing.T) {
		for _, addr := range []string{"2001:db8:1:3::1", "203.0.113.7"} {
			a := from(addr, "Bearer tok-nope")
			assert.Equal(t, http.StatusUnauthorized, a.status, addr)
		}
	})
}

func TestFailureLimitRefills(t *testing.T) {
	l := newFailureLimit(30)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for i := range 30 {
		ok, _ := l.failed("a", now)
		require.True(t, ok, i)
	}
	ok, wait := l.failed("a", now)
	assert.False(t, ok)
	assert.Equal(t, 2*time.Second, wait)
	ok, _ = l.failed("b", now)
	assert.True(t, ok, "another key has its own bucket")
	ok, _ = l.failed("a", now.Add(time.Second))
	assert.False(t, ok, "half a failure is not one")
	ok, _ = l.failed("a", now.Add(2*time.Second))
	assert.True(t, ok)
	ok, _ = l.failed("a", now.Add(2*time.Second))
	assert.False(t, ok)

	for i := range maxFailureBuckets + 10 {
		l.failed("k"+strconv.Itoa(i), now)
	}
	assert.LessOrEqual(t, len(l.buckets), maxFailureBuckets, "a flood of addresses stays bounded")
}

func TestAddressKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":           "203.0.113.7",
		"::ffff:203.0.113.7":    "203.0.113.7",
		"2001:db8:1:2::1":       "2001:db8:1:2::/64",
		"2001:db8:1:2:ff::9":    "2001:db8:1:2::/64",
		"2001:db8:1:3::1":       "2001:db8:1:3::/64",
		"not-an-address":        "not-an-address",
		strings.Repeat("x", 99): strings.Repeat("x", 64),
	} {
		assert.Equal(t, want, addressKey(in), in)
	}
}

// TestAdmitAccessPerAccountAndPerPerson: by default (Family Hub) the people of an account share its 16 places; with
// PerPerson and 8 (Homie) each person has their own 8.
func TestAdmitAccessPerAccountAndPerPerson(t *testing.T) {
	info := func(p core.PersonID, a core.AccountID) core.AccessInfo {
		return core.AccessInfo{PersonID: p, AccountID: a, ResourceID: "hello"}
	}
	take := func(t *testing.T, g *Guard, in core.AccessInfo, n int) []func() {
		t.Helper()
		var rels []func()
		for i := range n {
			rel, ok := g.AdmitAccess(httptest.NewRecorder(), in)
			require.True(t, ok, "%s: call %d", in.PersonID, i+1)
			rels = append(rels, rel)
		}
		return rels
	}
	refused := func(t *testing.T, g *Guard, in core.AccessInfo) {
		t.Helper()
		rec := httptest.NewRecorder()
		rel, ok := g.AdmitAccess(rec, in)
		require.False(t, ok, in.PersonID)
		assert.Nil(t, rel)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Equal(t, "1", rec.Header().Get("Retry-After"))
	}

	t.Run("per account", func(t *testing.T) {
		g := newHarness(t, harnessOptions{}).guard
		take(t, g, info("per_alice", "acc_a"), inFlightPerResource/2)
		take(t, g, info("per_bella", "acc_a"), inFlightPerResource/2)
		refused(t, g, info("per_alice", "acc_a"))
		refused(t, g, info("per_bella", "acc_a"))
		_, ok := g.Admit(httptest.NewRecorder(), "acc_a", "hello")
		assert.False(t, ok, "Admit and AdmitAccess share the account's places")
		take(t, g, info("per_bob", "acc_b"), 1)
	})
	t.Run("per person", func(t *testing.T) {
		g := newHarness(t, harnessOptions{inFlight: 8, key: PerPerson}).guard
		alice := take(t, g, info("per_alice", "acc_a"), 8)
		refused(t, g, info("per_alice", "acc_a"))
		bella := take(t, g, info("per_bella", "acc_a"), 8)
		refused(t, g, info("per_bella", "acc_a"))
		alice[0]()
		alice = append(alice[1:], take(t, g, info("per_alice", "acc_a"), 1)...)
		refused(t, g, info("per_alice", "acc_a"))
		for _, rel := range append(alice, bella...) {
			rel()
		}
		g.inFlight.mu.Lock()
		assert.Empty(t, g.inFlight.calls, "no counter outlives its calls")
		g.inFlight.mu.Unlock()
	})
}

// holdCalls sends n calls with token that the fake MCP server holds until the returned function is called; that
// function waits for them and returns their statuses.
func holdCalls(t *testing.T, h *harness, token string, n int) (finish func() []int) {
	t.Helper()
	arrived := make(chan struct{}, n)
	release := make(chan struct{})
	h.upstream.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp/hello/hold" {
			arrived <- struct{}{}
			select {
			case <-release:
			case <-time.After(failsafe):
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	})
	var wg sync.WaitGroup
	statuses := make(chan int, n)
	for range n {
		req := h.request(t, http.MethodPost, "/mcp/hello/hold", "Bearer "+token, strings.NewReader(`{}`))
		wg.Go(func() {
			resp, err := h.client.Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			_ = resp.Body.Close()
			statuses <- resp.StatusCode
		})
	}
	for range n {
		wait(t, arrived, "a held call to reach the server")
	}
	return func() []int {
		close(release)
		wg.Wait()
		close(statuses)
		var out []int
		for s := range statuses {
			out = append(out, s)
		}
		return out
	}
}

// TestAdmitPerPersonThroughTheApplication: under PerPerson one person's held calls do not lock out the rest of the
// household.
func TestAdmitPerPersonThroughTheApplication(t *testing.T) {
	h := newHarness(t, harnessOptions{inFlight: 8, key: PerPerson})
	finish := holdCalls(t, h, "tok-alice", 8)
	a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", strings.NewReader(`{}`)))
	require.Equal(t, http.StatusTooManyRequests, a.status, "the person's ninth call")
	assert.Equal(t, `{"error":"rate_limited","message":"too many calls to this module at once; try again shortly"}`,
		string(a.body))
	a = h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-bella", strings.NewReader(`{}`)))
	assert.Equal(t, http.StatusOK, a.status, "another person of the same account")
	for _, s := range finish() {
		assert.Equal(t, http.StatusOK, s)
	}
	a = h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", strings.NewReader(`{}`)))
	assert.Equal(t, http.StatusOK, a.status, "the places come back")
}

// TestKnownDeadTokensAreNoFailures is review GK-12: a token the validator knows to be expired or revoked is answered
// 401 invalid_token, never 429, and does not spend its address's failure budget.
func TestKnownDeadTokensAreNoFailures(t *testing.T) {
	h := newHarness(t, harnessOptions{clientIP: core.ClientIPCloudflare})
	h.tokens.set(func(f *fakeTokens) {
		f.dead = map[string]error{
			"tok-expired": fmt.Errorf("oauth: %w: %w", core.ErrInvalidToken, core.ErrExpired),
			"tok-unknown": core.ErrInvalidToken,
		}
	})
	const addr = "198.51.100.20"
	from := func(auth string) answer {
		req := h.request(t, http.MethodPost, "/mcp/hello", auth, strings.NewReader(`{}`))
		req.Header.Set("CF-Connecting-IP", addr)
		return h.do(t, req)
	}
	const body = `{"error":"invalid_token","message":"the access token is invalid, expired or for another module"}`
	for i := range failuresPerAddress + 5 {
		a := from("Bearer tok-expired")
		require.Equal(t, http.StatusUnauthorized, a.status, "expired %d", i+1)
		require.Equal(t, body, string(a.body))
		require.Equal(t, `Bearer error="invalid_token", `+helloPRM, a.header.Get("WWW-Authenticate"))
	}
	for i := range failuresPerAddress {
		require.Equal(t, http.StatusUnauthorized, from("Bearer tok-unknown").status, "the budget is whole: %d", i+1)
	}
	require.Equal(t, http.StatusTooManyRequests, from("Bearer tok-unknown").status, "junk is still limited")
	a := from("Bearer tok-expired")
	assert.Equal(t, http.StatusUnauthorized, a.status, "an expired token still gets the 401 that makes it refresh")
	assert.Equal(t, body, string(a.body))
	assert.Empty(t, h.logs.Records(), "the header was there every time")
}

func TestFailuresPerAddressOption(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	g, err := New(Options{
		Site: core.Site{PublicURL: hubURL, ClientIP: core.ClientIPRemote}, Paths: core.PerResource{Prefix: "/mcp/"},
		Tokens: h.tokens, People: h.people, Resources: h.resources, FailuresPerAddress: 2, Clock: h.clock.Now,
	})
	require.NoError(t, err)
	app := g.Middleware(http.NotFoundHandler())
	status := func() int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp/hello", nil)
		req.Header.Set("Authorization", "Bearer tok-nope")
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		return rec.Code
	}
	assert.Equal(t, []int{401, 401, 429}, []int{status(), status(), status()})
}

// TestTheMissingAddressHeaderIsLoggedOnce: in a header mode, a refusal of a request without the header is counted by
// the TCP peer, which behind a local connector is every client: the guard says so once.
func TestTheMissingAddressHeaderIsLoggedOnce(t *testing.T) {
	h := newHarness(t, harnessOptions{clientIP: core.ClientIPCloudflare})
	for range 3 {
		a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-nope", nil))
		require.Equal(t, http.StatusUnauthorized, a.status)
	}
	require.Equal(t, http.StatusOK, h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", nil)).status)
	recs := h.logs.Records()
	require.Len(t, recs, 1)
	assert.Equal(t, slog.LevelWarn, recs[0].Level)
	assert.Equal(t, "CF-Connecting-IP", recs[0].Attrs["header"])
	h.requireNoSecrets(t, "tok-nope", "tok-alice")

	quiet := newHarness(t, harnessOptions{}) // remote: there is no header to miss
	quiet.do(t, quiet.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-nope", nil))
	assert.Empty(t, quiet.logs.Records())
}

// TestEndedPeopleAreNoFailures: a valid token of a person whose access ended after it was issued (disabled, past
// their term, removed) is refused with the usual 401 but does not spend its address's failure budget: that address is
// an assistant provider's egress, shared with every other connector there. Junk still spends it.
func TestEndedPeopleAreNoFailures(t *testing.T) {
	h := newHarness(t, harnessOptions{clientIP: core.ClientIPCloudflare})
	const addr = "198.51.100.30"
	from := func(auth string) answer {
		req := h.request(t, http.MethodPost, "/mcp/hello", auth, strings.NewReader(`{}`))
		req.Header.Set("CF-Connecting-IP", addr)
		return h.do(t, req)
	}
	const body = `{"error":"invalid_token","message":"the access token is invalid, expired or for another module"}`
	ended := []string{
		"Bearer tok-off",   // disabled
		"Bearer tok-erin",  // past their term
		"Bearer tok-ghost", // removed
	}
	for i := range 2 * failuresPerAddress {
		a := from(ended[i%len(ended)])
		require.Equal(t, http.StatusUnauthorized, a.status, "refusal %d", i+1)
		require.Equal(t, body, string(a.body))
		require.Equal(t, `Bearer error="invalid_token", `+helloPRM, a.header.Get("WWW-Authenticate"))
	}
	h.guard.failures.mu.Lock()
	assert.Empty(t, h.guard.failures.buckets, "the address bucket is untouched")
	h.guard.failures.mu.Unlock()

	require.Equal(t, http.StatusUnauthorized, from("Bearer tok-nope").status)
	h.guard.failures.mu.Lock()
	require.Contains(t, h.guard.failures.buckets, addr, "junk is charged")
	assert.InDelta(t, float64(failuresPerAddress-1), h.guard.failures.buckets[addr].tokens, 0)
	h.guard.failures.mu.Unlock()
	for i := range failuresPerAddress - 1 {
		require.Equal(t, http.StatusUnauthorized, from("Bearer tok-nope").status, "junk %d", i+2)
	}
	require.Equal(t, http.StatusTooManyRequests, from("Bearer tok-nope").status, "junk is still limited")
	a := from("Bearer tok-erin")
	assert.Equal(t, http.StatusUnauthorized, a.status, "an ended person's token is never 429")
	assert.Equal(t, body, string(a.body))
}
