package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/adminsock"
	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/internal/testlog"
)

const (
	testHost   = "hub.example.com"
	testOrigin = "https://hub.example.com"
	safariMac  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15"
	safariIOS  = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1"

	// Family Hub's names, as it passes them (docs/PLAN.md §4.2.2).
	cookieName = "__Host-fh_session"
	csrfHeader = "X-Family-Hub"
	product    = "Family Hub"
)

// testSite is a site with only what auth needs: the public URL and a client address mode (core.Site.Validate).
var testSite = core.Site{PublicURL: testOrigin, ClientIP: core.ClientIPRemote}

// testBrand is Family Hub's brand.
var testBrand = core.Brand{Product: product, SessionCookie: cookieName, TxnCookie: "__Host-fh_txn", CSRFHeader: csrfHeader}

// clock is the fake time every test runs on.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// env is one site: the fake store, the clock, the captured logs, Auth and a mux with auth's routes and four probes
// behind the middlewares.
type env struct {
	t     *testing.T
	st    *fakeStore
	clock *clock
	logs  *testlog.Recorder
	a     *Auth
	h     http.Handler

	secretsMu sync.Mutex
	secrets   []string // every cookie, link token and challenge the tests saw: none may reach a log
}

// secret remembers a value that must never be logged.
func (e *env) secret(s string) {
	if s == "" {
		return
	}
	e.secretsMu.Lock()
	defer e.secretsMu.Unlock()
	e.secrets = append(e.secrets, s)
}

// newEnv sets up Family Hub's site; each of change may adjust the options first.
func newEnv(t *testing.T, change ...func(*Options)) *env {
	t.Helper()
	log, logs := testlog.New()
	e := &env{t: t, st: newFakeStore(), clock: &clock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}, logs: logs}
	o := Options{
		Site:  core.Site{PublicURL: testOrigin, RPID: testHost, ClientIP: core.ClientIPCloudflare},
		Brand: testBrand, Store: e.st, Logger: log, Clock: e.clock.Now, AdminCLI: "hub admin",
		ResetSteps: []ResetStep{legacyStep(e.st)},
	}
	for _, c := range change {
		c(&o)
	}
	a, err := New(o)
	require.NoError(t, err)
	e.a = a
	mux := http.NewServeMux()
	a.RegisterRoutes(mux)
	mux.Handle("GET /test/viewer", a.RequireViewer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := viewerOf(r)
		_, _ = io.WriteString(w, string(v.Person.ID)+" "+string(v.Account.ID))
	})))
	noContent := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("POST /test/write", a.RequireViewer(noContent))
	mux.Handle("POST /test/danger", a.RequireViewer(a.RequireStepUp(noContent)))
	mux.Handle("POST /test/public", a.SameOrigin(noContent))
	e.h = mux
	return e
}

// command runs one of auth's admin commands the way the socket does and returns its output.
func (e *env) command(name string, args ...string) (string, error) {
	e.t.Helper()
	return e.commandFrom(adminsock.Peer{}, name, args...)
}

// commandFrom is command run by the socket peer p.
func (e *env) commandFrom(p adminsock.Peer, name string, args ...string) (string, error) {
	e.t.Helper()
	for _, c := range e.a.AdminCommands() {
		if c.Name == name {
			var out bytes.Buffer
			if args == nil {
				args = []string{}
			}
			err := c.Run(context.Background(), adminsock.Invocation{Args: args, Out: &out, Peer: p})
			if i := strings.Index(out.String(), "#t="); i >= 0 {
				e.secret(strings.Fields(out.String()[i+3:])[0])
			}
			return out.String(), err
		}
	}
	e.t.Fatalf("no command %q", name)
	return "", nil
}

// setupLink runs the setup-link command and returns the token of the link it printed.
func (e *env) setupLink() string {
	e.t.Helper()
	out, err := e.command("setup-link")
	require.NoError(e.t, err)
	return tokenOf(e.t, out, testOrigin+"/setup#t=")
}

// tokenOf finds the link with prefix in text and returns its token.
func tokenOf(t *testing.T, text, prefix string) string {
	t.Helper()
	i := strings.Index(text, prefix)
	require.GreaterOrEqual(t, i, 0, "no link %s in %q", prefix, text)
	token := text[i+len(prefix):]
	if j := strings.IndexAny(token, " \n"); j >= 0 {
		token = token[:j]
	}
	require.True(t, wellFormedToken(token), "token %q", token)
	return token
}

// actions returns the audit actions in the order they were written.
func (e *env) actions() []string {
	var out []string
	for _, a := range e.st.Audit().(fakeAudit).entries() {
		out = append(out, a.Action)
	}
	return out
}

func (e *env) lastAudit() core.AuditEntry {
	e.t.Helper()
	all := e.st.Audit().(fakeAudit).entries()
	require.NotEmpty(e.t, all)
	return all[len(all)-1]
}

// logged reports whether a record with this message (and every attribute of attrs, as strings) was logged.
func (e *env) logged(msg string, attrs ...string) bool {
	for _, rec := range e.logs.Records() {
		if rec.Message != msg {
			continue
		}
		ok := true
		for i := 0; i+1 < len(attrs); i += 2 {
			ok = ok && rec.Attrs[attrs[i]] == attrs[i+1]
		}
		if ok {
			return true
		}
	}
	return false
}

// browser is one browser tab: it keeps the session cookie and sends the headers the SPA sends.
type browser struct {
	e      *env
	cookie string
	origin string // the Origin header; "" sends none
	ip     string // CF-Connecting-IP
	ua     string
	csrf   bool        // send X-Family-Hub: 1 on writes
	header http.Header // extra headers
}

func (e *env) browser() *browser {
	return &browser{e: e, origin: testOrigin, ip: "198.51.100.10", ua: safariMac, csrf: true, header: http.Header{}}
}

func (b *browser) do(method, path string, body any) *httptest.ResponseRecorder {
	b.e.t.Helper()
	var rd io.Reader
	switch v := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(v)
	default:
		raw, err := json.Marshal(v)
		require.NoError(b.e.t, err)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "https://"+testHost+path, rd)
	req.RemoteAddr = "172.18.0.5:41234" // cloudflared
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.csrf && method != http.MethodGet {
		req.Header.Set(csrfHeader, "1")
	}
	if b.origin != "" {
		req.Header.Set("Origin", b.origin)
	}
	if b.ip != "" {
		req.Header.Set("CF-Connecting-IP", b.ip)
	}
	req.Header.Set("User-Agent", b.ua)
	for k, v := range b.header {
		req.Header[k] = v
	}
	if b.cookie != "" {
		req.Header.Set("Cookie", cookieName+"="+b.cookie)
	}
	rec := httptest.NewRecorder()
	b.e.h.ServeHTTP(rec, req)
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	for _, c := range res.Cookies() {
		if c.Name == cookieName {
			if c.MaxAge < 0 {
				b.cookie = ""
			} else {
				b.cookie = c.Value
				b.e.secret(c.Value)
			}
		}
	}
	var begun struct {
		Options struct {
			Challenge string `json:"challenge"`
		} `json:"options"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &begun) == nil {
		b.e.secret(begun.Options.Challenge)
	}
	return rec
}

// device is a phone or a Mac with one passkey: a virtual authenticator and its credential.
type device struct {
	rp   virtualwebauthn.RelyingParty
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

// newDevice is a synced platform passkey (backup eligible and backed up), like iCloud Keychain.
func newDevice() *device {
	return &device{
		rp: virtualwebauthn.RelyingParty{ID: testHost, Name: product, Origin: testOrigin},
		auth: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
			BackupEligible: true, BackupState: true,
		}),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
}

// create answers creation options like navigator.credentials.create and remembers the user handle.
func (d *device) create(t *testing.T, options json.RawMessage) json.RawMessage {
	t.Helper()
	opts, err := virtualwebauthn.ParseAttestationOptions(string(options))
	require.NoError(t, err, "%s", options)
	d.auth.Options.UserHandle = []byte(opts.UserID)
	return json.RawMessage(virtualwebauthn.CreateAttestationResponse(d.rp, d.auth, d.cred, *opts))
}

// get answers request options like navigator.credentials.get.
func (d *device) get(t *testing.T, options json.RawMessage) json.RawMessage {
	t.Helper()
	opts, err := virtualwebauthn.ParseAssertionOptions(string(options))
	require.NoError(t, err, "%s", options)
	return json.RawMessage(virtualwebauthn.CreateAssertionResponse(d.rp, d.auth, d.cred, *opts))
}

// begin posts a begin and returns its options.
func (b *browser) begin(path string, body any) json.RawMessage {
	b.e.t.Helper()
	rec := b.do(http.MethodPost, path, body)
	wantStatus(b.e.t, rec, http.StatusOK)
	var out struct {
		Options json.RawMessage `json:"options"`
	}
	require.NoError(b.e.t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.NotEmpty(b.e.t, out.Options, "%s", rec.Body)
	return out.Options
}

// register runs register/begin and /finish with the token and the device.
func (b *browser) register(d *device, token, name, accountName string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	opts := b.begin("/api/auth/register/begin", map[string]string{"token": token, "name": name, "account_name": accountName})
	return b.do(http.MethodPost, "/api/auth/register/finish", map[string]any{"credential": d.create(b.e.t, opts)})
}

// login runs a discoverable sign-in with the device.
func (b *browser) login(d *device) *httptest.ResponseRecorder {
	b.e.t.Helper()
	opts := b.begin("/api/auth/login/begin", map[string]any{})
	return b.do(http.MethodPost, "/api/auth/login/finish", map[string]any{"credential": d.get(b.e.t, opts)})
}

// stepUp runs a step-up with the device.
func (b *browser) stepUp(d *device) *httptest.ResponseRecorder {
	b.e.t.Helper()
	opts := b.begin("/api/auth/stepup/begin", map[string]any{})
	return b.do(http.MethodPost, "/api/auth/stepup/finish", map[string]any{"credential": d.get(b.e.t, opts)})
}

// addPasskey registers the device as another passkey of the browser's person.
func (b *browser) addPasskey(d *device, name string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	opts := b.begin("/api/me/passkeys/begin", map[string]any{})
	return b.do(http.MethodPost, "/api/me/passkeys/finish", map[string]any{"credential": d.create(b.e.t, opts), "name": name})
}

// superadmin sets up a fresh site: a setup link, then the registration of the device as "Алиса" of "Семья".
func (e *env) superadmin(d *device) (*browser, signedIn) {
	e.t.Helper()
	b := e.browser()
	rec := b.register(d, e.setupLink(), "Алиса", "Семья")
	wantStatus(e.t, rec, http.StatusOK)
	return b, decodeAs[signedIn](e.t, rec)
}

// invited makes an invite of kind into account and registers the device with it.
func (e *env) invited(d *device, kind core.InviteKind, account core.AccountID, name string, by core.PersonID) *browser {
	e.t.Helper()
	inv, err := e.a.IssueInvite(context.Background(), kind, account, name, by)
	require.NoError(e.t, err)
	token := tokenOf(e.t, inv.URL, testOrigin+"/join#t=")
	e.secret(token)
	b := e.browser()
	b.ip = "203.0.113.50"
	wantStatus(e.t, b.register(d, token, "", ""), http.StatusOK)
	return b
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	require.Equal(t, status, rec.Code, "body: %s", rec.Body)
}

type errBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) errBody {
	t.Helper()
	wantStatus(t, rec, status)
	body := decodeAs[errBody](t, rec)
	require.Equal(t, code, body.Error, "body: %s", rec.Body)
	require.NotEmpty(t, body.Message)
	return body
}

func decodeAs[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &v), "body: %s", rec.Body)
	return v
}

// The JSON objects of Family Hub's §5.9, as the SPA reads them.
type personBody struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	Superadmin bool   `json:"superadmin"`
}

type accountBody struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type signedIn struct {
	Person  personBody  `json:"person"`
	Account accountBody `json:"account"`
}

type meBody struct {
	Person      personBody  `json:"person"`
	Account     accountBody `json:"account"`
	StepUpUntil *string     `json:"step_up_until"`
}

type passkeyBody struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
}
