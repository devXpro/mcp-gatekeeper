package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/internal/testlog"
)

const hubURL = "https://hub.example.com"

// testBrand is Family Hub's brand, the names the live hub puts on the wire.
var testBrand = core.Brand{
	Product: "Family Hub", SessionCookie: "__Host-fh_session", TxnCookie: "__Host-fh_txn", CSRFHeader: "X-Family-Hub",
}

// The assistants' callbacks and client ID metadata documents.
const (
	chatgptCallback   = "https://chatgpt.com/connector_platform_oauth_redirect"
	chatgptConnectors = "https://chatgpt.com/connector/oauth/cb_42"
	claudeCallback    = "https://claude.ai/api/mcp/auth_callback"
	chatgptDocument   = "https://chatgpt.com/oauth/client.json"
	claudeDocument    = "https://claude.ai/oauth/mcp-oauth-client-metadata"
)

// The fixtures: the Millers with Alice (owner) and Bob, and the Friends with Carol.
var (
	millers = core.Account{ID: "acc_millers", Name: "Millers"}
	friends = core.Account{ID: "acc_friends", Name: "Friends"}
	alice   = core.Viewer{Account: millers, Person: core.Person{
		ID: "per_alice", AccountID: millers.ID, Name: "Alice", Role: core.RoleOwner, Superadmin: true,
	}}
	bob = core.Viewer{Account: millers, Person: core.Person{
		ID: "per_bob", AccountID: millers.ID, Name: "Bob", Role: core.RoleMember,
	}}
	carol = core.Viewer{Account: friends, Person: core.Person{
		ID: "per_carol", AccountID: friends.ID, Name: "Carol", Role: core.RoleOwner,
	}}
)

var notesInfo = core.ResourceInfo{
	ID: "notes", Name: "Notes", Description: "Школьный дневник",
	Tools: []core.ToolInfo{
		{Name: "messages_list", Title: "Сообщения", Access: "read"},
		{Name: "message_send", Title: "Отправить сообщение", Access: "write"},
	},
}

// harness is the server with fakes behind it, served in process. Its requests go out of one browser, jar, unless a
// test names another.
type harness struct {
	t        *testing.T
	srv      *Server
	mux      *http.ServeMux
	store    *fakeStore
	catalog  *fakeCatalog
	fetcher  *fakeFetcher
	clock    *fakeClock
	sessions *fakeSessions
	jar      *browser
	logs     *testlog.Recorder
}

// newHarness serves hubURL with Family Hub's paths (core.PerResource at /mcp/), the default switches and these
// resources: notes and photos can be connected and are on for the Millers; old is on for them but cannot be
// connected (a stopped module); secret can be connected and is on only for the Friends. Alice, Bob and Carol are in
// the store without a term. Every session has a fresh step-up, as right after a sign-in, until a test makes it stale.
func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, nil)
}

// newHarnessWith is newHarness with Options changed by edit (nil: none).
func newHarnessWith(t *testing.T, edit func(o *Options)) *harness {
	t.Helper()
	logger, logs := testlog.New()
	h := &harness{
		t: t, store: newFakeStore(), catalog: newFakeCatalog(), fetcher: newFakeFetcher(), logs: logs,
		clock: &fakeClock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}, jar: newBrowser(),
	}
	h.catalog.add(notesInfo, true, millers.ID, friends.ID)
	h.catalog.add(core.ResourceInfo{
		ID: "photos", Name: "Детский сад", Description: "Новости группы",
		Tools: []core.ToolInfo{{Name: "photos_news", Title: "Новости", Access: "read"}},
	}, true, millers.ID)
	h.catalog.add(core.ResourceInfo{ID: "old", Name: "Old"}, false, millers.ID)
	h.catalog.add(core.ResourceInfo{ID: "secret", Name: "Secret"}, true, friends.ID)
	viewers := map[string]core.Viewer{"alice": alice, "bob": bob, "carol": carol}
	for _, v := range viewers {
		require.NoError(t, h.store.People().Create(t.Context(), v.Person))
	}
	h.sessions = &fakeSessions{viewers: viewers, clock: h.clock, store: h.store, stale: map[string]bool{}}
	o := Options{
		Site:  core.Site{PublicURL: hubURL, RPID: "hub.example.com", ClientIP: core.ClientIPRemote},
		Brand: testBrand, Store: h.store, Sessions: h.sessions, Catalog: h.catalog,
		Paths: core.PerResource{Prefix: "/mcp/"}, Logger: logger, Clock: h.clock.now,
	}
	if edit != nil {
		edit(&o)
	}
	srv, err := newServer(o, h.fetcher)
	require.NoError(t, err)
	h.srv = srv
	h.mux = http.NewServeMux()
	srv.RegisterRoutes(h.mux)
	return h
}

// logged returns the log records with message msg.
func (h *harness) logged(msg string) []testlog.Record {
	var out []testlog.Record
	for _, r := range h.logs.Records() {
		if r.Message == msg {
			out = append(out, r)
		}
	}
	return out
}

// count is the number of transactions kept, live or not.
func (s *txnStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// browser is what one browser profile holds of the server's cookies (the session is signIn's test cookie).
type browser struct {
	mu      sync.Mutex
	cookies map[string]string
}

func newBrowser() *browser { return &browser{cookies: map[string]string{}} }

// attach adds b's cookies to r.
func (b *browser) attach(r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for name, value := range b.cookies {
		addCookie(r, name, value)
	}
}

// addCookie adds a request cookie to r's Cookie header, as http.Request.AddCookie does.
func addCookie(r *http.Request, name, value string) {
	pair := name + "=" + value
	if prev := r.Header.Get("Cookie"); prev != "" {
		pair = prev + "; " + pair
	}
	r.Header.Set("Cookie", pair)
}

// keep stores the cookies of an answer's Set-Cookie headers; one with a negative Max-Age is dropped.
func (b *browser) keep(header http.Header) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, line := range header.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			continue
		}
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
}

// binding is b's binding cookie, "" without one.
func (b *browser) binding() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cookies[testBrand.TxnCookie]
}

func (h *harness) do(r *http.Request) *httptest.ResponseRecorder {
	return h.doIn(h.jar, r)
}

// doIn serves r as browser b sends it, with b's cookies, and keeps the cookies the answer sets.
func (h *harness) doIn(b *browser, r *http.Request) *httptest.ResponseRecorder {
	b.attach(r)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	b.keep(w.Header())
	return w
}

// signIn makes r carry the session cookie of person, a key of fakeSessions.
func signIn(r *http.Request, person string) {
	if person != "" {
		r.Header.Set("Cookie", testCookie+"="+person)
	}
}

// get sends GET target, signed in as person when it is not "".
func (h *harness) get(target, person string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	signIn(r, person)
	return h.do(r)
}

// consentPost sends a consent API POST as the SPA does: same origin, with the CSRF header.
func (h *harness) consentPost(target, person string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, nil)
	r.Header.Set(testBrand.CSRFHeader, "1")
	r.Header.Set("Origin", hubURL)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	signIn(r, person)
	return h.do(r)
}

// registerJSON sends body to POST /oauth/register as JSON.
func (h *harness) registerJSON(body any) *httptest.ResponseRecorder {
	b, err := json.Marshal(body)
	require.NoError(h.t, err)
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	return h.do(r)
}

// testClient is a client as its assistant holds it.
type testClient struct {
	id, secret, redirect string
	basic                bool // authenticates with HTTP Basic rather than form fields
}

// clientPost sends a token or revoke request of tc with form.
func (h *harness) clientPost(target string, tc testClient, form url.Values) *httptest.ResponseRecorder {
	form = cloneValues(form)
	if !tc.basic {
		form.Set("client_id", tc.id)
		if tc.secret != "" {
			form.Set("client_secret", tc.secret)
		}
	}
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if tc.basic {
		r.SetBasicAuth(url.QueryEscape(tc.id), url.QueryEscape(tc.secret))
	}
	return h.do(r)
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// registerDCR registers a client of redirect with the auth method.
func (h *harness) registerDCR(redirect, method string) testClient {
	h.t.Helper()
	w := h.registerJSON(map[string]any{
		"redirect_uris": []string{redirect}, "token_endpoint_auth_method": method, "client_name": "Test",
	})
	require.Equal(h.t, http.StatusCreated, w.Code, w.Body.String())
	var resp struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	decode(h.t, w, &resp)
	return testClient{id: resp.ClientID, secret: resp.ClientSecret, redirect: redirect, basic: method == authBasic}
}

// cimdClient serves a client metadata document for docURL and returns its client.
func (h *harness) cimdClient(docURL, redirect string) testClient {
	h.fetcher.set(docURL, metadataDoc(docURL, redirect))
	return testClient{id: docURL, redirect: redirect}
}

func metadataDoc(docURL string, redirects ...string) string {
	b, err := json.Marshal(map[string]any{
		"client_id": docURL, "client_name": "Claude", "client_uri": "https://claude.ai", "redirect_uris": redirects,
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// newPKCE returns a code_verifier and its S256 code_challenge.
func newPKCE() (string, string) {
	verifier := randomToken()
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizeParams is the authorization request an assistant sends for tc and resource, at Family Hub's path.
func authorizeParams(tc testClient, resource, challenge string) url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {tc.id}, "redirect_uri": {tc.redirect}, "state": {"st-" + resource},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"mcp offline_access"},
		"resource": {hubURL + "/mcp/" + resource},
	}
}

func (h *harness) authorize(params url.Values) *httptest.ResponseRecorder {
	return h.get("/oauth/authorize?"+params.Encode(), "")
}

// startTxn authorizes tc for resource and returns the transaction id and the PKCE verifier.
func (h *harness) startTxn(tc testClient, resource string) (string, string) {
	h.t.Helper()
	verifier, challenge := newPKCE()
	return h.startTxnWith(authorizeParams(tc, resource, challenge)), verifier
}

// startTxnWith sends the authorization request params and returns the transaction id.
func (h *harness) startTxnWith(params url.Values) string {
	h.t.Helper()
	w := h.authorize(params)
	require.Equal(h.t, http.StatusFound, w.Code, w.Body.String())
	id, ok := strings.CutPrefix(w.Header().Get("Location"), "/consent?txn=")
	require.True(h.t, ok, w.Header().Get("Location"))
	return id
}

// approveTxn approves txn as person and returns the redirect URL.
func (h *harness) approveTxn(txnID, person string) *url.URL {
	h.t.Helper()
	w := h.consentPost("/api/oauth/txn/"+txnID+"/approve", person)
	require.Equal(h.t, http.StatusOK, w.Code, w.Body.String())
	return redirectOf(h.t, w)
}

func redirectOf(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	var resp struct {
		RedirectURL string `json:"redirect_url"`
	}
	decode(t, w, &resp)
	u, err := url.Parse(resp.RedirectURL)
	require.NoError(t, err)
	return u
}

// codeFor walks authorize and approve and returns the code with its verifier.
func (h *harness) codeFor(tc testClient, person, resource string) (string, string) {
	h.t.Helper()
	txnID, verifier := h.startTxn(tc, resource)
	return h.approveTxn(txnID, person).Query().Get("code"), verifier
}

// exchangeForm is the token request that trades code.
func exchangeForm(tc testClient, code, verifier string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {tc.redirect}, "code_verifier": {verifier},
	}
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// connect walks the whole flow for tc, person and resource and returns the tokens.
func (h *harness) connect(tc testClient, person, resource string) tokens {
	h.t.Helper()
	code, verifier := h.codeFor(tc, person, resource)
	return h.exchange(tc, code, verifier)
}

// exchange trades code for tokens, which must work.
func (h *harness) exchange(tc testClient, code, verifier string) tokens {
	h.t.Helper()
	w := h.clientPost("/oauth/token", tc, exchangeForm(tc, code, verifier))
	require.Equal(h.t, http.StatusOK, w.Code, w.Body.String())
	var tk tokens
	decode(h.t, w, &tk)
	return tk
}

func (h *harness) refresh(tc testClient, refreshToken string) *httptest.ResponseRecorder {
	return h.clientPost("/oauth/token", tc, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

// valid reports whether access is a live token of resource.
func (h *harness) valid(access, resource string) bool {
	_, err := h.srv.ValidateAccess(h.t.Context(), access, core.ResourceID(resource))
	return err == nil
}

func decode(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), v), w.Body.String())
}

// errorOf is the "error" of a JSON error answer.
func errorOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Error string `json:"error"`
	}
	decode(t, w, &resp)
	return resp.Error
}
