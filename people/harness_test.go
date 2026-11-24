package people_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
	"github.com/devXpro/mcp-gatekeeper/internal/testlog"
	"github.com/devXpro/mcp-gatekeeper/people"
	"github.com/devXpro/mcp-gatekeeper/people/internal/memstore"
	"github.com/devXpro/mcp-gatekeeper/store"
)

const (
	publicURL  = "https://hub.test"
	cookieName = "__Host-fh_session"
	csrfHeader = "X-Family-Hub"
	inviteTTL  = 24 * time.Hour
)

var brand = core.Brand{Product: "Family Hub", SessionCookie: cookieName, TxnCookie: "__Host-fh_txn",
	CSRFHeader: csrfHeader}

func coreSite() core.Site {
	return core.Site{PublicURL: publicURL, RPID: "hub.test", ClientIP: core.ClientIPRemote}
}

// --- the name rule (package auth's, as far as these tests need it) ---

var errInvalidName = errors.New("invalid name")

func normalizeName(v string) (string, error) {
	v = strings.TrimSpace(v)
	if n := utf8.RuneCountInString(v); n < 1 || n > 40 {
		return "", fmt.Errorf("%w: it must be 1 to 40 characters", errInvalidName)
	}
	if strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) || strings.ContainsRune("\"\\`", r) }) {
		return "", fmt.Errorf("%w: it must not contain control characters, line breaks, quotes, backslashes or "+
			"backticks", errInvalidName)
	}
	return v, nil
}

// --- core.Sessions over the store: cookie → session → viewer, the CSRF checks and step-up ---

type fakeSessions struct{ st store.Store }

var _ core.Sessions = fakeSessions{}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func (f fakeSessions) Viewer(r *http.Request) (core.Viewer, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return core.Viewer{}, core.ErrNoSession
	}
	ctx := r.Context()
	s, err := f.st.Sessions().Get(ctx, hashToken(c.Value))
	if err != nil || !time.Now().Before(s.ExpiresAt) {
		return core.Viewer{}, core.ErrNoSession
	}
	p, err := f.st.People().Get(ctx, s.PersonID)
	if err != nil {
		return core.Viewer{}, core.ErrNoSession
	}
	acc, err := f.st.Accounts().Get(ctx, p.AccountID)
	if err != nil {
		return core.Viewer{}, core.ErrNoSession
	}
	return core.Viewer{Person: p, Account: acc, Session: s}, nil
}

func sameOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if r.Header.Get(csrfHeader) != "1" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != publicURL {
		return false
	}
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" {
		return false
	}
	return true
}

func (f fakeSessions) SameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			httpsec.WriteError(w, http.StatusForbidden, httpsec.CodeForbidden, "cross-site request")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (f fakeSessions) RequireViewer(next http.Handler) http.Handler {
	return f.SameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, err := f.Viewer(r)
		if err != nil {
			httpsec.WriteError(w, http.StatusUnauthorized, httpsec.CodeNoSession, "sign in first")
			return
		}
		next.ServeHTTP(w, r.WithContext(core.WithViewer(r.Context(), v)))
	}))
}

func (f fakeSessions) RequireStepUp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, _ := core.ViewerFrom(r.Context())
		if !time.Now().Before(v.Session.StepUpUntil) {
			httpsec.WriteError(w, http.StatusForbidden, httpsec.CodeStepUp, "confirm with your passkey")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- the inviter (package auth's IssueInvite and IssueInviteIn) ---

type fakeInviter struct{ st store.Store }

func (f fakeInviter) IssueInvite(ctx context.Context, kind core.InviteKind, account core.AccountID, name string,
	by core.PersonID) (people.IssuedInvite, error) {
	return f.IssueInviteIn(ctx, f.st, kind, account, name, by)
}

func (f fakeInviter) IssueInviteIn(ctx context.Context, st store.Store, kind core.InviteKind,
	account core.AccountID, name string, by core.PersonID) (people.IssuedInvite, error) {
	if kind != core.InviteOwner && kind != core.InviteMember {
		return people.IssuedInvite{}, fmt.Errorf("auth: invites of kind %q are not issued here", kind)
	}
	if account == "" || by == "" {
		return people.IssuedInvite{}, errors.New("auth: an invite needs an account and the person who asks")
	}
	name, err := normalizeName(name)
	if err != nil {
		return people.IssuedInvite{}, err
	}
	if _, err := st.Accounts().Get(ctx, account); err != nil {
		return people.IssuedInvite{}, fmt.Errorf("auth: invite to account %s: %w", account, err)
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token, now := base64.RawURLEncoding.EncodeToString(b), time.Now().UTC()
	inv := core.Invite{ID: core.NewID(core.PrefixInvite), TokenHash: hashToken(token), Kind: kind, AccountID: account,
		Name: name, CreatedBy: by, CreatedAt: now, ExpiresAt: now.Add(inviteTTL)}
	if err := st.Invites().Create(ctx, inv); err != nil {
		return people.IssuedInvite{}, fmt.Errorf("auth: store an invite: %w", err)
	}
	return people.IssuedInvite{ID: inv.ID, URL: publicURL + "/join#t=" + token, ExpiresAt: inv.ExpiresAt}, nil
}

// --- the grant revoker ((*oauth.Server).RevokeGrant): revokes in the store and audits oauth.grant.revoke ---

type fakeRevoker struct {
	st    store.Store
	mu    sync.Mutex
	calls []core.GrantID
}

func (f *fakeRevoker) RevokeGrant(ctx context.Context, id core.GrantID, actor core.PersonID, ip string) error {
	f.mu.Lock()
	f.calls = append(f.calls, id)
	f.mu.Unlock()
	g, err := f.st.OAuth().GetGrant(ctx, id)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := f.st.OAuth().RevokeGrant(ctx, id, now); err != nil {
		return err
	}
	return f.st.Audit().Append(ctx, core.AuditEntry{At: now, AccountID: g.AccountID, Actor: actor,
		Action: "oauth.grant.revoke", Target: string(id), IP: ip})
}

func (f *fakeRevoker) Calls() []core.GrantID {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// --- the application: its fields, its eraser and its own connections (what Family Hub plugs in) ---

// erasure is one EraseAccount call.
type erasure struct {
	Account   core.AccountID
	Actor     core.PersonID
	Cancelled bool // the context was cancelled when the call came
}

// fakeApp is an application with "modules": each account has a list of modules, the eraser erases the account from
// each, and the connections are legacy keys with "lk_" ids that only the owner deletes.
type fakeApp struct {
	st store.Store

	mu       sync.Mutex
	modules  map[core.AccountID][]string
	eraseErr error
	erased   []erasure
	keys     map[string]people.Connection // by id
	fields   map[string]any               // extra AccountFields, e.g. a reserved key
}

func newFakeApp(st store.Store) *fakeApp {
	return &fakeApp{st: st, modules: map[core.AccountID][]string{}, keys: map[string]people.Connection{}}
}

func (a *fakeApp) setModules(acc core.AccountID, ids ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.modules[acc] = ids
}

func (a *fakeApp) setEraseErr(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.eraseErr = err
}

func (a *fakeApp) erasures() []erasure {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.erased)
}

func (a *fakeApp) AccountFields(_ context.Context, v core.Viewer) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	mods := []map[string]any{}
	for _, id := range a.modules[v.Account.ID] {
		mods = append(mods, map[string]any{"id": id, "enabled": true})
	}
	out := map[string]any{"modules": mods}
	maps.Copy(out, a.fields)
	return out, nil
}

func (a *fakeApp) SummaryFields(_ context.Context, acc core.AccountID) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]any{"modules": len(a.modules[acc])}, nil
}

func (a *fakeApp) EraseAccount(ctx context.Context, acc core.AccountID, actor core.PersonID) (map[string]string,
	error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.erased = append(a.erased, erasure{Account: acc, Actor: actor, Cancelled: ctx.Err() != nil})
	if a.eraseErr != nil {
		return nil, a.eraseErr
	}
	ids := slices.Sorted(slices.Values(a.modules[acc]))
	return map[string]string{"modules": strings.Join(ids, ",")}, nil
}

// moduleFailure is the error Family Hub's eraser answers when module m did not erase the account.
func moduleFailure(m string) error {
	return &people.EraseError{Detail: map[string]string{"module": m}, Err: &people.APIError{
		Status: http.StatusBadGateway, Code: httpsec.CodeUpstream,
		Message: "the module " + m + " did not erase the account; try again later",
		Extra:   map[string]string{"module": m}}}
}

func (a *fakeApp) addKey(c people.Connection) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.keys[c.ID] = c
}

func (a *fakeApp) Connections(_ context.Context, _ core.Viewer, members []core.Person) ([]people.Connection,
	error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []people.Connection
	for _, c := range a.keys {
		if slices.ContainsFunc(members, func(p core.Person) bool { return p.ID == c.PersonID }) {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(x, y people.Connection) int { return x.CreatedAt.Compare(y.CreatedAt) })
	return out, nil
}

func (a *fakeApp) Owns(id string) bool { return strings.HasPrefix(id, "lk_") }

func (a *fakeApp) Revoke(ctx context.Context, v core.Viewer, id, ip string) error {
	a.mu.Lock()
	c, ok := a.keys[id]
	a.mu.Unlock()
	if ok {
		p, err := a.st.People().Get(ctx, c.PersonID)
		ok = err == nil && p.AccountID == v.Account.ID
	}
	switch {
	case !ok || v.Person.Role != core.RoleOwner && c.PersonID != v.Person.ID:
		return people.ErrNoConnection
	case v.Person.Role != core.RoleOwner:
		return people.ErrOwnerOnly
	}
	a.mu.Lock()
	delete(a.keys, id)
	a.mu.Unlock()
	return a.st.Audit().Append(ctx, core.AuditEntry{At: time.Now(), AccountID: v.Account.ID, Actor: v.Person.ID,
		Action: "account.legacy-key.revoke", Target: string(c.PersonID), IP: ip,
		Detail: map[string]string{"label": c.Label, "key": id}})
}

// --- the environment ---

// env is the API over the in-memory store, fake sessions with the real rules, and the fakes above.
type env struct {
	t    *testing.T
	st   *memstore.Store
	app  *fakeApp
	rev  *fakeRevoker
	svc  *people.Service
	mux  *http.ServeMux
	logs *testlog.Recorder
	seq  int
}

// at returns a creation time later than the previous one, so records sort in the order a test makes them.
func (e *env) at() time.Time {
	e.seq++
	return time.Now().UTC().Add(time.Duration(e.seq) * time.Millisecond)
}

// newEnv wires the service with every extension of fakeApp; edit changes the options first.
func newEnv(t *testing.T, edit ...func(*people.Options)) *env {
	t.Helper()
	log, logs := testlog.New()
	st := memstore.New()
	app, rev := newFakeApp(st), &fakeRevoker{st: st}
	o := people.Options{Site: coreSite(), Brand: brand, Sessions: fakeSessions{st: st}, Store: st,
		Inviter: fakeInviter{st: st}, Revoker: rev, NormalizeName: normalizeName, Eraser: app, Fields: app,
		Summaries: app, Connections: app, Log: log}
	for _, f := range edit {
		f(&o)
	}
	svc, err := people.New(o)
	require.NoError(t, err)
	mux := http.NewServeMux()
	svc.RegisterRoutes(mux)
	return &env{t: t, st: st, app: app, rev: rev, svc: svc, mux: mux, logs: logs}
}

// account makes an account with an owner (and, if superadmin, the owner is the superadmin).
func (e *env) account(name, owner string, superadmin bool) (core.Account, core.Person) {
	e.t.Helper()
	acc := core.Account{ID: core.AccountID(core.NewID(core.PrefixAccount)), Name: name, CreatedAt: e.at()}
	require.NoError(e.t, e.st.Accounts().Create(e.t.Context(), acc))
	return acc, e.person(acc, owner, core.RoleOwner, superadmin)
}

func (e *env) person(acc core.Account, name string, role core.Role, superadmin bool) core.Person {
	e.t.Helper()
	p := core.Person{ID: core.PersonID(core.NewID(core.PrefixPerson)), AccountID: acc.ID, Name: name, Role: role,
		Superadmin: superadmin, CreatedAt: e.at()}
	require.NoError(e.t, e.st.People().Create(e.t.Context(), p))
	return p
}

// session signs p in and returns the cookie value; stepUp gives it a fresh step-up.
func (e *env) session(p core.Person, stepUp bool) string {
	e.t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now().UTC()
	s := core.Session{IDHash: hashToken(token), PersonID: p.ID, CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(time.Hour)}
	if stepUp {
		s.StepUpUntil = now.Add(5 * time.Minute)
	}
	require.NoError(e.t, e.st.Sessions().Create(e.t.Context(), s))
	return token
}

type reqOpt func(*http.Request)

// noCSRF drops the CSRF header.
func noCSRF(r *http.Request) { r.Header.Del(csrfHeader) }

// do sends a request with the session token (none when ""); writes carry the CSRF header and a same-site Origin.
func (e *env) do(method, path string, body any, token string, opts ...reqOpt) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(e.t, err)
		rd = bytes.NewReader(raw)
	}
	r := httptest.NewRequestWithContext(e.t.Context(), method, path, rd)
	r.RemoteAddr = "198.51.100.7:4242"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		r.Header.Set(csrfHeader, "1")
		r.Header.Set("Origin", publicURL)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if token != "" {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: token, Secure: true, HttpOnly: true,
			SameSite: http.SameSiteStrictMode})
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

// errCode returns the code of an error answer.
func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), w.Body.String())
	return body.Error
}

func decodeJSON[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &v), w.Body.String())
	return v
}

// grant makes an active grant of p for notes by a client of assistant.
func (e *env) grant(p core.Person, assistant core.Assistant) core.Grant {
	e.t.Helper()
	cl := core.OAuthClient{ID: core.ClientID(core.NewID(core.PrefixClient)), Kind: core.ClientDCR, Assistant: assistant,
		Name: string(assistant) + " client", CreatedAt: time.Now().UTC()}
	require.NoError(e.t, e.st.OAuth().PutClient(e.t.Context(), cl))
	g := core.Grant{ID: core.GrantID(core.NewID(core.PrefixGrant)), PersonID: p.ID, AccountID: p.AccountID,
		ClientID: cl.ID, ResourceID: "notes", Scope: "mcp", CreatedAt: e.at()}
	require.NoError(e.t, e.st.OAuth().PutGrant(e.t.Context(), g))
	return g
}

// auditActions returns the actions of the audit entries of account a ("" is the system).
func (e *env) auditActions(a core.AccountID) []string {
	var out []string
	for _, en := range e.st.AuditEntries() {
		if en.AccountID == a {
			out = append(out, en.Action)
		}
	}
	return out
}

func mapValues(m map[string]string) []string { return slices.Collect(maps.Values(m)) }
