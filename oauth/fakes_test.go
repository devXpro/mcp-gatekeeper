package oauth

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// fakeData is the state behind fakeStore.
type fakeData struct {
	mu      sync.Mutex
	clients map[core.ClientID]core.OAuthClient
	codes   map[string]core.AuthCode
	grants  map[core.GrantID]core.Grant
	tokens  map[string]core.Token
	audit   []core.AuditEntry

	fail     map[string]error // a method name -> the error its calls return
	failOnce map[string]bool  // the failure of this method fires once
}

type fakeSnapshot struct {
	clients map[core.ClientID]core.OAuthClient
	codes   map[string]core.AuthCode
	grants  map[core.GrantID]core.Grant
	tokens  map[string]core.Token
	audit   []core.AuditEntry
}

func (d *fakeData) snapshot() fakeSnapshot {
	return fakeSnapshot{
		clients: maps.Clone(d.clients), codes: maps.Clone(d.codes), grants: maps.Clone(d.grants),
		tokens: maps.Clone(d.tokens), audit: slices.Clone(d.audit),
	}
}

func (d *fakeData) restore(s fakeSnapshot) {
	d.clients, d.codes, d.grants, d.tokens, d.audit = s.clients, s.codes, s.grants, s.tokens, s.audit
}

// failure returns the error set for method name. d.mu is held.
func (d *fakeData) failure(name string) error {
	err := d.fail[name]
	if err != nil && d.failOnce[name] {
		delete(d.fail, name)
		delete(d.failOnce, name)
	}
	return err
}

// revokeTokens revokes the live tokens that match. d.mu is held.
func (d *fakeData) revokeTokens(match func(core.Token) bool, at time.Time) {
	for k, t := range d.tokens {
		if match(t) && t.RevokedAt == nil {
			t.RevokedAt = &at
			d.tokens[k] = t
		}
	}
}

// fakeStore is store.Store with the OAuth and audit stores this package uses; the others are nil. It answers like
// the adapters of the store conformance suite: Tx rolls back when fn fails, a Tx inside a Tx joins it (the
// transaction travels in the context), and transactions run one at a time, so a call outside one waits for a running
// transaction.
type fakeStore struct {
	data *fakeData
	tx   *sync.Mutex // held for a whole transaction
}

var _ store.Store = (*fakeStore)(nil)

// fakeTxKey marks a context bound to a transaction of the fakeStore it holds.
type fakeTxKey struct{}

func newFakeStore() *fakeStore {
	return &fakeStore{
		data: &fakeData{
			clients: map[core.ClientID]core.OAuthClient{}, codes: map[string]core.AuthCode{},
			grants: map[core.GrantID]core.Grant{}, tokens: map[string]core.Token{},
			fail: map[string]error{}, failOnce: map[string]bool{},
		},
		tx: &sync.Mutex{},
	}
}

func (s *fakeStore) Accounts() store.AccountStore { return nil }
func (s *fakeStore) People() store.PersonStore    { return nil }
func (s *fakeStore) Passkeys() store.PasskeyStore { return nil }
func (s *fakeStore) Sessions() store.SessionStore { return nil }
func (s *fakeStore) Invites() store.InviteStore   { return nil }
func (s *fakeStore) OAuth() store.OAuthStore      { return fakeOAuth{s} }
func (s *fakeStore) Audit() store.AuditStore      { return fakeAudit{s} }
func (s *fakeStore) Close() error                 { return nil }

// inTx reports whether ctx is bound to a transaction of s.
func (s *fakeStore) inTx(ctx context.Context) bool {
	return ctx.Value(fakeTxKey{}) == s
}

func (s *fakeStore) Tx(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.inTx(ctx) {
		return fn(ctx)
	}
	s.tx.Lock()
	defer s.tx.Unlock()
	s.data.mu.Lock()
	snap := s.data.snapshot()
	s.data.mu.Unlock()
	if err := fn(context.WithValue(ctx, fakeTxKey{}, s)); err != nil {
		s.data.mu.Lock()
		s.data.restore(snap)
		s.data.mu.Unlock()
		return err
	}
	return nil
}

// lock is taken by every call. A call outside Tx first waits for a running transaction.
func (s *fakeStore) lock(ctx context.Context) func() {
	inTx := s.inTx(ctx)
	if !inTx {
		s.tx.Lock()
	}
	s.data.mu.Lock()
	return func() {
		s.data.mu.Unlock()
		if !inTx {
			s.tx.Unlock()
		}
	}
}

// failWith makes the calls of method fail with err: every call, or the next one only.
func (s *fakeStore) failWith(method string, err error, once bool) {
	defer s.lock(context.Background())()
	s.data.fail[method] = err
	s.data.failOnce[method] = once
}

func (s *fakeStore) client(id string) (core.OAuthClient, bool) {
	defer s.lock(context.Background())()
	c, ok := s.data.clients[core.ClientID(id)]
	return c, ok
}

func (s *fakeStore) deleteClient(id string) {
	defer s.lock(context.Background())()
	delete(s.data.clients, core.ClientID(id))
}

func (s *fakeStore) clientCount() int {
	defer s.lock(context.Background())()
	return len(s.data.clients)
}

func (s *fakeStore) code(raw string) (core.AuthCode, bool) {
	defer s.lock(context.Background())()
	c, ok := s.data.codes[string(hashOf(raw))]
	return c, ok
}

func (s *fakeStore) codeCount() int {
	defer s.lock(context.Background())()
	return len(s.data.codes)
}

func (s *fakeStore) grantList() []core.Grant {
	defer s.lock(context.Background())()
	out := slices.Collect(maps.Values(s.data.grants))
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *fakeStore) grant(id core.GrantID) core.Grant {
	defer s.lock(context.Background())()
	return s.data.grants[id]
}

func (s *fakeStore) token(raw string) (core.Token, bool) {
	defer s.lock(context.Background())()
	t, ok := s.data.tokens[string(hashOf(raw))]
	return t, ok
}

func (s *fakeStore) auditEntries() []core.AuditEntry {
	defer s.lock(context.Background())()
	return slices.Clone(s.data.audit)
}

// auditActions counts the audit entries by action.
func (s *fakeStore) auditActions() map[string]int {
	out := map[string]int{}
	for _, e := range s.auditEntries() {
		out[e.Action]++
	}
	return out
}

func fakeNotFound(what string) error { return fmt.Errorf("fake %s: %w", what, core.ErrNotFound) }

type fakeOAuth struct{ s *fakeStore }

func (o fakeOAuth) PutClient(ctx context.Context, c core.OAuthClient) error {
	defer o.s.lock(ctx)()
	d := o.s.data
	if err := d.failure("PutClient"); err != nil {
		return err
	}
	d.clients[c.ID] = c
	return nil
}

func (o fakeOAuth) GetClient(ctx context.Context, id core.ClientID) (core.OAuthClient, error) {
	defer o.s.lock(ctx)()
	d := o.s.data
	if err := d.failure("GetClient"); err != nil {
		return core.OAuthClient{}, err
	}
	c, ok := d.clients[id]
	if !ok {
		return core.OAuthClient{}, fakeNotFound("client")
	}
	return c, nil
}

func (o fakeOAuth) TouchClient(ctx context.Context, id core.ClientID, at time.Time) error {
	defer o.s.lock(ctx)()
	d := o.s.data
	c, ok := d.clients[id]
	if !ok {
		return fakeNotFound("client")
	}
	c.LastUsedAt = &at
	d.clients[id] = c
	return nil
}

func (o fakeOAuth) DeleteIdleClients(ctx context.Context, cutoff time.Time) (int, error) {
	defer o.s.lock(ctx)()
	d := o.s.data
	if err := d.failure("DeleteIdleClients"); err != nil {
		return 0, err
	}
	n := 0
	for id, c := range d.clients {
		if c.Kind != core.ClientDCR || !c.CreatedAt.Before(cutoff) {
			continue
		}
		used := false
		for _, g := range d.grants {
			used = used || g.ClientID == id
		}
		if !used {
			delete(d.clients, id)
			n++
		}
	}
	return n, nil
}

func (o fakeOAuth) PutCode(ctx context.Context, c core.AuthCode) error {
	defer o.s.lock(ctx)()
	d := o.s.data
	if err := d.failure("PutCode"); err != nil {
		return err
	}
	if _, ok := d.codes[string(c.CodeHash)]; ok {
		return fmt.Errorf("fake code: %w", core.ErrConflict)
	}
	d.codes[string(c.CodeHash)] = c
	return nil
}

// ConsumeCode deletes the code; an expired one is deleted too and answered core.ErrExpired, as the stores do.
func (o fakeOAuth) ConsumeCode(ctx context.Context, codeHash []byte, now time.Time) (core.AuthCode, error) {
	defer o.s.lock(ctx)()
	d := o.s.data
	c, ok := d.codes[string(codeHash)]
	if !ok {
		return core.AuthCode{}, fakeNotFound("code")
	}
	delete(d.codes, string(codeHash))
	if !c.ExpiresAt.After(now) {
		return core.AuthCode{}, fmt.Errorf("fake code: %w", core.ErrExpired)
	}
	return c, nil
}

// PutGrant inserts or replaces a grant; a second active grant of one (person, client, resource) is
// core.ErrConflict, the stores' unique index.
func (o fakeOAuth) PutGrant(ctx context.Context, g core.Grant) error {
	defer o.s.lock(ctx)()
	d := o.s.data
	if err := d.failure("PutGrant"); err != nil {
		return err
	}
	for _, other := range d.grants {
		if g.RevokedAt == nil && other.RevokedAt == nil && other.ID != g.ID && other.PersonID == g.PersonID &&
			other.ClientID == g.ClientID && other.ResourceID == g.ResourceID {
			return fmt.Errorf("fake grant: %w", core.ErrConflict)
		}
	}
	d.grants[g.ID] = g
	return nil
}

func (o fakeOAuth) GetGrant(ctx context.Context, id core.GrantID) (core.Grant, error) {
	defer o.s.lock(ctx)()
	d := o.s.data
	if err := d.failure("GetGrant"); err != nil {
		return core.Grant{}, err
	}
	g, ok := d.grants[id]
	if !ok {
		return core.Grant{}, fakeNotFound("grant")
	}
	return g, nil
}

func (o fakeOAuth) FindGrant(ctx context.Context, p core.PersonID, c core.ClientID, r core.ResourceID) (core.Grant, error) {
	defer o.s.lock(ctx)()
	d := o.s.data
	if err := d.failure("FindGrant"); err != nil {
		return core.Grant{}, err
	}
	for _, g := range d.grants {
		if g.RevokedAt == nil && g.PersonID == p && g.ClientID == c && g.ResourceID == r {
			return g, nil
		}
	}
	return core.Grant{}, fakeNotFound("grant")
}

func (o fakeOAuth) ListGrantsByAccount(ctx context.Context, a core.AccountID) ([]core.Grant, error) {
	defer o.s.lock(ctx)()
	var out []core.Grant
	for _, g := range o.s.data.grants {
		if g.AccountID == a && g.RevokedAt == nil {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (o fakeOAuth) TouchGrant(ctx context.Context, id core.GrantID, at time.Time) error {
	defer o.s.lock(ctx)()
	d := o.s.data
	if err := d.failure("TouchGrant"); err != nil {
		return err
	}
	g, ok := d.grants[id]
	if !ok {
		return fakeNotFound("grant")
	}
	g.LastUsedAt = &at
	d.grants[id] = g
	return nil
}

func (o fakeOAuth) RevokeGrant(ctx context.Context, id core.GrantID, at time.Time) error {
	defer o.s.lock(ctx)()
	d := o.s.data
	g, ok := d.grants[id]
	if !ok {
		return fakeNotFound("grant")
	}
	if g.RevokedAt == nil {
		g.RevokedAt = &at
		d.grants[id] = g
	}
	d.revokeTokens(func(t core.Token) bool { return t.GrantID == id }, at)
	return nil
}

func (o fakeOAuth) RevokeGrantsByResource(ctx context.Context, r core.ResourceID, at time.Time) error {
	defer o.s.lock(ctx)()
	d := o.s.data
	for id, g := range d.grants {
		if g.ResourceID != r {
			continue
		}
		if g.RevokedAt == nil {
			g.RevokedAt = &at
			d.grants[id] = g
		}
		d.revokeTokens(func(t core.Token) bool { return t.GrantID == id }, at)
	}
	return nil
}

func (o fakeOAuth) PutToken(ctx context.Context, t core.Token) error {
	defer o.s.lock(ctx)()
	d := o.s.data
	if err := d.failure("PutToken"); err != nil {
		return err
	}
	if _, ok := d.tokens[string(t.Hash)]; ok {
		return fmt.Errorf("fake token: %w", core.ErrConflict)
	}
	d.tokens[string(t.Hash)] = t
	return nil
}

func (o fakeOAuth) GetToken(ctx context.Context, hash []byte) (core.Token, error) {
	defer o.s.lock(ctx)()
	d := o.s.data
	if err := d.failure("GetToken"); err != nil {
		return core.Token{}, err
	}
	t, ok := d.tokens[string(hash)]
	if !ok {
		return core.Token{}, fakeNotFound("token")
	}
	return t, nil
}

// UseRefresh answers as the stores do: core.ErrUsed for a spent token, core.ErrNotFound for a revoked or unknown
// one or an access token, core.ErrExpired for an expired one.
func (o fakeOAuth) UseRefresh(ctx context.Context, hash []byte, at time.Time) (core.Token, error) {
	defer o.s.lock(ctx)()
	d := o.s.data
	t, ok := d.tokens[string(hash)]
	switch {
	case !ok, t.Kind != core.TokenRefresh:
		return core.Token{}, fakeNotFound("refresh token")
	case t.UsedAt != nil:
		return core.Token{}, fmt.Errorf("fake refresh token: %w", core.ErrUsed)
	case t.RevokedAt != nil:
		return core.Token{}, fakeNotFound("refresh token")
	case !t.ExpiresAt.After(at):
		return core.Token{}, fmt.Errorf("fake refresh token: %w", core.ErrExpired)
	}
	t.UsedAt = &at
	d.tokens[string(hash)] = t
	return t, nil
}

func (o fakeOAuth) RevokeToken(ctx context.Context, hash []byte, at time.Time) error {
	defer o.s.lock(ctx)()
	d := o.s.data
	t, ok := d.tokens[string(hash)]
	if !ok {
		return fakeNotFound("token")
	}
	if t.RevokedAt == nil {
		t.RevokedAt = &at
		d.tokens[string(hash)] = t
	}
	return nil
}

// RevokeFamily fails on a cancelled context, like a real store call, so tests see which context a revocation uses.
func (o fakeOAuth) RevokeFamily(ctx context.Context, family string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	defer o.s.lock(ctx)()
	o.s.data.revokeTokens(func(t core.Token) bool { return t.Family == family }, at)
	return nil
}

func (o fakeOAuth) DeleteExpiredTokens(ctx context.Context, now time.Time) (int, error) {
	defer o.s.lock(ctx)()
	d := o.s.data
	n := 0
	for k, t := range d.tokens {
		if !t.ExpiresAt.After(now) {
			delete(d.tokens, k)
			n++
		}
	}
	return n, nil
}

type fakeAudit struct{ s *fakeStore }

// Append fails on a cancelled context, like RevokeFamily.
func (a fakeAudit) Append(ctx context.Context, e core.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	defer a.s.lock(ctx)()
	d := a.s.data
	if err := d.failure("Append"); err != nil {
		return err
	}
	e.ID = fmt.Sprintf("%08d", len(d.audit)+1)
	d.audit = append(d.audit, e)
	return nil
}

func (a fakeAudit) ListByAccount(ctx context.Context, acc core.AccountID, before string, limit int) ([]core.AuditEntry, error) {
	return a.list(ctx, func(e core.AuditEntry) bool { return e.AccountID == acc }, before, limit), nil
}

func (a fakeAudit) ListSystem(ctx context.Context, before string, limit int) ([]core.AuditEntry, error) {
	return a.list(ctx, func(e core.AuditEntry) bool { return e.AccountID == "" }, before, limit), nil
}

func (a fakeAudit) list(ctx context.Context, match func(core.AuditEntry) bool, before string, limit int) []core.AuditEntry {
	defer a.s.lock(ctx)()
	var out []core.AuditEntry
	for i := len(a.s.data.audit) - 1; i >= 0 && len(out) < limit; i-- {
		if e := a.s.data.audit[i]; match(e) && (before == "" || e.ID < before) {
			out = append(out, e)
		}
	}
	return out
}

// testCookie names the viewer of a request to fakeSessions.
const testCookie = "fh_test"

// fakeSessions signs a request in by the cookie testCookie, whose value is a key of viewers. With a clock, a
// session's step-up is fresh for 5 minutes from now, as package auth makes it after a sign-in, unless the person is
// marked stale. Its RequireViewer keeps the contract of core.Sessions: a mutating request first passes the CSRF
// checks of docs/PLAN.md §4.4 (403 forbidden), then a request without a session is 401 no_session.
type fakeSessions struct {
	viewers map[string]core.Viewer
	clock   *fakeClock

	mu    sync.Mutex
	stale map[string]bool // persons whose session stepped up longer than 5 minutes ago
}

var _ core.Sessions = (*fakeSessions)(nil)

func (f *fakeSessions) Viewer(r *http.Request) (core.Viewer, error) {
	c, err := r.Cookie(testCookie)
	if err != nil {
		return core.Viewer{}, core.ErrNoSession
	}
	v, ok := f.viewers[c.Value]
	if !ok {
		return core.Viewer{}, core.ErrNoSession
	}
	f.mu.Lock()
	stale := f.stale[c.Value]
	f.mu.Unlock()
	if f.clock != nil && !stale {
		v.Session.StepUpUntil = f.clock.now().Add(5 * time.Minute)
	}
	return v, nil
}

// setStale makes person's session one whose step-up is no longer fresh, or fresh again.
func (f *fakeSessions) setStale(person string, stale bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stale[person] = stale
}

func (f *fakeSessions) RequireViewer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sameOriginWrite(r) {
			httpsec.WriteError(w, http.StatusForbidden, httpsec.CodeForbidden, "cross-site request")
			return
		}
		v, err := f.Viewer(r)
		if err != nil {
			httpsec.WriteError(w, http.StatusUnauthorized, httpsec.CodeNoSession, "sign in")
			return
		}
		next.ServeHTTP(w, r.WithContext(core.WithViewer(r.Context(), v)))
	})
}

func (f *fakeSessions) RequireStepUp(next http.Handler) http.Handler { return next }

func (f *fakeSessions) SameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sameOriginWrite(r) {
			httpsec.WriteError(w, http.StatusForbidden, httpsec.CodeForbidden, "cross-site request")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOriginWrite is the check package auth's RequireViewer makes of a mutating request (docs/PLAN.md §4.4): the
// brand's CSRF header with "1", and an Origin and a Sec-Fetch-Site naming the site whenever they are sent.
func sameOriginWrite(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if r.Header.Get(testBrand.CSRFHeader) != "1" {
		return false
	}
	if o := r.Header.Values("Origin"); len(o) > 1 || (len(o) == 1 && o[0] != hubURL) {
		return false
	}
	sf := r.Header.Values("Sec-Fetch-Site")
	return len(sf) == 0 || (len(sf) == 1 && sf[0] == "same-origin")
}

// fakeCatalog is core.ResourceCatalog over a map. A resource that is not live is not found, as a Family Hub module
// that does not run.
type fakeCatalog struct {
	mu        sync.Mutex
	resources map[core.ResourceID]core.ResourceInfo
	live      map[core.ResourceID]bool
	enabled   map[core.AccountID][]core.ResourceID
	err       error // every call fails with it while set
	availErr  error // Available alone fails with it while set
}

var _ core.ResourceCatalog = (*fakeCatalog)(nil)

func newFakeCatalog() *fakeCatalog {
	return &fakeCatalog{
		resources: map[core.ResourceID]core.ResourceInfo{},
		live:      map[core.ResourceID]bool{},
		enabled:   map[core.AccountID][]core.ResourceID{},
	}
}

func (f *fakeCatalog) add(info core.ResourceInfo, live bool, enabledIn ...core.AccountID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resources[info.ID] = info
	f.live[info.ID] = live
	for _, a := range enabledIn {
		f.enabled[a] = append(f.enabled[a], info.ID)
	}
}

func (f *fakeCatalog) setLive(id core.ResourceID, live bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.live[id] = live
}

func (f *fakeCatalog) setError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeCatalog) setAvailableError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.availErr = err
}

func (f *fakeCatalog) Resource(_ context.Context, id core.ResourceID) (core.ResourceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return core.ResourceInfo{}, f.err
	}
	info, ok := f.resources[id]
	if !ok || !f.live[id] {
		return core.ResourceInfo{}, fakeNotFound("resource")
	}
	return info, nil
}

func (f *fakeCatalog) Available(_ context.Context, a core.AccountID, id core.ResourceID) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	if f.availErr != nil {
		return false, f.availErr
	}
	return slices.Contains(f.enabled[a], id), nil
}

// fakeFetcher serves client metadata documents from a map, so no test fetches a real one.
type fakeFetcher struct {
	mu        sync.Mutex
	docs      map[string]string
	errs      map[string]error
	calls     map[string]int
	deadlines map[string]time.Time
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{
		docs: map[string]string{}, errs: map[string]error{}, calls: map[string]int{}, deadlines: map[string]time.Time{},
	}
}

func (f *fakeFetcher) set(rawURL, doc string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.docs[rawURL] = doc
	delete(f.errs, rawURL)
}

func (f *fakeFetcher) fail(rawURL string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[rawURL] = err
}

func (f *fakeFetcher) count(rawURL string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[rawURL]
}

func (f *fakeFetcher) deadline(rawURL string) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deadlines[rawURL]
}

func (f *fakeFetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[rawURL]++
	if dl, ok := ctx.Deadline(); ok {
		f.deadlines[rawURL] = dl
	}
	if err := f.errs[rawURL]; err != nil {
		return nil, err
	}
	doc, ok := f.docs[rawURL]
	if !ok {
		return nil, errors.New("fake fetch: status 404")
	}
	return []byte(doc), nil
}

// fakeClock is a core.Clock that moves only when told.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}
