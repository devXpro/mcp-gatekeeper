package auth

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// fakeStore is an in-memory store.Store with the semantics of Family Hub's internal/store (T1.1) for what auth uses:
// accounts, people, passkeys, sessions, invites and audit, plus the grants reset-access touches. The rest of the
// OAuth store answers ErrNotFound or nothing. It also keeps Family Hub's modules and legacy keys, which belong to the
// application: the tests reach them through a ResetStep (legacyStep).
//
//   - Times are kept at millisecond precision in UTC, as MongoDB keeps them.
//   - Invites.Peek and Consume: unknown or revoked ErrNotFound, used ErrUsed, expired ErrExpired.
//   - Sessions.Get returns the raw record; Sessions.Delete and every *ByPerson are idempotent; other single writes to
//     a missing record are ErrNotFound; repeated ids (and credential ids) are ErrConflict.
//   - Invites.ListByAccount returns unused, unrevoked invites, expired ones included.
//   - CountSuperadmins counts disabled superadmins too.
//   - Tx runs fn under one lock, with a context that marks the transaction, and restores everything when fn fails;
//     a Tx inside it joins it. A call with a context outside the transaction while one runs waits for the lock, so
//     code that forgets the transaction's context hangs the test instead of passing. With replay set, Tx runs fn,
//     rolls it back and runs it again, as the driver may on a transient error.
//
// fail makes a method ("Sessions.Create", "Tx", …) return an error, for the error paths.
type fakeStore struct {
	mu  *sync.Mutex
	d   *fakeData
	ctl *fakeControl
}

type fakeControl struct {
	mu     sync.Mutex
	fail   map[string]error
	replay bool
	txRuns int
}

// legacyKey is Family Hub's legacy Site key, as far as reset-access cares.
type legacyKey struct {
	Hash     []byte
	ModuleID string
	PersonID core.PersonID
	Label    string
}

type fakeData struct {
	accounts   map[core.AccountID]core.Account
	people     map[core.PersonID]core.Person
	passkeys   map[string]core.Passkey
	sessions   map[string]core.Session // by string(IDHash)
	invites    map[string]core.Invite
	grants     map[core.GrantID]core.Grant
	modules    map[string]bool
	legacyKeys map[string]legacyKey // by string(Hash)
	audit      []core.AuditEntry
	auditSeq   int
}

func newFakeStore() *fakeStore {
	return &fakeStore{mu: &sync.Mutex{}, ctl: &fakeControl{fail: map[string]error{}}, d: &fakeData{
		accounts: map[core.AccountID]core.Account{}, people: map[core.PersonID]core.Person{},
		passkeys: map[string]core.Passkey{}, sessions: map[string]core.Session{}, invites: map[string]core.Invite{},
		grants: map[core.GrantID]core.Grant{}, modules: map[string]bool{}, legacyKeys: map[string]legacyKey{},
	}}
}

var _ store.Store = (*fakeStore)(nil)

func (s *fakeStore) setFail(method string, err error) {
	s.ctl.mu.Lock()
	defer s.ctl.mu.Unlock()
	if err == nil {
		delete(s.ctl.fail, method)
		return
	}
	s.ctl.fail[method] = err
}

func (s *fakeStore) setReplay(on bool) {
	s.ctl.mu.Lock()
	defer s.ctl.mu.Unlock()
	s.ctl.replay = on
}

func (s *fakeStore) failure(method string) error {
	s.ctl.mu.Lock()
	defer s.ctl.mu.Unlock()
	return s.ctl.fail[method]
}

// txKey marks the context of a transaction of one fakeStore.
type txKey struct{}

func (s *fakeStore) inTx(ctx context.Context) bool {
	tx, _ := ctx.Value(txKey{}).(*fakeStore)
	return tx == s
}

// lock takes the store lock unless ctx is inside a Tx, which holds it already.
func (s *fakeStore) lock(ctx context.Context) func() {
	if s.inTx(ctx) {
		return func() {}
	}
	s.mu.Lock()
	return s.mu.Unlock
}

func (d *fakeData) clone() *fakeData {
	return &fakeData{
		accounts: maps.Clone(d.accounts), people: maps.Clone(d.people), passkeys: maps.Clone(d.passkeys),
		sessions: maps.Clone(d.sessions), invites: maps.Clone(d.invites), audit: slices.Clone(d.audit),
		auditSeq: d.auditSeq, grants: maps.Clone(d.grants), modules: maps.Clone(d.modules),
		legacyKeys: maps.Clone(d.legacyKeys),
	}
}

// ms is how the store keeps times: UTC, milliseconds.
func ms(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return time.UnixMilli(t.UnixMilli()).UTC()
}

func msPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := ms(*t)
	return &v
}

func (s *fakeStore) Tx(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.inTx(ctx) {
		return fn(ctx)
	}
	if err := s.failure("Tx"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctl.mu.Lock()
	replay := s.ctl.replay
	s.ctl.txRuns++
	s.ctl.mu.Unlock()
	tx := context.WithValue(ctx, txKey{}, s)
	snapshot := s.d.clone()
	if replay {
		_ = fn(tx)
		*s.d = *snapshot.clone()
	}
	if err := fn(tx); err != nil {
		*s.d = *snapshot
		return err
	}
	return nil
}

func (s *fakeStore) Close() error { return nil }

func (s *fakeStore) Accounts() store.AccountStore { return fakeAccounts{s} }
func (s *fakeStore) People() store.PersonStore    { return fakePeople{s} }
func (s *fakeStore) Passkeys() store.PasskeyStore { return fakePasskeys{s} }
func (s *fakeStore) Sessions() store.SessionStore { return fakeSessions{s} }
func (s *fakeStore) Invites() store.InviteStore   { return fakeInvites{s} }
func (s *fakeStore) OAuth() store.OAuthStore      { return fakeOAuth{s} }
func (s *fakeStore) Audit() store.AuditStore      { return fakeAudit{s} }

func notFound(what string) error { return fmt.Errorf("fake %s: %w", what, core.ErrNotFound) }

// --- accounts ---

type fakeAccounts struct{ s *fakeStore }

func (r fakeAccounts) Create(ctx context.Context, a core.Account) error {
	if err := r.s.failure("Accounts.Create"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.accounts[a.ID]; ok || a.ID == "" {
		return fmt.Errorf("fake account %q: %w", a.ID, core.ErrConflict)
	}
	a.CreatedAt = ms(a.CreatedAt)
	r.s.d.accounts[a.ID] = a
	return nil
}

func (r fakeAccounts) Get(ctx context.Context, id core.AccountID) (core.Account, error) {
	if err := r.s.failure("Accounts.Get"); err != nil {
		return core.Account{}, err
	}
	defer r.s.lock(ctx)()
	a, ok := r.s.d.accounts[id]
	if !ok {
		return core.Account{}, notFound("account")
	}
	return a, nil
}

func (r fakeAccounts) List(ctx context.Context) ([]core.Account, error) {
	if err := r.s.failure("Accounts.List"); err != nil {
		return nil, err
	}
	defer r.s.lock(ctx)()
	out := slices.Collect(maps.Values(r.s.d.accounts))
	slices.SortFunc(out, func(x, y core.Account) int {
		return cmp.Or(x.CreatedAt.Compare(y.CreatedAt), cmp.Compare(x.ID, y.ID))
	})
	return out, nil
}

func (r fakeAccounts) Rename(ctx context.Context, id core.AccountID, name string) error {
	if err := r.s.failure("Accounts.Rename"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	a, ok := r.s.d.accounts[id]
	if !ok {
		return notFound("account")
	}
	a.Name = name
	r.s.d.accounts[id] = a
	return nil
}

func (r fakeAccounts) Delete(ctx context.Context, id core.AccountID) error {
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.accounts[id]; !ok {
		return notFound("account")
	}
	delete(r.s.d.accounts, id)
	for pid, p := range r.s.d.people {
		if p.AccountID == id {
			r.s.d.deletePerson(pid)
		}
	}
	maps.DeleteFunc(r.s.d.invites, func(_ string, inv core.Invite) bool { return inv.AccountID == id })
	return nil
}

// --- people ---

type fakePeople struct{ s *fakeStore }

func (r fakePeople) Create(ctx context.Context, p core.Person) error {
	if err := r.s.failure("People.Create"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.people[p.ID]; ok || p.ID == "" {
		return fmt.Errorf("fake person %q: %w", p.ID, core.ErrConflict)
	}
	p.CreatedAt, p.DisabledAt = ms(p.CreatedAt), msPtr(p.DisabledAt)
	r.s.d.people[p.ID] = p
	return nil
}

func (r fakePeople) Get(ctx context.Context, id core.PersonID) (core.Person, error) {
	if err := r.s.failure("People.Get"); err != nil {
		return core.Person{}, err
	}
	defer r.s.lock(ctx)()
	p, ok := r.s.d.people[id]
	if !ok {
		return core.Person{}, notFound("person")
	}
	return p, nil
}

func (r fakePeople) ListByAccount(ctx context.Context, a core.AccountID) ([]core.Person, error) {
	if err := r.s.failure("People.ListByAccount"); err != nil {
		return nil, err
	}
	defer r.s.lock(ctx)()
	var out []core.Person
	for _, p := range r.s.d.people {
		if p.AccountID == a {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(x, y core.Person) int {
		return cmp.Or(x.CreatedAt.Compare(y.CreatedAt), cmp.Compare(x.ID, y.ID))
	})
	return out, nil
}

func (r fakePeople) CountSuperadmins(ctx context.Context) (int, error) {
	if err := r.s.failure("People.CountSuperadmins"); err != nil {
		return 0, err
	}
	defer r.s.lock(ctx)()
	n := 0
	for _, p := range r.s.d.people {
		if p.Superadmin {
			n++
		}
	}
	return n, nil
}

func (r fakePeople) Rename(ctx context.Context, id core.PersonID, name string) error {
	defer r.s.lock(ctx)()
	p, ok := r.s.d.people[id]
	if !ok {
		return notFound("person")
	}
	p.Name = name
	r.s.d.people[id] = p
	return nil
}

func (r fakePeople) Disable(ctx context.Context, id core.PersonID, at time.Time) error {
	defer r.s.lock(ctx)()
	p, ok := r.s.d.people[id]
	if !ok {
		return notFound("person")
	}
	p.DisabledAt = msPtr(&at)
	r.s.d.people[id] = p
	return nil
}

func (r fakePeople) Delete(ctx context.Context, id core.PersonID) error {
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.people[id]; !ok {
		return notFound("person")
	}
	r.s.d.deletePerson(id)
	return nil
}

func (d *fakeData) deletePerson(id core.PersonID) {
	delete(d.people, id)
	maps.DeleteFunc(d.passkeys, func(_ string, pk core.Passkey) bool { return pk.PersonID == id })
	maps.DeleteFunc(d.sessions, func(_ string, s core.Session) bool { return s.PersonID == id })
}

// --- passkeys ---

type fakePasskeys struct{ s *fakeStore }

func copyPasskey(k core.Passkey) core.Passkey {
	k.CredentialID, k.Data = bytes.Clone(k.CredentialID), bytes.Clone(k.Data)
	if k.LastUsedAt != nil {
		v := *k.LastUsedAt
		k.LastUsedAt = &v
	}
	return k
}

func (r fakePasskeys) Add(ctx context.Context, k core.Passkey) error {
	if err := r.s.failure("Passkeys.Add"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.passkeys[k.ID]; ok || k.ID == "" {
		return fmt.Errorf("fake passkey %q: %w", k.ID, core.ErrConflict)
	}
	for _, other := range r.s.d.passkeys {
		if bytes.Equal(other.CredentialID, k.CredentialID) {
			return fmt.Errorf("fake passkey credential: %w", core.ErrConflict)
		}
	}
	k = copyPasskey(k)
	k.CreatedAt, k.LastUsedAt = ms(k.CreatedAt), msPtr(k.LastUsedAt)
	r.s.d.passkeys[k.ID] = k
	return nil
}

func (r fakePasskeys) Get(ctx context.Context, id string) (core.Passkey, error) {
	if err := r.s.failure("Passkeys.Get"); err != nil {
		return core.Passkey{}, err
	}
	defer r.s.lock(ctx)()
	k, ok := r.s.d.passkeys[id]
	if !ok {
		return core.Passkey{}, notFound("passkey")
	}
	return copyPasskey(k), nil
}

func (r fakePasskeys) GetByCredentialID(ctx context.Context, credentialID []byte) (core.Passkey, error) {
	if err := r.s.failure("Passkeys.GetByCredentialID"); err != nil {
		return core.Passkey{}, err
	}
	defer r.s.lock(ctx)()
	for _, k := range r.s.d.passkeys {
		if bytes.Equal(k.CredentialID, credentialID) {
			return copyPasskey(k), nil
		}
	}
	return core.Passkey{}, notFound("passkey")
}

func (r fakePasskeys) ListByPerson(ctx context.Context, p core.PersonID) ([]core.Passkey, error) {
	if err := r.s.failure("Passkeys.ListByPerson"); err != nil {
		return nil, err
	}
	defer r.s.lock(ctx)()
	var out []core.Passkey
	for _, k := range r.s.d.passkeys {
		if k.PersonID == p {
			out = append(out, copyPasskey(k))
		}
	}
	slices.SortFunc(out, func(x, y core.Passkey) int {
		return cmp.Or(x.CreatedAt.Compare(y.CreatedAt), cmp.Compare(x.ID, y.ID))
	})
	return out, nil
}

func (r fakePasskeys) Update(ctx context.Context, id string, data []byte, lastUsed time.Time) error {
	if err := r.s.failure("Passkeys.Update"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	k, ok := r.s.d.passkeys[id]
	if !ok {
		return notFound("passkey")
	}
	k.Data, k.LastUsedAt = bytes.Clone(data), msPtr(&lastUsed)
	r.s.d.passkeys[id] = k
	return nil
}

func (r fakePasskeys) Rename(ctx context.Context, id, name string) error {
	if err := r.s.failure("Passkeys.Rename"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	k, ok := r.s.d.passkeys[id]
	if !ok {
		return notFound("passkey")
	}
	k.Name = name
	r.s.d.passkeys[id] = k
	return nil
}

func (r fakePasskeys) Delete(ctx context.Context, id string) error {
	if err := r.s.failure("Passkeys.Delete"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.passkeys[id]; !ok {
		return notFound("passkey")
	}
	delete(r.s.d.passkeys, id)
	return nil
}

func (r fakePasskeys) DeleteByPerson(ctx context.Context, p core.PersonID) error {
	if err := r.s.failure("Passkeys.DeleteByPerson"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	maps.DeleteFunc(r.s.d.passkeys, func(_ string, k core.Passkey) bool { return k.PersonID == p })
	return nil
}

// --- sessions ---

type fakeSessions struct{ s *fakeStore }

func (r fakeSessions) Create(ctx context.Context, s core.Session) error {
	if err := r.s.failure("Sessions.Create"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	key := string(s.IDHash)
	if _, ok := r.s.d.sessions[key]; ok || len(s.IDHash) == 0 {
		return fmt.Errorf("fake session: %w", core.ErrConflict)
	}
	s.IDHash = bytes.Clone(s.IDHash)
	s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.StepUpUntil = ms(s.CreatedAt), ms(s.LastSeenAt), ms(s.ExpiresAt), ms(s.StepUpUntil)
	r.s.d.sessions[key] = s
	return nil
}

func (r fakeSessions) Get(ctx context.Context, idHash []byte) (core.Session, error) {
	if err := r.s.failure("Sessions.Get"); err != nil {
		return core.Session{}, err
	}
	defer r.s.lock(ctx)()
	s, ok := r.s.d.sessions[string(idHash)]
	if !ok {
		return core.Session{}, notFound("session")
	}
	s.IDHash = bytes.Clone(s.IDHash)
	return s, nil
}

func (r fakeSessions) update(ctx context.Context, method string, idHash []byte, fn func(*core.Session)) error {
	if err := r.s.failure(method); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	s, ok := r.s.d.sessions[string(idHash)]
	if !ok {
		return notFound("session")
	}
	fn(&s)
	r.s.d.sessions[string(idHash)] = s
	return nil
}

func (r fakeSessions) Touch(ctx context.Context, idHash []byte, at time.Time) error {
	return r.update(ctx, "Sessions.Touch", idHash, func(s *core.Session) { s.LastSeenAt = ms(at) })
}

func (r fakeSessions) SetStepUp(ctx context.Context, idHash []byte, until time.Time) error {
	return r.update(ctx, "Sessions.SetStepUp", idHash, func(s *core.Session) { s.StepUpUntil = ms(until) })
}

func (r fakeSessions) Delete(ctx context.Context, idHash []byte) error {
	if err := r.s.failure("Sessions.Delete"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	delete(r.s.d.sessions, string(idHash))
	return nil
}

func (r fakeSessions) DeleteByPerson(ctx context.Context, p core.PersonID) error {
	if err := r.s.failure("Sessions.DeleteByPerson"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	maps.DeleteFunc(r.s.d.sessions, func(_ string, s core.Session) bool { return s.PersonID == p })
	return nil
}

func (r fakeSessions) DeleteExpired(ctx context.Context, now time.Time, idle time.Duration) (int, error) {
	if err := r.s.failure("Sessions.DeleteExpired"); err != nil {
		return 0, err
	}
	defer r.s.lock(ctx)()
	n := len(r.s.d.sessions)
	maps.DeleteFunc(r.s.d.sessions, func(_ string, s core.Session) bool {
		return !s.ExpiresAt.After(now) || s.LastSeenAt.Before(now.Add(-idle))
	})
	return n - len(r.s.d.sessions), nil
}

// all returns every session, for the tests.
func (r fakeSessions) all() []core.Session {
	defer r.s.lock(context.Background())()
	return slices.Collect(maps.Values(r.s.d.sessions))
}

// --- invites ---

type fakeInvites struct{ s *fakeStore }

func (r fakeInvites) Create(ctx context.Context, inv core.Invite) error {
	if err := r.s.failure("Invites.Create"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.invites[inv.ID]; ok || inv.ID == "" {
		return fmt.Errorf("fake invite: %w", core.ErrConflict)
	}
	for _, other := range r.s.d.invites {
		if bytes.Equal(other.TokenHash, inv.TokenHash) {
			return fmt.Errorf("fake invite token: %w", core.ErrConflict)
		}
	}
	inv.TokenHash = bytes.Clone(inv.TokenHash)
	inv.CreatedAt, inv.ExpiresAt, inv.UsedAt, inv.RevokedAt = ms(inv.CreatedAt), ms(inv.ExpiresAt), msPtr(inv.UsedAt), msPtr(inv.RevokedAt)
	r.s.d.invites[inv.ID] = inv
	return nil
}

func (r fakeInvites) byHash(tokenHash []byte) (core.Invite, bool) {
	for _, inv := range r.s.d.invites {
		if bytes.Equal(inv.TokenHash, tokenHash) {
			return inv, true
		}
	}
	return core.Invite{}, false
}

func (r fakeInvites) live(tokenHash []byte, now time.Time) (core.Invite, error) {
	inv, ok := r.byHash(tokenHash)
	switch {
	case !ok, inv.RevokedAt != nil:
		return core.Invite{}, notFound("invite")
	case inv.UsedAt != nil:
		return core.Invite{}, fmt.Errorf("fake invite: %w", core.ErrUsed)
	case !inv.ExpiresAt.After(now):
		return core.Invite{}, fmt.Errorf("fake invite: %w", core.ErrExpired)
	}
	return inv, nil
}

func (r fakeInvites) Peek(ctx context.Context, tokenHash []byte, now time.Time) (core.Invite, error) {
	if err := r.s.failure("Invites.Peek"); err != nil {
		return core.Invite{}, err
	}
	defer r.s.lock(ctx)()
	return r.live(tokenHash, now)
}

func (r fakeInvites) Consume(ctx context.Context, tokenHash []byte, now time.Time) (core.Invite, error) {
	if err := r.s.failure("Invites.Consume"); err != nil {
		return core.Invite{}, err
	}
	defer r.s.lock(ctx)()
	inv, err := r.live(tokenHash, now)
	if err != nil {
		return core.Invite{}, err
	}
	inv.UsedAt = msPtr(&now)
	r.s.d.invites[inv.ID] = inv
	return inv, nil
}

func (r fakeInvites) ListByAccount(ctx context.Context, a core.AccountID) ([]core.Invite, error) {
	if err := r.s.failure("Invites.ListByAccount"); err != nil {
		return nil, err
	}
	defer r.s.lock(ctx)()
	var out []core.Invite
	for _, inv := range r.s.d.invites {
		if inv.AccountID == a && inv.UsedAt == nil && inv.RevokedAt == nil {
			out = append(out, inv)
		}
	}
	slices.SortFunc(out, func(x, y core.Invite) int {
		return cmp.Or(x.CreatedAt.Compare(y.CreatedAt), cmp.Compare(x.ID, y.ID))
	})
	return out, nil
}

func (r fakeInvites) Revoke(ctx context.Context, id string, at time.Time) error {
	if err := r.s.failure("Invites.Revoke"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	inv, ok := r.s.d.invites[id]
	if !ok {
		return notFound("invite")
	}
	if inv.RevokedAt == nil {
		inv.RevokedAt = msPtr(&at)
		r.s.d.invites[id] = inv
	}
	return nil
}

func (r fakeInvites) RevokeKind(ctx context.Context, kind core.InviteKind, at time.Time) error {
	if err := r.s.failure("Invites.RevokeKind"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	for id, inv := range r.s.d.invites {
		if inv.Kind == kind && inv.UsedAt == nil && inv.RevokedAt == nil && inv.ExpiresAt.After(at) {
			inv.RevokedAt = msPtr(&at)
			r.s.d.invites[id] = inv
		}
	}
	return nil
}

// get returns an invite by its token hash, for the tests.
func (r fakeInvites) get(tokenHash []byte) (core.Invite, bool) {
	defer r.s.lock(context.Background())()
	return r.byHash(tokenHash)
}

// --- audit ---

type fakeAudit struct{ s *fakeStore }

func (r fakeAudit) Append(ctx context.Context, e core.AuditEntry) error {
	if err := r.s.failure("Audit.Append"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	r.s.d.auditSeq++
	e.ID = fmt.Sprintf("%024d", r.s.d.auditSeq)
	e.At = ms(e.At)
	e.Detail = maps.Clone(e.Detail)
	r.s.d.audit = append(r.s.d.audit, e)
	return nil
}

func (r fakeAudit) list(ctx context.Context, match func(core.AuditEntry) bool, before string, limit int) []core.AuditEntry {
	defer r.s.lock(ctx)()
	var out []core.AuditEntry
	for i := len(r.s.d.audit) - 1; i >= 0 && len(out) < limit; i-- {
		e := r.s.d.audit[i]
		if match(e) && (before == "" || e.ID < before) {
			out = append(out, e)
		}
	}
	return out
}

func (r fakeAudit) ListByAccount(ctx context.Context, a core.AccountID, before string, limit int) ([]core.AuditEntry, error) {
	return r.list(ctx, func(e core.AuditEntry) bool { return e.AccountID == a }, before, limit), nil
}

func (r fakeAudit) ListSystem(ctx context.Context, before string, limit int) ([]core.AuditEntry, error) {
	return r.list(ctx, func(e core.AuditEntry) bool { return e.AccountID == "" }, before, limit), nil
}

// entries returns the whole audit log, oldest first.
func (r fakeAudit) entries() []core.AuditEntry {
	defer r.s.lock(context.Background())()
	return slices.Clone(r.s.d.audit)
}

// --- OAuth grants: only what reset-access uses keeps state ---

type fakeOAuth struct{ s *fakeStore }

func (fakeOAuth) PutClient(context.Context, core.OAuthClient) error { return nil }
func (fakeOAuth) GetClient(context.Context, core.ClientID) (core.OAuthClient, error) {
	return core.OAuthClient{}, core.ErrNotFound
}
func (fakeOAuth) TouchClient(context.Context, core.ClientID, time.Time) error {
	return core.ErrNotFound
}
func (fakeOAuth) DeleteIdleClients(context.Context, time.Time) (int, error)   { return 0, nil }
func (fakeOAuth) PutCode(context.Context, core.AuthCode) error                { return nil }
func (fakeOAuth) TouchGrant(context.Context, core.GrantID, time.Time) error   { return core.ErrNotFound }
func (fakeOAuth) PutToken(context.Context, core.Token) error                  { return nil }
func (fakeOAuth) RevokeToken(context.Context, []byte, time.Time) error        { return core.ErrNotFound }
func (fakeOAuth) RevokeFamily(context.Context, string, time.Time) error       { return nil }
func (fakeOAuth) DeleteExpiredTokens(context.Context, time.Time) (int, error) { return 0, nil }
func (fakeOAuth) RevokeGrantsByResource(context.Context, core.ResourceID, time.Time) error {
	return nil
}
func (fakeOAuth) ConsumeCode(context.Context, []byte, time.Time) (core.AuthCode, error) {
	return core.AuthCode{}, core.ErrNotFound
}
func (fakeOAuth) FindGrant(context.Context, core.PersonID, core.ClientID, core.ResourceID) (core.Grant, error) {
	return core.Grant{}, core.ErrNotFound
}
func (fakeOAuth) GetToken(context.Context, []byte) (core.Token, error) {
	return core.Token{}, core.ErrNotFound
}
func (fakeOAuth) UseRefresh(context.Context, []byte, time.Time) (core.Token, error) {
	return core.Token{}, core.ErrNotFound
}

func (r fakeOAuth) PutGrant(ctx context.Context, g core.Grant) error {
	defer r.s.lock(ctx)()
	g.CreatedAt, g.LastUsedAt, g.RevokedAt = ms(g.CreatedAt), msPtr(g.LastUsedAt), msPtr(g.RevokedAt)
	r.s.d.grants[g.ID] = g
	return nil
}

func (r fakeOAuth) GetGrant(ctx context.Context, id core.GrantID) (core.Grant, error) {
	defer r.s.lock(ctx)()
	g, ok := r.s.d.grants[id]
	if !ok {
		return core.Grant{}, notFound("grant")
	}
	return g, nil
}

// ListGrantsByAccount returns the account's active grants, as Family Hub's internal/store does.
func (r fakeOAuth) ListGrantsByAccount(ctx context.Context, a core.AccountID) ([]core.Grant, error) {
	if err := r.s.failure("OAuth.ListGrantsByAccount"); err != nil {
		return nil, err
	}
	defer r.s.lock(ctx)()
	var out []core.Grant
	for _, g := range r.s.d.grants {
		if g.AccountID == a && g.RevokedAt == nil {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(x, y core.Grant) int { return cmp.Compare(x.ID, y.ID) })
	return out, nil
}

// RevokeGrant marks the grant revoked once; tokens are not modelled.
func (r fakeOAuth) RevokeGrant(ctx context.Context, id core.GrantID, at time.Time) error {
	if err := r.s.failure("OAuth.RevokeGrant"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	g, ok := r.s.d.grants[id]
	if !ok {
		return notFound("grant")
	}
	if g.RevokedAt == nil {
		g.RevokedAt = msPtr(&at)
		r.s.d.grants[id] = g
	}
	return nil
}

// --- Family Hub's modules and legacy keys, in the same transactions ---

func (s *fakeStore) putModule(ctx context.Context, id string) {
	defer s.lock(ctx)()
	s.d.modules[id] = true
}

func (s *fakeStore) listModules(ctx context.Context) ([]string, error) {
	if err := s.failure("Modules.List"); err != nil {
		return nil, err
	}
	defer s.lock(ctx)()
	return slices.Sorted(maps.Keys(s.d.modules)), nil
}

func (s *fakeStore) putLegacyKey(ctx context.Context, k legacyKey) {
	defer s.lock(ctx)()
	k.Hash = bytes.Clone(k.Hash)
	s.d.legacyKeys[string(k.Hash)] = k
}

func (s *fakeStore) legacyKeysOf(ctx context.Context, module string) ([]legacyKey, error) {
	if err := s.failure("LegacyKeys.ListByModule"); err != nil {
		return nil, err
	}
	defer s.lock(ctx)()
	var out []legacyKey
	for _, k := range s.d.legacyKeys {
		if k.ModuleID == module {
			out = append(out, k)
		}
	}
	slices.SortFunc(out, func(x, y legacyKey) int { return cmp.Compare(x.Label, y.Label) })
	return out, nil
}

func (s *fakeStore) deleteLegacyKey(ctx context.Context, hash []byte) error {
	if err := s.failure("LegacyKeys.Delete"); err != nil {
		return err
	}
	defer s.lock(ctx)()
	if _, ok := s.d.legacyKeys[string(hash)]; !ok {
		return notFound("legacy key")
	}
	delete(s.d.legacyKeys, string(hash))
	return nil
}

// legacyStep is Family Hub's part of reset-access, as its G9 adapter will pass it: the superadmin's legacy keys go,
// in every module (Modules().List + LegacyKeys().ListByModule + Delete, as T2.F2 did inside auth).
func legacyStep(st *fakeStore) ResetStep {
	return ResetStep{Key: "legacy_keys", Phrase: "legacy keys", Run: func(ctx context.Context, p core.Person, _ time.Time) (int, error) {
		mods, err := st.listModules(ctx)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, m := range mods {
			keys, err := st.legacyKeysOf(ctx, m)
			if err != nil {
				return 0, err
			}
			for _, k := range keys {
				if k.PersonID != p.ID {
					continue
				}
				if err := st.deleteLegacyKey(ctx, k.Hash); err != nil && !errors.Is(err, core.ErrNotFound) {
					return 0, err
				}
				n++
			}
		}
		return n, nil
	}}
}
