// Package memstore is an in-memory store.Store for the tests of package people (Family Hub's admintest store, on
// the gatekeeper's interfaces). Only tests import it.
package memstore

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// Store is an in-memory store.Store with the semantics of the real adapters:
//
//   - Times are kept at millisecond precision in UTC.
//   - Invites.Peek and Consume: unknown or revoked ErrNotFound, used ErrUsed, expired ErrExpired;
//     Invites.ListByAccount returns unused, unrevoked invites, expired ones included.
//   - ListGrantsByAccount and FindGrant see active grants only; revoking twice is a no-op.
//   - Accounts.Delete cascades to people, passkeys, sessions, invites, grants, codes and tokens; People.Delete to
//     passkeys, sessions, grants, codes and tokens. Audit entries stay.
//   - Audit ids are 24 hex characters that grow; a malformed before is an error.
//   - Tx runs fn under the store lock with the transaction in its context, and restores everything when fn fails;
//     a Tx inside a Tx joins the outer one.
//
// Fail makes a method ("Accounts.Delete", "Tx", …) return an error.
type Store struct {
	mu *sync.Mutex
	d  *data

	ctlMu sync.Mutex
	fail  map[string]error
}

type data struct {
	accounts map[core.AccountID]core.Account
	people   map[core.PersonID]core.Person
	passkeys map[string]core.Passkey
	sessions map[string]core.Session
	invites  map[string]core.Invite
	clients  map[core.ClientID]core.OAuthClient
	codes    map[string]core.AuthCode
	grants   map[core.GrantID]core.Grant
	tokens   map[string]core.Token
	audit    []core.AuditEntry
	auditSeq int
}

// New returns an empty Store.
func New() *Store {
	return &Store{mu: &sync.Mutex{}, fail: map[string]error{}, d: &data{
		accounts: map[core.AccountID]core.Account{}, people: map[core.PersonID]core.Person{},
		passkeys: map[string]core.Passkey{}, sessions: map[string]core.Session{}, invites: map[string]core.Invite{},
		clients: map[core.ClientID]core.OAuthClient{}, codes: map[string]core.AuthCode{},
		grants: map[core.GrantID]core.Grant{}, tokens: map[string]core.Token{},
	}}
}

var _ store.Store = (*Store)(nil)

// Fail makes method return err from now on; a nil err clears it.
func (s *Store) Fail(method string, err error) {
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	if err == nil {
		delete(s.fail, method)
		return
	}
	s.fail[method] = err
}

func (s *Store) failure(method string) error {
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	return s.fail[method]
}

type txKey struct{}

// inTx reports whether ctx carries a transaction of s, whose Tx holds the lock already.
func (s *Store) inTx(ctx context.Context) bool {
	tx, _ := ctx.Value(txKey{}).(*Store)
	return tx == s
}

// lock takes the store lock unless ctx is inside a Tx of s.
func (s *Store) lock(ctx context.Context) func() {
	if s.inTx(ctx) {
		return func() {}
	}
	s.mu.Lock()
	return s.mu.Unlock
}

func (d *data) clone() *data {
	return &data{
		accounts: maps.Clone(d.accounts), people: maps.Clone(d.people), passkeys: maps.Clone(d.passkeys),
		sessions: maps.Clone(d.sessions), invites: maps.Clone(d.invites), clients: maps.Clone(d.clients),
		codes: maps.Clone(d.codes), grants: maps.Clone(d.grants), tokens: maps.Clone(d.tokens),
		audit: slices.Clone(d.audit), auditSeq: d.auditSeq,
	}
}

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

func notFound(what string) error { return fmt.Errorf("fake %s: %w", what, core.ErrNotFound) }

// Tx implements store.Store.
func (s *Store) Tx(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.inTx(ctx) {
		return fn(ctx)
	}
	if err := s.failure("Tx"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := s.d.clone()
	if err := fn(context.WithValue(ctx, txKey{}, s)); err != nil {
		*s.d = *snapshot
		return err
	}
	return nil
}

// Close implements store.Store.
func (s *Store) Close() error { return nil }

// Accounts implements store.Store.
func (s *Store) Accounts() store.AccountStore { return accounts{s} }

// People implements store.Store.
func (s *Store) People() store.PersonStore { return people{s} }

// Passkeys implements store.Store.
func (s *Store) Passkeys() store.PasskeyStore { return passkeys{s} }

// Sessions implements store.Store.
func (s *Store) Sessions() store.SessionStore { return sessions{s} }

// Invites implements store.Store.
func (s *Store) Invites() store.InviteStore { return invites{s} }

// OAuth implements store.Store.
func (s *Store) OAuth() store.OAuthStore { return oauth{s} }

// Audit implements store.Store.
func (s *Store) Audit() store.AuditStore { return audit{s} }

// AuditEntries returns every audit entry, oldest first.
func (s *Store) AuditEntries() []core.AuditEntry {
	defer s.lock(context.Background())()
	return slices.Clone(s.d.audit)
}

// --- accounts ---

type accounts struct{ s *Store }

func (r accounts) Create(ctx context.Context, a core.Account) error {
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

func (r accounts) Get(ctx context.Context, id core.AccountID) (core.Account, error) {
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

func (r accounts) List(ctx context.Context) ([]core.Account, error) {
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

func (r accounts) Rename(ctx context.Context, id core.AccountID, name string) error {
	defer r.s.lock(ctx)()
	a, ok := r.s.d.accounts[id]
	if !ok {
		return notFound("account")
	}
	a.Name = name
	r.s.d.accounts[id] = a
	return nil
}

func (r accounts) Delete(ctx context.Context, id core.AccountID) error {
	if err := r.s.failure("Accounts.Delete"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	d := r.s.d
	if _, ok := d.accounts[id]; !ok {
		return notFound("account")
	}
	delete(d.accounts, id)
	for pid, p := range d.people {
		if p.AccountID == id {
			d.deletePerson(pid)
		}
	}
	for gid, g := range d.grants {
		if g.AccountID == id {
			d.deleteGrant(gid)
		}
	}
	maps.DeleteFunc(d.invites, func(_ string, inv core.Invite) bool { return inv.AccountID == id })
	return nil
}

func (d *data) deletePerson(id core.PersonID) {
	delete(d.people, id)
	maps.DeleteFunc(d.passkeys, func(_ string, pk core.Passkey) bool { return pk.PersonID == id })
	maps.DeleteFunc(d.sessions, func(_ string, s core.Session) bool { return s.PersonID == id })
	for gid, g := range d.grants {
		if g.PersonID == id {
			d.deleteGrant(gid)
		}
	}
}

func (d *data) deleteGrant(id core.GrantID) {
	delete(d.grants, id)
	maps.DeleteFunc(d.tokens, func(_ string, t core.Token) bool { return t.GrantID == id })
	maps.DeleteFunc(d.codes, func(_ string, c core.AuthCode) bool { return c.GrantID == id })
}

// --- people ---

type people struct{ s *Store }

func (r people) Create(ctx context.Context, p core.Person) error {
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

func (r people) Get(ctx context.Context, id core.PersonID) (core.Person, error) {
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

func (r people) ListByAccount(ctx context.Context, a core.AccountID) ([]core.Person, error) {
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

func (r people) CountSuperadmins(ctx context.Context) (int, error) {
	defer r.s.lock(ctx)()
	n := 0
	for _, p := range r.s.d.people {
		if p.Superadmin {
			n++
		}
	}
	return n, nil
}

func (r people) Rename(ctx context.Context, id core.PersonID, name string) error {
	defer r.s.lock(ctx)()
	p, ok := r.s.d.people[id]
	if !ok {
		return notFound("person")
	}
	p.Name = name
	r.s.d.people[id] = p
	return nil
}

func (r people) Disable(ctx context.Context, id core.PersonID, at time.Time) error {
	defer r.s.lock(ctx)()
	p, ok := r.s.d.people[id]
	if !ok {
		return notFound("person")
	}
	p.DisabledAt = msPtr(&at)
	r.s.d.people[id] = p
	return nil
}

func (r people) Delete(ctx context.Context, id core.PersonID) error {
	if err := r.s.failure("People.Delete"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.people[id]; !ok {
		return notFound("person")
	}
	r.s.d.deletePerson(id)
	return nil
}

// --- passkeys ---

type passkeys struct{ s *Store }

func (r passkeys) Add(ctx context.Context, k core.Passkey) error {
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.passkeys[k.ID]; ok || k.ID == "" {
		return fmt.Errorf("fake passkey %q: %w", k.ID, core.ErrConflict)
	}
	k.CreatedAt, k.LastUsedAt = ms(k.CreatedAt), msPtr(k.LastUsedAt)
	r.s.d.passkeys[k.ID] = k
	return nil
}

func (r passkeys) Get(ctx context.Context, id string) (core.Passkey, error) {
	defer r.s.lock(ctx)()
	k, ok := r.s.d.passkeys[id]
	if !ok {
		return core.Passkey{}, notFound("passkey")
	}
	return k, nil
}

func (r passkeys) GetByCredentialID(ctx context.Context, credentialID []byte) (core.Passkey, error) {
	defer r.s.lock(ctx)()
	for _, k := range r.s.d.passkeys {
		if bytes.Equal(k.CredentialID, credentialID) {
			return k, nil
		}
	}
	return core.Passkey{}, notFound("passkey")
}

func (r passkeys) ListByPerson(ctx context.Context, p core.PersonID) ([]core.Passkey, error) {
	defer r.s.lock(ctx)()
	var out []core.Passkey
	for _, k := range r.s.d.passkeys {
		if k.PersonID == p {
			out = append(out, k)
		}
	}
	slices.SortFunc(out, func(x, y core.Passkey) int { return cmp.Compare(x.ID, y.ID) })
	return out, nil
}

func (r passkeys) Update(ctx context.Context, id string, data []byte, lastUsed time.Time) error {
	defer r.s.lock(ctx)()
	k, ok := r.s.d.passkeys[id]
	if !ok {
		return notFound("passkey")
	}
	k.Data, k.LastUsedAt = bytes.Clone(data), msPtr(&lastUsed)
	r.s.d.passkeys[id] = k
	return nil
}

func (r passkeys) Rename(ctx context.Context, id, name string) error {
	defer r.s.lock(ctx)()
	k, ok := r.s.d.passkeys[id]
	if !ok {
		return notFound("passkey")
	}
	k.Name = name
	r.s.d.passkeys[id] = k
	return nil
}

func (r passkeys) Delete(ctx context.Context, id string) error {
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.passkeys[id]; !ok {
		return notFound("passkey")
	}
	delete(r.s.d.passkeys, id)
	return nil
}

func (r passkeys) DeleteByPerson(ctx context.Context, p core.PersonID) error {
	defer r.s.lock(ctx)()
	maps.DeleteFunc(r.s.d.passkeys, func(_ string, k core.Passkey) bool { return k.PersonID == p })
	return nil
}

// --- sessions ---

type sessions struct{ s *Store }

func (r sessions) Create(ctx context.Context, s core.Session) error {
	defer r.s.lock(ctx)()
	key := string(s.IDHash)
	if _, ok := r.s.d.sessions[key]; ok || key == "" {
		return fmt.Errorf("fake session: %w", core.ErrConflict)
	}
	s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.StepUpUntil = ms(s.CreatedAt), ms(s.LastSeenAt), ms(s.ExpiresAt),
		ms(s.StepUpUntil)
	r.s.d.sessions[key] = s
	return nil
}

func (r sessions) Get(ctx context.Context, idHash []byte) (core.Session, error) {
	defer r.s.lock(ctx)()
	s, ok := r.s.d.sessions[string(idHash)]
	if !ok {
		return core.Session{}, notFound("session")
	}
	return s, nil
}

func (r sessions) Touch(ctx context.Context, idHash []byte, at time.Time) error {
	defer r.s.lock(ctx)()
	s, ok := r.s.d.sessions[string(idHash)]
	if !ok {
		return notFound("session")
	}
	s.LastSeenAt = ms(at)
	r.s.d.sessions[string(idHash)] = s
	return nil
}

func (r sessions) SetStepUp(ctx context.Context, idHash []byte, until time.Time) error {
	defer r.s.lock(ctx)()
	s, ok := r.s.d.sessions[string(idHash)]
	if !ok {
		return notFound("session")
	}
	s.StepUpUntil = ms(until)
	r.s.d.sessions[string(idHash)] = s
	return nil
}

func (r sessions) Delete(ctx context.Context, idHash []byte) error {
	defer r.s.lock(ctx)()
	delete(r.s.d.sessions, string(idHash))
	return nil
}

func (r sessions) DeleteByPerson(ctx context.Context, p core.PersonID) error {
	defer r.s.lock(ctx)()
	maps.DeleteFunc(r.s.d.sessions, func(_ string, s core.Session) bool { return s.PersonID == p })
	return nil
}

func (r sessions) DeleteExpired(ctx context.Context, now time.Time, idle time.Duration) (int, error) {
	defer r.s.lock(ctx)()
	n := len(r.s.d.sessions)
	maps.DeleteFunc(r.s.d.sessions, func(_ string, s core.Session) bool {
		return !now.Before(s.ExpiresAt) || !now.Before(s.LastSeenAt.Add(idle))
	})
	return n - len(r.s.d.sessions), nil
}

// --- invites ---

type invites struct{ s *Store }

func (r invites) Create(ctx context.Context, inv core.Invite) error {
	if err := r.s.failure("Invites.Create"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.invites[inv.ID]; ok || inv.ID == "" {
		return fmt.Errorf("fake invite %q: %w", inv.ID, core.ErrConflict)
	}
	inv.CreatedAt, inv.ExpiresAt = ms(inv.CreatedAt), ms(inv.ExpiresAt)
	r.s.d.invites[inv.ID] = inv
	return nil
}

func (r invites) find(tokenHash []byte, now time.Time) (core.Invite, error) {
	for _, inv := range r.s.d.invites {
		if !bytes.Equal(inv.TokenHash, tokenHash) {
			continue
		}
		switch {
		case inv.RevokedAt != nil:
			return core.Invite{}, notFound("invite")
		case inv.UsedAt != nil:
			return core.Invite{}, fmt.Errorf("fake invite: %w", core.ErrUsed)
		case !now.Before(inv.ExpiresAt):
			return core.Invite{}, fmt.Errorf("fake invite: %w", core.ErrExpired)
		}
		return inv, nil
	}
	return core.Invite{}, notFound("invite")
}

func (r invites) Peek(ctx context.Context, tokenHash []byte, now time.Time) (core.Invite, error) {
	defer r.s.lock(ctx)()
	return r.find(tokenHash, now)
}

func (r invites) Consume(ctx context.Context, tokenHash []byte, now time.Time) (core.Invite, error) {
	defer r.s.lock(ctx)()
	inv, err := r.find(tokenHash, now)
	if err != nil {
		return core.Invite{}, err
	}
	inv.UsedAt = msPtr(&now)
	r.s.d.invites[inv.ID] = inv
	return inv, nil
}

func (r invites) ListByAccount(ctx context.Context, a core.AccountID) ([]core.Invite, error) {
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

func (r invites) Revoke(ctx context.Context, id string, at time.Time) error {
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

func (r invites) RevokeKind(ctx context.Context, kind core.InviteKind, at time.Time) error {
	defer r.s.lock(ctx)()
	for id, inv := range r.s.d.invites {
		if inv.Kind == kind && inv.RevokedAt == nil && inv.UsedAt == nil {
			inv.RevokedAt = msPtr(&at)
			r.s.d.invites[id] = inv
		}
	}
	return nil
}

// --- oauth ---

type oauth struct{ s *Store }

func (r oauth) PutClient(ctx context.Context, c core.OAuthClient) error {
	defer r.s.lock(ctx)()
	r.s.d.clients[c.ID] = c
	return nil
}

func (r oauth) GetClient(ctx context.Context, id core.ClientID) (core.OAuthClient, error) {
	if err := r.s.failure("OAuth.GetClient"); err != nil {
		return core.OAuthClient{}, err
	}
	defer r.s.lock(ctx)()
	c, ok := r.s.d.clients[id]
	if !ok {
		return core.OAuthClient{}, notFound("client")
	}
	return c, nil
}

func (r oauth) TouchClient(ctx context.Context, id core.ClientID, at time.Time) error {
	defer r.s.lock(ctx)()
	c, ok := r.s.d.clients[id]
	if !ok {
		return notFound("client")
	}
	c.LastUsedAt = msPtr(&at)
	r.s.d.clients[id] = c
	return nil
}

func (r oauth) DeleteIdleClients(context.Context, time.Time) (int, error) { return 0, nil }

func (r oauth) PutCode(ctx context.Context, c core.AuthCode) error {
	defer r.s.lock(ctx)()
	r.s.d.codes[string(c.CodeHash)] = c
	return nil
}

func (r oauth) ConsumeCode(ctx context.Context, codeHash []byte, now time.Time) (core.AuthCode, error) {
	defer r.s.lock(ctx)()
	c, ok := r.s.d.codes[string(codeHash)]
	if !ok {
		return core.AuthCode{}, notFound("code")
	}
	delete(r.s.d.codes, string(codeHash))
	if !now.Before(c.ExpiresAt) {
		return core.AuthCode{}, fmt.Errorf("fake code: %w", core.ErrExpired)
	}
	return c, nil
}

func (r oauth) PutGrant(ctx context.Context, g core.Grant) error {
	defer r.s.lock(ctx)()
	if g.RevokedAt == nil {
		for _, o := range r.s.d.grants {
			if o.ID != g.ID && o.RevokedAt == nil && o.PersonID == g.PersonID && o.ClientID == g.ClientID &&
				o.ResourceID == g.ResourceID {
				return fmt.Errorf("fake grant: %w", core.ErrConflict)
			}
		}
	}
	g.CreatedAt, g.LastUsedAt, g.RevokedAt = ms(g.CreatedAt), msPtr(g.LastUsedAt), msPtr(g.RevokedAt)
	r.s.d.grants[g.ID] = g
	return nil
}

func (r oauth) GetGrant(ctx context.Context, id core.GrantID) (core.Grant, error) {
	if err := r.s.failure("OAuth.GetGrant"); err != nil {
		return core.Grant{}, err
	}
	defer r.s.lock(ctx)()
	g, ok := r.s.d.grants[id]
	if !ok {
		return core.Grant{}, notFound("grant")
	}
	return g, nil
}

func (r oauth) FindGrant(ctx context.Context, p core.PersonID, c core.ClientID, res core.ResourceID) (core.Grant,
	error) {
	defer r.s.lock(ctx)()
	for _, g := range r.s.d.grants {
		if g.RevokedAt == nil && g.PersonID == p && g.ClientID == c && g.ResourceID == res {
			return g, nil
		}
	}
	return core.Grant{}, notFound("grant")
}

func (r oauth) ListGrantsByAccount(ctx context.Context, a core.AccountID) ([]core.Grant, error) {
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
	slices.SortFunc(out, func(x, y core.Grant) int {
		return cmp.Or(x.CreatedAt.Compare(y.CreatedAt), cmp.Compare(x.ID, y.ID))
	})
	return out, nil
}

func (r oauth) TouchGrant(ctx context.Context, id core.GrantID, at time.Time) error {
	defer r.s.lock(ctx)()
	g, ok := r.s.d.grants[id]
	if !ok {
		return notFound("grant")
	}
	g.LastUsedAt = msPtr(&at)
	r.s.d.grants[id] = g
	return nil
}

func (r oauth) revoke(id core.GrantID, at time.Time) {
	g := r.s.d.grants[id]
	if g.RevokedAt != nil {
		return
	}
	g.RevokedAt = msPtr(&at)
	r.s.d.grants[id] = g
	for h, t := range r.s.d.tokens {
		if t.GrantID == id && t.RevokedAt == nil {
			t.RevokedAt = msPtr(&at)
			r.s.d.tokens[h] = t
		}
	}
}

func (r oauth) RevokeGrant(ctx context.Context, id core.GrantID, at time.Time) error {
	defer r.s.lock(ctx)()
	if _, ok := r.s.d.grants[id]; !ok {
		return notFound("grant")
	}
	r.revoke(id, at)
	return nil
}

func (r oauth) RevokeGrantsByResource(ctx context.Context, res core.ResourceID, at time.Time) error {
	defer r.s.lock(ctx)()
	for id, g := range r.s.d.grants {
		if g.ResourceID == res {
			r.revoke(id, at)
		}
	}
	return nil
}

func (r oauth) PutToken(ctx context.Context, t core.Token) error {
	defer r.s.lock(ctx)()
	r.s.d.tokens[string(t.Hash)] = t
	return nil
}

func (r oauth) GetToken(ctx context.Context, hash []byte) (core.Token, error) {
	defer r.s.lock(ctx)()
	t, ok := r.s.d.tokens[string(hash)]
	if !ok {
		return core.Token{}, notFound("token")
	}
	return t, nil
}

func (r oauth) UseRefresh(ctx context.Context, hash []byte, at time.Time) (core.Token, error) {
	defer r.s.lock(ctx)()
	t, ok := r.s.d.tokens[string(hash)]
	switch {
	case !ok || t.Kind != core.TokenRefresh || t.RevokedAt != nil:
		return core.Token{}, notFound("token")
	case t.UsedAt != nil:
		return core.Token{}, fmt.Errorf("fake token: %w", core.ErrUsed)
	case !at.Before(t.ExpiresAt):
		return core.Token{}, fmt.Errorf("fake token: %w", core.ErrExpired)
	}
	t.UsedAt = msPtr(&at)
	r.s.d.tokens[string(hash)] = t
	return t, nil
}

func (r oauth) RevokeToken(ctx context.Context, hash []byte, at time.Time) error {
	defer r.s.lock(ctx)()
	t, ok := r.s.d.tokens[string(hash)]
	if !ok {
		return notFound("token")
	}
	if t.RevokedAt == nil {
		t.RevokedAt = msPtr(&at)
		r.s.d.tokens[string(hash)] = t
	}
	return nil
}

func (r oauth) RevokeFamily(ctx context.Context, family string, at time.Time) error {
	defer r.s.lock(ctx)()
	for h, t := range r.s.d.tokens {
		if t.Family == family && t.RevokedAt == nil {
			t.RevokedAt = msPtr(&at)
			r.s.d.tokens[h] = t
		}
	}
	return nil
}

func (r oauth) DeleteExpiredTokens(ctx context.Context, now time.Time) (int, error) {
	defer r.s.lock(ctx)()
	n := len(r.s.d.tokens)
	maps.DeleteFunc(r.s.d.tokens, func(_ string, t core.Token) bool { return !now.Before(t.ExpiresAt) })
	return n - len(r.s.d.tokens), nil
}

// --- audit ---

type audit struct{ s *Store }

func (r audit) Append(ctx context.Context, e core.AuditEntry) error {
	if err := r.s.failure("Audit.Append"); err != nil {
		return err
	}
	defer r.s.lock(ctx)()
	r.s.d.auditSeq++
	e.ID = fmt.Sprintf("%024x", r.s.d.auditSeq)
	e.At = ms(e.At)
	e.Detail = maps.Clone(e.Detail)
	r.s.d.audit = append(r.s.d.audit, e)
	return nil
}

func (r audit) list(ctx context.Context, match func(core.AuditEntry) bool, before string,
	limit int) ([]core.AuditEntry, error) {
	if before != "" && !isHex24(before) {
		return nil, fmt.Errorf("fake audit: cursor %q is not an audit id", before)
	}
	defer r.s.lock(ctx)()
	var out []core.AuditEntry
	for i := len(r.s.d.audit) - 1; i >= 0; i-- {
		e := r.s.d.audit[i]
		if !match(e) || (before != "" && e.ID >= before) {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out, nil
}

func isHex24(s string) bool {
	if len(s) != 24 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (r audit) ListByAccount(ctx context.Context, a core.AccountID, before string, limit int) ([]core.AuditEntry,
	error) {
	return r.list(ctx, func(e core.AuditEntry) bool { return e.AccountID == a }, before, limit)
}

func (r audit) ListSystem(ctx context.Context, before string, limit int) ([]core.AuditEntry, error) {
	return r.list(ctx, func(e core.AuditEntry) bool { return e.AccountID == "" }, before, limit)
}
