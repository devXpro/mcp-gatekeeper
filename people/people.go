// Package people keeps accounts and their members, and serves the account and superadmin JSON API: members and
// invites of an account, its connections and audit, accounts made by the superadmin, the system audit, and "delete
// everything", which lets the application erase its own data of the account before the gatekeeper deletes its rows.
//
// The account comes from the session, always: no account route takes an account id from the client, and no route
// returns another account's members, connections or audit, to anyone, the superadmin included. The superadmin's own
// account works like anyone else's. The superadmin routes manage accounts (counts only) and read the system audit.
//
// The application plugs in through small interfaces (see Options): the Inviter (package auth), the GrantRevoker
// (package oauth), and the optional AccountFields, SummaryFields, Eraser and ConnectionSource of its own.
package people

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/people/actorname"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// Audit actions of this package. Invites and members are audited in the account; creating and deleting accounts
// are system entries (a deleted account's own entries can no longer be read by anyone).
const (
	ActionInviteCreate = "account.invite.create"
	ActionInviteRevoke = "account.invite.revoke"
	ActionMemberRemove = "account.member.remove"
	ActionCreate       = "account.create"
	ActionDelete       = "account.delete"
	ActionDeleteFail   = "account.delete.fail"
)

var (
	// ErrSelf refuses removing yourself.
	ErrSelf = errors.New("people: you cannot remove yourself")
	// ErrSuperadmin refuses removing a superadmin from an account: the application would lose its administrator.
	ErrSuperadmin = fmt.Errorf("people: a superadmin cannot be removed from an account: %w", core.ErrConflict)
	// ErrInvalidName is wrapped by every refusal of a name (the rule is Options.NormalizeName).
	ErrInvalidName = errors.New("people: invalid name")
)

// IssuedInvite is a new one-time link. URL carries the token in its fragment: show it once to whoever asked, never
// log or store it. Its fields are those of auth.IssuedInvite, so one converts to the other.
type IssuedInvite struct {
	ID        string
	URL       string
	ExpiresAt time.Time
}

// Inviter issues owner and member invites; package auth implements it (its auth.IssuedInvite converts to
// IssuedInvite). Errors wrap core.ErrNotFound for an unknown account.
type Inviter interface {
	IssueInvite(ctx context.Context, kind core.InviteKind, account core.AccountID, name string,
		by core.PersonID) (IssuedInvite, error)
	// IssueInviteIn is IssueInvite on st; the transaction travels in ctx.
	IssueInviteIn(ctx context.Context, st store.Store, kind core.InviteKind, account core.AccountID, name string,
		by core.PersonID) (IssuedInvite, error)
}

// GrantRevoker revokes a connection and audits it; (*oauth.Server).RevokeGrant implements it.
type GrantRevoker interface {
	RevokeGrant(ctx context.Context, id core.GrantID, actor core.PersonID, ip string) error
}

// Eraser erases the application's own data of an account before the gatekeeper deletes the account's rows (Family
// Hub: every module the account used erases it).
type Eraser interface {
	// EraseAccount erases account a, deleted by actor. Its detail goes into the "account.delete" audit entry (never
	// "by", which this package sets). An error stops the deletion: the account stays, so deleting it again retries.
	// An *EraseError says what to audit and what to answer; any other error is audited without detail and answered
	// like every error of this package (an *APIError as it is, otherwise 500 internal). ctx is not cancelled when
	// the client goes away.
	EraseAccount(ctx context.Context, a core.AccountID, actor core.PersonID) (detail map[string]string, err error)
}

// EraseError is an Eraser's refusal: Detail goes into the "account.delete.fail" audit entry, Err is what the client
// is answered (an *APIError, e.g. 502 upstream with the failing part in Extra).
type EraseError struct {
	Detail map[string]string
	Err    error
}

func (e *EraseError) Error() string { return "people: the account was not erased: " + e.Err.Error() }

func (e *EraseError) Unwrap() error { return e.Err }

// Options configure New. Site, Brand.SessionCookie, Sessions, Store, Inviter, Revoker and NormalizeName are
// required.
type Options struct {
	Site     core.Site
	Brand    core.Brand // SessionCookie: DELETE /api/account clears it
	Sessions core.Sessions
	Store    store.Store
	Inviter  Inviter
	Revoker  GrantRevoker
	// NormalizeName is the name rule of package auth (auth.NormalizeName): it trims a display name or refuses it.
	NormalizeName func(string) (string, error)

	Eraser      Eraser           // nil: the application keeps nothing of an account
	Fields      AccountFields    // nil: GET /api/account has no fields of the application
	Summaries   SummaryFields    // nil: GET /api/admin/accounts has no fields of the application
	Connections ConnectionSource // nil: the connections are the OAuth grants only

	Log   *slog.Logger // nil discards
	Clock core.Clock   // nil is the system clock
}

// Service manages accounts and members and serves their API (RegisterRoutes). It is safe for concurrent use.
type Service struct {
	o   Options
	st  store.Store
	log *slog.Logger
	now core.Clock
}

var _ core.RouteRegistrar = (*Service)(nil)

// New returns a Service.
func New(o Options) (*Service, error) {
	var missing []string
	for name, absent := range map[string]bool{
		"Site.PublicURL": o.Site.PublicURL == "", "Brand.SessionCookie": o.Brand.SessionCookie == "",
		"Sessions": o.Sessions == nil, "Store": o.Store == nil, "Inviter": o.Inviter == nil,
		"Revoker": o.Revoker == nil, "NormalizeName": o.NormalizeName == nil,
	} {
		if absent {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, fmt.Errorf("people: missing options: %s", strings.Join(missing, ", "))
	}
	if !strings.HasPrefix(o.Brand.SessionCookie, "__Host-") {
		return nil, errors.New("people: Brand.SessionCookie must start with __Host-")
	}
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{o: o, st: o.Store, log: log, now: func() time.Time { return clock().UTC() }}, nil
}

// nameError marks a refusal of the name rule with ErrInvalidName and keeps its text.
type nameError struct{ err error }

func (e nameError) Error() string   { return e.err.Error() }
func (e nameError) Unwrap() []error { return []error{e.err, ErrInvalidName} }

// normalize applies the name rule; a refusal wraps ErrInvalidName.
func (s *Service) normalize(name string) (string, error) {
	n, err := s.o.NormalizeName(name)
	if err != nil {
		return "", nameError{err}
	}
	return n, nil
}

// audit appends e with the actor's name stamped on it (package actorname).
func (s *Service) audit(ctx context.Context, e core.AuditEntry) {
	e = actorname.Stamp(ctx, s.st.People(), e)
	if err := s.st.Audit().Append(ctx, e); err != nil {
		s.log.Error("people: cannot audit", "action", e.Action, "err", err)
	}
}

// --- members and invites of one account ---

// Members returns the people of account a, oldest first.
func (s *Service) Members(ctx context.Context, a core.AccountID) ([]core.Person, error) {
	ps, err := s.st.People().ListByAccount(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("people: list the members: %w", err)
	}
	return ps, nil
}

// Invites returns the live member invites of account a: not used, not withdrawn, not expired.
func (s *Service) Invites(ctx context.Context, a core.AccountID) ([]core.Invite, error) {
	list, err := s.st.Invites().ListByAccount(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("people: list the invites: %w", err)
	}
	now := s.now()
	return slices.DeleteFunc(list, func(inv core.Invite) bool {
		return inv.Kind != core.InviteMember || !now.Before(inv.ExpiresAt)
	}), nil
}

// CreateInvite makes a member invite to account a for a person called name, by from ip. A bad name wraps
// ErrInvalidName. The URL holds the token: it goes to the asker only, never to a log or the audit.
func (s *Service) CreateInvite(ctx context.Context, a core.AccountID, name string, by core.PersonID,
	ip string) (IssuedInvite, error) {
	// The inviter applies the same rule; checking here first marks a refusal as a bad name.
	if _, err := s.normalize(name); err != nil {
		return IssuedInvite{}, fmt.Errorf("people: issue an invite: %w", err)
	}
	inv, err := s.o.Inviter.IssueInvite(ctx, core.InviteMember, a, name, by)
	if err != nil {
		return IssuedInvite{}, fmt.Errorf("people: issue an invite: %w", err)
	}
	s.audit(ctx, core.AuditEntry{At: s.now(), AccountID: a, Actor: by, Action: ActionInviteCreate, Target: inv.ID,
		IP: ip})
	return inv, nil
}

// RevokeInvite withdraws live invite id of account a; an invite of another account is core.ErrNotFound.
func (s *Service) RevokeInvite(ctx context.Context, a core.AccountID, id string, by core.PersonID, ip string) error {
	list, err := s.st.Invites().ListByAccount(ctx, a)
	if err != nil {
		return fmt.Errorf("people: list the invites: %w", err)
	}
	if !slices.ContainsFunc(list, func(inv core.Invite) bool { return inv.ID == id }) {
		return fmt.Errorf("people: invite %q: %w", id, core.ErrNotFound)
	}
	now := s.now()
	return s.st.Tx(ctx, func(ctx context.Context) error {
		if err := s.st.Invites().Revoke(ctx, id, now); err != nil {
			return fmt.Errorf("people: revoke an invite: %w", err)
		}
		return s.st.Audit().Append(ctx, actorname.Stamp(ctx, s.st.People(), core.AuditEntry{At: now, AccountID: a,
			Actor: by, Action: ActionInviteRevoke, Target: id, IP: ip}))
	})
}

// RemoveMember deletes person target of account a with their passkeys, sessions and grants, by from ip. Removing
// yourself is ErrSelf, a superadmin ErrSuperadmin, a person of another account core.ErrNotFound.
func (s *Service) RemoveMember(ctx context.Context, a core.AccountID, target, by core.PersonID, ip string) error {
	if target == by {
		return ErrSelf
	}
	now := s.now()
	return s.st.Tx(ctx, func(ctx context.Context) error {
		p, err := s.st.People().Get(ctx, target)
		if err == nil && p.AccountID != a {
			err = core.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("people: member %q: %w", target, err)
		}
		if p.Superadmin {
			return ErrSuperadmin
		}
		if err := s.st.People().Delete(ctx, target); err != nil {
			return fmt.Errorf("people: delete a member: %w", err)
		}
		return s.st.Audit().Append(ctx, actorname.Stamp(ctx, s.st.People(), core.AuditEntry{At: now, AccountID: a,
			Actor: by, Action: ActionMemberRemove, Target: string(target), IP: ip}))
	})
}

// --- accounts (the superadmin) ---

// Summary is an account as the superadmin's list shows it: counts, no data.
type Summary struct {
	Account core.Account
	Members int
}

// Summaries lists every account with its counts, oldest first.
func (s *Service) Summaries(ctx context.Context) ([]Summary, error) {
	accounts, err := s.st.Accounts().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("people: list the accounts: %w", err)
	}
	out := make([]Summary, 0, len(accounts))
	for _, acc := range accounts {
		ps, err := s.st.People().ListByAccount(ctx, acc.ID)
		if err != nil {
			return nil, fmt.Errorf("people: list the members: %w", err)
		}
		out = append(out, Summary{Account: acc, Members: len(ps)})
	}
	return out, nil
}

// CreateAccount makes an account called name and the invite of its owner, called ownerName, in one transaction,
// by from ip. A bad name wraps ErrInvalidName.
func (s *Service) CreateAccount(ctx context.Context, name, ownerName string, by core.PersonID,
	ip string) (core.Account, IssuedInvite, error) {
	name, err := s.normalize(name)
	if err != nil {
		return core.Account{}, IssuedInvite{}, fmt.Errorf("people: the account name: %w", err)
	}
	if _, err := s.normalize(ownerName); err != nil {
		return core.Account{}, IssuedInvite{}, fmt.Errorf("people: the owner's name: %w", err)
	}
	now := s.now()
	acc := core.Account{ID: core.AccountID(core.NewID(core.PrefixAccount)), Name: name, CreatedAt: now}
	var inv IssuedInvite
	err = s.st.Tx(ctx, func(ctx context.Context) error {
		if err := s.st.Accounts().Create(ctx, acc); err != nil {
			return fmt.Errorf("people: create an account: %w", err)
		}
		var err error
		if inv, err = s.o.Inviter.IssueInviteIn(ctx, s.st, core.InviteOwner, acc.ID, ownerName, by); err != nil {
			return fmt.Errorf("people: issue the owner's invite: %w", err)
		}
		return s.st.Audit().Append(ctx, actorname.Stamp(ctx, s.st.People(), core.AuditEntry{At: now, Actor: by,
			Action: ActionCreate, Target: string(acc.ID), Detail: map[string]string{"invite": inv.ID}, IP: ip}))
	})
	if err != nil {
		return core.Account{}, IssuedInvite{}, err
	}
	return acc, inv, nil
}

// DeleteAccount erases account a everywhere, by actor from ip; by says who asked ("owner" or "superadmin").
//
// The application's Eraser erases its own data first. Only when it succeeded are the account's rows deleted, in one
// transaction; otherwise the account stays, so deleting it again retries, and the failure is audited in the account
// ("account.delete.fail"). The work runs on a context the client cannot cancel: a browser giving up must not leave
// it half done.
func (s *Service) DeleteAccount(ctx context.Context, a core.AccountID, actor core.PersonID, ip, by string) error {
	ctx = context.WithoutCancel(ctx)
	if _, err := s.st.Accounts().Get(ctx, a); err != nil {
		return fmt.Errorf("people: account %q: %w", a, err)
	}
	detail := map[string]string{}
	if s.o.Eraser != nil {
		extra, err := s.o.Eraser.EraseAccount(ctx, a, actor)
		if err != nil {
			var fail map[string]string
			if ee, ok := errors.AsType[*EraseError](err); ok {
				fail = maps.Clone(ee.Detail)
			}
			s.log.Warn("people: the application did not erase an account", "account", string(a), "err", err)
			s.audit(ctx, core.AuditEntry{At: s.now(), AccountID: a, Actor: actor, Action: ActionDeleteFail,
				Target: string(a), Detail: fail, IP: ip})
			return err
		}
		maps.Copy(detail, extra)
	}
	detail["by"] = by
	entry := core.AuditEntry{At: s.now(), Actor: actor, Action: ActionDelete, Target: string(a), Detail: detail}
	if by == "superadmin" {
		// The superadmin's own name and address. An owner's stay out of this system entry (T2.R L9): the superadmin
		// reads it, and it must not name a person of another account.
		entry.IP = ip
		entry = actorname.Stamp(ctx, s.st.People(), entry)
	}
	err := s.st.Tx(ctx, func(ctx context.Context) error {
		if err := s.st.Accounts().Delete(ctx, a); err != nil {
			return fmt.Errorf("people: delete the account: %w", err)
		}
		return s.st.Audit().Append(ctx, entry)
	})
	if errors.Is(err, core.ErrNotFound) {
		return nil // a parallel delete finished first
	}
	return err
}
