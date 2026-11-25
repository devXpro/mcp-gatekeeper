package auth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// IssuedInvite is a new one-time link. URL carries the token in its fragment (#t=…), so neither a proxy's log nor a
// Referer ever holds it: show the URL once to whoever asked, never log or store it.
type IssuedInvite struct {
	ID        string
	URL       string
	ExpiresAt time.Time
}

// IssueInvite makes an invite: core.InviteOwner (the owner of an account the superadmin made, or a co-owner of an
// account that has its owner already) or core.InviteMember (a member of an account, made by its owner). It lives 24
// hours and is used once; registering with it creates the person in the account, named name unless they type
// another. by is the person who asked. Who may ask for which kind is the caller's rule (package people). Errors wrap
// ErrInvalidName for a bad name and core.ErrNotFound for an unknown account. Called with a context inside
// store.Store.Tx, it joins that transaction.
func (a *Auth) IssueInvite(ctx context.Context, kind core.InviteKind, account core.AccountID, name string,
	by core.PersonID) (IssuedInvite, error) {
	return a.issueInvite(ctx, a.st, kind, account, name, by, nil, nil)
}

// IssueInviteIn is IssueInvite on st, e.g. the store whose transaction (carried in ctx) also creates the account.
func (a *Auth) IssueInviteIn(ctx context.Context, st store.Store, kind core.InviteKind, account core.AccountID,
	name string, by core.PersonID) (IssuedInvite, error) {
	return a.issueInvite(ctx, st, kind, account, name, by, nil, nil)
}

// IssueInviteWithAccess is IssueInvite for an invite that gives the person who redeems it a term (until; nil is no
// end) and the application's permission ids (perms; nil or empty is the application's default), the
// core.Person.AccessUntil and Permissions that registering copies to the new member in the same transaction. Only a
// member invite takes them: an owner has everything, with no end. A term that has already ended is refused. auth
// stores the ids as given; checking them against the application's catalog, and the term's bounds, is the caller's
// (package people, whose AccessInviter this is the core of).
func (a *Auth) IssueInviteWithAccess(ctx context.Context, kind core.InviteKind, account core.AccountID, name string,
	by core.PersonID, until *time.Time, perms []string) (IssuedInvite, error) {
	return a.issueInvite(ctx, a.st, kind, account, name, by, until, perms)
}

func (a *Auth) issueInvite(ctx context.Context, st store.Store, kind core.InviteKind, account core.AccountID,
	name string, by core.PersonID, until *time.Time, perms []string) (IssuedInvite, error) {
	if kind != core.InviteOwner && kind != core.InviteMember {
		return IssuedInvite{}, fmt.Errorf("auth: invites of kind %q are not issued here", kind)
	}
	if account == "" || by == "" {
		return IssuedInvite{}, errors.New("auth: an invite needs an account and the person who asks")
	}
	token, now := newToken(), a.now()
	if kind == core.InviteOwner && (until != nil || len(perms) > 0) {
		return IssuedInvite{}, errors.New("auth: an owner invite carries no term and no permissions")
	}
	if until != nil && !now.Before(*until) {
		return IssuedInvite{}, errors.New("auth: the invite's access term has already ended")
	}
	name, err := NormalizeName(name)
	if err != nil {
		return IssuedInvite{}, err
	}
	if _, err := st.Accounts().Get(ctx, account); err != nil {
		return IssuedInvite{}, fmt.Errorf("auth: invite to account %s: %w", account, err)
	}
	inv := core.Invite{
		ID: core.NewID(core.PrefixInvite), TokenHash: hashToken(token), Kind: kind, AccountID: account, Name: name,
		CreatedBy: by, CreatedAt: now, ExpiresAt: now.Add(InviteTTL),
	}
	if until != nil {
		end := until.UTC()
		inv.AccessUntil = &end
	}
	if kind == core.InviteMember {
		inv.Permissions = slices.Clone(perms)
	}
	if err := st.Invites().Create(ctx, inv); err != nil {
		return IssuedInvite{}, fmt.Errorf("auth: store an invite: %w", err)
	}
	return IssuedInvite{ID: inv.ID, URL: a.site.PublicURL + "/join#t=" + token, ExpiresAt: inv.ExpiresAt}, nil
}

// newSetupLink makes a setup link that lives ttl in the caller's transaction (ctx carries it) and revokes the older
// ones. It is refused while an enabled superadmin has a passkey of this site, and while every superadmin is disabled.
func (a *Auth) newSetupLink(ctx context.Context, now time.Time, ttl time.Duration) (url string, expires time.Time,
	err error) {
	if err := a.setupAllowed(ctx); err != nil {
		return "", time.Time{}, err
	}
	if err := a.st.Invites().RevokeKind(ctx, core.InviteSetup, now); err != nil {
		return "", time.Time{}, fmt.Errorf("auth: revoke the older setup links: %w", err)
	}
	token := newToken()
	inv := core.Invite{ID: core.NewID(core.PrefixInvite), TokenHash: hashToken(token), Kind: core.InviteSetup,
		CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if err := a.st.Invites().Create(ctx, inv); err != nil {
		return "", time.Time{}, fmt.Errorf("auth: store a setup link: %w", err)
	}
	return a.site.PublicURL + "/setup#t=" + token, inv.ExpiresAt, nil
}

// IssueSetupLink is the setup-link admin command for a caller inside the application process (Homie's first-run
// page on the home box): the same rule (only while no enabled superadmin has a usable passkey of this site; refused
// with an error wrapping core.ErrConflict otherwise), the same 15-minute link, and the older links revoked. It is
// audited as admin.setup-link with detail via=in-process. The URL carries the token in its fragment: show it to the
// person at the box only, never log or store it.
func (a *Auth) IssueSetupLink(ctx context.Context) (url string, expires time.Time, err error) {
	return a.IssueSetupLinkTTL(ctx, SetupLinkTTL)
}

// IssueSetupLinkTTL is IssueSetupLink with a shorter life for the link (Homie's first-run page: 3 minutes). A ttl
// that is not positive, or longer than SetupLinkTTL, means SetupLinkTTL. The stored link, expires and the audit's
// expires_at all carry the real end.
func (a *Auth) IssueSetupLinkTTL(ctx context.Context, ttl time.Duration) (url string, expires time.Time, err error) {
	if ttl <= 0 || ttl > SetupLinkTTL {
		ttl = SetupLinkTTL
	}
	return a.issueSetupLink(ctx, ttl, "in-process", map[string]string{"via": "in-process"}, nil)
}

// SuperadminCanSignIn reports whether an enabled superadmin has a usable passkey of this site: a stored passkey whose
// credential was registered for this Auth's RP ID. It is the rule IssueSetupLink and the setup-link command refuse a
// link by (they also refuse while every superadmin is disabled); an application asks it to know whether its
// first-run page must still offer a setup link, without reading auth's stored passkeys itself. Errors are store
// failures.
func (a *Auth) SuperadminCanSignIn(ctx context.Context) (bool, error) {
	can, _, _, err := a.superadminSignIn(ctx)
	return can, err
}

// issueSetupLink makes a setup link that lives ttl in a transaction of its own, then audits it as admin.setup-link
// with detail (expires_at added) and logs it as made where, with attrs.
func (a *Auth) issueSetupLink(ctx context.Context, ttl time.Duration, where string, detail map[string]string,
	attrs []any) (url string, expires time.Time, err error) {
	now := a.now()
	err = a.st.Tx(ctx, func(ctx context.Context) error {
		var err error
		url, expires, err = a.newSetupLink(ctx, now, ttl)
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	detail["expires_at"] = rfc3339(expires)
	a.audit(ctx, core.AuditEntry{At: now, Action: "admin.setup-link", Detail: detail})
	a.log.Info("auth: a setup link was made "+where, append([]any{slog.Time("expires", expires)}, attrs...)...)
	return url, expires, nil
}

// setupAllowed is the rule of the setup-link command: only while no superadmin exists, or after reset-access, i.e.
// while no enabled superadmin has a passkey of this site.
func (a *Auth) setupAllowed(ctx context.Context) error {
	can, enabled, total, err := a.superadminSignIn(ctx)
	switch {
	case err != nil:
		return err
	case can:
		return a.errSuperadminHasPasskey()
	case total > 0 && enabled == 0:
		return a.errSuperadminDisabled()
	}
	return nil
}

// superadminSignIn reports whether an enabled superadmin has a usable passkey of this site (stopping at the first
// one), and, when none has, how many superadmins there are and how many of them are enabled. ctx may carry a
// transaction.
func (a *Auth) superadminSignIn(ctx context.Context) (can bool, enabled, total int, err error) {
	sas, err := superadmins(ctx, a.st)
	if err != nil {
		return false, 0, 0, err
	}
	for _, p := range sas {
		if p.DisabledAt != nil {
			continue
		}
		enabled++
		pks, err := a.passkeysOf(ctx, p.ID)
		if err != nil {
			return false, 0, 0, err
		}
		if len(usableCreds(pks)) > 0 {
			return true, enabled, len(sas), nil
		}
	}
	return false, enabled, len(sas), nil
}

// superadmins returns every person flagged superadmin, disabled ones included, oldest first.
func superadmins(ctx context.Context, st store.Store) ([]core.Person, error) {
	accounts, err := st.Accounts().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: list accounts: %w", err)
	}
	var out []core.Person
	for _, acc := range accounts {
		people, err := st.People().ListByAccount(ctx, acc.ID)
		if err != nil {
			return nil, fmt.Errorf("auth: list people: %w", err)
		}
		for _, p := range people {
			if p.Superadmin {
				out = append(out, p)
			}
		}
	}
	slices.SortFunc(out, func(x, y core.Person) int {
		return cmp.Or(x.CreatedAt.Compare(y.CreatedAt), cmp.Compare(x.ID, y.ID))
	})
	return out, nil
}

// setupTarget is the superadmin a setup link adds a passkey to: the oldest enabled one. found is false when there is
// no superadmin at all, and the registration creates the first account; every superadmin disabled is a conflict.
func (a *Auth) setupTarget(ctx context.Context) (target core.Person, found bool, err error) {
	sas, err := superadmins(ctx, a.st)
	if err != nil {
		return core.Person{}, false, err
	}
	for _, p := range sas {
		if p.DisabledAt == nil {
			return p, true, nil
		}
	}
	if len(sas) > 0 {
		return core.Person{}, false, a.errSuperadminDisabled()
	}
	return core.Person{}, false, nil
}

// peekInvite returns the live invite behind a token: errToken when it is malformed, unknown, used, revoked or
// expired, or when the access it gives has already ended.
func (a *Auth) peekInvite(ctx context.Context, token string) (core.Invite, error) {
	if !wellFormedToken(token) {
		return core.Invite{}, errToken
	}
	now := a.now()
	inv, err := a.st.Invites().Peek(ctx, hashToken(token), now)
	if errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrUsed) || errors.Is(err, core.ErrExpired) {
		return core.Invite{}, errToken
	}
	if err != nil {
		return core.Invite{}, fmt.Errorf("auth: peek an invite: %w", err)
	}
	if termEnded(inv, now) {
		return core.Invite{}, errToken
	}
	return inv, nil
}

// termEnded reports whether a member invite gives access that has already ended at now: redeeming it would only make
// a person who cannot sign in.
func termEnded(inv core.Invite, now time.Time) bool {
	return inv.Kind == core.InviteMember && inv.AccessUntil != nil && !now.Before(*inv.AccessUntil)
}
