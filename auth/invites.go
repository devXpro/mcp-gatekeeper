package auth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
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

// IssueInvite makes an invite: core.InviteOwner (the owner of an account the superadmin made) or core.InviteMember (a
// member of an account, made by its owner). It lives 24 hours and is used once; registering with it creates the
// person in the account, named name unless they type another. by is the person who asked. Errors wrap
// ErrInvalidName for a bad name and core.ErrNotFound for an unknown account. Called with a context inside
// store.Store.Tx, it joins that transaction.
func (a *Auth) IssueInvite(ctx context.Context, kind core.InviteKind, account core.AccountID, name string,
	by core.PersonID) (IssuedInvite, error) {
	return a.IssueInviteIn(ctx, a.st, kind, account, name, by)
}

// IssueInviteIn is IssueInvite on st, e.g. the store whose transaction (carried in ctx) also creates the account.
func (a *Auth) IssueInviteIn(ctx context.Context, st store.Store, kind core.InviteKind, account core.AccountID,
	name string, by core.PersonID) (IssuedInvite, error) {
	if kind != core.InviteOwner && kind != core.InviteMember {
		return IssuedInvite{}, fmt.Errorf("auth: invites of kind %q are not issued here", kind)
	}
	if account == "" || by == "" {
		return IssuedInvite{}, errors.New("auth: an invite needs an account and the person who asks")
	}
	name, err := NormalizeName(name)
	if err != nil {
		return IssuedInvite{}, err
	}
	if _, err := st.Accounts().Get(ctx, account); err != nil {
		return IssuedInvite{}, fmt.Errorf("auth: invite to account %s: %w", account, err)
	}
	token, now := newToken(), a.now()
	inv := core.Invite{
		ID: core.NewID(core.PrefixInvite), TokenHash: hashToken(token), Kind: kind, AccountID: account, Name: name,
		CreatedBy: by, CreatedAt: now, ExpiresAt: now.Add(InviteTTL),
	}
	if err := st.Invites().Create(ctx, inv); err != nil {
		return IssuedInvite{}, fmt.Errorf("auth: store an invite: %w", err)
	}
	return IssuedInvite{ID: inv.ID, URL: a.site.PublicURL + "/join#t=" + token, ExpiresAt: inv.ExpiresAt}, nil
}

// newSetupLink makes a setup link in the caller's transaction (ctx carries it) and revokes the older ones. It is
// refused while an enabled superadmin has a passkey of this site, and while every superadmin is disabled.
func (a *Auth) newSetupLink(ctx context.Context, now time.Time) (url string, expires time.Time, err error) {
	if err := a.setupAllowed(ctx); err != nil {
		return "", time.Time{}, err
	}
	if err := a.st.Invites().RevokeKind(ctx, core.InviteSetup, now); err != nil {
		return "", time.Time{}, fmt.Errorf("auth: revoke the older setup links: %w", err)
	}
	token := newToken()
	inv := core.Invite{ID: core.NewID(core.PrefixInvite), TokenHash: hashToken(token), Kind: core.InviteSetup,
		CreatedAt: now, ExpiresAt: now.Add(SetupLinkTTL)}
	if err := a.st.Invites().Create(ctx, inv); err != nil {
		return "", time.Time{}, fmt.Errorf("auth: store a setup link: %w", err)
	}
	return a.site.PublicURL + "/setup#t=" + token, inv.ExpiresAt, nil
}

// setupAllowed is the rule of the setup-link command: only while no superadmin exists, or after reset-access, i.e.
// while no enabled superadmin has a passkey of this site.
func (a *Auth) setupAllowed(ctx context.Context) error {
	sas, err := superadmins(ctx, a.st)
	if err != nil {
		return err
	}
	enabled := 0
	for _, p := range sas {
		if p.DisabledAt != nil {
			continue
		}
		enabled++
		pks, err := a.passkeysOf(ctx, p.ID)
		if err != nil {
			return err
		}
		if len(usableCreds(pks)) > 0 {
			return a.errSuperadminHasPasskey()
		}
	}
	if len(sas) > 0 && enabled == 0 {
		return errSuperadminDisabled
	}
	return nil
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
		return core.Person{}, false, errSuperadminDisabled
	}
	return core.Person{}, false, nil
}

// peekInvite returns the live invite behind a token: errToken when it is malformed, unknown, used, revoked or
// expired.
func (a *Auth) peekInvite(ctx context.Context, token string) (core.Invite, error) {
	if !wellFormedToken(token) {
		return core.Invite{}, errToken
	}
	inv, err := a.st.Invites().Peek(ctx, hashToken(token), a.now())
	if errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrUsed) || errors.Is(err, core.ErrExpired) {
		return core.Invite{}, errToken
	}
	if err != nil {
		return core.Invite{}, fmt.Errorf("auth: peek an invite: %w", err)
	}
	return inv, nil
}
