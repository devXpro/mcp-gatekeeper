package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// beginJSON answers every begin: the WebAuthn options in their JSON form, exactly the
// PublicKeyCredential{Creation,Request}OptionsJSON that @simplewebauthn/browser takes as optionsJSON.
type beginJSON struct {
	Options any `json:"options"`
}

// finishBody is the request of every finish: the browser's answer, unchanged. Name labels a new passkey
// (me/passkeys/finish only).
type finishBody struct {
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

// begin stores a ceremony and answers its options.
func (a *Auth) begin(w http.ResponseWriter, r *http.Request, cer *ceremony, options any) {
	now := a.now()
	cer.expires = now.Add(CeremonyTTL)
	if !a.ceremonies.add(cer, now) {
		a.fail(w, r, errBusy)
		return
	}
	writeJSON(w, http.StatusOK, beginJSON{Options: options})
}

// --- POST /api/auth/token ---

type tokenInfoJSON struct {
	Kind        core.InviteKind `json:"kind"`
	Name        string          `json:"name"`
	AccountName string          `json:"account_name,omitempty"`
}

// tokenInfo says what a setup link or invite is: its kind, the name to show (the inviter's spelling, or the
// superadmin's after reset-access) and the account it joins. 404 when it is not usable.
func (a *Auth) tokenInfo(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decode(w, r, &body); err != nil {
		a.fail(w, r, err)
		return
	}
	ctx := r.Context()
	inv, err := a.peekInvite(ctx, body.Token)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := tokenInfoJSON{Kind: inv.Kind, Name: inv.Name}
	switch inv.Kind {
	case core.InviteSetup:
		target, found, err := a.setupTarget(ctx)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if found {
			acc, err := a.st.Accounts().Get(ctx, target.AccountID)
			if err != nil {
				a.fail(w, r, err)
				return
			}
			out.Name, out.AccountName = target.Name, acc.Name
		}
	case core.InviteOwner, core.InviteMember:
		acc, err := a.st.Accounts().Get(ctx, inv.AccountID)
		if errors.Is(err, core.ErrNotFound) {
			a.fail(w, r, errToken)
			return
		}
		if err != nil {
			a.fail(w, r, err)
			return
		}
		out.AccountName = acc.Name
	default:
		a.fail(w, r, errToken)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// --- registration ---

// registration is what a register/begin found the token to mean; register/finish carries it out.
type registration struct {
	kind        core.InviteKind
	inviteID    string
	tokenHash   []byte
	person      core.PersonID  // a new id, or the superadmin's after reset-access
	existing    bool           // a setup link after reset-access: the person exists
	personName  string         // the new person's name; for an existing person a new name ("" keeps it)
	account     core.AccountID // a new id for the first setup, or the account of the invite or the superadmin
	newAccount  bool           // the first setup: the account is created
	accountName string         // the new account's name; otherwise a new name ("" keeps it)
}

// registerBegin starts a passkey registration with a setup link or an invite. name is the person's name: required for
// the first setup, otherwise it defaults to the invite's. account_name names the first account, and renames the
// account for an owner invite or a later setup link; a member invite ignores it.
func (a *Auth) registerBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token       string `json:"token"`
		Name        string `json:"name"`
		AccountName string `json:"account_name"`
	}
	if err := decode(w, r, &body); err != nil {
		a.fail(w, r, err)
		return
	}
	ctx := r.Context()
	inv, err := a.peekInvite(ctx, body.Token)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	reg, displayName, err := a.planRegistration(ctx, inv, body.Name, body.AccountName)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	u := user{id: reg.person, name: displayName, rp: a.brand.Product}
	if reg.existing {
		pks, err := a.passkeysOf(ctx, reg.person)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		u.creds = usableCreds(pks)
	}
	creation, data, err := a.wa.BeginRegistration(u, webauthn.WithExclusions(webauthn.Credentials(u.creds).CredentialDescriptors()))
	if err != nil {
		a.fail(w, r, fmt.Errorf("auth: begin registration: %w", err))
		return
	}
	a.begin(w, r, &ceremony{kind: kindRegister, data: *data, person: reg.person, reg: reg}, creation.Response)
}

// optionalName checks a name the client may leave out; "" stays "".
func optionalName(field, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	return requiredName(field, v)
}

// requiredName checks a name for a request field, as a 400 invalid naming the field.
func requiredName(field, v string) (string, error) {
	n, problem := checkName(v)
	if problem != "" {
		return "", invalid("%s %s", field, problem)
	}
	return n, nil
}

// planRegistration decides what registering with inv creates, and the name the passkey shows.
func (a *Auth) planRegistration(ctx context.Context, inv core.Invite, name, accountName string) (*registration, string, error) {
	name, err := optionalName("name", name)
	if err != nil {
		return nil, "", err
	}
	accountName, err = optionalName("account_name", accountName)
	if err != nil {
		return nil, "", err
	}
	reg := &registration{kind: inv.Kind, inviteID: inv.ID, tokenHash: inv.TokenHash}
	switch inv.Kind {
	case core.InviteSetup:
		target, found, err := a.setupTarget(ctx)
		if err != nil {
			return nil, "", err
		}
		if found {
			reg.person, reg.existing, reg.account = target.ID, true, target.AccountID
			reg.personName, reg.accountName = name, accountName
			return reg, cmpOr(name, target.Name), nil
		}
		if name == "" {
			return nil, "", invalid("name is required")
		}
		if accountName == "" {
			return nil, "", invalid("account_name is required")
		}
		reg.person, reg.account, reg.newAccount = core.PersonID(core.NewID(core.PrefixPerson)),
			core.AccountID(core.NewID(core.PrefixAccount)), true
		reg.personName, reg.accountName = name, accountName
		return reg, name, nil
	case core.InviteOwner, core.InviteMember:
		if _, err := a.st.Accounts().Get(ctx, inv.AccountID); errors.Is(err, core.ErrNotFound) {
			return nil, "", errToken
		} else if err != nil {
			return nil, "", err
		}
		reg.personName = cmpOr(name, inv.Name)
		if reg.personName == "" {
			return nil, "", invalid("name is required")
		}
		reg.person, reg.account = core.PersonID(core.NewID(core.PrefixPerson)), inv.AccountID
		if inv.Kind == core.InviteOwner {
			reg.accountName = accountName
		}
		return reg, reg.personName, nil
	}
	return nil, "", errToken
}

func cmpOr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// registerFinish verifies the new passkey and, in one transaction, uses the token, creates the person (and the first
// account), stores the passkey and opens a session. Then it sets the cookie.
func (a *Auth) registerFinish(w http.ResponseWriter, r *http.Request) {
	var body finishBody
	if err := decode(w, r, &body); err != nil {
		a.fail(w, r, err)
		return
	}
	now := a.now()
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Credential)
	if err != nil {
		a.rejected("registration", r, err)
		a.fail(w, r, errNotVerified)
		return
	}
	cer, ok := a.ceremonies.take(parsed.Response.CollectedClientData.Challenge, now, isKind(kindRegister))
	if !ok {
		a.fail(w, r, errCeremony)
		return
	}
	reg := cer.reg
	cred, err := a.wa.CreateCredential(user{id: reg.person, rp: a.brand.Product}, cer.data, parsed)
	if err != nil {
		a.rejected("registration", r, err)
		a.fail(w, r, errNotVerified)
		return
	}
	blob, err := encodeCredential(a.site.RPID, cred)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	token, sess := a.newSession(reg.person, r.UserAgent(), now)
	var (
		person  core.Person
		account core.Account
	)
	err = a.st.Tx(r.Context(), func(ctx context.Context) error {
		inv, err := a.st.Invites().Consume(ctx, reg.tokenHash, now)
		if errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrUsed) || errors.Is(err, core.ErrExpired) {
			return errToken
		}
		if err != nil {
			return err
		}
		if inv.ID != reg.inviteID || inv.Kind != reg.kind {
			return errToken
		}
		if _, err := a.st.Passkeys().GetByCredentialID(ctx, cred.ID); err == nil {
			return errPasskeyExists
		} else if !errors.Is(err, core.ErrNotFound) {
			return err
		}
		if person, account, err = a.applyRegistration(ctx, reg, now); err != nil {
			return err
		}
		used := now
		err = a.st.Passkeys().Add(ctx, core.Passkey{
			ID: core.NewID(core.PrefixPasskey), PersonID: person.ID, CredentialID: cred.ID, Data: blob,
			Name: defaultPasskeyName(r.UserAgent()), CreatedAt: now, LastUsedAt: &used,
		})
		if errors.Is(err, core.ErrConflict) {
			return errPasskeyExists
		}
		if err != nil {
			return err
		}
		return a.st.Sessions().Create(ctx, sess)
	})
	if err != nil {
		if ae, ok := errors.AsType[*apiError](err); ok {
			a.log.Info("auth: registration refused", slog.String("kind", string(reg.kind)), slog.String("reason", ae.message),
				slog.String("client", a.clientIP(r)))
		}
		a.fail(w, r, err)
		return
	}
	action, detail := "auth.register", map[string]string{"kind": string(reg.kind)}
	if reg.kind != core.InviteSetup {
		action, detail["invite"] = "auth.join", reg.inviteID
	}
	a.audit(r.Context(), core.AuditEntry{At: now, AccountID: account.ID, Actor: person.ID, Action: action,
		Target: string(person.ID), Detail: detail, IP: a.clientIP(r)})
	a.log.Info("auth: a passkey was registered with a one-time link", slog.String("action", action),
		slog.String("person", string(person.ID)), slog.String("account", string(account.ID)))
	a.setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, signedInJSON{Person: personOf(person), Account: accountOf(account)})
}

// applyRegistration creates or updates the person and account of a registration, inside its transaction (ctx carries
// it): the first account and its superadmin owner, the superadmin again after reset-access, or a new person of an
// invite's account.
func (a *Auth) applyRegistration(ctx context.Context, reg *registration, now time.Time) (core.Person, core.Account, error) {
	st := a.st
	switch {
	case reg.newAccount:
		n, err := st.People().CountSuperadmins(ctx)
		if err != nil {
			return core.Person{}, core.Account{}, err
		}
		if n > 0 {
			return core.Person{}, core.Account{}, errSuperadminExists
		}
		acc := core.Account{ID: reg.account, Name: reg.accountName, CreatedAt: now}
		if err := st.Accounts().Create(ctx, acc); err != nil {
			return core.Person{}, core.Account{}, err
		}
		p := core.Person{ID: reg.person, AccountID: acc.ID, Name: reg.personName, Role: core.RoleOwner, Superadmin: true,
			CreatedAt: now}
		if err := st.People().Create(ctx, p); err != nil {
			return core.Person{}, core.Account{}, err
		}
		return p, acc, nil
	case reg.existing:
		p, err := st.People().Get(ctx, reg.person)
		if errors.Is(err, core.ErrNotFound) {
			return core.Person{}, core.Account{}, errToken
		}
		if err != nil {
			return core.Person{}, core.Account{}, err
		}
		if !p.Superadmin || p.DisabledAt != nil {
			return core.Person{}, core.Account{}, errToken
		}
		acc, err := st.Accounts().Get(ctx, p.AccountID)
		if errors.Is(err, core.ErrNotFound) {
			return core.Person{}, core.Account{}, errToken
		}
		if err != nil {
			return core.Person{}, core.Account{}, err
		}
		if reg.personName != "" && reg.personName != p.Name {
			if err := st.People().Rename(ctx, p.ID, reg.personName); err != nil {
				return core.Person{}, core.Account{}, err
			}
			p.Name = reg.personName
		}
		if reg.accountName != "" && reg.accountName != acc.Name {
			if err := st.Accounts().Rename(ctx, acc.ID, reg.accountName); err != nil {
				return core.Person{}, core.Account{}, err
			}
			acc.Name = reg.accountName
		}
		return p, acc, nil
	}
	acc, err := st.Accounts().Get(ctx, reg.account)
	if errors.Is(err, core.ErrNotFound) {
		return core.Person{}, core.Account{}, errToken
	}
	if err != nil {
		return core.Person{}, core.Account{}, err
	}
	if reg.accountName != "" && reg.accountName != acc.Name {
		if err := st.Accounts().Rename(ctx, acc.ID, reg.accountName); err != nil {
			return core.Person{}, core.Account{}, err
		}
		acc.Name = reg.accountName
	}
	role := core.RoleMember
	if reg.kind == core.InviteOwner {
		role = core.RoleOwner
	}
	p := core.Person{ID: reg.person, AccountID: acc.ID, Name: reg.personName, Role: role, CreatedAt: now}
	if err := st.People().Create(ctx, p); err != nil {
		return core.Person{}, core.Account{}, err
	}
	return p, acc, nil
}
