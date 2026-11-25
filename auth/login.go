package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// --- sign-in ---

// loginBegin starts a discoverable sign-in: no user name, the passkey says who it is.
func (a *Auth) loginBegin(w http.ResponseWriter, r *http.Request) {
	if err := decode(w, r, &struct{}{}); err != nil {
		a.fail(w, r, err)
		return
	}
	assertion, data, err := a.wa.BeginDiscoverableLogin()
	if err != nil {
		a.fail(w, r, fmt.Errorf("auth: begin login: %w", err))
		return
	}
	a.begin(w, r, &ceremony{kind: kindLogin, data: *data}, assertion.Response)
}

// loginFinish verifies a discoverable assertion (the user handle names a person, the credential is one of theirs,
// and challenge, origin, RP ID, user verification and signature hold) and opens a session. Every client-side failure
// is the same 400 invalid and counts towards an auth.login.fail audit entry (loginfail.go).
func (a *Auth) loginFinish(w http.ResponseWriter, r *http.Request) {
	var body finishBody
	if err := decode(w, r, &body); err != nil {
		a.fail(w, r, err)
		return
	}
	now := a.now()
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		a.rejected("sign-in", r, err)
		a.fail(w, r, errNotVerified)
		return
	}
	cer, ok := a.ceremonies.take(parsed.Response.CollectedClientData.Challenge, now, isKind(kindLogin))
	if !ok {
		a.fail(w, r, errCeremony)
		return
	}
	ctx := r.Context()
	var (
		person    core.Person
		pks       []passkey
		lookupErr error
	)
	lookup := func(_, userHandle []byte) (webauthn.User, error) {
		if !plausiblePersonID(userHandle) {
			return nil, errors.New("not a person id")
		}
		p, err := a.st.People().Get(ctx, core.PersonID(userHandle))
		if err != nil {
			if !errors.Is(err, core.ErrNotFound) {
				lookupErr = err
			}
			return nil, err
		}
		list, err := a.passkeysOf(ctx, p.ID)
		if err != nil {
			lookupErr = err
			return nil, err
		}
		person, pks = p, list
		return user{id: p.ID, name: p.Name, creds: usableCreds(list), rp: a.brand.Product}, nil
	}
	_, cred, err := a.wa.ValidatePasskeyLogin(lookup, cer.data, parsed)
	if lookupErr != nil {
		a.fail(w, r, lookupErr) // the store failed; it says nothing about the client
		return
	}
	if err != nil {
		a.rejected("sign-in", r, err)
		a.loginFailed(w, r)
		return
	}
	pk := byCredential(pks, cred.ID)
	if a.cloned(r, pk, cred) || person.DisabledAt != nil {
		a.loginFailed(w, r)
		return
	}
	if !person.Active(now) {
		// The passkey verified, so its holder may learn why: a guest whose term ended, until the owner extends it.
		a.log.Info("auth: sign-in refused: the access term has ended", slog.String("person", string(person.ID)))
		a.fail(w, r, errAccessEnded)
		return
	}
	account, err := a.st.Accounts().Get(ctx, person.AccountID)
	if errors.Is(err, core.ErrNotFound) {
		a.loginFailed(w, r)
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.recordUse(ctx, pk, cred, now); err != nil {
		if errors.Is(err, errNotVerified) {
			a.loginFailed(w, r)
			return
		}
		a.fail(w, r, err)
		return
	}
	token, sess := a.newSession(person.ID, r.UserAgent(), now)
	if err := a.st.Sessions().Create(ctx, sess); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(ctx, core.AuditEntry{At: now, AccountID: account.ID, Actor: person.ID, Action: "auth.login",
		Target: string(person.ID), IP: a.clientIP(r)})
	a.setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, signedInJSON{Person: personOf(person), Account: accountOf(account)})
}

// --- step-up ---

// stepUpBegin asks for a fresh assertion of one of the signed-in person's own passkeys.
func (a *Auth) stepUpBegin(w http.ResponseWriter, r *http.Request) {
	if err := decode(w, r, &struct{}{}); err != nil {
		a.fail(w, r, err)
		return
	}
	v := viewerOf(r)
	pks, err := a.passkeysOf(r.Context(), v.Person.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	creds := usableCreds(pks)
	if len(creds) == 0 {
		a.fail(w, r, a.errNoPasskey())
		return
	}
	assertion, data, err := a.wa.BeginLogin(user{id: v.Person.ID, name: v.Person.Name, creds: creds, rp: a.brand.Product})
	if err != nil {
		a.fail(w, r, fmt.Errorf("auth: begin step-up: %w", err))
		return
	}
	a.begin(w, r, &ceremony{kind: kindStepUp, data: *data, session: v.Session.IDHash, person: v.Person.ID},
		assertion.Response)
}

type stepUpJSON struct {
	StepUpUntil string `json:"step_up_until"`
}

// stepUpFinish verifies the assertion against the person's own passkeys (somebody else's fails like any other) in
// the session that began it, and marks the session stepped up for 5 minutes.
func (a *Auth) stepUpFinish(w http.ResponseWriter, r *http.Request) {
	var body finishBody
	if err := decode(w, r, &body); err != nil {
		a.fail(w, r, err)
		return
	}
	v := viewerOf(r)
	now := a.now()
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		a.rejected("step-up", r, err)
		a.fail(w, r, errNotVerified)
		return
	}
	cer, ok := a.ceremonies.take(parsed.Response.CollectedClientData.Challenge, now, ofSession(kindStepUp, v.Session.IDHash))
	if !ok {
		a.fail(w, r, errCeremony)
		return
	}
	ctx := r.Context()
	pks, err := a.passkeysOf(ctx, v.Person.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cred, err := a.wa.ValidateLogin(user{id: v.Person.ID, name: v.Person.Name, creds: usableCreds(pks), rp: a.brand.Product},
		cer.data, parsed)
	if err != nil {
		a.rejected("step-up", r, err)
		a.stepUpFailed(w, r, v)
		return
	}
	pk := byCredential(pks, cred.ID)
	if a.cloned(r, pk, cred) {
		a.stepUpFailed(w, r, v)
		return
	}
	if err := a.recordUse(ctx, pk, cred, now); err != nil {
		if errors.Is(err, errNotVerified) {
			a.stepUpFailed(w, r, v)
			return
		}
		a.fail(w, r, err)
		return
	}
	until := now.Add(StepUpWindow)
	if err := a.st.Sessions().SetStepUp(ctx, v.Session.IDHash, until); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			a.fail(w, r, errNoSession)
			return
		}
		a.fail(w, r, err)
		return
	}
	a.audit(ctx, core.AuditEntry{At: now, AccountID: v.Account.ID, Actor: v.Person.ID, Action: "auth.stepup",
		Target: string(v.Person.ID), IP: a.clientIP(r)})
	writeJSON(w, http.StatusOK, stepUpJSON{StepUpUntil: rfc3339(until)})
}

// stepUpFailed audits a step-up that did not verify in the person's account: a session without its passkey (a stolen
// cookie, say) is worth the owner's notice.
func (a *Auth) stepUpFailed(w http.ResponseWriter, r *http.Request, v core.Viewer) {
	a.audit(r.Context(), core.AuditEntry{AccountID: v.Account.ID, Actor: v.Person.ID, Action: "auth.stepup.fail",
		Target: string(v.Person.ID), IP: a.clientIP(r)})
	a.log.Info("auth: step-up failed", slog.String("person", string(v.Person.ID)))
	a.fail(w, r, errNotVerified)
}
