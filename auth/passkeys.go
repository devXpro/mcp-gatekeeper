package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// passkeyJSON is one passkey of Family Hub's §5.9; last_used_at is null for a passkey never used to sign in.
type passkeyJSON struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
}

func passkeyOf(pk core.Passkey) passkeyJSON {
	return passkeyJSON{ID: pk.ID, Name: pk.Name, CreatedAt: rfc3339(pk.CreatedAt), LastUsedAt: optTimePtr(pk.LastUsedAt)}
}

// listPasskeys answers the signed-in person's own passkeys, oldest first.
func (a *Auth) listPasskeys(w http.ResponseWriter, r *http.Request) {
	pks, err := a.st.Passkeys().ListByPerson(r.Context(), viewerOf(r).Person.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]passkeyJSON, 0, len(pks))
	for _, pk := range pks {
		out = append(out, passkeyOf(pk))
	}
	writeJSON(w, http.StatusOK, out)
}

// passkeyBegin starts the registration of another passkey for the signed-in person; their passkeys are excluded, so
// an authenticator that holds one says so at once.
func (a *Auth) passkeyBegin(w http.ResponseWriter, r *http.Request) {
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
	u := user{id: v.Person.ID, name: v.Person.Name, creds: usableCreds(pks), rp: a.brand.Product}
	creation, data, err := a.wa.BeginRegistration(u, webauthn.WithExclusions(webauthn.Credentials(u.creds).CredentialDescriptors()))
	if err != nil {
		a.fail(w, r, fmt.Errorf("auth: begin registration: %w", err))
		return
	}
	a.begin(w, r, &ceremony{kind: kindAddPasskey, data: *data, session: v.Session.IDHash, person: v.Person.ID},
		creation.Response)
}

// passkeyFinish stores the new passkey. Step-up is checked before the ceremony is taken (RequireStepUp), so the SPA
// can step up and retry the same finish.
func (a *Auth) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	var body finishBody
	if err := decode(w, r, &body); err != nil {
		a.fail(w, r, err)
		return
	}
	name := defaultPasskeyName(r.UserAgent())
	if body.Name != "" {
		var err error
		if name, err = requiredName("name", body.Name); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	v := viewerOf(r)
	now := a.now()
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Credential)
	if err != nil {
		a.rejected("new passkey", r, err)
		a.fail(w, r, errNotVerified)
		return
	}
	cer, ok := a.ceremonies.take(parsed.Response.CollectedClientData.Challenge, now,
		ofSession(kindAddPasskey, v.Session.IDHash))
	if !ok {
		a.fail(w, r, errCeremony)
		return
	}
	cred, err := a.wa.CreateCredential(user{id: v.Person.ID, rp: a.brand.Product}, cer.data, parsed)
	if err != nil {
		a.rejected("new passkey", r, err)
		a.fail(w, r, errNotVerified)
		return
	}
	blob, err := encodeCredential(a.site.RPID, cred)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ctx := r.Context()
	// A credential id that is already known, the person's own or anybody's, is refused (WebAuthn §7.1).
	if _, err := a.st.Passkeys().GetByCredentialID(ctx, cred.ID); err == nil {
		a.fail(w, r, errPasskeyExists)
		return
	} else if !errors.Is(err, core.ErrNotFound) {
		a.fail(w, r, err)
		return
	}
	pk := core.Passkey{ID: core.NewID(core.PrefixPasskey), PersonID: v.Person.ID, CredentialID: cred.ID, Data: blob,
		Name: name, CreatedAt: now}
	if err := a.st.Passkeys().Add(ctx, pk); errors.Is(err, core.ErrConflict) {
		a.fail(w, r, errPasskeyExists)
		return
	} else if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(ctx, core.AuditEntry{At: now, AccountID: v.Account.ID, Actor: v.Person.ID, Action: "auth.passkey.add",
		Target: pk.ID, Detail: map[string]string{"name": pk.Name}, IP: a.clientIP(r)})
	writeJSON(w, http.StatusCreated, passkeyOf(pk))
}

// ownPasskey is the signed-in person's passkey with the id of the path; somebody else's is not found.
func (a *Auth) ownPasskey(r *http.Request, v core.Viewer) (core.Passkey, error) {
	pk, err := a.st.Passkeys().Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, core.ErrNotFound) || err == nil && pk.PersonID != v.Person.ID {
		return core.Passkey{}, errPasskeyNotFound
	}
	return pk, err
}

func (a *Auth) renamePasskey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decode(w, r, &body); err != nil {
		a.fail(w, r, err)
		return
	}
	name, err := requiredName("name", body.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	v := viewerOf(r)
	pk, err := a.ownPasskey(r, v)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ctx := r.Context()
	if name != pk.Name {
		if err := a.st.Passkeys().Rename(ctx, pk.ID, name); errors.Is(err, core.ErrNotFound) {
			a.fail(w, r, errPasskeyNotFound)
			return
		} else if err != nil {
			a.fail(w, r, err)
			return
		}
		a.audit(ctx, core.AuditEntry{AccountID: v.Account.ID, Actor: v.Person.ID, Action: "auth.passkey.rename",
			Target: pk.ID, Detail: map[string]string{"name": name}, IP: a.clientIP(r)})
		pk.Name = name
	}
	writeJSON(w, http.StatusOK, passkeyOf(pk))
}

// deletePasskey removes one of the signed-in person's passkeys, never the last one that can sign in to this site
// (passkeys of another domain can always go), and ends the person's other sessions: 204 with a new cookie.
// Deletions are serialized, so two at once cannot both pass the check.
func (a *Auth) deletePasskey(w http.ResponseWriter, r *http.Request) {
	v := viewerOf(r)
	a.deletes.Lock()
	defer a.deletes.Unlock()
	pk, err := a.ownPasskey(r, v)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pks, err := a.passkeysOf(r.Context(), v.Person.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	usable, target := 0, false
	for _, p := range pks {
		if p.usable {
			usable++
			target = target || p.ID == pk.ID
		}
	}
	if target && usable <= 1 {
		a.fail(w, r, errLastPasskey)
		return
	}
	// The deleted passkey may have opened sessions on a lost device: every session of the person ends with it, and
	// this browser continues in a new one (T2.R M3).
	now := a.now()
	var (
		token string
		s     core.Session
	)
	err = a.st.Tx(r.Context(), func(ctx context.Context) error {
		if err := a.st.Passkeys().Delete(ctx, pk.ID); errors.Is(err, core.ErrNotFound) {
			return errPasskeyNotFound
		} else if err != nil {
			return err
		}
		var err error
		token, s, err = a.rotateIn(ctx, v, now)
		return err
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r.Context(), core.AuditEntry{At: now, AccountID: v.Account.ID, Actor: v.Person.ID,
		Action: "auth.passkey.delete", Target: pk.ID, Detail: map[string]string{"name": pk.Name}, IP: a.clientIP(r)})
	a.setSessionCookieFor(w, token, s.ExpiresAt.Sub(now))
	w.WriteHeader(http.StatusNoContent)
}
