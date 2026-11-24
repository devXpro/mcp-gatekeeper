package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// newWebAuthn configures go-webauthn: discoverable credentials and user verification required, no attestation, the RP
// ID and the one origin from the site, the relying party's name (a browser may show it next to the domain) from the
// product. Ceremony expiry is ours (CeremonyTTL, on the injected clock), not the
// library's.
func newWebAuthn(site core.Site, product string) (*webauthn.WebAuthn, error) {
	ttl := webauthn.TimeoutConfig{Timeout: CeremonyTTL, TimeoutUVD: CeremonyTTL}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  site.RPID,
		RPDisplayName:         product,
		RPOrigins:             []string{site.PublicURL},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{Login: ttl, Registration: ttl},
		// No extension is requested, and client extension outputs are unsigned and never read here, so an output a
		// password manager adds on its own must not fail an otherwise valid ceremony.
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: relying party %q: %w", site.RPID, err)
	}
	return wa, nil
}

// user is a person as go-webauthn sees them. The user handle is the person id: random, no personal data, and what a
// discoverable sign-in gives back.
type user struct {
	id    core.PersonID
	name  string
	creds []webauthn.Credential
	rp    string // the relying party's name: the name of a person who has none yet
}

func (u user) WebAuthnID() []byte { return []byte(u.id) }

func (u user) WebAuthnName() string {
	if u.name == "" {
		return u.rp
	}
	return u.name
}

func (u user) WebAuthnDisplayName() string                { return u.WebAuthnName() }
func (u user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// plausiblePersonID reports whether a user handle can be a person id, so junk never reaches the store.
func plausiblePersonID(handle []byte) bool {
	return len(handle) > len(core.PrefixPerson)+1 && len(handle) <= 64 &&
		strings.HasPrefix(string(handle), core.PrefixPerson+"_")
}

// storedCredential is core.Passkey.Data. The JSON form of webauthn.CredentialFlags drops the raw flags byte, so it is
// kept next to it; the RP ID records which domain the credential belongs to.
type storedCredential struct {
	V          int                 `json:"v"`
	RPID       string              `json:"rpId"`
	Flags      byte                `json:"flags"`
	Credential webauthn.Credential `json:"credential"`
}

func encodeCredential(rpID string, c *webauthn.Credential) ([]byte, error) {
	cred := *c
	cred.Authenticator.CloneWarning = false
	return json.Marshal(storedCredential{V: 1, RPID: rpID, Flags: byte(cred.Flags.ProtocolValue()), Credential: cred})
}

func decodeCredential(b []byte) (rpID string, c webauthn.Credential, err error) {
	var sc storedCredential
	if err := json.Unmarshal(b, &sc); err != nil {
		return "", webauthn.Credential{}, err
	}
	if sc.V != 1 {
		return "", webauthn.Credential{}, fmt.Errorf("unknown credential format %d", sc.V)
	}
	sc.Credential.Flags = webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(sc.Flags))
	return sc.RPID, sc.Credential, nil
}

// passkey is a stored passkey with its credential. usable means it belongs to this hub's relying party; passkeys of
// another domain (after a domain change) cannot sign in.
type passkey struct {
	core.Passkey
	cred   webauthn.Credential
	usable bool
}

// passkeysOf loads a person's passkeys (in ctx's transaction, if any). An unreadable one is kept, unusable, so it can still be deleted.
func (a *Auth) passkeysOf(ctx context.Context, p core.PersonID) ([]passkey, error) {
	pks, err := a.st.Passkeys().ListByPerson(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("auth: list passkeys: %w", err)
	}
	out := make([]passkey, 0, len(pks))
	for _, pk := range pks {
		rpID, cred, err := decodeCredential(pk.Data)
		if err != nil {
			a.log.Warn("auth: unreadable passkey", slog.String("passkey", pk.ID), slog.Any("error", err))
		}
		out = append(out, passkey{Passkey: pk, cred: cred, usable: err == nil && rpID == a.site.RPID})
	}
	return out, nil
}

// usableCreds are the credentials that can sign in to this hub.
func usableCreds(pks []passkey) []webauthn.Credential {
	var out []webauthn.Credential
	for _, pk := range pks {
		if pk.usable {
			out = append(out, pk.cred)
		}
	}
	return out
}

// byCredential finds the usable passkey of a credential id; the zero passkey (no id, so recordUse fails) when none.
func byCredential(pks []passkey, id []byte) passkey {
	for _, pk := range pks {
		if pk.usable && string(pk.CredentialID) == string(id) {
			return pk
		}
	}
	return passkey{}
}

// recordUse stores what an assertion updated (sign counter, flags) and the time of use. It outlives the request, so
// a client that went away cannot leave the counter behind.
func (a *Auth) recordUse(ctx context.Context, pk passkey, cred *webauthn.Credential, now time.Time) error {
	blob, err := encodeCredential(a.site.RPID, cred)
	if err != nil {
		return err
	}
	err = a.st.Passkeys().Update(context.WithoutCancel(ctx), pk.ID, blob, now)
	if errors.Is(err, core.ErrNotFound) {
		return errNotVerified // deleted while the ceremony ran
	}
	return err
}

// rejected logs why a passkey failed, without anything secret: go-webauthn's error type and details name the failed
// check; its debug info (the expected and received values) is never logged.
func (a *Auth) rejected(what string, r *http.Request, err error) {
	reason := err.Error()
	if pe, ok := errors.AsType[*protocol.Error](err); ok {
		reason = pe.Type + ": " + pe.Details
	}
	a.log.Info("auth: passkey rejected", slog.String("ceremony", what), slog.String("reason", clip(reason, 200)),
		slog.String("client", a.clientIP(r)))
}

// cloned reports, and logs, an assertion whose signature counter did not move forward: two copies of the private key
// may exist. Synced passkeys always report 0 and never trip it.
func (a *Auth) cloned(r *http.Request, pk passkey, cred *webauthn.Credential) bool {
	if !cred.Authenticator.CloneWarning {
		return false
	}
	a.log.Warn("auth: passkey signature counter went backwards; possible cloned authenticator",
		slog.String("passkey", pk.ID), slog.String("client", a.clientIP(r)))
	return true
}
