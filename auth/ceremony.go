package auth

import (
	"bytes"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// ceremonyKind tells the four passkey ceremonies apart; a ceremony can only be finished by its own endpoint.
type ceremonyKind uint8

const (
	kindRegister   ceremonyKind = iota + 1 // register/begin: a setup link or an invite
	kindLogin                              // login/begin: a discoverable sign-in
	kindStepUp                             // stepup/begin: a fresh assertion in a session
	kindAddPasskey                         // me/passkeys/begin: another passkey of the signed-in person
)

// public reports whether anybody may begin a ceremony of this kind, without a session.
func (k ceremonyKind) public() bool { return k == kindRegister || k == kindLogin }

// maxCeremonies bounds each of the two pools of pending ceremonies: the public ones and the ones of sessions, so an
// anonymous flood can never crowd out a signed-in person's step-up.
const maxCeremonies = 1000

// ceremony is the server side of a begun passkey ceremony: in memory, 5 minutes, single use. It is found again by its
// challenge, which the finish carries inside the credential's clientDataJSON.
type ceremony struct {
	kind    ceremonyKind
	data    webauthn.SessionData
	expires time.Time

	session []byte        // kindStepUp, kindAddPasskey: the hash of the session that began it
	person  core.PersonID // kindStepUp, kindAddPasskey: whose session it is
	reg     *registration // kindRegister: what the finish creates
}

// ceremonies holds the pending ceremonies by challenge.
type ceremonies struct {
	mu sync.Mutex
	m  map[string]*ceremony
}

func newCeremonies() *ceremonies { return &ceremonies{m: map[string]*ceremony{}} }

// add stores c under its challenge. When c's pool is full, a public ceremony takes the place of the oldest public one
// (a flood of begins cannot keep a real sign-in from starting) and a session's ceremony is refused (the per-session
// limits keep that pool far from full).
func (cs *ceremonies) add(c *ceremony, now time.Time) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if _, taken := cs.m[c.data.Challenge]; taken || c.data.Challenge == "" {
		return false // 32 random bytes do not repeat; refuse rather than replace
	}
	var (
		pool      int
		oldest    string
		oldestExp time.Time
	)
	for k, v := range cs.m {
		switch {
		case !now.Before(v.expires):
			delete(cs.m, k)
		case v.kind.public() == c.kind.public():
			pool++
			if oldest == "" || v.expires.Before(oldestExp) {
				oldest, oldestExp = k, v.expires
			}
		}
	}
	if pool >= maxCeremonies {
		if !c.kind.public() {
			return false
		}
		delete(cs.m, oldest)
	}
	cs.m[c.data.Challenge] = c
	return true
}

// take removes and returns the ceremony of a challenge when it is unexpired and match accepts it. A ceremony that
// match refuses (another kind, another session) stays, so a stray request cannot burn somebody else's ceremony.
func (cs *ceremonies) take(challenge string, now time.Time, match func(*ceremony) bool) (*ceremony, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	c, ok := cs.m[challenge]
	if !ok || !match(c) {
		return nil, false
	}
	delete(cs.m, challenge)
	if !now.Before(c.expires) {
		return nil, false
	}
	return c, true
}

func isKind(k ceremonyKind) func(*ceremony) bool {
	return func(c *ceremony) bool { return c.kind == k }
}

// ofSession accepts a ceremony of kind k begun by the session with this hash.
func ofSession(k ceremonyKind, sessionHash []byte) func(*ceremony) bool {
	return func(c *ceremony) bool { return c.kind == k && bytes.Equal(c.session, sessionHash) }
}
