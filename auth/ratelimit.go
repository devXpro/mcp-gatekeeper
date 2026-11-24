package auth

import (
	"encoding/hex"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

// Every class of endpoint has buckets of its own, so spending one never locks another: an anonymous flood of sign-in
// attempts cannot stop a signed-in person's step-up, and junk on auth/token cannot stop a sign-in (the GPT-Home
// rules). No bucket is shared by every client: a few addresses could spend it and lock everybody out (T2.R H2), and
// invite tokens are 256-bit, so there is no guessing a shared bucket would slow down.
const (
	tokenPerAddress = 20 // auth/token and register begin and finish: requests per minute per client address
	beginsPerKey    = 30 // login, step-up and passkey begins per minute per client address (login) or session
	failuresPerKey  = 10 // failed login, step-up and passkey finishes per minute per client address or session
	maxBuckets      = 4096
)

// limiter is a token bucket per key. A bucket holds a minute's worth of tokens and refills continuously.
type limiter struct {
	perKey float64 // tokens per minute

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perKey int) *limiter {
	return &limiter{perKey: float64(perKey), buckets: map[string]*bucket{}}
}

// refill brings the bucket up to now at rate tokens per minute; a new bucket starts full.
func (b *bucket) refill(rate float64, now time.Time) {
	if b.last.IsZero() {
		b.tokens = rate
	} else if d := now.Sub(b.last); d > 0 {
		b.tokens = min(rate, b.tokens+d.Minutes()*rate)
	}
	b.last = now
}

// wait is how long until the bucket holds a whole token again.
func (b *bucket) wait(rate float64) time.Duration {
	return time.Duration((1 - b.tokens) / rate * float64(time.Minute))
}

// peek reports whether the bucket holds a token, without taking it, and otherwise how long to wait.
func (b *bucket) peek(rate float64, now time.Time) (bool, time.Duration) {
	b.refill(rate, now)
	if b.tokens >= 1 {
		return true, 0
	}
	return false, b.wait(rate)
}

func (b *bucket) take(rate float64, now time.Time) (bool, time.Duration) {
	if ok, wait := b.peek(rate, now); !ok {
		return false, wait
	}
	b.tokens--
	return true, 0
}

// bucketLocked returns key's bucket, making it (and pruning the map when it is full). l.mu is held.
func (l *limiter) bucketLocked(key string, now time.Time) *bucket {
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			l.prune(now)
		}
		b = &bucket{}
		l.buckets[key] = b
	}
	return b
}

// take takes a token from key's bucket; when it refuses, it says how long to wait.
func (l *limiter) take(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bucketLocked(key, now).take(l.perKey, now)
}

// peek reports whether key has a token left, without taking it.
func (l *limiter) peek(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bucketLocked(key, now).peek(l.perKey, now)
}

// prune drops the buckets that refilled completely; if that is not enough (an address flood), it drops half of the
// rest.
func (l *limiter) prune(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) >= time.Minute {
			delete(l.buckets, k)
		}
	}
	for k := range l.buckets {
		if len(l.buckets) < maxBuckets/2 {
			break
		}
		delete(l.buckets, k)
	}
}

// gate limits one ceremony class per key, a client address (sign-in) or a session (step-up, another passkey): begins
// are counted, and so are failed finishes, not the successful ones. While a key's failures are spent, its begins and
// finishes are both refused.
type gate struct {
	begins, failures *limiter
}

func newGate() *gate {
	return &gate{begins: newLimiter(beginsPerKey), failures: newLimiter(failuresPerKey)}
}

func (g *gate) begin(key string, now time.Time) (bool, time.Duration) {
	if ok, wait := g.failures.peek(key, now); !ok {
		return false, wait
	}
	return g.begins.take(key, now)
}

func (g *gate) finish(key string, now time.Time) (bool, time.Duration) {
	return g.failures.peek(key, now)
}

func (g *gate) failed(key string, now time.Time) { g.failures.take(key, now) }

// rateClass names the buckets an endpoint uses.
type rateClass int

const (
	rateToken         rateClass = iota + 1 // every request, per client address
	rateLoginBegin                         // per client address: a begin, refused while the failures are spent
	rateLoginFinish                        // per client address: refused while the failures are spent
	rateStepUpBegin                        // per session, as rateLoginBegin
	rateStepUpFinish                       // per session, as rateLoginFinish
	ratePasskeyBegin                       // per session, as rateLoginBegin
	ratePasskeyFinish                      // per session, as rateLoginFinish
)

// limits are the buckets of the auth endpoints.
type limits struct {
	token   *limiter // auth/token, register/begin, register/finish, per client address
	login   *gate    // login/begin and login/finish, per client address
	stepUp  *gate    // stepup/begin and stepup/finish, per session
	passkey *gate    // me/passkeys/begin and me/passkeys/finish, per session
}

func newLimits() limits {
	return limits{token: newLimiter(tokenPerAddress), login: newGate(), stepUp: newGate(), passkey: newGate()}
}

func (l limits) admit(rc rateClass, key string, now time.Time) (bool, time.Duration) {
	switch rc {
	case rateToken:
		return l.token.take(key, now)
	case rateLoginBegin:
		return l.login.begin(key, now)
	case rateLoginFinish:
		return l.login.finish(key, now)
	case rateStepUpBegin:
		return l.stepUp.begin(key, now)
	case rateStepUpFinish:
		return l.stepUp.finish(key, now)
	case ratePasskeyBegin:
		return l.passkey.begin(key, now)
	case ratePasskeyFinish:
		return l.passkey.finish(key, now)
	}
	return true, 0
}

// failed counts a finish whose passkey or ceremony did not verify.
func (l limits) failed(rc rateClass, key string, now time.Time) {
	switch rc {
	case rateLoginFinish:
		l.login.failed(key, now)
	case rateStepUpFinish:
		l.stepUp.failed(key, now)
	case ratePasskeyFinish:
		l.passkey.failed(key, now)
	case rateToken, rateLoginBegin, rateStepUpBegin, ratePasskeyBegin:
	}
}

// perSession reports whether a class counts per session rather than per client address.
func (rc rateClass) perSession() bool {
	return rc == rateStepUpBegin || rc == rateStepUpFinish || rc == ratePasskeyBegin || rc == ratePasskeyFinish
}

// guard is the start of every auth ceremony endpoint: the CSRF checks and the endpoint's rate limit. After the
// handler it counts a finish whose passkey or ceremony did not verify against its client address or session.
func (a *Auth) guard(rc rateClass) core.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.sameOrigin(r) {
				a.fail(w, r, errCSRF)
				return
			}
			key := a.rateKey(r, rc)
			if ok, wait := a.limits.admit(rc, key, a.now()); !ok {
				a.fail(w, r, &apiError{status: http.StatusTooManyRequests, code: httpsec.CodeRateLimited,
					message: "too many attempts; try again later", retryAfter: wait})
				return
			}
			r, st := withState(r)
			next.ServeHTTP(w, r)
			if st.failed {
				a.limits.failed(rc, key, a.now())
			}
		})
	}
}

// rateKey is the bucket of a request: for the session classes the hash of the session cookie, found without a store
// lookup (a made-up cookie gets a bucket of its own and fails at authentication anyway); otherwise the client address.
func (a *Auth) rateKey(r *http.Request, rc rateClass) string {
	if rc.perSession() {
		if c, err := r.Cookie(a.brand.SessionCookie); err == nil && wellFormedToken(c.Value) {
			return "s:" + hex.EncodeToString(hashToken(c.Value))
		}
		return "s:none"
	}
	return "a:" + addressKey(a.clientIP(r))
}

// clientIP is the address of the client behind the proxy (core.Site.ClientIP; Family Hub's FH_CLIENT_IP).
func (a *Auth) clientIP(r *http.Request) string { return clip(core.ClientIP(r, a.site.ClientIP), 64) }

// addressKey groups IPv6 clients by /64, since one host can use a whole /64.
func addressKey(addr string) string {
	ip := net.ParseIP(addr)
	switch {
	case ip == nil:
		return addr
	case ip.To4() != nil:
		return ip.To4().String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
