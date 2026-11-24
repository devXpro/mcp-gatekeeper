package mcpguard

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

const (
	// inFlightPerResource is how many calls of one account may be inside one resource at once, open event streams
	// included: one family's runaway assistant must not take a resource every family shares.
	inFlightPerResource = 16
	// failuresPerAddress is how many unknown credentials one client address may present a minute.
	failuresPerAddress = 30
	// maxFailureBuckets bounds the failure limiter's memory under a flood of addresses.
	maxFailureBuckets = 4096
)

// Admit takes a place for a call of account a in resource id among the 16 calls that may be inside it at once, or
// answers 429 with Retry-After. The caller gives the place back with release when the call ends (a second release
// does nothing). Every door into the same resource admits its calls here (Family Hub: its legacy REST door too), so
// that they share the places.
func (g *Guard) Admit(w http.ResponseWriter, a core.AccountID, id core.ResourceID) (release func(), ok bool) {
	if !g.inFlight.acquire(a, id) {
		tooMany(w, time.Second, "too many calls to this module at once; try again shortly")
		return nil, false
	}
	return sync.OnceFunc(func() { g.inFlight.release(a, id) }), true
}

// failureLimit counts the unknown credentials each client address presents, in a token bucket per address that
// holds a minute's worth and refills continuously. It only ever turns a refusal into a 429: a valid credential
// passes whatever its address spent, because the assistants call from shared egress addresses, and junk sent from
// one of them must not stop every family's connector there (the lesson of Family Hub's T2.R H2).
type failureLimit struct {
	rate float64 // failures a minute

	mu      sync.Mutex
	buckets map[string]*failureBucket
}

type failureBucket struct {
	tokens float64
	last   time.Time
}

func newFailureLimit(perMinute int) *failureLimit {
	return &failureLimit{rate: float64(perMinute), buckets: map[string]*failureBucket{}}
}

// failed counts one unknown credential of key. When key had none left to spend it reports false and how long until
// it has one again.
func (l *failureLimit) failed(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxFailureBuckets {
			l.prune(now)
		}
		b = &failureBucket{tokens: l.rate, last: now}
		l.buckets[key] = b
	} else if d := now.Sub(b.last); d > 0 {
		b.tokens = min(l.rate, b.tokens+d.Minutes()*l.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Minute))
	}
	b.tokens--
	return true, 0
}

// prune drops the buckets that are full again; when a flood of addresses leaves too many, it drops half of the rest.
// l.mu is held.
func (l *failureLimit) prune(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) >= time.Minute {
			delete(l.buckets, k)
		}
	}
	for k := range l.buckets {
		if len(l.buckets) < maxFailureBuckets/2 {
			break
		}
		delete(l.buckets, k)
	}
}

// addressKey is the failure bucket of a client address: IPv6 clients are grouped by /64, since one host can use a
// whole /64. Something that is no address (a forwarding header's junk) is cut to 64 bytes.
func addressKey(addr string) string {
	ip := net.ParseIP(addr)
	switch {
	case ip == nil:
		return addr[:min(len(addr), 64)]
	case ip.To4() != nil:
		return ip.To4().String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// inFlight counts the calls inside each (account, resource).
type inFlight struct {
	limit int

	mu    sync.Mutex
	calls map[inFlightKey]int
}

type inFlightKey struct {
	account  core.AccountID
	resource core.ResourceID
}

func newInFlight(limit int) *inFlight { return &inFlight{limit: limit, calls: map[inFlightKey]int{}} }

// acquire takes a place for a call of account a in resource id; the caller gives it back with release. It reports
// false when all places are taken.
func (f *inFlight) acquire(a core.AccountID, id core.ResourceID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := inFlightKey{a, id}
	if f.calls[k] >= f.limit {
		return false
	}
	f.calls[k]++
	return true
}

func (f *inFlight) release(a core.AccountID, id core.ResourceID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := inFlightKey{a, id}
	if f.calls[k] <= 1 {
		delete(f.calls, k)
		return
	}
	f.calls[k]--
}

// tooMany answers 429 with Retry-After, in whole seconds and at least one.
func tooMany(w http.ResponseWriter, wait time.Duration, msg string) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
	httpsec.WriteError(w, http.StatusTooManyRequests, httpsec.CodeRateLimited, msg)
}
