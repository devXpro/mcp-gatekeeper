package oauth

import (
	"net"
	"sync"
	"time"
)

// limiter is a token bucket per key and, when total is set, one for every key together. A bucket holds a minute's
// worth of tokens and refills continuously.
type limiter struct {
	perKey, total float64 // tokens a minute; total 0 means no shared bucket

	mu      sync.Mutex
	all     bucket
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newLimiter allows perKey requests a minute per key and total for all of them (0: no shared limit).
func newLimiter(perKey, total int) *limiter {
	return &limiter{perKey: float64(perKey), total: float64(total), buckets: map[string]*bucket{}}
}

// addressKey is the key of a client address in the limits and the transaction store: an IPv4 address, or the /64 of
// an IPv6 one, since a single host can use a whole /64 (package auth groups the same way). Whatever is not an
// address shares one key, so made-up values cannot make buckets of their own.
func addressKey(addr string) string {
	ip := net.ParseIP(addr)
	switch {
	case ip == nil:
		return "invalid"
	case ip.To4() != nil:
		return ip.To4().String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// take takes a token for key and from the shared bucket. When either is empty it refuses and says how long to wait.
func (l *limiter) take(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucket(key, now)
	b.refill(l.perKey, now)
	if l.total > 0 {
		l.all.refill(l.total, now)
		if l.all.tokens < 1 {
			return false, l.all.wait(l.total)
		}
	}
	if b.tokens < 1 {
		return false, b.wait(l.perKey)
	}
	b.tokens--
	if l.total > 0 {
		l.all.tokens--
	}
	return true, 0
}

// bucket returns key's bucket, making it, and pruning the map when it is full. l.mu is held.
func (l *limiter) bucket(key string, now time.Time) *bucket {
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxKeys {
			l.prune(now)
		}
		b = &bucket{}
		l.buckets[key] = b
	}
	return b
}

// prune drops the buckets that are full again; when a flood of addresses leaves too many, it drops half of the rest.
func (l *limiter) prune(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) >= time.Minute {
			delete(l.buckets, k)
		}
	}
	for k := range l.buckets {
		if len(l.buckets) < maxKeys/2 {
			break
		}
		delete(l.buckets, k)
	}
}

// refill brings the bucket up to now at rate tokens a minute; a new bucket starts full.
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
