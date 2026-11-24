package auth

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auth/token and registration: every request counts, per client address only.
func TestRateLimitTokens(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.ip = "203.0.113.7"
	token := map[string]any{"token": "x"}
	for range tokenPerAddress {
		wantError(t, b.do(http.MethodPost, "/api/auth/token", token), http.StatusNotFound, "not_found")
	}
	rec := b.do(http.MethodPost, "/api/auth/token", token)
	wantError(t, rec, http.StatusTooManyRequests, "rate_limited")
	assert.Equal(t, "3", rec.Header().Get("Retry-After"), "a token comes back every 3 s")
	// Registration shares the class; sign-in is a class of its own.
	wantError(t, b.do(http.MethodPost, "/api/auth/register/begin", token), http.StatusTooManyRequests, "rate_limited")
	wantError(t, b.do(http.MethodPost, "/api/auth/register/finish", map[string]any{}), http.StatusTooManyRequests, "rate_limited")
	wantStatus(t, b.do(http.MethodPost, "/api/auth/login/begin", map[string]any{}), http.StatusOK)
	// Another client is not affected; the token comes back after 3 s.
	other := e.browser()
	other.ip = "203.0.113.8"
	wantError(t, other.do(http.MethodPost, "/api/auth/token", token), http.StatusNotFound, "not_found")
	e.clock.Add(3*time.Second + time.Millisecond)
	wantError(t, b.do(http.MethodPost, "/api/auth/token", token), http.StatusNotFound, "not_found")

	// No shared bucket (T2.R H2): a hundred addresses spending their own buckets leave every other address alone.
	for i := range 100 {
		c := e.browser()
		c.ip = "198.51.100." + strconv.Itoa(i)
		for range tokenPerAddress {
			wantError(t, c.do(http.MethodPost, "/api/auth/token", token), http.StatusNotFound, "not_found")
		}
		wantError(t, c.do(http.MethodPost, "/api/auth/token", token), http.StatusTooManyRequests, "rate_limited")
	}
	c := e.browser()
	c.ip = "192.0.2.1"
	wantError(t, c.do(http.MethodPost, "/api/auth/token", token), http.StatusNotFound, "not_found")
	wantError(t, c.do(http.MethodPost, "/api/auth/register/begin", token), http.StatusNotFound, "not_found")
	// An IPv6 client counts per /64.
	v6 := e.browser()
	for i := range tokenPerAddress {
		v6.ip = "2001:db8:5:6::" + strconv.Itoa(i+1)
		wantError(t, v6.do(http.MethodPost, "/api/auth/token", token), http.StatusNotFound, "not_found")
	}
	v6.ip = "2001:db8:5:6:ffff::1"
	wantError(t, v6.do(http.MethodPost, "/api/auth/token", token), http.StatusTooManyRequests, "rate_limited")
	v6.ip = "2001:db8:5:7::1"
	wantError(t, v6.do(http.MethodPost, "/api/auth/token", token), http.StatusNotFound, "not_found")
	// Logout is not limited.
	wantStatus(t, c.do(http.MethodPost, "/api/auth/logout", nil), http.StatusNoContent)
}

// Sign-in counts begins and failed finishes per client address, with no shared bucket: nobody can spend another's.
func TestRateLimitLogin(t *testing.T) {
	e := newEnv(t)
	d := newDevice()
	owner, _ := e.superadmin(d)
	owner.ip = "198.51.100.20"
	attacker := e.browser()
	attacker.ip = "203.0.113.7"
	bogus := map[string]any{"credential": map[string]any{}}
	for range failuresPerKey {
		wantError(t, attacker.do(http.MethodPost, "/api/auth/login/finish", bogus), http.StatusBadRequest, "invalid")
	}
	// The address's failures are spent: its finishes and begins wait.
	wantError(t, attacker.do(http.MethodPost, "/api/auth/login/finish", bogus), http.StatusTooManyRequests, "rate_limited")
	wantError(t, attacker.do(http.MethodPost, "/api/auth/login/begin", map[string]any{}), http.StatusTooManyRequests, "rate_limited")
	// The owner signs in from their own address, again and again: successes cost no failure.
	for range failuresPerKey + 2 {
		wantStatus(t, owner.login(d), http.StatusOK)
	}
	// Many addresses failing do not add up to anything shared.
	for i := range 50 {
		c := e.browser()
		c.ip = "192.0.2." + strconv.Itoa(i)
		wantError(t, c.do(http.MethodPost, "/api/auth/login/finish", bogus), http.StatusBadRequest, "invalid")
	}
	wantStatus(t, owner.login(d), http.StatusOK)
	// Begins alone are limited per address too (they hold pending ceremonies).
	spammer := e.browser()
	spammer.ip = "203.0.113.9"
	for range beginsPerKey {
		wantStatus(t, spammer.do(http.MethodPost, "/api/auth/login/begin", map[string]any{}), http.StatusOK)
	}
	wantError(t, spammer.do(http.MethodPost, "/api/auth/login/begin", map[string]any{}), http.StatusTooManyRequests, "rate_limited")
	wantStatus(t, owner.login(d), http.StatusOK)
	// An IPv6 client counts per /64.
	v6 := e.browser()
	for i := range beginsPerKey {
		v6.ip = "2001:db8:1:2::" + strconv.Itoa(i+1)
		wantStatus(t, v6.do(http.MethodPost, "/api/auth/login/begin", map[string]any{}), http.StatusOK)
	}
	v6.ip = "2001:db8:1:2:ffff::1"
	wantError(t, v6.do(http.MethodPost, "/api/auth/login/begin", map[string]any{}), http.StatusTooManyRequests, "rate_limited")
	v6.ip = "2001:db8:1:3::1"
	wantStatus(t, v6.do(http.MethodPost, "/api/auth/login/begin", map[string]any{}), http.StatusOK)
	// Failures refill like everything else.
	e.clock.Add(time.Minute)
	wantError(t, attacker.do(http.MethodPost, "/api/auth/login/finish", bogus), http.StatusBadRequest, "invalid")
}

// Step-up and new passkeys are limited per session, never by anonymous traffic.
func TestRateLimitPerSession(t *testing.T) {
	e := newEnv(t)
	d := newDevice()
	owner, _ := e.superadmin(d)
	// The anonymous internet spends every public bucket it can, from the owner's own address too.
	for i := range 80 {
		c := e.browser()
		c.ip = "203.0.113." + strconv.Itoa(i)
		c.do(http.MethodPost, "/api/auth/token", map[string]any{"token": "x"})
		c.do(http.MethodPost, "/api/auth/login/finish", map[string]any{"credential": map[string]any{}})
	}
	for range 100 {
		e.browser().do(http.MethodPost, "/api/auth/login/begin", map[string]any{}) // the owner's address
	}
	wantStatus(t, owner.stepUp(d), http.StatusOK)

	// A second session (a thief with a stolen cookie but no passkey, say) spends only its own step-up.
	other := e.browser()
	other.ip = "198.51.100.30"
	wantStatus(t, other.login(d), http.StatusOK)
	bogus := map[string]any{"credential": map[string]any{}}
	for range failuresPerKey {
		wantError(t, other.do(http.MethodPost, "/api/auth/stepup/finish", bogus), http.StatusBadRequest, "invalid")
	}
	wantError(t, other.do(http.MethodPost, "/api/auth/stepup/finish", bogus), http.StatusTooManyRequests, "rate_limited")
	wantError(t, other.do(http.MethodPost, "/api/auth/stepup/begin", map[string]any{}), http.StatusTooManyRequests, "rate_limited")
	// The other class (a new passkey) and every other session are untouched.
	wantStatus(t, owner.stepUp(d), http.StatusOK)
	wantStatus(t, other.do(http.MethodPost, "/api/me/passkeys/begin", map[string]any{}), http.StatusOK)
	for range failuresPerKey {
		wantError(t, other.do(http.MethodPost, "/api/me/passkeys/finish", bogus), http.StatusBadRequest, "invalid")
	}
	wantError(t, other.do(http.MethodPost, "/api/me/passkeys/finish", bogus), http.StatusTooManyRequests, "rate_limited")
	wantStatus(t, owner.do(http.MethodPost, "/api/me/passkeys/begin", map[string]any{}), http.StatusOK)
}

// Pending ceremonies: a public flood replaces the oldest public ones and never crowds out a session's step-up.
func TestCeremonyPools(t *testing.T) {
	cs := newCeremonies()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	mk := func(k ceremonyKind, challenge string, expires time.Time) *ceremony {
		c := &ceremony{kind: k, expires: expires}
		c.data.Challenge = challenge
		return c
	}
	require.True(t, cs.add(mk(kindLogin, "first", now.Add(CeremonyTTL)), now))
	for i := range maxCeremonies + 10 {
		require.True(t, cs.add(mk(kindLogin, "l"+strconv.Itoa(i), now.Add(CeremonyTTL+time.Duration(i+1)*time.Millisecond)), now))
	}
	_, ok := cs.take("first", now, isKind(kindLogin))
	assert.False(t, ok, "the oldest public ceremony gave way")
	assert.Len(t, cs.m, maxCeremonies)
	for i := range maxCeremonies {
		require.True(t, cs.add(mk(kindStepUp, "s"+strconv.Itoa(i), now.Add(CeremonyTTL)), now), "step-up %d", i)
	}
	assert.False(t, cs.add(mk(kindAddPasskey, "full", now.Add(CeremonyTTL)), now), "a full session pool takes no more")
	assert.False(t, cs.add(mk(kindLogin, "", now.Add(CeremonyTTL)), now), "no challenge, no ceremony")
	assert.False(t, cs.add(mk(kindLogin, "l500", now.Add(CeremonyTTL)), now), "a challenge is never replaced")
	_, ok = cs.take("l10", now, isKind(kindLogin))
	assert.True(t, ok, "a refused add evicts nothing")
	// Expired ones make room again.
	later := now.Add(CeremonyTTL + time.Hour)
	require.True(t, cs.add(mk(kindStepUp, "late", later.Add(CeremonyTTL)), later))
	assert.Len(t, cs.m, 1)
}

func TestLimiterPrune(t *testing.T) {
	l := newLimiter(1)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for i := range maxBuckets + 10 {
		l.take("k"+strconv.Itoa(i), now)
	}
	assert.LessOrEqual(t, len(l.buckets), maxBuckets)
}

func TestAddressKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":            "203.0.113.7",
		"::ffff:203.0.113.7":     "203.0.113.7",
		"2001:db8:1:2:3:4:5:6":   "2001:db8:1:2::/64",
		"2001:db8:1:2::1":        "2001:db8:1:2::/64",
		"garbage":                "garbage",
		strings.Repeat("x", 300): strings.Repeat("x", 300),
	} {
		assert.Equal(t, want, addressKey(in), in)
	}
}
