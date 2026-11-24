package oauth

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimiter(t *testing.T) {
	l := newLimiter(limitPerAddress, limitTotal)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for i := range limitPerAddress {
		ok, _ := l.take("a", now)
		require.True(t, ok, i)
	}
	ok, wait := l.take("a", now)
	assert.False(t, ok)
	assert.Equal(t, 3*time.Second, wait, "20 a minute is one every 3 s")

	for _, key := range []string{"b", "c"} {
		for i := range limitPerAddress {
			ok, _ := l.take(key, now)
			require.True(t, ok, key, i)
		}
	}
	ok, wait = l.take("d", now)
	assert.False(t, ok, "60 a minute from every address together")
	assert.Equal(t, time.Second, wait)

	now = now.Add(3 * time.Second)
	ok, _ = l.take("a", now)
	assert.True(t, ok, "a bucket refills")
	ok, _ = l.take("a", now)
	assert.False(t, ok)
}

func TestLimiterWithoutTotal(t *testing.T) {
	l := newLimiter(limitPerAddress, 0)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for i := range 10 * limitPerAddress {
		ok, _ := l.take(fmt.Sprintf("addr-%d", i/limitPerAddress), now)
		require.True(t, ok, i)
	}
}

func TestLimiterRate(t *testing.T) {
	l := newLimiter(limitFetches, 0)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for i := range limitFetches {
		ok, _ := l.take("a", now)
		require.True(t, ok, i)
	}
	ok, wait := l.take("a", now)
	assert.False(t, ok)
	assert.Equal(t, 12*time.Second, wait, "5 a minute is one every 12 s")
}

func TestLimiterPrunes(t *testing.T) {
	l := newLimiter(limitPerAddress, 0)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for i := range 3 * maxKeys {
		l.take(fmt.Sprintf("addr-%d", i), now)
	}
	assert.LessOrEqual(t, len(l.buckets), maxKeys)
}

func TestAddressKey(t *testing.T) {
	tests := []struct{ addr, want string }{
		{"192.0.2.1", "192.0.2.1"},
		{"::ffff:192.0.2.1", "192.0.2.1"}, // IPv4-mapped is the IPv4 address
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"}, // one /64, one key
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"::1", "::/64"},
		{"", "invalid"},
		{"not an address", "invalid"}, // made-up values share one key
		{"192.0.2.1:443", "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			assert.Equal(t, tt.want, addressKey(tt.addr))
		})
	}
}

func TestThrottle(t *testing.T) {
	th := newThrottle(time.Minute)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	assert.True(t, th.due("g", now))
	assert.False(t, th.due("g", now.Add(59*time.Second)))
	assert.True(t, th.due("other", now))
	assert.True(t, th.due("g", now.Add(time.Minute)))
	for i := range 2 * maxKeys {
		th.due(fmt.Sprintf("g-%d", i), now.Add(time.Duration(i)*time.Second))
	}
	assert.LessOrEqual(t, len(th.last), maxKeys+60, "keys older than a period are dropped")
}
