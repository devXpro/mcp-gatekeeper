package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// ValidateAccess implements core.TokenValidator. token must be a live access token, found by its sha256, whose grant
// is active, younger than grantTTL, and for resource r. Any other token is core.ErrInvalidToken. A store failure is
// returned as itself, so the MCP access check can answer 5xx rather than send the assistant to sign in again.
//
// It also records the grant's last use, at most once a minute, for the connections list.
func (s *Server) ValidateAccess(ctx context.Context, token string, r core.ResourceID) (core.AccessInfo, error) {
	if !opaquePattern.MatchString(token) {
		return core.AccessInfo{}, core.ErrInvalidToken
	}
	now := s.now()
	o := s.store.OAuth()
	t, err := o.GetToken(ctx, hashOf(token))
	if err != nil {
		return invalidOr(err)
	}
	if t.Kind != core.TokenAccess || t.RevokedAt != nil || !now.Before(t.ExpiresAt) {
		return core.AccessInfo{}, core.ErrInvalidToken
	}
	g, err := o.GetGrant(ctx, t.GrantID)
	if err != nil {
		return invalidOr(err)
	}
	if g.RevokedAt != nil || g.ResourceID != r || grantExpired(g, now) {
		return core.AccessInfo{}, core.ErrInvalidToken
	}
	client, err := o.GetClient(ctx, g.ClientID)
	if err != nil {
		return invalidOr(err)
	}
	if s.touched.due(string(g.ID), now) {
		if err := o.TouchGrant(ctx, g.ID, now); err != nil {
			s.log.Warn("oauth: recording a grant's use failed", slog.String("grant", string(g.ID)), slog.Any("error", err))
		}
	}
	return core.AccessInfo{
		GrantID: g.ID, PersonID: g.PersonID, AccountID: g.AccountID, ResourceID: g.ResourceID, ClientID: g.ClientID,
		Assistant: client.Assistant, Scope: g.Scope, ExpiresAt: earlier(t.ExpiresAt, grantEnd(g)),
	}, nil
}

// earlier is the earlier of a and b.
func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// invalidOr is core.ErrInvalidToken for a record that is not there, and the failure itself otherwise.
func invalidOr(err error) (core.AccessInfo, error) {
	if errors.Is(err, core.ErrNotFound) {
		return core.AccessInfo{}, core.ErrInvalidToken
	}
	return core.AccessInfo{}, fmt.Errorf("oauth: validate access: %w", err)
}

// throttle lets a key through at most once per period.
type throttle struct {
	period time.Duration

	mu   sync.Mutex
	last map[string]time.Time
}

func newThrottle(period time.Duration) *throttle {
	return &throttle{period: period, last: map[string]time.Time{}}
}

// due reports whether key's period has passed, and if so starts a new one.
func (t *throttle) due(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if at, ok := t.last[key]; ok && now.Sub(at) < t.period {
		return false
	}
	if len(t.last) >= maxKeys {
		for k, at := range t.last {
			if now.Sub(at) >= t.period {
				delete(t.last, k)
			}
		}
	}
	t.last[key] = now
	return true
}
