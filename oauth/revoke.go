package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// revoke is POST /oauth/revoke (RFC 7009). The client authenticates as at the token endpoint. A token it does not
// own, or one the server does not know, is answered 200 like any other, so the endpoint tells nothing about tokens.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	now, ip := s.now(), s.ip(r)
	if !s.allowOAuth(w, s.revokeLimit, ip, now) {
		return
	}
	form, ok := readForm(w, r, "token", "token_type_hint", "client_id", "client_secret")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), tokenDeadline)
	defer cancel()
	client, ok := s.authenticateClient(ctx, w, r, form)
	if !ok {
		return
	}
	token := form.Get("token")
	if token == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	if opaquePattern.MatchString(token) {
		if err := s.revokeToken(ctx, client, hashOf(token), now); err != nil {
			s.serverError(w, "revoke", err)
			return
		}
	}
	noStore(w)
	w.WriteHeader(http.StatusOK)
}

// revokeToken revokes a token of client (RFC 7009 §2.1): an access token alone, a refresh token with its whole
// family. token_type_hint is not needed: one lookup finds either kind.
func (s *Server) revokeToken(ctx context.Context, client core.OAuthClient, hash []byte, now time.Time) error {
	o := s.store.OAuth()
	t, err := o.GetToken(ctx, hash)
	if err != nil {
		return ignoreNotFound(err)
	}
	g, err := o.GetGrant(ctx, t.GrantID)
	if err != nil {
		return ignoreNotFound(err)
	}
	if g.ClientID != client.ID {
		return nil
	}
	if t.Kind == core.TokenRefresh {
		return o.RevokeFamily(ctx, t.Family, now)
	}
	return ignoreNotFound(o.RevokeToken(ctx, hash, now))
}

func ignoreNotFound(err error) error {
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	return err
}

// reasonExpired is the audited reason of a grant the server revoked because it outlived grantTTL.
const reasonExpired = "expired"

// RevokeGrant revokes grant id with every token of it and audits oauth.grant.revoke, by actor from ip. The caller
// has checked that actor may (the connections API of package people). A revoked grant is left as it is; an unknown
// one is core.ErrNotFound.
func (s *Server) RevokeGrant(ctx context.Context, id core.GrantID, actor core.PersonID, ip string) error {
	now := s.now()
	err := s.store.Tx(ctx, func(ctx context.Context) error {
		g, err := s.store.OAuth().GetGrant(ctx, id)
		if err != nil || g.RevokedAt != nil {
			return err
		}
		return s.revokeAudited(ctx, g, actor, ip, "", now)
	})
	if err != nil {
		return fmt.Errorf("oauth: revoke grant %s: %w", id, err)
	}
	return nil
}

// expireGrant revokes a grant that outlived grantTTL when its client tries to use it, so it leaves the connections
// list; a failure only logs, since the grant is refused anyway. It runs detached from the request, like a reuse.
func (s *Server) expireGrant(ctx context.Context, id core.GrantID, now time.Time) {
	ctx, cancel := detached(ctx)
	defer cancel()
	err := s.store.Tx(ctx, func(ctx context.Context) error {
		g, err := s.store.OAuth().GetGrant(ctx, id)
		if err != nil || g.RevokedAt != nil {
			return err
		}
		return s.revokeAudited(ctx, g, "", "", reasonExpired, now)
	})
	if err != nil {
		s.log.Error("oauth: revoking an expired grant failed", slog.String("grant", string(id)), slog.Any("error", err))
	}
}

// revokeAudited revokes g with its tokens and audits oauth.grant.revoke by actor from ip, in the store transaction
// of ctx; reason, when set, says why the server itself did it.
func (s *Server) revokeAudited(ctx context.Context, g core.Grant, actor core.PersonID, ip, reason string,
	now time.Time,
) error {
	if err := s.store.OAuth().RevokeGrant(ctx, g.ID, now); err != nil {
		return err
	}
	detail := map[string]string{detailResource: string(g.ResourceID)}
	if reason != "" {
		detail["reason"] = reason
	}
	return s.store.Audit().Append(ctx, core.AuditEntry{
		At: now, AccountID: g.AccountID, Actor: actor, Action: actionGrantRevoke, Target: string(g.ID), IP: ip,
		Detail: detail,
	})
}
