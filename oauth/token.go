package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// tokenResponse is a successful token answer (RFC 6749 §5.1).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// tokenPair is what one token answer hands out; expiresIn is the access token's life in whole seconds.
type tokenPair struct {
	access, refresh, family string
	expiresIn               int64
	replay                  bool // the refresh grace answers a lost answer again
}

// token is POST /oauth/token: the authorization_code and refresh_token grants, form-urlencoded, for an
// authenticated client.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	now, ip := s.now(), s.ip(r)
	if !s.allowOAuth(w, s.tokenLimit, ip, now) {
		return
	}
	form, ok := readForm(w, r, "grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "scope",
		"client_id", "client_secret")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), tokenDeadline)
	defer cancel()
	client, ok := s.authenticateClient(ctx, w, r, form)
	if !ok {
		return
	}
	switch form.Get("grant_type") {
	case grantCode:
		s.exchangeCode(ctx, w, client, form, now)
	case grantRefresh:
		s.refresh(ctx, w, client, form, now, ip)
	case "":
		oauthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

// exchangeCode is the authorization_code grant: the code is consumed, and it must be the client's, carry the same
// redirect_uri, pass PKCE, and match the resource when one is sent; its grant's person must still be active. It all
// runs in one transaction, so a failed check leaves the code to its own client, and a store failure leaves it for a
// retry.
func (s *Server) exchangeCode(ctx context.Context, w http.ResponseWriter, client core.OAuthClient, form url.Values,
	now time.Time,
) {
	code := form.Get("code")
	if code == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}
	resource, ok := oneResource(w, form)
	if !ok {
		return
	}
	if !opaquePattern.MatchString(code) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	hash := hashOf(code)
	var (
		out   tokenPair
		scope string
	)
	err := s.store.Tx(ctx, func(ctx context.Context) error {
		o := s.store.OAuth()
		ac, err := o.ConsumeCode(ctx, hash, now)
		if err != nil {
			return err
		}
		switch {
		case ac.ClientID != client.ID, ac.RedirectURI != form.Get("redirect_uri"),
			!pkceMatches(form.Get("code_verifier"), ac.CodeChallenge):
			return errGrant
		case resource != "" && resource != ac.Resource:
			return errTarget
		}
		g, err := o.GetGrant(ctx, ac.GrantID)
		switch {
		case errors.Is(err, core.ErrNotFound):
			return errGrant
		case err != nil:
			return err
		case g.RevokedAt != nil, g.ClientID != client.ID, grantExpired(g, now):
			return errGrant
		}
		person, err := s.activePerson(ctx, g, now)
		if err != nil {
			return err
		}
		p, err := issue(ctx, o, g.ID, core.NewID(prefixFamily), now, person.AccessUntil)
		if err != nil {
			return err
		}
		out, scope = p, ac.Scope
		return nil
	})
	switch {
	case err == nil:
	case errors.Is(err, core.ErrNotFound), errors.Is(err, core.ErrExpired):
		s.codeReplayed(ctx, hash, now)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code is unknown, used or expired")
		return
	case errors.Is(err, errGrant):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	case errors.Is(err, errTarget):
		oauthError(w, http.StatusBadRequest, "invalid_target", "the resource is not the one the code was issued for")
		return
	default:
		s.serverError(w, "code exchange", err)
		return
	}
	s.spent.add(hash, out.family, now.Add(codeTTL), now)
	issued(w, out, scope)
}

// refresh is the refresh_token grant. The token rotates: it is spent, and a new access and refresh token of the
// same family are issued. A spent token that comes back revokes its family and is audited as oauth.refresh.reuse;
// a dead one is invalid_grant.
//
// The refresh grace (review SR L5): a client whose answer was lost presents the token it just spent again. Within
// refreshGrace of its rotation, while the tokens it was replaced by are untouched (the replacing refresh token
// neither used nor revoked), that client gets the same answer again, not a revoked family: the new tokens are derived
// from the spent one (rotated), so they can be told again without keeping them. After refreshGrace, or once the
// replacement was used, the spent token is reuse as before. Rotating never extends the grant: once it outlived grantTTL, the refresh is
// invalid_grant and the grant is revoked, and the person consents again.
//
// A person who is no longer active (disabled, or past the end of their term) gets invalid_grant too, after the
// reuse check, so a stolen token is still caught. Nothing is spent or revoked then: the owner may extend the term,
// and the connection works again.
func (s *Server) refresh(ctx context.Context, w http.ResponseWriter, client core.OAuthClient, form url.Values,
	now time.Time, ip string,
) {
	rt := form.Get("refresh_token")
	if rt == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	resource, ok := oneResource(w, form)
	if !ok {
		return
	}
	if !opaquePattern.MatchString(rt) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	hash := hashOf(rt)
	var (
		out    tokenPair
		grant  core.Grant
		reused string // the family of a spent token that came back
	)
	err := s.store.Tx(ctx, func(ctx context.Context) error {
		o := s.store.OAuth()
		t, err := o.GetToken(ctx, hash)
		if err != nil {
			return err
		}
		if t.Kind != core.TokenRefresh {
			return errGrant
		}
		g, err := o.GetGrant(ctx, t.GrantID)
		switch {
		case errors.Is(err, core.ErrNotFound):
			return errGrant
		case err != nil:
			return err
		case g.ClientID != client.ID:
			return errGrant
		}
		grant = g
		if g.RevokedAt == nil && grantExpired(g, now) {
			return errGrantExpired
		}
		var replay bool
		if _, err := o.UseRefresh(ctx, hash, now); err != nil {
			if !errors.Is(err, core.ErrUsed) {
				return err
			}
			if out, replay, err = replayed(ctx, o, rt, now); err != nil {
				return err
			}
			if !replay {
				reused = t.Family
				return errReused
			}
		}
		switch {
		case g.RevokedAt != nil:
			return errGrant
		case resource != "" && resource != s.resourceURL(g.ResourceID):
			return errTarget
		}
		person, err := s.activePerson(ctx, g, now)
		if err != nil || replay {
			return err
		}
		access, refresh := rotated(rt)
		p, err := issueAs(ctx, o, g.ID, t.Family, now, person.AccessUntil, access, refresh)
		if err != nil {
			return err
		}
		out = p
		return nil
	})
	switch {
	case err == nil:
		if out.replay {
			s.log.Info("oauth: a refresh token replaced moments ago came back from its client; the same tokens are "+
				"answered", slog.String("grant", string(grant.ID)))
		}
	case errors.Is(err, errReused):
		s.refreshReused(ctx, grant, client, reused, now, ip)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	case errors.Is(err, errGrantExpired):
		s.expireGrant(ctx, grant.ID, now)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	case errors.Is(err, core.ErrNotFound), errors.Is(err, core.ErrExpired), errors.Is(err, errGrant):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "")
		return
	case errors.Is(err, errTarget):
		oauthError(w, http.StatusBadRequest, "invalid_target", "the resource is not the one the token was issued for")
		return
	default:
		s.serverError(w, "refresh", err)
		return
	}
	issued(w, out, grant.Scope)
}

// issue stores a new access token (1 h) and refresh token (30 d) of grant g in family. The access token ends at until
// instead when that is sooner: the end of the person's term (nil: none). The refresh token keeps its 30 days: every
// refresh checks the person again, so a term the owner extends keeps the connection.
func issue(ctx context.Context, o store.OAuthStore, g core.GrantID, family string, now time.Time, until *time.Time,
) (tokenPair, error) {
	return issueAs(ctx, o, g, family, now, until, randomToken(), randomToken())
}

// issueAs is issue with the tokens given: a refresh's, rotated from the token it spends.
func issueAs(ctx context.Context, o store.OAuthStore, g core.GrantID, family string, now time.Time, until *time.Time,
	access, refresh string,
) (tokenPair, error) {
	end := now.Add(accessTTL)
	if until != nil {
		end = earlier(end, *until)
	}
	p := tokenPair{access: access, refresh: refresh, family: family, expiresIn: int64(end.Sub(now) / time.Second)}
	err := o.PutToken(ctx, core.Token{
		Hash: hashOf(p.access), GrantID: g, Kind: core.TokenAccess, Family: family, CreatedAt: now, ExpiresAt: end,
	})
	if err != nil {
		return tokenPair{}, err
	}
	err = o.PutToken(ctx, core.Token{
		Hash: hashOf(p.refresh), GrantID: g, Kind: core.TokenRefresh, Family: family, CreatedAt: now,
		ExpiresAt: now.Add(refreshTTL),
	})
	if err != nil {
		return tokenPair{}, err
	}
	return p, nil
}

// rotated returns the access and refresh token a refresh with the refresh token rt issues: HMAC-SHA256 keyed with rt,
// so only who holds rt can work them out, and they look like any random token. That lets the refresh grace answer a
// spent rt again with the same tokens, while the store keeps only hashes.
func rotated(rt string) (access, refresh string) {
	derive := func(label string) string {
		m := hmac.New(sha256.New, []byte(rt))
		m.Write([]byte(label))
		return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	}
	return derive("mcp-gatekeeper refresh: access"), derive("mcp-gatekeeper refresh: refresh")
}

// replayed is the refresh grace: the tokens the spent refresh token rt was rotated into, when that happened at most
// refreshGrace before now and they are untouched (the refresh token live and never used, the access token live).
// ok is false otherwise, and the caller treats rt as reuse.
func replayed(ctx context.Context, o store.OAuthStore, rt string, now time.Time) (tokenPair, bool, error) {
	spent, err := o.GetToken(ctx, hashOf(rt))
	if err != nil {
		return tokenPair{}, false, err
	}
	if spent.UsedAt == nil || now.Sub(*spent.UsedAt) > refreshGrace {
		return tokenPair{}, false, nil
	}
	access, refresh := rotated(rt)
	untouched := func(raw string, kind core.TokenKind) (core.Token, bool, error) {
		t, err := o.GetToken(ctx, hashOf(raw))
		switch {
		case errors.Is(err, core.ErrNotFound):
			return core.Token{}, false, nil
		case err != nil:
			return core.Token{}, false, err
		}
		return t, t.Kind == kind && t.GrantID == spent.GrantID && t.Family == spent.Family && t.UsedAt == nil &&
			t.RevokedAt == nil && t.ExpiresAt.After(now), nil
	}
	if _, ok, err := untouched(refresh, core.TokenRefresh); !ok || err != nil {
		return tokenPair{}, false, err
	}
	a, ok, err := untouched(access, core.TokenAccess)
	if !ok || err != nil {
		return tokenPair{}, false, err
	}
	return tokenPair{
		access: access, refresh: refresh, family: spent.Family, expiresIn: int64(a.ExpiresAt.Sub(now) / time.Second),
		replay: true,
	}, true, nil
}

// issued answers a token request with p.
func issued(w http.ResponseWriter, p tokenPair, scope string) {
	noStore(w)
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: p.access, TokenType: "Bearer", ExpiresIn: p.expiresIn, RefreshToken: p.refresh, Scope: scope,
	})
}

// activePerson returns the person of grant g when they may still use it at now: they exist, are in the grant's
// account and are active (core.Person.Active: not disabled, and before the end of their term). Otherwise errGrant,
// which the token endpoint answers invalid_grant; a store failure is itself.
func (s *Server) activePerson(ctx context.Context, g core.Grant, now time.Time) (core.Person, error) {
	p, err := s.store.People().Get(ctx, g.PersonID)
	switch {
	case errors.Is(err, core.ErrNotFound):
		return core.Person{}, errGrant
	case err != nil:
		return core.Person{}, err
	case p.AccountID != g.AccountID, !p.Active(now):
		return core.Person{}, errGrant
	}
	return p, nil
}

// refreshReused handles a spent refresh token that came back: someone holds a stale copy, so its whole family is
// revoked and the event audited.
func (s *Server) refreshReused(ctx context.Context, g core.Grant, client core.OAuthClient, family string, now time.Time,
	ip string,
) {
	ctx, cancel := detached(ctx)
	defer cancel()
	if err := s.store.OAuth().RevokeFamily(ctx, family, now); err != nil {
		s.log.Error("oauth: revoking the family of a reused refresh token failed",
			slog.String("grant", string(g.ID)), slog.Any("error", err))
	}
	s.audit(ctx, core.AuditEntry{
		At: now, AccountID: g.AccountID, Action: actionRefreshReuse, Target: string(g.ID), IP: ip,
		Detail: map[string]string{detailResource: string(g.ResourceID), "assistant": string(client.Assistant)},
	})
	s.log.Warn("oauth: a spent refresh token came back; its family is revoked",
		slog.String("grant", string(g.ID)), slog.String("resource", string(g.ResourceID)))
}

// codeReplayed revokes the tokens a code got when that code comes back after its exchange (RFC 6749 §4.1.2).
func (s *Server) codeReplayed(ctx context.Context, hash []byte, now time.Time) {
	family, ok := s.spent.take(hash, now)
	if !ok {
		return
	}
	ctx, cancel := detached(ctx)
	defer cancel()
	if err := s.store.OAuth().RevokeFamily(ctx, family, now); err != nil {
		s.log.Error("oauth: revoking the tokens of a replayed code failed", slog.Any("error", err))
		return
	}
	s.log.Warn("oauth: an authorization code came back; the tokens it got are revoked")
}

// serverError logs a failure of the server itself and answers server_error.
func (s *Server) serverError(w http.ResponseWriter, what string, err error) {
	s.log.Error("oauth: "+what+" failed", slog.Any("error", err))
	oauthError(w, http.StatusInternalServerError, "server_error", "")
}

// authenticateClient finds and authenticates the client of a token or revoke request (RFC 6749 §2.3): HTTP Basic,
// or client_id with client_secret in the form; a client without a secret sends client_id alone. A request uses one
// method. It answers invalid_client (401) or invalid_request itself.
func (s *Server) authenticateClient(ctx context.Context, w http.ResponseWriter, r *http.Request, form url.Values,
) (core.OAuthClient, bool) {
	id, secret := form.Get("client_id"), form.Get("client_secret")
	basicID, basicSecret, basic := r.BasicAuth()
	if basic {
		var errID, errSecret error
		basicID, errID = url.QueryUnescape(basicID)
		basicSecret, errSecret = url.QueryUnescape(basicSecret)
		switch {
		case errID != nil || errSecret != nil:
			s.refuseClient(w, true)
			return core.OAuthClient{}, false
		case secret != "" || (id != "" && id != basicID):
			oauthError(w, http.StatusBadRequest, "invalid_request", "use one client authentication method")
			return core.OAuthClient{}, false
		}
		id, secret = basicID, basicSecret
	}
	client, err := s.lookupClient(ctx, id)
	switch {
	case errors.Is(err, errUnknownClient):
		s.refuseClient(w, basic)
		return core.OAuthClient{}, false
	case err != nil:
		s.serverError(w, "client lookup", err)
		return core.OAuthClient{}, false
	case !secretMatches(client, secret):
		s.refuseClient(w, basic)
		return core.OAuthClient{}, false
	}
	return client, true
}

// refuseClient answers invalid_client; after a Basic attempt with the challenge RFC 6749 §5.2 asks for.
func (s *Server) refuseClient(w http.ResponseWriter, basic bool) {
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+s.realm+`"`)
	}
	oauthError(w, http.StatusUnauthorized, "invalid_client", "")
}

// secretMatches checks secret against the client's, in constant time. A client without a secret needs none.
func secretMatches(client core.OAuthClient, secret string) bool {
	if len(client.SecretHash) == 0 {
		return true
	}
	return subtle.ConstantTimeCompare(hashOf(secret), client.SecretHash) == 1
}

// pkceMatches checks an S256 code_verifier against the code's challenge (RFC 7636 §4.6), in constant time.
func pkceMatches(verifier, challenge string) bool {
	if !verifierPattern.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// readForm reads the form of a token or revoke request: application/x-www-form-urlencoded, at most 16 KiB, each key
// of once at most once (RFC 6749 §3.2). It answers invalid_request itself.
func readForm(w http.ResponseWriter, r *http.Request, once ...string) (url.Values, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body must be application/x-www-form-urlencoded")
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the form cannot be read")
		return nil, false
	}
	form := r.PostForm
	for _, key := range once {
		if len(form[key]) > 1 {
			oauthError(w, http.StatusBadRequest, "invalid_request", key+" is repeated")
			return nil, false
		}
	}
	return form, true
}

// oneResource returns the resource of a token request, "" without one. More than one is invalid_target, answered
// here.
func oneResource(w http.ResponseWriter, form url.Values) (string, bool) {
	switch rs := nonEmpty(form["resource"]); len(rs) {
	case 0:
		return "", true
	case 1:
		return rs[0], true
	}
	oauthError(w, http.StatusBadRequest, "invalid_target", "one resource is expected")
	return "", false
}

// spentCodes remembers each exchanged code until it would have expired, with the family of tokens it got, so a code
// that comes back revokes them (RFC 6749 §4.1.2). Like the transactions, it lives in memory.
type spentCodes struct {
	mu    sync.Mutex
	codes map[string]spentCode
}

type spentCode struct {
	family  string
	expires time.Time
}

func newSpentCodes() *spentCodes {
	return &spentCodes{codes: map[string]spentCode{}}
}

func (s *spentCodes) add(hash []byte, family string, expires, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.codes {
		if !now.Before(v.expires) {
			delete(s.codes, k)
		}
	}
	s.codes[string(hash)] = spentCode{family: family, expires: expires}
}

// take returns and forgets the family of a spent code.
func (s *spentCodes) take(hash []byte, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.codes[string(hash)]
	delete(s.codes, string(hash))
	return v.family, ok && now.Before(v.expires)
}
