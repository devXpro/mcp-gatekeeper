package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// Viewer returns the signed-in person of r, or core.ErrNoSession; other errors are store failures. It owns the
// expiry rules: a session past its absolute end or idle for 12 hours, or whose person is gone or not active
// (core.Person.Active: disabled, or past the end of their term), or whose account is gone, is deleted. LastSeenAt is
// written at most once a minute.
func (a *Auth) Viewer(r *http.Request) (core.Viewer, error) {
	ck, err := r.Cookie(a.brand.SessionCookie)
	if err != nil || !wellFormedToken(ck.Value) {
		return core.Viewer{}, core.ErrNoSession
	}
	ctx := r.Context()
	hash := hashToken(ck.Value)
	s, err := a.st.Sessions().Get(ctx, hash)
	if errors.Is(err, core.ErrNotFound) {
		return core.Viewer{}, core.ErrNoSession
	}
	if err != nil {
		return core.Viewer{}, fmt.Errorf("auth: load session: %w", err)
	}
	// The store looked the hash up; compare once more in constant time, so a loose lookup can never let anyone in.
	if subtle.ConstantTimeCompare(s.IDHash, hash) != 1 {
		return core.Viewer{}, core.ErrNoSession
	}
	now := a.now()
	if !now.Before(s.ExpiresAt) || !now.Before(s.LastSeenAt.Add(IdleTimeout)) {
		a.dropSession(ctx, hash)
		return core.Viewer{}, core.ErrNoSession
	}
	person, err := a.st.People().Get(ctx, s.PersonID)
	if err == nil && !person.Active(now) {
		err = core.ErrNotFound
	}
	if errors.Is(err, core.ErrNotFound) {
		a.dropSession(ctx, hash)
		return core.Viewer{}, core.ErrNoSession
	}
	if err != nil {
		return core.Viewer{}, fmt.Errorf("auth: load person: %w", err)
	}
	account, err := a.st.Accounts().Get(ctx, person.AccountID)
	if errors.Is(err, core.ErrNotFound) {
		a.dropSession(ctx, hash)
		return core.Viewer{}, core.ErrNoSession
	}
	if err != nil {
		return core.Viewer{}, fmt.Errorf("auth: load account: %w", err)
	}
	if now.Sub(s.LastSeenAt) >= touchEvery {
		if err := a.st.Sessions().Touch(ctx, hash, now); err != nil {
			a.log.Warn("auth: cannot touch a session", slog.Any("error", err))
		} else {
			s.LastSeenAt = now
		}
	}
	return core.Viewer{Person: person, Account: account, Session: s}, nil
}

// dropSession deletes a session Viewer found unusable; a failure only leaves a row the sweep removes later.
func (a *Auth) dropSession(ctx context.Context, hash []byte) {
	if err := a.st.Sessions().Delete(context.WithoutCancel(ctx), hash); err != nil {
		a.log.Warn("auth: cannot delete a session", slog.Any("error", err))
	}
}

// RequireViewer is middleware: 401 no_session without a valid session; otherwise it stores the Viewer in the
// request context (core.ViewerFrom) and calls next. For a mutating method it first applies the CSRF checks (403
// forbidden), so every session-protected write of every package gets them.
func (a *Auth) RequireViewer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.sameOrigin(r) {
			a.fail(w, r, errCSRF)
			return
		}
		if _, ok := core.ViewerFrom(r.Context()); ok {
			next.ServeHTTP(w, r)
			return
		}
		v, err := a.Viewer(r)
		if errors.Is(err, core.ErrNoSession) {
			a.fail(w, r, errNoSession)
			return
		}
		if err != nil {
			a.fail(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(core.WithViewer(r.Context(), v)))
	})
}

// RequireStepUp is middleware after RequireViewer: 403 step_up_required unless the session's last passkey assertion
// (sign-in included) is less than 5 minutes old. Nothing of the request happens then; the SPA steps up and retries.
func (a *Auth) RequireStepUp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := core.ViewerFrom(r.Context())
		if !ok {
			a.fail(w, r, errNoSession)
			return
		}
		if !a.now().Before(v.Session.StepUpUntil) {
			a.fail(w, r, errStepUp)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SameOrigin is middleware with the checks of a mutating request: the header Brand.CSRFHeader: 1, an Origin (when
// the browser sends one) equal to the public URL, and a Sec-Fetch-Site (when sent) of same-origin; otherwise 403
// forbidden. GET, HEAD and OPTIONS pass. RequireViewer applies it already.
func (a *Auth) SameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.sameOrigin(r) {
			a.fail(w, r, errCSRF)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Auth) sameOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if r.Header.Get(a.brand.CSRFHeader) != "1" {
		return false
	}
	if o := r.Header.Values("Origin"); len(o) > 1 || len(o) == 1 && o[0] != a.site.PublicURL {
		return false
	}
	if sf := r.Header.Values("Sec-Fetch-Site"); len(sf) > 1 || len(sf) == 1 && sf[0] != "same-origin" {
		return false
	}
	return true
}

// newSession makes the session of a fresh sign-in or registration, which counts as step-up. The token is the cookie
// value; only its hash is stored.
func (a *Auth) newSession(p core.PersonID, userAgent string, now time.Time) (string, core.Session) {
	token := newToken()
	return token, core.Session{
		IDHash: hashToken(token), PersonID: p, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(AbsoluteTimeout),
		StepUpUntil: now.Add(StepUpWindow), UserAgent: clip(userAgent, maxUA),
	}
}

// setSessionCookie sends the cookie of a new session; Max-Age is the absolute lifetime.
func (a *Auth) setSessionCookie(w http.ResponseWriter, token string) {
	a.setSessionCookieFor(w, token, AbsoluteTimeout)
}

// setSessionCookieFor sends a session cookie that lives maxAge (at least a second).
func (a *Auth) setSessionCookieFor(w http.ResponseWriter, token string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: a.brand.SessionCookie, Value: token, Path: "/", MaxAge: max(1, int(maxAge/time.Second)),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie tells the browser to drop the session cookie, with the attributes it was set with. Logout sends
// it; so does an application that ended the session another way (Family Hub: deleting the whole account).
func (a *Auth) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: a.brand.SessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// rotateIn ends every session of v's person, v's own included, and opens a new one for v's browser in its place: a
// new token with the old session's sign-in time, absolute end, step-up and User-Agent. ctx carries the caller's
// transaction; a session that ended meanwhile (another device signed everybody out) is errNoSession, so it is never
// revived. The caller sends the cookie with setSessionCookieFor, until the session's absolute end.
func (a *Auth) rotateIn(ctx context.Context, v core.Viewer, now time.Time) (string, core.Session, error) {
	if _, err := a.st.Sessions().Get(ctx, v.Session.IDHash); errors.Is(err, core.ErrNotFound) {
		return "", core.Session{}, errNoSession
	} else if err != nil {
		return "", core.Session{}, err
	}
	if err := a.st.Sessions().DeleteByPerson(ctx, v.Person.ID); err != nil {
		return "", core.Session{}, err
	}
	token, old := newToken(), v.Session
	s := core.Session{IDHash: hashToken(token), PersonID: v.Person.ID, CreatedAt: old.CreatedAt, LastSeenAt: now,
		ExpiresAt: old.ExpiresAt, StepUpUntil: old.StepUpUntil, UserAgent: old.UserAgent}
	if err := a.st.Sessions().Create(ctx, s); err != nil {
		return "", core.Session{}, err
	}
	return token, s, nil
}

// revokeSessions is "sign out on other devices" (T2.R M3): every session of the person ends, and this browser gets
// a new one with the same sign-in time, absolute end and step-up. 204 with the new cookie.
func (a *Auth) revokeSessions(w http.ResponseWriter, r *http.Request) {
	if err := decode(w, r, &struct{}{}); err != nil {
		a.fail(w, r, err)
		return
	}
	v := viewerOf(r)
	now := a.now()
	var (
		token string
		s     core.Session
	)
	err := a.st.Tx(r.Context(), func(ctx context.Context) error {
		var err error
		token, s, err = a.rotateIn(ctx, v, now)
		return err
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r.Context(), core.AuditEntry{At: now, AccountID: v.Account.ID, Actor: v.Person.ID,
		Action: "auth.sessions.revoke", Target: string(v.Person.ID), IP: a.clientIP(r)})
	a.setSessionCookieFor(w, token, s.ExpiresAt.Sub(now))
	w.WriteHeader(http.StatusNoContent)
}

// The person and account objects of Family Hub's §5.9.
type personJSON struct {
	ID         core.PersonID `json:"id"`
	Name       string        `json:"name"`
	Role       core.Role     `json:"role"`
	Superadmin bool          `json:"superadmin"`
}

type accountJSON struct {
	ID   core.AccountID `json:"id"`
	Name string         `json:"name"`
}

// signedInJSON answers register/finish and login/finish.
type signedInJSON struct {
	Person  personJSON  `json:"person"`
	Account accountJSON `json:"account"`
}

// meJSON is GET /api/me; step_up_until is null when the session never stepped up.
type meJSON struct {
	Person      personJSON  `json:"person"`
	Account     accountJSON `json:"account"`
	StepUpUntil *string     `json:"step_up_until"`
}

func personOf(p core.Person) personJSON {
	return personJSON{ID: p.ID, Name: p.Name, Role: p.Role, Superadmin: p.Superadmin}
}

func accountOf(a core.Account) accountJSON { return accountJSON{ID: a.ID, Name: a.Name} }

func (a *Auth) me(w http.ResponseWriter, r *http.Request) {
	v := viewerOf(r)
	writeJSON(w, http.StatusOK, meJSON{Person: personOf(v.Person), Account: accountOf(v.Account),
		StepUpUntil: optTime(v.Session.StepUpUntil)})
}

// logout ends the session and clears the cookie; without a valid session it only clears the cookie. Always 204.
func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := a.Viewer(r)
	switch {
	case errors.Is(err, core.ErrNoSession):
	case err != nil:
		a.fail(w, r, err)
		return
	default:
		if err := a.st.Sessions().Delete(context.WithoutCancel(ctx), v.Session.IDHash); err != nil {
			a.fail(w, r, err)
			return
		}
		a.audit(ctx, core.AuditEntry{AccountID: v.Account.ID, Actor: v.Person.ID, Action: "auth.logout",
			Target: string(v.Person.ID), IP: a.clientIP(r)})
	}
	a.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}
