package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

// txnView is the answer of GET /api/oauth/txn/{txn}. started_from and client_kind are for the consent screen's
// warnings (T2.R H1): a request opened from elsewhere than the assistant is suspicious, and the name of a DCR client
// is whatever it registered with. Family Hub called the resource "module"; the rest is as it was.
type txnView struct {
	Assistant      core.Assistant  `json:"assistant"`
	ClientName     string          `json:"client_name"`
	ClientKind     core.ClientKind `json:"client_kind"`
	RedirectHost   string          `json:"redirect_host"`
	StartedFrom    string          `json:"started_from"`
	Resource       resourceView    `json:"resource"`
	Account        accountView     `json:"account"`
	AlreadyGranted bool            `json:"already_granted"`
	App            *appView        `json:"app,omitempty"` // a native app's client only
}

// appView is the native app of a transaction, for the consent screen to name it ("Desk on your computer") next
// to the client's own name.
type appView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type resourceView struct {
	ID          core.ResourceID `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Tools       []toolView      `json:"tools"`
}

type toolView struct {
	Name   string `json:"name"`
	Title  string `json:"title"`
	Access string `json:"access"`
}

type accountView struct {
	ID   core.AccountID `json:"id"`
	Name string         `json:"name"`
}

// redirectView is the answer of approve and deny: where the SPA sends the browser.
type redirectView struct {
	RedirectURL string `json:"redirect_url"`
}

// consentCall is a consent API call: its viewer and the live transaction of a resource that can be connected and is
// available to the viewer's account.
type consentCall struct {
	viewer core.Viewer
	txn    txn
	info   core.ResourceInfo
}

// txnInfo is GET /api/oauth/txn/{txn}: what the consent screen shows. It needs a session of an active person and the
// browser that started the transaction, and the resource must be available to the viewer's account (403 otherwise).
func (s *Server) txnInfo(w http.ResponseWriter, r *http.Request) {
	call, ok := s.consentCall(w, r)
	if !ok {
		return
	}
	t, v := call.txn, call.viewer
	g, err := s.store.OAuth().FindGrant(r.Context(), v.Person.ID, t.clientID, t.resource)
	if err != nil && !errors.Is(err, core.ErrNotFound) {
		s.log.Error("oauth: reading a grant failed", slog.Any("error", err))
		apiError(w, http.StatusInternalServerError, httpsec.CodeInternal, "the "+s.app+"'s store failed")
		return
	}
	tools := make([]toolView, 0, len(call.info.Tools))
	for _, tool := range call.info.Tools {
		tools = append(tools, toolView{Name: tool.Name, Title: tool.Title, Access: tool.Access})
	}
	var app *appView
	if a, ok := s.nativeApp(t.assistant); ok {
		app = &appView{ID: a.ID, Name: a.Name}
	}
	noStore(w)
	writeJSON(w, http.StatusOK, txnView{
		Assistant:    t.assistant,
		ClientName:   t.clientName,
		ClientKind:   t.clientKind,
		RedirectHost: redirectHost(t.redirectURI),
		StartedFrom:  t.startedFrom,
		Resource: resourceView{
			ID: t.resource, Name: call.info.Name, Description: call.info.Description, Tools: tools,
		},
		Account:        accountView{ID: v.Account.ID, Name: v.Account.Name},
		AlreadyGranted: err == nil && !grantExpired(g, s.now()),
		App:            app,
	})
}

// approve is POST /api/oauth/txn/{txn}/approve: the viewer lets the client use the resource. It reuses the active
// grant of (person, client, resource) or creates one, and answers with the client's redirect URI carrying a code that
// is good once for 5 minutes, the state and iss.
//
// Unless ConsentStepUpOff is set, a new grant needs a fresh step-up (T2.R M4): 403 step_up_required otherwise, and
// the transaction stays for the retry after the SPA's step-up. A sign-in counts as one for its first 5 minutes.
// Reusing the person's grant needs none, so reconnecting is one click.
func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	call, ok := s.consentCall(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if _, err := s.store.OAuth().GetClient(ctx, call.txn.clientID); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			apiError(w, http.StatusNotFound, httpsec.CodeNotFound, "this connection is gone; start connecting again")
			return
		}
		s.log.Error("oauth: reading a client failed", slog.Any("error", err))
		apiError(w, http.StatusInternalServerError, httpsec.CodeInternal, "the "+s.app+"'s store failed")
		return
	}
	now := s.now()
	id := r.PathValue("txn")
	t, ok := s.txns.take(id, now)
	if !ok {
		apiError(w, http.StatusNotFound, httpsec.CodeNotFound, "this connection request was answered already")
		return
	}
	needStepUp := s.cfg.stepUp && !now.Before(call.viewer.Session.StepUpUntil)
	code := randomToken()
	err := s.consent(ctx, call.viewer, t, hashOf(code), now, s.ip(r), needStepUp)
	switch {
	case errors.Is(err, errStepUp):
		s.txns.restore(id, t)
		apiError(w, http.StatusForbidden, httpsec.CodeStepUp, "approving a new connection needs a fresh passkey")
		return
	case err != nil:
		s.log.Error("oauth: storing a consent failed", slog.Any("error", err))
		apiError(w, http.StatusInternalServerError, httpsec.CodeInternal,
			"the "+s.app+"'s store failed; start connecting again")
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, redirectView{
		RedirectURL: s.responseURL(t.redirectURI, t.state, url.Values{"code": {code}}),
	})
}

// deny is POST /api/oauth/txn/{txn}/deny: the client's redirect URI with error=access_denied. Only the browser that
// started the transaction may deny it.
func (s *Server) deny(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.boundTxn(w, r); !ok {
		return
	}
	t, ok := s.txns.take(r.PathValue("txn"), s.now())
	if !ok {
		apiError(w, http.StatusNotFound, httpsec.CodeNotFound,
			"this connection request expired or was answered already")
		return
	}
	noStore(w)
	writeJSON(w, http.StatusOK, redirectView{
		RedirectURL: s.responseURL(t.redirectURI, t.state, url.Values{"error": {"access_denied"}}),
	})
}

// consentCall resolves the viewer and the transaction of a consent API call (boundTxn), answering 401 no_session when
// the viewer may no longer act (core.Person.Active), 404 when its resource can no longer be connected and 403 when it
// is not available to the viewer's account.
//
// Package auth already refuses the session of a person who is not active, with the same 401; the check here covers
// another core.Sessions and a term that ends while the call runs.
func (s *Server) consentCall(w http.ResponseWriter, r *http.Request) (consentCall, bool) {
	ctx := r.Context()
	t, ok := s.boundTxn(w, r)
	if !ok {
		return consentCall{}, false
	}
	v, _ := core.ViewerFrom(ctx)
	if !v.Person.Active(s.now()) {
		apiError(w, http.StatusUnauthorized, httpsec.CodeNoSession, "your access has ended")
		return consentCall{}, false
	}
	info, err := s.liveResource(ctx, t.resource)
	switch {
	case errors.Is(err, errNoResource):
		apiError(w, http.StatusNotFound, httpsec.CodeNotFound, "the "+s.noun+" is not available")
		return consentCall{}, false
	case err != nil:
		s.log.Error("oauth: reading a resource failed", slog.Any("error", err))
		apiError(w, http.StatusInternalServerError, httpsec.CodeInternal, "the "+s.noun+" registry failed")
		return consentCall{}, false
	}
	available, err := s.catalog.Available(ctx, v.Account.ID, t.resource)
	switch {
	case err != nil:
		s.log.Error("oauth: reading whether a resource is available failed", slog.Any("error", err))
		apiError(w, http.StatusInternalServerError, httpsec.CodeInternal, "the "+s.noun+" registry failed")
		return consentCall{}, false
	case !available:
		apiError(w, http.StatusForbidden, httpsec.CodeForbidden, "the "+s.noun+" is not on for your account")
		return consentCall{}, false
	}
	return consentCall{viewer: v, txn: t, info: info}, true
}

// boundTxn returns the live transaction of a consent API call made by a signed-in person in the browser that
// started it. It answers 401 without a viewer, 404 when the transaction is gone, and 403 other_browser when the
// browser's binding cookie is missing or another one (T2.R H1). other_browser is a code of its own, so the SPA never
// mistakes it for the 403 forbidden of a resource that is not available.
func (s *Server) boundTxn(w http.ResponseWriter, r *http.Request) (txn, bool) {
	v, ok := core.ViewerFrom(r.Context())
	if !ok {
		apiError(w, http.StatusUnauthorized, httpsec.CodeNoSession, "sign in first")
		return txn{}, false
	}
	t, ok := s.txns.get(r.PathValue("txn"), s.now())
	if !ok {
		apiError(w, http.StatusNotFound, httpsec.CodeNotFound, "this connection request expired; start connecting again")
		return txn{}, false
	}
	if s.cfg.binding && !s.sameBrowser(r, t.binding) {
		// A consent link opened by somebody else is what phishing looks like; the log keeps who and what.
		s.log.Warn("oauth: a consent call from another browser than the one that started it was refused",
			slog.String("person", string(v.Person.ID)), slog.String("client", string(t.clientID)),
			slog.String("resource", string(t.resource)))
		apiError(w, http.StatusForbidden, httpsec.CodeOtherBrowser,
			"this connection was started in another browser; start connecting from the assistant again")
		return txn{}, false
	}
	return t, true
}

// sameBrowser reports whether r carries the binding cookie whose sha256 is binding, comparing in constant time.
func (s *Server) sameBrowser(r *http.Request, binding []byte) bool {
	ck, err := r.Cookie(s.txnCookie)
	return err == nil && len(binding) == sha256.Size && subtle.ConstantTimeCompare(hashOf(ck.Value), binding) == 1
}

// consent stores the code of an approved transaction under the person's grant of (client, resource), all in one
// store transaction. It reuses the active grant while it is younger than grantTTL; otherwise it creates and audits a
// new one, first revoking the outlived one (T2.R L7). A new grant with needStepUp set is errStepUp, and nothing is
// written. Two approvals racing to create a grant meet at the store's unique index: the loser runs again and finds
// the winner's grant.
func (s *Server) consent(ctx context.Context, v core.Viewer, t txn, codeHash []byte, now time.Time, ip string,
	needStepUp bool,
) error {
	run := func() error {
		return s.store.Tx(ctx, func(ctx context.Context) error {
			o := s.store.OAuth()
			g, err := o.FindGrant(ctx, v.Person.ID, t.clientID, t.resource)
			if err != nil && !errors.Is(err, core.ErrNotFound) {
				return err
			}
			if err != nil || grantExpired(g, now) {
				if needStepUp {
					return errStepUp
				}
				if err == nil {
					if err := s.revokeAudited(ctx, g, "", "", reasonExpired, now); err != nil {
						return err
					}
				}
				g = core.Grant{
					ID: core.GrantID(core.NewID(core.PrefixGrant)), PersonID: v.Person.ID, AccountID: v.Account.ID,
					ClientID: t.clientID, ResourceID: t.resource, Scope: t.scope, CreatedAt: now,
				}
				if err := o.PutGrant(ctx, g); err != nil {
					return err
				}
				err = s.store.Audit().Append(ctx, core.AuditEntry{
					At: now, AccountID: v.Account.ID, Actor: v.Person.ID, Action: actionGrantCreate, Target: string(g.ID),
					IP: ip, Detail: map[string]string{
						detailResource: string(t.resource), "assistant": string(t.assistant), "client": string(t.clientID),
					},
				})
				if err != nil {
					return err
				}
			}
			return o.PutCode(ctx, core.AuthCode{
				CodeHash: codeHash, GrantID: g.ID, ClientID: t.clientID, RedirectURI: t.redirectURI,
				Resource: t.resourceURL, Scope: t.scope, CodeChallenge: t.challenge, CreatedAt: now,
				ExpiresAt: now.Add(codeTTL),
			})
		})
	}
	err := run()
	if errors.Is(err, core.ErrConflict) {
		err = run()
	}
	return err
}

// grantExpired reports whether g has outlived grantTTL (T2.R L7). Its tokens die with it, whatever their own expiry.
func grantExpired(g core.Grant, now time.Time) bool {
	return !now.Before(grantEnd(g))
}

// grantEnd is when g stops working: grantTTL after its consent.
func grantEnd(g core.Grant) time.Time {
	return g.CreatedAt.Add(grantTTL)
}

// redirectHost is the host of a redirect URI the callback rules accepted.
func redirectHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
