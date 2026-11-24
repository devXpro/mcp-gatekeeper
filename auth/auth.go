package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/devXpro/mcp-gatekeeper/adminsock"
	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// Lifetimes (Family Hub's docs/PLAN.md §2 "Login", card T1.2).
const (
	// IdleTimeout ends a session that made no request for this long.
	IdleTimeout = 12 * time.Hour
	// AbsoluteTimeout ends every session this long after sign-in.
	AbsoluteTimeout = 7 * 24 * time.Hour
	// StepUpWindow is how long a passkey assertion (sign-in included) counts as fresh for dangerous actions.
	StepUpWindow = 5 * time.Minute
	// CeremonyTTL is how long a begun passkey ceremony can be finished.
	CeremonyTTL = 5 * time.Minute
	// SetupLinkTTL is the life of a setup link.
	SetupLinkTTL = 15 * time.Minute
	// InviteTTL is the life of an owner or member invite.
	InviteTTL = 24 * time.Hour

	touchEvery = time.Minute // LastSeenAt is written at most this often per session
	sweepEvery = time.Hour   // expired sessions are deleted this often
	maxUA      = 256         // bytes of the User-Agent a session keeps
)

// Options is what New needs.
type Options struct {
	// Site is where the application is served: the public URL is the only WebAuthn origin and the base of the setup
	// and invite links; an empty RPID is the host of PublicURL.
	Site core.Site
	// Brand names the session cookie (SessionCookie, "__Host-…"), the CSRF header (CSRFHeader) and the relying party
	// a browser shows next to the domain (Product). TxnCookie is not auth's.
	Brand core.Brand
	// Store keeps people, passkeys, sessions, invites and the audit.
	Store store.Store
	// Logger gets auth's lines; nil discards.
	Logger *slog.Logger
	// Clock is the time; nil is the system clock.
	Clock core.Clock
	// Admin, when set, gets auth's admin commands (setup-link and reset-access, see AdminCommands).
	Admin *adminsock.Registry
	// AdminCLI is how the operator runs an admin command, named in messages, e.g. "hub admin"; "" is "admin".
	AdminCLI string
	// ResetSteps are the application's parts of reset-access (Family Hub: deleting the superadmin's legacy keys).
	ResetSteps []ResetStep
}

// Auth is the passkey, session and invite service. It is safe for concurrent use.
type Auth struct {
	site     core.Site
	brand    core.Brand
	st       store.Store
	log      *slog.Logger
	now      core.Clock // always UTC
	wa       *webauthn.WebAuthn
	adminCLI string
	steps    []ResetStep

	ceremonies *ceremonies
	limits     limits
	fails      *failedLogins // coalesces the auth.login.fail entries
	deletes    sync.Mutex    // serializes passkey deletions, so two at once cannot remove the last passkey

	sweepMu   sync.Mutex
	sweepStop context.CancelFunc
	sweepDone chan struct{}
}

var _ core.Sessions = (*Auth)(nil)
var _ core.RouteRegistrar = (*Auth)(nil)

// New checks the options and returns an Auth. Site.PublicURL must be an origin (scheme, host, optional port, nothing
// else). With Options.Admin set, it registers auth's admin commands there.
func New(o Options) (*Auth, error) {
	if o.Store == nil {
		return nil, errors.New("auth: a store is required")
	}
	site, err := checkSite(o.Site)
	if err != nil {
		return nil, err
	}
	if err := checkBrand(o.Brand); err != nil {
		return nil, err
	}
	if err := checkSteps(o.ResetSteps); err != nil {
		return nil, err
	}
	wa, err := newWebAuthn(site, o.Brand.Product)
	if err != nil {
		return nil, err
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	adminCLI := o.AdminCLI
	if adminCLI == "" {
		adminCLI = "admin"
	}
	a := &Auth{
		site: site, brand: o.Brand, st: o.Store, log: log, now: func() time.Time { return clock().UTC() }, wa: wa,
		adminCLI: adminCLI, steps: append([]ResetStep(nil), o.ResetSteps...),
		ceremonies: newCeremonies(), limits: newLimits(), fails: newFailedLogins(),
	}
	if o.Admin != nil {
		if err := o.Admin.Add(a.AdminCommands()...); err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
	}
	return a, nil
}

func checkSite(s core.Site) (core.Site, error) {
	u, err := url.Parse(s.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return core.Site{}, fmt.Errorf("auth: public URL %q is not an origin", s.PublicURL)
	}
	s.PublicURL = strings.ToLower(u.Scheme + "://" + u.Host)
	host := strings.ToLower(u.Hostname())
	if s.RPID == "" {
		s.RPID = host
	}
	s.RPID = strings.ToLower(s.RPID)
	if host != s.RPID && !strings.HasSuffix(host, "."+s.RPID) {
		return core.Site{}, fmt.Errorf("auth: RP ID %q is not the public URL's host or a parent of it", s.RPID)
	}
	return s, nil
}

// checkBrand refuses names that would put a broken cookie or header on the wire.
func checkBrand(b core.Brand) error {
	switch {
	case len(b.SessionCookie) <= len("__Host-") || !strings.HasPrefix(b.SessionCookie, "__Host-") || !isToken(b.SessionCookie):
		return fmt.Errorf("auth: the session cookie %q must be a cookie name starting with __Host-", b.SessionCookie)
	case !isToken(b.CSRFHeader):
		return fmt.Errorf("auth: the CSRF header %q is not a header name", b.CSRFHeader)
	case strings.TrimSpace(b.Product) == "":
		return errors.New("auth: the product name is required (the passkey prompt shows it)")
	}
	return nil
}

// isToken reports whether s is an RFC 9110 token: what a cookie or header name may be.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r > 0x7e || r <= ' ' || strings.ContainsRune(`"(),/:;<=>?@[\]{}`, r) {
			return false
		}
	}
	return true
}

// Start sweeps expired sessions now and then every hour, and writes the counted failed sign-ins every minute, until
// Stop.
func (a *Auth) Start(context.Context) error {
	a.sweepMu.Lock()
	defer a.sweepMu.Unlock()
	if a.sweepStop != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.sweepStop, a.sweepDone = cancel, make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		sweep, flush := time.NewTicker(sweepEvery), time.NewTicker(failWindow)
		defer sweep.Stop()
		defer flush.Stop()
		a.sweep(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sweep.C:
				a.sweep(ctx)
			case <-flush.C:
				a.flushLoginFails(ctx, false)
			}
		}
	}(a.sweepDone)
	return nil
}

// Stop ends the sweeps and writes the failed sign-ins still counted.
func (a *Auth) Stop(ctx context.Context) error {
	a.sweepMu.Lock()
	stop, done := a.sweepStop, a.sweepDone
	a.sweepStop, a.sweepDone = nil, nil
	a.sweepMu.Unlock()
	if stop == nil {
		return nil
	}
	stop()
	select {
	case <-done:
		a.flushLoginFails(ctx, true)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sweep deletes the sessions past their absolute end or idle for too long. Viewer refuses them anyway; this removes
// the abandoned ones.
func (a *Auth) sweep(ctx context.Context) {
	n, err := a.st.Sessions().DeleteExpired(ctx, a.now(), IdleTimeout)
	switch {
	case err != nil && ctx.Err() == nil:
		a.log.Warn("auth: cannot delete expired sessions", slog.Any("error", err))
	case n > 0:
		a.log.Debug("auth: deleted expired sessions", slog.Int("sessions", n))
	}
}

// RegisterRoutes adds the routes of Family Hub's §5.9 "Auth":
//
//	POST   /api/auth/token              public: what a setup link or invite is
//	POST   /api/auth/register/begin     public: a passkey for a setup link or invite
//	POST   /api/auth/register/finish    public: creates the person (and the first account) and signs in
//	POST   /api/auth/login/begin        public
//	POST   /api/auth/login/finish       public: signs in
//	POST   /api/auth/stepup/begin       session
//	POST   /api/auth/stepup/finish      session
//	POST   /api/auth/logout             204, with or without a session
//	GET    /api/me                      session
//	GET    /api/me/passkeys             session
//	POST   /api/me/passkeys/begin       session + step-up
//	POST   /api/me/passkeys/finish      session + step-up
//	PATCH  /api/me/passkeys/{id}        session
//	DELETE /api/me/passkeys/{id}        session + step-up; never the last passkey; ends the other sessions
//	POST   /api/me/sessions/revoke      session + step-up: sign out on other devices; 204 with a new cookie
func (a *Auth) RegisterRoutes(mux *http.ServeMux) {
	route := func(pattern string, h http.HandlerFunc, mw ...core.Middleware) {
		var next http.Handler = h
		for i := len(mw) - 1; i >= 0; i-- {
			next = mw[i](next)
		}
		mux.Handle(pattern, noStore(next))
	}
	route("POST /api/auth/token", a.tokenInfo, a.guard(rateToken))
	route("POST /api/auth/register/begin", a.registerBegin, a.guard(rateToken))
	route("POST /api/auth/register/finish", a.registerFinish, a.guard(rateToken))
	route("POST /api/auth/login/begin", a.loginBegin, a.guard(rateLoginBegin))
	route("POST /api/auth/login/finish", a.loginFinish, a.guard(rateLoginFinish))
	route("POST /api/auth/stepup/begin", a.stepUpBegin, a.guard(rateStepUpBegin), a.RequireViewer)
	route("POST /api/auth/stepup/finish", a.stepUpFinish, a.guard(rateStepUpFinish), a.RequireViewer)
	route("POST /api/auth/logout", a.logout, a.SameOrigin)
	route("GET /api/me", a.me, a.RequireViewer)
	route("GET /api/me/passkeys", a.listPasskeys, a.RequireViewer)
	route("POST /api/me/passkeys/begin", a.passkeyBegin, a.guard(ratePasskeyBegin), a.RequireViewer, a.RequireStepUp)
	route("POST /api/me/passkeys/finish", a.passkeyFinish, a.guard(ratePasskeyFinish), a.RequireViewer, a.RequireStepUp)
	route("PATCH /api/me/passkeys/{id}", a.renamePasskey, a.RequireViewer)
	route("DELETE /api/me/passkeys/{id}", a.deletePasskey, a.RequireViewer, a.RequireStepUp)
	route("POST /api/me/sessions/revoke", a.revokeSessions, a.RequireViewer, a.RequireStepUp)
}

// audit appends an entry. It outlives the request, so a client that goes away cannot drop it; a failure is logged.
func (a *Auth) audit(ctx context.Context, e core.AuditEntry) {
	if e.At.IsZero() {
		e.At = a.now()
	}
	if err := a.st.Audit().Append(context.WithoutCancel(ctx), e); err != nil {
		a.log.Error("auth: cannot write an audit entry", slog.String("action", e.Action), slog.Any("error", err))
	}
}

// viewerOf is the viewer RequireViewer stored.
func viewerOf(r *http.Request) core.Viewer {
	v, _ := core.ViewerFrom(r.Context())
	return v
}
