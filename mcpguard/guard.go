// Package mcpguard is the access check in front of an MCP endpoint (Family Hub docs/PLAN.md §5.6), taken from Family
// Hub's internal/gateway:
//   - Guard.Middleware finds the resource of the request path (Guard.MiddlewareFor is told it), checks the bearer
//     access token, the person behind it and the resource switch, answers 401 the way the MCP authorization spec
//     wants it, and puts the caller's core.AccessInfo and core.Person in the request context (AccessFrom, PersonFrom);
//   - the helpers an application's MCP handler or proxy uses: the header policy (RequestHeaders, ResponseHeaders),
//     the body cap (ReadBody), the in-flight cap (Guard.Admit, Guard.AdmitAccess), the failure limit for other doors
//     (Guard.Refuse) and the relay of an answer that flushes server-sent events and pings an idle stream
//     (Guard.Relay).
//
// The application keeps what is its own: resolving the resource to something that runs (its 404s go in front of the
// middleware), MCP session ids, the identity it hands its servers, and its call log.
package mcpguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

// Scope is the OAuth scope of MCP traffic, which a 401 tells the assistant to ask for.
const Scope = "mcp"

// metadataPrefix is where the protected-resource metadata of a resource path lives (RFC 9728 §3.1).
const metadataPrefix = "/.well-known/oauth-protected-resource"

const defaultPingInterval = 25 * time.Second

// People finds the person behind an access token; store.PersonStore implements it.
type People interface {
	Get(ctx context.Context, id core.PersonID) (core.Person, error)
}

// Options configure a Guard.
type Options struct {
	// Site gives PublicURL for resource_metadata and ClientIP for the failure limit; New checks it (Site.Validate).
	// A header mode needs httpsec.PeerGuard trusting only the connector (see there).
	Site      core.Site
	Paths     core.ResourcePaths   // the resource of a request path (Family Hub: core.PerResource{Prefix: "/mcp/"})
	Tokens    core.TokenValidator  // the access tokens (package oauth)
	People    People               // a person who is gone, disabled, past their term or moved makes their tokens worthless
	Resources core.ResourceCatalog // Available: whether the token's account may use the resource now (403)
	// Brand gives the words of the answers' messages (ResourceWord: "module" when empty); nothing else of it is read.
	Brand core.Brand
	// PingInterval is how long an event stream may stay silent before Relay writes ": ping" into it; 0 means 25 s,
	// under Cloudflare's 100 s cut.
	PingInterval time.Duration
	// InFlightPerResource is how many calls may be inside one resource at once for each holder InFlightKey names,
	// open event streams included; 0 means 16.
	InFlightPerResource int
	// InFlightKey is who holds those places: PerAccount (the default, every person of an account shares them) or
	// PerPerson (each person has their own; for an application where one account is a whole household).
	InFlightKey InFlightKey
	// FailuresPerAddress is how many unknown credentials one client address may present a minute (Refuse); 0 means
	// 30.
	FailuresPerAddress int
	Log                *slog.Logger // nil discards
	Clock              core.Clock   // nil is time.Now
}

// Guard is the access check of the MCP endpoints and the limits they share.
type Guard struct {
	site      core.Site
	paths     core.ResourcePaths
	tokens    core.TokenValidator
	people    People
	resources core.ResourceCatalog
	noun      string // Brand.ResourceWord
	ping      time.Duration
	perPerson bool
	log       *slog.Logger
	now       core.Clock
	failures  *failureLimit
	inFlight  *inFlight

	noAddressHeader atomic.Bool // the warning about a request without the ClientIP header was logged
}

// New returns a Guard.
func New(o Options) (*Guard, error) {
	if err := o.Site.Validate(); err != nil {
		return nil, fmt.Errorf("mcpguard: %w", err)
	}
	switch {
	case o.Paths == nil:
		return nil, errors.New("mcpguard: Paths is not set")
	case o.Tokens == nil:
		return nil, errors.New("mcpguard: Tokens is not set")
	case o.People == nil:
		return nil, errors.New("mcpguard: People is not set")
	case o.Resources == nil:
		return nil, errors.New("mcpguard: Resources is not set")
	case o.PingInterval < 0:
		return nil, fmt.Errorf("mcpguard: PingInterval %s is negative", o.PingInterval)
	case o.InFlightPerResource < 0:
		return nil, fmt.Errorf("mcpguard: InFlightPerResource %d is negative", o.InFlightPerResource)
	case o.FailuresPerAddress < 0:
		return nil, fmt.Errorf("mcpguard: FailuresPerAddress %d is negative", o.FailuresPerAddress)
	case o.InFlightKey != PerAccount && o.InFlightKey != PerPerson:
		return nil, fmt.Errorf("mcpguard: InFlightKey %d is neither PerAccount nor PerPerson", o.InFlightKey)
	}
	if o.PingInterval == 0 {
		o.PingInterval = defaultPingInterval
	}
	if o.InFlightPerResource == 0 {
		o.InFlightPerResource = inFlightPerResource
	}
	if o.FailuresPerAddress == 0 {
		o.FailuresPerAddress = failuresPerAddress
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &Guard{
		site: o.Site, paths: o.Paths, tokens: o.Tokens, people: o.People, resources: o.Resources,
		noun: o.Brand.ResourceWord(), ping: o.PingInterval, perPerson: o.InFlightKey == PerPerson, log: o.Log,
		now:      o.Clock,
		failures: newFailureLimit(o.FailuresPerAddress),
		inFlight: newInFlight(o.InFlightPerResource),
	}, nil
}

// caller is what the middleware leaves in the request context.
type caller struct {
	access core.AccessInfo
	person core.Person
}

type callerKey struct{}

// AccessFrom returns the access of the token that Guard.Middleware let through.
func AccessFrom(ctx context.Context) (core.AccessInfo, bool) {
	c, ok := ctx.Value(callerKey{}).(caller)
	return c.access, ok
}

// PersonFrom returns the person behind the token that Guard.Middleware let through, as the store had them then.
func PersonFrom(ctx context.Context) (core.Person, bool) {
	c, ok := ctx.Value(callerKey{}).(caller)
	return c.person, ok
}

// Middleware lets a request through to next only with a live access token for the resource of its path. In order:
//   - every answer gets SecureHeaders;
//   - a path outside Paths is 404;
//   - no bearer token is 401 unauthorized;
//   - a token that is unknown, dead or for another resource, or whose person is gone, disabled, past their term
//     (core.Person.Active) or in another account, is 401 invalid_token (429 when the client's address has presented
//     too many such tokens, see Refuse; a token the validator knows to be expired or revoked, and a valid token of a
//     person who is gone or not active, are neither counted nor ever 429);
//   - an account that may not use the resource now is 403;
//   - a failure of the services behind it is 500, logged.
//
// The 401s carry WWW-Authenticate with the resource's protected-resource metadata and Scope. The middleware does not
// check that the resource exists: an application with several resources answers its own 404 in front of it. next
// gets a request whose context holds the caller (AccessFrom, PersonFrom); in a framework that keeps its own request
// (Gin), read it from the *http.Request next is called with.
//
// The resource is the one Paths finds in r.URL.Path as it is (review GK-1). The application must route on that same
// path, with no cleaning of dot segments or repeated slashes and not on the escaped path, or check that
// AccessFrom(ctx).ResourceID is the resource it forwards to: a router that cleans /mcp/a/../b into /mcp/b would hand
// b a request the guard let through with a token for a. MiddlewareFor takes the resource from the application
// instead, and is the safer choice for a route that serves one resource.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SecureHeaders(w.Header())
		id, ok := g.paths.FromPath(r.URL.Path)
		if !ok {
			notFound(w)
			return
		}
		g.check(w, r, id, next)
	})
}

// MiddlewareFor is Middleware for a handler that serves resource id alone, as the application's router decided: the
// token must be for id, whatever the path says. A request whose path Paths does not find id in (another resource, or
// none) is 404, so that a router that cleans or unescapes paths can never forward a token for one resource to
// another (review GK-1). Homie mounts exactly "/mcp" with MiddlewareFor("home") over core.SingleResource.
//
// It panics when Paths cannot serve id (Paths.FromPath(Paths.Path(id)) is not id): a wiring mistake, like a bad
// ServeMux pattern.
func (g *Guard) MiddlewareFor(id core.ResourceID) func(http.Handler) http.Handler {
	if got, ok := g.paths.FromPath(g.paths.Path(id)); !ok || got != id {
		panic(fmt.Sprintf("mcpguard: MiddlewareFor(%q): the paths serve no such resource", id))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			SecureHeaders(w.Header())
			if got, ok := g.paths.FromPath(r.URL.Path); !ok || got != id {
				notFound(w)
				return
			}
			g.check(w, r, id, next)
		})
	}
}

// check is the access check of a request for resource id, once SecureHeaders are set (see Middleware).
func (g *Guard) check(w http.ResponseWriter, r *http.Request, id core.ResourceID, next http.Handler) {
	token, ok := bearer(r)
	if !ok {
		g.refuseMCP(w, id, false)
		return
	}
	ctx := r.Context()
	refuse := func() { g.Refuse(w, r, func() { g.refuseMCP(w, id, true) }) }
	info, err := g.tokens.ValidateAccess(ctx, token, id)
	switch {
	case err == nil:
	case errors.Is(err, core.ErrExpired):
		// A token the validator knows, past its end or revoked (review GK-12): no guess, so no failure of the address.
		// Its client needs the 401 that sends it to refresh, not a 429 earned by junk from a shared address.
		g.refuseMCP(w, id, true)
		return
	case isRefusal(err):
		refuse()
		return
	default:
		g.internal(w, id, "validate the access token", err)
		return
	}
	if info.ResourceID != id {
		refuse()
		return
	}
	// A valid token of a person who is gone or no longer active (their access ended after it was issued) is no guess
	// either: refused with the same 401, but not charged to the address, which for an assistant is its provider's
	// egress shared by every connector there, the owner's own included.
	ended := func() { g.refuseMCP(w, id, true) }
	person, ok := g.livePerson(w, r, info, refuse, ended)
	if !ok || !g.available(w, r, info) {
		return
	}
	ctx = context.WithValue(ctx, callerKey{}, caller{access: info, person: person})
	next.ServeHTTP(w, r.WithContext(ctx))
}

func notFound(w http.ResponseWriter) {
	httpsec.WriteError(w, http.StatusNotFound, httpsec.CodeNotFound, "no such resource")
}

// livePerson returns the person a token stands for. A person who is gone, not active (disabled, or past the end of
// their term) or in another account than the token's makes the token worthless: ended answers for the first two
// (their access ended, nothing was guessed), refuse for the last. ok is false once an answer is written.
func (g *Guard) livePerson(w http.ResponseWriter, r *http.Request, info core.AccessInfo,
	refuse, ended func()) (core.Person, bool) {
	p, err := g.people.Get(r.Context(), info.PersonID)
	switch {
	case errors.Is(err, core.ErrNotFound):
		ended()
		return core.Person{}, false
	case err != nil:
		g.internal(w, info.ResourceID, "look up the person", err)
		return core.Person{}, false
	case p.AccountID != info.AccountID:
		refuse()
		return core.Person{}, false
	case !p.Active(g.now()):
		ended()
		return core.Person{}, false
	}
	return p, true
}

// available answers 403 unless the token's account may use its resource now.
func (g *Guard) available(w http.ResponseWriter, r *http.Request, info core.AccessInfo) bool {
	on, err := g.resources.Available(r.Context(), info.AccountID, info.ResourceID)
	switch {
	case err != nil:
		g.internal(w, info.ResourceID, "check the resource switch", err)
		return false
	case !on:
		httpsec.WriteError(w, http.StatusForbidden, httpsec.CodeForbidden,
			"the "+g.noun+" is not on for this account")
		return false
	}
	return true
}

// warnNoAddressHeader logs once, at warn level, a failure of a request without the header its ClientIP mode reads:
// the failure limit then counts it by its TCP peer, which behind a local connector (a quick tunnel that does not send
// CF-Connecting-IP) is the same for every client.
func (g *Guard) warnNoAddressHeader(r *http.Request) {
	var name string
	switch g.site.ClientIP {
	case core.ClientIPCloudflare:
		name = "CF-Connecting-IP"
	case core.ClientIPForwarded:
		name = "X-Forwarded-For"
	default:
		return
	}
	if r.Header.Get(name) != "" || !g.noAddressHeader.CompareAndSwap(false, true) {
		return
	}
	g.log.Warn("mcpguard: a refused request came without the client address header; failures are counted by the TCP peer",
		slog.String("header", name))
}

// Refuse answers a credential the application does not know with refusal, unless the client's address has presented
// FailuresPerAddress such credentials in the last minute: 429 with Retry-After then. Every door of an application
// that takes credentials calls it on a refusal (Family Hub: its legacy REST door too), so that the failures of all
// doors count together; a request without a credential is no failure. A valid credential is never limited: the
// assistants call from shared egress addresses, and junk sent from one of them must not stop every family's
// connector there.
func (g *Guard) Refuse(w http.ResponseWriter, r *http.Request, refusal func()) {
	g.warnNoAddressHeader(r)
	addr := addressKey(core.ClientIP(r, g.site.ClientIP))
	if ok, wait := g.failures.failed(addr, g.now()); !ok {
		tooMany(w, wait, "too many invalid credentials; try again later")
		return
	}
	refusal()
}

// refuseMCP answers 401 the way the MCP authorization spec wants it: the protected-resource metadata of the resource
// and the scope to ask for, plus error="invalid_token" when a token came and is no good (RFC 6750 §3).
func (g *Guard) refuseMCP(w http.ResponseWriter, id core.ResourceID, invalid bool) {
	params := fmt.Sprintf(`resource_metadata="%s", scope="%s"`, g.metadataURL(id), Scope)
	if invalid {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", `+params)
		httpsec.WriteError(w, http.StatusUnauthorized, httpsec.CodeInvalidToken,
			"the access token is invalid, expired or for another "+g.noun)
		return
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+params)
	httpsec.WriteError(w, http.StatusUnauthorized, httpsec.CodeUnauthorized, "a bearer access token is required")
}

// metadataURL is the protected-resource metadata of resource id: the issuer, the well-known prefix and the resource's
// path. The id comes from the request path, so it is escaped: nothing it holds can end the quoted header value.
func (g *Guard) metadataURL(id core.ResourceID) string {
	return g.site.PublicURL + metadataPrefix + g.paths.Path(core.ResourceID(url.PathEscape(string(id))))
}

// internal answers 500 and logs why. The errors come from the application's own services and never hold a
// credential.
func (g *Guard) internal(w http.ResponseWriter, id core.ResourceID, what string, err error) {
	g.log.Error("mcpguard: "+what, slog.String("resource", string(id)), slog.Any("err", err))
	httpsec.WriteError(w, http.StatusInternalServerError, httpsec.CodeInternal, "internal error")
}

// isRefusal tells a credential the application does not know apart from a failure to look it up. A validator that
// knows a token but finds it expired or revoked says so by wrapping core.ErrExpired (with core.ErrInvalidToken, as
// core.TokenValidator asks): the guard then does not count it against the client's address.
func isRefusal(err error) bool {
	return errors.Is(err, core.ErrInvalidToken) || errors.Is(err, core.ErrNotFound) ||
		errors.Is(err, core.ErrExpired) || errors.Is(err, core.ErrUsed)
}

// bearer returns the credential of an "Authorization: Bearer <credential>" header.
func bearer(r *http.Request) (string, bool) {
	scheme, cred, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	cred = strings.TrimSpace(cred)
	if cred == "" || strings.ContainsAny(cred, " \t") {
		return "", false
	}
	return cred, true
}

// SecureHeaders marks an answer as data that no browser should sniff, render or frame, and that no cache may keep:
// whatever an MCP server sends is served from the application's own origin, and is one family's alone. Middleware
// sets them on every answer; Relay replaces Cache-Control with "no-cache, no-store" on an event stream. An
// application calls it itself on the answers it writes in front of the middleware.
func SecureHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
	h.Set("Cache-Control", "no-store")
}
