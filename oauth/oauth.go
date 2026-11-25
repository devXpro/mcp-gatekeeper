// Package oauth is the gatekeeper's OAuth 2.1 authorization server for MCP connectors (docs/security/G4.md): the
// metadata documents, dynamic client registration and client ID metadata documents, authorize with its in-memory
// transactions, the consent API the admin SPA calls, token, revoke, and core.TokenValidator for the MCP access check.
//
// One issuer at the application's root serves every resource, and a token is bound to one resource. The authorize
// request names the resource with the RFC 8707 resource <public URL><Paths.Path(id)> (Family Hub, with
// core.PerResource: <public URL>/mcp/<id>; with core.SingleResource: <public URL>/mcp), or, without one, with the
// scope mcp:<id>; the consent makes a grant of (person, client, resource); the validator refuses the token for any
// other resource.
//
// The rules: only ChatGPT's and Claude's callbacks are accepted and they tell the assistant, PKCE S256 is required,
// every secret, code and token is kept only as its sha256, and a refresh token is spent on use, so one that comes
// back revokes its whole family.
//
// A person acts only while core.Person.Active: the consent API, the code exchange and the refresh refuse anyone
// disabled or past the end of their term (Person.AccessUntil), and an access token never outlives that end. The
// grant itself stays, so a term the owner extends gives the person their connections back.
//
// The package came from Family Hub's internal/oauth. What it sends to the assistants and the SPA is byte-for-byte
// what Family Hub sent, its wording included, except the one rename of the consent view (docs/security/G4.md,
// "Compatibility"). The texts name a resource and the application by Brand.ResourceWord and Brand.AppWord, whose
// defaults are Family Hub's "module" and "hub".
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// Lifetimes (docs/security/G4.md, with the decisions of Family Hub's security review T2.R).
const (
	txnTTL         = 10 * time.Minute     // an authorize transaction waits this long for the consent
	codeTTL        = 5 * time.Minute      // an authorization code
	accessTTL      = time.Hour            // an access token
	refreshTTL     = 30 * 24 * time.Hour  // a refresh token; each rotation issues a new one
	grantTTL       = 180 * 24 * time.Hour // a grant, from its consent; refreshing never extends it (T2.R L7)
	idleClientTTL  = time.Hour            // a DCR client without a grant is deleted after this (T2.R H2)
	cimdCacheTTL   = 24 * time.Hour       // a fetched client ID metadata document is reused this long
	cimdFailureTTL = 5 * time.Minute      // a document that failed to fetch or was refused is not fetched again
	cimdTimeout    = 5 * time.Second
	// tokenDeadline bounds the store work of a token or revoke request and detachedTimeout the writes it decided on
	// (a revocation, an audit entry), so the answer never takes over 10 s.
	tokenDeadline   = 7 * time.Second
	detachedTimeout = 2 * time.Second
	// touchPeriod is how often a grant's last use is written at most.
	touchPeriod = time.Minute
)

// Bounds of what a request and the memory may hold.
const (
	cimdMaxBytes     = 64 << 10 // a client ID metadata document
	maxRegisterBody  = 64 << 10 // a DCR request
	maxFormBody      = 16 << 10 // a token or revoke request
	maxTxns          = 1000     // live authorize transactions
	maxTxnsPerGroup  = 20       // live transactions of one client address group (T2.R M1)
	maxTxnsPerClient = 100      // live transactions of one DCR client; a CIMD client id is shared, so it has none
	maxStateLen      = 1024     // the client's state, sent back to it
	maxScopeLen      = 1024
	maxURLLen        = 2048 // a redirect URI or a client_id URL
	maxRedirectURIs  = 10
	maxNameRunes     = 64   // a client's display name
	maxKeys          = 4096 // rate-limit buckets, throttled keys and remembered fetch failures kept in memory
	maxAddrLen       = 64   // a client address as the audit keeps it
)

// Rate limits in requests a minute per client address group: an IPv4 address or an IPv6 /64 (addressKey). Only
// registration also has a bucket for every address together, which bounds how fast the client store grows. Token
// and revoke have none (T2.R H2): three addresses could spend it and stop every family's refreshes, and codes and
// tokens are 256-bit, so there is no guessing to slow down. Authorize has the per-address limit only, and client
// metadata fetches a smaller one of their own.
const (
	limitPerAddress = 20
	limitTotal      = 60 // registrations from every address together
	limitFetches    = 5  // client ID metadata documents fetched for one address group
)

// Wire names.
const (
	scopeMCP            = "mcp"
	scopeOffline        = "offline_access"
	scopeResourcePrefix = "mcp:" // "mcp:<id>" names the resource of a request without a resource parameter

	grantCode    = "authorization_code"
	grantRefresh = "refresh_token"

	authNone  = "none"
	authPost  = "client_secret_post"
	authBasic = "client_secret_basic"

	prefixFamily = "fam" // the core.NewID prefix of a refresh rotation family

	// wellKnownResource is where the protected-resource metadata lives: a resource's MCP path follows it (RFC 9728
	// §3.1).
	wellKnownResource = "/.well-known/oauth-protected-resource"
	// consentPath is the SPA's consent screen, where authorize sends the browser.
	consentPath = "/consent"

	// Where the browser came from to authorize, as the consent screen shows it (T2.R H1).
	startedAssistant = "assistant"
	startedElsewhere = "elsewhere"
	startedUnknown   = "unknown"
)

// Audit actions and the detail key of a grant's resource. The key is Family Hub's "module": audit entries keep
// their keys (docs/PLAN.md §4.2.6).
const (
	actionClientRegister = "oauth.client.register"
	actionGrantCreate    = "oauth.grant.create"
	actionGrantRevoke    = "oauth.grant.revoke"
	actionRefreshReuse   = "oauth.refresh.reuse"

	detailResource = "module"
)

var (
	// resourceIDPattern is a resource id as a URL or a scope may name it (Family Hub's module ids; "home"). Anything
	// else is refused before the catalog is asked.
	resourceIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	clientIDPattern   = regexp.MustCompile(`^cli_[a-z2-7]{16}$`)        // core.NewID(core.PrefixClient)
	opaquePattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)       // randomToken: codes, tokens, secrets
	challengePattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)       // BASE64URL(SHA256(verifier)), RFC 7636 §4.2
	verifierPattern   = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`) // RFC 7636 §4.1
)

var (
	errUnknownClient   = errors.New("oauth: unknown client")
	errMetadataFetch   = errors.New("oauth: the client metadata document cannot be fetched")
	errMetadataInvalid = errors.New("oauth: the client metadata document is not acceptable")
	errNoResource      = errors.New("oauth: no such resource can be connected")
	errGrant           = errors.New("oauth: invalid grant")
	errTarget          = errors.New("oauth: invalid target")
	errReused          = errors.New("oauth: a spent refresh token came back")
	errGrantExpired    = errors.New("oauth: the grant outlived its lifetime")
	errStepUp          = errors.New("oauth: approving a new grant needs a fresh step-up")
)

// Options are the dependencies and switches of New.
type Options struct {
	// Site.PublicURL is the issuer: https://<host> without a path (http only on a loopback host). Site.ClientIP says
	// where the client address of the rate limits and the audit comes from. New refuses a Site that fails
	// Site.Validate, an empty or unknown ClientIP mode included.
	Site core.Site
	// Brand.TxnCookie names the cookie that binds a consent to the browser that started it; Brand.Product titles the
	// error pages and gives the realm of a Basic challenge ("Family Hub": realm="family-hub"); Brand.ResourceWord and
	// Brand.AppWord are the words of the error texts ("module" and "hub" by default).
	Brand core.Brand
	Store store.Store
	// Sessions resolves the signed-in person of the consent API (package auth).
	Sessions core.Sessions
	// Catalog says which resources can be connected and by which accounts. A resource id must match
	// ^[a-z][a-z0-9-]{1,30}$ (Family Hub's module ids; Homie's "home").
	Catalog core.ResourceCatalog
	// Paths maps resources to their MCP paths (Family Hub: core.PerResource{Prefix: "/mcp/"}); a resource's URL is
	// Site.PublicURL + Paths.Path(id).
	Paths  core.ResourcePaths
	Logger *slog.Logger // nil: discard
	Clock  core.Clock   // nil: the system clock in UTC

	// The switches of Family Hub's security review (T2.R). The zero value of each is Family Hub's default.

	// ConsentStepUpOff makes approving a new grant one click. By default it needs a fresh step-up (a sign-in counts
	// for 5 minutes); reconnecting an existing grant is one click either way. Family Hub: FH_CONSENT_STEPUP=off.
	ConsentStepUpOff bool
	// TxnBindingOff stops binding an authorize transaction to the browser that started it. Only for an assistant
	// window that loses the cookie. Family Hub: FH_OAUTH_TXN_BINDING=off.
	TxnBindingOff bool
	// RefuseConnectorCallback refuses ChatGPT's per-connector callback /connector/oauth/<id>, which closes the
	// mix-up of T2.R H1. Family Hub: FH_OAUTH_CONNECTOR_CALLBACK=refuse.
	RefuseConnectorCallback bool
}

// settings are the switches of Options, said the way the code asks them.
type settings struct {
	stepUp    bool // approving a new grant needs a fresh step-up
	binding   bool // transactions are bound to the browser that started them
	connector bool // ChatGPT's /connector/oauth/<id> callbacks are accepted
}

// Server is the authorization server. It serves the OAuth routes and the consent API (core.RouteRegistrar) and
// implements core.TokenValidator for the MCP access check.
type Server struct {
	issuer    string
	ipMode    core.ClientIPMode
	txnCookie string // the binding cookie (T2.R H1)
	product   string // the title of the error pages
	realm     string // the realm of a Basic challenge
	noun, app string // Brand.ResourceWord and Brand.AppWord: what the texts call a resource and the application
	store     store.Store
	sessions  core.Sessions
	catalog   core.ResourceCatalog
	paths     core.ResourcePaths
	log       *slog.Logger
	now       core.Clock
	fetcher   fetcher
	metadata  []byte   // the authorization-server metadata document
	cfg       settings // the switches of Options
	badDoc    pageText // pageMetadataInvalid in the application's words

	txns       *txnStore
	spent      *spentCodes
	touched    *throttle      // grants whose last use was written
	registered *throttle      // address groups whose registration was audited (T2.R L8)
	failures   *fetchFailures // client metadata documents that failed (T2.R M1)

	registerLimit, tokenLimit, revokeLimit, authorizeLimit, fetchLimit *limiter
}

var (
	_ core.TokenValidator = (*Server)(nil)
	_ core.RouteRegistrar = (*Server)(nil)
)

// New returns the authorization server of o.Site; its issuer is the public URL. It fetches client ID metadata
// documents over HTTPS from the assistants' hosts only.
func New(o Options) (*Server, error) {
	return newServer(o, newHTTPFetcher(cimdTimeout, cimdMaxBytes))
}

// newServer is New with the client metadata fetcher given, for tests.
func newServer(o Options, f fetcher) (*Server, error) {
	issuer, err := checkIssuer(o.Site.PublicURL)
	if err != nil {
		return nil, err
	}
	if err := o.Site.Validate(); err != nil {
		return nil, fmt.Errorf("oauth: %w", err)
	}
	if err := o.check(); err != nil {
		return nil, err
	}
	metadata, err := serverMetadataJSON(issuer)
	if err != nil {
		return nil, err
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := o.Clock
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	cfg := settings{stepUp: !o.ConsentStepUpOff, binding: !o.TxnBindingOff, connector: !o.RefuseConnectorCallback}
	return &Server{
		issuer:         issuer,
		ipMode:         o.Site.ClientIP,
		txnCookie:      o.Brand.TxnCookie,
		product:        o.Brand.Product,
		realm:          basicRealm(o.Brand.Product),
		noun:           o.Brand.ResourceWord(),
		app:            o.Brand.AppWord(),
		store:          o.Store,
		sessions:       o.Sessions,
		catalog:        o.Catalog,
		paths:          o.Paths,
		log:            log,
		now:            now,
		fetcher:        f,
		metadata:       metadata,
		cfg:            cfg,
		badDoc:         metadataInvalidText(o.Brand),
		txns:           newTxnStore(maxTxns, maxTxnsPerGroup, maxTxnsPerClient),
		spent:          newSpentCodes(),
		touched:        newThrottle(touchPeriod),
		registered:     newThrottle(time.Minute),
		failures:       newFetchFailures(),
		registerLimit:  newLimiter(limitPerAddress, limitTotal),
		tokenLimit:     newLimiter(limitPerAddress, 0),
		revokeLimit:    newLimiter(limitPerAddress, 0),
		authorizeLimit: newLimiter(limitPerAddress, 0),
		fetchLimit:     newLimiter(limitFetches, 0),
	}, nil
}

// check refuses Options the server cannot run with.
func (o Options) check() error {
	switch {
	case o.Store == nil:
		return errors.New("oauth: Options.Store is required")
	case o.Sessions == nil:
		return errors.New("oauth: Options.Sessions is required")
	case o.Catalog == nil:
		return errors.New("oauth: Options.Catalog is required")
	case o.Paths == nil:
		return errors.New("oauth: Options.Paths is required")
	case strings.TrimSpace(o.Brand.Product) == "":
		return errors.New("oauth: Options.Brand.Product is required")
	case !o.TxnBindingOff && !hostCookieName(o.Brand.TxnCookie):
		return fmt.Errorf("oauth: Options.Brand.TxnCookie %q is not a cookie name starting with __Host-",
			o.Brand.TxnCookie)
	}
	if one, ok := o.Paths.(core.SingleResource); ok && !resourceIDPattern.MatchString(string(one.ID)) {
		return fmt.Errorf("oauth: the resource id %q does not match %s", one.ID, resourceIDPattern)
	}
	return nil
}

// hostCookieName reports whether name can name a __Host- cookie.
func hostCookieName(name string) bool {
	c := http.Cookie{Name: name, Value: "v", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	return strings.HasPrefix(name, "__Host-") && c.Valid() == nil
}

// basicRealm is the realm of a Basic challenge: the product's name as a token of lower-case letters, digits and
// dashes ("Family Hub" is "family-hub", the realm Family Hub always sent).
func basicRealm(product string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(product)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "oauth"
	}
	return b.String()
}

// checkIssuer returns the public URL as the issuer (RFC 8414 §2): https, or http on a loopback host for development,
// with no path, query or fragment.
func checkIssuer(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err == nil && u.Host != "" && raw == u.Scheme+"://"+u.Host &&
		(u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return raw, nil
	}
	return "", fmt.Errorf("oauth: the public URL %q is not an issuer: https://<host> without a path", raw)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RegisterRoutes adds the OAuth routes to mux: the metadata, register, authorize, token and revoke for the
// assistants, and the consent API for the SPA.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.serverMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.serverMetadata)
	mux.HandleFunc("GET "+wellKnownResource, s.resourceMetadata)
	mux.HandleFunc("GET "+wellKnownResource+"/", s.resourceMetadata)
	mux.HandleFunc("POST /oauth/register", s.register)
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/revoke", s.revoke)

	// RequireViewer (package auth) also runs the CSRF checks of the two writes (docs/PLAN.md §4.4): 403 forbidden
	// before 401.
	viewer := s.sessions.RequireViewer
	mux.Handle("GET /api/oauth/txn/{txn}", viewer(http.HandlerFunc(s.txnInfo)))
	mux.Handle("POST /api/oauth/txn/{txn}/approve", viewer(http.HandlerFunc(s.approve)))
	mux.Handle("POST /api/oauth/txn/{txn}/deny", viewer(http.HandlerFunc(s.deny)))
}

// ResourceURL is the RFC 8707 resource of id: its MCP URL, the public URL followed by paths.Path(id) (Family Hub:
// <public URL>/mcp/<id>).
func ResourceURL(publicURL string, paths core.ResourcePaths, id core.ResourceID) string {
	return publicURL + paths.Path(id)
}

// ResourceMetadataURL is where the protected-resource metadata of id is served: the well-known between the public URL
// and the resource's MCP path (RFC 9728 §3.1; Family Hub: <public URL>/.well-known/oauth-protected-resource/mcp/<id>).
// The MCP access check names it in the WWW-Authenticate of a 401.
func ResourceMetadataURL(publicURL string, paths core.ResourcePaths, id core.ResourceID) string {
	return publicURL + wellKnownResource + paths.Path(id)
}

// resourceURL is the RFC 8707 resource of id on this server.
func (s *Server) resourceURL(id core.ResourceID) string {
	return ResourceURL(s.issuer, s.paths, id)
}

// resourceOf returns the resource whose RFC 8707 resource raw is: exactly the issuer and the resource's MCP path.
func (s *Server) resourceOf(raw string) (core.ResourceID, bool) {
	path, ok := strings.CutPrefix(raw, s.issuer)
	if !ok {
		return "", false
	}
	return s.resourceAt(path)
}

// resourceAt returns the resource whose MCP path is exactly path, with an id of resourceIDPattern. A path below a
// resource's, or with a trailing slash, names none.
func (s *Server) resourceAt(path string) (core.ResourceID, bool) {
	id, ok := s.paths.FromPath(path)
	if !ok || s.paths.Path(id) != path || !resourceIDPattern.MatchString(string(id)) {
		return "", false
	}
	return id, true
}

// randomToken returns 32 random bytes in base64url without padding: a client secret, a code or a token.
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error since Go 1.24
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashOf is how a secret, code or token is stored and looked up: its sha256.
func hashOf(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// ip is the client address of a request, for the audit; addressKey groups it for the rate limits.
func (s *Server) ip(r *http.Request) string {
	return clip(core.ClientIP(r, s.ipMode), maxAddrLen)
}

// clip cuts s to at most n bytes: a value from the request that goes into the audit or a log line.
func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// audit appends an audit entry, even when the client has gone. A failure only logs: what it records has happened.
func (s *Server) audit(ctx context.Context, e core.AuditEntry) {
	ctx, cancel := detached(ctx)
	defer cancel()
	if err := s.store.Audit().Append(ctx, e); err != nil {
		s.log.Error("oauth: audit failed", slog.String("action", e.Action), slog.Any("error", err))
	}
}

// detached is ctx without its cancellation, with a short deadline of its own: for the writes a request has decided
// on (a revocation, an audit entry), which must not be lost when the client hangs up or the request runs late. It is
// never given the context of a store transaction.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
}

// allowOAuth takes a request of the client's address group from l, or answers 429 in the OAuth error format.
func (s *Server) allowOAuth(w http.ResponseWriter, l *limiter, ip string, now time.Time) bool {
	ok, wait := l.take(addressKey(ip), now)
	if !ok {
		retryAfter(w, wait)
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many requests; try again later")
	}
	return ok
}

func retryAfter(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
}

// oauthErrorBody is an OAuth error answer (RFC 6749 §5.2, RFC 7591 §3.2.2).
type oauthErrorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// oauthError answers an OAuth endpoint in its RFC format.
func oauthError(w http.ResponseWriter, status int, code, description string) {
	noStore(w)
	writeJSON(w, status, oauthErrorBody{Error: code, Description: description})
}

// apiError answers the consent API and the metadata routes in the error form of httpsec.
func apiError(w http.ResponseWriter, status int, code, message string) {
	noStore(w)
	writeJSON(w, status, httpsec.ErrorBody{Error: code, Message: message})
}

// writeJSON answers with v the way Family Hub's Gin did, so the bytes stay the same: Content-Type
// application/json; charset=utf-8 and json.Marshal's output (HTML characters escaped, no trailing newline).
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil { // every value written here marshals; an empty 500 answers a bug
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func noStore(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}
