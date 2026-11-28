package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// authError is an authorization error that goes back to the client's redirect URI (RFC 6749 §4.1.2.1).
type authError struct{ code, description string }

func (e *authError) Error() string { return e.code + ": " + e.description }

func authErr(code, description string) error { return &authError{code: code, description: description} }

// authorize is GET /oauth/authorize. It checks the request and keeps it as a transaction for the consent screen,
// then sends the browser to /consent?txn=<id>. Until the client and its redirect URI are known to be valid, errors
// are pages; after that they go back to the redirect URI.
//
// The transaction is bound to this browser by the binding cookie (T2.R H1): the consent API answers only the browser
// that holds it, so a /consent link sent to somebody else is refused there. The transaction also notes where the
// browser came from, for the consent screen's warning.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	now, ip := s.now(), s.ip(r)
	group := addressKey(ip)
	if ok, wait := s.authorizeLimit.take(group, now); !ok {
		retryAfter(w, wait)
		s.page(w, http.StatusTooManyRequests, pageRateLimited)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		s.page(w, http.StatusBadRequest, pageBadRequest)
		return
	}
	clientID, okClient := single(q, "client_id")
	redirectURI, okRedirect := single(q, "redirect_uri")
	if !okClient || !okRedirect || clientID == "" || redirectURI == "" {
		s.page(w, http.StatusBadRequest, pageBadRequest)
		return
	}
	ctx := r.Context()
	client, err := s.resolveClient(ctx, clientID, ip)
	if err != nil {
		s.clientPage(w, err)
		return
	}
	if !s.redirectAllowed(client, redirectURI) {
		s.page(w, http.StatusBadRequest, pageBadRedirect)
		return
	}

	// The redirect URI is the client's own: from here on, errors go back to it.
	state, ok := single(q, "state")
	if !ok || len(state) > maxStateLen {
		s.authFail(w, redirectURI, "", authErr("invalid_request", "state is repeated or over 1024 bytes"))
		return
	}
	t, err := s.checkRequest(ctx, q)
	if err != nil {
		s.authFail(w, redirectURI, state, err)
		return
	}
	t.clientID, t.clientKind, t.assistant, t.clientName = client.ID, client.Kind, client.Assistant, client.Name
	t.redirectURI, t.state, t.expiresAt = redirectURI, state, now.Add(txnTTL)
	t.startedFrom, t.group = startedFrom(r, client.Assistant), group
	var binding string
	if s.cfg.binding {
		binding = s.browserBinding(r)
		t.binding = hashOf(binding)
	}
	id := s.txns.add(t, now)
	if s.cfg.binding {
		s.setBindingCookie(w, binding)
	}
	noStore(w)
	w.Header().Set("Location", consentPath+"?txn="+id)
	w.WriteHeader(http.StatusFound)
}

// redirectAllowed reports whether redirectURI may receive the answer of an authorization request of client. An
// assistant's client must name one of its callbacks exactly, and the callback rules are applied again, so a client
// stored before RefuseConnectorCallback was set cannot use a per-connector callback either. A native app's client,
// while its app is declared, names one of its loopback callbacks with any port (RFC 8252 §7.3), or one of the app's
// Ports when it has them: scheme, host and path exact.
func (s *Server) redirectAllowed(client core.OAuthClient, redirectURI string) bool {
	if _, native := NativeAppID(client.Assistant); native {
		registered, ok := loopbackCallback(redirectURI)
		app, declared := s.nativeApp(client.Assistant)
		return ok && declared && slices.Contains(client.RedirectURIs, registered) &&
			(len(app.Ports) == 0 || slices.Contains(app.Ports, loopbackPort(redirectURI)))
	}
	return slices.Contains(client.RedirectURIs, redirectURI) && callbackAssistant(redirectURI, s.cfg.connector) != ""
}

// browserBinding is the value of the browser's binding cookie: the one it sent, or a new one. One value per browser
// lets two connectors started in it wait for consent side by side.
func (s *Server) browserBinding(r *http.Request) string {
	if ck, err := r.Cookie(s.txnCookie); err == nil && opaquePattern.MatchString(ck.Value) {
		return ck.Value
	}
	return randomToken()
}

// setBindingCookie sends the binding cookie for as long as the newest transaction of the browser lives. It is
// SameSite=Lax, not Strict like the session cookie: the navigation from the assistant to authorize is cross-site, and
// only a Lax cookie comes along on it, which is what keeps one value per browser. The cookie authenticates nothing on
// its own; it is compared only by the consent API, whose calls also need the Strict session cookie and the CSRF
// checks.
func (s *Server) setBindingCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.txnCookie, Value: value, Path: "/", MaxAge: int(txnTTL / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// startedFrom says where the browser came from to authorize (T2.R H1): startedAssistant when the Referer is a host of
// the client's assistant, startedElsewhere when it is another site or the address was opened directly
// (Sec-Fetch-Site: none, e.g. a link from a messenger), and startedUnknown without either. The live test of the
// assistants' windows calibrates it.
//
// A native app's request is startedApp only when the browser says it was not navigated from any page: no Referer and
// Sec-Fetch-Site: none, which is what a system browser the app opens sends (review SR M1). A link on a web page, a
// redirect from another site or the server's own pages (cross-site, same-site, same-origin), and a request without the
// header are startedElsewhere, so the consent screen warns.
func startedFrom(r *http.Request, a core.Assistant) string {
	if _, native := NativeAppID(a); native {
		if site := r.Header.Values("Sec-Fetch-Site"); r.Referer() == "" && len(site) == 1 && site[0] == "none" {
			return startedApp
		}
		return startedElsewhere
	}
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Scheme == "https" && callbackHosts[u.Hostname()] == a {
			return startedAssistant
		}
		return startedElsewhere
	}
	if r.Header.Get("Sec-Fetch-Site") == "none" {
		return startedElsewhere
	}
	return startedUnknown
}

// checkRequest checks what an authorization request asks for once its client and redirect URI are valid:
// response_type, PKCE, scope and the resource. It returns the transaction without the client's part.
func (s *Server) checkRequest(ctx context.Context, q url.Values) (txn, error) {
	for _, key := range []string{"response_type", "code_challenge", "code_challenge_method", "scope"} {
		if len(q[key]) > 1 {
			return txn{}, authErr("invalid_request", key+" is repeated")
		}
	}
	switch q.Get("response_type") {
	case "code":
	case "":
		return txn{}, authErr("invalid_request", "response_type is required")
	default:
		return txn{}, authErr("unsupported_response_type", "response_type must be code")
	}
	challenge := q.Get("code_challenge")
	if q.Get("code_challenge_method") != "S256" || !challengePattern.MatchString(challenge) {
		return txn{}, authErr("invalid_request", "PKCE is required: code_challenge with code_challenge_method=S256")
	}
	raw := q.Get("scope")
	if len(raw) > maxScopeLen {
		return txn{}, authErr("invalid_scope", "scope is over 1024 bytes")
	}
	scope := parseScope(raw)
	id, err := s.target(ctx, nonEmpty(q["resource"]), scope)
	if err != nil {
		return txn{}, err
	}
	return txn{challenge: challenge, scope: scope.granted(), resource: id, resourceURL: s.resourceURL(id)}, nil
}

// target is the resource an authorization request is for: the one its resource parameter names, which must be
// exactly the resource URL of a resource that can be connected, or, without one, the one a scope mcp:<id> names. A
// present resource decides, and a scope naming another resource next to it is refused.
//
// The id of a scope goes through Paths both ways, as the resource of a resource parameter does (review GK-7): with
// core.SingleResource every id has the one path, and only the resource's own id comes back from it, so the scope
// mcp:<another id> cannot get a grant whose resource URL is the single resource's.
func (s *Server) target(ctx context.Context, resources []string, scope requestedScope) (core.ResourceID, error) {
	switch {
	case len(resources) > 1:
		return "", authErr("invalid_target", "one resource is expected")
	case len(resources) == 1:
		id, ok := s.resourceOf(resources[0])
		if !ok {
			return "", authErr("invalid_target", "the resource is not a "+s.noun+" of this "+s.app)
		}
		for _, named := range scope.resources {
			if named != string(id) {
				return "", authErr("invalid_scope", "the scope names another "+s.noun+" than the resource")
			}
		}
		return s.connectable(ctx, id, "invalid_target")
	case len(scope.resources) == 0:
		return "", authErr("invalid_target", "resource is required")
	case len(scope.resources) > 1:
		return "", authErr("invalid_scope", "the scope names more than one "+s.noun)
	}
	named := scope.resources[0]
	id, ok := s.resourceAt(s.paths.Path(core.ResourceID(named)))
	if !ok || string(id) != named {
		return "", authErr("invalid_scope", "the scope names no "+s.noun+" of this "+s.app)
	}
	return s.connectable(ctx, id, "invalid_scope")
}

// connectable returns resource id when it can be connected now; otherwise the error code, which says how the request
// named it.
func (s *Server) connectable(ctx context.Context, id core.ResourceID, code string) (core.ResourceID, error) {
	_, err := s.liveResource(ctx, id)
	switch {
	case errors.Is(err, errNoResource):
		return "", authErr(code, "no such "+s.noun+" is running")
	case err != nil:
		return "", err
	}
	return id, nil
}

// requestedScope is what the scope of an authorization request asks for: offline_access, and the resources of its
// mcp:<id> entries. Other scopes are ignored, which RFC 6749 §3.3 allows.
type requestedScope struct {
	offline   bool
	resources []string
}

func parseScope(raw string) requestedScope {
	var r requestedScope
	for _, s := range strings.Fields(raw) {
		if s == scopeOffline {
			r.offline = true
			continue
		}
		if id, ok := strings.CutPrefix(s, scopeResourcePrefix); ok && !slices.Contains(r.resources, id) {
			r.resources = append(r.resources, id)
		}
	}
	return r
}

// granted is the scope a grant gets: mcp, with offline_access when asked for. Refresh tokens come either way.
func (r requestedScope) granted() string {
	if r.offline {
		return scopeMCP + " " + scopeOffline
	}
	return scopeMCP
}

// resolveClient finds the client of an authorization request: a CIMD client by its URL, fetched when needed, or a
// DCR client by its id.
func (s *Server) resolveClient(ctx context.Context, id, ip string) (core.OAuthClient, error) {
	if strings.HasPrefix(id, "https://") {
		return s.metadataClient(ctx, id, ip)
	}
	return s.lookupClient(ctx, id)
}

// lookupClient returns a stored client: a DCR client by its id, or a CIMD client by its URL once authorize has
// fetched it. Anything else is errUnknownClient.
func (s *Server) lookupClient(ctx context.Context, id string) (core.OAuthClient, error) {
	if !clientIDPattern.MatchString(id) && metadataAssistant(id) == "" {
		return core.OAuthClient{}, errUnknownClient
	}
	client, err := s.store.OAuth().GetClient(ctx, core.ClientID(id))
	switch {
	case errors.Is(err, core.ErrNotFound):
		return core.OAuthClient{}, errUnknownClient
	case err != nil:
		return core.OAuthClient{}, fmt.Errorf("oauth: client %s: %w", id, err)
	}
	return client, nil
}

// clientPage shows why the client of an authorization request cannot be used.
func (s *Server) clientPage(w http.ResponseWriter, err error) {
	var limited *limitedError
	switch {
	case errors.As(err, &limited):
		retryAfter(w, limited.wait)
		s.page(w, http.StatusTooManyRequests, pageRateLimited)
	case errors.Is(err, errUnknownClient):
		s.page(w, http.StatusBadRequest, pageUnknownClient)
	case errors.Is(err, errMetadataFetch):
		s.page(w, http.StatusBadGateway, pageMetadataFetch)
	case errors.Is(err, errMetadataInvalid):
		s.page(w, http.StatusBadRequest, s.badDoc)
	default:
		s.log.Error("oauth: authorize failed", slog.Any("error", err))
		s.page(w, http.StatusInternalServerError, pageServerError)
	}
}

// authFail sends err back to the client's redirect URI (RFC 6749 §4.1.2.1) with state and iss. An error that is not
// an authError is the server's own: it is logged and sent as server_error.
func (s *Server) authFail(w http.ResponseWriter, redirectURI, state string, err error) {
	var ae *authError
	if !errors.As(err, &ae) {
		s.log.Error("oauth: authorize failed", slog.Any("error", err))
		ae = &authError{code: "server_error", description: "the " + s.app + " failed; try again"}
	}
	noStore(w)
	w.Header().Set("Location", s.responseURL(redirectURI, state, url.Values{
		"error": {ae.code}, "error_description": {ae.description},
	}))
	w.WriteHeader(http.StatusFound)
}

// responseURL is an authorization response (RFC 6749 §4.1.2): the client's redirect URI, which has no query by the
// callback rules, with params, the request's state when it had one, and iss (RFC 9207).
func (s *Server) responseURL(redirectURI, state string, params url.Values) string {
	if state != "" {
		params.Set("state", state)
	}
	params.Set("iss", s.issuer)
	return redirectURI + "?" + params.Encode()
}

// single returns the value of key in q, "" when it is absent; ok is false when the key is repeated (RFC 6749 §3.1).
func single(q url.Values, key string) (string, bool) {
	switch v := q[key]; len(v) {
	case 0:
		return "", true
	case 1:
		return v[0], true
	default:
		return "", false
	}
}

// nonEmpty drops the empty values: a parameter without a value counts as absent (RFC 6749 §3.1).
func nonEmpty(vs []string) []string {
	return slices.DeleteFunc(slices.Clone(vs), func(v string) bool { return v == "" })
}
