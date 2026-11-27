package oauth

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// registration is the part of an RFC 7591 registration request the server reads; the rest is ignored.
type registration struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientName              string   `json:"client_name"`
	SoftwareID              string   `json:"software_id"` // a native app's ID; read only for loopback callbacks
}

// registered is the answer of a registration (RFC 7591 §3.2.1).
type registered struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"` // 0 (never) whenever there is a secret
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	SoftwareID              string   `json:"software_id,omitempty"` // a native app's only
}

// register is POST /oauth/register, dynamic client registration (RFC 7591): only ChatGPT's or Claude's callbacks,
// all of one assistant, and a secret, stored hashed, only for a client that asks for client_secret_post or
// client_secret_basic. With Options.NativeApps, a native app may register too: its loopback callbacks only
// (nativeSet), its ID as software_id, and no secret; its client's assistant is "app:<ID>". On the way it deletes the
// DCR clients nobody approved within an hour. The audit gets one registration per client address group a minute
// (T2.R L8); the log gets every one.
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	now, ip := s.now(), s.ip(r)
	if !s.allowOAuth(w, s.registerLimit, ip, now) {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRegisterBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			oauthError(w, http.StatusRequestEntityTooLarge, "invalid_client_metadata", "the registration is over 64 KiB")
			return
		}
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body cannot be read")
		return
	}
	var req registration
	if err := json.Unmarshal(body, &req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "a JSON object is expected")
		return
	}
	uris, assistant, ok := callbackSet(req.RedirectURIs, s.cfg.connector)
	var app NativeApp
	native := false
	if !ok && s.apps != nil {
		uris, native = nativeSet(req.RedirectURIs)
		ok = native
	}
	if !ok {
		description := "only ChatGPT's or Claude's callbacks are accepted, 1 to 10 of one assistant"
		if s.apps != nil {
			description = "only ChatGPT's or Claude's callbacks, 1 to 10 of one assistant, or a native app's " +
				nativeCallbacks[0] + " are accepted"
		}
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", description)
		return
	}
	if native {
		if app, ok = s.apps[req.SoftwareID]; !ok {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata",
				"software_id must name a native app of this "+s.app)
			return
		}
		assistant = core.Assistant(AppAssistantPrefix + app.ID)
	}
	method := req.TokenEndpointAuthMethod
	switch {
	case method == "":
		method = authNone
	case native && method != authNone:
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata",
			"a native app is a public client: token_endpoint_auth_method must be none")
		return
	case method == authNone, method == authPost, method == authBasic:
	default:
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata",
			"token_endpoint_auth_method must be none, client_secret_post or client_secret_basic")
		return
	}
	name := displayName(req.ClientName, assistant)
	if native {
		// The name a native app's client chose is shown next to the app's, e.g. the computer's; without one, the app's.
		if name = displayName(req.ClientName, ""); name == "" {
			name = app.Name
		}
	}

	client := core.OAuthClient{
		ID: core.ClientID(core.NewID(core.PrefixClient)), Kind: core.ClientDCR, Assistant: assistant,
		Name: name, RedirectURIs: uris, AuthMethod: method, CreatedAt: now,
	}
	var secret string
	if method != authNone {
		secret = randomToken()
		client.SecretHash = hashOf(secret)
	}
	ctx := r.Context()
	if _, err := s.store.OAuth().DeleteIdleClients(ctx, now.Add(-idleClientTTL)); err != nil {
		s.log.Warn("oauth: deleting idle clients failed", slog.Any("error", err))
	}
	if err := s.store.OAuth().PutClient(ctx, client); err != nil {
		s.log.Error("oauth: storing a client failed", slog.Any("error", err))
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if s.registered.due(addressKey(ip), now) {
		s.audit(ctx, core.AuditEntry{
			At: now, Action: actionClientRegister, Target: string(client.ID), IP: ip,
			Detail: map[string]string{"kind": string(core.ClientDCR), "assistant": string(assistant), "auth_method": method},
		})
	}
	s.log.Info("oauth: client registered", slog.String("kind", string(core.ClientDCR)),
		slog.String("assistant", string(assistant)), slog.String("client", string(client.ID)))

	resp := registered{
		ClientID: string(client.ID), ClientIDIssuedAt: now.Unix(), ClientName: client.Name, RedirectURIs: uris,
		TokenEndpointAuthMethod: method, GrantTypes: []string{grantCode, grantRefresh}, ResponseTypes: []string{"code"},
		Scope: scopeMCP + " " + scopeOffline, SoftwareID: app.ID,
	}
	if secret != "" {
		var never int64
		resp.ClientSecret, resp.ClientSecretExpiresAt = secret, &never
	}
	noStore(w)
	writeJSON(w, http.StatusCreated, resp)
}
