package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

// serverMetadataDoc is the authorization-server metadata (RFC 8414 §2), served at both well-knowns.
type serverMetadataDoc struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ClientIDMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported"`
	AuthorizationResponseISSParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

// resourceMetadataDoc is the protected-resource metadata of one resource (RFC 9728 §2).
type resourceMetadataDoc struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

// serverMetadataJSON renders the authorization-server metadata of issuer once, at start.
func serverMetadataJSON(issuer string) ([]byte, error) {
	methods := []string{authNone, authPost, authBasic}
	b, err := json.Marshal(serverMetadataDoc{
		Issuer:                                     issuer,
		AuthorizationEndpoint:                      issuer + "/oauth/authorize",
		TokenEndpoint:                              issuer + "/oauth/token",
		RegistrationEndpoint:                       issuer + "/oauth/register",
		RevocationEndpoint:                         issuer + "/oauth/revoke",
		ResponseTypesSupported:                     []string{"code"},
		GrantTypesSupported:                        []string{grantCode, grantRefresh},
		CodeChallengeMethodsSupported:              []string{"S256"},
		TokenEndpointAuthMethodsSupported:          methods,
		RevocationEndpointAuthMethodsSupported:     methods,
		ScopesSupported:                            []string{scopeMCP, scopeOffline},
		ClientIDMetadataDocumentSupported:          true,
		AuthorizationResponseISSParameterSupported: true,
	})
	if err != nil {
		return nil, fmt.Errorf("oauth: server metadata: %w", err)
	}
	return b, nil
}

func (s *Server) serverMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.metadata)
}

// resourceMetadata serves the protected-resource metadata of a resource that can be connected now, at the well-known
// followed by exactly the resource's MCP path (Family Hub: /.well-known/oauth-protected-resource/mcp/<id>; with
// core.SingleResource at /mcp: /.well-known/oauth-protected-resource/mcp). Every other path under the well-known, the
// root one included, is a 404.
func (s *Server) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	id, ok := s.resourceAt(strings.TrimPrefix(r.URL.Path, wellKnownResource))
	if !ok {
		apiError(w, http.StatusNotFound, httpsec.CodeNotFound, "no such "+s.noun)
		return
	}
	_, err := s.liveResource(r.Context(), id)
	switch {
	case errors.Is(err, errNoResource):
		apiError(w, http.StatusNotFound, httpsec.CodeNotFound, "no such "+s.noun)
		return
	case err != nil:
		s.log.Error("oauth: protected-resource metadata failed", slog.String("resource", string(id)),
			slog.Any("error", err))
		apiError(w, http.StatusInternalServerError, httpsec.CodeInternal, "the "+s.noun+" registry failed")
		return
	}
	writeJSON(w, http.StatusOK, resourceMetadataDoc{
		Resource:               s.resourceURL(id),
		AuthorizationServers:   []string{s.issuer},
		ScopesSupported:        []string{scopeMCP, scopeOffline},
		BearerMethodsSupported: []string{"header"},
	})
}

// liveResource returns resource id as the catalog describes it when it can be connected now; errNoResource
// otherwise (Family Hub: a module that is not deployed or not running).
func (s *Server) liveResource(ctx context.Context, id core.ResourceID) (core.ResourceInfo, error) {
	info, err := s.catalog.Resource(ctx, id)
	switch {
	case errors.Is(err, core.ErrNotFound):
		return core.ResourceInfo{}, errNoResource
	case err != nil:
		return core.ResourceInfo{}, fmt.Errorf("oauth: resource %s: %w", id, err)
	}
	return info, nil
}
