package oauth

import (
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// golden compares a JSON document with testdata/<name>, indented; -update rewrites the file. The files of Family Hub
// came over unchanged: they prove the documents did not change.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(got, &v))
	pretty, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	pretty = append(pretty, '\n')
	if *update {
		require.NoError(t, os.WriteFile(filepath.Join("testdata", name), pretty, 0o600))
	}
	want, err := fs.ReadFile(os.DirFS("testdata"), name)
	require.NoError(t, err)
	assert.Equal(t, string(want), string(pretty))
}

func TestServerMetadata(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		t.Run(path, func(t *testing.T) {
			w := h.get(path, "")
			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
			assert.Empty(t, w.Header().Get("Cache-Control"), "the document may be cached, as before")
			golden(t, "authorization-server.json", w.Body.Bytes())
			assert.Equal(t, `{"issuer":"https://hub.example.com",`+
				`"authorization_endpoint":"https://hub.example.com/oauth/authorize",`+
				`"token_endpoint":"https://hub.example.com/oauth/token",`+
				`"registration_endpoint":"https://hub.example.com/oauth/register",`+
				`"revocation_endpoint":"https://hub.example.com/oauth/revoke",`+
				`"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],`+
				`"code_challenge_methods_supported":["S256"],`+
				`"token_endpoint_auth_methods_supported":["none","client_secret_post","client_secret_basic"],`+
				`"revocation_endpoint_auth_methods_supported":["none","client_secret_post","client_secret_basic"],`+
				`"scopes_supported":["mcp","offline_access"],"client_id_metadata_document_supported":true,`+
				`"authorization_response_iss_parameter_supported":true}`, w.Body.String(), "the bytes Family Hub sent")
		})
	}
}

func TestResourceMetadata(t *testing.T) {
	h := newHarness(t)
	w := h.get("/.well-known/oauth-protected-resource/mcp/notes", "")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	golden(t, "protected-resource-notes.json", w.Body.Bytes())
	assert.Equal(t, `{"resource":"https://hub.example.com/mcp/notes","authorization_servers":["https://hub.example.com"],`+
		`"scopes_supported":["mcp","offline_access"],"bearer_methods_supported":["header"]}`, w.Body.String(),
		"the bytes Family Hub sent")
	assert.Equal(t, hubURL+"/.well-known/oauth-protected-resource/mcp/notes",
		ResourceMetadataURL(hubURL, core.PerResource{Prefix: "/mcp/"}, "notes"),
		"the URL a 401 names is the one served")
	assert.Equal(t, hubURL+"/mcp/notes", ResourceURL(hubURL, core.PerResource{Prefix: "/mcp/"}, "notes"))
}

func TestResourceMetadataNotFound(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{
		"/.well-known/oauth-protected-resource", // the root variant
		"/.well-known/oauth-protected-resource/",
		"/.well-known/oauth-protected-resource/mcp",
		"/.well-known/oauth-protected-resource/mcp/",
		"/.well-known/oauth-protected-resource/mcp/old",    // cannot be connected
		"/.well-known/oauth-protected-resource/mcp/nobody", // unknown
		"/.well-known/oauth-protected-resource/mcp/Notes",
		"/.well-known/oauth-protected-resource/mcp/notes/",
		"/.well-known/oauth-protected-resource/mcp/notes/tools",
		"/.well-known/oauth-protected-resource/notes",
	} {
		t.Run(path, func(t *testing.T) {
			w := h.get(path, "")
			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.Equal(t, `{"error":"not_found","message":"no such module"}`, w.Body.String(),
				"the bytes Family Hub sent")
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
		})
	}
}

func TestResourceMetadataCatalogFailure(t *testing.T) {
	h := newHarness(t)
	h.catalog.setError(errors.New("catalog down"))
	w := h.get("/.well-known/oauth-protected-resource/mcp/notes", "")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "internal", errorOf(t, w))
	assert.Equal(t, http.StatusNotFound, h.get("/.well-known/oauth-protected-resource/mcp/Notes", "").Code,
		"an id no resource can have is refused before the catalog is asked")
}
