package oauth

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// homePaths serve one resource, the home, at /mcp (as Homie will).
var homePaths = core.SingleResource{At: "/mcp", ID: "home"}

// newHomeHarness is newHarness with homePaths and the resource home, on for the Millers.
func newHomeHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarnessWith(t, func(o *Options) { o.Paths = homePaths })
	h.catalog.add(core.ResourceInfo{
		ID: "home", Name: "Home", Description: "The house",
		Tools: []core.ToolInfo{{Name: "lights", Title: "Lights", Access: "write"}},
	}, true, millers.ID)
	return h
}

// homeParams is the authorization request for the home: its resource is <public URL>/mcp.
func homeParams(tc testClient, challenge string) url.Values {
	q := authorizeParams(tc, "home", challenge)
	q.Set("resource", hubURL+"/mcp")
	return q
}

func TestSingleResourceMetadata(t *testing.T) {
	h := newHomeHarness(t)
	w := h.get("/.well-known/oauth-protected-resource/mcp", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	golden(t, "protected-resource-home.json", w.Body.Bytes())
	assert.Equal(t, hubURL+"/.well-known/oauth-protected-resource/mcp", ResourceMetadataURL(hubURL, homePaths, "home"))
	assert.Equal(t, hubURL+"/mcp", ResourceURL(hubURL, homePaths, "home"))

	for _, path := range []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/",
		"/.well-known/oauth-protected-resource/mcp/",
		"/.well-known/oauth-protected-resource/mcp/home",
		"/.well-known/oauth-protected-resource/mcp/notes",
		"/.well-known/oauth-protected-resource/mcpx",
	} {
		assert.Equal(t, http.StatusNotFound, h.get(path, "").Code, path)
	}

	h.catalog.setLive("home", false)
	assert.Equal(t, http.StatusNotFound, h.get("/.well-known/oauth-protected-resource/mcp", "").Code,
		"a resource that cannot be connected has no metadata")
}

func TestSingleResourceFlow(t *testing.T) {
	h := newHomeHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	verifier, challenge := newPKCE()
	txnID := h.startTxnWith(homeParams(tc, challenge))
	got, ok := h.srv.txns.get(txnID, h.clock.now())
	require.True(t, ok)
	assert.Equal(t, core.ResourceID("home"), got.resource)
	assert.Equal(t, hubURL+"/mcp", got.resourceURL)

	w := h.get("/api/oauth/txn/"+txnID, "alice")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var view txnView
	decode(t, w, &view)
	assert.Equal(t, resourceView{
		ID: "home", Name: "Home", Description: "The house",
		Tools: []toolView{{Name: "lights", Title: "Lights", Access: "write"}},
	}, view.Resource)

	code := h.approveTxn(txnID, "alice").Query().Get("code")
	form := exchangeForm(tc, code, verifier)
	form.Set("resource", hubURL+"/mcp")
	w = h.clientPost("/oauth/token", tc, form)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tk tokens
	decode(t, w, &tk)
	info, err := h.srv.ValidateAccess(t.Context(), tk.AccessToken, "home")
	require.NoError(t, err)
	assert.Equal(t, core.ResourceID("home"), info.ResourceID)
	assert.False(t, h.valid(tk.AccessToken, "notes"))

	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken},
		"resource": {hubURL + "/mcp/home"}}
	w = h.clientPost("/oauth/token", tc, refresh)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_target", errorOf(t, w), "the home's resource is /mcp, nothing below it")
	refresh.Set("resource", hubURL+"/mcp")
	assert.Equal(t, http.StatusOK, h.clientPost("/oauth/token", tc, refresh).Code)

	// The scope may name it instead of the resource.
	_, challenge = newPKCE()
	q := homeParams(tc, challenge)
	q.Del("resource")
	q.Set("scope", "mcp:home offline_access")
	got, ok = h.srv.txns.get(h.startTxnWith(q), h.clock.now())
	require.True(t, ok)
	assert.Equal(t, hubURL+"/mcp", got.resourceURL)
}

func TestSingleResourceRefusals(t *testing.T) {
	h := newHomeHarness(t)
	tc := h.registerDCR(claudeCallback, authNone)
	_, challenge := newPKCE()
	for _, tt := range []struct{ resource, code string }{
		{hubURL + "/mcp/", "invalid_target"},
		{hubURL + "/mcp/home", "invalid_target"},
		{hubURL + "/mcp/notes", "invalid_target"},
		{hubURL + "/mcpx", "invalid_target"},
		{hubURL, "invalid_target"},
	} {
		t.Run(tt.resource, func(t *testing.T) {
			q := homeParams(tc, challenge)
			q.Set("resource", tt.resource)
			w := h.authorize(q)
			require.Equal(t, http.StatusFound, w.Code, w.Body.String())
			assert.Equal(t, tt.code, location(t, w).Query().Get("error"))
		})
	}
}
