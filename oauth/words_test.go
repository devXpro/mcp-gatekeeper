package oauth

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// TestBrandWords is review GK-18: every text that names a resource or the application takes the brand's words, here
// an application's own ("home" and "Homie"). The default words are Family Hub's "module" and "hub", whose bytes the
// other tests pin.
func TestBrandWords(t *testing.T) {
	h := newHarnessWith(t, func(o *Options) {
		o.Paths = homePaths
		o.Brand.Product, o.Brand.ResourceNoun, o.Brand.AppNoun = "Homie", "home", "Homie"
	})
	h.catalog.add(core.ResourceInfo{ID: "home", Name: "Home"}, true, millers.ID)
	tc := h.registerDCR(claudeCallback, authNone)
	_, challenge := newPKCE()

	// described is the error_description of an authorization request edited by edit.
	described := func(edit func(q url.Values)) string {
		q := homeParams(tc, challenge)
		edit(q)
		w := h.authorize(q)
		require.Equal(t, http.StatusFound, w.Code, w.Body.String())
		return location(t, w).Query().Get("error_description")
	}
	scopeOnly := func(scope string) func(url.Values) {
		return func(q url.Values) { q.Del("resource"); q.Set("scope", scope) }
	}
	// message is the message of an answer in the error form of httpsec, which must have status.
	message := func(w *httptest.ResponseRecorder, status int) string {
		require.Equal(t, status, w.Code, w.Body.String())
		var body struct{ Message string }
		decode(t, w, &body)
		return body.Message
	}
	failing := errors.New("down")
	txnID := h.startTxnWith(homeParams(tc, challenge))

	for _, tt := range []struct {
		name string
		got  func() string
		want string
	}{
		{"authorize: a resource of no home", func() string {
			return described(func(q url.Values) { q.Set("resource", hubURL+"/mcpx") })
		}, "the resource is not a home of this Homie"},
		{"authorize: a scope naming another one next to the resource", func() string {
			return described(func(q url.Values) { q.Set("scope", "mcp:notes") })
		}, "the scope names another home than the resource"},
		{"authorize: a scope naming two", func() string { return described(scopeOnly("mcp:home mcp:notes")) },
			"the scope names more than one home"},
		{"authorize: a scope naming none", func() string { return described(scopeOnly("mcp:notes")) },
			"the scope names no home of this Homie"},
		{"authorize: a home that cannot be connected", func() string {
			h.catalog.setLive("home", false)
			defer h.catalog.setLive("home", true)
			return described(func(url.Values) {})
		}, "no such home is running"},
		{"authorize: a failure", func() string {
			h.catalog.setError(failing)
			defer h.catalog.setError(nil)
			return described(func(url.Values) {})
		}, "the Homie failed; try again"},
		{"consent view: the store", func() string {
			h.store.failWith("FindGrant", failing, true)
			return message(h.get("/api/oauth/txn/"+txnID, "alice"), http.StatusInternalServerError)
		}, "the Homie's store failed"},
		{"approve: the store", func() string {
			h.store.failWith("GetClient", failing, true)
			return message(h.consentPost("/api/oauth/txn/"+txnID+"/approve", "alice"), http.StatusInternalServerError)
		}, "the Homie's store failed"},
		{"approve: storing the consent", func() string {
			other := h.startTxnWith(homeParams(tc, challenge))
			h.store.failWith("PutCode", failing, true)
			return message(h.consentPost("/api/oauth/txn/"+other+"/approve", "alice"), http.StatusInternalServerError)
		}, "the Homie's store failed; start connecting again"},
		{"consent view: a home that cannot be connected", func() string {
			h.catalog.setLive("home", false)
			defer h.catalog.setLive("home", true)
			return message(h.get("/api/oauth/txn/"+txnID, "alice"), http.StatusNotFound)
		}, "the home is not available"},
		{"consent view: the catalog", func() string {
			h.catalog.setError(failing)
			defer h.catalog.setError(nil)
			return message(h.get("/api/oauth/txn/"+txnID, "alice"), http.StatusInternalServerError)
		}, "the home registry failed"},
		{"consent view: the switch", func() string {
			h.catalog.setAvailableError(failing)
			defer h.catalog.setAvailableError(nil)
			return message(h.get("/api/oauth/txn/"+txnID, "alice"), http.StatusInternalServerError)
		}, "the home registry failed"},
		{"consent view: a home that is off for the account", func() string {
			return message(h.get("/api/oauth/txn/"+txnID, "carol"), http.StatusForbidden)
		}, "the home is not on for your account"},
		{"metadata: no such path", func() string {
			return message(h.get("/.well-known/oauth-protected-resource/mcpx", ""), http.StatusNotFound)
		}, "no such home"},
		{"metadata: a home that cannot be connected", func() string {
			h.catalog.setLive("home", false)
			defer h.catalog.setLive("home", true)
			return message(h.get("/.well-known/oauth-protected-resource/mcp", ""), http.StatusNotFound)
		}, "no such home"},
		{"metadata: the catalog", func() string {
			h.catalog.setError(failing)
			defer h.catalog.setError(nil)
			return message(h.get("/.well-known/oauth-protected-resource/mcp", ""), http.StatusInternalServerError)
		}, "the home registry failed"},
	} {
		assert.Equal(t, tt.want, tt.got(), tt.name)
	}

	// The page of a refused client metadata document: the English takes AppNoun, the Russian the product's name.
	h.fetcher.set(claudeDocument, metadataDoc(claudeDocument, "https://evil.example/cb"))
	w := h.authorize(authorizeParams(testClient{id: claudeDocument, redirect: claudeCallback}, "home", challenge))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(),
		template.HTMLEscapeString("The assistant's client description does not fit this Homie."))
	assert.Contains(t, w.Body.String(), "Описание клиента от ассистента не подходит для Homie.")
	assert.Contains(t, w.Body.String(), "<title>Homie</title>")
}
