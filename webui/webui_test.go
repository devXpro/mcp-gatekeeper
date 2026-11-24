package webui

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
	"github.com/devXpro/mcp-gatekeeper/internal/testlog"
)

var bigJS = "console.log(" + strings.Repeat(`"family-hub",`, 400) + ")"

// spaRoutes is Family Hub's client route list, the list the tests run with.
var spaRoutes = []string{
	"/", "/login", "/setup", "/join", "/consent", "/connect",
	"/account", "/account/{rest...}", "/admin", "/admin/{rest...}",
}

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":            {Data: []byte(`<!doctype html><html><head><script type="module" src="/assets/index-abc.js"></script></head><body><div id="root"></div></body></html>`)},
		"theme.js":              {Data: []byte(`document.documentElement.dataset.theme='dark'`)},
		"manifest.webmanifest":  {Data: []byte(`{"name":"Family Hub"}`)},
		"favicon.svg":           {Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)},
		"assets/index-abc.js":   {Data: []byte(bigJS)},
		"assets/index-abc.css":  {Data: []byte(`body{margin:0}`)},
		".gitkeep":              {Data: nil},
		"assets/.hidden-secret": {Data: []byte("nope")},
		"odd{name}.js":          {Data: []byte("x")},
	}
}

func options(fsys fstest.MapFS) Options {
	return Options{FS: fsys, Routes: spaRoutes, NoOpener: []string{"/consent"}, CSP: httpsec.DefaultCSP}
}

func newRoutes(t *testing.T, o Options) *Routes {
	t.Helper()
	rt, err := New(o)
	require.NoError(t, err)
	return rt
}

// handler registers the SPA next to stand-ins for every route the other packages own, so a conflict between them
// would panic here, and a test can see the SPA never answers for them.
func handler(t *testing.T, rt core.RouteRegistrar) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	owned := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }
	for _, p := range []string{
		"GET /healthz",
		"GET /.well-known/oauth-authorization-server",
		"GET /.well-known/openid-configuration",
		"GET /.well-known/oauth-protected-resource/mcp/{id}",
		"POST /oauth/register",
		"GET /oauth/authorize",
		"POST /oauth/token",
		"GET /api/oauth/txn/{txn}",
		"POST /api/oauth/txn/{txn}/approve",
		"GET /api/me",
		"GET /api/account",
		"GET /api/admin/modules",
		"POST /mcp/{id}",
		"GET /mcp/{id}/{rest...}",
		"/legacy/{id}/{rest...}",
	} {
		mux.HandleFunc(p, owned)
	}
	rt.RegisterRoutes(mux)
	return mux
}

func do(t *testing.T, h http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRoutes(t *testing.T) {
	h := handler(t, newRoutes(t, options(testFS())))
	const html, js, css, text = "text/html; charset=utf-8", "text/javascript; charset=utf-8", "text/css; charset=utf-8", "text/plain; charset=utf-8"
	tests := []struct {
		name, path  string
		status      int
		contentType string
		cache       string
		bodyHas     string
		coop        bool
	}{
		{"root", "/", 200, html, revalidate, `<div id="root">`, true},
		{"login", "/login", 200, html, revalidate, `<div id="root">`, true},
		{"setup, the token stays in the fragment", "/setup", 200, html, revalidate, `<div id="root">`, true},
		{"join", "/join", 200, html, revalidate, `<div id="root">`, true},
		{"consent keeps the assistant's opener", "/consent?txn=txn_abc", 200, html, revalidate, `<div id="root">`, false},
		{"connect", "/connect", 200, html, revalidate, `<div id="root">`, true},
		{"account", "/account", 200, html, revalidate, `<div id="root">`, true},
		{"account sub-page", "/account/passkeys", 200, html, revalidate, `<div id="root">`, true},
		{"farewell after delete", "/account/deleted", 200, html, revalidate, `<div id="root">`, true},
		{"admin", "/admin", 200, html, revalidate, `<div id="root">`, true},
		{"admin deep link", "/admin/modules/notes", 200, html, revalidate, `<div id="root">`, true},
		{"hashed js", "/assets/index-abc.js", 200, js, immutable, "family-hub", true},
		{"hashed css", "/assets/index-abc.css", 200, css, immutable, "margin", true},
		{"missing asset is not html", "/assets/index-old.js", 404, text, "no-store", "not found", true},
		{"hidden asset", "/assets/.hidden-secret", 404, text, "no-store", "not found", true},
		{"traversal stays in the assets", "/assets/..%2findex.html", 404, text, "no-store", "not found", true},
		{"public file", "/theme.js", 200, js, revalidate, "dataset.theme", true},
		{"manifest", "/manifest.webmanifest", 200, "application/manifest+json", revalidate, "Family Hub", true},
		{"icon", "/favicon.svg", 200, "image/svg+xml", revalidate, "<svg", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(t, h, http.MethodGet, tt.path, nil)
			require.Equal(t, tt.status, rec.Code, rec.Body.String())
			assert.Equal(t, tt.contentType, rec.Header().Get("Content-Type"))
			assert.Equal(t, tt.cache, rec.Header().Get("Cache-Control"))
			assert.Contains(t, rec.Body.String(), tt.bodyHas)
			assert.Equal(t, httpsec.DefaultCSP, rec.Header().Get("Content-Security-Policy"))
			assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
			assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
			assert.Equal(t, "max-age=31536000", rec.Header().Get("Strict-Transport-Security"))
			if tt.coop {
				assert.Equal(t, "same-origin", rec.Header().Get("Cross-Origin-Opener-Policy"))
			} else {
				assert.Empty(t, rec.Header().Get("Cross-Origin-Opener-Policy"))
			}
		})
	}
}

// TestOthersPaths checks the SPA answers nothing that belongs to another package, and nothing outside its list.
func TestOthersPaths(t *testing.T) {
	h := handler(t, newRoutes(t, options(testFS())))
	for _, p := range []string{"/healthz", "/.well-known/openid-configuration", "/oauth/authorize", "/api/me", "/api/account", "/api/admin/modules", "/api/oauth/txn/txn_1", "/mcp/notes/x", "/legacy/notes/grades"} {
		rec := do(t, h, http.MethodGet, p, nil)
		assert.Equal(t, http.StatusTeapot, rec.Code, p)
		assert.Empty(t, rec.Header().Get("Content-Security-Policy"), p)
	}
	// "/" is the root page only, not every path; a file with a name that is no safe route is not served.
	for _, p := range []string{"/nowhere", "/index.html", "/.gitkeep", "/api", "/assets", "/connect/extra", "/odd%7Bname%7D.js"} {
		rec := do(t, h, http.MethodGet, p, nil)
		assert.NotEqual(t, http.StatusOK, rec.Code, p)
		assert.NotContains(t, rec.Body.String(), `<div id="root">`, p)
	}
}

// The literal ../ is cleaned by the mux itself, which redirects before the SPA sees it.
func TestTraversalIsCleanedByTheMux(t *testing.T) {
	h := handler(t, newRoutes(t, options(testFS())))
	rec := do(t, h, http.MethodGet, "/assets/../index.html", nil)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), `<div id="root">`)
}

func TestMethods(t *testing.T) {
	h := handler(t, newRoutes(t, options(testFS())))
	rec := do(t, h, http.MethodPost, "/connect", nil)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), `<div id="root">`)

	rec = do(t, h, http.MethodHead, "/assets/index-abc.js", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Zero(t, rec.Body.Len())
	assert.Equal(t, strconv.Itoa(len(bigJS)), rec.Header().Get("Content-Length"))

	rec = do(t, h, http.MethodHead, "/consent", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Zero(t, rec.Body.Len())
}

func TestETag(t *testing.T) {
	h := handler(t, newRoutes(t, options(testFS())))
	etag := do(t, h, http.MethodGet, "/theme.js", nil).Header().Get("ETag")
	require.True(t, strings.HasPrefix(etag, `"`), etag)
	for _, header := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		rec := do(t, h, http.MethodGet, "/theme.js", map[string]string{"If-None-Match": header})
		assert.Equal(t, http.StatusNotModified, rec.Code, header)
		assert.Zero(t, rec.Body.Len(), header)
	}
	assert.Equal(t, http.StatusOK, do(t, h, http.MethodGet, "/theme.js", map[string]string{"If-None-Match": `"stale"`}).Code)
	// The pages revalidate too: a new build is picked up on the next load.
	page := do(t, h, http.MethodGet, "/connect", nil).Header().Get("ETag")
	assert.Equal(t, http.StatusNotModified, do(t, h, http.MethodGet, "/account", map[string]string{"If-None-Match": page}).Code)
}

func TestGzip(t *testing.T) {
	h := handler(t, newRoutes(t, options(testFS())))
	rec := do(t, h, http.MethodGet, "/assets/index-abc.js", map[string]string{"Accept-Encoding": "br, gzip"})
	require.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
	assert.Contains(t, rec.Header().Get("Vary"), "Accept-Encoding")
	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	require.NoError(t, err)
	plain, err := io.ReadAll(zr)
	require.NoError(t, err)
	assert.Equal(t, bigJS, string(plain))

	assert.Empty(t, do(t, h, http.MethodGet, "/assets/index-abc.js", map[string]string{"Accept-Encoding": "gzip;q=0"}).Header().Get("Content-Encoding"))
	// Small files are sent as they are.
	assert.Empty(t, do(t, h, http.MethodGet, "/assets/index-abc.css", map[string]string{"Accept-Encoding": "gzip"}).Header().Get("Content-Encoding"))
}

func TestAcceptsGzip(t *testing.T) {
	tests := map[string]bool{
		"":                  false,
		"gzip":              true,
		"GZIP":              true,
		"br, gzip, deflate": true,
		"gzip;q=0":          false,
		"gzip; q=0":         false,
		"gzip;q=0.5":        true,
		"gzip;q=1.0":        true,
		"deflate, br":       false,
		"x-gzip":            false,
	}
	for header, want := range tests {
		assert.Equal(t, want, acceptsGzip(header), header)
	}
}

func TestNotBuilt(t *testing.T) {
	o := options(fstest.MapFS{".gitkeep": {Data: nil}})
	o.NotBuiltHint = "run `make web`, then rebuild the hub."
	log, logs := testlog.New()
	o.Logger = log
	h := handler(t, newRoutes(t, o))
	rec := do(t, h, http.MethodGet, "/connect", nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "make web")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.NotEmpty(t, rec.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, httpsec.DefaultCSP, rec.Header().Get("Content-Security-Policy"))
	// The assets of a build that is not there are plain 404s.
	assert.Equal(t, http.StatusNotFound, do(t, h, http.MethodGet, "/assets/index-abc.js", nil).Code)

	recs := logs.Records()
	require.Len(t, recs, 1)
	assert.Equal(t, "WARN", recs[0].Level.String())

	o.NotBuiltHint = ""
	rec = do(t, handler(t, newRoutes(t, o)), http.MethodGet, "/", nil)
	assert.Contains(t, rec.Body.String(), DefaultNotBuilt)
}

func TestBuiltLog(t *testing.T) {
	o := options(testFS())
	log, logs := testlog.New()
	o.Logger = log
	newRoutes(t, o)
	recs := logs.Records()
	require.Len(t, recs, 1)
	assert.Equal(t, "INFO", recs[0].Level.String())
	assert.Equal(t, "webui: serving the SPA", recs[0].Message)
}

func TestNewValidates(t *testing.T) {
	good := options(testFS())
	tests := []struct {
		name string
		edit func(*Options)
		want string
	}{
		{"no FS", func(o *Options) { o.FS = nil }, "FS is nil"},
		{"no CSP", func(o *Options) { o.CSP = " " }, "CSP is empty"},
		{"route with a method", func(o *Options) { o.Routes = []string{"GET /x"} }, "without a method"},
		{"route without a slash", func(o *Options) { o.Routes = []string{"login"} }, "starting with /"},
		{"duplicate route", func(o *Options) { o.Routes, o.NoOpener = []string{"/a", "/a"}, nil }, "bad routes"},
		{"broken pattern", func(o *Options) { o.Routes, o.NoOpener = []string{"/a/{b"}, nil }, "bad routes"},
		{"unknown no-opener route", func(o *Options) { o.NoOpener = []string{"/nope"} }, "not in Routes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := good
			tt.edit(&o)
			_, err := New(o)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

// TestInHTTPFront runs the SPA behind the httpsec front, the way an application mounts it: the JSON 404 answers
// everything the SPA does not own.
func TestInHTTPFront(t *testing.T) {
	h, err := httpsec.New(httpsec.Options{Routes: []core.RouteRegistrar{newRoutes(t, options(testFS()))}})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, do(t, h, http.MethodGet, "/", nil).Code)
	assert.Equal(t, http.StatusOK, do(t, h, http.MethodGet, "/account/passkeys", nil).Code)
	rec := do(t, h, http.MethodGet, "/nowhere", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.JSONEq(t, `{"error":"not_found","message":"no such route"}`, rec.Body.String())
	assert.Equal(t, http.StatusNotFound, do(t, h, http.MethodPost, "/connect", nil).Code)
}
