// Package webui serves an application's built single-page app from an fs.FS (the application embeds its own build).
//
// It answers only the SPA's own paths: the client routes the application lists get index.html, so a reload of
// /account/passkeys or /consent?txn=… works; hashed assets under /assets/ are cached for a year; the static files at
// the top of the build (theme.js, the icons, the manifest) revalidate by ETag. Every other path is left to the
// packages that own it (/api, /oauth, /mcp, /.well-known, /healthz), so register the SPA next to them on the same
// mux: a conflict between two owners of one path panics at start, not in production.
//
// Every answer carries the application's CSP, HSTS, X-Frame-Options, Referrer-Policy: no-referrer and nosniff
// (httpsec.SetSecurityHeaders). Cross-Origin-Opener-Policy is same-origin everywhere except on the routes the
// application names in Options.NoOpener: a page that runs inside an assistant's connector window (the consent page)
// would lose the window's tie to the assistant's page under COOP.
package webui

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

const (
	immutable  = "public, max-age=31536000, immutable"
	revalidate = "no-cache"

	// DefaultNotBuilt is the 503 text of a binary without a build, when Options.NotBuiltHint is empty.
	DefaultNotBuilt = "The web UI is not built into this binary."
)

// publicName is a top-level file name safe to register as a route.
var publicName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9]+$`)

// Options configure the SPA handler.
type Options struct {
	// FS is the build: index.html at its root, hashed assets under assets/, public files at the top (fs.Sub of an
	// embed.FS). A build without index.html is "not built": the pages answer 503 and the assets 404.
	FS fs.FS
	// Routes are the client routes that answer index.html, as mux patterns without a method: "/" (the root page),
	// "/login", "/account", "/account/{rest...}". List a subtree's root and its "/{rest...}" both.
	Routes []string
	// NoOpener are routes (entries of Routes) sent without Cross-Origin-Opener-Policy.
	NoOpener []string
	// CSP is the Content-Security-Policy of every answer (httpsec.DefaultCSP is a strict one).
	CSP string
	// NotBuiltHint is the 503 text when FS has no index.html, e.g. "run `make web`, then rebuild"; "" is
	// DefaultNotBuilt.
	NotBuiltHint string
	// Logger says once whether a build was found; nil discards.
	Logger *slog.Logger
}

type file struct {
	body     []byte
	gzipped  []byte // nil when compression does not pay off
	etag     string
	mimeType string
}

// Routes serves one SPA build; it implements core.RouteRegistrar.
type Routes struct {
	files    map[string]*file // by path inside the build, e.g. "assets/index-abc.js"
	index    *file
	public   []string // the top-level files besides index.html, e.g. "theme.js"
	routes   []string
	noOpener map[string]bool
	csp      string
	notBuilt string
}

// New reads the build in o.FS and validates the options.
func New(o Options) (*Routes, error) {
	if o.FS == nil {
		return nil, errors.New("webui: FS is nil")
	}
	if strings.TrimSpace(o.CSP) == "" {
		return nil, errors.New("webui: CSP is empty")
	}
	rt := &Routes{
		files: map[string]*file{}, csp: strings.TrimSpace(o.CSP), noOpener: map[string]bool{},
		notBuilt: o.NotBuiltHint,
	}
	if rt.notBuilt == "" {
		rt.notBuilt = DefaultNotBuilt
	}
	for _, p := range o.Routes {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, " \t") {
			return nil, fmt.Errorf("webui: route %q must be a path pattern starting with /, without a method", p)
		}
	}
	rt.routes = o.Routes
	for _, p := range o.NoOpener {
		if !slices.Contains(o.Routes, p) {
			return nil, fmt.Errorf("webui: NoOpener route %q is not in Routes", p)
		}
		rt.noOpener[p] = true
	}
	_ = fs.WalkDir(o.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(path.Base(p), ".") {
			return nil
		}
		if body, err := fs.ReadFile(o.FS, p); err == nil {
			rt.files[p] = load(p, body)
		}
		return nil
	})
	rt.index = rt.files["index.html"]
	for p := range rt.files {
		// Top-level files with an extension only: such a route can never shadow /api, /oauth, /mcp or /healthz.
		if p != "index.html" && publicName.MatchString(p) {
			rt.public = append(rt.public, p)
		}
	}
	slices.Sort(rt.public)
	if err := tryRegister(rt); err != nil {
		return nil, err
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if rt.index == nil {
		log.Warn("webui: the SPA is not built into this binary; its pages answer 503 until it is built and the binary rebuilt")
	} else {
		log.Info("webui: serving the SPA", slog.Int("files", len(rt.files)))
	}
	return rt, nil
}

// RegisterRoutes adds GET (and so HEAD) for the client routes, the hashed assets and the public files.
func (rt *Routes) RegisterRoutes(mux *http.ServeMux) {
	for _, p := range rt.routes {
		coop := !rt.noOpener[p]
		pattern := p
		if p == "/" {
			pattern = "/{$}" // the root page only, not every path
		}
		mux.HandleFunc("GET "+pattern, func(w http.ResponseWriter, r *http.Request) { rt.page(w, r, coop) })
	}
	mux.HandleFunc("GET /assets/{file...}", func(w http.ResponseWriter, r *http.Request) {
		name := "assets/" + strings.TrimPrefix(path.Clean("/"+r.PathValue("file")), "/")
		rt.asset(w, r, rt.files[name])
	})
	for _, name := range rt.public {
		f := rt.files[name]
		mux.HandleFunc("GET /"+name, func(w http.ResponseWriter, r *http.Request) { rt.serve(w, r, f, revalidate, true) })
	}
}

// tryRegister registers the client routes on a throwaway mux, so a bad pattern or a duplicate is an error of New
// instead of a panic at start.
func tryRegister(rt *Routes) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("webui: bad routes: %v", v)
		}
	}()
	rt.RegisterRoutes(http.NewServeMux())
	return nil
}

// page answers a client route with index.html.
func (rt *Routes) page(w http.ResponseWriter, r *http.Request, coop bool) {
	if rt.index == nil {
		httpsec.SetSecurityHeaders(w.Header(), rt.csp, true)
		httpsec.SetNoStore(w)
		http.Error(w, rt.notBuilt, http.StatusServiceUnavailable)
		return
	}
	rt.serve(w, r, rt.index, revalidate, coop)
}

// asset answers a hashed asset, or 404: a stale page must never run index.html as a script.
func (rt *Routes) asset(w http.ResponseWriter, r *http.Request, f *file) {
	if f == nil {
		httpsec.SetSecurityHeaders(w.Header(), rt.csp, true)
		httpsec.SetNoStore(w)
		http.NotFound(w, r)
		return
	}
	rt.serve(w, r, f, immutable, true)
}

func (rt *Routes) serve(w http.ResponseWriter, r *http.Request, f *file, cache string, coop bool) {
	hdr := w.Header()
	httpsec.SetSecurityHeaders(hdr, rt.csp, coop)
	hdr.Set("Cache-Control", cache)
	hdr.Set("ETag", f.etag)
	hdr.Set("Content-Type", f.mimeType)
	hdr.Add("Vary", "Accept-Encoding")
	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, f.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := f.body
	if f.gzipped != nil && acceptsGzip(r.Header.Get("Accept-Encoding")) {
		hdr.Set("Content-Encoding", "gzip")
		body = f.gzipped
	}
	hdr.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func load(p string, body []byte) *file {
	sum := sha256.Sum256(body)
	f := &file{body: body, etag: `"` + hex.EncodeToString(sum[:12]) + `"`, mimeType: mimeOf(p)}
	if compressible(f.mimeType) && len(body) > 1024 {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		_, _ = zw.Write(body)
		_ = zw.Close()
		if buf.Len() < len(body)*9/10 {
			f.gzipped = buf.Bytes()
		}
	}
	return f
}

func mimeOf(p string) string {
	switch path.Ext(p) {
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".webmanifest":
		return "application/manifest+json"
	case ".png":
		return "image/png"
	}
	if t := mime.TypeByExtension(path.Ext(p)); t != "" {
		return t
	}
	return "application/octet-stream"
}

func compressible(mimeType string) bool {
	return strings.HasPrefix(mimeType, "text/") || strings.Contains(mimeType, "json") || strings.Contains(mimeType, "svg")
}

func etagMatches(header, etag string) bool {
	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimSpace(part)
		if part == "*" || strings.TrimPrefix(part, "W/") == etag {
			return true
		}
	}
	return false
}

// acceptsGzip reads Accept-Encoding: gzip is accepted unless its q-value is 0.
func acceptsGzip(header string) bool {
	for part := range strings.SplitSeq(header, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(name), "gzip") {
			continue
		}
		q, found := strings.CutPrefix(strings.ReplaceAll(params, " ", ""), "q=")
		if !found {
			return true
		}
		v, err := strconv.ParseFloat(q, 64)
		return err != nil || v > 0
	}
	return false
}
