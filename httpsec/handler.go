package httpsec

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// Chain wraps h in mws, the first one outermost: Chain(h, a, b) runs a, then b, then h.
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// Healthz answers {"status":"ok"} with Cache-Control: no-store (GET and HEAD).
func Healthz(w http.ResponseWriter, _ *http.Request) {
	SetNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// NotFound answers 404 {"error":"not_found","message":"no such route"}.
func NotFound(w http.ResponseWriter, _ *http.Request) {
	WriteError(w, http.StatusNotFound, CodeNotFound, "no such route")
}

// Options build the application's HTTP front with New.
type Options struct {
	// Site gives the client-address mode of the request log.
	Site core.Site
	// Routes register their routes on the mux, in order. None may register "/" or "GET /healthz": New does.
	Routes []core.RouteRegistrar
	// Trusted, Refused and RefusedMessage are the PeerGuard rules.
	Trusted        []netip.Prefix
	Refused        []netip.Prefix
	RefusedMessage string
	// MaxBody caps request bodies; 0 is the package's MaxBody.
	MaxBody int64
	// Logger is the request log and the panic log; nil discards.
	Logger *slog.Logger
}

// New returns the application's HTTP front: a mux with GET and HEAD /healthz and every registrar's routes, answering
// the JSON 404 for any other route, behind these middlewares, outermost first: RequestLog, Recover, PeerGuard,
// BodyLimit. Nothing compresses or buffers answers, so server-sent events reach the client as they are flushed.
func New(o Options) (http.Handler, error) {
	if o.MaxBody < 0 {
		return nil, errors.New("httpsec: MaxBody is negative")
	}
	if o.MaxBody == 0 {
		o.MaxBody = MaxBody
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", Healthz) // HEAD included
	for i, rr := range o.Routes {
		if rr == nil {
			return nil, fmt.Errorf("httpsec: Routes[%d] is nil", i)
		}
		rr.RegisterRoutes(mux)
	}
	mux.HandleFunc("/", NotFound)
	return Chain(mux,
		RequestLog(o.Logger, o.Site.ClientIP),
		Recover(o.Logger),
		PeerGuard(PeerOptions{Trusted: o.Trusted, Refused: o.Refused, RefusedMessage: o.RefusedMessage}),
		BodyLimit(o.MaxBody),
	), nil
}
