package httpsec

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// HealthPath is the route whose request lines are logged at debug level, so a container health probe does not flood
// the log.
const HealthPath = "/healthz"

// discard is the logger a nil *slog.Logger stands for.
func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// route is the mux pattern the request matched without its method (e.g. "/api/oauth/txn/{txn}"), or "(no route)".
// It is read after the mux has run: the mux sets r.Pattern on the request it was given. It is never the raw path or
// the query: those carry OAuth codes, states and transaction ids.
func route(r *http.Request) string {
	p := r.Pattern
	if _, rest, ok := strings.Cut(p, " "); ok {
		p = rest
	}
	if p == "" || p == "/" { // "/" is New's catch-all 404; an application's root page is "/{$}"
		return "(no route)"
	}
	return p
}

// RequestLog writes one line per request: the method, the route pattern, the status, the size, the duration and the
// client address (core.ClientIP under mode). It never has the raw path or the query string, a header (Authorization,
// cookies) or a body. Health checks go to debug, server errors to warn, the rest to info.
//
// Put it outermost, before Recover and PeerGuard, so it sees the final status and the address PeerGuard leaves.
func RequestLog(log *slog.Logger, mode core.ClientIPMode) func(http.Handler) http.Handler {
	if log == nil {
		log = discard()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := record(w)
			next.ServeHTTP(rec, r)
			rt := route(r)
			level := slog.LevelInfo
			switch {
			case rt == HealthPath:
				level = slog.LevelDebug
			case rec.status >= http.StatusInternalServerError:
				level = slog.LevelWarn
			}
			log.LogAttrs(r.Context(), level, "request",
				slog.String("method", r.Method),
				slog.String("route", rt),
				slog.Int("status", rec.status),
				slog.Int("bytes", rec.bytes),
				slog.Duration("took", time.Since(start)),
				slog.String("ip", core.ClientIP(r, mode)),
			)
		})
	}
}

// Recover turns a panic into a 500 {"error":"internal"} and a log line with the stack. http.ErrAbortHandler passes
// on: it is how a handler drops a connection on purpose. When the answer has started already, only the log line is
// written and the answer is left as it is.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = discard()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := record(w)
			defer func() {
				v := recover()
				if v == nil {
					return
				}
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				log.LogAttrs(r.Context(), slog.LevelError, "panic",
					slog.String("method", r.Method),
					slog.String("route", route(r)),
					slog.String("panic", fmt.Sprint(v)),
					slog.String("stack", string(debug.Stack())),
				)
				if !rec.wrote {
					WriteError(rec, http.StatusInternalServerError, CodeInternal, "internal error")
				}
			}()
			next.ServeHTTP(rec, r)
		})
	}
}
