package httpsec

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/internal/testlog"
)

var site = core.Site{PublicURL: "https://hub.example.com", RPID: "hub.example.com", ClientIP: core.ClientIPCloudflare}

// upstreamBodyLimit stands for an application's own, smaller body cap (Family Hub's MCP gateway: 1 MiB); the
// package's cap must leave it room to answer its own 413.
const upstreamBodyLimit = 1 << 20

// probe is a registrar with the routes the tests need.
type probe struct {
	stream chan string // the SSE handler writes each value as an event and flushes
}

func (p probe) RegisterRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /oauth/authorize", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusFound) })
	m.HandleFunc("GET /api/oauth/txn/{txn}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	m.HandleFunc("GET /panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
	m.HandleFunc("GET /panic-late", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "partial")
		panic("late boom")
	})
	m.HandleFunc("GET /abort", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
	m.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = fmt.Fprintf(w, "%d", len(b))
	})
	m.HandleFunc("GET /mcp/sse", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // the headers go out at once, as the gateway's do
		for v := range p.stream {
			_, _ = io.WriteString(w, "data: "+v+"\n\n")
			w.(http.Flusher).Flush()
		}
	})
}

// edge is the trusted range of the tests: httptest requests come from 192.0.2.1.
var edge = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}

func newHandler(t *testing.T) (http.Handler, *testlog.Recorder, probe) {
	t.Helper()
	return newHandlerWith(t, Options{Trusted: edge})
}

func newHandlerWith(t *testing.T, o Options) (http.Handler, *testlog.Recorder, probe) {
	t.Helper()
	log, rec := testlog.New()
	p := probe{stream: make(chan string)}
	o.Site, o.Logger = site, log
	o.Routes = []core.RouteRegistrar{p}
	h, err := New(o)
	require.NoError(t, err)
	return h, rec, p
}

func serve(h http.Handler, method, target string, body io.Reader, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	h, logs, _ := newHandler(t)
	rec := serve(h, http.MethodGet, "/healthz", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, http.StatusOK, serve(h, http.MethodHead, "/healthz", nil, nil).Code)
	recs := logs.Records()
	require.Len(t, recs, 2)
	assert.Equal(t, slog.LevelDebug, recs[0].Level, "health checks log at debug")
	assert.Equal(t, "/healthz", recs[0].Attrs["route"])
}

func TestNotFoundIsJSON(t *testing.T) {
	h, _, _ := newHandler(t)
	for _, tt := range []struct{ method, path string }{
		{http.MethodGet, "/nope"},
		{http.MethodPost, "/healthz"}, // a wrong method of a known route is an unknown route too
	} {
		rec := serve(h, tt.method, tt.path, nil, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code, tt.path)
		assert.JSONEq(t, `{"error":"not_found","message":"no such route"}`, rec.Body.String())
	}
}

func TestRequestLogKeepsNoSecrets(t *testing.T) {
	h, logs, _ := newHandler(t)
	hdr := http.Header{
		"Authorization":    {"Bearer tok-secret"},
		"Cookie":           {"__Host-fh_session=cookie-secret"},
		"Cf-Connecting-Ip": {"198.51.100.7"},
	}
	serve(h, http.MethodGet, "/oauth/authorize?code=code-secret&state=state-secret", nil, hdr)
	serve(h, http.MethodGet, "/consent?txn=txn-secret", nil, hdr)
	serve(h, http.MethodGet, "/api/oauth/txn/path-secret", nil, hdr)
	recs := logs.Records()
	require.Len(t, recs, 3)
	first := recs[0]
	assert.Equal(t, "request", first.Message)
	assert.Equal(t, "/oauth/authorize", first.Attrs["route"], "the pattern, without its method")
	assert.Equal(t, "302", first.Attrs["status"])
	assert.Equal(t, "198.51.100.7", first.Attrs["ip"])
	assert.Equal(t, "(no route)", recs[1].Attrs["route"])
	assert.Equal(t, "/api/oauth/txn/{txn}", recs[2].Attrs["route"], "the pattern, never the id in the path")
	for _, s := range []string{"tok-secret", "cookie-secret", "code-secret", "state-secret", "txn-secret", "path-secret", "?"} {
		assert.False(t, logs.Contains(s), s)
	}
	for _, rec := range recs {
		assert.ElementsMatch(t, []string{"method", "route", "status", "bytes", "took", "ip"}, keys(rec.Attrs))
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRequestLogLevelsAndSize(t *testing.T) {
	h, logs, _ := newHandler(t)
	serve(h, http.MethodGet, "/api/oauth/txn/x", nil, nil)
	serve(h, http.MethodGet, "/panic", nil, nil)
	serve(h, http.MethodGet, "/nope", nil, nil)
	var levels []slog.Level
	for _, rec := range logs.Records() {
		if rec.Message == "request" {
			levels = append(levels, rec.Level)
		}
	}
	assert.Equal(t, []slog.Level{slog.LevelInfo, slog.LevelWarn, slog.LevelInfo}, levels)
	nf := logs.Records()[len(logs.Records())-1]
	assert.Equal(t, "404", nf.Attrs["status"])
	assert.NotEqual(t, "0", nf.Attrs["bytes"], "the size of the answer is counted")
}

func TestRecovery(t *testing.T) {
	h, logs, _ := newHandler(t)
	rec := serve(h, http.MethodGet, "/panic", nil, nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.JSONEq(t, `{"error":"internal","message":"internal error"}`, rec.Body.String())
	var panics, requests []testlog.Record
	for _, r := range logs.Records() {
		switch r.Message {
		case "panic":
			panics = append(panics, r)
		case "request":
			requests = append(requests, r)
		}
	}
	require.Len(t, panics, 1)
	assert.Equal(t, "boom", panics[0].Attrs["panic"])
	assert.Equal(t, "/panic", panics[0].Attrs["route"])
	assert.Contains(t, panics[0].Attrs["stack"], "httpsec_test.go")
	require.Len(t, requests, 1)
	assert.Equal(t, "500", requests[0].Attrs["status"])

	assert.PanicsWithValue(t, http.ErrAbortHandler, func() { serve(h, http.MethodGet, "/abort", nil, nil) },
		"an intended abort is not swallowed")
}

// A panic after the answer has started cannot become a 500: the answer stays as it is and the panic is logged.
func TestRecoveryAfterWrite(t *testing.T) {
	h, logs, _ := newHandler(t)
	rec := serve(h, http.MethodGet, "/panic-late", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "partial", rec.Body.String())
	assert.True(t, logs.Contains("late boom"))
}

func TestBodyLimit(t *testing.T) {
	h, _, _ := newHandler(t)
	ok := serve(h, http.MethodPost, "/echo", strings.NewReader(strings.Repeat("a", upstreamBodyLimit+1)), nil)
	assert.Equal(t, http.StatusOK, ok.Code, "an application must see a body just above its own cap")
	assert.Equal(t, "1048577", ok.Body.String())

	big := serve(h, http.MethodPost, "/echo", strings.NewReader(strings.Repeat("a", MaxBody+1)), nil)
	assert.Equal(t, http.StatusRequestEntityTooLarge, big.Code)
	assert.JSONEq(t, `{"error":"invalid","message":"request body too large"}`, big.Body.String())

	// A body without a length is cut while it is read.
	req := httptest.NewRequest(http.MethodPost, "/echo", io.NopCloser(strings.NewReader(strings.Repeat("a", MaxBody+1))))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestBodyLimitOption(t *testing.T) {
	h, _, _ := newHandlerWith(t, Options{MaxBody: 10})
	assert.Equal(t, http.StatusOK, serve(h, http.MethodPost, "/echo", strings.NewReader("0123456789"), nil).Code)
	assert.Equal(t, http.StatusRequestEntityTooLarge, serve(h, http.MethodPost, "/echo", strings.NewReader("0123456789a"), nil).Code)
}

func TestNewValidates(t *testing.T) {
	_, err := New(Options{MaxBody: -1})
	require.ErrorContains(t, err, "MaxBody")
	_, err = New(Options{Routes: []core.RouteRegistrar{nil}})
	require.ErrorContains(t, err, "Routes[0]")
	_, err = NewServer(ServerOptions{Handler: http.NotFoundHandler()})
	require.ErrorContains(t, err, "Listen")
	_, err = NewServer(ServerOptions{Listen: "127.0.0.1:0"})
	require.ErrorContains(t, err, "Handler")
}

// TestServerStreams runs the real server and reads an SSE event before the handler has finished: nothing buffers.
func TestServerStreams(t *testing.T) {
	h, _, p := newHandler(t)
	s, err := NewServer(ServerOptions{Listen: "127.0.0.1:0", Handler: h})
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), s.srv.WriteTimeout, "SSE must not be cut")
	assert.Equal(t, time.Duration(0), s.srv.ReadTimeout, "SSE must not be cut")
	assert.Equal(t, ReadHeaderTimeout, s.srv.ReadHeaderTimeout)
	assert.Nil(t, s.Addr())
	require.NoError(t, s.Start(t.Context()))

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+s.Addr().String()+"/mcp/sse", nil)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Empty(t, resp.Header.Get("Content-Encoding"), "no compression")
	rd := bufio.NewReader(resp.Body)
	for _, v := range []string{"one", "two"} {
		p.stream <- v
		line, err := rd.ReadString('\n')
		require.NoError(t, err)
		assert.Equal(t, "data: "+v+"\n", line)
		_, _ = rd.ReadString('\n')
	}
	close(p.stream)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, s.Stop(ctx))
}

func TestStartFailsOnBusyPort(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	s, err := NewServer(ServerOptions{Listen: ln.Addr().String(), Handler: http.NotFoundHandler()})
	require.NoError(t, err)
	require.ErrorContains(t, s.Start(t.Context()), "listen on")
}

// whoAmI makes a route that echoes the client address core.ClientIP finds and the raw proxy headers.
type whoAmI struct{ mode core.ClientIPMode }

func (w whoAmI) RegisterRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /whoami", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]string{
			"ip": core.ClientIP(r, w.mode), "cf": r.Header.Get("CF-Connecting-IP"), "xff": r.Header.Get("X-Forwarded-For"),
		})
	})
}

func fromPeer(h http.Handler, remote string, hdr http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPeerGuard(t *testing.T) {
	o := Options{
		Trusted:        []netip.Prefix{netip.MustParsePrefix("10.230.0.0/24"), netip.MustParsePrefix("fd00:1::/64")},
		Refused:        []netip.Prefix{netip.MustParsePrefix("10.231.0.0/16")},
		RefusedMessage: "modules do not call the hub",
	}
	forged := http.Header{"Cf-Connecting-Ip": {"203.0.113.9"}, "X-Forwarded-For": {"203.0.113.8"}}
	tests := []struct {
		name   string
		mode   core.ClientIPMode
		remote string
		status int
		ip     string // the client address the handler sees
		cf     string
		xff    string
	}{
		{"cloudflared is believed", core.ClientIPCloudflare, "10.230.0.5:4000", 200, "203.0.113.9", "203.0.113.9", "203.0.113.8"},
		{"proxy is believed", core.ClientIPForwarded, "10.230.0.1:4000", 200, "203.0.113.8", "203.0.113.9", "203.0.113.8"},
		{"ipv6 edge is believed", core.ClientIPCloudflare, "[fd00:1::7]:4000", 200, "203.0.113.9", "203.0.113.9", "203.0.113.8"},
		{"mapped edge is believed", core.ClientIPCloudflare, "[::ffff:10.230.0.5]:4000", 200, "203.0.113.9", "203.0.113.9", "203.0.113.8"},
		{"stranger loses cf header", core.ClientIPCloudflare, "198.51.100.4:4000", 200, "198.51.100.4", "", ""},
		{"stranger loses xff", core.ClientIPForwarded, "198.51.100.4:4000", 200, "198.51.100.4", "", ""},
		{"the next /24 is a stranger", core.ClientIPCloudflare, "10.230.1.5:4000", 200, "10.230.1.5", "", ""},
		{"loopback is a stranger", core.ClientIPCloudflare, "127.0.0.1:4000", 200, "127.0.0.1", "", ""},
		{"refused peer", core.ClientIPCloudflare, "10.231.4.2:4000", 403, "", "", ""},
		{"refused peer far in the range", core.ClientIPCloudflare, "10.231.255.254:4000", 403, "", "", ""},
		{"mapped refused peer", core.ClientIPCloudflare, "[::ffff:10.231.4.2]:4000", 403, "", "", ""},
		{"no tcp peer", core.ClientIPCloudflare, "@", 200, "@", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := o
			o.Site, o.Routes = core.Site{ClientIP: tt.mode}, []core.RouteRegistrar{whoAmI{tt.mode}}
			h, err := New(o)
			require.NoError(t, err)
			rec := fromPeer(h, tt.remote, forged)
			require.Equal(t, tt.status, rec.Code)
			if tt.status != http.StatusOK {
				assert.JSONEq(t, `{"error":"forbidden","message":"modules do not call the hub"}`, rec.Body.String())
				return
			}
			assert.JSONEq(t, fmt.Sprintf(`{"ip":%q,"cf":%q,"xff":%q}`, tt.ip, tt.cf, tt.xff), rec.Body.String())
		})
	}
}

// With no trusted peers nothing is believed, and no refused range refuses nobody.
func TestPeerGuardEmptyOptions(t *testing.T) {
	h, err := New(Options{Site: site, Routes: []core.RouteRegistrar{whoAmI{core.ClientIPCloudflare}}})
	require.NoError(t, err)
	rec := fromPeer(h, "10.231.4.2:4000", http.Header{"Cf-Connecting-Ip": {"203.0.113.9"}})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"ip":"10.231.4.2","cf":"","xff":""}`, rec.Body.String())
}

func TestPeerGuardDefaultMessage(t *testing.T) {
	h, err := New(Options{Refused: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	require.NoError(t, err)
	rec := fromPeer(h, "10.1.2.3:1", nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.JSONEq(t, `{"error":"forbidden","message":"peer not allowed"}`, rec.Body.String())
}

// The request log shows the peer for a stranger's forged header, and the refusal of a refused peer is logged too.
func TestPeerGuardLog(t *testing.T) {
	log, logs := testlog.New()
	h, err := New(Options{
		Site: site, Logger: log, Routes: []core.RouteRegistrar{whoAmI{core.ClientIPCloudflare}},
		Refused: []netip.Prefix{netip.MustParsePrefix("10.231.0.0/16")},
	})
	require.NoError(t, err)
	fromPeer(h, "198.51.100.4:1", http.Header{"Cf-Connecting-Ip": {"203.0.113.9"}})
	fromPeer(h, "10.231.4.2:1", http.Header{"Cf-Connecting-Ip": {"203.0.113.9"}})
	recs := logs.Records()
	require.Len(t, recs, 2)
	assert.Equal(t, "198.51.100.4", recs[0].Attrs["ip"])
	assert.Equal(t, "403", recs[1].Attrs["status"])
	assert.Equal(t, "10.231.4.2", recs[1].Attrs["ip"])
}

func TestChainOrder(t *testing.T) {
	var order []string
	mw := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { order = append(order, "h") }), mw("a"), mw("b"))
	serve(h, http.MethodGet, "/", nil, nil)
	assert.Equal(t, []string{"a", "b", "h"}, order)
}

func TestSecurityHeaders(t *testing.T) {
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	rec := serve(SecurityHeaders("default-src 'none'")(ok), http.MethodGet, "/", nil, nil)
	assert.Equal(t, "default-src 'none'", rec.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "max-age=31536000", rec.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "same-origin", rec.Header().Get("Cross-Origin-Opener-Policy"))

	h := http.Header{}
	SetSecurityHeaders(h, "x", false)
	assert.Empty(t, h.Get("Cross-Origin-Opener-Policy"))
	assert.Equal(t, "x", h.Get("Content-Security-Policy"))
}

func TestNoStore(t *testing.T) {
	rec := serve(NoStore(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})), http.MethodGet, "/", nil, nil)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestDefaultCSPIsStrict(t *testing.T) {
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"} {
		assert.Contains(t, DefaultCSP, want)
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "*", "http:", "https:"} {
		assert.NotContains(t, DefaultCSP, bad)
	}
}

func TestWriteErrorUnderRecorder(t *testing.T) {
	// The recorder keeps flushing and unwrapping working: ResponseController reaches the real writer.
	rec := httptest.NewRecorder()
	r := record(rec)
	assert.Same(t, r, record(r), "an already wrapped writer is not wrapped twice")
	require.NoError(t, http.NewResponseController(r).Flush())
	assert.True(t, rec.Flushed)
}

func TestWriteErrorBytes(t *testing.T) {
	// Byte for byte what Family Hub's Gin c.JSON wrote: json.Marshal, HTML escaped, no trailing newline.
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusForbidden, CodeForbidden, "the module is not on for this account")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, `{"error":"forbidden","message":"the module is not on for this account"}`, rec.Body.String())
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	rec = httptest.NewRecorder()
	WriteError(rec, http.StatusBadRequest, CodeInvalid, "<b> & co")
	assert.True(t, json.Valid(rec.Body.Bytes()))
	for _, raw := range []string{"<", ">", "&"} {
		assert.NotContains(t, rec.Body.String(), raw, "HTML characters are escaped, as Gin's c.JSON does")
	}
}
