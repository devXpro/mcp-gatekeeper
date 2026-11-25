package httpsec

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// TestBodyLimitDeadline is review GK-17 through a real server: a client that does not send its body in time makes
// the handler's read fail with os.ErrDeadlineExceeded (here answered 408; /echo answers any read error with 413),
// and a body read in full leaves no deadline behind to end a long answer.
func TestBodyLimitDeadline(t *testing.T) {
	const timeout = 100 * time.Millisecond
	after := make(chan error, 1)
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				WriteError(w, http.StatusRequestTimeout, CodeInvalid, "too slow")
				return
			}
			WriteError(w, http.StatusRequestEntityTooLarge, CodeInvalid, "request body too large")
			return
		}
		select {
		case <-r.Context().Done():
		case <-time.After(3 * timeout):
		}
		after <- r.Context().Err()
		_, _ = io.WriteString(w, "ok")
	}), RequestLog(nil, core.ClientIPRemote), Recover(nil), bodyLimit(MaxBody, timeout))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	t.Run("a slow body", func(t *testing.T) {
		conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
		begin := time.Now()
		_, err = io.WriteString(conn, "POST /echo HTTP/1.1\r\nHost: hub.example.com\r\nContent-Length: 100\r\n\r\nabc")
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
		assert.JSONEq(t, `{"error":"invalid","message":"too slow"}`, string(b))
		assert.GreaterOrEqual(t, time.Since(begin), timeout, "not before the deadline")
		assert.True(t, resp.Close, "the connection is not kept for the rest of the body")
	})
	t.Run("a body in time, then a long answer", func(t *testing.T) {
		for range 2 { // the second request on the same connection has no deadline left from the first
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/echo", strings.NewReader("{}"))
			require.NoError(t, err)
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			b, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "ok", string(b))
			select {
			case err := <-after:
				assert.NoError(t, err, "the deadline did not end the request")
			case <-time.After(10 * time.Second):
				require.FailNow(t, "the handler did not finish")
			}
		}
	})
}

func TestBodyLimitKeepsItsBytes(t *testing.T) {
	assert.Equal(t, 30*time.Second, BodyReadTimeout)
	h, _, _ := newHandler(t)
	rec := serve(h, http.MethodPost, "/echo", strings.NewReader(strings.Repeat("a", MaxBody+1)), nil)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Equal(t, `{"error":"invalid","message":"request body too large"}`, rec.Body.String())
}

func TestBodyDeadlineWithoutDeadlines(t *testing.T) {
	lift := BodyDeadline(httptest.NewRecorder(), time.Second) // a recorder cannot set deadlines
	require.NotNil(t, lift)
	lift()
	lift()
}

func TestLoopbackPeers(t *testing.T) {
	a, b := LoopbackPeers(), LoopbackPeers()
	a[0] = netip.MustParsePrefix("0.0.0.0/0")
	assert.Equal(t, "127.0.0.0/8", b[0].String(), "each call has its own slice")

	h, err := New(Options{Trusted: LoopbackPeers(), Routes: []core.RouteRegistrar{whoAmI{core.ClientIPCloudflare}}})
	require.NoError(t, err)
	forged := http.Header{"Cf-Connecting-Ip": {"203.0.113.9"}}
	for remote, believed := range map[string]bool{
		"127.0.0.1:4000":          true,
		"127.10.0.3:4000":         true,
		"[::1]:4000":              true,
		"[::ffff:127.0.0.1]:4000": true,
		"192.0.2.10:4000":         false,
		"[::2]:4000":              false,
		"128.0.0.1:4000":          false,
	} {
		rec := fromPeer(h, remote, forged)
		require.Equal(t, http.StatusOK, rec.Code, remote)
		want := ""
		if believed {
			want = "203.0.113.9"
		}
		assert.Contains(t, rec.Body.String(), fmt.Sprintf(`"cf":%q`, want), remote)
	}
}

func TestMountClean(t *testing.T) {
	inner := http.NewServeMux()
	inner.HandleFunc("GET /api/items/{id}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "item")
	})
	inner.HandleFunc("GET /api/list/", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "list") })
	h := MountClean(inner)
	for target, want := range map[string]int{
		"/api/items/a":         http.StatusOK,
		"/api/items/a%20b":     http.StatusOK,
		"/api/list/":           http.StatusOK,
		"/api/items/..":        http.StatusNotFound,
		"/api/items/.":         http.StatusNotFound,
		"/api/items/a/../b":    http.StatusNotFound,
		"/api//items/a":        http.StatusNotFound,
		"/api/items/a%2Fb":     http.StatusNotFound,
		"/api/items/a%2fb":     http.StatusNotFound,
		"/api/items/%2e%2e":    http.StatusNotFound,
		"/api/list//":          http.StatusNotFound,
		"/api/items/a/./":      http.StatusNotFound,
		"/api/items/a?x=../..": http.StatusOK, // the query is no part of the path
	} {
		rec := serve(h, http.MethodGet, target, nil, nil)
		assert.Equal(t, want, rec.Code, target)
		if want == http.StatusNotFound {
			assert.JSONEq(t, `{"error":"not_found","message":"no such route"}`, rec.Body.String(), target)
			assert.Empty(t, rec.Header().Get("Location"), "no redirect")
		}
	}

	// Without it, the mux answers an unclean path with a redirect of its own.
	rec := serve(inner, http.MethodGet, "/api/items/a/../b", nil, nil)
	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code)

	for _, u := range []string{"", "api/items/a"} {
		assert.False(t, cleanURLPath(&url.URL{Path: u}), "%q", u)
	}
}
