package mcpguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

// TestForwardsModernRoutingHeaders: MCP 2026-07-28, which ChatGPT speaks, repeats the method, the tool name and
// arguments in Mcp-Method, Mcp-Name and Mcp-Param-* headers, and a server's SDK refuses a call whose headers are
// missing (Family Hub b0fc38b). They pass; lookalikes do not.
func TestForwardsModernRoutingHeaders(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"note_add","arguments":{"text":"x"}}}`
	req := h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", strings.NewReader(body))
	for k, v := range map[string]string{
		"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
		"Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "note_add", "mcp-param-text": "x",
		"Mcp-Param-": "no name", "Mcp-Params": "lookalike", "X-Mcp-Param-Text": "lookalike", "Mcp-Other": "1",
	} {
		req.Header.Set(k, v)
	}
	a := h.do(t, req)
	require.Equal(t, http.StatusOK, a.status, "body %s", a.body)

	got := h.upstream.only(t)
	assert.Equal(t, []string{"Accept", "Content-Length", "Content-Type", "Mcp-Method", "Mcp-Name", "Mcp-Param-Text",
		"Mcp-Protocol-Version"}, headerNames(got.header))
	assert.Equal(t, "tools/call", got.header.Get("Mcp-Method"))
	assert.Equal(t, "note_add", got.header.Get("Mcp-Name"))
	assert.Equal(t, "x", got.header.Get("Mcp-Param-Text"))
	assert.Equal(t, "2026-07-28", got.header.Get("Mcp-Protocol-Version"))
	assert.Equal(t, body, string(got.body))
}

func TestOnlyTheAllowedHeadersPass(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.upstream.handle(func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range map[string]string{
			"Content-Type": "application/json", "Mcp-Session-Id": "sess-42", "Cache-Control": "public, s-maxage=600",
			"Set-Cookie": "module=1; Path=/", "X-Powered-By": "module", "Access-Control-Allow-Origin": "*",
			"Location": "https://elsewhere.example/", "WWW-Authenticate": "Basic", "Content-Security-Policy": "default-src *",
			"Strict-Transport-Security": "max-age=1", "X-Frame-Options": "ALLOWALL", "Keep-Alive": "timeout=5",
		} {
			w.Header().Set(k, v)
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	})
	req := h.request(t, http.MethodPost, "/mcp/hello?trace=1", "Bearer tok-alice", strings.NewReader(`{}`))
	for k, v := range map[string]string{
		"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
		"Mcp-Session-Id": "sess-42", "Mcp-Protocol-Version": "2025-06-18", "Last-Event-ID": "7",
		"Cookie": "__Host-fh_session=s3cret", "X-Forwarded-For": "203.0.113.9", "CF-Connecting-IP": "203.0.113.9",
		"Origin": "https://chatgpt.com", "User-Agent": "openai-mcp/1.0", "X-Custom": "1", "X-Hub-Identity": "forged",
		"X-Request-Id": "req_forged", "Proxy-Authorization": "Basic eA==", "Te": "trailers",
		"Forwarded": "for=203.0.113.9",
	} {
		req.Header.Set(k, v)
	}
	a := h.do(t, req)

	require.Equal(t, http.StatusOK, a.status, "body %s", a.body)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`, string(a.body))
	assert.Equal(t, "application/json", a.header.Get("Content-Type"))
	assert.Equal(t, "sess-42", a.header.Get("Mcp-Session-Id"))
	assert.Equal(t, []string{"no-store"}, a.header.Values("Cache-Control"), "a server's Cache-Control never passes")
	assert.Equal(t, guardCSP, a.header.Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", a.header.Get("X-Content-Type-Options"))
	for _, k := range []string{"Set-Cookie", "X-Powered-By", "Access-Control-Allow-Origin", "Location",
		"WWW-Authenticate", "Strict-Transport-Security", "X-Frame-Options"} {
		assert.Empty(t, a.header.Values(k), "%s must not come back", k)
	}

	got := h.upstream.only(t)
	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "/mcp/hello?trace=1", got.uri)
	assert.Equal(t, []string{"Accept", "Content-Length", "Content-Type", "Last-Event-Id", "Mcp-Protocol-Version",
		"Mcp-Session-Id"}, headerNames(got.header), "no Authorization, cookie, hop-by-hop or forwarding header")
	assert.Equal(t, "application/json, text/event-stream", got.header.Get("Accept"))
	assert.Equal(t, "sess-42", got.header.Get("Mcp-Session-Id"))
	assert.Equal(t, "2025-06-18", got.header.Get("Mcp-Protocol-Version"))
	assert.Equal(t, "7", got.header.Get("Last-Event-ID"))
}

func TestHeaderCopiesAreTheirOwn(t *testing.T) {
	src := http.Header{"Mcp-Session-Id": {"a", "b"}, "Mcp-Param-X": {"1"}, "Content-Type": {"application/json"}}
	req, resp := http.Header{}, http.Header{}
	RequestHeaders(req, src)
	ResponseHeaders(resp, src)
	src["Mcp-Session-Id"][0] = "changed"
	src["Mcp-Param-X"][0] = "changed"
	assert.Equal(t, []string{"a", "b"}, req.Values("Mcp-Session-Id"), "every value, in a copy")
	assert.Equal(t, "1", req.Get("Mcp-Param-X"))
	assert.Equal(t, []string{"a", "b"}, resp.Values("Mcp-Session-Id"))
	assert.Equal(t, []string{"Content-Type", "Mcp-Session-Id"}, headerNames(resp))
}

func TestReadBody(t *testing.T) {
	read := func(r *http.Request) ([]byte, bool, *httptest.ResponseRecorder) {
		rec := httptest.NewRecorder()
		b, ok := ReadBody(rec, r)
		return b, ok, rec
	}
	exact := bytes.Repeat([]byte("a"), MaxBodyBytes)
	b, ok, _ := read(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp/x", bytes.NewReader(exact)))
	require.True(t, ok)
	assert.Len(t, b, MaxBodyBytes)

	over := bytes.Repeat([]byte("a"), MaxBodyBytes+1)
	tooLarge := `{"error":"invalid","message":"the request body is too large"}`
	_, ok, rec := read(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp/x", bytes.NewReader(over)))
	require.False(t, ok)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "with Content-Length")
	assert.Equal(t, tooLarge, rec.Body.String())

	chunked := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp/x", bytes.NewReader(over))
	chunked.ContentLength = -1 // the body runs over without saying so
	_, ok, rec = read(chunked)
	require.False(t, ok)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "chunked")
	assert.Equal(t, tooLarge, rec.Body.String())

	broken := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp/x",
		io.MultiReader(strings.NewReader("{"), iotest.ErrReader(errors.New("connection reset"))))
	broken.ContentLength = -1
	_, ok, rec = read(broken)
	require.False(t, ok)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var e httpsec.ErrorBody
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&e))
	assert.Equal(t, httpsec.CodeInvalid, e.Error)

	none := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/x", nil)
	none.Body = nil
	b, ok, _ = read(none)
	require.True(t, ok)
	assert.Empty(t, b)
}

// TestBodyCapThroughTheApplication: no oversized body reaches the server, chunked or not.
func TestBodyCapThroughTheApplication(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	over := bytes.Repeat([]byte("a"), MaxBodyBytes+1)
	a := h.do(t, h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", bytes.NewReader(over)))
	require.Equal(t, http.StatusRequestEntityTooLarge, a.status, "with Content-Length")
	chunked := h.request(t, http.MethodPost, "/mcp/hello", "Bearer tok-alice", struct{ io.Reader }{bytes.NewReader(over)})
	a = h.do(t, chunked)
	require.Equal(t, http.StatusRequestEntityTooLarge, a.status, "chunked")
	assert.Equal(t, httpsec.CodeInvalid, a.errorCode(t))
	assert.Empty(t, h.upstream.requests())
}
