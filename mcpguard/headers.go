package mcpguard

import (
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

// SessionHeader is the MCP session id (Streamable HTTP, session management). It passes both ways; an application
// that binds session ids to a grant (Family Hub) unwraps it in the request before RequestHeaders and wraps it in the
// answer after ResponseHeaders.
const SessionHeader = "Mcp-Session-Id"

// MaxBodyBytes is the largest request body ReadBody takes.
const MaxBodyBytes = 1 << 20

// The headers that pass between an assistant and an MCP server, and nothing else: Authorization, cookies, the
// hop-by-hop headers, forwarding headers and everything else stay behind. A server's Cache-Control never passes:
// SecureHeaders and Relay set the application's own on every answer, so that no cache in front of it (Cloudflare)
// keeps one family's answer for the next caller of the same URL.
var (
	// Mcp-Method and Mcp-Name, with the Mcp-Param- headers, are the routing headers of MCP 2026-07-28, which ChatGPT
	// speaks: an MCP server's SDK checks them against the body and answers 400 when they are missing.
	requestHeaders = []string{"Content-Type", "Accept", SessionHeader, "Mcp-Protocol-Version", "Last-Event-ID",
		"Mcp-Method", "Mcp-Name"}
	requestPrefixes = []string{"Mcp-Param-"} // canonical form
	responseHeaders = []string{"Content-Type", SessionHeader}
)

// RequestHeaders copies to dst the assistant's request headers in src that an MCP server may see: Content-Type,
// Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID, Mcp-Method, Mcp-Name and every Mcp-Param-<name>.
func RequestHeaders(dst, src http.Header) {
	copyHeaders(dst, src, requestHeaders)
	copyHeaderPrefixes(dst, src, requestPrefixes)
}

// ResponseHeaders copies to dst the MCP server's answer headers in src that the assistant may see: Content-Type and
// Mcp-Session-Id.
func ResponseHeaders(dst, src http.Header) {
	copyHeaders(dst, src, responseHeaders)
}

// copyHeaders copies the named headers, and only them, from src to dst.
func copyHeaders(dst, src http.Header, names []string) {
	for _, n := range names {
		if vs := src.Values(n); len(vs) > 0 {
			dst[http.CanonicalHeaderKey(n)] = slices.Clone(vs)
		}
	}
}

// copyHeaderPrefixes copies the headers of src whose canonical name starts with one of prefixes and is longer.
func copyHeaderPrefixes(dst, src http.Header, prefixes []string) {
	for k, vs := range src {
		k = http.CanonicalHeaderKey(k)
		for _, p := range prefixes {
			if len(k) > len(p) && strings.HasPrefix(k, p) {
				dst[k] = slices.Clone(vs)
				break
			}
		}
	}
}

// ReadBody buffers the request body: 413 above MaxBodyBytes, whether Content-Length says so or the body runs over,
// and 400 when it cannot be read. ok is false once an answer is written.
func ReadBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.ContentLength > MaxBodyBytes {
		httpsec.WriteError(w, http.StatusRequestEntityTooLarge, httpsec.CodeInvalid, "the request body is too large")
		return nil, false
	}
	if r.Body == nil {
		return nil, true
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		httpsec.WriteError(w, http.StatusBadRequest, httpsec.CodeInvalid, "the request body cannot be read")
		return nil, false
	}
	if len(b) > MaxBodyBytes {
		httpsec.WriteError(w, http.StatusRequestEntityTooLarge, httpsec.CodeInvalid, "the request body is too large")
		return nil, false
	}
	return b, true
}
