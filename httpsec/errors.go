// Package httpsec holds the HTTP plumbing every gatekeeper package shares: the JSON error form, security headers,
// the request log and the client-address rules.
//
// errors.go is frozen (docs/PLAN.md §4.1); the rest of the package belongs to card G5.
package httpsec

import (
	"encoding/json"
	"net/http"
)

// Error codes of the JSON error form {"error":"<code>","message":"…"} (docs/PLAN.md §4.4).
const (
	CodeNoSession    = "no_session"
	CodeStepUp       = "step_up_required"
	CodeForbidden    = "forbidden"
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"
	CodeInvalid      = "invalid"
	CodeRateLimited  = "rate_limited"
	CodeUpstream     = "upstream"
	CodeUnauthorized = "unauthorized" // no token
	CodeInvalidToken = "invalid_token"
	CodeInternal     = "internal"
	CodeOtherBrowser = "other_browser" // a consent transaction opened in another browser
)

// ErrorBody is the JSON error form. Message is English and never holds a secret.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// WriteError answers with the JSON error form and Cache-Control: no-store. The body is json.Marshal's, without a
// trailing newline, byte for byte what Family Hub's Gin wrote.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	b, _ := json.Marshal(ErrorBody{Error: code, Message: message}) //nolint:errchkjson // two strings always marshal
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
