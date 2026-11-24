package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

// apiError is an answer of the JSON error form, {"error":"<code>","message":"…"}. The message is English and never
// holds a secret.
type apiError struct {
	status     int
	code       string
	message    string
	retryAfter time.Duration // sent as Retry-After when positive
	ceremony   bool          // a passkey or ceremony that did not verify: counted against the finish limits
	cause      error         // a core sentinel the error stands for, so admin commands map it too
}

func (e *apiError) Error() string { return e.message }
func (e *apiError) Unwrap() error { return e.cause }

func newError(status int, code, message string) *apiError {
	return &apiError{status: status, code: code, message: message}
}

func invalid(format string, args ...any) *apiError {
	return newError(http.StatusBadRequest, httpsec.CodeInvalid, fmt.Sprintf(format, args...))
}

// The answers auth gives, by error code.
var (
	errNoSession = &apiError{status: http.StatusUnauthorized, code: httpsec.CodeNoSession, message: "sign in first",
		cause: core.ErrNoSession}
	errStepUp = &apiError{status: http.StatusForbidden, code: httpsec.CodeStepUp,
		message: "confirm with your passkey first", cause: core.ErrStepUpRequired}
	errCSRF = &apiError{status: http.StatusForbidden, code: httpsec.CodeForbidden, message: "cross-site request refused",
		cause: core.ErrForbidden}
	errToken = &apiError{status: http.StatusNotFound, code: httpsec.CodeNotFound,
		message: "the link is not valid: it is unknown, used, withdrawn or expired", cause: core.ErrNotFound}
	errPasskeyNotFound = &apiError{status: http.StatusNotFound, code: httpsec.CodeNotFound, message: "no such passkey",
		cause: core.ErrNotFound}
	errCeremony = &apiError{status: http.StatusBadRequest, code: httpsec.CodeInvalid,
		message: "the passkey ceremony expired or was already used; start again", ceremony: true}
	errNotVerified = &apiError{status: http.StatusBadRequest, code: httpsec.CodeInvalid,
		message: "the passkey did not verify", ceremony: true}
	errPasskeyExists = &apiError{status: http.StatusConflict, code: httpsec.CodeConflict,
		message: "this passkey is already registered", cause: core.ErrConflict}
	errLastPasskey = &apiError{status: http.StatusConflict, code: httpsec.CodeConflict,
		message: "this is your last passkey; add another one first", cause: core.ErrConflict}
	errNoPasskey = &apiError{status: http.StatusConflict, code: httpsec.CodeConflict,
		message: "you have no passkey of this hub to confirm with", cause: core.ErrConflict}
	errSuperadminExists = &apiError{status: http.StatusConflict, code: httpsec.CodeConflict,
		message: "the hub already has a superadmin", cause: core.ErrConflict}
	errSuperadminDisabled = &apiError{status: http.StatusConflict, code: httpsec.CodeConflict,
		message: "every superadmin of the hub is disabled", cause: core.ErrConflict}
	errBusy = newError(http.StatusTooManyRequests, httpsec.CodeRateLimited,
		"too many passkey ceremonies are in progress; try again in a minute")
	errInternal = newError(http.StatusInternalServerError, httpsec.CodeInternal, "internal error")
)

// errSuperadminHasPasskey refuses a setup link while the superadmin can sign in; it names the admin command that
// replaces their passkey.
func (a *Auth) errSuperadminHasPasskey() *apiError {
	return &apiError{status: http.StatusConflict, code: httpsec.CodeConflict,
		message: "the superadmin already has a passkey; `" + a.adminCLI + " reset-access` replaces it", cause: core.ErrConflict}
}

// reqState is what guard needs to learn from the handler after it ran: whether a finish's passkey or ceremony did
// not verify.
type reqState struct{ failed bool }

type reqStateKey struct{}

// fail writes err. Errors that are not an *apiError are logged and answered as 500 internal without their text.
func (a *Auth) fail(w http.ResponseWriter, r *http.Request, err error) {
	ae, ok := errors.AsType[*apiError](err)
	if !ok {
		a.log.Error("auth: request failed", slog.String("method", r.Method), slog.String("route", route(r)),
			slog.Any("error", err))
		ae = errInternal
	}
	if st, ok := r.Context().Value(reqStateKey{}).(*reqState); ok && ae.ceremony {
		st.failed = true
	}
	if ae.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(ae.retryAfter.Seconds()))))
	}
	httpsec.WriteError(w, ae.status, ae.code, ae.message)
}

// route is the path pattern a request matched, e.g. "/api/me/passkeys/{id}".
func route(r *http.Request) string {
	p := r.Pattern
	if _, path, ok := strings.Cut(p, " "); ok {
		p = path
	}
	return p
}

// withState returns r carrying a fresh reqState.
func withState(r *http.Request) (*http.Request, *reqState) {
	st := &reqState{}
	return r.WithContext(context.WithValue(r.Context(), reqStateKey{}, st)), st
}

// writeJSON answers v as JSON, the way the handlers always have: no trailing newline, HTML characters escaped.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		httpsec.WriteError(w, http.StatusInternalServerError, httpsec.CodeInternal, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// maxBody caps the request bodies of auth; a WebAuthn credential takes a few KiB.
const maxBody = 64 << 10

// decode reads a JSON object body into v. An empty body leaves v unchanged, so `{}` and nothing are the same. Unknown
// fields are ignored.
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return newError(http.StatusRequestEntityTooLarge, httpsec.CodeInvalid, "the request body is over 64 KiB")
		}
		return invalid("the request body could not be read")
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return newError(http.StatusUnsupportedMediaType, httpsec.CodeInvalid, "send application/json")
	}
	if body[0] != '{' {
		return invalid("the body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		if te, ok := errors.AsType[*json.UnmarshalTypeError](err); ok && te.Field != "" {
			return invalid("%s has the wrong type", te.Field)
		}
		return invalid("the body is not valid JSON")
	}
	if dec.More() {
		return invalid("the body holds more than one JSON value")
	}
	return nil
}

// timeFormat is RFC 3339 in UTC with milliseconds, the precision the store keeps.
const timeFormat = "2006-01-02T15:04:05.000Z07:00"

func rfc3339(t time.Time) string { return t.UTC().Format(timeFormat) }

// optTime is a time for JSON, or null when it is zero.
func optTime(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := rfc3339(t)
	return &s
}

func optTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	return optTime(*t)
}

// noStore keeps the answers of auth out of every cache.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
