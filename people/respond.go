package people

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/httpsec"
)

// APIError is an answer of the JSON error form {"error":"<code>","message":"…"} (httpsec). The message is English
// and never holds a secret or application data. Extra adds fields to the body (Family Hub: "module" and "reason"
// of a module that did not erase an account); it never replaces "error" or "message".
type APIError struct {
	Status  int
	Code    string
	Message string
	Extra   map[string]string
}

func (e *APIError) Error() string { return e.Message }

// NewError returns an *APIError.
func NewError(status int, code, message string) *APIError {
	return &APIError{Status: status, Code: code, Message: message}
}

func invalid(message string) *APIError {
	return NewError(http.StatusBadRequest, httpsec.CodeInvalid, message)
}

// Refusals an application's extension may answer with, so they read exactly as this package's own.
var (
	// ErrOwnerOnly is 403 forbidden for a member where only the owner may act.
	ErrOwnerOnly = NewError(http.StatusForbidden, httpsec.CodeForbidden, "only the owner of the account may do this")
	// ErrSuperadminOnly is 403 forbidden for anyone but the superadmin.
	ErrSuperadminOnly = NewError(http.StatusForbidden, httpsec.CodeForbidden, "only the superadmin may do this")
	// ErrNoConnection is 404 not_found for a connection the viewer may not see or that is gone.
	ErrNoConnection = NewError(http.StatusNotFound, httpsec.CodeNotFound, "no such connection")

	errInternal = NewError(http.StatusInternalServerError, httpsec.CodeInternal, "internal error")
)

// writeError answers ae with Cache-Control: no-store.
func writeError(w http.ResponseWriter, ae *APIError) {
	if len(ae.Extra) == 0 {
		httpsec.WriteError(w, ae.Status, ae.Code, ae.Message)
		return
	}
	// "error" and "message" first, then the extra fields by name; no trailing newline, as httpsec.WriteError (Family
	// Hub's Gin wrote these bodies with json.Marshal).
	var b bytes.Buffer
	b.WriteString("{")
	field := func(k, v string) {
		if b.Len() > 1 {
			b.WriteString(",")
		}
		kj, _ := json.Marshal(k)
		vj, _ := json.Marshal(v)
		b.Write(kj)
		b.WriteString(":")
		b.Write(vj)
	}
	field("error", ae.Code)
	field("message", ae.Message)
	for _, k := range slices.Sorted(maps.Keys(ae.Extra)) {
		if k != "error" && k != "message" {
			field(k, ae.Extra[k])
		}
	}
	b.WriteString("}")
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(ae.Status)
	_, _ = w.Write(b.Bytes())
}

// fail answers err in the JSON error form. Errors it cannot classify are logged and answered 500 internal without
// their text.
func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	ae := classify(err)
	if ae == nil {
		s.log.Error("people: request failed", "method", r.Method, "route", r.Pattern, "err", err)
		ae = errInternal
	}
	writeError(w, ae)
}

func classify(err error) *APIError {
	if ae, ok := errors.AsType[*APIError](err); ok {
		return ae
	}
	switch {
	case errors.Is(err, ErrSelf):
		return invalid("you cannot remove yourself")
	case errors.Is(err, ErrWidens):
		// updateMember retries behind step-up; this only answers a caller that did not.
		return NewError(http.StatusForbidden, httpsec.CodeStepUp, "confirm with your passkey")
	case errors.Is(err, ErrSuperadmin):
		return NewError(http.StatusConflict, httpsec.CodeConflict, "a superadmin cannot be removed from an account")
	case errors.Is(err, ErrInvalidName):
		return invalid(lastPart(err))
	case errors.Is(err, core.ErrNotFound):
		return NewError(http.StatusNotFound, httpsec.CodeNotFound, "not found")
	case errors.Is(err, core.ErrConflict):
		return NewError(http.StatusConflict, httpsec.CodeConflict, "conflict")
	case errors.Is(err, core.ErrForbidden):
		return NewError(http.StatusForbidden, httpsec.CodeForbidden, "forbidden")
	}
	return nil
}

// lastPart is the text of a refusal without the package prefix in front of it.
func lastPart(err error) string {
	msg := err.Error()
	for _, prefix := range []string{"people: ", "modules: ", "auth: "} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return msg
}

// maxBody caps request bodies.
const maxBody = 256 << 10

// decode reads a JSON object body into v. An empty body leaves v unchanged; unknown fields are ignored.
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return NewError(http.StatusRequestEntityTooLarge, httpsec.CodeInvalid, "the request body is too large")
		}
		return invalid("the request body could not be read")
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return NewError(http.StatusUnsupportedMediaType, httpsec.CodeInvalid, "send application/json")
	}
	if body[0] != '{' {
		return invalid("the body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		if te, ok := errors.AsType[*json.UnmarshalTypeError](err); ok && te.Field != "" {
			return invalid(te.Field + " has the wrong type")
		}
		return invalid("the body is not valid JSON")
	}
	if dec.More() {
		return invalid("the body holds more than one JSON value")
	}
	return nil
}

// writeJSON answers 200 with v.
func (s *Service) writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeRaw(w, raw)
}

// writeRaw answers 200 with the JSON document raw.
func writeRaw(w http.ResponseWriter, raw []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw) //nolint:gosec // G705: JSON marshalled here, sent as application/json with nosniff
}

// timeFormat is RFC 3339 in UTC with milliseconds, as package auth answers.
const timeFormat = "2006-01-02T15:04:05.000Z07:00"

func rfc3339(t time.Time) string { return t.UTC().Format(timeFormat) }

func optTime(t *time.Time) *string {
	if t == nil || t.IsZero() {
		return nil
	}
	s := rfc3339(*t)
	return &s
}

// NoStore keeps every answer of next out of caches.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// RequireOwner lets only the account's owner through (403 forbidden). It runs after core.Sessions.RequireViewer.
func RequireOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if viewer(r).Person.Role != core.RoleOwner {
			writeError(w, ErrOwnerOnly)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSuperadmin lets only the superadmin through (403 forbidden). It runs after core.Sessions.RequireViewer.
func RequireSuperadmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !viewer(r).Person.Superadmin {
			writeError(w, ErrSuperadminOnly)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// viewer is the signed-in person RequireViewer stored.
func viewer(r *http.Request) core.Viewer {
	v, _ := core.ViewerFrom(r.Context())
	return v
}

func noContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }
