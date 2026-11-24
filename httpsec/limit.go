package httpsec

import "net/http"

// MaxBody is the default cap on a request body. An application's own, smaller limit (Family Hub's MCP gateway) stays
// below it, so that limit's own 413 still answers.
const MaxBody = 2 << 20

// BodyLimit refuses a declared body above limit at once with 413 {"error":"invalid"} and caps the rest while it is
// read (the reader then fails with *http.MaxBytesError).
func BodyLimit(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				WriteError(w, http.StatusRequestEntityTooLarge, CodeInvalid, "request body too large")
				return
			}
			if r.Body != nil && r.Body != http.NoBody {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}
