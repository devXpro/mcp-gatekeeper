package httpsec

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// MountClean is a middleware for a gatekeeper package's handler (its http.ServeMux) mounted route by route under
// another router (review GK-19). It answers NotFound to a request whose path is not clean and passes the rest to next:
//   - a path that is empty or does not start with "/";
//   - a "." or ".." segment, or an empty one ("//"), which the mux would answer with a 307 to the cleaned path,
//     outside the application's own answers;
//   - an escaped "/" (%2F), which the outer router may take for part of a parameter while the mux does not.
//
// A ServeMux at the top of the application does not need it: its redirect sends the client through the whole chain
// again. The check is about consistency, not access: every guard of a package runs inside its handlers.
func MountClean(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cleanURLPath(r.URL) {
			NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cleanURLPath reports whether u's path is what ServeMux would route as it is: rooted, with no dot or empty segment
// (a trailing "/" is kept, as ServeMux keeps it) and no escaped "/".
func cleanURLPath(u *url.URL) bool {
	p := u.Path
	if p == "" || p[0] != '/' || strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") {
		return false
	}
	c := path.Clean(p)
	if c != "/" && strings.HasSuffix(p, "/") {
		c += "/"
	}
	return c == p
}
