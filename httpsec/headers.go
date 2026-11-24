package httpsec

import "net/http"

// HSTSValue is the Strict-Transport-Security header: a year, without includeSubDomains or preload (the domain belongs
// to the application's owner, who may serve other things on its subdomains).
const HSTSValue = "max-age=31536000"

// DefaultCSP is the strict Content-Security-Policy Family Hub ships for its SPA: no inline script or style, no eval,
// everything from the page's own origin, no framing. An application passes its own policy where it needs more; it
// should stay at least this tight.
const DefaultCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'self'; " +
	"frame-ancestors 'none'"

// SetSecurityHeaders sets the headers every page carries: the CSP csp, nosniff, Referrer-Policy: no-referrer,
// X-Frame-Options: DENY and HSTS. coop adds Cross-Origin-Opener-Policy: same-origin; leave it off for a page that
// runs inside an assistant's connector window (the consent page), where COOP would cut the window's tie to the
// assistant's page.
func SetSecurityHeaders(h http.Header, csp string, coop bool) {
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Strict-Transport-Security", HSTSValue)
	if coop {
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
	}
}

// SecurityHeaders is a middleware that sets SetSecurityHeaders (with COOP) on every answer of next.
func SecurityHeaders(csp string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			SetSecurityHeaders(w.Header(), csp, true)
			next.ServeHTTP(w, r)
		})
	}
}

// SetNoStore marks the answer as uncacheable: Cache-Control: no-store.
func SetNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

// NoStore is a middleware that sends Cache-Control: no-store on every answer of next (a handler may still replace
// it).
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetNoStore(w)
		next.ServeHTTP(w, r)
	})
}
