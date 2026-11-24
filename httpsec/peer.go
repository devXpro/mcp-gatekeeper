package httpsec

import (
	"net/http"
	"net/netip"
)

// PeerOptions are the rules PeerGuard applies by the TCP peer of a request.
type PeerOptions struct {
	// Trusted are the peers allowed to say who the client is (CF-Connecting-IP, X-Forwarded-For): the network
	// where cloudflared or the host's reverse proxy reaches the application. Nothing else is believed.
	Trusted []netip.Prefix
	// Refused are peers that get 403 {"error":"forbidden"} and nothing else (Family Hub: its module networks;
	// modules never call the hub). Optional.
	Refused []netip.Prefix
	// RefusedMessage is the message of that 403; "" is "peer not allowed".
	RefusedMessage string
}

// PeerGuard keeps a request from claiming more than its TCP peer is. A peer outside Trusted does not get to name the
// client: its CF-Connecting-IP and X-Forwarded-For headers are deleted, so core.ClientIP, which runs later in the
// handlers and in the request log, falls back to the peer. A peer in Refused is answered with 403. An address that
// does not parse (no TCP peer) is neither trusted nor refused. With no Trusted prefixes nothing is believed.
func PeerGuard(o PeerOptions) func(http.Handler) http.Handler {
	msg := o.RefusedMessage
	if msg == "" {
		msg = "peer not allowed"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, ok := peerAddr(r.RemoteAddr)
			if !ok || !contains(o.Trusted, peer) {
				r.Header.Del("CF-Connecting-IP")
				r.Header.Del("X-Forwarded-For")
			}
			if ok && contains(o.Refused, peer) {
				// The headers are gone already, so the request log names the refused peer's own address.
				WriteError(w, http.StatusForbidden, CodeForbidden, msg)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// peerAddr is the IP of a "host:port" remote address; an IPv4-mapped IPv6 address becomes IPv4.
func peerAddr(remote string) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

func contains(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
