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

// LoopbackPeers is the network of a connector on the same machine (cloudflared run by the application itself):
// 127.0.0.0/8 and ::1/128, for PeerOptions.Trusted or Options.Trusted. An IPv4-mapped peer (::ffff:127.0.0.1) counts
// as its IPv4 address. Each call returns a new slice.
//
// Trust it only on a listener bound to loopback: any process on the machine can then name the client, and is trusted
// as much as the user it runs as anyway.
func LoopbackPeers() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
}

// PeerGuard keeps a request from claiming more than its TCP peer is. A peer outside Trusted does not get to name the
// client: its CF-Connecting-IP and X-Forwarded-For headers are deleted, so core.ClientIP, which runs later in the
// handlers and in the request log, falls back to the peer. A peer in Refused is answered with 403. An address that
// does not parse (no TCP peer) is neither trusted nor refused. With no Trusted prefixes nothing is believed.
//
// A Site whose ClientIP mode reads a header (core.ClientIPCloudflare, core.ClientIPForwarded) needs this guard with
// Trusted holding only the connector's or proxy's address, or any client names its own address to the per-address
// limits and the audit (review GK-2). A connector on the same machine: LoopbackPeers, and listen on loopback only, so
// that every request comes through it; a request that arrives without the header is counted by its TCP peer, which
// would then be the same for every client.
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
