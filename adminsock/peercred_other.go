//go:build !linux && !darwin

package adminsock

import (
	"errors"
	"net"
)

// peerUID cannot tell the peer's user on this platform, so every connection is refused.
func peerUID(net.Conn) (int, error) {
	return -1, errors.New("peer credentials are not supported on this platform")
}

// peerProcess cannot tell the peer process on this platform (no peer is accepted anyway).
func peerProcess(net.Conn) (int, string) { return 0, "" }

// peerChain cannot tell the peer's ancestors on this platform.
func peerChain(int) string { return "" }
