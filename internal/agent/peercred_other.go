//go:build unix && !linux && !darwin

package agent

import "net"

// peerUID fails closed on unix platforms without a peer-credential
// implementation: every connection is rejected rather than silently trusted.
func peerUID(_ *net.UnixConn) (uint32, error) {
	return 0, ErrUnsupportedPlatform
}

func peerPID(_ *net.UnixConn) int { return 0 }
