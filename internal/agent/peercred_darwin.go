//go:build darwin

package agent

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of a unix socket
// connection (darwin: LOCAL_PEERCRED).
func peerUID(uc *net.UnixConn) (uint32, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var sockErr error
	if cerr := raw.Control(func(fd uintptr) {
		xu, gerr := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if gerr != nil {
			sockErr = gerr
			return
		}
		uid = xu.Uid
	}); cerr != nil {
		return 0, cerr
	}
	if sockErr != nil {
		return 0, fmt.Errorf("getsockopt LOCAL_PEERCRED: %w", sockErr)
	}
	return uid, nil
}

// peerPID is unavailable via LOCAL_PEERCRED on darwin; return 0.
func peerPID(_ *net.UnixConn) int { return 0 }
