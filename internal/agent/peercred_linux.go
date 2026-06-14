//go:build linux

package agent

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of a unix socket
// connection (linux: SO_PEERCRED).
func peerUID(uc *net.UnixConn) (uint32, error) {
	cred, err := peerCred(uc)
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}

// peerPID returns the pid of the connecting peer (linux only; best-effort).
func peerPID(uc *net.UnixConn) int {
	cred, err := peerCred(uc)
	if err != nil {
		return 0
	}
	return int(cred.Pid)
}

func peerCred(uc *net.UnixConn) (*unix.Ucred, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var sockErr error
	if cerr := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil {
		return nil, cerr
	}
	if sockErr != nil {
		return nil, fmt.Errorf("getsockopt SO_PEERCRED: %w", sockErr)
	}
	return cred, nil
}
