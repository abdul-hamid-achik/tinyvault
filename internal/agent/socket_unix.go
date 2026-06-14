//go:build unix

package agent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxSocketPath is the conservative sun_path limit (darwin 104, linux 108).
const maxSocketPath = 104

func socketPath(dir string) string { return filepath.Join(dir, SocketName) }
func pidPath(dir string) string    { return filepath.Join(dir, pidName) }

// acquireLock takes an exclusive, non-blocking flock on the agent lockfile.
// The returned file is held for the agent's lifetime (the authoritative
// single-instance guard); ErrAgentAlreadyRunning means another agent owns it.
func acquireLock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, lockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lockfile: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, ErrAgentAlreadyRunning
	}
	return f, nil
}

func releaseLock(f *os.File, dir string) {
	if f == nil {
		return
	}
	_ = f.Close() // closing the fd releases the flock
	_ = os.Remove(filepath.Join(dir, lockName))
}

// verifyDirPerms ensures the vault dir is 0700 and owned by us — the agent's
// socket security rests on the directory being private.
func verifyDirPerms(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("vault dir %s is group/world-accessible (mode %#o); run: chmod 700 %s", dir, fi.Mode().Perm(), dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("vault dir %s is not owned by the current user", dir)
	}
	return nil
}

// listen creates the agent's unix socket with tight permissions. The caller
// must already hold the agent lock so stale-socket cleanup is race-free.
func listen(dir string) (*net.UnixListener, error) {
	path := socketPath(dir)
	if len(path) >= maxSocketPath {
		return nil, fmt.Errorf("%w: %q is %d bytes (max %d)", ErrSocketPathTooLong, path, len(path), maxSocketPath-1)
	}
	// Remove a stale socket only if it is a socket we own; never touch a path
	// of a different type or owner.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket file at %s", path)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Geteuid()) {
			return nil, fmt.Errorf("refusing to replace socket owned by another user at %s", path)
		}
		_ = os.Remove(path)
	}
	// Tight umask so the inode is created 0600 with no listen→chmod window.
	old := unix.Umask(0o077)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", path, err)
	}
	l.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return l, nil
}
