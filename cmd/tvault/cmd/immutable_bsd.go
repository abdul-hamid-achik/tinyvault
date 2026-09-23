//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package cmd

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// setImmutable sets or clears the user-immutable flag (UF_IMMUTABLE, what
// `chflags uchg` sets). While set, the file cannot be modified, renamed, or
// deleted — `rm -rf` fails with "Operation not permitted" — until its owner
// clears it (`chflags nouchg`). It is a guard against accidents and careless
// automation, not against a process that deliberately clears the flag.
func setImmutable(path string, on bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot read flags of %s", errImmutableUnsupported, path)
	}
	flags := st.Flags
	if on {
		flags |= unix.UF_IMMUTABLE
	} else {
		flags &^= unix.UF_IMMUTABLE
	}
	if flags == st.Flags {
		return nil
	}
	return unix.Chflags(path, int(flags))
}
