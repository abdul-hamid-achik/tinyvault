//go:build unix

package cmd

import (
	"os"
	"syscall"
)

// ownedByCurrentUser reports whether info belongs to the effective uid.
func ownedByCurrentUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Geteuid()
}
