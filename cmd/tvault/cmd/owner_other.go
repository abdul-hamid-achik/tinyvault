//go:build !unix

package cmd

import "os"

// ownedByCurrentUser has no portable owner check off Unix; the mode check in
// checkConfigTrusted and the user-profile location of the file carry it.
func ownedByCurrentUser(os.FileInfo) bool { return true }
