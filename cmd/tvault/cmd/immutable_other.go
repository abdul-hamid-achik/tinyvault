//go:build !(darwin || freebsd || netbsd || openbsd || dragonfly)

package cmd

// setImmutable is unsupported here: Linux's immutable attribute (chattr +i)
// needs CAP_LINUX_IMMUTABLE, and Windows has no equivalent. Clearing is a
// no-op so rotation still works.
func setImmutable(_ string, on bool) error {
	if !on {
		return nil
	}
	return errImmutableUnsupported
}
