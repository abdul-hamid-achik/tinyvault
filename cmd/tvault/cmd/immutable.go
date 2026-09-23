package cmd

import "errors"

// errImmutableUnsupported reports that this platform cannot mark a snapshot
// immutable for an unprivileged user.
var errImmutableUnsupported = errors.New("immutable snapshots are not supported on this platform")
