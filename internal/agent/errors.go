package agent

import "errors"

var (
	// ErrUnsupportedPlatform is returned by the agent on non-unix platforms.
	ErrUnsupportedPlatform = errors.New("tvault agent is unix-only (linux/macOS); use the direct CLI or mcp on this platform")

	// ErrAgentNotRunning is returned by Stop/Status when no agent is listening.
	ErrAgentNotRunning = errors.New("tvault agent is not running")

	// ErrAgentAlreadyRunning is returned by Start when another agent holds the lock.
	ErrAgentAlreadyRunning = errors.New("tvault agent is already running (run: tvault agent stop)")

	// ErrSocketPathTooLong is returned when the socket path exceeds the OS limit.
	ErrSocketPathTooLong = errors.New("socket path too long; shorten TVAULT_DIR")
)

// SocketName is the agent socket filename inside the vault dir.
const SocketName = "agent.sock"

// pidName / lockName are the agent's pidfile and lockfile inside the vault dir.
const (
	pidName  = "agent.pid"
	lockName = "agent.lock"
)
