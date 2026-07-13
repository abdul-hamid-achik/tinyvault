// Package agent implements the tvault local agent: a foreground, single-user
// process that holds the vault's KEK in memory and answers read requests over
// a unix-domain socket, so day-to-day `tvault get/env/run` (and shell hooks)
// avoid re-deriving the KEK (Argon2id ~200ms) and re-prompting for the
// passphrase. It is unix-only (linux/darwin); other platforms get a clear
// "unsupported" error via build-tagged stubs.
//
// The agent caches ONLY the KEK — not an open database handle — and reopens
// the vault per request under a serializing mutex. bbolt takes an exclusive
// file lock, so holding the DB open would block every other tvault process
// (including writes and the --no-agent fallback); reopening briefly keeps
// direct access working between requests.
package agent

import "time"

// ProtocolVersion is the wire protocol version. A mismatching client is
// rejected with a clear error rather than mis-parsed.
const ProtocolVersion = 1

// MaxRequestBytes caps a single request line to prevent unbounded memory use
// from a malformed or hostile peer. MaxResponseBytes bounds a getall reply.
const (
	MaxRequestBytes  = 64 * 1024
	MaxResponseBytes = 16 * 1024 * 1024
)

// Options configures a starting agent. Defined here (no build tag) so the
// non-unix stub can reference it.
type Options struct {
	Dir     string        // vault dir; socket/lock/pid derive from it
	KEK     []byte        // cached KEK; the agent owns it and zeros it on every exit path
	Project string        // current project (for status display only)
	Idle    time.Duration // 0 = never auto-lock
	OnReady func(socket string, pid int)
	// RequireToken, when true, denies any socket request that does not carry a
	// valid capability token from TokenFile — a privilege-separation gate for a
	// delegate the OS confines from the raw socket (a different uid / container
	// / sandbox). It is NOT a control against a same-uid attacker, who can read
	// the token or dial the socket directly. See
	// docs/reference/security.md#token-honesty.
	RequireToken bool
	TokenFile    string // 0600 file of `token[:project]` lines (require-token mode)
}

// Request is one newline-delimited JSON request. One request → one response
// per connection, then the connection closes (no pipelining).
type Request struct {
	V       int    `json:"v"`
	Op      string `json:"op"` // "get" | "getall" | "status" | "stop"
	Project string `json:"project,omitempty"`
	Key     string `json:"key,omitempty"`
	// Token is an optional capability token (TVAULT_AGENT_TOKEN). It is ignored
	// unless the agent runs with --require-token; the field is omitempty so a
	// token-less client is byte-identical to before (no protocol bump needed).
	Token string `json:"token,omitempty"`
}

// Response is the agent's reply. Value/Secrets are present only for get/getall.
type Response struct {
	V       int               `json:"v"`
	OK      bool              `json:"ok"`
	Value   string            `json:"value,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
	Project string            `json:"project,omitempty"` // the resolved project (for empty-project requests)
	Status  *StatusInfo       `json:"status,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// StatusInfo is returned by the "status" op.
type StatusInfo struct {
	PID                  int    `json:"pid"`
	Socket               string `json:"socket"`
	Project              string `json:"project"`
	UptimeSeconds        int    `json:"uptime_seconds"`
	IdleRemainingSeconds int    `json:"idle_remaining_seconds"`
}

// Op constants.
const (
	OpGet    = "get"
	OpGetAll = "getall"
	OpStatus = "status"
	OpStop   = "stop"
)
