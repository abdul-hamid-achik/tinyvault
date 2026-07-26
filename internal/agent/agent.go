//go:build unix

package agent

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"charm.land/log/v2"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

// Supported reports whether the agent runs on this platform (unix only).
func Supported() bool { return true }

type agentState struct {
	opts     Options
	kek      []byte
	listener *net.UnixListener
	started  time.Time

	vaultMu sync.Mutex // serializes per-request vault opens (bbolt is single-writer)
	wg      sync.WaitGroup
	shut    sync.Once

	idleMu    sync.Mutex // guards idleTimer + idleAt
	idleTimer *time.Timer
	idleAt    time.Time

	requireToken bool
	tokenFile    string
	tokMu        sync.RWMutex
	tokens       map[string]tokenScope

	// lg is never nil: Start substitutes a discard logger when the caller
	// supplies none, so every call site can log unconditionally.
	lg *log.Logger
}

// Start runs the agent in the FOREGROUND, blocking until shutdown (a signal,
// the idle timeout, or a "stop" request). The KEK is zeroed on every exit
// path. The agent never daemonizes — forking a live Go runtime is unsafe;
// backgrounding (&, nohup, systemd Type=simple, launchd) is the caller's job.
func Start(opts Options) (err error) {
	defer crypto.ZeroBytes(opts.KEK) // belt-and-suspenders: zero on any return

	if perr := verifyDirPerms(opts.Dir); perr != nil {
		return perr
	}
	lock, lerr := acquireLock(opts.Dir)
	if lerr != nil {
		return lerr
	}
	defer releaseLock(lock, opts.Dir)

	l, serr := listen(opts.Dir)
	if serr != nil {
		return serr
	}

	lg := opts.Logger
	if lg == nil {
		// No destination configured: discard rather than defaulting to stderr,
		// which would corrupt a caller that reads the agent's output.
		lg = log.New(io.Discard)
	}
	a := &agentState{
		opts: opts, kek: opts.KEK, listener: l, started: time.Now(),
		requireToken: opts.RequireToken, tokenFile: opts.TokenFile, lg: lg,
	}
	if opts.RequireToken {
		toks, terr := loadTokens(opts.TokenFile)
		if terr != nil {
			_ = l.Close()
			return fmt.Errorf("--require-token: %w", terr)
		}
		a.tokens = toks
	}

	//nolint:errcheck // pidfile is diagnostics-only; flock is the real singleton
	os.WriteFile(pidPath(opts.Dir), []byte(strconv.Itoa(os.Getpid())), 0o600)
	defer os.Remove(pidPath(opts.Dir))

	// SIGHUP reloads the token file (revoke without restart); INT/TERM shut down.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	// Stop (no more sends) then close so the handler's range loop unblocks even
	// on a non-signal shutdown (idle/stop) — no leaked goroutine.
	defer func() { signal.Stop(sigCh); close(sigCh) }()
	go func() {
		for s := range sigCh {
			if s == syscall.SIGHUP {
				a.reloadTokens()
				continue
			}
			a.triggerShutdown()
			return
		}
	}()

	if opts.Idle > 0 {
		// Arm under idleMu so the timer assignment is synchronized with
		// triggerShutdown's locked read (the callback may fire concurrently).
		a.idleMu.Lock()
		a.idleAt = time.Now().Add(opts.Idle)
		a.idleTimer = time.AfterFunc(opts.Idle, a.triggerShutdown)
		a.idleMu.Unlock()
	}

	if opts.OnReady != nil {
		opts.OnReady(socketPath(opts.Dir), os.Getpid())
	}

	idle := "disabled"
	if opts.Idle > 0 {
		idle = opts.Idle.String()
	}
	lg.Info("agent listening",
		"socket", socketPath(opts.Dir),
		"pid", os.Getpid(),
		"vault_dir", opts.Dir,
		"project", opts.Project,
		"idle", idle,
		"require_token", opts.RequireToken,
	)

	a.acceptLoop()
	a.drain()
	// Logged before Start's deferred ZeroBytes so the record cannot outlive the
	// process without an explanation for why the agent stopped serving.
	lg.Info("agent stopped", "uptime", time.Since(a.started).Round(time.Second).String())
	return nil
}

func (a *agentState) acceptLoop() {
	for {
		conn, err := a.listener.AcceptUnix()
		if err != nil {
			return // listener closed by triggerShutdown
		}
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.handleConn(conn)
		}()
	}
}

// drain waits for in-flight handlers so the KEK is never zeroed while a
// request is still using it. The bound exceeds the per-connection deadline
// (connDeadline) so a handler blocked on a slow/withheld peer always finishes
// (or hits its own deadline) before we give up and zero the KEK.
func (a *agentState) drain() {
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(connDeadline + 2*time.Second):
	}
}

func (a *agentState) resetIdle() {
	a.idleMu.Lock()
	defer a.idleMu.Unlock()
	if a.idleTimer != nil {
		a.idleTimer.Reset(a.opts.Idle)
		a.idleAt = time.Now().Add(a.opts.Idle)
	}
}

func (a *agentState) idleRemaining() int {
	a.idleMu.Lock()
	defer a.idleMu.Unlock()
	if a.opts.Idle <= 0 || a.idleAt.IsZero() {
		return 0
	}
	if d := time.Until(a.idleAt); d > 0 {
		return int(d.Seconds())
	}
	return 0
}

func (a *agentState) triggerShutdown() {
	a.shut.Do(func() {
		a.idleMu.Lock()
		if a.idleTimer != nil {
			a.idleTimer.Stop()
		}
		a.idleMu.Unlock()
		_ = a.listener.Close() // unblocks acceptLoop; SetUnlinkOnClose removes the socket
	})
}
