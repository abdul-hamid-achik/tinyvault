//go:build unix

package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// startTestAgent creates a vault with some secrets and starts an agent over a
// temp dir, returning the dir and a stop func. It blocks until the agent is
// listening.
func startTestAgent(t *testing.T, idle time.Duration) (string, func()) {
	dir, _, stop := startTestAgentKEK(t, idle)
	return dir, stop
}

// startTestAgentKEK also returns the KEK slice passed to Start (which the agent
// aliases and zeros on exit), so tests can assert it is wiped after shutdown.
func startTestAgentKEK(t *testing.T, idle time.Duration) (string, []byte, func()) {
	t.Helper()
	// A short base dir: t.TempDir() embeds the (long) test name and can push
	// the socket path past the ~104-byte sun_path limit on macOS.
	dir, err0 := os.MkdirTemp("", "tva")
	if err0 != nil {
		t.Fatal(err0)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Create(dir, "pw")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	for k, val := range map[string]string{"DB_URL": "postgres://x", "API_KEY": "sk_live"} {
		if serr := v.SetSecret("default", k, val); serr != nil {
			t.Fatal(serr)
		}
	}
	kek, err := v.KEK()
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Start(Options{
			Dir: dir, KEK: kek, Project: "default", Idle: idle,
			OnReady: func(sock string, _ int) { ready <- sock },
		})
	}()
	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("agent failed to start: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not become ready")
	}
	stop := func() {
		if c, derr := Dial(dir, time.Second); derr == nil {
			_ = c.Stop()
		}
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
			t.Error("agent did not shut down")
		}
	}
	return dir, kek, stop
}

func TestAgentGetGetAllStatus(t *testing.T) {
	dir, stop := startTestAgent(t, 0)
	defer stop()

	c, err := Dial(dir, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if v, gerr := c.Get("default", "DB_URL"); gerr != nil || v != "postgres://x" {
		t.Errorf("Get = %q (err %v)", v, gerr)
	}
	// Empty project resolves to current ("default").
	if v, gerr := c.Get("", "API_KEY"); gerr != nil || v != "sk_live" {
		t.Errorf("Get empty-project = %q (err %v)", v, gerr)
	}
	secrets, proj, gerr := c.GetAll("default")
	if gerr != nil || secrets["DB_URL"] != "postgres://x" || secrets["API_KEY"] != "sk_live" {
		t.Errorf("GetAll = %v (err %v)", secrets, gerr)
	}
	if proj != "default" {
		t.Errorf("resolved project = %q, want default", proj)
	}
	st, serr := c.Status()
	if serr != nil || st.Project != "default" || st.PID == 0 {
		t.Errorf("Status = %+v (err %v)", st, serr)
	}
}

func TestAgentSocketAndDirPerms(t *testing.T) {
	dir, stop := startTestAgent(t, 0)
	defer stop()

	fi, err := os.Stat(socketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %#o, want 0600", fi.Mode().Perm())
	}
}

func TestAgentProjectScoping(t *testing.T) {
	dir, stop := startTestAgent(t, 0)
	defer stop()

	// Add a separate project with its own secret via a direct (no-agent) open;
	// the agent reopens per request so this is allowed once we're between calls.
	kek := mustKEK(t, dir) // acquire before opening v (only one bbolt handle at a time)
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if uerr := v.UnlockWithKEK(kek); uerr != nil {
		t.Fatal(uerr)
	}
	if _, perr := v.CreateProject("prod", ""); perr != nil {
		t.Fatal(perr)
	}
	if serr := v.SetSecret("prod", "PROD_ONLY", "p"); serr != nil {
		t.Fatal(serr)
	}
	_ = v.Close()

	c, _ := Dial(dir, time.Second)
	secrets, _, gerr := c.GetAll("prod")
	if gerr != nil {
		t.Fatalf("GetAll prod: %v", gerr)
	}
	if _, leaked := secrets["DB_URL"]; leaked {
		t.Error("prod getall leaked a default-project secret")
	}
	if secrets["PROD_ONLY"] != "p" {
		t.Errorf("prod getall missing its own secret: %v", secrets)
	}
}

func TestAgentProtocolRobustness(t *testing.T) {
	dir, stop := startTestAgent(t, 0)
	defer stop()

	// Oversized request → rejected (an error response, or the agent drops the
	// connection mid-write — either way it is not accepted).
	t.Run("oversized", func(t *testing.T) {
		if !agentRejects(t, dir, strings.Repeat("A", MaxRequestBytes+10)) {
			t.Error("agent should reject an oversized request")
		}
	})
	// Malformed JSON → invalid request, no crash.
	t.Run("malformed", func(t *testing.T) {
		resp := rawRequest(t, dir, "{not json")
		if resp.OK || resp.Error == "" {
			t.Errorf("malformed: %+v", resp)
		}
	})
	// Wrong protocol version → mismatch error.
	t.Run("version", func(t *testing.T) {
		resp := rawRequest(t, dir, `{"v":999,"op":"status"}`)
		if resp.OK || !strings.Contains(resp.Error, "version mismatch") {
			t.Errorf("version: %+v", resp)
		}
	})
	// Agent still serves a valid request afterward (didn't die).
	c, _ := Dial(dir, time.Second)
	if _, err := c.Status(); err != nil {
		t.Errorf("agent unresponsive after bad requests: %v", err)
	}
}

func TestAgentSingleton(t *testing.T) {
	dir, stop := startTestAgent(t, 0)
	defer stop()

	err := Start(Options{Dir: dir, KEK: mustKEK(t, dir), Idle: 0})
	if err == nil || err != ErrAgentAlreadyRunning {
		t.Errorf("second Start should be ErrAgentAlreadyRunning, got %v", err)
	}
}

func TestAgentIdleExit(t *testing.T) {
	dir, _ := startTestAgent(t, 150*time.Millisecond)
	// No requests → the agent idle-exits and removes its socket.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath(dir)); os.IsNotExist(err) {
			return // idle-exit cleaned up
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("agent did not idle-exit / clean up its socket")
}

func TestAgentStopRemovesSocket(t *testing.T) {
	dir, stop := startTestAgent(t, 0)
	stop()
	if _, err := os.Stat(socketPath(dir)); !os.IsNotExist(err) {
		t.Error("socket should be removed after stop")
	}
}

func TestPeerUIDIsSelf(t *testing.T) {
	dir, stop := startTestAgent(t, 0)
	defer stop()
	conn, err := dialUnix(socketPath(dir), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uid, err := peerUID(conn.(*net.UnixConn))
	if err != nil {
		t.Fatalf("peerUID: %v", err)
	}
	if uid != uint32(os.Geteuid()) {
		t.Errorf("peerUID = %d, want %d", uid, os.Geteuid())
	}
}

func isZeroed(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func TestKEKZeroedAfterStop(t *testing.T) {
	_, kek, stop := startTestAgentKEK(t, 0)
	if isZeroed(kek) {
		t.Fatal("kek should be non-zero while running")
	}
	stop()
	if !isZeroed(kek) {
		t.Error("KEK must be zeroed after stop")
	}
}

func TestKEKZeroedAfterIdle(t *testing.T) {
	dir, kek, _ := startTestAgentKEK(t, 150*time.Millisecond)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath(dir)); os.IsNotExist(err) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Small grace for the deferred zeroing after acceptLoop/drain return.
	time.Sleep(100 * time.Millisecond)
	if !isZeroed(kek) {
		t.Error("KEK must be zeroed after idle exit")
	}
}

func TestStaleKEKAfterRotationRejected(t *testing.T) {
	dir, stop := startTestAgent(t, 0)
	defer stop()

	// Rotate the passphrase out from under the agent (its cached KEK is now stale).
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rerr := v.RotatePassphrase("pw", "new-pw-123"); rerr != nil {
		t.Fatal(rerr)
	}
	_ = v.Close()

	c, _ := Dial(dir, time.Second)
	if _, gerr := c.Get("default", "DB_URL"); gerr == nil {
		t.Error("get with a stale (pre-rotation) KEK must fail")
	}
	// The agent is still alive (didn't crash) and serves status.
	if _, serr := c.Status(); serr != nil {
		t.Errorf("agent should survive a stale-KEK request: %v", serr)
	}
}

func TestSocketPathTooLong(t *testing.T) {
	long := "/" + strings.Repeat("a", maxSocketPath+10)
	if _, err := listen(long); err == nil {
		t.Error("over-long socket path should be rejected")
	}
}

func TestStaleSocketNonSocketRefused(t *testing.T) {
	dir, err := os.MkdirTemp("", "tvs")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0o700)
	// Plant a regular file where the socket would go.
	if werr := os.WriteFile(socketPath(dir), []byte("x"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	if _, lerr := listen(dir); lerr == nil {
		t.Error("listen should refuse to replace a non-socket file")
	}
}

func TestStaleSocketOursRemoved(t *testing.T) {
	dir, err := os.MkdirTemp("", "tvs")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0o700)
	// Leave a stale socket file (own it; disable unlink-on-close).
	l0, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath(dir), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l0.SetUnlinkOnClose(false)
	_ = l0.Close()
	if _, serr := os.Stat(socketPath(dir)); serr != nil {
		t.Skip("platform removed the socket on close; stale-path case not reproducible here")
	}
	// listen must clean up our own stale socket and succeed.
	l, lerr := listen(dir)
	if lerr != nil {
		t.Fatalf("listen over our own stale socket: %v", lerr)
	}
	_ = l.Close()
}

func TestAuditLogsAgentReads(t *testing.T) {
	dir, stop := startTestAgent(t, 0)
	defer stop()
	c, _ := Dial(dir, time.Second)
	if _, err := c.Get("default", "DB_URL"); err != nil {
		t.Fatal(err)
	}

	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	entries, err := v.ListAudit(store.AuditFilter{Action: "secret.read"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Metadata["via"] == "agent" {
			found = true
			if e.Metadata["peer_uid"] == nil {
				t.Error("agent audit entry missing peer_uid")
			}
		}
	}
	if !found {
		t.Error("expected a via:agent audit entry after an agent-served read")
	}
}

func TestConcurrentRequests(t *testing.T) {
	dir, stop := startTestAgent(t, 0)
	defer stop()
	const n = 12
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			c, derr := Dial(dir, 2*time.Second)
			if derr != nil {
				errs <- derr
				return
			}
			v, gerr := c.Get("default", "DB_URL")
			if gerr == nil && v != "postgres://x" {
				gerr = fmt.Errorf("wrong value %q", v)
			}
			errs <- gerr
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent request %d: %v", i, err)
		}
	}
}

func TestStatusIdleRemaining(t *testing.T) {
	dir, stop := startTestAgent(t, time.Hour)
	defer stop()
	c, _ := Dial(dir, time.Second)
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.IdleRemainingSeconds <= 0 {
		t.Errorf("IdleRemainingSeconds should be positive with a 1h idle, got %d", st.IdleRemainingSeconds)
	}
}

// --- helpers ---

func mustKEK(t *testing.T, dir string) []byte {
	t.Helper()
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	kek, err := v.KEK()
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

// agentRejects writes line and reports whether the agent rejected it — a
// non-OK response, or the connection being dropped during the write/read
// (which a large rejected request triggers).
func agentRejects(t *testing.T, dir, line string) bool {
	t.Helper()
	conn, err := dialUnix(socketPath(dir), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, werr := conn.Write([]byte(line + "\n")); werr != nil {
		return true // dropped mid-write
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), MaxResponseBytes)
	if !sc.Scan() {
		return true // closed without a response
	}
	var resp Response
	if json.Unmarshal(sc.Bytes(), &resp) != nil {
		return true
	}
	return !resp.OK
}

func rawRequest(t *testing.T, dir, line string) Response {
	t.Helper()
	conn, err := dialUnix(socketPath(dir), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), MaxResponseBytes)
	if !sc.Scan() {
		t.Fatalf("no response: %v", sc.Err())
	}
	var resp Response
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", sc.Bytes(), err)
	}
	return resp
}
