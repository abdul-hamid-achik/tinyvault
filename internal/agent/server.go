//go:build unix

package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/abdul-hamid-achik/tinyvault/internal/store"
	"github.com/abdul-hamid-achik/tinyvault/internal/validation"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

const connDeadline = 10 * time.Second

func (a *agentState) handleConn(conn *net.UnixConn) {
	defer conn.Close()
	// A handler panic must never leak the KEK: lock the agent down.
	defer func() {
		if r := recover(); r != nil {
			a.triggerShutdown()
		}
	}()

	// Same-uid isolation: reject any peer whose uid is not ours (fail-closed
	// on any peer-cred error).
	uid, err := peerUID(conn)
	if err != nil || uid != uint32(os.Geteuid()) {
		writeResponse(conn, errResp("permission denied"))
		return
	}
	pid := peerPID(conn)

	if err := conn.SetReadDeadline(time.Now().Add(connDeadline)); err != nil {
		return
	}
	if err := conn.SetWriteDeadline(time.Now().Add(connDeadline)); err != nil {
		return
	}

	req, rerr := readRequest(conn)
	a.resetIdle() // any activity (even malformed) defers the idle timeout
	if rerr != nil {
		writeResponse(conn, errResp(rerr.Error()))
		return
	}
	if req.V != ProtocolVersion {
		writeResponse(conn, errResp(fmt.Sprintf("protocol version mismatch: client %d, server %d", req.V, ProtocolVersion)))
		return
	}

	// Capability-token gate: in --require-token mode every op needs a valid
	// token (the operator stops the agent with a signal, not the socket).
	var scope tokenScope
	if a.requireToken {
		s, ok := a.lookupToken(req.Token)
		if !ok {
			// The token is never logged, only the fact that one was missing or
			// unknown; tokenID's hash prefix is what identifies a valid one.
			a.lg.Warn("request denied",
				"op", req.Op, "peer_uid", uid, "peer_pid", pid,
				"reason", "token required or invalid")
			writeResponse(conn, errResp("token required or invalid"))
			return
		}
		scope = s
	}
	writeResponse(conn, a.dispatch(req, uid, pid, scope))
}

// dispatch records one structured line per request around dispatchOp.
//
// The fields describe the *shape* of the request — operation, peer, project,
// key name, how many keys were selected — which is the same metadata the audit
// log already keeps. No decrypted value, passphrase, KEK byte or capability
// token reaches the log; a token appears only as tokenID's hash prefix.
func (a *agentState) dispatch(req Request, uid uint32, pid int, scope tokenScope) Response {
	start := time.Now()
	resp := a.dispatchOp(req, uid, pid, scope)

	fields := []any{
		"op", req.Op,
		"peer_uid", uid,
		"peer_pid", pid,
		"dur", time.Since(start).Round(time.Millisecond).String(),
	}
	if req.Project != "" {
		fields = append(fields, "project", req.Project)
	}
	if req.Key != "" {
		fields = append(fields, "key", req.Key)
	}
	// Counts rather than the names themselves: a bulk selection can carry
	// dozens of keys and would drown the record without adding much.
	if len(req.Only) > 0 {
		fields = append(fields, "only_count", len(req.Only))
	}
	if req.Prefix != "" {
		fields = append(fields, "prefix", req.Prefix)
	}
	if a.requireToken {
		fields = append(fields, "token_id", tokenID(req.Token))
	}

	if resp.OK {
		a.lg.Info("request served", fields...)
	} else {
		a.lg.Warn("request failed", append(fields, "err", resp.Error)...)
	}
	return resp
}

func (a *agentState) dispatchOp(req Request, uid uint32, pid int, scope tokenScope) Response {
	tokID := ""
	if a.requireToken {
		tokID = tokenID(req.Token)
	}
	switch req.Op {
	case OpStop:
		// Only an unrestricted token (or any peer in default mode) may stop the
		// agent — a project-scoped delegate must not shut it down for everyone.
		if a.requireToken && !scope.allows("") {
			return errResp("only an unrestricted token may stop the agent")
		}
		a.triggerShutdown()
		return Response{V: ProtocolVersion, OK: true}

	case OpStatus:
		// A status request may name the project whose prompt-free read
		// availability the client is checking. Validate a scoped token here,
		// without opening the vault or reading a secret. Empty preserves the
		// historical metadata-only status behavior.
		if req.Project != "" && !scope.allows(req.Project) {
			return errResp(errScope(req.Project).Error())
		}
		return Response{V: ProtocolVersion, OK: true, Status: &StatusInfo{
			PID:                  os.Getpid(),
			Socket:               socketPath(a.opts.Dir),
			Project:              a.opts.Project,
			UptimeSeconds:        int(time.Since(a.started).Seconds()),
			IdleRemainingSeconds: a.idleRemaining(),
		}}

	case OpGet:
		return a.doGet(req, scope, uid, pid, tokID)

	case OpGetAll:
		return a.doGetAll(req, scope, uid, pid, tokID)

	case OpGetSelected:
		return a.doGetSelected(req, scope, uid, pid, tokID)

	default:
		return errResp("unknown op: " + req.Op)
	}
}

func (a *agentState) doGet(req Request, scope tokenScope, uid uint32, pid int, tokID string) Response {
	if req.Key == "" {
		return errResp("get requires a key")
	}
	var val string
	if err := a.withVault(func(v *vault.Vault) error {
		project := resolveProject(v, req.Project)
		if !scope.allows(project) {
			return errScope(project)
		}
		s, e := v.GetSecretWithMeta(project, req.Key, agentAuditExtra(uid, pid, tokID))
		if e != nil {
			return e
		}
		val = s
		return nil
	}); err != nil {
		return errResp(err.Error())
	}
	return Response{V: ProtocolVersion, OK: true, Value: val}
}

func (a *agentState) doGetAll(req Request, scope tokenScope, uid uint32, pid int, tokID string) Response {
	var secrets map[string]string
	var resolved string
	if err := a.withVault(func(v *vault.Vault) error {
		resolved = resolveProject(v, req.Project)
		if !scope.allows(resolved) {
			return errScope(resolved)
		}
		m, e := v.GetAllSecrets(resolved)
		if e != nil {
			return e
		}
		secrets = m
		auditRead(v, resolved, "", uid, pid, tokID)
		return nil
	}); err != nil {
		return errResp(err.Error())
	}
	return Response{V: ProtocolVersion, OK: true, Secrets: secrets, Project: resolved}
}

func (a *agentState) doGetSelected(req Request, scope tokenScope, uid uint32, pid int, tokID string) Response {
	if req.Key != "" {
		return errResp("getselected does not accept key")
	}
	if err := validateSelection(req.Only, req.Prefix); err != nil {
		return errResp(err.Error())
	}
	var secrets map[string]string
	var missing []string
	var resolved string
	if err := a.withVault(func(v *vault.Vault) error {
		resolved = resolveProject(v, req.Project)
		if !scope.allows(resolved) {
			return errScope(resolved)
		}
		var readErr error
		secrets, missing, readErr = v.GetSelectedSecrets(resolved, req.Only, req.Prefix)
		if readErr != nil {
			return readErr
		}
		auditRead(v, resolved, "", uid, pid, tokID)
		return nil
	}); err != nil {
		return errResp(err.Error())
	}
	return Response{V: ProtocolVersion, OK: true, Secrets: secrets, Missing: missing, Project: resolved}
}

// validateSelection rejects malformed selector fields before the agent opens
// the vault. Prefix is constrained to the same safe key alphabet: a prefix is
// an incomplete key, not a glob or an expression language.
func validateSelection(only []string, prefix string) error {
	if len(only) == 0 && prefix == "" {
		return fmt.Errorf("getselected requires only or prefix")
	}
	for _, key := range only {
		if err := validation.SecretKey(key); err != nil {
			return fmt.Errorf("invalid selected key: %w", err)
		}
	}
	if prefix != "" {
		if err := validation.SecretKey(prefix); err != nil {
			return fmt.Errorf("invalid selected prefix: %w", err)
		}
	}
	return nil
}

// allows reports whether the token scope permits reading the given project
// (an empty scope project means "any project").
func (s tokenScope) allows(project string) bool {
	return s.project == "" || s.project == project
}

func errScope(project string) error {
	return fmt.Errorf("token not in scope for project %q", project)
}

// auditRead records an agent-served read on the open vault. Best-effort: an
// audit failure must never block the response (and never includes a value).
// tokID, when non-empty, is a hash prefix of the capability token (never the
// token itself).
func agentAuditExtra(uid uint32, pid int, tokID string) map[string]any {
	meta := map[string]any{"via": "agent", "peer_uid": uid}
	if pid > 0 {
		meta["peer_pid"] = pid
	}
	if tokID != "" {
		meta["token_id"] = tokID
	}
	return meta
}

func auditRead(v *vault.Vault, project, key string, uid uint32, pid int, tokID string) {
	meta := agentAuditExtra(uid, pid, tokID)
	meta["project"] = project
	//nolint:errcheck // audit is best-effort
	v.AppendAudit(&store.AuditEntry{
		Action:       "secret.read",
		ResourceType: "secret",
		ResourceName: key,
		Timestamp:    time.Now().UTC(),
		Metadata:     meta,
	})
}

// withVault opens the vault, unlocks it with the cached KEK, runs fn, and
// closes it — serialized so the agent never holds two bbolt opens at once and
// the DB stays free for direct CLI access between requests.
func (a *agentState) withVault(fn func(*vault.Vault) error) error {
	a.vaultMu.Lock()
	defer a.vaultMu.Unlock()

	v, err := vault.Open(a.opts.Dir)
	if err != nil {
		return err
	}
	defer v.Close()
	if err := v.UnlockWithKEK(a.kek); err != nil {
		return fmt.Errorf("unlock: %w (passphrase rotated? restart the agent)", err)
	}
	return fn(v)
}

func readRequest(conn net.Conn) (Request, error) {
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), MaxRequestBytes)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			if errors.Is(err, bufio.ErrTooLong) {
				return Request{}, fmt.Errorf("request too large")
			}
			return Request{}, err
		}
		return Request{}, fmt.Errorf("empty request")
	}
	var req Request
	if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
		return Request{}, fmt.Errorf("invalid request")
	}
	return req, nil
}

// writeResponse is best-effort: a write failure to a soon-to-close connection
// is not actionable, so the error is intentionally not propagated.
func writeResponse(conn net.Conn, resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	//nolint:errcheck // best-effort write to a soon-to-close connection
	conn.Write(append(data, '\n'))
}

func errResp(msg string) Response {
	return Response{V: ProtocolVersion, OK: false, Error: msg}
}

// resolveProject mirrors the CLI's project resolution: an explicit name wins,
// else the vault's current project, else "default".
func resolveProject(v *vault.Vault, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if cur, err := v.GetCurrentProject(); err == nil && cur != "" {
		return cur
	}
	return "default"
}
