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
	writeResponse(conn, a.dispatch(req, uid, pid))
}

func (a *agentState) dispatch(req Request, uid uint32, pid int) Response {
	switch req.Op {
	case OpStop:
		a.triggerShutdown()
		return Response{V: ProtocolVersion, OK: true}

	case OpStatus:
		return Response{V: ProtocolVersion, OK: true, Status: &StatusInfo{
			PID:                  os.Getpid(),
			Socket:               socketPath(a.opts.Dir),
			Project:              a.opts.Project,
			UptimeSeconds:        int(time.Since(a.started).Seconds()),
			IdleRemainingSeconds: a.idleRemaining(),
		}}

	case OpGet:
		if req.Key == "" {
			return errResp("get requires a key")
		}
		var val string
		if err := a.withVault(func(v *vault.Vault) error {
			project := resolveProject(v, req.Project)
			s, e := v.GetSecret(project, req.Key)
			if e != nil {
				return e
			}
			val = s
			auditRead(v, project, req.Key, uid, pid)
			return nil
		}); err != nil {
			return errResp(err.Error())
		}
		return Response{V: ProtocolVersion, OK: true, Value: val}

	case OpGetAll:
		var secrets map[string]string
		var resolved string
		if err := a.withVault(func(v *vault.Vault) error {
			resolved = resolveProject(v, req.Project)
			m, e := v.GetAllSecrets(resolved)
			if e != nil {
				return e
			}
			secrets = m
			auditRead(v, resolved, "", uid, pid)
			return nil
		}); err != nil {
			return errResp(err.Error())
		}
		return Response{V: ProtocolVersion, OK: true, Secrets: secrets, Project: resolved}

	default:
		return errResp("unknown op: " + req.Op)
	}
}

// auditRead records an agent-served read on the open vault. Best-effort: an
// audit failure must never block the response (and never includes a value).
func auditRead(v *vault.Vault, project, key string, uid uint32, pid int) {
	meta := map[string]any{"via": "agent", "project": project, "peer_uid": uid}
	if pid > 0 {
		meta["peer_pid"] = pid
	}
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
