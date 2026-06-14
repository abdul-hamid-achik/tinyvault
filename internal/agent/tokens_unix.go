//go:build unix

package agent

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
)

// tokenScope is what a capability token is allowed to read. An empty project
// means "any project" (an unrestricted-but-revocable token).
type tokenScope struct {
	project string
}

// loadTokens reads a token file — one `token[:project]` per line, with '#'
// comments and blank lines ignored — and returns a map keyed by the hex
// SHA-256 of each token. The raw token is never retained. The file must be
// 0600 (it holds bearer credentials).
func loadTokens(path string) (map[string]tokenScope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, serr := f.Stat()
	if serr != nil {
		return nil, serr
	}
	if fi.Mode().Perm()&0o077 != 0 { // fail closed on a loose-perm token file
		return nil, fmt.Errorf("token file %s must be 0600 (got %#o)", path, fi.Mode().Perm())
	}

	out := map[string]tokenScope{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tok, project := line, ""
		if i := strings.IndexByte(line, ':'); i >= 0 {
			tok = strings.TrimSpace(line[:i])
			project = strings.TrimSpace(line[i+1:])
		}
		if tok == "" {
			continue
		}
		out[tokenHash(tok)] = tokenScope{project: project}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("token file %s has no tokens", path)
	}
	return out, nil
}

func tokenHash(raw string) string { return hex.EncodeToString(crypto.HashTokenString(raw)) }

// tokenID is a short, non-reversible identifier for audit/logs (a hash prefix,
// never the token itself).
func tokenID(raw string) string {
	h := tokenHash(raw)
	if len(h) >= 8 {
		return h[:8]
	}
	return h
}

// lookupToken resolves a raw token to its scope, or (zero,false) if unknown.
func (a *agentState) lookupToken(raw string) (tokenScope, bool) {
	if raw == "" {
		return tokenScope{}, false
	}
	a.tokMu.RLock()
	defer a.tokMu.RUnlock()
	s, ok := a.tokens[tokenHash(raw)]
	return s, ok
}

// reloadTokens re-reads the token file (on SIGHUP), so a token can be revoked
// by editing the file without restarting the agent. A bad file is logged and
// the current set is kept.
func (a *agentState) reloadTokens() {
	if a.tokenFile == "" {
		return
	}
	m, err := loadTokens(a.tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tvault agent: token reload failed, keeping current set: %v\n", err)
		return
	}
	a.tokMu.Lock()
	a.tokens = m
	a.tokMu.Unlock()
	fmt.Fprintf(os.Stderr, "tvault agent: reloaded %d token(s)\n", len(m))
}
