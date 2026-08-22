package mcp

import (
	"errors"
	"fmt"

	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// readSecret decrypts one key. When the server has no cached KEK it uses the
// local agent (read-only); otherwise it uses the request-scoped vault.
func (s *VaultMCPServer) readSecret(project, key string) (string, error) {
	if s.agent != nil && len(s.kek) == 0 {
		s.releaseVaultForAgent()
		return s.agent.Get(project, key)
	}
	return s.vault.GetSecret(project, key)
}

func (s *VaultMCPServer) readSecretMeta(project, key string, extra map[string]any) (string, error) {
	if s.agent != nil && len(s.kek) == 0 {
		s.releaseVaultForAgent()
		return s.agent.Get(project, key)
	}
	return s.vault.GetSecretWithMeta(project, key, extra)
}

func (s *VaultMCPServer) readAllSecrets(project string) (map[string]string, error) {
	if s.agent != nil && len(s.kek) == 0 {
		s.releaseVaultForAgent()
		secrets, _, err := s.agent.GetAll(project)
		return secrets, err
	}
	return s.vault.GetAllSecrets(project)
}

func (s *VaultMCPServer) readSelectedSecrets(project string, only []string, prefix string) (map[string]string, []string, error) {
	if s.agent != nil && len(s.kek) == 0 {
		s.releaseVaultForAgent()
		secrets, missing, _, err := s.agent.GetSelected(project, only, prefix)
		return secrets, missing, err
	}
	return s.vault.GetSelectedSecrets(project, only, prefix)
}

// releaseVaultForAgent drops the request-scoped bbolt open so the agent can
// reopen the same file. The middleware Close is skipped when s.vault is nil.
func (s *VaultMCPServer) releaseVaultForAgent() {
	if s.vault == nil {
		return
	}
	_ = s.vault.Close()
	s.vault = nil
}

func (s *VaultMCPServer) writeLockedHint(err error) error {
	if err == nil {
		return nil
	}
	if s.agent != nil && len(s.kek) == 0 && errors.Is(err, vault.ErrLocked) {
		return fmt.Errorf("%w: agent-backed MCP is read-only; set TVAULT_PASSPHRASE to write", err)
	}
	return err
}

// denyAgentWrite rejects vault mutations when mcp is serving through the
// local agent with no cached KEK. Some store writes (delete, project
// delete) do not require an unlocked vault, so policy CanWrite is not
// enough — we must not mutate the DB in agent-backed mode.
func (s *VaultMCPServer) denyAgentWrite() error {
	if s.reopen && len(s.kek) == 0 {
		return fmt.Errorf("%w: agent-backed MCP is read-only; set TVAULT_PASSPHRASE to write", vault.ErrLocked)
	}
	return nil
}
