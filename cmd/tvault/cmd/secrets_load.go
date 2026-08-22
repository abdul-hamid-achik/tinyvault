package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/abdul-hamid-achik/tinyvault/internal/crypto"
	"github.com/abdul-hamid-achik/tinyvault/internal/vault"
)

// secretSelectOpts is the shared loader for `tvault env` and `tvault ssh`.
type secretSelectOpts struct {
	identity string
	group    string
	envName  string
	only     []string
	prefix   string
	via      string
}

func envSecretsSelected(only []string, prefix string) (map[string]string, []string, error) {
	return loadSelectedSecrets(secretSelectOpts{
		identity: envIdentity,
		group:    envGroupFlag,
		envName:  envEnvFlag,
		only:     only,
		prefix:   prefix,
		via:      "env",
	})
}

func loadSelectedSecrets(opts secretSelectOpts) (map[string]string, []string, error) {
	if opts.via == "" {
		opts.via = "env"
	}
	if err := validateGroupEnvFlags(opts.group, opts.envName); err != nil {
		return nil, nil, err
	}
	identityRequested := opts.identity != "" || strings.TrimSpace(os.Getenv(envIdentityKey)) != ""

	if opts.group != "" && opts.envName != "" {
		var v *vault.Vault
		var id *crypto.Identity
		var source string
		var err error
		if identityRequested {
			id, source, err = resolveIdentity(opts.identity)
			if err != nil {
				return nil, nil, err
			}
			if id == nil {
				return nil, nil, fmt.Errorf("no identity available: pass --identity <name> or set %s", envIdentityKey)
			}
			v, err = vault.Open(getVaultDir())
			if err != nil {
				return nil, nil, fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", getVaultDir(), err)
			}
			warnEnvKeyUsed(os.Stderr, source, opts.via)
		} else {
			v, err = openAndUnlockVault()
		}
		if err != nil {
			return nil, nil, err
		}
		defer v.Close()
		selectorsPresent := len(opts.only) > 0 || opts.prefix != ""
		if identityRequested && selectorsPresent {
			selected, missing, _, selectErr := resolveSelectedWithInheritanceIdentity(v, id, opts.group, opts.envName, opts.only, opts.prefix)
			if selectErr != nil {
				return nil, nil, selectErr
			}
			recordAudit(v, "secret.read", "environment_group", opts.group, map[string]any{
				"via": "identity", "source": source, "environment": opts.envName, "selected": true, "command": opts.via,
			})
			return selected, missing, nil
		}
		if identityRequested {
			secrets, _, readErr := resolveAllWithInheritanceIdentity(v, id, opts.group, opts.envName)
			if readErr != nil {
				return nil, nil, readErr
			}
			recordAudit(v, "secret.read", "environment_group", opts.group, map[string]any{
				"via": "identity", "source": source, "environment": opts.envName, "command": opts.via,
			})
			return secrets, nil, nil
		}
		if selectorsPresent {
			selected, missing, _, selectErr := resolveSelectedWithInheritance(v, opts.group, opts.envName, opts.only, opts.prefix)
			if selectErr != nil {
				return nil, nil, selectErr
			}
			return selected, missing, nil
		}
		secrets, _, err := resolveAllWithInheritance(v, opts.group, opts.envName)
		if err != nil {
			return nil, nil, err
		}
		return secrets, nil, nil
	}

	if identityRequested {
		id, source, err := resolveIdentity(opts.identity)
		if err != nil {
			return nil, nil, err
		}
		if id == nil {
			return nil, nil, fmt.Errorf("no identity available: pass --identity <name> or set %s", envIdentityKey)
		}
		dir := getVaultDir()
		v, err := vault.Open(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("vault not found at %s, run 'tvault init' first: %w", dir, err)
		}
		defer v.Close()
		warnEnvKeyUsed(os.Stderr, source, opts.via)
		project := resolveProject(v, projectName)
		if len(opts.only) > 0 || opts.prefix != "" {
			selected, missing, selectErr := v.GetSelectedSecretsWithIdentity(project, id, opts.only, opts.prefix)
			if selectErr != nil {
				return nil, nil, fmt.Errorf("read selected project keys %q with identity: %w", project, selectErr)
			}
			recordAudit(v, "secret.read", "project", project, map[string]any{
				"via": "identity", "source": source, "selected": true, "command": opts.via,
			})
			return selected, missing, nil
		}
		secrets, err := v.GetAllSecretsWithIdentity(project, id)
		if err != nil {
			return nil, nil, fmt.Errorf("read project %q with identity: %w", project, err)
		}
		recordAudit(v, "secret.read", "project", project, map[string]any{"via": "identity", "source": source, "command": opts.via})
		return secrets, nil, nil
	}

	if len(opts.only) == 0 && opts.prefix == "" {
		if secrets, _, ok := agentAllSecrets(projectName); ok {
			return secrets, nil, nil
		}
	} else if secrets, missing, _, ok := agentSelectedSecrets(projectName, opts.only, opts.prefix); ok {
		return secrets, missing, nil
	}

	v, err := openAndUnlockVault()
	if err != nil {
		return nil, nil, err
	}
	defer v.Close()
	project := resolveProject(v, projectName)
	if len(opts.only) > 0 || opts.prefix != "" {
		selected, missing, selectErr := v.GetSelectedSecrets(project, opts.only, opts.prefix)
		if selectErr != nil {
			return nil, nil, fmt.Errorf("failed to get selected secrets: %w", selectErr)
		}
		return selected, missing, nil
	}
	secrets, err := v.GetAllSecrets(project)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get secrets: %w", err)
	}
	return secrets, nil, nil
}
