package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abdul-hamid-achik/tinyvault/internal/processenv"
)

type runWithSecretsInput struct {
	Project        string   `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Command        string   `json:"command" jsonschema:"The command to execute (e.g. 'npm start')."`
	Secrets        []string `json:"secrets,omitempty" jsonschema:"Specific secret keys to inject. If omitted all project secrets are injected."`
	Prefix         string   `json:"prefix,omitempty" jsonschema:"Inject only secret keys with this prefix (least privilege). Combined with 'secrets' as a union."`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"Maximum execution time in seconds. Default: 300."`
	Group          string   `json:"group,omitempty" jsonschema:"Environment group name. When set with env, resolves secrets through the inheritance chain."`
	Env            string   `json:"env,omitempty" jsonschema:"Environment name within the group (requires group)."`
}

type runResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// filterExecSecrets narrows allSecrets to the requested subset. 'only' is a
// strict allowlist — a named key that is absent is an error, so an agent's typo
// fails loudly; 'prefix' adds every matching key on top (union). With neither
// set, all secrets are returned unchanged.
func filterExecSecrets(allSecrets map[string]string, only []string, prefix, project string) (map[string]string, error) {
	if len(only) == 0 && prefix == "" {
		return allSecrets, nil
	}
	secrets := make(map[string]string)
	for _, key := range only {
		val, ok := allSecrets[key]
		if !ok {
			return nil, fmt.Errorf("secret %q not found in project %q", key, project)
		}
		secrets[key] = val
	}
	if prefix != "" {
		for k, v := range allSecrets {
			if strings.HasPrefix(k, prefix) {
				secrets[k] = v
			}
		}
	}
	return secrets, nil
}

func (s *VaultMCPServer) registerExecTools() {
	sdkmcp.AddTool(s.server, &sdkmcp.Tool{
		Name: "vault_run_with_secrets",
		Description: "Execute a command with vault secrets injected as environment variables. " +
			"Secret values are NEVER returned to the AI -- they are only passed to the subprocess environment. " +
			"Output is scanned and any secret values are redacted. " +
			"This is the PREFERRED way to use secrets.",
	}, s.handleRunWithSecrets)
}

//nolint:gocognit,gocyclo // group/env resolution + exec + redaction branching
func (s *VaultMCPServer) handleRunWithSecrets(ctx context.Context, _ *sdkmcp.CallToolRequest, input runWithSecretsInput) (*sdkmcp.CallToolResult, runResult, error) {
	if !s.policy.CanExec() {
		return nil, runResult{}, fmt.Errorf("command execution is not allowed by policy")
	}

	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, runResult{}, fmt.Errorf("project %q is not allowed by policy", project)
	}

	var allSecrets map[string]string
	var err error
	if input.Group != "" && input.Env != "" {
		// Resolution through environment group inheritance.
		group, gErr := s.vault.GetEnvGroup(input.Group)
		if gErr != nil {
			return nil, runResult{}, fmt.Errorf("group: %w", gErr)
		}
		childProject, pErr := resolveEnvProject(group, input.Env)
		if pErr != nil {
			return nil, runResult{}, pErr
		}
		if !s.policy.CanAccessProject(childProject) {
			return nil, runResult{}, fmt.Errorf("project %q is not allowed by policy", childProject)
		}
		project = childProject
		allSecrets, err = resolveAllWithInheritanceMCP(s.vault, group, input.Env, childProject)
		if err != nil {
			return nil, runResult{}, fmt.Errorf("resolve secrets: %w", err)
		}
	} else {
		allSecrets, err = s.vault.GetAllSecrets(project)
		if err != nil {
			return nil, runResult{}, fmt.Errorf("get secrets: %w", err)
		}
	}

	secrets, err := filterExecSecrets(allSecrets, input.Secrets, input.Prefix, project)
	if err != nil {
		return nil, runResult{}, err
	}
	for _, key := range input.Secrets {
		if !s.policy.CanAccessSecret(key) {
			return nil, runResult{}, fmt.Errorf("secret %q is not allowed by policy", key)
		}
	}
	for key := range secrets {
		if !s.policy.CanAccessSecret(key) {
			delete(secrets, key)
		}
	}

	timeout := time.Duration(input.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	env := processenv.Sanitize(os.Environ())
	for k, v := range secrets {
		env = append(env, k+"="+v)
	}
	env = processenv.Sanitize(env)

	cmd := exec.CommandContext(execCtx, "sh", "-c", input.Command) //nolint:gosec // MCP tool intentionally runs user commands
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		switch {
		case errors.As(err, &exitErr):
			exitCode = exitErr.ExitCode()
		case execCtx.Err() != nil:
			return nil, runResult{}, fmt.Errorf("command timed out after %s", timeout)
		default:
			return nil, runResult{}, fmt.Errorf("run command: %w", err)
		}
	}

	outStr := stdout.String()
	errStr := stderr.String()

	s.audit("secret.exec", "command", input.Command, map[string]any{"project": project, "exit_code": exitCode})

	if s.policy.RedactOutput {
		outStr = redactSecrets(outStr, secrets)
		errStr = redactSecrets(errStr, secrets)
	}

	return nil, runResult{
		ExitCode: exitCode,
		Stdout:   outStr,
		Stderr:   errStr,
	}, nil
}
