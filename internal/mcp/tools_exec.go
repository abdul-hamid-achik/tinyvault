package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type runWithSecretsInput struct {
	Project        string   `json:"project,omitempty" jsonschema:"Project name. If omitted uses the current project."`
	Command        string   `json:"command" jsonschema:"The command to execute (e.g. 'npm start')."`
	Secrets        []string `json:"secrets,omitempty" jsonschema:"Specific secret keys to inject. If omitted all project secrets are injected."`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"Maximum execution time in seconds. Default: 300."`
}

type runResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
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

func (s *VaultMCPServer) handleRunWithSecrets(ctx context.Context, _ *sdkmcp.CallToolRequest, input runWithSecretsInput) (*sdkmcp.CallToolResult, runResult, error) {
	if !s.policy.CanExec() {
		return nil, runResult{}, fmt.Errorf("command execution is not allowed by policy")
	}

	project := s.resolveProject(input.Project)
	if !s.policy.CanAccessProject(project) {
		return nil, runResult{}, fmt.Errorf("project %q is not allowed by policy", project)
	}

	allSecrets, err := s.vault.GetAllSecrets(project)
	if err != nil {
		return nil, runResult{}, fmt.Errorf("get secrets: %w", err)
	}

	// Filter to requested secrets if specified.
	secrets := allSecrets
	if len(input.Secrets) > 0 {
		secrets = make(map[string]string, len(input.Secrets))
		for _, key := range input.Secrets {
			val, ok := allSecrets[key]
			if !ok {
				return nil, runResult{}, fmt.Errorf("secret %q not found in project %q", key, project)
			}
			secrets[key] = val
		}
	}

	timeout := time.Duration(input.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	env := os.Environ()
	for k, v := range secrets {
		env = append(env, k+"="+v)
	}

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

	if s.policy.RedactOutput {
		outStr = redactSecrets(outStr, allSecrets)
		errStr = redactSecrets(errStr, allSecrets)
	}

	return nil, runResult{
		ExitCode: exitCode,
		Stdout:   outStr,
		Stderr:   errStr,
	}, nil
}
