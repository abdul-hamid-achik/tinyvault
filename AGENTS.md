# AGENTS.md -- AI Agent Instructions for TinyVault

## Project Overview

TinyVault is a **local-first CLI tool and MCP server** for secrets management. Single Go binary, no external services.

- **Storage**: bbolt (pure Go key-value store) at `~/.tvault/vault.db`
- **Encryption**: AES-256-GCM with two-tier key hierarchy (Argon2id passphrase -> KEK -> per-project DEKs)
- **CLI**: `tvault` using cobra/viper
- **MCP**: stdio-based server using `github.com/modelcontextprotocol/go-sdk`

## Quick Commands

```bash
# Build
go build -o bin/tvault ./cmd/tvault

# Test (all packages, race detector)
go test -race ./...

# Lint
golangci-lint run ./...

# Security scan
govulncheck ./...

# Full check before committing
go build ./... && go test -race ./... && golangci-lint run ./...
```

## Project Structure

```
cmd/tvault/
  main.go                    # Entry point
  cmd/
    root.go                  # Root command, global flags (--vault, --project, --json)
    vault_helper.go          # Shared: getVaultDir(), openAndUnlockVault(), resolveProject()
    init.go                  # tvault init
    unlock.go / lock.go      # tvault unlock / lock
    status.go                # tvault status
    get.go / set.go          # tvault get KEY / tvault set KEY VALUE
    list.go / delete.go      # tvault list / tvault delete KEY
    run.go                   # tvault run -- CMD (inject secrets as env vars)
    env.go                   # tvault env (export in shell/dotenv/json/yaml/k8s format)
    export.go                # tvault export (write secrets to file)
    import.go                # tvault import (read secrets from file)
    projects.go / use.go     # tvault projects list/create / tvault use PROJECT
    backup.go                # tvault backup / tvault backup --restore
    rotate.go                # tvault key rotate
    mcp_server.go            # tvault mcp-server (stdio MCP transport)
    ci.go                    # tvault ci init (generate CI workflow files)
    completion.go            # Shell completion
    output.go                # Color output helpers (Success, Error, Warning, Info)

internal/
  crypto/
    crypto.go                # AES-256-GCM encrypt/decrypt, Argon2id key derivation
    crypto_test.go           # Comprehensive crypto tests
  store/
    store.go                 # Store interface
    types.go                 # VaultMeta, Project, SecretEntry, AuditEntry
    bbolt.go                 # BoltStore implementation
    bbolt_test.go            # 10 store tests
  vault/
    vault.go                 # Create, Open, Unlock, Lock, RotatePassphrase
    project.go               # CreateProject, ListProjects, SetCurrentProject
    secret.go                # SetSecret, GetSecret, ListSecrets, DeleteSecret, GetAllSecrets
    errors.go                # Sentinel errors (ErrLocked, ErrWrongPassphrase, etc.)
    vault_test.go            # 16 vault tests
  mcp/
    server.go                # VaultMCPServer, tool registration, Run()
    tools_projects.go        # vault_list_projects
    tools_secrets.go         # vault_list/get/set/delete_secret
    tools_exec.go            # vault_run_with_secrets (exec + output redaction)
    tools_env.go             # vault_export_env (writes .env, returns path only)
    config.go                # AccessPolicy, LoadPolicy, allow/deny pattern matching
    redact.go                # redactSecrets() replaces values with [REDACTED:KEY]
    server_test.go           # Integration tests with in-memory MCP transport
  validation/
    validation.go            # Input validation (keys, project names)
```

## Security Rules

### Encryption
- **ALWAYS** use `crypto/rand` for random bytes (never `math/rand`)
- **ALWAYS** generate unique nonces for each AES-GCM encryption
- **NEVER** log or print secret values
- **ALWAYS** zero keys from memory after use (`crypto.ZeroBytes()`)

### Key Hierarchy
```
User Passphrase
  -> Argon2id(passphrase, salt) -> KEK (Key Encryption Key)
    -> AES-GCM(KEK, DEK) -> Encrypted per-project DEK
      -> AES-GCM(DEK, secret) -> Encrypted secret value
```

### MCP Security
- `redactSecrets()` scans command output and replaces secret values with `[REDACTED:KEY]`
- `vault_export_env` writes .env file to disk but only returns the file path to the AI
- Access policy controls which projects/secrets the AI can access
- `allow_exec: false` disables command execution entirely

## Code Conventions

### Import Ordering (goimports with local-prefixes)
```go
import (
    // 1. Standard library
    "fmt"
    "os"

    // 2. Third-party packages
    "github.com/spf13/cobra"

    // 3. Internal packages (separated by blank line)
    "github.com/abdul-hamid-achik/tinyvault/internal/vault"
)
```

### Error Handling
- Wrap errors with context: `fmt.Errorf("failed to X: %w", err)`
- Use sentinel errors in `internal/vault/errors.go` for well-known conditions
- Use `errors.As` not type assertions for wrapped errors
- Intentionally ignored errors must have `//nolint:errcheck` with reason

### Octal Literals
- Use modern Go style: `0o600` not `0600`

### Testing
- All tests run with `-race` flag
- Use `t.TempDir()` for test directories
- Crypto package: test encrypt/decrypt round-trips, invalid keys, empty data
- Vault package: test full lifecycle (create -> unlock -> set -> get -> lock)
- MCP package: use `mcp.NewInMemoryTransports()` for integration tests

### Local Builds
Always output to `bin/` (gitignored):
```bash
go build -o bin/tvault ./cmd/tvault    # correct
go build -o tvault ./cmd/tvault        # wrong (root is gitignored with /tvault)
```

## MCP Go SDK Notes

Using `github.com/modelcontextprotocol/go-sdk` v1.2.0:

- `jsonschema` struct tags are plain description strings: `jsonschema:"Project name"`
- Tool registration: `mcp.AddTool[In, Out](server, tool, handler)`
- Handler signature: `func(ctx, *mcp.CallToolRequest, Input) (*mcp.CallToolResult, Output, error)`
- Testing: `mcp.NewInMemoryTransports()` -- connect server first, then client
- Production: `mcp.StdioTransport{}` for stdio mode

## Commit Checklist

Before every commit:

- [ ] `go build ./...` compiles
- [ ] `go test -race ./...` passes
- [ ] `golangci-lint run ./...` passes
- [ ] No hardcoded secrets or credentials
- [ ] New crypto code uses `crypto/rand` and zeros keys after use
- [ ] Tests added for new functionality
- [ ] Error messages don't leak internal details to users

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TVAULT_PASSPHRASE` | Vault passphrase (CI/CD, skips interactive prompt) |
| `TVAULT_DIR` | Vault directory (default: `~/.tvault`) |

## Dependencies (go.mod)

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/spf13/viper` | Configuration |
| `github.com/fatih/color` | Colored terminal output |
| `github.com/google/uuid` | UUID generation for project IDs |
| `go.etcd.io/bbolt` | Embedded key-value store |
| `golang.org/x/crypto` | Argon2id key derivation |
| `golang.org/x/term` | Secure passphrase input (no echo) |
| `github.com/modelcontextprotocol/go-sdk` | MCP server SDK |
| `go.yaml.in/yaml/v3` | YAML parsing (access policy) |
