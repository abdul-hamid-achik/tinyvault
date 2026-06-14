# AGENTS.md -- AI Agent Instructions for TinyVault

## Project Overview

TinyVault is a **local-first CLI tool and MCP server** for secrets management.
One Go binary, no servers, no accounts, no cloud.

- **Primary users:** developers managing `.env` sprawl; AI agents that need
  to use secrets without the values ever entering the model context.
- **Adjacent tools:** `pass`, 1Password CLI, Doppler, Vault dev mode. TinyVault
  is the local-first, agent-first complement. See [SPEC.md](SPEC.md) for the
  full positioning and threat model.
- **Storage:** bbolt (pure Go key-value store) at `~/.tvault/vault.db`,
  accessed through a **SQL-shaped tabular Store interface** with
  per-table sub-interfaces (MetaStore, ProjectStore, SecretStore,
  AuditStore, ConfigStore). Relational queries (prefix scan, time
  range, name glob, cross-project) are first-class methods, not
  string-template SQL. The bbolt file is the only on-disk artifact;
  there is no separate search index.
- **Encryption:** AES-256-GCM with two-tier key hierarchy
  (Argon2id passphrase -> KEK -> per-project DEKs)
- **CLI:** `tvault` using cobra/viper
- **MCP:** stdio-based server using `github.com/modelcontextprotocol/go-sdk`

**Before making non-trivial changes, read [SPEC.md](SPEC.md).** It documents
the architecture, threat model, and roadmap. The README is a quickstart;
SPEC.md is the source of truth for *why* things are the way they are.

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
    unlock.go / lock.go      # tvault unlock / tvault lock
    status.go                # tvault status
    get.go / set.go          # tvault get KEY (--version N) / tvault set KEY VALUE (with --from-env / --from-file)
    history.go / rollback.go # tvault history KEY / tvault rollback KEY --to N (secret version history)
    list.go / delete.go      # tvault list / tvault delete KEY (list supports --prefix; delete purges history)
    run.go                   # tvault run -- CMD; --env-file + ${tvault://...} interpolation
    env.go                   # tvault env (export in shell/dotenv/json/yaml/k8s format)
    export.go                # tvault export (write secrets to file)
    import.go                # tvault import (read secrets from file)
    import_interactive.go    # interactive (text-prompt) file picker for --interactive imports
    sync.go                  # tvault sync --direction pull|push|mirror
    encrypted_env.go         # tvault encrypt-env / decrypt-env (.env.encrypted v1 KEK + v2 recipient)
    search.go                # tvault search (relational query, metadata only)
    diff.go                  # tvault diff <file> (key/value drift vs a .env; metadata-only by default)
    identity.go              # tvault identity new/list/export + resolveIdentity (X25519, TVAULT_IDENTITY_KEY — Spine A)
    project_share.go         # tvault projects share/unshare/recipients (Spine A)
    gitfilter.go             # tvault git-filter install/track/status/checkout + clean/smudge (Spine A)
    k8s.go                   # tvault seal --format k8s + tvault k8s render (commit-safe SealedSecret — Spine A)
    json_helper.go           # writeJSON(): shared --json encoder
    docs.go                  # tvault docs (machine-readable feature manifest)
    projects.go / use.go     # tvault projects list/create / tvault use PROJECT
    backup.go                # tvault backup <path> / tvault restore <path> (restore is a separate command)
    rotate.go                # tvault key rotate
    mcp_server.go            # tvault mcp-server (stdio MCP transport)
    ci.go                    # tvault ci init --mode=passphrase|identity (generate CI workflow files)
    browse.go                # tvault browse (cobra wiring + TTY checks; calls browse pkg)
    doctor.go                # tvault doctor (read-only setup diagnostics; --json)
    audit_helper.go          # recordAudit(): CLI/TUI audit logging (MCP-vocab actions)
    config_helper.go         # typed ~/.tvault/config.yaml (browse: defaults)
    completion.go            # Shell completion
    output.go                # Color output helpers (Success, Error, Warning, Info)
    browse/                  # The interactive browser (the ONLY package importing charm.land/*)
      run.go                 # Run(): builds the model, runs the Bubble Tea v2 program
      model.go               # tea.Model: state, Init/Update, key handling
      view.go                # View(): responsive 4-pane layout, panes, overlays
      styles.go              # themeStyles: catppuccin light/dark, picked at runtime
      keymap.go              # key.Binding set; implements help.KeyMap
      data.go                # read-only loaders wrapping internal/vault + tea.Cmd msgs
      anim.go                # pure-Go easing + animation gating (no harmonica)
      help.go                # in-app help markdown, glamour-rendered
      *_test.go              # model/data/styles/keymap/layout tests + glyphrun dump helper

internal/
  crypto/
    crypto.go                # AES-256-GCM encrypt/decrypt, Argon2id key derivation
    recipient.go             # X25519 recipient layer: WrapDEK/UnwrapDEK, Identity (Spine A)
    crypto_test.go           # Comprehensive crypto tests
  agent/                     # local unlock-once agent (unix only — build-tagged)
    protocol.go              # wire types + Options (no build tag)
    agent.go / server.go     # listener, lifecycle, idle, per-request vault open
    socket_unix.go           # socket perms, flock single-instance, path-length guard
    peercred_{darwin,linux,other}.go  # SO_PEERCRED / LOCAL_PEERCRED (fail-closed)
    client.go / stub_other.go # client + !unix stub (ErrUnsupportedPlatform)
  store/
    store.go                 # SQL-shaped tabular Store interface
                             # (MetaStore, ConfigStore, ProjectStore,
                             #  SecretStore, AuditStore) and row types
    bbolt.go                 # BoltStore: bbolt-backed impl; buckets incl.
                             #  secrets (current) + secret_versions (history).
                             #  GetSecretVersion / ListSecretVersions /
                             #  ListSecretVersionEntries; RekeyProject re-keys
                             #  current + history atomically.
    bbolt_test.go            # bbolt integration tests
    version_test.go          # secret-version archive / rollback / purge tests
    query_test.go            # Relational query tests
  vault/
    vault.go                 # Create, Open, Unlock, Lock, RotatePassphrase, KEK()
    project.go               # CreateProject, ListProjects, SetCurrentProject
    secret.go                # SetSecret, GetSecret, ListSecrets, DeleteSecret,
                             # GetAllSecrets, ListSecretMetadata,
                             # ListSecretVersions, GetSecretVersionValue, RollbackSecret
    query.go                 # Relational query layer (Search, CountSecrets,
                             # SearchProjects, ListAudit, SnapshotProjects)
    sharing.go               # ShareProject/UnshareProject (DEK re-key on revoke),
                             # GetAllSecretsWithIdentity (recipient read) — Spine A
    errors.go                # Sentinel errors (ErrLocked, ErrWrongPassphrase, etc.)
    vault_test.go            # Vault lifecycle tests
    query_test.go            # Relational query tests
    encrypted_env_test.go    # End-to-end encrypted .env round-trip via vault
  mcp/
    server.go                # VaultMCPServer, tool registration, Run()
    tools_projects.go        # vault_list/create/delete_project
    tools_secrets.go         # vault_list/get/set/delete_secret
    tools_exec.go            # vault_run_with_secrets (exec + output redaction)
    tools_env.go             # vault_export_env (writes .env, returns path only)
    tools_status.go          # vault_status, vault_audit_log
    tools_generate.go        # vault_generate_secret (random secret, never returns value)
    tools_query.go           # vault_search_secrets, vault_list_secrets_by_prefix,
                             # vault_audit_log_since (relational MCP tools)
    config.go                # AccessPolicy, LoadPolicy, allow/deny pattern matching
    redact.go                # redactSecrets() replaces values with [REDACTED:KEY]
    prompts.go               # MCP prompts (setup-project, inject-secrets)
    resources.go             # MCP resources (vault://status, vault://projects, vault://projects/{name}/keys)
    server_test.go           # Integration tests with in-memory MCP transport
  dotenv/
    dotenv.go                # Safe dotenv parser (no shell expansion, name allowlist)
    interpolate.go           # tvault:// reference parsing + Resolve
    dotenv_test.go           # Parser tests
    interpolate_test.go      # Interpolation tests
    open_unix.go             # openParseTarget: POSIX variant
    open_nonunix.go          # openParseTarget: Windows variant
  sync/
    sync.go                  # Two-way reconciliation between .env and vault
    sync_test.go             # Direction + conflict + round-trip tests
  encryptedenv/
    encryptedenv.go          # .env.encrypted: v1 (KEK-tied) + v2 (recipient-based, commit-safe)
    encryptedenv_test.go     # v1: round-trip, tamper, wrong-KEK, salt/nonce randomness
    encryptedenv_v2_test.go  # v2: multi-recipient, wrong/absent identity, KEK-independence, version detect
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

Recipient layer (passphrase-independent, alongside the KEK wrap):
  X25519 ECDH -> HKDF-SHA256 -> ChaCha20-Poly1305(wrap_key, DEK)  [one stanza per recipient]
  -> powers projects share/unshare, .env.encrypted v2, and git-filter
```

### MCP Security
- `redactSecrets()` scans command output and replaces secret values with `[REDACTED:KEY]`
- `vault_export_env` writes .env file to disk but only returns the file path to the AI
- `vault_generate_secret` stores the secret but only returns `{stored: true}` to the AI
- Access policy controls which projects/secrets the AI can access
- `allow_exec: false` disables `vault_run_with_secrets` entirely
- Every privileged MCP action writes an entry to the audit bucket

### Dotenv / .env.encrypted Safety
- The dotenv parser rejects file names outside the allowlist (`.env`,
  `.env.<env>`, `.env.<env>.local`, `.env.local`). A user cannot trick
  the parser into reading `~/.bashrc` as a dotenv file.
- The parser does **no** variable expansion or command substitution.
  A value like `${tvault://KEY}` is preserved verbatim; only `tvault
  run` (or explicit `Resolve`) interprets it.
- `.env.encrypted` **v1** files use AES-256-GCM with a per-file key
  derived via HKDF-SHA256 from the vault KEK. Tampered or wrong-KEK
  files fail decryption. Passphrase rotation invalidates prior v1 files
  by design.
- `.env.encrypted` **v2** files (`encrypt-env --recipient`) wrap a random
  per-file key to X25519 recipients — KEK-independent, so they survive
  passphrase rotation and are decryptable only with a matching identity
  (`--identity`). `decrypt-env` auto-detects the version. `tvault git-filter`
  uses v2 for transparent encrypt-on-commit / decrypt-on-checkout; secret
  values never enter git history in plaintext.

See [SPEC.md section 3](SPEC.md#3-threat-model) for the full threat model,
including out-of-scope items (no HSM, no recovery without passphrase, etc.).

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

Using `github.com/modelcontextprotocol/go-sdk` v1.4.1:

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
- [ ] If MCP surface changed, [SPEC.md](SPEC.md) section 4 is updated

## Environment Variables

| Variable               | Description                                                                |
|------------------------|----------------------------------------------------------------------------|
| `TVAULT_PASSPHRASE`    | Vault passphrase (CI/CD, scripts, MCP server — skips interactive prompt).  |
| `TVAULT_NO_AGENT`      | Bypass a running `tvault agent` and unlock the vault directly.             |
| `TVAULT_IDENTITY_KEY`  | Private identity (`tvault-key1…`) for passphrase-free decrypt in CI/ssh/agents (`resolveIdentity`); a local key file takes precedence + warns. Never echoed in errors. |
| `TVAULT_IDENTITY`      | Default identity name for git filters / recipient reads (default: `default`). |
| `TVAULT_DIR`           | Vault directory (default: `~/.tvault`).                                    |

## Dependencies (go.mod)

| Package                                  | Purpose                                  |
|------------------------------------------|------------------------------------------|
| `github.com/spf13/cobra`                 | CLI framework                            |
| `github.com/spf13/viper`                 | Configuration                            |
| `github.com/fatih/color`                 | Colored terminal output                  |
| `github.com/google/uuid`                 | UUID generation for project IDs          |
| `go.etcd.io/bbolt`                       | Encrypted vault storage (single file)    |
| `golang.org/x/crypto`                    | Argon2id, HKDF (encrypted-env)           |
| `golang.org/x/term`                      | Secure passphrase input (no echo)        |
| `golang.org/x/sys`                       | unix peer-credential check for the agent (now a direct require; was indirect — no new module) |
| `github.com/modelcontextprotocol/go-sdk` | MCP server SDK                           |
| `go.yaml.in/yaml/v3`                     | YAML parsing (access policy)             |
| `charm.land/bubbletea/v2`                | TUI runtime (`tvault browse` only)          |
| `charm.land/lipgloss/v2`                 | TUI styling/layout (`tvault browse` only)   |
| `charm.land/bubbles/v2`                  | TUI components: textinput, spinner, help, viewport, key |
| `charm.land/glamour/v2`                  | Markdown rendering for the in-app help pane |

The browser is a `cmd/` subcommand, **not** an `internal/` package — it
imports the `charm.land/*` v2 libraries that are otherwise absent from
the project. Those libraries are pulled in **only** by `tvault browse`; no
other command links them at runtime. The stack is strictly the v2 line
(no `harmonica`, no `huh`): animations are hand-rolled easing.

## Where things live

- **Product framing, threat model, roadmap:** [SPEC.md](SPEC.md)
- **Quickstart and feature list:** [README.md](README.md)
- **Contributing guide:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **CI:** `.github/workflows/ci.yml` (test, lint, govulncheck, build)
- **Release:** `.github/workflows/release.yml` (GoReleaser on `v*` tags)
- **MCP host config example:** see SPEC.md section 8 or README.md
