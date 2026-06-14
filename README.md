# TinyVault

Dead-simple local secrets management for developers and AI agents.

[![CI](https://github.com/abdul-hamid-achik/tinyvault/actions/workflows/ci.yml/badge.svg)](https://github.com/abdul-hamid-achik/tinyvault/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/abdul-hamid-achik/tinyvault)](https://goreportcard.com/report/github.com/abdul-hamid-achik/tinyvault)

TinyVault is a single-binary CLI tool and [MCP server](https://modelcontextprotocol.io) that stores secrets locally with strong encryption. No accounts, no servers, no cloud -- just a passphrase-protected vault on your machine.

> **See [SPEC.md](SPEC.md) for the full design doc** -- architecture, threat model, MCP security story, comparison with 1Password CLI / `pass` / Vault / Doppler, and roadmap.

## Features

- **AES-256-GCM Encryption** -- Two-tier key hierarchy with per-project data encryption keys
- **Argon2id Key Derivation** -- Memory-hard passphrase hashing resistant to GPU/ASIC attacks
- **Single Binary** -- One `tvault` binary for CLI use and MCP server mode
- **MCP Server** -- 18 tools: AI agents can manage secrets via the Model Context Protocol (stdio) without the values ever entering the model context
- **Multi-Project** -- Organize secrets into projects with independent encryption keys
- **.env Ecosystem** -- Safe dotenv parser (no shell expansion), `tvault://` placeholder interpolation, two-way sync (pull/push/mirror), and `.env.encrypted` files (Rails credentials pattern, KEK-tied, safe to commit)
- **Relational Search** -- `tvault search` and `vault_search_secrets` for prefix, name glob, time-range, version, and cross-project queries
- **Interactive Browser** -- `tvault browse`: a full-screen, read-only terminal UI (Bubble Tea v2) to browse status, projects, secrets, and audit — with a live filter and reveal-on-demand (`r` shows a value, `esc` re-masks). Never writes; all mutations stay in the CLI
- **Output Redaction** -- MCP server automatically redacts secret values from command output
- **Access Policy** -- YAML-based allow/deny patterns control what AI agents can access
- **Zero External Dependencies at Runtime** -- No database servers, no Docker, no network -- just a local bbolt file
- **Cross-Platform** -- Linux, macOS, Windows (amd64 and arm64)

## Install

```bash
# Homebrew (macOS/Linux)
brew install abdul-hamid-achik/tap/tvault

# Go install
go install github.com/abdul-hamid-achik/tinyvault/cmd/tvault@latest

# Or download a release binary from GitHub
```

## Quick Start

```bash
# Initialize a new vault (creates ~/.tvault/vault.db)
tvault init

# Store some secrets
tvault set DATABASE_URL "postgres://user:pass@localhost/mydb"
tvault set API_KEY "sk-abc123"

# Retrieve a secret
tvault get DATABASE_URL

# List all secrets
tvault list

# Run a command with secrets injected as environment variables
tvault run -- npm start

# Run with a .env file that has tvault:// placeholders (commit-safe templates)
tvault run --env-file .env -- npm start

# Export secrets
tvault env                     # shell format (eval-able)
tvault env --format dotenv     # .env file format
tvault env --format json       # JSON format
tvault env --format yaml       # YAML
tvault env --format k8s-secret --name=my-secret  # K8s Secret manifest

# Import dotenv files safely (no shell expansion, name allowlist)
tvault import .env
tvault import --env production
tvault import --interactive --env production

# Two-way sync between .env files and the vault
tvault sync --direction pull --path .env       # vault -> .env
tvault sync --direction push --path .env       # .env -> vault
tvault sync --direction mirror --path .env     # both, with conflict reporting

# Search secret metadata across all projects (metadata only, never decrypts)
tvault search --prefix STRIPE_
tvault search --project prod --name-like 'DB_*'
tvault search --since 2026-01-01T00:00:00Z
tvault list --prefix STRIPE_                    # project-scoped shortcut

# Encrypted .env files (Rails credentials pattern; safe to commit)
tvault encrypt-env --in .env --out .env.encrypted
tvault decrypt-env --in .env.encrypted --out .env

# Read a value from a .env file without unlocking the vault
tvault get API_KEY --from .env

# Machine-readable feature manifest for AI agents
tvault docs features
```

## Interactive Browser

`tvault browse` opens a full-screen terminal UI for browsing the vault — the
**human** surface alongside the CLI (scripts) and the MCP server (agents).

```bash
tvault browse                       # browse the current project
tvault browse webapp                # open a specific project
tvault browse --single-pane         # one pane at a time (small terminals)
tvault browse --no-anim             # disable animations (SSH / screen readers)
```

Four panes — **status**, **projects**, **secrets**, **audit** — with vim,
arrow, and mouse-wheel navigation. Press `/` to filter keys live, `r` to reveal
the selected value (warm orange = a secret is showing), `R` to reveal all,
`c` to copy, and `esc` to re-mask. Revealed values live only in memory and
are wiped on `esc`, on pane change, and on quit.

The browser is **read-only** — it never writes to the vault. Browsing
project/secret metadata works while the vault is locked; press `u` to
unlock in-app and reveal values. Light/dark theme is auto-detected from
your terminal. Run `tvault help browse` for the full keybinding cheat sheet.

## Projects

Organize secrets into isolated projects, each with its own encryption key:

```bash
# Create and switch to a project
tvault projects create staging
tvault use staging

# Secrets are now scoped to "staging"
tvault set DATABASE_URL "postgres://staging-server/mydb"

# Switch back
tvault use default

# List all projects
tvault projects list
```

## MCP Server (AI Agent Integration)

TinyVault can serve as an MCP server over stdio, letting AI agents (Claude, etc.) securely access and manage secrets.

### Setup with Claude Code

Add to `.claude/settings.local.json`:

```json
{
  "mcpServers": {
    "tvault": {
      "command": "tvault",
      "args": ["mcp-server"],
      "env": {
        "TVAULT_PASSPHRASE": "your-vault-passphrase"
      }
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `vault_list_projects` | List all projects with secret counts |
| `vault_create_project` | Create a project with its own DEK |
| `vault_delete_project` | Delete a project and all its secrets |
| `vault_list_secrets` | List secret keys in a project (metadata only) |
| `vault_search_secrets` | Relational search: by project, prefix, name glob, update time, version |
| `vault_list_secrets_by_prefix` | Cheaper prefix-only list (autocomplete-style) |
| `vault_get_secret` | Get a decrypted secret value (use sparingly) |
| `vault_set_secret` | Create or update a secret |
| `vault_delete_secret` | Delete a secret |
| `vault_generate_secret` | Generate a random secret and store it (value never returned) |
| `vault_run_with_secrets` | Run a command with secrets as env vars (output redacted) |
| `vault_export_env` | Write a .env file and return the path (values never sent to AI) |
| `vault_list_env_files` | Discover safe dotenv files without returning any values |
| `vault_preview_env_import` | Preview a dotenv import with key names, counts, and diagnostics only |
| `vault_import_env_files` | Import dotenv files into the vault without exposing values |
| `vault_status` | Vault metadata + lock state |
| `vault_audit_log` | Recent audit entries (newest first) |
| `vault_audit_log_since` | Time-range + action-filtered audit log |

The recommended pattern for an agent is to discover the surface once via
`tvault docs features`, then use the relational tools
(`vault_search_secrets`, `vault_list_secrets_by_prefix`) to find keys
without ever asking the model to enumerate values. Use
`vault_run_with_secrets` whenever the agent needs to *use* a value;
the value goes into the subprocess environment and never appears in
the model's context.

### Safe Dotenv Imports

TinyVault can safely read dotenv-family files like `.env`, `.env.local`,
`.env.production`, and `.env.production.local` without executing shell syntax or
expanding variables.

```bash
# Import an explicit file
tvault import .env.local

# Use the default chain for an environment:
# .env -> .env.production -> .env.local -> .env.production.local
tvault import --env production

# Interactively choose files, preview key-level changes, then confirm
tvault import --interactive --env production

# Explicit multi-file import in a custom order
tvault import --file .env --file .env.local --overwrite
```

### Access Policy

Control what the AI agent can access with `~/.tvault/mcp-policy.yaml`:

```yaml
access_mode: read-write    # read-only | read-write | full
allow_exec: false          # disable vault_run_with_secrets
redact_output: true        # redact secret values from command output

projects_allow:
  - "dev-*"
  - "staging"

projects_deny:
  - "production"

secrets_allow:
  - "DATABASE_*"
  - "API_KEY"

secrets_deny:
  - "*_PASSWORD"
  - "MASTER_KEY"
```

## CI/CD Integration

Use `TVAULT_PASSPHRASE` environment variable for non-interactive unlock:

```bash
export TVAULT_PASSPHRASE="your-vault-passphrase"
tvault get DATABASE_URL           # no prompt
tvault run -- ./deploy.sh         # secrets injected automatically
```

Generate CI workflow helpers:

```bash
tvault ci init --provider=github-actions
tvault ci init --provider=gitlab
```

## Key Management

```bash
# Rotate your vault passphrase
tvault key rotate

# Backup the vault
tvault backup ~/.tvault-backup/vault.db

# Restore from backup
tvault restore ~/.tvault-backup/vault.db
```

## Security

- **Encryption**: AES-256-GCM with random nonces per operation
- **Key Derivation**: Argon2id (64MB memory, 3 iterations, 4 parallelism)
- **Key Hierarchy**: Passphrase -> KEK (Key Encryption Key) -> per-project DEKs (Data Encryption Keys)
- **Storage**: Single bbolt file at `~/.tvault/vault.db` with 0600 permissions
- **Memory Safety**: Keys zeroed from memory after use
- **MCP Redaction**: Secret values automatically replaced with `[REDACTED:KEY]` in command output

## Architecture

```
~/.tvault/
  vault.db          # bbolt database (encrypted secrets, project metadata)
  config.yaml       # optional CLI configuration
  mcp-policy.yaml   # optional MCP access policy
```

```
tvault (single binary)
  cmd/tvault/       # CLI commands (cobra)
  internal/
    crypto/         # AES-256-GCM, Argon2id, key generation
    store/          # bbolt storage layer
    vault/          # High-level vault operations
    mcp/            # MCP server (18 tools, access policy, redaction)
    validation/     # Input validation
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TVAULT_PASSPHRASE` | Vault passphrase (for CI/CD, skips interactive prompt) |
| `TVAULT_DIR` | Vault directory (default: `~/.tvault`) |

## License

MIT
