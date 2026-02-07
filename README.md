# TinyVault

Dead-simple local secrets management for developers and AI agents.

[![CI](https://github.com/abdul-hamid-achik/tinyvault/actions/workflows/ci.yml/badge.svg)](https://github.com/abdul-hamid-achik/tinyvault/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/abdul-hamid-achik/tinyvault)](https://goreportcard.com/report/github.com/abdul-hamid-achik/tinyvault)

TinyVault is a single-binary CLI tool and [MCP server](https://modelcontextprotocol.io) that stores secrets locally with strong encryption. No accounts, no servers, no cloud -- just a passphrase-protected vault on your machine.

## Features

- **AES-256-GCM Encryption** -- Two-tier key hierarchy with per-project data encryption keys
- **Argon2id Key Derivation** -- Memory-hard passphrase hashing resistant to GPU/ASIC attacks
- **Single Binary** -- One `tvault` binary for CLI use and MCP server mode
- **MCP Server** -- AI agents can manage secrets via the Model Context Protocol (stdio)
- **Multi-Project** -- Organize secrets into projects with independent encryption keys
- **Output Redaction** -- MCP server automatically redacts secret values from command output
- **Access Policy** -- YAML-based allow/deny patterns control what AI agents can access
- **Zero Dependencies** -- No database servers, no Docker, no network -- just a local bbolt file
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

# Export secrets
tvault env                     # shell format (eval-able)
tvault env --format dotenv     # .env file format
tvault env --format json       # JSON format
```

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
| `vault_list_secrets` | List secret keys in a project |
| `vault_get_secret` | Get a decrypted secret value |
| `vault_set_secret` | Create or update a secret |
| `vault_delete_secret` | Delete a secret |
| `vault_run_with_secrets` | Run a command with secrets as env vars (output redacted) |
| `vault_export_env` | Write a .env file and return the path (values never sent to AI) |

### Access Policy

Control what the AI agent can access with `~/.tvault/mcp-policy.yaml`:

```yaml
access_mode: read-write    # read-only | read-write | full
allow_exec: false          # disable vault_run_with_secrets
redact_output: true        # redact secret values from command output

allow_projects:
  - "dev-*"
  - "staging"

deny_projects:
  - "production"

allow_secrets:
  - "DATABASE_*"
  - "API_KEY"

deny_secrets:
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
tvault backup --restore ~/.tvault-backup/vault.db
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
    mcp/            # MCP server (7 tools, access policy, redaction)
    validation/     # Input validation
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TVAULT_PASSPHRASE` | Vault passphrase (for CI/CD, skips interactive prompt) |
| `TVAULT_DIR` | Vault directory (default: `~/.tvault`) |

## License

MIT
