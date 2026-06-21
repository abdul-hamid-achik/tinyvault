# TinyVault

Dead-simple local secrets management for developers and AI agents.

[![CI](https://github.com/abdul-hamid-achik/tinyvault/actions/workflows/ci.yml/badge.svg)](https://github.com/abdul-hamid-achik/tinyvault/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/abdul-hamid-achik/tinyvault)](https://goreportcard.com/report/github.com/abdul-hamid-achik/tinyvault)

📖 **Documentation → [tinyvault.dev](https://tinyvault.dev)**

TinyVault is a single-binary CLI tool and [MCP server](https://modelcontextprotocol.io) that stores secrets locally with strong encryption. No accounts, no servers, no cloud -- just a passphrase-protected vault on your machine.

> **See [SPEC.md](SPEC.md) for the full design doc** -- architecture, threat model, MCP security story, comparison with 1Password CLI / `pass` / Vault / Doppler, and roadmap.

## Documentation

📖 **Full documentation: [tinyvault.dev](https://tinyvault.dev)** — the guide, the complete CLI reference, the MCP tool catalog, configuration, architecture, and the threat model. The site is built from [`docs/`](docs/) (VitePress + Bun) and deployed on Vercel.

## For AI agents

TinyVault is built to be driven by agents without secret values ever entering the model's context. **Run `tvault docs features`** for a machine-readable JSON manifest of every capability, then follow the discover → search → use loop (`tvault help agent --json` documents it). Connect an MCP client to `tvault mcp` (36 tools). Start at the [For AI Agents](https://tinyvault.dev/guide/for-ai-agents) guide.

## Features

- **AES-256-GCM Encryption** -- Two-tier key hierarchy with per-project data encryption keys
- **Argon2id Key Derivation** -- Memory-hard passphrase hashing resistant to GPU/ASIC attacks
- **Single Binary** -- One `tvault` binary for CLI use and MCP server mode
- **MCP Server** -- 36 tools: AI agents can manage secrets via the Model Context Protocol (stdio) without the values ever entering the model context
- **Multi-Project** -- Organize secrets into projects with independent encryption keys
- **.env Ecosystem** -- Safe dotenv parser (no shell expansion), `tvault://` placeholder interpolation, two-way sync (pull/push/mirror), and `.env.encrypted` files (Rails credentials pattern, safe to commit)
- **Share & commit secrets** -- X25519 recipients (age-style): share a project without the passphrase, commit self-decrypting secrets via `git-filter` (transparent clean/smudge) or v2 `.env.encrypted`, and seal for recipients over MCP. Revocation rotates the key and re-encrypts.
- **Versioned secrets** -- every overwrite archives the prior value; `tvault history`, `tvault get --version N`, and `tvault rollback --to N` (also over MCP) let you inspect and restore past values. History survives key rotation.
- **Local agent (unix)** -- `tvault agent` holds the vault unlocked over a private 0600 socket so daily `get/env/run` skip the passphrase prompt and Argon2id; `tvault hook` wires it into bash/zsh/fish/direnv. Auto-locks when idle.
- **Relational Search** -- `tvault search` and `vault_search_secrets` for prefix, name glob, time-range, version, and cross-project queries
- **Interactive Studio** -- `tvault studio` (aliases: `browse`, `ui`): a full-screen terminal UI (Bubble Tea v2) to browse status, projects, secrets, and audit — with a live filter and reveal-on-demand (`r` shows a value, `esc` re-masks). Read-only by default; `--rw` enables audited in-app new/edit/delete
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

# Debian/Ubuntu/Fedora/Alpine — .deb / .rpm / .apk on the Releases page
# (or grab the .tar.gz for your OS/arch)

# Already installed? Update in place (checksum-verified):
tvault self-update
```

Deploying to a server? See [Deploy to DigitalOcean & SSH servers](https://tinyvault.dev/guide/digitalocean) for the passphrase-free, manage-over-SSH workflow.

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

# See how a .env has drifted from the vault (metadata-only; --values compares values)
tvault diff .env
tvault diff .env --values

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
tvault encrypt-env --in .env --out .env.encrypted          # tied to the passphrase
tvault decrypt-env --in .env.encrypted --out .env
tvault encrypt-env --in .env --recipient tvault1… --out .env.encrypted  # commit-safe, no passphrase
tvault decrypt-env --in .env.encrypted --identity ci --out .env

# Read a value from a .env file without unlocking the vault
tvault get API_KEY --from .env

# Machine-readable feature manifest for AI agents
tvault docs features
```

## Interactive Studio

`tvault studio` opens a full-screen terminal UI for browsing the vault — the
**human** surface alongside the CLI (scripts) and the MCP server (agents). The
`browse` and `ui` aliases still work for backwards compatibility.

```bash
tvault studio                       # browse the current project
tvault studio --rw                  # enable in-app new/edit/delete (audited)
tvault studio webapp                # open a specific project
tvault studio --single-pane         # one pane at a time (small terminals)
tvault studio --no-anim             # disable animations (SSH / screen readers)
```

Four panes — **status**, **projects**, **secrets**, **audit** — with vim,
arrow, and mouse-wheel navigation. Press `/` to filter keys live, `r` to reveal
the selected value (warm orange = a secret is showing), `R` to reveal all,
`c` to copy, and `esc` to re-mask. Revealed values live only in memory and
are wiped on `esc`, on pane change, and on quit.

The studio is **read-only by default** — a stray keystroke can't change
anything. Launch with `--rw` to enable in-app `n`ew / `e`dit / `d`elete,
which use the same encryption path as the CLI and are written to the audit
log just like `tvault set`/`delete`. Browsing metadata works while locked;
press `u` to unlock in-app. Light/dark theme is auto-detected. Run
`tvault help studio` for the full keybinding cheat sheet.

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

## Local agent (unlock once)

Re-entering the passphrase (and paying ~200ms of Argon2id) on every command
gets old. The agent (unix: linux/macOS) unlocks once and serves reads over a
private socket, so `get`/`env`/`run` are instant and prompt-free:

```bash
tvault agent start &                 # unlock once; runs in the foreground (background it)
eval "$(tvault hook zsh)"            # add to ~/.zshrc; defines tvault_load
tvault get DATABASE_URL              # no prompt — served by the agent
tvault_load                          # load the current project's secrets into the shell
tvault agent status
tvault agent stop                    # zeroes the KEK
```

The socket is `0600` inside the `0700` vault dir and accepts only same-uid
peers; the agent caches **only the KEK** (not an open database), so direct CLI
access keeps working between requests, and it **auto-locks after 15m idle**
(`--idle`), zeroing the KEK on stop/idle/signal. Bypass it any time with
`--no-agent` or `TVAULT_NO_AGENT=1`. Not available on Windows (use the direct
CLI or `mcp`). See `tvault docs agent`.

For an OS-confined delegate (a different uid, a container with the socket
bind-mounted, a sandbox) you can run the agent with `--require-token
--token-file <f>`: it then denies any socket request without a valid token, and
a `token[:project]` line scopes a token to one project (set `TVAULT_AGENT_TOKEN`
in the delegate). This is privilege separation, **not** a defense against a
same-uid process — for untrusted/CI/container delegation, prefer a scoped
**identity** (`tvault identity new` + `projects share`), which is cryptographic
and atomically revocable. See `tvault docs agent` and SPEC §5.5.

## Secret history & rollback

Every time you overwrite a secret, the prior value is archived as a version —
so a fat-fingered `set` or a bad rotation is always recoverable:

```bash
tvault set API_KEY v1 && tvault set API_KEY v2 && tvault set API_KEY v3
tvault history API_KEY            # v1, v2, v3 (metadata only — no values, no unlock)
tvault get API_KEY --version 1    # print a specific past value
tvault rollback API_KEY --to 1    # restore v1 as a new v4 (non-destructive)
```

Rollback is non-destructive: the value it replaces is itself archived, and
version numbers are never reused. History is encrypted with the project key, so
it survives passphrase rotation and recipient revocation (the key rotates and
every version is re-encrypted). Agents get the same via the `vault_secret_history`
and `vault_rollback_secret` MCP tools — neither ever returns a value.

## Sharing secrets (without sharing the passphrase)

Share a project with a teammate, a CI runner, or an agent using **X25519
recipients** (age-style) — no one needs the master passphrase:

```bash
# On the recipient's side: make an identity; the recipient string is public.
tvault identity new ci            # prints: tvault1…  (private key stays 0600)

# On the owner's side: grant that recipient access to a project.
tvault projects share tvault1…    # -p webapp to pick a project
tvault projects recipients        # see who has access

# The recipient reads the project with their identity — no passphrase:
tvault env --identity ci --format dotenv

# Revoke: rotates the project key and re-encrypts every value, so the
# removed recipient loses access even from an old copy of the vault.
tvault projects unshare tvault1…
```

The data key is wrapped per-recipient (X25519 → HKDF-SHA256 →
ChaCha20-Poly1305); secret values stay encrypted under the project key.
This is also the foundation for committing self-decrypting secrets to a
repo (below). See `tvault docs secret-sharing`.

## Committing secrets to your repo

Two ways to keep secrets *in* the repo while keeping them encrypted in
history — both keyed by the same X25519 recipients, so no passphrase ever
touches the files.

**1. Standalone encrypted files** (`encrypt-env --recipient`, or `seal`). A
self-contained `.env.encrypted` (v2 format) that anyone holding a matching
identity can open — a teammate, CI, or an agent — with no vault unlock, and
rotating the vault passphrase doesn't invalidate it:

```bash
tvault encrypt-env --in .env --recipient tvault1… --out .env.encrypted
tvault decrypt-env --in .env.encrypted --identity ci          # no passphrase

# Or seal a project straight from the vault (no plaintext .env on disk):
tvault seal --recipient tvault1… > .env.encrypted
tvault open --in .env.encrypted --identity ci > .env
tvault seal -r tvault1… | ssh deploy 'tvault open --identity host > .env'
```

**2. Transparent git filters** (`git-filter`) — secrets look like plaintext
in your working tree but are stored encrypted in history, git-crypt style:

```bash
tvault identity new                                   # if you don't have one
tvault git-filter install --recipient tvault1…        # configure this repo
tvault git-filter track .env 'secrets/*.env'          # what to encrypt
git add .gitattributes .tvault-recipients && git commit -m "enable tvault"

# A teammate / CI / agent who holds a recipient identity:
git clone … && cd … && tvault git-filter install      # decrypts the working tree
```

Recipients live in a committed `.tvault-recipients` file (public keys only),
so the read-set travels with the repo — add a teammate by appending their
recipient and committing. Anyone without an identity sees only ciphertext
("locked"), and the clean filter re-emits unchanged blobs so `git status`
stays quiet. `tvault git-filter status` shows config, recipients, and
whether your identity is available. See `tvault docs committable-secrets`.

**3. Kubernetes (commit-safe Secrets, SealedSecret-style)** — seal a project
into a manifest you commit, then render a real `Secret` at deploy with the
cluster's identity (no cluster controller required):

```bash
# author (has the cluster's public recipient):
tvault seal --format k8s --name app-secrets -p prod --recipient tvault1cluster… > sealed.yaml
git add sealed.yaml                       # encryptedData is ciphertext — safe to commit

# deploy (holds the cluster identity, e.g. TVAULT_IDENTITY_KEY in an init container):
tvault k8s render --in sealed.yaml --identity cluster | kubectl apply -f -
```

The rendered `Secret` is plaintext — pipe it to `kubectl`, never commit it.
See `tvault docs k8s`.

## MCP Server (AI Agent Integration)

TinyVault can serve as an MCP server over stdio, letting AI agents (Claude, etc.) securely access and manage secrets.

### Setup with Claude Code

Add to `.claude/settings.local.json`:

```json
{
  "mcpServers": {
    "tvault": {
      "command": "tvault",
      "args": ["mcp"],
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
| `vault_seal_for_recipients` | Seal secrets to X25519 recipients (returns ciphertext only; openable with `decrypt-env --identity`) |
| `vault_secret_history` | List a secret's version history (metadata only, never values) |
| `vault_rollback_secret` | Restore an earlier version as a new version (returns version numbers only) |
| `vault_get_current_project` | Report the current/default project |
| `vault_set_current_project` | Switch the current/default project |
| `vault_count_secrets` | Count secrets in a project (no keys or values) |
| `vault_search_projects` | Find projects by name/description glob (`*`) |
| `vault_projects_overview` | Every accessible project with description, secret count, and timestamps |
| `vault_list_secrets_detailed` | List keys with their real version and created/updated timestamps |
| `vault_list_secrets_global` | Cross-project secret discovery by prefix, name, time, or version |
| `vault_share_project` | Grant an X25519 recipient (`tvault1…`) read access (wraps the DEK) |
| `vault_unshare_project` | Revoke a recipient (rotates the DEK and re-encrypts every value + version) |
| `vault_project_recipients` | List the public recipients a project is shared with |
| `vault_diff_env` | Drift between a `.env` file and the project (verdicts only, never values) |
| `vault_sync_env` | Reconcile a `.env` with the project: pull / push / mirror |
| `vault_export_env_encrypted` | Write a commit-safe `.env.encrypted` (v2) sealed to the project's current recipients (ciphertext only) |
| `vault_identity_new` | Create an X25519 identity; returns the public recipient only (never the private key) |
| `vault_identity_list` | List local identities and their public recipients |

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

### CI without the passphrase (per-context identity)

Better still, give CI a **per-context identity** instead of the master
passphrase. The runner holds a `tvault-key1…` private key as the
`TVAULT_IDENTITY_KEY` secret and decrypts committed/recipient-sealed secrets
with it — the passphrase never leaves your machine, and rotating it doesn't
break CI:

```bash
tvault identity new ci                                  # provision a CI identity
tvault projects share <recipient>                       # or add it to .tvault-recipients
tvault identity export ci --force | gh secret set TVAULT_IDENTITY_KEY
tvault ci init --provider=github-actions --mode=identity --identity=ci
```

In the workflow, `TVAULT_IDENTITY_KEY` is enough — `decrypt-env`, `open`, and
`git-filter checkout` all use it automatically (no `--identity` needed). A
local identity file always takes precedence over the env key, so dev machines
stay deterministic. The same `TVAULT_IDENTITY_KEY` works over ssh and for
agents: `tvault seal | ssh host 'tvault open > .env'`.

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
    mcp/            # MCP server (36 tools, access policy, redaction)
    validation/     # Input validation
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TVAULT_PASSPHRASE` | Vault passphrase (for CI/CD, skips interactive prompt) |
| `TVAULT_NO_AGENT` | Set to bypass a running `tvault agent` and unlock the vault directly |
| `TVAULT_AGENT_TOKEN` | Capability token sent to a `--require-token` agent (privilege separation for confined delegates) |
| `TVAULT_IDENTITY_KEY` | A private identity (`tvault-key1…`) for passphrase-free decrypt in CI/ssh/agents; a local identity file takes precedence |
| `TVAULT_IDENTITY` | Default identity name for git filters / recipient reads (default: `default`) |
| `TVAULT_DIR` | Vault directory (default: `~/.tvault`) |

## License

MIT
