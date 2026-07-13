---
title: Secrets & Search
description: Set, read, list, delete, and search secrets in TinyVault — encrypted at rest with AES-256-GCM, with metadata search that never decrypts.
---

# Secrets & Search

Secrets are key/value pairs stored inside a project. Every value is encrypted at rest with AES-256-GCM under the project's data-encryption key. This page covers the commands you use day to day — `set`, `get`, `list`, `delete` — and the relational `search` that finds keys without ever decrypting them.

All commands operate on the **active project** unless you pass `-p`/`--project`. See [Projects](/guide/projects) for how the active project is chosen.

## Setting secrets

`tvault set <key> [value]` (alias `s`) writes a secret. There are several ways to supply the value so you never have to paste a plaintext secret onto your shell history.

```bash
# Inline value (visible in shell history — fine for throwaway values)
tvault set DATABASE_URL "postgres://user:pass@localhost/app"

# From stdin (keeps the value out of history; great for pipes)
echo "sk-xxxx" | tvault set API_KEY --stdin

# From a file (multi-line values, JSON credentials, certs)
tvault set GCP_CREDENTIALS --from-file credentials.json

# From a dotenv file, matching the same key name
tvault set DATABASE_URL --from-env .env

# From a dotenv file when the source key name differs
tvault set DB_URL --from-env .env --key DATABASE_URL
```

When you do not pass a value and stdin is not a terminal, `tvault set` reads the value from stdin automatically — so `cat secret.txt | tvault set TOKEN` works without `--stdin`. On an interactive terminal it prompts you instead.

| Flag | Purpose |
| --- | --- |
| `--stdin` | Read the value from stdin. |
| `-f`, `--from-file <path>` | Read the value verbatim from a file. |
| `--from-env <path>` | Read the value from a dotenv file. |
| `--key <name>` | Source key name in the dotenv file when it differs from `<key>`. Only meaningful with `--from-env`. |

::: warning
An empty value is rejected. `tvault set` requires a non-empty string.
:::

::: info
Every `set` archives the prior value before overwriting it, in the same transaction. Nothing is lost — you can inspect or restore old values later. See [Versioning & Rollback](/guide/versioning).
:::

### Generating random secrets

There is **no** `tvault generate` command. Random secret generation is available only over MCP, via the `vault_generate_secret` tool, so an AI agent can create and store a strong value without a human ever seeing it. See [MCP Tools](/mcp/tools).

## Reading secrets

`tvault get <key>` (alias `g`) prints the decrypted value to **stdout**. Status messages go to stderr, so the command is pipe- and `$(...)`-friendly.

```bash
tvault get DATABASE_URL

# Capture into a shell variable
DB_URL=$(tvault get DATABASE_URL)

# JSON output (key + value)
tvault get API_KEY --json

# Read a specific historical version
tvault get API_KEY --version 2

# Read a value straight from a dotenv file (no vault, no unlock)
tvault get DATABASE_URL --from .env
```

| Flag | Purpose |
| --- | --- |
| `--from <path>` | Read the value from a dotenv file instead of the vault. No unlock; the value is read verbatim with no interpolation. |
| `--version <N>` | Print a specific historical version instead of the current one. |

For `${tvault://...}` interpolation, use [`tvault run`](/guide/run-and-env) rather than `get --from`.

::: tip
A running [agent](/guide/agent) serves current-version reads with no passphrase prompt and no Argon2id work. Use `--no-agent` to force a direct unlock.
:::

## Listing secrets

`tvault list` (alias `ls`) prints the key names in the active project. It shows **keys only** — never values.

```bash
# All keys in the active project
tvault list

# Keys in a specific project
tvault list -p production

# Keys matching a prefix
tvault list --prefix STRIPE_
```

| Flag | Purpose |
| --- | --- |
| `--prefix <str>` | Only list keys starting with this prefix. |

## Deleting secrets

`tvault delete <key>` (aliases `rm`, `remove`) removes a secret from the active project. By default it asks you to confirm.

```bash
tvault delete OLD_TOKEN

# Skip the confirmation prompt
tvault delete OLD_TOKEN -y
```

| Flag | Purpose |
| --- | --- |
| `-y`, `--yes` | Skip the confirmation prompt. |

::: warning
Deleting a key also purges that key's version history. This is destructive and cannot be undone from within the vault — restore from a [backup](/cli/) if you need it back.
:::

## Search

`tvault search` runs a relational query over the vault's **metadata** — project names, key names, versions, and update timestamps. By default it runs across **all** projects.

::: danger Search never decrypts
`tvault search` never reads, decrypts, or returns a secret value. It only matches metadata. To use a value, follow up with `tvault get <key>` or [`tvault run`](/guide/run-and-env). This makes search safe to wire into agents and dashboards that should discover keys but never see secrets.
:::

```bash
# Every key matching a prefix, across all projects
tvault search --prefix STRIPE_

# Keys in one project matching a wildcard pattern
tvault search --project production --name-like 'DB_*'

# Secrets updated on or after a timestamp
tvault search --since 2026-01-01T00:00:00Z

# Secrets that have been rotated at least twice
tvault search --project default --min-version 2

# Machine-readable output for tooling
tvault search --prefix API_ --json
```

| Flag | Purpose |
| --- | --- |
| `-p`, `--project <name>` | Restrict to one project. Omit to search every project. |
| `--prefix <str>` | Only keys starting with this prefix. |
| `--name-like <pat>` | Pattern with `*` as the wildcard, e.g. `STRIPE_*` or `*_URL`. |
| `--since <ts>` | RFC3339 timestamp; only secrets updated at or after it. |
| `--until <ts>` | RFC3339 timestamp; only secrets updated at or before it. |
| `--min-version <N>` | Only secrets whose current version is `>= N`. |
| `--limit <N>` | Maximum number of results (default `200`). |

The default text output is one tab-separated row per match — `project/key`, version, and update time:

```
production/DATABASE_URL	v3	2026-06-18T10:42:11Z
production/DB_REPLICA_URL	v1	2026-05-02T09:15:00Z
```

With `--json` you get a structured object containing the `query`, a `count`, and the `results` array — convenient when an agent or CI step needs to enumerate keys programmatically.

## Encryption & integrity

Every secret value is encrypted with **AES-256-GCM** under the project's data-encryption key, which is itself wrapped by your passphrase-derived key via Argon2id. Values are never written to disk in plaintext, and the GCM tag detects tampering on read.

::: warning Plaintext appears only where you ask for it
Commands that exist to emit usable values — `tvault get`, [`env`](/guide/run-and-env), [`export`](/cli/), and `k8s render` — print **plaintext**. Pipe them into the consumer (a shell, `kubectl`, a process) and never redirect them into a committed file.
:::

When removing a recipient, [`tvault projects unshare`](/guide/sharing) **rotates the project DEK and re-encrypts every current value and archived version in the updated live vault**. The removed identity cannot decrypt that new state or future writes under the new DEK. Pre-removal vault copies and already exported, sealed, or decrypted data remain readable, so rotate underlying credentials when needed.

## Global flags

These persistent flags work on every command on this page:

| Flag | Purpose |
| --- | --- |
| `--config <file>` | Compatibility selector for Viper input; it does not relocate the typed studio config. |
| `--vault <dir>` | Use a specific vault directory. |
| `-p`, `--project <name>` | Operate on this project instead of the active one. |
| `--json` | Emit machine-readable JSON. |
| `-v`, `--verbose` | Verbose output. |
| `--no-agent` | Bypass the local agent and unlock directly. |

`-h`/`--help` is available everywhere; `--version` is a root-only flag (there is no `version` subcommand).

## Exit codes

Scripts and CI can branch on the exit code:

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Generic error. |
| `3` | Vault is locked. |
| `4` | Secret or project not found. |
| `5` | Vault is not initialized. |
| `6` | Wrong passphrase. |

## See also

- [Versioning & Rollback](/guide/versioning) — inspect and restore prior values that `set` archives.
- [Run & Environment](/guide/run-and-env) — inject secrets into a process and resolve `${tvault://...}` references.
- [Projects](/guide/projects) — how the active project is chosen and scoped.
- [MCP Tools](/mcp/tools) — generation (`vault_generate_secret`) and the rest of the agent-facing surface.
