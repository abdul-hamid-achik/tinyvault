---
title: Configuration & File Layout
description: How TinyVault reads ~/.tvault/config.yaml, where it stores the encrypted vault and identities on disk, and the precedence rules for the vault directory, identity, and project.
---

# Configuration & File Layout

This page documents the optional `~/.tvault/config.yaml` file, the complete on-disk layout under `~/.tvault/`, the repo-side files TinyVault touches in your project, and the precedence rules that decide which vault, identity, and project a command uses.

TinyVault works with zero configuration. A config file is optional, and a missing file is never an error. Everything here is for when you want to tune defaults or understand exactly where bytes live.

## The config file: `~/.tvault/config.yaml`

`tvault` reads a single optional YAML file at `~/.tvault/config.yaml`. Point at a different file with the global `--config <file>` flag.

A **missing** file is fine — `tvault` falls back to built-in defaults. A **malformed** file is a real error and is flagged by [`tvault doctor`](/cli/), so you can catch a broken config before it bites you in CI.

```yaml
# ~/.tvault/config.yaml

# Defaults for the interactive studio (tvault studio / browse / ui).
# The key is "browse:" for backwards compatibility with the old command name.
browse:
  no_anim: false       # disable studio animations
  single_pane: false   # use a single-pane layout instead of split panes
  audit_limit: 100     # how many audit-log entries the studio loads

# Bound to the global persistent flags (read by viper).
vault: ~/.tvault       # vault directory (same as --vault)
project: default       # current project (same as --project / -p)
verbose: false         # verbose output (same as --verbose / -v)
```

### What the typed config parses

Only the `browse:` block is parsed into TinyVault's typed config. It configures the [studio](/guide/studio), the interactive terminal UI.

| Key | Type | Default | What it does |
| --- | --- | --- | --- |
| `browse.no_anim` | bool | `false` | Disable studio animations. Also auto-disabled over SSH or when `TERM=dumb`. |
| `browse.single_pane` | bool | `false` | Render a single-pane layout instead of the split-pane view. |
| `browse.audit_limit` | int | `100` | How many audit-log entries the studio loads on open. |

### viper-bound keys

Beyond `browse:`, viper reads three top-level keys from the same file and binds them to the global persistent flags: `vault`, `project`, and `verbose`. Each is overridable by the matching environment variable.

| Config key | Flag | Environment override |
| --- | --- | --- |
| `vault` | `--vault <dir>` | `TVAULT_VAULT` |
| `project` | `-p` / `--project <name>` | `TVAULT_PROJECT` |
| `verbose` | `-v` / `--verbose` | `TVAULT_VERBOSE` |

::: tip Explicit flags always win
For every setting above, an explicit command-line flag overrides the config file. So `tvault studio --no-anim` disables animations even if `browse.no_anim` is `false`, and `tvault -p prod get API_KEY` uses `prod` regardless of `project:` in the file.
:::

::: warning A broken config is caught by doctor
If `~/.tvault/config.yaml` fails to parse, `tvault doctor` reports it and exits non-zero. Run `tvault doctor` after editing the file:

```bash
tvault doctor
```

`doctor` checks the vault directory and permissions, vault validity, lock state, the config and MCP-policy files, environment, and terminal — all **without** unlocking the vault.
:::

## The MCP access policy: `mcp-policy.yaml`

If you run the MCP server, an optional `~/.tvault/mcp-policy.yaml` lets you allow- or deny-list tools and enforce per-project access for AI agents. It lives alongside `config.yaml` and is validated by `tvault doctor`.

That file has its own page. See [MCP Access Policy](/mcp/access-policy) for the schema and examples.

::: danger Redaction is a safety net, not a control
The MCP server redacts secret values from tool output, but redaction only replaces literal values longer than three characters and can be evaded by transforming a value (encoding, slicing, reordering). It reduces accidental leaks; it does not contain a hostile agent. The MCP server never returns a raw secret value **except** `vault_get_secret`, which warns when it does. Use [`tvault projects share`](/guide/sharing) and the recipient model for real delegation, and lock down agents with [`mcp-policy.yaml`](/mcp/access-policy).
:::

## File layout: `~/.tvault/`

The vault directory is created with `0700` permissions (owner-only). Override its location with `--vault` or `TVAULT_DIR` (see [precedence](#path-precedence) below).

```text
~/.tvault/                         0700  vault directory (owner-only)
├── vault.db                       0600  bbolt database — the encrypted vault
├── config.yaml                    0600  optional, this page
├── mcp-policy.yaml                0600  optional, MCP access policy
├── identities/                    0700  asymmetric identities
│   └── <name>.key                 0600  one identity keypair per file
├── agent.sock                     0600  unix: agent socket (unix only)
├── agent.pid                            unix: agent PID file
└── agent.lock                           unix: agent single-instance lock
```

### What each file holds

| Path | Mode | Contents |
| --- | --- | --- |
| `vault.db` | `0600` | The bbolt database. Holds the encrypted `secrets` and `secret_versions`, project metadata with wrapped per-project DEKs, the audit log, and the KEK verifier plus Argon2id salt. This is the only file that contains secret material. |
| `config.yaml` | `0600` | Optional configuration ([above](#the-config-file-tvault-config-yaml)). |
| `mcp-policy.yaml` | `0600` | Optional [MCP access policy](/mcp/access-policy). |
| `identities/<name>.key` | `0600` | One asymmetric identity per file. Stores the **private** half (`tvault-key1...`); the **public** half (`tvault1...`) is derived and shareable. See [Sharing](/guide/sharing) and [Key management](/guide/key-management). |
| `agent.sock` | `0600` | Unix-only. The [agent](/guide/agent) listens here so `get`/`env`/`run` can skip the passphrase prompt. |
| `agent.pid` | — | Unix-only. PID of the running agent. |
| `agent.lock` | — | Unix-only. `flock` file enforcing a single agent instance. |

::: info Agent files are unix-only
`agent.sock`, `agent.pid`, and `agent.lock` exist only on Linux and macOS. The agent is not available on Windows.
:::

::: danger Never commit the vault directory
`~/.tvault/` contains your encrypted vault and private identity keys. Keep it out of version control and out of backups you do not control. `tvault identity export` prints a **private** key (`tvault-key1...`); it is TTY-guarded and requires `--force` to write off a terminal, precisely because that output must never land in a log or a committed file.
:::

## Repo-side files (in your project)

These files live in your **project repository**, not under `~/.tvault/`. They make encrypted secrets safe to commit and let `git` filters encrypt and decrypt on the fly. See [Committable secrets](/guide/committable-secrets) and [Git filter](/guide/git-filter).

| File | Commit it? | Contents |
| --- | --- | --- |
| `.tvault-recipients` | Yes | The read-set: a list of public recipients (`tvault1...`) who can decrypt. Used by the git filter and by sealing. Committing it is safe — public keys only. |
| `.env.encrypted` | Yes | Committable ciphertext. v1 is passphrase-based; v2 wraps to the recipients in `.tvault-recipients` and is KEK-independent. |
| `.gitattributes` | Yes | Registers the clean/smudge filter (written by `tvault git-filter track`). |
| `.env` (and other plaintext dotenvs) | **No** | Plaintext import/export targets. Keep these in `.gitignore`. |

```bash
# Typical project setup
tvault projects share myapp --to tvault1exampleRecipient   # writes .tvault-recipients
tvault git-filter track                                     # writes .gitattributes
git add .tvault-recipients .gitattributes .env.encrypted
echo ".env" >> .gitignore
```

::: warning `.env` is plaintext — never commit it
The plaintext `.env` is an import/export convenience only. Commit `.env.encrypted` instead, and keep `.env` in `.gitignore`. Likewise, `tvault k8s render` writes **plaintext** YAML to stdout — pipe it straight to `kubectl` and never commit the result:

```bash
tvault k8s render myapp --project myapp | kubectl apply -f -
```
:::

::: tip Revocation is real, not cosmetic
When you remove a recipient with `tvault projects unshare`, TinyVault rotates the project DEK and **re-encrypts every value and its version history**. A revoked recipient cannot decrypt new ciphertext, and old wrapped keys are invalidated — this is true revocation, not key re-wrapping.
:::

## Path precedence

When a setting can come from several places, TinyVault resolves it left-to-right (first match wins).

### Vault directory

```text
--vault <dir>   >   TVAULT_DIR   >   ~/.tvault
```

The flag beats the environment variable, which beats the default home location.

### Identity: file vs. env key

The **private key material** is resolved before its name:

```text
~/.tvault/identities/<name>.key   >   TVAULT_IDENTITY_KEY
```

A local identity **file** always takes precedence over a `TVAULT_IDENTITY_KEY` set in the environment. When a file overrides a set env key, `tvault` prints a warning to stderr so the override is visible. The env key's value is never echoed in an error message.

::: info `TVAULT_IDENTITY_KEY` is for CI and agents
`TVAULT_IDENTITY_KEY` carries a **private** identity string (`tvault-key1...`) for passphrase-free decryption in CI, SSH sessions, or agents that have no key file on disk. Treat it like any other secret — inject it from your CI secret store, never hard-code it. See [CI/CD](/guide/ci-cd).
:::

### Identity name

Which named identity to use (when not supplying raw key material):

```text
--identity <name>   >   TVAULT_IDENTITY   >   git config tvault.identity   >   "default"
```

This is the **name** used for git-filter and recipient reads, not the key itself. The fallback chain ends at the identity literally named `default`.

### Project

```text
--project <name>   >   stored current project   >   "default"
```

The `-p`/`--project` flag beats the project you last selected (stored in the vault), which beats the project named `default`.

## Global persistent flags

These six flags work on **every** `tvault` command:

| Flag | Effect |
| --- | --- |
| `--config <file>` | Use an alternate config file instead of `~/.tvault/config.yaml`. |
| `--vault <dir>` | Use an alternate vault directory. |
| `-p`, `--project <name>` | Operate on a specific project. |
| `--json` | Emit machine-readable JSON. |
| `-v`, `--verbose` | Verbose output. |
| `--no-agent` | Bypass a running agent and unlock directly (same as `TVAULT_NO_AGENT`). |

`-h`/`--help` is available everywhere. `--version` is **root-only** — print it with `tvault --version` (there is no `version` subcommand).

For the full environment-variable reference, see [Environment variables](/reference/environment-variables).

## Exit codes

Scripts can branch on `tvault`'s exit status:

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Generic error. |
| `3` | Vault is locked at rest. |
| `4` | Secret or project not found. |
| `5` | Vault not initialized. |
| `6` | Wrong passphrase. |
| `7` | Vault database is in use by another process. |

```bash
if ! tvault get API_KEY --project myapp >/dev/null 2>&1; then
  case $? in
    3) echo "vault is locked — run: tvault unlock" ;;
    4) echo "no such secret" ;;
    5) echo "run: tvault init" ;;
    6) echo "wrong passphrase" ;;
    *) echo "tvault failed" ;;
  esac
fi
```

## See also

- [Environment variables](/reference/environment-variables) — every `TVAULT_*` variable in detail.
- [MCP Access Policy](/mcp/access-policy) — the schema for `mcp-policy.yaml`.
- [Studio](/guide/studio) — the interactive UI the `browse:` block configures.
- [Security](/reference/security) — the threat model behind these defaults.
