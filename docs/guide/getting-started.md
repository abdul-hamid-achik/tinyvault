---
title: Getting Started
description: Install TinyVault, create your first encrypted vault, and learn the core set/get/run/env loop in a few minutes.
---

# Getting Started

TinyVault is a single binary (`tvault`, written in Go) that stores secrets locally in one encrypted file and works with any stack — `tvault run` injects secrets as env vars into Node, Python, Ruby, Rust, PHP, Go, or anything that reads them. This page takes you from zero to a working vault: install the binary, initialize a vault, store and read a secret, and inject secrets into a process.

## Install

Pick whichever fits your setup. All three give you the same `tvault` binary.

```bash
# Homebrew (macOS / Linux)
brew install abdul-hamid-achik/tap/tvault

# Go toolchain (Go 1.22+)
go install github.com/abdul-hamid-achik/tinyvault/cmd/tvault@latest

# Or download a prebuilt release binary and put it on your PATH:
# https://github.com/abdul-hamid-achik/tinyvault/releases
```

Verify the install:

```bash
tvault --version
```

::: info
`--version` is a root-only flag; there is no `tvault version` subcommand. `--help` (and `-h`) works on every command, and `tvault help` opens the long-form manual.
:::

## Initialize your vault

`tvault init` creates the vault file and a `default` project, then prompts you to set a passphrase. This passphrase is the only thing that can unlock your vault, so choose a strong one and store it somewhere safe.

```bash
tvault init
```

This writes `~/.tvault/vault.db` — a single encrypted [bbolt](https://github.com/etcd-io/bbolt) file, mode `0600` — inside `~/.tvault/` (mode `0700`). Your secrets, their version history, project metadata, the audit log, and the key-derivation salt all live in that one file.

::: warning
There is no passphrase recovery. The passphrase feeds Argon2id to derive the key that protects everything in the vault. If you lose it, the data is unrecoverable by design. Keep a [backup](/guide/key-management) of the vault file and the passphrase.
:::

For non-interactive use (CI, scripts), set `TVAULT_PASSPHRASE` and `init` uses it instead of prompting:

```bash
export TVAULT_PASSPHRASE='your-strong-passphrase'
tvault init
```

::: tip
Exporting `TVAULT_PASSPHRASE` into your shell history or a CI log is risky. For pipelines, prefer the passphrase-free, identity-based flow in [CI/CD](/guide/ci-cd) and [Committable secrets](/guide/committable-secrets).
:::

## The core loop: set, get, list

Store a secret with `tvault set <key> [value]`. Keys are uppercase, environment-style names by convention.

```bash
tvault set DATABASE_URL "postgres://user:pass@localhost/app"
tvault set API_KEY "sk-xxxx"
```

Read it back with `tvault get <key>`:

```bash
tvault get DATABASE_URL
```

List the keys in the current project with `tvault list` — metadata only, it never prints values:

```bash
tvault list
tvault list --prefix STRIPE_   # only keys starting with STRIPE_
```

A few things worth knowing about `set`:

| Flag | What it does |
| --- | --- |
| `--stdin` | Read the value from standard input (no value on the command line). |
| `-f`, `--from-file <path>` | Read the value from a file (whole-file contents). |
| `--from-env <path>` | Read the value for this key out of a dotenv file. |
| `--key <name>` | Override the key name (useful with the file/stdin sources). |

```bash
# Avoid putting the value in your shell history:
printf 'sk-xxxx' | tvault set API_KEY --stdin

# Pull a multi-line secret (a private key, a cert) from a file:
tvault set TLS_CERT --from-file ./server.pem
```

An empty value is rejected. Every overwrite archives the prior value first, so you keep a version history — see [Versioning](/guide/versioning). To remove a key and purge its history:

```bash
tvault delete API_KEY        # prompts for confirmation
tvault delete API_KEY -y     # skip the prompt
```

## Run a command with secrets injected

`tvault run` decrypts the current project's secrets, exports them as environment variables for a child process, and runs it. Everything after `--` is the command and its arguments — the `--` separator is required.

```bash
tvault run -- npm start
tvault run -- python manage.py migrate
```

`run` forwards `SIGINT`/`SIGTERM` to the child and exits with the child's exit code, so it composes cleanly in scripts and supervisors.

| Flag | What it does |
| --- | --- |
| `-e`, `--env-file <path>` | Also load a `.env` file (supports `tvault://` placeholders). |
| `--no-vault` | Do not inject vault secrets; load only the `--env-file` values. |

```bash
# Run with a commit-safe .env template that references vault keys:
tvault run --env-file .env -- npm start
```

See [Run & env](/guide/run-and-env) for the full process model and [Dotenv](/guide/dotenv) for the `tvault://` placeholder syntax.

## Export secrets as environment variables

`tvault env` prints secrets in a chosen format. The default is shell, with `export` prefixes, so you can `eval` it into your current shell.

```bash
eval "$(tvault env)"               # load into the current shell
tvault env --format dotenv         # .env style
tvault env --format json
tvault env --format yaml
tvault env --format k8s-secret --name app-secrets
```

| Flag | What it does |
| --- | --- |
| `-f`, `--format <shell\|dotenv\|json\|yaml\|k8s-secret>` | Output format (default `shell`). |
| `-e`, `--export` | Add `export` prefixes in shell output (default on). |
| `--name`, `--namespace` | Metadata for the `k8s-secret` format. |
| `--identity <name>` | Read a **shared** project with an X25519 identity, no passphrase. |

::: warning
`tvault env` and `tvault export` write plaintext secret values to stdout. Pipe them, never commit them. For Kubernetes specifically, `tvault env --format k8s-secret` (and `tvault k8s render`) produces a plaintext `Secret` manifest — pipe it to `kubectl apply -f -` and do not check it in.
:::

## Working with projects

A vault holds multiple projects, each with its own encryption key. `init` creates a `default` project. Create more, and switch between them.

```bash
tvault projects create webapp -d "Web frontend secrets"
tvault projects list

# Set the active project for subsequent commands:
tvault use webapp                  # shorthand for: tvault projects use webapp
```

The active project is sticky — it is stored in the vault and used until you switch again. You can also target a single command without switching, using the global `-p`/`--project` flag:

```bash
tvault -p webapp set API_KEY "sk-xxxx"
tvault -p webapp list
```

Project precedence is `--project` > the stored current project > `default`. See [Projects](/guide/projects) for sharing, deletion, and recipients.

::: danger
`tvault projects unshare <recipient>` is **true** revocation, not a flag flip: it rotates the project's data encryption key and re-encrypts every value and its history under the new key. That is the point — a removed recipient cannot decrypt anything going forward, even copies of old ciphertext.
:::

## Where your data lives and the lock model

Everything TinyVault owns is under `~/.tvault/` (mode `0700`):

| Path | What it is |
| --- | --- |
| `~/.tvault/vault.db` | The encrypted vault (secrets, version history, project metadata, audit log, salt). Mode `0600`. |
| `~/.tvault/config.yaml` | Optional config (see [Configuration](/reference/configuration)). |
| `~/.tvault/identities/<name>.key` | Optional X25519 identities for sharing. Mode `0600`. |

You can move the vault directory with `--vault <dir>` or the `TVAULT_DIR` environment variable. Precedence is `--vault` > `TVAULT_DIR` > `~/.tvault`.

The vault is locked at rest. A command that needs plaintext (like `get`, `env`, or `run`) unlocks the vault for the duration of that command by deriving the key from your passphrase — it does not stay unlocked between commands. Operations that only touch metadata (`list`, `search`, `history`, `projects recipients`, `diff` without `--values`) never decrypt and never need the passphrase.

```bash
tvault status     # is a vault present? which project is active?
tvault doctor     # read-only diagnostics; non-zero exit if a check fails
tvault unlock     # cache an unlock (where supported)
tvault lock       # clear any cached unlock
```

::: tip
On Unix, the optional [agent](/guide/agent) (`tvault agent start`) holds the vault unlocked over a private `0600` socket so daily `get`/`env`/`run` skip the prompt and Argon2id. It is opt-in and auto-locks when idle.
:::

## Global flags and exit codes

These six persistent flags work on **every** command:

| Flag | Effect |
| --- | --- |
| `--config <file>` | Use a specific config file. |
| `--vault <dir>` | Use a specific vault directory. |
| `-p`, `--project <name>` | Target a specific project for this command. |
| `--json` | Emit machine-readable JSON where supported. |
| `-v`, `--verbose` | Verbose logging. |
| `--no-agent` | Bypass the local agent and unlock directly. |

Exit codes let scripts branch on the failure mode:

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Generic error. |
| `3` | Vault is locked. |
| `4` | Secret or project not found. |
| `5` | Vault not initialized (run `tvault init`). |
| `6` | Wrong passphrase. |

## A note for AI agents

The same binary is the [MCP server](/mcp/) (via the `mcp` subcommand) and an interactive terminal [studio](/guide/studio). Two honesty caveats to internalize early:

::: warning
MCP **output redaction** is a safety net, not a security control. It only replaces literal secret values longer than three characters in tool output and can be evaded by transforming a value before printing it. Treat it as defense-in-depth, never as the boundary. The MCP server never returns a raw secret value **except** `vault_get_secret`, which warns when it does.
:::

Secret **generation** is available only over MCP (`vault_generate_secret`) — there is no `tvault generate` CLI command. Auditing is internal: it surfaces over MCP (`vault_audit_log`) and in the studio, not as a CLI subcommand.

## See also

- [What is TinyVault](/guide/what-is-tinyvault) — the design and threat model in one page.
- [Run & env](/guide/run-and-env) — inject secrets into processes the right way.
- [CLI reference](/cli/) — every command and flag.
- [Security model](/reference/security) — what TinyVault does and does not defend against.
