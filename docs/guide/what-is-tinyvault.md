---
title: What is TinyVault?
description: TinyVault is a local-first secrets manager, written in Go and shipped as a single binary, with a CLI, an interactive terminal studio, and a built-in MCP server for AI agents. Language-agnostic — it injects secrets as env vars into any process.
---

# What is TinyVault?

TinyVault is a local-first secrets manager that lives in a single binary, `tvault`, written in Go. It stores your secrets in one encrypted file on your own machine — no servers, no accounts, no cloud — and exposes that same store through three surfaces: a CLI, an interactive terminal studio, and an MCP server for AI agents.
It is **not** a Go-only tool. TinyVault is written in Go (which is why it ships as one self-contained binary with no runtime dependencies), but it works with any stack: `tvault run` injects secrets as environment variables into any subprocess, so your app can be Node, Python, Ruby, Rust, PHP, Go, or anything that reads env vars.

If you have ever wanted a `.env` file that is actually encrypted, versioned, shareable, and safe to hand to an AI agent, that is the problem TinyVault solves.

## The one-binary, local-first idea

You download one binary. You run `tvault init`. From then on, everything lives in a single encrypted [bbolt](https://github.com/etcd-io/bbolt) file (default `~/.tvault/vault.db`).

- **No servers.** There is no backend to deploy or pay for. Everything runs as a local process.
- **No accounts.** There is no sign-up, no login, no API key to a hosted service.
- **No cloud.** Your secrets never leave your machine unless you explicitly export, share, or commit them.
- **One file.** Back it up by copying one file. Move machines by copying one file.

Every value at rest is encrypted with AES-256-GCM under a per-project data-encryption key (DEK), and each DEK is wrapped by a key-encryption key (KEK) derived from your passphrase with Argon2id. See [Architecture](/reference/architecture) and [Security](/reference/security) for the full design.

::: danger No recovery, by design
There is **no escrow and no recovery key**. If you forget your passphrase, the vault is irrecoverable. This is a deliberate trade-off in favor of having no hosted recovery service. Keep a backup of the file and remember your passphrase.
:::

## Three surfaces, one vault

All three surfaces talk to the same vault API and obey the same crypto and audit rules. You are never looking at a stale copy or a different store.

### The CLI — for humans and scripts

The everyday interface. Initialize a vault, add and read secrets, organize them into projects, run a process with secrets injected as environment variables, and manage keys and sharing.

```bash
tvault init
tvault projects create webapp
tvault set DATABASE_URL postgres://user:pass@localhost/app -p webapp
tvault run -p webapp -- ./server
```

The full command list lives in the [CLI reference](/cli/). Start with [Getting started](/guide/getting-started).

### The studio — an interactive terminal UI

```bash
tvault studio          # aliases: browse, ui
```

A full-screen TUI (built on Bubble Tea v2) to browse status, projects, secrets, and the audit log, with a live filter and reveal-on-demand: press `r` to reveal a value, `esc` to re-mask it. It is **read-only by default** — a stray keystroke cannot change anything. Pass `--rw` to enable audited in-app new/edit/delete. See [The studio](/guide/studio).

### The MCP server — for AI agents

The same binary is also a [Model Context Protocol](/mcp/) server (via the `mcp` subcommand). Point an AI agent — Claude, an editor assistant, an automation — at it, and the agent can work with your secrets without the plaintext ever needing to enter the model's context.

```bash
tvault mcp
```

The agent can inject secrets into a subprocess, write an env file to disk, generate a secret, or seal ciphertext for a recipient — all without seeing raw values. Access is gated by a disk-loaded [access policy](/mcp/access-policy), not by the model. See the [MCP overview](/mcp/) and the [tool reference](/mcp/tools).

## What problem it solves

A plain `.env` file is plaintext on disk, has no history, is awkward to share securely, and is dangerous to expose to an autonomous agent. TinyVault gives you a `.env` that is:

- **Encrypted** — AES-256-GCM under a per-project DEK; the file at rest reveals nothing.
- **Versioned** — every overwrite archives the prior value, so you can inspect history and roll back. See [Versioning & rollback](/guide/versioning).
- **Shareable** — wrap secrets to a recipient's public key with no shared passphrase, and commit encrypted values straight into git. See [Sharing](/guide/sharing), [Committable secrets](/guide/committable-secrets), and the [git filter](/guide/git-filter).
- **Agent-safe** — the MCP layer is built so values do not need to flow through the model. See [MCP](/mcp/).

## What it is — and is not

::: info It is
A local-first, single-binary secrets store for one developer (or one machine), with first-class AI-agent and scripting integration. Best for personal projects, local development, CI without a hosted backend, and wiring secrets to AI agents safely.
:::

::: warning It is not
- **Not a HashiCorp Vault replacement for production.** Dynamic/short-lived credentials, HSM/KMS integration, and recovery shards are explicit non-goals.
- **Not a team-sync backend.** There is no hosted service that syncs secrets between machines and people. You share by copying or committing an encrypted file, or by sealing values to a recipient's key.
- **Not a multi-user isolation layer on a shared host.** The vault is permission-gated by file mode, not separated per OS user.
:::

## Feature tour

| Area | What you get | Guide |
| --- | --- | --- |
| Secrets | Set, get, list, delete secrets in an encrypted store | [Secrets](/guide/secrets) |
| Projects | Per-project DEK isolation; organize and scope secrets | [Projects](/guide/projects) |
| Run & env | Inject secrets into a subprocess or print export lines | [Run & env](/guide/run-and-env) |
| Dotenv | Import/export `.env` safely (no shell expansion) | [Dotenv](/guide/dotenv) |
| Versioning | Per-key history and non-destructive rollback | [Versioning](/guide/versioning) |
| Key management | Passphrase change and KEK rotation | [Key management](/guide/key-management) |
| Sharing | Seal values to a recipient's public key; true revocation | [Sharing](/guide/sharing) |
| Committable secrets | Commit-safe `.env.encrypted` (v2) format | [Committable secrets](/guide/committable-secrets) |
| Git filter | Transparent clean/smudge encryption in git | [Git filter](/guide/git-filter) |
| CI/CD | Passphrase-free, identity-based CI workflows | [CI/CD](/guide/ci-cd) |
| Studio | Interactive terminal UI for browsing the vault | [Studio](/guide/studio) |
| Agent | Opt-in daemon that holds the vault unlocked (unix-only) | [Agent](/guide/agent) |
| MCP | Policy-and-redaction layer for AI agents | [MCP](/mcp/) |

For the conceptual model behind projects, DEKs, KEKs, and the threat boundary, read [Concepts](/guide/concepts).

## Global flags

These six persistent flags are available on **every** command:

| Flag | Purpose |
| --- | --- |
| `--config <file>` | Use a specific config file |
| `--vault <dir>` | Use a specific vault directory |
| `-p`, `--project <name>` | Operate on a named project |
| `--json` | Emit machine-readable JSON |
| `-v`, `--verbose` | Verbose output |
| `--no-agent` | Bypass the local agent and unlock directly |

`-h` / `--help` works everywhere. `--version` is root-only — there is no `version` subcommand.

::: tip Exit codes
Scripts can branch on the exit code: `0` ok, `1` generic error, `3` vault locked, `4` secret/project not found, `5` not initialized, `6` wrong passphrase.
:::

## Security at a glance

TinyVault is built to be honest about what it does and does not protect. A few points worth internalizing before you rely on it:

- **Reading the vault file at rest is safe.** Every value, DEK, and verifier is authenticated AES-256-GCM; tampering yields a decryption error, not a silent bad read.
- **Brute-forcing the passphrase is expensive.** Argon2id (64 MiB / 3 / 4) makes each guess memory-bound and roughly 200 ms.
- **Revocation is real.** `tvault projects unshare` rotates the project DEK and re-encrypts every value *and its history* — a revoked recipient's old copy is useless. See [Sharing](/guide/sharing).
- **Dotenv import is hardened.** The parser does no shell/variable/command expansion, enforces a key allowlist, skips symlinks, and caps input at 1 MiB. See [Dotenv](/guide/dotenv).

There are also caveats you must respect:

::: danger Honest security caveats
- **MCP output redaction is a safety net, not a control.** It only replaces literal values longer than 3 characters in captured output, and an agent that transforms a value can evade it. It does not stop network exfiltration or logging outside the captured stream. The MCP server never returns a raw value **except** `vault_get_secret`, which carries an explicit warning.
- **Agent capability tokens are privilege separation for an OS-confined (different-uid) delegate only.** They are **not** a defense against a malicious same-uid process — a same-uid process can read the token file or dial the socket directly. For untrusted delegation, use a scoped [identity](/guide/sharing) instead. See [The agent](/guide/agent).
- **`tvault identity export` prints a PRIVATE key.** It is TTY-guarded; never paste its output where it can be logged or committed.
- **`tvault k8s render` output is PLAINTEXT.** Pipe it to `kubectl`; never commit it.
:::

Read the full [Security](/reference/security) page for the complete threat model, including the explicit non-goals (memory forensics of a running process, multi-user isolation, dynamic credentials, team sync).

## How it compares

An honest comparison. The right tool depends on whether you want local-first simplicity or a hosted/production system.

| | TinyVault | 1Password CLI | pass | HashiCorp Vault | Doppler |
| --- | --- | --- | --- | --- | --- |
| Single binary, no account | Yes | No (account/cloud) | Yes | No (server) | No (account/cloud) |
| Local-only by default | Yes | No | Yes | Configurable | No (hosted) |
| Per-project key isolation | Yes (per-project DEK) | Vaults | No | Yes | Yes |
| First-class MCP for agents | Yes | No | No | No | No |
| Redaction-safe agent exec | Yes | No | No | No | No |
| Team sync between people | No | Yes | Via git/GPG | Yes | Yes (core feature) |
| Passphrase/account recovery | No (by design) | Yes | GPG-based | Recovery shards | Yes |
| Dynamic/short-lived secrets | No (non-goal) | No | No | Yes | Limited |

In short:

- **vs 1Password CLI** — TinyVault has no account or cloud and is a single binary with first-class MCP and redaction-safe exec; 1Password offers team sync and passphrase recovery, which TinyVault does not.
- **vs pass** — both are local and account-free; TinyVault adds per-project DEK isolation, MCP, and redaction-safe exec, while pass has GPG-based recovery and git-native sharing.
- **vs HashiCorp Vault** — Vault is the production answer (dynamic secrets, HSM/KMS, recovery shards), all explicit non-goals here; TinyVault is local-first and agent-first and is **not** a Vault replacement in production.
- **vs Doppler** — Doppler solves team sync with a hosted backend (account, network round-trip, subscription); TinyVault is fully local with MCP, but intentionally does not do Doppler-style team sync.

## See also

- [Getting started](/guide/getting-started) — install, init, and your first secret.
- [Concepts](/guide/concepts) — projects, DEKs, KEKs, and the trust boundary.
- [MCP overview](/mcp/) — wire TinyVault up to an AI agent.
- [Security](/reference/security) — the full threat model and non-goals.
