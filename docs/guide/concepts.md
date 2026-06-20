---
title: Core Concepts
description: The mental model behind TinyVault — the encrypted vault, lock/unlock and the in-memory KEK, per-project DEK isolation, identities and recipients, the audit log, and the three interfaces.
---

# Core Concepts

This page is the mental model for TinyVault. It is a concept map, not a command reference — each idea links to the page that covers it in depth. Read it once and the rest of the docs will click into place.

TinyVault is a single Go binary, `tvault`. The same binary is your CLI, an interactive terminal studio, and (via the `mcp` subcommand) an MCP server for AI agents. All three sit on one local, encrypted file. There are no servers, no accounts, and no network calls.

## The vault

The vault is one encrypted [bbolt](https://github.com/etcd-io/bbolt) file at `~/.tvault/vault.db` (mode `0600`, inside a `0700` directory). Everything lives there: your encrypted secret values, their version history, project metadata, the wrapped per-project keys, the audit log, and the verifier used to check your passphrase.

```bash
tvault init                 # create the vault and set your passphrase
```

You can point `tvault` at a different vault directory with the `--vault` flag or the `TVAULT_DIR` environment variable. The resolution order is `--vault` > `TVAULT_DIR` > `~/.tvault`.

::: info One file, three interfaces
The CLI, the [studio TUI](/guide/studio), and the [MCP server](/mcp/) all talk to the same vault API. There is no daemon coordinating them and no separate datastore — they read and write the same `vault.db`. On Unix, the optional [local agent](/guide/agent) can hold the unlocked key in memory so repeated commands skip the prompt, but it never holds the database open.
:::

## Lock and unlock

The vault is encrypted at rest and only readable while it is **unlocked**.

- **Unlock.** You supply your passphrase. TinyVault runs it through Argon2id to derive a **KEK** (key-encryption key) that exists only in RAM for the duration of the operation. A small built-in *verifier* lets unlock confirm the passphrase is correct **without decrypting any secret**.
- **Lock.** The KEK (and every key derived from it) is zeroed in memory. Locked means locked: nothing in the vault is readable.

```bash
tvault unlock               # derive the KEK and confirm the passphrase
tvault lock                 # zero the KEK in memory
```

Read a secret while the vault is locked and the command exits with code `3` (see [Exit codes](#exit-codes)). A wrong passphrase exits with code `6`.

::: tip The passphrase never unlocks a value directly
Your passphrase decrypts the KEK. The KEK unwraps a project's DEK. The DEK decrypts the value. This two-step indirection is what makes [passphrase rotation](/guide/key-management) cheap — see the key hierarchy below.
:::

## Projects and the current project

A **project** is a named namespace for secrets — typically one per app, service, or environment. Each secret key lives inside exactly one project, so `DATABASE_URL` in `api` and `DATABASE_URL` in `worker` are independent values.

```bash
tvault projects create api
tvault projects use api          # set the current (active) project
tvault projects list
```

Most commands operate on the **current project**. Override it per command with the global `-p`/`--project` flag, or set a default with `TVAULT_PROJECT`. The resolution order is `--project` > the stored current project > `default`.

```bash
tvault get DATABASE_URL                 # uses the current project
tvault get DATABASE_URL -p worker       # one-off override
```

### Project isolation

Isolation is cryptographic, not just organizational. **Each project has its own DEK** (data-encryption key). A project's values — and its full version history — are encrypted under that project's DEK and nothing else. This is the unit of sharing and of revocation: when you [share](/guide/sharing) or [unshare](/guide/projects) a project, you are operating on one project's DEK.

## The key hierarchy

TinyVault uses a two-tier key hierarchy. At a glance:

```
passphrase ──Argon2id──▶ KEK ──unwraps──▶ per-project DEK ──decrypts──▶ secret values
              (in RAM)            (AES-256-GCM)            (AES-256-GCM)
```

| Tier | Key | Derived / protected by | Protects |
| --- | --- | --- | --- |
| User | **KEK** | Argon2id over your passphrase | Wraps each project's DEK |
| Project | **DEK** | AES-256-GCM, wrapped by the KEK | Encrypts that project's values + history |

The KEK is never stored — it is re-derived on unlock and held in RAM only while the vault is open. Each DEK is stored *wrapped* in its project record and is only ever decrypted in memory. Because values are encrypted under the DEK (not the KEK), rotating your passphrase only re-wraps the DEKs; it never re-encrypts a single secret value.

::: info Go deeper
The full crypto design — Argon2id parameters, the AES-256-GCM wire format, the verifier, memory hygiene, and what passphrase rotation does and doesn't touch — is in [Architecture](/reference/architecture) and [Security](/reference/security).
:::

## Identities and recipients

The key hierarchy above is symmetric: it is all gated by your passphrase. To **share** a project with a teammate, a CI pipeline, or an agent — without sharing your passphrase — TinyVault adds an asymmetric layer built on identities and recipients.

An **identity** is a passphrase-independent keypair stored at `~/.tvault/identities/<name>.key`. It has two halves with distinct, hard-to-confuse formats:

| Half | Format | Share it? |
| --- | --- | --- |
| Public **recipient** | `tvault1...` | Yes — shareable and commit-safe |
| Private **identity** | `tvault-key1...` | **No — this is a secret key** |

```bash
tvault identity new ci                              # create an identity named "ci"
tvault projects share api tvault1exampleRecipient  # rewrap the DEK to that recipient
```

Sharing rewraps the project's DEK to each recipient's public key, so a recipient can unwrap the DEK with their private identity — no passphrase required. This same recipient layer powers [committable secrets](/guide/committable-secrets) and the [git filter](/guide/git-filter).

::: danger Two security facts to keep straight
**`tvault identity export` prints a PRIVATE key** (`tvault-key1...`). It is TTY-guarded for that reason. Treat its output like a password and never commit it.

**`tvault projects unshare` is true revocation.** It does not merely drop a name from a list — it rotates the project's DEK and re-encrypts every value *and* the full history under the new DEK, rewrapping only to the remaining recipients. A removed recipient cannot read the project even with an old copy of the vault file.
:::

See [Sharing](/guide/sharing) for the full workflow.

## The audit log

Every privileged action — unlocking, revealing a value, setting or deleting a secret, sharing, rotating keys — is recorded in an append-only audit log stored inside the vault.

You read the audit log in two places:

- In the [studio TUI](/guide/studio), which surfaces recent entries (how many is configurable via `browse.audit_limit`).
- Over [MCP](/mcp/) with the `vault_audit_log` tool, so an agent host can review what was accessed.

::: warning There is no `tvault audit` command
Auditing is internal. It is surfaced in the studio and over MCP — there is **no** `tvault audit` CLI subcommand, regardless of what older help text may suggest. Likewise, secret **generation** exists only over MCP (`vault_generate_secret`); there is no `tvault generate` command.
:::

## The three interfaces

The same vault is reachable three ways. Pick the one that fits the caller.

### CLI

The default interface for humans and scripts: `tvault <command>` with the global flags below.

```bash
tvault set API_KEY                       # prompts for the value (never echoed)
tvault run -- ./server                   # inject secrets as env for one process
```

See the [full CLI reference](/cli/).

### Studio (terminal UI)

An interactive browser for your vault. Read-only by default — with no flags it never writes, and the only decryption is the on-demand reveal (`r`), which is audited like `tvault get`. Pass `--rw` to enable audited in-app edits.

```bash
tvault studio                            # aliases: tvault browse, tvault ui
```

See the [Studio guide](/guide/studio).

### MCP server

A [Model Context Protocol](/mcp/) server on stdio for AI agents, started by the `mcp` subcommand (your agent host launches it for you). The design goal is that **secret values never enter the model context**: prefer tools like `vault_run_with_secrets` and `vault_export_env` that act on secrets without returning them.

::: danger Two MCP security facts to keep straight
**The MCP server never returns a raw secret value — except `vault_get_secret`, which warns.** Every other tool is designed to keep values out of the model's context.

**MCP output redaction is a safety net, not a control.** It only replaces literal value strings longer than three characters, and it is trivially evaded by a model that transforms a value before emitting it (encoding, slicing, reordering). Do not rely on redaction as a security boundary — design your agent flows so the value is never needed in the first place.
:::

See the [MCP overview](/mcp/), the [tool reference](/mcp/tools), and the [access policy](/mcp/access-policy).

## Global flags

These six persistent flags work on **every** command:

| Flag | Effect |
| --- | --- |
| `--config <file>` | Use an alternate config file (default `~/.tvault/config.yaml`) |
| `--vault <dir>` | Use an alternate vault directory |
| `-p`, `--project <name>` | Operate on a specific project for this command |
| `--json` | Emit machine-readable JSON |
| `-v`, `--verbose` | Verbose output |
| `--no-agent` | Bypass the [local agent](/guide/agent); unlock directly |

`-h`/`--help` is available everywhere. `--version` is root-only — run `tvault --version`; there is no `version` subcommand.

## Exit codes

Scripts and CI can branch on the exit code:

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Generic error |
| `3` | Vault is locked |
| `4` | Secret or project not found |
| `5` | Vault not initialized |
| `6` | Wrong passphrase |

## See also

- [Architecture](/reference/architecture) — the crypto design and key hierarchy in depth
- [Security](/reference/security) — threat model and the honest limits of each control
- [Working with secrets](/guide/secrets) — set, get, list, and reveal values
- [Projects](/guide/projects) — create, switch, share, and revoke projects
