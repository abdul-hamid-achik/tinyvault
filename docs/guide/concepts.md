---
title: Core Concepts
description: The mental model behind TinyVault — the local vault database, per-command unlocking, per-project DEK isolation, identities and recipients, the audit log, and the CLI and MCP surfaces.
---

# Core Concepts

This page is the mental model for TinyVault. It is a concept map, not a command reference — each idea links to the page that covers it in depth. Read it once and the rest of the docs will click into place.

TinyVault is a single binary, `tvault`, written in Go. The same binary is your CLI and (via the `mcp` subcommand) an MCP server for AI agents. It is language-agnostic—secrets can be injected as environment variables into any process—and both surfaces use one local bbolt database. Normal vault operations need no account or hosted backend.

## The vault

The vault is one [bbolt](https://github.com/etcd-io/bbolt) file at `~/.tvault/vault.db` (mode `0600`, inside a `0700` directory). Secret values, version payloads, wrapped project keys, and the passphrase verifier are encrypted. Project names, key names, timestamps, version numbers, configuration, and audit metadata are readable and should not be treated as confidential.

```bash
tvault init                 # create the vault and set your passphrase
```

You can point `tvault` at a different vault directory with the `--vault` flag or the `TVAULT_DIR` environment variable. The resolution order is `--vault` > `TVAULT_DIR` > `~/.tvault`.

::: info One file, two interfaces
The CLI and the [MCP server](/mcp/) talk to the same vault API. There is no daemon coordinating them and no separate datastore — they read and write the same `vault.db`. On Unix, the optional [local agent](/guide/agent) can hold the unlocked key in memory so repeated commands skip the prompt, but it never holds the database open.
:::

## Lock and unlock

Normal CLI commands unlock per process. You supply the passphrase, TinyVault runs it through Argon2id to derive a **KEK** (key-encryption key), performs the operation, zeros key material, and exits. A verifier confirms the passphrase without decrypting a secret value.

The standalone commands do not create shared state:

```bash
tvault unlock               # validate the passphrase in this process, then exit
tvault lock                 # clear key material in this process, then exit
```

`tvault unlock` does not cache an unlock for the next command, and `tvault lock` does not stop a running local agent. Use [`tvault agent start`](/guide/agent) on Unix when you intentionally want a KEK held in memory between reads; stop that agent to remove the cached key. In a non-interactive process without the agent or `TVAULT_PASSPHRASE`, an unlock-requiring command exits with code `3`. A wrong passphrase exits with code `6`.

::: tip The passphrase never unlocks a value directly
Argon2id derives the KEK from your passphrase. The KEK unwraps a project's DEK. The DEK decrypts the value. This indirection is what makes [passphrase rotation](/guide/key-management) cheap—see the key hierarchy below.
:::

## Projects and the current project

A **project** is a named namespace for secrets — typically one per app, service, or environment. Each secret key lives inside exactly one project, so `DATABASE_URL` in `api` and `DATABASE_URL` in `worker` are independent values.

```bash
tvault projects create api
tvault projects use api          # set the current (active) project
tvault projects list
```

Most commands operate on the **current project**. Override it per command with the global `-p`/`--project` flag. The resolution order is `--project` > the stored current project > `default`.

```bash
tvault get DATABASE_URL                 # uses the current project
tvault get DATABASE_URL -p worker       # one-off override
```

### Project isolation

Isolation is cryptographic, not just organizational. **Each project has its own DEK** (data-encryption key). A project's values — and its full version history — are encrypted under that project's DEK and nothing else. This is the unit of sharing and live-vault recipient removal: when you [share](/guide/sharing) or [unshare](/guide/projects) a project, you are operating on one project's DEK.

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

**`tvault projects unshare` re-keys the updated live vault.** It does not merely drop a name from a list — it rotates the project's DEK and re-encrypts every current value *and* the full history under the new DEK, rewrapping only to the remaining recipients. A removed identity cannot read that updated state or future writes. A pre-removal vault copy remains readable, as do previously exported, sealed, or decrypted artifacts; rotate underlying credentials when retained data is a concern.
:::

See [Sharing](/guide/sharing) for the full workflow.

## The audit log

TinyVault records secret and project primitives in an audit bucket at the vault layer, so CLI, MCP, and the agent share one trail. Generation, execution, exports, sharing, and env-group mutations are logged at those surfaces. It is an operational trail, not exhaustive process telemetry: unlocking, passphrase rotation, and bulk passphrase-based `tvault env` are not recorded as per-key reads.

You read the audit log in two places:

- From the CLI with `tvault audit` (metadata only; lock-free).
- Over [MCP](/mcp/) with the `vault_audit_log` tool, so an agent host can review what was accessed.

::: info Generation never prints the value
`tvault generate KEY` and MCP `vault_generate_secret` store a random secret and return only metadata (`key`, `length`, `charset`, `stored`). Use `tvault run` / `vault_run_with_secrets` when a process needs the value.
:::

## The two interfaces

The same vault is reachable two ways. Pick the one that fits the caller.

### CLI

The default interface for humans and scripts: `tvault <command>` with the global flags below.

```bash
tvault set API_KEY --from-env .env       # import without putting the value in argv
tvault run -- ./server                   # inject secrets as env for one process
tvault audit                             # recent actions, metadata only
```

See the [full CLI reference](/cli/).

### MCP server

A [Model Context Protocol](/mcp/) server on stdio for AI agents, started by the `mcp` subcommand (your agent host launches it for you). The recommended workflow minimizes plaintext in model context: prefer tools that generate, export, or pass values to a trusted destination without first returning a dedicated plaintext field. Command stdout/stderr remains an explicit leak path.

::: danger Two MCP security facts to keep straight
**`vault_get_secret` deliberately returns a stored secret in a plaintext field.** Most other tools are value-minimizing, but `vault_run_with_secrets` returns arbitrary child-process output and can carry raw, short, or transformed values back to the client.

**MCP output redaction is optional and is a safety net, not a control.** When policy enables it, it replaces literal value strings longer than three characters; short or transformed values (encoding, slicing, reordering) bypass it. Do not rely on redaction as a security boundary — design your agent flows so the value is not returned whenever possible.
:::

See the [MCP overview](/mcp/), the [tool reference](/mcp/tools), and the [access policy](/mcp/access-policy).

## CLI conventions

Global flags, aliases, machine-readable output, and exit codes live in the
[CLI reference](/cli/). Keeping them there avoids duplicating volatile command
details in this conceptual guide.

## See also

- [Architecture](/reference/architecture) — the crypto design and key hierarchy in depth
- [Security](/reference/security) — threat model and the honest limits of each control
- [Working with secrets](/guide/secrets) — set, get, list, and reveal values
- [Projects](/guide/projects) — create, switch, share, and remove recipients from live projects
