---
title: Environment Variables
description: Reference for the supported TVAULT_* runtime variables — passphrase, vault directory, agent routing, identities, and studio animation control.
---

# Environment Variables

`tvault` reads a small, explicit set of `TVAULT_*` environment variables so you can run it non-interactively — in CI, over ssh, inside containers, or behind an AI agent. This page lists the runtime variables that the command implementation uses and the security caveats for the sensitive ones.

There is no generic environment-variable mapping for command flags. Use only the variables listed below; each section documents its actual resolution rules.

## Quick reference

| Variable | Reads it | What it does |
| --- | --- | --- |
| `TVAULT_PASSPHRASE` | commands that unlock directly; also `init`, `agent start`, `studio`, `mcp` | Vault passphrase for non-interactive unlock; skips the prompt. |
| `TVAULT_DIR` | every command | Vault directory override. Default `~/.tvault`. |
| `TVAULT_NO_AGENT` | `get`, `env`, `run` | If set, bypass a running agent and unlock directly (same as `--no-agent`). |
| `TVAULT_AGENT_TOKEN` | agent-routed `get`, `env`, `run` | Bearer token sent to a `--require-token` agent after the mandatory same-uid check. |
| `TVAULT_IDENTITY_KEY` | `open`, `decrypt-env`, identity-mode `env`, `k8s render`, git filters | A **private** identity string (`tvault-key1...`) for passphrase-free decryption when the selected key file is absent. |
| `TVAULT_IDENTITY` | `open`, git filters | Default identity **name** (not the key). |
| `TVAULT_NO_ANIM` | `studio` | Disable studio animations. |

## Vault location

### `TVAULT_DIR`

Points `tvault` at a vault directory other than `~/.tvault`. The directory holds `vault.db` (the local bbolt database; secret payloads and key material are encrypted while operational metadata remains readable), the optional `config.yaml` and `mcp-policy.yaml`, your `identities/` keys, and — on Unix — the agent runtime files.

```bash
export TVAULT_DIR=/srv/secrets/tvault
tvault list
```

Precedence for the vault directory is:

```
--vault <dir>   >   TVAULT_DIR   >   ~/.tvault
```

::: info
`--vault` is a global persistent flag available on every command, so a one-off `tvault --vault /tmp/scratch list` always wins over an exported `TVAULT_DIR`.
:::

## Unlocking

### `TVAULT_PASSPHRASE`

Supplies the vault passphrase so a command that opens the vault directly can unlock without an interactive prompt. This includes ordinary direct reads/writes and the `unlock`, `init`, `agent start`, `studio`, and `mcp` commands. Agent-served `get`, `env`, and `run` calls do not need it.

```bash
# CI: unlock without a TTY
export TVAULT_PASSPHRASE='your-vault-passphrase'
tvault env --project api > .env
```

::: danger Treat this as a live secret
`TVAULT_PASSPHRASE` is the key to the whole vault. Anything that can read your process environment can read it — `/proc/<pid>/environ`, a `ps -E` from the same user, a CI log that echoes the environment, or shell history if you typed it inline.

- Prefer your CI provider's masked-secret mechanism over an exported value, and never `echo` the variable.
- For passphrase-free CI, consider an identity key instead (see [`TVAULT_IDENTITY_KEY`](#tvault-identity-key)); it scopes access to specific recipients rather than handing over the master passphrase.
:::

If the passphrase is wrong, `tvault` exits with code **6**. If the vault has not been initialized yet, it exits with code **5**.

::: info `unlock` and `lock` do not persist across commands
Each CLI invocation is a separate process. `tvault unlock` validates the passphrase, holds the derived key only for that invocation, and then exits. `tvault lock` clears only its own process state; it does not persist a locked flag and does not stop a running agent. Use `tvault agent start` / `tvault agent stop` for a persistent in-memory unlock.
:::

## The local agent

The optional [local agent](/guide/agent) (Unix only) holds the vault unlocked over a private socket so `get`, `env`, and `run` skip the prompt and the Argon2id work.

### `TVAULT_NO_AGENT`

Set this (to any value) to bypass a running agent and unlock directly. It is exactly equivalent to passing `--no-agent`.

```bash
# Ignore any running agent for this shell
export TVAULT_NO_AGENT=1
tvault get --project api STRIPE_KEY
```

### `TVAULT_AGENT_TOKEN`

When an agent is started with `--require-token`, clients must present a capability token. `TVAULT_AGENT_TOKEN` carries that token to the agent.

`tvault status --json` reports this distinction without reading a secret: `agent_running` means the socket exists, while `agent_accessible` means the current process can use it for the selected project (explicit `--project`, then the stored current project, then `default`) with the token it has. The command reports `locked: true` when the agent is running but this process lacks a valid token for that project, because a value read would still need another unlock path.

The agent first verifies that the connecting process has the **same uid** as the agent. Only after that check succeeds does it parse the request and validate `TVAULT_AGENT_TOKEN`. A token therefore cannot grant access to a different uid; it is an additional, optionally project-scoped bearer gate among same-uid clients.

::: warning Tokens do not replace the same-uid boundary
A malicious same-uid process may be able to read the token file, inspect another process's environment, or otherwise obtain a bearer token. Use tokens for an extra gate between cooperating or OS-confined same-uid clients, not for cross-uid delegation. For a cryptographic boundary across CI, machines, teammates, or untrusted agents, use the [recipient/identity sharing model](/guide/sharing).
:::

## Identities and sharing

TinyVault's [sharing layer](/guide/sharing) uses X25519 keypairs called *identities*. The public half (`tvault1...`) is shareable and committable; the private half (`tvault-key1...`) is not. Two environment variables feed this layer, and they do different things, so read both.

### `TVAULT_IDENTITY_KEY`

A **private** identity string (`tvault-key1...`) used to decrypt recipient-encrypted material when there is no key file on disk — the canonical case being CI, ssh sessions, and agents. It is read by `open`, `decrypt-env`, `env --identity`, and the git clean/smudge filters.

```bash
# CI: decrypt a committed .env.encrypted with no key file present
export TVAULT_IDENTITY_KEY='tvault-key1examplePrivate'
tvault decrypt-env .env.encrypted > .env
```

Precedence: a local identity **file** always wins over the env key.

```
~/.tvault/identities/<name>.key   >   TVAULT_IDENTITY_KEY
```

When a file overrides a set env key, `tvault` prints a one-line warning to stderr so the override is never silent.

::: danger Private key — never commit, never echo
`tvault-key1...` is a private key. Anyone who has it can decrypt everything shared to that identity.

- The value is **never echoed in an error message**, even on a decode failure — don't defeat that by logging the environment yourself.
- Use your CI provider's masked secrets; never write it into `.env`, a tracked file, or shell history.
- To mint one, run `tvault identity new`. To print an existing private key, use `tvault identity export` (it is TTY-guarded and refuses to print to a non-terminal without `--force`).
:::

### `TVAULT_IDENTITY`

The default identity **name** — not the key — used automatically by `tvault open` and the git clean/smudge filters.

```bash
export TVAULT_IDENTITY=ci-runner
tvault open --in .env.encrypted > .env
```

The name is resolved differently by those two surfaces:

- `tvault open`: `--identity` > `TVAULT_IDENTITY` > `default`.
- Git filters: `TVAULT_IDENTITY` > `git config tvault.identity` > `default`.

Other `--identity` flags do not read `TVAULT_IDENTITY` automatically. For example, `decrypt-env` and `k8s render` use the explicit flag when present and otherwise select the `default` identity file before trying `TVAULT_IDENTITY_KEY`.

::: tip Name vs. key
`TVAULT_IDENTITY` selects a key by name (it expects a matching `<vault-dir>/identities/<name>.key`). `TVAULT_IDENTITY_KEY` *is* the key material itself, for when the selected file does not exist. Set one or the other depending on whether your runner has a key file on disk.
:::

## Studio

### `TVAULT_NO_ANIM`

Disables animations in the interactive [studio](/guide/studio). Set it for screen recordings, slow terminals, or accessibility.

```bash
TVAULT_NO_ANIM=1 tvault studio
```

Animations are also disabled automatically over ssh. The same setting can be made permanent via `browse.no_anim` in [`config.yaml`](/reference/configuration), and the `--no-anim` flag disables them for one invocation. If `TERM=dumb`, the studio refuses to start rather than merely disabling animation.

## Exit codes

Scripts that read these variables will want to branch on the process exit code:

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Generic error. |
| `3` | Vault is locked at rest. |
| `4` | Secret or project not found. |
| `5` | Vault not initialized. |
| `6` | Wrong passphrase. |
| `7` | Vault database is in use by another process. |

## See also

- [Configuration](/reference/configuration) — the `config.yaml` file and the `browse:` block.
- [CI/CD](/guide/ci-cd) — wiring up passphrase-free and identity-based pipelines.
- [Sharing Secrets](/guide/sharing) — identities, recipients, live-vault re-keying, and retained-data limits.
- [Local Agent](/guide/agent) — the unlocked-vault daemon and `--require-token`.
