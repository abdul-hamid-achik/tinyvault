---
title: Environment Variables
description: Reference for every TVAULT_* environment variable that tvault reads — passphrase, vault directory, agent bypass, identity keys, and precedence rules.
---

# Environment Variables

`tvault` reads a small set of `TVAULT_*` environment variables so you can run it non-interactively — in CI, over ssh, inside containers, or behind an AI agent — without a prompt or a config file. This page lists every variable, who reads it, how it interacts with flags, and the security caveats for the sensitive ones.

An environment variable never overrides an explicit command-line flag. The general order is **flag > environment variable > config file > built-in default**.

## Quick reference

| Variable | Reads it | What it does |
| --- | --- | --- |
| `TVAULT_PASSPHRASE` | `unlock`, `init`, `agent start`, `studio`, `mcp` | Vault passphrase for non-interactive unlock; skips the prompt. |
| `TVAULT_DIR` | every command | Vault directory override. Default `~/.tvault`. |
| `TVAULT_NO_AGENT` | `get`, `env`, `run` | If set, bypass a running agent and unlock directly (same as `--no-agent`). |
| `TVAULT_AGENT_TOKEN` | agent clients (`get` / `env` / `run`) | Capability token sent to a `--require-token` agent. |
| `TVAULT_IDENTITY_KEY` | `open`, `decrypt-env`, `env --identity`, git filters | A **private** identity string (`tvault-key1...`) for passphrase-free decryption when no key file is on disk. |
| `TVAULT_IDENTITY` | git filters, recipient reads | Default identity **name** (not the key). Default `default`. |
| `TVAULT_NO_ANIM` | `studio` | Disable studio animations. |

Beyond these, viper's `AutomaticEnv` (prefix `TVAULT`) lets you set any flag-bound key from the environment — see [viper-bound variables](#viper-bound-variables) below.

## Vault location

### `TVAULT_DIR`

Points `tvault` at a vault directory other than `~/.tvault`. The directory holds `vault.db` (the encrypted bbolt file), the optional `config.yaml` and `mcp-policy.yaml`, your `identities/` keys, and — on Unix — the agent runtime files.

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

Supplies the vault passphrase so commands that need to decrypt the master key can run without an interactive prompt. It is read by `unlock`, `init`, `agent start`, `studio`, and the `mcp` subcommand.

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

::: warning Tokens are privilege separation, not a same-uid control
Capability tokens gate access for an **OS-confined delegate that runs as a different uid** (a sandboxed subprocess, a constrained service account). They are **not** a defense against a malicious process running as your own user — a same-uid process can read the token file or simply dial the agent socket directly. For real delegation across trust boundaries, use the [recipient/identity sharing model](/guide/sharing), not tokens.
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

The default identity **name** — not the key — used by the git filters and recipient reads to pick which identity to act as. The built-in default is `default`.

```bash
export TVAULT_IDENTITY=ci-runner
tvault env --project api --identity "$TVAULT_IDENTITY"
```

Precedence for the identity name is:

```
--identity   >   TVAULT_IDENTITY   >   git config tvault.identity   >   "default"
```

::: tip Name vs. key
`TVAULT_IDENTITY` selects a key by name (it expects a matching `~/.tvault/identities/<name>.key`). `TVAULT_IDENTITY_KEY` *is* the key material itself, for when no file exists. Set one or the other depending on whether your runner has a key file on disk.
:::

## Studio

### `TVAULT_NO_ANIM`

Disables animations in the interactive [studio](/guide/studio). Set it for screen recordings, slow terminals, or accessibility.

```bash
TVAULT_NO_ANIM=1 tvault studio
```

Animations are also disabled automatically over ssh and when `TERM=dumb`. The same setting can be made permanent via `browse.no_anim` in [`config.yaml`](/reference/configuration); an explicit flag still wins over both.

## viper-bound variables

`tvault` uses viper's `AutomaticEnv` with the prefix `TVAULT`, so the global persistent flags that are bound to config keys can also be set from the environment. The env name maps to the flag key:

| Variable | Equivalent flag | Effect |
| --- | --- | --- |
| `TVAULT_VAULT` | `--vault <dir>` | Vault directory. |
| `TVAULT_PROJECT` | `-p` / `--project <name>` | Default project. |
| `TVAULT_VERBOSE` | `-v` / `--verbose` | Verbose output. |

```bash
export TVAULT_PROJECT=api
export TVAULT_VERBOSE=1
tvault list      # operates on the "api" project, verbosely
```

These read from `config.yaml` as well (`vault`, `project`, `verbose`), and an explicit flag always overrides the environment.

::: info `TVAULT_VAULT` vs `TVAULT_DIR`
Both can point `tvault` at a vault directory. `TVAULT_VAULT` is the viper-bound twin of `--vault`; `TVAULT_DIR` is the lower-precedence default location. The full order is `--vault` (and its `TVAULT_VAULT` binding) `> TVAULT_DIR > ~/.tvault`.
:::

## Test-only variables

`TVAULT_TUI_DUMP`, `TVAULT_COLS`, and `TVAULT_ROWS` exist solely for the studio test harness (deterministic PTY sizing and frame dumps). They are not part of the public interface, and you should not rely on them in scripts.

## Exit codes

Scripts that read these variables will want to branch on the process exit code:

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Generic error. |
| `3` | Vault is locked. |
| `4` | Secret or project not found. |
| `5` | Vault not initialized. |
| `6` | Wrong passphrase. |

## See also

- [Configuration](/reference/configuration) — the `config.yaml` file and the `browse:` block.
- [CI/CD](/guide/ci-cd) — wiring up passphrase-free and identity-based pipelines.
- [Sharing Secrets](/guide/sharing) — identities, recipients, and true revocation.
- [Local Agent](/guide/agent) — the unlocked-vault daemon and `--require-token`.
