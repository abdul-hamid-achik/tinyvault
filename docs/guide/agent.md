---
title: Local Agent
description: Run a local tvault agent on Linux or macOS to hold your vault unlocked over a private unix socket, so daily get, env, and run calls skip the passphrase prompt and Argon2id.
---

# Local Agent

The `tvault agent` holds your vault unlocked in memory and serves secret reads over a private unix socket, so your daily `get`, `env`, and `run` calls skip the passphrase prompt and the ~200ms Argon2id key derivation. It is opt-in, off by default, and unix-only.

::: info Unix only
The agent runs on Linux and macOS. On Windows the command reports that it is unsupported — use commands that unlock directly with your passphrase instead.
:::

## Why an agent

Every direct `tvault` unlock derives your key with Argon2id (64 MiB, 3 passes, 4 lanes), which is deliberately slow (~200ms) and memory-bound to resist brute-force. That cost is fine once, but it adds up when you run `get` or `env` dozens of times an hour.

The agent unlocks once, caches the resulting key in memory, and answers read requests over the socket. Subsequent reads are prompt-free and fast.

## Quick start

Start the agent, then background it however you prefer:

```bash
# Foreground (Ctrl-C to stop)
tvault agent start

# Or background it yourself
tvault agent start &
nohup tvault agent start >/dev/null 2>&1 &
```

The agent runs in the **foreground** and never daemonizes itself. Background it with `&`, `nohup`, a systemd `Type=simple` unit, or a launchd agent.

Once it is running, `get`, `env`, and `run` automatically route through it:

```bash
tvault get DATABASE_URL     # no prompt, no Argon2id
tvault env --format shell   # same
tvault run -- npm start     # same
```

If no agent is running, these commands fall back to a direct unlock (which prompts), so nothing breaks when the agent is off.

::: tip
`tvault agent start` needs a TTY to prompt for the passphrase, or set `TVAULT_PASSPHRASE` in its environment to unlock non-interactively (handy for systemd or launchd units).
:::

## Shell integration with `tvault hook`

`tvault hook <shell>` prints a snippet that defines a `tvault_load` helper. Paired with a running agent, `tvault_load` loads the active project's secrets into your current shell, fast and prompt-free.

Add the eval to your shell rc:

```bash
# ~/.zshrc
eval "$(tvault hook zsh)"

# ~/.bashrc
eval "$(tvault hook bash)"
```

```fish
# config.fish
tvault hook fish | source
```

Then load a project into your shell:

```bash
tvault_load            # load the active project
tvault_load backend    # load a named project
```

`hook` supports four targets:

| Shell    | Install                                            |
| -------- | -------------------------------------------------- |
| `bash`   | `eval "$(tvault hook bash)"` in `~/.bashrc`        |
| `zsh`    | `eval "$(tvault hook zsh)"` in `~/.zshrc`          |
| `fish`   | `tvault hook fish \| source` in `config.fish`      |
| `direnv` | `tvault hook direnv >> ~/.config/direnv/direnvrc`  |

For `direnv`, the snippet defines `use_tvault`, which you call from a project's `.envrc`:

```bash
# .envrc
use tvault            # active project
use tvault backend    # named project
```

The hook sources the output of `tvault env --format shell`, which is already safely quoted — secret values are never interpolated into the hook text, so a value can't inject shell.

## Status and stopping

```bash
tvault agent status        # running? pid, socket, project, idle countdown
tvault agent status --json # machine-readable
tvault agent stop          # stop it and zero the cached key
```

`agent stop` zeroes the cached key in memory. The key is also zeroed on idle auto-lock, on any termination signal, and on a recovered panic — every exit path.

`tvault unlock` and `tvault lock` do not control this process. Each command opens the vault in its own short-lived process: `unlock` validates the passphrase for that invocation, and `lock` clears only that invocation's in-memory key. Neither persists an unlocked state, and `tvault lock` does not stop a running agent. Use `tvault agent start` for a persistent unlock and `tvault agent stop` (or a termination signal) to clear it.

::: info Stopping a token-required agent
In `--require-token` mode, every socket operation requires a token. The operator should stop the foreground process with **Ctrl-C** or send it a termination signal; the plain `tvault agent stop` command does not attach `TVAULT_AGENT_TOKEN`.
:::

## Idle auto-lock

The agent holds your key in memory, so it auto-locks after a period of inactivity and forgets the key:

```bash
tvault agent start --idle 1h    # auto-lock after 1h idle
tvault agent start --idle 0     # never auto-lock
```

The default is 15 minutes. After auto-lock the socket is gone and commands fall back to direct unlocks until you start the agent again.

## Bypassing the agent

To force a direct unlock even when an agent is running:

```bash
tvault get DATABASE_URL --no-agent
TVAULT_NO_AGENT=1 tvault env --format shell
```

Both `--no-agent` and `TVAULT_NO_AGENT` skip the socket and unlock directly (prompting for the passphrase). `--no-agent` is a global flag, so it works on any command.

## `agent start` flags

| Flag                  | Default | Description                                                                      |
| --------------------- | ------- | -------------------------------------------------------------------------------- |
| `--idle <dur>`        | `15m`   | Auto-lock after this idle duration. `0` disables auto-lock.                       |
| `--require-token`     | off     | Deny socket requests without a valid capability token. Pair with `--token-file`. |
| `--token-file <path>` | —       | A `0600` file of `token[:project]` lines for `--require-token` (SIGHUP reloads). |

## Security model

The agent is designed so that turning it on does not widen your trust boundary beyond the OS user that already controls the vault.

- **Socket permissions.** The socket is created `0600` inside the `0700` vault directory, born with the right mode via a tight umask (no listen-then-`chmod` race).
- **Same-uid peers only.** Every connection's peer uid is checked against the agent's own uid and rejected if it differs (fail-closed; `LOCAL_PEERCRED` on macOS, `SO_PEERCRED` on Linux).
- **Caches only the key, not an open database.** bbolt is single-writer, so a held-open database would block every other `tvault` process. The agent caches only the KEK and reopens the vault per request (serialized by a mutex), so direct CLI access keeps working between requests.
- **Read-only.** The agent serves reads (`get`, `getall`, `status`, `stop`) only. Writes (`set`, `delete`, rotation, project changes) always go through a direct CLI unlock.
- **Single instance.** A `flock` prevents two agents from racing on the same vault.
- **Key zeroing.** The cached key is wiped on stop, idle auto-lock, any signal, and a recovered panic.

::: warning Memory is not zeroed by SIGKILL
The key lives in the memory of a running, unlocked process. A `SIGKILL` (or memory forensics of the live process) cannot trigger the zeroing path. This is an accepted residual risk — see [Security](/reference/security).
:::

## Capability tokens (same-UID clients only)

The socket's peer-credential check always runs first. A client whose uid differs from the agent's uid is rejected before the request or its token is read, so a token cannot grant cross-uid access.

For same-uid clients, `--require-token` adds a bearer-token check after the peer check. Tokens can be unrestricted or scoped to one project, which is useful for cooperating clients or a same-uid process that is OS-confined from the other tokens.

```bash
# token-file: one token[:project] line per token, 0600
# tokenAAAA            -> any project the agent serves
# tokenBBBB:backend    -> scoped to the "backend" project
tvault agent start --require-token --token-file ~/.tvault/agent-tokens &
```

The delegate supplies its token via `TVAULT_AGENT_TOKEN`:

```bash
TVAULT_AGENT_TOKEN=tokenBBBB tvault get DATABASE_URL
```

Tokens are stored only as their SHA-256, the audit log records an 8-character hash prefix (never the token itself), and the agent reloads the token file on `SIGHUP` — so you revoke a token by removing its line and sending `SIGHUP`.

::: danger Tokens do not expand or replace the peer boundary
`--require-token` is an additional gate **within** the mandatory same-uid boundary. It does not let a different uid connect. It is also not a strong boundary against a malicious same-uid process that can read the token file, inspect another client's environment, or otherwise obtain a bearer token.

For untrusted delegation — CI, another machine, a teammate, an AI agent you don't fully trust — use a **scoped identity** instead. Removing an identity with `tvault projects unshare` atomically re-keys the updated live vault, but pre-removal snapshots and artifacts remain readable; rotate underlying credentials after a compromise. See [Sharing](/guide/sharing) and [Committable secrets](/guide/committable-secrets). For CI specifically, `TVAULT_IDENTITY_KEY` gives a context a passphrase-free decrypt key — see [CI/CD](/guide/ci-cd).
:::

## See also

- [Run & environment](/guide/run-and-env) — `run`, `env`, and how they route through the agent
- [Sharing](/guide/sharing) — scoped identities for real, revocable delegation
- [Environment variables](/reference/environment-variables) — `TVAULT_NO_AGENT`, `TVAULT_AGENT_TOKEN`, `TVAULT_PASSPHRASE`
- [Security](/reference/security) — the full threat model and trust boundaries
