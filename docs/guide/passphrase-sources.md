---
title: Keep the passphrase out of plaintext
description: Move TVAULT_PASSPHRASE out of a plaintext file and into 1Password, the macOS Keychain, or pass with agent.passphrase_command — plus a safe, staged migration using tvault shell-init.
---

# Keep the passphrase out of plaintext

Non-interactive TinyVault (CI, `tvault agent` under launchd/systemd, a login shell) has always been able to read the vault passphrase from a `0600` env-style file. That is fine for many setups, but a plaintext file has one property you cannot configure away: **any process running as you can read it.** A password manager or the OS keychain can require a human to approve each unlock instead.

`agent.passphrase_command` (and its env-var counterpart, `TVAULT_PASSPHRASE_COMMAND`) lets the passphrase live in 1Password, the macOS Keychain, `pass`, or any helper whose stdout is the passphrase. This page covers how it works, how `tvault mcp` and `tvault agent` treat it, and a staged migration off a plaintext `~/.config/secrets/env` that does not break anything mid-way.

## The unlock precedence

Every non-interactive unlock (a direct CLI read/write, `tvault agent start`, `tvault mcp`) resolves the passphrase in this order — environment beats config, and within each layer a command beats a file:

1. `TVAULT_PASSPHRASE`
2. `TVAULT_PASSPHRASE_COMMAND`
3. `TVAULT_PASSPHRASE_FILE`
4. `agent.passphrase_command` (config.yaml)
5. `agent.passphrase_file` (config.yaml)
6. `~/.config/secrets/env`, implicitly — only for the default vault, and only when the file actually defines `TVAULT_PASSPHRASE`

Then, if nothing above applies, an interactive TTY prompt.

::: info The implicit file is skipped, not an error, once it's empty
Step 6 is a convenience fallback for a file your shell already sources at startup. If that file exists but no longer holds a usable `TVAULT_PASSPHRASE` (because you moved it into 1Password, say), TinyVault treats it as "not a source" and keeps going down the list rather than failing. An **explicitly named** file (`TVAULT_PASSPHRASE_FILE` or `agent.passphrase_file`) is still strict — a missing or unusable file there is a hard error, because you asked for it by name.
:::

A locally running [`tvault agent`](/guide/agent) sits outside this list entirely: it serves reads (`get`/`env`/`run`) without needing any of these sources, because the agent already holds the KEK in memory. Writes always need the passphrase, agent or not.

## `agent.passphrase_command`

```yaml
# ~/.tvault/config.yaml
agent:
  passphrase_command: ["/opt/homebrew/bin/op", "read", "op://Private/tvault/password"]
```

A YAML **list** is the preferred form — no shell-quoting rules to think about. A single string is also accepted and is split on whitespace, with `'`/`"` grouping for arguments that contain spaces:

```yaml
agent:
  passphrase_command: "security find-generic-password -s tvault -a \"$USER\" -w"
```

(That particular string won't work as written — `$USER` is not expanded, see below. Prefer the list form for anything with variables; resolve them yourself before writing the config.)

The equivalent one-shot override is `TVAULT_PASSPHRASE_COMMAND`, split the same way:

```bash
export TVAULT_PASSPHRASE_COMMAND="op read op://Private/tvault/password"
tvault doctor
```

### How it runs

- **No shell.** The argv is executed directly (`exec`, not `sh -c`), so there is no variable expansion, globbing, or command substitution — `"$USER"` in the string above is passed to the program literally, not expanded by a shell that never runs.
- **stdin is `/dev/null`.** This matters under `tvault mcp`, whose own stdin is the MCP protocol stream — a helper must never be able to consume it.
- **stderr is inherited.** A password manager's own prompt (Touch ID, a master-password dialog) or error message stays visible to you.
- **A 2-minute timeout.** Generous enough for a human to approve a Touch ID prompt, finite enough that a wedged helper cannot hang an agent or an MCP host forever.
- **Output is capped at 4096 bytes** and refused if larger — a passphrase is short; a bigger blob usually means a misconfigured command (for example, one that dumps a whole 1Password item as JSON instead of just the field).
- **Trailing CR/LF is trimmed.** Empty output is refused.
- **Errors never include stdout.** Only the program name, exit status, and where the command came from are reported — never anything it printed.

### The config-file trust check

A command from `config.yaml` only runs when that file is **owned by the current user and not writable by group or others**. Otherwise TinyVault refuses it outright. This is a code-execution guard: `agent.passphrase_command` makes `config.yaml` a program invocation, so a loosely permissioned config file would let anyone who can write it run arbitrary code as you the next time `tvault` reads its passphrase source.

```bash
chmod 600 ~/.tvault/config.yaml
```

Note this check is about **writability**, not readability — unlike the plaintext passphrase file (below), a group-readable `config.yaml` is not itself refused, because the command's argv (a 1Password reference, a keychain item name) is not a secret. The command's *output* is what matters, and that never touches the file.

### Provider examples

**1Password CLI**, with Touch ID per unlock when the 1Password app integration is enabled:

```yaml
agent:
  passphrase_command: ["/opt/homebrew/bin/op", "read", "op://Private/tvault/password"]
```

**macOS Keychain**, via the `security` CLI:

```bash
# One-time: store the passphrase (prompts for it)
security add-generic-password -s tvault -a "$USER" -w
```

```yaml
agent:
  passphrase_command: ["/usr/bin/security", "find-generic-password", "-s", "tvault", "-a", "YOUR_USERNAME", "-w"]
```

::: warning Be honest about what the Keychain buys you
macOS Keychain access-control lists are per-binary, not per-caller-process. Any process that can run `security find-generic-password -w` as you can read the item the same way `tvault` does, because the ACL sees `security`, not `tvault`. This route mainly gets the plaintext **off disk and out of backups** — it is not a same-uid boundary. **1Password with biometric approval is the stronger choice** when you want a human gate on each unlock, not just "no plaintext file."
:::

**`pass`** (the standard unix password manager):

```yaml
agent:
  passphrase_command: ["/usr/bin/pass", "show", "tvault"]
```

Replace every `op://Private/tvault/password` and `tvault`/`YOUR_USERNAME` above with your own item paths — never commit a real path that embeds a secret value itself (a passphrase or key, not an item *reference*, is the thing to keep out of git).

## The agent and launchd/systemd

`tvault agent start` needs a non-interactive unlock source when it has no TTY (a service manager gives it none). A configured passphrase command counts as a valid source there, same as `TVAULT_PASSPHRASE` or a passphrase file:

```bash
tvault agent start &        # TTY present: prompts if nothing else is configured
# under systemd/launchd, with agent.passphrase_command set in config.yaml:
tvault agent start          # runs the command, no prompt possible
```

`tvault agent install` (which writes a launchd `LaunchAgent` on macOS or a systemd user unit on Linux) accepts `agent.passphrase_command` from config **as an alternative to** `--passphrase-file`. Unlike the file path, no passphrase material is baked into the generated plist or unit — the agent reads `config.yaml` itself at start and runs the command then.

```bash
tvault agent install                          # uses agent.passphrase_command from config.yaml
tvault agent install --passphrase-file ~/.config/secrets/env   # or the file-based route
```

Two things `tvault agent install` warns you about, because they are the two ways a service-managed command most often fails silently:

- **A non-absolute program name may not resolve.** A service starts with a minimal `PATH`, so `passphrase_command: ["op", "read", "..."]` can work in your interactive shell and fail at boot. Use the full path (`command -v op` to find it, e.g. `/opt/homebrew/bin/op`).
- **The helper may need a logged-in, unlocked GUI session.** 1Password's Touch ID integration and the macOS Keychain both assume a human is logged in. At boot, before you unlock your screen, the command can fail — the agent will then fall back to failing that unlock rather than hanging, and the next direct command retries it.

## `tvault mcp` behavior

`tvault mcp` treats a passphrase command differently from an env var or a passphrase file, on purpose:

- If `TVAULT_PASSPHRASE` or a passphrase file (env or config) resolves, `tvault mcp` unlocks directly at startup, exactly as before.
- A passphrase **command** — whether `TVAULT_PASSPHRASE_COMMAND` in the host's env or `agent.passphrase_command` in config — is **not** counted as a "cheap" source for that decision. `tvault mcp` prefers a running [local agent](/guide/agent) for reads first, and only runs the command as the **fallback unlock** when no agent is reachable.

The reasoning: a passphrase command may block on a human (a Touch ID prompt, a password-manager unlock dialog). If `tvault mcp` ran it eagerly on every server start, every MCP session start would demand biometric approval even though a running agent could have served the reads for free. Keep an agent running (`tvault agent install`) if you want MCP sessions to start without any prompt at all; the command still works as a safety net when the agent is down.

Writes always need the passphrase regardless of how reads are served — the agent is read-only.

## `tvault doctor`

`doctor` reports which non-interactive source would be used, without ever running the command or printing anything sensitive:

```bash
tvault doctor
```

| Result | Meaning |
| --- | --- |
| `TVAULT_PASSPHRASE (environment)` | OK — an env var is set. |
| `passphrase command "op" from ~/.tvault/config.yaml (not run by doctor)` | OK — a command is configured. `doctor` also warns if the program isn't found on `PATH`. |
| `passphrase stored in plaintext file ~/.config/secrets/env; ...` | WARN — suggests moving to `agent.passphrase_command`. |
| `none (interactive prompt, or a running agent for reads)` | Info — nothing configured; reads can still go through a running agent. |

`doctor` never unlocks the vault and never prints a secret — this check only inspects configuration.

## `tvault shell-init` — load a project at shell startup, safely

`tvault shell-init <bash\|zsh\|fish> --project <name>` prints assignments for `eval` at shell startup (`~/.zshrc`, `~/.bashrc`, `config.fish`):

```bash
eval "$(tvault shell-init zsh --project personal)"          # ~/.zshrc
eval "$(tvault shell-init bash -p personal --only GITHUB_TOKEN,OPENAI_API_KEY)"
tvault shell-init fish --project personal | source            # config.fish
```

It exists specifically for the login-shell case, where prompting or breaking startup is unacceptable:

- **It never prompts.** Values come from a running `tvault agent`. With `--allow-unlock` it may also unlock directly, but only from a **non-interactive** source (the precedence list above) — never a TTY prompt.
- **A locked vault never blocks shell startup.** If nothing is available, `shell-init` prints nothing on stdout, one notice on stderr (silence it with `--quiet`/`-q`), and exits `0`.
- **`--project` is required.** A login shell must load a named project, not whatever `tvault use` last selected — that would make shell startup depend on state from a previous, unrelated session.
- **Values are quoted safely** for the target shell, and keys that are not valid shell identifiers are skipped with a name-only warning (never the value — emitting an invalid key like `A;id` verbatim would let it inject a command into the `eval`).

```bash
tvault shell-init zsh --project personal --only GITHUB_TOKEN,OPENAI_API_KEY --quiet
tvault shell-init zsh --project personal --prefix NUXT_
```

`--only`/`--prefix` narrow the loaded set (least privilege) exactly as they do for `tvault run` and `tvault env`.

::: warning Pair it with a running agent
`tvault shell-init ... --project personal` (no `--allow-unlock`) depends on a **running agent**. If no agent is reachable, it is silently a no-op every time you open a shell — nothing is loaded, and (unless `--quiet`) you get a one-line notice. Run `tvault agent install` (or start the agent yourself) alongside `shell-init` so it actually has something to serve. Adding `--allow-unlock` as a fallback means a shell opened with no agent running will fall through to your passphrase command instead — which, for a Touch ID–gated command, means a biometric prompt on every new shell that starts without the agent.
:::

::: danger Every process started from that shell inherits these
Unlike `tvault run` (one process) or the agent's `get`/`env` (on demand), variables loaded at shell startup are inherited by **every** process you start from that shell for its entire lifetime — including any AI agent or long-running tool you launch from it. Keep the startup project small (`--only`/`--prefix`), and prefer `tvault run -- <cmd>` for secrets only one program needs.
:::

### `shell-init` vs. `hook` vs. `run` vs. `env`

| Command | When it runs | Prompts? | Scope |
| --- | --- | --- | --- |
| `tvault shell-init` | Once, at shell **startup** (`.zshrc` etc.) | Never | Everything you `--only`/`--prefix` select, for the whole shell session |
| `tvault hook` + `tvault_load` | On demand, when you type `tvault_load` | Only if no agent is running | Everything in the loaded project, for the rest of the shell session |
| `tvault run -- <cmd>` | Per invocation, for one child process | Only if no agent is running and no other source | Just that one process |
| `tvault env` | Per invocation, printed for you to `eval` | Only if no agent is running and no other source | Whatever you `eval`, for the shell you eval it in |

`shell-init` and `hook`/`tvault_load` both load secrets into the current shell's environment and share the same blast radius once loaded. The difference is *when*: `shell-init` runs unattended at login and must never block or fail loudly, while `tvault_load` is something you invoke deliberately and can afford to prompt.

## Safe migration: from a plaintext env file to a password manager

This walks through moving from a `~/.config/secrets/env` that holds `export TVAULT_PASSPHRASE=...` plus a pile of `export API_KEY=...`-style lines, to: secrets imported into a `personal` project, the vault passphrase in 1Password, and the env file reduced to non-secret exports plus a `shell-init` line. Each stage is independently verifiable and the old file keeps working until you deliberately edit it in the last stage — nothing breaks mid-way.

Assume you already have a vault (`tvault init`) and 1Password CLI configured (`op read op://Private/tvault/password` returns your passphrase on its own).

### 1. Add the passphrase command, verify it, leave the old file alone

```yaml
# ~/.tvault/config.yaml
agent:
  passphrase_command: ["/opt/homebrew/bin/op", "read", "op://Private/tvault/password"]
  # passphrase_file: ~/.config/secrets/env   # delete this line if you had it
```

```bash
chmod 600 ~/.tvault/config.yaml
```

If the config already had `passphrase_file:` pointing at the env file, remove it: the command outranks it, but once the file stops holding `TVAULT_PASSPHRASE` an explicitly named file is a hard error, so the line would only be a trap.

Your shell almost certainly already has `TVAULT_PASSPHRASE` exported (that is what the old file's `export TVAULT_PASSPHRASE=...` line does on every login), and the env var wins over the command in the precedence list — so testing in your current shell would just confirm the *old* source still works, not the new one. Unset the higher-precedence variables for one invocation to test the command specifically:

```bash
env -u TVAULT_PASSPHRASE -u TVAULT_PASSPHRASE_FILE tvault doctor
env -u TVAULT_PASSPHRASE -u TVAULT_PASSPHRASE_FILE TVAULT_NO_AGENT=1 tvault list
```

`doctor` should report the passphrase command as the unlock source (and warn if `op` isn't on `PATH` — use the absolute path from `command -v op` if so), and `tvault list` should succeed without a prompt. Your `.zshrc`/`.bashrc` is untouched; every existing shell keeps working exactly as before.

### 2. Import the secrets into a project

`tvault import` reads dotenv-shaped files, but only ones named `.env`, `.env.local`, `.env.<environment>`, or `.env.<environment>.local` — `~/.config/secrets/env` isn't one of those names, so copy the `export KEY=VALUE` lines (everything **except** `TVAULT_PASSPHRASE`) into a temporary file with a name `tvault import` accepts:

```bash
tmp=$(mktemp -d)
# Drop the passphrase and anything that is configuration, not a secret
# (PATH, EDITOR, …) — adjust the pattern to your file.
grep -Ev '^(export )?(TVAULT_PASSPHRASE|PATH|EDITOR|VISUAL)=' ~/.config/secrets/env > "$tmp/.env"
chmod 600 "$tmp/.env"

tvault import --project personal --file "$tmp/.env" --dry-run   # preview first
tvault import --project personal --file "$tmp/.env"

rm -f "$tmp/.env" && rmdir "$tmp"
```

`import` accepts `export KEY=VALUE` lines (the `export ` prefix is stripped) as well as plain `KEY=VALUE`. Verify:

```bash
tvault list --project personal
```

The old file is still there and still works for everything else.

### 3. Test `shell-init` in a throwaway shell — print names only

Never print values while testing. A subshell started with `-f` (no rc files) keeps this fully isolated from your real login shell:

```bash
zsh -f -c 'eval "$(tvault shell-init zsh -p personal)"; env | cut -d= -f1'
```

If a `tvault agent` isn't already running, start one first (`tvault agent start &`, or `tvault agent install` for a persistent service) so the throwaway shell has something to load from — without an agent and without `--allow-unlock`, the command is a safe no-op and the test won't show anything loaded. Confirm the key **names** you expect appear in that output, and that no unexpected keys do.

### 4. Edit the env file — keep a backup

Only now touch the file every shell already sources.

```bash
cp -p ~/.config/secrets/env ~/.config/secrets/env.bak-$(date +%Y%m%d)
chmod 600 ~/.config/secrets/env.bak-$(date +%Y%m%d)
```

Replace its contents with the non-secret exports plus the `shell-init` line:

```bash
# ~/.config/secrets/env — reduced: no more TVAULT_PASSPHRASE or API_KEY exports
export EDITOR=nvim
export PATH="$HOME/.local/bin:$PATH"

# Load the "personal" project via the agent; never prompts, never blocks startup.
eval "$(tvault shell-init zsh --project personal --quiet)"
```

Open a **new** terminal (don't just re-source the current one — you want a clean process) and confirm the values are present:

```bash
tvault doctor
env | cut -d= -f1 | grep -E 'API_KEY|GITHUB_TOKEN'   # names only
```

Keep the dated backup somewhere with restrictive permissions until you're confident, then delete it.

### 5. Fix MCP hosts that named the old file explicitly

If any MCP host config sets `TVAULT_PASSPHRASE_FILE` pointing at the old file directly (in the server's `env` block, not through your shell), it stops working the moment the file no longer holds `TVAULT_PASSPHRASE` — an **explicitly** named file is a hard error, unlike the implicit fallback. `TVAULT_PASSPHRASE_FILE` also outranks `agent.passphrase_command` in the precedence list, so leaving it set would keep failing even after step 1.

Remove `TVAULT_PASSPHRASE_FILE` from the host's config so `tvault mcp` falls through to a running agent for reads (writes still need a passphrase source — set `TVAULT_PASSPHRASE_COMMAND` in that same `env` block if the host never has an agent available):

```jsonc
{
  "mcpServers": {
    "tvault": {
      "command": "tvault",
      "args": ["mcp"]
      // no TVAULT_PASSPHRASE_FILE — reads come from the agent,
      // writes fall back to agent.passphrase_command in config.yaml
    }
  }
}
```

The same applies to wrapper scripts (an MCP launcher, a cron job) that `source` the env file to obtain `TVAULT_PASSPHRASE`: after step 4 they get no passphrase from it, so point them at the agent or `TVAULT_PASSPHRASE_COMMAND`.

Restart the MCP session after this change — a cached unlock does not pick up the new configuration on its own.

## See also

- [Environment variables](/reference/environment-variables) — `TVAULT_PASSPHRASE_FILE`, `TVAULT_CONFIG`, and the rest.
- [Configuration](/reference/configuration) — `config.yaml` location resolution and the full `agent:` schema.
- [The local agent](/guide/agent) — `tvault agent`, `tvault agent install`, and its security model.
- [Run & environment](/guide/run-and-env) — `tvault run`/`tvault env` and the shell-quoting fix below.
- [Security](/reference/security) — the full threat model, including what a same-uid process can and cannot reach.
