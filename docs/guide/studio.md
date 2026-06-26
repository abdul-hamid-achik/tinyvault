---
title: Interactive Studio
description: tvault studio is a full-screen terminal UI for browsing and optionally editing your TinyVault secrets — read-only by default, with audited reveals.
---

# Interactive Studio

`tvault studio` is a full-screen terminal UI for your vault. It is the human surface that sits alongside the [CLI](/cli/) and the [MCP server](/mcp/) — a place to see what is in the vault, filter keys, reveal a value on demand, and (when you opt in) make audited edits without leaving the terminal.

It is **read-only by default**: with no flags, a stray keystroke cannot change anything. The only decryption the studio performs is the on-demand reveal, which is audited exactly like `tvault get`.

```bash
tvault studio                 # read-only browser
tvault studio --rw            # enable audited in-app new / edit / delete
tvault studio webapp          # open straight into a project
```

The command is also available as `browse` and `ui`; both are kept aliases for the same UI:

```bash
tvault browse
tvault ui
```

::: info Needs a TTY
The studio requires an interactive terminal. It will not run when stdin/stdout is piped or redirected. For non-interactive use (scripts, CI, agents) use the CLI or MCP instead.
:::

## The four panes

The studio is divided into four panes. Move between them with the arrow keys, `h`/`l` (vim), the number keys `1`–`4`, `tab`/`shift+tab` to cycle, or the mouse.

| # | Pane | What it shows |
|---|----------|---------------|
| 1 | **Status** | Vault state (locked/unlocked), the active project, counts, env group membership, and the current studio mode. |
| 2 | **Projects** | All projects with env-group annotations. Press `enter` to open the selected project; its secrets load into the secrets pane. |
| 3 | **Secrets** | Keys in the active project, masked. This is where you filter, reveal, copy, and (with `--rw`) edit. |
| 4 | **Audit** | The most recent audit entries (reveals, edits, unlocks). Size it with `--audit-limit`. |

Light and dark terminal themes are auto-detected, so the studio fits your existing color scheme.

## Keybindings

Press `?` inside the studio for the in-app cheat sheet, or run `tvault help studio` for the full reference.

### Navigation

| Key | Action |
|-----|--------|
| `↑` / `k`, `↓` / `j` | Move selection up / down |
| `←` / `h`, `→` / `l` | Previous / next pane |
| `1` `2` `3` `4` | Jump to status / projects / secrets / audit |
| `tab` / `shift+tab` | Cycle panes forward / back |
| `enter` | Open the selected project |
| mouse | Click a pane or row to select it |

### Working with secrets

| Key | Action |
|-----|--------|
| `/` | Filter keys live as you type |
| `r` | Reveal the selected value (audited) |
| `R` | Reveal all values in the current project (audited) |
| `c` | Copy the selected value to the clipboard |
| `esc` | Re-mask / go back / clear the filter / close an overlay |
| `u` | Unlock the vault in-app (prompts for your passphrase) |
| `L` | Lock the vault |
| `^r` | Reload data from disk |
| `^l` | Force a redraw |
| `q` / `^c` | Quit |

### Environment groups

When the current project is part of an [environment group](/guide/env-groups), three extra bindings are available:

| Key | Action |
|-----|--------|
| `g` | Cycle to the next environment in the group (loads its secrets) |
| `D` | Show an env drift overlay — key-set diff across all environments |
| `G` | List all env groups with their environments and inheritance |

The Secrets pane marks inherited keys with `←` (resolved from a base env at read time) and pinned keys with `◈` (local value, inheritance broken for that key). The Projects pane annotates grouped projects with their env name (e.g. `·production`, `·preview`).

When a secret is showing, the studio paints it in a warm amber accent, so the revealed state is never silent or ambiguous.

::: tip Filter, then reveal
`/` filters on the key name only and never decrypts. Narrow the list first, then press `r` on the one key you actually need — that keeps the audit log tight and your screen clean.
:::

## The reveal security model

Revealed plaintext lives **only in memory**, and only for as long as you are looking at it. The studio wipes revealed values on every transition that could leave a secret on screen:

- `esc` (re-mask)
- changing panes
- locking the vault (`L`)
- reloading (`^r`)
- quitting (`q`)

Each `r` / `R` reveal is written to the audit log just like a `tvault get`, so a browse session leaves the same trail as scripted access. There is no setting that turns auditing off.

::: warning Reveal is a real decryption
`r` and `R` decrypt the value and put plaintext on your screen, and `c` puts it on the clipboard. Treat a revealed studio the same way you would treat a terminal with `tvault get` output in the scrollback — over a shared screen, an SSH session, or a recorded demo it is just as exposed.
:::

## Editing in the studio (`--rw`)

By default the studio cannot write. Pass `--rw` to enable in-app mutations:

```bash
tvault studio --rw
```

In `--rw` mode the secrets pane gains three actions:

| Key | Action |
|-----|--------|
| `n` | New secret (add a key/value to the active project) |
| `e` | Edit the selected secret's value |
| `d` | Delete the selected secret |

These reuse the exact same code path as the CLI — `vault.SetSecret` / `vault.DeleteSecret` — so they enforce the same rules and produce the same audit records as `tvault set` / `tvault delete`. As on the CLI, editing a value **archives the prior version** (see [Versioning](/guide/versioning)), and deleting a key purges that key's history. Prefilling the edit field reveals the current value, which is audited as a read.

::: info What stays in the CLI
The studio edits values; it does not manage the vault's structure. Project create/delete, secret rotation, key rotation, and sharing stay in the CLI. See [Projects](/guide/projects), [Key management](/guide/key-management), and [Sharing](/guide/sharing).
:::

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `[project]` | active project | Positional arg: open straight into this project. |
| `--rw` | off | Enable audited in-app new / edit / delete. Omit it to stay read-only. |
| `--single-pane` | off | Single-pane layout for small terminals. |
| `--no-anim` | off | Disable animations (good for SSH, `screen`/`tmux`, and screen readers). Also set via `TVAULT_NO_ANIM`. |
| `--audit-limit <N>` | `100` | How many recent audit entries to load into the audit pane. |

The six global persistent flags work here too: `--config <file>`, `--vault <dir>`, `-p`/`--project <name>`, `--json`, `-v`/`--verbose`, and `--no-agent`. `-h`/`--help` is available on every command.

```bash
# Small terminal, single pane, no animations
tvault studio --single-pane --no-anim

# Open the staging project with a deeper audit window
tvault studio staging --audit-limit 200
```

::: tip SSH and accessibility
On a remote shell, inside `tmux`/`screen`, or with a screen reader, run with `--no-anim` (or export `TVAULT_NO_ANIM=1`) for a calmer, redraw-friendly UI.
:::

## Configuration defaults

The optional `browse:` block in `~/.tvault/config.yaml` supplies studio defaults. The block keeps the name `browse` for backwards compatibility with the old command name — it configures `studio`. Explicit CLI flags always win over these values.

```yaml
# ~/.tvault/config.yaml
browse:
  no_anim: true        # default --no-anim
  single_pane: false   # default --single-pane
  audit_limit: 200     # default --audit-limit
```

A missing config file is fine. A malformed one is flagged by `tvault doctor`. See [Configuration](/reference/configuration) for the full file reference.

## See also

- [The local agent](/guide/agent) — keep the vault unlocked so reveals skip the prompt
- [Versioning & rollback](/guide/versioning) — every `--rw` edit archives the prior value
- [Security model](/reference/security) — the threat model behind reveal, audit, and redaction
- [CLI reference](/cli/) — the scriptable surface for everything the studio shows
