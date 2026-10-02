---
title: Desktop App
description: Install and run the TinyVault desktop GUI from the repository — an Electron front end over tvault mcp for browsing, editing, sharing, and recovering secrets without living in a terminal.
---

# Desktop App

The desktop app is an Electron GUI over the same binary you already use. It is a front end, not a second implementation: it spawns `tvault mcp` and speaks JSON-RPC over stdio, so the Go process keeps sole ownership of the crypto, the audit log, and the single-writer bbolt lock. Your CLI keeps working while the window is open.

::: warning Unsigned and unnotarized
Release builds are attached to every `v*` GitHub Release, but they are **not signed and not notarized** — there is no Developer ID or Authenticode certificate in this project. Your OS will warn on first launch, and the steps below are not optional. There is no auto-update: to upgrade, download the new asset. If you would rather not run an unsigned binary, [build it from source](#install-from-the-repository) — the result is bit-for-bit the same app with the same warnings.
:::

## What it gives you

- Secrets per project with per-field reveal (values auto-hide after 30s), copy with a self-clearing clipboard, create, edit, delete, and cryptographically random generate that never displays the value
- Version history and non-destructive rollback
- Cross-project search, and the audit log with server-side time-range, action, and resource-type filters
- Environment groups: create one by linking existing projects, a drift matrix across production/preview/staging, promote with a dry-run preview, add and remove environments, delete a group, set inheritance, and pin or unpin an inherited key
- Sharing: local identities, project recipients, share and revoke, seal secrets to a commit-safe `.env.encrypted`, and open a sealed blob back to a `0600` file
- `.env` files: discover dotenv files in a folder, preview an import (key names and actions, never values), import, diff against a project, sync in either direction, and export plaintext or encrypted
- Vault ops: write a snapshot, list the existing ones, restore one

## Download a release build

Every [`v*` release](https://github.com/abdul-hamid-achik/tinyvault/releases) carries the desktop artifacts beside the CLI archives:

| Platform | Asset |
|---|---|
| macOS (Apple silicon) | `TinyVault-<version>-mac-arm64.dmg` |
| macOS (Intel) | `TinyVault-<version>-mac-x64.dmg` |
| Linux | `TinyVault-<version>-linux-x64.AppImage`, `…-linux-arm64.AppImage` |
| Windows | `TinyVault-<version>-win-x64.exe`, `…-win-arm64.exe` |

They are built by `.github/workflows/release-app.yml` from the same tag as the CLI, so the app and the binary it drives are always the same release.

### First launch

The app needs the `tvault` CLI on `PATH` — it is a front end, not a self-contained bundle. Install the CLI first ([Install & quickstart](/guide/getting-started)), then clear your OS's warning:

**macOS** — Gatekeeper blocks an unsigned app. Move it to `/Applications`, then either right-click → *Open*, or:

```bash
xattr -dr com.apple.quarantine /Applications/TinyVault.app
```

**Windows** — SmartScreen warns. Choose *More info* → *Run anyway*.

**Linux** — make the AppImage executable and run it. If FUSE is unavailable:

```bash
chmod +x TinyVault-<version>-linux-x64.AppImage
./TinyVault-<version>-linux-x64.AppImage --appimage-extract-and-run
```

## Requirements

| Need | Why |
|---|---|
| `tvault` on PATH | the app spawns it; Homebrew, npm, or a local build all work |
| [bun](https://bun.sh) | installs dependencies and builds the renderer |
| macOS, Linux, or Windows (amd64/arm64) | the same matrix the CLI ships |

The local [agent](/guide/agent) is optional: with a passphrase source configured the app unlocks directly and supports writes; with only a running agent it serves reads and disables writes.

## Install from the repository

```bash
git clone https://github.com/abdul-hamid-achik/tinyvault.git
cd tinyvault/app
bun install
bun run build     # writes out/: the main, preload, and renderer entry points

# Run it
bunx electron .
```

`bun run build` is not optional on a fresh clone — `out/` is gitignored and `package.json` points Electron's `main` at `out/main/index.js`, so `bunx electron .` has nothing to load without it. For live reload while developing, use `bun run dev` instead; it builds and watches in one step.

### Put it in /Applications (macOS)

```bash
bun run package
ditto release/mac-arm64/TinyVault.app /Applications/TinyVault.app
```

Because the copy is local, macOS does not tag it with the quarantine attribute, so Gatekeeper stays out of the way. On an Intel Mac the bundle lands in `release/mac/` instead of `release/mac-arm64/`. On Linux and Windows, `bun run package` produces an unpacked app under `release/` (`linux-unpacked/`, `win-unpacked/`) that you can run or shortcut directly.

To update later, close the app and re-run those commands, starting from `bun install`.

## Before first launch: three things the app checks

The **Connection** screen reports each of these rather than failing opaquely.

1. **The binary.** Resolution order is a saved setting, `TVAULT_BIN`, the bundled npm package, then the usual install prefixes and PATH. A macOS app launched from Finder inherits a minimal PATH, so the app augments it with `/opt/homebrew/bin` and friends.
2. **`~/.tvault/mcp-policy.yaml`.** Without it the server falls back to the fail-closed default — read-only with every secret key denied — and the app shows an empty vault. All eight fields are mandatory, and unknown fields are rejected:

```yaml
access_mode: read-write
projects_allow: ["*"]
projects_deny: []
secrets_allow: ["*"]
secrets_deny: []
allow_exec: false
max_reads_per_session: 100
redact_output: true
```

3. **A non-interactive passphrase source** for writes: `agent.passphrase_file` or `agent.passphrase_command` in [config.yaml](/reference/configuration), or `TVAULT_PASSPHRASE`. A `passphrase_command` pointing at 1Password with biometric approval is the strongest option — a human gate on every unlock.

::: tip max_reads_per_session is a budget, not a suggestion
`vault_get_secret` is capped per MCP session by this number, and `0` means deny, not unlimited. The sidebar shows `used/limit` live and offers a session restart when you run out.
:::

## How it stays safe

- The renderer is sandboxed: no Node, no filesystem access, no navigation, every permission request denied, strict CSP. The preload exposes a fixed method list — there is no generic IPC escape hatch.
- **The renderer cannot author a file path.** Anything that reads or writes a file (`.env` import, drift diff, sync, plaintext export, sealing, opening a sealed blob) gets its path from an OS dialog answered in the main process, or from a dotenv file the server discovered inside a folder you picked. Main records every path it issued and refuses anything else, so a compromised renderer cannot aim an export or a sync at an arbitrary file.
- The window never opens `vault.db`. Holding it would block your CLI, because bbolt is single-writer.
- Values are hidden until you reveal one, hide themselves after 30 seconds, and are dropped when you switch project.
- Copying clears the clipboard after 30s, and again on quit.
- Screen-capture exclusion turns on only while a value is on screen, or permanently via View → *Always exclude from screen captures*, so ordinary screenshots still work.
- The passphrase never reaches the renderer.

## What it deliberately does not do

- **Rotate the passphrase.** A form would put the current and the new passphrase into renderer state and across IPC — exactly what the CLI's no-echo prompt exists to avoid. The Vault screen hands you `tvault key rotate` instead.
- **Choose where a backup or restore goes.** Unlike the `.env` and sealing flows, which ask you through an OS dialog, snapshots have no picker at all: they are listed from `backup.dir` (or the vault directory when unset), and restore accepts only one of those paths. A vault snapshot is the whole database, so there is no destination worth letting anyone choose.
- **Open external links.** `window.open` is denied outright; forwarding URLs to a browser would be an exfiltration channel for a compromised renderer.

## Verifying your install

```bash
cd app
bun run typecheck   # both TypeScript projects
bun run build       # main + preload + renderer
bun run verify      # shape and security assertions against a throwaway vault
```

`bun run verify` never touches `~/.tvault`. It asserts the wire shape of every MCP tool the app calls, plus the properties the UI depends on — files written `0600`, no plaintext in any response, `env_name` versus `env`, writes refused under a read-only policy. Run it after any change to `internal/mcp` output structs; that is the drift it exists to catch, and it prints its own pass count.

## See also

- [Local Agent](/guide/agent) — the read-only socket path the app can fall back to
- [Access Policy](/mcp/access-policy) — the file that scopes everything above
- [Backups & recovery](/guide/backups) — what a snapshot is, and what it is not
