---
title: Desktop App
description: Install and run the TinyVault desktop GUI from the repository — an Electron front end over tvault mcp for browsing, editing, sharing, and recovering secrets without living in a terminal.
---

# Desktop App

The desktop app is an Electron GUI over the same binary you already use. It is a front end, not a second implementation: it spawns `tvault mcp` and speaks JSON-RPC over stdio, so the Go process keeps sole ownership of the crypto, the audit log, and the single-writer bbolt lock. Your CLI keeps working while the window is open.

::: warning Local use, not a release artifact
The app lives in the repository at `app/` and is built from source. It is **unsigned and unnotarized**, has no auto-update, and is not part of the `v*` release pipeline. Install it on machines you control.
:::

## What it gives you

- Secrets per project with per-field reveal (values auto-hide after 30s), copy with a self-clearing clipboard, create, edit, delete, and cryptographically random generate that never displays the value
- Version history and non-destructive rollback
- Cross-project search, and the audit log with action and text filters
- Environment groups: a drift matrix across production/preview/staging, promote with a dry-run preview, and inheritance
- Sharing: local identities, project recipients, share and revoke
- Vault ops: write a snapshot, list the existing ones, restore one

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

# Run it
bunx electron .
```

For live reload while developing, use `bun run dev` instead.

### Put it in /Applications (macOS)

```bash
bun run package
ditto release/mac-arm64/TinyVault.app /Applications/TinyVault.app
```

Because the copy is local, macOS does not tag it with the quarantine attribute, so Gatekeeper stays out of the way. On Linux and Windows, `bun run package` produces an unpacked app under `release/` that you can run or shortcut directly.

To update later, close the app and re-run those two commands.

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
- The window never opens `vault.db`. Holding it would block your CLI, because bbolt is single-writer.
- Values are hidden until you reveal one, hide themselves after 30 seconds, and are dropped when you switch project.
- Copying clears the clipboard after 30s, and again on quit.
- Screen-capture exclusion turns on only while a value is on screen, or permanently via View → *Always exclude from screen captures*, so ordinary screenshots still work.
- The passphrase never reaches the renderer.

## What it deliberately does not do

- **Rotate the passphrase.** A form would put the current and the new passphrase into renderer state and across IPC — exactly what the CLI's no-echo prompt exists to avoid. The Vault screen hands you `tvault key rotate` instead.
- **Choose where a backup or restore goes.** Snapshots are listed from `backup.dir` (or the vault directory when unset), and restore accepts only one of those paths, so the renderer cannot aim either at an arbitrary file.
- **Open external links.** `window.open` is denied outright; forwarding URLs to a browser would be an exfiltration channel for a compromised renderer.

## Verifying your install

```bash
cd app
bun run typecheck   # both TypeScript projects
bun run build       # main + preload + renderer
bun run verify      # 94 shape and security assertions against a throwaway vault
```

`bun run verify` never touches `~/.tvault`. Run it after any change to `internal/mcp` output structs — that is the drift it exists to catch.

## See also

- [Local Agent](/guide/agent) — the read-only socket path the app can fall back to
- [Access Policy](/mcp/access-policy) — the file that scopes everything above
- [Backups & recovery](/guide/backups) — what a snapshot is, and what it is not
