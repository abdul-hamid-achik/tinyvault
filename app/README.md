# TinyVault Desktop

An Electron GUI over the existing `tvault` binary. It is a **front end**, not a
second implementation: all vault access goes through `tvault mcp`, so the Go code
keeps sole ownership of the crypto, the audit log and the single-writer bbolt
lock.

**Unsigned and unnotarized** — this project holds no Developer ID or Authenticode
certificate, so Gatekeeper and SmartScreen warn on first launch. It *is*
distributed, though: `.github/workflows/release-app.yml` runs after the Release
workflow and attaches `TinyVault-<version>-{mac,linux,win}-<arch>` artifacts to the
same GitHub Release. There is no auto-update, and the app does not bundle the Go
binary — it resolves `tvault` at runtime.

---

## Run it

```bash
cd app
bun install
bun run dev          # HMR
bun run build && bunx electron .   # production bundle
```

`bun run build` is not optional before `bunx electron .`: `out/` is gitignored and
`package.json` points Electron's `main` at `out/main/index.js`.

### Packaging

```bash
bun run package      # electron-builder --dir: an unpacked app under release/, for local use
bun run dist         # real artifacts (dmg / AppImage / nsis) under release/
```

CI builds the artifacts, not this directory — see
`.github/workflows/release-app.yml`. It stamps the release version into
`package.json` before packaging, which is why the version there is not kept in
sync by hand.

### Prerequisites

1. **`tvault` on PATH.** Resolution order is `settings.json` → `TVAULT_BIN` →
   the bundled `@thelacanians/tinyvault-<platform>` npm binary → `/opt/homebrew/bin`,
   `/usr/local/bin`, `~/.local/bin`, `~/go/bin` → bare `tvault` on an augmented
   PATH. The augmentation matters: a macOS app launched from Finder inherits a
   minimal PATH, so a Homebrew `tvault` would otherwise be invisible (the same
   class of bug as CHANGELOG v0.21.1).

2. **`~/.tvault/mcp-policy.yaml`.** Without it the server uses the fail-closed
   `SafeDefaultPolicy` — read-only with every secret key denied — and the app
   shows an empty vault. All eight fields are mandatory; the Go loader rejects an
   incomplete file and rejects unknown fields too:

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

3. **A non-interactive passphrase source.** `agent.passphrase_file` or
   `agent.passphrase_command` in `~/.tvault/config.yaml`, or `TVAULT_PASSPHRASE`.
   A `passphrase_command` pointing at 1Password with biometric approval is the
   strongest option — it gives a human-in-the-loop gate on every unlock. Without
   any of these the child falls back to the read-only local agent and writes are
   refused.

The **Connection** screen in the app reports the state of all four prerequisites
(binary, vault, policy, session) rather than failing with a generic error.

---

## Architecture

```
Electron main (Node)
  ├─ McpSession ──spawn stdio──► tvault mcp ──► KEK cache + reopen-per-request ──► vault.db
  │              JSON-RPC (@modelcontextprotocol/sdk)
  ├─ runCli ─────spawn argv────► tvault backup / doctor      (no MCP tool exists)
  └─ clipboard (auto-clear)
        │
        │ contextBridge — exactly the methods in src/preload/index.ts
        ▼
Electron renderer (sandboxed Chromium) — never spawns, never touches the fs
```

**Do not open `vault.db` from this process.** bbolt is single-writer; a held-open
handle would block the user's CLI. `tvault mcp` already implements the correct
pattern — cache only the KEK, reopen per request under a mutex — and this app
inherits it by construction. `AGENTS.md` calls that invariant non-negotiable.

### Layout

```
src/shared/     types.ts (wire shapes mirroring internal/mcp structs), ipc.ts (channel names)
src/main/       index.ts (window + hardening), mcp.ts (session), cli.ts (argv runner),
                binary.ts (resolution + PATH), policy.ts, paths.ts, clipboard.ts, ipc.ts,
                fsaccess.ts (dialog-issued paths), config.ts (settings.json),
                lifecycle.ts (quit ordering), protection.ts (screen-capture exclusion)
src/preload/    index.ts — the entire bridge surface
src/renderer/   React UI
scripts/        spike-mcp.ts (handshake probe), verify-contracts.ts (shape contract test),
                make-icons.mjs (build/ icon regeneration), shot-hover.mjs (screenshot helper)
```

---

## Security model

The renderer is treated as potentially hostile:

- `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, `webSecurity: true`,
  no `webviewTag`, no node integration in workers or subframes.
- The preload exposes a **fixed method list** — no generic `invoke(channel, …)`
  escape hatch, so a compromised renderer cannot reach a channel the app never
  wired up.
- Strict CSP; `script-src 'self'` blocks inline script entirely.
- Navigation is blocked, `window.open` is denied (http(s) links are not forwarded
  anywhere — see the invariants below), and every permission request is refused.
- Screen-capture exclusion is **dynamic**: the window is excluded from
  `screencapture` and screen-share pickers only while a value is actually on
  screen (a revealed row, or the editor holding a loaded value). Always-on was
  tried first and silently broke Cmd+Shift+4 and `screencapture` for this window
  entirely — the user could not screenshot their own app. View → *Always exclude
  from screen captures* forces it for a whole session.
- The passphrase never reaches the renderer; it is resolved by the Go child.

Secret values are transient by construction:

- Values are hidden until an explicit per-field reveal.
- A revealed value auto-hides after 30s and is dropped from React state — it is
  never cached, so re-revealing spends another unit of the policy read budget.
- Revealed values are cleared on project switch.
- Copy goes through main, which clears the clipboard after 30s and only if the
  value it wrote is still there (it will not clobber unrelated clipboard content).
- Editing masks the field by default; "show while editing" re-masks on blur.
- Nothing is persisted to `localStorage`/IndexedDB except the light/dark theme.

Known residual risks — accepted, and the same ones `docs/reference/security.md`
already documents for any same-uid process:

- **No memory zeroing.** Go calls `crypto.ZeroBytes` on the KEK and DEKs at every
  exit path; V8 gives no equivalent, so a revealed value lingers in the renderer
  heap until GC.
- **Chromium is a large same-uid attack surface** holding decrypted values.
- The CSP keeps two `ws://localhost` entries for Vite HMR that a static meta tag
  cannot strip from the packaged build. Connecting there requires a local
  same-uid listener, which is already inside the trust boundary.

### Invariants — do not undo these without a reason

Each of these was a real bug found in review, not a stylistic choice:

- **Reveals carry a generation counter** (`SecretsView.tsx` → `useReveals`).
  Switching projects while a reveal is in flight must discard the response.
  Without the check, a key name shared by both projects (`DATABASE_URL` exists
  almost everywhere) shows project A's value under project B — and the copy
  button copies it.
- **The editor guards its load-current-value fetch the same way**, and wipes
  `value` from state on close. A slow response for key A landing after the modal
  moved to key B would let Save overwrite B with A.
- **Delete targets are a discriminated union, never a magic string.**
  `__project__` satisfies the Go key regex (`^[a-zA-Z_][a-zA-Z0-9_]*$`), so using
  it as the project sentinel meant a secret actually named `__project__` would
  delete the entire project.
- **`flushClipboard()` clears the pasteboard on quit.** Cancelling the timer
  without clearing leaves a secret copied seconds ago on the system clipboard
  after the app is gone.
- **`max_reads_per_session: 0` means DENY, not unlimited.** `consumeValueRead`
  in `internal/mcp/config.go` returns false for `limit <= 0`. Treat 0 as
  exhausted everywhere.
- **The policy is read once at connect, never live.** The Go server loads
  `mcp-policy.yaml` at startup only; re-reading it in the app would let the
  displayed budget diverge from what is actually enforced.
- **The child env is an allowlist.** Spreading `process.env` would forward
  `GITHUB_TOKEN`, cloud credentials and the user's own passphrase into a
  long-lived child for no reason.
- **`setWindowOpenHandler` denies unconditionally.** Forwarding http(s) to
  `shell.openExternal` would give a compromised renderer an exfil channel that
  `connect-src` otherwise closes. This app renders no external links.
- **Capture protection follows the values, not the window.** `setContentProtection`
  at window creation excluded the window from every capture unconditionally and
  broke ordinary screenshots. The renderer now drives it from reveal state
  (`setProtectionActive`), and the View menu offers a force-always checkbox. Do
  not set it back to always-on.
- **The macOS traffic lights get their own empty drag band**, with the brand row
  below it. `hiddenInset` draws them inside the window; reserving left padding
  beside them still left them touching the logo.
- **MCP calls and restarts share one promise queue**, and `connect()` publishes
  its client only if its generation still matches. Two overlapping restarts
  would otherwise orphan a child holding a derived KEK.
- **`vault_list_secrets_detailed`, never `vault_list_secrets`.** The latter
  hardcodes `version: 1` for every key.
- **`backup()` takes no destination.** Letting the renderer name a path would
  make it an arbitrary-file-write primitive. With no argument the Go side writes
  to `backup.dir` from `config.yaml`, which is the only place that should decide.
- **`maskValue` is always a full mask.** Showing the first and last characters
  looks friendly, but for `sk-live-…` the affix is the identifying part, and the
  hint sits on screen indefinitely — outside both the auto-hide and the budget.
- **Every async view has a stale-response guard.** `loadSecrets`, `runDiff` and
  the reveals all capture a generation and discard late responses; without it,
  switching quickly paints the previous project's data under the new one.
- **A timeout is not a clean failure.** `Promise.race` abandons the call but the
  server may still apply the write, so the message tells the user to refresh
  rather than retry — retrying double-applies a non-idempotent mutation.
- **Config/env-supplied binary paths are trust-checked** (owner + not
  group/world-writable), mirroring what the Go side does for
  `agent.passphrase_command`. Well-known prefixes only require non-writable,
  since a package manager may legitimately install a root-owned binary.
- **`readPolicy` never trims its lines.** The `^key\s*:` anchors depend on that
  to match top-level keys only; trimming would make a nested key
  indistinguishable from a real policy field.

---

## Coverage

`tvault mcp` exposes 50 tools and this app calls 43 of them: secrets CRUD,
per-field reveal, generate (value never returned), version history, rollback,
projects, cross-project search, the audit log including the relational
`vault_audit_log_since` query behind the time/action/resource filters,
environment groups (create, drift matrix, promote with dry-run preview, add and
remove environments, delete, inheritance, pin/unpin, seal), sharing (identities,
recipients, share/unshare, seal for recipients, open a sealed blob), and the whole
dotenv surface (list files, preview, import, diff, sync, export, export
encrypted).

The contract test asserts 44: those 43 plus `vault_list_secrets`, which the UI
deliberately does **not** call. It is asserted so the trap stays documented — that
tool's `version` field is hardcoded to `1` for every key (`secretMeta{Key: k,
Version: 1}` in `tools_secrets.go`), so it carries no information at all. Real
version numbers come from `vault_list_secrets_detailed`, which is what the secrets
screen uses.

The seven it does not call, and why:

- `vault_run_with_secrets` — the shipped policy sets `allow_exec: false`, and
  running arbitrary commands is the CLI's job.
- `vault_list_projects` and `vault_count_secrets` — `vault_projects_overview`
  returns both in one call.
- `vault_list_secrets` — see above.
- `vault_list_secrets_by_prefix` and `vault_search_secrets` — the secrets screen
  filters client-side over a list it already holds; cross-project search uses
  `vault_list_secrets_global`.
- `vault_search_projects` — the sidebar's filter box already narrows the loaded
  project list.

The authoritative list is the `required` array at the top of
`scripts/verify-contracts.ts`: add a tool there when a screen starts calling it,
and the contract test asserts its shape from then on.

**Not covered by MCP**, so these stay CLI-only: `ssh`, `docker`, `git-filter`,
`identity export`, `self-update`, `ci init`, agent lifecycle, and passphrase
rotation. `backup`, `restore`, and `doctor` are shelled out to directly through
`cli.ts`, all three through `--json` — metadata only, since a snapshot is copied
as opaque bytes and never decrypted. `restore --json` requires `--yes`, because a
confirmation prompt cannot be answered on a machine-readable stream; that is why
the Vault screen's restore confirmation is the app's, not the CLI's.

One security note from that change: `tvault sync --json` used to emit plaintext
secret values. `sync.Conflict` carried both sides of a conflict with no json
tags and the command marshals the whole result, so every conflict leaked both
values to stdout. Nothing consumed those fields, so they are gone, and
`json_output_test.go` holds a regression test asserting neither side reaches
stdout. If you parse `sync --json` anywhere, its conflict entries are now
`{key, resolution}` and the top level is snake_case.

---

## Verification

```bash
bun run typecheck    # both tsconfig projects
bun run build        # main (ESM) + preload (CJS) + renderer
bun run verify       # assertions against a THROWAWAY vault in $TMPDIR
bun run spike        # minimal handshake probe
```

`verify` never touches `~/.tvault`. It builds a scratch vault, writes a policy
with `max_reads_per_session: 3`, and asserts the response shape of every tool the
UI consumes plus the security properties it depends on. It prints its own pass
count, so the number is never stale in prose:

- `vault_list_secrets` reports `version: 1` for every key — the trap that makes
  the UI use `vault_list_secrets_detailed` instead.
- `vault_env_group_add` / `_remove` reject `env`: the field is `env_name`, unlike
  every other env-group tool. The reference docs once said `env`.
- values survive `&`, `<`, `>` without HTML escaping.
- `vault_generate_secret` has no `value` field in its response.
- the 4th plaintext read is refused once the budget is spent.
- no secret value appears anywhere in the audit log.
- history, diff and search responses carry no value field.
- `vault_diff_env` reports only `same` / `differs` / `error` verdicts, and
  `vault_sync_env` only key names — including in its `conflicts` list, which is
  where the CLI once leaked both sides of a conflict.
- every file the server writes for us is `0600`: sealed blobs, opened blobs, and
  plaintext exports. Sealed and exported responses carry no plaintext; the
  plaintext export does land on disk, which is why the UI confirms first.
- `vault_env_seal` honours `output_path` and returns the path instead of the
  blob. It used to ignore it and always return base64.
- `vault_env_group_remove` and `vault_env_group_delete` leave every project (and
  every secret) intact — they detach metadata only.
- `vault_open_sealed` refuses an identity that does not exist.
- a read-only policy refuses writes server-side, so the UI's disabled buttons are
  backed by a real control and not just cosmetics.

The scratch environment is hermetic: `TVAULT_NO_AGENT=1` is forced and
`TVAULT_IDENTITY_KEY`, `TVAULT_PASSPHRASE_FILE`/`_COMMAND`, `TVAULT_CONFIG` and
`TVAULT_AGENT_TOKEN` are stripped, so a key or a running agent in your shell
cannot change what the test proves.

Run it after any change to `internal/mcp` output structs — that is the drift this
test exists to catch.

Debug a live run with `TVAULT_DESKTOP_DEBUG=1 bunx electron .`, which mirrors the
renderer console to stdout. It logs counts, names and errors only, never values.

### Shutdown leaves no orphans

A stranded `tvault mcp` would keep a derived KEK in memory indefinitely, so the
graceful-quit path is worth checking by hand after any change to `mcp.ts` or
`lifecycle.ts`:

```bash
TVAULT_DESKTOP_DEBUG=1 ./node_modules/.bin/electron . & EPID=$!
sleep 15
ps -eo pid,ppid,command | grep -E '/tvault mcp$' | grep -v grep   # expect exactly one child
kill -TERM $EPID; sleep 6
ps -eo pid,command | grep -E '/tvault mcp$' | grep -v grep        # expect nothing
```

Match on the binary path, not the bare string `tvault mcp` — any agent process
whose command line quotes this README will otherwise match too. Verified
2026-09-27: one child while running, zero survivors after SIGTERM.

---

## CI

`.github/workflows/ci-app.yml` runs on changes under `app/**`: `bun install
--frozen-lockfile`, `typecheck`, `build`, then `go build ./cmd/tvault` and
`TVAULT_BIN=… bun run verify`. The other workflows are Go-only and run on every
push. Run the same three locally before committing — `verify` spawns a real
`tvault`, so point it at your own build:

```bash
TVAULT_BIN=../bin/tvault bun run verify
```

`--frozen-lockfile` means a dependency bump has to commit an updated `bun.lock`,
or CI fails on install before it ever typechecks.

`dist/` in the repo root belongs to GoReleaser, which is why this package builds
to `out/` and would package to `release/`.
