# CLAUDE.md — working in this repo with Claude Code

TinyVault is a **single Go binary**: a local-first secrets CLI (`tvault`) plus
an MCP server (`tvault mcp`, alias `mcp-server`), backed by one local bbolt
database whose secret payloads and key material are encrypted. No servers, no
accounts, no cloud. There is also an interactive terminal
studio UI, `tvault studio` (aliases: `browse`, `ui`).

**Read these first — they are the source of truth:**
- [AGENTS.md](AGENTS.md) — project structure, code conventions, security
  rules, dependency table. **Read it before any non-trivial change.**
- [Architecture](docs/reference/architecture.md) and
  [Security](docs/reference/security.md) — crypto design and threat boundary.
- [README.md](README.md) — user-facing quickstart and feature list.
- [ROADMAP.md](ROADMAP.md) — product direction and deferred work.

## Quick commands (these mirror CI exactly — there is no Makefile/Taskfile)

```bash
go build ./...                 # Build
go test -race -count=1 ./...   # Test (race detector)
golangci-lint run ./...        # Lint — MUST be 0 issues
govulncheck ./...              # Security Scan
```

CI (`.github/workflows/ci.yml`) gates `main` on four jobs: **Test, Lint,
Security Scan, Build**. All four must be green.

> ⚠️ **Run `golangci-lint run ./...` locally before pushing.** It is not
> installed by default (`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`).
> `go build` + `go test` passing is **not** enough — the Lint job (gocritic,
> exhaustive, revive, unparam, gosec, …) is strict and is a common cause of a
> red `main`. Config lives in `.golangci.yml`.

## Non-negotiable conventions (full list in AGENTS.md)

- **Imports:** goimports with `-local github.com/abdul-hamid-achik/tinyvault`
  (stdlib, third-party, local — three groups).
- **Octal literals:** `0o600` / `0o700`, never `0600`.
- **Errors:** wrap with `%w`; sentinel errors in `internal/vault/errors.go`.
- **Security:** never log or print a secret value; never commit `~/.tvault/`
  or `*.db`; AES-256-GCM + Argon2id only; output redaction is a safety net,
  not a control. Only deliberately value-returning surfaces such as
  `vault_get_secret` may return plaintext, and they must remain explicit and
  policy-gated.
- **Exhaustive switches:** a `default:` clause counts as exhaustive
  (`default-signifies-exhaustive`). Enum sentinels like `paneCount` don't need
  an explicit case.

## Sharing & committable secrets (the recipient layer)

- `internal/crypto/recipient.go` is the asymmetric layer: X25519 → HKDF-SHA256
  → ChaCha20-Poly1305 wrapping (`WrapDEK`/`UnwrapDEK`, `Identity`). It uses
  only stdlib `crypto/ecdh` + already-vendored `x/crypto` — **do not add
  `filippo.io/age` or any new crypto dependency** without discussion.
- Built on it: `tvault identity new/list`, `projects share/unshare/recipients`
  (recipient removal **rotates the DEK and re-encrypts every current value and
  archived version in the updated live vault** via `store.RekeyProject`;
  pre-removal snapshots and previously distributed artifacts remain readable),
  the `.env.encrypted` **v2** format (`EncryptV2`/`DecryptV2`, commit-safe,
  KEK-independent), and `tvault git-filter` (clean/smudge, `gitfilter.go`).
- Identities are passphrase-independent keypairs at
  `~/.tvault/identities/<name>.key` (0600). Public half = `tvault1…`
  (shareable/committable), private half = `tvault-key1…` (never commit).
- **CI/ssh/agents** supply a per-context identity via `TVAULT_IDENTITY_KEY`
  (a `tvault-key1…` string) — `resolveIdentity` (identity.go) is the single
  resolver behind `open`/`decrypt-env`/`env --identity`/git filters. Precedence
  is **file > env key** (with a stderr warning when a file overrides a set env
  key), and the env-key value must **never** be echoed in an error. `tvault
  identity export` prints the private key (TTY-guarded, `--force` off a tty);
  `tvault ci init --mode=identity` scaffolds a passphrase-free workflow.
- `git-filter` invariants worth preserving: the clean filter is **idempotent**
  (re-emits the staged blob when plaintext is unchanged, or `git status` is
  perpetually dirty), refuses to run with no recipients, passes already-encrypted
  input through (no double-encrypt), and in **locked mode** (no identity) the
  smudge filter passes ciphertext through instead of failing checkout.

## Versioned secrets & rollback

- Prior values live in the `secret_versions` bbolt bucket, keyed
  `projectID/key/%010d(version)` (current value stays in `secrets`). `SetSecret`
  **archives the old entry before overwriting, in the same transaction** — keep
  that all-or-nothing invariant. `DeleteSecret` purges a key's history.
- Surfaces: `tvault history` / `tvault get --version N` / `tvault rollback --to N`
  (CLI), `vault_secret_history` / `vault_rollback_secret` (MCP, **never return a
  value**). Rollback is non-destructive — it re-stores an old version as a new
  one; version numbers are monotonic, never reused.
- **Invariant:** history is encrypted with the project DEK, so any DEK rotation
  must re-encrypt it. `UnshareProject` feeds `ListSecretVersionEntries` through
  the re-encrypt loop into `RekeyProject` (which writes current + history
  atomically). `TestUnshareReEncryptsHistory` guards this — keep it passing.
  KEK rotation (`tvault key rotate`) doesn't touch values, so history is safe.

## The local agent (`tvault agent`) — `internal/agent/`

- Unix-only, opt-in daemon that holds the vault unlocked over a private 0600
  unix socket so `get`/`env`/`run` skip the prompt + Argon2id. Build-tagged
  (`*_unix.go` + `stub_other.go`); Windows gets `ErrUnsupportedPlatform`.
- **Invariant — KEK-only, never an open DB.** bbolt is single-writer-process;
  holding the database open would block every other `tvault`. The agent caches
  only the KEK and reopens the vault per request (`vault.UnlockWithKEK`),
  serialized by a mutex, so direct CLI access keeps working. Don't "optimize"
  this into a held-open store.
- **Security invariants worth preserving:** socket 0600 in the 0700 dir, tight
  umask (no listen→chmod window), `flock` single-instance, mandatory peer-uid
  check (fail-closed; per-OS `peercred_*.go`), read-only ops, and KEK zeroing on
  **every** exit path (signal/idle/stop/panic). `agent start` never daemonizes.
- CLI routing (`get`/`env`/`run`) tries the agent then falls back to a direct
  unlock; `--no-agent` / `TVAULT_NO_AGENT` force direct. `x/sys` is now a direct
  require for the peer-cred calls (was indirect — no new module).
- **`--require-token` honesty:** capability tokens (`tokens_unix.go`) are a
  privilege-separation gate for an **OS-confined** delegate only — they are
  **not** a control against a same-uid process (it can read the token or dial
  the socket). Keep [token honesty](docs/reference/security.md#token-honesty)
  and [capability tokens](docs/guide/agent.md#capability-tokens-same-uid-clients-only)
  truthful. **Do not** build
  the full broker (in-band mint, per-key allowlists, TTL) — a design panel ruled
  it security theater; the recipient/identity model is the answer for real
  delegation. Tokens are out-of-band (0600 file, SIGHUP reload), only their
  SHA-256 is stored, and audit logs a hash prefix (`token_id`), never the token.

## The interactive studio UI (`tvault studio`, aliases `browse`/`ui`)

- Lives in `cmd/tvault/cmd/studio/` — the **only** package that imports
  `charm.land/*` (Bubble Tea v2 / Lip Gloss v2 / Bubbles v2 / Glamour v2).
  Strictly the v2 line: no `harmonica`, no `huh`; animations are hand-rolled.
  `browse` and `ui` remain working aliases for `studio`; the `browse:` config
  block in `~/.tvault/config.yaml` keeps its name.
- **Read-only by default** — with no flags it never writes; the only decryption
  is the on-demand reveal (`r`), audited like `tvault get`. `--rw` enables
  audited in-app edits (`n`/`e`/`d`) that reuse the CLI's `vault.SetSecret`/
  `DeleteSecret` path; rotation + project create/delete stay in the CLI.
- **Invariant:** every rendered `View().Content` must be exactly the terminal
  `width × height` cells, or Bubble Tea's cell-diff renderer corrupts the
  screen. `layout_test.go` enforces this across all modes — keep it passing.
- Reveal-map values are wiped on `esc`, pane change, lock, reload, and quit,
  and a late (epoch-stale) reveal is dropped so it can't resurrect a value.
- **Verify TUI changes in a real PTY** with glyphrun (the `glyph` CLI, at
  `~/projects/glyphrun`): `glyph run specs/glyphrun/studio_reveal.yml --format md`.
  The full e2e suite (reveal, filter, panes, reveal-all, unlock, `--rw` edit,
  env group status, cycle envs, drift overlay, groups overlay)
  and two glyphrun gotchas (config-injected passphrase; overlays / single-cell
  updates not always repainting → drive modals blind) are documented in
  `specs/glyphrun/README.md`.

## Documentation site (`docs/` → tinyvault.dev)

User-facing docs live in `docs/` — a **VitePress (v1) + Bun** site deployed to
**Vercel** at **[tinyvault.dev](https://tinyvault.dev)** (served at
`www.tinyvault.dev`; the apex 308-redirects to www, so `SITE_URL`/canonical/
sitemap use www). It is **git-connected**: any push to `main` that touches
`docs/` auto-builds and deploys (Vercel project `tinyvault-docs`, root directory
`docs/`, `bun run docs:build`, output `.vitepress/dist`). Iterate locally with
`cd docs && bun run docs:dev`; gate with `bun run docs:build` (it fails on dead
links). Theme + config live in `docs/.vitepress/` ("Vault Amber"). Content is
verified against the real binary — there is **no `tvault generate` and no
`tvault audit`** command despite older help-text mentions.

## Committing

Branch off `main` for changes; ensure all four CI checks pass locally before
pushing. Keep `AGENTS.md`, `README.md`, `ROADMAP.md`, the Architecture,
Security, and MCP docs, and `tvault help` / `tvault docs` in sync when behavior
changes — they cross-reference each other.
