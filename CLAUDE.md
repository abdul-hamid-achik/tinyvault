# CLAUDE.md — working in this repo with Claude Code

TinyVault is a **single Go binary**: a local-first secrets CLI (`tvault`) plus
an MCP server, backed by one encrypted bbolt file. No servers, no accounts,
no cloud. There is also an interactive terminal browser, `tvault browse`.

**Read these first — they are the source of truth:**
- [AGENTS.md](AGENTS.md) — project structure, code conventions, security
  rules, dependency table. **Read it before any non-trivial change.**
- [SPEC.md](SPEC.md) — architecture, threat model, crypto design, the *why*.
- [README.md](README.md) — user-facing quickstart and feature list.

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
  not a control. The MCP server must never return raw secret values.
- **Exhaustive switches:** a `default:` clause counts as exhaustive
  (`default-signifies-exhaustive`). Enum sentinels like `paneCount` don't need
  an explicit case.

## The interactive browser (`tvault browse`)

- Lives in `cmd/tvault/cmd/browse/` — the **only** package that imports
  `charm.land/*` (Bubble Tea v2 / Lip Gloss v2 / Bubbles v2 / Glamour v2).
  Strictly the v2 line: no `harmonica`, no `huh`; animations are hand-rolled.
- **Read-only by design** — it never writes to the vault. The only decryption
  it performs is the on-demand reveal (`r`), audited exactly like `tvault get`.
- **Invariant:** every rendered `View().Content` must be exactly the terminal
  `width × height` cells, or Bubble Tea's cell-diff renderer corrupts the
  screen. `layout_test.go` enforces this across all modes — keep it passing.
- Reveal-map values are wiped on `esc`, pane change, lock, reload, and quit,
  and a late (epoch-stale) reveal is dropped so it can't resurrect a value.
- **Verify TUI changes in a real PTY** with glyphrun (the `glyph` CLI, at
  `~/projects/glyphrun`): `glyph run specs/glyphrun/browse_reveal.yml --format md`.

## Committing

Branch off `main` for changes; ensure all four CI checks pass locally before
pushing. Keep `AGENTS.md`, `SPEC.md`, `README.md`, and `tvault help` /
`tvault docs` in sync when behavior changes — they cross-reference each other.
