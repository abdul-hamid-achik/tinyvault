# Changelog

All notable changes to TinyVault are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0] - 2026-06-20

### Added

- **15 new MCP tools** (21 → 36), all metadata- or ciphertext-only — none
  return a raw secret value (only the pre-existing `vault_get_secret` does):
  - **Navigation & discovery:** `vault_get_current_project`,
    `vault_set_current_project`, `vault_count_secrets`, `vault_search_projects`,
    `vault_projects_overview`, `vault_list_secrets_detailed`,
    `vault_list_secrets_global`.
  - **Sharing:** `vault_share_project`, `vault_unshare_project`,
    `vault_project_recipients`.
  - **.env:** `vault_diff_env`, `vault_sync_env`, `vault_export_env_encrypted`.
  - **Identities:** `vault_identity_new`, `vault_identity_list` — return the
    public recipient (`tvault1…`) only; the private key is never returned.
- `internal/identity` package — the single source of truth for the X25519
  identity key-file layout, shared by the CLI and the MCP server.
- A [VitePress](https://vitepress.dev) documentation site under `docs/`,
  deployed to **[tinyvault.dev](https://tinyvault.dev)** (Bun + Vercel,
  auto-deploys on push to `main`).

### Changed

- Renamed the `mcp-server` command to **`mcp`** and made it visible (no longer
  hidden). `mcp-server` remains a backward-compatible alias, so existing MCP
  host configs keep working.
- Upgraded the MCP SDK `github.com/modelcontextprotocol/go-sdk` to **v1.6.1**.

### CI

- Bumped GitHub Actions to Node 24 runtimes (`checkout` v5, `setup-go` v6,
  `golangci-lint-action` v9, `codecov-action` v5, `goreleaser-action` v7),
  clearing the Node 20 deprecation warnings.
- Pinned `golangci-lint` (v2.12.2) and `govulncheck` (v1.4.0) for reproducible
  runs; the **Security Scan** job now fails on a called vulnerability (was
  advisory); added `concurrency` cancel-in-progress.

## [0.10.1] - 2026-06-15

### Fixed

- Studio `--rw` edit input is sized so its placeholder and value render
  correctly.

## [0.10.0] - 2026-06-15

### Changed

- Renamed the `browse` command to **`studio`** (`browse`/`ui` kept as aliases).

### Added

- Extensive [glyphrun](https://github.com/abdul-hamid-achik/tinyvault) e2e PTY
  specs covering every CLI command and studio interaction; raised Go unit-test
  coverage across `cmd`, `mcp`, and `vault`.

## [0.9.0] - 2026-06-14

### Added

- **X25519 recipient layer** + `tvault identity` — the foundation for sharing
  and committable secrets.
- **Project sharing** to X25519 recipients with key-rotating revocation
  (`projects share`/`unshare`/`recipients`).
- **`.env.encrypted` v2** — commit-safe, recipient-based, KEK-independent.
- **`tvault git-filter`** — transparent encrypt-on-commit / decrypt-on-checkout.
- **`tvault seal`/`open`** with round-trip-safe dotenv rendering.
- **Per-context identity transport** (`TVAULT_IDENTITY_KEY`) for CI/ssh/agents.
- **Kubernetes commit-safe Secrets** (SealedSecret pattern, no controller).
- **Versioned secrets + rollback** (history-preserving store + CLI/MCP).
- **Local `tvault agent`** + shell hooks — unlock once for prompt-free daily
  use (unix), with a `--require-token` privilege-separation gate.
- `vault_seal_for_recipients` (MCP), `tvault diff`, `tvault doctor`, a typed
  `~/.tvault/config.yaml`, meaningful CLI exit codes, CLI/TUI audit logging,
  and studio `--rw` (audited in-app new/edit/delete).

## Earlier releases

See the [GitHub releases](https://github.com/abdul-hamid-achik/tinyvault/releases)
for v0.8.0 and earlier.

[Unreleased]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.8.0...v0.9.0
