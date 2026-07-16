# Changelog

All notable changes to TinyVault are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.18.0] - 2026-07-16

## [0.17.2] - 2026-07-13

### Fixed

- Made CLI secret-source validation fail closed before reading a dotenv file,
  contacting the agent, opening the vault, or launching a child process.
  Ambiguous `get` modes, incomplete `--group`/`--env` pairs, group selection
  with `run --no-vault`, and group selection mixed with identity mode now fail
  with explicit errors.
- Updated Homebrew install and upgrade examples to select the maintained cask
  explicitly instead of the retired formula.
- Updated the MCP handshake implementation version to 0.17.2.

## [0.17.1] - 2026-07-13

### Fixed

- Made `get --group ... --env ...` bypass the direct-project agent fast path
  and resolve the requested environment through the unlocked vault, preventing
  a value from the current project from being returned for a grouped lookup.

## [0.17.0] - 2026-07-11

### Security

- Changed the production MCP server to fail closed when no access policy is
  configured: project/status metadata remains available, while secret reads,
  writes, and command execution require an explicit policy.
- Enforced secret allowlists and per-session value-read limits for MCP access.
- Removed TinyVault control credentials (`TVAULT_PASSPHRASE`,
  `TVAULT_IDENTITY_KEY`, and `TVAULT_AGENT_TOKEN`) from CLI- and MCP-launched
  child-process environments.

### Changed

- Refreshed the security toolchain by pinning CI to Go 1.26.5 and upgrading
  Goldmark to 1.7.17.

## [0.16.0] - 2026-07-07

### Added

- **Lock-free, value-free enumeration + deterministic "vault locked" signal**
  — lets a non-interactive agent (e.g. Cortex) enumerate and probe the vault
  without a passphrase and without ever seeing sensitive free text:
  - `tvault projects list --json --names-only` → `[{"name":"app"}]` (no
    descriptions, no unlock; exit 0 on a locked vault).
  - `tvault list -p PROJECT --json --names-only` → `["DB_URL","API_KEY"]`
    (no unlock).
  - `tvault status --json` adds `locked` and `agent_running` (so a caller
    can distinguish "reachable but locked" from "broken/unreachable").
  - When an unlock-requiring command runs non-interactively (stdin not a
    TTY) with no `TVAULT_PASSPHRASE` and no agent, it fails fast **without
    prompting**: exit code `3`, and under `--json`,
    `{"error":"vault_locked","locked":true}` on stdout with nothing on
    stderr — replacing the opaque "failed to read passphrase" error.

### Changed

- Migrated Homebrew distribution from the retired formula to a cask and
  published raw versionless binaries for direct download (goreleaser v2.8 and
  v2.10 configuration updates).

## [0.15.0] - 2026-06-26

### Added

- **Environment groups in studio** — brought the environment-group surface
  into the interactive TUI: env-name annotations (`·production`, `·preview`)
  for grouped projects, `g` cycles between environments in a group,
  inherited (`←`) and pinned (`◈`) markers with inheritance-aware
  reveal/copy, `D` opens a key-set drift overlay across environments (no
  decryption needed), and `G` opens a groups list overlay. All read-only
  (work without `--rw`) and metadata-only (work when locked).

## [0.14.0] - 2026-06-25

### Added

- **Environment groups / profiles** — link projects as named environments
  (production, preview, staging) of the same application. Pure metadata; each
  environment keeps its own DEK. Adds:
  - `tvault env group create/list/show/add/remove/delete` for group membership.
  - `tvault env diff` — key-set (and optional value) drift across environments.
  - `tvault env promote` — copy a value between environments, versioned and
    audited (`secret.promote`).
  - `tvault env inherit` / `pin` / `unpin` / `inherited` — metadata-only
    read-time key inheritance from a base environment, with per-key pinning.
  - `tvault env seal` — pack all environments into one recipient-sealed v2
    blob (decrypt in CI with `decrypt-env --section <env>`).
  - Group/environment resolution (`--group`/`--env`) on the `get`, `run`, and
    `env` commands, with the group shown in the studio status pane.
  - 13 new MCP tools (`vault_env_group_*`, `vault_env_diff`,
    `vault_env_promote`, `vault_env_inherit`, `vault_env_inherited`,
    `vault_env_pin`, `vault_env_unpin`, `vault_env_seal`) — all metadata- or
    ciphertext-only. Tool count: 36 → 49.

## [0.13.1] - 2026-06-25

### Changed

- Documentation housekeeping for the codemap integration: recorded the shipped
  integration-plan slices (scanner, secret-impact) and the least-privilege
  required-keys seal scope, and removed the superseded FEATURE.md in favor of
  SPEC.md.

## [0.13.0] - 2026-06-24

### Added

- **Codemap integration** — a documented, strictly value-free MCP surface for
  codemap (a local code-graph indexer): rotation blast radius, private-registry
  LSP creds, env-var audit, credential freshness, and least-privilege seal
  scope. Only key names, metadata, audit rows, and recipients cross the seam;
  codemap never ingests a secret value. Adds integration tests verifying the
  value-free, policy-gated, and audit-logged guarantees plus a
  `tvault docs codemap` topic.

### Fixed

- Made the run-with-secrets shell tests portable by using POSIX `printenv`
  per key (macOS flakiness from grep ANSI color codes).

## [0.12.0] - 2026-06-21

### Added

- **`tvault self-update`** (alias `upgrade`) — checksum-verified in-place
  binary update from the official GitHub releases. `--check` reports
  availability without installing; `--version vX.Y.Z` pins/downgrades.
  Replaces the removed `install.sh`.
- `tvault run --only` / `--prefix` — least-privilege secret injection: expose
  only the named or prefixed keys to the child process.
- `pulumi-config` env export format plus a Pulumi/IaC guide.
- Server install script and a DigitalOcean/SSH server-secrets guide.

### Fixed

- Made `tvault mcp` coexist with the CLI: the server reopens the vault per
  request instead of holding bbolt's exclusive lock for its lifetime, so
  `tvault set/get/run/import` keep working while the MCP server runs.

## [0.11.1] - 2026-06-20

### Added

- Documentation site pages: "For AI Agents" (with `llms.txt` and a README
  section), Troubleshooting & FAQ, Changelog, and MCP Recipes (agent
  cookbook); added this CHANGELOG.md through v0.11.0.

### Fixed

- Corrected agent-facing manifest drift and the homepage tool count.

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
- **Local `tvault agent`** + shell hooks — unlock once for prompt-free daily
  use (unix), with a `--require-token` privilege-separation gate.
- `vault_seal_for_recipients` (MCP), `tvault diff`, `tvault doctor`, a typed
  `~/.tvault/config.yaml`, meaningful CLI exit codes, CLI/TUI audit logging,
  and studio `--rw` (audited in-app new/edit/delete).

## Earlier releases

See the [GitHub releases](https://github.com/abdul-hamid-achik/tinyvault/releases)
for v0.8.0 and earlier.

[Unreleased]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.17.2...HEAD
[0.17.2]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.17.1...v0.17.2
[0.17.1]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.13.1...v0.14.0
[0.13.1]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/abdul-hamid-achik/tinyvault/compare/v0.8.0...v0.9.0
