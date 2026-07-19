---
title: Changelog
description: Release history for TinyVault (tvault) — what changed in each version.
---

# Changelog

Release history for TinyVault. Full notes and binaries are on the
[GitHub releases](https://github.com/abdul-hamid-achik/tinyvault/releases) page;
the canonical source is [`CHANGELOG.md`](https://github.com/abdul-hamid-achik/tinyvault/blob/main/CHANGELOG.md) in the repo.

Install or upgrade:

```bash
brew upgrade --cask tvault   # Homebrew
go install github.com/abdul-hamid-achik/tinyvault/cmd/tvault@latest
```

If `tvault` was installed from the retired formula, migrate once with
`brew uninstall --formula tvault`, then run
`brew install --cask abdul-hamid-achik/tap/tvault`.

## Unreleased

## 0.18.2 — 2026-07-19

- Windows builds work again: the non-Unix agent client now includes the
  project-scoped status probe and continues to fail closed with
  `ErrUnsupportedPlatform`.
- CI compiles all six Linux, macOS, and Windows targets that GoReleaser ships,
  so platform-only API drift is caught before tagging.

## 0.18.1 — 2026-07-19

- `tvault status --json` adds `agent_accessible`, separating “the local socket
  exists” from “this process can use it for the selected project with its
  current token.”
- `locked` now stays true when a token-required agent is running but the token
  is absent, invalid, or scoped to another project. The check remains
  lock-free and never reads a secret.
- The release workflow is pinned to GoReleaser v2.17.0.

## 0.18.0 — 2026-07-16

- The MCP initialize handshake now reports the real build version instead of a
  hand-edited literal that had shipped stale in at least two prior releases.
- README's MCP tools table covers all 49 tools, anchored to the canonical
  [tools reference](/mcp/tools).
- CI and release workflows pin GitHub Actions to verified commit SHAs (the
  release workflow produces the checksums `tvault self-update` trusts).
- Changelog sections backfilled for v0.11.1 through v0.15.0, with retro-bundled
  0.16.0 bullets moved to the releases that actually shipped them.

## 0.17.2 — 2026-07-13

**Fixed**

- CLI secret-source flags now fail closed before reading a dotenv file,
  contacting the agent, opening the vault, or launching a child process.
  Ambiguous `get` modes, incomplete `--group`/`--env` pairs, group selection
  with `run --no-vault`, and group selection mixed with identity mode are
  rejected explicitly.
- Homebrew install and upgrade examples select the maintained cask explicitly.
- The MCP handshake now reports version 0.17.2.

## 0.17.1 — 2026-07-13

**Fixed**

- `get --group ... --env ...` bypasses the direct-project agent fast path and
  resolves the requested environment through the unlocked vault, preventing a
  value from the current project from being returned for a grouped lookup.

## 0.17.0 — 2026-07-11

**Security**

- The production MCP server now fails closed without an explicit access
  policy: project/status metadata remains available, while secret reads,
  writes, and command execution are denied.
- MCP secret allowlists and per-session value-read limits are enforced.
- CLI- and MCP-launched child processes no longer inherit TinyVault control
  credentials (`TVAULT_PASSPHRASE`, `TVAULT_IDENTITY_KEY`, or
  `TVAULT_AGENT_TOKEN`).

**Maintenance**

- CI is pinned to Go 1.26.5 and Goldmark is upgraded to 1.7.17.

## 0.16.0 — 2026-07-07

**Added**

- **Lock-free, value-free enumeration + a deterministic "vault locked" signal** — lets a non-interactive agent enumerate and probe the vault without a passphrase and without ever seeing sensitive free text: `tvault projects list --json --names-only` and `tvault list -p PROJECT --json --names-only` work on a locked vault; `tvault status --json` adds `locked` and `agent_running`; and unlock-requiring commands run non-interactively fail fast with exit code `3` and `{"error":"vault_locked","locked":true}` under `--json` instead of prompting.

**Changed**

- Homebrew distribution migrated from the retired formula to a cask, and raw versionless binaries are published for direct download.

## 0.15.0 — 2026-06-26

**Added**

- **Environment groups in studio** — env-name annotations (`·production`, `·preview`) for grouped projects, `g` cycles between environments in a group, inherited (`←`) and pinned (`◈`) markers with inheritance-aware reveal/copy, `D` opens a key-set drift overlay across environments (no decryption needed), and `G` opens a groups list overlay. All read-only (work without `--rw`) and metadata-only (work when locked). See [Studio](/guide/studio).

## 0.14.0 — 2026-06-25

**Added**

- **Environment groups / profiles** — link projects as named environments (production, preview, staging) of the same application. Pure metadata; each environment keeps its own DEK. See [Environment groups](/guide/env-groups).
  - `tvault env group create/list/show/add/remove/delete` for group membership.
  - `tvault env diff` — key-set (and optional value) drift across environments.
  - `tvault env promote` — copy a value between environments, versioned and audited (`secret.promote`).
  - `tvault env inherit` / `pin` / `unpin` / `inherited` — metadata-only read-time key inheritance from a base, with per-key pinning.
  - `tvault env seal` — pack every environment into one recipient-sealed v2 blob (decrypt in CI with `decrypt-env --section <env>`).
  - Group/environment resolution (`--group`/`--env`) on the `get`, `run`, and `env` commands.
  - 13 new MCP tools (`vault_env_group_*`, `vault_env_diff`, `vault_env_promote`, `vault_env_inherit`, `vault_env_inherited`, `vault_env_pin`, `vault_env_unpin`, `vault_env_seal`) — all metadata- or ciphertext-only. Tool count: 36 → 49. See [MCP tools reference](/mcp/tools).

## 0.13.1 — 2026-06-25

- **Changed:** documentation housekeeping for the codemap integration — recorded the shipped integration-plan slices and the least-privilege required-keys seal scope; removed the superseded FEATURE.md in favor of SPEC.md.

## 0.13.0 — 2026-06-24

**Added**

- **Codemap integration** — a documented, metadata-first MCP surface for codemap (a local code-graph indexer): rotation blast radius, private-registry LSP creds, env-var audit, credential freshness, and least-privilege seal scope. Most results are metadata, paths, or ciphertext; the private-registry recipe deliberately injects selected credentials into the launched indexer process. See [Codemap integration](/guide/codemap).

**Fixed**

- Portable run-with-secrets shell tests (POSIX `printenv` per key, fixing macOS flakiness).

## 0.12.0 — 2026-06-21

**Added**

- **`tvault self-update`** (alias `upgrade`) — checksum-verified in-place binary update from the official GitHub releases. `--check` reports availability without installing; `--version vX.Y.Z` pins/downgrades. Replaces the removed `install.sh`. See [CLI reference](/cli/).
- `tvault run --only` / `--prefix` — least-privilege secret injection: expose only the named or prefixed keys to the child process.
- `pulumi-config` env export format plus a Pulumi/IaC guide.
- Server install script and a DigitalOcean/SSH server-secrets guide.

**Fixed**

- `tvault mcp` now coexists with the CLI: the server reopens the vault per request instead of holding bbolt's exclusive lock for its lifetime, so `tvault set/get/run/import` keep working while the MCP server runs.

## 0.11.1 — 2026-06-20

- **Added:** documentation site pages — "For AI Agents" (with `llms.txt`), Troubleshooting & FAQ, this Changelog page, and [MCP Recipes](/mcp/recipes); plus the repo's CHANGELOG.md through v0.11.0.
- **Fixed:** agent-facing manifest drift and the homepage tool count.

## 0.11.0 — 2026-06-20

**Added**

- **15 new MCP tools** (21 → 36), all metadata- or ciphertext-only. `vault_get_secret` remains the dedicated plaintext-read tool; separately, command execution can relay child-process output:
  - *Navigation & discovery:* `vault_get_current_project`, `vault_set_current_project`, `vault_count_secrets`, `vault_search_projects`, `vault_projects_overview`, `vault_list_secrets_detailed`, `vault_list_secrets_global`.
  - *Sharing:* `vault_share_project`, `vault_unshare_project`, `vault_project_recipients`.
  - *.env:* `vault_diff_env`, `vault_sync_env`, `vault_export_env_encrypted`.
  - *Identities:* `vault_identity_new`, `vault_identity_list` — public recipient only; the private key is never returned.
- This documentation site (built with VitePress, deployed at [tinyvault.dev](https://tinyvault.dev)).

**Changed**

- The MCP command is now **`tvault mcp`** (was `mcp-server`, kept as an alias) and is no longer hidden.
- Upgraded the MCP SDK to `modelcontextprotocol/go-sdk` v1.6.1.

**CI/maintenance**

- GitHub Actions bumped to Node 24 runtimes; `golangci-lint`/`govulncheck` pinned; the Security Scan now fails on a called vulnerability.

See the new [MCP Recipes](/mcp/recipes) for end-to-end agent workflows using these tools.

## 0.10.1 — 2026-06-15

- **Fixed:** studio `--rw` edit input sizing (placeholder/value render).

## 0.10.0 — 2026-06-15

- **Changed:** the `browse` command is now **`studio`** (`browse`/`ui` kept as aliases).
- **Added:** broad end-to-end PTY test coverage for every CLI command and studio interaction.

## 0.9.0 — 2026-06-14

- **Added:** X25519 recipient layer + `tvault identity`; project sharing with key rotation on live-vault recipient removal (retained snapshots and artifacts remain readable); `.env.encrypted` v2 (commit-safe); `tvault git-filter`; `tvault seal`/`open`; per-context identity transport (`TVAULT_IDENTITY_KEY`); Kubernetes commit-safe SealedSecrets; versioned secrets + rollback; the local `tvault agent` + shell hooks; `vault_seal_for_recipients`; `tvault diff`; `tvault doctor`; studio `--rw` mode.

## Earlier

See the [GitHub releases](https://github.com/abdul-hamid-achik/tinyvault/releases) for v0.8.0 and earlier.
