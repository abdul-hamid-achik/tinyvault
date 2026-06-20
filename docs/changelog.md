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
brew upgrade tvault          # Homebrew
go install github.com/abdul-hamid-achik/tinyvault/cmd/tvault@latest
```

## 0.11.0 — 2026-06-20

**Added**

- **15 new MCP tools** (21 → 36), all metadata- or ciphertext-only — none return a raw secret value (only `vault_get_secret` does):
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

- **Added:** X25519 recipient layer + `tvault identity`; project sharing with key-rotating revocation; `.env.encrypted` v2 (commit-safe); `tvault git-filter`; `tvault seal`/`open`; per-context identity transport (`TVAULT_IDENTITY_KEY`); Kubernetes commit-safe SealedSecrets; versioned secrets + rollback; the local `tvault agent` + shell hooks; `vault_seal_for_recipients`; `tvault diff`; `tvault doctor`; studio `--rw` mode.

## Earlier

See the [GitHub releases](https://github.com/abdul-hamid-achik/tinyvault/releases) for v0.8.0 and earlier.
