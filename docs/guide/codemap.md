---
title: Codemap integration
description: How TinyVault's value-free MCP surface plugs into codemap — a local code-graph indexer — so a code index can answer "where is this secret used?", "what's its blast radius?", and "is it fresh?" without ever ingesting a secret value.
---

# Codemap integration

[codemap](https://github.com/abdul-hamid-achik/tinyvault) is a local code-graph indexer: it learns *where* in your code a secret is referenced. TinyVault knows *which* secrets exist and their lineage. The integration connects the two so a code index can answer rotation, blast-radius, and freshness questions without a secret value ever crossing the seam.

The contract is strict: **only key names, metadata, audit rows, and recipient strings leave the vault.** codemap never ingests a secret value. Every integration below is backed by an existing MCP tool — no functional code was added to TinyVault, only tests pinning the contract.

:::: info This page is about the agent integration, not a CLI command
There is no `tvault codemap` command. The surface is the MCP server (`tvault mcp`); codemap is an MCP host that calls these tools. Discover it programmatically with `tvault docs codemap`.
::::

## Prerequisites

- TinyVault exposed as an MCP server (`tvault mcp`), with an [access policy](/mcp/access-policy) that grants the caller the read tools (and `full` access for the `run`-based integration).
- codemap configured to use TinyVault as an MCP server.

## The five integrations

### A. Rotation blast radius

*Question: "If I rotate this project's key, which secrets — and therefore which code paths — are affected?"*

codemap derives the set of secret keys reachable from a code symbol (by name or prefix), then asks TinyVault for their metadata. Two tools, both metadata-only:

- `vault_list_secrets_by_prefix` — autocomplete-style listing for a prefix, e.g. `STRIPE_`.
- `vault_search_secrets` — relational search (`name_like`, `since`, `until`, `min_version`, `limit`).

Neither returns a value. The result is a set of key names; codemap maps those back to the call sites it already indexed.

```text
# codemap effectively runs:
#   vault_list_secrets_by_prefix(project="payments", prefix="STRIPE_")
#   vault_search_secrets(project="payments", name_like="STRIPE_*")
# → ["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", ...]   (names only)
```

### B. Private-registry LSP credentials

*Question: "An LSP / indexer needs to fetch from a private registry. How do I hand it the credentials without leaking them into the index or the model context?"*

`vault_run_with_secrets` runs codemap's indexing command in a subprocess with only the requested secrets injected as environment variables. The `secrets[]` argument is an **allowlist** — codemap's process sees exactly those keys and nothing else. The values live only in the child's environment; the MCP response carries only the (redacted) `stdout`/`stderr` and exit code.

This is the same tool used to run any command with secrets; here it scopes the index to exactly the keys the private-registry fetch needs.

```text
# vault_run_with_secrets(project="infra", command="codemap index --registry private",
#                        secrets=["NPM_TOKEN","GH_PACKAGE_TOKEN"])
# → { exit_code: 0, stdout: "...", stderr: "..." }   (values redacted)
```

:::: warning Redaction is a guardrail, not a boundary
`redact_output` only replaces literal secret values longer than 3 characters in `stdout`/`stderr`. A command that transforms a value defeats it. The real control is the `secrets[]` allowlist plus `secrets_deny` in policy. See [MCP tools reference](/mcp/tools#vault-run-with-secrets).
::::

### C. Environment-variable audit

*Question: "Which projects and keys are actually in use as env vars across this monorepo, and which are dead?"*

codemap collects the set of environment-variable names referenced in the code; TinyVault reports which of those exist across **all** accessible projects in one call. The tool is `vault_list_secrets_global` — cross-project key discovery by metadata (`prefix`, `name_like`, `since`, `until`, `min_version`, `limit`). The intersection is "env vars the code references that have a backing secret"; the remainder is either dead config or missing secrets.

No values, and no per-project enumeration needed — one global query.

### D. Credential freshness

*Question: "Is this credential stale? When was it last rotated, and has anyone read or changed it recently?"*

Two tools compose:

- `vault_secret_history` — version metadata for a key (version numbers and timestamps; never a value).
- `vault_audit_log_since` — filtered audit rows since a timestamp, by action or resource type.

Together they answer "how many versions does this key have, when was the latest, and what has touched it lately." Both return metadata only. This is how codemap flags a credential that hasn't rotated in N days, or one whose last change predates a known incident.

### E. Least-privilege seal scope

*Question: "I need to ship a sealed bundle for CI / a teammate. How do I include only the keys this slice of the codebase actually needs — and fail loudly if I typo one?"*

Three sealing tools all take a `keys[]` filter and **error on a missing key** (a typo fails rather than silently sealing a subset):

- `vault_seal_for_recipients` — explicit recipient list, v2 ciphertext.
- `vault_export_env` — writes a `0600` dotenv/json/shell file; returns the path, not values.
- `vault_export_env_encrypted` — commit-safe v2 `.env.encrypted` sealed to the project's current recipients.

codemap derives the required key set from the call graph for the slice being shipped, then seals exactly that set. The result is the smallest合法 blob — least privilege by construction.

```text
# vault_seal_for_recipients(project="payments",
#   recipients=["tvault1ci…"],
#   keys=["STRIPE_SECRET_KEY","STRIPE_WEBHOOK_SECRET"])
# → ciphertext (or { path }) — never plaintext
```

## Policy gating

The integrations sit behind the same [access policy](/mcp/access-policy) as every other tool:

| Integration | Tools | Gate |
| --- | --- | --- |
| A. Blast radius | `vault_list_secrets_by_prefix`, `vault_search_secrets` | any `access_mode`; project + secret globs. |
| B. Registry creds | `vault_run_with_secrets` | **`CanExec`** — `access_mode: full` **and** `allow_exec: true`. |
| C. Env-var audit | `vault_list_secrets_global` | any `access_mode`; project + secret globs. |
| D. Freshness | `vault_secret_history`, `vault_audit_log_since` | any `access_mode`; project + secret globs. |
| E. Least-privilege seal | `vault_seal_for_recipients`, `vault_export_env`, `vault_export_env_encrypted` | any `access_mode` (seal/export read secrets + write a file); project + secret globs. |

If the policy denies a project or key, the tool reports it as inaccessible rather than leaking metadata. `vault_status` lets the caller discover its own access without escalating.

## Discoverability

Agents learn the surface once at session start:

```bash
tvault docs features      # JSON manifest of every feature, incl. codemap-integration
tvault docs codemap       # the codemap topic (this page, machine-readable)
tvault docs mcp           # the MCP server topic
```

The `codemap-integration` feature in the manifest lists the backing commands and points here; the `codemap` topic is the short-form version an agent reads in-context.

## See also

- [MCP tools reference](/mcp/tools) — full per-tool inputs, returns, and policy gates for every tool above.
- [Access policy](/mcp/access-policy) — the `mcp-policy.yaml` fields that gate each integration.
- [For AI agents](/guide/for-ai-agents) — the value-free design principle codemap relies on.
- [Environment groups](/guide/env-groups) — a related value-free surface (drift, promote, seal across envs).