---
title: MCP Tools Reference
description: Complete reference for all 36 TinyVault MCP tools, 3 resources, and 2 prompts — their inputs, what they return, and the policy gate each sits behind.
---

# MCP Tools Reference

This is the full reference for the TinyVault MCP surface: **36 tools, 3 resources, and 2 prompts**, served over stdio by the `tvault mcp` subcommand (the older `mcp-server` name still works as an alias) and built on the [modelcontextprotocol go-sdk](https://github.com/modelcontextprotocol/go-sdk). For setup — wiring `tvault` into Claude Code and other clients — see the [MCP overview](/mcp/). For the policy file that gates these tools, see [Access Policy](/mcp/access-policy).

The single most important fact: **only `vault_get_secret` returns a raw plaintext value.** Every other tool returns metadata, a path, a count, or ciphertext. That is the whole design — agents should *use* secrets without ever pulling them into the model's context.

## Tool summary

| Tool | Returns value? | Purpose |
| --- | :---: | --- |
| `vault_list_projects` | No | List projects with descriptions and secret counts. |
| `vault_create_project` | No | Create a new project. |
| `vault_delete_project` | No | Delete a project (irreversible). |
| `vault_list_secrets` | No | List key names and metadata in a project. |
| `vault_get_secret` | **Yes** | Decrypt and return one secret value (warns). |
| `vault_set_secret` | No | Store or update a secret (archives prior version). |
| `vault_delete_secret` | No | Delete a secret and purge its history. |
| `vault_search_secrets` | No | Relational search over key metadata. |
| `vault_list_secrets_by_prefix` | No | Autocomplete-style key listing. |
| `vault_generate_secret` | No | Generate and store a random secret; value not returned. |
| `vault_run_with_secrets` | No | Run a subprocess with secrets injected as env. |
| `vault_export_env` | No | Write secrets to a `0600` file (dotenv/json/shell). |
| `vault_list_env_files` | No | Discover `.env` files on disk. |
| `vault_preview_env_import` | No | Preview a `.env` import (counts only). |
| `vault_import_env_files` | No | Import `.env` files into a project. |
| `vault_status` | No | Lock state, project count, vault id, creation time. |
| `vault_audit_log` | No | Recent audit entries. |
| `vault_audit_log_since` | No | Filtered audit entries. |
| `vault_seal_for_recipients` | No | Produce commit-safe ciphertext for recipients. |
| `vault_secret_history` | No | Version metadata for a key. |
| `vault_rollback_secret` | No | Restore an old version as a new one. |
| `vault_get_current_project` | No | Report the current/default project. |
| `vault_set_current_project` | No | Switch the current/default project. |
| `vault_count_secrets` | No | Count the secrets in a project (no keys/values). |
| `vault_search_projects` | No | Find projects by name/description glob. |
| `vault_projects_overview` | No | Every accessible project with counts and timestamps. |
| `vault_list_secrets_detailed` | No | List keys with real version + timestamps. |
| `vault_list_secrets_global` | No | Cross-project secret discovery by metadata. |
| `vault_share_project` | No | Grant a recipient read access (wraps the DEK). |
| `vault_unshare_project` | No | Revoke a recipient (rotates the DEK, re-encrypts). |
| `vault_project_recipients` | No | List the recipients a project is shared with. |
| `vault_diff_env` | No | Drift between a `.env` file and the project. |
| `vault_sync_env` | No | Reconcile a `.env` with the project (pull/push/mirror). |
| `vault_export_env_encrypted` | No | Write a commit-safe `.env.encrypted` (v2) for current recipients. |
| `vault_identity_new` | No | Create an X25519 identity; returns the public recipient only. |
| `vault_identity_list` | No | List local identities and their public recipients. |

::: tip The recommended agent pattern
Discover the surface once with `tvault docs features`. Then use the relational tools — `vault_search_secrets` and `vault_list_secrets_by_prefix` — to find keys *without* enumerating values, and use `vault_run_with_secrets` when you actually need to *use* a value. That keeps secrets out of the model context, which is exactly what `vault_get_secret` cannot guarantee.
:::

## How the policy gate works

Every tool is checked against the [access policy](/mcp/access-policy) at `~/.tvault/mcp-policy.yaml` before it runs. The gates referenced below are:

- **`access_mode`** — `read-only`, `read-write`, or `full`. Reads and audit are always allowed; `read-write` adds writes; `full` additionally permits `vault_run_with_secrets`.
- **`CanWrite`** — `access_mode` is `read-write` or `full`.
- **`CanExec`** — `allow_exec` **and** `access_mode == full`. Both must be true for `vault_run_with_secrets`.
- **Project / secret globs** — `projects_allow`/`projects_deny` and `secrets_allow`/`secrets_deny` filter what a tool can see or touch. Deny is checked before allow.

If `~/.tvault/mcp-policy.yaml` is absent, the server runs a permissive default (`access_mode: full`, all globs `*`, `allow_exec: true`, `redact_output: true`). The model cannot edit the policy at runtime — it is loaded from disk at server start. The model can call `vault_status` to discover its own access, but it cannot escalate.

---

## Projects

### `vault_list_projects`

Lists the projects the policy lets the caller see.

- **Inputs:** none.
- **Returns:** project names, descriptions, and secret counts (filtered by `projects_allow`/`projects_deny`).
- **Policy gate:** any `access_mode`; project globs applied.

### `vault_create_project`

Creates a new project.

- **Inputs:** `name` (required), `description` (optional).
- **Returns:** confirmation metadata — no secret values.
- **Policy gate:** `CanWrite` (`read-write` or `full`); must pass project globs.

### `vault_delete_project`

Deletes a project and everything in it.

- **Inputs:** `name` (required).
- **Returns:** confirmation metadata.
- **Policy gate:** `CanWrite`; project globs.

::: danger Irreversible
`vault_delete_project` permanently removes the project and all of its secrets and history. There is no undo.
:::

---

## Secrets: read

### `vault_list_secrets`

Lists the keys in a project — names and metadata only, never values.

- **Inputs:** `project` (optional; falls back to the configured default project).
- **Returns:** key names plus metadata (version, timestamps) for keys allowed by `secrets_allow`/`secrets_deny`.
- **Policy gate:** any `access_mode`; project and per-key secret globs applied.

### `vault_get_secret`

The one tool that returns cleartext. Reach for it last.

- **Inputs:** `project` (optional), `key` (required).
- **Returns:** `{ key, value, warning }`. The `warning` reminds the caller that the value is now in the model's context.
- **Policy gate:** any `access_mode`; project and secret globs applied (the requested key must pass `secrets_allow`/`secrets_deny`).

::: warning Prefer using the value over reading it
Once `vault_get_secret` returns, the plaintext is in the model context — it can be logged, echoed, or sent onward. When the goal is to *run something* with the secret, use [`vault_run_with_secrets`](#vault-run-with-secrets) instead; when the goal is to *hand it to a teammate or CI*, use [`vault_seal_for_recipients`](#vault-seal-for-recipients). Lock this tool down in [policy](/mcp/access-policy) with `secrets_deny` for sensitive keys.
:::

---

## Secrets: write

### `vault_set_secret`

Stores or updates a secret, encrypted at rest. Overwriting archives the prior value into version history first.

- **Inputs:** `project` (optional), `key` (required), `value` (required).
- **Returns:** confirmation metadata (new version number) — not the value.
- **Policy gate:** `CanWrite`; project and secret globs.

### `vault_delete_secret`

Removes a key and **purges its version history**.

- **Inputs:** `project` (optional), `key` (required).
- **Returns:** confirmation metadata.
- **Policy gate:** `CanWrite`; project and secret globs.

### `vault_generate_secret`

Generates a cryptographically random secret and stores it directly — the value is **never returned**.

- **Inputs:** `project` (optional), `key` (required), `length` (optional, default `32`, max `256`), `charset` (optional: `alphanumeric` | `hex` | `base64` | `ascii`).
- **Returns:** `{ stored: true }`. The generated value stays in the vault.
- **Policy gate:** `CanWrite`; project and secret globs.

::: info Generation is MCP-only
There is no `tvault generate` CLI command. Random secret generation exists only over MCP, via this tool. To use a generated value afterward, run it with `vault_run_with_secrets` or export it with `vault_export_env`.
:::

---

## Search & discovery

These tools let an agent find the right key without ever reading values — the preferred way to navigate a vault.

### `vault_search_secrets`

Relational, multi-filter search over secret metadata.

- **Inputs:** `project` (optional), `prefix` (optional), `name_like` (optional), `since` (optional), `until` (optional), `min_version` (optional), `limit` (optional, default `1000`).
- **Returns:** matching key names and metadata only — no values.
- **Policy gate:** any `access_mode`; project and per-key secret globs.

### `vault_list_secrets_by_prefix`

Fast, autocomplete-style listing for a key prefix.

- **Inputs:** `project` (optional), `prefix` (required), `limit` (optional, default `200`).
- **Returns:** key names matching the prefix — metadata only.
- **Policy gate:** any `access_mode`; project and secret globs.

---

## Navigation & discovery

These tools help an agent orient itself across the vault — which project is active, what projects exist, and richer key metadata — without ever reading a value.

### `vault_get_current_project`

Reports the current (default) project the server is operating on.

- **Inputs:** none.
- **Returns:** the current project name. No values.
- **Policy gate:** any `access_mode`.

### `vault_set_current_project`

Switches the current (default) project for subsequent calls.

- **Inputs:** `name` (required).
- **Returns:** confirmation metadata — the newly selected project. No values.
- **Policy gate:** `CanWrite` (`read-write` or `full`); project globs.

### `vault_count_secrets`

Counts the secrets in a project without enumerating keys or values.

- **Inputs:** `project` (optional).
- **Returns:** a count only — no key names, no values.
- **Policy gate:** any `access_mode`; project globs.

### `vault_search_projects`

Finds projects by a glob (`*`) over name and/or description.

- **Inputs:** `name_like` (optional), `description_like` (optional), `limit` (optional).
- **Returns:** matching project names, descriptions, and secret counts (filtered by project globs). No values.
- **Policy gate:** any `access_mode`; project globs.

### `vault_projects_overview`

Lists every accessible project with its description, secret count, and timestamps in one call.

- **Inputs:** none.
- **Returns:** for each project, `description`, `secret_count`, `created_at`, and `updated_at` (filtered by project globs). No values.
- **Policy gate:** any `access_mode`; project globs.

### `vault_list_secrets_detailed`

Lists keys with their **real** version number and created/updated timestamps. Use this instead of `vault_list_secrets`, which reports version `1` for every key.

- **Inputs:** `project` (optional).
- **Returns:** key names with accurate version and timestamp metadata. Never values.
- **Policy gate:** any `access_mode`; project and per-key secret globs.

### `vault_list_secrets_global`

Cross-project secret discovery: search key metadata across every accessible project at once.

- **Inputs:** `prefix` (optional), `name_like` (optional), `since` (optional), `until` (optional), `min_version` (optional), `limit` (optional).
- **Returns:** matching keys (with their project) and metadata only — no values.
- **Policy gate:** any `access_mode`; project and per-key secret globs.

---

## Run & export

### `vault_run_with_secrets`

Runs a command in a subprocess with the requested secrets injected as environment variables. The values are decrypted only inside the child process, so they never enter the model context.

- **Inputs:** `project` (optional), `command` (required), `secrets` (optional list; the keys to inject), `timeout_seconds` (optional, default `300`).
- **Returns:** `{ exit_code, stdout, stderr }`, with secret values redacted from the output when `redact_output` is on.
- **Policy gate:** **`CanExec`** — requires `access_mode: full` **and** `allow_exec: true`; project and secret globs.

```bash
# What the agent effectively orchestrates: secrets land in the child env,
# the migration runs, and only the redacted exit/stdout/stderr come back.
# vault_run_with_secrets(project="api", command="npm run migrate",
#                        secrets=["DATABASE_URL"])
```

::: warning Redaction is a safety net, not a control
`redact_output` only replaces literal secret values **longer than 3 characters** in `stdout`/`stderr` with `[REDACTED:KEY]`. A command that transforms a value — base64-encodes it, reverses it, prints one character per line — defeats it. Treat redaction as a guardrail against accidental leakage, never as a security boundary. The real controls are `secrets_deny` and `access_mode`.
:::

### `vault_export_env`

Writes selected secrets to a file on disk with `0600` permissions. The values go to the file, not to the model.

- **Inputs:** `project` (optional), `format` (optional: `dotenv` | `json` | `shell`), `output_path` (optional), `keys` (optional list).
- **Returns:** `{ path, count, keys }` — the file path, how many were written, and which key names. No values.
- **Policy gate:** any `access_mode` (it reads and writes to disk); project and per-key secret globs determine which keys are exported.

::: warning Exported files are plaintext on disk
The file `vault_export_env` writes contains real secret values in plaintext. It is `0600` (owner-only), but it is not encrypted. Delete it when done and never commit it. To produce something commit-safe, use `vault_seal_for_recipients` instead.
:::

---

## .env import

A three-step, value-safe import flow: discover, preview, then import. None of these tools return secret values.

### `vault_list_env_files`

Discovers `.env`-style files on disk.

- **Inputs:** `directory` (optional), `environment` (optional).
- **Returns:** the file paths found — no values are read.
- **Policy gate:** any `access_mode`.

### `vault_preview_env_import`

Dry-runs an import so the agent can see what would happen before committing.

- **Inputs:** `project` (optional), `directory` (optional), `files` (optional), `environment` (optional), `overwrite` (optional).
- **Returns:** counts of keys that would be created, overwritten, or skipped. No values.
- **Policy gate:** `CanWrite` (it previews a write); project globs.

### `vault_import_env_files`

Imports the `.env` values into the vault without exposing them in the response.

- **Inputs:** `project` (optional), `directory` (optional), `files` (optional), `environment` (optional), `overwrite` (optional).
- **Returns:** counts of what was created, overwritten, or skipped. No values.
- **Policy gate:** `CanWrite`; project and per-key secret globs.

---

## Audit & status

### `vault_status`

Reports the server's view of the vault — also how an agent discovers its own access without escalating.

- **Inputs:** none.
- **Returns:** lock state, project count, vault id, and creation time.
- **Policy gate:** any `access_mode`.

### `vault_audit_log`

Returns the most recent audit entries.

- **Inputs:** `limit` (optional, default `20`, max `100`).
- **Returns:** recent audit entries (action, resource, timestamp). No secret values.
- **Policy gate:** any `access_mode`.

### `vault_audit_log_since`

Filtered audit query for narrowing by time, action, or resource type.

- **Inputs:** `since` (optional), `until` (optional), `action` (optional), `resource_type` (optional), `limit` (optional, default `100`, max `1000`).
- **Returns:** matching audit entries — no values.
- **Policy gate:** any `access_mode`.

::: info Auditing has no CLI subcommand
There is no `tvault audit` command. The audit trail is internal; you read it over MCP with these two tools, or browse it in the [interactive studio](/guide/studio).
:::

---

## Versioning

See the [versioning guide](/guide/versioning) for the full model. Both tools return version numbers only — never a value.

### `vault_secret_history`

Lists the version history for a key.

- **Inputs:** `project` (optional), `key` (required).
- **Returns:** version metadata (version numbers, timestamps). Never a value.
- **Policy gate:** any `access_mode`; project and secret globs.

### `vault_rollback_secret`

Restores a previous version. Rollback is non-destructive: the old value is re-stored as a **new** version, so version numbers stay monotonic and are never reused.

- **Inputs:** `project` (optional), `key` (required), `to_version` (required).
- **Returns:** the version numbers involved (the restored-from version and the new version). No value.
- **Policy gate:** `CanWrite`; project and secret globs.

---

## Sealing

### `vault_seal_for_recipients`

Produces commit-safe ciphertext for one or more X25519 recipients — the agent-facing equivalent of `tvault seal`. The output is a v2 `.env.encrypted` document (or a path to one) that is safe to commit, because only the named recipients can decrypt it.

- **Inputs:** `recipients` (required list of `tvault1…` public keys), `project` (optional), `keys` (optional list), `output_path` (optional).
- **Returns:** the ciphertext (v2 `.env.encrypted`) inline, or `{ path }` when `output_path` is set. Either way, no plaintext.
- **Policy gate:** any `access_mode`; project and per-key secret globs.

```bash
# The agent seals the project for a teammate's public key.
# vault_seal_for_recipients(project="api",
#   recipients=["tvault1exampleRecipient"],
#   output_path=".env.encrypted")
```

::: tip This is the safe way to hand off secrets
Unlike `vault_get_secret` (plaintext into the model) or `vault_export_env` (plaintext onto disk), sealed output is ciphertext. It is the right tool when an agent needs to deliver secrets to a person, a CI runner, or another identity. See [Committable Secrets](/guide/committable-secrets) and [Sharing Secrets](/guide/sharing).
:::

---

## Sharing

These tools manage which X25519 recipients can open a project — the agent-facing equivalent of `tvault projects share` / `unshare` / `recipients`. None of them returns a secret value.

### `vault_share_project`

Grants a recipient read access to a project by wrapping that project's DEK to their public key.

- **Inputs:** `recipient` (required, a `tvault1…` public key), `project` (optional).
- **Returns:** confirmation metadata — the project and the added recipient. No values.
- **Policy gate:** `CanWrite`; project globs.

### `vault_unshare_project`

Revokes a recipient. This is **true revocation**: it rotates the project DEK and re-encrypts every value *and* its version history under the fresh key, re-wrapping only to the remaining recipients.

- **Inputs:** `recipient` (required, a `tvault1…` public key), `project` (optional).
- **Returns:** confirmation metadata. No values.
- **Policy gate:** `CanWrite`; project globs.

::: tip Why a rotation, not just a re-wrap
A removed recipient may have cached the old DEK, so merely dropping their stanza would be security theater. `vault_unshare_project` re-encrypts everything under a new DEK so an old copy of the vault becomes useless to them.
:::

### `vault_project_recipients`

Lists the public recipients a project is currently shared with.

- **Inputs:** `project` (optional).
- **Returns:** the `tvault1…` public recipients of the project — metadata only, no values.
- **Policy gate:** any `access_mode`; project globs.

---

## .env

A trio of tools for working with `.env` files against the vault — comparing drift, reconciling, and writing commit-safe ciphertext. Verdicts and counts only; raw values never appear in a response.

### `vault_diff_env`

Compares a `.env` file on disk against the project and reports the drift.

- **Inputs:** `file` (required), `project` (optional), `compare_values` (optional).
- **Returns:** the key sets `only_in_vault`, `only_in_file`, and `in_both`; with `compare_values`, each shared key also gets a `same` / `differs` verdict. **Never the values themselves.**
- **Policy gate:** any `access_mode` (value comparison audits each read); project and per-key secret globs.

### `vault_sync_env`

Reconciles a `.env` file with the project in one of three directions.

- **Inputs:** `direction` (required: `pull` | `push` | `mirror`), `path` (optional), `project` (optional), `overwrite` (optional).
- **Returns:** counts of what was pulled, pushed, or mirrored. No values.
- **Policy gate:** `pull` reads (any `access_mode`); `push` and `mirror` are writes and require `CanWrite`. Project and per-key secret globs apply.

### `vault_export_env_encrypted`

Writes a commit-safe `.env.encrypted` (v2) sealed to the project's **current** recipients — the asymmetric, KEK-independent format that is safe to commit.

- **Inputs:** `project` (optional), `output_path` (optional), `keys` (optional list).
- **Returns:** `{ path }` (or the ciphertext) — only ciphertext, never plaintext. Errors if the project has no recipients.
- **Policy gate:** any `access_mode`; project and per-key secret globs.

::: tip Seals to current recipients, not an arbitrary key
Unlike `vault_seal_for_recipients` (which takes explicit recipient keys), `vault_export_env_encrypted` seals to whoever the project is already shared with. Share the project first (`vault_share_project`) if the recipient list is empty.
:::

## Identities

These manage the X25519 identity key files used by the recipient layer. They return only the **public** recipient string (`tvault1…`) — never the private key (`tvault-key1…`).

### `vault_identity_new`

Generates a new identity keypair, writes the private key `0600` under the vault's `identities/` directory, and returns the public recipient and the file path.

- **Inputs:** `name` (optional; letters/digits/`-`/`_`, max 64; default `default`). Errors if an identity with that name already exists.
- **Returns:** `{ name, recipient, path }` — the public `tvault1…` recipient and the on-disk path. The private key is **never** returned.
- **Policy gate:** `CanWrite` (it creates a file).

### `vault_identity_list`

Lists local identities and their public recipient strings, so you can pick a recipient to share or seal to.

- **Inputs:** none.
- **Returns:** `{ identities: [{ name, recipient }] }` — public halves only.
- **Policy gate:** read-only.

---

## Resources

The server exposes three read-only MCP resources. All return JSON, contain **metadata only**, and are filtered by the same policy globs as the tools.

| Resource URI | Contents |
| --- | --- |
| `vault://status` | Lock state, project count, vault id, creation time. |
| `vault://projects` | The list of projects (names, descriptions, counts). |
| `vault://projects/{name}/keys` | Key names and metadata for one project. |

::: info No values in resources
Resources are for discovery. None of them ever returns a secret value — to read one you still have to call `vault_get_secret` (and pass the policy gate).
:::

## Prompts

Two MCP prompts give clients ready-made starting points:

- **`setup-project`** — scaffolds a new project. Argument: `name` (required).
- **`inject-secrets`** — guides running a command with injected secrets. Arguments: `project` (optional), `command` (required).

## See also

- [MCP Overview & Setup](/mcp/) — wiring `tvault mcp` into Claude Code and other clients.
- [Access Policy](/mcp/access-policy) — the `mcp-policy.yaml` fields that gate every tool above.
- [Security & Threat Model](/reference/security) — why redaction is a safety net, and what the real controls are.
- [Sharing Secrets](/guide/sharing) — the recipient model behind `vault_seal_for_recipients`.
