---
title: MCP Recipes
description: Practical end-to-end recipes for AI agents using the TinyVault MCP tools — find and use secrets without reading them, share projects, keep .env files in sync, and ship commit-safe ciphertext.
---

# MCP Recipes

Concrete, copy-the-shape workflows for an agent connected to the TinyVault [MCP server](/mcp/). These recipes minimize raw values in tool results; they are patterns, not a sandbox. Tool details live in the [Tools Reference](/mcp/tools); what's allowed is set by the [Access Policy](/mcp/access-policy).

::: tip Orient first
At the start of a session, call `vault_status` and `vault_get_current_project` to learn the lock state and the default project, and `tvault docs features` (CLI) for the machine-readable catalog. Then work relationally — never enumerate values.
:::

## Use a secret without reading it

The single most important pattern: **find the key, then use it in a subprocess**. The tool does not intentionally return the value to the conversation.

1. Find the key — `vault_search_secrets` (by prefix / name pattern / time) or `vault_list_secrets_by_prefix`. Both return metadata only.
2. Run the command — `vault_run_with_secrets` with `command` and (optionally) `secrets: ["DATABASE_URL", …]`. The values are injected as env vars into the subprocess. Its stdout/stderr are returned; when policy enables `redact_output`, TinyVault first scans them for literal values longer than three characters.

```text
vault_search_secrets   { "prefix": "DATABASE_" }      → ["DATABASE_URL", …] (names only)
vault_run_with_secrets { "command": "npm run migrate", "secrets": ["DATABASE_URL"] }
                       → { exit_code, stdout, stderr }  (command output; optional literal redaction)
```

If you genuinely must see a value, `vault_get_secret` is the one tool that returns it — and it includes a warning that the value is now in context. Prefer the pattern above.

::: warning Redaction is not containment
The child process can transform a value, write it to a file, or send it over the network. When enabled, literal-value redaction reduces accidental stdout/stderr leaks; it cannot make an untrusted command safe.
:::

## Write secrets to disk for a tool that needs a file

Some tools want a real `.env`. `vault_export_env` writes one (`0600`) and returns **only the path** — never the contents.

```text
vault_export_env { "format": "dotenv", "output_path": ".env" } → { path: ".env", count, keys }
```

## Share a project with a teammate, CI, or another agent

No passphrase changes hands — sharing is by X25519 recipient.

1. The **recipient** creates an identity and gives you their public string: `vault_identity_new { "name": "ci" }` → `{ recipient: "tvault1…" }` (the private key stays on their machine and is never returned).
2. **You** grant access: `vault_share_project { "recipient": "tvault1…", "project": "webapp" }`.
3. Audit who has access anytime: `vault_project_recipients { "project": "webapp" }`.
4. Remove future live-vault access: `vault_unshare_project { "recipient": "tvault1…" }` — this **rotates the project key and re-encrypts every current value + archived version** in the updated vault. Pre-removal snapshots and already distributed artifacts remain readable, so rotate underlying credentials and re-seal them when needed.

## Ship commit-safe secrets

Produce ciphertext you can commit or hand back to the conversation safely:

- **To specific recipients:** `vault_seal_for_recipients { "recipients": ["tvault1…"], "output_path": ".env.encrypted" }`.
- **To the project's current recipients** (after `vault_share_project`): `vault_export_env_encrypted { "project": "webapp", "output_path": ".env.encrypted" }` — no need to re-list recipients.

Both return ciphertext (a path or base64). Only a holder of a matching private identity can open it (`tvault decrypt-env --identity …`).

## Check and reconcile a `.env`

```text
vault_diff_env { "file": ".env", "compare_values": true }
   → { only_in_vault, only_in_file, in_both, value_diffs: { KEY: "same"|"differs" }, in_sync }
```

`value_diffs` reports only `same`/`differs` — never the values. To fix drift:

```text
vault_sync_env { "direction": "pull", "path": ".env" }    # vault → file
vault_sync_env { "direction": "push", "path": ".env", "overwrite": true }   # file → vault
```

## Generate and store a secret (value never returned)

```text
vault_generate_secret { "key": "SESSION_SECRET", "length": 48, "charset": "base64" }
   → { key: "SESSION_SECRET", length: 48, charset: "base64", stored: true }
     # generation metadata is returned; the generated value is not
```

## See what changed

```text
vault_audit_log_since { "since": "2026-06-20T00:00:00Z", "action": "secret.write" }
   → recent entries, newest first (no values)
```

## Roll back a bad write

```text
vault_secret_history  { "key": "API_KEY" }        → version metadata (no values)
vault_rollback_secret { "key": "API_KEY", "to_version": 3 }   → { new_version }  (non-destructive)
```

## See also

- [Tools Reference](/mcp/tools) — every tool's inputs, returns, and policy gate
- [Access Policy](/mcp/access-policy) — scope what an agent may do
- [Sharing Secrets](/guide/sharing) and [Committable Secrets](/guide/committable-secrets) — the CLI side of the same flows
- [Security & Threat Model](/reference/security) — why redaction is a safety net, not a control
