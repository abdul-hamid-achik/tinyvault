---
title: MCP Server
description: Connect AI agents to TinyVault over the Model Context Protocol — one Go binary that serves 21 tools over stdio while keeping secret values out of the model context.
---

# MCP Server

TinyVault speaks the [Model Context Protocol](https://modelcontextprotocol.io) (MCP), the open standard that lets AI agents call tools, read resources, and use prompts. The same `tvault` binary that is your CLI is also the MCP server, so an agent can manage your vault without ever seeing a secret value.

## What it is

`tvault` serves MCP over **stdio** through a hidden subcommand:

```bash
tvault mcp-server
```

You rarely run this by hand — your MCP host (Claude Code, Claude Desktop, or any MCP client) launches it for you. The server is a thin **policy-and-redaction layer** over the same vault API the CLI uses: every call is checked against an [access policy](/mcp/access-policy), privileged actions are audited, and outputs are filtered so plaintext stays out of the conversation.

It exposes **21 tools, 3 resources, and 2 prompts**, built on the official [modelcontextprotocol go-sdk](https://github.com/modelcontextprotocol/go-sdk).

::: info Same vault, same crypto
The MCP server is not a separate datastore. It unlocks the one encrypted bbolt vault at `~/.tvault/vault.db` and reads and writes through the identical AES-256-GCM path as the CLI and [studio](/guide/studio). See [Architecture](/reference/architecture).
:::

## The core promise: values stay out of the model

The design goal is that a secret value **never needs to enter the model's context**. The tools are shaped to give an agent a way to *use* a secret without *reading* it:

| Tool | What the agent gets back |
| --- | --- |
| `vault_run_with_secrets` | Injects secrets as env vars into a subprocess; returns `{exit_code, stdout, stderr}` with values redacted |
| `vault_export_env` | Writes a `0600` file to disk; returns only `{path, count, keys}` |
| `vault_generate_secret` | Generates and stores a secret; returns only `{stored: true}` |
| `vault_seal_for_recipients` | Returns commit-safe ciphertext (or just a path) |
| `vault_get_secret` | **The one exception** — returns the cleartext value with a warning |

`vault_get_secret` is the single tool that returns a raw value. It returns `{key, value, warning}`, where the warning reminds the caller the value is now in the model context. Prefer `vault_run_with_secrets` for *using* a value, and the search tools (`vault_search_secrets`, `vault_list_secrets_by_prefix`) for *finding* keys. The [Tools Reference](/mcp/tools) documents all 21.

::: warning Redaction is a safety net, not a control
With `redact_output` on, the server scrubs secret values from `vault_run_with_secrets` stdout/stderr, but it only replaces literal values longer than 3 characters with `[REDACTED:KEY]`. A subprocess that transforms a value — base64-encodes it, reverses it, splits it across lines — can evade redaction. Treat it as defense in depth, not a guarantee, and trust the *commands* you let an agent run.
:::

## Setup with Claude Code

Add an MCP server entry whose `command` is `tvault`, whose `args` are `["mcp-server"]`, and whose `env` carries the vault passphrase. The `TVAULT_PASSPHRASE` env var is how the server unlocks the vault non-interactively — there is no prompt over stdio.

Create or edit `.claude/settings.local.json` in your project:

```json
{
  "mcpServers": {
    "tvault": {
      "command": "tvault",
      "args": ["mcp-server"],
      "env": {
        "TVAULT_PASSPHRASE": "your-vault-passphrase"
      }
    }
  }
}
```

Or register it from the CLI:

```bash
claude mcp add tvault --env TVAULT_PASSPHRASE=your-vault-passphrase -- tvault mcp-server
```

::: danger Keep the passphrase out of version control
`.claude/settings.local.json` holds your plaintext passphrase, so it must never be committed. Add it to `.gitignore`. If you would rather not put a passphrase in a config file, run the [local agent](/guide/agent) or use an [identity key](/guide/sharing) instead.
:::

::: tip Optional: point at a non-default vault
The MCP server honors the global persistent flags. To serve a vault in a custom directory, pass `--vault` in `args`, for example `["mcp-server", "--vault", "/path/to/vault-dir"]`. See [Configuration](/reference/configuration) and [Environment Variables](/reference/environment-variables).
:::

## Resources and prompts

Alongside the tools, the server publishes three read-only **resources** (JSON, metadata only, filtered by your policy):

| Resource URI | Contents |
| --- | --- |
| `vault://status` | Lock state, project count, vault id, creation time |
| `vault://projects` | Project names, descriptions, secret counts |
| `vault://projects/{name}/keys` | Key names and metadata for one project (no values) |

It also publishes two **prompts** that scaffold common agent flows:

| Prompt | Arguments |
| --- | --- |
| `setup-project` | `name` (required) |
| `inject-secrets` | `project` (optional), `command` (required) |

## The recommended agent pattern

The most context-safe way for an agent to work with TinyVault is:

1. **Discover the surface once.** Run `tvault docs features` at the start of a session to get a JSON manifest of every feature and tool — no guessing.

   ```bash
   tvault docs features
   ```

2. **Find keys relationally, not by enumerating values.** Use `vault_search_secrets` (filter by prefix, name pattern, time window, version) or `vault_list_secrets_by_prefix` (autocomplete-style) to locate the key you need. Both return metadata only.

3. **Use a value without reading it.** Call `vault_run_with_secrets` to run a command with the secret injected as an env var. The value flows into the subprocess, not the conversation.

This keeps `vault_get_secret` reserved for the rare case where the model genuinely must see a value — and even then, the warning makes that explicit.

## Everything privileged is audited

Reveals, writes, runs, exports, and rollbacks are recorded in the vault's audit log, just like the equivalent CLI commands. The model can inspect recent activity with `vault_audit_log` and `vault_audit_log_since`, but audit entries never contain secret values.

The model also **cannot escalate** its own access. The policy is loaded from disk at server start and cannot be changed at runtime. An agent can call `vault_status` to learn what it is allowed to do, but not to widen it.

::: info Exit codes
If the server fails to start, the exit code tells you why: `3` vault locked, `5` not initialized, `6` wrong passphrase. (`0` is ok, `1` is a generic error, `4` is not found.)
:::

## See also

- [Tools Reference](/mcp/tools) — all 21 tools, their inputs, and exactly what each returns
- [Access Policy](/mcp/access-policy) — scope an agent with `mcp-policy.yaml` (modes, globs, exec gate)
- [Local Agent](/guide/agent) — unlock once, skip the passphrase prompt
- [Security & Threat Model](/reference/security) — what redaction and tokens do and do not protect
