---
title: MCP Server
description: Connect AI agents to TinyVault over the Model Context Protocol — one Go binary that serves 49 tools over stdio while keeping secret values out of the model context.
---

# MCP Server

TinyVault speaks the [Model Context Protocol](https://modelcontextprotocol.io) (MCP), the open standard that lets AI agents call tools, read resources, and use prompts. The same `tvault` binary that is your CLI is also the MCP server, so an agent can manage your vault without ever seeing a secret value.

## What it is

`tvault` serves MCP over **stdio** through a dedicated subcommand:

```bash
tvault mcp
```

(`mcp-server` remains a working alias.)

You rarely run this by hand — your MCP host (Claude Code, Claude Desktop, or any MCP client) launches it for you. The server is a thin **policy-and-redaction layer** over the same vault API the CLI uses: every call is checked against an [access policy](/mcp/access-policy), privileged actions are audited, and outputs are filtered so plaintext stays out of the conversation.

It exposes **49 tools, 3 resources, and 2 prompts**, built on the official [modelcontextprotocol go-sdk](https://github.com/modelcontextprotocol/go-sdk).

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

`vault_get_secret` is the single tool that returns a raw value. It returns `{key, value, warning}`, where the warning reminds the caller the value is now in the model context. Prefer `vault_run_with_secrets` for *using* a value, and the search tools (`vault_search_secrets`, `vault_list_secrets_by_prefix`) for *finding* keys. The [Tools Reference](/mcp/tools) documents all 36.

::: warning Redaction is a safety net, not a control
With `redact_output` on, the server scrubs secret values from `vault_run_with_secrets` stdout/stderr, but it only replaces literal values longer than 3 characters with `[REDACTED:KEY]`. A subprocess that transforms a value — base64-encodes it, reverses it, splits it across lines — can evade redaction. Treat it as defense in depth, not a guarantee, and trust the *commands* you let an agent run.
:::

## Connecting an MCP client

Any MCP-capable client can launch `tvault mcp`. Because the server unlocks the vault from `TVAULT_PASSPHRASE` (there is no prompt over stdio), the only real decision is **how each client supplies that passphrase**. The most robust, secret-out-of-config pattern is a tiny launcher script — defined [below](#keeping-the-passphrase-out-of-every-config) — and the per-client commands here point at it (`tvault-mcp`). Swap in plain `tvault mcp` if you prefer to manage the passphrase yourself.

### Claude Code

```bash
claude mcp add tinyvault -s user -- tvault-mcp
```

Or edit `.claude/settings.local.json` directly. Claude Code expands `${TVAULT_PASSPHRASE}` from its environment, so no secret is written to the file:

```json
{
  "mcpServers": {
    "tinyvault": {
      "command": "tvault",
      "args": ["mcp"],
      "env": { "TVAULT_PASSPHRASE": "${TVAULT_PASSPHRASE}" }
    }
  }
}
```

### Codex

```bash
codex mcp add tinyvault -- tvault-mcp
```

Writes an `[mcp_servers.tinyvault]` block to `~/.codex/config.toml`.

### opencode

Add to the `mcp` object in `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "tinyvault": {
      "type": "local",
      "command": ["tvault-mcp"],
      "enabled": true
    }
  }
}
```

opencode also resolves `{env:TVAULT_PASSPHRASE}` inside an `environment` block if you'd rather pass it explicitly.

### Hermes

```bash
hermes mcp add tinyvault --command tvault-mcp
hermes mcp test tinyvault          # verify once the passphrase is set
```

### Claude Desktop

Add the same `mcpServers` block as Claude Code to `~/Library/Application Support/Claude/claude_desktop_config.json`. GUI apps don't inherit your shell environment, so the launcher (which reads the passphrase from a file) is the easiest way to feed it the passphrase.

### Keeping the passphrase out of every config

The cleanest setup is a one-line launcher that loads the passphrase from a single place and execs the server — so none of the agent configs above hold the secret:

```sh
#!/bin/sh
# ~/.local/bin/tvault-mcp   (chmod +x)
[ -f "$HOME/.config/secrets/env" ] && . "$HOME/.config/secrets/env"
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"
exec tvault mcp "$@"
```

Point every client at `tvault-mcp` and keep `export TVAULT_PASSPHRASE=…` in `~/.config/secrets/env` (or your secrets manager / the macOS Keychain). This works for CLI **and** GUI clients and keeps the passphrase out of all the JSON/TOML/YAML configs.

::: danger Never commit a passphrase
If you do embed `TVAULT_PASSPHRASE` in a config file (e.g. `.claude/settings.local.json`), it must never be committed — add it to `.gitignore`. For passphrase-free setups, run the [local agent](/guide/agent) or use an [identity key](/guide/sharing).
:::

::: tip Optional: point at a non-default vault
The MCP server honors the global persistent flags. To serve a vault in a custom directory, pass `--vault` in `args`, for example `["mcp", "--vault", "/path/to/vault-dir"]`. See [Configuration](/reference/configuration) and [Environment Variables](/reference/environment-variables).
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

## Runs alongside the CLI

The server validates the passphrase once at startup, then caches **only the key** and reopens the vault per request — it does not keep the [bbolt](https://github.com/etcd-io/bbolt) database locked for its lifetime. So a long-running `tvault mcp` no longer blocks `tvault set`/`get`/`run`/`import` on the same machine; the lock is free between calls. (This mirrors the [local agent](/guide/agent).) The remaining long-lived holder is `tvault studio`, the interactive UI.

::: info Exit codes
If the server fails to start, the exit code tells you why: `3` vault locked at rest, `5` not initialized, `6` wrong passphrase, `7` the database is in use by another process. (`0` is ok, `1` is a generic error, `4` is not found.)
:::

## See also

- [Tools Reference](/mcp/tools) — all 49 tools, their inputs, and exactly what each returns
- [Access Policy](/mcp/access-policy) — scope an agent with `mcp-policy.yaml` (modes, globs, exec gate)
- [Local Agent](/guide/agent) — unlock once, skip the passphrase prompt
- [Security & Threat Model](/reference/security) — what redaction and tokens do and do not protect
