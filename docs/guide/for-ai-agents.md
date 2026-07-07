---
title: For AI Agents
description: How an AI agent should discover and use TinyVault — run `tvault docs features` to learn the surface, then discover → search → use, keeping secret values out of the model context.
---

# For AI Agents

TinyVault is built to be driven by AI agents — over [MCP](/mcp/) or as a CLI subprocess — **without secret values ever entering the model's context**. This page is the agent's starting point.

## Start here: discover the surface

Don't guess at commands. TinyVault ships a **machine-readable manifest** of everything it can do:

```bash
tvault docs features      # JSON: every feature, its commands, and a description
tvault docs topics        # JSON: topics with worked examples
tvault help agent --json  # the recommended agent workflow, as JSON
```

Call `tvault docs features` **once at the start of a session**, then drill into a topic (`tvault docs interpolate`, `tvault docs mcp`, …). An agent connected over MCP is told the same thing in the server's startup instructions.

## The loop: discover → search → use

1. **Discover** — `tvault docs features` (CLI) once per session.
2. **Find a key, not a value** — `vault_search_secrets` / `vault_list_secrets_by_prefix` (MCP) or `tvault search` (CLI). These return metadata only.
3. **Use a value without reading it** — `vault_run_with_secrets` (MCP) or `tvault run -- <cmd>` (CLI): the value is injected into the subprocess environment, not the conversation.
4. **Confirm** — `vault_audit_log_since` (MCP) or the studio Audit pane.

## Values stay out of the model

Every tool returns metadata, a file path, or ciphertext — **except** `vault_get_secret`, which returns a value *with a warning*. Prefer the alternatives:

| Need | Use | What comes back |
| --- | --- | --- |
| Run something with a secret | `vault_run_with_secrets` | exit code + redacted output |
| Hand a tool a `.env` | `vault_export_env` | a file path only |
| Generate a secret | `vault_generate_secret` | `{ stored: true }` |
| Package secrets to share/commit | `vault_seal_for_recipients` / `vault_export_env_encrypted` | ciphertext only |

## Two ways to connect

- **MCP** (recommended): point your client at `tvault mcp`. See [MCP Overview](/mcp/) for setup, the [Tools Reference](/mcp/tools) (49 tools), and the [Recipes](/mcp/recipes) cookbook.
- **CLI subprocess**: call `tvault` directly; `tvault docs`/`tvault help --json` are the structured surfaces.

## Anti-patterns

- Don't call `vault_get_secret` / `tvault get` in a loop to enumerate secrets — use the search/list tools.
- Don't grep `tvault env` output to find a key — search for it.
- Don't ask the model to hold a value — inject it into a subprocess with `vault_run_with_secrets`.

## See also

- [MCP Recipes](/mcp/recipes) — end-to-end workflows
- [MCP Tools Reference](/mcp/tools) — all 49 tools, inputs, and returns
- [Access Policy](/mcp/access-policy) — scope what an agent may do
- [Security & Threat Model](/reference/security) — what redaction does and doesn't protect
