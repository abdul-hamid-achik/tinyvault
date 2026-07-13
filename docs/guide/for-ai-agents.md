---
title: AI Agent Workflow
description: Discover, find, and use TinyVault secrets while minimizing plaintext in the model context.
---

# AI agent workflow

TinyVault gives an agent ways to act on secret values without first returning a dedicated plaintext field. This is a value-minimizing workflow, not a guarantee that plaintext can never reach the model: `vault_get_secret` and `vault_set_secret` handle raw values explicitly, and a subprocess can leak what it receives through its output or side effects.

Use [MCP](/mcp/) when the client supports it. Use the CLI as a subprocess when it does not.

## Recommended loop

### 1. Discover the surface

An MCP client receives the server's tool schemas during initialization. A CLI-driven agent can inspect TinyVault's machine-readable help instead of guessing:

```bash
tvault docs features
tvault docs topics
tvault help agent --json
```

### 2. Find a key by metadata

Use `vault_search_secrets`, `vault_list_secrets_by_prefix`, or `vault_list_secrets`. These tools return key names and metadata, not values.

For a CLI-driven agent, use:

```bash
tvault list --names-only
tvault search --name-like 'DATABASE_*'
```

`list --names-only` is lock-free. `search` currently unlocks the vault even though its result contains metadata only.

### 3. Use the narrowest value path

Choose the operation that keeps plaintext closest to its consumer:

| Need | Preferred MCP tool | What the tool result contains |
| --- | --- | --- |
| Run a command | `vault_run_with_secrets` with `secrets` or `prefix` | Exit code and captured output; injected values are not response fields |
| Give a local tool an environment file | `vault_export_env` with `keys` | Path, key names, and count; plaintext is written to disk |
| Create a new random credential | `vault_generate_secret` | Storage confirmation and generation metadata |
| Package values for recipients | `vault_seal_for_recipients` or `vault_export_env_encrypted` | Ciphertext or a path plus metadata |
| Import values already stored in dotenv files | `vault_import_env_files` | Import metadata rather than the source values |

For a CLI-driven agent, prefer a narrow injection:

```bash
tvault run --only DATABASE_URL -- your-command
tvault run --prefix STRIPE_ -- your-command
```

### 4. Review the result

Check the command's exit status and returned metadata. Use `vault_audit_log_since` when you need to review recently recorded vault activity.

## The two raw-value exceptions

`vault_get_secret` returns `{key, value, warning}`. The plaintext value becomes part of the MCP response and can enter conversation history, logs, or traces. Reserve it for a task that genuinely requires the model to inspect the value.

`vault_set_secret` accepts the plaintext value as a tool argument. That value may already be present in the prompt or tool-call transcript. If the value does not need to be chosen by the model, prefer `vault_generate_secret` or import it from a file the server can read.

The CLI has the same distinction: `tvault get` and rendered `tvault env` output expose values, while `tvault run` can pass them directly to a process.

## Output redaction has a narrow scope

When `redact_output` is enabled, `vault_run_with_secrets` replaces literal injected values longer than three characters in the captured stdout and stderr it returns.

Redaction does not:

- detect encoded, split, hashed, reversed, or otherwise transformed values;
- cover values of three characters or fewer;
- inspect files, child-process logs, or traffic sent over the network; or
- constrain a hostile command that deliberately exfiltrates its environment.

Treat redaction as protection against accidental literal output. Restrict the policy and approve only commands you trust with the selected keys.

## Policy limits matter

If `~/.tvault/mcp-policy.yaml` is absent, the production `tvault mcp` command uses a fail-closed default: project and status metadata remain available, but secret keys, writes, and command execution are denied.

An explicit policy can scope projects, key patterns, writes, command execution, and the number of `vault_get_secret` reads. The current policy cannot allow a key for `vault_run_with_secrets` while categorically denying `vault_get_secret` for that same key. Tool choice and client approval remain part of the safety boundary.

See [MCP access policy](/mcp/access-policy) before granting an agent access.

## Avoid these patterns

- Do not enumerate values with repeated `vault_get_secret` or `tvault get` calls.
- Do not render every secret when one key or prefix is sufficient.
- Do not ask a subprocess to print its environment to confirm injection.
- Do not treat a redacted response as proof that no other channel received the value.
- Do not leave plaintext files created by `vault_export_env` longer than the consumer needs them.

## Next steps

- [MCP setup and security model](/mcp/)
- [MCP tools reference](/mcp/tools)
- [MCP recipes](/mcp/recipes)
- [Security and threat model](/reference/security)
