---
title: MCP Server
description: Connect an MCP client to TinyVault, scope it with a fail-closed policy, and use secrets without returning plaintext by default.
---

# MCP server

`tvault mcp` serves the local TinyVault database over the Model Context Protocol (MCP) using stdio. An MCP host launches the same binary as the CLI and receives tools for projects, secret metadata, process injection, encrypted export, sharing, and vault operations.

The recommended design is value-minimizing: give the agent operations that use a secret at its destination instead of first returning the plaintext to the model.

## Before you connect

You need:

1. an initialized vault;
2. `tvault` available to the MCP host;
3. `TVAULT_PASSPHRASE` in the server process's environment; and
4. an access policy for anything beyond fail-closed metadata access.

`tvault mcp` cannot prompt for a passphrase because stdin carries MCP messages. Supply the passphrase through the host's secret/environment configuration or a launcher that retrieves it from an OS credential store. Do not commit it in an MCP configuration file.

The server validates the passphrase at startup, caches the derived key, and reopens the database only for each vault request. Restart it after rotating the passphrase.

## Connect an MCP host

Configure the host to launch:

```bash
tvault mcp
```

Most MCP hosts use a configuration shaped like this:

```json
{
  "mcpServers": {
    "tinyvault": {
      "command": "tvault",
      "args": ["mcp"]
    }
  }
}
```

Make sure the host process inherits `TVAULT_PASSPHRASE`. GUI applications often do not inherit your interactive shell environment, so use the host's environment controls or a credential-store launcher in that case.

`tvault mcp-server` remains an alias for compatibility.

## Start with the fail-closed default

If `~/.tvault/mcp-policy.yaml` does not exist, the production command uses a safe default:

- project and status metadata are available;
- all secret keys and values are denied;
- writes are denied; and
- command execution is denied.

This lets you verify the connection before granting access. Add a policy only for the projects and keys the client needs.

A narrowly scoped read-only policy might be:

```yaml
# ~/.tvault/mcp-policy.yaml
access_mode: read-only
projects_allow:
  - myapp
secrets_allow:
  - DATABASE_URL
allow_exec: false
redact_output: true
max_reads_per_session: 1
```

`read-only` prevents mutations; it does not mean value-free. This example still permits one `vault_get_secret` response for `DATABASE_URL` during the session.

To enable `vault_run_with_secrets`, set both:

```yaml
access_mode: full
allow_exec: true
```

`full` also enables write operations. The current policy does not have an exec-without-write mode, nor a per-tool rule that allows injection while denying `vault_get_secret` for the same key. Review the complete [access policy](/mcp/access-policy) before enabling it.

The policy is loaded once at startup. There is no MCP policy-edit or reload tool, and changing the file does not alter the in-memory policy for that process; restart the server to apply an edit. If you enable `vault_run_with_secrets`, remember that the launched shell command can modify any file the server user can write, including the policy file used by a future restart.

## Prefer operations that do not return values

| Tool | Plaintext path | Result returned to the client |
| --- | --- | --- |
| `vault_run_with_secrets` | Injected into a subprocess environment | Exit code, stdout, and stderr |
| `vault_export_env` | Written to a local plaintext file | Path, key names, and count |
| `vault_generate_secret` | Generated and stored inside TinyVault | Key and generation metadata |
| `vault_seal_for_recipients` | Encrypted to recipient public keys | Ciphertext or path plus metadata |
| `vault_export_env_encrypted` | Encrypted in memory or written to disk | Ciphertext or path plus metadata |

Search and listing tools return names and metadata, so an agent can locate a key before choosing a value path.

### Explicit raw-value tools

`vault_get_secret` is intentionally different: it returns the plaintext value with a warning. The response can enter the model context, conversation history, client logs, and traces.

`vault_set_secret` accepts a plaintext value in its tool arguments. If the model supplied that argument, the value can already be present in its context. Prefer server-side generation or file import when the model does not need to choose the value.

See [AI agent workflow](/guide/for-ai-agents) for the discover, find, use, and review loop.

## Understand output redaction

When the policy enables `redact_output`, TinyVault scans stdout and stderr returned by `vault_run_with_secrets` and replaces literal injected values longer than three characters with `[REDACTED:KEY]`.

This is defense in depth, not a sandbox. Encoding or transforming a value bypasses literal matching. Redaction does not cover files, external logs, network traffic, or any other side effect of the command. Give command execution only to clients and commands you trust with the allowed secrets.

## Resources and prompts

The server also publishes metadata resources:

| Resource | Contents |
| --- | --- |
| `vault://status` | Vault status and project summary |
| `vault://projects` | Policy-filtered project metadata |
| `vault://projects/{name}/keys` | Policy-filtered key metadata, without values |

Two prompts scaffold common flows:

| Prompt | Purpose |
| --- | --- |
| `setup-project` | Plan a project setup |
| `inject-secrets` | Plan process injection for a command |

## Operational notes

- The MCP server and direct CLI commands can share the vault because the server reopens it per request instead of holding the bbolt lock continuously.
- A running studio session does hold the database open and can cause a database-in-use error.
- Policy decisions happen in the server process, not in model instructions.
- Audit rows are operational metadata, not a tamper-proof external log. Do not place secrets in key names, command strings, or paths.

## Next steps

- [AI agent workflow](/guide/for-ai-agents) — the recommended value-minimizing loop.
- [Access policy](/mcp/access-policy) — every policy field and enforcement rule.
- [Tools reference](/mcp/tools) — tool inputs, outputs, and gates.
- [Recipes](/mcp/recipes) — task-oriented examples.
- [Security and threat model](/reference/security) — the full trust boundary.
