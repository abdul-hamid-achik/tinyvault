---
title: MCP Access Policy
description: Control what an AI agent can do over TinyVault's MCP server with ~/.tvault/mcp-policy.yaml — access modes, project and secret globs, and command execution.
---

# MCP Access Policy

The MCP access policy constrains what an AI agent can do once it can talk to your vault. It lives in a single flat YAML file at `~/.tvault/mcp-policy.yaml` and is read once when the server starts. TinyVault exposes no policy-edit or reload tool, so the in-memory policy does not change during that process.

This page covers every field, the enforcement helpers behind them, and where the policy is a real control versus a safety net. Pair it with the [Tools Reference](/mcp/tools), which lists the access each tool requires.

## What the policy does, and does not, do

The policy decides, per request, whether the server will:

- perform a write (`set` / `delete` / `create` / `generate` / `import` / `rollback`),
- run a subprocess with secrets injected (`vault_run_with_secrets`), and
- touch a given project or secret key.

It is a gate in front of the server's tool handlers. It is **not** encryption, and it is **not** a sandbox for the agent process. An agent that reads a value over `vault_get_secret` has that value; the policy's job is to shrink what the agent is *allowed to ask for* in the first place.

::: info Loaded once, from disk
The policy is loaded when the `tvault mcp` process starts. Tool handlers cannot mutate or reload that in-memory policy. To apply a change, edit the file and restart the server. `vault_status` reports vault state, not the policy contents.

This is not filesystem containment: if you grant `vault_run_with_secrets`, its arbitrary shell command can edit files the server user can write, including the policy file that a later restart would load.
:::

## The safe policy (file absent)

If `~/.tvault/mcp-policy.yaml` does not exist, the production `tvault mcp` command uses `SafeDefaultPolicy`, a fail-closed policy:

| Field | Default value |
| --- | --- |
| `access_mode` | `read-only` |
| `allow_exec` | `false` |
| `redact_output` | `true` |
| `projects_allow` | `["*"]` |
| `projects_deny` | (none) |
| `secrets_allow` | (none) |
| `secrets_deny` | `["*"]` |
| `max_reads_per_session` | `0` |

With this policy, project/status and audit metadata remain available, but key-scoped secret access and plaintext values are denied, writes are disabled, and command execution is disabled. The `0` read limit means “no numeric cap,” but it does not weaken the safe state because `secrets_deny: ["*"]` blocks every plaintext read first.

::: info An explicit file is not merged with these defaults
Once `mcp-policy.yaml` exists, TinyVault decodes that file directly. Omitted fields take their Go zero values: empty allow lists allow all unmatched names, `false` disables booleans, and a non-positive `max_reads_per_session` means unlimited plaintext reads. Include every security-relevant field explicitly, as in the example below.
:::

## A complete example

Here is a realistic policy for an agent that should read and use secrets in two projects, write to one of them, never see anything that looks like a private key, and run commands:

```yaml
# ~/.tvault/mcp-policy.yaml
# Flat document — no apiVersion, no nesting beyond these keys.

access_mode: full          # read-only | read-write | full

allow_exec: true           # master switch for vault_run_with_secrets
redact_output: true        # scrub values from subprocess stdout/stderr

# Glob patterns (filepath.Match) over PROJECT names.
# Deny is evaluated before allow. Empty allow = allow all.
projects_allow:
  - app-staging
  - app-ci
projects_deny:
  - "*-prod"

# Glob patterns over secret KEY names.
secrets_allow: []          # empty = every key the project exposes
secrets_deny:
  - "*PRIVATE_KEY*"
  - "*_SEED"

max_reads_per_session: 50  # cap plaintext vault_get_secret calls for this server session
```

Apply it by restarting the server. Validate that the file parses from your shell:

```bash
tvault doctor          # reports whether a policy file was found and parsed
```

## Fields

### `access_mode`

The coarse read/write/exec dial. One of three values:

| Mode | What it permits |
| --- | --- |
| `read-only` | Reads and audit only — list, get, search, history, status, audit log, resources. No `set` / `delete` / `create` / `generate` / `import` / `rollback`. |
| `read-write` | Everything `read-only` allows, plus writes (`vault_set_secret`, `vault_delete_secret`, `vault_create_project`, `vault_delete_project`, `vault_generate_secret`, env import, `vault_rollback_secret`). |
| `full` | Everything `read-write` allows, plus `vault_run_with_secrets`. |

`vault_get_secret` is a read, so it is available in **every** mode — including `read-only`. It is the only tool that deliberately returns a stored secret in a dedicated plaintext field, and it warns that the value is now in model context. `vault_run_with_secrets` avoids that direct-read shape, but its arbitrary child output can still contain plaintext. See the [Tools Reference](/mcp/tools) for the per-tool requirements.

### `allow_exec`

A boolean master switch for `vault_run_with_secrets`, the only tool that injects secret values into a subprocess.

It is effective only when `access_mode` is `full`. The enforcement helper is `CanExec = allow_exec && access_mode == "full"`, so setting `allow_exec: true` under `read-write` does nothing. To run commands you need both `access_mode: full` and `allow_exec: true`.

### `redact_output`

When `true`, the server attempts to scrub literal occurrences of injected values longer than three characters from the `stdout` / `stderr` returned by `vault_run_with_secrets`, replacing matches with a `[REDACTED:key]` marker.

::: danger redact_output is a safety net, not a control
Redaction only replaces the *literal* value, and only when the value is **longer than 3 characters**. It is trivially evaded: a subprocess that base64-encodes, reverses, or otherwise transforms a value before printing it defeats redaction entirely, and short values are never redacted at all. Treat it as a guard against accidental leakage in logs, never as a boundary against a hostile command. The real control is `allow_exec` / `access_mode`: if you do not trust the command, do not let the agent run it.
:::

### `projects_allow` / `projects_deny`

Glob patterns (`filepath.Match` syntax) over **project names**. They apply wherever the server enumerates or selects a project.

Rules:

- **Deny is checked before allow.** If a name matches `projects_deny`, it is rejected even if it also matches `projects_allow`.
- **An empty `projects_allow` means allow all.** Add entries only when you want to *restrict* to that set.

```yaml
projects_allow:
  - app-*          # any project starting with app-
projects_deny:
  - app-prod       # ...except this one
```

### `secrets_allow` / `secrets_deny`

Glob patterns over **secret key names**, with the same deny-before-allow and empty-allow-means-all semantics as projects. These apply per-key wherever keys are listed, fetched, searched, exported, imported, sealed, or have their history read.

```yaml
secrets_deny:
  - "*PRIVATE_KEY*"
  - "*_TOKEN"
secrets_allow: []   # otherwise allow every key the project exposes
```

A denied key is filtered out of listings and refused on direct access, so an agent cannot reach it via `vault_get_secret`, `vault_search_secrets`, `vault_seal_for_recipients`, or any other key-scoped tool.

### `max_reads_per_session`

An integer cap on plaintext `vault_get_secret` calls during the MCP server session. A positive value enables the cap; `0` or a negative value means unlimited reads.

The server checks the project and key policy first, then consumes one read before resolving the value. Once the cap is reached, later `vault_get_secret` calls fail with `secret value read limit reached for this MCP session`. Restarting `tvault mcp` starts a new session and resets the counter.

The counter applies only to the plaintext-returning `vault_get_secret` tool, including environment-group reads. Metadata searches, history, exports, sealing, and `vault_run_with_secrets` do not consume it.

::: warning A read cap is not a “never reveal” policy
A positive cap limits how many plaintext reads the tool can make; it does not disable the first reads. TinyVault currently has no separate tool-level switch that denies `vault_get_secret` while allowing `vault_run_with_secrets`. Use project/key deny lists to make sensitive keys unreachable, and instruct the agent to prefer value-minimizing tools.
:::

## Enforcement helpers

Tool handlers route their access decisions through four methods on the loaded policy. Plaintext reads also pass through the session counter described above:

| Helper | True when | Gates |
| --- | --- | --- |
| `CanWrite()` | `access_mode` is `read-write` or `full` | all write tools |
| `CanExec()` | `allow_exec` **and** `access_mode == full` | `vault_run_with_secrets` |
| `CanAccessProject(name)` | not in `projects_deny`, and (`projects_allow` empty or matched) | project selection / enumeration |
| `CanAccessSecret(key)` | not in `secrets_deny`, and (`secrets_allow` empty or matched) | per-key access |
| plaintext read counter | `max_reads_per_session <= 0`, or the positive cap has not been reached | `vault_get_secret` only |

Because the policy is loaded at startup and these helpers run on every request, ordinary tool handlers provide no path to mutate the in-memory policy or grant broader access. The command-execution caveat above still applies to files on disk.

## Recommended starting points

- **Read-only inspector** — let an agent map your secrets without writing or running anything:

  ```yaml
  access_mode: read-only
  allow_exec: false
  ```

- **Scoped executor** — let an agent run jobs with secrets and steer it toward `vault_run_with_secrets`; this does not technically disable `vault_get_secret` for otherwise allowed keys:

  ```yaml
  access_mode: full
  allow_exec: true
  redact_output: true
  secrets_deny:
    - "*PRIVATE_KEY*"
  ```

- **Scoped writer** — confine an agent to non-production projects:

  ```yaml
  access_mode: read-write
  allow_exec: false
  projects_allow:
    - app-staging
  projects_deny:
    - "*-prod"
  ```

::: tip Discover, then act
Have the agent learn the surface once with `tvault docs features`, then use the relational tools (`vault_search_secrets`, `vault_list_secrets_by_prefix`) to find keys by metadata, and `vault_run_with_secrets` to *use* a value without first requesting it as a direct field. The launched command must still be trusted not to leak its environment through stdout, files, or the network. The policy backs this pattern up by denying keys the agent should never reach.
:::

## See also

- [MCP Tools Reference](/mcp/tools) — every tool, what it returns, and the access it requires.
- [MCP overview & setup](/mcp/) — wiring `tvault mcp` into Claude Code and other clients.
- [Security model](/reference/security) — the threat model behind redaction, exec, and the recipient layer.
- [Sharing secrets](/guide/sharing) — recipient removal, live-vault re-keying, and committable encrypted artifacts.
