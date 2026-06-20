---
title: MCP Access Policy
description: Control what an AI agent can do over TinyVault's MCP server with ~/.tvault/mcp-policy.yaml — access modes, project and secret globs, and command execution.
---

# MCP Access Policy

The MCP access policy constrains what an AI agent can do once it can talk to your vault. It lives in a single flat YAML file at `~/.tvault/mcp-policy.yaml`, is read once when the server starts, and the model cannot change it at runtime.

This page covers every field, the enforcement helpers behind them, and where the policy is a real control versus a safety net. Pair it with the [Tools Reference](/mcp/tools), which lists the access each tool requires.

## What the policy does, and does not, do

The policy decides, per request, whether the server will:

- perform a write (`set` / `delete` / `create` / `generate` / `import` / `rollback`),
- run a subprocess with secrets injected (`vault_run_with_secrets`), and
- touch a given project or secret key.

It is a gate in front of the server's tool handlers. It is **not** encryption, and it is **not** a sandbox for the agent process. An agent that reads a value over `vault_get_secret` has that value; the policy's job is to shrink what the agent is *allowed to ask for* in the first place.

::: info Loaded once, from disk
The policy is loaded when the `tvault mcp-server` process starts. The model can call `vault_status` to discover its own access level, but it cannot edit the file or escalate its permissions mid-session. To change the policy, edit the file and restart the server.
:::

## The default policy (file absent)

If `~/.tvault/mcp-policy.yaml` does not exist, the server falls back to a fully permissive `DefaultPolicy`:

| Field | Default value |
| --- | --- |
| `access_mode` | `full` |
| `allow_exec` | `true` |
| `redact_output` | `true` |
| `projects_allow` | `["*"]` |
| `projects_deny` | (none) |
| `secrets_allow` | `["*"]` |
| `secrets_deny` | (none) |
| `max_reads_per_session` | `50` |

::: warning No policy file means no restrictions
With no file present, the agent can read every value, write to any project, and run subprocesses with injected secrets. If you are wiring up an agent you do not fully trust, write an explicit policy before you start the server. The default exists for local convenience, not for least privilege.
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

max_reads_per_session: 50  # parsed today, NOT yet enforced (see below)
```

Apply it by restarting the server. Verify what the agent now sees with `vault_status`, or from your shell:

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

`vault_get_secret` is a read, so it is available in **every** mode — including `read-only`. It is also the only tool that returns a raw plaintext value, and it returns a warning that the value is now in the model's context. If you want an agent that acts on secrets without ever pulling cleartext into its context, set `access_mode: full`, keep reads available, and steer the agent toward `vault_run_with_secrets` instead of `vault_get_secret`. See the [Tools Reference](/mcp/tools) for the per-tool requirements.

### `allow_exec`

A boolean master switch for `vault_run_with_secrets`, the only tool that injects secret values into a subprocess.

It is effective only when `access_mode` is `full`. The enforcement helper is `CanExec = allow_exec && access_mode == "full"`, so setting `allow_exec: true` under `read-write` does nothing. To run commands you need both `access_mode: full` and `allow_exec: true`.

### `redact_output`

When `true`, the server scrubs injected secret values out of the `stdout` / `stderr` it returns from `vault_run_with_secrets`, replacing each occurrence with a `[REDACTED:key]` marker.

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

An integer (default `50`), documented as a cap on `vault_get_secret` calls in one session.

::: warning Parsed, but not yet enforced
`max_reads_per_session` is read from the file and stored on the policy, but **no handler currently enforces it** — there is no per-session counter wired up today. Set it to document intent if you like, but do not rely on it as a limit. It is aspirational, not a control. Use `secrets_deny` and `access_mode` for guarantees that hold right now.
:::

## Enforcement helpers

Every tool handler routes its decision through one of four methods on the loaded policy. Knowing them makes the YAML predictable:

| Helper | True when | Gates |
| --- | --- | --- |
| `CanWrite()` | `access_mode` is `read-write` or `full` | all write tools |
| `CanExec()` | `allow_exec` **and** `access_mode == full` | `vault_run_with_secrets` |
| `CanAccessProject(name)` | not in `projects_deny`, and (`projects_allow` empty or matched) | project selection / enumeration |
| `CanAccessSecret(key)` | not in `secrets_deny`, and (`secrets_allow` empty or matched) | per-key access |

Because the policy is loaded from disk at server start and these helpers run on every request, the model has no path to mutate it. The most it can do is observe its own access via `vault_status` — it cannot grant itself more.

## Recommended starting points

- **Read-only inspector** — let an agent map your secrets without writing or running anything:

  ```yaml
  access_mode: read-only
  allow_exec: false
  ```

- **Use-but-never-reveal** — let an agent run jobs with secrets, but discourage pulling cleartext into context by relying on `vault_run_with_secrets`:

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
Have the agent learn the surface once with `tvault docs features`, then use the relational tools (`vault_search_secrets`, `vault_list_secrets_by_prefix`) to find keys by metadata, and `vault_run_with_secrets` to *use* a value — all of which keep cleartext out of the model's context. The policy backs this pattern up by denying the keys the agent should never see.
:::

## See also

- [MCP Tools Reference](/mcp/tools) — every tool, what it returns, and the access it requires.
- [MCP overview & setup](/mcp/) — wiring `tvault mcp-server` into Claude Code and other clients.
- [Security model](/reference/security) — the threat model behind redaction, exec, and the recipient layer.
- [Sharing secrets](/guide/sharing) — true revocation and committable, recipient-encrypted secrets.
