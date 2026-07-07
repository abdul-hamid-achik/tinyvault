---
title: Environment Groups
description: Link projects as named environments of the same application, diff key sets across them, promote values between them, and let one environment inherit another's missing keys.
---

# Environment Groups

An **environment group** links several projects together as named environments of the same application — typically `production`, `preview`, and `staging`. Each environment points at a real project with its own data encryption key (DEK); the group itself is pure metadata. No new crypto, no new buckets, no copied values.

The group is the hub for three workflows that otherwise don't compose well:

- **Drift detection** — see which keys exist in one environment but not another.
- **Promotion** — copy a secret *value* from one environment to another, versioned and audited.
- **Inheritance** — let a child environment resolve missing keys from a base at read time, without copying anything.

```bash
tvault env group create liftclub --description "LIFT Club" \
  --env production=liftclub --env preview=liftclub-preview
```

:::: info The group never holds values
A group stores only the `name → project` mapping, an optional description, and (per child) an optional inheritance pointer. Secret values stay in their own projects, encrypted under their own DEKs. Deleting a group never touches a secret.
::::

## Prerequisites

Every environment you link must already exist as a project. Create the projects first, then link them:

```bash
tvault projects create liftclub
tvault projects create liftclub-preview
tvault env group create liftclub --env production=liftclub --env preview=liftclub-preview
```

A project can belong to **at most one** group. Pass `--force` to `env group create` to overwrite an existing group or re-link a project that is already in another group.

## Create a group

```bash
tvault env group create <name> --env <name=project> [--env ...] [-d <desc>] [--force]
```

```bash
tvault env group create liftclub --description "LIFT Club" \
  --env production=liftclub --env preview=liftclub-preview --env staging=liftclub-staging
```

| Flag | Description |
| --- | --- |
| `-d`, `--description <str>` | Human-readable description shown in `env group list`. |
| `--env <name=project>` | Link an environment to a project. Repeatable; the first is typically `production`. |
| `--force` | Overwrite an existing group, or re-link a project already in another group. |

Environment names must be unique within the group. At least one `--env` is required.

## List and inspect groups

```bash
tvault env group list
```

```
NAME       ENVIRONMENTS                                  DESCRIPTION
liftclub   production, preview, staging                  LIFT Club
```

`env group show` prints the environments, any inheritance configured, and a metadata-only drift verdict (no unlock needed):

```bash
tvault env group show liftclub
```

```
Group: liftclub
Description: LIFT Club

Environments:
  production → liftclub
  preview → liftclub-preview (inherits from production)
  staging → liftclub-staging

No drift — all environments have the same key set
```

## Edit a group's membership

```bash
# Add an environment (project must already exist and not be in another group)
tvault env group add staging --group liftclub --project liftclub-staging

# Remove an environment (the project is NOT deleted)
tvault env group remove staging --group liftclub

# Delete the group entirely (projects and secrets are untouched)
tvault env group delete liftclub -y
```

| Command | Flags |
| --- | --- |
| `env group add <env>` | `--group <name>` (required), `-p`, `--project <name>` (required) |
| `env group remove <env>` | `--group <name>` (required) |
| `env group delete <name>` | `-y`, `--yes` — skip the confirmation prompt |

## Diff: detect drift across environments

`env diff` compares the **key sets** across all environments in a group. By default it is metadata-only — no unlock, no decryption, fast.

```bash
tvault env diff liftclub
tvault env diff liftclub --values      # also compare values (same/different; needs unlock)
tvault env diff liftclub --keys-only   # force key-set-only (no decryption)
tvault env diff liftclub --json
```

The key-set diff produces a table of `✓` / `✗` per environment and a per-key verdict:

```
KEY              PRODUCTION  PREVIEW  STAGING  STATUS
DATABASE_URL      ✓           ✓        ✗       drift
STRIPE_SECRET     ✓           ✓        ✓       same
API_TOKEN         ✓           ✗        ✓       drift
```

`--values` upgrades the verdict from presence-only to `same` / `different` by decrypting each value, but **values are never printed** — only the verdict. Each decryption with `--values` is audited, just like a `get`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No drift — every environment has the same key set. |
| `1` | Drift detected (missing or extra keys). |
| `2` | Group not found. |
| `3` | Vault is locked (only with `--values`). |

## Promote: copy values between environments

`env promote` decrypts a value from the source environment's project and re-encrypts it into the target environment's project, creating a **new version** (the prior value is archived, so `tvault history` and `tvault rollback` still work). Each promoted key gets an audit entry: `secret.promote`.

```bash
tvault env promote DATABASE_URL --group liftclub --from preview --to production
tvault env promote --all --group liftclub --from preview --to production --dry-run
tvault env promote --all --group liftclub --from preview --to production --yes
```

| Flag | Description |
| --- | --- |
| `--group <name>` | Group name (required). |
| `--from <env>` | Source environment (required). |
| `--to <env>` | Target environment (required). |
| `<keys...>` | Positional keys to promote. Omit when using `--all`. |
| `--all` | Promote every key whose value differs between source and target. |
| `--dry-run` | Show what would change without writing. |
| `-y`, `--yes` | Skip the confirmation prompt (required for non-interactive runs). |

:::: warning Promote copies real values
Unlike inheritance, promote is a real write: it decrypts the source value and stores a new secret in the target project. The target project's DEK encrypts the copy, and the prior value is archived as a version. Use `--dry-run` first when you are unsure of the blast radius.
::::

## Inherit: resolve missing keys from a base

Inheritance is **metadata-only**. You point a child environment at a base; at read time, any key missing from the child is resolved from the base instead. No values are copied, so there is nothing to keep in sync — change the base and every inheriting child sees the new value on the next read.

```bash
tvault env inherit --group liftclub --env preview --from production
```

| Flag | Description |
| --- | --- |
| `--group <name>` | Group name (required). |
| `--env <child>` | The environment that will inherit (required). |
| `--from <base>` | The environment to inherit missing keys from (required). |

Resolution order for a key in an inheriting environment:

1. The child project's own value, if the key exists locally (including a pinned value — see below).
2. Otherwise, the base environment's value for that key.
3. If the key is not found anywhere, `ErrSecretNotFound` (exit code `4`).

### Pin and unpin a single key

`env pin` writes the *currently resolved* value of a key into the child project, breaking inheritance for **that key only**. After pinning, the child has its own local copy and no longer falls back to the base. `env unpin` deletes that local copy and restores inheritance.

```bash
tvault env pin API_TOKEN --group liftclub --env preview
tvault env unpin API_TOKEN --group liftclub --env preview
```

| Command | Flags |
| --- | --- |
| `env pin <key>` | `--group <name>` (required), `--env <child>` (required) |
| `env unpin <key>` | `--group <name>` (required), `--env <child>` (required) |

### List inherited vs. local keys

```bash
tvault env inherited --group liftclub --env preview
```

```
KEY             INHERITED-FROM   PINNED
DATABASE_URL    production       no
API_TOKEN       —               yes
```

A `—` in `INHERITED-FROM` means the key is local to the child (not inherited). `PINNED=yes` means the child has its own copy and inheritance is broken for that key.

## Seal: ship every environment in one blob

`env seal` packs all (or a subset of) environments' secrets into a single `.env.encrypted` **v2** blob, keyed by environment name. The output is ciphertext only — secret values are never returned to the terminal.

```bash
tvault env seal --group liftclub --recipient tvault1ci… -o ci/migration.sealed
tvault env seal --group liftclub --keys DATABASE_URL,STRIPE_SECRET_KEY --recipient tvault1ci…
tvault env seal --group liftclub --envs production,preview --recipient tvault1ci…
```

The blob contains one section per environment:

```
--- tvault-env:production ---
KEY=value
--- tvault-env:preview ---
KEY=value
--- end ---
```

| Flag | Description |
| --- | --- |
| `--group <name>` | Group name (required). |
| `--recipient <tvault1…>` | X25519 recipient (repeatable; required). |
| `-o`, `--out <file>` | Write to a file (default: stdout). |
| `--keys <list>` | Specific keys to include (comma-separated or repeatable). |
| `--envs <list>` | Specific environments to include (comma-separated or repeatable). |

### Decrypt one environment in CI

Because the blob is v2 (recipient-encrypted, KEK-independent), CI decrypts it with an identity, no passphrase and no vault unlock. Use `--section` to extract a single environment:

```bash
tvault decrypt-env -i ci/migration.sealed --identity ci-key --section production
```

Without `--section`, the full multi-environment plaintext is returned. See [Committable secrets](/guide/committable-secrets) for the v2 format and identity model.

## In the studio

When the active project is part of an environment group, the [studio](/guide/studio) adds three bindings and annotates the panes:

| Key | Action |
|-----|--------|
| `g` | Cycle to the next environment in the group (loads its secrets). |
| `D` | Show a drift overlay — the key-set diff across all environments. |
| `G` | List all env groups with their environments and inheritance. |

The Secrets pane marks inherited keys with `←` and pinned keys with `◈`. The Projects pane annotates grouped projects with their env name (e.g. `·production`, `·preview`).

## Over MCP

The same surface is available to AI agents over MCP — discover it with `tvault docs features`. The env-group tools are metadata- or ciphertext-only: `vault_env_group_*` manage membership, `vault_env_diff` reports drift, `vault_env_promote` copies values (audited), `vault_env_inherit` / `vault_env_pin` / `vault_env_unpin` / `vault_env_inherited` manage inheritance, and `vault_env_seal` produces a recipient-sealed blob. None of them return a raw secret value. See the [MCP tools reference](/mcp/tools).

## Exit codes

Env-group commands use the standard TinyVault exit codes:

| Code | Meaning |
| --- | --- |
| `0` | OK (or, for `env diff`, no drift). |
| `1` | Generic error (or, for `env diff`, drift detected). |
| `2` | Group not found (`env diff`). |
| `3` | Vault is locked (`env diff --values`, `env promote`, `env pin`, `env seal`, …). |
| `4` | Secret or project not found. |

## See also

- [Projects](/guide/projects) — create the projects you link as environments.
- [Concepts](/guide/concepts) — KEK, per-project DEKs, and why each environment keeps its own key.
- [Committable secrets](/guide/committable-secrets) — the v2 blob format that `env seal` produces.
- [Interactive studio](/guide/studio) — the `g` / `D` / `G` bindings for grouped projects.
- [CLI reference](/cli/) — every `env` subcommand and flag.