---
title: Projects
description: Organize TinyVault secrets into isolated projects, each with its own data encryption key, and scope any command to a project.
---

# Projects

A project is a named namespace for secrets. Every project has its own data encryption key (DEK), so the values in one project are cryptographically independent of every other project. You select a project to work in, or scope a single command to one with `-p`.

## Why projects exist

Each project's secrets are encrypted under a per-project DEK. Those DEKs are wrapped by your vault key (KEK) and never stored in the clear. Because the keys are separate, exposing or rotating one project does not affect another.

This isolation is what makes [sharing](/guide/sharing) and revocation precise: you grant or revoke access at the project level, and revocation rotates only that project's DEK. See [Concepts](/guide/concepts) for how the KEK, DEKs, and wrapping fit together.

A fresh vault already has one project named `default`, created by `tvault init`.

## Create a project

```bash
tvault projects create staging
tvault projects create prod -d "Production API and database credentials"
```

| Flag | Description |
| --- | --- |
| `-d`, `--description <str>` | Human-readable description shown in `projects list`. |

`projects` has the aliases `project` and `p`, so `tvault p create staging` works too.

## List projects

```bash
tvault projects list
```

```
NAME     DESCRIPTION                              CURRENT
default
staging
prod     Production API and database credentials  *
```

The `CURRENT` column marks your active project with `*`. For scripting, add the global `--json` flag:

```bash
tvault projects list --json
```

`projects list` also answers to the alias `ls`, so `tvault p ls` works.

## The active project

TinyVault tracks one active (current) project per vault. Commands that read or write secrets — `set`, `get`, `list`, `delete`, `env`, `run`, `export`, and others — operate on the active project unless you override it.

Switch the active project with `projects use`, or its top-level shorthand `use`:

```bash
tvault projects use prod
# identical:
tvault use prod
```

The selection is stored in the vault and persists across commands and shells until you change it.

::: info `status` and `doctor` show the active project
Run `tvault status` to see the current project (plus lock state and vault path). `tvault doctor` reports it as a read-only diagnostic and exits non-zero if a check fails.
:::

## Scoping a single command

`-p`/`--project` is a global flag on every command. Use it to act on a different project for one invocation without changing the active project:

```bash
# Read from prod without switching to it
tvault get DATABASE_URL -p prod

# Write into staging while your active project is default
tvault set API_KEY sk-xxxx -p staging

# Inject one project's secrets into a command
tvault run -p prod -- ./deploy.sh
```

### Resolution order

When a command needs a project, TinyVault picks the first of:

1. The `-p`/`--project` flag.
2. The stored active project (set by `use`).
3. `default`.

So you can pin a project once with `use` and still override it ad hoc with `-p`:

```bash
tvault use staging
tvault list                # lists staging (the active project)
tvault list -p prod        # lists prod for this one call
```

See [Environment variables](/reference/environment-variables) for the full list of supported variables.

## Delete a project

```bash
tvault projects delete staging
```

You are prompted to confirm. Skip the prompt with `-y`/`--yes` (useful in scripts):

```bash
tvault projects delete staging -y
```

::: danger Deletion is permanent
`projects delete` removes the project and every secret in it, including version history. The per-project DEK goes with it. There is no undo — take a [backup](/guide/key-management) first if you might need the data.
:::

## Sharing a project

Projects are the unit of sharing. You grant a recipient (an X25519 public key, a `tvault1…` string) access to a project, list who has access, and revoke it:

```bash
tvault projects share tvault1exampleRecipient -p prod
tvault projects recipients -p prod        # metadata only, no unlock
tvault projects unshare tvault1exampleRecipient -p prod
```

::: warning Unshare is true revocation
`projects unshare` does not merely drop a wrapped key. It rotates the project's DEK and re-encrypts every value, and every version of its history, under the new key. Re-wrapping alone would be security theater — a revoked recipient who kept the old DEK could still read old ciphertext. Rotation costs a full re-encrypt but actually removes access.
:::

The recipient model and identities are covered in depth on the [Sharing](/guide/sharing) page; for committing encrypted values to a repo, see [Committable secrets](/guide/committable-secrets).

## Exit codes

Project-scoped commands use the standard TinyVault exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Generic error |
| `3` | Vault is locked |
| `4` | Secret or project not found |
| `5` | Vault not initialized (run `tvault init`) |
| `6` | Wrong passphrase |

A missing project — for example, `use` on a name that does not exist — returns exit code `4`.

## See also

- [Concepts](/guide/concepts) — KEK, per-project DEKs, and key wrapping.
- [Secrets](/guide/secrets) — set, get, list, and delete within a project.
- [Sharing](/guide/sharing) — grant and revoke project access with recipients and identities.
- [CLI reference](/cli/) — every command and flag.
