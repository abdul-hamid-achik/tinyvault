---
title: Versioning & Rollback
description: Every overwrite of a TinyVault secret archives the prior value, so you can inspect a key's history, read any past version, and roll back without losing anything.
---

# Versioning & Rollback

TinyVault keeps the history of every secret. Each time you overwrite a key, the previous value is archived as its own version before the new value is written. You can inspect that timeline without unlocking the vault, read any specific past value, and roll back to an earlier version without losing anything.

## How versioning works

Every secret starts at version 1. When you run `tvault set` on a key that already exists, TinyVault archives the current value as a numbered version and then writes the new value as the new current version. You never opt in — versioning is always on.

```bash
tvault set DATABASE_URL "postgres://user:pass@localhost/app"   # v1
tvault set DATABASE_URL "postgres://user:pass@db.internal/app" # v2 (v1 archived)
tvault set DATABASE_URL "postgres://user:pass@db.prod/app"     # v3 (v2 archived)
```

Version numbers are monotonic and never reused. They only go up, even after a rollback (see below), so a version number is a stable, permanent handle to a specific value.

::: info Where versions live
The current value of each key lives in the `secrets` bucket of the vault. Archived values live in a separate `secret_versions` bucket, keyed by `projectID/key/version` (zero-padded). The two stay consistent by one rule: `set` archives the prior entry **and** writes the new value in the **same bbolt transaction**, so the move is all-or-nothing. There is no window where a key has lost its old value but not yet committed the new one.
:::

## Inspect a key's history

Use `tvault history` to see every version of a key with its timestamps. This is metadata only — no values are printed, and the vault does **not** need to be unlocked.

```bash
tvault history DATABASE_URL
```

```
Version history for "DATABASE_URL" (project "default"):

VERSION   CREATED                UPDATED
v1        2026-06-10 09:12:04    2026-06-10 09:12:04
v2        2026-06-12 14:30:51    2026-06-12 14:30:51
v3        2026-06-18 08:05:22    2026-06-18 08:05:22  (current)
```

The newest version is at the bottom, tagged `(current)`. The command has two aliases, `versions` and `hist`:

```bash
tvault versions DATABASE_URL
tvault hist DATABASE_URL --json
```

With the global `--json` flag you get a machine-readable object — `{key, project, versions}`, where each entry is `{version, created_at, updated_at}` — useful when an agent or script needs to find the previous version programmatically.

::: tip No unlock needed
`history` reads version metadata, not values, so it works on a locked vault. It is still recorded in the audit log (as a read against the key) for traceability.
:::

## Read a specific past value

To print the value of a particular version, pass `--version` to `tvault get`:

```bash
tvault get DATABASE_URL --version 1
```

This decrypts and prints exactly that historical value — handy for comparing the old and new secret before deciding whether to roll back. Reading a value requires an unlocked vault and is audited like any other `get`.

| Flag | Applies to | Meaning |
| --- | --- | --- |
| `--version <N>` | `get` | Print the value of version `N` instead of the current value. |
| `--from <path>` | `get` | Read the key from a dotenv file instead of the vault (no unlock; unrelated to versions). |

## Roll back to an earlier version

`tvault rollback` restores an earlier version as the new current value. The `--to <N>` flag is **required**:

```bash
tvault rollback DATABASE_URL --to 2
```

```
DATABASE_URL: rolled back to v2 (new version v3)
```

Rollback is **non-destructive**. It does not delete or rewrite history — it re-stores the chosen version's value as a brand-new current version. The value you are replacing is itself archived first, so it stays recoverable. Because version numbers are never reused, rolling back to v2 when v3 is current produces a new v4 that holds v2's value:

```bash
tvault history DATABASE_URL
# ... v3 (current) ...
tvault rollback DATABASE_URL --to 2
tvault history DATABASE_URL
# ... v4 (current)  <- holds the value from v2
```

Rollback is always safe to run: nothing is lost, and you can roll back a rollback. The operation requires an unlocked vault and is recorded in the audit log with the source and target versions.

| Flag | Meaning |
| --- | --- |
| `--to <N>` | Version number to restore. Required; the command errors if it is missing or not positive. |

::: tip Find the version first
Run `tvault history <key>` (or `tvault history <key> --json`) to see which version numbers exist before rolling back.
:::

## How history survives key changes

History is encrypted with the **per-project DEK**, the same key that protects current values. This has two practical consequences.

- **Passphrase rotation leaves history untouched.** `tvault key rotate` re-wraps each project's DEK under a new KEK but never re-encrypts the values themselves. Your full version history survives a passphrase change with no extra work — and stays just as cheap.
- **Recipient removal re-encrypts the live history too.** `tvault projects unshare <recipient>` rotates the project DEK and re-encrypts **every current value and the entire version history in the updated vault** under the fresh DEK, then re-wraps it to the remaining recipients only. The removed identity cannot read that re-keyed state. A vault snapshot copied before removal still contains the old history and recipient wrap and remains readable.

::: warning Delete purges history
`tvault delete <key>` removes the key **and all of its archived versions**. Deletion is the one operation that is destructive to history — there is no version to roll back to once a key is deleted. Use rollback, not delete, if you only want to revert a value.
:::

## Over MCP

The same two capabilities are exposed to AI agents through the MCP server. These two versioning tools return metadata only; they do not return secret values:

| MCP tool | CLI equivalent | Returns a value? |
| --- | --- | --- |
| `vault_secret_history` | `tvault history <key>` | No — version metadata only. |
| `vault_rollback_secret` | `tvault rollback <key> --to <N>` | No — reports the new version number. |

`vault_rollback_secret` performs the same non-destructive restore as the CLI, so an agent can revert a bad change without ever seeing — or being able to leak — the underlying value.

::: danger Redaction is a safety net, not a control
MCP output redaction only replaces literal secret values longer than three characters and can be evaded by transforming a value (encoding, slicing, reversing). Treat it as a guardrail against accidental leakage, not as access control. The real boundary is that history and rollback tools never emit a value in the first place.
:::

## See also

- [Secrets](/guide/secrets) — setting, reading, listing, and deleting keys.
- [Key management](/guide/key-management) — passphrase rotation and the key hierarchy that protects history.
- [Sharing](/guide/sharing) — recipients, live-vault DEK rotation, and retained-data limits.
- [MCP tools](/mcp/tools) — the full list of tools available to AI agents.
