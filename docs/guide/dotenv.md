---
title: Working with .env Files
description: Import, diff, sync, and encrypt .env files with TinyVault — a strict safe parser, value-blind diffing, one-way and mirrored sync, and passphrase-bound encrypted .env files.
---

# Working with .env Files

TinyVault treats `.env` files as a first-class input and output format. You can pull an existing file into the vault, compare a file against the vault without leaking values, keep a file and the vault in sync, and produce an encrypted `.env` for local use.

This page covers the import, diff, sync, and encrypt side of the `.env` ecosystem. To load secrets into a running process (`tvault run`) or export an environment (`tvault env`), see [Run & Environment](/guide/run-and-env).

## Import an .env file into the vault

`tvault import` reads one or more `.env` files and writes their keys into the active project. It never decrypts anything — it only writes.

```bash
# Import an explicit file
tvault import .env

# Auto-discover the default chain in the current directory
tvault import

# Discover files for a named environment
tvault import --env production

# Combine several files (later files win on duplicate keys)
tvault import --file .env --file .env.local --overwrite

# Preview without writing
tvault import --dry-run

# Decide each key interactively
tvault import --interactive
```

### Import flags

| Flag | Description |
| --- | --- |
| `--dir <path>` | Directory to discover files in (default `.`). Used by the default chain. |
| `--env <name>` | Include environment-specific files in the discovery chain (see below). |
| `--file <path>` | Add a file to import. Repeatable. |
| `--overwrite` | Overwrite keys that already exist in the project. Without it, existing keys are skipped. |
| `--dry-run` | Show what would be imported without writing. |
| `--interactive` | Prompt for each key before importing it. |

::: info Explicit file vs. discovery
An explicit file argument (`tvault import .env.staging`) cannot be combined with `--file`. Use one form or the other.
:::

### The default discovery chain

With no explicit file and no `--file`, import discovers files in `--dir` in this order, importing each one that exists:

1. `.env`
2. `.env.<env>` (only with `--env <env>`)
3. `.env.local`
4. `.env.<env>.local` (only with `--env <env>`)

Later files in the chain override earlier ones on duplicate keys, matching the conventional precedence of local overrides.

### The parser is strict on purpose

The `.env` parser is deliberately conservative, so a malicious or malformed file cannot do anything surprising:

- **No shell expansion.** Values are taken literally. `$VAR`, command substitution, and arithmetic are never evaluated. A value of `$HOME` is stored as the five characters `$HOME`.
- **Name allowlist.** Keys must look like environment variable names. Junk lines and unusual names are rejected rather than silently imported.
- **Symlinks are refused.** A `.env` file that is a symlink is rejected, so a checked-in symlink cannot redirect a read to an arbitrary path.
- **Size cap.** Files larger than 1 MiB are rejected.

::: tip Quoting and escapes
Double-quoted values support standard escapes (for example, `\n` becomes a newline); single-quoted values are literal. This is parsing only — it is not interpolation. There is no shell or `${VAR}` substitution at import time.
:::

## Diff a file against the vault

`tvault diff <file>` reports which keys are only in the file, only in the vault, or in both. By default it compares **metadata only** — key names, not values — so it does not need an unlocked vault.

```bash
# Compare key sets (no unlock, no decryption)
tvault diff .env
```

To also check whether shared keys hold the same value, add `--values`. This compares values **without ever printing them**: the output is a verdict (same or differs), never the secret itself. Because it reads vault values, `--values` requires an unlock and audits each read like `tvault get`.

```bash
# Also compare values — reports same/differs, never prints them
tvault diff .env --values
```

| Flag | Description |
| --- | --- |
| `--values` | Also compare the values of keys present on both sides. Reports same/differs; never prints values. Needs an unlock and audits each read. |

::: tip Diff before you sync
Run `tvault diff` first to see exactly what will change. Run it with `--values` to find keys that drifted between the file and the vault, without exposing them in your terminal or shell history.
:::

## Sync a file with the vault

`tvault sync` reconciles a `.env` file with the vault in one of three directions. Unlike import, sync can write in either direction.

```bash
# Vault -> file (vault is source of truth)
tvault sync --direction pull --path .env

# File -> vault (file is source of truth), allowing overwrites
tvault sync --direction push --path .env --overwrite

# Reconcile both ways
tvault sync --direction mirror --path .env
```

| Flag | Description |
| --- | --- |
| `--path <file>` | The `.env` file to sync (default `.env`). |
| `-d, --direction <pull\|push\|mirror>` | Sync direction (default `pull`). |
| `--overwrite` | Allow overwriting existing keys on the destination (applies to `push` and `mirror`). |

The directions:

- **`pull`** — write the vault to the file. The vault is the source of truth; the file is regenerated.
- **`push`** — write the file into the vault. The file is the source of truth. Without `--overwrite`, existing vault keys are left untouched.
- **`mirror`** — reconcile both ways. When a key exists on both sides with **different values**, sync reports it as a **conflict** rather than silently picking a winner.

::: warning `pull` writes plaintext to disk
`pull` writes secret values into a plaintext `.env` file. Make sure that file is gitignored and never committed. To commit secrets safely, use the encrypted v2 / `--recipient` flow described in [Committable Secrets](/guide/committable-secrets).
:::

::: info No `-p` shorthand on sync
`sync` has no `-p` shorthand for its path — use the long `--path`. The global `-p`/`--project` flag still selects the project as usual.
:::

## Encrypted .env files (v1, passphrase-bound)

`tvault encrypt-env` produces an encrypted `.env` file you can decrypt later with `tvault decrypt-env`. Used **without** `--recipient`, it creates a **v1** file that is tied to your vault passphrase.

```bash
# Encrypt a file (v1, tied to your passphrase)
tvault encrypt-env --in .env --out .env.encrypted

# Decrypt it back (format is auto-detected)
tvault decrypt-env --in .env.encrypted --out .env
```

| Command | Flags |
| --- | --- |
| `encrypt-env` | `-i, --in <file>` (default stdin), `-o, --out <file>`, `--recipient <tvault1...>` (repeatable) |
| `decrypt-env` | `-i, --in <file>`, `-o, --out <file>`, `--identity <name>` (for v2) |

`decrypt-env` auto-detects the format: a v1 file is decrypted with your passphrase, a v2 file with an X25519 identity.

::: danger v1 is invalidated by passphrase rotation
A v1 `.env.encrypted` is bound to the passphrase that was active when it was written. Running `tvault key rotate` re-wraps your DEKs under a new passphrase and **invalidates every v1 encrypted `.env` made under the old passphrase** — you will no longer be able to decrypt them. v1 is meant for local, short-lived use, not for files you keep around or commit.
:::

::: tip Want commit-safe encrypted .env files?
Pass one or more `--recipient tvault1exampleRecipient` flags to `encrypt-env` to write a **v2** file instead. v2 is asymmetric (X25519), independent of your passphrase, and safe to commit because it can only be decrypted by a holder of a matching private identity — not by anyone who simply has the file. See [Committable Secrets](/guide/committable-secrets) for the full recipient workflow, and [Git Filter](/guide/git-filter) to make this transparent in your repo.
:::

## See also

- [Run & Environment](/guide/run-and-env) — load `.env`-derived secrets into a process with `run`, and export them with `env`.
- [Committable Secrets](/guide/committable-secrets) — the commit-safe v2 / `--recipient` encrypted `.env` flow.
- [Git Filter](/guide/git-filter) — transparently encrypt and decrypt tracked `.env` files in Git.
- [Secrets](/guide/secrets) — set, get, list, and delete individual secrets.
