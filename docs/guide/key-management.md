---
title: Key Management & Maintenance
description: Rotate the TinyVault passphrase, back up and restore its local database, run read-only diagnostics, and understand per-process locking — the day-two operations for tvault.
---

# Key Management & Maintenance

These are the day-two operations for a TinyVault vault: rotating the passphrase, taking and restoring backups, checking health with read-only diagnostics, and understanding lock state. They operate on the local `vault.db` file and do not call a hosted TinyVault service.

## How the key hierarchy works (the 30-second version)

Knowing the key layout makes the rest of this page obvious — especially why rotation is cheap and which parts of a backup remain protected.

- Your **passphrase** is stretched through Argon2id into a **KEK** (key-encryption key). The KEK lives in RAM only while the vault is unlocked.
- Each project has its own **DEK** (data-encryption key). Every DEK is AES-256-GCM-wrapped by the KEK and stored inside the project record.
- **Secret values** (and their version history) are encrypted with the project DEK.

So the passphrase guards the KEK, the KEK guards the DEKs, and the DEKs guard the values. Rotating the passphrase only re-wraps the DEKs — the values themselves never move.

::: info
The vault is a single bbolt file at `~/.tvault/vault.db` (mode `0600`, in a `0700` directory). There are no servers, accounts, or cloud calls. See [Architecture](/reference/architecture) for the full crypto design.
:::

## Rotate the passphrase

Use `tvault key rotate` to re-encrypt the vault under a **new passphrase**. It derives a fresh KEK under a new salt and re-wraps every project DEK with it. Secret **values are not re-encrypted**, so rotation is fast and safe to run often — even on a large vault.

```bash
tvault key rotate
```

The command is interactive: it prompts for your current passphrase to unlock, then for the new passphrase (entered twice to confirm). On success it reports `Passphrase rotated successfully`.

::: tip Rotation is prompt-driven by design
`key rotate` always reads the new passphrase from an interactive prompt — there is no environment variable to supply it non-interactively. That keeps a fresh secret out of shell history and process listings. Run it from a terminal.
:::

### What rotation does and does not do

| Affected by rotation | Untouched by rotation |
| --- | --- |
| The KEK (new salt, new derivation) | Secret values in the `secrets` bucket |
| The wrapped DEK on every project | The version history in `secret_versions` |
| The passphrase verifier | Recipient stanzas (X25519 shares) |

Because values and history are encrypted under the project DEK — not the KEK — they survive a passphrase rotation completely untouched.

::: warning v1 `.env.encrypted` files are invalidated
A **v1** committable file (made with `tvault encrypt-env` **without** `--recipient`) is tied to the passphrase. After you rotate, old v1 ciphertext can no longer be decrypted with the new passphrase — re-encrypt those files.

This does **not** affect **v2** files (made with `--recipient`), which are keyed to X25519 identities and are independent of the passphrase. Prefer v2 for anything you commit. See [Committable Secrets](/guide/committable-secrets).
:::

::: tip Rotate the passphrase vs. rotate a DEK
`key rotate` changes the passphrase. To rotate a **project's DEK** (re-encrypting every value in the updated live vault), remove a recipient with `tvault projects unshare`, which atomically generates a new DEK and re-encrypts all current values and history. Pre-removal snapshots remain readable under the old DEK; see [Sharing Secrets](/guide/sharing).
:::

## Back up the vault

`tvault backup <path>` writes a byte copy of `vault.db` to the path you give. Secret payloads and key material stay encrypted, so decrypting values still requires the passphrase or a matching recipient identity. Operational metadata — including project and key names, timestamps, versions, configuration, and audit rows — remains readable to anyone who can inspect the backup.

```bash
# Timestamped backup into a directory you control
tvault backup ~/backups/tvault-$(date +%Y%m%d).db
```

The vault does **not** need to be unlocked to take a backup; the command copies the database without decrypting its records. Still treat every backup as sensitive because its metadata is visible and its ciphertext can be attacked offline. Store it only in a location whose access and retention you control.

::: warning Keep your passphrase and identities with your strategy
Restoring the complete owner view of a `vault.db` snapshot requires the passphrase that derived its KEK. A matching private recipient identity can instead recover only the projects that snapshot shared with it. Preserve the snapshot's passphrase and any identities your recovery plan relies on; if every matching credential is lost, there is no recovery service.
:::

::: danger Never commit a vault or a private key
Do not commit `~/.tvault/`, `vault.db`, any backup of it, or any `tvault-key1...` private identity to source control. Only `tvault1...` public recipients are commit-safe.
:::

## Restore the vault

`tvault restore <path>` overwrites the current `~/.tvault/vault.db` with the backup at `<path>`. This is destructive: the existing vault file is replaced.

```bash
# Prompts for confirmation before overwriting
tvault restore ~/backups/tvault-20260619.db

# Skip the confirmation prompt (for scripts / automation)
tvault restore ~/backups/tvault-20260619.db -y
```

After restoring, the vault uses the passphrase that was in effect when **that backup** was taken — restoring does not change which passphrase unlocks it.

| Flag | Purpose |
| --- | --- |
| `-y`, `--yes` | Skip the confirmation prompt and overwrite the current vault. |

::: warning `restore` overwrites in place
There is no automatic safety copy. If the current vault has changes that are not in your backup, take a fresh `tvault backup` first.
:::

## Read-only diagnostics

Two commands report on the vault without changing it. Neither ever prints the passphrase.

### `tvault status`

Shows a quick summary of the vault — where it lives, whether it is initialized, the active project, and lock state. Use it as a human-friendly health check.

```bash
tvault status
tvault status --json   # machine-readable
```

`--json` is a global flag, so it works the same way on every command.

### `tvault doctor`

Runs a set of read-only health checks (file permissions, vault integrity, configuration sanity) and **exits non-zero if any check fails**. That makes it ideal for scripts and CI gates.

```bash
tvault doctor
echo "exit: $?"
```

```bash
# Fail a pipeline early if the vault is unhealthy
tvault doctor || exit 1
```

::: tip Diagnostics are non-destructive
`status` and `doctor` are strictly read-only — they never write to the vault and never print secret values or your passphrase. Run them freely.
:::

#### Exit codes

`doctor` (and every other command) uses a stable exit-code contract, which is what makes it scriptable:

| Code | Meaning |
| --- | --- |
| `0` | OK |
| `1` | Generic error |
| `3` | Vault is locked |
| `4` | Secret or project not found |
| `5` | Vault not initialized |
| `6` | Wrong passphrase |

## Lock and unlock

`tvault unlock` validates your passphrase and confirms the vault can be opened. Both `unlock` and `lock` run in short-lived processes; neither creates or clears a persistent session.

```bash
tvault unlock   # prompts for the passphrase, verifies it, then exits
tvault lock     # clears only this command's in-memory vault handle
```

The passphrase check uses a dedicated **verifier** — AES-256-GCM over a fixed constant — so `unlock` can confirm the passphrase is correct **without reading any secret**. After use, the KEK and DEKs are zeroed from memory.

::: info Locking, the agent, and per-command unlock
Most commands (`get`, `env`, `run`, …) unlock on demand and clear their key material when they finish, so you do not normally manage lock state by hand. If you run the optional [local agent](/guide/agent), it holds the KEK so those commands skip the prompt. `tvault lock` does not control that process; use `tvault agent stop` (or a termination signal) to clear the agent's cached key. Use `--no-agent` on any command to force a direct unlock.
:::

## Common maintenance recipes

A passphrase rotation with a backup on either side:

```bash
tvault backup ~/backups/tvault-pre-rotate.db
tvault key rotate
tvault doctor && tvault backup ~/backups/tvault-post-rotate.db
```

A nightly cron-safe backup that fails loudly if the vault is unhealthy:

```bash
tvault doctor && tvault backup "$HOME/backups/tvault-$(date +%F).db"
```

::: tip Global flags apply here too
Every command accepts the global flags `--config <file>`, `--vault <dir>`, `-p`/`--project <name>`, `--json`, `-v`/`--verbose`, and `--no-agent`. Use `--vault` to operate on a non-default vault location, for example when restoring into a fresh directory before promoting it.
:::

## See also

- [Versioning & Rollback](/guide/versioning) — prior values, history, and non-destructive rollback.
- [Sharing Secrets](/guide/sharing) — DEK rotation, live-vault recipient removal, and retained-data limits.
- [Architecture](/reference/architecture) — the full key hierarchy and crypto design.
- [Security & Threat Model](/reference/security) — what TinyVault does and does not protect against.
