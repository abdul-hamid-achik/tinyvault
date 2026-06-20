---
title: Troubleshooting & FAQ
description: Fixes for common TinyVault issues — locked vaults, wrong passphrase, MCP servers that won't connect, the agent on Windows, "no recipients", and exit codes.
---

# Troubleshooting & FAQ

Quick fixes for the things people actually hit. For the long-form CLI manual, `tvault help troubleshooting`.

## Exit codes

`tvault` returns meaningful exit codes, so scripts can branch on them:

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Generic error |
| `3` | Vault is locked |
| `4` | Secret or project not found |
| `5` | Vault not initialized |
| `6` | Wrong passphrase |

## "Vault is locked" / "wrong passphrase"

The vault is encrypted; reads need it unlocked.

- Interactively: `tvault unlock` (or just run a command — you'll be prompted).
- Non-interactively (CI, scripts, MCP): set `TVAULT_PASSPHRASE` in the environment. See [Environment Variables](/reference/environment-variables).
- Exit code `6` means the passphrase was wrong; `3` means it's locked and no passphrase was available.

## "vault not found" / "not initialized"

Exit code `5`. Create a vault first:

```bash
tvault init
```

By default the vault lives at `~/.tvault/vault.db` (override with `--vault` or `TVAULT_DIR`). See [Configuration](/reference/configuration).

## The MCP server won't connect

The MCP server (`tvault mcp`) speaks JSON-RPC over stdio and **unlocks the vault at startup** — there is no prompt over a pipe.

- **"Connection closed" right away** → the server couldn't unlock. The host must pass `TVAULT_PASSPHRASE` in the server's `env`. The cleanest fix is a small launcher that loads it from one place — see [MCP Overview → Keeping the passphrase out of every config](/mcp/#keeping-the-passphrase-out-of-every-config).
- **`open bolt db: timeout`** → another `tvault` process already holds the vault. The on-disk store ([bbolt](https://github.com/etcd-io/bbolt)) is **single-writer**, so a running MCP server or [agent](/guide/agent) locks the file. Stop the other process (e.g. the previous MCP connection, or `tvault agent stop`) and retry. After changing the passphrase, **restart your agent/MCP sessions** so they reconnect.
- **Tools appear but calls are denied** → the [Access Policy](/mcp/access-policy) is gating them (`access_mode`, `allow_exec`, project/secret globs). Check `~/.tvault/mcp-policy.yaml`.

## `tvault agent` says "unix-only"

The [local agent](/guide/agent) is **Linux/macOS only** — on Windows it returns "unsupported platform". Use the direct CLI or the [MCP server](/mcp/) instead; both work everywhere.

## "project has no recipients"

`vault_export_env_encrypted` (and `tvault seal` with no `--recipient`/`.tvault-recipients`) seal to the project's *current* recipients. If none are set, share the project first:

```bash
tvault projects share tvault1…          # CLI
```

…or use `tvault seal --recipient tvault1…` / `vault_seal_for_recipients` with explicit recipients. See [Sharing](/guide/sharing) and [Committable Secrets](/guide/committable-secrets).

## `tvault studio` won't start

The [studio](/guide/studio) needs an **interactive terminal** — it refuses to run under `TERM=dumb` or when stdout isn't a TTY (e.g. piped, or some CI shells). Run it in a real terminal, or use the CLI/MCP for non-interactive access.

## "identity export refuses to print"

`tvault identity export` prints a **private key**, so it refuses to write to a non-terminal (to avoid landing in a captured log). Pipe it deliberately with `--force`:

```bash
tvault identity export ci --force | gh secret set TVAULT_IDENTITY_KEY
```

## Rotating the passphrase broke my `.env.encrypted`

`tvault key rotate` re-wraps the vault keys but **invalidates v1 (passphrase-tied) `.env.encrypted` files**. Use the **v2, recipient-based** format (`encrypt-env --recipient` / `seal`), which is KEK-independent and survives rotation. See [Committable Secrets](/guide/committable-secrets).

## FAQ

**Where is my data?** One encrypted file at `~/.tvault/vault.db` (`0600`), in a `0700` directory. Identities, optional config, and the MCP policy live beside it. See [Configuration](/reference/configuration).

**I forgot my passphrase — can I recover it?** No. There is no escrow or recovery key by design (local-first). Keep a backup of the passphrase (e.g. in a password manager). You *can* still share/recover *projects* via [identities](/guide/sharing) if you set them up beforehand.

**Can an AI agent read my secret values?** Not unless you let it. Every MCP tool returns metadata or ciphertext except `vault_get_secret`, which returns a value *with a warning*. Prefer `vault_run_with_secrets`. See the [MCP safety model](/mcp/) and [Security](/reference/security).

**Is it safe to commit `.env.encrypted` / `.tvault-recipients`?** Yes — `.env.encrypted` is ciphertext and `.tvault-recipients` holds only public keys. Never commit `~/.tvault/`, `*.key` identity files, or a plaintext `.env`.

**Does it work on Windows?** The CLI and MCP server: yes (amd64/arm64). The unlock-once agent: no (unix only).

**How do I back up the vault?** `tvault backup <path>` copies the still-encrypted `vault.db`; the passphrase is still required to use it. See [Key Management](/guide/key-management).

## See also

- [CLI Reference](/cli/) — every command, flag, and the exit-code table
- [Environment Variables](/reference/environment-variables) — `TVAULT_PASSPHRASE`, `TVAULT_DIR`, identities
- [MCP Overview](/mcp/) — setup, the launcher pattern, and the safety model
- [Security & Threat Model](/reference/security) — what is and isn't protected
