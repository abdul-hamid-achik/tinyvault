---
title: Architecture
description: How TinyVault works under the hood — its two-tier key hierarchy, AES-256-GCM and Argon2id internals, the X25519 recipient layer, DEK rotation, versioning, and single-file bbolt storage.
---

# Architecture

This page is the deep technical design of TinyVault: the *how* behind the binary. For the conceptual model first, read [Concepts](/guide/concepts); for the threat model and what TinyVault does and does not defend against, read [Security](/reference/security).

TinyVault is a single Go binary, `tvault`. The same binary is the CLI, an interactive terminal [studio](/guide/studio), and (via the `mcp` subcommand) an [MCP server](/mcp/) for AI agents. All three sit on one vault API and one encrypted file on disk. There are no servers, no accounts, and no network calls.

## The big picture

```
            passphrase
                │  Argon2id (memory-hard)
                ▼
              KEK ───────────────► verifier check (unlock)
                │  AES-256-GCM
                │  (wrap / unwrap)
                ▼
   per-project DEK ◄──────────── recipient stanzas (X25519, for sharing)
                │  AES-256-GCM
                ▼
         secret values  +  version history
                │
                ▼
   single bbolt file: ~/.tvault/vault.db  (0600, in a 0700 dir)
                │
   ┌────────────┼────────────┐
   ▼            ▼            ▼
  CLI        studio TUI   MCP server
```

Three layers sit on top of one storage file:

1. A symmetric key hierarchy that turns your passphrase into the key that encrypts values.
2. An asymmetric recipient layer that wraps a project key to other people or machines, so secrets can be shared and committed without sharing the passphrase.
3. A single bbolt file holding everything, exposed through one API to three front ends.

## Two-tier key hierarchy

TinyVault never encrypts a secret value directly with your passphrase. It uses a two-tier hierarchy so that rotating the passphrase is cheap and so that each project can be shared independently.

```
passphrase
   │  Argon2id(salt) → 32-byte key
   ▼
  KEK                       (Key Encryption Key, RAM only while unlocked)
   │  AES-256-GCM wrap
   ▼
project DEK (one per project)   (Data Encryption Key, stored wrapped)
   │  AES-256-GCM
   ▼
secret values + version history
```

| Tier | What it is | How it is protected | Where it lives |
| --- | --- | --- | --- |
| Passphrase | What you type | Never stored | Your head |
| KEK | 32-byte key derived from the passphrase | Argon2id, salted | In RAM only while the vault is unlocked |
| DEK | One 32-byte key per project | AES-256-GCM-wrapped by the KEK | In the project record on disk (wrapped) |
| Values | Your secret data and its history | AES-256-GCM under the project DEK | In the `secrets` and `secret_versions` buckets |

The KEK is derived on the fly at unlock and held in memory only while the vault is open. Each project gets its own DEK, wrapped by the KEK and stored alongside the project record. Values (and their history) are encrypted under the project's DEK. This is why a passphrase change does not have to touch a single secret value, and why one project can be shared with someone without exposing any other project.

### Argon2id key derivation

Your passphrase becomes the KEK through Argon2id, a memory-hard function that resists GPU and ASIC cracking. The same parameters back password hashing in the vault.

| Parameter | Value |
| --- | --- |
| Algorithm | Argon2id |
| Time / iterations | 3 |
| Memory | 64 MiB |
| Parallelism | 4 threads |
| Salt | 16 random bytes, per vault |
| Output | 32 bytes (the KEK) |

A fresh 16-byte salt is generated per vault and stored with the vault metadata. Derivation costs roughly 200 ms — slow enough to make offline guessing expensive, fast enough that interactive unlock feels instant.

::: tip Use a long passphrase
Argon2id raises the cost per guess, but it cannot rescue a weak passphrase. The strength of everything below the KEK ultimately rests on your passphrase entropy. Prefer a long, unique passphrase.
:::

### AES-256-GCM for everything symmetric

Both DEK wrapping and value encryption use AES-256-GCM, an authenticated cipher.

| Detail | Value |
| --- | --- |
| Key size | 32 bytes (AES-256) |
| Nonce | 12 random bytes, fresh per operation, prepended to the output |
| Auth tag | 16 bytes |
| Wire format | `nonce(12) ‖ ciphertext ‖ tag(16)` |

Every encryption draws a fresh random 12-byte nonce and prepends it, so the same plaintext encrypts to different ciphertext each time. On decrypt, the 16-byte authentication tag is verified before any plaintext is returned.

::: info Authenticated, never partial
If the tag does not verify — because the ciphertext, nonce, or wrapped DEK was tampered with, or the wrong key was used — decryption returns an error and **no plaintext at all**. There is no "best effort" partial decryption. This is what makes a wrong passphrase, a corrupted file, or a flipped bit a clean failure rather than silent corruption.
:::

### Verifier-based unlock

To check a passphrase, TinyVault does not decrypt any secret. It stores a verifier: `AES-256-GCM(KEK, "tinyvault-verify-v1")`. On unlock it derives the candidate KEK, attempts to open the verifier, and the GCM tag check tells it whether the passphrase was right — without reading or revealing any value.

This is why a wrong passphrase exits with code `6` long before any secret is touched, and why the vault can confirm "you're in" with nothing decrypted.

### Memory hygiene

The KEK and DEKs are sensitive only while the process holds them. After use they are zeroed out of memory (the `ZeroBytes` helper overwrites the buffer). The recipient layer zeroes ECDH shared secrets and derived wrap keys the moment they are no longer needed.

::: warning Memory zeroing is best-effort
Go is a garbage-collected language, so zeroing reduces but cannot fully guarantee that no copy of a key lingers (the runtime may move buffers). It is a hardening measure, not an absolute guarantee. See [Security](/reference/security) for the full picture.
:::

### Passphrase rotation is cheap

Because values are encrypted under DEKs, not under the KEK, `tvault key rotate` only re-derives the KEK under a fresh salt and re-wraps each project DEK. Secret values are never re-encrypted, so rotation is fast and leaves version history untouched.

```bash
# Rotate the passphrase: new salt, new KEK, re-wrap every DEK
tvault key rotate
```

::: warning Rotation invalidates v1 .env.encrypted files
A v1 `.env.encrypted` file is bound to the KEK, so rotating the passphrase invalidates v1 files written under the old one. The commit-safe **v2** format is KEK-independent and is unaffected — see [Committable secrets](/guide/committable-secrets).
:::

## The recipient layer (asymmetric sharing)

The symmetric hierarchy above answers "how do I encrypt my own secrets." The recipient layer answers "how do I let someone else — a teammate, a CI runner, an agent on another machine — open a project, without handing them my passphrase."

It is built on standard, vendored primitives. There is **no new crypto dependency** — no `filippo.io/age`. It uses only `crypto/ecdh` from the standard library plus `chacha20poly1305` and `hkdf` from the already-vendored `x/crypto`.

### Identities and recipients

An identity is an X25519 keypair, completely independent of your vault passphrase. The public half is a *recipient* you can share; the private half is the *identity* you keep secret.

| Key | Prefix | Encoding | Safe to share? |
| --- | --- | --- | --- |
| Public recipient | `tvault1...` | lowercase, unpadded base32 | Yes — shareable, commit-safe |
| Private identity | `tvault-key1...` | lowercase, unpadded base32 | No — never commit or share |

Identities live at `~/.tvault/identities/<name>.key` (mode `0600`) and are created with:

```bash
tvault identity new laptop
tvault identity list
```

::: danger identity export prints a private key
`tvault identity export` prints the `tvault-key1...` **private** key to stdout. It is TTY-guarded: it refuses to dump a private key into a pipe or file unless you force it. Treat its output like a password — anyone with it can open every project shared to that identity. See [Sharing](/guide/sharing) and [CI/CD](/guide/ci-cd) for how to move identities to machines safely.
:::

### The stanza format

To share a project, TinyVault wraps that project's DEK to each recipient, producing one independently-openable **stanza** per recipient. The scheme is the standard ECIES / sealed-box construction.

```
For each recipient:
  ephemeral X25519 keypair  (eph_priv, eph_pub)
  shared   = ECDH(eph_priv, recipient_pub)
  wrap_key = HKDF-SHA256(
               ikm  = shared,
               salt = eph_pub ‖ recipient_pub,
               info = "tvault-recipient-v1")
  stanza   = 0x01 ‖ eph_pub(32) ‖ nonce(12)
             ‖ ChaCha20-Poly1305(wrap_key, DEK, AAD = eph_pub)
```

| Field | Size | Purpose |
| --- | --- | --- |
| Version byte | 1 (`0x01`) | Format agility |
| Ephemeral public key | 32 | The throwaway X25519 public key for this stanza |
| Nonce | 12 | ChaCha20-Poly1305 nonce |
| Ciphertext + tag | DEK length + 16 | The wrapped DEK, with `eph_pub` as additional authenticated data |

The HKDF `info` string domain-separates this construction from any other use of the same ECDH output, and the salt binds the wrap key to both the ephemeral and recipient public keys. The ephemeral public key is fed in as AAD so the stanza header cannot be swapped. To open a stanza, a recipient runs ECDH with their private identity against the ephemeral public key, re-derives the same wrap key, and decrypts. TinyVault tries each stanza against your identity and returns the DEK from the first that opens.

This is the foundation for [sharing](/guide/sharing), [committable secrets](/guide/committable-secrets) (the v2 `.env.encrypted` format), and the [git filter](/guide/git-filter).

## DEK rotation on revocation

Sharing is easy to add; the hard part is taking it back. `tvault projects unshare` is **true revocation**, not a paper exercise.

```bash
tvault projects unshare myapp tvault1exampleRecipient
```

When you remove a recipient, `store.RekeyProject` runs atomically and:

1. Generates a **fresh** project DEK.
2. Re-encrypts **every current value** with the new DEK.
3. Re-encrypts the **full version history** with the new DEK.
4. Re-wraps the new DEK to the **remaining** recipients only.

```
unshare recipient R:
  old_DEK ──► new_DEK (fresh random)
  re-encrypt: all current values   → under new_DEK
  re-encrypt: all secret_versions  → under new_DEK
  re-wrap:    new_DEK → remaining recipients (R gets no stanza)
  (all in one transaction)
```

Because the DEK itself changes, a removed recipient loses access even if they kept an old copy of the entire vault file — their identity can no longer derive a key that opens any value. Merely re-wrapping the *same* DEK to fewer recipients would be security theater (the old stanza in the old copy still works), so TinyVault deliberately does not do that.

::: warning Revocation cannot un-read what was already read
Rotation stops future access. It cannot retract a value a recipient already decrypted and copied. After revoking a recipient, rotate the underlying credential at its source (the database password, the API key, and so on).
:::

## Versioning storage

Every value has history, and it is kept encrypted just like the current value.

- The current value lives in the `secrets` bucket.
- Prior values live in a separate `secret_versions` bbolt bucket, keyed `projectID/key/version` with a zero-padded version number.
- `SetSecret` **archives the prior entry before overwriting, in the same transaction** — it is all-or-nothing. Either the new value lands and the old one is archived, or nothing changes.
- Version numbers are **monotonic and never reused**. Rollback is **non-destructive**: it re-stores an old version as a new version rather than deleting anything.

```bash
tvault history DATABASE_URL          # list versions
tvault get DATABASE_URL --version 3  # read a specific past version
tvault rollback DATABASE_URL --to 3  # restore v3 as a new, current version
```

Because history is encrypted under the **project DEK** (not the KEK):

- It survives passphrase rotation untouched (rotation only re-wraps DEKs).
- It is re-encrypted whenever the DEK rotates (revocation), keeping it consistent with current values.

See [Versioning](/guide/versioning) for the full workflow.

## Single-file bbolt storage

Everything — projects, wrapped DEKs, the verifier, current values, history, recipient stanzas, audit records — lives in one bbolt file:

```
~/.tvault/vault.db        # the vault file, mode 0600
~/.tvault/                # the directory, mode 0700
~/.tvault/identities/     # per-identity keypairs, each 0600
```

bbolt is an embedded, single-writer key/value store. There is no daemon, no socket (except the optional [agent](/guide/agent)), and no network. You can point `tvault` at a different location with the `--vault <dir>` global flag, which is handy for tests and isolated profiles.

::: danger Never commit the vault or identities
`~/.tvault/vault.db` and any `tvault-key1...` private identity must never be committed or backed up unencrypted to a shared location. The public `tvault1...` recipients are the only key material that is safe to share. The commit-safe path for secrets is the v2 `.env.encrypted` format in [Committable secrets](/guide/committable-secrets).
:::

## Three interfaces, one API

The CLI, the studio TUI, and the MCP server are thin front ends over the same vault API. They share the same crypto, the same storage, and the same audit log. The differences are in surface and policy, not in how secrets are handled underneath.

| Interface | How you reach it | Notes |
| --- | --- | --- |
| CLI | `tvault ...` | The primary surface; everything below is also reachable here. |
| Studio TUI | `tvault studio` (aliases `browse`, `ui`) | Read-only by default; `--rw` enables audited in-app edits. |
| MCP server | `tvault mcp` | For AI agents; uses the same API under an access policy. |

### Global flags

Every command accepts the same global persistent flags, plus `-h`/`--help` everywhere. `--version` is root-only (there is no `version` subcommand).

| Flag | Meaning |
| --- | --- |
| `--config <file>` | Use a specific config file |
| `--vault <dir>` | Use a specific vault directory |
| `-p`, `--project <name>` | Operate on a named project |
| `--json` | Machine-readable JSON output |
| `-v`, `--verbose` | More detailed output |
| `--no-agent` | Bypass the local [agent](/guide/agent), unlock directly |

See [Configuration](/reference/configuration) and [Environment variables](/reference/environment-variables) for the full set of knobs, and [Exit codes](#exit-codes) below for scripting.

### MCP and the studio: same crypto, stricter output

The MCP server gives an AI agent the same vault API, but under an [access policy](/mcp/access-policy). Two honesty points matter at the architecture level.

::: danger Output redaction is a safety net, not a control
The MCP server redacts secret values from tool output, but redaction only replaces literal value strings longer than 3 characters. It can be evaded by transforming a value (encoding it, splicing it, computing on it). Do not rely on redaction to keep a value from an agent that can run code. The real control is **not exposing the value in the first place** — which is why the MCP server **never returns a raw secret value, except `vault_get_secret`** (and that tool warns). Secret generation lives only over MCP as `vault_generate_secret`; auditing is internal and surfaced as `vault_audit_log` and in the studio — there is no `tvault generate` or `tvault audit` CLI command. See [MCP tools](/mcp/tools).
:::

The studio is read-only by default. With no flags it never writes; its only decryption is the on-demand reveal, which is audited exactly like `tvault get`. The `--rw` flag enables audited in-app edits that reuse the CLI's own `SetSecret`/`DeleteSecret` path. See [Studio](/guide/studio).

### Other plaintext-output surfaces

::: warning k8s render emits plaintext
`tvault k8s render` produces a **plaintext** Kubernetes manifest. Pipe it straight to `kubectl` — never commit it.

```bash
tvault k8s render | kubectl apply -f -
```
:::

The local [agent](/guide/agent) is an optional, opt-in convenience that caches the KEK over a private socket to skip repeated Argon2id. Its capability tokens are privilege separation for an **OS-confined, different-uid delegate only** — they are **not** a defense against a malicious process running as your own uid, which can read the token or dial the socket directly. See the [agent guide](/guide/agent) and [Security](/reference/security).

## Exit codes

Front ends share one set of exit codes, which makes scripting and CI predictable.

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Generic error |
| `3` | Vault is locked at rest |
| `4` | Secret or project not found |
| `5` | Vault not initialized |
| `6` | Wrong passphrase |
| `7` | Vault database is in use by another process |

```bash
tvault get DATABASE_URL
case $? in
  0) ;;                        # got it
  3) echo "vault locked"     >&2 ;;
  4) echo "no such secret"   >&2 ;;
  5) echo "run: tvault init" >&2 ;;
  6) echo "wrong passphrase" >&2 ;;
esac
```

## See also

- [Concepts](/guide/concepts) — the mental model, without the crypto internals
- [Security](/reference/security) — threat model and the honest limits of each control
- [Key management](/guide/key-management) — rotation, locking, and KEK lifecycle in practice
- [Sharing](/guide/sharing) — the recipient layer from the user's side
