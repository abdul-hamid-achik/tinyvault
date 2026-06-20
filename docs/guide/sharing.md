---
title: Sharing Secrets
description: Share a TinyVault project with a teammate, CI runner, or AI agent using X25519 recipients — no shared passphrase, with true cryptographic revocation.
---

# Sharing Secrets

Give someone access to a project without ever sharing your passphrase. Each recipient holds their own keypair; you wrap the project's key to their public half, and they read with their private half. Revoking is real revocation — TinyVault rotates the key and re-encrypts every value.

This is the asymmetric layer on top of the [passphrase hierarchy](/guide/key-management). Your passphrase still protects your own vault on disk; recipients never touch it.

## The model in one minute

A TinyVault identity is an X25519 keypair, independent of any passphrase:

- A **public recipient** string, `tvault1…` — shareable and safe to commit.
- A **private key** string, `tvault-key1…` — secret, stored `0600`, never commit it.

When you share a project, TinyVault wraps that project's data-encryption key (DEK) to the recipient's public half. The recipient unwraps it with their private key and reads the project — no passphrase, no unlock prompt. Revoking with `unshare` rotates the DEK and re-encrypts the whole project, so an old copy of the vault is useless to the removed recipient.

::: info Two ways to share
This page covers sharing a **live project** inside a vault (a teammate or CI runner reads it directly). To put ciphertext *in a git repo* — `.env.encrypted` files or a transparent git filter — see [Committable Secrets](/guide/committable-secrets) and [Git Filter](/guide/git-filter). Both use the same `tvault1…` recipients.
:::

## Step 1 — the recipient creates an identity

The person (or machine) who wants access runs this on **their** side. It generates a keypair and prints the public recipient string to share with you:

```bash
tvault identity new alice
```

```
Created identity 'alice'
  recipient: tvault1exampleRecipient
  key file:  ~/.tvault/identities/alice.key  (0600)
```

The name is optional and defaults to `default`. The private key stays in `~/.tvault/identities/<name>.key` and never leaves their machine. They send you only the `tvault1…` recipient string — over Slack, email, or a commit; it is not sensitive.

List local identities at any time:

```bash
tvault identity list
```

## Step 2 — the owner shares the project

Take the recipient string and grant it access. Use `-p` to pick a project, or it shares the active one:

```bash
# share the active project
tvault projects share tvault1exampleRecipient

# share a specific project
tvault projects share tvault1exampleRecipient -p webapp
```

This wraps the project's DEK to that recipient and stores the wrapped key in the project record. It does not copy or move any secret values.

Audit who can read a project — no unlock required, this is metadata only:

```bash
tvault projects recipients -p webapp
```

```
Project 'webapp' is shared with:
  tvault1exampleRecipient
```

## Step 3 — the recipient reads with their identity

Back on the recipient's side, they read the shared project with their identity instead of a passphrase. `tvault env --identity <name>` resolves the local key file, unwraps the DEK, and emits the environment:

```bash
# print export lines for the shell
tvault env --identity alice -p webapp

# or feed a process directly
eval "$(tvault env --identity alice -p webapp)"
```

`env` honors the same `--format`, `--name`, and `--namespace` options it always has — see [Run & Environment](/guide/run-and-env). The read is audited exactly like a `tvault get`.

::: tip No identity flag in scripts?
If you don't want to pass `--identity` on every call, set `TVAULT_IDENTITY_KEY` instead (next section). The recipient path also backs `tvault open` (sealed files) and the git smudge filter, so a CI runner with one identity reads everything it is entitled to.
:::

## Step 4 — revoke access (true revocation)

When someone should lose access, `unshare` them. This is not a metadata flip:

```bash
tvault projects unshare tvault1exampleRecipient -p webapp
```

```
Revoked tvault1exampleRecipient from project 'webapp' (key rotated, secrets re-encrypted)
```

Under the hood `unshare` **rotates the project DEK**: it generates a fresh key, re-encrypts every current value *and the full version history*, and re-wraps the new key to the **remaining** recipients only. The removed recipient cannot decrypt anything afterward — not even from an old, copied vault file.

::: warning Revocation is the whole point
TinyVault deliberately does **not** "revoke" by just dropping a wrapped key — that would be security theater, since anyone with a stale vault copy keeps the old DEK. Because `unshare` rewrites the data, it is heavier than sharing, and it touches history too. That is intentional: it is what makes removal real. See [Versioning & Rollback](/guide/versioning) for how history is re-encrypted in the same atomic step.
:::

## Identities for CI, ssh, and agents

A machine has no terminal to type a passphrase, and copying a key file around is awkward. For those contexts, supply the private key through the `TVAULT_IDENTITY_KEY` environment variable — a `tvault-key1…` string — and TinyVault uses it automatically (`env --identity`, `open`, and the git filters all resolve through it).

Resolution precedence:

| Source | Wins when |
| --- | --- |
| Local key file (`~/.tvault/identities/<name>.key`) | A file for the named identity exists. **File beats env.** |
| `TVAULT_IDENTITY_KEY` environment value | No matching key file is present. |

When a file overrides a set environment key, TinyVault prints a warning to stderr so the override is never silent. The environment key's value is **never** echoed in any error or log message.

### Exporting a private key for a runner

To get the `tvault-key1…` value into a CI secret store, export it. Because this prints a **private** key, it is TTY-guarded: it refuses to write to anything that is not a terminal unless you pass `--force`.

```bash
# interactive: prints to your terminal
tvault identity export alice

# pipe to a secret manager (non-TTY → --force required)
tvault identity export ci --force | gh secret set TVAULT_IDENTITY_KEY
```

::: danger This is your private key — handle it like one
`tvault-key1…` is the secret half of an identity. Anyone who has it can read every project shared with that identity.

- **Never commit it.** Only the `tvault1…` (public) half is commit-safe.
- Store it in a real secret manager (GitHub Actions secrets, GitLab CI variables, your OS keychain) — not in a dotfile, not in shell history.
- The `--force` flag exists so you can pipe into a secret store; it is **not** permission to drop the key into a log or an artifact.
- Use a **distinct identity per context** (one for CI, one per teammate). Then revoking one runner with `tvault projects unshare` does not affect anyone else.
:::

For a ready-made workflow file that wires an identity into your pipeline, run `tvault ci init --provider github-actions --mode identity` (or `--provider gitlab`) and see [CI/CD](/guide/ci-cd).

## How the wrapping works

Each share produces one self-contained stanza per recipient. At a high level:

1. TinyVault generates an ephemeral X25519 keypair and runs **ECDH** between the ephemeral private key and the recipient's public key.
2. The shared secret is run through **HKDF-SHA256** (salted with both public keys) to derive a one-time wrapping key.
3. The project DEK is sealed under that key with **ChaCha20-Poly1305**, authenticated against the ephemeral public key.

The recipient reverses it with their private key. The construction uses only Go's standard `crypto/ecdh` plus the already-vendored `x/crypto` — there is no third-party crypto dependency. It is the same shape used by age, but TinyVault speaks its own `tvault1…` / `tvault-key1…` formats.

For the exact wire format, the AAD, and the full key hierarchy, see [Architecture](/reference/architecture) and the [Security & Threat Model](/reference/security).

## Quick reference

| Command | Side | What it does |
| --- | --- | --- |
| `tvault identity new [name]` | recipient | Create a keypair; print the `tvault1…` recipient. Name defaults to `default`. |
| `tvault identity list` | recipient | List local identities. |
| `tvault identity export [name]` | recipient | Print the **private** `tvault-key1…` key (TTY-guarded; `--force` off a tty). |
| `tvault projects share <recipient>` | owner | Wrap the project DEK to a `tvault1…` recipient. `-p` to choose a project. |
| `tvault projects recipients` | owner | List a project's recipients (metadata, no unlock). `-p` to choose a project. |
| `tvault projects unshare <recipient>` | owner | Revoke: **rotate the DEK and re-encrypt every value + history**. |
| `tvault env --identity <name>` | recipient | Read a shared project with an identity — no passphrase. |

Global flags such as `-p/--project`, `--json`, `--vault`, `--config`, `-v/--verbose`, and `--no-agent` work on these commands as they do everywhere; see the [CLI reference](/cli/).

## See also

- [Committable Secrets](/guide/committable-secrets) — put ciphertext (`.env.encrypted`, sealed files) in git, using the same recipients.
- [Git Filter](/guide/git-filter) — transparent encrypt-on-commit / decrypt-on-checkout with `tvault1…` recipients.
- [CI/CD](/guide/ci-cd) — wire an identity into GitHub Actions or GitLab with `tvault ci init`.
- [Architecture](/reference/architecture) — the key hierarchy and the exact recipient wire format.
