---
title: Committable Secrets
description: Keep encrypted secrets inside your Git repo with TinyVault — X25519 recipient encryption (no passphrase in the files), standalone .env.encrypted, sealed SealedSecret manifests for Kubernetes, and the committed .tvault-recipients read-set.
---

# Committable Secrets

Sometimes you want secrets to live **in** the repository — encrypted in history, decrypting only for the people and machines you trust. TinyVault does this with its **recipient layer**: ciphertext is keyed to X25519 public keys, so the files carry **no passphrase** and survive passphrase rotation untouched.

This page covers three ways to commit encrypted secrets:

1. **Standalone encrypted files** — `encrypt-env` / `decrypt-env`, plus `seal` / `open`, which read straight from the vault with no plaintext `.env` on disk.
2. **Kubernetes** — `seal --format k8s` produces a commit-safe `SealedSecret`; `k8s render` decrypts it into a real `Secret` for `kubectl`.
3. **Transparent Git filters** — clean/smudge so files look like plaintext in your working tree but are stored encrypted; covered on the [Git Filter](/guide/git-filter) page.

::: info How recipient encryption works
A **recipient** is an X25519 public key in `tvault1…` form (shareable, commit-safe). The matching private **identity** is `tvault-key1…` (secret, never commit). Sealing wraps a project's data encryption key to each recipient using X25519 → HKDF-SHA256 → ChaCha20-Poly1305 — only a holder of a matching identity can open it. There is no passphrase anywhere in the file. See [Sharing Secrets](/guide/sharing) for the full key model.
:::

## Prerequisites: an identity

Anyone who needs to **decrypt** a committable file needs an identity. Create one once:

```bash
tvault identity new            # creates the "default" identity
tvault identity new ci         # or a named one, e.g. for CI
tvault identity list           # shows each name and its tvault1… recipient
```

Identities live at `~/.tvault/identities/<name>.key` (mode `0600`) and are independent of your vault passphrase. The public half printed by `identity list` is the `tvault1…` recipient you hand out.

::: danger `identity export` prints a PRIVATE key
`tvault identity export <name>` writes the `tvault-key1…` **private** key to stdout. It is TTY-guarded — it refuses to print to a terminal unless you pass `--force`. Use it only to provision a secret store, e.g. `tvault identity export ci --force | gh secret set TVAULT_IDENTITY_KEY`. Never commit the output and never paste it into a file the repo tracks.
:::

## The `.tvault-recipients` file

Put the **public** recipient keys for a repo into a `.tvault-recipients` file at the repo root, one per line, and **commit it**. It contains only public `tvault1…` keys, so it is safe to track. The read-set then travels with the repo: anyone who clones it knows exactly who can decrypt.

```
# .tvault-recipients — public keys only, safe to commit
tvault1exampleRecipientAlice
tvault1exampleRecipientBob
tvault1exampleRecipientCluster
```

`seal` reads this file automatically when you don't pass `--recipient`. It refuses to run with no recipients at all — there must be at least one in the file or on the flag.

::: tip Adding and removing readers
Adding a recipient is a one-line edit plus a re-seal. **Removing** one is different: editing the file does not retroactively lock anyone out of ciphertext they already cloned. Use `tvault projects unshare` to re-key the updated live vault, then rotate the underlying credentials and re-seal any committed files without that recipient. Pre-removal snapshots and sealed artifacts remain readable. See [Sharing Secrets](/guide/sharing).
:::

## Approach 1: Standalone encrypted files

### Encrypt an existing `.env`

`encrypt-env` reads a plaintext dotenv and writes an encrypted blob. Pass `--recipient` (repeatable) to produce a **commit-safe v2** file keyed to those recipients — no passphrase, KEK-independent:

```bash
tvault encrypt-env \
  --in .env \
  --out .env.encrypted \
  --recipient tvault1exampleRecipient

git add .env.encrypted .tvault-recipients
git commit -m "store encrypted env"
```

| Flag | Meaning |
| --- | --- |
| `-i, --in <file>` | Plaintext dotenv input (default: stdin). |
| `-o, --out <file>` | Where to write the encrypted blob (default: stdout). |
| `--recipient <tvault1…>` | Recipient public key. **Repeatable.** Produces a v2, commit-safe, passphrase-free file. |

::: warning Without `--recipient` you get a v1 file tied to your passphrase
If you omit `--recipient`, `encrypt-env` produces a **v1** blob encrypted under your vault passphrase. That is fine for a personal backup, but it is **not** portable across machines and `tvault key rotate` **invalidates** any v1 `.env.encrypted` made under the old passphrase. For anything you commit, always use `--recipient`.
:::

### Decrypt with your identity

`decrypt-env` auto-detects the format: v2 files decrypt with an identity (no passphrase), and v1 files fall back to your passphrase.

```bash
tvault decrypt-env \
  --in .env.encrypted \
  --out .env \
  --identity default
```

| Flag | Meaning |
| --- | --- |
| `-i, --in <file>` | Encrypted input (default: stdin). |
| `-o, --out <file>` | Where to write the plaintext dotenv (default: stdout). |
| `--identity <name>` | Identity to decrypt a v2 file. |

### Seal straight from the vault (no plaintext on disk)

`seal` is the better path when the secrets already live in your vault: it reads them directly and emits an encrypted blob, so **no plaintext `.env` ever lands on disk**. It requires the vault to be unlocked, since it reads real values. `open` is its inverse.

```bash
# Seal the active project's secrets to the committed recipient set
tvault seal -p prod > .env.encrypted

# Or pick specific keys and explicit recipients
tvault seal \
  -p prod \
  --key DATABASE_URL --key STRIPE_KEY \
  --recipient tvault1exampleRecipient \
  --out .env.encrypted
```

| Flag | Meaning |
| --- | --- |
| `-r, --recipient <tvault1…>` | Recipient public key. **Repeatable.** Defaults to `.tvault-recipients` when omitted. |
| `--key <name>` | Limit to specific keys. **Repeatable.** Default: all keys in the project. |
| `-o, --out <file>` | Output file (default: stdout). |
| `--format <raw\|k8s>` | `raw` is a v2 blob (default); `k8s` is a SealedSecret manifest — see below. |
| `--name <str>` | Kubernetes `Secret` name (required for `--format k8s`). |
| `--namespace <str>` | Kubernetes namespace (`--format k8s`; default `default`). |

Open a sealed `raw` blob back into a dotenv with your identity (v2 only):

```bash
tvault open --in .env.encrypted --identity default --out .env
```

| Flag | Meaning |
| --- | --- |
| `-i, --in <file>` | Sealed input (default: stdin). |
| `--identity <name>` | Identity to open with. Default: `$TVAULT_IDENTITY`, then `default`. |
| `-o, --out <file>` | Output dotenv (default: stdout). |

::: tip Use the file directly without decrypting to disk
For local development you usually don't need to decrypt at all — `tvault run`, `tvault env`, and `tvault get --from` can read secrets without writing a plaintext `.env`. See [Run & Environment](/guide/run-and-env) and [.env Files](/guide/dotenv).
:::

## Approach 2: Kubernetes (`SealedSecret` pattern)

You can commit Kubernetes secrets without a cluster-side controller. `seal --format k8s` emits a manifest whose `encryptedData` is a v2 ciphertext blob keyed to the recipient(s) you choose — typically a cluster identity. The manifest is **safe to commit**.

```bash
tvault seal \
  --format k8s \
  --name app-secrets \
  --namespace prod \
  -p prod \
  --recipient tvault1exampleRecipientCluster \
  --out sealed.yaml

git add sealed.yaml
git commit -m "add sealed k8s secret"
```

At deploy time, `k8s render` decrypts the manifest into a real `kind: Secret`. It does **not** unlock the vault — it needs only the matching identity (a local identity file, or `TVAULT_IDENTITY_KEY` in CI). Pipe the result straight to `kubectl`:

```bash
tvault k8s render --in sealed.yaml --identity cluster | kubectl apply -f -
```

| Flag | Meaning |
| --- | --- |
| `-i, --in <file>` | SealedSecret input (default: stdin). |
| `--identity <name>` | Identity used to decrypt. |
| `-o, --out <file>` | Output file (default: stdout). |

::: danger `k8s render` output is PLAINTEXT — never commit it
The rendered `kind: Secret` contains your secret values in the clear (base64 is not encryption). Pipe it directly into `kubectl apply -f -` or hand it to your deploy step. **Do not** write it to a tracked file, and do not redirect it into the repo. Only the **sealed** manifest (`sealed.yaml`) is commit-safe.
:::

::: tip Provisioning the cluster identity in CI
Generate an identity for the deploy context and store its private key as a CI secret, then let `k8s render` pick it up from the environment:

```bash
tvault identity new cluster
tvault identity export cluster --force | gh secret set TVAULT_IDENTITY_KEY
```

In CI, `TVAULT_IDENTITY_KEY` (a `tvault-key1…` string) lets `k8s render` / `open` / `decrypt-env` work with no passphrase and no key file. See [CI/CD](/guide/ci-cd) and [Environment Variables](/reference/environment-variables).
:::

## Approach 3: Transparent Git filters

If you want matched files (like `.env`) to appear as **plaintext in your working tree** while being stored **encrypted in history** — no manual encrypt/decrypt step — use TinyVault's Git clean/smudge filters. They use the same recipient layer and the same committed `.tvault-recipients` read-set, so anyone holding an identity sees plaintext on checkout and everyone else sees ciphertext ("locked") rather than a broken checkout.

```bash
tvault git-filter install --recipient tvault1exampleRecipient
tvault git-filter track .env 'secrets/*.env'
git add .gitattributes .tvault-recipients
git commit -m "enable transparent encryption"
```

See the full walkthrough — install, track, status, checkout, and the idempotency and locked-mode behavior — on the [Git Filter](/guide/git-filter) page.

## Choosing an approach

| You want… | Use |
| --- | --- |
| A single committed `.env.encrypted` you decrypt explicitly | `encrypt-env --recipient` / `decrypt-env --identity` |
| To seal from the vault with no plaintext touching disk | `seal` / `open` |
| Commit-safe Kubernetes secrets, no cluster controller | `seal --format k8s` / `k8s render` |
| Files that look like plaintext locally, encrypted in history | [Git Filter](/guide/git-filter) |

::: info Where MCP fits
An AI agent can produce the same v2 blob over MCP with the `vault_seal_for_recipients` tool, whose own result is **ciphertext only**. Elsewhere, `vault_get_secret` deliberately returns plaintext and `vault_run_with_secrets` can carry values through child output. Optional literal-value redaction is a safety net, not a control. See [MCP Tools](/mcp/tools) and [Access Policy](/mcp/access-policy).
:::

## See also

- [Sharing Secrets](/guide/sharing) — the X25519 recipient/identity model, live-vault re-keying, and retained-data limits.
- [Git Filter](/guide/git-filter) — transparent clean/smudge encryption for tracked files.
- [CI/CD](/guide/ci-cd) — passphrase-free pipelines with `TVAULT_IDENTITY_KEY` and `ci init`.
- [Environment Variables](/reference/environment-variables) — `TVAULT_IDENTITY`, `TVAULT_IDENTITY_KEY`, and friends.
