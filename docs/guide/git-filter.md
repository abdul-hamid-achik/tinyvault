---
title: Transparent Git Filter
description: Commit secrets safely with git-crypt-style transparent encryption — ciphertext lives in git history, plaintext appears in the working tree for identity holders.
---

# Transparent Git Filter

`tvault git-filter` wires git clean/smudge filters into a repository so matched files are stored **encrypted** in git history and appear as **plaintext** in your working tree. It is the git-crypt experience, keyed by TinyVault's X25519 recipient layer instead of a shared symmetric key: anyone holding a recipient identity sees plaintext, everyone else sees ciphertext.

Reach for this when you want a `.env`, a `secrets/` directory, or config files to live *in* the repo, encrypted, with zero friction for the people allowed to read them.

## How it works

Git runs two filters on files it tracks under `filter=tvault`:

- **clean** runs on the way *into* git (on `git add`/commit). It encrypts plaintext to the recipients in `.tvault-recipients`, and the ciphertext is what gets committed.
- **smudge** runs on the way *out* of git (on checkout). It decrypts ciphertext to plaintext in your working tree using your local identity.

The plaintext never enters git history. The read-set travels with the repo as a committed `.tvault-recipients` file (one `tvault1…` public key per line). Decryption uses your local identity, resolved in this order: `$TVAULT_IDENTITY`, then `git config tvault.identity`, then `default`, loaded from `~/.tvault/identities/<name>.key`. A CI checkout can instead supply the private key out-of-band via `TVAULT_IDENTITY_KEY`.

::: info `git-clean` and `git-smudge` are internal
The hidden `tvault git-clean` and `tvault git-smudge` subcommands are invoked *by git*, not by you. You configure them once with `git-filter install`; you never run them directly.
:::

## Setup

### 1. Make sure you have an identity

The filter needs an identity to decrypt your working tree. If you don't have one yet:

```bash
tvault identity new
```

This writes a keypair to `~/.tvault/identities/default.key` (mode `0600`). The public half (`tvault1…`) is shareable and committable; the private half (`tvault-key1…`) never leaves that file. See [Sharing & identities](/guide/sharing) for the model.

### 2. Install the filters and seed recipients

From inside the repository:

```bash
tvault git-filter install --recipient tvault1exampleRecipient
```

This does three things:

- Sets `filter.tvault.clean`, `filter.tvault.smudge`, and `filter.tvault.required=true` in this repo's git config.
- Appends each `--recipient` to `.tvault-recipients`, creating it with a header comment if needed. The flag is repeatable — pass one per reader (you, a teammate, CI).
- Decrypts any already-committed, still-encrypted tracked files into your working tree (a fresh-clone refresh). A failure here warns rather than aborting the install.

```bash
# Add yourself and CI in one shot
tvault git-filter install \
  --recipient tvault1exampleRecipient \
  --recipient tvault1exampleCiRecipient
```

### 3. Choose what to encrypt

`track` appends `<pattern> filter=tvault` lines to `.gitattributes`, the way `git lfs track` works. Patterns already present are left untouched.

```bash
tvault git-filter track .env
tvault git-filter track 'secrets/*.env' 'config/*.secret'
```

### 4. Commit the config

`.gitattributes` and `.tvault-recipients` are both public, commit-intended files (mode `0644`). Commit them so the workflow travels with the repo:

```bash
git add .gitattributes .tvault-recipients
git commit -m "enable tvault transparent encryption"
```

From here, `git add`-ing a tracked file commits ciphertext automatically. Your working copy stays plaintext.

::: tip Verify before you trust
After the first commit, confirm git stored ciphertext, not plaintext:

```bash
git show HEAD:.env | head -c 64   # should be tvault encrypted-env bytes, not your secrets
```
:::

## Onboarding a teammate or CI

A new reader clones the repo (so they get `.gitattributes` and `.tvault-recipients`) and runs `install` to register the filters locally and decrypt the tree:

```bash
git clone https://github.com/your-org/your-repo
tvault git-filter install        # registers filters + smudges tracked files
```

If the filters are already installed and you just need to (re-)decrypt the working tree, use `checkout` instead:

```bash
tvault git-filter checkout
```

`checkout` re-applies the smudge filter to every tvault-tracked file that is currently ciphertext. Files already in plaintext are skipped, so your local edits are never clobbered. Without an identity, the files simply stay encrypted.

### Granting access to a new reader

Access is the union of `.tvault-recipients`. To add someone, append their recipient and re-encrypt the files so they're wrapped to the new set:

```bash
tvault git-filter install --recipient tvault1exampleNewReader
touch .env                       # force the clean filter to re-run
git add .env .tvault-recipients
git commit -m "share secrets with new reader"
```

::: warning Adding a recipient does not revoke history
Anyone who could read a value before can still read the old committed ciphertext from git history. The git filter is an **access list for new commits**, not a revocation mechanism. For true revocation of a *vault* project — rotating the DEK and re-encrypting every value and its history — use [`tvault projects unshare`](/guide/sharing). For committed files, removing a recipient only stops *future* encryptions from including them; rotate the underlying secrets if a key is compromised.
:::

### CI without a passphrase

CI holds a per-context identity via the `TVAULT_IDENTITY_KEY` environment variable (a `tvault-key1…` string), so a checkout decrypts transparently with no passphrase prompt. Scaffold a workflow with:

```bash
tvault ci init --provider github-actions --mode identity
```

See [CI/CD](/guide/ci-cd) and [Committable secrets](/guide/committable-secrets) for the full identity-based CI pattern.

::: danger Never commit a private key
`TVAULT_IDENTITY_KEY` is a secret. Put it in your CI provider's secret store, never in the repo, and never in `.tvault-recipients` (which holds only public `tvault1…` keys). `tvault identity export` prints the **private** key and is TTY-guarded for exactly this reason.
:::

## Status

`status` reports the filter configuration, the recipient set, your identity availability, and the tracked patterns — without unlocking anything:

```bash
tvault git-filter status
```

```text
✓ Filters installed in /Users/you/project
Recipients: 2 (tvault1exampleRecipi…, tvault1exampleCiReci…)
Identity:   default (available)
Tracked:    .env, secrets/*.env
```

If your identity is missing, the line reads `missing — files will stay encrypted` — that is the **locked** state described below, not an error.

Add `--json` (the global flag) to get machine-readable output for scripts:

```bash
tvault git-filter status --json
```

## Uninstall

`uninstall` removes the `[filter "tvault"]` section from this repo's git config. It deliberately **leaves `.gitattributes` and `.tvault-recipients` in place** — those are committed config, and removing them is your call.

```bash
tvault git-filter uninstall
```

A repo that was never installed has no such section, which is not an error.

## Invariants worth knowing

These behaviors are guaranteed by the filter and are why the workflow stays quiet and safe:

| Invariant | Behavior |
| --- | --- |
| **Idempotent clean** | Re-encrypting unchanged plaintext would otherwise produce different bytes every time (AEAD is randomized) and make `git status` perpetually dirty. When the staged blob already decrypts to the exact same plaintext, the clean filter re-emits that blob verbatim — so an unchanged file shows no diff. |
| **No double-encrypt** | If the clean filter receives input that is already a tvault encrypted-env file (v1 or v2), it passes it straight through instead of wrapping it again. |
| **Refuses with no recipients** | The clean filter errors if `.tvault-recipients` is empty rather than silently committing plaintext. Add recipients or run `git-filter install --recipient <tvault1…>`. |
| **Locked mode** | When no identity is available, the smudge filter passes ciphertext through unchanged instead of failing the checkout. The repo stays usable; the protected files just remain encrypted ("locked") until an identity is present. |
| **Edits survive** | `checkout` only touches files that are currently ciphertext, so a plaintext working-tree edit is never overwritten. |

::: tip Locked is a feature, not a failure
A contributor without a recipient identity can still clone, build, and commit unrelated changes — they just can't read or meaningfully edit the encrypted files. `filter.tvault.required=true` ensures git surfaces a hard error if the filter program itself is missing, so an unconfigured machine can't silently commit plaintext.
:::

## Relationship to other commands

The git filter is the transparent UX layer over the same v2 committable-secrets format used by:

- [`tvault encrypt-env` / `decrypt-env`](/guide/committable-secrets) — the explicit, one-shot version of the same encryption (`--recipient` for commit-safe v2).
- [`tvault seal` / `open`](/guide/committable-secrets) — seal vault values to recipients and open them with an identity.

If you want manual control over *when* files are encrypted, use those. If you want git to do it for you on every commit, use the filter.

## See also

- [Committable secrets](/guide/committable-secrets) — the v2 encrypted-env format the filter is built on
- [Sharing & identities](/guide/sharing) — recipients, `tvault identity`, and true revocation
- [CI/CD](/guide/ci-cd) — passphrase-free identity workflows for pipelines
- [CLI reference](/cli/) — every command and flag
