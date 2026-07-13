---
title: CI/CD Integration
description: Run tvault non-interactively in CI/CD with a passphrase or, better, a passphrase-free per-context identity that decrypts committed secrets on the runner.
---

# CI/CD Integration

You can run `tvault` in any pipeline without an interactive prompt. There are two ways to do it: give CI the vault **passphrase**, or give CI a per-context **identity** that decrypts committed and recipient-sealed secrets with no passphrase at all. Identity mode is the better default — your master passphrase never leaves your machine.

## The two modes at a glance

| | Passphrase mode | Identity mode (recommended) |
|---|---|---|
| What CI holds | `TVAULT_PASSPHRASE` | `TVAULT_IDENTITY_KEY` (a private `tvault-key1…`) |
| Master passphrase exposed to CI? | Yes | No |
| Decrypts | The full vault (read access) | Only what the identity is a recipient of |
| Rotating the credential | Re-enters the passphrase everywhere | Rotate the identity; the passphrase is untouched |
| Works with | `tvault env`, `tvault get`, `tvault run` | `tvault decrypt-env`, `tvault open`, `tvault git-filter checkout`, `tvault env --identity`, `tvault k8s render` |

::: tip
Both modes are scaffolded by `tvault ci init`. Skip to [Scaffolding a workflow](#scaffolding-a-workflow) if you just want the file.
:::

## Passphrase mode

Set `TVAULT_PASSPHRASE` in the environment and every command that needs to unlock the vault skips the prompt. This is the simplest path when CI has direct access to the vault file.

```bash
export TVAULT_PASSPHRASE='your vault passphrase'

# Load every secret in the active project as exported shell vars
eval "$(tvault env --format=shell)"

# Or read a single key
tvault get DATABASE_URL

# Or wrap a command with the vault injected into its environment
tvault run -- npm test
```

In a GitHub Actions step the credential comes from a repository secret:

```yaml
- name: Load secrets from TinyVault
  env:
    TVAULT_PASSPHRASE: ${{ secrets.TVAULT_PASSPHRASE }}
  run: |
    tvault env --format=shell --export=false >> "$GITHUB_ENV"
```

::: warning
Passphrase mode gives the runner the keys to the whole vault. Anyone who can read the CI logs or environment of that job can read every secret it can decrypt. Prefer identity mode, and scope what each runner can see.
:::

## Identity mode (passphrase-free)

Instead of the master passphrase, you hand CI a **per-context identity** — an X25519 keypair created specifically for that pipeline. The runner uses it to decrypt only the secrets you have shared with it. The passphrase that protects your vault never travels to CI, and rotating the CI identity does not touch it.

This builds on the recipient layer: see [Sharing](/guide/sharing), [Committable secrets](/guide/committable-secrets), and the [git filter](/guide/git-filter) for how secrets get sealed to a recipient in the first place.

### 1. Create the CI identity

```bash
tvault identity new ci
```

This writes a keypair to `~/.tvault/identities/ci.key` (mode `0600`). The public half is a shareable `tvault1…` recipient string; the private half is a `tvault-key1…` string you will give to CI.

### 2. Share secrets with it

Make the CI identity a recipient. For a vault-backed shared project:

```bash
tvault projects share tvault1exampleRecipient
```

Or, for committed secrets handled by the git filter, add the public `tvault1…` string to `.tvault-recipients` (see [Committable secrets](/guide/committable-secrets)). Either way the CI identity can now decrypt what you sealed to it.

### 3. Export the private key into a CI secret

```bash
tvault identity export ci --force | gh secret set TVAULT_IDENTITY_KEY
```

`tvault identity export` prints the **private** key. It is TTY-guarded: it refuses to print to a terminal unless you pass `--force`. Piping it straight into your CI secret manager — `gh secret set` here — keeps it off your screen and out of your shell history.

::: danger
`tvault identity export` emits a private `tvault-key1…` key. Treat it like a password: never commit it, never echo it into CI logs, never paste it into a chat. The only place it belongs is a CI/CD secret store (a GitHub Actions secret, a GitLab masked variable, etc.). If a CI identity leaks, remove it with `tvault projects unshare`; this rotates the project DEK and re-encrypts the updated live vault. It cannot invalidate snapshots or artifacts the runner already obtained, so also rotate the underlying credentials and re-seal distributed files.
:::

### 4. Decrypt on the runner — no `--identity` needed

In the workflow you only set `TVAULT_IDENTITY_KEY`. With it in the environment, the recipient-aware commands find it automatically — you do **not** have to pass `--identity`:

```yaml
- name: Decrypt secrets with the CI identity
  env:
    TVAULT_IDENTITY_KEY: ${{ secrets.TVAULT_IDENTITY_KEY }}
  run: |
    # (a) git-filter: files tracked in .gitattributes auto-decrypt on checkout
    tvault git-filter checkout

    # (b) a committed v2 .env.encrypted (recipient-sealed):
    tvault decrypt-env --in .env.encrypted --out .env

    # (c) a sealed manifest (from `tvault seal --format k8s`) -> plaintext Secret:
    tvault k8s render --in sealed.yaml | kubectl apply -f -
```

Pick the line that matches how you committed your secrets. All three read `TVAULT_IDENTITY_KEY` with no passphrase and no key file on disk.

::: warning
`tvault k8s render` writes a **plaintext** Kubernetes Secret. Pipe it straight to `kubectl apply` — never write it to a file you commit. It needs only the identity, not a vault unlock.
:::

::: info Precedence: a local identity file always wins
`tvault` prefers a key file on disk over the env key. If `~/.tvault/identities/<name>.key` exists **and** `TVAULT_IDENTITY_KEY` is set, the file is used and `tvault` prints a one-line warning to stderr. CI runners have no key file, so the env key is what gets used there. The env key's value is never echoed in an error message.
:::

## Scaffolding a workflow

`tvault ci init` writes a starter workflow for your provider. The `--provider` flag is required.

```bash
# Passphrase mode (default), GitHub Actions
tvault ci init --provider=github-actions

# Identity mode, GitHub Actions, baking in the "ci" identity
tvault ci init --provider=github-actions --mode=identity --identity=ci

# GitLab snippet, identity mode, printed to stdout
tvault ci init --provider=gitlab --mode=identity --output=-
```

### `ci init` flags

| Flag | Values | Default | Notes |
|---|---|---|---|
| `--provider` | `github-actions`, `gitlab` | _(required)_ | Selects the output format. |
| `--mode` | `passphrase`, `identity` | `passphrase` | `identity` is the passphrase-free path. |
| `--identity` | identity name | `default` | The name baked into the generated workflow (identity mode). |
| `--output` | a path, or `-` | provider default | `-` prints to stdout. |

The default output path depends on the provider: GitHub Actions writes `.github/workflows/tinyvault-secrets.yml`, and GitLab prints its snippet to stdout (it is meant to be pasted into your `.gitlab-ci.yml`). File targets refuse to overwrite an existing file — remove it first to regenerate.

After an identity-mode `github-actions` scaffold, `tvault` prints the bootstrap steps to stderr: create the identity, share it, export it into `TVAULT_IDENTITY_KEY`, and commit your `.gitattributes` / `.tvault-recipients` / encrypted files alongside the workflow.

::: tip
The global flags work in CI too. `--no-agent` (or `TVAULT_NO_AGENT`) forces a direct unlock — useful on runners where no [agent](/guide/agent) is running. `-p/--project` selects the project, and `--json` gives machine-readable output for parsing in a later step. See [Environment variables](/reference/environment-variables) for the full list.
:::

## The same identity works over SSH

`TVAULT_IDENTITY_KEY` is not GitHub- or GitLab-specific. Any non-interactive context — an SSH session, a deploy host, a build agent — can export the same private key string and decrypt without a passphrase or a key file:

```bash
ssh deploy@host '
  export TVAULT_IDENTITY_KEY=tvault-key1examplePrivate
  tvault decrypt-env --in .env.encrypted --out .env
'
```

Because identities are independent keypairs, you can mint one per host or per pipeline and remove any of them from the updated live vault with `tvault projects unshare` without disturbing the remaining recipients. Pre-removal snapshots and artifacts remain readable, so rotate underlying credentials after a compromise.

## Verifying a pipeline

`tvault doctor` runs read-only diagnostics and exits non-zero if a check fails, which makes it a useful first step in a job. Knowing the exit codes lets you branch cleanly:

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic error |
| `3` | Vault locked |
| `4` | Secret or project not found |
| `5` | Not initialized |
| `6` | Wrong passphrase |

For example, a wrong `TVAULT_PASSPHRASE` exits `6`, and an identity that is not a recipient of the file you ask it to open fails rather than silently returning nothing.

## See also

- [Committable secrets](/guide/committable-secrets) — the v2 `.env.encrypted` format CI decrypts.
- [Git filter](/guide/git-filter) — transparent encrypt-on-commit / decrypt-on-checkout, the `tvault git-filter checkout` step.
- [Sharing](/guide/sharing) — `projects share` / `unshare` and the recipient model behind identity mode.
- [Environment variables](/reference/environment-variables) — `TVAULT_PASSPHRASE`, `TVAULT_IDENTITY_KEY`, and the rest.
