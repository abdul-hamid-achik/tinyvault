---
title: DigitalOcean & SSH servers
description: Install TinyVault on a DigitalOcean droplet (or any Linux server), manage its secrets over SSH, and feed them to your apps — either passphrase-free with a per-server identity key, or with a full vault you manage directly over SSH.
---

# DigitalOcean & SSH servers

This guide puts `tvault` on a Linux server (a DigitalOcean droplet, but anything with SSH works) so you can **manage that server's secrets over SSH** and feed them to the apps running on it. Two models, pick per use case:

- **[Model A — sealed secrets, managed centrally](#model-a-sealed-secrets-passphrase-free)** *(recommended for app config)*: the canonical vault stays on your laptop. You seal secrets to a **per-server identity** and the server decrypts them with its private key — **no vault passphrase ever touches the server.**
- **[Model B — a full vault on the server](#model-b-a-full-vault-you-manage-over-ssh)**: `tvault init` on the droplet and manage secrets directly over SSH with `tvault set/get/list`. Use when the server itself is where you want to author secrets.

## Install on the droplet

`tvault` is a single static binary, so installing on a droplet is quick. Pick whichever fits your base image:

```bash
# Debian/Ubuntu — the .deb from the latest release
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
curl -fsSLO "https://github.com/abdul-hamid-achik/tinyvault/releases/latest/download/tvault_$(curl -fsSL https://api.github.com/repos/abdul-hamid-achik/tinyvault/releases/latest | grep -oE '"tag_name": *"v[^"]+"' | grep -oE '[0-9.]+')_linux_${ARCH}.deb"
sudo dpkg -i tvault_*_linux_${ARCH}.deb

# Fedora/RHEL: the .rpm  ·  Alpine: the .apk  (same release page)

# Homebrew (also works on Linux via Linuxbrew)
brew install abdul-hamid-achik/tap/tvault

# Have a Go toolchain on the box?
go install github.com/abdul-hamid-achik/tinyvault/cmd/tvault@latest
```

Don't want to hand-build a URL? Grab the `tvault_<ver>_linux_<arch>.tar.gz` (or `.deb`/`.rpm`/`.apk`) for your droplet straight from the [Releases page](https://github.com/abdul-hamid-achik/tinyvault/releases/latest) — each release ships `linux/amd64` and `linux/arm64`.

### Staying current

Once `tvault` is on the box, it can update itself — checksum-verified, straight from the official releases:

```bash
tvault self-update --check     # is a newer release available?
tvault self-update             # download + verify + replace in place
```

If you installed via Homebrew or a system package, update through that package manager instead so its bookkeeping stays correct.

## Model A — sealed secrets, passphrase-free

The server holds only a keypair, never the passphrase. Compromising the droplet exposes only what you sealed to it, and you can revoke it centrally.

**1. On your laptop — make a per-server identity and seal to it.** Generate the identity locally so the public half can be committed and the private half handed to the server:

```bash
tvault identity new web-prod          # prints tvault1…  (public, shareable)
tvault identity export web-prod       # prints tvault-key1… (private — copy to the server)
```

Seal the project's secrets to that recipient. The output is a commit-safe v2 blob — you can check it into the repo or `scp` it:

```bash
tvault seal --recipient tvault1<web-prod-public> --out .env.encrypted
```

**2. On the server — drop the private key and decrypt.** Put the private key in a root-only file and decrypt with `tvault open` (no passphrase, no vault):

```bash
sudo install -d -m 700 /etc/tvault
printf 'TVAULT_IDENTITY_KEY=%s\n' 'tvault-key1<web-prod-private>' | sudo tee /etc/tvault/identity >/dev/null
sudo chmod 600 /etc/tvault/identity

# materialize the .env (env var picked up automatically by tvault open):
set -a; . /etc/tvault/identity; set +a
tvault open --in /etc/app/.env.encrypted --out /run/app.env
```

**3. Wire it into systemd.** Decrypt to a tmpfs path just before the app starts, so plaintext never lands on disk:

```ini
# /etc/systemd/system/myapp.service
[Service]
EnvironmentFile=/etc/tvault/identity
RuntimeDirectory=myapp                       # /run/myapp, tmpfs, 0700
ExecStartPre=/usr/local/bin/tvault open --in /etc/app/.env.encrypted --out /run/myapp/.env
ExecStart=/usr/local/bin/myapp               # reads /run/myapp/.env
```

**Rotate / revoke** centrally from your laptop. Editing a secret means re-seal + redeploy; removing a server's access is a true cryptographic revocation (it **rotates the project DEK and re-encrypts every value**):

```bash
tvault set NUXT_DATABASE_URL "…"; tvault seal --recipient tvault1<web-prod> --out .env.encrypted   # update
tvault projects unshare tvault1<web-prod>                                                          # revoke
```

::: tip
`tvault ci init --provider github-actions --mode identity --identity web-prod` scaffolds the same passphrase-free flow for a pipeline that builds and ships to the droplet.
:::

## Model B — a full vault you manage over SSH

When you want to author secrets *on the server*, give it a real vault.

```bash
ssh you@droplet
tvault init                                  # creates ~/.tvault (0700), prompts for a passphrase
tvault set DATABASE_URL "postgres://…"
tvault set API_KEY "$(openssl rand -hex 24)"
tvault list
```

For non-interactive use (scripts, systemd, `ssh droplet 'tvault …'`), supply the passphrase via a root-only env file instead of the prompt:

```bash
sudo install -d -m 700 /etc/tvault
printf 'TVAULT_PASSPHRASE=%s\n' 'your-passphrase' | sudo tee /etc/tvault/env >/dev/null
sudo chmod 600 /etc/tvault/env

set -a; . /etc/tvault/env; set +a
tvault run -- myapp                           # injects all project secrets as env vars
```

Run the [local agent](/guide/agent) so repeated reads in one SSH session skip the prompt and the Argon2id derivation:

```bash
tvault agent start &                          # unix socket, 0600, peer-uid checked
tvault hook >> ~/.bashrc                      # optional: auto-route get/env/run through it
```

systemd for an app that reads from the server's vault:

```ini
# /etc/systemd/system/myapp.service
[Service]
EnvironmentFile=/etc/tvault/env               # TVAULT_PASSPHRASE (0600, root-only)
ExecStart=/usr/local/bin/tvault run --only DATABASE_URL,API_KEY -- /usr/local/bin/myapp
```

::: warning
Model B keeps the passphrase on the server. Prefer Model A for app config; reserve Model B for a server you treat as a secrets-authoring host. Either way, keep `/etc/tvault/*` at `0600` and `~/.tvault` at `0700`, and never commit `vault.db` or a `tvault-key1…` private key.
:::

## Provisioning the droplet with Pulumi

The droplet, its SSH key, and the firewall are themselves IaC. Provision them with Pulumi, injecting the DigitalOcean token from the same vault (see [Pulumi & IaC](/guide/pulumi)):

```bash
tvault run --only DIGITALOCEAN_TOKEN -- pulumi up
```

Have the droplet install `tvault` and drop its identity key on first boot via cloud-init `user_data`:

```yaml
#cloud-config
packages: [curl]
runcmd:
  # install the .deb for this droplet's arch from the latest release
  - ARCH=$(dpkg --print-architecture)
  - VER=$(curl -fsSL https://api.github.com/repos/abdul-hamid-achik/tinyvault/releases/latest | grep -oE '"tag_name": *"v[^"]+"' | grep -oE '[0-9.]+')
  - curl -fsSLO "https://github.com/abdul-hamid-achik/tinyvault/releases/latest/download/tvault_${VER}_linux_${ARCH}.deb"
  - dpkg -i "tvault_${VER}_linux_${ARCH}.deb"
write_files:
  - path: /etc/tvault/identity
    permissions: '0600'
    content: "TVAULT_IDENTITY_KEY=tvault-key1<web-prod-private>"
```

In Pulumi, supply that `user_data` as a `pulumi.secret()` so the key stays encrypted in state.

## Security checklist

- `~/.tvault` is `0700`; `/etc/tvault/*` env/identity files are `0600` and root-owned.
- The server holds a **private identity key** (Model A) or a **passphrase** (Model B) — never both, and never the vault passphrase in Model A.
- Decrypt to **tmpfs** (`/run/...`, `RuntimeDirectory=`), not to a persistent disk path.
- Never commit `vault.db` or `tvault-key1…`. `tvault1…` (public) and `.env.encrypted` (sealed) are safe to commit.
- Revoke a lost server with `tvault projects unshare` — it rotates the DEK and re-encrypts, so the old key is truly dead.

## See also

- [Pulumi & IaC](/guide/pulumi) — provision the droplet and deploy with secrets injected
- [Committable Secrets](/guide/committable-secrets) — the `.env.encrypted` v2 format and `seal`/`open`
- [Sharing Secrets](/guide/sharing) — identities, recipients, and true revocation
- [Local Agent](/guide/agent) — prompt-free reads on the server
- [CI/CD](/guide/ci-cd) — passphrase-free pipelines with `TVAULT_IDENTITY_KEY`
