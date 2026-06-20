---
layout: home
title: Local-first secrets for developers & AI agents

hero:
  name: TinyVault
  text: Secrets that never leave your machine.
  tagline: A single Go binary — an encrypted local vault, a full .env toolkit, and an MCP server for AI agents. No servers, no accounts, no cloud.
  image:
    src: /logo.svg
    alt: TinyVault vault-door logo
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: What is TinyVault?
      link: /guide/what-is-tinyvault
    - theme: alt
      text: View on GitHub
      link: https://github.com/abdul-hamid-achik/tinyvault

features:
  - icon: 🔐
    title: Strong, simple crypto
    details: AES-256-GCM with a two-tier passphrase → KEK → per-project DEK hierarchy. Argon2id (64 MiB, memory-hard) key derivation. Keys zeroed from memory after use.
  - icon: 📦
    title: One binary, zero deps
    details: tvault is the CLI, the MCP server, and an interactive terminal studio. No database server, no Docker, no network — just one encrypted bbolt file.
  - icon: 🤖
    title: Built for AI agents
    details: A 21-tool MCP server where secret values never enter the model's context. Inject into a subprocess, write to disk, or seal to a recipient instead.
  - icon: 🧬
    title: A real .env toolkit
    details: Safe dotenv parsing (no shell expansion), tvault:// placeholders, two-way sync, drift diffs, and commit-safe .env.encrypted files.
  - icon: 🤝
    title: Share without the passphrase
    details: X25519 recipients (age-style) let a teammate, CI runner, or agent read a project with their own key. Revoking rotates the key and re-encrypts everything.
  - icon: 🌿
    title: Commit secrets safely
    details: Transparent git filters and sealed files keep ciphertext in history and plaintext in your working tree — git-crypt style, with no passphrase in the repo.
  - icon: 🕰️
    title: Versioned & recoverable
    details: Every overwrite archives the prior value. Inspect history, read a past version, and roll back non-destructively. History survives key rotation.
  - icon: ⚡
    title: Unlock once
    details: An opt-in local agent holds the vault unlocked over a private 0600 socket, so daily get/env/run skip the prompt and the Argon2id cost. Auto-locks when idle.
---

<div style="max-width: 880px; margin: 4rem auto 0; padding: 0 24px;">

## Install & go

```bash
# Homebrew (macOS / Linux)
brew install abdul-hamid-achik/tap/tvault

# or with Go
go install github.com/abdul-hamid-achik/tinyvault/cmd/tvault@latest
```

```bash
tvault init                                   # create ~/.tvault/vault.db
tvault set DATABASE_URL "postgres://localhost/app"
tvault run -- npm start                        # secrets injected as env vars
```

That's the whole loop: an encrypted vault on your disk, and a command that runs
your app with the secrets injected — no plaintext `.env` left lying around, and
nothing sent anywhere. Everything else (sharing, committing, versioning, the MCP
server, the studio) builds on top.

<p style="margin-top: 2rem;">
  <a href="/guide/getting-started">Read the Getting Started guide →</a>
</p>

</div>
