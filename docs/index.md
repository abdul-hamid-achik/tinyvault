---
layout: home
title: Local-first secrets manager & MCP server for developers and AI agents
description: TinyVault is a local-first secrets manager and MCP server for developers and AI agents, written in Go and shipped as a single binary. It is language-agnostic — tvault run injects secrets as env vars into Node, Python, Ruby, Rust, PHP, Go, or anything. AES-256-GCM + Argon2id, .env toolkit, X25519 sharing, versioned secrets, a 49-tool MCP server. No servers, no accounts, no cloud.

hero:
  name: TinyVault
  text: Secrets that never leave your machine.
  tagline: One Go binary, any stack — an encrypted local vault, a full .env toolkit, and a 49-tool MCP server for AI agents. No servers, no accounts, no cloud.
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
    title: One binary, any stack
    details: Written in Go as one static binary — the CLI, the MCP server, and the terminal studio, with no runtime or Docker. Language-agnostic — `tvault run` injects secrets as env vars into Node, Python, Ruby, Rust, Go, or anything that reads them.
  - icon: 🤖
    title: Built for AI agents
    details: A 49-tool MCP server where secret values never enter the model's context. Inject into a subprocess, write to disk, or seal to a recipient instead.
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

<div class="tv-landing">

<HomeStatBar />

<HomeTerminal />

<HomeHowItWorks />

<HomeUseCases />

<HomeCompare />

<HomeCTA />

</div>