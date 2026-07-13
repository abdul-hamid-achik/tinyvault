---
title: What is TinyVault?
description: Decide whether TinyVault's local-first, single-binary approach fits your secrets workflow.
---

# What is TinyVault?

TinyVault is a local-first secrets manager for developers and AI-assisted workflows. One `tvault` binary stores encrypted secret values in a local database, injects selected values into any process that reads environment variables, and exposes the same vault through a CLI, terminal studio, and MCP server.

Normal vault operations require no hosted TinyVault account or service. You decide when encrypted artifacts or plaintext exports leave the machine.

## TinyVault is a good fit when

- You want to replace scattered plaintext `.env` values with one local store.
- You run applications, scripts, or deployment tools from a developer machine.
- You want an AI agent to use a credential without reading it by default.
- You prefer a CLI and a single local database over operating a secrets server.
- You can exchange recipient-encrypted files when CI or another person needs access.

TinyVault is language-agnostic. `tvault run` passes selected secrets through a child process's environment, so the application can be written in Node.js, Python, Ruby, Rust, PHP, Go, or any other stack.

## TinyVault is probably not the right fit when

- You need a hosted team-sync service with centralized administration.
- You need dynamic credentials, automatic lease renewal, or server-side revocation.
- You require HSM or cloud-KMS integration, recovery shares, or a hosted recovery path.
- You need strong isolation between mutually untrusted users or processes on one machine.
- You need to prevent a trusted subprocess from logging or transmitting a credential it receives.

For those cases, use a networked secrets platform designed for the required control plane. TinyVault can still complement it for local development, but it is not a replacement for that platform.

## What stays local

By default, TinyVault keeps its state in `~/.tvault/vault.db`. Secret values, versioned values, and key material are encrypted. Project names, secret key names, timestamps, audit metadata, and other operational metadata are readable to anyone who can read the database file.

The owner passphrase has no recovery path. Restoring the complete owner view therefore requires both the database and the matching passphrase, stored separately. A recipient identity provisioned beforehand can read only projects shared to it.

See [Security and threat model](/reference/security) for the full boundary and [Architecture](/reference/architecture) for the key hierarchy.

## Three ways to use the same vault

- The [CLI](/cli/) supports scripts, process injection, import/export, sharing, and operations.
- [Studio](/guide/studio) provides an interactive terminal browser and optional editing mode.
- The [MCP server](/mcp/) gives an AI agent policy-scoped tools and value-minimizing workflows.

All three surfaces use the same local database. There is no separate MCP or studio copy to synchronize.

## Start with one working flow

Follow [Getting started](/guide/getting-started) to create a vault, store one demo value through standard input, list its key, and inject it into a process. The [guide index](/guide/) routes from there to projects, dotenv files, sharing, CI, and operations.
