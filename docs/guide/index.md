---
title: TinyVault Guides
description: Choose the TinyVault guide for your goal, from the first local vault to process injection, MCP agents, sharing, and operations.
---

# TinyVault guides

TinyVault stores secret values locally and makes them available through a CLI, a terminal studio, and an MCP server. Start with the quickstart, then follow the workflow that matches what you are trying to do.

## Start here

| Goal | Guide |
| --- | --- |
| Decide whether TinyVault fits your use case | [What is TinyVault?](/guide/what-is-tinyvault) |
| Create a vault and run an app with one secret | [Getting started](/guide/getting-started) |
| Understand projects, keys, and the encryption hierarchy | [Core concepts](/guide/concepts) |
| Evaluate the trust boundaries | [Security and threat model](/reference/security) |

## Everyday workflows

- [Secrets](/guide/secrets) — create, inspect, update, and delete keys.
- [Run and env](/guide/run-and-env) — inject secrets into a child process or render environment output.
- [Projects](/guide/projects) — isolate secrets by application or scope.
- [Environment groups](/guide/env-groups) — model development, staging, and production inheritance.
- [Dotenv workflows](/guide/dotenv) — import, export, diff, sync, and interpolate `.env` files.
- [Versioning and rollback](/guide/versioning) — inspect history and restore a prior value.

## Share and deploy

- [Sharing](/guide/sharing) — create identities and grant recipient access to a project.
- [Committable secrets](/guide/committable-secrets) — choose a recipient-encrypted file format.
- [Git filter](/guide/git-filter) — encrypt on commit and decrypt on checkout.
- [CI/CD](/guide/ci-cd) — use recipient identities in automation.
- [Kubernetes SealedSecret workflow](/guide/committable-secrets#approach-2-kubernetes-sealedsecret-pattern) — seal and render Kubernetes secrets.

## Choose an interface

- [Studio](/guide/studio) — browse the vault in a terminal UI.
- [Local agent](/guide/agent) — keep the vault available between CLI commands on Unix.
- [MCP server](/mcp/) — connect an AI agent through a disk-controlled policy.
- [AI agent workflow](/guide/for-ai-agents) — find and use keys while minimizing plaintext in model context.

## Operate TinyVault

- [Key management](/guide/key-management) — back up, restore, and rotate key material.
- [Configuration](/reference/configuration) — configure the vault and studio.
- [Environment variables](/reference/environment-variables) — non-interactive and CI inputs.
- [Troubleshooting](/reference/troubleshooting) — diagnose common failures.
- [CLI reference](/cli/) — look up commands and flags.

## Integrations

The integration guides build on the core workflows:

- [Pulumi](/guide/pulumi)
- [DigitalOcean](/guide/digitalocean)
- [Codemap](/guide/codemap)
