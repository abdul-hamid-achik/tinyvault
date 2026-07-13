---
title: Pulumi & IaC
description: Drive Pulumi (and other IaC tools) with TinyVault — inject secrets at deploy time with `tvault run`, or push them into Pulumi's encrypted config. Keeps the DigitalOcean token and app secrets out of state files and shell history.
---

# Pulumi & IaC

TinyVault wraps any infrastructure tool that reads its credentials from the environment — `pulumi`, `terraform`, `docker`, `flyctl`. The same project that powers local dev also drives your deploy: one source of truth, no `.env` on disk.

## The recommended pattern: inject at deploy time

Key your secrets by their **real environment-variable names**, then let `tvault run` inject them into the Pulumi process:

```bash
tvault run -- bun run dev        # local dev
tvault run -- pulumi up          # deploy — DIGITALOCEAN_TOKEN + app secrets injected
```

Pulumi's DigitalOcean provider reads `DIGITALOCEAN_TOKEN` straight from the environment, so no provider config is needed. Write your Pulumi program to read each secret **env-first**, falling back to Pulumi config:

```ts
// infra/index.ts
import * as pulumi from '@pulumi/pulumi'

const config = new pulumi.Config()

// Env-first: tvault injects the value locally; Pulumi config is the CI fallback.
function requiredSecret(envName: string, configKey: string): pulumi.Output<string> {
  const v = process.env[envName]
  return v ? pulumi.secret(v) : config.requireSecret(configKey)
}

const databaseUrl = requiredSecret('NUXT_DATABASE_URL', 'databaseUrl')
```

This is the cleanest model: secrets are wrapped in `pulumi.secret()` (encrypted in state) only when they flow through Pulumi at all, and `tvault run` keeps them out of your shell history.

### Least privilege: inject only what the deploy needs

`tvault run` injects the whole project by default. Narrow it to just the keys `pulumi` needs with [`--only` / `--prefix`](/guide/run-and-env#injecting-only-a-subset-least-privilege):

```bash
tvault run --only DIGITALOCEAN_TOKEN,NUXT_DATABASE_URL,NUXT_REDIS_URL -- pulumi up
```

## Self-managed state backend

If you keep Pulumi state in a bucket (e.g. DigitalOcean Spaces, which speaks the S3 API), those credentials are just more secrets in the same project:

```bash
tvault set AWS_ACCESS_KEY_ID     "<spaces-key>"
tvault set AWS_SECRET_ACCESS_KEY "<spaces-secret>"
tvault set AWS_REGION            "us-east-1"
tvault set PULUMI_CONFIG_PASSPHRASE "$(openssl rand -hex 24)"

tvault run -- pulumi stack select prod
tvault run -- pulumi up
```

## CI: passphrase-free with an identity key

In CI there is no interactive passphrase. [Share](/guide/sharing) the deploy project with a CI identity once, then give the pipeline only that identity's private key as `TVAULT_IDENTITY_KEY` — no vault passphrase ever leaves your machine:

```bash
# one time, locally:
tvault identity new ci
tvault projects share <ci-public-key>      # tvault1…

# in CI (TVAULT_IDENTITY_KEY = the ci private key, tvault-key1…):
tvault run --identity ci -- pulumi up
```

See [CI/CD](/guide/ci-cd) for the full passphrase-free recipe.

## Alternative: store secrets in Pulumi config

If your team prefers Pulumi's own encrypted config over deploy-time injection, emit the `pulumi config set` lines and pipe them to a shell:

```bash
tvault env --format pulumi-config --stack prod | sh
```

Each line is `pulumi config set --secret --stack prod KEY VALUE`, shell-quoted so glob and whitespace are safe.

::: warning
This writes values into Pulumi's state/config and, transiently, your shell's process list. The `tvault run -- pulumi up` path above avoids both. Use `pulumi-config` only when storing them in Pulumi is a deliberate choice.
:::

## See also

- [Run & Environment](/guide/run-and-env) — `tvault run`, `--only`/`--prefix`, output formats
- [CI/CD](/guide/ci-cd) — passphrase-free pipelines with identity keys
- [Sharing Secrets](/guide/sharing) — identities, recipients, live-vault re-keying, and retained-data limits
