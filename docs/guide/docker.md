---
title: Docker
description: Inject TinyVault secrets into docker build, compose, and run without putting values on the Docker command line.
---

# Docker

`tvault docker` wraps the Docker CLI so a project's secrets reach a **build**, a **compose** stack, or a **container** without putting values on the `docker` command line or writing a plaintext `.env`.

You still need Docker on `PATH`. TinyVault does not talk to the daemon itself.

```bash
tvault docker build --only NPM_TOKEN -- -t app .
tvault docker compose --only DATABASE_URL -- up
tvault docker run --only DATABASE_URL -- --rm alpine env
tvault docker init    # Dockerfile + compose snippets
```

`--only`, `--prefix`, `--strict`, `--identity`, `--group`, and `--env` work the same as on `tvault run`. Put TinyVault flags before `--`; everything after is passed to Docker.

## BuildKit secret mounts

`tvault docker build` sets `DOCKER_BUILDKIT=1` and adds one `--secret id=KEY,env=KEY` per selected key. Values live in the `docker` process environment, not on argv. The Dockerfile reads them from a build tmpfs:

```dockerfile
FROM node:22
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=secret,id=NPM_TOKEN \
    NPM_TOKEN="$(cat /run/secrets/NPM_TOKEN)" npm ci
COPY . .
```

```bash
tvault docker build --only NPM_TOKEN -- -t app .
```

If you only read the secret in that `RUN`, it is not stored in an image layer. Prefer `--only` / `--prefix` so the build client only sees the keys the Dockerfile mounts.

Print a starter snippet with `tvault docker init`.

## Compose interpolation

`tvault docker compose` injects selected keys into the compose **process** environment. Compose expands `${KEY}` in the compose file from that environment. Values do not appear as `-e` flags on argv.

```yaml
services:
  app:
    build: .
    environment:
      DATABASE_URL: ${DATABASE_URL}
```

```bash
tvault docker compose --only DATABASE_URL -- up
```

For a compose **build** secret, declare it from the same environment:

```yaml
secrets:
  npm_token:
    environment: NPM_TOKEN
services:
  app:
    build:
      secrets:
        - npm_token
```

## `docker run`

`tvault docker run` adds `-e KEY` (the **name** only) for each selected key. Docker reads the value from the client environment, so it does not appear on argv. The container still has the value in its environment — the same residual risk as `tvault run`.

```bash
tvault docker run --only DATABASE_URL -- --rm alpine env
```

## What this does not do

- It does not put a vault inside the image. In-cluster or CI fetch still uses a [recipient identity](/guide/sharing) (`TVAULT_IDENTITY_KEY`) and committed ciphertext, not the developer laptop's passphrase.
- It does not replace `tvault run -- docker compose up`, which already injects the full project env. `tvault docker compose --only …` is the least-privilege form.
- BuildKit `--secret` requires a modern Docker engine (BuildKit is the default). The wrapper sets `DOCKER_BUILDKIT=1` on the child.

::: warning
Compose interpolation and `docker run` still place plaintext in a process or container environment. Treat that process as trusted. For a file you can commit, use [committable secrets](/guide/committable-secrets) instead of baking values into an image.
:::
