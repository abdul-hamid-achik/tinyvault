---
title: Run & Environment
description: Inject TinyVault secrets into a process or your shell at runtime with tvault run and tvault env, without leaving plaintext on disk.
---

# Run & Environment

Use your secrets at runtime without writing them to disk or pasting them into shell history. `tvault run` injects a project's secrets into a single child process, `tvault env` emits them for `eval`, and `tvault export` writes a file when you genuinely need one. Committed `.env` templates can carry `tvault://` placeholders that resolve against the vault at run time.

## tvault run — inject secrets into one process

`tvault run -- <command> [args...]` unlocks the active project, sets each secret as an environment variable in a child process, runs the command, and exits with the child's exit code. The secrets live only in that child's environment — never in a file, never in your shell.

```bash
tvault run -- npm start
tvault run -- python manage.py runserver
tvault run -p production -- ./deploy.sh
```

The first run prompts for your passphrase. If a [local agent](/guide/agent) is running, `run` routes through it and skips the prompt and the Argon2id derivation; `--no-agent` (or `TVAULT_NO_AGENT`) forces a direct unlock.

### The `--` separator

Use `--` to stop TinyVault from interpreting flags meant for your command. Everything after `--` is passed through verbatim.

```bash
tvault run --env-file .env -- npm start              # npm gets no extra flags
tvault run -- docker compose up --build              # --build goes to compose
tvault run python manage.py runserver                # no flag conflict, -- optional
```

The `--` is only required when your command takes flags that `tvault` would otherwise parse. When there is no conflict you can omit it, but using it always is the safe habit.

### Merging a dotenv file

`-e`/`--env-file <path>` loads a dotenv file and merges it with the vault. **The vault wins on conflict** — a key present in both the file and the vault takes the vault's value. This lets you keep non-secret config (`PORT`, `LOG_LEVEL`) in a committed `.env` while secrets stay in the vault.

```bash
tvault run --env-file .env -- npm start
tvault run --env-file .env.production -- ./deploy.sh
```

To run with **only** the dotenv file and skip the vault entirely, add `--no-vault`:

```bash
tvault run --no-vault --env-file .env -- npm test
```

::: warning
With `--no-vault`, any `tvault://` placeholders in the file cannot be resolved (the vault is not loaded) and `run` will error. Use `--no-vault` only for files that contain literal values.
:::

### Injecting only a subset (least privilege)

By default `run` injects **every** secret in the project. When you wrap a third-party tool (`pulumi`, `terraform`, `docker`), inject only the keys it needs to shrink the blast radius:

```bash
tvault run --only DIGITALOCEAN_TOKEN,NUXT_DATABASE_URL,NUXT_REDIS_URL -- pulumi up
tvault run --prefix NUXT_ -- bun run dev
```

- `--only` is an explicit allowlist (comma-separated). A listed key that doesn't exist prints a warning to stderr (so typos surface) but doesn't fail.
- `--prefix` injects every key with that prefix.
- Given both, a key is injected if it matches **either** (union).
- Explicit `${tvault://...}` references in `--env-file` still resolve against the full project — the filters only narrow the bulk auto-injection.

`--only`/`--prefix` cannot be combined with `--no-vault` (there are no vault secrets to select).

### Signal forwarding and exit codes

`tvault run` forwards `SIGINT` and `SIGTERM` to the child process, so `Ctrl-C` and orderly shutdowns reach your application. When the child exits, `tvault` propagates the child's exit code as its own. This makes `tvault run` safe to use as a process wrapper in supervisors, Procfiles, and CI steps.

### Flags

| Flag | Description |
| --- | --- |
| `-e`, `--env-file <path>` | Merge a dotenv file; vault values win on conflict. |
| `--no-vault` | Skip vault secrets; use only `--env-file` values. |
| `--only <k1,k2>` | Inject only these secret keys (comma-separated allowlist). |
| `--prefix <p>` | Inject only secret keys with this prefix. |

## tvault env — emit secrets for your shell

`tvault env` prints the active project's secrets to stdout in a chosen format. The default is shell-friendly `export` lines you can `eval`:

```bash
eval "$(tvault env)"
# or
source <(tvault env)
```

::: warning
`eval`/`source` puts plaintext secrets into your **current shell's** environment, where they persist and are inherited by every command you run in that shell. Prefer `tvault run` when you only need secrets for a single process. Reach for `tvault env` when you genuinely need them shell-wide — for example, an interactive debugging session.
:::

### Formats

Select a format with `-f`/`--format`. The default is `shell`.

| Format | Output |
| --- | --- |
| `shell` (default) | `export KEY=value` lines (shell-quoted). |
| `dotenv` | `KEY=value` lines for a `.env` file. |
| `json` | A flat JSON object of key/value pairs. |
| `yaml` | A flat YAML mapping. |
| `k8s-secret` | A Kubernetes `Secret` manifest (base64 `data:`). Requires `--name`. |

```bash
tvault env --format dotenv > .env
tvault env --format json | jq .
tvault env --format yaml > secrets.yaml
tvault env --format k8s-secret --name app-secrets --namespace prod > secret.yaml
```

For the `shell` format, `-e`/`--export` (on by default) controls the `export ` prefix. Pass `--export=false` to emit bare `KEY=value` lines:

```bash
tvault env --export=false
```

::: danger
The `k8s-secret` format emits **base64-encoded plaintext**, not encrypted data — base64 is encoding, not encryption. Pipe it straight into `kubectl apply -f -`; never commit the rendered manifest. For a recipient-encrypted, commit-safe Kubernetes workflow, author with `tvault seal --format k8s` and render with `tvault k8s render` (see [Committable secrets](/guide/committable-secrets)).
:::

### Reading a shared project without a passphrase

`--identity <name>` reads a project that was [shared](/guide/sharing) with you, decrypting it with an X25519 identity instead of the vault passphrase. This is the path for CI, remote hosts, and agents that hold a recipient key but no passphrase.

```bash
tvault env --identity ci --format dotenv > .env
```

The identity is resolved from the named key file, or — when no file exists — from the `TVAULT_IDENTITY_KEY` environment variable carrying a `tvault-key1examplePrivate` string. Every passphrase-free read prints a one-line notice to stderr, so it is never silent. See [CI/CD](/guide/ci-cd) for the full wiring.

### Flags

| Flag | Description |
| --- | --- |
| `-f`, `--format <fmt>` | `shell` (default), `dotenv`, `json`, `yaml`, `k8s-secret`. |
| `-e`, `--export` | Include the `export ` prefix (shell format only; default `true`). |
| `--name <str>` | Kubernetes `Secret` name (required for `k8s-secret`). |
| `--namespace <str>` | Kubernetes namespace (`k8s-secret`; default `default`). |
| `--identity <name>` | Read a shared project with an X25519 identity, no passphrase. |

## tvault export — write a file

`tvault export` is `tvault env` aimed at a file. It defaults to `dotenv` format and writes to stdout unless you give it `-o`/`--output`.

```bash
tvault export --format dotenv -o .env
tvault export --format json -o secrets.json
tvault export --format k8s-secret --name app-secrets -o secret.yaml
```

::: danger
`tvault export` writes **plaintext** to disk. Add the output path to `.gitignore`, scope its file permissions, and delete it when you are done. If you need a file you can commit, use the encrypted-env or git-filter workflows in [Committable secrets](/guide/committable-secrets) instead.
:::

### Flags

| Flag | Description |
| --- | --- |
| `-f`, `--format <fmt>` | `dotenv` (default), `json`, `yaml`, `k8s-secret`. |
| `-o`, `--output <file>` | Write to a file instead of stdout. |
| `--name <str>` | Kubernetes `Secret` name (required for `k8s-secret`). |
| `--namespace <str>` | Kubernetes namespace (`k8s-secret`; default `default`). |

## `tvault://` interpolation in .env files

A `.env` file can hold **placeholders** instead of values. The placeholder names a vault key; the real value is filled in at run time. Because the file contains no secret material, you can commit it.

A placeholder is written inside a `${...}` wrapper with a `tvault://` scheme. The grammar is:

```dotenv
# Current project — recommended forms:
DATABASE_URL=${tvault://DATABASE_URL}
STRIPE_KEY=${tvault://current/STRIPE_KEY}

# Explicit project, for a multi-project template:
DB_PROD=${tvault://production/DATABASE_URL}
```

Read the two-segment form as `tvault://<project>/<key>`. The single-segment form `tvault://<key>` (no slash) and the literal `tvault://current/<key>` both mean "the active project" — resolved at run time, so the same committed file works across environments. The key must be a single segment (no further `/`).

You can verify the exact syntax from the binary itself:

```bash
tvault docs interpolate
```

### How resolution works

When you run `tvault run --env-file <file> -- <command>`, the dotenv parser keeps every placeholder **verbatim** — it is inert text on disk. At run time, `tvault run` walks the file and replaces each `${tvault://...}` reference with the value from the unlocked vault.

```bash
tvault run --env-file .env -- npm start          # placeholders resolved here
```

Resolution is deliberately narrow:

- It is a **literal substitution** between `${` and `}`. There is no shell expansion, no command substitution, no arithmetic, no nesting.
- Only references with the `tvault://` scheme are touched. A value that merely happens to contain `tvault://` outside a `${...}` wrapper (or a `${VAR}` that is not a `tvault://` reference) is left exactly as written.
- A reference can sit inside a larger value (`postgres://${tvault://DB_USER}:${tvault://DB_PASS}@db/app`), and multiple references in one value are each resolved.
- A malformed reference, a current-project reference with no active project, or a missing key is a **hard error** — `run` fails rather than passing a broken value through. Partial references never leak into the process as literal text.

::: info
Only `tvault run` resolves `${tvault://...}` against the unlocked vault. The same placeholder text is preserved verbatim by the [sync and import](/guide/dotenv) surfaces, which store the literal reference rather than expanding it. `tvault env` and `tvault export` likewise do not expand placeholders; they emit your vault's literal values.
:::

### A commit-safe .env template

This entire file is safe to check into version control: it contains zero secret values, only references to vault keys.

```dotenv
# .env — committed template. No secret values live here.
# Non-secret config can use literal values:
PORT=3000
LOG_LEVEL=info

# Secrets are resolved from the active project at run time:
DATABASE_URL=${tvault://DATABASE_URL}
STRIPE_KEY=${tvault://current/STRIPE_KEY}

# Composed value — references can sit inside a larger string:
REDIS_URL=redis://:${tvault://REDIS_PASSWORD}@localhost:6379/0

# Pull one value from a specific project:
ANALYTICS_KEY=${tvault://production/ANALYTICS_KEY}
```

Run it:

```bash
tvault run --env-file .env -- npm start
```

At run time, `PORT` and `LOG_LEVEL` pass through as literals, while `DATABASE_URL`, `STRIPE_KEY`, `REDIS_URL`, and `ANALYTICS_KEY` are filled from the vault. If a referenced key is missing, the command refuses to start.

::: tip
Pair this template with a [git filter](/guide/git-filter) or [encrypted .env](/guide/committable-secrets) when you also want some values stored (encrypted) alongside the repo, rather than only referenced.
:::

## Exit codes

`tvault run` propagates the **child process's** exit code. The other commands on this page use TinyVault's standard exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Generic error. |
| `3` | Vault is locked. |
| `4` | Secret or project not found (for example, a `tvault://` reference to a missing key). |
| `5` | Vault not initialized — run `tvault init`. |
| `6` | Wrong passphrase. |

## Global flags

Every command on this page also accepts the global persistent flags: `--config <file>`, `--vault <dir>`, `-p`/`--project <name>`, `--json`, `-v`/`--verbose`, and `--no-agent`. Use `-p` to target a project other than the active one without switching:

```bash
tvault run -p staging --env-file .env -- ./smoke-test.sh
tvault env -p production --format dotenv > prod.env
```

## See also

- [Working with .env files](/guide/dotenv) — import, diff, two-way sync, and the full dotenv surface.
- [Committable secrets](/guide/committable-secrets) — encrypted `.env` files and recipient-sealed values you can commit.
- [The local agent](/guide/agent) — unlock once, run prompt-free.
- [CI/CD](/guide/ci-cd) — passphrase-free reads with `--identity` and `TVAULT_IDENTITY_KEY`.
