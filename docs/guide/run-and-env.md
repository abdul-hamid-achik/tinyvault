---
title: Run & Environment
description: Inject TinyVault secrets into a process, a remote SSH command, or your shell at runtime with tvault run, tvault ssh, and tvault env.
---

# Run & Environment

Use your secrets at runtime without writing them to disk or pasting them into shell history. `tvault run` injects a project's secrets into a single child process, `tvault ssh` does the same for a remote command over SSH, `tvault env` emits them for `eval`, and `tvault export` writes a file when you genuinely need one. Committed `.env` templates can carry `tvault://` placeholders that resolve against the vault at run time.

## tvault run — inject secrets into one process

`tvault run -- <command> [args...]` unlocks the active project, sets each secret as an environment variable in a child process, runs the command, and exits with the child's exit code. TinyVault does not write those values to a file or export them into your parent shell; they are still plaintext in TinyVault and child-process memory while the command runs.

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
tvault run --strict --only DIGITALOCEAN_TOKEN,NUXT_DATABASE_URL -- pulumi up
tvault run --prefix NUXT_ -- bun run dev
```

- `--only` is an explicit allowlist (comma-separated). A listed key that doesn't exist prints a warning to stderr for backward compatibility.
- `--strict` turns a missing `--only` key into an error before the child starts. Use it for CI, deployments, and migrations.
- `--prefix` injects every key with that prefix.
- Given both, a key is injected if it matches **either** (union).
- Explicit `${tvault://PROJECT/KEY}` references in `--env-file` resolve the named project; `${tvault://KEY}` and `${tvault://current/KEY}` resolve the active project. The filters only narrow bulk auto-injection.

The selectors are provider-side: TinyVault enumerates key metadata and decrypts
only the selected values. This remains true for direct reads, environment-group
inheritance, recipient identities, and a current local agent. An env-file
placeholder decrypts only its referenced key; it does not turn a selected run
back into an all-secrets read.

`--only`/`--prefix` cannot be combined with `--no-vault` (there are no vault secrets to select).

### What the child does *not* inherit

The child gets the selected values and nothing else from TinyVault: every
`TVAULT_*` variable is removed from its environment before it starts. A wrapped
process that leaks or logs its environment cannot leak your passphrase, identity
key, or agent token along with the two values you gave it.

The consequence to know about is a **nested `tvault`**:

```bash
tvault run --only API_KEY -- tvault get API_KEY -p demo    # works (served by the agent)
tvault run --only API_KEY -- tvault set PROBE x -p demo    # "vault is locked" (exit 3)
```

Reads route through the [agent](/guide/agent) and keep working. Writes do not:
the agent serves reads only and never hands out the key, and the child inherited
no passphrase — so `set`, `delete`, `import`, and `rotate` have no credential.
Run vault writes outside `tvault run`, or pass that one child a credential
explicitly (`sh -c 'TVAULT_PASSPHRASE=... tvault set …'`), knowing it then holds
the whole vault rather than the subset you selected. See
[Troubleshooting](/reference/troubleshooting).

### Resolving through an environment group

When the active project is part of an [environment group](/guide/env-groups), `--group <name> --env <child>` makes `run` resolve the child's secrets **through the inheritance chain**: the child's own keys are loaded, then any missing keys are filled in from the base environment at run time. No values are copied — inheritance is metadata-only, so the child always sees the base's latest value.

```bash
tvault run --group liftclub --env preview -- ./deploy.sh
```

This composes with `--only`/`--prefix`: the allowlist filters the merged (child + inherited) key set. Pin a key (`tvault env pin`) to give the child its own local copy and break inheritance for that key only.

### Running a shared project without a passphrase

`--identity <name>` gives `run` the same recipient-read behavior as `env`:
it decrypts a project shared to that X25519 identity without unlocking the
owner vault. This is useful for CI and remote deployment hosts.

```bash
tvault run --identity deploy --strict --only DIGITALOCEAN_TOKEN -- pulumi up
```

The identity comes from its local key file or, if no matching file exists,
`TVAULT_IDENTITY_KEY`. It can resolve an environment group too: share every
project whose values participate in the selected environment (the child and
its configured base) with that identity, then use both flag sets together.
TinyVault reads the group metadata but never falls back to the owner passphrase
for a project that identity cannot open. Identity mode still cannot combine
with `--no-vault`.

Identity mode reads the recipient wraps and ciphertext from the local
`vault.db`; it does not fetch a vault over the network. Use it on a trusted
host or ephemeral runner that already has a protected vault copy containing
the shared project. Use recipient-sealed files when a target should not receive
a vault database.

```bash
tvault run --identity deploy --group app --env preview \
  --strict --only DATABASE_URL -- ./deploy.sh
tvault env --identity deploy --group app --env preview \
  --only DATABASE_URL --format dotenv
```

### Signal forwarding and exit codes

`tvault run` forwards `SIGINT` and `SIGTERM` to the child process, so `Ctrl-C` and orderly shutdowns reach your application. When the child exits, `tvault` propagates the child's exit code as its own. This makes `tvault run` safe to use as a process wrapper in supervisors, Procfiles, and CI steps.

### Flags

| Flag | Description |
| --- | --- |
| `-e`, `--env-file <path>` | Merge a dotenv file; vault values win on conflict. |
| `--no-vault` | Skip vault secrets; use only `--env-file` values. |
| `--only <k1,k2>` | Inject only these secret keys (comma-separated allowlist). |
| `--prefix <p>` | Inject only secret keys with this prefix. |
| `--strict` | Fail before execution when an explicit `--only` key is missing. |
| `--identity <name>` | Read a shared project with an X25519 identity instead of the vault passphrase. |
| `--group <name>` | Resolve secrets through an [environment group](/guide/env-groups)'s inheritance chain. |
| `--env <name>` | Environment within the group (requires `--group`). |

## tvault ssh — inject secrets into a remote command

`tvault ssh <destination> -- <command>` is `tvault run` over SSH. It loads the project locally, then streams a POSIX `export` script over the SSH channel into `sh -s` on the remote host. The remote process sees the secrets as environment variables. Nothing is written to remote disk, and values do not appear on the `ssh` command line (so they do not show up in `ps`).

```bash
tvault ssh deploy@prod -- systemctl restart api
tvault ssh --only DATABASE_URL deploy@prod -- ./migrate
tvault ssh --ssh-arg=-p --ssh-arg=2222 deploy@prod -- hostname
tvault ssh --identity ci deploy@prod -- docker compose up
```

The remote host needs a POSIX `sh`. Extra OpenSSH client flags (`-p`, `-i`, `-F`, …) go in repeatable `--ssh-arg` values so TinyVault does not parse them as its own flags. `--only`, `--prefix`, `--strict`, `--identity`, `--group`, and `--env` work the same as on `tvault run`.

::: warning
The secrets are still plaintext in the remote process environment — the same residual risk as `tvault run`. Prefer `--only` / `--prefix` so the remote command receives only the keys it needs. Do not use `tvault ssh` to dump a `.env` onto the server; for a committed remote artifact, use [committable secrets](/guide/committable-secrets).
:::

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
| `json` | A flat JSON object of key/value pairs. Control bytes are escaped; `&`, `<`, and `>` stay literal. |
| `yaml` | A flat YAML mapping. |
| `k8s-secret` | A Kubernetes `Secret` manifest (base64 `data:`). Requires `--name`. |
| `pulumi-config` | `pulumi config set --secret KEY VALUE` lines (shell-quoted). Optional `--stack`. |

```bash
tvault env --format dotenv > .env
tvault env --only DATABASE_URL,MIGRATIONS_DATABASE_URL --format dotenv
tvault env --prefix CHALUPA_ --format dotenv
tvault env --format json | jq .
tvault env --format yaml > secrets.yaml
tvault env --format k8s-secret --name app-secrets --namespace prod > secret.yaml
tvault env --format pulumi-config --stack prod | sh   # push into Pulumi config
```

`--only` and `--prefix` are provider-side selectors: TinyVault queries key
metadata first and decrypts only the matching values, including for recipient
identity reads, identity-backed environment groups, and passphrase-backed
environment-group inheritance. An explicit missing
`--only` key fails before any output is emitted. When selectors are present,
the command uses a direct short-lived vault read instead of the agent's
all-values operation.

::: tip Pulumi
For Pulumi you usually want `tvault run -- pulumi up`: it injects provider credentials at deploy time without first copying them into Pulumi config or your parent shell. Your Pulumi program still determines what is persisted in state. The `pulumi-config` format is for teams who intentionally store values in Pulumi's encrypted config. See [Pulumi & IaC](/guide/pulumi).
:::

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
| `--only <k1,k2>` | Emit only these keys; a missing explicit key fails closed. |
| `--prefix <p>` | Emit only keys with this prefix; combines with `--only` as a union. |

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
