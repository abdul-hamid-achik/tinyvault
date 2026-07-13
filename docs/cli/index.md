---
title: CLI Reference
description: The complete tvault command reference — global flags, exit codes, aliases, and every subcommand with its usage and local flags.
---

# CLI Reference

`tvault` is a single binary, written in Go: a local-first secrets CLI, an MCP server (via the `mcp` subcommand), and an interactive terminal studio. This page documents every command, its usage line, and its command-local flags.

Run `tvault help` for the long-form manual or `tvault docs` for machine-readable docs aimed at agents. Every command also supports `-h`/`--help`.

::: info Looking for secret generation or an audit subcommand?
There is **no** `tvault generate` and **no** `tvault audit` command. Secret generation is available only over MCP (`vault_generate_secret`). Auditing is internal — it is surfaced over MCP (`vault_audit_log`) and in the studio, not as a CLI subcommand.
:::

## Global flags

These persistent flags are available on **every** command:

| Flag | Description |
| --- | --- |
| `--config <file>` | Compatibility selector for Viper's config input. Current typed studio settings still load from `<vault-dir>/config.yaml`; use `--vault` to relocate them. |
| `--vault <dir>` | Vault directory (default `~/.tvault`). |
| `-p`, `--project <name>` | Project to operate on (default: the active project). |
| `--json` | Emit machine-readable JSON instead of human text. |
| `-v`, `--verbose` | Verbose output. |
| `--no-agent` | Bypass a running `tvault agent` and unlock directly (also `TVAULT_NO_AGENT`). |
| `-h`, `--help` | Help for any command. |

Root-only:

| Flag | Description |
| --- | --- |
| `--version` | Print the version and exit. There is no `version` subcommand. |

```bash
tvault --version
tvault get DATABASE_URL -p api --json
tvault env -p web --no-agent
```

## Exit codes

Commands return meaningful exit codes so scripts and agents can branch on *why* something failed without parsing stderr.

| Code | Meaning |
| --- | --- |
| `0` | OK. |
| `1` | Generic error. |
| `3` | Vault is locked. |
| `4` | Secret or project not found. |
| `5` | Not initialized — run `tvault init`. |
| `6` | Wrong passphrase (unlock failed). |

```bash
tvault get MISSING_KEY; echo "exit=$?"   # exit=4
```

## Aliases

| Command | Aliases |
| --- | --- |
| `set` | `s` |
| `get` | `g` |
| `list` | `ls` |
| `delete` | `rm`, `remove` |
| `projects` | `project`, `p` |
| `history` | `versions`, `hist` |
| `studio` | `browse`, `ui` |

`tvault use <project>` is shorthand for `tvault projects use <project>`.

---

## Getting started

### `init`

```bash
tvault init
```

Create the vault and a default project. Prompts for a passphrase interactively; set `TVAULT_PASSPHRASE` to skip the prompt (useful in CI). Run this once before anything else.

This command takes no command-local flags.

### `status`

```bash
tvault status
```

Show vault state: whether it is initialized, locked or unlocked, and the active project. Takes no command-local flags.

### `doctor`

```bash
tvault doctor
```

Run read-only diagnostics over the vault and configuration. Exits non-zero if any check fails, so it is safe to gate CI on.

---

## Secrets

### `set`

```bash
tvault set DATABASE_URL postgres://user:pass@localhost/app
tvault set API_KEY --stdin
tvault set TLS_CERT -f ./cert.pem
tvault set NEW_KEY --from-env .env --key OLD_KEY
```

Store a secret. The current value is encrypted with the project DEK, and the prior version is archived in the same transaction. An empty value is rejected. Alias: `s`.

| Flag | Description |
| --- | --- |
| `--stdin` | Read the value from stdin. |
| `-f`, `--from-file <path>` | Read the value from a file. |
| `--from-env <path>` | Read the value from a dotenv file. |
| `--key <name>` | Source key when `--from-env` is used (defaults to `<key>`). |

### `get`

```bash
tvault get DATABASE_URL
tvault get API_KEY --version 3
tvault get API_KEY --from .env
```

Print a single secret value. Reading from the vault decrypts on demand and is audited. Alias: `g`.

| Flag | Description |
| --- | --- |
| `--from <path>` | Read the value from a dotenv file instead of the vault (no unlock). |
| `--version <N>` | Print a specific historical version (default: current). |

### `list`

```bash
tvault list
tvault list --prefix STRIPE_
```

List secret keys in the active project. Metadata only — values are never printed or decrypted. Alias: `ls`.

| Flag | Description |
| --- | --- |
| `--prefix <str>` | Only show keys starting with this prefix. |

### `delete`

```bash
tvault delete API_KEY
tvault delete API_KEY -y
```

Delete a secret. This also purges that key's version history. Aliases: `rm`, `remove`.

| Flag | Description |
| --- | --- |
| `-y`, `--yes` | Skip the confirmation prompt. |

### `search`

```bash
tvault search --name-like 'STRIPE_*' --since 2026-01-01T00:00:00Z
tvault search -p api --prefix DB_ --limit 50
```

Search secret **metadata** across projects. Never decrypts values.

| Flag | Description |
| --- | --- |
| `-p`, `--project <name>` | Restrict to one project (default: all projects). |
| `--prefix <str>` | Keys starting with this prefix. |
| `--name-like <pattern>` | SQL-like pattern with `*` wildcard, e.g. `STRIPE_*`. |
| `--since <RFC3339>` | Updated at or after this timestamp. |
| `--until <RFC3339>` | Updated at or before this timestamp. |
| `--min-version <N>` | Only secrets with version `>= N`. |
| `--limit <N>` | Maximum results (default `200`). |

---

## Projects

### `projects`

```bash
tvault projects <subcommand>
```

Manage projects. Aliases: `project`, `p`. Subcommands below.

#### `projects list`

```bash
tvault projects list
```

List all projects. No command-local flags.

#### `projects create`

```bash
tvault projects create api -d "Backend API secrets"
```

| Flag | Description |
| --- | --- |
| `-d`, `--description <str>` | Optional project description. |

#### `projects delete`

```bash
tvault projects delete api -y
```

| Flag | Description |
| --- | --- |
| `-y`, `--yes` | Skip the confirmation prompt. |

#### `projects use`

```bash
tvault projects use api
```

Set the active project. `tvault use <name>` is the shorthand. No command-local flags.

#### `projects share`

```bash
tvault projects share tvault1exampleRecipient
```

Share the active project with a recipient public key (`tvault1…`), so they can decrypt it with their X25519 identity. No command-local flags.

#### `projects unshare`

```bash
tvault projects unshare tvault1exampleRecipient
```

Remove a recipient from the updated live vault. This rotates the project DEK and re-encrypts every current value *and* archived version. No command-local flags.

::: warning Scope of recipient removal
A recipient may have cached the old DEK, so re-wrapping alone would leave the live vault's existing ciphertext readable. `unshare` re-encrypts the updated live state under a fresh DEK. A pre-removal snapshot or previously exported, sealed, or decrypted artifact remains readable; rotate underlying credentials when retained data is a concern.
:::

#### `projects recipients`

```bash
tvault projects recipients
```

List the recipients of the active project. Metadata only — no unlock required. No command-local flags.

### `use`

```bash
tvault use api
```

Set the active project. Shorthand for `tvault projects use`. No command-local flags.

---

## Run & environment

### `run`

```bash
tvault run -- node server.js
tvault run -e .env.local -- ./start.sh
tvault run --no-vault -- env
tvault run --only DATABASE_URL,API_TOKEN -- pulumi up
tvault run --group liftclub --env preview -- ./deploy.sh
```

Run a command with the project's secrets injected into its environment. Use `--` to separate `tvault` flags from the child command. Forwards `SIGINT`/`SIGTERM` to the child and propagates its exit code.

| Flag | Description |
| --- | --- |
| `-e`, `--env-file <path>` | Also load variables from this dotenv file. |
| `--no-vault` | Do not inject vault secrets (use only `--env-file` / inherited env). |
| `--only <k1,k2>` | Inject only these secret keys (comma-separated allowlist). |
| `--prefix <p>` | Inject only secret keys with this prefix. |
| `--group <name>` | Resolve secrets through an [environment group](/guide/env-groups)'s inheritance chain. |
| `--env <name>` | Environment within the group (requires `--group`). |

### `env`

```bash
eval "$(tvault env)"
tvault env -f dotenv > .env
tvault env -p shared --identity laptop
```

Print the project's secrets as environment assignments. The default format is `shell` with `export` prefixes, ready to `eval`. Identity-based reads add an audit row; the direct passphrase-unlock path currently does not. There is no output-file flag — redirect stdout to write to a file.

| Flag | Description |
| --- | --- |
| `-f`, `--format <fmt>` | `shell`, `dotenv`, `json`, `yaml`, or `k8s-secret` (default `shell`). |
| `-e`, `--export` | Prefix shell output with `export` (default `true`). |
| `--name <str>` | Secret name (for `k8s-secret`). |
| `--namespace <str>` | Namespace (for `k8s-secret`). |
| `--identity <name>` | Read a **shared** project with an X25519 identity — no passphrase needed. |

### `env group`

```bash
tvault env group create liftclub --env production=liftclub --env preview=liftclub-preview -d "LIFT Club"
tvault env group list
tvault env group show liftclub
tvault env group add staging --group liftclub --project liftclub-staging
tvault env group remove staging --group liftclub
tvault env group delete liftclub -y
```

Link multiple projects as named environments of the same application. Pure metadata — no new crypto, no copied values; deleting a group never touches a secret. A project belongs to at most one group unless `--force` is used on `create`. See [Environment groups](/guide/env-groups).

| Subcommand | Flags |
| --- | --- |
| `create <name>` | `-d`, `--description <str>`; `--env <name=project>` (repeatable, required); `--force`. |
| `list` | — |
| `show <name>` | — |
| `add <env>` | `--group <name>` (required); `-p`, `--project <name>` (required). |
| `remove <env>` | `--group <name>` (required). |
| `delete <name>` | `-y`, `--yes`. |

### `env diff`

```bash
tvault env diff liftclub
tvault env diff liftclub --values
tvault env diff liftclub --keys-only --json
```

Compare key sets across all environments in a group. Default is metadata-only (no unlock). `--values` also reports `same`/`different` (needs unlock; values never printed). Exit codes: `0` no drift, `1` drift, `2` group not found, `3` locked (`--values` only).

| Flag | Description |
| --- | --- |
| `--values` | Also compare values (same/different; never prints values). |
| `--keys-only` | Compare only key sets (fast, no decryption). |

### `env promote`

```bash
tvault env promote DATABASE_URL --group liftclub --from preview --to production
tvault env promote --all --group liftclub --from preview --to production --dry-run
```

Copy secret *values* from one environment to another. The source value is decrypted and re-encrypted into the target, creating a new version (prior value archived). Each promoted key is audited as `secret.promote`. Promotes always prompt unless `--yes` is passed.

| Flag | Description |
| --- | --- |
| `--group <name>` | Group name (required). |
| `--from <env>` | Source environment (required). |
| `--to <env>` | Target environment (required). |
| `<keys...>` | Positional keys to promote (omit when using `--all`). |
| `--all` | Promote all keys that differ. |
| `--dry-run` | Show what would change without writing. |
| `-y`, `--yes` | Skip the confirmation prompt. |

### `env inherit` / `pin` / `unpin` / `inherited`

```bash
tvault env inherit --group liftclub --env preview --from production
tvault env pin API_TOKEN --group liftclub --env preview
tvault env unpin API_TOKEN --group liftclub --env preview
tvault env inherited --group liftclub --env preview
```

Inheritance is metadata-only: a child resolves missing keys from a base at read time. `pin` writes the resolved value into the child (breaking inheritance for that key only); `unpin` deletes it (restoring inheritance). All four take `--group <name>` and `--env <child>` (required).

### `env seal`

```bash
tvault env seal --group liftclub --recipient tvault1ci… -o ci/migration.sealed
tvault env seal --group liftclub --keys DATABASE_URL,STRIPE_SECRET_KEY --recipient tvault1ci…
```

Seal all (or a subset of) environments into one `.env.encrypted` v2 blob keyed by environment name. Output is ciphertext only — values are never returned. In CI, decrypt with `tvault decrypt-env --identity <id> --section <env>` to extract one environment.

| Flag | Description |
| --- | --- |
| `--group <name>` | Group name (required). |
| `--recipient <tvault1…>` | X25519 recipient (repeatable; required). |
| `-o`, `--out <file>` | Output file (default: stdout). |
| `--keys <list>` | Specific keys to include (comma-separated or repeatable). |
| `--envs <list>` | Specific environments to include (comma-separated or repeatable). |

---

## Import / export / sync

### `import`

```bash
tvault import .env
tvault import --dir . --env production --dry-run
tvault import --file .env --file .env.local --overwrite
tvault import --interactive
```

Import secrets from dotenv files. An explicit file argument cannot be combined with `--file`.

| Flag | Description |
| --- | --- |
| `--dir <path>` | Directory to scan (default `.`). |
| `--env <name>` | Environment name for the default dotenv chain, e.g. `production`. |
| `--file <path>` | Dotenv file to import, in order. Repeatable. |
| `--overwrite` | Overwrite existing secrets. |
| `--dry-run` | Show what would be imported without writing. |
| `--interactive` | Select and preview files before importing. |

### `export`

```bash
tvault export -f json -o secrets.json
tvault export -f k8s-secret --name app-secrets --namespace prod
```

Export the project's secrets. **Prints plaintext** — never commit the output.

| Flag | Description |
| --- | --- |
| `-f`, `--format <fmt>` | `dotenv`, `json`, `yaml`, or `k8s-secret` (default `dotenv`). |
| `-o`, `--output <file>` | Write to a file instead of stdout. |
| `--name <str>` | Secret name (for `k8s-secret`). |
| `--namespace <str>` | Namespace (for `k8s-secret`). |

::: danger Plaintext output
`tvault export` writes decrypted values. Treat the output like the secrets themselves: keep it out of version control and off shared disks.
:::

### `diff`

```bash
tvault diff .env
tvault diff .env --values
```

Compare a dotenv file against the project. The default (key-level) diff needs no unlock. `--values` also compares values — each read is audited, but values are **never printed**.

| Flag | Description |
| --- | --- |
| `--values` | Also compare values (audits each read; never prints them). |

### `sync`

```bash
tvault sync --path .env -d pull
tvault sync -d push --overwrite
tvault sync -d mirror
```

Reconcile a dotenv file with the project. Note: `sync` has no `-p` shorthand for project — use `--project`.

| Flag | Description |
| --- | --- |
| `--path <file>` | Dotenv file path (default `.env`). |
| `-d`, `--direction <dir>` | `pull`, `push`, or `mirror` (default `pull`). |
| `--overwrite` | Allow overwriting existing keys (push/mirror). |

---

## Committable & shared secrets

These commands produce or consume the commit-safe `.env.encrypted` v2 format and other recipient-encrypted blobs.

### `encrypt-env`

```bash
tvault encrypt-env -i .env -o .env.encrypted --recipient tvault1exampleRecipient
cat .env | tvault encrypt-env > .env.encrypted
```

Encrypt a dotenv file. With one or more `--recipient`, you get **v2** output: commit-safe and not tied to your passphrase. Without `--recipient`, you get **v1**, encrypted under your passphrase.

| Flag | Description |
| --- | --- |
| `-i`, `--in <file>` | Input file (default stdin). |
| `-o`, `--out <file>` | Output file (default stdout). |
| `--recipient <tvault1…>` | Recipient public key. Repeatable. Switches output to v2. |

### `decrypt-env`

```bash
tvault decrypt-env -i .env.encrypted -o .env --identity laptop
```

Decrypt a `.env.encrypted` file. The format is auto-detected: v1 uses your passphrase, v2 uses your identity.

| Flag | Description |
| --- | --- |
| `-i`, `--in <file>` | Input file (default stdin). |
| `-o`, `--out <file>` | Output file (default stdout). |
| `--identity <name>` | Identity to unwrap v2 blobs. |

### `seal`

```bash
tvault seal -r tvault1exampleRecipient -o secrets.sealed
tvault seal --key API_KEY --key DB_URL --format k8s --name app -o sealed.yaml
```

Seal selected secrets to one or more recipients. Requires an unlock. This is the inverse of `open`. Recipients default to `.tvault-recipients`.

| Flag | Description |
| --- | --- |
| `-r`, `--recipient <tvault1…>` | Recipient public key. Repeatable. Defaults to `.tvault-recipients`. |
| `--key <name>` | Secret key to include. Repeatable (default: all). |
| `-o`, `--out <file>` | Output file (default stdout). |
| `--format <fmt>` | `raw` or `k8s` (default `raw`). |
| `--name <str>` | Kubernetes Secret name (required for `--format k8s`). |
| `--namespace <str>` | Kubernetes namespace (`--format k8s`). |

### `open`

```bash
tvault open -i secrets.sealed --identity laptop -o .env
```

Open a sealed (v2) blob with an identity. No vault unlock — only the identity.

| Flag | Description |
| --- | --- |
| `-i`, `--in <file>` | Sealed input file (default stdin). |
| `--identity <name>` | Identity to use (default `$TVAULT_IDENTITY`, then `default`). |
| `-o`, `--out <file>` | Output file (default stdout). |

### `git-filter`

```bash
tvault git-filter install --recipient tvault1exampleRecipient
tvault git-filter track 'secrets/**'
tvault git-filter status
tvault git-filter checkout
tvault git-filter uninstall
```

Manage the git clean/smudge filter that transparently encrypts tracked files on commit and decrypts them on checkout.

| Subcommand | Usage | Notes |
| --- | --- | --- |
| `install` | `git-filter install [--recipient …]` | Wire the filter into the repo. `--recipient` is repeatable. |
| `track <pattern>…` | `git-filter track 'secrets/**'` | Add `.gitattributes` patterns to filter. |
| `status` | `git-filter status` | Show filter and recipient configuration. |
| `checkout` | `git-filter checkout` | Re-run the smudge filter over tracked files. |
| `uninstall` | `git-filter uninstall` | Remove the filter from the repo. |

### `identity`

```bash
tvault identity new laptop
tvault identity list
tvault identity export laptop
```

Manage X25519 identities (passphrase-independent keypairs at `~/.tvault/identities/<name>.key`). The public half (`tvault1…`) is shareable; the private half (`tvault-key1…`) must never be committed.

| Subcommand | Usage | Flags |
| --- | --- | --- |
| `new [name]` | `identity new [name]` | name defaults to `default` |
| `list` | `identity list` | — |
| `export [name]` | `identity export [name]` | `--force` (allow printing off a TTY) |

::: danger `identity export` prints a private key
`tvault identity export` prints the `tvault-key1…` **private** key. It is TTY-guarded — printing to a non-terminal requires `--force`. Never commit, log, or paste the private half.
:::

---

## Kubernetes

### `k8s render`

```bash
# Author the sealed blob with `seal --format k8s`, then render it:
tvault seal --format k8s --name app -r tvault1exampleRecipient -o sealed.yaml
tvault k8s render -i sealed.yaml --identity laptop | kubectl apply -f -
```

Render a sealed blob into a Kubernetes `Secret`. Authoring is done with `seal --format k8s`; `k8s render` does the decryption side. No vault unlock — only the identity.

| Flag | Description |
| --- | --- |
| `-i`, `--in <file>` | Sealed input file (default stdin). |
| `--identity <name>` | Identity to unwrap with. |
| `-o`, `--out <file>` | Output file (default stdout). |

::: danger Rendered output is plaintext
`k8s render` emits a plaintext `Secret` manifest. Pipe it straight to `kubectl apply` — never commit it.
:::

---

## Versioning

### `history`

```bash
tvault history API_KEY
```

Show the version history for a key. Metadata only — no unlock, no values. Aliases: `versions`, `hist`. No command-local flags.

### `rollback`

```bash
tvault rollback API_KEY --to 3
```

Restore an earlier version. Non-destructive: it re-stores the old version as a *new* one, so version numbers stay monotonic and are never reused.

| Flag | Description |
| --- | --- |
| `--to <N>` | Version to restore (**required**). |

---

## Agent & shell

### `agent`

```bash
tvault agent start
tvault agent start --idle 30m
tvault agent start --require-token --token-file ~/.tvault/agent.token
tvault agent status
tvault agent stop
```

Run the local agent (Unix only). It unlocks the vault once and serves secret reads over a private 0600 unix socket, so `get`/`env`/`run` skip the prompt and Argon2id. It caches only the KEK and reopens the vault per request, so direct CLI access keeps working. `agent start` runs in the **foreground** — background it yourself (`&`, `nohup`, systemd, launchd).

| Subcommand | Flags |
| --- | --- |
| `start` | `--idle <dur>` (default `15m`; `0` = never), `--require-token`, `--token-file <path>` |
| `status` | — |
| `stop` | — |

::: warning Capability tokens are privilege separation, not same-uid defense
`--require-token` gates an **OS-confined (different-uid) delegate** only. A malicious **same-uid** process can read the token file or dial the socket directly, so tokens are not a defense against it. For untrusted/CI/container delegation, use a scoped identity instead.
:::

### `hook`

```bash
tvault hook zsh   >> ~/.zshrc
tvault hook direnv
```

Print a shell snippet that defines `tvault_load` for loading a project's secrets via the agent. No command-local flags.

| Argument | Values |
| --- | --- |
| `<shell>` | `bash`, `zsh`, `fish`, `direnv` |

---

## CI/CD

### `ci init`

```bash
tvault ci init --provider github-actions
tvault ci init --provider gitlab --mode identity --identity ci
tvault ci init --provider github-actions --output -
```

Scaffold a CI workflow that consumes the vault. `--mode passphrase` uses `TVAULT_PASSPHRASE`; `--mode identity` scaffolds a passphrase-free flow using `TVAULT_IDENTITY_KEY`.

| Flag | Description |
| --- | --- |
| `--provider <name>` | `github-actions` or `gitlab` (**required**). |
| `--mode <mode>` | `passphrase` or `identity` (default `passphrase`). |
| `--identity <name>` | Identity to reference (default `default`). |
| `--output <path>` | Output path (`-` for stdout). |

---

## Maintenance

### `key rotate`

```bash
tvault key rotate
```

Re-encrypt the vault under a new passphrase. It rewraps the DEKs; the secret values themselves are untouched.

::: warning Invalidates old v1 encrypted files
A passphrase rotation invalidates any v1 `.env.encrypted` files made under the **old** passphrase. v2 (recipient-encrypted) files are unaffected because they are KEK-independent.
:::

### `backup`

```bash
tvault backup ./tvault-backup.db
```

Write a byte-for-byte database backup to `<path>`. Secret payloads and key material remain encrypted, while operational metadata remains readable. No command-local flags.

### `restore`

```bash
tvault restore ./tvault-backup.db -y
```

Restore the vault from a backup file.

| Flag | Description |
| --- | --- |
| `-y`, `--yes` | Skip the confirmation prompt. |

### `unlock`

```bash
tvault unlock
```

Unlock the vault for the session. No command-local flags.

### `lock`

```bash
tvault lock
```

Lock the vault and clear cached keys. No command-local flags.

### `self-update`

```bash
tvault self-update
tvault self-update --check
tvault self-update --version v0.11.1
```

Update the `tvault` binary in place: download the latest release for this OS/arch from the official GitHub releases, verify its SHA-256 checksum, and atomically replace the running binary. Alias: `upgrade`. The download source is fixed and cannot be overridden at runtime — a self-replacing binary must not let an attacker redirect it.

`--check` reports whether an update is available without installing. `--version` installs a specific release tag (to pin or downgrade). If you installed via Homebrew or a system package (`apt`/`dnf`/`apk`), update through that package manager instead so its bookkeeping stays correct.

| Flag | Description |
| --- | --- |
| `-c`, `--check` | Only report whether an update is available; don't install. |
| `--version <tag>` | Install a specific release tag (e.g. `v0.11.1`) instead of the latest. |

---

## Interactive UI

### `studio`

```bash
tvault studio
tvault studio api
tvault studio --rw
tvault studio --single-pane --no-anim --audit-limit 50
```

Launch the interactive terminal studio. Requires a TTY. **Read-only by default** — the only decryption is an on-demand reveal (audited like `tvault get`). Aliases: `browse`, `ui`.

| Flag | Description |
| --- | --- |
| `--single-pane` | Force single-pane mode (small terminals). |
| `--no-anim` | Disable animations (also `$TVAULT_NO_ANIM`). |
| `--audit-limit <N>` | Recent audit entries to load (default `100`). |
| `--rw` | Enable in-app new/edit/delete; read-only by default. |

::: tip
`--rw` edits reuse the same audited `SetSecret`/`DeleteSecret` path as the CLI. Rotation and project create/delete stay in the CLI.
:::

---

## AI / MCP

TinyVault speaks MCP through the same binary. See the [MCP overview](/mcp/) and the [tools reference](/mcp/tools).

### `mcp`

```bash
tvault mcp
```

Start the MCP server over stdio. Loads `~/.tvault/mcp-policy.yaml` and serves the agent-facing tools, resources, and prompts. Your MCP host (Claude Code, Claude Desktop, or any MCP client) usually launches this for you rather than you running it by hand. It unlocks the vault from `TVAULT_PASSPHRASE` (there is no prompt over stdio). Alias: `mcp-server`. No command-local flags.

::: warning MCP output redaction is a safety net, not a control
When policy enables `redact_output`, redaction replaces literal values longer than three characters and can be evaded by shortening or transforming a value (e.g. base64). It is a last line of defense, not access control. `vault_get_secret` deliberately returns plaintext, and `vault_run_with_secrets` can carry plaintext through arbitrary child output.
:::

### Internal commands

A few commands are hidden because they are wired up by other tools, not run by hand:

- `git-clean` / `git-smudge` — the clean/smudge endpoints invoked by git through `git-filter install`.

---

## Help & docs

### `help`

```bash
tvault help
tvault help workflow
tvault help safety --json
```

Long-form manual. Topics: `workflow`, `safety`, `recipes`, `output`, `agent`, `troubleshooting`, `studio`, `topics`.

| Flag | Description |
| --- | --- |
| `--json` | Emit the manual as JSON. |

### `docs`

```bash
tvault docs
tvault docs run
tvault docs -t mcp
```

Machine-readable docs for agents. Subtopics: `features`, `topics`, `run`, `mcp`, `interpolate`, `sync`, `encrypted-env`, `safety`, `quickstart`, `studio`.

| Flag | Description |
| --- | --- |
| `-t`, `--topic <name>` | Print a specific subtopic. |

### `completion`

```bash
tvault completion zsh > "${fpath[1]}/_tvault"
```

Generate a shell completion script.

| Argument | Values |
| --- | --- |
| `<shell>` | `bash`, `zsh`, `fish`, `powershell` |

---

## See also

- [Getting started](/guide/getting-started) — install, init, and your first secret.
- [Run & env](/guide/run-and-env) — inject secrets into processes.
- [MCP tools](/mcp/tools) — the agent-facing tool surface.
- [Configuration](/reference/configuration) — config file and environment variables.
