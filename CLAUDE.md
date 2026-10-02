# CLAUDE.md — working in this repo with Claude Code

TinyVault is a **single Go binary**: a local-first secrets CLI (`tvault`) plus
an MCP server (`tvault mcp`, alias `mcp-server`), backed by one local bbolt
database whose secret payloads and key material are encrypted. No servers, no
accounts, no cloud. There is no interactive TUI; humans use the CLI. The optional
Electron GUI in `app/` is a front end that drives `tvault mcp` — it never opens
`vault.db` itself. See [app/README.md](app/README.md).

**Read these first — they are the source of truth:**
- [AGENTS.md](AGENTS.md) — project structure, code conventions, security
  rules, dependency table. **Read it before any non-trivial change.**
- [Architecture](docs/reference/architecture.md) and
  [Security](docs/reference/security.md) — crypto design and threat boundary.
- [README.md](README.md) — user-facing quickstart and feature list.
- Docs site: Vercel auto-builds **`main` only** (`docs/vercel.json`). Tags release the CLI; do not promote docs.
- [ROADMAP.md](ROADMAP.md) — product direction and deferred work.

Scope split, so the two briefs do not drift into each other: **AGENTS.md is
structure and conventions** (where things live, import order, the commit
checklist); **this file is invariants and rationale** (the properties that must
survive a refactor, and the incident or test that pins each one).

## Quick commands (there is no Makefile/Taskfile)

```bash
go build ./...                 # Build
go test -race -count=1 ./...   # Test (race detector)
golangci-lint run ./...        # Lint — MUST be 0 issues
govulncheck ./...              # Security Scan
```

CI (`.github/workflows/ci.yml`) gates `main` on four jobs: **Test, Lint,
Security Scan, Build**. All four must be green. The Build job is a six-way
cross-compile with `CGO_ENABLED=0`, so `go build ./...` is necessary but not
quite sufficient. Three more workflows run beside it: `ci-app.yml` (desktop app:
typecheck, build, contract test — only on `app/**` changes), `release.yml`
(GoReleaser on `v*` tags), and `npm-publish.yml` (publishes
`@thelacanians/tinyvault` after a Release, then smoke-tests it on three OSes).

> ⚠️ **Run `golangci-lint run ./...` locally before pushing.** It is not
> installed by default. **Match CI's pinned versions** — `ci.yml` uses
> golangci-lint **v2.12.2** and govulncheck **v1.4.0**, and a newer local linter
> reports findings CI does not (new rules land between versions), which reads
> exactly like a red `main` that is not:
> `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2`,
> `go install golang.org/x/vuln/cmd/govulncheck@v1.4.0`.
> `go build` + `go test` passing is **not** enough — the Lint job (gocritic,
> exhaustive, revive, unparam, gosec, …) is strict and is a common cause of a
> red `main`. Config lives in `.golangci.yml`.

## Non-negotiable conventions (full list in AGENTS.md)

- **Imports:** goimports with `-local github.com/abdul-hamid-achik/tinyvault`
  (stdlib, third-party, local — three groups).
- **Octal literals:** `0o600` / `0o700`, never `0600`.
- **Errors:** wrap with `%w`; sentinel errors in `internal/vault/errors.go`.
- **Security:** never log or print a secret value; never commit `~/.tvault/`
  or `*.db`; AES-256-GCM + Argon2id only; output redaction is a safety net,
  not a control. Only deliberately value-returning surfaces such as
  `vault_get_secret` may return plaintext, and they must remain explicit and
  policy-gated.
- **Exhaustive switches:** a `default:` clause counts as exhaustive
  (`default-signifies-exhaustive`), so an enum's trailing count sentinel does not
  need a case that could only panic.

## Sharing & committable secrets (the recipient layer)

- `internal/crypto/recipient.go` is the asymmetric layer: X25519 → HKDF-SHA256
  → ChaCha20-Poly1305 wrapping (`WrapDEK`/`UnwrapDEK`, `Identity`). It uses
  only stdlib `crypto/ecdh` + already-vendored `x/crypto` — **do not add
  `filippo.io/age` or any new crypto dependency** without discussion.
- Built on it: `tvault identity new/list`, `projects share/unshare/recipients`
  (recipient removal **rotates the DEK and re-encrypts every current value and
  archived version in the updated live vault** via `store.RekeyProject`;
  pre-removal snapshots and previously distributed artifacts remain readable),
  the `.env.encrypted` **v2** format (`EncryptV2`/`DecryptV2`, commit-safe,
  KEK-independent), and `tvault git-filter` (clean/smudge, `gitfilter.go`).
- Identities are passphrase-independent keypairs at
  `~/.tvault/identities/<name>.key` (0600). Public half = `tvault1…`
  (shareable/committable), private half = `tvault-key1…` (never commit).
- **CI/ssh/agents** supply a per-context identity via `TVAULT_IDENTITY_KEY`
  (a `tvault-key1…` string) — `resolveIdentity` (identity.go) is the single
  resolver behind `open`/`decrypt-env`/`env --identity`/git filters. Precedence
  is **file > env key** (with a stderr warning when a file overrides a set env
  key), and the env-key value must **never** be echoed in an error. `tvault
  identity export` prints the private key (TTY-guarded, `--force` off a tty);
  `tvault ci init --mode=identity` scaffolds a passphrase-free workflow.
- `git-filter` invariants worth preserving: the clean filter is **idempotent**
  (re-emits the staged blob when plaintext is unchanged, or `git status` is
  perpetually dirty), refuses to run with no recipients, passes already-encrypted
  input through (no double-encrypt), and in **locked mode** (no identity) the
  smudge filter passes ciphertext through instead of failing checkout.

## Versioned secrets & rollback

- Prior values live in the `secret_versions` bbolt bucket, keyed
  `projectID/key/%010d(version)` (current value stays in `secrets`). `SetSecret`
  **archives the old entry before overwriting, in the same transaction** — keep
  that all-or-nothing invariant. `DeleteSecret` purges a key's history.
- Surfaces: `tvault history` / `tvault get --version N` / `tvault rollback --to N`
  (CLI), `vault_secret_history` / `vault_rollback_secret` (MCP, **never return a
  value**). Rollback is non-destructive — it re-stores an old version as a new
  one; version numbers are monotonic, never reused.
- **Invariant:** history is encrypted with the project DEK, so any DEK rotation
  must re-encrypt it. `UnshareProject` feeds `ListSecretVersionEntries` through
  the re-encrypt loop into `RekeyProject` (which writes current + history
  atomically). `TestUnshareReEncryptsHistory` guards this — keep it passing.
  KEK rotation (`tvault key rotate`) doesn't touch values, so history is safe.

## Backups (`backup.go`, `internal/store/snapshot.go`)

- **Snapshots are always `store.Snapshot` (`Tx.WriteTo`), never a raw copy of
  the live file.** `Tx.WriteTo` runs inside a bbolt read transaction, so it
  reflects one committed state even if another `tvault` writes concurrently —
  don't reintroduce a byte-for-byte `os.Open`/`io.Copy` of `vault.db` for
  backups. `snapshotTo` (backup.go) writes into a private temp file in the
  destination dir, `fsync`s it, and only proceeds after `store.VerifySnapshot`
  (open read-only, check the core buckets exist) — **verify before rename**,
  every time, so a failed/interrupted backup never leaves a truncated file at
  the destination.
- **Destructive ops must call `snapshotBeforeDestructive` / `guardDestructive`
  and fail closed.** `delete`, `projects delete`, `restore` (CLI), and
  `vault_delete_secret`/`vault_delete_project` (MCP, via
  `VaultMCPServer.SetBeforeDestructive`) all take a safety snapshot first when
  `backup.dir` is configured; if that snapshot fails, the destructive
  operation must not proceed — no case should let a delete/restore continue
  after a snapshot error.
- **Rotation only touches files it owns.** `pruneSnapshots`/`listSnapshots`
  match only `rotatedSnapshotName` (the exact
  `vault-YYYYMMDD-HHMMSS.mmm[-reason].db[.gz]` names rotation writes) in the
  configured directory. Never widen that pattern, or rotation could delete
  something a user put there themselves.
- **Snapshot warnings go to stderr, not stdout.** `stdout` is the MCP protocol
  stream under `tvault mcp`; a rotation or immutability warning written to
  stdout there would corrupt JSON-RPC framing. Keep using
  `fmt.Fprintf(os.Stderr, ...)` for anything printed from `rotatedSnapshot`/
  `pruneSnapshots`.
- `--immutable` (`immutable_bsd.go`) is best-effort and platform-gated
  (`immutable_other.go` returns `errImmutableUnsupported` only when turning it
  *on*; clearing is always a no-op so rotation keeps working on unsupported
  platforms). Never let a failed/unsupported `setImmutable` call fail the
  backup itself — it's a warning, not a requirement.

## The local agent (`tvault agent`) — `internal/agent/`

- Unix-only, opt-in daemon that holds the vault unlocked over a private 0600
  unix socket so `get`/`env`/`run` skip the prompt + Argon2id. Build-tagged
  (`*_unix.go` + `stub_other.go`); Windows gets `ErrUnsupportedPlatform`.
- **Invariant — KEK-only, never an open DB.** bbolt is single-writer-process;
  holding the database open would block every other `tvault`. The agent caches
  only the KEK and reopens the vault per request (`vault.UnlockWithKEK`),
  serialized by a mutex, so direct CLI access keeps working. Don't "optimize"
  this into a held-open store.
- **Security invariants worth preserving:** socket 0600 in the 0700 dir, tight
  umask (no listen→chmod window), `flock` single-instance, mandatory peer-uid
  check (fail-closed; per-OS `peercred_*.go`), read-only ops, and KEK zeroing on
  **every** exit path (signal/idle/stop/panic). `agent start` never daemonizes.
- **Two lifecycles, not one.** `agent start` is a foreground process; backgrounding
  it (`&`, `nohup`) is the caller's business. `agent install` registers a per-user
  service instead (launchd on macOS, systemd on Linux — `internal/service/`), taking
  `--passphrase-file`, `--idle`, `--log-dir`/`--log-level`, `--no-load`, and
  `--dry-run`; `restart` picks up an upgraded binary, `uninstall` removes the
  definition, and `logs` reports (or with `--clear` deletes) the log path. The
  service resolves its own passphrase source at start, so an installed agent is the
  durable form of the same read-only boundary — it does not widen it.
- CLI routing tries the agent then falls back to a direct unlock for every
  read-path command — `get`, `env`, `run`, `ssh`, `docker`, and `tvault mcp`
  (through `secrets_load.go` / `agent_client.go`); `--no-agent` /
  `TVAULT_NO_AGENT` force direct. `x/sys` is now a direct require for the
  peer-cred calls (was indirect — no new module).
- **The agent accelerates reads; it never unlocks a write.** There is no write
  op and no way to obtain the KEK over the socket, so `set`/`delete`/`import`/
  `rotate` need the passphrase even while it runs
  (`TestAgentServesNoWriteOrKeyOperation` pins this). The non-interactive locked
  error (`lockedRemedy` in `vault_helper.go`) must stay honest about it: never
  advise starting an agent for a command that needs the key, and keep saying
  that a `tvault run` / MCP-exec child inherits no `TVAULT_*` and must bring its
  own credential. Making nested writes "work" by adding a write op or a KEK
  hand-out trades an integrity boundary for convenience — don't.
- **`--require-token` honesty:** capability tokens (`tokens_unix.go`) are a
  privilege-separation gate for an **OS-confined** delegate only — they are
  **not** a control against a same-uid process (it can read the token or dial
  the socket). Keep [token honesty](docs/reference/security.md#token-honesty)
  and [capability tokens](docs/guide/agent.md#capability-tokens-same-uid-clients-only)
  truthful. **Do not** build
  the full broker (in-band mint, per-key allowlists, TTL) — a design panel ruled
  it security theater; the recipient/identity model is the answer for real
  delegation. Tokens are out-of-band (0600 file, SIGHUP reload), only their
  SHA-256 is stored, and audit logs a hash prefix (`token_id`), never the token.

## Non-interactive unlock (`agent.passphrase_command`, `shell-init`)

- `agent.passphrase_command` / `TVAULT_PASSPHRASE_COMMAND` (`passphrase_command.go`)
  lets the passphrase live in a password manager instead of a plaintext file.
  Precedence: `TVAULT_PASSPHRASE` > `TVAULT_PASSPHRASE_COMMAND` >
  `TVAULT_PASSPHRASE_FILE` > `agent.passphrase_command` > `agent.passphrase_file`
  > implicit `~/.config/secrets/env` (`passphrase_file.go`, `resolvePassphrasePlan`).
- **Invariants to preserve:** `passphraseSource`/`checkUnlockSource` (doctor.go)
  and `mcpHasPassphrase` (mcp_server.go) must **never execute** the command —
  they only report which source *would* be used. The command itself runs with
  **stdin `/dev/null`** (critical under `tvault mcp`, whose own stdin is the
  protocol stream — a helper must never be able to read it), inherited stderr,
  a 2-minute timeout, and a 4096-byte output cap; errors must never include
  anything the command printed on stdout. A command sourced from `config.yaml`
  only runs after `checkConfigTrusted` passes (owned by the caller, not
  group/world-writable) — don't relax that guard, it is what stops
  `agent.passphrase_command` from being a code-execution primitive for anyone
  who can write the config file. `tvault mcp` deliberately excludes a command
  from `mcpHasPassphrase`'s "cheap source" check (only env/file count) so a
  server start prefers a running agent over forcing a Touch ID prompt; keep
  that asymmetry. The **implicit** `~/.config/secrets/env` fallback is
  *skipped, not an error*, once it no longer defines `TVAULT_PASSPHRASE`
  (`errPassphraseFileUnusable`) — an **explicitly** named file stays strict.
- `tvault shell-init` (`shell_init.go`) prints quoted export lines for a
  login shell's rc file. **Invariants:** it must **never prompt** — reads go
  through a running agent, and only `--allow-unlock` permits a direct unlock,
  restricted to non-interactive sources (never a TTY). When nothing is
  available it must exit **0** (a locked vault must never block shell
  startup), printing at most one stderr notice, silenced by `--quiet`.
  `--project` is **required** — a login shell must load a named project, not
  whatever `tvault use` last selected. Keys that aren't valid shell
  identifiers (`shellIdentifier` regex) are skipped with a **name-only**
  warning — never print the key verbatim, that would let a crafted key inject
  into the `eval`. Values go through the same `escapeShellValue`/`fishQuote`
  quoting as `tvault env`'s shell format (see the security fix below).
- **Security fix worth remembering:** `escapeShellValue` (env.go) now
  single-quotes anything outside `[A-Za-z0-9@%+=:,./_-]`. Before this, a
  stored value with `;`, `&`, `|`, `<`, `>`, `(`, `*`, `~`, or `#` was emitted
  unquoted by `tvault env --format shell`, `tvault ssh`'s remote script, and
  `shell-init`, so `eval "$(tvault env)"` could execute part of the value.
  Any new shell-emitting surface must go through the same helper.

## Environment groups (`internal/vault/envgroup.go`, `cmd/tvault/cmd/env_group.go`)

- A group links **existing projects** as named environments of one application
  (`production=liftclub`, `preview=liftclub-preview`). It is **pure metadata**: no
  new crypto, no copied values, and deleting a group never touches a project or a
  secret. A project belongs to at most one group unless `create --force` says
  otherwise.
- **Inheritance is resolved at read time, not stored.** `ResolveKey(group, env, key)`
  walks the child→base chain; `--group`/`--env` on `get`, `env`, `run`, `ssh`,
  `docker`, and the MCP equivalents all go through it, and `--show-source` reports
  which environment answered. Keep that resolution in one place — a second
  implementation would disagree about precedence.
- **`pin` is the only operation here that writes a value.** It copies the resolved
  value into the child project (breaking inheritance for that key); `unpin`
  **deletes** it, which purges that key's version history in the child. That is why
  the desktop UI disables unpin when the child has no base: with nothing to fall
  back to, the key would simply become missing.
- `promote` copies values between environments (decrypt + re-encrypt into the
  target, creating a new version and archiving the old one) and audits each key as
  `secret.promote`. `--dry-run` reports candidates without writing; without `--yes`
  it always prompts.
- `env seal` writes **one** v2 blob with a labelled section per environment
  (`--- tvault-env:<name> ---`), which `decrypt-env --section <env>` extracts. With
  `output_path` it writes a 0600 file and returns only the path — never the blob —
  matching `vault_seal_for_recipients` and `vault_export_env_encrypted`.
- MCP surface is `vault_env_group_create/list/show/add/remove/delete`,
  `vault_env_diff/promote/inherit/inherited/pin/unpin/seal`. Note the trap: `add`
  and `remove` take **`env_name`**, while every other env tool takes `env`.

## Distribution & machine output

- **Four install channels, and they must be documented consistently:** the
  Homebrew **cask** `abdul-hamid-achik/tap/tvault` (the formula is retired —
  `tap_migrations.json` maps it to the cask, so always write `--cask`), npm
  `@thelacanians/tinyvault` (a launcher in `npm/cli` plus six
  `@thelacanians/tinyvault-<platform>` binary packages that `npm/scripts/pack.mjs`
  fills from the release's checksummed raw binaries), `go install …/cmd/tvault@latest`
  (builds from source, so `--version` reports `dev` — the version string is stamped
  by GoReleaser's ldflags, not by the toolchain), and the release archives /
  `.deb` / `.rpm` / `.apk`. `tvault self-update` is only for a binary you downloaded
  yourself. Touching one install instruction means checking README.md,
  docs/guide/getting-started.md, docs/changelog.md, docs/mcp/index.md,
  npm/cli/README.md, and the hero command in HomePage.vue.
- **`--json` is a global persistent flag** (`root.go`), not a per-command
  afterthought: `list`, `projects`, `search`, `status`, `sync`, `diff`, `doctor`,
  `env diff`, `agent status`, `backup`, `restore`, `key rotate`, and the
  locked-vault envelope all honour it. Every writer goes through **one** encoder
  (`writeJSON`/`marshalJSON` in `json_helper.go`, `SetEscapeHTML(false)`) — adding a
  second `json.Marshal` call site is how HTML escaping creeps back in and corrupts
  a `DATABASE_URL` with a query string. Prompts and warnings go to **stderr** so
  stdout stays a single JSON document, and any command that would otherwise prompt
  (`restore`) requires `--yes` under `--json`.
- **Machine output is metadata-only by construction.** `json_output_test.go` pins
  the `backup`/`restore`/`rotate` shapes; the `sync` value leak (a `Conflict`
  struct carrying `VaultValue`/`EnvValue` with no JSON tags) is the regression it
  exists to prevent. If a new `--json` surface has a value in scope, the answer is
  to remove the field, not to tag it out.

## Documentation site (`docs/` → tinyvault.dev)

User-facing docs live in `docs/` — a **VitePress (v1) + Bun** site deployed to
**Vercel** at **[tinyvault.dev](https://tinyvault.dev)** (served at
`www.tinyvault.dev`; the apex 308-redirects to www, so `SITE_URL`/canonical/
sitemap use www). It is **git-connected**: any push to `main` that touches
`docs/` auto-builds and deploys (Vercel project `tinyvault-docs`, root directory
`docs/`, `bun run docs:build`, output `.vitepress/dist`). Iterate locally with
`cd docs && bun run docs:dev`; gate with `bun run docs:build` (it fails on dead
links). Theme + config live in `docs/.vitepress/` ("Vault Amber"). Content is
verified against the real binary.

## Committing

Branch off `main` for changes; ensure the four `ci.yml` checks pass locally before
pushing, plus `bun run typecheck` / `build` / `verify` under `app/` when the change
touches the desktop app or any `internal/mcp` output struct. Keep `AGENTS.md`,
`CLAUDE.md`, `README.md`, `ROADMAP.md`, the Architecture, Security, and MCP docs,
and `tvault help` / `tvault docs` in sync when behavior changes — they
cross-reference each other, and `tvault docs --help` builds its topic list from the
registry so it cannot drift (the topics themselves still can).
