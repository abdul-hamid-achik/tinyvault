# TinyVault — Specification

> Local-first secrets management for developers and AI agents.

This document is the canonical design and product reference for TinyVault.
The README is a quickstart; this is the *why* and the *how*.

---

## 1. What TinyVault is

TinyVault is a **single Go binary** that provides two products in one:

1. **A local secrets CLI** for developers — like `pass`, 1Password CLI, or
   `doppler run`, but with no account, no server, no cloud, and a single
   encrypted file under your home directory.
2. **An MCP server** for AI agents — lets Claude, GPT, or any MCP-compatible
   agent use secrets without the secret values ever entering the model's
   context window.

The same vault file powers both surfaces. The CLI is the canonical interface;
the MCP server is a thin policy-and-redaction layer over the same vault API.

### What it is not

- **Not a hosted service.** There is no TinyVault cloud, no account, no
  subscription. The vault is a file on your disk.
- **Not a team vault.** There is no sync between machines. To share a vault
  with a teammate, you `backup` it and they `restore` it (or you commit the
  file to a private repo / artifact store). Team-vault features are out of
  scope for now.
- **Not a general-purpose secret store.** No HSM, no dynamic secrets, no
  short-lived credentials, no cloud KMS integration. Single-passphrase
  local encryption only.
- **Not a replacement for 1Password / Vault in production.** Production
  secret management has requirements (HA, RBAC, audit pipelines, dynamic
  credentials) TinyVault deliberately does not try to meet.

### Why this product

Three problems that the existing toolchain does not solve well:

1. **`.env` files are insecure and unscalable.** Plaintext on disk, no
   per-project isolation, no audit, no safe way to share.
2. **1Password CLI / `pass` / Vault are good for humans but bad for agents.**
   They expose values to whatever process asks. An AI agent that needs to
   call `stripe.Charge(...)` ends up with the API key in its conversation
   context — visible in logs, telemetry, and any prompt that gets cached.
3. **Hosted services (Doppler, Infisical) solve the team problem but add a
   network round-trip, an account, and a subscription for a workflow that
   is fundamentally local.**

TinyVault is the smallest thing that solves all three: a local encrypted
file, with a CLI for humans, and an MCP surface designed for agents that
**never need to see the bytes**.

---

## 2. Architecture

### 2.1 Storage

- **Backend:** [bbolt](https://github.com/etcd-io/bbolt) (a pure-Go,
  single-file, embedded key-value store).
- **API shape:** SQL-shaped tabular interface. Rows are typed Go
  structs (`Project`, `SecretEntry`, `AuditEntry`). Operations are
  typed methods on a per-table `Store` interface (`MetaStore`,
  `ProjectStore`, `SecretStore`, `AuditStore`, `ConfigStore`).
  Relational queries (`ListSecretKeysFiltered`, `ListSecretsByProject`,
  `ListAuditFiltered`, `ListProjectsFiltered`) are first-class methods,
  not string-template SQL. The bbolt file is the only on-disk
  artifact.
- **Location:** `~/.tvault/vault.db` (override with `TVAULT_DIR`).
- **File mode:** `0600`. The vault directory is `0700`.
- **Format:** JSON values keyed by string. Six buckets:
  - `_meta` — vault metadata (version, salt, verifier, creation time, vault UUID)
  - `_config` — key/value config (currently holds the "current project" name)
  - `projects` — project records, keyed by project UUID
  - `secrets` — secret entries, keyed by `<project-uuid>/<key>`
  - `project_names` — name index for projects (allows O(1) lookup by name)
  - `audit` — append-only audit log

### Why bbolt and not a relational engine

We deliberately do not use SQLite or a relational engine here. The
trade-off is documented in `internal/store/store.go`:

- The vault is a single-process, single-user artifact. bbolt's
  flock-based concurrency and embedded mmap are exactly the right
  fit. SQLite's WAL, query planner, and schema migrations solve
  problems we do not have.
- The encryption layer must be auditable. With bbolt, the
  encrypt/decrypt calls are adjacent to the read/write calls in
  the same file. With a SQL engine + generated code, the data path
  is split across a schema, generated Go, and a runtime that an
  auditor has to read separately.
- Supply-chain surface is smaller with bbolt. modernc.org/sqlite is
  a fine library but is a larger attack surface for code that
  handles plaintext secret values.
- The vault is single-writer by design. A SQL engine's row-level
  locking and multi-writer semantics buy us nothing.

A future backend (Postgres, encrypted SQL, etc.) can be slotted in
by implementing the `Store` interface. We have not done so because
the local-first product does not need it.

### Search and relational queries

There is no separate search index, no FTS5 database, no derived
artifact. Search is done by iterating the bbolt cursor and filtering
in Go. The filter is applied to the *metadata* of each row only:
`SecretEntry.EncryptedValue` is never decrypted during a search. The
cost is O(N) over keys + project names, which is fine for the
expected scale (hundreds to low thousands of secrets per vault). For
a local-first single-user tool, this is the right trade-off.

The `Store` interface exposes the relational queries directly:

- `ListSecretKeysFiltered(projectID, SecretFilter)` — by prefix, name
  glob (`*` wildcard), update time, version, with limit/offset.
- `ListSecretsByProject(SecretFilter)` — same, but across all
  projects; returns `SecretLocation` rows.
- `ListAuditFiltered(AuditFilter)` — by action, resource type, time
  range, with limit/offset.
- `ListProjectsFiltered(ProjectFilter)` — by name/description glob,
  with limit/offset.

The CLI surfaces these as `tvault search` (secret metadata) and
`tvault list --prefix` (project-scoped). The MCP server exposes
`vault_search_secrets`, `vault_list_secrets_by_prefix`, and
`vault_audit_log_since`.

### 2.2 Cryptography

All cryptography lives in `internal/crypto`. Only standard library primitives
plus `golang.org/x/crypto/argon2`.

| Primitive             | Purpose                                  | Parameters                                   |
|-----------------------|------------------------------------------|----------------------------------------------|
| **Argon2id**          | Passphrase → KEK derivation              | time=3, memory=64 MiB, threads=4, salt=16 B  |
| **AES-256-GCM**       | Symmetric encryption (KEK, DEK, values)  | 32-byte key, 12-byte random nonce per op     |
| **`crypto/rand`**     | All randomness (nonces, salts, DEKs)     | n/a                                          |
| **`ZeroBytes`**       | Key zeroization after use                | n/a                                          |

**Key hierarchy:**

```
User passphrase
   └─ Argon2id(passphrase, vault_salt) ───► KEK (Key Encryption Key)
                                              │  held in RAM only when unlocked
                                              │
                                              ├─ AES-GCM(KEK, project_DEK) ─► Encrypted DEK, stored in project record
                                              │      └─ project_DEK
                                              │           └─ AES-GCM(project_DEK, secret_value) ─► Encrypted value
                                              │
                                              └─ AES-GCM(KEK, "tinyvault-verify-v1") ─► Verifier
                                                                                       (decrypts iff passphrase is correct)
```

**Properties:**

- **Two-tier.** Compromise of a single project's DEK does not compromise the
  KEK or any other project's DEK.
- **Verifier-validated passphrase.** The vault stores
  `AES-GCM(KEK, "tinyvault-verify-v1")` at creation. Unlock decrypts it; if
  GCM authentication fails or the plaintext is wrong, the passphrase is
  rejected without ever reading any secret.
- **Per-operation nonce.** Every AES-GCM call generates a fresh 12-byte
  random nonce. No nonce reuse, ever.
- **Memory hygiene.** The KEK and DEKs are zeroed after use via
  `crypto.ZeroBytes`. They live in process memory only while the vault is
  unlocked.
- **Passphrase rotation without re-encrypting secrets.** `tvault key rotate`
  re-derives a new KEK under a new salt, decrypts every project DEK with
  the old KEK, re-encrypts it with the new KEK, and swaps. Secret values
  are never touched.

**Argon2id parameters are conservative.** 64 MiB / 3 iterations / 4 threads
is ~200 ms on a modern x86 laptop. Tunable in `internal/crypto/crypto.go`
if hardware targets change.

### 2.3 Package layout

```
cmd/tvault/
  main.go                    # entry point
  cmd/
    root.go                  # root command, global flags
    vault_helper.go          # shared: getVaultDir(), openAndUnlockVault(), resolveProject()
    init.go / unlock.go / lock.go
    status.go
    get.go / set.go          # tvault get KEY / tvault set KEY VALUE
    list.go / delete.go
    run.go                   # run -- CMD with secrets as env vars
    env.go                   # export in shell/dotenv/json/yaml/k8s formats
    export.go / import.go / import_interactive.go
    sync.go                  # two-way reconciliation between .env and vault
    encrypted_env.go         # encrypt-env / decrypt-env (.env.encrypted)
    search.go                # tvault search (relational query, metadata only)
    docs.go                  # machine-readable docs surface (features, topics)
    projects.go / use.go
    backup.go
    rotate.go
    mcp_server.go            # starts the MCP server
    ci.go                    # generate CI workflow helpers
    completion.go
    output.go                # color output helpers

internal/
  crypto/         AES-256-GCM, Argon2id, token helpers, password hashing
  store/          SQL-shaped tabular Store interface + BoltStore (bbolt)
  vault/          high-level vault ops + relational query layer
                  (Create/Open/Unlock/Lock, project, secret, Search, ...)
  dotenv/         safe dotenv parser, name allowlist, tvault:// interpolation
  sync/           two-way reconciliation between .env files and the vault
  encryptedenv/   .env.encrypted format (tvault-encrypted-v1, KEK-tied)
  mcp/            MCP server (tools, prompts, resources, access policy, redaction)
  validation/     key + project name validation
```

### 2.4 State machine

```
              init                  unlock                  Lock()
[no vault] ──────────► [locked] ─────────► [unlocked] ─────────► [locked]
                            │                    │
                            └──── Close() ──────►│  (zeroes KEK, closes bbolt)
                                                 │
                                            Create/Set/Get/...
                                            require unlocked
```

`Unlock` requires a passphrase and verifies it against the verifier blob
before setting `vault.kek` (the in-memory KEK). `Lock` zeroes `vault.kek` and
flips back to `locked` without touching disk. The bbolt file is only
written through `Update`/`View` transactions; locking does not modify the
file.

---

## 3. Threat model

### 3.1 In scope

| Threat                                           | Mitigation                                                                                                                                |
|--------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| Attacker reads `~/.tvault/vault.db` at rest      | Every secret value is AES-256-GCM-encrypted with a per-project DEK; DEKs are encrypted by a KEK derived from the user's passphrase.     |
| Attacker tries to brute-force the passphrase      | Argon2id with 64 MiB / 3 iter / 4 threads makes each attempt ~200 ms and memory-bound, hostile to GPU/ASIC attacks.                       |
| Vault file is tampered with                      | AES-GCM authentication tag on every encrypted value, DEK, and verifier; tampering causes `ErrDecryptionFailed` and is rejected.         |
| AI agent leaks secret into its prompt / logs     | MCP redaction pattern: `vault_run_with_secrets` injects values as env vars only; `vault_export_env` writes to disk and returns path; `vault_generate_secret` returns only `{stored: true}`. |
| AI agent escapes its allow-list                  | `AccessPolicy` (`~/.tvault/mcp-policy.yaml`) gates projects + secrets via glob allow/deny; `access_mode` controls write/exec/audit.       |
| Compromised subprocess leaks secrets to stderr   | `redactSecrets()` post-processes `vault_run_with_secrets` output, replacing any occurrence of a secret value > 3 chars with `[REDACTED:KEY]`. |
| Attacker obtains a vault backup                  | Backups are byte-identical copies of `vault.db`; the passphrase is required to read them. No additional encryption.                      |
| Passphrase leak via shell history                | `TVAULT_PASSPHRASE` env var for CI / scripts; passphrase prompts use `term.ReadPassword` (no echo).                                       |

### 3.2 Out of scope (explicit non-goals)

- **Side-channel resistance beyond Go's stdlib.** No constant-time guarantees
  beyond what `crypto/subtle` and `crypto/aes` provide. We do not run on
  smartcards, HSMs, or TEEs.
- **Memory forensics after process exit.** `ZeroBytes` reduces the window
  but cannot guarantee clean memory. If an attacker can read your process
  memory while `tvault` is running and unlocked, the KEK is recoverable.
- **Multi-user key separation on a shared host.** The vault file is
  permission-gated, not OS-user-isolated. A second user with read access
  to your home directory can attempt offline brute-force.
- **Recovery without the passphrase.** There is no escrow, no recovery key,
  no social recovery. Forgetting the passphrase means the vault is
  irrecoverable. This is intentional and matches the local-first ethos.
- **Forward secrecy at the network level.** There is no network. The vault
  never leaves the disk unless you explicitly `backup` or commit it.

### 3.3 MCP-specific threat model

The MCP server is the most security-sensitive surface. The design rules:

1. **Default-deny on values.** Tools that need to use a secret should prefer
   `vault_run_with_secrets` (env-inject) over `vault_get_secret` (return
   the value). The latter is gated by `max_reads_per_session` and emits a
   warning in its output.
2. **Default-deny on commands.** `vault_run_with_secrets` is disabled unless
   `access_mode: full` and `allow_exec: true`. There is no per-command
   allowlist yet — the access policy gates by project and secret, not by
   the command being run.
3. **Output redaction is a safety net, not a guarantee.** It catches
   accidental leakage via subprocess output. It does **not** catch:
   - Secrets sent to a network (the subprocess has full network access).
   - Secrets logged to a file outside the captured stdout/stderr.
   - Secrets that happen to be > 3 chars and match a non-trivial regex in
     the output (false-negative rate is non-zero).
4. **Policy is loaded from disk, not from the model.** The
   `mcp-policy.yaml` is read at MCP server start; the model cannot modify
   it at runtime. The model can call `vault_status` to discover what it
   has access to; it cannot escalate.
5. **Every privileged action is audited.** `secret.read`, `secret.write`,
   `secret.delete`, `secret.generate`, `secret.exec`, `secret.export`,
   `project.create`, `project.delete` all write to the audit bucket. The
   audit log is queryable via `vault_audit_log`.

---

## 4. The MCP surface

18 tools, 2 prompts, 3 resources. All registered through
`github.com/modelcontextprotocol/go-sdk` v1.4.1.

### 4.1 Tools

| Tool                          | Reads values? | Writes values? | Executes commands? | Requires policy       |
|-------------------------------|---------------|----------------|--------------------|-----------------------|
| `vault_list_projects`         | no            | no             | no                 | `CanAccessProject`    |
| `vault_create_project`        | no            | yes            | no                 | `CanWrite`            |
| `vault_delete_project`        | no            | yes            | no                 | `CanWrite`            |
| `vault_list_secrets`          | no            | no             | no                 | `CanAccessProject` + `CanAccessSecret` |
| `vault_get_secret`            | **yes**       | no             | no                 | `CanAccessProject` + `CanAccessSecret` |
| `vault_set_secret`            | no            | yes            | no                 | `CanWrite` + `CanAccessProject` + `CanAccessSecret` |
| `vault_delete_secret`         | no            | yes            | no                 | `CanWrite` + `CanAccessProject` + `CanAccessSecret` |
| `vault_run_with_secrets`      | no (env only) | no             | **yes**            | `CanExec` + `CanAccessProject` |
| `vault_export_env`            | no (writes to disk) | no      | no                 | `CanAccessProject` + `CanAccessSecret` |
| `vault_generate_secret`      | no            | yes            | no                 | `CanWrite` + `CanAccessProject` + `CanAccessSecret` |
| `vault_status`                | no            | no             | no                 | always allowed        |
| `vault_audit_log`             | no            | no             | no                 | `CanWrite` (read-back of audit trail) |
| `vault_search_secrets`        | no            | no             | no                 | `CanAccessProject` + `CanAccessSecret` |
| `vault_list_secrets_by_prefix`| no            | no             | no                 | `CanAccessProject` + `CanAccessSecret` |
| `vault_audit_log_since`       | no            | no             | no                 | `CanWrite` |
| `vault_list_env_files`        | no            | no             | no                 | always allowed        |
| `vault_preview_env_import`    | no            | no             | no                 | always allowed        |
| `vault_import_env_files`      | no            | yes            | no                 | `CanWrite`            |

The value-returning tools are deliberately few and each returns the value
only when the agent has no alternative. `vault_get_secret` even includes a
`warning` field reminding the caller that the value is now in the model
context.

### 4.2 Prompts

- `setup-project` — interactive walkthrough for creating a new project
  and adding initial secrets.
- `inject-secrets` — guide for running a command with secrets injected
  from a project.

These exist to give the agent a known-good starting point instead of
forcing the model to invent the workflow.

### 4.3 Resources

- `vault://status` — JSON dump of vault metadata + lock state.
- `vault://projects` — JSON list of all projects (with secret counts).
- `vault://projects/{name}/keys` — JSON list of secret key names in a
  project (no values).

### 4.4 Access policy

Loaded from `~/.tvault/mcp-policy.yaml`. Example:

```yaml
access_mode: read-write      # read-only | read-write | full
allow_exec: false            # disable vault_run_with_secrets
redact_output: true          # redact secret values from command output

projects_allow:
  - "dev-*"
  - "staging"

projects_deny:
  - "production"

secrets_allow:
  - "DATABASE_*"
  - "API_KEY"

secrets_deny:
  - "*_PASSWORD"
  - "MASTER_KEY"

max_reads_per_session: 50    # cap on vault_get_secret calls
```

Semantics: `deny_*` is checked first, then `allow_*`. Empty `allow_*` means
"allow everything not denied." `access_mode: full` is the only mode that
permits `vault_run_with_secrets`.

---

## 5. CLI surface

Cobra-based. Global flags: `--vault` (override `TVAULT_DIR`), `--project`
(or `-p`, override current project), `--json`, `--verbose`.

```
tvault init                       # create a new vault
tvault unlock                     # unlock with passphrase (or use TVAULT_PASSPHRASE)
tvault lock                       # zero in-memory KEK
tvault status                     # vault metadata + lock state

tvault set KEY VALUE              # store a secret in the current project
tvault set KEY --from-env .env    # set KEY from a dotenv file (use --key for source)
tvault get KEY                    # print a secret to stdout
tvault get KEY --from .env        # read a value from a dotenv file (no unlock)
tvault list                       # list all secret keys in the current project
tvault delete KEY                 # remove a secret

tvault run -- <cmd> [args...]     # run cmd with project secrets as env vars
tvault run --env-file .env -- CMD # merge .env with vault; resolve ${tvault://...}
tvault env [--format=...]         # export in shell/dotenv/json/yaml/k8s-secret
tvault export <file>              # write all secrets to a file
tvault import [file]              # safe dotenv import (no shell expansion)
tvault import --env production    # import the .env.*.production chain
tvault sync --direction pull      # vault -> .env
tvault sync --direction push      # .env -> vault
tvault sync --direction mirror    # reconcile in both directions

tvault encrypt-env --in .env      # .env -> .env.encrypted (KEK-tied, commit-safe)
tvault decrypt-env --in .env.enc  # reverse

tvault search --prefix STRIPE_    # relational query (metadata only, no decrypt)
tvault search --project prod --name-like 'DB_*'
tvault search --since 2026-01-01T00:00:00Z
tvault list --prefix STRIPE_      # shortcut: project-scoped prefix search

tvault docs                       # JSON manifest of every feature (for agents)
tvault docs features              # narrow to features
tvault docs topics                # narrow to topics
tvault docs interpolate           # topic detail

tvault projects list              # list projects
tvault projects create <name>     # create a project (gets its own DEK)
tvault use <project>              # switch the current project
tvault projects delete <name>     # soft-delete a project
tvault import --interactive       # TUI picker with key counts and diagnostics

tvault projects list              # list projects
tvault projects create <name>     # create a project (gets its own DEK)
tvault use <project>              # switch the current project
tvault projects delete <name>     # soft-delete a project

tvault backup <path>              # copy vault.db to path
tvault restore <path>             # replace vault.db from a backup
tvault key rotate                 # re-encrypt every project DEK under a new KEK

tvault doctor                     # read-only setup diagnostics (--json; exit 1 on failure)
tvault diff <file>                # key drift vs a .env (--values compares values, never prints them)

tvault ci init --provider=github-actions
tvault ci init --provider=gitlab

tvault mcp-server                 # start the MCP server on stdio
tvault completion bash|zsh|...    # shell completion
```

### 5.1 The dotenv safety story

`internal/dotenv` parses dotenv files **without executing shell features**.
Specifically:

- No variable expansion (`$VAR`, `${VAR}`).
- No command substitution (`` `cmd` ``, `$(cmd)`).
- File-name allowlist: only `.env`, `.env.<env>`, `.env.<env>.local`,
  `.env.local`. Files like `.env.example`, `.env.sample`, `.env.template`
  are ignored.
- Symlinks are skipped (`info.Mode()&os.ModeSymlink != 0`).
- A 1 MiB per-file size cap (`maxFileSizeBytes`).
- Inline comments (`KEY=value # comment`) and quoted values
  (single/double with backslash escapes) are parsed correctly.

This means: importing a dotenv file cannot execute a payload embedded in
the file. The worst case is a malformed line, which is reported as a
diagnostic, not executed.

### 5.2 The .env ecosystem

Beyond `import`, the dotenv layer has four other surfaces:

**`tvault://` interpolation.** A committed `.env` file can hold
*placeholders* instead of values:

```dotenv
DATABASE_URL=${tvault://DATABASE_URL}
DB_PROD=${tvault://production/DATABASE_URL}
```

The dotenv parser keeps the placeholders verbatim. `tvault run
--env-file .env -- CMD` resolves them against the unlocked vault at run
time. There is no shell expansion, no command substitution, no other
syntax. The placeholders are inert text until `tvault run` walks the
vault. This means a `.env` template with only placeholders is safe to
commit.

**Two-way sync.** A `.env` file is a projection of the vault.

```
tvault sync --direction pull --path .env       # vault -> .env
tvault sync --direction push --path .env       # .env -> vault
tvault sync --direction mirror --path .env     # both, with conflict reporting
```

Pull is non-destructive: keys in `.env` that are not in the vault are
preserved. Push without `--overwrite` skips existing vault keys.
Mirror pushes env-only keys to the vault, pulls vault-only keys to
`.env`, and reports conflicts in a `Result.Conflicts` slice (visible
with `--json`). Either side can be the source of truth per invocation.

**Encrypted .env files (Rails credentials pattern).** A `.env` can be
encrypted to a `.env.encrypted` file using the vault's KEK:

```bash
tvault encrypt-env --in .env --out .env.encrypted
tvault decrypt-env --in .env.encrypted --out .env
```

The output is a self-contained binary file with magic `tvault-encrypted-v1`,
a per-file salt, a per-file nonce, and AES-256-GCM ciphertext. The
key is derived via HKDF-SHA256 from the vault KEK + the file's salt.
Decryption requires the vault to be unlocked with the same passphrase
that was active at encryption time. **Passphrase rotation invalidates
all previously encrypted files** — this matches `RotatePassphrase`
semantics. The format is documented in `internal/encryptedenv/encryptedenv.go`.

### 5.3 Agent discoverability

`tvault docs` is a machine-readable manifest designed for AI agents
that want to learn what tvault can do:

```bash
tvault docs            # full JSON catalog (features + topics)
tvault docs features   # just the feature list
tvault docs topics     # just the topic list
tvault docs interpolate  # human-readable topic detail
```

The catalog is structured (machine-parseable JSON) and includes the
exact CLI command(s) for each feature plus a `see_also` cross-reference.
Agents should call this once at the start of a session to learn the
surface, then drill into specific topics as needed. See the
[source of truth for the catalog](cmd/tvault/cmd/docs.go) for the
complete list of features and topics.

---

### 5.4 The interactive browser (`tvault browse`)

`tvault browse` is the **human** surface — a full-screen terminal UI for
browsing the vault, **read-only by default**. It is the natural sibling to
`tvault docs` (agent-readable manifest) and `tvault help` (long-form
manual). With no flags it only reads, so a stray keystroke can't change
anything; the only decryption is the on-demand reveal, recorded in the
audit log exactly like `tvault get`. Pass `--rw` to enable in-app edits
(`n` new, `e` edit, `d` delete): these reuse the CLI's encryption path
(`internal/vault.SetSecret`/`DeleteSecret`) and are audited as
`secret.write`/`secret.delete`. Rotation and project create/delete still
go through the CLI.

```
┌──────────────────────────────────────────────────────────────────┐
│ tvault  •  ● unlocked  •  webapp  •  47 secrets  •  3 projects     │  header
├────────────────────────┬─────────────────────────────────────────┤
│ 2 Projects (3)         │ 3 Secrets (47)                            │
│ ▸ webapp           47  │ STRIPE_KEY            ••••••••            │
│   api               6  │ DATABASE_URL          ••••••••            │
│   batch             2  │ AWS_SECRET            ••••••••            │
├────────────────────────┤ ...                                      │
│ 1 Status               ├─────────────────────────────────────────┤
│ ● unlocked             │ 4 Audit (100)                             │
│ project  webapp        │ 14:32  set  STRIPE_KEY                    │
│ secrets  55            │ 14:31  unlock  webapp                     │
└────────────────────────┴─────────────────────────────────────────┘
  secrets — r reveal · R reveal all · c copy · / filter                footer
  ↑↓ navigate  / filter  r reveal  c copy  ? help  q quit
```

**Layout.** Four panes — status, projects, secrets, audit — are shown
together as a responsive grid (two columns, ≥ 90×20). On smaller
terminals (or with `--single-pane`) it collapses to one pane at a time
with a `[1][2][3][4]` tab strip. The rendered frame is always exactly
the terminal size, which the Bubble Tea v2 cell-diff renderer requires.

**Keybindings.** Vim + arrow + mouse-wheel: `↑↓`/`jk` (or the wheel)
navigate, `←→`/`hl` and `1`–`4`/`tab` switch panes, `⏎` opens a project,
`/` filters keys, `r` reveals the selected value (`R` reveals all), `c`
copies to the clipboard, `u`/`L` unlock/lock, `esc` re-masks, `?` toggles
in-app help (glamour-rendered), `q` quits.

**Reveal-map security model.** Decrypted values live only in an in-memory
map, only while displayed, and are wiped aggressively — on `esc`, on pane
change, and on quit. They never touch disk and never enter the audit log
(only the fact that a reveal occurred is recorded). The reveal accent is
a deliberate warm orange ("this is a secret value, be careful"), distinct
from the red used for errors. Project and secret *metadata* can be
browsed while the vault is locked (`Search` / `SnapshotProjects` /
`ListAudit` read metadata only); revealing a value requires unlocking,
which can be done in-app with `u`.

**Animation system.** Tasteful, gated, and pure-Go (no spring library):
a loading spinner, a soft pulse on the lock indicator while locked, and a
brief flash on reveal. All animations disable automatically under
`--no-anim`, `$TVAULT_NO_ANIM`, or an SSH session (`$SSH_CONNECTION` /
`$SSH_TTY`), and the frame ticker only runs while something is actually
animating, so an idle browser is free.

**Dependency footprint.** The browser is the only thing that pulls in the
`charm.land/*` v2 stack — `bubbletea/v2`, `lipgloss/v2`, `bubbles/v2`,
and `glamour/v2` (for the help pane). It is opt-in via the `browse`
subcommand; no other command imports those libraries. Adding the stack
takes the binary from ~12 MB to ~24 MB uncompressed. No `harmonica` —
animations are hand-rolled easing — and no `huh`, keeping the dependency
set strictly to the v2 line.

---

## 6. Comparison with adjacent tools

|                         | TinyVault      | 1Password CLI | `pass`         | Vault dev mode  | Doppler        |
|-------------------------|----------------|---------------|----------------|-----------------|----------------|
| Account / cloud         | **no**         | yes           | no             | no              | yes            |
| Network round-trip      | **no**         | no            | no             | no (dev)        | **yes**        |
| AI agent integration    | **first-class**| none          | none           | partial         | partial        |
| Redaction-safe exec     | **built-in**   | no            | no             | no              | no             |
| Multi-project isolation | **yes** (per-project DEK) | yes | no   | yes (engines)   | yes            |
| Team sync               | no (manual backup) | yes      | via git        | via storage     | yes (core)     |
| Dynamic secrets         | no             | no            | no             | **yes**         | no             |
| HSM / KMS               | no             | no            | no             | **yes**         | no             |
| Recovery without pw     | no             | yes           | yes (GPG)      | yes (recovery shards) | yes     |
| Single binary           | **yes**        | no            | no             | no              | no             |

TinyVault is **not** a replacement for any of these in production. It is a
local-first, agent-first complement. The honest gap: no team sync, no
recovery without passphrase, no dynamic credentials.

---

## 7. Roadmap

Sequenced by leverage-to-effort ratio. The lower tiers are not commitments;
they are sketches of where the product could go.

### Tier 1 — Table stakes (small, high-value)

- **`tvault doctor`** — diagnose vault issues: wrong file permissions,
  passphrase correct but no projects, policy syntax errors, bbolt file
  integrity hints. (Small.)
- **Shell completion for nushell.** Currently bash/zsh/fish/powershell
  only. (Small.)
- **`vault_secret_metadata` MCP tool** — return `created_at`, `updated_at`,
  `version` (which is already stored, just not exposed). (Small.)
- **`vault_rotate_secret` MCP tool** — generate-and-replace with
  supersession grace period. (Small.)
- **Pre-commit / clean filter for committing an encrypted vault file.**
  The killer feature for "1Password CLI but better" — `git diff` shows
  only key names, never values. (Medium.)

### Tier 2 — Agent-first differentiators

- **Versioned secrets with diff and rollback.** `Version` is already
  tracked in `SecretEntry`; expose it via `vault_diff`, `vault_snapshot`,
  `vault_rollback`. (Medium.)
- **Time-bound project switching.** `tvault use staging --ttl 1h` —
  auto-switches back. Useful for "I'm about to do something risky."
  (Small.)
- **Richer access policy.** Regex (not just glob), env-conditional rules
  (e.g., "only if MCP host is `claude-code`"), per-command allowlist for
  `vault_run_with_secrets`. (Medium.)
- **Audit log export.** `tvault audit export --format=jsonl` for piping
  into a SIEM or a log aggregator. (Small.)

### Tier 3 — Beyond local

- **Pluggable secret sources.** Pull a secret from 1Password CLI, macOS
  Keychain, or `pass` as if it were in TinyVault. Lets users migrate
  gradually without a "big bang" import. (Medium.)
- **Encrypted portable backups.** QR-code encoded `vault.db` for transfer
  via phone, with a one-time code. Memorable, not enterprise-y. (Big but
  unique.)

What is **not** on the roadmap: hosted TinyVault, team accounts, web UI,
mobile app, browser extension. The product is a CLI + MCP server. Adding
surfaces dilutes the security story.

---

## 8. Operating notes

- **Build:** `go build -o bin/tvault ./cmd/tvault` (always `bin/`,
  gitignored).
- **Test:** `go test -race ./...`. All packages must pass with the race
  detector; the crypto and MCP packages are the most important to keep
  that way.
- **Lint:** `golangci-lint run ./...`. Config in `.golangci.yml`.
- **Release:** tag a `v*` commit, push it. `.github/workflows/release.yml`
  runs GoReleaser across macOS / Linux / Windows, amd64 + arm64, and
  publishes a Homebrew tap.
- **MCP host config** (Claude Code):
  ```json
  {
    "mcpServers": {
      "tvault": {
        "command": "tvault",
        "args": ["mcp-server"],
        "env": { "TVAULT_PASSPHRASE": "<your-passphrase>" }
      }
    }
  }
  ```
- **CI:** `TVAULT_PASSPHRASE` as a repo secret, commit `vault.db` (or
  download it as an artifact), `tvault env --format=shell --export=false
  >> $GITHUB_ENV`.

---

## 9. Security disclosure

TinyVault is a small, security-sensitive tool. If you find a vulnerability,
please open a private security advisory on GitHub rather than a public
issue. Cryptographic correctness issues and MCP prompt-injection or
secret-leakage paths are the highest-priority classes.
