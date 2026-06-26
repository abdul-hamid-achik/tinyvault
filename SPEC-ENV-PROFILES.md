# Environment Profiles — Product Definition Spec

> **Status:** proposal — analysis & design, not yet built.
> **Author:** abdulachik
> **Date:** 2026-06-25
> **Depends on:** existing project model (`internal/store/store.go`, `internal/vault/project.go`),
> recipient layer (`internal/crypto/recipient.go`), sealed-env v2 (`internal/encryptedenv/`).

---

## 1. Problem

TinyVault projects are isolated namespaces with independent DEKs. This is
the right security model — production and preview have different encryption
keys, different recipients, and different audit trails. But when projects
represent **environments of the same application** (production, preview,
staging), a new failure mode emerges: **key drift**.

A project like `liftclub` has 33 secrets. Its preview counterpart
`liftclub-preview` needs most of the same keys with different values
(`DATABASE_URL`, `BETTER_AUTH_URL`, `STRIPE_SECRET_KEY`, etc.), plus a few
preview-only keys. Today:

- Adding `STRIPE_WEBHOOK_SECRET` to `liftclub` but forgetting `liftclub-preview`
  silently breaks the preview deploy. There is no drift detection.
- Populating a new environment means re-entering 33 keys manually, even
  though most values share a prefix or pattern.
- There is no "promote this value from preview to production" workflow —
  you `get` from one project and `set` into the other, losing lineage.
- Sealing N environments = N `tvault seal` commands and N blobs, with no
  structural link between them.

This gets worse at 3–4+ environments. The pain is real at 2 (liftclub today)
and acute at 3+.

## 2. What we are NOT building

- **A hosted control plane.** TinyVault stays local-first. No server, no
  sync, no cloud. Environment profiles are a local metadata layer over
  existing projects.
- **A replacement for the project model.** Projects remain the unit of
  encryption, sharing, and isolation. Profiles are a *relationship* between
  projects, not a new storage primitive.
- **Automatic value sync.** Profiles do not auto-copy values between
  environments. That would be dangerous (a preview value pushed to
  production by accident). Every copy is explicit and audited.
- **Environment-scoped encryption.** The DEK stays per-project. Profiles
  are metadata that links projects; they do not introduce a new key tier.

## 3. Design

### 3.1 Core concept: environment groups

An **environment group** is a named set of linked projects with an
ordered environment list. It is pure metadata — no new crypto, no new
buckets, no new key material.

```yaml
# stored in the _config bucket as a JSON document
groups:
  liftclub:
    description: "LIFT Club — liftclub.social environments"
    environments:
      - name: production
        project: liftclub
      - name: preview
        project: liftclub-preview
      # future:
      # - name: staging
      #   project: liftclub-staging
```

Key properties:

- **A project belongs to at most one group.** Linking a project that's
  already in another group fails unless `--force` is passed (re-links).
- **Environment names are unique within a group.** `production`, `preview`,
  `staging` — whatever you call them.
- **The project is the storage unit.** The group only records which
  projects correspond to which environments. Delete a project, the group
  entry becomes stale (detected by `diff`).
- **Groups are optional.** Projects that aren't in a group work exactly as
  they do today. Zero migration, zero breaking changes.

### 3.2 Key inheritance

When a project is linked to a group, it can **inherit** keys from another
project in the same group. Inheritance is a *resolve-time* concept, not
stored duplication:

```
resolve(group="liftclub", env="preview", key="DATABASE_URL")
  → looks up DATABASE_URL in liftclub-preview
  → if present, returns that value
  → if absent, falls back to the "base" environment (production)
  → if absent there too, returns "not found"
```

This means:

- **Preview can define only the keys that differ** (DATABASE_URL,
  BETTER_AUTH_URL, NUXT_PUBLIC_APP_URL) and inherit the rest from
  production. No duplication.
- **Inheritance is read-only.** Inherited values are never written to the
  child project. They're resolved at `get`/`run`/`env`/`export` time.
- **Inheritance is explicit.** A project opts in via `tvault env link
  --inherit-from <base-env>`. It can be disabled per-key with
  `tvault env pin <key>` (writes the current resolved value into the
  project, breaking inheritance for that key).
- **Inheritance does not leak values across DEKs.** The base project's
  value is decrypted with the base project's DEK, then re-encrypted with
  the child project's DEK only when `pin`-ed. At resolve time, both DEKs
  are available (same vault, same passphrase), so the value is decrypted
  from the base and returned — it never touches the child's ciphertext.

### 3.3 Sealed-profile bundles

A new seal format that packages **all environments of a group** into a
single sealed blob, keyed by environment name:

```bash
tvault env seal --group liftclub --recipient tvault1ci… -o ci/migration.sealed
```

The blob contains `DATABASE_URL` for each environment, distinguished by
a section header:

```
[production]
DATABASE_URL=postgresql://...prod-host...

[preview]
DATABASE_URL=postgresql://...preview-host...
```

In CI, decrypt and select the section matching the branch:

```bash
tvault decrypt-env --in ci/migration.sealed --identity ci --section preview --out .env
```

This replaces the current N-blobs-per-environment pattern with one blob
per group. The `--section` flag is the only new decrypt-env surface.

## 4. CLI commands

### 4.1 Group management

```bash
# Create an environment group
tvault env group create liftclub \
  --description "LIFT Club environments" \
  --production liftclub \
  --preview liftclub-preview

# Add an environment to an existing group
tvault env group add staging --project liftclub-staging --group liftclub

# List groups
tvault env group list
# NAME       ENVIRONMENTS                         DESCRIPTION
# liftclub   production, preview                  LIFT Club environments

# Show group details (which projects, key drift, inheritance status)
tvault env group show liftclub

# Remove an environment from a group (does not delete the project)
tvault env group remove preview --group liftclub

# Delete a group entirely (projects are untouched)
tvault env group delete liftclub
```

### 4.2 Linking and inheritance

```bash
# Link a project into a group as a named environment
tvault env link --project liftclub-preview --group liftclub --name preview

# Set up inheritance: preview inherits from production
tvault env inherit --group liftclub --env preview --from production

# Pin a specific key (write the resolved value into the child project,
# breaking inheritance for that key only)
tvault env pin DATABASE_URL --group liftclub --env preview

# Unpin (restore inheritance — deletes the pinned value from the child,
# falling back to the base)
tvault env unpin DATABASE_URL --group liftclub --env preview

# Show inheritance status for all keys
tvault env inherited --group liftclub --env preview
# KEY                 INHERITED-FROM   PINNED
# STRIPE_SECRET_KEY   production       no
# DATABASE_URL        —                yes (local value)
# BETTER_AUTH_URL     —                no (local value)
# RESEND_KEY          production       no
```

### 4.3 Drift detection

```bash
# Compare key sets across environments in a group
tvault env diff liftclub
# KEY                 PRODUCTION   PREVIEW   STATUS
# DATABASE_URL        ✓            ✓         different
# STRIPE_SECRET_KEY   ✓            ✓         same
# BETTER_AUTH_URL     ✓            ✓         different
# STRIPE_WEBHOOK_SEC  ✓            ✗         missing in preview
# E2E_DATABASE_URL    ✗            ✓         preview-only
# QR_SIGNING_SECRET   ✓            ✗         missing in preview  ← drift!

# Compare values (metadata: same/different, never prints values)
tvault env diff liftclub --values

# Compare only key sets (fast, no decryption needed)
tvault env diff liftclub --keys-only

# JSON output for CI
tvault env diff liftclub --json
```

Exit codes for `env diff`:

| Code | Meaning |
|------|---------|
| 0 | All environments have the same key set (no drift) |
| 1 | Drift detected (missing keys, extra keys) |
| 2 | Group not found |
| 3 | Vault locked |

### 4.4 Promote

```bash
# Copy a single key's value from preview to production
tvault env promote DATABASE_URL --group liftclub --from preview --to production

# Copy multiple keys
tvault env promote STRIPE_SECRET_KEY RESEND_KEY --group liftclub --from preview --to production

# Copy all keys that differ (--all)
tvault env promote --all --group liftclub --from preview --to production

# Dry run (show what would be promoted, metadata only)
tvault env promote DATABASE_URL --group liftclub --from preview --to production --dry-run

# Promote with --yes (no confirmation prompt)
tvault env promote --all --group liftclub --from preview --to production --yes
```

**Safety:**

- Promote always prompts unless `--yes` is passed.
- `--dry-run` shows what would change without writing.
- Each promoted key gets an audit entry: `secret.promote` with
  `from_env`, `to_env`, `key`, `from_version`, `to_version`.
- Promote writes a new version (not a rollback) — the prior value is
  archived in the target project's history.

### 4.5 Sealed-profile bundles

```bash
# Seal all environments of a group into one blob
tvault env seal --group liftclub --recipient tvault1ci… -o ci/migration.sealed

# Seal specific keys only
tvault env seal --group liftclub --keys DATABASE_URL,STRIPE_SECRET_KEY \
  --recipient tvault1ci… -o ci/migration.sealed

# Seal specific environments only
tvault env seal --group liftclub --envs production,preview \
  --recipient tvault1ci… -o ci/migration.sealed

# Decrypt and extract one environment's section
tvault decrypt-env --in ci/migration.sealed --identity ci --section preview --out .env

# Decrypt and extract all sections (for local dev/inspection)
tvault decrypt-env --in ci/migration.sealed --identity ci --out .env.all
```

### 4.6 Resolution-aware get/run/env

```bash
# get resolves through inheritance
tvault get STRIPE_SECRET_KEY -p liftclub-preview
# → resolves from liftclub-preview if present, else from liftclub (production)

# run injects resolved values
tvault run -p liftclub-preview -- npm start
# → STRIPE_SECRET_KEY resolved from production (inherited)
# → DATABASE_URL resolved from preview (local value)

# env exports resolved values
tvault env -p liftclub-preview --format shell
# → all keys, with inherited values resolved

# Show which project a value came from
tvault get STRIPE_SECRET_KEY -p liftclub-preview --show-source
# STRIPE_SECRET_KEY=inherited:production
```

## 5. MCP tools

### 5.1 New tools

```json
{
  "vault_env_group_create": {
    "description": "Create an environment group linking multiple projects. The group is metadata-only — projects keep their own DEKs. Returns the group name and linked environments.",
    "input": {
      "name": "string — group name (e.g. 'liftclub')",
      "description": "string — human-readable description",
      "environments": [
        {
          "name": "string — environment name (production, preview, staging)",
          "project": "string — existing tvault project name"
        }
      ]
    },
    "output": {
      "name": "string",
      "environments": ["{name, project}"]
    }
  },

  "vault_env_group_list": {
    "description": "List all environment groups with their linked projects. Metadata only; no secret values.",
    "output": {
      "groups": ["{name, description, environments: [{name, project}]}"]
    }
  },

  "vault_env_diff": {
    "description": "Compare key sets across environments in a group. Reports missing/extra keys and same/different values (metadata only — never prints values). Returns exit-code-equivalent status: 'ok' or 'drift'.",
    "input": {
      "group": "string — group name",
      "values": "boolean — compare values (same/different, never prints them). Default false (key-set only)."
    },
    "output": {
      "group": "string",
      "status": "'ok' | 'drift'",
      "keys": [
        {
          "key": "string",
          "environments": ["{env: 'production', present: true, status: 'same|different|missing|local-only'}"]
        }
      ]
    }
  },

  "vault_env_promote": {
    "description": "Copy a secret value from one environment to another within a group. The value is decrypted from the source, re-encrypted into the target, and a new version is created in the target. The prior value is archived (non-destructive). Audit entry: secret.promote.",
    "input": {
      "group": "string — group name",
      "keys": ["string[] — keys to promote. Empty + all=true promotes all differing keys."],
      "from_env": "string — source environment name",
      "to_env": "string — target environment name",
      "all": "boolean — promote all keys that differ. Default false.",
      "dry_run": "boolean — show what would change without writing. Default false."
    },
    "output": {
      "promoted": ["{key, from_version, to_version}"],
      "skipped": ["{key, reason}"]
    }
  },

  "vault_env_seal": {
    "description": "Seal all environments of a group into a single recipient-sealed blob. Each environment's secrets are in a labeled section. In CI, decrypt with --section <env> to extract one environment's values. Output is ciphertext — safe to commit. Secret values are NEVER returned.",
    "input": {
      "group": "string — group name",
      "recipients": ["string[] — X25519 recipient strings (tvault1…)"],
      "keys": ["string[] — specific keys to seal. If omitted, seals all keys (policy-filtered)."],
      "envs": ["string[] — specific environment names to include. If omitted, all environments."],
      "output_path": "string — write the sealed blob to this file. If empty, returns base64."
    },
    "output": {
      "path": "string (if output_path was set)",
      "sealed_base64": "string (if no output_path)",
      "bytes": "int",
      "environments": ["string — names of environments included"],
      "keys": ["string — key names included"],
      "recipient_count": "int"
    }
  },

  "vault_env_inherit": {
    "description": "Configure key inheritance for an environment. The child environment resolves missing keys from the base environment at read time (get/run/env/export). Inheritance is metadata-only — no values are copied. Returns the inheritance configuration.",
    "input": {
      "group": "string — group name",
      "env": "string — child environment name",
      "from": "string — base environment name to inherit from"
    },
    "output": {
      "group": "string",
      "env": "string",
      "inherits_from": "string"
    }
  },

  "vault_env_inherited": {
    "description": "Show which keys in an environment are inherited vs. local (pinned). Metadata only — no values.",
    "input": {
      "group": "string — group name",
      "env": "string — environment name"
    },
    "output": {
      "keys": [
        {
          "key": "string",
          "source": "'local' | 'inherited:<env>' | 'missing'",
          "pinned": "boolean"
        }
      ]
    }
  }
}
```

### 5.2 Existing tools (enhanced)

- `vault_get_secret` — add optional `group` + `env` params. When both are
  set, resolution walks the inheritance chain. When only `project` is set,
  behavior is unchanged (backward compatible).
- `vault_run_with_secrets` — add optional `group` + `env` params. Same
  resolution semantics.
- `vault_export_env` — add optional `group` + `env` params.
- `vault_seal_for_recipients` — unchanged. The new `vault_env_seal` is a
  separate tool that seals multiple environments in one blob.

### 5.3 Security

- **No cross-DEK leakage.** Inheritance resolves at read time: the value
  is decrypted from the base project's DEK and returned. It is never
  written to the child project's ciphertext. `pin` is the only operation
  that copies a value across DEKs (decrypt from base, encrypt into child).
- **Audit.** Every promote, pin, unpin, inherit, and group change writes
  an audit entry. The action field is `secret.promote`, `secret.pin`,
  `secret.unpin`, `env.inherit`, `env.group.*`.
- **MCP redaction.** `vault_env_diff` with `values=true` returns only
  `same`/`different` verdicts. `vault_env_promote` returns only version
  numbers, never values. `vault_env_seal` returns ciphertext only.
- **Policy.** Access policy applies per-project. A policy that denies
  `production` blocks promote-to-production, inheritance-from-production,
  and sealing production's keys.

## 6. Storage model

### 6.1 Where group metadata lives

Group metadata is stored in the existing `_config` bucket under a
reserved key prefix:

```
_config/group:{name} → JSON document
```

The JSON schema:

```json
{
  "name": "liftclub",
  "description": "LIFT Club environments",
  "created_at": "2026-06-25T20:00:00Z",
  "updated_at": "2026-06-25T20:00:00Z",
  "environments": [
    {"name": "production", "project": "liftclub"},
    {"name": "preview", "project": "liftclub-preview"}
  ],
  "inheritance": {
    "preview": {"from": "production"}
  }
}
```

No new bbolt buckets. No store interface changes. The `ConfigStore`
(`GetConfig`/`SetConfig`/`DeleteConfig`) already supports arbitrary
key/value pairs. A `group:` prefix namespace is all that's needed.

### 6.2 Where sealed-profile blobs live

The sealed blob is a `.env.encrypted` v2 file with a multi-section body:

```
magic ‖ ver=2 ‖ reserved ‖ count=1 ‖ stanzas ‖ body
```

The body is a dotenv file with section headers:

```
--- tvault-env:production ---
DATABASE_URL=postgresql://...
STRIPE_SECRET_KEY=sk_live_...
--- tvault-env:preview ---
DATABASE_URL=postgresql://...
--- end ---
```

`decrypt-env --section preview` extracts only the lines between
`--- tvault-env:preview ---` and the next `--- tvault-env:` (or `--- end ---`).
This is a thin parser addition to `internal/encryptedenv/`, not a new
crypto format.

### 6.3 Backward compatibility

- Projects not in a group: zero behavior change. All existing commands work
  identically.
- `vault_get_secret` with no `group`/`env` params: unchanged.
- `tvault seal` (single project): unchanged. `tvault env seal` is a new
  command that produces multi-section blobs.
- `tvault decrypt-env` on existing v2 blobs (no section headers): unchanged.
  Section parsing only activates when `--- tvault-env:` markers are present.
- `tvault diff <file>` (env-file drift): unchanged. `tvault env diff` is a
  new command for cross-project drift.

## 7. Implementation plan

### Phase 1 — Group metadata + drift detection (no inheritance)

**Files touched:**

- `internal/vault/envgroup.go` — new file: `EnvGroup` struct, CRUD
  methods on `Vault`, config-bucket serialization.
- `internal/vault/query.go` — add `DiffEnvironments(groupName string) (*EnvDiff, error)`
  that compares key sets across linked projects (metadata only, no decryption).
- `cmd/tvault/cmd/env_group.go` — new file: CLI commands for group
  create/list/show/add/remove/delete.
- `cmd/tvault/cmd/env_diff.go` — new file: `tvault env diff` CLI.
- `internal/mcp/tools_env_groups.go` — new file: MCP tools
  `vault_env_group_create`, `vault_env_group_list`, `vault_env_diff`.

**Effort:** M. No crypto changes, no store interface changes. Pure
metadata + comparison logic.

**Value:** solves the #1 pain (silent drift). You can create a group,
link `liftclub` + `liftclub-preview`, and run `tvault env diff liftclub`
to see that `STRIPE_WEBHOOK_SECRET` is missing in preview.

### Phase 2 — Promote

**Files touched:**

- `internal/vault/envgroup.go` — add `Promote(groupName, fromEnv, toEnv string, keys []string, dryRun bool) (*PromoteResult, error)`.
  Decrypts from source project, re-encrypts into target project, writes audit.
- `cmd/tvault/cmd/env_promote.go` — new file: `tvault env promote` CLI.
- `internal/mcp/tools_env_groups.go` — add `vault_env_promote`.

**Effort:** S. The crypto path already exists (decrypt + encrypt). The
new logic is: resolve source project by env name, resolve target project
by env name, loop keys, `GetSecret` from source, `SetSecret` into target,
  audit. Dry-run just reports without writing.

**Value:** "promote from preview to production" is a one-liner with
audit trail.

### Phase 3 — Sealed-profile bundles

**Files touched:**

- `internal/encryptedenv/encryptedenv.go` — add section-header parsing to
  `DecryptV2` (or a new `DecryptV2Sections` that returns a
  `map[string]map[string]string`). Add `EncryptV2MultiSection` that
  builds the multi-section body.
- `cmd/tvault/cmd/env_seal.go` — new file: `tvault env seal` CLI.
- `cmd/tvault/cmd/encrypted_env.go` — add `--section` flag to
  `decrypt-env`.
- `internal/mcp/tools_env_groups.go` — add `vault_env_seal`.

**Effort:** M. The section format is a thin parser on top of the
existing v2 body. The seal command iterates environments, resolves
keys (with inheritance if Phase 4 is done), and builds the multi-section
body.

**Value:** one sealed blob per group instead of N. CI workflows
decrypt once and select by `--section`.

### Phase 4 — Inheritance + pin

**Files touched:**

- `internal/vault/envgroup.go` — add inheritance config CRUD,
  `ResolveKey(groupName, envName, key string) (string, string, error)`
  (returns value + source-env-name), `PinKey`/`UnpinKey`.
- `internal/vault/secret.go` — add `GetSecretWithInheritance` that
  walks the chain.
- `cmd/tvault/cmd/env_inherit.go` — new file: `tvault env inherit`,
  `tvault env pin`, `tvault env unpin`, `tvault env inherited` CLI.
- `internal/mcp/tools_env_groups.go` — add `vault_env_inherit`,
  `vault_env_inherited`.
- `internal/mcp/tools_secrets.go` — enhance `vault_get_secret` with
  optional `group` + `env` params.
- `internal/mcp/tools_exec.go` — enhance `vault_run_with_secrets` with
  optional `group` + `env` params.
- `internal/mcp/tools_env.go` — enhance `vault_export_env` with
  optional `group` + `env` params.

**Effort:** L. Inheritance touches the resolution path of get/run/env,
which is the most-used code path. The key constraint: when `group`+`env`
are not provided, the existing path runs untouched (zero regression risk).
The inheritance path is a new branch, not a modification of the existing one.

**Value:** preview defines only the keys that differ. Everything else
inherits from production. No duplication, no drift on shared keys.

### Phase 5 — Resolution-aware run/env/get (CLI)

**Files touched:**

- `cmd/tvault/cmd/get.go` — add `--group` + `--env` flags, resolution
  through `ResolveKey`.
- `cmd/tvault/cmd/run.go` — add `--group` + `--env` flags, inject resolved
  values.
- `cmd/tvault/cmd/env.go` — add `--group` + `--env` flags, export resolved
  values.
- `cmd/tvault/cmd/export.go` — same.

**Effort:** M. The flags are additive. The resolution function from
Phase 4 is the shared logic.

### Recommended sequence

1. **Phase 1** (group metadata + drift) — ships the #1 value first.
2. **Phase 2** (promote) — small, high-value, builds on Phase 1.
3. **Phase 3** (sealed bundles) — simplifies CI for multi-env projects.
4. **Phase 4** (inheritance) — the big ergonomic win, but also the biggest
   change to the resolution path. Ship after the metadata model is proven.
5. **Phase 5** (resolution-aware CLI) — makes inheritance useful. Depends
   on Phase 4.

Each phase is independently shippable. Phase 1 alone solves the drift
detection problem. Phases 1+2 add the promote workflow. Phases 1+2+3
replace the N-blobs-per-environment pattern.

## 8. Non-goals (explicit)

- **No automatic sync.** Profiles do not watch for changes and propagate.
  Every cross-environment write is explicit (promote, pin).
- **No environment-level RBAC.** Sharing/revocation stays per-project
  (per-DEK). If preview and production need different recipients, they're
  different projects with different `RecipientWraps`. The group doesn't
  change that.
- **No environment-level DEK derivation.** The DEK is per-project. We do
  not derive child DEKs from a parent. Each project generates its own
  random DEK, full stop.
- **No hosted registry.** Groups are local metadata. If two developers
  need the same group, they each create it (or one exports it as JSON and
  the other imports). No sync.
- **No breaking changes to existing commands.** Every new feature is
  opt-in via new flags (`--group`, `--env`) or new commands (`env *`).
  Projects not in a group work identically to today.

## 9. Threat model additions

- **Inheritance does not weaken isolation.** Inheritance is a read-time
  resolution that decrypts from the base project's DEK. The child project's
  ciphertext is never touched by inheritance. A compromised child project
  (leaked DEK) does not grant access to the base project's values — the
  attacker would need the base project's DEK.
- **Promote is a controlled cross-DEK copy.** The value is decrypted from
  the source DEK and encrypted into the target DEK. The plaintext exists
  in memory for the duration of the operation. This is the same threat
  surface as `get` + `set` done manually — promote just makes it atomic
  and audited.
- **Sealed-profile blobs are per-recipient.** The multi-section blob is
  sealed with the same v2 recipient layer. A holder of the `ci` identity
  can decrypt all sections. If you need per-environment recipients
  (preview CI can't read production), seal separately — `tvault env seal`
  with `--envs preview` produces a preview-only blob.
- **Group metadata is not encrypted.** The group config (which projects
  map to which environments) is stored in `_config`, which is in the
  clear (same as `current_project` today). This reveals environment names
  and project relationships, but not secret values. This is acceptable
  for the same reason `current_project` is: the vault file is `0600` and
  the threat model is local-disk compromise, which is already game-over.

## 10. Testing plan

- **Unit tests:** `EnvGroup` CRUD, `DiffEnvironments` key-set comparison,
  `Promote` dry-run + real, `ResolveKey` inheritance chain, `PinKey`/
  `UnpinKey`, multi-section seal/decrypt round-trip.
- **Integration tests:** create group, link 2 projects, add key to one,
  detect drift via diff, promote to fix drift, re-diff (clean), seal +
  decrypt --section round-trip.
- **MCP tests:** `vault_env_diff` returns metadata only, `vault_env_promote`
  returns version numbers only, `vault_env_seal` returns ciphertext only.
  Use `mcp.NewInMemoryTransports()` as existing tests do.
- **Backward compatibility:** existing `get`/`run`/`env`/`seal`/`decrypt-env`
  commands produce identical output with no `--group`/`--env` flags.
- **Security tests:** promote to a policy-denied project fails; inheritance
  from a policy-denied project fails; sealed blob with `--envs preview`
  does not contain production section.