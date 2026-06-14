# ROADMAP — making `tvault` a great secrets tool

> Product analysis of TinyVault across TUI, DX, CLI, API, and the
> "manage + share secrets everywhere" vision (docker, bun, .env, ssh, CI,
> commit-to-repo, agents). Grounded in the codebase; every proposal was
> adversarially stress-tested for security/feasibility before landing here.
> Status: **analysis & proposal — nothing built yet.** Pick the threads to pursue.

---

## TL;DR

TinyVault today is an excellent **single-user, single-machine, local-first**
secrets manager with a strong agent story (MCP) and now a great TUI. The
vision — *share* secrets across people/CI/agents, *commit* them to the repo,
*pull* them over many transports — is blocked by **two architectural gaps**.
Everything else is quick wins or builds on these two:

1. **Crypto is symmetric-only.** `passphrase → Argon2id KEK → per-project DEK
   → value`. The only way to grant access is to hand over the passphrase. You
   cannot safely share with a teammate, commit per-recipient-decryptable
   secrets, or let CI/an agent decrypt without distributing the master secret.
   → **Decision A: add an asymmetric recipient layer (X25519, age-style).**

2. **There is no cross-process unlocked session.** Every command re-derives
   the Argon2id KEK in-process, and bbolt is opened with an *exclusive* lock
   (no `ReadOnly`), so two `tvault` processes can't even read concurrently.
   This blocks the "use it everywhere" half — docker, the bun/direnv hook,
   ssh, a broker, an agent all need a resident unlocked owner.
   → **Decision B: add a resident agent + local broker (ssh-agent model).**

Plus one **foundation fix** that several features quietly depend on:
**audit logging is MCP-only today** — CLI/TUI `set`/`delete`/`get` write *no*
audit entry. "Audited mutations", an audit timeline, and tamper-evident logs
all need this first. Cheap, high-leverage.

---

## The two spines + how everything hangs off them

```
WAVE 0  Foundations & quick wins ── need neither spine ──────────────┐
  audit-everywhere · --output/JSON envelope+exit codes · doctor+config │
  TUI safe mutations · TUI .env drift/diff · secret history/rollback   │
                                                                       │
SPINE B: Resident agent + broker        SPINE A: Asymmetric recipients │
  tvault agent (resident KEK owner)       recipient.go (X25519 stanza) │
  fix bbolt exclusive-lock                identity new/list, share/    │
  tvault serve (unix-socket broker,         unshare, .tvault-recipients│
    fetch-by-reference, capability tokens)                            │
        │                                       │                      │
        ▼                                       ▼                      │
  docker secret provider                 .env.encrypted v2 (commit-safe)
  tvault hook (bun/node/direnv)          git clean/smudge filters       
  tvault ssh                             OIDC/keyless + ssh transports   
  transport-aware MCP, ephemeral tokens  k8s SealedSecret-equiv, MCP seal
  thin Python/Node broker clients        
```

---

## Wave 0 — Foundations & quick wins (no new architecture)

Ship these first: high value, low risk, no crypto/transport prerequisites.

| Item | Why | Effort | Notes from stress-test |
|---|---|---|---|
| **Audit everywhere** — write audit entries from the CLI/TUI vault path, not just MCP | "Audited mutations", audit timeline, tamper-evidence all depend on it | **S–M** | Today only `internal/mcp` calls `AppendAudit`; `vault.SetSecret`/`DeleteSecret`/`GetSecret` don't. Add it at the vault layer so every surface is covered once. |
| **Uniform machine output** — a real `--output text\|json`, one JSON envelope, meaningful exit codes | Strengthens the agent/scripting identity | **M** | `env.go`'s hand-rolled JSON (`escapeJSONValue`) doesn't escape control bytes (`\r`, NUL) → invalid JSON; switch to `encoding/json`. Design exit codes to avoid collision with cobra's `64`. |
| **`tvault doctor` + a typed config file** | Diagnoses setup; anchors DX and feeds TUI/hook toggles | **M** | `root.go` wires viper to `~/.tvault/config.yaml` but binds only 3 flags — a typed config struct is purely additive. All read-only methods doctor needs already exist (`Status`, `SnapshotProjects`). |
| **TUI: safe, audited mutations** (`set`/`edit`/`delete`/`generate`) behind an explicit `--rw` edit mode | The #1 "what's next" for the browser | **L** | Reuses the CLI's DEK path; slots `modeEdit`/`modeConfirm` into the existing `handleKey` switch like `modeUnlock`. Default-off `--rw`. *Requires the audit-everywhere fix to be truly "audited."* |
| **`.env` drift / diff** | Answers "is my `.env` in sync with the vault?" | **L** | ✅ Shipped as the CLI `tvault diff <file>` (metadata-only by default; `--values` compares values without printing them). A live indicator inside the browser is a nice follow-up. |
| ~~Secret history & rollback~~ → **version history** (later wave) | A version *number* exists, but… | **L** | ⚠️ **Scope correction (found during Wave 0):** `store.SetSecret` (`bbolt.go`) bumps the `Version` *counter* but **overwrites the value** — no prior values are kept, so `rollback` is impossible without a new version-history bucket (a storage change, not a quick win). Only version metadata (number + created/updated) is surfaceable today. Moved out of Wave 0; do the history-store change in a later wave alongside crypto-agility. |

---

## Spine B — Resident agent & local broker ("use it everywhere")

The unifier for docker/bun/ssh/CI. **Build the agent first; everything else attaches.**

| Item | Why | Effort | Critical refinement |
|---|---|---|---|
| **`tvault agent`** — a resident process that holds the unlocked vault (ssh-agent model); unlock once, reuse across commands | Kills the "re-type passphrase / pay 64 MiB Argon2id every command" pain; the prerequisite for the hook, docker, ssh, broker | **M–L** | **Must fix the bbolt exclusive lock first** (`bbolt.go` opens `0o600` with no `ReadOnly`, 1s timeout → second process blocks). Either the agent becomes the *sole* owner that others talk to, or readers open `ReadOnly`. This is the load-bearing detail. |
| **`tvault serve`** — local broker over a unix socket: fetch-**by-reference** with per-caller **capability tokens** + audit | Other processes/containers get values without env-dumping; values stay out of scrollback | **L** | Keep the "reference in, value out, audited" shape. Capability tokens scope a caller to specific projects/keys. |
| **`tvault hook`** — direnv-style shell autoload for bun/node/any dotenv | The everyday DX win | **M** | ⚠️ **Stress-test flagged this "flawed" as originally framed**: there's no cross-process session to read from *without the agent*, and auto-dumping decrypted values into the shell env on `cd` is real exposure. Gate it: requires the agent, opt-in per-dir, prefer reference-injection over plaintext env. |
| **Docker integration** — BuildKit `--mount=type=secret` provider, compose env injection, container entrypoint wrapper | "Use it across docker" | **L** | Builds cleanly on `run`/`env` + the broker. |
| **`tvault ssh host -- cmd`** — inject secrets into a remote command without writing them to the remote disk | "Pass data safely over ssh" | **M** | Stream over the ssh channel into the remote process env; never touch remote disk. |
| **Transport-aware MCP + ephemeral tokens** — `mcp-server --connect unix://…agent.sock`, `tvault token issue` (short-lived, policy-bound) | The agent-fetch-in-CI/over-ssh story | **M** | Lets agents fetch through the broker with scoped, expiring creds instead of `TVAULT_PASSPHRASE`. |

---

## Spine A — Asymmetric recipients & "secrets as code" (the headline)

This is the centerpiece of your vision and the biggest differentiator vs. SOPS+age / dotenvx / sealed-secrets. **`recipient.go` unlocks the whole column.**

| Item | Why | Effort | Critical refinement |
|---|---|---|---|
| **Asymmetric recipient layer** — `internal/crypto/recipient.go`: X25519 → HKDF-SHA256 → ChaCha20-Poly1305 wrapping of the project DEK; `tvault identity new/list`, `tvault project share/unshare --recipient tvault1…` | Relocates trust from "everyone shares the passphrase" to "per-actor keypairs" — *genuinely safe* sharing | **XL** | ✅ **Landed:** `recipient.go` (WrapDEK/UnwrapDEK + Identity, crypto/ecdh + chacha20poly1305 + hkdf, tvault-native stanza, **no new dependency**, crypto-reviewed); `tvault identity new/list`; `tvault projects share/unshare/recipients`; and `tvault env --identity <name>` (recipient read with no passphrase). `RecipientWraps []DEKWrap` is stored beside the KEK wrap (backward-compatible). **Revocation is real** — `unshare` rotates the DEK and re-encrypts every value atomically (`store.RekeyProject`), re-wraps to remaining recipients, and audits grant/revoke. age/sops interop stays deferred. **Done next:** `.env.encrypted v2` and the git clean/smudge filters, both ✅ landed (rows below). |
| **`.env.encrypted` v2** — commit-safe, per-recipient-wrapped DEK, **no dependence on the local KEK** | "Commit secrets to the repo, they decode when needed" (the dotenvx/SOPS pattern) | **L** | ✅ **Landed:** `encryptedenv.EncryptV2/DecryptV2` + `FileVersion`. A random per-file key encrypts the body and is wrapped to recipients (`WrapDEK`); layout `magic‖ver=2‖reserved‖count‖stanzas‖body`. `encrypt-env --recipient` writes v2; `decrypt-env --identity` opens it and auto-detects v1 (KEK) vs v2. KEK-independent — passphrase rotation does not invalidate it. Tested: round-trip, multi-recipient, wrong/absent identity, v1↔v2 cross-rejection, truncation, tamper. |
| **Git clean/smudge filters** — `tvault git-filter` to auto-encrypt on commit / decrypt on checkout | "Have them decode themselves" with zero manual steps | **L** | ✅ **Landed:** `cmd/tvault/cmd/gitfilter.go` — `install`/`track`/`status`/`checkout`/`uninstall` + hidden `git-clean`/`git-smudge`. Recipients in a committed `.tvault-recipients`; identity from `$TVAULT_IDENTITY`→`git config tvault.identity`→`default`. **Idempotent clean** (re-emits the staged blob when plaintext is unchanged) so `git status` stays quiet; **locked mode** passes ciphertext through without an identity; anti-double-encrypt. `install`/`checkout` re-smudge the working tree post-clone. Verified end-to-end against a real repo (commit→clone→edit). Bootstrapping reality unchanged: a teammate/CI still needs their *private* key delivered once. |
| **Keyless/OIDC + ssh transports for CI/agents** — decrypt with a per-context identity, never the passphrase | "Agent pulling secrets in CI or over ssh, safely" | **XL** | ⚠️ Stress-test: this is **impossible without Spine A** (otherwise you ship the passphrase to CI). Sequence it *after* recipients. OIDC binds a CI identity to a recipient key. |
| **k8s SealedSecret-equivalent + external-secrets sync** | Commit-safe k8s manifests; render Secrets at deploy | **L–M** | Same recipient model, k8s-shaped output. |
| **MCP `vault_seal_for_recipients` / `vault_open_sealed`** | Agents seal/open secrets for others without seeing the master key | **M** | Thin MCP wrappers over `recipient.go`. |

---

## Cross-cutting hardening (do alongside, not after)

- **Revocation = DEK rotation + re-encrypt** (see above) — bake into the design from day one, not bolted on.
- **Redaction limits** — `run`'s output redaction misses multiline/base64-encoded values and isn't applied on the CLI `run` path the way it is in MCP. Harden + extend.
- **Enforce policy claims** — `max_reads_per_session` and per-command allowlist are documented but not all enforced; close the SPEC↔code gap. Tamper-evident audit (hash chain).
- **Crypto agility** — version every wrapped artifact so committed ciphertext stays upgradeable over its (long) lifetime.

---

## Competitive positioning (why this wins)

- vs **SOPS+age / git-crypt / sealed-secrets**: they do commit-safe asymmetric secrets but have *no agent story, no TUI, no run-injection, no MCP*. Spine A closes the crypto gap; TinyVault keeps the UX + agent lead.
- vs **dotenvx**: similar commit-safe `.env` story; TinyVault adds projects, audit, MCP, the TUI, and broker-based injection.
- vs **Doppler/Infisical/Vault**: they're hosted/server-first. TinyVault stays **local-first + zero-infra**, which is the whole point — don't chase a control plane.
- **Unique seat:** local-first **+** agent-first (MCP) **+** secrets-as-code (Spine A) **+** use-it-everywhere broker (Spine B). Nobody else sits in all four.

---

## Recommended sequencing

1. **Wave 0 quick wins** — immediate value, unblocks "audited" everything. Start with **audit-everywhere** + **`--output`/exit codes** + **`doctor`/config**, then **TUI mutations**.
2. **Pick the headline spine.** If the priority is *team/CI/commit sharing* → **Spine A (recipients)** is the differentiator. If the priority is *daily local DX across docker/bun/ssh* → **Spine B (agent/broker)** removes the most friction first. They're largely independent and can interleave.
3. **Transports & integrations (Wave 3)** ride on whichever spine they need (the table marks it).

*First concrete sprint suggestion:* audit-everywhere → `tvault doctor` + config → uniform `--output` → TUI `--rw` mutations. Small, shippable, and every later wave benefits.
