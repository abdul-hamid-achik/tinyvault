---
title: Security & Threat Model
description: TinyVault's honest threat model — what local-first encryption, the MCP redaction layer, and the unix agent protect against, and the residual risks they do not.
---

# Security & Threat Model

This is the honest security page. TinyVault is a single binary (written in Go) that encrypts secrets at rest, redacts them from AI agents, and serves them over a tightly-confined local socket. None of those layers is magic. This page tells you exactly what each one stops, what it does not, and how TinyVault compares to the tools you might reach for instead.

Read this before you trust TinyVault with anything that matters. The short version: it protects your secrets at rest with strong cryptography and keeps values out of an AI model's context window, but it has no recovery story, no team sync, and it cannot defend a running, unlocked process from another process running as the same user.

## The model at a glance

- The vault is a single file (`~/.tvault/vault.db`, mode `0600`, in a `0700` directory). Every secret value is AES-256-GCM encrypted under a per-project key.
- The encryption key for the whole vault (the KEK) is derived from your passphrase with Argon2id and only ever lives in RAM while the vault is unlocked.
- There is no account, no server, no network. The vault never leaves your disk unless you explicitly back it up, seal it, or commit a sealed blob.
- Three optional surfaces extend this: an MCP server for AI agents, a unix-socket agent for fast repeated access, and a recipient/identity layer for sharing. Each has its own security model, covered below.

For the cryptographic design and key hierarchy, see [Architecture](/reference/architecture). For how the pieces fit together conceptually, see [Concepts](/guide/concepts).

## Key hierarchy

TinyVault uses a two-tier key scheme so that compromising one project's data does not compromise the rest.

```
your passphrase
  └─ Argon2id ───────────► KEK            (in RAM only while unlocked)
                            │
                            ├─ AES-GCM(KEK, project DEK) ─► encrypted DEK in project record
                            │        └─ project DEK
                            │              └─ AES-GCM(DEK, value) ─► encrypted secret value
                            │
                            └─ AES-GCM(KEK, verifier) ──► passphrase check
```

| Primitive | Role | Parameters |
|-----------|------|------------|
| Argon2id | Passphrase → KEK | 64 MiB memory, 3 iterations, 4 threads |
| AES-256-GCM | Encrypts the KEK-wrapped DEKs, every value, and the verifier | 32-byte key, fresh 12-byte nonce per operation |
| X25519 + HKDF-SHA256 + ChaCha20-Poly1305 | Recipient layer (sharing, committable secrets) | stdlib `crypto/ecdh`, domain-separated HKDF |

Rotating your passphrase (`tvault key rotate`) re-derives a new KEK and re-wraps each project DEK; it never touches the encrypted values themselves. See [Key Management](/guide/key-management).

## Threat model: in scope

These are the threats TinyVault is built to mitigate, and how.

- **Someone reads `vault.db` at rest.** Every value is AES-256-GCM encrypted under a per-project DEK, and each DEK is wrapped by the KEK. Without the passphrase (or a recipient identity), the file is ciphertext.
- **Someone brute-forces your passphrase.** Argon2id at 64 MiB / 3 / 4 makes each guess roughly 200 ms and memory-bound, which is hostile to GPU and ASIC cracking.
- **The vault file is tampered with.** Every value, DEK, and the verifier carries an AES-GCM authentication tag. Any modification fails authentication and is rejected with a decryption error rather than silently returning corrupt data.
- **An AI agent leaks a secret into its prompt or logs.** The MCP layer is built so values never need to enter the model context: `vault_run_with_secrets` injects values as environment variables into a subprocess, `vault_export_env` writes to disk and returns a path, `vault_generate_secret` returns only `{ "stored": true }`, and `vault_seal_for_recipients` returns ciphertext. Only `vault_get_secret` returns a raw value, and it attaches a warning.
- **An AI agent escapes its allow-list.** An [access policy](/mcp/access-policy) (`~/.tvault/mcp-policy.yaml`) gates projects and secret keys with glob allow/deny lists, and `access_mode` controls whether writes and command execution are permitted. It is loaded from disk at server start; the model cannot edit it at runtime.
- **A revoked recipient keeps an old copy of the vault.** `tvault projects unshare` is true revocation: it rotates the project DEK, re-encrypts every value and its version history, and re-wraps to the remaining recipients atomically. A removed recipient cannot read new data even with a stale vault file. See [Sharing](/guide/sharing).
- **An OS-confined (different-uid) process reaches the agent socket.** The agent performs a mandatory peer-credential check and rejects any peer whose uid does not match its own. The optional `--require-token` flag adds a second gate for confined delegates.
- **A malicious dotenv file is imported.** The parser does no shell, variable, or command expansion; it enforces a filename allowlist, skips symlinks, and caps files at 1 MiB. Importing a `.env` cannot execute a payload embedded in it. See [Dotenv files](/guide/dotenv).

## Threat model: out of scope

These are explicit non-goals. They are not bugs — they are the accepted residual risk of a local-first, single-passphrase design. Plan around them.

::: danger No passphrase recovery
There is no escrow, no recovery key, no social recovery. If you forget your passphrase, the vault is **irrecoverable**. This is intentional: an escrow path is an attack surface and a trust dependency that a local-first tool refuses to take on. Back up your passphrase the same way you would back up any root credential, and keep an offline copy of the vault file.
:::

::: danger A malicious same-uid process is the trust boundary
Any process running as **your user** can read your secrets when the agent is unlocked, or unlock the vault itself if it can prompt for or capture your passphrase. Capability tokens do **not** change this — a same-uid process can read the token file, the environment, or dial the socket directly. If you do not trust code running as your own user, do not run it on a machine where your vault is unlocked.
:::

::: warning Memory forensics of a running, unlocked process
While the vault is unlocked, the KEK lives in RAM. TinyVault zeros keys after use (`crypto.ZeroBytes`) and on every clean exit path, but it cannot defend against an attacker who reads your process memory while it runs, and a `SIGKILL` bypasses the zeroing entirely. This is the same residual risk every agent (ssh-agent, gpg-agent) accepts.
:::

::: warning No multi-user isolation on a shared host
The vault is protected by filesystem permissions (`0600`), not by OS-user isolation at the crypto layer. Another user who can read your home directory can copy `vault.db` and attempt an offline brute-force. On a shared host, the Argon2id cost is your only line of defense for the file itself.
:::

The following are deliberately not on the roadmap and are not provided:

- **Team sync between machines.** There is no hosted backend and no automatic sync. Sharing is manual: back up and restore the file, or use the recipient layer to seal secrets you can commit. See [Sharing](/guide/sharing) and [Committable secrets](/guide/committable-secrets).
- **Dynamic or short-lived credentials.** TinyVault stores secrets you give it. It does not mint database credentials, lease cloud tokens, or rotate on a schedule.
- **HSM / KMS / cloud key management.** All keys are software keys derived from your passphrase. There is no integration with hardware security modules or cloud KMS.
- **Side-channel hardening beyond the Go standard library.** Constant-time guarantees are limited to what `crypto/subtle` and `crypto/aes` provide. There is no smartcard, TEE, or enclave support.

## The MCP safety model

The [MCP server](/mcp/) is the most security-sensitive surface, because it hands tools to an AI agent. Its core principle: **secret values never need to enter the model's context window.**

The server is a thin policy-and-redaction layer over the same vault API the CLI uses. The tools that touch values are designed so the agent can accomplish its task without ever seeing the bytes:

| Tool | What it returns to the model |
|------|------------------------------|
| `vault_run_with_secrets` | exit status and (redacted) output — values are injected into the subprocess env |
| `vault_export_env` | a file path on disk, not the contents |
| `vault_generate_secret` | only `{ "stored": true }` |
| `vault_seal_for_recipients` | ciphertext (a sealed `.env.encrypted` blob) |
| `vault_get_secret` | the raw value — **plus a warning** that it is now in context |

`vault_get_secret` is the single deliberate exception, gated by `max_reads_per_session` and intended for cases where the agent genuinely has no alternative. No other tool returns a raw value.

Every privileged action is audited — `secret.read`, `secret.write`, `secret.delete`, `secret.generate`, `secret.exec`, `secret.export`, `project.create`, and `project.delete` all write to the audit log, which is queryable over MCP via `vault_audit_log`.

::: warning Redaction is a safety net, not a control
`vault_run_with_secrets` post-processes subprocess output and replaces any literal occurrence of a secret value longer than 3 characters with `[REDACTED:KEY]`. This catches accidental leakage to stdout/stderr. It does **not** stop:

- Secrets sent over the **network** — the subprocess has full network access.
- Secrets written to a **file** outside the captured output.
- Secrets that are **transformed** (base64-encoded, split, re-cased) before being emitted — only literal matches are redacted.
- Values of **3 characters or fewer**, which are never redacted.

Treat redaction as a last line of defense against accidents, not as a barrier against a hostile or buggy subprocess. The real control is the access policy plus running the agent with `allow_exec: false` unless you need execution.
:::

See [MCP tools](/mcp/tools) for the full tool list and [Access policy](/mcp/access-policy) for how to constrain what an agent can reach.

::: info There is no `tvault generate` or `tvault audit` command
Secret generation is MCP-only (`vault_generate_secret`). The audit log is surfaced over MCP (`vault_audit_log`) and in the [studio](/guide/studio) — there is no standalone CLI subcommand for either.
:::

## The local agent security model

The [agent](/guide/agent) is an opt-in, unix-only daemon that holds the vault unlocked over a private socket so repeated `get` / `env` / `run` calls skip the passphrase prompt and the Argon2id derivation. It is **off by default**. Windows is unsupported.

Its design is deliberately conservative:

- **KEK-only, reopen per request.** bbolt is single-writer, so an agent that held the database open would block every other `tvault` invocation. Instead the agent caches **only the KEK** and reopens the vault for each request (validating the cached KEK against the verifier, no Argon2id), serialized by a mutex. Direct CLI access keeps working between requests.
- **Socket born locked.** The socket is created `0600` via a tight umask inside the `0700` vault directory — there is no listen-then-chmod window. Stale-socket cleanup refuses to reuse a path owned by another user or of the wrong type. A `flock`-held lockfile is the authoritative single-instance guard.
- **Mandatory peer-uid check, fail-closed.** Every connection is checked with `LOCAL_PEERCRED` (macOS) or `SO_PEERCRED` (Linux) and rejected unless the peer's uid equals the agent's. Platforms without a peer-credential implementation fail closed.
- **Read-only operations.** The wire protocol is newline-delimited JSON, one request per connection, version- and size-checked (64 KB cap), with read/write deadlines. The only operations are `get`, `getall`, `status`, and `stop`. The agent cannot write secrets.
- **KEK zeroed on every exit path.** Signal, idle auto-lock (default 15 minutes, `--idle 0` to disable), explicit `stop`, and panic-recovery all zero the KEK. The accepted residual risk is `SIGKILL`, which cannot run the zeroing — the same caveat that applies to any agent.
- **No daemonization.** `agent start` runs in the **foreground**. Backgrounding (`&`, `nohup`, systemd `Type=simple`, launchd) is your job, which keeps the live Go runtime from being forked unsafely.

CLI routing tries the agent first and silently falls back to a direct unlock if it is absent. `--no-agent` or `TVAULT_NO_AGENT=1` forces a direct unlock.

### Token honesty

::: warning Capability tokens are privilege separation, not a same-uid control
The agent's default access control is the same-uid peer-credential check, which means **any same-uid process can read any secret** through the socket. `tvault agent start --require-token --token-file <file>` does not change that. It is a privilege-separation gate that is load-bearing **only** for a delegate the OS confines away from the raw socket — a different uid, a container, a namespace, a sandbox.

A malicious same-uid process can read the token from the file, the environment, or `/proc`, or simply dial the unprotected socket itself. Tokens are not a defense against it.

Tokens are provisioned out-of-band in a `0600` file (a `SIGHUP` reloads it to revoke). There is no in-agent mint operation, so there is no same-uid mint primitive to abuse. Only the token's SHA-256 is stored, and the audit log records an 8-character hash prefix (`token_id`), never the token itself.
:::

For genuinely untrusted delegation — CI runners, containers, another person — use a scoped **identity** instead of a token. An identity is cryptographic, transport-agnostic, and atomically revocable via DEK re-key, and it needs no socket or running agent. See [Sharing](/guide/sharing) and [CI/CD](/guide/ci-cd).

## Sharing, committing, and rendering: handle with care

The recipient layer lets you share and commit secrets safely, but a few commands produce sensitive output. Know which is which.

::: danger `tvault identity export` prints a PRIVATE key
```bash
tvault identity export ci
```
This prints a `tvault-key1...` **private** key, intended for injection into a CI or SSH secret store. It is TTY-guarded: it refuses to write to a non-terminal stdout without `--force`, so it cannot silently land in a log. Never commit a `tvault-key1...` value. Only `tvault1...` recipients (the public half) are safe to share or commit.
:::

::: warning `tvault k8s render` emits a PLAINTEXT Secret
```bash
tvault k8s render --in sealed.yaml --identity cluster | kubectl apply -f -
```
The rendered output is a real Kubernetes `Secret` with **plaintext** values (base64 is not encryption). Pipe it straight to `kubectl` and never write it to a file you might commit. The committable artifact is the *sealed* input (`tvault seal --format k8s`), not the rendered output.
:::

Sealed `.env.encrypted` v2 blobs, `tvault1...` recipients, and the `.tvault-recipients` file are all safe to commit — they are ciphertext or public keys. See [Committable secrets](/guide/committable-secrets) and [Git filter](/guide/git-filter).

## Honest comparison

TinyVault is a local-first, agent-first complement to these tools, not a drop-in replacement for any of them in production. Here is the candid breakdown.

| | TinyVault | 1Password CLI | `pass` | HashiCorp Vault | Doppler |
|--|-----------|---------------|--------|-----------------|---------|
| Account / cloud required | no | yes | no | no (self-host) | yes |
| Network round-trip | no | no | no | yes | yes |
| First-class AI agent (MCP) | yes | no | no | no | no |
| Redaction-safe exec | yes | no | no | no | no |
| Per-project key isolation | yes | yes | no | yes | yes |
| Team sync | no | yes | via git | yes | yes (core) |
| Recovery without passphrase | no | yes | yes (GPG) | yes (recovery shards) | yes |
| Dynamic / short-lived secrets | no | no | no | yes | no |
| HSM / KMS | no | no | no | yes | no |
| Single binary | yes | no | no | no | no |

- **vs 1Password CLI.** TinyVault has no account and no cloud, ships as one binary, and adds first-class MCP with redaction-safe exec. 1Password gives you team sync and passphrase recovery, which TinyVault deliberately does not.
- **vs `pass`.** Both are local and account-free. TinyVault adds per-project DEK isolation, the MCP surface, and redaction-safe exec. `pass` gives you GPG-based recovery and git-based sharing out of the box.
- **vs HashiCorp Vault.** Vault is the production answer: dynamic secrets, HSM/KMS, recovery shards, HA. Those are explicit non-goals for TinyVault, which is local-first and agent-first. If you need a production secrets backend, use Vault — TinyVault is not a replacement.
- **vs Doppler.** Doppler solves team sync with a hosted backend, which means an account, a network round-trip, and a subscription. TinyVault is fully local with MCP, but it does not do Doppler-style team sync.

The honest gap, stated plainly: **no team sync, no recovery without the passphrase, no dynamic credentials.** If those are requirements, TinyVault is the wrong tool.

## Exit codes

Scripts and CI can branch on TinyVault's exit codes.

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | generic error |
| `3` | vault is locked at rest |
| `4` | secret or project not found |
| `5` | vault is not initialized |
| `6` | wrong passphrase |
| `7` | vault database is in use by another process |

```bash
tvault get API_KEY >/dev/null 2>&1
case $? in
  0) echo "ok" ;;
  3) echo "locked — run tvault unlock" ;;
  6) echo "wrong passphrase" ;;
  *) echo "error" ;;
esac
```

## Reporting a vulnerability

TinyVault is a small, security-sensitive tool. If you find a vulnerability, please open a private security advisory on the [GitHub repository](https://github.com/abdul-hamid-achik/tinyvault) rather than a public [issue](https://github.com/abdul-hamid-achik/tinyvault/issues). Cryptographic correctness bugs and MCP prompt-injection or secret-leakage paths are the highest priority.

## See also

- [Architecture](/reference/architecture) — the cryptographic design and storage internals behind this threat model.
- [MCP access policy](/mcp/access-policy) — how to constrain what an AI agent can reach.
- [The local agent](/guide/agent) — set up and operate the unix-socket agent.
- [Sharing](/guide/sharing) — recipients, identities, and true revocation.
