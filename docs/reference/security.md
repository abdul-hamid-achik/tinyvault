---
title: Security & Threat Model
description: TinyVault's honest threat model — what local-first encryption, the MCP redaction layer, and the unix agent protect against, and the residual risks they do not.
---

# Security & Threat Model

This is the honest security page. TinyVault is a single binary (written in Go) that encrypts secret payloads at rest, offers value-minimizing tools for AI agents, and can serve reads over a tightly confined local socket. None of those layers is magic. This page tells you exactly what each one stops and what it does not.

Read this before you trust TinyVault with anything that matters. The short version: it protects secret values at rest with strong cryptography and supports agent workflows that do not return those values, but it has no recovery story, no team sync, and it cannot defend a running, unlocked process from another process running as the same user.

## The model at a glance

- The vault is a single bbolt file (`~/.tvault/vault.db`, mode `0600`, in a `0700` directory). Secret values and key material are encrypted; project names, key names, timestamps, versions, configuration, and audit metadata are readable.
- The root wrapping key (the KEK) is derived from your passphrase with Argon2id and only ever lives in RAM while a process has the vault unlocked. It wraps per-project DEKs and the verifier; it does not encrypt the database as one opaque blob.
- There is no TinyVault account or hosted vault backend. Normal vault operations stay local, but exports, backups, recipient-sealed artifacts, `self-update`, and launched subprocesses can cross disk or network boundaries when you invoke them.
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

- **Someone reads `vault.db` at rest.** Every value is AES-256-GCM encrypted under a per-project DEK, and each DEK is wrapped by the KEK. Without the passphrase (or a matching recipient identity), the secret payloads are unreadable. Names and operational metadata are not encrypted and may still be sensitive.
- **Someone brute-forces your passphrase.** Argon2id at 64 MiB / 3 / 4 makes each guess roughly 200 ms and memory-bound, which is hostile to GPU and ASIC cracking.
- **The vault file is tampered with.** Every value, DEK, and the verifier carries an AES-GCM authentication tag. Any modification fails authentication and is rejected with a decryption error rather than silently returning corrupt data.
- **An AI agent accidentally pulls a secret into its prompt or logs.** The MCP layer offers workflows that do not intentionally return values: `vault_run_with_secrets` injects selected values into a subprocess, `vault_export_env` writes to disk and returns a path, `vault_generate_secret` returns generation metadata but not the generated value, and `vault_seal_for_recipients` returns ciphertext. `vault_get_secret` deliberately returns a raw value, `vault_set_secret` accepts one from the client, and subprocesses can leak or transform what they receive; policy is the real control.
- **An AI agent escapes its allow-list through normal tool handlers.** An [access policy](/mcp/access-policy) (`~/.tvault/mcp-policy.yaml`) gates projects and secret keys with glob allow/deny lists, and `access_mode` controls whether writes and command execution are permitted. The in-memory policy is loaded once and has no mutation tool. If command execution is enabled, however, the launched shell can modify any file the server user can write — including the policy file used on a future restart.
- **A removed recipient tries to read the updated live vault.** `tvault projects unshare` atomically rotates the project DEK, re-encrypts every current value and archived version, and re-wraps the new DEK to the remaining recipients. The removed identity cannot decrypt that updated state or future writes under the new DEK. See [Sharing](/guide/sharing).
- **A different-uid process reaches the agent socket.** The agent performs a mandatory peer-credential check before token validation and rejects any peer whose uid does not match its own. For accepted same-uid clients, `--require-token` adds a second bearer-token gate and can scope a token to one project.
- **A malicious dotenv file is imported.** The parser does no shell, variable, or command expansion; it enforces a filename allowlist, skips symlinks, and caps files at 1 MiB. Importing a `.env` cannot execute a payload embedded in it. See [Dotenv files](/guide/dotenv).

## Threat model: out of scope

These are explicit non-goals. They are not bugs — they are the accepted residual risk of a local-first, single-passphrase design. Plan around them.

::: danger No passphrase recovery
There is no escrow, recovery key, or social recovery for the owner KEK. If you forget the passphrase, you cannot recover the complete owner view of the vault. A private recipient identity created beforehand may still read only the projects shared to it. Back up the passphrase as a root credential, keep an offline copy of the vault file, and preserve any identities your recovery plan relies on.
:::

::: danger A malicious same-uid process is the trust boundary
Any process running as **your user** can read your secrets when the agent is unlocked, or unlock the vault itself if it can prompt for or capture your passphrase. Capability tokens do **not** change this — a same-uid process can read the token file, the environment, or dial the socket directly. If you do not trust code running as your own user, do not run it on a machine where your vault is unlocked.
:::

::: danger Recipient removal cannot invalidate retained data
A vault snapshot copied before `tvault projects unshare` still contains the old ciphertext and the removed recipient's DEK wrap, so it remains readable. The operation also cannot retract plaintext already decrypted or update previously exported or sealed artifacts. Rotate the underlying credentials, then re-seal and redeploy distributed artifacts when access must be withdrawn completely.
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

The [MCP server](/mcp/) is the most security-sensitive surface, because it hands tools to an AI agent. Its core principle is value minimization: prefer destination-shaped operations over returning stored secrets as dedicated plaintext fields.

The server is a thin policy-and-redaction layer over the same vault API the CLI uses. Most value-touching tools avoid a dedicated plaintext result, with command output as the important exception:

| Tool | What it returns to the model |
|------|------------------------------|
| `vault_run_with_secrets` | exit status and command output — literal-value redaction applies only when policy enables it |
| `vault_export_env` | a file path on disk, not the contents |
| `vault_generate_secret` | key, length, charset, and `stored: true` — never the generated value |
| `vault_seal_for_recipients` | ciphertext (a sealed `.env.encrypted` blob) |
| `vault_get_secret` | the raw value — **plus a warning** that it is now in context |

`vault_get_secret` is the single tool that deliberately returns a stored secret in a dedicated plaintext field, gated by `max_reads_per_session`. `vault_run_with_secrets` can still carry raw, short, or transformed values back through arbitrary child-process output, especially when redaction is disabled; the warning below is the controlling caveat.

Explicit MCP handlers for `secret.read`, `secret.write`, `secret.delete`, `secret.generate`, `secret.exec`, `secret.export`, `project.create`, and `project.delete` write to the audit log, which is queryable over MCP via `vault_audit_log`. The trail is not exhaustive: unlocking, passphrase rotation, direct passphrase-based `tvault env`, and some value comparisons are not recorded.

::: warning Redaction is a safety net, not a control
When policy enables `redact_output`, `vault_run_with_secrets` post-processes subprocess output and replaces literal occurrences of secret values longer than 3 characters with `[REDACTED:KEY]`. This can catch accidental leakage to stdout/stderr. It does **not** stop:

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

For genuinely untrusted delegation — CI runners, containers, another person — use a scoped **identity** instead of a token. An identity is cryptographic and transport-agnostic, and its access to the updated live vault can be removed atomically via DEK re-key. Pre-removal snapshots and artifacts remain readable, so rotate underlying credentials after a compromise. See [Sharing](/guide/sharing) and [CI/CD](/guide/ci-cd).

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

## Where TinyVault fits

TinyVault is a local developer tool, not an enterprise control plane. It fits
when one developer or machine needs encrypted-at-rest values, process injection,
recipient-sealed artifacts, and an agent tool surface without operating a
hosted vault backend.

Choose a production secrets platform instead when you need organization-wide
team sync, centralized RBAC or SSO, account recovery, high availability,
dynamic credentials, audit export pipelines, HSMs, or cloud KMS. Product
feature matrices age quickly; the durable distinction is the operating model:
TinyVault is deliberately local and single-user.

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
  3) echo "locked — run in a TTY, set TVAULT_PASSPHRASE, or start the local agent" ;;
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
- [Sharing](/guide/sharing) — recipients, identities, live-vault re-keying, and retained-data limits.
