---
title: Backups & Recovery
description: Take consistent, verified, encrypted snapshots of the vault, restore them safely, schedule rotation, and understand the safety snapshots that guard delete and restore.
---

# Backups & recovery

TinyVault is a **single bbolt file** (`~/.tvault/vault.db`). There is no server, no replication, and no hosted copy — if that one file is lost or corrupted, so is everything in it. This page covers `tvault backup`, `tvault restore`, the safety snapshots destructive commands take automatically, scheduling, and `tvault doctor`'s backup health check.

For rotation of the passphrase and DEKs, see [Key management](/guide/key-management). For the threat model behind these defaults, see [Security](/reference/security).

## Why a snapshot, not a file copy

Copying `vault.db` byte-for-byte while another `tvault` process might be writing to it risks capturing a half-written page — a torn copy that fails to open. `tvault backup` instead takes the snapshot **inside a bbolt read transaction** (`Tx.WriteTo`), so it always reflects one consistent, committed state, even if another `tvault` writes at the same moment.

The snapshot is written to a private temporary file in the destination directory, `fsync`'d, **verified** by opening it read-only and checking that TinyVault's core buckets are present, and only then renamed atomically into place at mode `0600`. A failed or interrupted backup never leaves a truncated file at the destination.

No unlock and no passphrase are needed to take a backup: secret payloads and per-project key material stay encrypted in the copy, exactly as they are in the live vault. The database's operational metadata — project and key names, timestamps, versions, and the audit log — remains readable in the backup, the same as in `vault.db` itself. Treat every backup as sensitive for that reason.

## Take a backup

```bash
# One snapshot at an explicit path (gzip-compressed if it ends in .gz)
tvault backup ~/backups/vault.db.bak
tvault backup ~/backups/vault-2026-09-23.db.gz

# Rotated, timestamped snapshots into a directory
tvault backup --dir ~/Backups/tvault --keep 30 --immutable

# Uses backup.dir / backup.keep / backup.immutable from config.yaml
tvault backup
```

| Flag | Description |
| --- | --- |
| `--dir <path>` | Directory for timestamped, rotated snapshots (default: `backup.dir` in `config.yaml`). |
| `--keep <N>` | Number of rotated snapshots to keep (default: `backup.keep`, else `30`). |
| `--immutable` | Mark snapshots immutable (macOS/BSD user flag) so `rm` cannot delete them. |

With an explicit `[path]` argument, `tvault backup` writes exactly one snapshot there. Without a path, it needs `--dir` (or `backup.dir` in `config.yaml`) and writes a compressed, timestamped snapshot named:

```text
vault-YYYYMMDD-HHMMSS.mmm[-reason].db.gz
```

into that directory, then **rotation** deletes the oldest snapshots beyond `--keep` / `backup.keep`. Rotation only ever touches files whose names match the exact pattern it writes (`vault-YYYYMMDD-HHMMSS.mmm[-reason].db[.gz]`), so a hand-made `vault-before-migration.db`, or anything else in that directory, is never removed.

::: tip The audit log usually dominates a vault's size
For a real vault, the audit log is typically the largest thing in `vault.db` and compresses roughly 10x — a 120 MiB vault can produce a ~9 MiB `.gz` snapshot even though the secrets themselves might total only ~170 KiB. A rotated snapshot may therefore be noticeably smaller than `vault.db`, and that is expected, not a sign of missing data.
:::

## Configuration

```yaml
# ~/.tvault/config.yaml
backup:
  dir: ~/Library/Application Support/tvault/backups
  keep: 30
  immutable: true
```

| Key | Type | Default | What it does |
| --- | --- | --- | --- |
| `backup.dir` | string | empty | Directory for rotated `tvault backup` snapshots. Setting it also makes `delete`, `projects delete`, `restore`, and the MCP delete tools take a [safety snapshot](#safety-snapshots-before-destructive-commands) first. |
| `backup.keep` | int | `30` | How many rotated snapshots survive pruning. |
| `backup.immutable` | bool | `false` | Mark rotated snapshots with the [macOS/BSD user-immutable flag](#immutability). |

Command-line flags (`--dir`, `--keep`, `--immutable`) override the corresponding `backup:` config values, same precedence as everywhere else in TinyVault.

::: warning `backup.dir` unset means nothing changes
If `backup.dir` is not configured, `delete`, `projects delete`, and `restore` behave exactly as before — no automatic snapshot is taken. Set `backup.dir` to opt into the safety-snapshot behavior below.
:::

## Immutability

`--immutable` / `backup.immutable: true` sets the macOS/BSD **user-immutable** flag (`chflags uchg`) on each rotated snapshot. While the flag is set, the file cannot be modified, renamed, or deleted by its owner either — a careless `rm -rf` on the backup directory fails with `Operation not permitted` instead of silently destroying your last good copy.

```bash
tvault backup --dir ~/Backups/tvault --immutable
chflags nouchg ~/Backups/tvault/vault-20260923-030000.000.db.gz   # clear it by hand
```

TinyVault clears the flag itself on the snapshots it rotates away, so `--keep` pruning still works — you never have to manually `chflags nouchg` a file that has aged out.

::: warning Immutability is unsupported on Linux and Windows
Linux's immutable attribute (`chattr +i`) needs `CAP_LINUX_IMMUTABLE`, which an unprivileged `tvault` process does not have, and Windows has no equivalent. On those platforms `--immutable` prints a warning to stderr and the snapshot is still written normally — the flag is best-effort, not a hard requirement.
:::

::: info What this flag is actually for
The immutable flag is a guard against **accidents and careless automation** — a script that does `rm -rf backups/`, a fat-fingered cleanup, a buggy retention job. It is **not** a defense against a process that deliberately clears the flag before deleting: anything running as the file's owner can run `chflags nouchg` first. Treat it as a safety rail, not a security boundary. See [Security](/reference/security) for the honest threat model behind TinyVault's other "guard, not control" features.
:::

## Safety snapshots before destructive commands

When `backup.dir` is configured, the following commands take a rotated snapshot **first**, tagged with a reason, and are **refused** — leaving nothing changed — if that snapshot fails to write:

| Command | Reason tag |
| --- | --- |
| `tvault delete` | `pre-delete` |
| `tvault projects delete` | `pre-delete-project` |
| `tvault restore` | `pre-restore` |
| MCP `vault_delete_secret` | `pre-delete` |
| MCP `vault_delete_project` | `pre-delete-project` |

```bash
tvault delete API_KEY
# tvault: safety snapshot: /Users/you/Backups/tvault/vault-20260923-141207.512-pre-delete.db.gz
# ✔ Secret 'API_KEY' deleted
```

Deleting a secret also purges its version history — `history`/`rollback` cannot bring it back — so the pre-delete snapshot is the only way to recover a deleted key's value if you decide afterward that you still need it. Similarly, `tvault projects delete` removes every secret in that project.

The `tvault mcp` server installs the same hook (`SetBeforeDestructive`), so an AI agent deleting a secret or a project through `vault_delete_secret` / `vault_delete_project` gets an identical safety snapshot when `backup.dir` is configured — this does not widen what the agent can do, it only makes the destructive action recoverable.

::: danger A failed safety snapshot blocks the operation
If `backup.dir` points at a directory that can't be written to (permissions, a full disk, a missing parent), the destructive command fails with an error naming the problem and **nothing is deleted or overwritten**. Fix `backup.dir`, or remove it from `config.yaml` to go back to unguarded deletes, and try again.
:::

## Restore the vault

```bash
tvault restore ~/backups/vault.db.bak
tvault restore ~/backups/vault-20260923-030000.000.db.gz -y   # skip the confirmation prompt
```

| Flag | Description |
| --- | --- |
| `-y`, `--yes` | Skip the confirmation prompt. |

`tvault restore <file>` accepts either a plain or a gzip-compressed snapshot — the format is detected from the file's magic bytes, not its name, so a `.db.gz` you renamed to `.db` still works. The sequence is:

1. **Stage and verify first.** The backup is decompressed (if needed) into a temporary file next to `vault.db` and verified as a real TinyVault database. Decompression stops at 8 GiB, so a crafted `.gz` cannot fill the disk. Nothing about the current vault is touched yet, so a corrupt or unrelated file is rejected before it can do any damage.
2. **Save the current vault.** If a `vault.db` already exists, it is snapshotted first — into `backup.dir` (tagged `pre-restore`) when configured, otherwise next to `vault.db` as `vault.db.pre-restore-<timestamp>` (millisecond resolution; these fallback copies are not rotated, so delete old ones yourself). `tvault restore` reports the path it used.
3. **Atomic swap.** The staged, verified file is renamed over `vault.db` while the old vault stays locked (on Windows, which cannot rename over an open file, the lock is released just before the swap).

```bash
tvault restore ~/backups/vault-20260601.db.gz
# This will replace the current vault database (a snapshot of it is kept first).
# Restore from backup? [y/N] y
# Current vault saved to /Users/you/Backups/tvault/vault-20260923-141900.221-pre-restore.db.gz
# ✔ Vault restored from /Users/you/backups/vault-20260601.db.gz
```

After restoring, the vault uses whichever passphrase was in effect when *that backup* was taken — restoring does not change which passphrase unlocks it.

::: tip Restoring into a fresh vault
Use `--vault <dir>` to restore into an alternate location before promoting it, instead of overwriting your live `~/.tvault`:

```bash
tvault --vault /tmp/tvault-check restore ~/backups/vault-20260601.db.gz -y
tvault --vault /tmp/tvault-check doctor
```
:::

## Scheduling

TinyVault has no built-in scheduler — `tvault backup` needs no passphrase to run, so the scheduling job holds no secret, and you can drive it from whatever job runner you already trust.

### macOS: launchd

Create `~/Library/LaunchAgents/dev.tinyvault.backup.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.tinyvault.backup</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/tvault</string>
    <string>backup</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>3</integer>
    <key>Minute</key>
    <integer>0</integer>
  </dict>
  <key>RunAtLoad</key>
  <false/>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/.local/state/tvault/backup.err.log</string>
</dict>
</plist>
```

```bash
mkdir -p ~/.local/state/tvault
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.tinyvault.backup.plist
launchctl kickstart gui/$(id -u)/dev.tinyvault.backup   # run it once now, to confirm
```

Use the absolute path to `tvault` (`command -v tvault`) — launchd jobs start with a minimal `PATH`, the same caveat that applies to `tvault agent install` (see [Local agent](/guide/agent#installing-as-a-persistent-service)).

### Linux: systemd (user timer)

`~/.config/systemd/user/tvault-backup.service`:

```ini
[Unit]
Description=TinyVault backup

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tvault backup
```

`~/.config/systemd/user/tvault-backup.timer`:

```ini
[Unit]
Description=Daily TinyVault backup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now tvault-backup.timer
systemctl --user list-timers tvault-backup.timer
```

`Persistent=true` catches up a missed run (laptop asleep at 03:00) the next time the user session is active.

::: tip Copy backups off the machine
A backup on the same disk as `vault.db` does not survive disk loss or theft. Point `backup.dir` at (or additionally sync it to) a location off the machine — a synced folder, an external disk, or your own off-site storage. Remember that a synced or off-site copy still carries readable metadata (project/key names, audit entries), so protect its access the same way you would `~/.tvault/` itself.
:::

## `tvault doctor`'s backup check

`tvault doctor` includes a **backups** check that reports, without ever unlocking the vault:

| Status | When |
| --- | --- |
| `WARN` | `backup.dir` is not configured. |
| `WARN` | `backup.dir` is configured but has no snapshots yet. |
| `WARN` | The newest snapshot is older than 7 days — is the scheduled backup running? |
| `OK` | At least one snapshot exists and the newest is 7 days old or newer; reports the count and age. |

```bash
tvault doctor
# ✔  backups           3 snapshot(s) in /Users/you/Backups/tvault, newest 4h12m0s ago
```

Wire this into your scheduling job so a silently broken schedule surfaces as a doctor warning instead of an empty backup directory discovered during an incident:

```bash
tvault backup && tvault doctor
```

## Threat notes

- **Metadata is readable in every backup, including immutable ones.** Project names, key names, timestamps, versions, and the audit log are not encrypted — only secret values and key material are. Treat a backup file with the same care you'd give `~/.tvault/vault.db` itself; see [Security](/reference/security).
- **The passphrase (or a matching recipient identity) is still required to read values out of a restored vault.** A backup does not weaken encryption — decrypting it needs the same credential the live vault needed.
- **`--immutable` stops accidents, not attackers.** See [Immutability](#immutability) above — it is explicitly a "guard, not a control," in the same spirit as [MCP output redaction](/reference/security#the-mcp-safety-model) and [capability tokens](/reference/security#token-honesty).
- **Safety snapshots make destructive commands recoverable, not confirmation-optional.** `delete`/`projects delete` still prompt (unless `-y`) and `restore` still prompts (unless `-y`); the snapshot is an additional safety net under that confirmation, not a replacement for it.

## See also

- [Key management](/guide/key-management) — rotate the passphrase and understand the key hierarchy.
- [Configuration](/reference/configuration) — the full `config.yaml` schema and file layout.
- [Troubleshooting](/reference/troubleshooting) — fixes for a refused delete or an `Operation not permitted` on an immutable snapshot.
- [Security](/reference/security) — the full threat model, including what "guard, not control" means across TinyVault.
- [Local agent](/guide/agent) — the same launchd/systemd pattern used for `tvault agent install`.
