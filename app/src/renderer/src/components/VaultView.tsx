import { useCallback, useEffect, useState } from "react";

import type { BackupReport, BackupSnapshot } from "@shared/types";

import { fullTime, relTime, unwrap } from "../lib/api";
import { Badge, Button, EmptyState, Icon, IconButton, Modal, Spinner, useToast } from "./ui";

function humanBytes(n: number): string {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${n} B`;
}

/**
 * Vault-level operations that MCP deliberately does not expose: snapshots and
 * restore.
 *
 * Restore is the one genuinely dangerous action in this app — it replaces the
 * vault database — so the renderer never chooses a path freely. It can only ask
 * for one of the snapshots main listed, and main re-validates against that same
 * list before shelling out. The CLI then takes its own pre-restore safety
 * snapshot and refuses if that fails.
 *
 * Passphrase rotation is NOT here on purpose: a form would put the current and
 * the new passphrase into renderer state and across IPC, which is exactly what
 * the CLI's no-echo terminal prompt exists to avoid. The card below says so and
 * hands over the command instead.
 */
export default function VaultView({
  readOnly,
  onChanged
}: {
  readOnly: boolean;
  onChanged: () => void;
}): React.JSX.Element {
  const toast = useToast();
  const [snapshots, setSnapshots] = useState<BackupSnapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [backingUp, setBackingUp] = useState(false);
  const [lastBackup, setLastBackup] = useState<BackupReport | null>(null);
  const [restoreTarget, setRestoreTarget] = useState<BackupSnapshot | null>(null);
  const [restoring, setRestoring] = useState(false);
  const [restoreError, setRestoreError] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      setSnapshots(await unwrap(window.tvault.listBackups()));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const backupNow = async (): Promise<void> => {
    setBackingUp(true);
    try {
      const report = await unwrap(window.tvault.backup());
      setLastBackup(report);
      toast.success(
        "Snapshot written",
        `${report.path.split("/").pop()} · ${humanBytes(report.bytes)}${report.immutable ? " · immutable" : ""}`
      );
      await load();
    } catch (err) {
      toast.error("Backup failed", err instanceof Error ? err.message : String(err));
    } finally {
      setBackingUp(false);
    }
  };

  const runRestore = async (): Promise<void> => {
    if (!restoreTarget) return;
    setRestoring(true);
    setRestoreError(null);
    try {
      const report = await unwrap(window.tvault.restore(restoreTarget.path));
      toast.success(
        "Vault restored",
        report.saved_snapshot ? `Safety snapshot kept at ${report.saved_snapshot.split("/").pop()}` : undefined
      );
      setRestoreTarget(null);
      // The child caches a KEK derived from the database it opened; a restored
      // database may carry a different salt, so the session must be reborn
      // rather than reused.
      await unwrap(window.tvault.restartSession());
      await load();
      onChanged();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setRestoreError(message);
      toast.error("Restore failed", message);
    } finally {
      setRestoring(false);
    }
  };

  return (
    <div className="flex h-full min-w-0 flex-col">
      <header className="shrink-0 border-b border-line px-6 pb-4 pt-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-[17px] font-semibold tracking-[-0.01em] text-ink">Vault</h1>
            <p className="mt-1 max-w-2xl text-[12.5px] leading-relaxed text-muted">
              Snapshots and recovery. A snapshot is the encrypted database copied as opaque
              bytes — it is never opened or decrypted here, so listing and restoring cannot
              read a single value.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <IconButton icon="refresh" label="Reload snapshots" onClick={() => void load()} />
            {!readOnly ? (
              <Button size="sm" variant="primary" icon="save" disabled={backingUp} onClick={() => void backupNow()}>
                {backingUp ? "Writing…" : "Backup now"}
              </Button>
            ) : null}
          </div>
        </div>
        {lastBackup ? (
          <div className="mono mt-3 flex flex-wrap items-center gap-2 rounded-tv-sm border border-line bg-soft/60 px-3 py-2 text-[11.5px] text-muted">
            <span className="text-success">
              <Icon name="check" size={12} />
            </span>
            <span className="break-all text-ink">{lastBackup.path}</span>
            <Badge tone="neutral">{humanBytes(lastBackup.bytes)}</Badge>
            {lastBackup.compressed ? <Badge tone="neutral">gzip</Badge> : null}
            {lastBackup.immutable ? <Badge tone="accent">immutable</Badge> : null}
          </div>
        ) : null}
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto p-5">
        <div className="space-y-6">
          <section>
            <h2 className="mb-2.5 text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
              Snapshots
            </h2>
            {loading ? (
              <div className="flex h-24 items-center justify-center gap-2.5 text-muted">
                <Spinner /> <span className="text-[12.5px]">Listing snapshots…</span>
              </div>
            ) : error ? (
              <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
                {error}
              </p>
            ) : snapshots.length === 0 ? (
              <EmptyState
                icon="save"
                title="No snapshots yet"
                body="Backups land in backup.dir from config.yaml, or next to vault.db when it is unset. Rotation keeps the newest 30 by default."
                action={
                  !readOnly ? (
                    <Button variant="primary" icon="save" onClick={() => void backupNow()}>
                      Write the first one
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <ul className="space-y-1.5">
                {snapshots.map((s) => (
                  <li
                    key={s.path}
                    className="group flex items-center gap-3 rounded-tv-sm border border-line bg-raised px-3.5 py-2.5"
                  >
                    <span className="text-faint">
                      <Icon name="save" size={14} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="mono truncate text-[12px] text-ink">{s.name}</p>
                      <p className="mt-0.5 flex items-center gap-2 text-[11px] text-faint">
                        <span title={fullTime(s.created_at)}>{relTime(s.created_at)}</span>
                        <span>·</span>
                        <span>{humanBytes(s.bytes)}</span>
                        {s.compressed ? (
                          <>
                            <span>·</span>
                            <span>gzip</span>
                          </>
                        ) : null}
                        {s.dir !== undefined && snapshots.some((o) => o.dir !== s.dir) ? (
                          <>
                            <span>·</span>
                            <span className="truncate">{s.dir}</span>
                          </>
                        ) : null}
                      </p>
                    </div>
                    {!readOnly ? (
                      <Button
                        size="sm"
                        icon="rollback"
                        className="opacity-60 transition-opacity group-hover:opacity-100"
                        onClick={() => {
                          setRestoreError(null);
                          setRestoreTarget(s);
                        }}
                      >
                        Restore
                      </Button>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section>
            <h2 className="mb-2.5 text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
              Passphrase rotation
            </h2>
            <div className="rounded-tv-md border border-line bg-raised px-4 py-3.5">
              <p className="flex items-start gap-2.5 text-[12.5px] leading-relaxed text-muted">
                <span className="mt-0.5 shrink-0 text-accent">
                  <Icon name="lock" size={14} />
                </span>
                <span>
                  Rotating the passphrase stays in the terminal, deliberately. A form here would
                  put the current <em>and</em> the new passphrase into renderer state and across
                  the IPC bridge — the exact thing the CLI's no-echo prompt exists to avoid. Run
                  it yourself; the app picks the new passphrase up on its next session.
                </span>
              </p>
              <div className="mt-3 flex items-center gap-2">
                <code className="mono flex-1 overflow-x-auto rounded-tv-sm border border-line bg-console px-3 py-2 text-[12px] text-console-text">
                  tvault key rotate
                </code>
                <CopyCommandButton command="tvault key rotate" />
              </div>
            </div>
          </section>
        </div>
      </div>

      <Modal
        open={restoreTarget !== null}
        title="Restore this snapshot?"
        subtitle={restoreTarget?.name}
        onClose={() => setRestoreTarget(null)}
        width="max-w-md"
        footer={
          <>
            <Button variant="ghost" onClick={() => setRestoreTarget(null)} disabled={restoring}>
              Cancel
            </Button>
            <Button variant="danger" icon="rollback" disabled={restoring} onClick={() => void runRestore()}>
              {restoring ? "Restoring…" : "Restore vault"}
            </Button>
          </>
        }
      >
        <p className="text-[13px] leading-relaxed text-muted">
          The current database is replaced by this snapshot. Everything written after the
          snapshot was taken stops being current — though it stays recoverable from history if
          the snapshot predates none of it.
        </p>
        <p className="mt-3 flex items-start gap-2 rounded-tv-sm border border-success/30 bg-success/8 px-3 py-2.5 text-[12px] leading-relaxed text-muted">
          <span className="mt-0.5 text-success">
            <Icon name="shield" size={13} />
          </span>
          The CLI saves a pre-restore safety snapshot first and refuses to proceed if that
          fails, so this is reversible. The MCP session is restarted afterwards, because a
          restored database can carry a different key salt.
        </p>
        {restoreError ? (
          <p className="mono mt-3 rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
            {restoreError}
          </p>
        ) : null}
      </Modal>
    </div>
  );
}

function CopyCommandButton({ command }: { command: string }): React.JSX.Element {
  const toast = useToast();
  return (
    <IconButton
      icon="copy"
      label="Copy command"
      onClick={() => {
        // A command, not a secret: plain clipboard, no auto-clear timer needed.
        navigator.clipboard
          .writeText(command)
          .then(() => toast.success("Command copied"))
          .catch(() => toast.error("Copy failed"));
      }}
    />
  );
}
