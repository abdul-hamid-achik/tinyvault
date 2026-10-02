import { useEffect, useRef, useState, type ReactNode } from "react";

import type {
  DotenvDiagnostic,
  EnvFileDiff,
  EnvFileList,
  EnvImportPreview,
  EnvImportRequest,
  EnvImportResult,
  EnvSyncResult,
  ExportEncryptedResult,
  ExportEnvResult,
  SyncDirection
} from "@shared/types";

import { unwrap } from "../lib/api";
import {
  Badge,
  Button,
  EmptyState,
  Field,
  Icon,
  IconButton,
  Modal,
  Spinner,
  TextInput,
  useToast,
  type IconName
} from "./ui";

type ExportFormat = "dotenv" | "json" | "shell";
type Busy = "scan" | "preview" | "import" | "diff" | "sync" | "export" | null;
type Confirm = "sync" | "plain" | "sealed" | null;

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Absolute path → file name. Paths only ever arrive from a dialog or a scan. */
function baseName(path: string): string {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return cut === -1 ? path : path.slice(cut + 1);
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

const ACTION_TONE: Record<string, "success" | "warn" | "neutral"> = {
  create: "success",
  overwrite: "warn",
  skip: "neutral"
};

const VERDICT_TONE: Record<string, "success" | "warn" | "danger"> = {
  same: "success",
  differs: "warn",
  error: "danger"
};

const DIRECTIONS: Array<{ id: SyncDirection; says: string }> = [
  { id: "pull", says: "Rewrites the chosen file from the vault. The vault is not touched." },
  { id: "push", says: "Writes the file's keys into the vault. The file is not touched." },
  { id: "mirror", says: "Both ways. Keys that disagree are reported as conflicts, not guessed at." }
];

/**
 * The `.env` workflow: discover, import, compare, sync, export.
 *
 * No value is reachable: discovery reports key counts, import reports key names
 * and an action per key, diff reports same/differs/error, sync reports key-name
 * lists, export reports a path and a count. There is no reveal affordance here
 * to guard, because none of these tools could feed one.
 *
 * No path is authored: every path in this component's state came from
 * `pickDirectory` / `pickSaveFile` / `pickEnvFile` or from a `listEnvFiles`
 * result, and main refuses anything it did not issue. That is why the folder and
 * file controls are buttons that open dialogs, and why the only free-text field
 * on the screen is an environment *name*.
 */
export default function DotEnvView({
  readOnly,
  projects,
  defaultProject,
  onChanged
}: {
  readOnly: boolean;
  projects: string[];
  defaultProject: string | null;
  onChanged: () => void;
}): React.JSX.Element {
  const toast = useToast();

  const [project, setProject] = useState(defaultProject ?? projects[0] ?? "");
  const [directory, setDirectory] = useState<string | null>(null);
  const [environment, setEnvironment] = useState("");
  const [listing, setListing] = useState<EnvFileList | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [overwrite, setOverwrite] = useState(false);
  const [preview, setPreview] = useState<EnvImportPreview | null>(null);
  const [imported, setImported] = useState<EnvImportResult | null>(null);

  const [target, setTarget] = useState<string | null>(null);
  const [compareValues, setCompareValues] = useState(false);
  const [diff, setDiff] = useState<EnvFileDiff | null>(null);
  const [direction, setDirection] = useState<SyncDirection>("pull");
  const [syncOverwrite, setSyncOverwrite] = useState(false);
  const [synced, setSynced] = useState<EnvSyncResult | null>(null);

  const [format, setFormat] = useState<ExportFormat>("dotenv");
  const [plainPath, setPlainPath] = useState<string | null>(null);
  const [sealedPath, setSealedPath] = useState<string | null>(null);
  const [exported, setExported] = useState<string | null>(null);

  const [busy, setBusy] = useState<Busy>(null);
  const [confirm, setConfirm] = useState<Confirm>(null);

  // Keep the selection valid if the project list arrives after first render.
  useEffect(() => {
    if (!project && (defaultProject || projects[0])) setProject(defaultProject ?? projects[0] ?? "");
  }, [project, defaultProject, projects]);

  /**
   * Generation guard, same hazard as `secretsGen` in App.tsx: switch folder or
   * project while a call is in flight and the slower response would otherwise
   * paint the old context's keys under the new one. Every async result carries
   * the generation it started at and is dropped if the counter has moved.
   */
  const gen = useRef(0);

  /** Context changed: nothing derived from the previous one may survive. */
  const invalidate = (): void => {
    gen.current += 1;
    // The dropped call's `finally` will not clear this (its generation no longer
    // matches), so release the lock here or every button stays disabled.
    setBusy(null);
    setPreview(null);
    setImported(null);
    setDiff(null);
    setSynced(null);
    setExported(null);
    setScanError(null);
  };

  const scan = async (dir: string, env: string): Promise<void> => {
    const mine = ++gen.current;
    setBusy("scan");
    setScanError(null);
    try {
      const list = await unwrap(window.tvault.listEnvFiles(dir, env.trim() || undefined));
      if (mine !== gen.current) return;
      setListing(list);
    } catch (err) {
      if (mine !== gen.current) return;
      setListing(null);
      setScanError(message(err));
    } finally {
      if (mine === gen.current) setBusy(null);
    }
  };

  const chooseFolder = async (): Promise<void> => {
    try {
      const dir = await unwrap(window.tvault.pickDirectory("Choose the folder holding your .env files"));
      if (!dir) return; // cancelled
      invalidate();
      setDirectory(dir);
      setListing(null);
      setSelected([]);
      setTarget(null);
      await scan(dir, environment);
    } catch (err) {
      toast.error("Folder picker failed", message(err));
    }
  };

  const chooseFile = async (): Promise<void> => {
    try {
      const path = await unwrap(window.tvault.pickEnvFile("Choose a dotenv file to compare"));
      if (!path) return;
      setTarget(path);
      setDiff(null);
      setSynced(null);
    } catch (err) {
      toast.error("File picker failed", message(err));
    }
  };

  const importRequest = (): EnvImportRequest => ({
    project,
    directory: directory ?? undefined,
    // Nothing ticked means "the chain the server suggests for this environment";
    // an explicit list is validated against the folder before it is read.
    files: selected.length > 0 ? selected : undefined,
    environment: environment.trim() || undefined,
    overwrite
  });

  const runPreview = async (): Promise<void> => {
    if (!directory) return;
    const mine = ++gen.current;
    setBusy("preview");
    setImported(null);
    try {
      const res = await unwrap(window.tvault.previewEnvImport(importRequest()));
      if (mine !== gen.current) return;
      setPreview(res);
      if (res.blocked_count > 0) {
        toast.push(
          "warn",
          `${plural(res.blocked_count, "key")} blocked by policy`,
          "Listed in the preview; they will not be imported."
        );
      }
    } catch (err) {
      if (mine !== gen.current) return;
      setPreview(null);
      toast.error("Preview failed", message(err));
    } finally {
      if (mine === gen.current) setBusy(null);
    }
  };

  const runImport = async (): Promise<void> => {
    // Guarded twice: the button is disabled without a preview, and this bails.
    if (!preview || !directory) return;
    const mine = ++gen.current;
    setBusy("import");
    try {
      const res = await unwrap(window.tvault.importEnvFiles(importRequest()));
      if (mine !== gen.current) return;
      setImported(res);
      setDiff(null); // the vault just changed; any comparison is stale
      setPreview(null); // the next import needs a plan of its own
      toast.success(
        `Imported ${plural(res.create_count + res.overwrite_count, "key")} into ${res.project}`,
        res.skip_count > 0 ? `${plural(res.skip_count, "key")} skipped` : undefined
      );
      onChanged();
    } catch (err) {
      if (mine !== gen.current) return;
      toast.error("Import failed", message(err));
    } finally {
      if (mine === gen.current) setBusy(null);
    }
  };

  const runDiff = async (): Promise<void> => {
    if (!target || !project) return;
    const mine = ++gen.current;
    setBusy("diff");
    setDiff(null);
    try {
      const res = await unwrap(window.tvault.diffEnv(target, project, compareValues));
      if (mine !== gen.current) return;
      setDiff(res);
    } catch (err) {
      if (mine !== gen.current) return;
      toast.error("Compare failed", message(err));
    } finally {
      if (mine === gen.current) setBusy(null);
    }
  };

  const runSync = async (): Promise<void> => {
    if (!target || !project) return;
    const mine = ++gen.current;
    setBusy("sync");
    setConfirm(null);
    try {
      const res = await unwrap(
        window.tvault.syncEnv({ direction, path: target, project, overwrite: syncOverwrite })
      );
      if (mine !== gen.current) return;
      setSynced(res);
      setDiff(null);
      toast.success(
        `Sync ${res.direction} finished`,
        `${plural(res.created.length, "created")} · ${plural(res.updated.length, "updated")} · ${plural(res.conflicts.length, "conflict")}`
      );
      // pull only rewrites the file; push and mirror wrote to the vault.
      if (direction !== "pull") onChanged();
    } catch (err) {
      if (mine !== gen.current) return;
      toast.error("Sync failed", message(err));
    } finally {
      if (mine === gen.current) setBusy(null);
    }
  };

  const chooseExportPath = async (kind: "plain" | "sealed"): Promise<void> => {
    const plain = kind === "plain";
    const name = format === "json" ? "secrets.json" : format === "shell" ? "secrets.sh" : ".env";
    try {
      const path = await unwrap(
        window.tvault.pickSaveFile(
          plain ? "Where should the PLAINTEXT export be written?" : "Where should the sealed file go?",
          plain ? name : ".env.encrypted"
        )
      );
      if (!path) return;
      if (plain) setPlainPath(path);
      else setSealedPath(path);
      setExported(null);
    } catch (err) {
      toast.error("Save dialog failed", message(err));
    }
  };

  const runExport = async (kind: "plain" | "sealed"): Promise<void> => {
    const path = kind === "plain" ? plainPath : sealedPath;
    if (!path || !project) return;
    const mine = ++gen.current;
    setBusy("export");
    setConfirm(null);
    try {
      if (kind === "plain") {
        const res: ExportEnvResult = await unwrap(
          window.tvault.exportEnv({ project, format, outputPath: path })
        );
        if (mine !== gen.current) return;
        setExported(`Plaintext ${format}: ${plural(res.count, "key")} written to ${res.path}, mode 0600.`);
        toast.success("Plaintext export written", `${plural(res.count, "key")} · ${res.path}`);
      } else {
        const res: ExportEncryptedResult = await unwrap(
          window.tvault.exportEnvEncrypted({ project, outputPath: path })
        );
        if (mine !== gen.current) return;
        setExported(
          `Sealed: ${plural(res.count, "key")} to ${plural(res.recipient_count, "recipient")} at ${res.path ?? baseName(path)}.`
        );
        toast.success("Commit-safe export written", `${plural(res.count, "key")} · ciphertext only`);
      }
    } catch (err) {
      if (mine !== gen.current) return;
      toast.error(kind === "plain" ? "Export failed" : "Sealing failed", message(err));
    } finally {
      if (mine === gen.current) setBusy(null);
    }
  };

  const toggleSelected = (path: string): void => {
    setPreview(null); // the plan describes a specific file set
    setSelected((prev) => (prev.includes(path) ? prev.filter((p) => p !== path) : [...prev, path]));
  };

  const files = listing?.files ?? [];
  const busyNow = busy !== null;
  const env = environment.trim();

  return (
    <div className="flex h-full min-w-0 flex-col">
      <header className="shrink-0 border-b border-line px-6 pb-4 pt-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-[17px] font-semibold tracking-[-0.01em] text-ink">.env workflow</h1>
            <p className="mt-1 max-w-2xl text-[12.5px] leading-relaxed text-muted">
              Discover the dotenv files in a folder, import them, find drift against a project,
              reconcile, export. No step returns a value: previews report key names and actions,
              comparisons report <span className="mono">same</span>/<span className="mono">differs</span>,
              exports report a path and a count.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <select
              value={project}
              aria-label="Project"
              onChange={(e) => {
                invalidate();
                setProject(e.target.value);
              }}
              className="mono h-8 max-w-[200px] rounded-tv-sm border border-line bg-raised px-2 text-[12.5px] text-ink focus:border-accent focus:outline-none"
            >
              {projects.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
            {readOnly ? <Badge tone="warn">read-only</Badge> : null}
          </div>
        </div>
      </header>

      {projects.length === 0 ? (
        <EmptyState
          icon="folder"
          title="No project to work against"
          body="Every dotenv operation lands in a project, which is what gives it an encryption key. Create one from the Secrets screen, then come back."
        />
      ) : (
        <div className="min-h-0 flex-1 overflow-y-auto p-5">
          <div className="space-y-5">
            <Section
              icon="folder"
              title="Folder"
              note={directory ?? undefined}
              aside={
                <>
                  {directory ? (
                    <IconButton
                      icon="refresh"
                      label="Rescan this folder"
                      disabled={busyNow}
                      onClick={() => void scan(directory, environment)}
                    />
                  ) : null}
                  <Button size="sm" icon="folder" disabled={busyNow} onClick={() => void chooseFolder()}>
                    {directory ? "Change folder…" : "Choose folder…"}
                  </Button>
                </>
              }
            >
              <div className="mb-3 max-w-xs">
                <Field label="Environment" hint="Names the chain the server suggests: .env, .env.local, .env.<env>, .env.<env>.local. Rescan after changing it.">
                  <TextInput
                    mono
                    value={environment}
                    spellCheck={false}
                    autoComplete="off"
                    placeholder="production"
                    onChange={(e) => {
                      setEnvironment(e.target.value);
                      setPreview(null); // the suggested chain depends on it
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && directory) void scan(directory, environment);
                    }}
                  />
                </Field>
              </div>

              {!directory ? (
                <EmptyState
                  icon="folder"
                  title="No folder chosen yet"
                  body="Start with the picker above. Every path in this window comes from an OS dialog or from scanning the folder you chose — never from a typed string, because main refuses any path it did not issue. That is what stops a dotenv tool from becoming an arbitrary file read or write."
                  action={
                    <Button variant="primary" icon="folder" disabled={busyNow} onClick={() => void chooseFolder()}>
                      Choose a folder…
                    </Button>
                  }
                />
              ) : busy === "scan" ? (
                <div className="flex h-24 items-center justify-center gap-2.5 text-muted">
                  <Spinner /> <span className="text-[12.5px]">Scanning for dotenv files…</span>
                </div>
              ) : scanError ? (
                <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
                  {scanError}
                </p>
              ) : files.length === 0 ? (
                <EmptyState
                  icon="search"
                  title="No dotenv files in this folder"
                  body="Only the allowlist is discovered — .env, .env.local, .env.<env>, .env.<env>.local — one level deep, regular files. Anything else is skipped by the parser itself, not by this window."
                />
              ) : (
                <ul className="space-y-1.5">
                  {files.map((f) => (
                    <li key={f.path} className="flex items-center gap-3 rounded-tv-sm border border-line bg-raised px-3.5 py-2">
                      <input
                        type="checkbox"
                        checked={selected.includes(f.path)}
                        disabled={readOnly}
                        onChange={() => toggleSelected(f.path)}
                        aria-label={`Include ${baseName(f.path)} in the import`}
                        className="accent-[var(--tv-accent)]"
                      />
                      <span className="mono min-w-0 truncate text-[12.5px] text-ink">{baseName(f.path)}</span>
                      {f.suggested ? <Badge tone="accent">suggested</Badge> : null}
                      <Badge tone="neutral">{plural(f.key_count, "key")}</Badge>
                      {f.diagnostic_count > 0 ? <Badge tone="warn">{plural(f.diagnostic_count, "note")}</Badge> : null}
                      <span className="flex-1" />
                      <IconButton
                        icon="diff"
                        tone={target === f.path ? "accent" : "muted"}
                        label={target === f.path ? "Chosen for compare and sync" : `Compare and sync ${baseName(f.path)}`}
                        onClick={() => {
                          setTarget(f.path);
                          setDiff(null);
                          setSynced(null);
                        }}
                      />
                    </li>
                  ))}
                </ul>
              )}
            </Section>

            <Section
              icon="plus"
              title={`Import into ${project}`}
              note={directory ? (selected.length > 0 ? `${plural(selected.length, "file")} ticked` : `suggested chain${env ? ` for ${env}` : ""}`) : undefined}
              aside={
                !readOnly ? (
                  <>
                    <Button size="sm" icon="eye" disabled={busyNow || !directory} onClick={() => void runPreview()}>
                      {busy === "preview" ? "Reading…" : "Preview"}
                    </Button>
                    <Button size="sm" variant="primary" icon="plus" disabled={busyNow || !preview} onClick={() => void runImport()}>
                      {busy === "import" ? "Importing…" : "Import"}
                    </Button>
                  </>
                ) : (
                  <Badge tone="warn">import disabled</Badge>
                )
              }
            >
              {!directory ? (
                <p className="text-[12.5px] text-faint">Choose a folder to import from.</p>
              ) : (
                <div className="space-y-3">
                  <label className="flex cursor-pointer items-start gap-2 text-[12.5px] text-muted">
                    <input
                      type="checkbox"
                      checked={overwrite}
                      disabled={readOnly}
                      onChange={(e) => {
                        setOverwrite(e.target.checked);
                        setPreview(null);
                      }}
                      className="mt-0.5 accent-[var(--tv-accent)]"
                    />
                    <span>
                      Overwrite keys that already exist in {project}
                      <span className="block text-[11.5px] text-faint">
                        Off by default: an existing key is skipped and listed, never silently
                        replaced. Either way an imported key becomes a version, so it is reversible.
                      </span>
                    </span>
                  </label>

                  {readOnly ? (
                    <ReadOnlyNote what="Importing" />
                  ) : !preview && !imported ? (
                    <p className="text-[12.5px] leading-relaxed text-faint">
                      Preview first: Import stays disabled until the per-key plan for these files has
                      been shown in this session.
                    </p>
                  ) : null}

                  {preview ? <PreviewBody preview={preview} /> : null}
                  {imported ? <ImportBody result={imported} /> : null}
                </div>
              )}
            </Section>

            <Section
              icon="diff"
              title="Compare and sync"
              note={target ? baseName(target) : undefined}
              aside={
                <Button size="sm" icon="diff" disabled={busyNow || !target} onClick={() => void runDiff()}>
                  {busy === "diff" ? "Comparing…" : "Compare"}
                </Button>
              }
            >
              {!target ? (
                <div className="space-y-2">
                  <p className="text-[12.5px] leading-relaxed text-muted">
                    Mark a discovered file with the compare icon, or choose one directly. The path
                    comes from a picker — this window cannot type one.
                  </p>
                  <Button size="sm" icon="folder" disabled={busyNow} onClick={() => void chooseFile()}>
                    Choose a .env file…
                  </Button>
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="mono min-w-0 flex-1 truncate text-[12px] text-ink">{target}</span>
                    <IconButton icon="x" label="Clear this file" onClick={() => setTarget(null)} />
                    <Button size="sm" icon="folder" disabled={busyNow} onClick={() => void chooseFile()}>
                      Different file…
                    </Button>
                  </div>

                  <label className="flex cursor-pointer items-start gap-2 text-[12.5px] text-muted">
                    <input
                      type="checkbox"
                      checked={compareValues}
                      onChange={(e) => {
                        setCompareValues(e.target.checked);
                        setDiff(null);
                      }}
                      className="mt-0.5 accent-[var(--tv-accent)]"
                    />
                    <span>
                      Also compare values
                      <span className="block text-[11.5px] text-faint">
                        Returns a verdict per shared key — same, differs or error. The values stay in
                        the vault and the file; neither is sent here.
                      </span>
                    </span>
                  </label>

                  {diff ? <DiffBody diff={diff} /> : null}

                  {readOnly ? (
                    <ReadOnlyNote what="Syncing" />
                  ) : (
                    <div className="rounded-tv-sm border border-line bg-soft/50 p-3">
                      <div className="flex flex-wrap items-center gap-1.5">
                        {DIRECTIONS.map((d) => (
                          <button
                            key={d.id}
                            onClick={() => {
                              setDirection(d.id);
                              setSynced(null);
                            }}
                            className={`mono h-7 rounded-tv-sm border px-2.5 text-[12px] transition-colors ${
                              direction === d.id
                                ? "border-accent-line bg-accent-soft text-accent"
                                : "border-line bg-raised text-faint hover:text-ink"
                            }`}
                          >
                            {d.id}
                          </button>
                        ))}
                        <span className="flex-1" />
                        <Button size="sm" variant="danger" icon="refresh" disabled={busyNow} onClick={() => setConfirm("sync")}>
                          Sync {direction}…
                        </Button>
                      </div>
                      <p className="mt-2 text-[12px] leading-relaxed text-muted">
                        {DIRECTIONS.find((d) => d.id === direction)?.says}
                      </p>
                      <label className="mt-2 flex cursor-pointer items-center gap-2 text-[12px] text-muted">
                        <input
                          type="checkbox"
                          checked={syncOverwrite}
                          onChange={(e) => setSyncOverwrite(e.target.checked)}
                          className="accent-[var(--tv-accent)]"
                        />
                        Allow overwriting existing values (push and mirror)
                      </label>
                    </div>
                  )}

                  {synced ? <SyncBody result={synced} /> : null}
                </div>
              )}
            </Section>

            <Section icon="save" title={`Export ${project}`}>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-tv-sm border border-warn/30 bg-raised p-3.5">
                  <div className="flex items-center gap-2">
                    <h3 className="text-[13px] font-semibold text-ink">Plaintext file</h3>
                    <Badge tone="danger">decrypted on disk</Badge>
                  </div>
                  <p className="mt-1.5 text-[12px] leading-relaxed text-muted">
                    The real values, unencrypted, for a process that cannot read the vault. Keep it
                    out of version control.
                  </p>
                  <div className="mt-3 max-w-[170px]">
                    <Field label="Format">
                      <select
                        value={format}
                        onChange={(e) => {
                          setFormat(e.target.value as ExportFormat);
                          setPlainPath(null); // the suggested file name follows the format
                          setExported(null);
                        }}
                        className="mono h-9 w-full rounded-tv-sm border border-line bg-raised px-2 text-[12.5px] text-ink focus:border-accent focus:outline-none"
                      >
                        <option value="dotenv">dotenv</option>
                        <option value="json">json</option>
                        <option value="shell">shell</option>
                      </select>
                    </Field>
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <Button size="sm" icon="folder" disabled={busyNow} onClick={() => void chooseExportPath("plain")}>
                      {plainPath ? baseName(plainPath) : "Choose location…"}
                    </Button>
                    <Button size="sm" variant="danger" icon="save" disabled={busyNow || readOnly || !plainPath} onClick={() => setConfirm("plain")}>
                      Export…
                    </Button>
                  </div>
                  {readOnly ? <p className="mt-2 text-[11.5px] text-warn">Disabled: read-only session.</p> : null}
                </div>

                <div className="rounded-tv-sm border border-accent-line bg-raised p-3.5">
                  <div className="flex items-center gap-2">
                    <h3 className="text-[13px] font-semibold text-ink">.env.encrypted</h3>
                    <Badge tone="accent">commit-safe</Badge>
                  </div>
                  <p className="mt-1.5 text-[12px] leading-relaxed text-muted">
                    Ciphertext sealed to the project's current recipients (v2, X25519). Safe to
                    commit, survives passphrase rotation, opens only with a matching identity — so
                    the project must be shared first.
                  </p>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <Button size="sm" icon="folder" disabled={busyNow} onClick={() => void chooseExportPath("sealed")}>
                      {sealedPath ? baseName(sealedPath) : "Choose location…"}
                    </Button>
                    <Button size="sm" variant="primary" icon="shield" disabled={busyNow || readOnly || !sealedPath} onClick={() => setConfirm("sealed")}>
                      Seal and export…
                    </Button>
                  </div>
                  {readOnly ? <p className="mt-2 text-[11.5px] text-warn">Disabled: read-only session.</p> : null}
                </div>
              </div>

              {exported ? (
                <p className="mono mt-3 flex items-start gap-2 rounded-tv-sm border border-line bg-soft/60 px-3 py-2 text-[11.5px] leading-relaxed text-muted">
                  <span className="mt-0.5 text-success">
                    <Icon name="check" size={12} />
                  </span>
                  <span className="break-all">{exported}</span>
                </p>
              ) : null}
            </Section>
          </div>
        </div>
      )}

      <Modal
        open={confirm !== null}
        width="max-w-md"
        title={confirm === "sync" ? `Sync ${direction}?` : confirm === "plain" ? "Write a plaintext export?" : "Write a commit-safe export?"}
        subtitle={confirm === "sync" ? (target ?? undefined) : confirm === "plain" ? (plainPath ?? undefined) : (sealedPath ?? undefined)}
        onClose={() => setConfirm(null)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirm(null)} disabled={busyNow}>
              Cancel
            </Button>
            {confirm === "sync" ? (
              <Button variant="danger" icon="refresh" disabled={busyNow} onClick={() => void runSync()}>
                {busy === "sync" ? "Syncing…" : `Sync ${direction}`}
              </Button>
            ) : confirm === "plain" ? (
              <Button variant="danger" icon="save" disabled={busyNow} onClick={() => void runExport("plain")}>
                {busy === "export" ? "Writing…" : "Write plaintext"}
              </Button>
            ) : (
              <Button variant="primary" icon="shield" disabled={busyNow} onClick={() => void runExport("sealed")}>
                {busy === "export" ? "Sealing…" : "Seal and write"}
              </Button>
            )}
          </>
        }
      >
        {confirm === "sync" ? (
          <div className="space-y-3">
            <p className="text-[13px] leading-relaxed text-muted">
              {DIRECTIONS.find((d) => d.id === direction)?.says}
            </p>
            <p className="mono break-all rounded-tv-sm border border-line bg-soft/60 px-3 py-2 text-[11.5px] text-ink">
              {direction} · {project} · {target}
            </p>
            <p
              className={`flex items-start gap-2 rounded-tv-sm border px-3 py-2.5 text-[12px] leading-relaxed ${
                direction === "pull" ? "border-warn/30 bg-warn/8 text-warn" : "border-line bg-soft/60 text-muted"
              }`}
            >
              <span className="mt-0.5">
                <Icon name="alert" size={13} />
              </span>
              {direction === "pull"
                ? "The file is rewritten from the vault: anything only in the file is dropped, and a file has no version history to roll back to. Commit it first if it matters."
                : syncOverwrite
                  ? "Overwrite is on, so keys present on both sides take the file's value. Each one still becomes a new version in the vault, so it can be rolled back."
                  : "Overwrite is off, so keys that already exist are left alone and reported as conflicts with the resolution that was applied."}
            </p>
          </div>
        ) : confirm === "plain" ? (
          <div className="space-y-3">
            <p className="text-[13px] leading-relaxed text-muted">
              This writes the project's <strong className="text-ink">decrypted values</strong> to
              that path in the clear — the one action here that puts plaintext on disk.
            </p>
            <p className="flex items-start gap-2 rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2.5 text-[12px] leading-relaxed text-danger">
              <span className="mt-0.5">
                <Icon name="alert" size={13} />
              </span>
              The file is written mode 0600, readable only by your user — but it is not encrypted and
              is not covered by the vault's key hierarchy. Keep it out of version control: gitignore
              it, and delete it once the process that needed it is done.
            </p>
            <p className="text-[12px] leading-relaxed text-muted">
              Prefer the sealed export beside it if this file is going anywhere near a repository.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-[13px] leading-relaxed text-muted">
              Writes a <span className="mono">.env.encrypted</span> v2 blob: the values are sealed to
              the project's current recipients, so the file is{" "}
              <strong className="text-ink">ciphertext and safe to commit</strong>.
            </p>
            <p className="flex items-start gap-2 rounded-tv-sm border border-accent-line bg-accent-soft px-3 py-2.5 text-[12px] leading-relaxed text-muted">
              <span className="mt-0.5 text-accent">
                <Icon name="shield" size={13} />
              </span>
              It is KEK-independent, so it keeps working after a passphrase rotation, and only a
              matching identity can open it. A project with no recipients is refused — share it first.
            </p>
          </div>
        )}
      </Modal>
    </div>
  );
}

// --- pieces ---------------------------------------------------------------

function Section({
  icon,
  title,
  note,
  aside,
  children
}: {
  icon: IconName;
  title: string;
  note?: string;
  aside?: ReactNode;
  children: ReactNode;
}): React.JSX.Element {
  return (
    <section className="overflow-hidden rounded-tv-md border border-line bg-paper">
      <header className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2.5">
        <span className="text-accent">
          <Icon name={icon} size={14} />
        </span>
        <h2 className="text-[13px] font-semibold text-ink">{title}</h2>
        {note ? <span className="mono min-w-0 truncate text-[11.5px] text-faint">{note}</span> : null}
        <span className="flex-1" />
        {aside}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

function ReadOnlyNote({ what }: { what: string }): React.JSX.Element {
  return (
    <p className="flex items-start gap-2 rounded-tv-sm border border-warn/30 bg-warn/8 px-3 py-2.5 text-[12px] leading-relaxed text-warn">
      <span className="mt-0.5">
        <Icon name="lock" size={13} />
      </span>
      {what} is disabled here: the access policy is read-only, or the vault is served by the local
      agent, which can read but never write. Scanning, previewing and comparing still work.
    </p>
  );
}

function Diagnostics({ items }: { items: DotenvDiagnostic[] }): React.JSX.Element | null {
  if (items.length === 0) return null;
  return (
    <div className="rounded-tv-sm border border-warn/30 bg-warn/8 px-3 py-2.5">
      <p className="text-[11px] font-semibold uppercase tracking-[0.07em] text-warn">
        {plural(items.length, "parser diagnostic")}
      </p>
      <ul className="mt-1.5 max-h-32 space-y-1 overflow-y-auto">
        {items.map((d, i) => (
          <li key={`${d.path}:${d.line ?? 0}:${i}`} className="mono text-[11.5px] leading-relaxed">
            <span className="text-faint">
              {baseName(d.path)}
              {d.line ? `:${d.line}` : ""}
            </span>{" "}
            {d.key ? <span className="text-ink">{d.key}</span> : null}{" "}
            <span className="text-muted">{d.message}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function PreviewBody({ preview }: { preview: EnvImportPreview }): React.JSX.Element {
  return (
    <div className="space-y-2.5">
      <p className="text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
        Preview — nothing written yet
      </p>
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge tone="success">{plural(preview.create_count, "create")}</Badge>
        <Badge tone="warn">{plural(preview.overwrite_count, "overwrite")}</Badge>
        <Badge tone="neutral">{plural(preview.skip_count, "skip")}</Badge>
        {preview.blocked_count > 0 ? <Badge tone="danger">{plural(preview.blocked_count, "blocked")}</Badge> : null}
        <span className="mono text-[11px] text-faint">{preview.files.map(baseName).join(" · ")}</span>
      </div>
      {preview.keys.length === 0 ? (
        <p className="rounded-tv-sm border border-line bg-soft/60 px-3 py-2.5 text-[12.5px] text-muted">
          Nothing would be written: every key in these files already exists in the project, or the
          policy blocks it.
        </p>
      ) : (
        <ul className="max-h-56 space-y-0.5 overflow-y-auto rounded-tv-sm border border-line bg-soft/40 px-3 py-2">
          {preview.keys.map((k) => (
            <li key={`${k.source_path}:${k.key}`} className="flex items-center gap-2">
              <Badge tone={ACTION_TONE[k.action] ?? "neutral"} className="w-[76px] justify-center">
                {k.action}
              </Badge>
              <span className="mono min-w-0 flex-1 truncate text-[12px] text-ink">{k.key}</span>
              <span className="mono shrink-0 text-[11px] text-faint">{baseName(k.source_path)}</span>
            </li>
          ))}
        </ul>
      )}
      {preview.blocked_keys.length > 0 ? (
        <p className="rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] leading-relaxed text-danger">
          <span className="mono">{preview.blocked_keys.join(", ")}</span> — denied by the access
          policy, so they are not imported and are not readable here either.
        </p>
      ) : null}
      <Diagnostics items={preview.diagnostics} />
    </div>
  );
}

function ImportBody({ result }: { result: EnvImportResult }): React.JSX.Element {
  return (
    <div className="space-y-2 rounded-tv-sm border border-success/30 bg-success/8 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-success">
          <Icon name="check" size={13} />
        </span>
        <span className="text-[12.5px] font-medium text-ink">Imported into {result.project}</span>
        <Badge tone="success">{plural(result.create_count, "created")}</Badge>
        <Badge tone="warn">{plural(result.overwrite_count, "overwritten")}</Badge>
        <Badge tone="neutral">{plural(result.skip_count, "skipped")}</Badge>
      </div>
      {result.skipped_keys.length > 0 ? (
        <p className="mono text-[11.5px] leading-relaxed text-muted">skipped: {result.skipped_keys.join(", ")}</p>
      ) : null}
      {result.blocked_keys.length > 0 ? (
        <p className="mono text-[11.5px] leading-relaxed text-danger">
          blocked by policy: {result.blocked_keys.join(", ")}
        </p>
      ) : null}
      <Diagnostics items={result.diagnostics} />
    </div>
  );
}

function DiffBody({ diff }: { diff: EnvFileDiff }): React.JSX.Element {
  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap items-center gap-2">
        {diff.in_sync ? <Badge tone="success">in sync</Badge> : <Badge tone="warn">drift</Badge>}
        <span className="mono text-[11.5px] text-faint">
          {diff.project} · {baseName(diff.file)} ·{" "}
          {diff.value_diffs ? "values compared" : "key sets only"}
        </span>
      </div>
      <div className="grid grid-cols-3 gap-2.5">
        <KeyColumn title="Only in vault" keys={diff.only_in_vault} tone="accent" />
        <KeyColumn title="Only in file" keys={diff.only_in_file} tone="warn" />
        <KeyColumn title="In both" keys={diff.in_both} tone="neutral" verdicts={diff.value_diffs} />
      </div>
    </div>
  );
}

function KeyColumn({
  title,
  keys,
  tone,
  verdicts
}: {
  title: string;
  keys: string[];
  tone: "neutral" | "accent" | "warn";
  verdicts?: Record<string, string>;
}): React.JSX.Element {
  const sorted = [...keys].sort((a, b) => a.localeCompare(b));
  return (
    <div className="min-w-0 rounded-tv-sm border border-line bg-soft/50">
      <p className="flex items-center gap-1.5 border-b border-line px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
        {title} <Badge tone={tone}>{keys.length}</Badge>
      </p>
      {sorted.length === 0 ? (
        <p className="px-3 py-2.5 text-[12px] text-faint">none</p>
      ) : (
        <ul className="max-h-52 space-y-0.5 overflow-y-auto px-3 py-2">
          {sorted.map((k) => {
            const verdict = verdicts?.[k];
            return (
              <li key={k} className="flex items-center gap-2">
                <span className="mono min-w-0 flex-1 truncate text-[12px] text-ink">{k}</span>
                {verdict ? <Badge tone={VERDICT_TONE[verdict] ?? "neutral"}>{verdict}</Badge> : null}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function SyncBody({ result }: { result: EnvSyncResult }): React.JSX.Element {
  const counts = [
    { n: result.created.length, word: "created", tone: "success" as const },
    { n: result.updated.length, word: "updated", tone: "warn" as const },
    { n: result.skipped.length, word: "skipped", tone: "neutral" as const },
    { n: result.unchanged.length, word: "unchanged", tone: "neutral" as const }
  ].filter((c) => c.n > 0);
  return (
    <div className="space-y-2 rounded-tv-sm border border-line bg-soft/50 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge tone="accent">{result.direction}</Badge>
        <span className="text-[12.5px] text-ink">{result.project}</span>
        {result.env_created ? <Badge tone="success">file created</Badge> : null}
        {counts.map((c) => (
          <Badge key={c.word} tone={c.tone}>
            {plural(c.n, c.word)}
          </Badge>
        ))}
        <span className="mono text-[11px] text-faint">
          {result.vault_entries} in vault · {result.env_entries} in file
        </span>
      </div>
      {result.conflicts.length > 0 ? (
        <div className="rounded-tv-sm border border-warn/30 bg-warn/8 px-3 py-2">
          <p className="text-[11px] font-semibold uppercase tracking-[0.07em] text-warn">
            {plural(result.conflicts.length, "conflict")}
          </p>
          <ul className="mt-1 max-h-32 space-y-0.5 overflow-y-auto">
            {result.conflicts.map((c) => (
              <li key={c.key} className="flex items-center gap-2">
                <span className="mono min-w-0 flex-1 truncate text-[12px] text-ink">{c.key}</span>
                <span className="mono shrink-0 text-[11px] text-warn">{c.resolution}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
