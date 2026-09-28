import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { REVEAL_AUTOHIDE_MS } from "@shared/ipc";
import type { ProjectOverview, RollbackResult, SecretMeta, SecretVersionMeta } from "@shared/types";

import { fullTime, maskValue, readSort, relTime, writeSort, type SortColumn, type SortState } from "../lib/api";
import {
  Badge,
  Button,
  EmptyState,
  Field,
  Icon,
  IconButton,
  Modal,
  Spinner,
  TextArea,
  TextInput,
  Tooltip,
  useToast
} from "./ui";

const CHARSETS = ["alphanumeric", "hex", "base64", "ascii"];

interface Reveal {
  value: string;
  expiresAt: number;
}

/**
 * Discriminated rather than a magic string: `__project__` satisfies the Go
 * secret-key regex (`^[a-zA-Z_][a-zA-Z0-9_]*$`, internal/validation/validation.go),
 * so a secret actually named `__project__` would have made "delete secret"
 * delete the entire project instead.
 */
type DeleteTarget = { kind: "project" } | { kind: "secret"; key: string };

export interface SecretActions {
  reveal: (key: string) => Promise<string>;
  save: (key: string, value: string) => Promise<void>;
  remove: (key: string) => Promise<void>;
  generate: (key: string, length: number, charset: string) => Promise<void>;
  history: (key: string) => Promise<SecretVersionMeta[]>;
  rollback: (key: string, version: number) => Promise<RollbackResult>;
  copy: (value: string) => Promise<number>;
  makeCurrent: () => Promise<void>;
  deleteProject: () => Promise<void>;
}

/**
 * A revealed value is transient by construction: it is dropped from React state
 * after REVEAL_AUTOHIDE_MS, and the reveal itself is never cached between hides,
 * so re-revealing spends another unit of the policy read budget.
 */
function useReveals(actions: SecretActions, projectKey: string) {
  const [reveals, setReveals] = useState<Record<string, Reveal>>({});
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const timers = useRef<Record<string, number>>({});
  // Bumped on every project switch. An in-flight reveal from the previous
  // project must not land in the new project's map: with a shared key name
  // (DATABASE_URL exists in most projects) that would display project A's value
  // under project B, and the copy button would copy it.
  const generation = useRef(0);
  // Ref mirror of `pending`, so the double-click guard does not depend on state
  // having flushed.
  const pendingRef = useRef<Record<string, boolean>>({});

  const clearTimer = (key: string): void => {
    const id = timers.current[key];
    if (id) window.clearTimeout(id);
    delete timers.current[key];
  };

  const clearAllTimers = (): void => {
    for (const id of Object.values(timers.current)) window.clearTimeout(id);
    timers.current = {};
  };

  useEffect(() => () => clearAllTimers(), []);

  // Drop every revealed value when the project changes — nothing follows you
  // across projects, and no stale timer may fire into the new project's map.
  useEffect(() => {
    generation.current += 1;
    clearAllTimers();
    pendingRef.current = {};
    setReveals({});
    setPending({});
  }, [projectKey]);

  // A single 1s ticker drives the visible countdowns without per-row timers.
  const [, forceTick] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => forceTick((n) => n + 1), 1000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    const now = Date.now();
    const expired = Object.entries(reveals).filter(([, r]) => r.expiresAt <= now);
    if (expired.length === 0) return;
    setReveals((prev) => {
      const next = { ...prev };
      for (const [key] of expired) {
        delete next[key];
        clearTimer(key);
      }
      return next;
    });
  }, [reveals]);

  const hide = useCallback((key: string) => {
    clearTimer(key);
    setReveals((prev) => {
      const next = { ...prev };
      delete next[key];
      return next;
    });
  }, []);

  const show = useCallback(
    async (key: string) => {
      if (reveals[key]) {
        hide(key);
        return;
      }
      // Without this a double-click starts two reads and spends two units of the
      // policy's max_reads_per_session budget for one reveal.
      if (pendingRef.current[key]) return;
      const gen = generation.current;
      pendingRef.current[key] = true;
      setPending((p) => ({ ...p, [key]: true }));
      try {
        const value = await actions.reveal(key);
        // The project changed while this was in flight; discard the value.
        if (gen !== generation.current) return;
        clearTimer(key);
        setReveals((prev) => ({
          ...prev,
          [key]: { value, expiresAt: Date.now() + REVEAL_AUTOHIDE_MS }
        }));
        timers.current[key] = window.setTimeout(() => hide(key), REVEAL_AUTOHIDE_MS);
      } finally {
        delete pendingRef.current[key];
        if (gen === generation.current) {
          setPending((p) => {
            const next = { ...p };
            delete next[key];
            return next;
          });
        }
      }
    },
    [actions, hide, reveals]
  );

  return { reveals, pending, show, hide };
}

function secondsLeft(r: Reveal | undefined): number {
  if (!r) return 0;
  return Math.max(0, Math.ceil((r.expiresAt - Date.now()) / 1000));
}

export default function SecretsView({
  project,
  secrets,
  loading,
  error,
  readOnly,
  actions,
  onRefresh,
  focusToken,
  newSecretToken,
  projectsEmpty,
  onCreateProject
}: {
  project: ProjectOverview | null;
  secrets: SecretMeta[];
  loading: boolean;
  error: string | null;
  readOnly: boolean;
  actions: SecretActions;
  onRefresh: () => void;
  /** Incremented by Cmd+K while the secrets view owns the focus target. */
  focusToken: number;
  /** Incremented by Cmd+N to open the new-secret editor. */
  newSecretToken: number;
  /** True when the vault itself has no projects, so this is a first run. */
  projectsEmpty: boolean;
  onCreateProject: () => void;
}): React.JSX.Element {
  const toast = useToast();
  const [filter, setFilter] = useState("");
  const [editor, setEditor] = useState<{ key: string; value: string; isNew: boolean } | null>(null);
  const [generator, setGenerator] = useState(false);
  const [historyFor, setHistoryFor] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<DeleteTarget | null>(null);

  const { reveals, pending, show, hide } = useReveals(actions, project?.name ?? "");

  // Screen-capture exclusion follows the values: on while anything is revealed
  // or the editor holds a loaded value, off otherwise, so ordinary screenshots
  // of the app keep working. Only sent on change to avoid toggling the window's
  // sharing type on every render.
  const protectionOn = useRef(false);
  useEffect(() => {
    const active = Object.keys(reveals).length > 0 || editor !== null;
    if (active === protectionOn.current) return;
    protectionOn.current = active;
    void window.tvault.setProtectionActive(active);
  }, [reveals, editor]);

  useEffect(
    () => () => {
      void window.tvault.setProtectionActive(false);
    },
    []
  );

  const [sort, setSort] = useState<SortState>(readSort);
  useEffect(() => {
    writeSort(sort);
  }, [sort]);

  const toggleSort = (column: SortColumn): void => {
    setSort((prev) =>
      prev.column === column
        ? { column, dir: prev.dir === "asc" ? "desc" : "asc" }
        : { column, dir: "asc" }
    );
  };

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const list = q ? secrets.filter((s) => s.key.toLowerCase().includes(q)) : secrets;
    const mul = sort.dir === "asc" ? 1 : -1;
    return [...list].sort((a, b) => {
      switch (sort.column) {
        case "version":
          return (a.version - b.version) * mul || a.key.localeCompare(b.key);
        case "updated": {
          const delta = (Date.parse(a.updated_at) || 0) - (Date.parse(b.updated_at) || 0);
          return delta * mul || a.key.localeCompare(b.key);
        }
        default:
          return a.key.localeCompare(b.key) * mul;
      }
    });
  }, [secrets, filter, sort]);

  // vault_projects_overview counts secrets before policy filtering, while
  // vault_list_secrets_detailed filters through secrets_deny. A gap between the
  // two is expected when the policy hides keys, and saying so beats looking broken.
  const hiddenByPolicy = project ? Math.max(0, project.secret_count - secrets.length) : 0;

  const openNew = (): void => setEditor({ key: "", value: "", isNew: true });

  const keyFilterRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (focusToken > 0) keyFilterRef.current?.focus();
  }, [focusToken]);
  useEffect(() => {
    if (newSecretToken > 0) openNew();
    // openNew is a stable per-render closure over setEditor; the token is the
    // only thing that should retrigger this.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [newSecretToken]);

  if (!project) {
    if (projectsEmpty) {
      return (
        <div className="flex h-full flex-col items-center justify-center gap-5 px-10 text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-tv-md border border-accent-line bg-accent-soft text-accent">
            <Icon name="lock" size={24} />
          </div>
          <div className="space-y-2">
            <h2 className="text-[17px] font-semibold tracking-[-0.01em] text-ink">
              This vault is empty
            </h2>
            <p className="mx-auto max-w-md text-[13px] leading-relaxed text-muted">
              A project is a namespace with its own encryption key, so compromising one never
              exposes the others. Create the first one here, or bring an existing{" "}
              <span className="mono text-ink">.env</span> across from the terminal.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {!readOnly ? (
              <Button variant="primary" icon="plus" onClick={onCreateProject}>
                Create your first project
              </Button>
            ) : null}
            <Button
              variant="default"
              icon="copy"
              onClick={() => {
                // A command, not a secret: plain clipboard is fine.
                navigator.clipboard
                  .writeText("tvault import .env")
                  .then(() => toast.success("Import command copied"))
                  .catch(() => toast.error("Copy failed"));
              }}
            >
              Copy “tvault import .env”
            </Button>
          </div>
        </div>
      );
    }
    return (
      <EmptyState
        icon="folder"
        title="No project selected"
        body="Pick a project from the sidebar to browse its secrets. Values stay encrypted at rest and are only decrypted for the specific key you reveal."
      />
    );
  }

  const copyValue = async (key: string, value: string): Promise<void> => {
    try {
      const ms = await actions.copy(value);
      toast.success(
        `Copied ${key}`,
        `Clears in ${Math.round(ms / 1000)}s — clipboard-history managers may keep a copy`
      );
    } catch (err) {
      toast.error("Copy failed", err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="flex h-full min-w-0 flex-col">
      <header className="shrink-0 border-b border-line px-6 pb-4 pt-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2.5">
              <h1 className="mono truncate text-[17px] font-semibold tracking-[-0.01em] text-ink">
                {project.name}
              </h1>
              <Badge tone="neutral">{secrets.length} keys</Badge>
              {hiddenByPolicy > 0 ? (
                <Badge tone="warn" className="cursor-help" >
                  {hiddenByPolicy} hidden by policy
                </Badge>
              ) : null}
            </div>
            {project.description ? (
              <p className="mt-1 max-w-2xl text-[12.5px] leading-relaxed text-muted">
                {project.description}
              </p>
            ) : null}
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <IconButton icon="refresh" label="Refresh" onClick={onRefresh} />
            {!readOnly ? (
              <>
                <Button size="sm" icon="key" onClick={() => setGenerator(true)}>
                  Generate
                </Button>
                <Button size="sm" variant="primary" icon="plus" onClick={openNew}>
                  New secret
                </Button>
              </>
            ) : (
              <Badge tone="warn">read-only policy</Badge>
            )}
          </div>
        </div>

        <div className="mt-3.5 flex items-center gap-2">
          <div className="flex h-8 flex-1 items-center gap-2 rounded-tv-sm border border-line bg-raised px-2.5">
            <span className="text-faint">
              <Icon name="search" size={13} />
            </span>
            <input
              ref={keyFilterRef}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter keys in this project"
              spellCheck={false}
              className="mono h-full min-w-0 flex-1 bg-transparent text-[12.5px] text-ink placeholder:font-sans placeholder:text-faint focus:outline-none"
            />
            {filter ? (
              <IconButton icon="x" label="Clear" onClick={() => setFilter("")} />
            ) : (
              <span className="mono shrink-0 text-[11px] text-faint">
                {rows.length}/{secrets.length}
              </span>
            )}
          </div>
          <ProjectMenu
            readOnly={readOnly}
            onMakeCurrent={async () => {
              await actions.makeCurrent();
              toast.success(`${project.name} is now the current project`);
            }}
            onDeleteProject={() => setConfirmDelete({ kind: "project" })}
          />
        </div>
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex h-40 items-center justify-center gap-2.5 text-muted">
            <Spinner /> <span className="text-[12.5px]">Loading keys…</span>
          </div>
        ) : error ? (
          <div className="m-6 rounded-tv-md border border-danger/30 bg-danger/8 px-4 py-3.5">
            <p className="flex items-center gap-2 text-[13px] font-medium text-danger">
              <Icon name="alert" size={14} /> Could not load secrets
            </p>
            <p className="mono mt-1.5 break-words text-[11.5px] leading-relaxed text-muted">{error}</p>
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            icon="key"
            title={secrets.length === 0 ? "No secrets yet" : "No key matches that filter"}
            body={
              secrets.length === 0
                ? "Add a key/value pair, or generate a cryptographically random secret that is never displayed."
                : undefined
            }
            action={
              secrets.length === 0 && !readOnly ? (
                <Button variant="primary" icon="plus" onClick={openNew}>
                  New secret
                </Button>
              ) : undefined
            }
          />
        ) : (
          <table className="w-full border-collapse">
            {/* No z-index on purpose: sticky already paints above in-flow rows,
                and an explicit z here let the header beat portalled overlays
                (tooltips, modals) that sit far above it in z. */}
            <thead className="sticky top-0 bg-paper">
              <tr className="border-b border-line text-left">
                <SortHeader label="Key" column="key" sort={sort} onSort={toggleSort} className="pl-6 pr-2" />
                <SortHeader label="Ver" column="version" sort={sort} onSort={toggleSort} className="w-16 px-2" />
                <SortHeader label="Updated" column="updated" sort={sort} onSort={toggleSort} className="w-28 px-2" />
                <th className="w-[38%] px-2 py-2 text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
                  Value
                </th>
                <th className="w-32 px-6 py-2 text-right text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => {
                const revealed = reveals[s.key];
                const busy = pending[s.key];
                const left = secondsLeft(revealed);
                return (
                  <tr
                    key={s.key}
                    className="group border-b border-line/60 transition-colors duration-75 hover:bg-soft/70"
                  >
                    <td className="px-6 py-2.5">
                      <span className="mono text-[12.5px] text-ink">{s.key}</span>
                    </td>
                    <td className="px-2 py-2.5">
                      <Tooltip label="Version history">
                        <button
                          onClick={() => setHistoryFor(s.key)}
                          className="mono rounded px-1.5 py-0.5 text-[11.5px] text-muted
                            transition-all duration-150 ease-out hover:scale-105
                            hover:bg-accent-soft hover:text-accent"
                        >
                          v{s.version}
                        </button>
                      </Tooltip>
                    </td>
                    <td className="px-2 py-2.5">
                      <span className="text-[11.5px] text-faint" title={fullTime(s.updated_at)}>
                        {relTime(s.updated_at)}
                      </span>
                    </td>
                    <td className="px-2 py-2.5">
                      {revealed ? (
                        <div className="flex items-center gap-2">
                          <code className="mono min-w-0 flex-1 truncate rounded border border-accent-line bg-accent-soft px-2 py-1 text-[12px] text-ink">
                            {revealed.value}
                          </code>
                          <span
                            className={`mono shrink-0 text-[11px] ${left <= 5 ? "text-danger" : "text-faint"}`}
                            title="Auto-hides"
                          >
                            {left}s
                          </span>
                          <IconButton
                            icon="copy"
                            label="Copy value"
                            onClick={() => void copyValue(s.key, revealed.value)}
                          />
                          <IconButton icon="eyeOff" label="Hide now" onClick={() => hide(s.key)} />
                        </div>
                      ) : (
                        <button
                          onClick={() =>
                            void show(s.key).catch((err: unknown) => {
                              toast.error(
                                "Reveal failed",
                                err instanceof Error ? err.message : String(err)
                              );
                            })
                          }
                          className="group/icon flex items-center gap-2 text-muted transition-all
                            duration-150 ease-out hover:scale-[1.03] hover:text-accent"
                        >
                          {busy ? (
                            <Spinner size={12} />
                          ) : (
                            <>
                              <Icon name="eye" size={13} animated />
                              <span className="masked text-[12px] text-faint">••••••••••••</span>
                              <span className="text-[11.5px] font-medium">Reveal</span>
                            </>
                          )}
                        </button>
                      )}
                    </td>
                    <td className="px-6 py-2.5">
                      <div className="flex items-center justify-end gap-0.5 opacity-70 transition-opacity duration-100 group-hover:opacity-100">
                        <IconButton
                          icon="history"
                          label="Version history"
                          onClick={() => setHistoryFor(s.key)}
                        />
                        {!readOnly ? (
                          <>
                            <IconButton
                              icon="pencil"
                              label="Edit value"
                              onClick={() => setEditor({ key: s.key, value: "", isNew: false })}
                            />
                            <IconButton
                              icon="trash"
                              label="Delete secret"
                              tone="danger"
                              onClick={() => setConfirmDelete({ kind: "secret", key: s.key })}
                            />
                          </>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <SecretEditorModal
        state={editor}
        project={project.name}
        readOnly={readOnly}
        actions={actions}
        onClose={() => setEditor(null)}
        onSaved={(key) => {
          toast.success(`Saved ${key}`);
          onRefresh();
        }}
      />

      <GenerateModal
        open={generator}
        project={project.name}
        actions={actions}
        onClose={() => setGenerator(false)}
        onDone={(key) => {
          toast.success(`Generated ${key}`, "The value was stored and never displayed.");
          onRefresh();
        }}
      />

      <HistoryModal
        secretKey={historyFor}
        project={project.name}
        readOnly={readOnly}
        actions={actions}
        onClose={() => setHistoryFor(null)}
        onRolledBack={(key, v, nv) => {
          toast.success(`Rolled back ${key}`, `v${v} restored as v${nv}`);
          onRefresh();
        }}
      />

      <ConfirmDeleteModal
        target={confirmDelete}
        project={project.name}
        actions={actions}
        onClose={() => setConfirmDelete(null)}
        onDeleted={(what, wasProject) => {
          toast.success(`Deleted ${what}`);
          // Deleting the project already reloads the list and clears the selection
          // in App; refreshing secrets for a project that no longer exists would
          // only produce a spurious error toast.
          if (!wasProject) onRefresh();
        }}
      />
    </div>
  );
}

function SortHeader({
  label,
  column,
  sort,
  onSort,
  className = ""
}: {
  label: string;
  column: SortColumn;
  sort: SortState;
  onSort: (c: SortColumn) => void;
  className?: string;
}): React.JSX.Element {
  const active = sort.column === column;
  return (
    <th className={`py-2 ${className}`}>
      <button
        onClick={() => onSort(column)}
        className={`group/sort flex items-center gap-1 text-[11px] font-semibold uppercase
          tracking-[0.07em] transition-colors duration-100 ${
            active ? "text-accent" : "text-faint hover:text-ink"
          }`}
        title={
          active
            ? `Sorted ${sort.dir === "asc" ? "ascending" : "descending"} — click to flip`
            : `Sort by ${label.toLowerCase()}`
        }
      >
        {label}
        <span
          className={`transition-opacity duration-100 ${
            active ? "opacity-100" : "opacity-0 group-hover/sort:opacity-60"
          }`}
        >
          <Icon name="chevron" size={11} className={active && sort.dir === "asc" ? "rotate-180" : ""} />
        </span>
      </button>
    </th>
  );
}

function ProjectMenu({
  readOnly,
  onMakeCurrent,
  onDeleteProject
}: {
  readOnly: boolean;
  onMakeCurrent: () => Promise<void>;
  onDeleteProject: () => void;
}): React.JSX.Element {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent): void => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <IconButton
        icon="more"
        label="Project actions"
        onClick={() => setOpen((o) => !o)}
        className={open ? "bg-soft text-ink" : ""}
      />
      {open ? (
        <div
          className="animate-in absolute right-0 top-8 z-30 w-56 overflow-hidden rounded-tv-sm border border-line bg-raised py-1"
          style={{ boxShadow: "var(--tv-shadow-sm)" }}
        >
          <button
            onClick={() => {
              setOpen(false);
              void onMakeCurrent();
            }}
            className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-[12.5px] text-ink transition-colors hover:bg-soft"
          >
            <Icon name="arrowRight" size={13} /> Set as current project
          </button>
          {!readOnly ? (
            <button
              onClick={() => {
                setOpen(false);
                onDeleteProject();
              }}
              className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-[12.5px] text-danger transition-colors hover:bg-danger/10"
            >
              <Icon name="trash" size={13} /> Delete project…
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function SecretEditorModal({
  state,
  project,
  readOnly,
  actions,
  onClose,
  onSaved
}: {
  state: { key: string; value: string; isNew: boolean } | null;
  project: string;
  readOnly: boolean;
  actions: SecretActions;
  onClose: () => void;
  onSaved: (key: string) => void;
}): React.JSX.Element | null {
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [spentRead, setSpentRead] = useState(false);
  const toast = useToast();

  // Guards the load-current-value fetch so it runs exactly once per modal open.
  // Without it, a change in `actions` identity re-runs the effect and silently
  // burns another unit of the policy's max_reads_per_session budget.
  const loadedFor = useRef<unknown>(null);
  // Compared against the captured request so a slow response for key A cannot
  // land in the field after the modal moved on to key B — saving would then
  // overwrite B with A's value.
  const activeState = useRef<{ key: string; value: string; isNew: boolean } | null>(null);

  useEffect(() => {
    activeState.current = state;
    if (!state) {
      loadedFor.current = null;
      // Never leave plaintext sitting in React state after the modal closes.
      setValue("");
      setKey("");
      setErr(null);
      return;
    }
    setKey(state.key);
    setValue(state.value);
    setErr(null);
    setRevealed(false);
    setSpentRead(false);
    if (loadedFor.current === state) return;
    loadedFor.current = state;
    if (!state.isNew && state.value === "") {
      const requested = state;
      // Editing an existing key: pull the current value so the field cannot be
      // saved blank by accident. This deliberately spends one reveal.
      void actions
        .reveal(state.key)
        .then((v) => {
          if (activeState.current !== requested) return;
          setValue(v);
          setSpentRead(true);
        })
        .catch((e: unknown) => {
          if (activeState.current !== requested) return;
          setErr(
            `Could not load the current value: ${e instanceof Error ? e.message : String(e)}`
          );
        });
    }
  }, [state, actions]);

  /**
   * Native Cmd+C / Cmd+X would put the value on the system pasteboard with
   * nothing scheduled to remove it. Routing through main applies the same 30s
   * auto-clear as the table's copy button. Cut is prevented rather than honoured
   * — removing text from a secret field is never what the user means.
   */
  const onCopyOrCut = (e: React.ClipboardEvent<HTMLTextAreaElement>): void => {
    e.preventDefault();
    const el = e.currentTarget;
    const start = el.selectionStart ?? 0;
    const end = el.selectionEnd ?? 0;
    const selected = el.value.slice(start, end);
    if (!selected) return;
    void actions.copy(selected).then(
      (ms) =>
        toast.success(
          "Copied",
          `Clears in ${Math.round(ms / 1000)}s — clipboard-history managers may keep a copy`
        ),
      (err: unknown) =>
        toast.error("Copy failed", err instanceof Error ? err.message : String(err))
    );
  };

  if (!state) return null;

  const submit = async (): Promise<void> => {
    const k = key.trim();
    if (!k) {
      setErr("Key name is required.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await actions.save(k, value);
      onSaved(k);
      onClose();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setErr(msg);
      toast.error("Save failed", msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      title={state.isNew ? "New secret" : `Edit ${state.key}`}
      subtitle={project}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" icon="save" onClick={() => void submit()} disabled={busy || readOnly}>
            {busy ? "Saving…" : "Save"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field
          label="Key"
          hint={
            state.isNew ? (
              <>
                Stored in plaintext inside the vault file, like all key names. Use{" "}
                <span className="mono">SCREAMING_SNAKE_CASE</span> to match dotenv convention.
              </>
            ) : undefined
          }
        >
          <TextInput
            mono
            value={key}
            disabled={!state.isNew}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setKey(e.target.value)}
            placeholder="DATABASE_URL"
          />
        </Field>

        <Field label="Value">
          <div className="space-y-2">
            <TextArea
              rows={4}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onCopy={onCopyOrCut}
              onCut={onCopyOrCut}
              placeholder="postgres://user:pass@host:5432/db"
              className={revealed ? "" : "text-transparent caret-ink selection:bg-accent/30"}
              onBlur={() => setRevealed(false)}
            />
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => setRevealed((r) => !r)}
                className="inline-flex items-center gap-1.5 text-[12px] font-medium text-muted transition-colors hover:text-accent"
              >
                <Icon name={revealed ? "eyeOff" : "eye"} size={13} />
                {revealed ? "Hide while typing" : "Show while editing"}
              </button>
              <span className="mono text-[11.5px] text-faint">{value.length} chars</span>
            </div>
          </div>
        </Field>

        {spentRead ? (
          <p className="flex items-start gap-2 text-[11.5px] leading-relaxed text-faint">
            <span className="mt-0.5">
              <Icon name="eye" size={12} />
            </span>
            Opening this editor loaded the current value, which spent one unit of the session
            reveal budget — see the counter in the sidebar.
          </p>
        ) : null}

        {!revealed && value ? (
          <p className="text-[11.5px] leading-relaxed text-faint">
            Masked: <span className="mono text-muted">{maskValue(value)}</span>
          </p>
        ) : null}

        {err ? (
          <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] leading-relaxed text-danger">
            {err}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}

function GenerateModal({
  open,
  project,
  actions,
  onClose,
  onDone
}: {
  open: boolean;
  project: string;
  actions: SecretActions;
  onClose: () => void;
  onDone: (key: string) => void;
}): React.JSX.Element | null {
  const [key, setKey] = useState("");
  const [length, setLength] = useState(32);
  const [charset, setCharset] = useState(CHARSETS[0]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!open) return null;

  const submit = async (): Promise<void> => {
    const k = key.trim();
    if (!k) {
      setErr("Key name is required.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await actions.generate(k, length, charset);
      setKey("");
      onDone(k);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      title="Generate secret"
      subtitle={project}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" icon="key" onClick={() => void submit()} disabled={busy}>
            {busy ? "Generating…" : "Generate & store"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="flex items-start gap-2.5 rounded-tv-sm border border-accent-line bg-accent-soft px-3.5 py-3">
          <span className="mt-0.5 text-accent">
            <Icon name="shield" size={14} />
          </span>
          <p className="text-[12.5px] leading-relaxed text-ink">
            The value is generated with <span className="mono">crypto/rand</span>, stored encrypted, and{" "}
            <strong className="font-semibold">never returned</strong> — not to this window, not to any
            log. If you need to see it later, reveal it from the secrets table.
          </p>
        </div>

        <Field label="Key">
          <TextInput
            mono
            value={key}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setKey(e.target.value)}
            placeholder="STRIPE_WEBHOOK_SECRET"
          />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label={`Length — ${length}`}>
            <input
              type="range"
              min={8}
              max={128}
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
              className="mt-2.5 w-full accent-[var(--tv-accent)]"
            />
          </Field>
          <Field label="Charset">
            <select
              value={charset}
              onChange={(e) => setCharset(e.target.value)}
              className="mono h-9 w-full rounded-tv-sm border border-line bg-raised px-2.5 text-[12.5px] text-ink focus:border-accent focus:outline-none"
            >
              {CHARSETS.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </Field>
        </div>

        <p className="mono text-[11.5px] text-faint">
          ≈ {Math.floor((length * (charset === "hex" ? 4 : charset === "alphanumeric" ? 5.95 : 6.5)) )} bits
          of entropy
        </p>

        {err ? (
          <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
            {err}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}

function HistoryModal({
  secretKey,
  project,
  readOnly,
  actions,
  onClose,
  onRolledBack
}: {
  secretKey: string | null;
  project: string;
  readOnly: boolean;
  actions: SecretActions;
  onClose: () => void;
  onRolledBack: (key: string, from: number, newVersion: number) => void;
}): React.JSX.Element | null {
  const [versions, setVersions] = useState<SecretVersionMeta[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);

  useEffect(() => {
    if (!secretKey) return;
    setLoading(true);
    setErr(null);
    setVersions([]);
    actions
      .history(secretKey)
      .then(setVersions)
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, [secretKey, actions]);

  if (!secretKey) return null;

  const rollback = async (version: number): Promise<void> => {
    setBusy(version);
    try {
      const res = await actions.rollback(secretKey, version);
      onRolledBack(secretKey, version, res.new_version);
      const next = await actions.history(secretKey);
      setVersions(next);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Modal
      open
      title="Version history"
      subtitle={`${project} / ${secretKey}`}
      onClose={onClose}
      width="max-w-xl"
    >
      <div className="mb-3 flex items-start gap-2.5 rounded-tv-sm border border-line bg-soft/60 px-3.5 py-2.5">
        <span className="mt-0.5 text-faint">
          <Icon name="history" size={13} />
        </span>
        <p className="text-[12px] leading-relaxed text-muted">
          History is metadata only — version numbers and timestamps, never values. Rollback is
          non-destructive: it re-stores the old value as a <em>new</em> version, and version numbers
          are never reused.
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center gap-2 py-10 text-muted">
          <Spinner /> <span className="text-[12.5px]">Loading history…</span>
        </div>
      ) : err ? (
        <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
          {err}
        </p>
      ) : versions.length === 0 ? (
        <p className="py-8 text-center text-[12.5px] text-faint">
          No archived versions. History appears once a key is overwritten.
        </p>
      ) : (
        <ul className="space-y-1">
          {[...versions]
            .sort((a, b) => b.version - a.version)
            .map((v, i) => (
              <li
                key={v.version}
                className="flex items-center gap-3 rounded-tv-sm border border-line bg-raised px-3.5 py-2.5"
              >
                <span className="mono w-10 shrink-0 text-[12px] font-medium text-accent">
                  v{v.version}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-[12px] text-ink">{fullTime(v.updated_at)}</span>
                  <span className="block text-[11.5px] text-faint">{relTime(v.updated_at)}</span>
                </span>
                {i === 0 ? (
                  <Badge tone="accent">current</Badge>
                ) : readOnly ? null : (
                  <Button
                    size="sm"
                    icon="rollback"
                    disabled={busy !== null}
                    onClick={() => void rollback(v.version)}
                  >
                    {busy === v.version ? "Restoring…" : "Roll back"}
                  </Button>
                )}
              </li>
            ))}
        </ul>
      )}
    </Modal>
  );
}

function ConfirmDeleteModal({
  target,
  project,
  actions,
  onClose,
  onDeleted
}: {
  target: DeleteTarget | null;
  project: string;
  actions: SecretActions;
  onClose: () => void;
  onDeleted: (what: string, wasProject: boolean) => void;
}): React.JSX.Element | null {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!target) return null;

  const isProject = target.kind === "project";
  const secretKey = target.kind === "secret" ? target.key : "";

  const run = async (): Promise<void> => {
    setBusy(true);
    setErr(null);
    try {
      if (isProject) {
        await actions.deleteProject();
        onDeleted(`project ${project}`, true);
      } else {
        await actions.remove(secretKey);
        onDeleted(secretKey, false);
      }
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      title={isProject ? `Delete project ${project}?` : `Delete ${secretKey}?`}
      subtitle={isProject ? undefined : project}
      onClose={onClose}
      width="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" icon="trash" onClick={() => void run()} disabled={busy}>
            {busy ? "Deleting…" : "Delete"}
          </Button>
        </>
      }
    >
      <p className="text-[13px] leading-relaxed text-muted">
        {isProject ? (
          <>
            This deletes the project, its encryption key and <strong className="text-ink">every
            secret and archived version</strong> in it.
          </>
        ) : (
          <>
            This purges the key and its <strong className="text-ink">full version history</strong>.
          </>
        )}
      </p>
      <p className="mt-3 flex items-start gap-2 rounded-tv-sm border border-line bg-soft/60 px-3 py-2.5 text-[12px] leading-relaxed text-muted">
        <span className="mt-0.5 text-success">
          <Icon name="shield" size={13} />
        </span>
        A rotated safety snapshot is taken first and the delete is refused if that snapshot fails —
        provided <span className="mono text-ink">backup.dir</span> is configured.
      </p>
      {err ? (
        <p className="mono mt-3 rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
          {err}
        </p>
      ) : null}
    </Modal>
  );
}
