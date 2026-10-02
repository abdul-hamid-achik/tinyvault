import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import type {
  EnvDiffResult,
  EnvGroupDetail,
  EnvGroupFull,
  EnvSealResult,
  IdentityEntry,
  InheritedKey,
  PromoteResult
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
  Tooltip,
  useToast,
  type IconName
} from "./ui";

type DiffMode = "keys" | "values";

const STATUS_TONE: Record<string, "success" | "accent" | "warn" | "danger" | "neutral"> = {
  same: "success",
  different: "warn",
  missing: "danger",
  "local-only": "accent"
};

/** `diff_status` as recorded server-side by `vault_env_group_show`. */
const RECORDED_TONE: Record<string, "success" | "warn" | "neutral"> = {
  ok: "success",
  drift: "warn"
};

const UNKNOWN_STATUS_HINT =
  "unknown means the server could not compare these environments at all — usually fewer than two are linked, or a linked project no longer exists. It is not a verdict of \"in sync\".";

const READ_ONLY_HINT = "The active policy is read-only, so the server would refuse this.";

/** Which mutations the confirmation dialog is describing. */
type ConfirmRequest = { kind: "env"; env: string } | { kind: "group" };

/**
 * Environment groups are the feature this UI earns its keep on: drift across
 * production/preview/staging is a matrix, and a matrix is miserable in a terminal.
 *
 * Values are never displayed here. `vault_env_diff` compares values but reports
 * only same/different, promote moves bytes between DEKs without either side
 * reaching this process, and pin/unpin report an empty object — so nothing on
 * this screen can render a value even by accident.
 *
 * Membership and inheritance are metadata edits, and the two that sound
 * destructive (unlinking an environment, deleting a group) delete no project and
 * no secret; both confirmations say so in those words.
 */
export default function EnvGroupsView({
  readOnly,
  projects,
  onChanged
}: {
  readOnly: boolean;
  projects: string[];
  onChanged: () => void;
}): React.JSX.Element {
  const toast = useToast();
  const [groups, setGroups] = useState<EnvGroupDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  const [mode, setMode] = useState<DiffMode>("keys");
  const [diff, setDiff] = useState<EnvDiffResult | null>(null);
  const [diffing, setDiffing] = useState(false);
  const [diffError, setDiffError] = useState<string | null>(null);

  const [promote, setPromote] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [addEnv, setAddEnv] = useState(false);
  const [inheritOpen, setInheritOpen] = useState(false);
  const [sealOpen, setSealOpen] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmRequest | null>(null);
  const [mutating, setMutating] = useState(false);

  const [detail, setDetail] = useState<EnvGroupFull | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  // Bumped after any membership edit so the detail effect re-runs for the group
  // that is already selected (the effect only depends on `selected`).
  const [detailEpoch, setDetailEpoch] = useState(0);

  const load = useCallback(async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const list = await unwrap(window.tvault.envGroups());
      setGroups(list);
      setSelected((prev) => prev ?? list[0]?.name ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const group = useMemo(
    () => groups.find((g) => g.name === selected) ?? null,
    [groups, selected]
  );

  // `vault_env_group_show`: recorded drift verdict, description, inheritance
  // pointers. Generation-guarded exactly like the diff below — switching groups
  // quickly must not paint the previous group's detail.
  const detailGen = useRef(0);

  const loadDetail = useCallback(async (name: string): Promise<void> => {
    const gen = ++detailGen.current;
    try {
      const full = await unwrap(window.tvault.envGroupShow(name));
      if (gen !== detailGen.current) return;
      setDetail(full);
      setDetailError(null);
    } catch (err) {
      if (gen !== detailGen.current) return;
      setDetail(null);
      setDetailError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    if (!selected) {
      setDetail(null);
      setDetailError(null);
      return;
    }
    void loadDetail(selected);
  }, [selected, detailEpoch, loadDetail]);

  // Switching group or compare mode quickly can let the slower request resolve
  // last and paint the previous group's matrix. Same shape as the reveal guard.
  const diffGen = useRef(0);

  const runDiff = useCallback(async (name: string, m: DiffMode): Promise<void> => {
    const gen = ++diffGen.current;
    setDiffing(true);
    setDiffError(null);
    try {
      const result = await unwrap(window.tvault.envDiff(name, m === "values"));
      if (gen !== diffGen.current) return;
      setDiff(result);
    } catch (err) {
      if (gen !== diffGen.current) return;
      setDiff(null);
      setDiffError(err instanceof Error ? err.message : String(err));
    } finally {
      if (gen === diffGen.current) setDiffing(false);
    }
  }, []);

  useEffect(() => {
    if (!selected) {
      setDiff(null);
      return;
    }
    void runDiff(selected, mode);
  }, [selected, mode, runDiff]);

  const drifted = diff?.status === "drift";
  const driftCount = useMemo(
    () =>
      diff
        ? diff.keys.filter((k) =>
            k.environments.some((e) => e.status === "missing" || e.status === "different")
          ).length
        : 0,
    [diff]
  );

  /** Project → the group that already links it, so the add dialog can explain a refusal up front. */
  const linkedProjects = useMemo(() => {
    const map = new Map<string, string>();
    for (const g of groups) for (const e of g.environments) map.set(e.project, g.name);
    return map;
  }, [groups]);

  /** Key names offered to the seal dialog. Names are metadata; values never are. */
  const sealKeys = useMemo(
    () => (diff ? diff.keys.map((k) => k.key).sort((a, b) => a.localeCompare(b)) : []),
    [diff]
  );

  const recorded = detail?.diff_status ?? null;
  const inheritance = detail?.inheritance;

  /** Mutating controls stay visible but disabled; the reason travels with them. */
  const tip = (text: string): string => (readOnly ? READ_ONLY_HINT : text);

  /** Splices the server's own response back into the list — it is authoritative. */
  const applyGroup = useCallback((updated: EnvGroupDetail): void => {
    setGroups((prev) => prev.map((g) => (g.name === updated.name ? updated : g)));
    setDetailEpoch((n) => n + 1);
  }, []);

  /** `force` can overwrite a group of the same name, so replace-or-append. */
  const onCreated = useCallback(
    (created: EnvGroupDetail): void => {
      setGroups((prev) =>
        prev.some((g) => g.name === created.name)
          ? prev.map((g) => (g.name === created.name ? created : g))
          : [...prev, created]
      );
      setSelected(created.name);
      onChanged();
    },
    [onChanged]
  );

  const runConfirm = useCallback(async (): Promise<void> => {
    if (!confirm || !group) return;
    const name = group.name;
    setMutating(true);
    try {
      if (confirm.kind === "env") {
        const project = group.environments.find((e) => e.name === confirm.env)?.project ?? "";
        const updated = await unwrap(window.tvault.envGroupRemove(name, confirm.env));
        applyGroup(updated);
        toast.success(
          `Unlinked ${confirm.env}`,
          `${project} is still in the vault with every one of its secrets. Only the link was removed.`
        );
      } else {
        await unwrap(window.tvault.envGroupDelete(name));
        const remaining = groups.filter((g) => g.name !== name);
        setGroups(remaining);
        setSelected(remaining[0]?.name ?? null);
        setDetail(null);
        toast.success(
          `Deleted group ${name}`,
          "Group metadata only — no project and no secret was touched."
        );
      }
      onChanged();
      setConfirm(null);
    } catch (err) {
      toast.error(
        confirm.kind === "env" ? "Could not unlink environment" : "Could not delete group",
        err instanceof Error ? err.message : String(err)
      );
    } finally {
      setMutating(false);
    }
  }, [confirm, group, groups, applyGroup, onChanged, toast]);

  return (
    <div className="flex h-full min-w-0 flex-col">
      <header className="shrink-0 border-b border-line px-6 pb-4 pt-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-[17px] font-semibold tracking-[-0.01em] text-ink">Environments</h1>
            <p className="mt-1 max-w-2xl text-[12.5px] leading-relaxed text-muted">
              Linked projects representing environments of one application. Drift detection catches
              the key you added to <span className="mono">production</span> and forgot in{" "}
              <span className="mono">preview</span> before the deploy does.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <Button size="sm" icon="refresh" onClick={() => void load()}>
              Refresh
            </Button>
            {/* Lives here, not in the per-group toolbar: with zero groups that
                toolbar never renders, and this is the button that fixes it. */}
            {readOnly ? <Badge tone="warn">read-only policy</Badge> : null}
            <Button
              size="sm"
              variant="primary"
              icon="plus"
              disabled={readOnly || projects.length === 0}
              title={
                readOnly
                  ? READ_ONLY_HINT
                  : projects.length === 0
                    ? "A group links existing projects — create a project first"
                    : "Link existing projects as environments of one application"
              }
              onClick={() => setCreateOpen(true)}
            >
              New group
            </Button>
          </div>
        </div>
      </header>

      {loading ? (
        <div className="flex flex-1 items-center justify-center gap-2.5 text-muted">
          <Spinner /> <span className="text-[12.5px]">Loading environment groups…</span>
        </div>
      ) : error ? (
        <div className="m-6 rounded-tv-md border border-danger/30 bg-danger/8 px-4 py-3.5">
          <p className="flex items-center gap-2 text-[13px] font-medium text-danger">
            <Icon name="alert" size={14} /> {error}
          </p>
        </div>
      ) : groups.length === 0 ? (
        <EmptyState
          icon="layers"
          title="No environment groups"
          body={
            readOnly
              ? "Groups link existing projects as environments of one application. The active policy is read-only, so create one from the CLI:  tvault env group create myapp --env production=myapp --env preview=myapp-preview"
              : "Link existing projects as environments of one application so drift between them becomes a matrix. No project is created here — every environment points at one that already exists."
          }
          action={
            readOnly ? undefined : (
              <>
                <Button
                  variant="primary"
                  icon="plus"
                  disabled={projects.length === 0}
                  onClick={() => setCreateOpen(true)}
                >
                  New group
                </Button>
                <p className="mono max-w-md text-[11.5px] leading-relaxed text-faint">
                  CLI equivalent: tvault env group create myapp --env production=myapp --env
                  preview=myapp-preview
                </p>
              </>
            )
          }
        />
      ) : (
        <div className="flex min-h-0 flex-1">
          <div className="w-[210px] shrink-0 overflow-y-auto border-r border-line bg-soft/40 p-2">
            {groups.map((g) => (
              <button
                key={g.name}
                onClick={() => setSelected(g.name)}
                className={`mb-0.5 flex w-full items-center gap-2 rounded-tv-sm px-2.5 py-2 text-left transition-colors duration-100 ${
                  g.name === selected ? "bg-raised" : "hover:bg-deep/50"
                }`}
              >
                <span className={g.name === selected ? "text-accent" : "text-faint"}>
                  <Icon name="layers" size={13} />
                </span>
                <span className="min-w-0 flex-1">
                  <span
                    className={`mono block truncate text-[12.5px] ${
                      g.name === selected ? "font-medium text-ink" : "text-muted"
                    }`}
                  >
                    {g.name}
                  </span>
                  <span className="block text-[11px] text-faint">
                    {g.environments.length} env{g.environments.length === 1 ? "" : "s"}
                  </span>
                </span>
              </button>
            ))}
          </div>

          <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
            {group ? (
              <>
                <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line px-5 py-3">
                  <span className="mono text-[13.5px] font-semibold text-ink">{group.name}</span>
                  {drifted ? (
                    <Badge tone="warn">
                      drift · {driftCount} key{driftCount === 1 ? "" : "s"}
                    </Badge>
                  ) : diff ? (
                    <Badge tone="success">in sync</Badge>
                  ) : null}
                  <span className="flex-1" />
                  <div className="flex items-center gap-0.5 rounded-tv-sm border border-line bg-raised p-0.5">
                    {(["keys", "values"] as const).map((m) => (
                      <button
                        key={m}
                        onClick={() => setMode(m)}
                        title={
                          m === "keys"
                            ? "Compare key sets only"
                            : "Also compare values — reports same/different, never prints them"
                        }
                        className={`h-6 rounded px-2 text-[11.5px] transition-colors ${
                          mode === m ? "bg-accent-soft text-accent" : "text-faint hover:text-ink"
                        }`}
                      >
                        {m === "keys" ? "key sets" : "key sets + values"}
                      </button>
                    ))}
                  </div>
                  {readOnly ? <Badge tone="warn">read-only policy</Badge> : null}
                  <Button
                    size="sm"
                    icon="plus"
                    disabled={readOnly || mutating}
                    title={tip("Link an existing project as another environment")}
                    onClick={() => setAddEnv(true)}
                  >
                    Add env
                  </Button>
                  <Button
                    size="sm"
                    icon="branch"
                    disabled={readOnly || mutating || group.environments.length < 2}
                    title={tip("Set which environment inherits from which, and pin or unpin keys")}
                    onClick={() => setInheritOpen(true)}
                  >
                    Inheritance
                  </Button>
                  <Button
                    size="sm"
                    icon="lock"
                    disabled={readOnly || mutating || group.environments.length === 0}
                    title={tip("Write one commit-safe .env.encrypted for these environments")}
                    onClick={() => setSealOpen(true)}
                  >
                    Seal
                  </Button>
                  <Button
                    size="sm"
                    variant="primary"
                    icon="arrowRight"
                    disabled={readOnly || group.environments.length < 2}
                    title={tip("Copy values from one environment to another")}
                    onClick={() => setPromote(true)}
                  >
                    Promote
                  </Button>
                  <IconButton
                    icon="trash"
                    tone="danger"
                    disabled={readOnly || mutating}
                    label={
                      readOnly
                        ? `Delete group ${group.name} — ${READ_ONLY_HINT}`
                        : `Delete group ${group.name} (metadata only — no project, no secret)`
                    }
                    onClick={() => setConfirm({ kind: "group" })}
                  />
                </div>

                <div className="flex shrink-0 flex-wrap gap-1.5 border-b border-line px-5 py-2.5">
                  {group.environments.length === 0 ? (
                    <span className="text-[11.5px] text-faint">
                      No environments linked — the group still exists, but there is nothing to
                      compare. Add one to link an existing project again.
                    </span>
                  ) : null}
                  {group.environments.map((e) => {
                    const base = inheritance?.[e.name];
                    return (
                      <span
                        key={e.name}
                        className="inline-flex items-center gap-1.5 rounded-full border border-line bg-raised py-0.5 pl-2.5 pr-1"
                        title={e.project}
                      >
                        <span className="text-[11.5px] font-medium text-ink">{e.name}</span>
                        <span className="mono text-[11px] text-faint">→ {e.project}</span>
                        {base ? (
                          <span className="mono inline-flex items-center gap-1 text-[11px] text-accent">
                            <Icon name="branch" size={10} /> ← {base}
                          </span>
                        ) : null}
                        <IconButton
                          icon="x"
                          tone="danger"
                          className="h-5 w-5"
                          disabled={readOnly || mutating}
                          label={
                            readOnly
                              ? `Unlink ${e.name} — ${READ_ONLY_HINT}`
                              : `Unlink ${e.name} from this group — keeps ${e.project} and all of its secrets`
                          }
                          onClick={() => setConfirm({ kind: "env", env: e.name })}
                        />
                      </span>
                    );
                  })}
                </div>

                <div className="flex shrink-0 flex-wrap items-center gap-x-2.5 gap-y-1 border-b border-line px-5 py-1.5 text-[11.5px] text-faint">
                  <span className="inline-flex items-center gap-1.5">
                    <Icon name="shield" size={12} /> Recorded
                  </span>
                  {recorded ? (
                    <Tooltip
                      side="bottom"
                      label={
                        recorded === "unknown"
                          ? UNKNOWN_STATUS_HINT
                          : "What the server stored the last time it compared this group. The badge above is computed live, in this window."
                      }
                    >
                      <Badge tone={RECORDED_TONE[recorded] ?? "neutral"}>{recorded}</Badge>
                    </Tooltip>
                  ) : (
                    <span>—</span>
                  )}
                  {detail?.description ? (
                    <span className="min-w-0 truncate text-muted" title={detail.description}>
                      {detail.description}
                    </span>
                  ) : null}
                  <span className="flex-1" />
                  {detailError ? <span className="mono text-danger">{detailError}</span> : null}
                </div>

                <div className="min-h-0 flex-1 overflow-auto">
                  {diffing ? (
                    <div className="flex h-32 items-center justify-center gap-2.5 text-muted">
                      <Spinner /> <span className="text-[12.5px]">Comparing environments…</span>
                    </div>
                  ) : diffError ? (
                    <div className="m-5 rounded-tv-md border border-danger/30 bg-danger/8 px-4 py-3">
                      <p className="mono text-[11.5px] text-danger">{diffError}</p>
                    </div>
                  ) : !diff || diff.keys.length === 0 ? (
                    <EmptyState icon="diff" title="No keys to compare" />
                  ) : (
                    <DiffMatrix diff={diff} />
                  )}
                </div>
              </>
            ) : null}
          </div>
        </div>
      )}

      {/* Outside the `group` guard on purpose: it has to be reachable when the
          vault has no groups at all, which is when it is needed most. */}
      <CreateGroupModal
        open={createOpen}
        groups={groups}
        projects={projects}
        linked={linkedProjects}
        readOnly={readOnly}
        onClose={() => setCreateOpen(false)}
        onDone={onCreated}
      />

      {group ? (
        <>
          <PromoteModal
            open={promote}
            group={group}
            onClose={() => setPromote(false)}
            onDone={(res) => {
              toast.success(
                `Promoted ${res.promoted.length} key${res.promoted.length === 1 ? "" : "s"}`,
                res.skipped.length > 0 ? `${res.skipped.length} skipped` : undefined
              );
              void runDiff(group.name, mode);
              onChanged();
            }}
          />

          <AddEnvironmentModal
            open={addEnv}
            group={group}
            projects={projects}
            linked={linkedProjects}
            readOnly={readOnly}
            onClose={() => setAddEnv(false)}
            onDone={(updated) => {
              applyGroup(updated);
              onChanged();
            }}
          />

          <InheritanceModal
            open={inheritOpen}
            group={group}
            inheritance={inheritance}
            readOnly={readOnly}
            onClose={() => setInheritOpen(false)}
            onMutated={() => {
              setDetailEpoch((n) => n + 1);
              void runDiff(group.name, mode);
              onChanged();
            }}
          />

          <SealModal
            open={sealOpen}
            group={group}
            availableKeys={sealKeys}
            readOnly={readOnly}
            onClose={() => setSealOpen(false)}
            onSealed={(res) => {
              toast.success(
                `Sealed ${res.environments.length} environment${res.environments.length === 1 ? "" : "s"}`,
                `${res.bytes} bytes to ${res.recipient_count} recipient${res.recipient_count === 1 ? "" : "s"} — ciphertext only`
              );
              onChanged();
            }}
          />

          <ConfirmModal
            open={confirm !== null}
            group={group}
            request={confirm}
            inheritance={inheritance}
            busy={mutating}
            onClose={() => setConfirm(null)}
            onConfirm={() => void runConfirm()}
          />
        </>
      ) : null}
    </div>
  );
}

/**
 * The two membership edits that sound like data loss. Neither is: unlinking
 * drops a pointer, deleting a group drops the pointer list. The copy says so
 * before the button is reachable, because "remove environment from group" reads
 * like "delete my production secrets" if you are in a hurry.
 */
function ConfirmModal({
  open,
  group,
  request,
  inheritance,
  busy,
  onClose,
  onConfirm
}: {
  open: boolean;
  group: EnvGroupDetail;
  request: ConfirmRequest | null;
  inheritance?: Record<string, string>;
  busy: boolean;
  onClose: () => void;
  onConfirm: () => void;
}): React.JSX.Element | null {
  if (!open || !request) return null;

  const env =
    request.kind === "env"
      ? (group.environments.find((e) => e.name === request.env) ?? null)
      : null;
  const base = env ? inheritance?.[env.name] : undefined;
  const count = group.environments.length;

  const title = env ? "Unlink this environment?" : "Delete this environment group?";
  const subtitle = env ? `${group.name} · ${env.name}` : group.name;
  const body = env
    ? `This removes the link between the group and the project ${env.project}. That project stays in the vault and every secret in it stays exactly as it is — nothing is decrypted, moved, re-keyed or deleted.`
    : `This deletes the group's metadata only: its list of ${count} environment${count === 1 ? "" : "s"}, its description and its inheritance pointers. The ${count} linked project${count === 1 ? "" : "s"} stay in the vault with all their secrets — nothing is decrypted, moved, re-keyed or deleted.`;

  return (
    <Modal
      open
      title={title}
      subtitle={subtitle}
      onClose={onClose}
      width="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" icon="trash" disabled={busy} onClick={onConfirm}>
            {busy
              ? env
                ? "Unlinking…"
                : "Deleting…"
              : env
                ? `Unlink ${env.name}`
                : `Delete ${group.name}`}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-[13px] leading-relaxed text-muted">{body}</p>
        <Note tone="warn" icon="alert">
          {env ? (
            <>
              The drift matrix will no longer cover <span className="mono">{env.name}</span>
              {base ? (
                <>
                  , and its inheritance pointer (
                  <span className="mono">{`${env.name} ← ${base}`}</span>) goes with the link
                </>
              ) : null}
              . Keys it had of its own are untouched; re-link the same project at any time.
            </>
          ) : (
            <>
              Blobs you already sealed for this group stay openable with a matching identity —
              deleting the group does not reach into files on disk.
            </>
          )}
        </Note>
      </div>
    </Modal>
  );
}

/** One editable environment row in the create dialog. `id` keeps React keys stable across removals. */
type EnvRow = { id: number; name: string; project: string };

/**
 * Creating a group is pure metadata: a name, an optional description, and a list
 * of environment → project links. Projects are offered as a select, never as a
 * text field, so a typo cannot name a project that does not exist and the "must
 * already exist" rule cannot be tripped by accident.
 *
 * `force` is off until deliberately switched on, and switching it on restates
 * both of its effects — overwriting a same-named group and pulling projects out
 * of the groups that currently claim them. When it would overwrite, the primary
 * button stops saying "Create".
 */
function CreateGroupModal({
  open,
  groups,
  projects,
  linked,
  readOnly,
  onClose,
  onDone
}: {
  open: boolean;
  groups: EnvGroupDetail[];
  projects: string[];
  linked: Map<string, string>;
  readOnly: boolean;
  onClose: () => void;
  onDone: (created: EnvGroupDetail) => void;
}): React.JSX.Element | null {
  const toast = useToast();
  const rowId = useRef(1);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [rows, setRows] = useState<EnvRow[]>([]);
  const [force, setForce] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    rowId.current = 1;
    setName("");
    setDescription("");
    setForce(false);
    setErr(null);
    setRows([{ id: 0, name: "", project: projects[0] ?? "" }]);
  }, [open, projects]);

  if (!open) return null;

  const groupName = name.trim();
  // Main drops rows missing either half before the tool ever sees them, so only
  // these travel — and the dropped count is worth saying out loud.
  const complete = rows
    .map((r) => ({ name: r.name.trim(), project: r.project }))
    .filter((r) => r.name !== "" && r.project !== "");
  const dropped = rows.length - complete.length;
  const dupe = complete.find((r, i) => complete.findIndex((o) => o.name === r.name) !== i);
  const clash = groups.some((g) => g.name === groupName);
  const claimed = complete.filter((r) => {
    const owner = linked.get(r.project);
    return owner !== undefined && owner !== groupName;
  });

  const blocker =
    projects.length === 0
      ? "This vault has no projects yet. A group links projects that already exist — create one on the Projects screen first."
      : complete.length === 0
        ? "A group needs at least one environment linked to a project. A row missing either half is ignored."
        : dupe
          ? `Environment name ${dupe.name} appears twice — each one must be unique within the group.`
          : clash && !force
            ? `Group ${groupName} already exists. Force overwrites it.`
            : claimed.length > 0 && !force
              ? `${claimed[0].project} already belongs to group ${linked.get(claimed[0].project)}. A project links to one group at a time unless force re-links it.`
              : null;

  const canSubmit = !readOnly && !busy && groupName !== "" && blocker === null;

  const setRow = (id: number, patch: Partial<Omit<EnvRow, "id">>): void => {
    setRows((prev) => prev.map((r) => (r.id === id ? { ...r, ...patch } : r)));
    setErr(null);
  };

  const submit = async (): Promise<void> => {
    setBusy(true);
    setErr(null);
    try {
      const created = await unwrap(
        window.tvault.envGroupCreate({
          name: groupName,
          description: description.trim() === "" ? undefined : description.trim(),
          environments: complete,
          force
        })
      );
      toast.success(
        `Created group ${created.name}`,
        `${created.environments.length} environment${created.environments.length === 1 ? "" : "s"} linked to existing projects. No project was created and no secret was read.`
      );
      onDone(created);
      onClose();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setErr(msg);
      toast.error("Could not create group", msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      title="New environment group"
      subtitle="Links existing projects as environments of one application"
      onClose={onClose}
      width="max-w-xl"
      footer={
        <>
          {readOnly ? <Badge tone="warn">read-only policy</Badge> : null}
          <span className="flex-1" />
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" icon="plus" disabled={!canSubmit} onClick={() => void submit()}>
            {busy ? "Creating…" : clash && force ? "Overwrite group" : "Create group"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Group name" hint="e.g. myapp — the name the drift matrix is filed under.">
          <TextInput
            mono
            value={name}
            spellCheck={false}
            autoComplete="off"
            placeholder="myapp"
            onChange={(e) => {
              setName(e.target.value);
              setErr(null);
            }}
          />
        </Field>

        <div className="space-y-1.5">
          <p className="text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
            Environments — one row per linked project
          </p>
          {rows.map((r, i) => (
            <div key={r.id} className="flex items-center gap-2">
              <TextInput
                mono
                className="w-40 shrink-0"
                value={r.name}
                spellCheck={false}
                autoComplete="off"
                placeholder={i === 0 ? "production" : "preview"}
                onChange={(e) => setRow(r.id, { name: e.target.value })}
              />
              <select
                value={r.project}
                onChange={(e) => setRow(r.id, { project: e.target.value })}
                className="mono h-9 min-w-0 flex-1 rounded-tv-sm border border-line bg-raised px-2.5 text-[12.5px] text-ink focus:border-accent focus:outline-none"
              >
                {r.project === "" ? <option value="">Choose a project…</option> : null}
                {projects.map((p) => {
                  const owner = linked.get(p);
                  const elsewhere = owner !== undefined && owner !== groupName;
                  return (
                    <option key={p} value={p} disabled={elsewhere && !force}>
                      {p}
                      {elsewhere ? ` — already in ${owner}` : ""}
                    </option>
                  );
                })}
              </select>
              <IconButton
                icon="trash"
                tone="danger"
                disabled={rows.length === 1}
                label={
                  rows.length === 1
                    ? "A group needs at least one environment"
                    : `Remove the ${r.name.trim() || "untitled"} row`
                }
                onClick={() => setRows((prev) => prev.filter((row) => row.id !== r.id))}
              />
            </div>
          ))}
          <Button
            size="sm"
            icon="plus"
            disabled={busy}
            onClick={() =>
              setRows((prev) => [
                ...prev,
                {
                  id: rowId.current++,
                  name: "",
                  // Preselect the first project this form is not already using.
                  project: projects.find((p) => !prev.some((r) => r.project === p)) ?? ""
                }
              ])
            }
          >
            Add environment
          </Button>
        </div>

        {dropped > 0 ? (
          <Note tone="warn" icon="alert">
            {dropped} row{dropped === 1 ? "" : "s"} still missing a name or a project — the server
            needs both halves, so {dropped === 1 ? "that row is" : "those rows are"} ignored.
          </Note>
        ) : null}

        <Field label="Description" hint="Optional. Shown on the group's detail line.">
          <TextInput
            value={description}
            autoComplete="off"
            placeholder="One application, three environments"
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>

        <label className="flex cursor-pointer items-start gap-2 text-[12px] leading-relaxed text-muted">
          <input
            type="checkbox"
            checked={force}
            onChange={(e) => {
              setForce(e.target.checked);
              setErr(null);
            }}
            className="mt-0.5 accent-[var(--tv-accent)]"
          />
          <span>
            <strong className="font-medium text-ink">Force</strong> — off by default. Overwrites a
            group already called <span className="mono">{groupName || "this name"}</span>, and
            re-links projects that another group currently claims.
          </span>
        </label>
        {force ? (
          <Note tone="warn" icon="alert">
            Force is on. A group already called <span className="mono">{groupName || "this name"}</span>{" "}
            is replaced wholesale — its environment list, description and inheritance pointers go
            with it — and any project claimed by another group leaves that group and joins this one.
            Projects and their secrets are never touched; only the links move.
          </Note>
        ) : null}

        <Note>
          This writes metadata only: a name, an optional description and a list of environment →
          project links. It creates no project, and there is no secret value anywhere in this dialog
          to read or write.
        </Note>

        {err ?? blocker ? (
          <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
            {err ?? blocker}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}

/**
 * Linking an environment means pointing the group at a project that already
 * exists; the server will not create one, and it refuses a project another group
 * already claims. Both rules are stated here so the refusal is not a surprise.
 */
function AddEnvironmentModal({
  open,
  group,
  projects,
  linked,
  readOnly,
  onClose,
  onDone
}: {
  open: boolean;
  group: EnvGroupDetail;
  projects: string[];
  linked: Map<string, string>;
  readOnly: boolean;
  onClose: () => void;
  onDone: (updated: EnvGroupDetail) => void;
}): React.JSX.Element | null {
  const toast = useToast();
  const [envName, setEnvName] = useState("");
  const [project, setProject] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setEnvName("");
    setErr(null);
    setProject(projects.find((p) => !linked.has(p)) ?? "");
  }, [open, projects, linked]);

  if (!open) return null;

  const name = envName.trim();
  const clash = group.environments.some((e) => e.name === name);
  const owner = linked.get(project);
  const elsewhere = owner !== undefined && owner !== group.name ? owner : null;
  const canSubmit = !readOnly && !busy && name !== "" && project !== "" && !clash && !elsewhere;

  // Stated before the call, because the server would refuse it anyway and a bare
  // failure message is a poor way to learn the two membership rules.
  const blocker = clash
    ? `${group.name} already has an environment called ${name}.`
    : elsewhere
      ? `${project} already belongs to group ${elsewhere} — a project links to one group at a time.`
      : projects.length === 0
        ? "This vault has no projects yet. Create one on the Projects screen first, then link it here."
        : null;

  const submit = async (): Promise<void> => {
    setBusy(true);
    setErr(null);
    try {
      const updated = await unwrap(window.tvault.envGroupAdd(group.name, name, project));
      toast.success(
        `Linked ${name}`,
        `${project} is now an environment of ${group.name}. No secret was read or written.`
      );
      onDone(updated);
      onClose();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setErr(msg);
      toast.error("Could not add environment", msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      title="Add an environment"
      subtitle={group.name}
      onClose={onClose}
      width="max-w-lg"
      footer={
        <>
          {readOnly ? <Badge tone="warn">read-only policy</Badge> : null}
          <span className="flex-1" />
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" icon="plus" disabled={!canSubmit} onClick={() => void submit()}>
            {busy ? "Linking…" : "Link project"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Environment name" hint="How this environment is labelled in the drift matrix, e.g. preview.">
          <TextInput
            mono
            value={envName}
            spellCheck={false}
            autoComplete="off"
            placeholder="preview"
            onChange={(e) => {
              setEnvName(e.target.value);
              setErr(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && canSubmit) void submit();
            }}
          />
        </Field>

        <Field label="Project">
          <select
            value={project}
            onChange={(e) => {
              setProject(e.target.value);
              setErr(null);
            }}
            className="mono h-9 w-full rounded-tv-sm border border-line bg-raised px-2.5 text-[12.5px] text-ink focus:border-accent focus:outline-none"
          >
            {project === "" ? <option value="">Choose a project…</option> : null}
            {projects.map((p) => {
              const claimedBy = linked.get(p);
              const blocked = claimedBy !== undefined && claimedBy !== group.name;
              return (
                <option key={p} value={p} disabled={blocked}>
                  {p}
                  {blocked
                    ? ` — already in ${claimedBy}`
                    : claimedBy === group.name
                      ? " — in this group"
                      : ""}
                </option>
              );
            })}
          </select>
        </Field>

        <Note>
          Adding an environment links a project that <em>already exists</em> — this never creates
          one, and it never reads or writes a secret. A project belongs to at most one group, so
          projects claimed elsewhere are listed but disabled. Unlinking later removes only the
          pointer.
        </Note>

        {err ?? blocker ? (
          <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
            {err ?? blocker}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}

/**
 * Inheritance: a child environment resolves a key it does not have from its base.
 * Pinning writes the resolved value into the child so it stops following the
 * base; unpinning deletes that copy so it follows again. Both report `{}` — the
 * value moves between two projects' DEKs and is never handed to this window, so
 * there is deliberately nothing here that could display one.
 */
function InheritanceModal({
  open,
  group,
  inheritance,
  readOnly,
  onClose,
  onMutated
}: {
  open: boolean;
  group: EnvGroupDetail;
  inheritance?: Record<string, string>;
  readOnly: boolean;
  onClose: () => void;
  onMutated: () => void;
}): React.JSX.Element | null {
  const toast = useToast();
  const envs = group.environments;
  const [child, setChild] = useState(envs[0]?.name ?? "");
  const [base, setBase] = useState(envs[1]?.name ?? "");
  const [rows, setRows] = useState<InheritedKey[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(false);
  const [keysError, setKeysError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [epoch, setEpoch] = useState(0);

  useEffect(() => {
    if (!open) return;
    setChild(envs[0]?.name ?? "");
    setBase(envs[1]?.name ?? "");
  }, [open, envs]);

  // Pinned/unpinned flips the list, and switching child races the previous
  // request — same generation guard as the diff matrix.
  const keysGen = useRef(0);

  const loadKeys = useCallback(
    async (env: string): Promise<void> => {
      const gen = ++keysGen.current;
      setLoadingKeys(true);
      setKeysError(null);
      try {
        const list = await unwrap(window.tvault.envInherited(group.name, env));
        if (gen !== keysGen.current) return;
        setRows(list);
      } catch (err) {
        if (gen !== keysGen.current) return;
        setRows([]);
        setKeysError(err instanceof Error ? err.message : String(err));
      } finally {
        if (gen === keysGen.current) setLoadingKeys(false);
      }
    },
    [group.name]
  );

  useEffect(() => {
    if (!open || !child) {
      setRows([]);
      return;
    }
    void loadKeys(child);
  }, [open, child, epoch, loadKeys]);

  if (!open) return null;

  const currentBase = inheritance?.[child];
  const canSet = !readOnly && !busy && child !== "" && base !== "" && child !== base;

  const applyInheritance = async (): Promise<void> => {
    setBusy(true);
    try {
      const res = await unwrap(window.tvault.envInherit(group.name, child, base));
      toast.success(
        `${res.env} now inherits from ${res.inherits_from}`,
        "Keys the child does not have of its own resolve from the base. No value is shown here."
      );
      setEpoch((n) => n + 1);
      onMutated();
    } catch (err) {
      toast.error("Could not set inheritance", err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const flipPin = async (key: string, pin: boolean): Promise<void> => {
    setBusy(true);
    try {
      await unwrap(
        pin
          ? window.tvault.envPin(group.name, child, key)
          : window.tvault.envUnpin(group.name, child, key)
      );
      toast.success(
        pin ? `Pinned ${key} in ${child}` : `Unpinned ${key} in ${child}`,
        pin
          ? `${child} keeps its own copy from now on. The value moved server-side and was never returned.`
          : `${child} follows ${currentBase ?? "its base"} again for this key.`
      );
      setEpoch((n) => n + 1);
      onMutated();
    } catch (err) {
      toast.error(pin ? "Pin failed" : "Unpin failed", err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const envSelect = (value: string, onChange: (v: string) => void, exclude?: string) => (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-9 w-full rounded-tv-sm border border-line bg-raised px-2.5 text-[12.5px] text-ink focus:border-accent focus:outline-none"
    >
      {envs
        .filter((e) => e.name !== exclude)
        .map((e) => (
          <option key={e.name} value={e.name}>
            {e.name} ({e.project})
          </option>
        ))}
    </select>
  );

  return (
    <Modal
      open
      title="Inheritance"
      subtitle={group.name}
      onClose={onClose}
      width="max-w-2xl"
      footer={
        <>
          {readOnly ? <Badge tone="warn">read-only policy</Badge> : null}
          <span className="flex-1" />
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Close
          </Button>
          <Button
            variant="primary"
            icon="branch"
            disabled={!canSet}
            onClick={() => void applyInheritance()}
          >
            {busy ? "Working…" : "Set inheritance"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Child" hint="Resolves keys it does not have of its own.">
            {envSelect(child, (v) => {
              setChild(v);
              // The base list excludes the child, so a base that just became the
              // child would leave the select showing nothing.
              if (base === v) setBase(envs.find((e) => e.name !== v)?.name ?? "");
            })}
          </Field>
          <Field label="Inherits from" hint="The base environment.">
            {envSelect(base, setBase, child)}
          </Field>
        </div>
        {currentBase ? (
          <Note>
            <span className="mono">{child}</span> currently inherits from{" "}
            <span className="mono">{currentBase}</span>. Setting a new base replaces that pointer.
          </Note>
        ) : null}

        <div className="space-y-2">
          <p className="text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
            Keys in {child || "—"}
          </p>
          {loadingKeys ? (
            <div className="flex h-20 items-center justify-center gap-2.5 text-muted">
              <Spinner /> <span className="text-[12.5px]">Resolving key sources…</span>
            </div>
          ) : keysError ? (
            <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
              {keysError}
            </p>
          ) : rows.length === 0 ? (
            <p className="rounded-tv-sm border border-line bg-soft/60 px-3 py-2.5 text-[12px] text-faint">
              Nothing to resolve yet.
            </p>
          ) : (
            <ul className="max-h-56 space-y-1 overflow-y-auto">
              {rows.map((r) => {
                const from = r.source.startsWith("inherited:") ? r.source.slice(10) : null;
                const unpinBlocked = !currentBase;
                return (
                  <li
                    key={r.key}
                    className="flex items-center gap-2 rounded-tv-sm border border-line bg-raised px-3 py-1.5"
                  >
                    <span className="mono min-w-0 flex-1 truncate text-[12px] text-ink">{r.key}</span>
                    <Badge tone={r.source === "missing" ? "danger" : from ? "accent" : "neutral"}>
                      {r.source === "missing" ? "missing" : from ? `from ${from}` : "own copy"}
                    </Badge>
                    <IconButton
                      icon="save"
                      disabled={readOnly || busy || !from}
                      label={
                        readOnly
                          ? `Pin ${r.key} — ${READ_ONLY_HINT}`
                          : from
                            ? `Pin ${r.key}: write the value resolved from ${from} into ${child}, so it stops following the base`
                            : `${r.key} is not resolved from a base, so there is nothing to pin`
                      }
                      onClick={() => void flipPin(r.key, true)}
                    />
                    <IconButton
                      icon="branch"
                      disabled={readOnly || busy || !r.pinned || unpinBlocked}
                      label={
                        readOnly
                          ? `Unpin ${r.key} — ${READ_ONLY_HINT}`
                          : !r.pinned
                            ? `${r.key} has no copy of its own in ${child}`
                            : unpinBlocked
                              ? `${child} has no base to fall back to, so unpinning would leave ${r.key} missing here`
                              : `Unpin ${r.key}: delete ${child}'s own copy so it follows ${currentBase} again`
                      }
                      onClick={() => void flipPin(r.key, false)}
                    />
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <Note>
          <strong className="font-medium text-ink">Pin</strong> copies the value resolved from the
          base into the child, breaking inheritance for that one key.{" "}
          <strong className="font-medium text-ink">Unpin</strong> deletes the child's own copy so the
          base applies again. Both happen inside the vault; neither returns the value, and nothing on
          this screen can show one.
        </Note>
        <Note tone="warn" icon="alert">
          Unpinning deletes that key from the child project, including its version history there —
          the base's copy is untouched, which is why unpin is only offered where a base exists.
        </Note>
      </div>
    </Modal>
  );
}

/**
 * One commit-safe v2 blob for the whole group. The output path can only come
 * from a save dialog answered in main (`pickSaveFile`); main refuses any path it
 * did not issue, so there is no text field here and never will be.
 */
function SealModal({
  open,
  group,
  availableKeys,
  readOnly,
  onClose,
  onSealed
}: {
  open: boolean;
  group: EnvGroupDetail;
  availableKeys: string[];
  readOnly: boolean;
  onClose: () => void;
  onSealed: (res: EnvSealResult) => void;
}): React.JSX.Element | null {
  const toast = useToast();
  const [identities, setIdentities] = useState<IdentityEntry[]>([]);
  const [shared, setShared] = useState<string[]>([]);
  const [loadingRecipients, setLoadingRecipients] = useState(false);
  const [recipientsError, setRecipientsError] = useState<string | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [keys, setKeys] = useState<string[]>([]);
  const [envs, setEnvs] = useState<string[]>([]);
  const [path, setPath] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<EnvSealResult | null>(null);

  useEffect(() => {
    if (!open) return;
    let live = true;
    setPicked([]);
    setKeys([]);
    setEnvs([]);
    setPath(null);
    setErr(null);
    setResult(null);
    setLoadingRecipients(true);
    setRecipientsError(null);
    void (async (): Promise<void> => {
      try {
        const ids = await unwrap(window.tvault.identities());
        // Public halves already wrapped to this group's projects are the obvious
        // default audience; a project that cannot be read is simply skipped.
        const lists = await Promise.all(
          group.environments.map((e) =>
            unwrap(window.tvault.recipients(e.project)).catch((): string[] => [])
          )
        );
        if (!live) return;
        setIdentities(ids);
        setShared([...new Set(lists.flat())]);
      } catch (e) {
        if (!live) return;
        setRecipientsError(e instanceof Error ? e.message : String(e));
      } finally {
        if (live) setLoadingRecipients(false);
      }
    })();
    return () => {
      live = false;
    };
  }, [open, group]);

  if (!open) return null;

  const toggle = (list: string[], set: (v: string[]) => void) => (value: string): void => {
    set(list.includes(value) ? list.filter((v) => v !== value) : [...list, value]);
  };

  const recipientOptions = [
    ...identities.map((id) => ({ value: id.recipient, label: id.name, hint: "your identity" })),
    ...shared
      .filter((r) => !identities.some((id) => id.recipient === r))
      .map((r) => ({ value: r, label: `${r.slice(0, 20)}…`, hint: "already shared" }))
  ];

  const choosePath = async (): Promise<void> => {
    setPicking(true);
    setErr(null);
    try {
      const chosen = await unwrap(
        window.tvault.pickSaveFile(`Seal ${group.name} environments`, `${group.name}.env.encrypted`)
      );
      // null is a cancelled dialog, not a failure: keep whatever was chosen.
      if (chosen !== null) setPath(chosen);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setErr(msg);
      toast.error("Could not open the save dialog", msg);
    } finally {
      setPicking(false);
    }
  };

  const seal = async (): Promise<void> => {
    if (picked.length === 0) {
      setErr("Choose at least one recipient.");
      return;
    }
    if (path === null) {
      setErr("Choose where to write the sealed file — the path can only come from the save dialog.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const res = await unwrap(
        window.tvault.envSeal({
          group: group.name,
          recipients: picked,
          keys: keys.length > 0 ? keys : undefined,
          envs: envs.length > 0 ? envs : undefined,
          outputPath: path
        })
      );
      setResult(res);
      onSealed(res);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setErr(msg);
      toast.error("Seal failed", msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      title="Seal environments"
      subtitle={group.name}
      onClose={onClose}
      width="max-w-2xl"
      footer={
        result ? (
          <Button variant="primary" icon="check" onClick={onClose}>
            Done
          </Button>
        ) : (
          <>
            {readOnly ? <Badge tone="warn">read-only policy</Badge> : null}
            <span className="flex-1" />
            <Button variant="ghost" onClick={onClose} disabled={busy || picking}>
              Close
            </Button>
            <Button
              variant="default"
              icon="save"
              disabled={busy || picking || readOnly}
              title={readOnly ? READ_ONLY_HINT : undefined}
              onClick={() => void choosePath()}
            >
              {picking ? "Choosing…" : path ? "Change file…" : "Choose file…"}
            </Button>
            <Button
              variant="primary"
              icon="lock"
              disabled={busy || readOnly || picked.length === 0 || path === null}
              onClick={() => void seal()}
            >
              {busy ? "Sealing…" : "Seal"}
            </Button>
          </>
        )
      }
    >
      {result ? (
        <div className="space-y-3">
          <div className="rounded-tv-sm border border-success/30 bg-success/8 px-3.5 py-3">
            <p className="mono break-all text-[12px] font-medium text-success">
              {result.path ?? path}
            </p>
            <p className="mt-1.5 text-[12px] text-muted">
              {result.bytes} bytes · {result.environments.length} environment
              {result.environments.length === 1 ? "" : "s"} · {result.keys.length} key
              {result.keys.length === 1 ? "" : "s"} · {result.recipient_count} recipient
              {result.recipient_count === 1 ? "" : "s"}
            </p>
            <p className="mono mt-2 break-all text-[11px] leading-relaxed text-faint">
              envs: {result.environments.join(", ")}
            </p>
            <p className="mono mt-1 break-all text-[11px] leading-relaxed text-faint">
              keys: {result.keys.join(", ")}
            </p>
          </div>
          <Note>
            That file is a v2 <span className="mono">.env.encrypted</span> blob: ciphertext whose
            per-file key is wrapped to each recipient's X25519 public key, with no passphrase-derived
            key involved. It is safe to commit, and only a matching identity can open it (
            <span className="mono">tvault decrypt-env --identity</span>).
          </Note>
          <Note tone="warn" icon="alert">
            Removing a recipient later re-keys the live vault but does <em>not</em> retroactively
            invalidate this file — whoever holds it can still open it. If a recipient is compromised,
            rotate the underlying credentials and seal a new blob.
          </Note>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="space-y-1.5">
            <p className="text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
              Recipients — public halves only
            </p>
            {loadingRecipients ? (
              <div className="flex h-16 items-center justify-center gap-2.5 text-muted">
                <Spinner /> <span className="text-[12.5px]">Loading recipients…</span>
              </div>
            ) : (
              <CheckList
                options={recipientOptions}
                selected={picked}
                onToggle={toggle(picked, setPicked)}
                empty="No identities and no shared recipients. Create an identity on the Sharing screen first — sealing needs at least one public key."
              />
            )}
            {recipientsError ? (
              <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
                {recipientsError}
              </p>
            ) : null}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <p className="text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
                Environments — empty means all
              </p>
              <CheckList
                maxHeight="max-h-32"
                options={group.environments.map((e) => ({
                  value: e.name,
                  label: e.name,
                  hint: e.project
                }))}
                selected={envs}
                onToggle={toggle(envs, setEnvs)}
              />
            </div>
            <div className="space-y-1.5">
              <p className="text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
                Keys — empty means all
              </p>
              <CheckList
                maxHeight="max-h-32"
                options={availableKeys.map((k) => ({ value: k, label: k }))}
                selected={keys}
                onToggle={toggle(keys, setKeys)}
                empty="No key names loaded — the diff has not run or found nothing. Leave this empty to seal every key."
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <p className="text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
              Write to
            </p>
            <p className="mono break-all rounded-tv-sm border border-line bg-soft/60 px-3 py-2 text-[11.5px] text-muted">
              {path ?? "No file chosen yet — the save dialog is the only source of a path."}
            </p>
          </div>

          <Note>
            Main writes the ciphertext to that file itself; only the path, the byte count and the key
            names come back. No plaintext and no blob ever crosses into this window.
          </Note>

          {err ? (
            <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
              {err}
            </p>
          ) : null}
        </div>
      )}
    </Modal>
  );
}

/** Checkbox list shared by the seal dialog's recipients, environments and keys. */
function CheckList({
  options,
  selected,
  onToggle,
  maxHeight = "max-h-40",
  empty = "Nothing to choose from."
}: {
  options: { value: string; label: string; hint?: string }[];
  selected: string[];
  onToggle: (value: string) => void;
  maxHeight?: string;
  empty?: string;
}): React.JSX.Element {
  if (options.length === 0) {
    return (
      <p className="rounded-tv-sm border border-line bg-soft/60 px-3 py-2.5 text-[12px] leading-relaxed text-faint">
        {empty}
      </p>
    );
  }
  return (
    <ul className={`${maxHeight} space-y-1 overflow-y-auto`}>
      {options.map((o) => {
        const on = selected.includes(o.value);
        return (
          <li key={o.value}>
            <label
              className={`flex cursor-pointer items-center gap-2 rounded-tv-sm border px-3 py-1.5 transition-colors ${
                on ? "border-accent-line bg-accent-soft" : "border-line bg-raised hover:bg-soft"
              }`}
            >
              <input
                type="checkbox"
                checked={on}
                onChange={() => onToggle(o.value)}
                className="accent-[var(--tv-accent)]"
              />
              <span
                className={`mono min-w-0 flex-1 truncate text-[12px] ${on ? "text-accent" : "text-ink"}`}
              >
                {o.label}
              </span>
              {o.hint ? <span className="shrink-0 text-[11px] text-faint">{o.hint}</span> : null}
            </label>
          </li>
        );
      })}
    </ul>
  );
}

/** Explainer box. `warn` is for the sentence a user must not skip past. */
function Note({
  tone = "info",
  icon = "shield",
  children
}: {
  tone?: "info" | "warn";
  icon?: IconName;
  children: ReactNode;
}): React.JSX.Element {
  const box = tone === "warn" ? "border-warn/30 bg-warn/8" : "border-line bg-soft/60";
  const glyph = tone === "warn" ? "text-warn" : "text-faint";
  return (
    <div className={`flex items-start gap-2.5 rounded-tv-sm border px-3.5 py-2.5 ${box}`}>
      <span className={`mt-0.5 ${glyph}`}>
        <Icon name={icon} size={13} />
      </span>
      <p className="text-[12px] leading-relaxed text-muted">{children}</p>
    </div>
  );
}

function DiffMatrix({ diff }: { diff: EnvDiffResult }): React.JSX.Element {
  const envs = useMemo(() => {
    const seen: string[] = [];
    for (const k of diff.keys) for (const e of k.environments) if (!seen.includes(e.env)) seen.push(e.env);
    return seen;
  }, [diff]);

  const [onlyDrift, setOnlyDrift] = useState(false);

  const rows = useMemo(() => {
    const list = onlyDrift
      ? diff.keys.filter((k) =>
          k.environments.some((e) => e.status === "missing" || e.status === "different")
        )
      : diff.keys;
    return [...list].sort((a, b) => a.key.localeCompare(b.key));
  }, [diff.keys, onlyDrift]);

  return (
    <>
      <div className="flex items-center gap-2 border-b border-line px-5 py-2">
        <label className="flex cursor-pointer items-center gap-2 text-[12px] text-muted">
          <input
            type="checkbox"
            checked={onlyDrift}
            onChange={(e) => setOnlyDrift(e.target.checked)}
            className="accent-[var(--tv-accent)]"
          />
          Only drifted keys
        </label>
        <span className="mono ml-auto text-[11.5px] text-faint">
          {rows.length}/{diff.keys.length}
        </span>
      </div>
      <table className="w-full border-collapse">
        {/* No z-index: sticky paints above in-flow rows on its own, and an
            explicit z let this header beat portalled overlays above it. */}
        <thead className="sticky top-0 bg-paper">
          <tr className="border-b border-line text-left">
            <th className="px-5 py-2 text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
              Key
            </th>
            {envs.map((e) => (
              <th
                key={e}
                className="px-3 py-2 text-center text-[11px] font-semibold uppercase tracking-[0.07em] text-faint"
              >
                {e}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((k) => (
            <tr key={k.key} className="border-b border-line/60 transition-colors hover:bg-soft/70">
              <td className="mono px-5 py-2 text-[12.5px] text-ink">{k.key}</td>
              {envs.map((env) => {
                const cell = k.environments.find((e) => e.env === env);
                const status = cell?.status ?? "missing";
                return (
                  <td key={env} className="px-3 py-2 text-center">
                    <Badge tone={STATUS_TONE[status] ?? "neutral"}>{status}</Badge>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function PromoteModal({
  open,
  group,
  onClose,
  onDone
}: {
  open: boolean;
  group: EnvGroupDetail;
  onClose: () => void;
  onDone: (res: PromoteResult) => void;
}): React.JSX.Element | null {
  const toast = useToast();
  const envs = group.environments;
  const [from, setFrom] = useState(envs[0]?.name ?? "");
  const [to, setTo] = useState(envs[1]?.name ?? "");
  const [keys, setKeys] = useState("");
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<PromoteResult | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setPreview(null);
    setErr(null);
  }, [open]);

  if (!open) return null;

  const keyList = keys
    .split(/[,\s]+/)
    .map((k) => k.trim())
    .filter(Boolean);

  const execute = async (dry: boolean): Promise<void> => {
    if (from === to) {
      setErr("Source and target environment must differ.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const res = await unwrap(
        window.tvault.envPromote({
          group: group.name,
          from_env: from,
          to_env: to,
          keys: keyList.length > 0 ? keyList : undefined,
          all: keyList.length === 0,
          dry_run: dry
        })
      );
      if (dry) {
        setPreview(res);
      } else {
        onDone(res);
        onClose();
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setErr(msg);
      toast.error("Promote failed", msg);
    } finally {
      setBusy(false);
    }
  };

  const canCommit = preview !== null && preview.promoted.length > 0;

  return (
    <Modal
      open
      title="Promote values"
      subtitle={group.name}
      onClose={onClose}
      width="max-w-xl"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Close
          </Button>
          <Button variant="default" icon="eye" disabled={busy} onClick={() => void execute(true)}>
            {busy && !canCommit ? "Comparing…" : "Preview"}
          </Button>
          <Button
            variant="primary"
            icon="arrowRight"
            disabled={busy || !canCommit}
            onClick={() => void execute(false)}
          >
            {busy && canCommit ? "Promoting…" : "Promote"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <Field label="From">
            <select
              value={from}
              onChange={(e) => {
                setFrom(e.target.value);
                setPreview(null);
              }}
              className="h-9 w-full rounded-tv-sm border border-line bg-raised px-2.5 text-[12.5px] text-ink focus:border-accent focus:outline-none"
            >
              {envs.map((e) => (
                <option key={e.name} value={e.name}>
                  {e.name} ({e.project})
                </option>
              ))}
            </select>
          </Field>
          <Field label="To">
            <select
              value={to}
              onChange={(e) => {
                setTo(e.target.value);
                setPreview(null);
              }}
              className="h-9 w-full rounded-tv-sm border border-line bg-raised px-2.5 text-[12.5px] text-ink focus:border-accent focus:outline-none"
            >
              {envs.map((e) => (
                <option key={e.name} value={e.name}>
                  {e.name} ({e.project})
                </option>
              ))}
            </select>
          </Field>
        </div>

        <Field
          label="Keys"
          hint="Leave empty to promote every key that differs. Comma or space separated."
        >
          <TextInput
            mono
            value={keys}
            spellCheck={false}
            onChange={(e) => {
              setKeys(e.target.value);
              setPreview(null);
            }}
            placeholder="STRIPE_WEBHOOK_SECRET, DATABASE_URL"
          />
        </Field>

        <Note>
          Promotion decrypts under the source project's DEK and re-encrypts under the target's, in
          one transaction. Values never reach this window. Each promoted key becomes a new version in
          the target, so it is reversible via history.
        </Note>

        {preview ? (
          <div className="space-y-2">
            <p className="text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
              Preview — nothing written yet
            </p>
            {preview.promoted.length === 0 ? (
              <p className="rounded-tv-sm border border-success/30 bg-success/8 px-3 py-2.5 text-[12.5px] text-success">
                Nothing to promote — these environments already agree.
              </p>
            ) : (
              <ul className="max-h-40 space-y-1 overflow-y-auto">
                {preview.promoted.map((p) => (
                  <li
                    key={p.key}
                    className="flex items-center gap-2 rounded-tv-sm border border-line bg-raised px-3 py-1.5"
                  >
                    <span className="mono min-w-0 flex-1 truncate text-[12px] text-ink">{p.key}</span>
                    <span className="mono shrink-0 text-[11px] text-faint">
                      v{p.from_version} → v{p.to_version}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {preview.skipped.length > 0 ? (
              <ul className="space-y-1">
                {preview.skipped.map((s) => (
                  <li
                    key={s.key}
                    className="mono flex items-center gap-2 rounded-tv-sm border border-warn/25 bg-warn/8 px-3 py-1.5 text-[11.5px]"
                  >
                    <span className="min-w-0 flex-1 truncate text-ink">{s.key}</span>
                    <span className="shrink-0 text-warn">{s.reason}</span>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}

        {err ? (
          <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
            {err}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}
