import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { EnvDiffResult, EnvGroupDetail, PromoteResult } from "@shared/types";

import { unwrap } from "../lib/api";
import {
  Badge,
  Button,
  EmptyState,
  Field,
  Icon,
  Modal,
  Spinner,
  TextInput,
  useToast
} from "./ui";

type DiffMode = "keys" | "values";

const STATUS_TONE: Record<string, "success" | "accent" | "warn" | "danger" | "neutral"> = {
  same: "success",
  different: "warn",
  missing: "danger",
  "local-only": "accent"
};

/**
 * Environment groups are the feature this UI earns its keep on: drift across
 * production/preview/staging is a matrix, and a matrix is miserable in a terminal.
 *
 * Values are never displayed here. `vault_env_diff` compares values but reports
 * only same/different, and promote moves bytes between DEKs without either side
 * reaching this process.
 */
export default function EnvGroupsView({
  readOnly,
  onChanged
}: {
  readOnly: boolean;
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
          body="Create one from the CLI to link existing projects as environments of the same app:  tvault env group create myapp --env production=myapp --env preview=myapp-preview"
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
                  {!readOnly ? (
                    <Button
                      size="sm"
                      variant="primary"
                      icon="arrowRight"
                      disabled={group.environments.length < 2}
                      onClick={() => setPromote(true)}
                    >
                      Promote
                    </Button>
                  ) : null}
                </div>

                <div className="flex shrink-0 flex-wrap gap-1.5 border-b border-line px-5 py-2.5">
                  {group.environments.map((e) => (
                    <span
                      key={e.name}
                      className="inline-flex items-center gap-1.5 rounded-full border border-line bg-raised px-2.5 py-1"
                      title={e.project}
                    >
                      <span className="text-[11.5px] font-medium text-ink">{e.name}</span>
                      <span className="mono text-[11px] text-faint">→ {e.project}</span>
                    </span>
                  ))}
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

      {group ? (
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
      ) : null}
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
        <thead className="sticky top-0 z-10 bg-paper">
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

        <div className="flex items-start gap-2.5 rounded-tv-sm border border-line bg-soft/60 px-3.5 py-2.5">
          <span className="mt-0.5 text-faint">
            <Icon name="shield" size={13} />
          </span>
          <p className="text-[12px] leading-relaxed text-muted">
            Promotion decrypts under the source project's DEK and re-encrypts under the target's, in
            one transaction. Values never reach this window. Each promoted key becomes a new version
            in the target, so it is reversible via history.
          </p>
        </div>

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
