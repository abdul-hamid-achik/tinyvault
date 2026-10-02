import { Fragment, useEffect, useMemo, useRef, useState } from "react";

import type { AuditEntry, AuditSinceRequest } from "@shared/types";

import { clockTime, fullTime, relTime, unwrap } from "../lib/api";
import { Badge, Button, EmptyState, Icon, IconButton, Spinner } from "./ui";

const LIMITS = [25, 50, 100];
const ALL = "all";

const CONTROL =
  "mono h-8 rounded-tv-sm border border-line bg-raised px-2.5 text-[12px] text-ink " +
  "focus:border-accent focus:outline-none";

type RangeKey = "all" | "15m" | "1h" | "24h" | "7d" | "custom";

/** `ms` is the window length; 0 means no lower bound ("all") or user-supplied ("custom"). */
const RANGES: { key: RangeKey; label: string; ms: number }[] = [
  { key: "all", label: "All time", ms: 0 },
  { key: "15m", label: "15 min", ms: 15 * 60_000 },
  { key: "1h", label: "1 hour", ms: 60 * 60_000 },
  { key: "24h", label: "24 hours", ms: 24 * 60 * 60_000 },
  { key: "7d", label: "7 days", ms: 7 * 24 * 60 * 60_000 },
  { key: "custom", label: "Custom", ms: 0 }
];

const META_VALUE_MAX = 200;
const META_TOTAL_MAX = 2000;

/**
 * `metadata` is sanitized server-side, but its shape is not ours to assume: cap
 * every value and the whole block so an unexpected blob cannot reach the DOM.
 */
function metadataText(md: Record<string, unknown>): string {
  const keys = Object.keys(md);
  const lines: string[] = [];
  let used = 0;
  for (const key of keys) {
    let value: string;
    try {
      value = typeof md[key] === "string" ? (md[key] as string) : String(JSON.stringify(md[key]));
    } catch {
      value = "[unserializable]";
    }
    const line = `${key}: ${value.length > META_VALUE_MAX ? `${value.slice(0, META_VALUE_MAX)}…` : value}`;
    if (used + line.length > META_TOTAL_MAX) {
      lines.push(`… ${keys.length - lines.length} more not shown`);
      break;
    }
    lines.push(line);
    used += line.length + 1;
  }
  return lines.join("\n");
}

/** `datetime-local` → RFC3339. Never hand-format: the server rejects malformed bounds. */
function toRFC3339(local: string): string | undefined {
  const t = Date.parse(local);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
}

function distinct(prev: string[], entries: AuditEntry[], pick: (e: AuditEntry) => string): string[] {
  const set = new Set(prev);
  for (const e of entries) if (pick(e)) set.add(pick(e));
  return [...set].sort();
}

function countBy(entries: AuditEntry[], pick: (e: AuditEntry) => string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const e of entries) {
    const value = pick(e);
    if (value) counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return counts;
}

interface CustomRange {
  since?: string;
  until?: string;
  error: string | null;
}

/**
 * The audit bucket is lock-free metadata and never contains secret values — the
 * Go layer records counts and key names only. Safe to render in full.
 *
 * Two filter layers, deliberately separate: the **query** row (time range,
 * action, resource type) is exact-match and runs server-side through
 * `vault_audit_log_since`, so nothing outside it is ever returned; the **render**
 * text box narrows only what is already on screen.
 */
export default function AuditView(): React.JSX.Element {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [limit, setLimit] = useState(50);
  const [filter, setFilter] = useState("");
  const [action, setAction] = useState(ALL);
  const [type, setType] = useState(ALL);
  const [range, setRange] = useState<RangeKey>("all");
  // Draft vs applied: a half-typed datetime-local must not fire a query.
  const [draftFrom, setDraftFrom] = useState("");
  const [draftTo, setDraftTo] = useState("");
  const [custom, setCustom] = useState<CustomRange>({ error: null });
  // Option lists accumulate across loads. Deriving them from the loaded page
  // alone would collapse the action menu to the one action just filtered on.
  const [vocab, setVocab] = useState<{ actions: string[]; types: string[] }>({
    actions: [],
    types: []
  });
  const [expanded, setExpanded] = useState<number | null>(null);

  // Same hazard as `secretsGen` in App.tsx: a slow filtered query must not
  // paint over the results of a faster later one.
  const gen = useRef(0);

  const serverActive = range !== "all" || action !== ALL || type !== ALL;

  const load = useMemo(
    () => async (): Promise<void> => {
      const my = ++gen.current;
      setLoading(true);
      // A rejected custom range only blocks while that range is selected;
      // picking a preset supersedes it.
      if (range === "custom" && custom.error) {
        setEntries([]);
        setError(custom.error);
        setLoading(false);
        return;
      }
      setError(null);
      const preset = RANGES.find((r) => r.key === range);
      // Recomputed per call, so "last hour" slides when Refresh is pressed.
      const since =
        range === "custom"
          ? custom.since
          : preset && preset.ms > 0
            ? new Date(Date.now() - preset.ms).toISOString()
            : undefined;
      const req: AuditSinceRequest = {
        since,
        until: range === "custom" ? custom.until : undefined,
        action: action === ALL ? undefined : action,
        resource_type: type === ALL ? undefined : type,
        limit
      };
      try {
        const list = serverActive
          ? await unwrap(window.tvault.auditLogSince(req))
          : await unwrap(window.tvault.auditLog(limit));
        if (my !== gen.current) return;
        setEntries(list);
        setExpanded(null);
        setVocab((prev) => ({
          actions: distinct(prev.actions, list, (e) => e.action),
          types: distinct(prev.types, list, (e) => e.resource_type)
        }));
      } catch (err) {
        if (my !== gen.current) return;
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (my === gen.current) setLoading(false);
      }
    },
    [limit, range, action, type, serverActive, custom.since, custom.until, custom.error]
  );

  useEffect(() => {
    void load();
  }, [load]);

  const applyCustom = (): void => {
    const since = draftFrom ? toRFC3339(draftFrom) : undefined;
    const until = draftTo ? toRFC3339(draftTo) : undefined;
    if ((draftFrom !== "" && !since) || (draftTo !== "" && !until)) {
      setCustom({ error: "That date could not be read — use the picker." });
      return;
    }
    // Both are toISOString() output, so lexicographic order is time order.
    if (since && until && until < since) {
      setCustom({ since, until, error: "The end of the range is before its start." });
      return;
    }
    setCustom({ since, until, error: null });
  };

  const resetFilters = (): void => {
    setRange("all");
    setAction(ALL);
    setType(ALL);
    setFilter("");
    setDraftFrom("");
    setDraftTo("");
    setCustom({ error: null });
  };

  const actionCounts = useMemo(() => countBy(entries, (e) => e.action), [entries]);
  const typeCounts = useMemo(() => countBy(entries, (e) => e.resource_type), [entries]);

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter(
      (e) =>
        e.action.toLowerCase().includes(q) ||
        e.resource_type.toLowerCase().includes(q) ||
        e.resource_name?.toLowerCase().includes(q) ||
        e.resource_id?.toLowerCase().includes(q)
    );
  }, [entries, filter]);

  return (
    <div className="flex h-full min-w-0 flex-col">
      <header className="shrink-0 border-b border-line px-6 pb-4 pt-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-[17px] font-semibold tracking-[-0.01em] text-ink">Audit log</h1>
            <p className="mt-1 max-w-2xl text-[12.5px] leading-relaxed text-muted">
              One shared trail for the CLI, the MCP server and this app — get, set, delete, project
              changes, rollback, generate and share all land here. Values are never recorded.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <div className="flex items-center gap-0.5 rounded-tv-sm border border-line bg-raised p-0.5">
              {LIMITS.map((n) => (
                <button
                  key={n}
                  onClick={() => setLimit(n)}
                  className={`mono h-6 rounded px-2 text-[11.5px] transition-colors ${
                    limit === n ? "bg-accent-soft text-accent" : "text-faint hover:text-ink"
                  }`}
                >
                  {n}
                </button>
              ))}
            </div>
            <Button size="sm" icon="refresh" onClick={() => void load()}>
              Refresh
            </Button>
          </div>
        </div>

        <div className="mt-3.5 flex flex-wrap items-center gap-2">
          <span className="w-[52px] shrink-0 text-[10px] font-semibold uppercase tracking-[0.07em] text-faint">
            Query
          </span>
          <div className="flex items-center gap-0.5 rounded-tv-sm border border-line bg-raised p-0.5">
            {RANGES.map((r) => (
              <button
                key={r.key}
                onClick={() => setRange(r.key)}
                className={`h-6 rounded px-2 text-[11.5px] transition-colors ${
                  range === r.key ? "bg-accent-soft text-accent" : "text-faint hover:text-ink"
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
          <select
            value={action}
            onChange={(e) => setAction(e.target.value)}
            title="Exact match, applied server-side. The list is the actions seen in the log so far — no wildcards."
            className={CONTROL}
          >
            <option value={ALL}>all actions</option>
            {vocab.actions.map((a) => (
              <option key={a} value={a}>
                {actionCounts.get(a) ? `${a} (${actionCounts.get(a)})` : a}
              </option>
            ))}
          </select>
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            title="Exact match, applied server-side. The list is the resource types seen in the log so far — no wildcards."
            className={CONTROL}
          >
            <option value={ALL}>all types</option>
            {vocab.types.map((t) => (
              <option key={t} value={t}>
                {typeCounts.get(t) ? `${t} (${typeCounts.get(t)})` : t}
              </option>
            ))}
          </select>
          <span className="ml-auto flex items-center gap-1.5">
            {serverActive ? <Badge tone="accent">filters active</Badge> : null}
            <Badge tone="neutral">limit {limit}</Badge>
            {serverActive || filter ? (
              <IconButton icon="x" label="Reset all filters" onClick={resetFilters} />
            ) : null}
          </span>
        </div>

        {range === "custom" ? (
          <div className="mt-2 flex flex-wrap items-center gap-2 pl-[60px]">
            <label className="flex items-center gap-1.5 text-[11.5px] text-faint">
              From
              <input
                type="datetime-local"
                value={draftFrom}
                onChange={(e) => setDraftFrom(e.target.value)}
                className={CONTROL}
              />
            </label>
            <label className="flex items-center gap-1.5 text-[11.5px] text-faint">
              To
              <input
                type="datetime-local"
                value={draftTo}
                onChange={(e) => setDraftTo(e.target.value)}
                className={CONTROL}
              />
            </label>
            <Button size="sm" icon="search" onClick={applyCustom}>
              Apply
            </Button>
            <span className="text-[11px] text-faint">
              {custom.error ? (
                <span className="text-danger">{custom.error}</span>
              ) : (
                "Leave a side empty to keep it open."
              )}
            </span>
          </div>
        ) : null}

        <div className="mt-2 flex items-center gap-2">
          <span className="w-[52px] shrink-0 text-[10px] font-semibold uppercase tracking-[0.07em] text-faint">
            Render
          </span>
          <div className="flex h-8 flex-1 items-center gap-2 rounded-tv-sm border border-line bg-raised px-2.5">
            <span className="text-faint">
              <Icon name="search" size={13} />
            </span>
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Narrow what is on screen — action, key, project or type"
              spellCheck={false}
              className="h-full min-w-0 flex-1 bg-transparent text-[12.5px] text-ink placeholder:text-faint focus:outline-none"
            />
            {filter ? <IconButton icon="x" label="Clear text filter" onClick={() => setFilter("")} /> : null}
            <span className="mono shrink-0 text-[11px] text-faint">
              {rows.length}/{entries.length}
            </span>
          </div>
        </div>

        {entries.length >= limit ? (
          <p className="mt-1.5 pl-[60px] text-[11px] text-warn">
            At limit {limit}: older matching entries, if any, are not shown.
          </p>
        ) : null}
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex h-40 items-center justify-center gap-2.5 text-muted">
            <Spinner /> <span className="text-[12.5px]">Loading audit log…</span>
          </div>
        ) : error ? (
          <div className="m-6 rounded-tv-md border border-danger/30 bg-danger/8 px-4 py-3.5">
            <p className="flex items-center gap-2 text-[13px] font-medium text-danger">
              <Icon name="alert" size={14} /> {error}
            </p>
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            icon="history"
            title={
              entries.length > 0
                ? "Nothing matches that text filter"
                : serverActive
                  ? "No entries match this query"
                  : "No audit entries"
            }
            body={
              entries.length > 0
                ? "The query returned entries; the text box narrowed them all away."
                : serverActive
                  ? "Widen the time range, or drop the action and type filter."
                  : "Entries appear as soon as the vault is read or written through any surface."
            }
            action={
              entries.length > 0 ? (
                <Button icon="x" onClick={() => setFilter("")}>
                  Clear text filter
                </Button>
              ) : serverActive ? (
                <Button icon="rollback" onClick={resetFilters}>
                  Reset query
                </Button>
              ) : undefined
            }
          />
        ) : (
          <table className="w-full border-collapse">
            {/* No z-index: sticky paints above in-flow rows on its own, and an
                explicit z let this header beat portalled overlays above it. */}
            <thead className="sticky top-0 bg-paper">
              <tr className="border-b border-line text-left">
                <th className="w-44 px-6 py-2 text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
                  When
                </th>
                <th className="w-44 px-2 py-2 text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
                  Action
                </th>
                <th className="w-24 px-2 py-2 text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
                  Type
                </th>
                <th className="px-2 py-2 text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
                  Resource
                </th>
                <th className="w-10 px-6 py-2" />
              </tr>
            </thead>
            <tbody>
              {rows.map((e, i) => {
                const tone = e.action.startsWith("secret.delete") || e.action.includes("delete")
                  ? "danger"
                  : e.action.startsWith("secret.set") || e.action.includes("create")
                    ? "accent"
                    : "neutral";
                const open = expanded === i;
                return (
                  <Fragment key={i}>
                    <tr
                      className="group border-b border-line/60 transition-colors duration-75 hover:bg-soft/70"
                    >
                      <td className="px-6 py-2">
                        <span className="block text-[12px] text-muted" title={fullTime(e.timestamp)}>
                          {relTime(e.timestamp)}
                        </span>
                        <span className="mono block text-[10.5px] text-faint">
                          {clockTime(e.timestamp)}
                        </span>
                      </td>
                      <td className="px-2 py-2">
                        <Badge tone={tone as "danger" | "accent" | "neutral"}>
                          <span className="mono">{e.action}</span>
                        </Badge>
                      </td>
                      <td className="px-2 py-2">
                        <span className="mono text-[11.5px] text-faint">{e.resource_type}</span>
                      </td>
                      <td className="mono px-2 py-2 text-[12px] text-ink">
                        {e.resource_name || e.resource_id || "—"}
                      </td>
                      <td className="px-6 py-2 text-right">
                        {e.metadata && Object.keys(e.metadata).length > 0 ? (
                          <button
                            onClick={() => setExpanded(open ? null : i)}
                            className="text-faint transition-colors hover:text-accent"
                            title="Metadata"
                          >
                            <Icon name="chevron" size={13} className={open ? "" : "-rotate-90"} />
                          </button>
                        ) : null}
                      </td>
                    </tr>
                    {open && e.metadata ? (
                      <tr className="border-b border-line/60 bg-soft/40">
                        <td colSpan={5} className="px-6 py-2.5">
                          <pre className="mono whitespace-pre-wrap break-words text-[11.5px] leading-relaxed text-muted">
                            {metadataText(e.metadata)}
                          </pre>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
