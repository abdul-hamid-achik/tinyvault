import { Fragment, useEffect, useMemo, useState } from "react";

import type { AuditEntry } from "@shared/types";

import { clockTime, fullTime, relTime, unwrap } from "../lib/api";
import { Badge, Button, EmptyState, Icon, Spinner } from "./ui";

const LIMITS = [25, 50, 100];

/**
 * The audit bucket is lock-free metadata and never contains secret values — the
 * Go layer records counts and key names only. Safe to render in full.
 */
export default function AuditView(): React.JSX.Element {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [limit, setLimit] = useState(50);
  const [filter, setFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("all");
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = useMemo(
    () => async (): Promise<void> => {
      setLoading(true);
      setError(null);
      try {
        setEntries(await unwrap(window.tvault.auditLog(limit)));
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setLoading(false);
      }
    },
    [limit]
  );

  useEffect(() => {
    void load();
  }, [load]);

  const actions = useMemo(() => {
    const set = new Map<string, number>();
    for (const e of entries) set.set(e.action, (set.get(e.action) ?? 0) + 1);
    return [...set.entries()].sort((a, b) => b[1] - a[1]);
  }, [entries]);

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return entries.filter((e) => {
      if (actionFilter !== "all" && e.action !== actionFilter) return false;
      if (!q) return true;
      return (
        e.action.toLowerCase().includes(q) ||
        e.resource_name?.toLowerCase().includes(q) ||
        e.resource_id?.toLowerCase().includes(q)
      );
    });
  }, [entries, filter, actionFilter]);

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

        <div className="mt-3.5 flex items-center gap-2">
          <div className="flex h-8 flex-1 items-center gap-2 rounded-tv-sm border border-line bg-raised px-2.5">
            <span className="text-faint">
              <Icon name="search" size={13} />
            </span>
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by action, key or project"
              spellCheck={false}
              className="h-full min-w-0 flex-1 bg-transparent text-[12.5px] text-ink placeholder:text-faint focus:outline-none"
            />
          </div>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="mono h-8 rounded-tv-sm border border-line bg-raised px-2.5 text-[12px] text-ink focus:border-accent focus:outline-none"
          >
            <option value="all">all actions</option>
            {actions.map(([a, n]) => (
              <option key={a} value={a}>
                {a} ({n})
              </option>
            ))}
          </select>
        </div>
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
            title={entries.length === 0 ? "No audit entries" : "Nothing matches those filters"}
            body={
              entries.length === 0
                ? "Entries appear as soon as the vault is read or written through any surface."
                : undefined
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
                            <Icon
                              name="chevron"
                              size={13}
                              className={open ? "" : "-rotate-90"}
                            />
                          </button>
                        ) : null}
                      </td>
                    </tr>
                    {open && e.metadata ? (
                      <tr className="border-b border-line/60 bg-soft/40">
                        <td colSpan={5} className="px-6 py-2.5">
                          <pre className="mono overflow-x-auto text-[11.5px] leading-relaxed text-muted">
                            {JSON.stringify(e.metadata, null, 2)}
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
