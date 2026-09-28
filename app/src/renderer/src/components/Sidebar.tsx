import { useEffect, useMemo, useRef, useState } from "react";

import type { Bootstrap, ProjectOverview } from "@shared/types";

import { Badge, Icon, IconButton, type IconName } from "./ui";
import { Logo } from "./Logo";

export type View = "secrets" | "groups" | "sharing" | "audit" | "setup";

const NAV: Array<{ id: View; label: string; icon: IconName }> = [
  { id: "secrets", label: "Secrets", icon: "key" },
  { id: "groups", label: "Environments", icon: "layers" },
  { id: "sharing", label: "Sharing", icon: "branch" },
  { id: "audit", label: "Audit log", icon: "history" },
  { id: "setup", label: "Connection", icon: "shield" }
];

export default function Sidebar({
  projects,
  selected,
  onSelect,
  view,
  onView,
  currentProject,
  onMakeCurrent,
  onCreateProject,
  boot,
  theme,
  onToggleTheme,
  onRestartSession,
  focusToken
}: {
  projects: ProjectOverview[];
  selected: string | null;
  onSelect: (name: string) => void;
  view: View;
  onView: (v: View) => void;
  currentProject: string | null;
  onMakeCurrent: (name: string) => void;
  onCreateProject: () => void;
  boot: Bootstrap | null;
  theme: "light" | "dark";
  onToggleTheme: () => void;
  onRestartSession: () => void;
  /** Incremented by the Cmd+K shortcut when this sidebar owns the focus target. */
  focusToken: number;
}): React.JSX.Element {
  const [filter, setFilter] = useState("");
  const filterRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (focusToken > 0) filterRef.current?.focus();
  }, [focusToken]);

  // The macOS traffic lights render inside the window at x≈20..72 (see the
  // trafficLightPosition comment in main). On other platforms the native title
  // bar owns them, so the header row starts at the normal inset.
  const isMac = window.tvault.platform === "darwin";

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const list = q
      ? projects.filter(
          (p) => p.name.toLowerCase().includes(q) || p.description.toLowerCase().includes(q)
        )
      : projects;
    return [...list].sort((a, b) => a.name.localeCompare(b.name));
  }, [projects, filter]);

  const session = boot?.session;
  const budget = session ? session.reads_limit : 0;
  const used = session ? session.reads_used : 0;
  const exhausted = budget > 0 && used >= budget;
  const tight = budget > 0 && !exhausted && used / budget >= 0.7;

  return (
    <aside className="flex w-[248px] shrink-0 flex-col border-r border-line bg-soft/60">
      {/*
        macOS hiddenInset draws the traffic lights inside the window, at
        x≈20..72 and vertically centred in this row (trafficLightPosition in
        main). The brand row shares the row and starts clear of them. Other
        platforms get a native title bar, so the normal inset applies.
      */}
      <div
        className={`drag flex h-11 shrink-0 items-center gap-2 pr-4 ${
          isMac ? "pl-[84px]" : "pl-4"
        }`}
      >
        {boot?.status?.is_unlocked === false ? (
          <span className="no-drag">
            <Badge tone="danger">locked</Badge>
          </span>
        ) : null}
        {/* The whole lockup (mark + wordmark) anchors the right edge; the traffic
            lights own the left of this row. */}
        <span className="no-drag ml-auto flex items-center gap-2">
          <Logo size={20} />
          <span className="text-[12.5px] font-semibold tracking-[-0.01em] text-ink">
            TinyVault
          </span>
        </span>
      </div>

      <nav className="shrink-0 space-y-0.5 px-2.5 pb-3">
        {NAV.map((item) => (
          <button
            key={item.id}
            onClick={() => onView(item.id)}
            className={`group/icon flex h-8 w-full items-center gap-2.5 rounded-tv-sm px-2.5 text-[12.5px]
              font-medium transition-all duration-150 ease-out hover:translate-x-0.5 ${
                view === item.id
                  ? "bg-accent-soft text-accent"
                  : "text-muted hover:bg-deep/60 hover:text-ink"
              }`}
          >
            <Icon name={item.icon} size={14} animated />
            {item.label}
            {item.id === "secrets" && projects.length > 0 ? (
              <span className="mono ml-auto text-[11px] text-faint">
                {projects.reduce((n, p) => n + p.secret_count, 0)}
              </span>
            ) : null}
          </button>
        ))}
      </nav>

      <div className="flex shrink-0 items-center gap-1.5 border-y border-line px-2.5 py-2">
        <span className="text-faint">
          <Icon name="search" size={13} />
        </span>
        <input
          ref={filterRef}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter projects"
          spellCheck={false}
          className="h-6 min-w-0 flex-1 bg-transparent text-[12.5px] text-ink placeholder:text-faint focus:outline-none"
        />
        {filter ? <IconButton icon="x" label="Clear filter" onClick={() => setFilter("")} /> : null}
        <IconButton icon="plus" label="New project" onClick={onCreateProject} tone="accent" />
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-1.5 py-1.5">
        {filtered.length === 0 ? (
          <p className="px-2.5 py-6 text-center text-[12px] leading-relaxed text-faint">
            {projects.length === 0 ? "No projects in this vault yet." : `No project matches “${filter}”.`}
          </p>
        ) : (
          filtered.map((p) => {
            const active = p.name === selected && view === "secrets";
            const isCurrent = p.name === currentProject;
            return (
              <div
                key={p.name}
                className={`group relative mb-0.5 rounded-tv-sm transition-colors duration-100 ${
                  active ? "bg-raised" : "hover:bg-deep/50"
                }`}
              >
                {active ? (
                  <span className="absolute left-0 top-1/2 h-5 w-[2.5px] -translate-y-1/2 rounded-r bg-accent" />
                ) : null}
                <button
                  onClick={() => onSelect(p.name)}
                  onDoubleClick={() => onMakeCurrent(p.name)}
                  title={p.description || p.name}
                  className="flex w-full items-center gap-2 py-2 pl-3 pr-2 text-left"
                >
                  <span className={active ? "text-accent" : "text-faint"}>
                    <Icon name="folder" size={13} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span
                      className={`mono block truncate text-[12.5px] ${
                        active ? "font-medium text-ink" : "text-muted group-hover:text-ink"
                      }`}
                    >
                      {p.name}
                    </span>
                    {p.description ? (
                      <span className="block truncate text-[11px] text-faint">{p.description}</span>
                    ) : null}
                  </span>
                  <span className="mono shrink-0 text-[11px] text-faint">{p.secret_count}</span>
                </button>
                {isCurrent ? (
                  <span className="pointer-events-none absolute right-2 top-1.5">
                    <span className="block h-1.5 w-1.5 rounded-full bg-accent" title="Current project" />
                  </span>
                ) : null}
              </div>
            );
          })
        )}
      </div>

      <footer className="shrink-0 space-y-2 border-t border-line px-3 py-2.5">
        {budget > 0 ? (
          <div className="flex items-center gap-2">
            <span className={`text-[11px] ${exhausted ? "text-danger" : tight ? "text-warn" : "text-faint"}`}>
              <Icon name="eye" size={12} />
            </span>
            <span
              className={`mono flex-1 text-[11px] ${
                exhausted ? "text-danger" : tight ? "text-warn" : "text-faint"
              }`}
            >
              {used}/{budget} reveals
            </span>
            {exhausted || tight ? (
              <button
                onClick={onRestartSession}
                className="rounded px-1.5 py-0.5 text-[11px] font-medium text-accent transition-colors hover:bg-accent-soft"
                title="Restarting the MCP child resets the per-session reveal budget"
              >
                reset
              </button>
            ) : null}
          </div>
        ) : null}
        <div className="flex items-center justify-between">
          <span className="mono truncate text-[11px] text-faint">
            {boot?.binary ? `v${boot.binary.version}` : "no binary"}
          </span>
          <IconButton
            icon={theme === "dark" ? "sun" : "moon"}
            label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            onClick={onToggleTheme}
          />
        </div>
      </footer>
    </aside>
  );
}
