import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { AgentInfo, PolicyInfo } from "@shared/types";

import { childEnv } from "./binary";
import { vaultDir } from "./paths";
import { runCliJson } from "./cli";

export function policyPath(): string {
  return join(vaultDir(), "mcp-policy.yaml");
}

/**
 * Reads `~/.tvault/mcp-policy.yaml` without a YAML dependency: the fields the UI
 * needs are all flat scalars or simple inline arrays, and pulling in a YAML
 * parser just to render a status badge is not worth it. Anything this cannot
 * parse is reported as `parse_error` rather than guessed at — the Go loader is
 * the authority, and a malformed file is surfaced by `tvault mcp` failing.
 */
export function readPolicy(): PolicyInfo {
  const path = policyPath();
  const base: PolicyInfo = { exists: false, path };

  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return base;
  }
  base.exists = true;

  const stripComment = (line: string): string => {
    // Only strip ` #` outside quotes; the policy file uses trailing comments heavily.
    let inSingle = false;
    let inDouble = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === "'" && !inDouble) inSingle = !inSingle;
      else if (c === '"' && !inSingle) inDouble = !inDouble;
      else if (c === "#" && !inSingle && !inDouble) return line.slice(0, i);
    }
    return line;
  };

  const lines = raw
    .split(/\r?\n/)
    .map(stripComment)
    .filter((l) => l.trim().length > 0 && !l.trimStart().startsWith("#"));

  // NOTE: `lines` is deliberately NOT trimmed. The `^key\s*:` anchors below rely
  // on that to match top-level keys only — trimming would make a nested key
  // inside some future block indistinguishable from a real policy field.
  const scalar = (key: string): string | undefined => {
    const hit = lines.find((l) => new RegExp(`^${key}\\s*:`).test(l));
    if (!hit) return undefined;
    const value = hit.slice(hit.indexOf(":") + 1).trim();
    return value.replace(/^["']|["']$/g, "");
  };

  const bool = (key: string): boolean | undefined => {
    const v = scalar(key);
    if (v === undefined) return undefined;
    if (v === "true") return true;
    if (v === "false") return false;
    return undefined;
  };

  const num = (key: string): number | undefined => {
    const v = scalar(key);
    if (v === undefined) return undefined;
    const n = Number.parseInt(v, 10);
    return Number.isFinite(n) ? n : undefined;
  };

  /**
   * Reads a list field in either YAML style:
   *
   *   secrets_deny: ["A", "B"]      # flow / inline
   *   secrets_deny:                 # block
   *     - "A"
   *     - "B"
   *
   * The Go loader accepts both, so the diagnostics badge must too — otherwise a
   * block-style deny list silently looks empty here while still being enforced
   * server-side.
   */
  const list = (key: string): string[] | undefined => {
    const idx = lines.findIndex((l) => new RegExp(`^${key}\\s*:`).test(l));
    if (idx === -1) return undefined;

    const inline = lines[idx].slice(lines[idx].indexOf(":") + 1).trim();
    if (inline.startsWith("[")) {
      try {
        const parsed = JSON.parse(inline.replace(/'/g, '"')) as unknown;
        return Array.isArray(parsed) ? parsed.map(String) : undefined;
      } catch {
        return inline
          .slice(1, -1)
          .split(",")
          .map((s) => s.trim().replace(/^["']|["']$/g, ""))
          .filter(Boolean);
      }
    }
    if (inline !== "") return undefined; // a scalar, not a list

    const out: string[] = [];
    for (let i = idx + 1; i < lines.length; i++) {
      const item = /^\s+-\s*(.*)$/.exec(lines[i]);
      if (!item) break; // next top-level key, or a comment-only gap
      out.push(item[1].trim().replace(/^["']|["']$/g, ""));
    }
    return out;
  };

  const mode = scalar("access_mode");
  if (mode && !["read-only", "read-write", "full"].includes(mode)) {
    base.parse_error = `unrecognised access_mode "${mode}"`;
  }

  return {
    ...base,
    access_mode: mode as PolicyInfo["access_mode"],
    allow_exec: bool("allow_exec"),
    redact_output: bool("redact_output"),
    max_reads_per_session: num("max_reads_per_session"),
    secrets_deny: list("secrets_deny"),
    projects_deny: list("projects_deny")
  };
}

/**
 * `tvault agent status --json`. The agent is optional and unix-only, so any
 * failure collapses to "not running" rather than surfacing an error.
 */
export async function readAgentStatus(): Promise<AgentInfo> {
  const result = await runCliJson<AgentInfo>(["agent", "status", "--json"], {
    env: childEnv(),
    timeoutMs: 5000
  });
  if (!result.ok) return { running: false };
  return result.value;
}
