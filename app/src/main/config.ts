import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { expandHome, vaultDir } from "./paths";

/**
 * Mirrors, approximately, the Go config resolution order that matters here
 * (cmd/tvault/cmd/config_helper.go): TVAULT_CONFIG, then <vault dir>/config.yaml,
 * then the XDG location when the vault dir is the default one. Reading the exact
 * same precedence is not worth a YAML dependency; if none of these yields a
 * backup.dir the snapshots live next to vault.db, which is also where the Go
 * side puts them when backup.dir is unset.
 */
function configCandidates(): string[] {
  const out: string[] = [];
  const env = process.env.TVAULT_CONFIG?.trim();
  if (env) out.push(expandHome(env));
  out.push(join(vaultDir(), "config.yaml"));
  const xdg = process.env.XDG_CONFIG_HOME?.trim();
  out.push(join(xdg ? expandHome(xdg) : join(homedir(), ".config"), "tvault", "config.yaml"));
  return out;
}

/**
 * The configured `backup.dir`, or null when unset. Only the nested `dir:` inside
 * the top-level `backup:` block counts — a `dir:` anywhere else is unrelated.
 */
export function readBackupDir(): string | null {
  for (const path of configCandidates()) {
    let raw: string;
    try {
      raw = readFileSync(path, "utf8");
    } catch {
      continue;
    }
    const lines = raw.split(/\r?\n/);
    const idx = lines.findIndex((l) => /^backup\s*:\s*(#.*)?$/.test(l));
    if (idx === -1) continue;
    for (let i = idx + 1; i < lines.length; i++) {
      const line = lines[i];
      if (/^\S/.test(line)) break; // left the backup block
      const m = /^\s+dir\s*:\s*(.*)$/.exec(line);
      if (!m) continue;
      const value = m[1].split("#")[0].trim().replace(/^["']|["']$/g, "");
      return value ? expandHome(value) : null;
    }
  }
  return null;
}
