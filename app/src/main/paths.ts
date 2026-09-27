import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { app } from "electron";

/** Expands a leading `~` the way the Go CLI's config loader does. */
export function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

/**
 * Mirrors the Go `getVaultDir()` resolution: `--vault` (not applicable here),
 * then `TVAULT_DIR`, then `~/.tvault`.
 */
export function vaultDir(): string {
  const fromSettings = loadSettings().vaultDir?.trim();
  if (fromSettings) return expandHome(fromSettings);
  const env = process.env.TVAULT_DIR?.trim();
  if (env) return expandHome(env);
  return join(homedir(), ".tvault");
}

export interface Settings {
  binaryPath?: string;
  vaultDir?: string;
}

function settingsFile(): string {
  return join(app.getPath("userData"), "settings.json");
}

export function loadSettings(): Settings {
  // Called before app.whenReady() in some paths; guard rather than throw.
  try {
    const raw = readFileSync(settingsFile(), "utf8");
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as Settings) : {};
  } catch {
    return {};
  }
}
