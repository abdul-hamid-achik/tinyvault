import { existsSync, statSync } from "node:fs";
import { resolve as resolvePath } from "node:path";

import { BrowserWindow, dialog } from "electron";

/**
 * Every file path this app touches, and how it got there.
 *
 * The dotenv and sealing tools all take a path, and several of them WRITE
 * (`vault_export_env`, `vault_export_env_encrypted`, `vault_seal_for_recipients`,
 * `vault_env_seal`, `vault_open_sealed`) or READ a file the user chose
 * (`vault_diff_env`, `vault_sync_env`, `vault_import_env_files`). Letting the
 * renderer supply an arbitrary string would turn those into an
 * arbitrary-file-write and arbitrary-file-read primitive. That is the same
 * hazard `TvaultApi.restore` already closes by accepting only a path main
 * listed itself; this generalises it.
 *
 * A path enters the app in exactly two ways:
 *
 *  1. An OS dialog answered here, in the main process.
 *  2. A dotenv file discovered by `vault_list_env_files`, whose names the Go
 *     parser already restricts to the dotenv allowlist (`.env`, `.env.<env>`,
 *     `.env.local`, `.env.<env>.local`) inside a directory the user picked.
 *
 * Both are recorded in `issued`, and the IPC handlers refuse anything else.
 * The renderer therefore never authors a path — it only echoes one back.
 */

/** Bounded FIFO: a long session picking many folders must not grow this forever. */
const MAX_ISSUED = 200;
const issued: string[] = [];
const issuedSet = new Set<string>();

function issue(path: string): string {
  const resolved = resolvePath(path);
  if (!issuedSet.has(resolved)) {
    issued.push(resolved);
    issuedSet.add(resolved);
    while (issued.length > MAX_ISSUED) {
      const dropped = issued.shift();
      if (dropped !== undefined) issuedSet.delete(dropped);
    }
  }
  return resolved;
}

/**
 * Records paths main itself discovered (the `vault_list_env_files` result) so the
 * user can act on a listed file without a second dialog for each one.
 */
export function issueDiscovered(paths: string[]): void {
  for (const path of paths) {
    if (typeof path === "string" && path.length > 0) issue(path);
  }
}

/**
 * Validates a path the renderer handed back. Returns the resolved absolute path,
 * or throws with a message that names what was refused — never the path itself,
 * so a probing renderer gets no confirmation about the filesystem.
 */
export function assertIssued(path: unknown, what: string): string {
  if (typeof path !== "string" || path.trim() === "") {
    throw new Error(`${what}: no path given`);
  }
  const resolved = resolvePath(path);
  if (!issuedSet.has(resolved)) {
    throw new Error(`${what}: refusing a path this app did not offer you`);
  }
  return resolved;
}

/** True when the issued path still exists as a regular file. */
export function isIssuedFile(path: string): boolean {
  try {
    return existsSync(path) && statSync(path).isFile();
  } catch {
    return false;
  }
}

function parentWindow(): BrowserWindow | undefined {
  return BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0] ?? undefined;
}

/** Directory picker. Returns null when the user cancelled. */
export async function pickDirectory(title: string): Promise<string | null> {
  const parent = parentWindow();
  const options = {
    title,
    buttonLabel: "Choose folder",
    properties: ["openDirectory", "dontAddToRecent"] as Array<"openDirectory" | "dontAddToRecent">
  };
  const result = parent
    ? await dialog.showOpenDialog(parent, options)
    : await dialog.showOpenDialog(options);
  if (result.canceled || result.filePaths.length === 0) return null;
  return issue(result.filePaths[0]);
}

/**
 * Save dialog for a file this app is about to write. `defaultName` seeds the
 * filename (`.env`, `.env.encrypted`); no extension filter is applied, because
 * dotenv files are dotfiles whose "extension" is the environment name.
 */
export async function pickSaveFile(
  title: string,
  defaultName: string,
  defaultDir?: string
): Promise<string | null> {
  const parent = parentWindow();
  const options: Electron.SaveDialogOptions = {
    title,
    buttonLabel: "Write file",
    defaultPath:
      defaultDir && existsSync(defaultDir) ? resolvePath(defaultDir, defaultName) : defaultName,
    properties: ["dontAddToRecent", "createDirectory"]
  };
  const result = parent
    ? await dialog.showSaveDialog(parent, options)
    : await dialog.showSaveDialog(options);
  if (result.canceled || !result.filePath) return null;
  return issue(result.filePath);
}

/** Open dialog for an existing file the user wants this app to read. */
export async function pickExistingFile(title: string): Promise<string | null> {
  const parent = parentWindow();
  const options: Electron.OpenDialogOptions = {
    title,
    buttonLabel: "Choose file",
    properties: ["openFile", "dontAddToRecent"]
  };
  const result = parent
    ? await dialog.showOpenDialog(parent, options)
    : await dialog.showOpenDialog(options);
  if (result.canceled || result.filePaths.length === 0) return null;
  return issue(result.filePaths[0]);
}
