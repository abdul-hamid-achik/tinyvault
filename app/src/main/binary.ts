import { execFileSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { delimiter, dirname, join } from "node:path";

import type { BinaryInfo } from "@shared/types";

import { loadSettings } from "./paths";

/**
 * A macOS app launched from Finder/Dock inherits a minimal PATH
 * (`/usr/bin:/bin:/usr/sbin:/sbin`), so a Homebrew-installed `tvault` is not on
 * it. This repo hit exactly that class of bug before — see CHANGELOG v0.21.1,
 * "GUI-launched MCP hosts do not inherit a login shell". Prepending the usual
 * install prefixes avoids needing a login-shell round-trip.
 */
export function augmentedPath(): string {
  const extra = [
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    join(homedir(), ".local", "bin"),
    join(homedir(), "go", "bin"),
    join(homedir(), ".bun", "bin"),
    join(homedir(), ".cargo", "bin")
  ];
  const current = (process.env.PATH ?? "").split(delimiter).filter(Boolean);
  return [...new Set([...extra, ...current])].join(delimiter);
}

function childEnv(): NodeJS.ProcessEnv {
  return { ...process.env, PATH: augmentedPath() };
}

const NPM_PLATFORMS = [
  "darwin-arm64",
  "darwin-x64",
  "linux-arm64",
  "linux-x64",
  "win32-arm64",
  "win32-x64"
] as const;

/** Resolves the binary shipped inside `@thelacanians/tinyvault-<platform>`, if installed. */
function resolveFromNpm(): string | null {
  const key = `${process.platform}-${process.arch}`;
  if (!NPM_PLATFORMS.includes(key as (typeof NPM_PLATFORMS)[number])) return null;
  try {
    const req = createRequire(import.meta.url);
    const pkgJson = req.resolve(`@thelacanians/tinyvault-${key}/package.json`);
    const bin = join(
      dirname(pkgJson),
      "bin",
      process.platform === "win32" ? "tvault.exe" : "tvault"
    );
    return existsSync(bin) ? bin : null;
  } catch {
    return null;
  }
}

function localCandidatePaths(): string[] {
  const exe = process.platform === "win32" ? "tvault.exe" : "tvault";
  return [
    "/opt/homebrew/bin/tvault",
    "/usr/local/bin/tvault",
    "/usr/bin/tvault",
    join(homedir(), ".local", "bin", exe),
    join(homedir(), "go", "bin", exe)
  ];
}

function versionOf(path: string): string {
  try {
    const out = execFileSync(path, ["--version"], {
      encoding: "utf8",
      timeout: 8000,
      env: childEnv(),
      stdio: ["ignore", "pipe", "pipe"]
    });
    // "tvault version 0.24.0 (commit f2c3a2c, built ...)"
    const m = /version\s+([^\s(]+)/.exec(out);
    return (m?.[1] ?? out.trim()).slice(0, 64);
  } catch {
    return "unknown";
  }
}

function probe(path: string, source: string): BinaryInfo {
  return { path, source, version: versionOf(path) };
}

/**
 * Mirrors the trust check the Go side applies to `agent.passphrase_command`: a
 * path supplied by config or environment must be a regular file owned by the
 * current user and not writable by group or others. Otherwise anyone able to
 * write that file can run code as this user — and here that code would be
 * spawned as the MCP child holding a derived KEK.
 *
 * Defense in depth, not a boundary: same-uid writes are already inside the trust
 * boundary per docs/reference/security.md. It keeps this app consistent with the
 * project's own stated rule rather than inventing a weaker one.
 */
function isTrustedExecutable(path: string, requireOwnership: boolean): boolean {
  try {
    const st = statSync(path);
    if (!st.isFile()) return false;
    // 0o022 = group-writable or world-writable. Rejected regardless of owner:
    // anyone able to write the file could replace the binary this app then runs
    // as the MCP child, holding a derived KEK.
    if (st.mode & 0o022) return false;
    if (!requireOwnership) return true;
    const uid = process.getuid?.();
    return uid === undefined || st.uid === uid;
  } catch {
    return false;
  }
}

function refuse(path: string, source: string): never {
  throw new Error(
    `Refusing to run ${path} (from ${source}): it must be a regular file that is not ` +
      "group- or world-writable" +
      (source === "settings.json" || source === "TVAULT_BIN" ? " and must be owned by you" : "") +
      "."
  );
}

/**
 * Resolution order: explicit setting → TVAULT_BIN → bundled npm binary →
 * well-known install prefixes → bare name on PATH (so a `which tvault` that only
 * works in an interactive shell still resolves under the augmented PATH).
 *
 * Memoized for the process lifetime, because resolution spawns `tvault --version`
 * and the app resolves several times per startup (bootstrap, agent status, MCP
 * connect). The path can only change by editing settings.json or the environment,
 * both of which require a restart anyway.
 */
let cached: BinaryInfo | null = null;

export function resolveBinary(): BinaryInfo {
  if (cached) return cached;
  cached = findBinary();
  return cached;
}

function findBinary(): BinaryInfo {
  // Config- and env-supplied paths get the full check (owner + writability),
  // matching the rule the Go side applies to `agent.passphrase_command`.
  const setting = loadSettings().binaryPath?.trim();
  if (setting) {
    if (!existsSync(setting)) {
      throw new Error(`settings.json points at ${setting}, which does not exist`);
    }
    if (!isTrustedExecutable(setting, true)) refuse(setting, "settings.json");
    return probe(setting, "setting");
  }

  const env = process.env.TVAULT_BIN?.trim();
  if (env) {
    // TVAULT_BIN may name a command on PATH rather than an absolute path.
    const resolved = existsSync(env) ? env : whichOnPath(env);
    if (!resolved) throw new Error(`TVAULT_BIN points at ${env}, which does not exist`);
    if (!isTrustedExecutable(resolved, true)) refuse(resolved, "TVAULT_BIN");
    return probe(resolved, "env");
  }

  const fromNpm = resolveFromNpm();
  if (fromNpm) {
    if (!isTrustedExecutable(fromNpm, false)) refuse(fromNpm, "npm package");
    return probe(fromNpm, "npm");
  }

  // Well-known prefixes are skipped if untrusted rather than fatal: a package
  // manager may legitimately install a root-owned binary, and the next candidate
  // is just as good. Writability is still required.
  for (const candidate of localCandidatePaths()) {
    if (existsSync(candidate) && isTrustedExecutable(candidate, false)) {
      return probe(candidate, "path");
    }
  }

  const onPath = whichOnPath("tvault");
  if (onPath) {
    if (!isTrustedExecutable(onPath, false)) refuse(onPath, "PATH");
    return probe(onPath, "path");
  }

  throw new Error(
    "Could not find the tvault binary. Install TinyVault (brew install tvault, or " +
      "npm i -g @thelacanians/tinyvault), or set an explicit path in Settings."
  );
}

function whichOnPath(name: string): string | null {
  try {
    const which = process.platform === "win32" ? "where" : "which";
    const out = execFileSync(which, [name], {
      encoding: "utf8",
      timeout: 5000,
      env: childEnv(),
      stdio: ["ignore", "pipe", "pipe"]
    });
    const first = out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)[0];
    return first && existsSync(first) ? first : null;
  } catch {
    return null;
  }
}

export { childEnv };
