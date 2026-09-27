import { spawn } from "node:child_process";

import { augmentedPath, resolveBinary } from "./binary";

export interface CliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface CliOptions {
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  /** Fed to the child's stdin, then closed. Never a shell string. */
  stdin?: string;
}

export type JsonResult<T> = { ok: true; value: T } | { ok: false; error: string };

/**
 * Spawns `tvault` with the given argv. No shell is ever involved, so arguments
 * cannot be re-interpreted — the same rule the Go CLI applies to
 * `agent.passphrase_command`.
 *
 * Output is capped: a runaway child should not be able to exhaust the main
 * process heap.
 */
export function runCli(args: string[], opts: CliOptions = {}): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    let bin: string;
    try {
      bin = resolveBinary().path;
    } catch (err) {
      reject(err instanceof Error ? err : new Error(String(err)));
      return;
    }

    const child = spawn(bin, args, {
      env: { PATH: augmentedPath(), ...(opts.env ?? process.env) },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true
    });

    const MAX = 8 * 1024 * 1024;
    let stdout = "";
    let stderr = "";
    let settled = false;

    const timer = opts.timeoutMs
      ? setTimeout(() => {
          if (settled) return;
          settled = true;
          child.kill("SIGKILL");
          reject(new Error(`tvault ${args[0] ?? ""} timed out after ${opts.timeoutMs}ms`));
        }, opts.timeoutMs)
      : null;

    child.stdout.on("data", (d: Buffer) => {
      if (stdout.length < MAX) stdout += d.toString();
    });
    child.stderr.on("data", (d: Buffer) => {
      if (stderr.length < MAX) stderr += d.toString();
    });

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      reject(err);
    });

    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ exitCode: code ?? -1, stdout, stderr });
    });

    if (opts.stdin !== undefined) {
      child.stdin.on("error", () => {});
      child.stdin.end(opts.stdin);
    } else {
      child.stdin.end();
    }
  });
}

/** Runs a command expected to emit JSON on stdout. */
export async function runCliJson<T>(args: string[], opts: CliOptions = {}): Promise<JsonResult<T>> {
  try {
    const res = await runCli(args, opts);
    if (res.exitCode !== 0) {
      const detail = res.stderr.trim() || res.stdout.trim() || `exit ${res.exitCode}`;
      return { ok: false, error: `tvault ${args.join(" ")} failed: ${detail}`.slice(0, 500) };
    }
    const text = res.stdout.trim();
    if (!text) return { ok: false, error: "empty JSON output" };
    return { ok: true, value: JSON.parse(text) as T };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
