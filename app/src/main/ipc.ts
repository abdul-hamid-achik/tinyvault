import { readdirSync, statSync, type Dirent } from "node:fs";
import { join, resolve as resolvePath } from "node:path";

import { ipcMain } from "electron";

import { IPC } from "@shared/ipc";
import type {
  AuditEntry,
  BackupReport,
  BackupSnapshot,
  Bootstrap,
  EnvDiffResult,
  EnvGroupDetail,
  GenerateResult,
  IdentityCreated,
  IdentityEntry,
  InheritedKey,
  ProjectOverview,
  PromoteRequest,
  PromoteResult,
  Result,
  RollbackResult,
  SearchHit,
  SearchRequest,
  SecretMeta,
  SecretVersionMeta,
  SessionInfo,
  ShareResult,
  RestoreReport,
  UnshareResult,
  VaultStatus
} from "@shared/types";

import { resolveBinary } from "./binary";
import { runCliJson } from "./cli";
import { writeSecretToClipboard } from "./clipboard";
import { readBackupDir } from "./config";
import { session } from "./mcp";
import { vaultDir } from "./paths";
import { readAgentStatus, readPolicy } from "./policy";
import { setRevealActive } from "./protection";

const ok = <T>(value: T): Result<T> => ({ ok: true, value });

// Snapshot naming, mirroring cmd/tvault/cmd/backup.go: rotated snapshots are
// vault-<timestamp>.db[.gz]; when backup.dir is unset the pre-restore safety
// copy lands next to the database as vault.db.pre-restore-<timestamp>.
const SNAPSHOT_RE = /^vault-.*\.db(\.gz)?$/;
const PRE_RESTORE_RE = /^vault\.db\.pre-restore-.+$/;

function backupDirs(): string[] {
  const dirs = new Set<string>();
  const configured = readBackupDir();
  if (configured) dirs.add(configured);
  dirs.add(vaultDir());
  return [...dirs];
}

/**
 * Scans the backup directory (and the vault directory, where snapshots fall
 * when backup.dir is unset) for files matching the snapshot conventions.
 * Filenames and sizes only — a snapshot is never opened, so nothing sensitive
 * is read here.
 */
function listSnapshots(): BackupSnapshot[] {
  const out: BackupSnapshot[] = [];
  for (const dir of backupDirs()) {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (!SNAPSHOT_RE.test(entry.name) && !PRE_RESTORE_RE.test(entry.name)) continue;
      const path = join(dir, entry.name);
      try {
        const st = statSync(path);
        out.push({
          path,
          name: entry.name,
          dir,
          bytes: st.size,
          created_at: st.mtime.toISOString(),
          compressed: entry.name.endsWith(".gz")
        });
      } catch {
        continue;
      }
    }
  }
  return out.sort((a, b) => b.created_at.localeCompare(a.created_at));
}

const fail = (err: unknown): Result<never> => ({
  ok: false,
  error: err instanceof Error ? err.message : String(err)
});

/**
 * Wraps a handler so a throw becomes a typed Result instead of an IPC rejection.
 *
 * `A` is declared before `T` on purpose: callers never pass explicit type
 * arguments, and supplying even one would disable inference for the rest. The
 * renderer's type safety comes from `TvaultApi`, not from these registrations.
 */
function handle<A extends unknown[], T>(
  channel: string,
  fn: (...args: A) => Promise<T>
): void {
  ipcMain.handle(channel, async (_event, ...args: A): Promise<Result<T>> => {
    try {
      return ok(await fn(...args));
    } catch (err) {
      // Secret values must never leak through an error string. The Go side does
      // not interpolate values into its error messages, so these are safe to
      // surface verbatim.
      return fail(err);
    }
  });
}

interface ProjectsOverviewOut {
  projects: ProjectOverview[];
}
interface ListSecretsDetailedOut {
  project: string;
  secrets: SecretMeta[];
}
interface GetSecretOut {
  key: string;
  value: string;
  warning: string;
  source?: string;
}
interface HistoryOut {
  versions: SecretVersionMeta[];
}
interface SearchOut {
  results: SearchHit[];
  count: number;
}
interface AuditOut {
  entries: AuditEntry[];
}
interface EnvGroupListOut {
  groups: EnvGroupDetail[];
}
interface EnvInheritedOut {
  keys: InheritedKey[];
}
interface CurrentProjectOut {
  current_project: string;
}

export function registerIpc(): void {
  handle(IPC.bootstrap, async (): Promise<Bootstrap> => {
    let binary: Bootstrap["binary"] = null;
    let binaryError: string | undefined;
    try {
      binary = resolveBinary();
    } catch (err) {
      binaryError = err instanceof Error ? err.message : String(err);
    }

    const policy = readPolicy();
    const agent = await readAgentStatus();

    let status: VaultStatus | null = null;
    let currentProject: string | null = null;

    if (binary) {
      try {
        status = await session.call<VaultStatus>("vault_status");
        const cur = await session.call<CurrentProjectOut>("vault_get_current_project");
        currentProject = cur.current_project || null;
      } catch {
        // The setup screen surfaces session.last_error; do not mask it here.
      }
    }

    return {
      binary,
      binary_error: binaryError,
      vault_dir: vaultDir(),
      status,
      policy,
      agent,
      session: session.info(),
      current_project: currentProject
    };
  });

  handle(IPC.restartSession, async (): Promise<SessionInfo> => {
    await session.restart();
    return session.info();
  });

  handle(IPC.sessionInfo, async (): Promise<SessionInfo> => session.info());

  // --- projects ---

  handle(IPC.projectsOverview, async (): Promise<ProjectOverview[]> => {
    const out = await session.call<ProjectsOverviewOut>("vault_projects_overview");
    return out.projects ?? [];
  });

  handle(
    IPC.createProject,
    async (name: string, description: string): Promise<{ name: string; created: boolean }> =>
      session.call("vault_create_project", { name, description: description || undefined })
  );

  handle(
    IPC.deleteProject,
    async (name: string): Promise<{ name: string; deleted: boolean }> =>
      session.call("vault_delete_project", { name })
  );

  handle(
    IPC.setCurrentProject,
    async (name: string): Promise<{ name: string; set: boolean }> =>
      session.call("vault_set_current_project", { name })
  );

  // --- secrets ---

  handle(IPC.listSecrets, async (project: string): Promise<SecretMeta[]> => {
    // vault_list_secrets_detailed, NOT vault_list_secrets: the latter hardcodes
    // version 1 for every key (secretMeta in tools_secrets.go).
    const out = await session.call<ListSecretsDetailedOut>("vault_list_secrets_detailed", {
      project
    });
    return out.secrets ?? [];
  });

  handle(
    IPC.revealSecret,
    async (project: string, key: string): Promise<{ key: string; value: string }> => {
      const out = await session.call<GetSecretOut>("vault_get_secret", { project, key });
      return { key: out.key, value: out.value };
    }
  );

  handle(
    IPC.setSecret,
    async (project: string, key: string, value: string): Promise<{ key: string }> =>
      session.call("vault_set_secret", { project, key, value })
  );

  handle(
    IPC.deleteSecret,
    async (project: string, key: string): Promise<{ key: string; deleted: boolean }> =>
      session.call("vault_delete_secret", { project, key })
  );

  handle(
    IPC.generateSecret,
    async (
      project: string,
      key: string,
      length: number,
      charset: string
    ): Promise<GenerateResult> =>
      session.call("vault_generate_secret", { project, key, length, charset })
  );

  handle(IPC.history, async (project: string, key: string): Promise<SecretVersionMeta[]> => {
    const out = await session.call<HistoryOut>("vault_secret_history", { project, key });
    return out.versions ?? [];
  });

  handle(
    IPC.rollback,
    async (project: string, key: string, toVersion: number): Promise<RollbackResult> =>
      session.call("vault_rollback_secret", { project, key, to_version: toVersion })
  );

  handle(IPC.searchSecrets, async (req: SearchRequest): Promise<SearchHit[]> => {
    const out = await session.call<SearchOut>("vault_list_secrets_global", {
      prefix: req.prefix || undefined,
      name_like: req.name_like || undefined,
      limit: req.limit || undefined
    });
    return out.results ?? [];
  });

  // --- audit ---

  handle(IPC.auditLog, async (limit: number): Promise<AuditEntry[]> => {
    const out = await session.call<AuditOut>("vault_audit_log", { limit });
    return out.entries ?? [];
  });

  // --- environment groups ---

  handle(IPC.envGroups, async (): Promise<EnvGroupDetail[]> => {
    const out = await session.call<EnvGroupListOut>("vault_env_group_list");
    return out.groups ?? [];
  });

  handle(
    IPC.envDiff,
    async (group: string, values: boolean): Promise<EnvDiffResult> =>
      session.call("vault_env_diff", { group, values })
  );

  handle(IPC.envPromote, async (req: PromoteRequest): Promise<PromoteResult> =>
    session.call("vault_env_promote", {
      group: req.group,
      from_env: req.from_env,
      to_env: req.to_env,
      keys: req.keys?.length ? req.keys : undefined,
      all: req.all ?? false,
      dry_run: req.dry_run ?? false
    })
  );

  handle(IPC.envInherited, async (group: string, env: string): Promise<InheritedKey[]> => {
    const out = await session.call<EnvInheritedOut>("vault_env_inherited", { group, env });
    return out.keys ?? [];
  });

  // --- sharing / identities ---
  //
  // Every one of these returns public halves only (tvault1…). The private key
  // (tvault-key1…) is never returned by the Go side, and `tvault identity export`
  // stays CLI-only and TTY-guarded, so this app cannot leak one.

  handle(IPC.identities, async (): Promise<IdentityEntry[]> => {
    const out = await session.call<{ identities: IdentityEntry[] }>("vault_identity_list");
    return out.identities ?? [];
  });

  handle(IPC.newIdentity, async (name: string): Promise<IdentityCreated> =>
    session.call("vault_identity_new", { name: name || undefined })
  );

  handle(IPC.recipients, async (project: string): Promise<string[]> => {
    const out = await session.call<{ project: string; recipients: string[] }>(
      "vault_project_recipients",
      { project }
    );
    return out.recipients ?? [];
  });

  handle(
    IPC.shareProject,
    async (project: string, recipient: string): Promise<ShareResult> =>
      session.call("vault_share_project", { project, recipient })
  );

  handle(
    IPC.unshareProject,
    async (project: string, recipient: string): Promise<UnshareResult> =>
      session.call("vault_unshare_project", { project, recipient })
  );

  // --- CLI-only operations (verified: no MCP tool exists for these) ---

  handle(IPC.backup, async (): Promise<BackupReport> => {
    // No destination argument by design — see TvaultApi.backup. Letting the
    // renderer choose a path would make this an arbitrary-file-write primitive.
    // `--json` exists for backup as of the single-encoder change, so parse the
    // report instead of scraping the human-readable line.
    const res = await runCliJson<BackupReport>(["backup", "--json"], { timeoutMs: 120_000 });
    if (!res.ok) throw new Error(res.error);
    return res.value;
  });

  handle(
    IPC.doctor,
    async (): Promise<{ healthy: boolean; failed: string[]; checks: unknown }> => {
      const res = await runCliJson<{ healthy: boolean; failed: string[]; checks: unknown }>(
        ["doctor", "--json"],
        { timeoutMs: 30_000 }
      );
      if (!res.ok) throw new Error(res.error);
      return res.value;
    }
  );

  // --- snapshots and restore ---

  handle(IPC.listBackups, async (): Promise<BackupSnapshot[]> => listSnapshots());

  handle(IPC.restore, async (requested: string): Promise<RestoreReport> => {
    // Restore replaces the vault database, so the path is not the renderer's to
    // choose. The only acceptable values are the ones listSnapshots() returned:
    // a regular file, in backup.dir or the vault directory, matching the
    // snapshot naming convention. Anything else is refused outright.
    const allowed = new Set(listSnapshots().map((s) => s.path));
    const resolved = resolvePath(requested);
    if (!allowed.has(resolved)) {
      throw new Error(
        "refusing to restore: the path is not a snapshot this app listed (backup.dir or the vault directory)"
      );
    }
    const res = await runCliJson<RestoreReport>(["restore", resolved, "--yes", "--json"], {
      timeoutMs: 300_000
    });
    if (!res.ok) throw new Error(res.error);
    return res.value;
  });

  handle(IPC.copySecret, async (value: string): Promise<{ clearsInMs: number }> => {
    if (typeof value !== "string" || value.length === 0) {
      throw new Error("nothing to copy");
    }
    return writeSecretToClipboard(value);
  });

  handle(IPC.setProtectionActive, async (active: boolean): Promise<void> => {
    setRevealActive(active === true);
  });
}
