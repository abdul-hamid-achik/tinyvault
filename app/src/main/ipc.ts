import { readdirSync, statSync, type Dirent } from "node:fs";
import { join, resolve as resolvePath } from "node:path";

import { ipcMain } from "electron";

import { IPC } from "@shared/ipc";
import type {
  AuditEntry,
  AuditSinceRequest,
  BackupReport,
  BackupSnapshot,
  Bootstrap,
  EnvDiffResult,
  EnvFileDiff,
  EnvFileList,
  EnvGroupCreateRequest,
  EnvGroupDetail,
  EnvGroupFull,
  EnvImportPreview,
  EnvImportRequest,
  EnvImportResult,
  EnvSealRequest,
  EnvSealResult,
  EnvSyncRequest,
  EnvSyncResult,
  ExportEncryptedRequest,
  ExportEncryptedResult,
  ExportEnvRequest,
  ExportEnvResult,
  GenerateResult,
  IdentityCreated,
  IdentityEntry,
  InheritResult,
  InheritedKey,
  OpenSealedRequest,
  OpenSealedResult,
  ProjectOverview,
  PromoteRequest,
  PromoteResult,
  Result,
  RollbackResult,
  SearchHit,
  SearchRequest,
  SecretMeta,
  SecretVersionMeta,
  SealRequest,
  SealResult,
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
import {
  assertIssued,
  isIssuedFile,
  issueDiscovered,
  pickDirectory,
  pickExistingFile,
  pickSaveFile
} from "./fsaccess";
import { session } from "./mcp";
import { vaultDir } from "./paths";
import { readAgentStatus, readPolicy } from "./policy";
import { setRevealActive } from "./protection";

const ok = <T>(value: T): Result<T> => ({ ok: true, value });

// --- argument hygiene ------------------------------------------------------
//
// IPC arguments come from the renderer, which the threat model treats as
// potentially compromised. Every handler narrows what it forwards: a missing or
// wrong-typed optional becomes `undefined` (so the Go side applies its own
// default) rather than being passed through, and a required string that is not a
// non-empty string is refused outright. Nothing here echoes an argument back
// into an error message.

/** A non-empty string, trimmed, or undefined. */
function str(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

/** A required non-empty string. */
function reqStr(value: unknown, what: string): string {
  const s = str(value);
  if (s === undefined) throw new Error(`${what} is required`);
  return s;
}

/** A positive integer, or undefined. */
function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : undefined;
}

/** A non-empty array of non-empty strings, or undefined. */
function strList(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out: string[] = [];
  for (const item of value) {
    const s = str(item);
    if (s !== undefined) out.push(s);
  }
  return out.length > 0 ? out : undefined;
}

/** A required non-empty array of non-empty strings. */
function reqStrList(value: unknown, what: string): string[] {
  const list = strList(value);
  if (list === undefined) throw new Error(`${what} requires at least one entry`);
  return list;
}

/**
 * Shared argument shaping for the import preview and the import itself — the Go
 * side uses one input struct for both (`importEnvFilesInput = previewEnvImportInput`).
 *
 * Either a dialog-chosen directory or an explicit list of issued files is
 * required. Neither tool is ever called with both omitted, because then it would
 * fall back to scanning the *server's* working directory, which for a GUI app is
 * wherever the binary happened to be launched from.
 */
function importArgs(req: EnvImportRequest): Record<string, unknown> {
  const directory =
    req?.directory === undefined ? undefined : assertIssued(req.directory, "importing");
  const files = Array.isArray(req?.files)
    ? (req.files as unknown[]).map((file) => assertIssued(file, "importing"))
    : undefined;
  if (directory === undefined && (files === undefined || files.length === 0)) {
    // Wording is deliberate. electron-vite's esmShimPlugin picks the insertion
    // point for its CommonJS shim with a regex meant for static import
    // statements, but that regex also matches inside string literals: a message
    // whose LAST WORD is `import`, immediately followed by the closing quote,
    // reads as a bare import of some specifier. The shim is then injected
    // mid-string somewhere later in the chunk and esbuild fails with
    // "Unterminated string literal" pointing at a completely unrelated line, so
    // the cause is very hard to find. Keep the tail of this message — and of any
    // other string in the main process — away from that word.
    throw new Error("choose a folder, or pick at least one dotenv file");
  }
  return {
    project: str(req?.project),
    directory,
    files: files && files.length > 0 ? files : undefined,
    environment: str(req?.environment),
    overwrite: req?.overwrite === true
  };
}

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

  handle(IPC.auditLogSince, async (req: AuditSinceRequest): Promise<AuditEntry[]> => {
    // Timestamps are forwarded as-is after trimming: the Go side parses RFC3339
    // and rejects a malformed bound, which is a better place for that rule to
    // live than a second parser here.
    const out = await session.call<AuditOut>("vault_audit_log_since", {
      since: str(req?.since),
      until: str(req?.until),
      action: str(req?.action),
      resource_type: str(req?.resource_type),
      limit: num(req?.limit)
    });
    return out.entries ?? [];
  });

  // --- environment groups ---

  handle(IPC.envGroups, async (): Promise<EnvGroupDetail[]> => {
    const out = await session.call<EnvGroupListOut>("vault_env_group_list");
    return out.groups ?? [];
  });

  handle(IPC.envGroupCreate, async (req: EnvGroupCreateRequest): Promise<EnvGroupDetail> => {
    // Drop half-filled rows rather than forwarding them: the server requires both
    // a name and an existing project per entry, and a blank row from the UI is a
    // typing artifact, not an intent.
    const environments = (Array.isArray(req?.environments) ? req.environments : [])
      .map((entry) => ({ name: str(entry?.name), project: str(entry?.project) }))
      .filter(
        (entry): entry is { name: string; project: string } =>
          entry.name !== undefined && entry.project !== undefined
      );
    if (environments.length === 0) {
      throw new Error("a group needs at least one environment linked to a project");
    }
    return session.call("vault_env_group_create", {
      name: reqStr(req?.name, "group name"),
      description: str(req?.description),
      environments,
      force: req?.force === true
    });
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

  handle(IPC.envGroupShow, async (name: string): Promise<EnvGroupFull> =>
    session.call("vault_env_group_show", { name: reqStr(name, "group name") })
  );

  handle(
    IPC.envGroupAdd,
    async (group: string, envName: string, project: string): Promise<EnvGroupDetail> =>
      // The field is `env_name`, not `env` — these two tools are the exception
      // among the env-group surface (see envGroupAddInput in tools_env_groups.go).
      session.call("vault_env_group_add", {
        group: reqStr(group, "group name"),
        env_name: reqStr(envName, "environment name"),
        project: reqStr(project, "project name")
      })
  );

  handle(
    IPC.envGroupRemove,
    async (group: string, envName: string): Promise<EnvGroupDetail> =>
      session.call("vault_env_group_remove", {
        group: reqStr(group, "group name"),
        env_name: reqStr(envName, "environment name")
      })
  );

  // Deletes the group's metadata only. The Go handler never touches a project or
  // a secret, so there is nothing here to confirm beyond the group name.
  handle(
    IPC.envGroupDelete,
    async (name: string): Promise<Record<string, never>> =>
      session.call("vault_env_group_delete", { name: reqStr(name, "group name") })
  );

  handle(
    IPC.envInherit,
    async (group: string, env: string, from: string): Promise<InheritResult> =>
      session.call("vault_env_inherit", {
        group: reqStr(group, "group name"),
        env: reqStr(env, "child environment"),
        from: reqStr(from, "base environment")
      })
  );

  // Pin copies the resolved value into the child project; unpin deletes it. Both
  // return an empty object — neither ever reports the value it moved.
  handle(
    IPC.envPin,
    async (group: string, env: string, key: string): Promise<Record<string, never>> =>
      session.call("vault_env_pin", {
        group: reqStr(group, "group name"),
        env: reqStr(env, "child environment"),
        key: reqStr(key, "key")
      })
  );

  handle(
    IPC.envUnpin,
    async (group: string, env: string, key: string): Promise<Record<string, never>> =>
      session.call("vault_env_unpin", {
        group: reqStr(group, "group name"),
        env: reqStr(env, "child environment"),
        key: reqStr(key, "key")
      })
  );

  handle(IPC.envSeal, async (req: EnvSealRequest): Promise<EnvSealResult> => {
    // Always sealed to a file the user chose in a save dialog. Requesting the
    // base64 form instead would pull a whole ciphertext blob into renderer
    // memory for no benefit, so that path is never exercised.
    const outputPath = assertIssued(req?.outputPath, "seal environments");
    return session.call("vault_env_seal", {
      group: reqStr(req?.group, "group name"),
      recipients: reqStrList(req?.recipients, "sealing"),
      keys: strList(req?.keys),
      envs: strList(req?.envs),
      output_path: outputPath
    });
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

  // --- sealing and opening v2 blobs ---
  //
  // Sealing produces ciphertext, which is safe to hand around; opening one writes
  // PLAINTEXT to a 0600 file and returns only that file's path and key names. So
  // `openSealed` is the dangerous direction, and both of its paths are
  // re-validated against the ones main issued through a dialog.

  handle(IPC.sealForRecipients, async (req: SealRequest): Promise<SealResult> => {
    const outputPath = assertIssued(req?.outputPath, "sealing");
    return session.call("vault_seal_for_recipients", {
      project: str(req?.project),
      recipients: reqStrList(req?.recipients, "sealing"),
      keys: strList(req?.keys),
      output_path: outputPath
    });
  });

  handle(IPC.exportEnvEncrypted, async (req: ExportEncryptedRequest): Promise<ExportEncryptedResult> => {
    // No recipients argument: this tool seals to the project's current set.
    const outputPath = assertIssued(req?.outputPath, "encrypted export");
    return session.call("vault_export_env_encrypted", {
      project: str(req?.project),
      keys: strList(req?.keys),
      output_path: outputPath
    });
  });

  handle(IPC.openSealed, async (req: OpenSealedRequest): Promise<OpenSealedResult> => {
    const blob = assertIssued(req?.path, "opening a sealed file");
    if (!isIssuedFile(blob)) throw new Error("that sealed file does not exist");
    const outputPath = assertIssued(req?.outputPath, "opening a sealed file");
    return session.call("vault_open_sealed", {
      path: blob,
      identity: str(req?.identity),
      output_path: outputPath
    });
  });

  // --- dotenv workflows ---
  //
  // The renderer cannot author a path anywhere in this section. Dialogs are
  // answered in main and recorded; discovered dotenv files are recorded too, so
  // the user can act on a listed file without a dialog per file. Anything not in
  // that record is refused before a tool call is made.

  handle(IPC.pickDirectory, async (title: string): Promise<string | null> =>
    pickDirectory(str(title) ?? "Choose a project folder")
  );

  handle(IPC.pickSaveFile, async (title: string, defaultName: string): Promise<string | null> =>
    pickSaveFile(str(title) ?? "Save file", str(defaultName) ?? ".env")
  );

  handle(IPC.pickEnvFile, async (title: string): Promise<string | null> =>
    pickExistingFile(str(title) ?? "Choose a dotenv file")
  );

  handle(
    IPC.listEnvFiles,
    async (directory: string, environment?: string): Promise<EnvFileList> => {
      const dir = assertIssued(directory, "scanning for dotenv files");
      const out = await session.call<EnvFileList>("vault_list_env_files", {
        directory: dir,
        environment: str(environment)
      });
      const files = out.files ?? [];
      // Names only, and already restricted to the dotenv allowlist by the Go
      // parser — recording them cannot widen what the renderer may read.
      issueDiscovered(files.map((f) => f.path));
      issueDiscovered(out.suggested_files ?? []);
      return { ...out, files };
    }
  );

  handle(IPC.previewEnvImport, async (req: EnvImportRequest): Promise<EnvImportPreview> =>
    session.call("vault_preview_env_import", importArgs(req))
  );

  handle(IPC.importEnvFiles, async (req: EnvImportRequest): Promise<EnvImportResult> =>
    session.call("vault_import_env_files", importArgs(req))
  );

  handle(
    IPC.diffEnv,
    async (file: string, project: string, compareValues: boolean): Promise<EnvFileDiff> => {
      const path = assertIssued(file, "comparing a dotenv file");
      if (!isIssuedFile(path)) throw new Error("that dotenv file does not exist");
      return session.call("vault_diff_env", {
        file: path,
        project: str(project),
        // Verdicts only: same/differs/error per shared key, never a value.
        compare_values: compareValues === true
      });
    }
  );

  handle(IPC.syncEnv, async (req: EnvSyncRequest): Promise<EnvSyncResult> => {
    const direction = req?.direction;
    if (direction !== "pull" && direction !== "push" && direction !== "mirror") {
      throw new Error("direction must be pull, push, or mirror");
    }
    // Required: the tool's own default is `.env` under the server's working
    // directory, which for a GUI app is wherever the binary was launched from.
    const path = assertIssued(req?.path, "syncing a dotenv file");
    return session.call("vault_sync_env", {
      direction,
      path,
      project: str(req?.project),
      overwrite: req?.overwrite === true
    });
  });

  handle(IPC.exportEnv, async (req: ExportEnvRequest): Promise<ExportEnvResult> => {
    // Writes PLAINTEXT to disk. The path is dialog-issued and the response is the
    // tool's own metadata — path, count, key names — so no value crosses back.
    const outputPath = assertIssued(req?.outputPath, "exporting secrets");
    const format = req?.format === "json" || req?.format === "shell" ? req.format : "dotenv";
    return session.call("vault_export_env", {
      project: str(req?.project),
      format,
      output_path: outputPath,
      keys: strList(req?.keys),
      group: str(req?.group),
      env: str(req?.env)
    });
  });

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
