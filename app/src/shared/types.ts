/**
 * Shared contract between the main process, the preload bridge and the renderer.
 *
 * Every field name mirrors the Go structs in internal/mcp exactly — those are the
 * wire shapes `tvault mcp` emits, so renaming here would silently break parsing.
 */

export type Result<T> = { ok: true; value: T } | { ok: false; error: string };

export type AccessMode = "read-only" | "read-write" | "full";

// --- vault_status → internal/vault.Status ---
export interface VaultStatus {
  vault_id: string;
  path: string;
  is_unlocked: boolean;
  project_count: number;
  created_at: string;
}

// --- vault_projects_overview → projectOverviewItem ---
export interface ProjectOverview {
  name: string;
  description: string;
  secret_count: number;
  created_at: string;
  updated_at: string;
}

// --- vault_list_secrets_detailed → secretMetaOut ---
//
// Deliberately NOT vault_list_secrets: that tool hardcodes version 1 for every
// key (see secretMeta in tools_secrets.go). The detailed variant is the only
// accurate source of per-key version + timestamps.
export interface SecretMeta {
  key: string;
  version: number;
  created_at: string;
  updated_at: string;
}

// --- vault_secret_history → secretVersionMeta ---
export interface SecretVersionMeta {
  version: number;
  created_at: string;
  updated_at: string;
}

// --- vault_rollback_secret → rollbackSecretOutput ---
export interface RollbackResult {
  rolled_back: boolean;
  rolled_back_from: number;
  new_version: number;
}

// --- vault_generate_secret → generateSecretOutput ---
// Never carries the generated value; that is the tool's whole point.
export interface GenerateResult {
  key: string;
  length: number;
  charset: string;
  stored: boolean;
}

// --- vault_list_secrets_global / vault_search_secrets → secretRefOut ---
export interface SearchHit {
  project: string;
  key: string;
  version: number;
  updated_at: string;
}

// --- vault_audit_log → store.AuditEntry ---
export interface AuditEntry {
  action: string;
  resource_type: string;
  resource_id?: string;
  resource_name?: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

// --- env groups ---
export interface EnvGroupEntry {
  name: string;
  project: string;
}

export interface EnvGroupDetail {
  name: string;
  description?: string;
  environments: EnvGroupEntry[];
}

export type EnvEntryStatus = "same" | "different" | "missing" | "local-only";

export interface EnvDiffEntry {
  env: string;
  present: boolean;
  status: EnvEntryStatus;
}

export interface EnvDiffKey {
  key: string;
  environments: EnvDiffEntry[];
}

export interface EnvDiffResult {
  group: string;
  status: "ok" | "drift";
  keys: EnvDiffKey[];
}

export interface PromotedKey {
  key: string;
  from_version: number;
  to_version: number;
}

export interface SkippedKey {
  key: string;
  reason: string;
}

export interface PromoteResult {
  promoted: PromotedKey[];
  skipped: SkippedKey[];
}

export interface InheritedKey {
  key: string;
  // "local" | "inherited:<env>" | "missing"
  source: string;
  pinned: boolean;
}

export interface PromoteRequest {
  group: string;
  from_env: string;
  to_env: string;
  keys?: string[];
  all?: boolean;
  dry_run?: boolean;
}

export interface SearchRequest {
  prefix?: string;
  name_like?: string;
  limit?: number;
}

// --- vault_audit_log_since → auditLogSinceInput / store.AuditEntry ---
export interface AuditSinceRequest {
  /** RFC3339. Entries at or after this instant. */
  since?: string;
  /** RFC3339. Entries at or before this instant. */
  until?: string;
  /** Exact action, e.g. `secret.read`. */
  action?: string;
  /** Exact resource type, e.g. `secret`. */
  resource_type?: string;
  /** Default 100, max 1000. */
  limit?: number;
}

// --- vault_env_group_create → envGroupCreateInput ---
export interface EnvGroupCreateRequest {
  name: string;
  description?: string;
  /** At least one environment → existing project link. Creates no project. */
  environments: Array<{ name: string; project: string }>;
  /** Overwrite an existing group, or re-link a project already in another group. */
  force?: boolean;
}

// --- vault_env_group_show → envGroupShowOutput ---
export interface EnvGroupFull {
  name: string;
  description?: string;
  environments: EnvGroupEntry[];
  /** `ok` | `drift` | `unknown` — unknown when the group could not be compared. */
  diff_status: string;
  /** Child environment → base environment, for environments that inherit. */
  inheritance?: Record<string, string>;
}

// --- vault_env_inherit → envInheritOutput ---
export interface InheritResult {
  group: string;
  env: string;
  inherits_from: string;
}

// --- sealing: vault_seal_for_recipients / vault_export_env_encrypted ---
//
// Ciphertext only, by construction. The app always supplies an output path, so
// `sealed_base64` stays empty and no blob is ever held in renderer memory.
export interface SealResult {
  path?: string;
  sealed_base64?: string;
  bytes: number;
  count: number;
  keys: string[];
  recipient_count: number;
}

/** vault_export_env_encrypted returns the same shape. */
export type ExportEncryptedResult = SealResult;

// --- vault_env_seal → envSealOutput (environments instead of a key count) ---
export interface EnvSealResult {
  path?: string;
  sealed_base64?: string;
  bytes: number;
  environments: string[];
  keys: string[];
  recipient_count: number;
}

// --- vault_open_sealed → openSealedOutput ---
// The decrypted dotenv is written to disk at 0600; only its path and key names
// come back. Plaintext never crosses the bridge.
export interface OpenSealedResult {
  path: string;
  count: number;
  keys: string[];
}

export interface SealRequest {
  project?: string;
  recipients: string[];
  keys?: string[];
  /** Must be a path main issued through a save dialog. */
  outputPath: string;
}

export interface EnvSealRequest {
  group: string;
  recipients: string[];
  keys?: string[];
  envs?: string[];
  /** Must be a path main issued through a save dialog. */
  outputPath: string;
}

export interface OpenSealedRequest {
  /** A v2 `.env.encrypted` blob, chosen through a file dialog. */
  path: string;
  /** Identity name; defaults to $TVAULT_IDENTITY, else `default`. */
  identity?: string;
  /** Where to write the 0600 dotenv; must be dialog-issued. */
  outputPath: string;
}

// --- dotenv discovery: vault_list_env_files → listEnvFilesOutput ---
export interface EnvFileInfo {
  diagnostic_count: number;
  key_count: number;
  path: string;
  suggested?: boolean;
}

export interface EnvFileList {
  directory: string;
  environment?: string;
  files: EnvFileInfo[];
  suggested_files: string[];
}

// --- dotenv import: vault_preview_env_import / vault_import_env_files ---
// Neither carries a value: the preview reports key names and actions, the import
// reports which key names landed.
export interface DotenvDiagnostic {
  path: string;
  line?: number;
  key?: string;
  message: string;
}

export interface EnvImportKeyPreview {
  /** `create` | `overwrite` | `skip` */
  action: string;
  key: string;
  source_path: string;
}

export interface EnvImportRequest {
  project?: string;
  /** Must be a directory main issued through a folder dialog. */
  directory?: string;
  /** Must be paths main issued (dialog, or discovered by listEnvFiles). */
  files?: string[];
  environment?: string;
  overwrite?: boolean;
}

export interface EnvImportPreview {
  blocked_count: number;
  create_count: number;
  diagnostic_count: number;
  diagnostics: DotenvDiagnostic[];
  files: string[];
  keys: EnvImportKeyPreview[];
  blocked_keys: string[];
  overwrite_count: number;
  project: string;
  skip_count: number;
}

export interface EnvImportResult {
  blocked_count: number;
  blocked_keys: string[];
  create_count: number;
  diagnostic_count: number;
  diagnostics: DotenvDiagnostic[];
  files: string[];
  imported_keys: string[];
  overwrite_count: number;
  project: string;
  skipped_keys: string[];
  skip_count: number;
}

// --- vault_diff_env → diffEnvOutput ---
export interface EnvFileDiff {
  project: string;
  file: string;
  only_in_vault: string[];
  only_in_file: string[];
  in_both: string[];
  /** Per shared key: `same` | `differs` | `error`. Present only with compareValues. */
  value_diffs?: Record<string, string>;
  in_sync: boolean;
}

// --- vault_sync_env → syncEnvOutput ---
export type SyncDirection = "pull" | "push" | "mirror";

export interface SyncConflict {
  key: string;
  resolution: string;
}

export interface EnvSyncRequest {
  direction: SyncDirection;
  /**
   * Required, and must be a path main issued. The Go tool defaults to `.env`
   * relative to the *server's* working directory, which for a GUI app is
   * whatever directory the binary happened to be launched from — so this app
   * never relies on that default.
   */
  path: string;
  project?: string;
  overwrite?: boolean;
}

export interface EnvSyncResult {
  direction: string;
  project: string;
  path: string;
  env_created: boolean;
  vault_entries: number;
  env_entries: number;
  created: string[];
  updated: string[];
  skipped: string[];
  unchanged: string[];
  conflicts: SyncConflict[];
}

// --- vault_export_env → exportEnvOutput ---
// Writes PLAINTEXT to disk and returns only the path, count, and key names.
export interface ExportEnvRequest {
  project?: string;
  format?: "dotenv" | "json" | "shell";
  keys?: string[];
  group?: string;
  env?: string;
  /** Must be a path main issued through a save dialog. */
  outputPath: string;
}

export interface ExportEnvResult {
  path: string;
  count: number;
  keys: string[];
}

// --- vault_export_env_encrypted → exportEnvEncryptedInput ---
// Takes no recipients: it seals to the project's current recipient set.
export interface ExportEncryptedRequest {
  project?: string;
  keys?: string[];
  /** Must be a path main issued through a save dialog. */
  outputPath: string;
}

// --- diagnostics ---
export interface BinaryInfo {
  path: string;
  // env | npm | path | setting
  source: string;
  version: string;
}

export interface PolicyInfo {
  exists: boolean;
  path: string;
  access_mode?: AccessMode;
  allow_exec?: boolean;
  redact_output?: boolean;
  max_reads_per_session?: number;
  secrets_deny?: string[];
  projects_deny?: string[];
  parse_error?: string;
}

export interface AgentInfo {
  running: boolean;
  pid?: number;
  socket?: string;
  project?: string;
  uptime_seconds?: number;
  idle_remaining_seconds?: number;
  stale_socket?: boolean;
}

export type McpBackend = "kek" | "agent" | "unknown";

export interface SessionInfo {
  connected: boolean;
  server_name?: string;
  server_version?: string;
  tool_count?: number;
  backend: McpBackend;
  // vault_get_secret is capped by policy.max_reads_per_session for the lifetime
  // of one `tvault mcp` process. When used >= limit every reveal fails until the
  // session is restarted, so the UI surfaces the budget instead of erroring late.
  reads_used: number;
  reads_limit: number;
  /**
   * True when max_reads_per_session is 0, which the Go server treats as DENY
   * (consumeValueRead returns false for limit <= 0) rather than unlimited.
   */
  reveals_denied: boolean;
  started_at?: number;
  last_error?: string;
}

export interface Bootstrap {
  binary: BinaryInfo | null;
  binary_error?: string;
  vault_dir: string;
  status: VaultStatus | null;
  policy: PolicyInfo;
  agent: AgentInfo;
  session: SessionInfo;
  current_project: string | null;
}

// --- sharing / identities ---
export interface IdentityEntry {
  name: string;
  recipient: string;
}

export interface IdentityCreated {
  name: string;
  recipient: string;
  path: string;
}

export interface ShareResult {
  project: string;
  recipient: string;
  shared: boolean;
}

export interface UnshareResult {
  project: string;
  recipient: string;
  revoked: boolean;
}

// --- backup report: the --json shape of `tvault backup` (cmd/tvault/cmd/backup.go) ---
export interface BackupReport {
  path: string;
  bytes: number;
  raw_bytes: number;
  compressed: boolean;
  immutable: boolean;
  created_at: string;
}

// --- snapshots on disk, listed by main; the renderer never scans the fs ---
export interface BackupSnapshot {
  path: string;
  name: string;
  dir: string;
  bytes: number;
  created_at: string;
  compressed: boolean;
}

// --- the --json shape of `tvault restore` ---
export interface RestoreReport {
  restored: boolean;
  source: string;
  vault_dir: string;
  saved_snapshot?: string;
  restored_at: string;
}

// --- the bridge surface exposed on window.tvault ---
export interface TvaultApi {
  /**
   * Host platform, for layout only: the macOS traffic lights sit inside the
   * window, so the leftmost header row must clear them. Sandboxed preloads can
   * read process.platform even though the renderer cannot.
   */
  readonly platform: string;

  bootstrap(): Promise<Result<Bootstrap>>;
  restartSession(): Promise<Result<SessionInfo>>;
  /** Cheap read of the session counters — used to keep the reveal budget live. */
  sessionInfo(): Promise<Result<SessionInfo>>;

  projectsOverview(): Promise<Result<ProjectOverview[]>>;
  createProject(name: string, description: string): Promise<Result<{ name: string; created: boolean }>>;
  deleteProject(name: string): Promise<Result<{ name: string; deleted: boolean }>>;
  setCurrentProject(name: string): Promise<Result<{ name: string; set: boolean }>>;

  listSecrets(project: string): Promise<Result<SecretMeta[]>>;
  revealSecret(project: string, key: string): Promise<Result<{ key: string; value: string }>>;
  setSecret(project: string, key: string, value: string): Promise<Result<{ key: string }>>;
  deleteSecret(project: string, key: string): Promise<Result<{ key: string; deleted: boolean }>>;
  generateSecret(
    project: string,
    key: string,
    length: number,
    charset: string
  ): Promise<Result<GenerateResult>>;
  history(project: string, key: string): Promise<Result<SecretVersionMeta[]>>;
  rollback(project: string, key: string, toVersion: number): Promise<Result<RollbackResult>>;
  searchSecrets(req: SearchRequest): Promise<Result<SearchHit[]>>;

  auditLog(limit: number): Promise<Result<AuditEntry[]>>;
  /**
   * Time-range and action filters over the same metadata-only log. Timestamps
   * are RFC3339; omit a bound to leave that side open.
   */
  auditLogSince(req: AuditSinceRequest): Promise<Result<AuditEntry[]>>;

  envGroups(): Promise<Result<EnvGroupDetail[]>>;
  /**
   * Links existing projects as named environments of one application. Creates no
   * project and copies no value — a group is pure metadata.
   */
  envGroupCreate(req: EnvGroupCreateRequest): Promise<Result<EnvGroupDetail>>;
  envDiff(group: string, values: boolean): Promise<Result<EnvDiffResult>>;
  envPromote(req: PromoteRequest): Promise<Result<PromoteResult>>;
  envInherited(group: string, env: string): Promise<Result<InheritedKey[]>>;
  /** One group with its drift status and inheritance pointers. No values. */
  envGroupShow(name: string): Promise<Result<EnvGroupFull>>;
  envGroupAdd(group: string, envName: string, project: string): Promise<Result<EnvGroupDetail>>;
  /** Detaches an environment; the underlying project and its secrets survive. */
  envGroupRemove(group: string, envName: string): Promise<Result<EnvGroupDetail>>;
  /** Deletes the group only — never a project or a secret. */
  envGroupDelete(name: string): Promise<Result<Record<string, never>>>;
  envInherit(group: string, env: string, from: string): Promise<Result<InheritResult>>;
  /** Writes the resolved value into the child, breaking inheritance for that key. */
  envPin(group: string, env: string, key: string): Promise<Result<Record<string, never>>>;
  /** Deletes the pinned value, restoring inheritance. Returns no value. */
  envUnpin(group: string, env: string, key: string): Promise<Result<Record<string, never>>>;
  /** Seals every (or some) environment into one recipient-sealed v2 blob. */
  envSeal(req: EnvSealRequest): Promise<Result<EnvSealResult>>;

  // Sharing. Identities and recipients are public halves only (tvault1…); the
  // private key (tvault-key1…) is never returned by any of these, and exporting
  // it stays a CLI-only, TTY-guarded operation.
  identities(): Promise<Result<IdentityEntry[]>>;
  newIdentity(name: string): Promise<Result<IdentityCreated>>;
  recipients(project: string): Promise<Result<string[]>>;
  shareProject(project: string, recipient: string): Promise<Result<ShareResult>>;
  unshareProject(project: string, recipient: string): Promise<Result<UnshareResult>>;

  /**
   * Seals a project's secrets to X25519 recipients and writes a commit-safe v2
   * `.env.encrypted`. Returns metadata about the ciphertext — never plaintext,
   * and (because the path is always supplied) never the blob itself either.
   */
  sealForRecipients(req: SealRequest): Promise<Result<SealResult>>;

  /**
   * Opens a v2 blob with a local identity and writes a `0600` dotenv. Only the
   * path, a count, and key names come back; the decrypted values stay on disk.
   * Both paths are re-validated in main against the ones it issued.
   */
  openSealed(req: OpenSealedRequest): Promise<Result<OpenSealedResult>>;

  // --- dotenv workflows ---------------------------------------------------
  //
  // Path handling is the whole security story here. `export_env` writes
  // PLAINTEXT, `sync_env --direction pull` overwrites a file, and `diff_env` /
  // `import_env_files` read one. So the renderer never authors a path: it asks
  // main for a dialog, and main records what the user actually chose (see
  // main/fsaccess.ts). Every handler below re-validates against that record.

  /** Folder picker. Resolves null when the user cancelled. */
  pickDirectory(title: string): Promise<Result<string | null>>;
  /** Save dialog, for files this app is about to write. Null on cancel. */
  pickSaveFile(
    title: string,
    defaultName: string,
    /** Seed folder — must itself be a path main issued (a folder you picked). */
    defaultDir?: string
  ): Promise<Result<string | null>>;
  /** Open dialog, for an existing file this app is about to read. Null on cancel. */
  pickEnvFile(title: string): Promise<Result<string | null>>;

  /** Dotenv-family files in a directory: names, key counts, parse diagnostics. */
  listEnvFiles(directory: string, environment?: string): Promise<Result<EnvFileList>>;
  previewEnvImport(req: EnvImportRequest): Promise<Result<EnvImportPreview>>;
  importEnvFiles(req: EnvImportRequest): Promise<Result<EnvImportResult>>;
  /** Drift between a `.env` and the project. Verdicts only, never values. */
  diffEnv(file: string, project: string, compareValues: boolean): Promise<Result<EnvFileDiff>>;
  syncEnv(req: EnvSyncRequest): Promise<Result<EnvSyncResult>>;
  /** Writes plaintext to the dialog-chosen path and returns only its metadata. */
  exportEnv(req: ExportEnvRequest): Promise<Result<ExportEnvResult>>;
  /** Commit-safe v2 export, sealed to the project's current recipients. */
  exportEnvEncrypted(req: ExportEncryptedRequest): Promise<Result<ExportEncryptedResult>>;

  // Operations MCP does not expose (verified: no backup/restore/rotate tools in
  // internal/mcp). These shell out to the CLI instead.
  //
  // `backup` deliberately takes no destination argument: the renderer must not be
  // able to aim a vault snapshot at an arbitrary path. With no argument the Go
  // side writes to `backup.dir` from config.yaml, which is the only place that
  // should decide. It reports the snapshot's metadata via `backup --json`; the
  // snapshot is copied as opaque bytes and never decrypted, so there is no value
  // in the report.
  backup(): Promise<Result<BackupReport>>;
  doctor(): Promise<Result<{ healthy: boolean; failed: string[]; checks: unknown }>>;

  /**
   * Snapshots main found in `backup.dir` (or next to vault.db when unset).
   * Restore accepts only one of these paths — see TvaultApi.restore.
   */
  listBackups(): Promise<Result<BackupSnapshot[]>>;

  /**
   * Replaces the vault database with a snapshot. Main re-validates the path
   * against its own listing and the snapshot naming convention, so a
   * compromised renderer cannot aim this at an arbitrary file. The CLI takes a
   * pre-restore safety snapshot first and refuses if that fails.
   */
  restore(path: string): Promise<Result<RestoreReport>>;

  /**
   * Copies a value to the OS clipboard and schedules its own clearing. Handled in
   * main because a sandboxed preload has no clipboard access, and because the
   * timer must survive a renderer reload.
   */
  copySecret(value: string): Promise<Result<{ clearsInMs: number }>>;

  /**
   * Tells main whether a secret value is currently on screen. Main excludes the
   * window from screen capture and screen sharing only while this is true (or
   * while the user forces it from the View menu), so ordinary screenshots of the
   * app keep working the rest of the time.
   *
   * Always-on protection was tried first and it silently broke Cmd+Shift+4 and
   * `screencapture` for the window entirely — worse than the risk it prevented.
   */
  setProtectionActive(active: boolean): Promise<Result<void>>;
}

declare global {
  interface Window {
    tvault: TvaultApi;
  }
}
