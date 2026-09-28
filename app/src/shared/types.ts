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

  envGroups(): Promise<Result<EnvGroupDetail[]>>;
  envDiff(group: string, values: boolean): Promise<Result<EnvDiffResult>>;
  envPromote(req: PromoteRequest): Promise<Result<PromoteResult>>;
  envInherited(group: string, env: string): Promise<Result<InheritedKey[]>>;

  // Sharing. Identities and recipients are public halves only (tvault1…); the
  // private key (tvault-key1…) is never returned by any of these, and exporting
  // it stays a CLI-only, TTY-guarded operation.
  identities(): Promise<Result<IdentityEntry[]>>;
  newIdentity(name: string): Promise<Result<IdentityCreated>>;
  recipients(project: string): Promise<Result<string[]>>;
  shareProject(project: string, recipient: string): Promise<Result<ShareResult>>;
  unshareProject(project: string, recipient: string): Promise<Result<UnshareResult>>;

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
