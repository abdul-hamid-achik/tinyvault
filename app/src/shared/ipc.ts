/**
 * IPC channel names. Single source of truth so main and preload cannot drift.
 * The preload exposes exactly these as methods on window.tvault — the renderer
 * never touches ipcRenderer directly.
 */
export const IPC = {
  bootstrap: "tvault:bootstrap",
  restartSession: "tvault:restart-session",
  sessionInfo: "tvault:session-info",

  projectsOverview: "tvault:projects-overview",
  createProject: "tvault:create-project",
  deleteProject: "tvault:delete-project",
  setCurrentProject: "tvault:set-current-project",

  listSecrets: "tvault:list-secrets",
  revealSecret: "tvault:reveal-secret",
  setSecret: "tvault:set-secret",
  deleteSecret: "tvault:delete-secret",
  generateSecret: "tvault:generate-secret",
  history: "tvault:history",
  rollback: "tvault:rollback",
  searchSecrets: "tvault:search-secrets",

  auditLog: "tvault:audit-log",
  auditLogSince: "tvault:audit-log-since",

  envGroups: "tvault:env-groups",
  envGroupCreate: "tvault:env-group-create",
  envDiff: "tvault:env-diff",
  envPromote: "tvault:env-promote",
  envInherited: "tvault:env-inherited",
  envGroupShow: "tvault:env-group-show",
  envGroupAdd: "tvault:env-group-add",
  envGroupRemove: "tvault:env-group-remove",
  envGroupDelete: "tvault:env-group-delete",
  envInherit: "tvault:env-inherit",
  envPin: "tvault:env-pin",
  envUnpin: "tvault:env-unpin",
  envSeal: "tvault:env-seal",

  identities: "tvault:identities",
  newIdentity: "tvault:new-identity",
  recipients: "tvault:recipients",
  shareProject: "tvault:share-project",
  unshareProject: "tvault:unshare-project",
  sealForRecipients: "tvault:seal-for-recipients",
  openSealed: "tvault:open-sealed",

  // Dotenv workflows. Every path crosses the bridge through a dialog answered in
  // main (see main/fsaccess.ts), so these channels never author a path.
  pickDirectory: "tvault:pick-directory",
  pickSaveFile: "tvault:pick-save-file",
  pickEnvFile: "tvault:pick-env-file",
  listEnvFiles: "tvault:list-env-files",
  previewEnvImport: "tvault:preview-env-import",
  importEnvFiles: "tvault:import-env-files",
  diffEnv: "tvault:diff-env",
  syncEnv: "tvault:sync-env",
  exportEnv: "tvault:export-env",
  exportEnvEncrypted: "tvault:export-env-encrypted",

  backup: "tvault:backup",
  doctor: "tvault:doctor",
  listBackups: "tvault:list-backups",
  restore: "tvault:restore",

  copySecret: "tvault:copy-secret",

  setProtectionActive: "tvault:set-protection-active"
} as const;

export type IpcChannel = (typeof IPC)[keyof typeof IPC];

/**
 * Auto-hide delay for a revealed secret value, in ms. A revealed value is the
 * single most leak-prone thing on screen (screen sharing, screenshots, someone
 * walking past), so it never stays visible indefinitely.
 */
export const REVEAL_AUTOHIDE_MS = 30_000;

/** Clipboard is cleared this long after copying a secret value. */
export const CLIPBOARD_CLEAR_MS = 30_000;
