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

  envGroups: "tvault:env-groups",
  envDiff: "tvault:env-diff",
  envPromote: "tvault:env-promote",
  envInherited: "tvault:env-inherited",

  identities: "tvault:identities",
  newIdentity: "tvault:new-identity",
  recipients: "tvault:recipients",
  shareProject: "tvault:share-project",
  unshareProject: "tvault:unshare-project",

  backup: "tvault:backup",
  doctor: "tvault:doctor",

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
