import { contextBridge, ipcRenderer } from "electron";

import { IPC } from "@shared/ipc";
import type { TvaultApi } from "@shared/types";

/**
 * The entire bridge surface. The renderer can only reach these methods — there is
 * no generic `invoke(channel, ...)` escape hatch, so a compromised renderer
 * cannot call an IPC channel the app never intended to expose.
 */
const api: TvaultApi = {
  platform: process.platform,

  bootstrap: () => ipcRenderer.invoke(IPC.bootstrap),
  restartSession: () => ipcRenderer.invoke(IPC.restartSession),
  sessionInfo: () => ipcRenderer.invoke(IPC.sessionInfo),

  projectsOverview: () => ipcRenderer.invoke(IPC.projectsOverview),
  createProject: (name, description) => ipcRenderer.invoke(IPC.createProject, name, description),
  deleteProject: (name) => ipcRenderer.invoke(IPC.deleteProject, name),
  setCurrentProject: (name) => ipcRenderer.invoke(IPC.setCurrentProject, name),

  listSecrets: (project) => ipcRenderer.invoke(IPC.listSecrets, project),
  revealSecret: (project, key) => ipcRenderer.invoke(IPC.revealSecret, project, key),
  setSecret: (project, key, value) => ipcRenderer.invoke(IPC.setSecret, project, key, value),
  deleteSecret: (project, key) => ipcRenderer.invoke(IPC.deleteSecret, project, key),
  generateSecret: (project, key, length, charset) =>
    ipcRenderer.invoke(IPC.generateSecret, project, key, length, charset),
  history: (project, key) => ipcRenderer.invoke(IPC.history, project, key),
  rollback: (project, key, toVersion) =>
    ipcRenderer.invoke(IPC.rollback, project, key, toVersion),
  searchSecrets: (req) => ipcRenderer.invoke(IPC.searchSecrets, req),

  auditLog: (limit) => ipcRenderer.invoke(IPC.auditLog, limit),
  auditLogSince: (req) => ipcRenderer.invoke(IPC.auditLogSince, req),

  envGroups: () => ipcRenderer.invoke(IPC.envGroups),
  envGroupCreate: (req) => ipcRenderer.invoke(IPC.envGroupCreate, req),
  envDiff: (group, values) => ipcRenderer.invoke(IPC.envDiff, group, values),
  envPromote: (req) => ipcRenderer.invoke(IPC.envPromote, req),
  envInherited: (group, env) => ipcRenderer.invoke(IPC.envInherited, group, env),
  envGroupShow: (name) => ipcRenderer.invoke(IPC.envGroupShow, name),
  envGroupAdd: (group, envName, project) =>
    ipcRenderer.invoke(IPC.envGroupAdd, group, envName, project),
  envGroupRemove: (group, envName) => ipcRenderer.invoke(IPC.envGroupRemove, group, envName),
  envGroupDelete: (name) => ipcRenderer.invoke(IPC.envGroupDelete, name),
  envInherit: (group, env, from) => ipcRenderer.invoke(IPC.envInherit, group, env, from),
  envPin: (group, env, key) => ipcRenderer.invoke(IPC.envPin, group, env, key),
  envUnpin: (group, env, key) => ipcRenderer.invoke(IPC.envUnpin, group, env, key),
  envSeal: (req) => ipcRenderer.invoke(IPC.envSeal, req),

  identities: () => ipcRenderer.invoke(IPC.identities),
  newIdentity: (name) => ipcRenderer.invoke(IPC.newIdentity, name),
  recipients: (project) => ipcRenderer.invoke(IPC.recipients, project),
  shareProject: (project, recipient) => ipcRenderer.invoke(IPC.shareProject, project, recipient),
  unshareProject: (project, recipient) =>
    ipcRenderer.invoke(IPC.unshareProject, project, recipient),
  sealForRecipients: (req) => ipcRenderer.invoke(IPC.sealForRecipients, req),
  openSealed: (req) => ipcRenderer.invoke(IPC.openSealed, req),

  pickDirectory: (title) => ipcRenderer.invoke(IPC.pickDirectory, title),
  pickSaveFile: (title, defaultName, defaultDir) =>
    ipcRenderer.invoke(IPC.pickSaveFile, title, defaultName, defaultDir),
  pickEnvFile: (title) => ipcRenderer.invoke(IPC.pickEnvFile, title),
  listEnvFiles: (directory, environment) =>
    ipcRenderer.invoke(IPC.listEnvFiles, directory, environment),
  previewEnvImport: (req) => ipcRenderer.invoke(IPC.previewEnvImport, req),
  importEnvFiles: (req) => ipcRenderer.invoke(IPC.importEnvFiles, req),
  diffEnv: (file, project, compareValues) =>
    ipcRenderer.invoke(IPC.diffEnv, file, project, compareValues),
  syncEnv: (req) => ipcRenderer.invoke(IPC.syncEnv, req),
  exportEnv: (req) => ipcRenderer.invoke(IPC.exportEnv, req),
  exportEnvEncrypted: (req) => ipcRenderer.invoke(IPC.exportEnvEncrypted, req),

  backup: () => ipcRenderer.invoke(IPC.backup),
  doctor: () => ipcRenderer.invoke(IPC.doctor),
  listBackups: () => ipcRenderer.invoke(IPC.listBackups),
  restore: (path) => ipcRenderer.invoke(IPC.restore, path),

  copySecret: (value) => ipcRenderer.invoke(IPC.copySecret, value),

  setProtectionActive: (active) => ipcRenderer.invoke(IPC.setProtectionActive, active)
};

contextBridge.exposeInMainWorld("tvault", api);
