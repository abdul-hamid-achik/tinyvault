import { contextBridge, ipcRenderer } from "electron";

import { IPC } from "@shared/ipc";
import type { TvaultApi } from "@shared/types";

/**
 * The entire bridge surface. The renderer can only reach these methods — there is
 * no generic `invoke(channel, ...)` escape hatch, so a compromised renderer
 * cannot call an IPC channel the app never intended to expose.
 */
const api: TvaultApi = {
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

  envGroups: () => ipcRenderer.invoke(IPC.envGroups),
  envDiff: (group, values) => ipcRenderer.invoke(IPC.envDiff, group, values),
  envPromote: (req) => ipcRenderer.invoke(IPC.envPromote, req),
  envInherited: (group, env) => ipcRenderer.invoke(IPC.envInherited, group, env),

  backup: () => ipcRenderer.invoke(IPC.backup),
  doctor: () => ipcRenderer.invoke(IPC.doctor),

  copySecret: (value) => ipcRenderer.invoke(IPC.copySecret, value)
};

contextBridge.exposeInMainWorld("tvault", api);
