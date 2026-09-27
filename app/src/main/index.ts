import { fileURLToPath } from "node:url";
import { join } from "node:path";

import { app, BrowserWindow, Menu, nativeTheme, session } from "electron";

import { flushClipboard } from "./clipboard";
import { registerIpc } from "./ipc";
import { mcpSessionForQuit } from "./lifecycle";
import { applyProtection, isForceProtection, setForceProtection } from "./protection";

// Works whether electron-vite emits ESM (import.meta) or CJS (__dirname).
const here =
  typeof __dirname === "string" ? __dirname : fileURLToPath(new URL(".", import.meta.url));

let mainWindow: BrowserWindow | null = null;
let quitting = false;

/**
 * Opt-in diagnostics for running from a terminal: `TVAULT_DESKTOP_DEBUG=1`
 * mirrors the renderer's console into stdout and tells the renderer (via a query
 * param, since a sandboxed page cannot read the environment) to log milestones.
 *
 * Only counts, names and errors are ever logged — never a secret value.
 */
const DEBUG = process.env.TVAULT_DESKTOP_DEBUG === "1";

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 960,
    minHeight: 620,
    show: false,
    // Match the theme so there is no flash of the wrong background before paint.
    // Both values are --tv-paper from docs/.vitepress/theme/tokens.css.
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#11120f" : "#fbfaf6",
    title: "TinyVault",
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    // The sidebar reserves an empty 40px drag band at the top on macOS (see
    // Sidebar), so centre the lights in that band: (40 - 12) / 2 = 14. Three 12px
    // lights with centres 20px apart occupy x≈20..72, all inside the band.
    trafficLightPosition: { x: 20, y: 14 },
    webPreferences: {
      preload: join(here, "../preload/index.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      spellcheck: false,
      // A secrets editor has no business autofilling or caching form state.
      enableBlinkFeatures: "",
      disableBlinkFeatures: ""
    }
  });

  // Capture exclusion is off by default and turns on only while a value is on
  // screen (or when forced from the View menu) — see protection.ts.
  applyProtection();

  mainWindow.on("ready-to-show", () => mainWindow?.show());

  // Deny unconditionally. Forwarding to shell.openExternal would hand a
  // compromised renderer an exfiltration channel — window.open with a secret in
  // the query string — that the CSP's connect-src otherwise closes. This app
  // renders no external links, so there is nothing legitimate to forward.
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));

  // The renderer is a local bundle; any navigation away from it is a hijack.
  // Compared by origin, not by string prefix, so `http://localhost:5173.evil.example`
  // does not match a dev server on `http://localhost:5173`.
  mainWindow.webContents.on("will-navigate", (event, url) => {
    const devUrl = process.env.ELECTRON_RENDERER_URL;
    if (!devUrl) {
      event.preventDefault();
      return;
    }
    try {
      if (new URL(url).origin !== new URL(devUrl).origin) event.preventDefault();
    } catch {
      event.preventDefault();
    }
  });

  if (process.env.ELECTRON_RENDERER_URL) {
    const url = new URL(process.env.ELECTRON_RENDERER_URL);
    if (DEBUG) url.searchParams.set("debug", "1");
    void mainWindow.loadURL(url.toString());
  } else {
    void mainWindow.loadFile(join(here, "../renderer/index.html"), {
      query: DEBUG ? { debug: "1" } : {}
    });
  }

  if (DEBUG) {
    // Electron 44 deprecated the positional (event, level, message, ...) form in
    // favour of a single details object; let TS infer it from the overload.
    mainWindow.webContents.on("console-message", (details) => {
      process.stdout.write(
        `[renderer:${details.level}] ${details.message} :${details.lineNumber}\n`
      );
    });
    mainWindow.webContents.on("did-fail-load", (_e, code, desc, url) => {
      process.stdout.write(`[renderer] did-fail-load ${code} ${desc} ${url}\n`);
    });
    mainWindow.webContents.on("render-process-gone", (_e, details) => {
      process.stdout.write(`[renderer] process gone: ${details.reason}\n`);
    });
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

function buildMenu(): void {
  const isMac = process.platform === "darwin";
  const viewSubmenu: Electron.MenuItemConstructorOptions[] = [
    { role: "reload" },
    { role: "forceReload" }
  ];
  // DevTools can read revealed values out of React state, so it is only on the
  // menu in the debug build a developer launched from a terminal.
  if (DEBUG) viewSubmenu.push({ role: "toggleDevTools" });
  viewSubmenu.push(
    { type: "separator" },
    {
      label: "Always exclude from screen captures",
      type: "checkbox",
      checked: isForceProtection(),
      click: (item) => setForceProtection(item.checked)
    },
    { type: "separator" },
    { role: "resetZoom" },
    { role: "zoomIn" },
    { role: "zoomOut" },
    { type: "separator" },
    { role: "togglefullscreen" }
  );

  const template: Electron.MenuItemConstructorOptions[] = [
    ...(isMac ? ([{ role: "appMenu" }] as Electron.MenuItemConstructorOptions[]) : []),
    { role: "fileMenu" },
    // Without an Edit role, Cmd+C / Cmd+V / Cmd+A do nothing in macOS inputs.
    { role: "editMenu" },
    { label: "View", submenu: viewSubmenu },
    { role: "windowMenu" }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

/**
 * Locks down every webContents: no permission prompts (camera, mic, geolocation,
 * notifications) and no external navigation. A secrets manager needs none of them.
 */
function hardenSession(): void {
  const ses = session.defaultSession;
  ses.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  ses.setPermissionCheckHandler(() => false);
  ses.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        "Referrer-Policy": ["no-referrer"],
        "X-Content-Type-Options": ["nosniff"]
      }
    });
  });
}

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  });

  void app.whenReady().then(() => {
    hardenSession();
    buildMenu();
    registerIpc();
    createWindow();

    app.on("activate", () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });
}

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", (event) => {
  if (quitting) return;
  quitting = true;
  event.preventDefault();

  // Two things must finish before the process goes away:
  //  - the clipboard clear, so a secret copied seconds ago does not outlive us
  //    on the system pasteboard;
  //  - a graceful child shutdown, so the Go server can run its KEK-zeroing exit
  //    paths. A SIGKILL would skip them — the residual risk
  //    docs/reference/security.md already documents for `tvault agent`.
  const hardDeadline = new Promise<void>((resolve) => setTimeout(resolve, 2500));
  void Promise.race([
    Promise.all([
      flushClipboard().catch(() => undefined),
      mcpSessionForQuit().promise
    ]).then(() => undefined),
    hardDeadline
  ]).then(() => app.exit(0));
});
