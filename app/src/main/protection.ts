import { BrowserWindow } from "electron";

/**
 * Screen-capture exclusion is a two-input OR:
 *
 *  - `force` — the View menu checkbox, for sessions where the user wants the
 *    window hidden from captures unconditionally;
 *  - `reveal` — driven by the renderer, true only while a secret value is
 *    actually on screen (a revealed row, or the editor holding a loaded value).
 *
 * Default is OFF. Always-on was tried first and it silently broke Cmd+Shift+4
 * and `screencapture` for this window entirely — the user could not screenshot
 * their own app, and neither could any automated check. Protecting only the
 * moments a value is visible keeps the guarantee where it matters.
 */
let force = false;
let reveal = false;

function apply(): void {
  const on = force || reveal;
  for (const w of BrowserWindow.getAllWindows()) w.setContentProtection(on);
}

export function setForceProtection(on: boolean): void {
  force = on;
  apply();
}

export function isForceProtection(): boolean {
  return force;
}

export function setRevealActive(on: boolean): void {
  if (reveal === on) return;
  reveal = on;
  apply();
}

/** Called once after the window exists so the initial state is applied. */
export function applyProtection(): void {
  apply();
}
