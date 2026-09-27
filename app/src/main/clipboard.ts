import { clipboard } from "electron";

import { CLIPBOARD_CLEAR_MS } from "@shared/ipc";

/**
 * Clipboard writes live in main, not the renderer: a sandboxed preload has no
 * `clipboard` access, and owning the timer here means the value is still cleared
 * if the renderer reloads or closes mid-countdown.
 *
 * Electron 44 models this API on W3C `navigator.clipboard`, so reads and writes
 * are promise-returning; only `clear()` is still synchronous.
 */
let timer: NodeJS.Timeout | null = null;
let copied = "";

function cancelTimer(): void {
  if (timer) clearTimeout(timer);
  timer = null;
}

/** Clears the pasteboard only if it still holds what we put there. */
async function clearIfStillOurs(): Promise<void> {
  const expected = copied;
  copied = "";
  if (!expected) return;
  try {
    // Never clobber something the user copied from another app in the meantime.
    if ((await clipboard.readText()) === expected) clipboard.clear();
  } catch {
    // Clipboard unavailable (locked screen, remote session); nothing to clear.
  }
}

export async function writeSecretToClipboard(value: string): Promise<{ clearsInMs: number }> {
  cancelTimer();
  // Clear the previous secret BEFORE writing the new one. Dropping the old timer
  // without clearing would leave that value on the pasteboard with nothing
  // scheduled to remove it if the write below then fails.
  await clearIfStillOurs();
  await clipboard.writeText(value);
  copied = value;
  timer = setTimeout(() => {
    timer = null;
    void clearIfStillOurs();
  }, CLIPBOARD_CLEAR_MS);
  return { clearsInMs: CLIPBOARD_CLEAR_MS };
}

/**
 * Called from `before-quit`. Forgetting the timer is not enough — a secret copied
 * seconds before quitting would otherwise outlive the app on the system
 * pasteboard, which is exactly the leak the countdown exists to prevent.
 */
export async function flushClipboard(): Promise<void> {
  cancelTimer();
  await clearIfStillOurs();
}
