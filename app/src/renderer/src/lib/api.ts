import type { Result } from "@shared/types";

/** Raised when the main process returns `{ ok: false }`. */
export class ApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApiError";
  }
}

/** Turns the IPC Result envelope into a normal value-or-throw. */
export async function unwrap<T>(promise: Promise<Result<T>>): Promise<T> {
  const result = await promise;
  if (!result.ok) throw new ApiError(result.error);
  return result.value;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** Compact relative time, e.g. "3m ago", "2d ago". Falls back to a date. */
export function relTime(iso: string | undefined | null): string {
  if (!iso) return "—";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "—";
  const delta = Date.now() - then;
  if (delta < 0) return "just now";
  if (delta < MINUTE) return "just now";
  if (delta < HOUR) return `${Math.floor(delta / MINUTE)}m ago`;
  if (delta < DAY) return `${Math.floor(delta / HOUR)}h ago`;
  if (delta < 30 * DAY) return `${Math.floor(delta / DAY)}d ago`;
  return new Date(then).toISOString().slice(0, 10);
}

/** Absolute timestamp for audit rows and history, where precision matters. */
export function fullTime(iso: string | undefined | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

/**
 * Masks a secret value for the editor's "masked" hint.
 *
 * Always a full mask. Showing the first and last characters looked like a
 * friendly affordance, but for formatted credentials (`sk-live-…`, `…-prod`)
 * the affix is the most identifying part of the value, and this hint is on
 * screen indefinitely — outside the 30s auto-hide and outside the reveal budget.
 */
export function maskValue(value: string): string {
  return "•".repeat(Math.min(Math.max(value.length, 8), 24));
}

/** HH:MM:SS for audit rows. NaN-guarded: a malformed timestamp must not throw in render. */
export function clockTime(iso: string | undefined | null): string {
  if (!iso) return "--:--:--";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return d.toISOString().slice(11, 19);
}

const THEME_KEY = "tv-theme";

/**
 * True when the app was launched with `TVAULT_DESKTOP_DEBUG=1`; main forwards the
 * renderer console to stdout in that mode.
 *
 * Never pass a secret value to `debug` — these lines leave the process.
 */
export const DEBUG = new URLSearchParams(window.location.search).has("debug");

export function debug(label: string, detail?: unknown): void {
  if (!DEBUG) return;
  // Single stringified argument: Electron's console-message forwarding only
  // carries the first argument's string form to the main process.
  const suffix = detail === undefined ? "" : ` ${safeStringify(detail)}`;
  console.log(`[tv] ${label}${suffix}`);
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export type Theme = "light" | "dark";

export function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    // Storage unavailable; fall through to the system preference.
  }
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle("dark", theme === "dark");
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    // Non-fatal: the theme simply will not persist.
  }
}
