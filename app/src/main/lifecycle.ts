import { session } from "./mcp";

/**
 * Split out from index.ts so `before-quit` can await the child's shutdown without
 * a circular import back into the window module.
 *
 * `shutdown()` also waits out an in-progress connect, so quitting during the
 * initial handshake cannot abandon a freshly spawned child holding a derived KEK.
 */
export function mcpSessionForQuit(): { done: boolean; promise: Promise<void> } {
  if (!session.info().connected) {
    // Still worth calling: a connect may be mid-flight with no client published.
    const promise = session.shutdown().catch(() => undefined);
    return { done: false, promise };
  }

  // Never let a hung child block quit for more than a moment.
  const timeout = new Promise<void>((resolve) => setTimeout(resolve, 1500));
  return {
    done: false,
    promise: Promise.race([session.shutdown().catch(() => undefined), timeout])
  };
}
