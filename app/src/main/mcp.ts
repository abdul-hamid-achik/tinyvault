import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import type { McpBackend, SessionInfo } from "@shared/types";

import { augmentedPath, resolveBinary } from "./binary";
import { readPolicy } from "./policy";

/** Shape of an MCP CallToolResult, narrowed to what this app reads. */
interface RawToolResult {
  content?: Array<{ type?: string; text?: string }>;
  structuredContent?: unknown;
  isError?: boolean;
}

export class McpError extends Error {
  constructor(
    message: string,
    readonly tool: string,
    readonly kind: "tool" | "transport" | "budget" | "policy" | "timeout" | "unknown" = "unknown"
  ) {
    super(message);
    this.name = "McpError";
  }
}

/**
 * Deadline for one tool call. Without it a child wedged on a filesystem lock or
 * a hanging passphrase helper leaves the UI spinner up forever. 60s is generous
 * for every tool this app calls, including a large env promote.
 */
const CALL_TIMEOUT_MS = 60_000;

function textOf(res: RawToolResult): string {
  return (res.content ?? [])
    .filter((c) => c?.type === "text")
    .map((c) => c.text ?? "")
    .join("\n")
    .trim();
}

const STALE_KEK = /passphrase rotated|restart 'tvault mcp'/i;
const BUDGET = /read limit reached/i;
const AGENT_MARKER = /using local agent/i;

/**
 * Environment allowlist for the child.
 *
 * Spreading all of `process.env` would forward every shell variable — GITHUB_TOKEN,
 * cloud credentials, the user's own TVAULT_PASSPHRASE — into a long-lived child
 * process for no reason. The child needs its PATH (to find a passphrase_command
 * helper), HOME (to resolve ~/.tvault), locale, temp dirs, and the TVAULT_* knobs.
 */
function childEnv(): Record<string, string> {
  const PASSTHROUGH = [
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME"
  ];
  const env: Record<string, string> = { PATH: augmentedPath() };
  for (const key of PASSTHROUGH) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  for (const [key, value] of Object.entries(process.env)) {
    if (key.startsWith("TVAULT_") && value !== undefined) env[key] = value;
  }
  return env;
}

/**
 * One long-lived `tvault mcp` child, spoken to over stdio JSON-RPC.
 *
 * The child deliberately owns all vault access. It caches only the KEK and
 * reopens bbolt per request under its own mutex (NewReopeningVaultMCPServer), so
 * this app never holds the single-writer lock and the CLI keeps working
 * alongside it. Do not "optimize" by keeping a vault handle here.
 *
 * Calls and restarts are serialized through one promise chain. The Go server
 * already serializes requests under its own mutex, so this costs no throughput;
 * it exists so a respawn can never interleave with an in-flight call or with a
 * second respawn (which would orphan a child still holding a derived KEK).
 */
export class McpSession {
  private client: Client | null = null;
  private connecting: Promise<void> | null = null;
  private queue: Promise<unknown> = Promise.resolve();
  /** Bumped on every dispose so a superseded connect cannot publish its client. */
  private generation = 0;

  private serverName = "";
  private serverVersion = "";
  private toolCount = 0;
  private backend: McpBackend = "unknown";
  private startedAt = 0;
  private readsUsed = 0;
  private lastError = "";

  /**
   * Captured at connect, not read live: the Go server loads mcp-policy.yaml once
   * at startup, so editing the file afterwards does NOT change what is enforced.
   * Re-reading it here would let the displayed budget diverge from the real one.
   *
   * A cap of 0 means DENY, not unlimited — internal/mcp/config.go's
   * consumeValueRead() returns false whenever limit <= 0.
   */
  private readsLimit = 0;

  info(): SessionInfo {
    return {
      connected: this.client !== null,
      server_name: this.serverName || undefined,
      server_version: this.serverVersion || undefined,
      tool_count: this.toolCount || undefined,
      backend: this.backend,
      reads_used: this.readsUsed,
      reads_limit: this.readsLimit,
      reveals_denied: this.readsLimit <= 0,
      started_at: this.startedAt || undefined,
      last_error: this.lastError || undefined
    };
  }

  /** True when the policy forbids every plaintext read, so reveal cannot work. */
  revealsDenied(): boolean {
    return this.readsLimit <= 0;
  }

  /** Runs `fn` after everything already queued, keeping the chain alive on error. */
  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.queue.then(fn, fn);
    this.queue = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  async ensureConnected(): Promise<void> {
    if (this.client) return;
    if (this.connecting) return this.connecting;
    const promise = this.connect();
    this.connecting = promise;
    // Only the promise that still owns the slot may clear it.
    void promise.then(
      () => {
        if (this.connecting === promise) this.connecting = null;
      },
      () => {
        if (this.connecting === promise) this.connecting = null;
      }
    );
    return promise;
  }

  private async connect(): Promise<void> {
    const generation = ++this.generation;
    const bin = resolveBinary();
    const policy = readPolicy();
    this.readsLimit = policy.max_reads_per_session ?? 0;

    const stderrChunks: string[] = [];
    const transport = new StdioClientTransport({
      command: bin.path,
      args: ["mcp"],
      stderr: "pipe",
      env: childEnv()
    });

    // The "using local agent" line is printed before the server starts serving,
    // but stderr delivery is asynchronous and can land after connect() resolves.
    // Keep evaluating chunks as they arrive rather than sampling once.
    transport.stderr?.on("data", (d: Buffer) => {
      const chunk = d.toString();
      stderrChunks.push(chunk);
      if (stderrChunks.length > 40) stderrChunks.shift();
      if (AGENT_MARKER.test(chunk)) this.backend = "agent";
    });

    const client = new Client({ name: "tinyvault-desktop", version: "0.1.0" });

    // A child that dies must stop reporting as connected, otherwise Retry keeps
    // reusing a dead client and every call fails the same way forever.
    transport.onclose = () => {
      if (this.client === client) {
        this.client = null;
        this.lastError = this.lastError || "the tvault mcp child exited unexpectedly";
      }
    };
    transport.onerror = (err) => {
      this.lastError = err instanceof Error ? err.message : String(err);
    };

    try {
      await client.connect(transport);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      const stderr = stderrChunks.join("").trim();
      this.lastError = stderr ? `${detail}\n${stderr}` : detail;
      throw new McpError(
        `Could not start \`tvault mcp\`: ${this.lastError.slice(0, 600)}`,
        "connect",
        "transport"
      );
    }

    let tools: Array<{ name: string }>;
    try {
      const listed = await client.listTools();
      tools = listed.tools;
    } catch (err) {
      await client.close().catch(() => undefined);
      const detail = err instanceof Error ? err.message : String(err);
      this.lastError = detail;
      throw new McpError(`Could not list tools: ${detail}`, "listTools", "transport");
    }

    // Superseded by a newer connect (or a dispose) while we were awaiting.
    // Close this child rather than leaving it alive with a derived KEK.
    if (generation !== this.generation) {
      await client.close().catch(() => undefined);
      return;
    }

    this.client = client;
    this.startedAt = Date.now();
    this.readsUsed = 0;
    this.lastError = "";
    this.backend = AGENT_MARKER.test(stderrChunks.join("")) ? "agent" : "kek";

    const version = client.getServerVersion();
    this.serverName = version?.name ?? "";
    this.serverVersion = version?.version ?? "";
    this.toolCount = tools.length;
  }

  /**
   * Calls a tool and returns its structured output.
   *
   * Retries once after a transparent respawn when the cached KEK went stale
   * (passphrase rotated underneath us) — see internal/mcp/server.go, which
   * surfaces that as "passphrase rotated? restart 'tvault mcp'".
   */
  async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
    return this.enqueue(async () => {
      await this.ensureConnected();
      try {
        return await this.invoke<T>(tool, args);
      } catch (err) {
        if (err instanceof McpError && STALE_KEK.test(err.message)) {
          // Already inside the queue, so use the unqueued path — enqueueing here
          // would deadlock against ourselves.
          await this.teardown();
          await this.ensureConnected();
          return this.invoke<T>(tool, args);
        }
        throw err;
      }
    });
  }

  /** Public restart, serialized against in-flight calls. */
  async restart(): Promise<void> {
    return this.enqueue(async () => {
      await this.teardown();
      await this.ensureConnected();
    });
  }

  private async invoke<T>(tool: string, args: Record<string, unknown>): Promise<T> {
    const client = this.client;
    if (!client) throw new McpError("session is not connected", tool, "transport");

    const countsAsRead = tool === "vault_get_secret";
    if (countsAsRead && this.readsUsed >= this.readsLimit) {
      throw new McpError(
        this.readsLimit <= 0
          ? "Revealing values is disabled: max_reads_per_session is 0 in mcp-policy.yaml. " +
            "Raise it above zero to allow plaintext reads."
          : `Reveal budget exhausted (${this.readsUsed}/${this.readsLimit} for this session). ` +
            "Restart the session to reset it, or raise max_reads_per_session in mcp-policy.yaml.",
        tool,
        "budget"
      );
    }

    let res: RawToolResult;
    try {
      res = (await this.withTimeout(
        client.callTool({ name: tool, arguments: args }),
        tool
      )) as RawToolResult;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.lastError = message;
      const kind: McpError["kind"] = STALE_KEK.test(message)
        ? "transport"
        : /timed out/.test(message)
          ? "timeout"
          : "unknown";
      throw new McpError(message, tool, kind);
    }

    if (res.isError) {
      const message = textOf(res) || `tool ${tool} returned an error`;
      this.lastError = message;
      const kind: McpError["kind"] = BUDGET.test(message)
        ? "budget"
        : /not allowed by policy|disabled by policy/.test(message)
          ? "policy"
          : STALE_KEK.test(message)
            ? "transport"
            : "tool";
      // Trust the server's own counter, but never write a 0 limit into it — that
      // would look like "0 of 0 used" instead of "denied".
      if (kind === "budget" && this.readsLimit > 0) this.readsUsed = this.readsLimit;
      throw new McpError(message, tool, kind);
    }

    if (countsAsRead) this.readsUsed += 1;

    if (res.structuredContent && typeof res.structuredContent === "object") {
      return res.structuredContent as T;
    }

    const text = textOf(res);
    if (!text) return {} as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      // Never echo the payload back for a value-returning tool: an unparseable
      // vault_get_secret result could contain part of the secret.
      const detail = countsAsRead
        ? `${tool} returned a result this app could not parse`
        : `unparseable result from ${tool}: ${text.slice(0, 200)}`;
      throw new McpError(detail, tool, "tool");
    }
  }

  private async withTimeout<T>(promise: Promise<T>, tool: string): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () =>
              // A timeout is NOT a clean failure: Promise.race abandons the call
              // but the Go server may still be mid-write. Reporting "failed"
              // invites a retry that double-applies a non-idempotent mutation.
              reject(
                new Error(
                  `${tool} did not answer within ${CALL_TIMEOUT_MS}ms. The operation may still ` +
                    "have completed server-side — refresh before retrying rather than assuming it failed."
                )
              ),
            CALL_TIMEOUT_MS
          );
        })
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** Closes the child if any. Bumps the generation so pending connects self-cancel. */
  private async teardown(): Promise<void> {
    this.generation += 1;
    const client = this.client;
    this.client = null;
    if (!client) return;
    try {
      await client.close();
    } catch {
      // Already gone.
    }
  }

  /**
   * Full shutdown for app quit. Also waits out an in-progress connect, because a
   * child spawned during the handshake is not yet reachable through `client` and
   * would otherwise be abandoned with a derived KEK in memory.
   *
   * A graceful close lets the Go server run its KEK-zeroing exit paths; a
   * SIGKILL would skip them — the same residual risk docs/reference/security.md
   * already documents for `tvault agent`.
   */
  async shutdown(): Promise<void> {
    const pending = this.connecting;
    await this.teardown();
    if (pending) {
      try {
        await pending;
      } catch {
        // A failed connect has nothing to close.
      }
    }
    // A connect that finished after teardown published nothing (generation
    // mismatch) and already closed its own child.
    const late = this.client;
    this.client = null;
    if (late) await late.close().catch(() => undefined);
  }
}

export const session = new McpSession();
