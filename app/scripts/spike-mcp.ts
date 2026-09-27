/**
 * Phase 0 spike — validate that an Electron main process can drive `tvault mcp`
 * over stdio JSON-RPC before any UI is written.
 *
 * Metadata only by construction: this never calls vault_get_secret, so no secret
 * value can reach stdout. Run with `bun run spike`.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

function binaryPath(): string {
  if (process.env.TVAULT_BIN) return process.env.TVAULT_BIN;
  return "tvault";
}

function textOf(result: unknown): string {
  const r = result as {
    content?: Array<{ type?: string; text?: string }>;
    isError?: boolean;
  };
  const parts = (r?.content ?? [])
    .filter((c) => c?.type === "text")
    .map((c) => c.text ?? "");
  const body = parts.join("\n").trim();
  return r?.isError ? `[TOOL ERROR] ${body}` : body;
}

async function main(): Promise<void> {
  const bin = binaryPath();
  console.log(`→ spawning: ${bin} mcp\n`);

  const stderrChunks: string[] = [];
  const transport = new StdioClientTransport({
    command: bin,
    args: ["mcp"],
    stderr: "pipe",
  });

  const client = new Client({ name: "tinyvault-desktop-spike", version: "0.1.0" });

  // The Go server writes diagnostics to stderr; surface them, they explain
  // which backend path was chosen (agent vs cached-KEK reopen).
  transport.onerror = (err) => stderrChunks.push(`[transport] ${String(err)}`);
  transport.stderr?.on("data", (d: Buffer) => stderrChunks.push(d.toString()));

  const t0 = Date.now();
  await client.connect(transport);
  console.log(`✓ connected in ${Date.now() - t0}ms`);

  const serverInfo = client.getServerVersion();
  console.log(`✓ server: ${JSON.stringify(serverInfo)}`);

  const { tools } = await client.listTools();
  console.log(`✓ listTools → ${tools.length} tools\n`);

  const names = tools.map((t) => t.name).sort();
  const grouped = new Map<string, string[]>();
  for (const n of names) {
    const prefix = n.split("_")[1] ?? "other";
    grouped.set(prefix, [...(grouped.get(prefix) ?? []), n]);
  }
  for (const [prefix, list] of [...grouped.entries()].sort()) {
    console.log(`  ${prefix.padEnd(10)} ${list.length.toString().padStart(2)}  ${list.join(", ")}`);
  }

  console.log("\n--- vault_status ---");
  const status = await client.callTool({ name: "vault_status", arguments: {} });
  console.log(textOf(status));

  console.log("\n--- vault_list_projects ---");
  const projects = await client.callTool({ name: "vault_list_projects", arguments: {} });
  const projectsText = textOf(projects);
  console.log(projectsText.slice(0, 1200));

  console.log("\n--- vault_get_current_project ---");
  const current = await client.callTool({ name: "vault_get_current_project", arguments: {} });
  console.log(textOf(current));

  await client.close();
  console.log("\n✓ closed cleanly");

  if (stderrChunks.length > 0) {
    console.log("\n--- child stderr ---");
    console.log(stderrChunks.join("").trim());
  }
}

main().catch((err) => {
  console.error("\n✗ SPIKE FAILED:", err instanceof Error ? err.stack : err);
  process.exit(1);
});
