/**
 * Contract test: asserts that every MCP tool this app calls still returns the
 * shape the renderer expects, and that the security properties the UI relies on
 * actually hold.
 *
 * It runs against a THROWAWAY vault in a temp dir — never against ~/.tvault — so
 * it can write, delete and exhaust the read budget freely.
 *
 *   bun run verify
 *
 * If internal/mcp changes an output struct, this fails before the UI silently
 * renders `undefined`.
 */
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const TVAULT = process.env.TVAULT_BIN ?? "tvault";
const PASSPHRASE = "contract-test-passphrase";
const READ_BUDGET = 3;

interface RawResult {
  content?: Array<{ type?: string; text?: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

let client: Client;
let passed = 0;
const failures: string[] = [];
// Module scope so the finally block can remove the scratch vault.
let scratchDir = "";

function check(name: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failures.push(name);
    console.log(`  ✗ ${name}${detail === undefined ? "" : `  → ${JSON.stringify(detail)}`}`);
  }
}

function assertObject(name: string, value: unknown): Record<string, unknown> {
  const isObj = typeof value === "object" && value !== null && !Array.isArray(value);
  check(`${name} is an object`, isObj, value);
  return isObj ? (value as Record<string, unknown>) : {};
}

function textOf(res: RawResult): string {
  return (res.content ?? [])
    .filter((c) => c?.type === "text")
    .map((c) => c.text ?? "")
    .join("\n")
    .trim();
}

/** Calls a tool, returning its parsed structured output. */
async function call<T extends Record<string, unknown>>(
  tool: string,
  args: Record<string, unknown> = {}
): Promise<T> {
  const res = (await client.callTool({ name: tool, arguments: args })) as RawResult;
  if (res.isError) throw new Error(`${tool} returned an error: ${textOf(res)}`);
  if (res.structuredContent) return res.structuredContent as T;
  return JSON.parse(textOf(res)) as T;
}

/** Calls a tool expecting failure, returning the error text. */
async function callFails(tool: string, args: Record<string, unknown> = {}): Promise<string> {
  const res = (await client.callTool({ name: tool, arguments: args })) as RawResult;
  if (!res.isError) {
    try {
      const out = res.structuredContent ?? JSON.parse(textOf(res));
      throw new Error(`${tool} unexpectedly succeeded: ${JSON.stringify(out).slice(0, 200)}`);
    } catch (err) {
      if (err instanceof SyntaxError) throw new Error(`${tool} unexpectedly succeeded`);
      throw err;
    }
  }
  return textOf(res);
}

async function main(): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "tvault-contract-"));
  scratchDir = dir;
  chmodSync(dir, 0o700);
  const env = { ...process.env, TVAULT_DIR: dir, TVAULT_PASSPHRASE: PASSPHRASE };

  console.log(`scratch vault: ${dir}\n`);

  try {
    execFileSync(TVAULT, ["init"], { env, stdio: "pipe" });
  } catch (err) {
    const e = err as { stdout?: Buffer; stderr?: Buffer };
    throw new Error(
      `tvault init failed: ${e.stderr?.toString() ?? ""}${e.stdout?.toString() ?? ""}`.trim()
    );
  }

  // All eight fields are mandatory; the Go loader rejects an incomplete file.
  writeFileSync(
    join(dir, "mcp-policy.yaml"),
    [
      "access_mode: read-write",
      'projects_allow: ["*"]',
      "projects_deny: []",
      'secrets_allow: ["*"]',
      "secrets_deny: []",
      "allow_exec: false",
      `max_reads_per_session: ${READ_BUDGET}`,
      "redact_output: true",
      ""
    ].join("\n"),
    { mode: 0o600 }
  );

  const transport = new StdioClientTransport({ command: TVAULT, args: ["mcp"], env, stderr: "pipe" });
  client = new Client({ name: "tinyvault-contract-test", version: "0.1.0" });
  await client.connect(transport);

  const { tools } = await client.listTools();
  const names = new Set(tools.map((t) => t.name));

  console.log("tools the app depends on:");
  const required = [
    "vault_status",
    "vault_get_current_project",
    "vault_set_current_project",
    "vault_projects_overview",
    "vault_create_project",
    "vault_delete_project",
    "vault_list_secrets",
    "vault_list_secrets_detailed",
    "vault_list_secrets_global",
    "vault_get_secret",
    "vault_set_secret",
    "vault_delete_secret",
    "vault_generate_secret",
    "vault_secret_history",
    "vault_rollback_secret",
    "vault_audit_log",
    "vault_env_group_create",
    "vault_env_group_list",
    "vault_env_diff",
    "vault_env_promote",
    "vault_env_inherited"
  ];
  for (const t of required) check(`tool present: ${t}`, names.has(t));
  console.log(`  (${tools.length} tools total)\n`);

  console.log("vault_status:");
  const status = await call<Record<string, unknown>>("vault_status");
  assertObject("status", status);
  check("status.is_unlocked === true", status.is_unlocked === true, status);
  check("status.path is a string", typeof status.path === "string");
  check("status.project_count is a number", typeof status.project_count === "number");
  check("status.vault_id is a string", typeof status.vault_id === "string");

  console.log("\nprojects:");
  const created = await call<{ name: string; created: boolean }>("vault_create_project", {
    name: "contract-app",
    description: "production"
  });
  check("create → {name, created:true}", created.created === true && created.name === "contract-app", created);
  await call("vault_create_project", { name: "contract-preview", description: "preview" });
  await call("vault_set_current_project", { name: "contract-app" });
  const current = await call<{ current_project: string }>("vault_get_current_project");
  check("set_current_project round-trips", current.current_project === "contract-app", current);

  const overview = await call<{ projects: Array<Record<string, unknown>> }>("vault_projects_overview");
  check("overview.projects is an array", Array.isArray(overview.projects));
  const first = overview.projects[0] ?? {};
  for (const field of ["name", "description", "secret_count", "created_at", "updated_at"]) {
    check(`overview.projects[0] has ${field}`, field in first, first);
  }

  console.log("\nsecrets — write/read round trip:");
  const setValue = "postgres://u:p@h:5432/db?a=1&b=2<3>";
  await call("vault_set_secret", { project: "contract-app", key: "DATABASE_URL", value: setValue });
  const setOut = await call<{ key: string }>("vault_set_secret", {
    project: "contract-app",
    key: "API_TOKEN",
    value: "tok_first"
  });
  check("set → {key} only (no value echoed)", Object.keys(setOut).join() === "key", setOut);

  const detailed = await call<{ project: string; secrets: Array<Record<string, unknown>> }>(
    "vault_list_secrets_detailed",
    { project: "contract-app" }
  );
  check("detailed.project is the requested project", detailed.project === "contract-app", detailed.project);
  check("detailed.secrets has 2 entries", detailed.secrets.length === 2, detailed.secrets);
  const meta = detailed.secrets.find((s) => s.key === "API_TOKEN") ?? {};
  for (const field of ["key", "version", "created_at", "updated_at"]) {
    check(`detailed.secrets[] has ${field}`, field in meta, meta);
  }
  check("detailed reports version 1 for a new key", meta.version === 1, meta);

  // The trap this app must avoid: vault_list_secrets hardcodes version 1.
  const plain = await call<{ secrets: Array<{ key: string; version: number }> }>("vault_list_secrets", {
    project: "contract-app"
  });
  check(
    "KNOWN TRAP: vault_list_secrets reports version 1 (why the UI uses _detailed)",
    plain.secrets.every((s) => s.version === 1)
  );

  // Read #1
  const got = await call<{ key: string; value: string; warning: string }>("vault_get_secret", {
    project: "contract-app",
    key: "DATABASE_URL"
  });
  check("get returns the exact value (& and < survive, no HTML escaping)", got.value === setValue, {
    length: got.value.length
  });
  check("get carries a context warning", typeof got.warning === "string" && got.warning.length > 0);

  console.log("\nversioning:");
  await call("vault_set_secret", { project: "contract-app", key: "API_TOKEN", value: "tok_second" });
  const detailed2 = await call<{ secrets: Array<{ key: string; version: number }> }>(
    "vault_list_secrets_detailed",
    { project: "contract-app" }
  );
  const tokMeta = detailed2.secrets.find((s) => s.key === "API_TOKEN");
  check("overwrite bumps version to 2", tokMeta?.version === 2, tokMeta);

  const history = await call<{ versions: Array<Record<string, unknown>> }>("vault_secret_history", {
    project: "contract-app",
    key: "API_TOKEN"
  });
  check("history.versions is an array", Array.isArray(history.versions));
  check("history has 2 versions", history.versions.length === 2, history.versions);
  const v0 = history.versions[0] ?? {};
  for (const field of ["version", "created_at", "updated_at"]) {
    check(`history.versions[] has ${field}`, field in v0, v0);
  }
  check(
    "history never carries a value field",
    history.versions.every((v) => !("value" in v)),
    history.versions
  );

  // Read #2 — after rollback the current value must be the archived one.
  const rolled = await call<{ rolled_back: boolean; rolled_back_from: number; new_version: number }>(
    "vault_rollback_secret",
    { project: "contract-app", key: "API_TOKEN", to_version: 1 }
  );
  check("rollback → {rolled_back:true, rolled_back_from, new_version}", rolled.rolled_back === true && rolled.new_version > rolled.rolled_back_from, rolled);
  const afterRollback = await call<{ value: string }>("vault_get_secret", {
    project: "contract-app",
    key: "API_TOKEN"
  });
  check("rollback restored the v1 value", afterRollback.value === "tok_first");

  console.log("\ngenerate:");
  const gen = await call<Record<string, unknown>>("vault_generate_secret", {
    project: "contract-app",
    key: "SESSION_SECRET",
    length: 48,
    charset: "alphanumeric"
  });
  check("generate → {key, length, charset, stored}", ["charset", "key", "length", "stored"].every((k) => k in gen), Object.keys(gen));
  check("generate NEVER returns a value field", !("value" in gen), Object.keys(gen));
  check("generate reports stored:true", gen.stored === true);
  check("generate echoes the requested length", gen.length === 48, gen.length);
  // Read #3 — consumes the last unit of the budget.
  const genValue = await call<{ value: string }>("vault_get_secret", {
    project: "contract-app",
    key: "SESSION_SECRET"
  });
  check("generated value is 48 chars", genValue.value.length === 48, { len: genValue.value.length });

  console.log(`\nread budget (max_reads_per_session: ${READ_BUDGET}, 3 consumed):`);
  const budgetErr = await callFails("vault_get_secret", {
    project: "contract-app",
    key: "DATABASE_URL"
  });
  check("4th plaintext read is refused", /read limit reached/i.test(budgetErr), budgetErr.slice(0, 160));

  console.log("\nsearch / audit:");
  const search = await call<{ results: Array<Record<string, unknown>>; count: number }>(
    "vault_list_secrets_global",
    { prefix: "DATA" }
  );
  check("search returns {results, count}", Array.isArray(search.results) && typeof search.count === "number", search);
  check("search filters by prefix", search.results.every((r) => String(r.key).startsWith("DATA")), search.results);
  const hit = search.results[0] ?? {};
  for (const field of ["project", "key", "version", "updated_at"]) {
    check(`search.results[] has ${field}`, field in hit, hit);
  }
  check("search never returns a value", search.results.every((r) => !("value" in r)));

  const audit = await call<{ entries: Array<Record<string, unknown>> }>("vault_audit_log", {
    limit: 100
  });
  check("audit.entries is an array", Array.isArray(audit.entries));
  check("audit log is non-empty after all that activity", audit.entries.length > 0, { n: audit.entries.length });
  const entry = audit.entries[0] ?? {};
  for (const field of ["action", "resource_type", "timestamp"]) {
    check(`audit.entries[] has ${field}`, field in entry, entry);
  }
  check(
    "audit entries never carry a 'value' field",
    audit.entries.every((e) => !("value" in e)),
    Object.keys(entry)
  );
  const leaked = audit.entries.some((e) => JSON.stringify(e).includes(setValue));
  check("no secret value appears anywhere in the audit log", !leaked);

  console.log("\nenv groups:");
  await call("vault_env_group_create", {
    name: "contract",
    description: "contract-test group",
    environments: [
      { name: "production", project: "contract-app" },
      { name: "preview", project: "contract-preview" }
    ]
  });
  const groups = await call<{ groups: Array<Record<string, unknown>> }>("vault_env_group_list");
  check("group_list → {groups:[...]}", Array.isArray(groups.groups) && groups.groups.length === 1, groups);
  const g = groups.groups[0] ?? {};
  check("group has name + environments", g.name === "contract" && Array.isArray(g.environments), g);
  const envEntry = (g.environments as Array<Record<string, unknown>>)[0] ?? {};
  check("environments[] has {name, project}", "name" in envEntry && "project" in envEntry, envEntry);

  const diff = await call<{ group: string; status: string; keys: Array<Record<string, unknown>> }>(
    "vault_env_diff",
    { group: "contract", values: false }
  );
  check("diff → {group, status, keys}", diff.group === "contract" && Array.isArray(diff.keys), diff);
  check("diff.status is ok|drift", diff.status === "ok" || diff.status === "drift", diff.status);
  check("diff detects drift (preview has no keys)", diff.status === "drift", { status: diff.status });
  const diffKey = diff.keys[0] ?? {};
  check("diff.keys[] has key + environments", "key" in diffKey && Array.isArray(diffKey.environments), diffKey);
  const diffEnv = (diffKey.environments as Array<Record<string, unknown>>)[0] ?? {};
  for (const field of ["env", "present", "status"]) {
    check(`diff environments[] has ${field}`, field in diffEnv, diffEnv);
  }
  check(
    "diff never carries a value",
    diff.keys.every((k) => !("value" in k) && (k.environments as Array<Record<string, unknown>>).every((e) => !("value" in e)))
  );

  const promoteDry = await call<{ promoted: Array<Record<string, unknown>>; skipped: unknown[] }>(
    "vault_env_promote",
    { group: "contract", from_env: "production", to_env: "preview", all: true, dry_run: true }
  );
  check("promote dry-run → {promoted, skipped}", Array.isArray(promoteDry.promoted) && Array.isArray(promoteDry.skipped), promoteDry);
  check("promote dry-run has candidates", promoteDry.promoted.length > 0, promoteDry.promoted);
  const pk = promoteDry.promoted[0] ?? {};
  for (const field of ["key", "from_version", "to_version"]) {
    check(`promoted[] has ${field}`, field in pk, pk);
  }

  const inherited = await call<{ keys: Array<Record<string, unknown>> }>("vault_env_inherited", {
    group: "contract",
    env: "preview"
  });
  check("env_inherited → {keys:[...]}", Array.isArray(inherited.keys), inherited);

  console.log("\ndestructive ops:");
  const deleted = await call<{ key: string; deleted: boolean }>("vault_delete_secret", {
    project: "contract-app",
    key: "API_TOKEN"
  });
  check("delete_secret → {key, deleted:true}", deleted.deleted === true && deleted.key === "API_TOKEN", deleted);
  const delProject = await call<{ name: string; deleted: boolean }>("vault_delete_project", {
    name: "contract-preview"
  });
  check("delete_project → {name, deleted:true}", delProject.deleted === true, delProject);

  console.log("\nwrites must be refused when the policy is read-only:");
  // A second server against a read-only policy — proves the UI's readOnly flag
  // is backed by a real server-side control, not just a disabled button.
  writeFileSync(
    join(dir, "mcp-policy.yaml"),
    [
      "access_mode: read-only",
      'projects_allow: ["*"]',
      "projects_deny: []",
      'secrets_allow: ["*"]',
      "secrets_deny: []",
      "allow_exec: false",
      `max_reads_per_session: ${READ_BUDGET}`,
      "redact_output: true",
      ""
    ].join("\n"),
    { mode: 0o600 }
  );
  const roTransport = new StdioClientTransport({ command: TVAULT, args: ["mcp"], env, stderr: "pipe" });
  const roClient = new Client({ name: "contract-test-readonly", version: "0.1.0" });
  await roClient.connect(roTransport);
  const realClient = client;
  client = roClient;
  const roErr = await callFails("vault_set_secret", {
    project: "contract-app",
    key: "SHOULD_NOT_EXIST",
    value: "x"
  });
  check("read-only policy refuses writes", /not allowed by policy|disabled by policy/i.test(roErr), roErr.slice(0, 160));
  await roClient.close();
  client = realClient;

  await client.close();

  console.log(`\n${"=".repeat(56)}`);
  console.log(`${passed} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    console.log("\nfailures:");
    for (const f of failures) console.log(`  - ${f}`);
  }
  console.log("=".repeat(56));
  process.exitCode = failures.length > 0 ? 1 : 0;
}

main()
  .catch((err) => {
    console.error("\n✗ contract test crashed:", err instanceof Error ? err.stack : err);
    process.exitCode = 1;
  })
  .finally(() => {
    // The scratch vault lives in a temp dir; leave nothing behind.
    if (scratchDir) rmSync(scratchDir, { recursive: true, force: true });
  });
