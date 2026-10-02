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
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
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

/** Permission bits as an octal string, for the 0600 claims this app makes. */
function perm(path: string): string {
  return (statSync(path).mode & 0o777).toString(8);
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

  // Hermetic on purpose. These knobs come from the developer's shell (or CI's)
  // and would otherwise change what this test proves:
  //   TVAULT_IDENTITY_KEY  — `open_sealed` falls back to it when no identity file
  //                          matches, so a key in the environment would make the
  //                          "unknown identity is refused" case succeed instead.
  //   TVAULT_PASSPHRASE_FILE / _COMMAND — shadow the passphrase set below.
  //   TVAULT_CONFIG        — a personal config.yaml (backup.dir, agent.*) leaks in.
  //   TVAULT_AGENT_TOKEN   — belongs to some other agent, not this test.
  // TVAULT_NO_AGENT is set (not stripped) so a `tvault agent` running on the
  // machine cannot change which backend answers: this test exercises the
  // passphrase/KEK path, deterministically.
  const stripped = new Set([
    "TVAULT_IDENTITY",
    "TVAULT_IDENTITY_KEY",
    "TVAULT_PASSPHRASE_FILE",
    "TVAULT_PASSPHRASE_COMMAND",
    "TVAULT_CONFIG",
    "TVAULT_AGENT_TOKEN"
  ]);
  const env: Record<string, string> = {
    TVAULT_DIR: dir,
    TVAULT_PASSPHRASE: PASSPHRASE,
    TVAULT_NO_AGENT: "1"
  };
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !stripped.has(key) && !(key in env)) env[key] = value;
  }

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
    "vault_audit_log_since",
    "vault_env_group_create",
    "vault_env_group_list",
    "vault_env_group_show",
    "vault_env_group_add",
    "vault_env_group_remove",
    "vault_env_group_delete",
    "vault_env_diff",
    "vault_env_promote",
    "vault_env_inherit",
    "vault_env_inherited",
    "vault_env_pin",
    "vault_env_unpin",
    "vault_env_seal",
    "vault_identity_new",
    "vault_identity_list",
    "vault_project_recipients",
    "vault_share_project",
    "vault_unshare_project",
    "vault_seal_for_recipients",
    "vault_open_sealed",
    "vault_export_env_encrypted",
    "vault_list_env_files",
    "vault_preview_env_import",
    "vault_import_env_files",
    "vault_diff_env",
    "vault_sync_env",
    "vault_export_env"
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

  // The relational query the Audit screen's filters run on.
  const since = new Date(Date.now() - 60_000).toISOString();
  const ranged = await call<{ entries: Array<Record<string, unknown>> }>("vault_audit_log_since", {
    since,
    limit: 50
  });
  check("audit_log_since → {entries}", Array.isArray(ranged.entries), Object.keys(ranged));
  check("audit_log_since returns the activity just generated", ranged.entries.length > 0, {
    n: ranged.entries.length
  });
  check(
    "audit_log_since honours `since`",
    ranged.entries.every((e) => Date.parse(String(e.timestamp)) >= Date.parse(since) - 1000),
    ranged.entries.slice(0, 2)
  );
  // Derive the action from the log itself rather than hardcoding a string the Go
  // side is free to rename.
  const someAction = String(entry.action ?? "");
  const byAction = await call<{ entries: Array<Record<string, unknown>> }>("vault_audit_log_since", {
    action: someAction,
    limit: 50
  });
  check(
    `audit_log_since filters by action (${someAction})`,
    byAction.entries.length > 0 && byAction.entries.every((e) => e.action === someAction),
    byAction.entries.slice(0, 3)
  );
  check(
    "audit_log_since never carries a value",
    !JSON.stringify(ranged).includes(setValue) && !JSON.stringify(byAction).includes(setValue)
  );

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

  console.log("\nenv group management (the Environments screen's write path):");
  const shown = await call<Record<string, unknown>>("vault_env_group_show", { name: "contract" });
  check(
    "group_show → {name, environments, diff_status}",
    shown.name === "contract" &&
      Array.isArray(shown.environments) &&
      typeof shown.diff_status === "string",
    Object.keys(shown)
  );
  check(
    "group_show.diff_status is ok|drift|unknown",
    ["ok", "drift", "unknown"].includes(String(shown.diff_status)),
    shown.diff_status
  );
  check("group_show carries no value", !JSON.stringify(shown).includes(setValue));

  // These two tools take `env_name`, not `env` — unlike every other env-group
  // tool. Pinned here because the reference docs once said `env`, which makes an
  // agent send a call with a missing required argument.
  const wrongField = await callFails("vault_env_group_add", {
    group: "contract",
    env: "staging",
    project: "contract-app"
  });
  check(
    "group_add rejects `env` — the field is env_name",
    wrongField.length > 0,
    wrongField.slice(0, 160)
  );

  await call("vault_create_project", { name: "contract-staging", description: "staging" });
  const added = await call<{ environments: Array<Record<string, unknown>> }>("vault_env_group_add", {
    group: "contract",
    env_name: "staging",
    project: "contract-staging"
  });
  check(
    "group_add returns the updated group with the new environment",
    Array.isArray(added.environments) && added.environments.length === 3,
    added.environments
  );

  const removed = await call<{ environments: Array<Record<string, unknown>> }>(
    "vault_env_group_remove",
    { group: "contract", env_name: "staging" }
  );
  check(
    "group_remove detaches the environment",
    Array.isArray(removed.environments) && removed.environments.length === 2,
    removed.environments
  );
  const afterRemove = await call<{ projects: Array<{ name: string }> }>("vault_projects_overview");
  check(
    "group_remove does NOT delete the underlying project",
    afterRemove.projects.some((p) => p.name === "contract-staging"),
    afterRemove.projects.map((p) => p.name)
  );

  console.log("\ninheritance (pin / unpin move a value and never report it):");
  const inherit = await call<{ group: string; env: string; inherits_from: string }>(
    "vault_env_inherit",
    { group: "contract", env: "preview", from: "production" }
  );
  check(
    "env_inherit → {group, env, inherits_from}",
    inherit.env === "preview" && inherit.inherits_from === "production",
    inherit
  );
  const shownInheriting = await call<{ inheritance?: Record<string, string> }>("vault_env_group_show", {
    name: "contract"
  });
  check(
    "group_show reports the inheritance pointer",
    shownInheriting.inheritance?.preview === "production",
    shownInheriting.inheritance
  );

  const beforePin = await call<{ keys: Array<Record<string, unknown>> }>("vault_env_inherited", {
    group: "contract",
    env: "preview"
  });
  check(
    "the child resolves DATABASE_URL from the base",
    beforePin.keys.some((k) => k.key === "DATABASE_URL" && k.source === "inherited:production"),
    beforePin.keys
  );

  const pinOut = await call<Record<string, unknown>>("vault_env_pin", {
    group: "contract",
    env: "preview",
    key: "DATABASE_URL"
  });
  check("env_pin returns an empty object — no value", Object.keys(pinOut).length === 0, pinOut);
  const afterPin = await call<{ keys: Array<Record<string, unknown>> }>("vault_env_inherited", {
    group: "contract",
    env: "preview"
  });
  const pinnedKey = afterPin.keys.find((k) => k.key === "DATABASE_URL") ?? {};
  check(
    "pin makes the key local and pinned",
    pinnedKey.pinned === true && pinnedKey.source === "local",
    pinnedKey
  );
  check("env_inherited still reports no value", !JSON.stringify(afterPin).includes(setValue));

  const unpinOut = await call<Record<string, unknown>>("vault_env_unpin", {
    group: "contract",
    env: "preview",
    key: "DATABASE_URL"
  });
  check("env_unpin returns an empty object — no value", Object.keys(unpinOut).length === 0, unpinOut);
  const afterUnpin = await call<{ keys: Array<Record<string, unknown>> }>("vault_env_inherited", {
    group: "contract",
    env: "preview"
  });
  const unpinnedKey = afterUnpin.keys.find((k) => k.key === "DATABASE_URL") ?? {};
  check(
    "unpin restores inheritance",
    unpinnedKey.pinned === false && unpinnedKey.source === "inherited:production",
    unpinnedKey
  );

  console.log("\nsealing — ciphertext out, plaintext never:");
  const ident = await call<{ name: string; recipient: string; path: string }>("vault_identity_new", {
    name: "contract-ci"
  });
  check(
    "identity_new → {name, recipient, path}",
    ident.name === "contract-ci" && ident.recipient.startsWith("tvault1"),
    Object.keys(ident)
  );
  check(
    "identity_new never returns the private key",
    !JSON.stringify(ident).includes("tvault-key1"),
    Object.keys(ident)
  );

  const shared = await call<{ project: string; recipient: string; shared: boolean }>(
    "vault_share_project",
    { project: "contract-app", recipient: ident.recipient }
  );
  check("share_project → {project, recipient, shared:true}", shared.shared === true, shared);

  const sealPath = join(dir, "sealed.env.encrypted");
  const sealed = await call<Record<string, unknown>>("vault_seal_for_recipients", {
    project: "contract-app",
    recipients: [ident.recipient],
    output_path: sealPath
  });
  for (const field of ["path", "bytes", "count", "keys", "recipient_count"]) {
    check(`seal_for_recipients has ${field}`, field in sealed, Object.keys(sealed));
  }
  check("seal wrote to the requested path", sealed.path === sealPath, sealed.path);
  check(
    "seal omits the blob when given a path (so it never lands in renderer memory)",
    sealed.sealed_base64 === undefined || sealed.sealed_base64 === "",
    typeof sealed.sealed_base64
  );
  check("seal response carries no plaintext", !JSON.stringify(sealed).includes(setValue));
  check("the sealed file is 0600", perm(sealPath) === "600", perm(sealPath));
  check(
    "the sealed file does not contain the plaintext value",
    !readFileSync(sealPath, "utf8").includes(setValue)
  );

  const openedPath = join(dir, "opened.env");
  const opened = await call<{ path: string; count: number; keys: string[] }>("vault_open_sealed", {
    path: sealPath,
    identity: "contract-ci",
    output_path: openedPath
  });
  check(
    "open_sealed → {path, count, keys}",
    opened.path === openedPath && typeof opened.count === "number" && Array.isArray(opened.keys),
    Object.keys(opened)
  );
  check("open_sealed returns no value", !JSON.stringify(opened).includes(setValue), Object.keys(opened));
  check("the opened dotenv is 0600", perm(openedPath) === "600", perm(openedPath));
  check(
    "the opened dotenv holds the plaintext on disk (why the UI warns before opening)",
    readFileSync(openedPath, "utf8").includes(setValue)
  );
  const wrongIdentity = await callFails("vault_open_sealed", {
    path: sealPath,
    identity: "not-an-identity-here",
    output_path: join(dir, "should-not-exist.env")
  });
  check("open_sealed refuses an unknown identity", wrongIdentity.length > 0, wrongIdentity.slice(0, 160));

  const envSealPath = join(dir, "group.env.encrypted");
  const envSealed = await call<Record<string, unknown>>("vault_env_seal", {
    group: "contract",
    recipients: [ident.recipient],
    output_path: envSealPath
  });
  for (const field of ["path", "bytes", "environments", "keys", "recipient_count"]) {
    check(`env_seal has ${field}`, field in envSealed, Object.keys(envSealed));
  }
  check("env_seal wrote to the requested path", envSealed.path === envSealPath, envSealed.path);
  check("env_seal response carries no plaintext", !JSON.stringify(envSealed).includes(setValue));
  check(
    "env_seal names the environments it sealed",
    Array.isArray(envSealed.environments) && (envSealed.environments as string[]).length >= 1,
    envSealed.environments
  );

  const encPath = join(dir, "export.env.encrypted");
  const encrypted = await call<Record<string, unknown>>("vault_export_env_encrypted", {
    project: "contract-app",
    output_path: encPath
  });
  for (const field of ["path", "bytes", "count", "keys", "recipient_count"]) {
    check(`export_env_encrypted has ${field}`, field in encrypted, Object.keys(encrypted));
  }
  check("export_env_encrypted response carries no plaintext", !JSON.stringify(encrypted).includes(setValue));
  check(
    "export_env_encrypted seals to the project's recipients",
    Number(encrypted.recipient_count) >= 1,
    encrypted.recipient_count
  );

  console.log("\ndotenv workflows — key names and verdicts, never values:");
  const projDir = join(dir, "project");
  mkdirSync(projDir, { mode: 0o700 });
  writeFileSync(join(projDir, ".env"), `DATABASE_URL=${setValue}\nNEW_KEY=from-file\n`, {
    mode: 0o600
  });

  const listed = await call<Record<string, unknown>>("vault_list_env_files", { directory: projDir });
  check(
    "list_env_files → {directory, files, suggested_files}",
    listed.directory === projDir && Array.isArray(listed.files) && Array.isArray(listed.suggested_files),
    Object.keys(listed)
  );
  const listedFile = (listed.files as Array<Record<string, unknown>>)[0] ?? {};
  for (const field of ["path", "key_count", "diagnostic_count"]) {
    check(`list_env_files.files[] has ${field}`, field in listedFile, listedFile);
  }
  check("list_env_files returns no value", !JSON.stringify(listed).includes(setValue));

  const preview = await call<Record<string, unknown>>("vault_preview_env_import", {
    project: "contract-app",
    directory: projDir
  });
  for (const field of [
    "project",
    "files",
    "keys",
    "create_count",
    "overwrite_count",
    "skip_count",
    "blocked_count",
    "blocked_keys",
    "diagnostic_count",
    "diagnostics"
  ]) {
    check(`preview_env_import has ${field}`, field in preview, Object.keys(preview));
  }
  const previewKey = (preview.keys as Array<Record<string, unknown>>)[0] ?? {};
  for (const field of ["action", "key", "source_path"]) {
    check(`preview_env_import.keys[] has ${field}`, field in previewKey, previewKey);
  }
  check(
    "preview reports NEW_KEY as a create",
    (preview.keys as Array<Record<string, unknown>>).some(
      (k) => k.key === "NEW_KEY" && k.action === "create"
    ),
    preview.keys
  );
  check("preview carries no plaintext", !JSON.stringify(preview).includes(setValue));

  const imported = await call<Record<string, unknown>>("vault_import_env_files", {
    project: "contract-app",
    directory: projDir
  });
  for (const field of [
    "project",
    "files",
    "imported_keys",
    "skipped_keys",
    "create_count",
    "overwrite_count",
    "skip_count",
    "blocked_count",
    "blocked_keys",
    "diagnostics"
  ]) {
    check(`import_env_files has ${field}`, field in imported, Object.keys(imported));
  }
  check(
    "import created NEW_KEY",
    (imported.imported_keys as string[]).includes("NEW_KEY"),
    imported.imported_keys
  );
  check(
    "import skipped the key that already exists",
    (imported.skipped_keys as string[]).includes("DATABASE_URL"),
    imported.skipped_keys
  );
  check("import response carries no plaintext", !JSON.stringify(imported).includes(setValue));

  const fileDiff = await call<Record<string, unknown>>("vault_diff_env", {
    file: join(projDir, ".env"),
    project: "contract-app",
    compare_values: true
  });
  for (const field of [
    "project",
    "file",
    "only_in_vault",
    "only_in_file",
    "in_both",
    "in_sync"
  ]) {
    check(`diff_env has ${field}`, field in fileDiff, Object.keys(fileDiff));
  }
  check(
    "diff_env value verdicts are same|differs|error only",
    Object.values((fileDiff.value_diffs ?? {}) as Record<string, string>).every((v) =>
      ["same", "differs", "error"].includes(v)
    ),
    fileDiff.value_diffs
  );
  check("diff_env carries no plaintext", !JSON.stringify(fileDiff).includes(setValue));

  const synced = await call<Record<string, unknown>>("vault_sync_env", {
    direction: "pull",
    path: join(projDir, ".env"),
    project: "contract-app"
  });
  for (const field of [
    "direction",
    "project",
    "path",
    "env_created",
    "vault_entries",
    "env_entries",
    "created",
    "updated",
    "skipped",
    "unchanged",
    "conflicts"
  ]) {
    check(`sync_env has ${field}`, field in synced, Object.keys(synced));
  }
  check(
    "sync_env reports key names, not values",
    (synced.conflicts as Array<Record<string, unknown>>).every(
      (c) => !("value" in c) && !("vault_value" in c) && !("env_value" in c)
    ),
    synced.conflicts
  );
  check("sync_env response carries no plaintext", !JSON.stringify(synced).includes(setValue));

  const exportPath = join(dir, "exported.env");
  const exported = await call<{ path: string; count: number; keys: string[] }>("vault_export_env", {
    project: "contract-app",
    output_path: exportPath
  });
  check(
    "export_env → {path, count, keys}",
    exported.path === exportPath && typeof exported.count === "number" && Array.isArray(exported.keys),
    Object.keys(exported)
  );
  check("export_env response carries no plaintext", !JSON.stringify(exported).includes(setValue));
  check("the exported dotenv is 0600", perm(exportPath) === "600", perm(exportPath));
  check(
    "the exported dotenv holds plaintext on disk (why the UI confirms before exporting)",
    readFileSync(exportPath, "utf8").includes(setValue)
  );

  console.log("\nenv group delete (metadata only):");
  const deletedGroup = await call<Record<string, unknown>>("vault_env_group_delete", {
    name: "contract"
  });
  check("group_delete returns an empty object", Object.keys(deletedGroup).length === 0, deletedGroup);
  const groupsAfter = await call<{ groups: unknown[] }>("vault_env_group_list");
  check("the group is gone", groupsAfter.groups.length === 0, groupsAfter.groups);
  const projectsAfter = await call<{ projects: Array<{ name: string }> }>("vault_projects_overview");
  check(
    "group_delete left every project intact",
    ["contract-app", "contract-preview", "contract-staging"].every((name) =>
      projectsAfter.projects.some((p) => p.name === name)
    ),
    projectsAfter.projects.map((p) => p.name)
  );

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
