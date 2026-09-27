import type { Bootstrap } from "@shared/types";

import { Badge, Button, Icon, Spinner, type IconName } from "./ui";

function Row({
  icon,
  label,
  ok,
  detail,
  children
}: {
  icon: IconName;
  label: string;
  ok: boolean | null;
  detail?: string;
  children?: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className="flex items-start gap-3 border-b border-line px-5 py-3.5 last:border-0">
      <span className={`mt-0.5 ${ok === null ? "text-faint" : ok ? "text-success" : "text-danger"}`}>
        <Icon name={ok === null ? icon : ok ? "check" : "alert"} size={15} />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-3">
          <p className="text-[13px] font-medium text-ink">{label}</p>
          {detail ? <p className="mono truncate text-[11.5px] text-faint">{detail}</p> : null}
        </div>
        {children}
      </div>
    </div>
  );
}

/**
 * Shown when the `tvault mcp` child could not be started or the vault is not
 * usable. Its job is to say precisely which of the four prerequisites failed —
 * binary, vault, policy, passphrase — instead of a generic error.
 */
export default function SetupScreen({
  boot,
  loading,
  onRetry
}: {
  boot: Bootstrap | null;
  loading: boolean;
  onRetry: () => void;
}): React.JSX.Element {
  if (loading || !boot) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-muted">
        <Spinner size={20} />
        <p className="text-[13px]">Connecting to tvault mcp…</p>
      </div>
    );
  }

  const binary = boot.binary;
  const policy = boot.policy;
  const session = boot.session;
  const connected = session.connected && boot.status !== null;

  // Without this file the Go server falls back to SafeDefaultPolicy, which denies
  // every secret key. This is the single most common reason the app shows nothing.
  const policyUsable =
    policy.exists &&
    (policy.access_mode === "read-write" || policy.access_mode === "full") &&
    (policy.max_reads_per_session ?? 0) > 0;

  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <div className="mx-auto w-full max-w-2xl px-6 py-10">
        <div className="mb-7">
          <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-tv-md border border-accent-line bg-accent-soft text-accent">
            <Icon name="shield" size={18} />
          </div>
          <h1 className="text-[19px] font-semibold tracking-[-0.01em] text-ink">
            {connected ? "Vault connected" : "Vault not reachable"}
          </h1>
          <p className="mt-1.5 max-w-lg text-[13px] leading-relaxed text-muted">
            TinyVault Desktop never opens <span className="mono text-ink">vault.db</span> itself. It
            spawns <span className="mono text-ink">tvault mcp</span> and talks JSON-RPC over stdio, so
            the Go binary keeps sole ownership of the single-writer bbolt lock and the CLI keeps
            working while this window is open.
          </p>
        </div>

        <div className="overflow-hidden rounded-tv-md border border-line bg-raised">
          <Row
            icon="terminal"
            label="tvault binary"
            ok={binary ? true : null}
            detail={binary ? binary.version : undefined}
          >
            <p className="mono mt-1 break-all text-[11.5px] text-muted">
              {binary ? `${binary.path}  ·  via ${binary.source}` : (boot.binary_error ?? "not found")}
            </p>
          </Row>

          <Row icon="lock" label="Vault" ok={boot.status ? boot.status.is_unlocked : false} detail={boot.vault_dir}>
            {boot.status ? (
              <p className="mt-1 text-[12px] text-muted">
                {boot.status.project_count} projects · unlocked ·{" "}
                <span className="mono text-[11.5px]">{boot.status.vault_id.slice(0, 8)}</span>
              </p>
            ) : (
              <p className="mt-1 text-[12px] text-muted">
                No status returned. The vault may be locked, uninitialised, or the passphrase source
                may be unavailable to a GUI-launched process.
              </p>
            )}
          </Row>

          <Row
            icon="shield"
            label="MCP access policy"
            ok={policy.exists ? (policyUsable ? true : false) : false}
            detail={policy.path}
          >
            {!policy.exists ? (
              <div className="mt-2 space-y-2">
                <p className="text-[12px] leading-relaxed text-muted">
                  Missing. Without it the server uses the fail-closed{" "}
                  <span className="mono text-ink">SafeDefaultPolicy</span> — read-only with every
                  secret key denied — so this app would show an empty vault.
                </p>
                <pre className="mono overflow-x-auto rounded-tv-sm border border-line bg-console px-3 py-2.5 text-[11.5px] leading-relaxed text-console-text">
{`access_mode: read-write
projects_allow: ["*"]
projects_deny: []
secrets_allow: ["*"]
secrets_deny: []
allow_exec: false
max_reads_per_session: 100
redact_output: true`}
                </pre>
                <p className="text-[11.5px] text-faint">
                  All eight fields are required — the Go loader rejects the file if any is missing,
                  and rejects unknown fields too.
                </p>
              </div>
            ) : (
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                <Badge tone={policyUsable ? "success" : "warn"}>{policy.access_mode ?? "unknown"}</Badge>
                <Badge tone={policy.allow_exec ? "danger" : "neutral"}>
                  exec {policy.allow_exec ? "on" : "off"}
                </Badge>
                <Badge tone={(policy.max_reads_per_session ?? 0) > 0 ? "neutral" : "warn"}>
                  {policy.max_reads_per_session ?? 0} reveals / session
                </Badge>
                {policy.secrets_deny && policy.secrets_deny.length > 0 ? (
                  <Badge tone="neutral">deny {policy.secrets_deny.join(", ")}</Badge>
                ) : null}
              </div>
            )}
            {policy.exists && !policyUsable ? (
              <p className="mt-2 text-[12px] leading-relaxed text-warn">
                {(policy.max_reads_per_session ?? 0) === 0
                  ? "max_reads_per_session is 0, so revealing any value will be refused. Raise it to use the reveal button."
                  : `access_mode "${policy.access_mode ?? "?"}" does not permit writes.`}
              </p>
            ) : null}
            {policy.parse_error ? (
              <p className="mono mt-1.5 text-[11.5px] text-danger">{policy.parse_error}</p>
            ) : null}
          </Row>

          <Row
            icon="branch"
            label="Local agent"
            ok={null}
            detail={boot.agent.running ? `pid ${boot.agent.pid}` : "not running"}
          >
            <p className="mt-1 text-[12px] leading-relaxed text-muted">
              {boot.agent.running
                ? "Running. Reads can be served without a passphrase, but the agent is read-only — writes still need the passphrase."
                : "Not required. This app unlocks directly through the cached-KEK path, which supports reads and writes."}
            </p>
          </Row>

          <Row
            icon="layers"
            label="MCP session"
            ok={session.connected ? true : false}
            detail={
              session.connected
                ? `${session.server_name ?? "tvault"} ${session.server_version ?? ""} · ${session.tool_count ?? 0} tools`
                : undefined
            }
          >
            {session.connected ? (
              <p className="mt-1 text-[12px] text-muted">
                Backend:{" "}
                <span className={session.backend === "agent" ? "text-warn" : "text-success"}>
                  {session.backend === "agent"
                    ? "agent (read-only — writes will be refused)"
                    : "cached KEK, reopen-per-request (reads + writes)"}
                </span>
              </p>
            ) : (
              <pre className="mono mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap break-words rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2.5 text-[11.5px] leading-relaxed text-danger">
                {session.last_error || "no error reported"}
              </pre>
            )}
          </Row>
        </div>

        <div className="mt-6 flex items-center gap-2">
          <Button variant="primary" icon="refresh" onClick={onRetry}>
            Retry connection
          </Button>
          <span className="text-[12px] text-faint">
            {connected ? "All prerequisites satisfied." : "Fix the rows above, then retry."}
          </span>
        </div>
      </div>
    </div>
  );
}
