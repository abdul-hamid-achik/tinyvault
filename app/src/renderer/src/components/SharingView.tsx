import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import type { IdentityEntry, OpenSealedResult, SealResult } from "@shared/types";

import { unwrap } from "../lib/api";
import {
  Badge,
  Button,
  EmptyState,
  Field,
  Icon,
  IconButton,
  Modal,
  Spinner,
  TextInput,
  Tooltip,
  useToast
} from "./ui";

/** Sealed blobs are small; this only has to be honest, not exhaustive. */
function humanBytes(n: number): string {
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

/** `crypto.EncodeRecipient` — a public recipient is always `tvault1…`. */
const RECIPIENT_PREFIX = "tvault1";

/**
 * Sharing is the recipient layer: X25519 public halves (tvault1…) wrapping a
 * project's data key, so granting read access never involves sharing a
 * passphrase.
 *
 * Everything on this screen is public material. The private key (tvault-key1…)
 * is never returned by any MCP tool and `tvault identity export` stays a
 * CLI-only, TTY-guarded operation — so this view cannot leak one, by
 * construction rather than by care.
 *
 * The two dialogs at the bottom are what sharing exists for: sealing a project
 * into a commit-safe v2 `.env.encrypted`, and opening one. Neither changes the
 * vault, and neither ever puts a value on screen — sealing returns ciphertext
 * metadata, opening writes plaintext to a 0600 file and returns only its path
 * and key names.
 */
export default function SharingView({
  readOnly,
  projects,
  defaultProject,
  onChanged
}: {
  readOnly: boolean;
  projects: string[];
  defaultProject: string | null;
  onChanged: () => void;
}): React.JSX.Element {
  const toast = useToast();

  const [identities, setIdentities] = useState<IdentityEntry[]>([]);
  const [identitiesLoading, setIdentitiesLoading] = useState(true);
  const [identitiesError, setIdentitiesError] = useState<string | null>(null);

  const [project, setProject] = useState(defaultProject ?? projects[0] ?? "");
  const [recipients, setRecipients] = useState<string[]>([]);
  const [recipientsLoading, setRecipientsLoading] = useState(false);
  const [recipientsError, setRecipientsError] = useState<string | null>(null);

  const [newIdentityName, setNewIdentityName] = useState("");
  const [creatingIdentity, setCreatingIdentity] = useState(false);

  const [shareRecipient, setShareRecipient] = useState("");
  const [sharing, setSharing] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);

  const [revoke, setRevoke] = useState<string | null>(null);

  const [showSeal, setShowSeal] = useState(false);
  const [showOpen, setShowOpen] = useState(false);

  // Keep the selection valid if the project list arrives after first render.
  useEffect(() => {
    if (!project && (defaultProject || projects[0])) {
      setProject(defaultProject ?? projects[0] ?? "");
    }
  }, [project, defaultProject, projects]);

  const loadIdentities = useCallback(async (): Promise<void> => {
    setIdentitiesLoading(true);
    setIdentitiesError(null);
    try {
      setIdentities(await unwrap(window.tvault.identities()));
    } catch (err) {
      setIdentitiesError(err instanceof Error ? err.message : String(err));
    } finally {
      setIdentitiesLoading(false);
    }
  }, []);

  const loadRecipients = useCallback(async (name: string): Promise<void> => {
    if (!name) {
      setRecipients([]);
      return;
    }
    setRecipientsLoading(true);
    setRecipientsError(null);
    try {
      setRecipients(await unwrap(window.tvault.recipients(name)));
    } catch (err) {
      setRecipients([]);
      setRecipientsError(err instanceof Error ? err.message : String(err));
    } finally {
      setRecipientsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadIdentities();
  }, [loadIdentities]);

  useEffect(() => {
    void loadRecipients(project);
  }, [project, loadRecipients]);

  const identityByRecipient = useMemo(() => {
    const map = new Map<string, string>();
    for (const id of identities) map.set(id.recipient, id.name);
    return map;
  }, [identities]);

  const copy = async (label: string, value: string): Promise<void> => {
    try {
      const { clearsInMs } = await unwrap(window.tvault.copySecret(value));
      toast.success(
        `Copied ${label}`,
        `Clears in ${Math.round(clearsInMs / 1000)}s — clipboard-history managers may keep a copy`
      );
    } catch (err) {
      toast.error("Copy failed", err instanceof Error ? err.message : String(err));
    }
  };

  const createIdentity = async (): Promise<void> => {
    const name = newIdentityName.trim();
    if (!name) {
      toast.error("Identity name is required");
      return;
    }
    setCreatingIdentity(true);
    try {
      const created = await unwrap(window.tvault.newIdentity(name));
      toast.success(
        `Created identity ${created.name}`,
        "Only the public recipient left the vault; the private key is on disk, mode 0600."
      );
      setNewIdentityName("");
      await loadIdentities();
      onChanged();
    } catch (err) {
      toast.error("Could not create identity", err instanceof Error ? err.message : String(err));
    } finally {
      setCreatingIdentity(false);
    }
  };

  const share = async (): Promise<void> => {
    const recipient = shareRecipient.trim();
    if (!project) {
      toast.error("No project selected");
      return;
    }
    if (!recipient) {
      setShareError("Paste a recipient string (tvault1…) or pick one of your identities.");
      return;
    }
    setSharing(true);
    setShareError(null);
    try {
      await unwrap(window.tvault.shareProject(project, recipient));
      toast.success(`Shared ${project}`, "The project data key was wrapped to that recipient.");
      setShareRecipient("");
      await loadRecipients(project);
      onChanged();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setShareError(message);
      toast.error("Share failed", message);
    } finally {
      setSharing(false);
    }
  };

  const runRevoke = async (): Promise<void> => {
    if (!revoke) return;
    setSharing(true);
    try {
      await unwrap(window.tvault.unshareProject(project, revoke));
      toast.success(
        `Revoked ${identityByRecipient.get(revoke) ?? "recipient"}`,
        "The data key was rotated. Pre-removal snapshots and exports stay readable — rotate the underlying credentials if that matters."
      );
      setRevoke(null);
      await loadRecipients(project);
      onChanged();
    } catch (err) {
      toast.error("Revoke failed", err instanceof Error ? err.message : String(err));
    } finally {
      setSharing(false);
    }
  };

  return (
    <div className="flex h-full min-w-0 flex-col">
      <header className="shrink-0 border-b border-line px-6 pb-4 pt-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-[17px] font-semibold tracking-[-0.01em] text-ink">Sharing</h1>
            <p className="mt-1 max-w-2xl text-[12.5px] leading-relaxed text-muted">
              Recipient-based access: a project's data key is wrapped to an X25519 public key, so
              granting read access never means sharing a passphrase. Everything here is public
              material — private keys never reach this window. Sealing packages a project's values
              into a commit-safe blob for a teammate, a CI runner or another agent; opening one
              needs a matching private identity.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {readOnly ? <Badge tone="warn">read-only policy</Badge> : null}
            <Button size="sm" icon="key" disabled={readOnly} onClick={() => setShowOpen(true)}>
              Open a blob
            </Button>
            <Button
              size="sm"
              variant="primary"
              icon="lock"
              disabled={readOnly}
              onClick={() => setShowSeal(true)}
            >
              Seal for recipients
            </Button>
          </div>
        </div>
      </header>

      <div className="grid min-h-0 flex-1 grid-cols-2 divide-x divide-line overflow-hidden">
        {/* --- identities --- */}
        <section className="flex min-w-0 flex-col overflow-hidden">
          <div className="flex shrink-0 items-center gap-2 border-b border-line px-5 py-3">
            <span className="text-accent">
              <Icon name="branch" size={14} />
            </span>
            <h2 className="text-[13px] font-semibold text-ink">Your identities</h2>
            <span className="flex-1" />
            <IconButton icon="refresh" label="Reload identities" onClick={() => void loadIdentities()} />
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto p-4">
            {identitiesLoading ? (
              <div className="flex h-24 items-center justify-center gap-2.5 text-muted">
                <Spinner /> <span className="text-[12.5px]">Loading identities…</span>
              </div>
            ) : identitiesError ? (
              <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
                {identitiesError}
              </p>
            ) : identities.length === 0 ? (
              <EmptyState
                icon="branch"
                title="No identities yet"
                body="An identity is an X25519 keypair. Its public half (tvault1…) is what other people share projects to; the private half stays on this machine."
              />
            ) : (
              <ul className="space-y-1.5">
                {identities.map((id) => (
                  <li
                    key={id.name}
                    className="rounded-tv-sm border border-line bg-raised px-3.5 py-2.5"
                  >
                    <div className="flex items-center gap-2">
                      <span className="mono text-[12.5px] font-medium text-ink">{id.name}</span>
                      <span className="flex-1" />
                      <Tooltip label="Copy public recipient">
                        <IconButton
                          icon="copy"
                          label={`Copy recipient for ${id.name}`}
                          onClick={() => void copy(id.name, id.recipient)}
                        />
                      </Tooltip>
                    </div>
                    <p className="mono mt-1 break-all text-[11px] leading-relaxed text-faint">
                      {id.recipient}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {!readOnly ? (
            <div className="shrink-0 border-t border-line px-4 py-3">
              <div className="flex items-center gap-2">
                <TextInput
                  mono
                  value={newIdentityName}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="work-laptop"
                  onChange={(e) => setNewIdentityName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void createIdentity();
                  }}
                />
                <Button
                  variant="primary"
                  icon="plus"
                  disabled={creatingIdentity}
                  onClick={() => void createIdentity()}
                >
                  {creatingIdentity ? "Creating…" : "New"}
                </Button>
              </div>
              <p className="mt-2 flex items-start gap-1.5 text-[11.5px] leading-relaxed text-faint">
                <span className="mt-0.5">
                  <Icon name="lock" size={11} />
                </span>
                The private key is written 0600 under the vault's identities directory and is
                never returned here. Exporting one is deliberately CLI-only:
                <span className="mono">tvault identity export</span>
              </p>
            </div>
          ) : null}
        </section>

        {/* --- project recipients --- */}
        <section className="flex min-w-0 flex-col overflow-hidden">
          <div className="flex shrink-0 items-center gap-2 border-b border-line px-5 py-3">
            <span className="text-accent">
              <Icon name="shield" size={14} />
            </span>
            <h2 className="text-[13px] font-semibold text-ink">Project recipients</h2>
            <span className="flex-1" />
            <select
              value={project}
              onChange={(e) => setProject(e.target.value)}
              className="mono h-7 max-w-[180px] rounded-tv-sm border border-line bg-raised px-2 text-[12px] text-ink focus:border-accent focus:outline-none"
            >
              {projects.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
            <IconButton
              icon="refresh"
              label="Reload recipients"
              onClick={() => void loadRecipients(project)}
            />
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto p-4">
            {!project ? (
              <EmptyState icon="folder" title="No project selected" />
            ) : recipientsLoading ? (
              <div className="flex h-24 items-center justify-center gap-2.5 text-muted">
                <Spinner /> <span className="text-[12.5px]">Loading recipients…</span>
              </div>
            ) : recipientsError ? (
              <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
                {recipientsError}
              </p>
            ) : recipients.length === 0 ? (
              <EmptyState
                icon="shield"
                title={`${project} is not shared`}
                body="Only the vault passphrase can open it. Share it below to wrap its data key to a recipient instead."
              />
            ) : (
              <ul className="space-y-1.5">
                {recipients.map((r) => {
                  const known = identityByRecipient.get(r);
                  return (
                    <li
                      key={r}
                      className="group flex items-start gap-2.5 rounded-tv-sm border border-line bg-raised px-3.5 py-2.5"
                    >
                      <span className="mt-0.5 text-faint">
                        <Icon name="branch" size={13} />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="mono text-[12px] text-ink">
                            {known ?? `${r.slice(0, 16)}…`}
                          </span>
                          {known ? <Badge tone="accent">yours</Badge> : <Badge tone="neutral">external</Badge>}
                        </div>
                        <p className="mono mt-1 break-all text-[11px] leading-relaxed text-faint">{r}</p>
                      </div>
                      <div className="flex shrink-0 items-center gap-0.5 opacity-40 transition-opacity group-hover:opacity-100">
                        <IconButton icon="copy" label="Copy recipient" onClick={() => void copy("recipient", r)} />
                        {!readOnly ? (
                          <IconButton
                            icon="trash"
                            label="Revoke access"
                            tone="danger"
                            onClick={() => setRevoke(r)}
                          />
                        ) : null}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}

            {!recipientsLoading && !recipientsError && recipients.length > 0 ? (
              <p className="mt-3 flex items-start gap-2 rounded-tv-sm border border-line bg-soft/60 px-3 py-2.5 text-[11.5px] leading-relaxed text-faint">
                <span className="mt-0.5 shrink-0 text-warn">
                  <Icon name="alert" size={12} />
                </span>
                Revoking a recipient re-keys the live vault only. A{" "}
                <span className="mono">.env.encrypted</span> you already sealed, a snapshot you
                already copied, or anything already exported stays readable with the old key — so
                revocation is not retroactive. If a recipient is compromised, rotate the
                credentials inside and re-seal what you handed out.
              </p>
            ) : null}
          </div>

          {!readOnly ? (
            <div className="shrink-0 space-y-2 border-t border-line px-4 py-3">
              {identities.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {identities
                    .filter((id) => !recipients.includes(id.recipient))
                    .map((id) => (
                      <button
                        key={id.name}
                        onClick={() => setShareRecipient(id.recipient)}
                        className="rounded-full border border-line bg-raised px-2.5 py-1 text-[11.5px] text-muted transition-colors hover:border-accent-line hover:text-accent"
                      >
                        + {id.name}
                      </button>
                    ))}
                </div>
              ) : null}
              <div className="flex items-center gap-2">
                <TextInput
                  mono
                  value={shareRecipient}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="tvault1…"
                  onChange={(e) => {
                    setShareRecipient(e.target.value);
                    setShareError(null);
                  }}
                />
                <Button variant="primary" icon="arrowRight" disabled={sharing} onClick={() => void share()}>
                  {sharing ? "Sharing…" : "Share"}
                </Button>
              </div>
              {shareError ? (
                <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
                  {shareError}
                </p>
              ) : null}
            </div>
          ) : null}
        </section>
      </div>

      <Modal
        open={revoke !== null}
        title="Revoke this recipient?"
        subtitle={project}
        onClose={() => setRevoke(null)}
        width="max-w-md"
        footer={
          <>
            <Button variant="ghost" onClick={() => setRevoke(null)} disabled={sharing}>
              Cancel
            </Button>
            <Button variant="danger" icon="trash" disabled={sharing} onClick={() => void runRevoke()}>
              {sharing ? "Revoking…" : "Revoke"}
            </Button>
          </>
        }
      >
        <p className="mono break-all text-[11.5px] leading-relaxed text-muted">{revoke}</p>
        <p className="mt-3 text-[13px] leading-relaxed text-muted">
          Revoking rotates the project's data key and re-encrypts every current value and
          archived version, so the recipient loses access going forward.
        </p>
        <p className="mt-3 flex items-start gap-2 rounded-tv-sm border border-warn/30 bg-warn/8 px-3 py-2.5 text-[12px] leading-relaxed text-warn">
          <span className="mt-0.5">
            <Icon name="alert" size={13} />
          </span>
          Vault snapshots taken before this moment, and anything already exported, sealed or
          decrypted, stay readable with the old key. Rotate the underlying credentials if this
          recipient is compromised.
        </p>
      </Modal>

      <SealModal
        open={showSeal}
        projects={projects}
        initialProject={project}
        identities={identities}
        readOnly={readOnly}
        onClose={() => setShowSeal(false)}
      />

      <OpenSealedModal
        open={showOpen}
        identities={identities}
        readOnly={readOnly}
        onClose={() => setShowOpen(false)}
      />
    </div>
  );
}

// --- seal / open ---------------------------------------------------------

const selectClass =
  "h-9 w-full rounded-tv-sm border border-line bg-raised px-2.5 text-[12.5px] text-ink focus:border-accent focus:outline-none";

/**
 * A titled block for composite controls. `Field` renders a <label>, which is
 * right for a single input but would hand a click on the heading to the first
 * checkbox or button inside a list.
 */
function Group({
  label,
  hint,
  children
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}): React.JSX.Element {
  return (
    <div>
      <span className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
        {label}
      </span>
      {children}
      {hint ? <span className="mt-1.5 block text-[12px] leading-relaxed text-faint">{hint}</span> : null}
    </div>
  );
}

/**
 * A dialog-issued path, echoed back read-only. There is deliberately no text
 * input here: main records every path it offers and refuses anything else, so
 * a typed path could only ever produce that refusal.
 */
function PathRow({
  path,
  placeholder,
  pickLabel,
  busy,
  onPick
}: {
  path: string | null;
  placeholder: string;
  pickLabel: string;
  busy: boolean;
  onPick: () => void;
}): React.JSX.Element {
  return (
    <div className="flex items-center gap-2">
      <p
        className={`mono min-w-0 flex-1 truncate rounded-tv-sm border border-line px-3 py-2 text-[11.5px] ${
          path ? "bg-soft/60 text-ink" : "bg-soft/40 text-faint"
        }`}
      >
        {path ?? placeholder}
      </p>
      <Button size="sm" icon="folder" disabled={busy} onClick={onPick}>
        {pickLabel}
      </Button>
    </div>
  );
}

/** Chips of key names — metadata, never values. */
function KeyChips({ keys }: { keys: string[] }): React.JSX.Element {
  return (
    <ul className="flex flex-wrap gap-1">
      {keys.map((k) => (
        <li
          key={k}
          className="mono rounded-tv-sm border border-line bg-raised px-1.5 py-0.5 text-[11px] text-muted"
        >
          {k}
        </li>
      ))}
    </ul>
  );
}

/** Add-or-drop, immutably. */
function toggled(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

interface CheckItem {
  value: string;
  label: string;
  note?: string;
  tone?: "accent" | "neutral";
  removable?: boolean;
}

/**
 * The scrollable checkbox list both dialogs need: recipients to seal to, and
 * the project's key names. Identifiers and key names only — a value is never an
 * item here, because neither dialog ever receives one.
 */
function CheckList({
  items,
  selected,
  maxHeight,
  onToggle,
  onRemove
}: {
  items: CheckItem[];
  selected: string[];
  maxHeight: string;
  onToggle: (value: string) => void;
  onRemove?: (value: string) => void;
}): React.JSX.Element {
  return (
    <ul
      className={`${maxHeight} space-y-0.5 overflow-y-auto rounded-tv-sm border border-line bg-soft/40 p-1.5`}
    >
      {items.map((it) => (
        <li
          key={it.value}
          className="flex items-center gap-1.5 rounded px-2 py-1.5 transition-colors hover:bg-raised"
        >
          <label className="flex min-w-0 flex-1 cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              checked={selected.includes(it.value)}
              onChange={() => onToggle(it.value)}
              className="accent-[var(--tv-accent)]"
            />
            <span className="mono min-w-0 truncate text-[12px] text-ink">{it.label}</span>
            {it.note ? <Badge tone={it.tone ?? "neutral"}>{it.note}</Badge> : null}
          </label>
          {onRemove && it.removable ? (
            <IconButton icon="x" label={`Remove ${it.label}`} onClick={() => onRemove(it.value)} />
          ) : null}
        </li>
      ))}
    </ul>
  );
}

/**
 * Seals a project's values to X25519 recipients and writes a v2
 * `.env.encrypted`. Everything that comes back is ciphertext metadata: the app
 * always supplies an output path, so `sealed_base64` stays empty and no blob —
 * let alone a value — is ever held in renderer state.
 */
function SealModal({
  open,
  projects,
  initialProject,
  identities,
  readOnly,
  onClose
}: {
  open: boolean;
  projects: string[];
  initialProject: string;
  identities: IdentityEntry[];
  readOnly: boolean;
  onClose: () => void;
}): React.JSX.Element | null {
  const toast = useToast();

  const [project, setProject] = useState(initialProject);
  const [shared, setShared] = useState<string[]>([]);
  const [keys, setKeys] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [chosen, setChosen] = useState<string[]>([]);
  const [pastedOnly, setPastedOnly] = useState<string[]>([]);
  const [pasted, setPasted] = useState("");
  const [pickedKeys, setPickedKeys] = useState<string[]>([]);
  const [outputPath, setOutputPath] = useState<string | null>(null);

  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<SealResult | null>(null);

  // Switching project quickly can let the slower request resolve last and paint
  // the previous project's keys under the new selection.
  const loadGen = useRef(0);

  useEffect(() => {
    if (!open) return;
    // Re-seeded on every open, so a destination left over from the last seal
    // cannot silently receive the next one.
    setProject(initialProject);
    setChosen([]);
    setPastedOnly([]);
    setPasted("");
    setPickedKeys([]);
    setOutputPath(null);
    setErr(null);
    setResult(null);
  }, [open, initialProject]);

  const loadFor = useCallback(async (name: string): Promise<void> => {
    const gen = ++loadGen.current;
    if (!name) {
      setShared([]);
      setKeys([]);
      return;
    }
    setLoading(true);
    setLoadError(null);
    try {
      const [existing, secrets] = await Promise.all([
        unwrap(window.tvault.recipients(name)),
        unwrap(window.tvault.listSecrets(name))
      ]);
      if (gen !== loadGen.current) return;
      setShared(existing);
      // Key names only: listSecrets is the metadata tool, no values involved.
      setKeys(secrets.map((s) => s.key).sort((a, b) => a.localeCompare(b)));
      // Pre-fill with everyone who can already read the project. Sealing to the
      // current set is the common case; dropping one becomes a deliberate edit.
      setChosen(existing);
    } catch (e) {
      if (gen !== loadGen.current) return;
      setShared([]);
      setKeys([]);
      setLoadError(e instanceof Error ? e.message : String(e));
    } finally {
      if (gen === loadGen.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!open || !project) return;
    void loadFor(project);
  }, [open, project, loadFor]);

  const rows = useMemo<CheckItem[]>(() => {
    const out: CheckItem[] = [];
    const seen = new Set<string>();
    const add = (item: CheckItem): void => {
      if (seen.has(item.value)) return;
      seen.add(item.value);
      out.push(item);
    };
    for (const id of identities) {
      add({ value: id.recipient, label: id.name, note: "yours", tone: "accent" });
    }
    for (const r of shared) {
      add({ value: r, label: `${r.slice(0, 16)}…`, note: "already shared" });
    }
    for (const r of pastedOnly) {
      add({ value: r, label: `${r.slice(0, 16)}…`, note: "pasted", removable: true });
    }
    return out;
  }, [identities, shared, pastedOnly]);

  const addPasted = (): void => {
    const value = pasted.trim();
    if (!value) return;
    if (!value.startsWith(RECIPIENT_PREFIX)) {
      // Also stops the one paste that would really hurt — a tvault-key1…
      // private identity — before it crosses the bridge at all.
      setErr(`A recipient is a public key and starts with ${RECIPIENT_PREFIX}…`);
      return;
    }
    setErr(null);
    setPastedOnly((prev) => (prev.includes(value) ? prev : [...prev, value]));
    setChosen((prev) => (prev.includes(value) ? prev : [...prev, value]));
    setPasted("");
  };

  const dropPasted = (recipient: string): void => {
    setPastedOnly((prev) => prev.filter((r) => r !== recipient));
    setChosen((prev) => prev.filter((r) => r !== recipient));
  };

  const chooseOutput = async (): Promise<void> => {
    setErr(null);
    try {
      const picked = await unwrap(
        window.tvault.pickSaveFile("Save sealed .env.encrypted", ".env.encrypted")
      );
      // Null is a cancelled dialog, not a failure: keep the previous choice.
      if (picked !== null) setOutputPath(picked);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const seal = async (): Promise<void> => {
    if (!project) {
      setErr("No project selected.");
      return;
    }
    if (chosen.length === 0) {
      setErr("Pick at least one recipient.");
      return;
    }
    if (outputPath === null) {
      setErr("Choose where to write the sealed file.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const sealed = await unwrap(
        window.tvault.sealForRecipients({
          project,
          recipients: chosen,
          keys: pickedKeys.length > 0 ? pickedKeys : undefined,
          outputPath
        })
      );
      setResult(sealed);
      toast.success(
        `Sealed ${sealed.count} key${sealed.count === 1 ? "" : "s"}`,
        `${humanBytes(sealed.bytes)} · ${sealed.recipient_count} recipient${
          sealed.recipient_count === 1 ? "" : "s"
        } · the vault itself is unchanged`
      );
      // No onChanged(): sealing reads secrets and writes a file. Nothing in the
      // vault moved, so there is nothing to refresh.
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setErr(message);
      toast.error("Sealing failed", message);
    } finally {
      setBusy(false);
    }
  };

  if (!open) return null;

  // `keys.length > 0` keeps the button honest when the project is empty or the
  // policy hides everything: sealing would write a valid blob with nothing in it.
  const canSeal =
    !readOnly && !busy && !loading && chosen.length > 0 && keys.length > 0 && outputPath !== null;

  return (
    <Modal
      open
      title="Seal for recipients"
      subtitle={project || undefined}
      onClose={onClose}
      width="max-w-xl"
      footer={
        result ? (
          <>
            <Button variant="ghost" onClick={onClose} disabled={busy}>
              Close
            </Button>
            <Button icon="lock" disabled={busy} onClick={() => setResult(null)}>
              Seal another
            </Button>
          </>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" icon="lock" disabled={!canSeal} onClick={() => void seal()}>
              {busy ? "Sealing…" : "Seal & write"}
            </Button>
          </>
        )
      }
    >
      <div className="space-y-4">
        <p className="flex items-start gap-2.5 rounded-tv-sm border border-line bg-soft/60 px-3.5 py-2.5 text-[12px] leading-relaxed text-muted">
          <span className="mt-0.5 shrink-0 text-accent">
            <Icon name="lock" size={13} />
          </span>
          <span>
            Writes a v2 <span className="mono">.env.encrypted</span> — ciphertext, so it is safe to
            commit. Two properties make the format worth using: it is{" "}
            <span className="font-medium text-ink">KEK-independent</span>, so rotating the vault
            passphrase does not invalidate it, and it opens{" "}
            <span className="font-medium text-ink">only</span> with a matching private identity,
            never with the passphrase.
          </span>
        </p>

        {projects.length === 0 ? (
          <p className="rounded-tv-sm border border-warn/30 bg-warn/8 px-3 py-2 text-[12px] text-warn">
            No projects yet — create one on the Secrets screen first.
          </p>
        ) : (
          <Field label="Project">
            <select
              value={project}
              onChange={(e) => setProject(e.target.value)}
              className={selectClass}
            >
              {projects.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </Field>
        )}

        <Group
          label="Recipients"
          hint={
            chosen.length === 0
              ? "At least one recipient is required."
              : `${chosen.length} selected — each of them can open this blob with their private identity`
          }
        >
          {loading ? (
            <div className="flex h-16 items-center justify-center gap-2.5 text-muted">
              <Spinner /> <span className="text-[12px]">Loading recipients and keys…</span>
            </div>
          ) : loadError ? (
            <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
              {loadError}
            </p>
          ) : rows.length === 0 ? (
            <p className="rounded-tv-sm border border-line bg-soft/40 px-3 py-2.5 text-[12px] leading-relaxed text-muted">
              No identities on this machine and this project is not shared yet. Paste a recipient
              below — they are public by design, so anyone can send you one.
            </p>
          ) : (
            <CheckList
              items={rows}
              selected={chosen}
              maxHeight="max-h-44"
              onToggle={(v) => setChosen((prev) => toggled(prev, v))}
              onRemove={dropPasted}
            />
          )}
          <div className="mt-2 flex items-center gap-2">
            <TextInput
              mono
              value={pasted}
              spellCheck={false}
              autoComplete="off"
              placeholder="tvault1… — paste someone else's public recipient"
              onChange={(e) => {
                setPasted(e.target.value);
                setErr(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addPasted();
                }
              }}
            />
            <Button
              size="sm"
              icon="plus"
              disabled={busy || pasted.trim() === ""}
              onClick={addPasted}
            >
              Add
            </Button>
          </div>
        </Group>

        <Group
          label="Keys"
          hint={
            keys.length === 0
              ? "This project has no keys yet."
              : pickedKeys.length === 0
                ? `Nothing checked seals all ${keys.length} key${keys.length === 1 ? "" : "s"}.`
                : `${pickedKeys.length} of ${keys.length} checked — only those are sealed.`
          }
        >
          {keys.length > 0 ? (
            <CheckList
              items={keys.map((k) => ({ value: k, label: k }))}
              selected={pickedKeys}
              maxHeight="max-h-40"
              onToggle={(v) => setPickedKeys((prev) => toggled(prev, v))}
            />
          ) : null}
        </Group>

        <Group label="Destination">
          <PathRow
            path={outputPath}
            placeholder="No file chosen"
            pickLabel={outputPath ? "Change…" : "Choose…"}
            busy={busy}
            onPick={() => void chooseOutput()}
          />
        </Group>

        {result ? (
          <div className="space-y-2.5 rounded-tv-sm border border-line bg-soft/60 px-3.5 py-3">
            <p className="flex items-center gap-2 text-[12.5px] font-medium text-ink">
              <span className="text-success">
                <Icon name="check" size={13} />
              </span>
              Sealed {result.count} key{result.count === 1 ? "" : "s"} for{" "}
              {result.recipient_count} recipient{result.recipient_count === 1 ? "" : "s"}
            </p>
            <p className="mono break-all text-[11.5px] leading-relaxed text-muted">
              {result.path ?? outputPath}
            </p>
            <div className="flex flex-wrap gap-1.5">
              <Badge tone="neutral">{humanBytes(result.bytes)}</Badge>
              <Badge tone="neutral">v2 · recipient-sealed</Badge>
              <Badge tone="accent">safe to commit</Badge>
            </div>
            <KeyChips keys={result.keys} />
            <p className="flex items-start gap-2 rounded-tv-sm border border-warn/30 bg-warn/8 px-3 py-2.5 text-[11.5px] leading-relaxed text-warn">
              <span className="mt-0.5 shrink-0">
                <Icon name="alert" size={12} />
              </span>
              Handing this file over is not something the vault can undo. Revoking a recipient
              later re-keys the live vault, not this blob — whoever holds it keeps these values.
              Rotate the credentials inside if a recipient turns out to be compromised.
            </p>
          </div>
        ) : null}

        {readOnly ? (
          <p className="rounded-tv-sm border border-warn/30 bg-warn/8 px-3 py-2 text-[12px] text-warn">
            The active policy is read-only, so the server refuses to seal.
          </p>
        ) : null}

        {err ? (
          <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
            {err}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}

/**
 * The reverse direction: open a v2 blob with a local identity and write a
 * plaintext dotenv. The values never cross the bridge — the tool returns the
 * destination path, a count and key names. Both paths came from main's dialogs
 * and are re-validated there, so this component cannot aim the write anywhere.
 */
function OpenSealedModal({
  open,
  identities,
  readOnly,
  onClose
}: {
  open: boolean;
  identities: IdentityEntry[];
  readOnly: boolean;
  onClose: () => void;
}): React.JSX.Element | null {
  const toast = useToast();

  const [blob, setBlob] = useState<string | null>(null);
  const [identity, setIdentity] = useState("");
  const [outputPath, setOutputPath] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<OpenSealedResult | null>(null);

  useEffect(() => {
    if (!open) return;
    setBlob(null);
    setIdentity("");
    setOutputPath(null);
    setErr(null);
    setResult(null);
  }, [open]);

  const chooseBlob = async (): Promise<void> => {
    setErr(null);
    try {
      const picked = await unwrap(window.tvault.pickEnvFile("Choose a sealed .env.encrypted"));
      if (picked !== null) setBlob(picked);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const chooseOutput = async (): Promise<void> => {
    setErr(null);
    try {
      const picked = await unwrap(window.tvault.pickSaveFile("Save the decrypted dotenv", ".env"));
      if (picked !== null) setOutputPath(picked);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const run = async (): Promise<void> => {
    if (blob === null || outputPath === null) {
      setErr("Choose the sealed file and where to write the decrypted dotenv.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const opened = await unwrap(
        window.tvault.openSealed({
          path: blob,
          identity: identity === "" ? undefined : identity,
          outputPath
        })
      );
      setResult(opened);
      toast.success(
        `Wrote ${opened.count} key${opened.count === 1 ? "" : "s"} in plaintext`,
        opened.path
      );
      // No onChanged(): the vault was only read.
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      setErr(message);
      toast.error("Could not open that sealed file", message);
    } finally {
      setBusy(false);
    }
  };

  if (!open) return null;

  const canRun = !readOnly && !busy && blob !== null && outputPath !== null;

  return (
    <Modal
      open
      title="Open a sealed blob"
      subtitle={blob?.split("/").pop()}
      onClose={onClose}
      width="max-w-lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Close
          </Button>
          <Button variant="primary" icon="save" disabled={!canRun} onClick={() => void run()}>
            {busy ? "Decrypting…" : "Decrypt to file"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <p className="flex items-start gap-2.5 rounded-tv-sm border border-warn/30 bg-warn/8 px-3.5 py-2.5 text-[12px] leading-relaxed text-warn">
          <span className="mt-0.5 shrink-0">
            <Icon name="alert" size={13} />
          </span>
          <span>
            This writes <span className="font-medium">plaintext</span> to disk, mode 0600. The
            decrypted values never reach this window — the tool returns the destination path, a
            key count and the key names, and nothing else. Delete the file when you are done.
          </span>
        </p>

        <Group label="Sealed file">
          <PathRow
            path={blob}
            placeholder="No file chosen"
            pickLabel={blob ? "Change…" : "Choose…"}
            busy={busy}
            onPick={() => void chooseBlob()}
          />
        </Group>

        <Field
          label="Identity"
          hint="Left empty, the server uses $TVAULT_IDENTITY, else the identity named default. Only identities on this machine are listed here."
        >
          <select
            value={identity}
            onChange={(e) => setIdentity(e.target.value)}
            className={selectClass}
          >
            <option value="">Server default</option>
            {identities.map((id) => (
              <option key={id.name} value={id.name}>
                {id.name}
              </option>
            ))}
          </select>
        </Field>

        <Group label="Write decrypted values to">
          <PathRow
            path={outputPath}
            placeholder="No destination chosen"
            pickLabel={outputPath ? "Change…" : "Choose…"}
            busy={busy}
            onPick={() => void chooseOutput()}
          />
        </Group>

        {result ? (
          <div className="space-y-2.5 rounded-tv-sm border border-line bg-soft/60 px-3.5 py-3">
            <p className="flex items-center gap-2 text-[12.5px] font-medium text-ink">
              <span className="text-success">
                <Icon name="check" size={13} />
              </span>
              Wrote {result.count} key{result.count === 1 ? "" : "s"} — plaintext, on disk
            </p>
            <p className="mono break-all text-[11.5px] leading-relaxed text-muted">{result.path}</p>
            <KeyChips keys={result.keys} />
            <p className="flex items-start gap-2 rounded-tv-sm border border-line bg-raised px-3 py-2.5 text-[11.5px] leading-relaxed text-faint">
              <span className="mt-0.5 shrink-0 text-warn">
                <Icon name="alert" size={12} />
              </span>
              Being able to open this does not mean the sender still wants you to. Revoking a
              recipient re-keys their live vault, not a blob already written — these values stay
              readable until whoever sealed it rotates the credentials themselves.
            </p>
          </div>
        ) : null}

        {readOnly ? (
          <p className="rounded-tv-sm border border-warn/30 bg-warn/8 px-3 py-2 text-[12px] text-warn">
            The active policy is read-only, and an agent-backed session has no identity to open
            with — the server refuses this.
          </p>
        ) : null}

        {err ? (
          <p className="mono rounded-tv-sm border border-danger/30 bg-danger/8 px-3 py-2 text-[11.5px] text-danger">
            {err}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}
