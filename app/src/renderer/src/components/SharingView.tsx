import { useCallback, useEffect, useMemo, useState } from "react";

import type { IdentityEntry } from "@shared/types";

import { unwrap } from "../lib/api";
import {
  Badge,
  Button,
  EmptyState,
  Icon,
  IconButton,
  Modal,
  Spinner,
  TextInput,
  Tooltip,
  useToast
} from "./ui";

/**
 * Sharing is the recipient layer: X25519 public halves (tvault1…) wrapping a
 * project's data key, so granting read access never involves sharing a
 * passphrase.
 *
 * Everything on this screen is public material. The private key (tvault-key1…)
 * is never returned by any MCP tool and `tvault identity export` stays a
 * CLI-only, TTY-guarded operation — so this view cannot leak one, by
 * construction rather than by care.
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
        <h1 className="text-[17px] font-semibold tracking-[-0.01em] text-ink">Sharing</h1>
        <p className="mt-1 max-w-2xl text-[12.5px] leading-relaxed text-muted">
          Recipient-based access: a project's data key is wrapped to an X25519 public key, so
          granting read access never means sharing a passphrase. Everything here is public
          material — private keys never reach this window.
        </p>
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
    </div>
  );
}
