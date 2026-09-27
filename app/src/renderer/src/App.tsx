import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { Bootstrap, ProjectOverview, SecretMeta, SecretVersionMeta } from "@shared/types";

import AuditView from "./components/AuditView";
import EnvGroupsView from "./components/EnvGroupsView";
import SecretsView, { type SecretActions } from "./components/SecretsView";
import SetupScreen from "./components/SetupScreen";
import Sidebar, { type View } from "./components/Sidebar";
import { Button, ErrorBoundary, Field, Modal, TextInput, ToastProvider, useToast } from "./components/ui";
import { applyTheme, debug, initialTheme, unwrap, type Theme } from "./lib/api";

export default function App(): React.JSX.Element {
  const [theme, setTheme] = useState<Theme>(initialTheme);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  return (
    <ToastProvider>
      <Shell theme={theme} onToggleTheme={() => setTheme((t) => (t === "dark" ? "light" : "dark"))} />
    </ToastProvider>
  );
}

function Shell({
  theme,
  onToggleTheme
}: {
  theme: Theme;
  onToggleTheme: () => void;
}): React.JSX.Element {
  const toast = useToast();

  const [boot, setBoot] = useState<Bootstrap | null>(null);
  const [bootLoading, setBootLoading] = useState(true);
  const [view, setView] = useState<View>("secrets");
  const [projects, setProjects] = useState<ProjectOverview[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [secretsLoading, setSecretsLoading] = useState(false);
  const [secretsError, setSecretsError] = useState<string | null>(null);
  const [newProject, setNewProject] = useState(false);

  const session = boot?.session ?? null;
  const connected = Boolean(session?.connected) && boot?.status !== null;
  // A missing policy file means the server loaded SafeDefaultPolicy: read-only
  // with secrets_deny ["*"], so nothing is visible and nothing can be written.
  const policyMissing = connected && !boot?.policy.exists;
  // Writes are refused by a read-only policy, by a missing policy, and by the
  // agent-backed path where the child has no passphrase (denyAgentWrite).
  // A zero read cap (reveals denied) does not block writes, so it is handled at
  // bootstrap by routing to the Connection screen rather than here.
  const readOnly =
    !connected ||
    policyMissing ||
    boot?.policy.access_mode === "read-only" ||
    session?.backend === "agent";

  const syncSession = useCallback(async (): Promise<void> => {
    try {
      const info = await unwrap(window.tvault.sessionInfo());
      setBoot((prev) => (prev ? { ...prev, session: info } : prev));
    } catch {
      // The budget badge is advisory; a stale count is not worth an error toast.
    }
  }, []);

  // Same hazard as the reveal generation guard: switching projects quickly lets
  // the slower listSecrets resolve last and paint the old project's keys under
  // the new one.
  const secretsGen = useRef(0);

  const loadSecrets = useCallback(async (project: string): Promise<void> => {
    const gen = ++secretsGen.current;
    setSecretsLoading(true);
    setSecretsError(null);
    try {
      const list = await unwrap(window.tvault.listSecrets(project));
      if (gen !== secretsGen.current) return;
      setSecrets(list);
      debug("secrets loaded", { project, count: list.length });
    } catch (err) {
      if (gen !== secretsGen.current) return;
      setSecrets([]);
      const message = err instanceof Error ? err.message : String(err);
      setSecretsError(message);
      debug("secrets FAILED", { project, error: message });
    } finally {
      if (gen === secretsGen.current) setSecretsLoading(false);
    }
  }, []);

  const loadProjects = useCallback(
    async (preferred?: string | null): Promise<void> => {
      try {
        const list = await unwrap(window.tvault.projectsOverview());
        setProjects(list);
        setSelected((prev) => {
          const wanted = preferred ?? prev;
          if (wanted && list.some((p) => p.name === wanted)) return wanted;
          return list[0]?.name ?? null;
        });
      } catch (err) {
        toast.error("Could not list projects", err instanceof Error ? err.message : String(err));
      }
    },
    [toast]
  );

  const loadBootstrap = useCallback(async (): Promise<void> => {
    setBootLoading(true);
    try {
      const result = await unwrap(window.tvault.bootstrap());
      setBoot(result);
      debug("bootstrap", {
        binary: result.binary ? `${result.binary.path} v${result.binary.version}` : result.binary_error,
        vault_dir: result.vault_dir,
        unlocked: result.status?.is_unlocked,
        projects: result.status?.project_count,
        policy_mode: result.policy.access_mode,
        policy_exists: result.policy.exists,
        reads_limit: result.policy.max_reads_per_session,
        agent_running: result.agent.running,
        session_connected: result.session.connected,
        backend: result.session.backend,
        tools: result.session.tool_count,
        current_project: result.current_project,
        session_error: result.session.last_error
      });
      if (result.session.connected && result.status) {
        await loadProjects(result.current_project);
        // Land on the Connection screen when the vault is reachable but the app
        // cannot do anything useful: a missing policy denies every key, and a
        // zero read cap denies every reveal. Both are explained there.
        if (!result.policy.exists) {
          debug("policy file missing — routing to Connection screen");
          setView("setup");
        } else if (result.session.reveals_denied) {
          debug("max_reads_per_session is 0 — routing to Connection screen");
          setView("setup");
        } else if (result.session.backend === "agent") {
          toast.info(
            "Connected through the local agent",
            "Reads work without a passphrase, but the agent is read-only — writes are disabled."
          );
        }
      } else {
        debug("bootstrap: NOT connected, showing setup screen");
        setView("setup");
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      debug("bootstrap THREW", message);
      toast.error("Startup failed", message);
      setView("setup");
    } finally {
      setBootLoading(false);
    }
  }, [loadProjects, toast]);

  // Guarded so a change in any callback identity can never turn startup into a
  // reload loop against the vault; retries go through the explicit button.
  const bootstrapped = useRef(false);
  useEffect(() => {
    if (bootstrapped.current) return;
    bootstrapped.current = true;
    void loadBootstrap();
  }, [loadBootstrap]);

  useEffect(() => {
    if (!selected || view !== "secrets") return;
    void loadSecrets(selected);
  }, [selected, view, loadSecrets]);

  const refresh = useCallback(async (): Promise<void> => {
    await Promise.all([loadProjects(selected), syncSession()]);
    if (selected) await loadSecrets(selected);
  }, [loadProjects, loadSecrets, selected, syncSession]);

  const restartSession = useCallback(async (): Promise<void> => {
    try {
      const info = await unwrap(window.tvault.restartSession());
      setBoot((prev) => (prev ? { ...prev, session: info } : prev));
      toast.success("Session restarted", "Reveal budget reset.");
      if (selected) await loadSecrets(selected);
    } catch (err) {
      toast.error("Restart failed", err instanceof Error ? err.message : String(err));
    }
  }, [loadSecrets, selected, toast]);

  /**
   * Retry must respawn, not just re-read. `ensureConnected()` returns the
   * existing client immediately, so after a child crash a plain re-bootstrap
   * would fail the same way forever.
   */
  const retryConnection = useCallback(async (): Promise<void> => {
    try {
      await unwrap(window.tvault.restartSession());
    } catch {
      // loadBootstrap below surfaces whatever is actually wrong.
    }
    await loadBootstrap();
  }, [loadBootstrap]);

  const actions = useMemo<SecretActions>(() => {
    const requireProject = (): string => {
      if (!selected) throw new Error("no project selected");
      return selected;
    };
    const budgetAware = async <T,>(fn: () => Promise<T>): Promise<T> => {
      try {
        return await fn();
      } finally {
        void syncSession();
      }
    };

    return {
      reveal: async (key) =>
        budgetAware(async () => (await unwrap(window.tvault.revealSecret(requireProject(), key))).value),
      save: async (key, value) => {
        await budgetAware(() => unwrap(window.tvault.setSecret(requireProject(), key, value)));
      },
      remove: async (key) => {
        await unwrap(window.tvault.deleteSecret(requireProject(), key));
      },
      generate: async (key, length, charset) => {
        await unwrap(window.tvault.generateSecret(requireProject(), key, length, charset));
      },
      history: async (key): Promise<SecretVersionMeta[]> =>
        unwrap(window.tvault.history(requireProject(), key)),
      rollback: async (key, version) => unwrap(window.tvault.rollback(requireProject(), key, version)),
      copy: async (value) => (await unwrap(window.tvault.copySecret(value))).clearsInMs,
      makeCurrent: async () => {
        const name = requireProject();
        await unwrap(window.tvault.setCurrentProject(name));
        setBoot((prev) => (prev ? { ...prev, current_project: name } : prev));
      },
      deleteProject: async () => {
        const name = requireProject();
        await unwrap(window.tvault.deleteProject(name));
        setSelected(null);
        await loadProjects(null);
      }
    };
  }, [loadProjects, selected, syncSession]);

  const project = useMemo(
    () => projects.find((p) => p.name === selected) ?? null,
    [projects, selected]
  );

  return (
    <div className="flex h-full overflow-hidden bg-paper">
      <Sidebar
        projects={projects}
        selected={selected}
        onSelect={(name) => {
          setSelected(name);
          setView("secrets");
        }}
        view={view}
        onView={setView}
        currentProject={boot?.current_project ?? null}
        onMakeCurrent={async (name) => {
          try {
            await unwrap(window.tvault.setCurrentProject(name));
            setBoot((prev) => (prev ? { ...prev, current_project: name } : prev));
            toast.success(`${name} is now the current project`);
          } catch (err) {
            toast.error("Could not switch project", err instanceof Error ? err.message : String(err));
          }
        }}
        onCreateProject={() => setNewProject(true)}
        boot={boot}
        theme={theme}
        onToggleTheme={onToggleTheme}
        onRestartSession={() => void restartSession()}
      />

      <main className="flex min-w-0 flex-1 flex-col">
        <ErrorBoundary>
          {!connected ? (
            <SetupScreen
              boot={boot}
              loading={bootLoading}
              onRetry={() => void retryConnection()}
            />
          ) : view === "secrets" ? (
            <SecretsView
              project={project}
              secrets={secrets}
              loading={secretsLoading}
              error={secretsError}
              readOnly={readOnly}
              actions={actions}
              onRefresh={() => void refresh()}
            />
          ) : view === "groups" ? (
            <EnvGroupsView readOnly={readOnly} onChanged={() => void refresh()} />
          ) : view === "audit" ? (
            <AuditView />
          ) : (
            <SetupScreen boot={boot} loading={false} onRetry={() => void retryConnection()} />
          )}
        </ErrorBoundary>
      </main>

      <NewProjectModal
        open={newProject}
        readOnly={readOnly}
        onClose={() => setNewProject(false)}
        onCreated={async (name) => {
          toast.success(`Created project ${name}`);
          await loadProjects(name);
          setSelected(name);
          setView("secrets");
        }}
      />
    </div>
  );
}

function NewProjectModal({
  open,
  readOnly,
  onClose,
  onCreated
}: {
  open: boolean;
  readOnly: boolean;
  onClose: () => void;
  onCreated: (name: string) => Promise<void>;
}): React.JSX.Element | null {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setName("");
    setDescription("");
    setErr(null);
  }, [open]);

  if (!open) return null;

  const submit = async (): Promise<void> => {
    const n = name.trim();
    if (!n) {
      setErr("Project name is required.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await unwrap(window.tvault.createProject(n, description.trim()));
      await onCreated(n);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open
      title="New project"
      onClose={onClose}
      width="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            icon="plus"
            disabled={busy || readOnly}
            onClick={() => void submit()}
          >
            {busy ? "Creating…" : "Create"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label="Name" hint="Lowercase, dash-separated. Becomes the namespace for its own DEK.">
          <TextInput
            mono
            value={name}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void submit();
            }}
            placeholder="myapp-preview"
          />
        </Field>
        <Field label="Description">
          <TextInput
            value={description}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setDescription(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void submit();
            }}
            placeholder="Preview environment — test credentials only."
          />
        </Field>
        <p className="flex items-start gap-2 rounded-tv-sm border border-line bg-soft/60 px-3 py-2.5 text-[12px] leading-relaxed text-muted">
          Each project gets an isolated encryption key, so compromising one does not expose the
          others. Descriptions are stored in plaintext, like all project metadata.
        </p>
        {readOnly ? (
          <p className="rounded-tv-sm border border-warn/30 bg-warn/8 px-3 py-2 text-[12px] text-warn">
            The active policy is read-only, so this will be refused by the server.
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
