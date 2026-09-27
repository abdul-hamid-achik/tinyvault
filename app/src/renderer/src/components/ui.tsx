import {
  Component,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode
} from "react";

// --- error boundary ------------------------------------------------------

/**
 * Without this, any throw during render unmounts the whole tree and the user is
 * left with a blank window and no way to recover. A malformed audit timestamp is
 * enough to trigger it.
 */
export class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  override state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error): { error: Error } {
    return { error };
  }

  override render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4 px-10 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-tv-md border border-danger/30 bg-danger/10 text-danger">
          <Icon name="alert" size={20} />
        </div>
        <div className="space-y-1.5">
          <p className="text-[15px] font-semibold text-ink">This view crashed</p>
          <p className="mx-auto max-w-md text-[12.5px] leading-relaxed text-muted">
            Nothing was written to the vault. Revealed values are dropped when the
            window reloads.
          </p>
        </div>
        <pre className="mono max-w-lg overflow-x-auto rounded-tv-sm border border-line bg-soft px-3 py-2 text-left text-[11.5px] leading-relaxed text-muted">
          {error.message}
        </pre>
        <Button variant="primary" icon="refresh" onClick={() => window.location.reload()}>
          Reload window
        </Button>
      </div>
    );
  }
}

// --- icons ---------------------------------------------------------------

const PATHS = {
  key: "M15.5 8.5a3.5 3.5 0 1 1-3.2-3.49L4 13.3V17h3.7l1.3-1.3v-1.6h1.6L12 12.7v-1.5l3.5.01A3.5 3.5 0 0 1 15.5 8.5Z",
  eye: "M12 5c-5 0-8.5 5.2-9.3 6.5a1 1 0 0 0 0 1C3.5 13.8 7 19 12 19s8.5-5.2 9.3-6.5a1 1 0 0 0 0-1C20.5 10.2 17 5 12 5Zm0 11a4 4 0 1 1 0-8 4 4 0 0 1 0 8Z",
  eyeOff:
    "M3.3 2.3 2.3 3.3l3 3C3.5 7.7 2.4 9.5 2.1 10.5a1 1 0 0 0 0 1C2.9 12.8 6.4 18 11.4 18c1.6 0 3-.5 4.2-1.2l3.1 3.1 1-1L3.3 2.3Zm8.7 12.7c-3.4 0-6-3.7-6.7-5 .5-.9 1.5-2.3 2.9-3.3l1.9 1.9a3 3 0 0 0 3.8 3.8l1.5 1.5c-.9.6-2 1.1-3.4 1.1Z",
  copy: "M9 3h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm-4 4v12a2 2 0 0 0 2 2h9v-2H7a2 2 0 0 1-2-2V7H5Z",
  check: "M20 6.5 9.4 17.1 4 11.7l1.4-1.4 4 4L18.6 5 20 6.5Z",
  plus: "M11 5h2v6h6v2h-6v6h-2v-6H5v-2h6V5Z",
  trash:
    "M9 3h6l1 2h4v2H4V5h4l1-2ZM6 8h12l-1 12a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L6 8Zm4 3v8h1.5v-8H10Zm3 0v8h1.5v-8H13Z",
  pencil: "M4 20h4L20 8l-4-4L4 16v4Zm10.5-13.5 3 3L7 20H5v-2l9.5-9.5Z",
  history:
    "M12 4a8 8 0 1 1-7.7 10.1l1.9-.6A6 6 0 1 0 12 6v3L7.5 5.5 12 2v2Zm-1 4h2v4.4l3.2 1.9-1 1.7L11 16.5V8Z",
  search: "M10 4a6 6 0 1 1-3.9 10.6l-3.4 3.4-1.4-1.4 3.4-3.4A6 6 0 0 1 10 4Zm0 2a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z",
  refresh:
    "M12 5V2L8 6l4 4V7a5 5 0 1 1-5 5H5a7 7 0 1 0 7-7Zm7 7a7 7 0 0 1-1.4 4.2l1.6 1.2A9 9 0 0 0 21 12h-2Z",
  shield:
    "M12 2 4 5.5V11c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5.5L12 2Zm0 2.2 6 2.6V11c0 4-2.6 7.5-6 8.9-3.4-1.4-6-4.9-6-8.9V6.8l6-2.6Z",
  folder: "M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z",
  layers:
    "m12 2 9 5-9 5-9-5 9-5Zm0 2.3L6.6 7 12 9.7 17.4 7 12 4.3ZM3.5 10.4 12 15l8.5-4.6 1.5.8-10 5.5-10-5.5 1.5-.8Z",
  alert:
    "M12 2 1 21h22L12 2Zm0 4.5L18.5 19h-13L12 6.5ZM11 10v5h2v-5h-2Zm0 6v2h2v-2h-2Z",
  x: "M6.4 5 5 6.4 10.6 12 5 17.6 6.4 19 12 13.4 17.6 19 19 17.6 13.4 12 19 6.4 17.6 5 12 10.6 6.4 5Z",
  terminal:
    "M3 4h18a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Zm1 2v12h16V6H4Zm3 2.7 3 3.3-3 3.3-1.2-1.2 2-2.1-2-2.1L7 8.7ZM12 14h5v1.6h-5V14Z",
  chevron: "m12 8 6 6-1.4 1.4L12 10.8l-4.6 4.6L6 14l6-6Z",
  arrowRight: "M13 5l7 7-7 7-1.4-1.4 4.6-4.6H4v-2h12.2L11.6 6.4 13 5Z",
  sun: "M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10Zm-1-5h2v3h-2V2Zm0 17h2v3h-2v-3ZM2 11h3v2H2v-2Zm17 0h3v2h-3v-2ZM4.9 3.5l1.4 1.4-1.4 1.4L3.5 4.9l1.4-1.4Zm12.7 12.7 1.4 1.4-1.4 1.4-1.4-1.4 1.4-1.4ZM19.1 3.5l1.4 1.4-1.4 1.4-1.4-1.4 1.4-1.4ZM6.3 16.2l1.4 1.4-1.4 1.4-1.4-1.4 1.4-1.4Z",
  moon: "M12.5 3a8.5 8.5 0 1 0 8.4 10 7 7 0 0 1-8.4-10Z",
  lock: "M12 2a5 5 0 0 1 5 5v3h2v11H5V10h2V7a5 5 0 0 1 5-5Zm0 2a3 3 0 0 0-3 3v3h6V7a3 3 0 0 0-3-3Zm0 9a1.8 1.8 0 0 0-.8 3.4V19h1.6v-2.2A1.8 1.8 0 0 0 12 13Z",
  save: "M5 3h11l3 3v15H5V3Zm2 2v4h8V5H7Zm0 8v6h10v-6H7Zm2 2h6v2H9v-2Z",
  diff: "M8 3v14H4v2h4v2h2v-2h4v-2h-4V5H8Zm6 0v2h4v12h2V5h-4V3h-2Z",
  branch:
    "M7 3a2.5 2.5 0 0 1 1 4.8V10a4 4 0 0 0 4 4h3.2a2.5 2.5 0 1 1 0 2H12a6 6 0 0 1-6-6V7.8A2.5 2.5 0 0 1 7 3Zm10 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2ZM7 5a1 1 0 1 0 0 2 1 1 0 0 0 0-2Z"
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({
  name,
  size = 15,
  className = ""
}: {
  name: IconName;
  size?: number;
  className?: string;
}): React.JSX.Element {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      className={className}
      style={{ flexShrink: 0 }}
    >
      <path d={PATHS[name]} />
    </svg>
  );
}

// --- buttons -------------------------------------------------------------

type Variant = "primary" | "default" | "ghost" | "danger";

const VARIANTS: Record<Variant, string> = {
  primary:
    "bg-accent text-white hover:bg-accent-strong border border-transparent dark:text-[#18130f]",
  default: "bg-raised text-ink border border-line hover:border-line-strong hover:bg-soft",
  ghost: "bg-transparent text-muted border border-transparent hover:text-ink hover:bg-soft",
  danger: "bg-transparent text-danger border border-line hover:bg-danger/10 hover:border-danger/40"
};

export function Button({
  variant = "default",
  size = "md",
  icon,
  children,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: "sm" | "md";
  icon?: IconName;
}): React.JSX.Element {
  const pad = size === "sm" ? "h-7 px-2.5 text-[12px] gap-1.5" : "h-9 px-3.5 text-[13px] gap-2";
  return (
    <button
      {...rest}
      className={`inline-flex items-center justify-center rounded-tv-sm font-medium transition-colors
        duration-100 disabled:opacity-40 disabled:pointer-events-none whitespace-nowrap ${pad}
        ${VARIANTS[variant]} ${className}`}
    >
      {icon ? <Icon name={icon} size={size === "sm" ? 13 : 15} /> : null}
      {children}
    </button>
  );
}

export function IconButton({
  icon,
  label,
  className = "",
  tone = "muted",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  icon: IconName;
  label: string;
  tone?: "muted" | "danger" | "accent";
}): React.JSX.Element {
  const tones = {
    muted: "text-faint hover:text-ink hover:bg-soft",
    danger: "text-faint hover:text-danger hover:bg-danger/10",
    accent: "text-faint hover:text-accent hover:bg-accent-soft"
  };
  return (
    <button
      {...rest}
      title={label}
      aria-label={label}
      className={`inline-flex h-7 w-7 items-center justify-center rounded-md transition-colors
        duration-100 disabled:opacity-30 disabled:pointer-events-none ${tones[tone]} ${className}`}
    >
      <Icon name={icon} size={14} />
    </button>
  );
}

// --- layout bits ---------------------------------------------------------

export function Badge({
  children,
  tone = "neutral",
  className = ""
}: {
  children: ReactNode;
  tone?: "neutral" | "accent" | "success" | "warn" | "danger";
  className?: string;
}): React.JSX.Element {
  const tones = {
    neutral: "bg-soft text-muted border-line",
    accent: "bg-accent-soft text-accent border-accent-line",
    success: "bg-success/12 text-success border-success/30",
    warn: "bg-warn/12 text-warn border-warn/30",
    danger: "bg-danger/12 text-danger border-danger/30"
  };
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px]
        font-medium leading-4 ${tones[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

export function Field({
  label,
  hint,
  children
}: {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
}): React.JSX.Element {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.07em] text-faint">
        {label}
      </span>
      {children}
      {hint ? <span className="mt-1.5 block text-[12px] leading-relaxed text-faint">{hint}</span> : null}
    </label>
  );
}

const inputBase =
  "w-full rounded-tv-sm border border-line bg-raised px-3 text-[13px] text-ink placeholder:text-faint " +
  "transition-colors duration-100 focus:border-accent focus:outline-none";

export function TextInput({
  className = "",
  mono = false,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }): React.JSX.Element {
  return <input {...rest} className={`${inputBase} h-9 ${mono ? "mono" : ""} ${className}`} />;
}

export function TextArea({
  className = "",
  ...rest
}: React.TextareaHTMLAttributes<HTMLTextAreaElement>): React.JSX.Element {
  return (
    <textarea
      {...rest}
      className={`${inputBase} mono resize-y py-2 leading-relaxed ${className}`}
      spellCheck={false}
      autoComplete="off"
    />
  );
}

export function Spinner({ size = 15 }: { size?: number }): React.JSX.Element {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className="animate-spin" aria-hidden="true">
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="2.5" opacity="0.2" />
      <path
        d="M21 12a9 9 0 0 0-9-9"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function EmptyState({
  icon = "key",
  title,
  body,
  action
}: {
  icon?: IconName;
  title: string;
  body?: string;
  action?: ReactNode;
}): React.JSX.Element {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 px-8 py-20 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-tv-md border border-line bg-soft text-faint">
        <Icon name={icon} size={20} />
      </div>
      <div className="space-y-1">
        <p className="text-[14px] font-medium text-ink">{title}</p>
        {body ? <p className="mx-auto max-w-sm text-[12.5px] leading-relaxed text-muted">{body}</p> : null}
      </div>
      {action}
    </div>
  );
}

// --- modal ---------------------------------------------------------------

export function Modal({
  open,
  title,
  subtitle,
  onClose,
  children,
  footer,
  width = "max-w-lg"
}: {
  open: boolean;
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}): React.JSX.Element | null {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    // Focus the first field so the modal is keyboard-usable immediately.
    const first = ref.current?.querySelector<HTMLElement>(
      "input:not([type=hidden]), textarea, select, button"
    );
    first?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/45 p-6 backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      role="presentation"
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`animate-in w-full ${width} overflow-hidden rounded-tv-md border border-line bg-raised`}
        style={{ boxShadow: "var(--tv-shadow-lg)" }}
      >
        <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
          <div className="min-w-0">
            <h2 className="truncate text-[14.5px] font-semibold text-ink">{title}</h2>
            {subtitle ? (
              <p className="mono mt-0.5 truncate text-[12px] text-muted">{subtitle}</p>
            ) : null}
          </div>
          <IconButton icon="x" label="Close" onClick={onClose} />
        </header>
        <div className="max-h-[65vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer ? (
          <footer className="flex items-center justify-end gap-2 border-t border-line bg-soft/60 px-5 py-3.5">
            {footer}
          </footer>
        ) : null}
      </div>
    </div>
  );
}

// --- toasts --------------------------------------------------------------

export type ToastTone = "success" | "error" | "info" | "warn";

interface Toast {
  id: number;
  tone: ToastTone;
  title: string;
  body?: string;
}

interface ToastApi {
  push: (tone: ToastTone, title: string, body?: string) => void;
  success: (title: string, body?: string) => void;
  error: (title: string, body?: string) => void;
  info: (title: string, body?: string) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside <ToastProvider>");
  return ctx;
}

export function ToastProvider({ children }: { children: ReactNode }): React.JSX.Element {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (tone: ToastTone, title: string, body?: string) => {
      const id = nextId.current++;
      setToasts((prev) => [...prev.slice(-4), { id, tone, title, body }]);
      setTimeout(() => dismiss(id), tone === "error" ? 9000 : 4200);
    },
    [dismiss]
  );

  const api = useMemo<ToastApi>(
    () => ({
      push,
      success: (t, b) => push("success", t, b),
      error: (t, b) => push("error", t, b),
      info: (t, b) => push("info", t, b)
    }),
    [push]
  );

  const tones: Record<ToastTone, { border: string; icon: IconName; color: string }> = {
    success: { border: "border-success/35", icon: "check", color: "text-success" },
    error: { border: "border-danger/40", icon: "alert", color: "text-danger" },
    warn: { border: "border-warn/40", icon: "alert", color: "text-warn" },
    info: { border: "border-line-strong", icon: "shield", color: "text-accent" }
  };

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed bottom-5 right-5 z-[60] flex w-[340px] flex-col gap-2">
        {toasts.map((t) => {
          const tone = tones[t.tone];
          return (
            <div
              key={t.id}
              className={`animate-toast pointer-events-auto flex items-start gap-2.5 rounded-tv-sm border
                ${tone.border} bg-raised px-3.5 py-3`}
              style={{ boxShadow: "var(--tv-shadow-sm)" }}
              role="status"
            >
              <span className={`mt-0.5 ${tone.color}`}>
                <Icon name={tone.icon} size={14} />
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-[12.5px] font-medium leading-snug text-ink">{t.title}</p>
                {t.body ? (
                  <p className="mono mt-1 break-words text-[11.5px] leading-relaxed text-muted">
                    {t.body}
                  </p>
                ) : null}
              </div>
              <IconButton icon="x" label="Dismiss" onClick={() => dismiss(t.id)} className="-mr-1 -mt-1" />
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
