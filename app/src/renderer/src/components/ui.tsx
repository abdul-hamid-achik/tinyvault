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
import { createPortal } from "react-dom";
import {
  ArrowRight,
  Check,
  ChevronDown,
  Copy,
  Ellipsis,
  Eye,
  EyeOff,
  Folder,
  GitBranch,
  GitCompareArrows,
  History,
  KeyRound,
  Layers,
  Lock,
  Moon,
  Pencil,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  Shield,
  Sun,
  Terminal,
  Trash2,
  TriangleAlert,
  X,
  type LucideIcon
} from "lucide-react";

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

/**
 * lucide-react: stroke-based marks on a consistent 24px grid. The hand-rolled
 * fill paths they replace read thin and uneven next to these. Keeping the name
 * map means the ~40 call sites do not change.
 */
const ICONS = {
  key: KeyRound,
  eye: Eye,
  eyeOff: EyeOff,
  copy: Copy,
  check: Check,
  plus: Plus,
  trash: Trash2,
  pencil: Pencil,
  history: History,
  search: Search,
  refresh: RefreshCw,
  shield: Shield,
  folder: Folder,
  layers: Layers,
  alert: TriangleAlert,
  x: X,
  terminal: Terminal,
  chevron: ChevronDown,
  arrowRight: ArrowRight,
  sun: Sun,
  moon: Moon,
  lock: Lock,
  save: Save,
  diff: GitCompareArrows,
  branch: GitBranch,
  // Horizontal ellipsis is the conventional "more actions" affordance; a lone
  // chevron-down reads as "collapse", and this app already uses chevrons for
  // collapsing the filter row and expanding audit metadata.
  more: Ellipsis,
  // Counter-clockwise rotate means undo/restore; RefreshCw means reload.
  rollback: RotateCcw
} as const satisfies Record<string, LucideIcon>;

export type IconName = keyof typeof ICONS;

/**
 * Hover micro-animations, applied only inside a `group/icon` parent (i.e. an
 * IconButton). Rotational ones suit icons whose meaning is motion; the rest get
 * a small scale so every action acknowledges the pointer the same way.
 */
const ICON_HOVER: Partial<Record<IconName, string>> = {
  refresh: "group-hover/icon:rotate-180",
  rollback: "group-hover/icon:-rotate-90",
  history: "group-hover/icon:-rotate-45",
  branch: "group-hover/icon:-rotate-12",
  pencil: "group-hover/icon:-rotate-12",
  arrowRight: "group-hover/icon:translate-x-0.5",
  chevron: ""
};

export function Icon({
  name,
  size = 15,
  className = "",
  animated = false
}: {
  name: IconName;
  size?: number;
  className?: string;
  /** Opt into the hover micro-animation; needs a `group/icon` ancestor. */
  animated?: boolean;
}): React.JSX.Element {
  const Cmp = ICONS[name];
  const hover = animated ? (ICON_HOVER[name] ?? "group-hover/icon:scale-110") : "";
  return (
    <Cmp
      size={size}
      strokeWidth={2}
      aria-hidden="true"
      className={`shrink-0 transition-transform duration-200 ease-out ${hover} ${className}`}
    />
  );
}

// --- tooltip -------------------------------------------------------------

export type TooltipSide = "top" | "bottom" | "left" | "right";

const TOOLTIP_DELAY_MS = 350;

function place(rect: DOMRect, side: TooltipSide): { x: number; y: number; transform: string } {
  switch (side) {
    case "bottom":
      return { x: rect.left + rect.width / 2, y: rect.bottom + 8, transform: "translate(-50%, 0)" };
    case "left":
      return { x: rect.left - 8, y: rect.top + rect.height / 2, transform: "translate(-100%, -50%)" };
    case "right":
      return { x: rect.right + 8, y: rect.top + rect.height / 2, transform: "translate(0, -50%)" };
    case "top":
    default:
      return { x: rect.left + rect.width / 2, y: rect.top - 8, transform: "translate(-50%, -100%)" };
  }
}

/**
 * Portal-rendered so scroll containers (the secrets table, the sidebar list)
 * cannot clip it. Native `title` tooltips wait ~1s, cannot be styled and do not
 * animate, which left the icon-only actions effectively unlabelled.
 */
export function Tooltip({
  label,
  side = "top",
  children
}: {
  label: string;
  side?: TooltipSide;
  children: ReactNode;
}): React.JSX.Element {
  const anchor = useRef<HTMLSpanElement>(null);
  const timer = useRef<number | null>(null);
  const [pos, setPos] = useState<{ x: number; y: number; transform: string } | null>(null);

  const hide = useCallback(() => {
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = null;
    setPos(null);
  }, []);

  const show = useCallback(() => {
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      const rect = anchor.current?.getBoundingClientRect();
      if (!rect) return;
      const p = place(rect, side);
      // Keep top/bottom tooltips on screen near the window edges.
      if (side === "top" || side === "bottom") {
        p.x = Math.min(Math.max(p.x, 80), window.innerWidth - 80);
      }
      setPos(p);
    }, TOOLTIP_DELAY_MS);
  }, [side]);

  // A tooltip anchored to a target that moved is worse than none.
  useEffect(() => {
    if (!pos) return;
    window.addEventListener("scroll", hide, true);
    window.addEventListener("resize", hide);
    return () => {
      window.removeEventListener("scroll", hide, true);
      window.removeEventListener("resize", hide);
    };
  }, [pos, hide]);

  useEffect(() => hide, [hide]);

  return (
    <>
      <span
        ref={anchor}
        style={{ display: "inline-flex" }}
        onMouseEnter={show}
        onMouseLeave={hide}
        onPointerDown={hide}
        onBlur={hide}
      >
        {children}
      </span>
      {pos
        ? createPortal(
            <div
              role="tooltip"
              className="tv-tooltip"
              style={{ left: pos.x, top: pos.y, transform: pos.transform }}
            >
              {label}
            </div>,
            document.body
          )
        : null}
    </>
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
      className={`group/icon inline-flex items-center justify-center rounded-tv-sm font-medium
        transition-all duration-150 ease-out hover:-translate-y-px
        hover:shadow-[var(--tv-shadow-icon)] active:translate-y-0 active:scale-[0.97]
        active:shadow-none disabled:pointer-events-none disabled:opacity-40
        disabled:hover:translate-y-0 disabled:hover:shadow-none whitespace-nowrap ${pad}
        ${VARIANTS[variant]} ${className}`}
    >
      {icon ? <Icon name={icon} size={size === "sm" ? 13 : 15} animated /> : null}
      {children}
    </button>
  );
}

export function IconButton({
  icon,
  label,
  className = "",
  tone = "muted",
  tooltipSide = "top",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  icon: IconName;
  label: string;
  tone?: "muted" | "danger" | "accent";
  tooltipSide?: TooltipSide;
}): React.JSX.Element {
  const tones = {
    muted: "text-faint hover:text-ink hover:bg-raised hover:border-line",
    danger: "text-faint hover:text-danger hover:bg-danger/10 hover:border-danger/30",
    accent: "text-faint hover:text-accent hover:bg-accent-soft hover:border-accent-line"
  };
  return (
    <Tooltip label={label} side={tooltipSide}>
      <button
        {...rest}
        aria-label={label}
        className={`group/icon inline-flex h-7 w-7 items-center justify-center rounded-md
          border border-transparent transition-all duration-150 ease-out
          hover:-translate-y-px hover:shadow-[var(--tv-shadow-icon)]
          active:translate-y-0 active:scale-90 active:shadow-none
          disabled:pointer-events-none disabled:opacity-30 disabled:hover:translate-y-0
          disabled:hover:shadow-none
          ${tones[tone]} ${className}`}
      >
        <Icon name={icon} size={14} animated />
      </button>
    </Tooltip>
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
