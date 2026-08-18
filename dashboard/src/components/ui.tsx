// Shared UI primitives for the SOC dashboard. Small, composable, themeable.
import { useEffect, type ReactNode } from "react";
import { Icon, type IconName } from "./icons";
import { SEV_COLOR, type Severity } from "../lib/taxonomy";

// ---- Panels ----------------------------------------------------------------

export function Panel({
  title,
  subtitle,
  icon,
  action,
  className = "",
  bodyClass = "",
  children,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  icon?: IconName;
  action?: ReactNode;
  className?: string;
  bodyClass?: string;
  children: ReactNode;
}) {
  return (
    <section className={`card p-4 animate-fade-in ${className}`}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 mb-3">
          <div className="min-w-0">
            {title && (
              <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                {icon && <Icon name={icon} size={15} className="text-aegis-accent shrink-0" />}
                <span className="truncate">{title}</span>
              </h3>
            )}
            {subtitle && <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  );
}

// ---- KPI card --------------------------------------------------------------

export function KpiCard({
  label,
  value,
  icon,
  delta,
  tone = "accent",
  spark,
  sub,
}: {
  label: string;
  value: ReactNode;
  icon?: IconName;
  delta?: { dir: "up" | "down"; text: string; good?: boolean };
  tone?: "accent" | "danger" | "ok" | "warn";
  spark?: number[];
  sub?: string;
}) {
  const toneColor = {
    accent: "#4f8cff",
    danger: "#ff4d6d",
    ok: "#2dd4a7",
    warn: "#ffb454",
  }[tone];
  return (
    <div className="card p-4 relative overflow-hidden group animate-slide-up">
      <div
        className="absolute -right-6 -top-8 w-24 h-24 rounded-full blur-2xl opacity-20 transition-opacity group-hover:opacity-30"
        style={{ background: toneColor }}
      />
      <div className="flex items-center justify-between">
        <span className="kpi-label">{label}</span>
        {icon && (
          <span
            className="grid place-items-center w-8 h-8 rounded-lg"
            style={{ background: `${toneColor}1a`, color: toneColor }}
          >
            <Icon name={icon} size={16} />
          </span>
        )}
      </div>
      <div className="mt-2 flex items-end gap-2">
        <span className="text-3xl font-bold tnum tracking-tight text-slate-50">{value}</span>
        {delta && (
          <span
            className="mb-1 text-xs font-semibold inline-flex items-center gap-0.5"
            style={{ color: delta.good ? "#2dd4a7" : "#ff4d6d" }}
          >
            {delta.dir === "up" ? "▲" : "▼"} {delta.text}
          </span>
        )}
      </div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
      {spark && spark.length > 1 && (
        <div className="mt-2 -mx-1">
          <Sparkline data={spark} color={toneColor} height={26} />
        </div>
      )}
    </div>
  );
}

// ---- Badges ----------------------------------------------------------------

export function SeverityBadge({ sev, small }: { sev: Severity; small?: boolean }) {
  const c = SEV_COLOR[sev];
  return (
    <span
      className={`pill ${small ? "!text-[10px] !px-1.5" : ""}`}
      style={{ background: `${c}22`, color: c, boxShadow: `inset 0 0 0 1px ${c}44` }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: c }} />
      {sev.toUpperCase()}
    </span>
  );
}

export function VerdictPill({ verdict }: { verdict: string }) {
  const map: Record<string, [string, string]> = {
    block: ["#ff4d6d", "BLOCKED"],
    review: ["#ffb454", "REVIEW"],
    allow: ["#2dd4a7", "ALLOWED"],
  };
  const [c, label] = map[verdict] ?? ["#64748b", verdict.toUpperCase()];
  return (
    <span className="pill" style={{ background: `${c}22`, color: c, boxShadow: `inset 0 0 0 1px ${c}44` }}>
      {label}
    </span>
  );
}

// ---- Gauges & meters -------------------------------------------------------

export function GaugeRing({
  value,
  size = 120,
  stroke = 10,
  color = "#4f8cff",
  track = "rgba(255,255,255,0.08)",
  label,
  sub,
}: {
  value: number; // 0..1
  size?: number;
  stroke?: number;
  color?: string;
  track?: string;
  label?: ReactNode;
  sub?: ReactNode;
}) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(1, value));
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={track} strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - v)}
          style={{ transition: "stroke-dashoffset 600ms cubic-bezier(0.22,1,0.36,1)" }}
        />
      </svg>
      <div className="absolute text-center">
        {label && <div className="text-2xl font-bold tnum text-slate-50 leading-none">{label}</div>}
        {sub && <div className="text-[10px] uppercase tracking-wider text-slate-500 mt-1">{sub}</div>}
      </div>
    </div>
  );
}

export function Bar({ value, color = "#4f8cff", track = "rgba(255,255,255,0.06)" }: { value: number; color?: string; track?: string }) {
  return (
    <div className="h-2 rounded-full overflow-hidden" style={{ background: track }}>
      <div
        className="h-full rounded-full"
        style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%`, background: color, transition: "width 500ms cubic-bezier(0.22,1,0.36,1)" }}
      />
    </div>
  );
}

// ---- Sparkline -------------------------------------------------------------

export function Sparkline({
  data,
  color = "#4f8cff",
  height = 32,
  width = 120,
  fill = true,
}: {
  data: number[];
  color?: string;
  height?: number;
  width?: number;
  fill?: boolean;
}) {
  if (data.length < 2) return <div style={{ height }} />;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const span = max - min || 1;
  const pts = data.map((d, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((d - min) / span) * (height - 2) - 1;
    return [x, y] as const;
  });
  const line = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const area = `${line} L${width},${height} L0,${height} Z`;
  const gid = `sg-${color.replace(/[^a-z0-9]/gi, "")}`;
  return (
    <svg width="100%" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{ height }}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <path d={area} fill={`url(#${gid})`} />}
      <path d={line} fill="none" stroke={color} strokeWidth={1.6} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

// ---- States ----------------------------------------------------------------

export function EmptyState({ icon = "search", title, hint }: { icon?: IconName; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-10 px-4 text-slate-500">
      <div className="grid place-items-center w-12 h-12 rounded-xl bg-white/[0.04] mb-3">
        <Icon name={icon} size={22} />
      </div>
      <div className="text-sm font-medium text-slate-300">{title}</div>
      {hint && <div className="text-xs mt-1 max-w-xs">{hint}</div>}
    </div>
  );
}

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <span
      className="inline-block rounded-full border-2 border-white/20 border-t-aegis-accent animate-spin"
      style={{ width: size, height: size, animationDuration: "0.7s" }}
    />
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} />;
}

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 text-sm rounded-lg px-3 py-2 bg-sev-critical/10 text-sev-critical border border-sev-critical/20">
      <Icon name="alert" size={15} /> {message}
    </div>
  );
}

// ---- Modal -----------------------------------------------------------------

export function Modal({
  open,
  onClose,
  title,
  children,
  wide,
}: {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  children: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 grid place-items-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in" onClick={onClose}>
      <div
        className={`card p-5 w-full ${wide ? "max-w-3xl" : "max-w-lg"} max-h-[85vh] overflow-auto animate-slide-up`}
        onClick={(e) => e.stopPropagation()}
      >
        {title && (
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold text-slate-100">{title}</h3>
            <button className="btn-ghost !p-1.5" onClick={onClose} aria-label="Close">
              <Icon name="x" size={16} />
            </button>
          </div>
        )}
        {children}
      </div>
    </div>
  );
}

// ---- Segmented control -----------------------------------------------------

export function Segmented<T extends string>({
  options,
  value,
  onChange,
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="inline-flex p-0.5 rounded-lg bg-black/30 border border-white/[0.06] text-xs">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={`px-2.5 py-1 rounded-md font-medium transition-colors ${
            value === o.value ? "bg-aegis-accent text-white" : "text-slate-400 hover:text-slate-200"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function LiveDot({ on }: { on: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium">
      <span className={`relative flex w-2 h-2`}>
        {on && <span className="absolute inline-flex w-full h-full rounded-full bg-aegis-ok opacity-60 animate-ping" />}
        <span className={`relative inline-flex w-2 h-2 rounded-full ${on ? "bg-aegis-ok" : "bg-slate-600"}`} />
      </span>
      {on ? "LIVE" : "PAUSED"}
    </span>
  );
}
