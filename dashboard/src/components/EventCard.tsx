// Reusable security-event presentations shared across pages.
import { useEffect, useState, type MouseEvent as ReactMouseEvent } from "react";
import type { SecurityEvent } from "../lib/store";
import { SeverityBadge, VerdictPill } from "./ui";
import { Icon, type IconName } from "./icons";
import { FLAG, timeAgo } from "../lib/format";
import { confidencePct } from "../lib/taxonomy";
import { createIncident } from "../lib/incidents";
import { useToast } from "./Toaster";

/** Right-click context menu for a security event. */
function useEventMenu(e: SecurityEvent, onInspect?: () => void) {
  const toast = useToast();
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);

  useEffect(() => {
    if (!pos) return;
    const close = () => setPos(null);
    window.addEventListener("click", close);
    window.addEventListener("scroll", close, true);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("scroll", close, true);
    };
  }, [pos]);

  const items: { label: string; icon: IconName; run: () => void }[] = [
    ...(onInspect ? [{ label: "Investigate", icon: "search" as IconName, run: onInspect }] : []),
    {
      label: "Create incident",
      icon: "alert" as IconName,
      run: () => {
        const inc = createIncident(e);
        toast({ kind: "success", title: `Case ${inc.id} created`, body: inc.title });
      },
    },
    {
      label: "Copy details",
      icon: "copy" as IconName,
      run: () => {
        const text = `${e.category.label} | ${e.outcome.verdict} | ${confidencePct(e.outcome)}% | ${e.source.city} (${e.source.cc}) | ${e.app}`;
        navigator.clipboard?.writeText(text).catch(() => {});
        toast({ kind: "info", title: "Copied to clipboard" });
      },
    },
  ];

  const onContextMenu = (ev: ReactMouseEvent) => {
    ev.preventDefault();
    setPos({ x: ev.clientX, y: ev.clientY });
  };

  const menu = pos ? (
    <div
      className="fixed z-[80] card p-1 w-44 animate-fade-in"
      style={{ left: Math.min(pos.x, window.innerWidth - 190), top: Math.min(pos.y, window.innerHeight - 130) }}
      onClick={(ev) => ev.stopPropagation()}
    >
      {items.map((it) => (
        <button
          key={it.label}
          className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-white/[0.06] text-left"
          onClick={() => { it.run(); setPos(null); }}
        >
          <Icon name={it.icon} size={13} className="text-slate-500" /> {it.label}
        </button>
      ))}
    </div>
  ) : null;

  return { onContextMenu, menu };
}

/** Compact one-line row for dense feeds/timelines. */
export function EventRow({ e, onClick }: { e: SecurityEvent; onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-white/[0.04] transition-colors group"
    >
      <SeverityBadge sev={e.severity} small />
      <span className="text-sm text-slate-200 truncate flex-1 min-w-0">
        {e.replayName ?? e.category.label}
        {e.evasion && <span className="text-slate-500"> · {e.evasion}</span>}
      </span>
      <span className="text-xs text-slate-500 hidden sm:inline whitespace-nowrap">
        {FLAG[e.source.cc] ?? ""} {e.source.cc}
      </span>
      <VerdictPill verdict={e.outcome.verdict} />
      <span className="text-[11px] text-slate-600 tnum w-14 text-right">{timeAgo(e.ts)}</span>
      <Icon name="chevronRight" size={14} className="text-slate-600 group-hover:text-slate-300" />
    </button>
  );
}

/** Rich animated card for the live threat stream. */
export function ThreatCard({ e, onInspect }: { e: SecurityEvent; onInspect?: () => void }) {
  const blocked = e.outcome.blocked;
  const { onContextMenu, menu } = useEventMenu(e, onInspect);
  return (
    <div
      className="card p-3 animate-slide-in-right"
      style={{ boxShadow: blocked ? "inset 0 0 0 1px rgba(255,77,109,0.18)" : undefined }}
      onContextMenu={onContextMenu}
    >
      {menu}
      <div className="flex items-center gap-2 mb-2">
        <SeverityBadge sev={e.severity} />
        <span className="text-sm font-semibold text-slate-100 truncate">{e.replayName ?? e.category.label}</span>
        <span className="ml-auto text-[11px] text-slate-500 tnum">{timeAgo(e.ts)}</span>
      </div>
      <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs text-slate-400">
        <div className="flex items-center gap-1.5">
          <Icon name="globe" size={12} className="text-slate-500" />
          {FLAG[e.source.cc] ?? ""} {e.source.city}
        </div>
        <div className="flex items-center gap-1.5">
          <Icon name="layers" size={12} className="text-slate-500" />
          {e.app}
        </div>
        <div className="flex items-center gap-1.5">
          <Icon name="target" size={12} className="text-slate-500" />
          conf {confidencePct(e.outcome)}%
        </div>
        <div className="flex items-center gap-1.5">
          <Icon name="clock" size={12} className="text-slate-500" />
          {(e.outcome.latency_ms ?? 0).toFixed(2)} ms
        </div>
      </div>
      {e.evasion && (
        <div className="mt-2">
          <span className="pill bg-aegis-warn/15 text-aegis-warn">evasion: {e.evasion} → normalized</span>
        </div>
      )}
      <div className="flex items-center gap-2 mt-2.5">
        <VerdictPill verdict={e.outcome.verdict} />
        {e.category.owasp && <span className="chip !py-0.5 !text-[10px]">{e.category.owasp}</span>}
        {e.category.mitre && <span className="chip !py-0.5 !text-[10px]">{e.category.mitre.id}</span>}
        {onInspect && (
          <button className="btn-ghost !py-1 !px-2 ml-auto !text-xs" onClick={onInspect}>
            <Icon name="search" size={12} /> Investigate
          </button>
        )}
      </div>
    </div>
  );
}
