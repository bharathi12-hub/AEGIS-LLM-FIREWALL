// Live Threat Monitor — the real-time attack stream. Animated threat cards with
// severity/verdict filtering, full-text search and live feed controls. Every
// card is a real detection outcome from the shared event stream.
import { useMemo, useState } from "react";
import { store, useEvents, useSimRunning, computeStats } from "../lib/store";
import { ThreatCard } from "../components/EventCard";
import { Panel, EmptyState, LiveDot, SeverityBadge } from "../components/ui";
import { Icon } from "../components/icons";
import { SEVERITY_ORDER, type Severity } from "../lib/taxonomy";
import { useNav } from "../lib/nav";

type VerdictFilter = "all" | "block" | "allow";

export default function LiveThreatMonitor() {
  const events = useEvents();
  const running = useSimRunning();
  const { investigate } = useNav();

  const [q, setQ] = useState("");
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [verdict, setVerdict] = useState<VerdictFilter>("all");

  const stats = useMemo(() => computeStats(events), [events]);

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase();
    return events.filter((e) => {
      if (verdict !== "all" && e.outcome.verdict !== verdict) return false;
      if (sevFilter.size && !sevFilter.has(e.severity)) return false;
      if (query) {
        const hay = `${e.replayName ?? ""} ${e.category.label} ${e.source.city} ${e.source.cc} ${e.app} ${e.evasion ?? ""}`.toLowerCase();
        if (!hay.includes(query)) return false;
      }
      return true;
    });
  }, [events, q, sevFilter, verdict]);

  const toggleSev = (s: Severity) =>
    setSevFilter((cur) => {
      const next = new Set(cur);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="card p-3 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px]">
          <Icon name="search" size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            className="!pl-9"
            placeholder="Search category, source, app…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>

        <div className="flex items-center gap-1 rounded-lg bg-black/30 border border-white/[0.06] p-0.5 text-xs">
          {(["all", "block", "allow"] as VerdictFilter[]).map((v) => (
            <button
              key={v}
              onClick={() => setVerdict(v)}
              className={`px-2.5 py-1 rounded-md font-medium capitalize transition-colors ${
                verdict === v ? "bg-aegis-accent text-white" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {v === "block" ? "Blocked" : v === "allow" ? "Allowed" : "All"}
            </button>
          ))}
        </div>

        <button
          className={running ? "btn-danger" : "btn"}
          onClick={() => store.toggle()}
        >
          <Icon name={running ? "pause" : "play"} size={14} />
          {running ? "Pause feed" : "Start feed"}
        </button>
        <button className="btn-ghost" onClick={() => store.clear()}>
          <Icon name="refresh" size={14} /> Clear
        </button>
      </div>

      {/* Severity filter chips + counts */}
      <div className="flex flex-wrap items-center gap-2">
        {SEVERITY_ORDER.map((s) => {
          const n = stats.severity[s];
          const active = sevFilter.has(s);
          return (
            <button
              key={s}
              onClick={() => toggleSev(s)}
              className={`transition-all ${active ? "scale-105" : "opacity-70 hover:opacity-100"}`}
              style={{ filter: sevFilter.size && !active ? "grayscale(0.4)" : undefined }}
            >
              <span className="chip !gap-2">
                <SeverityBadge sev={s} small />
                <span className="tnum text-slate-300">{n}</span>
              </span>
            </button>
          );
        })}
        <div className="ml-auto flex items-center gap-3">
          <LiveDot on={running} />
          <span className="text-xs text-slate-500">
            {filtered.length} / {events.length} events
          </span>
        </div>
      </div>

      {/* Stream */}
      {filtered.length === 0 ? (
        <Panel>
          <EmptyState
            icon="radar"
            title={events.length ? "No events match your filters" : "The stream is quiet"}
            hint={events.length ? "Adjust the severity or verdict filters." : "Start the live feed to watch attacks arrive in real time."}
          />
        </Panel>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
          {filtered.slice(0, 48).map((e) => (
            <ThreatCard key={e.id} e={e} onInspect={() => investigate(e)} />
          ))}
        </div>
      )}
    </div>
  );
}
