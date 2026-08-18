// Incident Response — promote a blocked detection into a tracked case with a
// status workflow, evidence viewer, timeline, analyst notes and PDF/CSV export.
// Fully functional: cases persist for the session and drive real reports.
import { useMemo, useState } from "react";
import { useEvents } from "../lib/store";
import {
  useIncidents, createIncident, setStatus, addNote, removeIncident,
  STATUS_FLOW, STATUS_COLOR, type Incident, type IncidentStatus,
} from "../lib/incidents";
import { openIncidentReport, exportIncidentsCSV, incidentExecutiveSummary } from "../lib/reports";
import { Panel, KpiCard, SeverityBadge, EmptyState, Spinner } from "../components/ui";
import { Icon } from "../components/icons";
import { FLAG, timeAgo, clockTime } from "../lib/format";
import { confidencePct } from "../lib/taxonomy";
import { useNav } from "../lib/nav";
import { useToast } from "../components/Toaster";

function StatusPill({ status }: { status: IncidentStatus }) {
  const c = STATUS_COLOR[status];
  return (
    <span className="pill" style={{ background: `${c}22`, color: c, boxShadow: `inset 0 0 0 1px ${c}44` }}>
      {status.toUpperCase()}
    </span>
  );
}

export default function IncidentResponse() {
  const events = useEvents();
  const incidents = useIncidents();
  const { investigate } = useNav();
  const toast = useToast();
  const [selId, setSelId] = useState<string | null>(null);
  const [note, setNote] = useState("");

  const selected = incidents.find((i) => i.id === selId) ?? incidents[0] ?? null;

  const casedEventIds = useMemo(() => new Set(incidents.map((i) => i.event.id)), [incidents]);
  const openable = useMemo(
    () => events.filter((e) => e.outcome.blocked && !casedEventIds.has(e.id)).slice(0, 6),
    [events, casedEventIds],
  );

  const counts = {
    total: incidents.length,
    open: incidents.filter((i) => i.status === "open").length,
    critical: incidents.filter((i) => i.severity === "critical").length,
    closed: incidents.filter((i) => i.status === "closed").length,
  };

  const create = (eventId: string) => {
    const e = events.find((x) => x.id === eventId);
    if (!e) return;
    const inc = createIncident(e);
    setSelId(inc.id);
    toast({ kind: "success", title: `Case ${inc.id} created`, body: inc.title });
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KpiCard label="Total Cases" value={counts.total} icon="scroll" tone="accent" />
        <KpiCard label="Open" value={counts.open} icon="alert" tone="danger" />
        <KpiCard label="Critical" value={counts.critical} icon="zap" tone="warn" />
        <KpiCard label="Closed" value={counts.closed} icon="check" tone="ok" />
      </div>

      {/* Create case from a live detection */}
      <Panel
        title="Open a Case"
        icon="target"
        subtitle="Promote a blocked detection into a tracked incident"
        action={
          incidents.length > 0 ? (
            <button className="btn-ghost !py-1 !px-2 !text-xs" onClick={() => { exportIncidentsCSV(incidents); toast({ kind: "success", title: "Cases exported", body: `${incidents.length} cases → CSV` }); }}>
              <Icon name="download" size={12} /> Export all (CSV)
            </button>
          ) : undefined
        }
      >
        {openable.length === 0 ? (
          <div className="text-xs text-slate-500 flex items-center gap-2"><Spinner size={13} /> Waiting for blocked detections… start the live feed or replay an attack.</div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {openable.map((e) => (
              <div key={e.id} className="flex items-center gap-2 p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.06]">
                <SeverityBadge sev={e.severity} small />
                <div className="min-w-0 flex-1">
                  <div className="text-xs text-slate-200 truncate">{e.replayName ?? e.category.label}</div>
                  <div className="text-[10px] text-slate-500">{FLAG[e.source.cc]} {e.source.city} · {timeAgo(e.ts)}</div>
                </div>
                <button className="btn !py-1 !px-2 !text-[11px]" onClick={() => create(e.id)}>
                  <Icon name="arrowRight" size={11} /> Case
                </button>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {incidents.length === 0 ? (
        <Panel>
          <EmptyState icon="scroll" title="No incidents yet" hint="Create a case from a blocked detection above to begin an investigation." />
        </Panel>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-4">
          {/* Case list */}
          <Panel title="Cases" icon="scroll" bodyClass="space-y-1.5">
            {incidents.map((i) => (
              <button
                key={i.id}
                onClick={() => setSelId(i.id)}
                className={`w-full text-left p-2.5 rounded-lg border transition-colors ${
                  selected?.id === i.id ? "border-aegis-accent/50 bg-aegis-accent/10" : "border-white/[0.06] bg-white/[0.02] hover:bg-white/[0.05]"
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-aegis-cyan">{i.id}</span>
                  <StatusPill status={i.status} />
                  <SeverityBadge sev={i.severity} small />
                </div>
                <div className="text-xs text-slate-200 truncate mt-1">{i.title}</div>
                <div className="text-[10px] text-slate-500">{timeAgo(i.createdAt)}</div>
              </button>
            ))}
          </Panel>

          {/* Case detail */}
          {selected && <CaseDetail incident={selected} note={note} setNote={setNote} onInvestigate={() => investigate(selected.event)} toast={toast} onDeleted={() => setSelId(null)} />}
        </div>
      )}
    </div>
  );
}

function CaseDetail({
  incident, note, setNote, onInvestigate, toast, onDeleted,
}: {
  incident: Incident;
  note: string;
  setNote: (v: string) => void;
  onInvestigate: () => void;
  toast: ReturnType<typeof useToast>;
  onDeleted: () => void;
}) {
  const e = incident.event;
  const evidence: [string, string][] = [
    ["Attack category", e.category.label],
    ["OWASP", e.category.owasp ?? "—"],
    ["MITRE ATT&CK", e.category.mitre ? `${e.category.mitre.id} · ${e.category.mitre.name}` : "—"],
    ["Verdict", e.outcome.verdict.toUpperCase()],
    ["Confidence", `${confidencePct(e.outcome)}%`],
    ["Source", `${FLAG[e.source.cc] ?? ""} ${e.source.city} (${e.source.cc})`],
    ["Application", e.app],
    ["Detection latency", `${(e.outcome.latency_ms ?? 0).toFixed(2)} ms`],
    ["Evasion", e.evasion ?? "none"],
  ];

  return (
    <Panel
      title={`${incident.id} · ${incident.title}`}
      icon="alert"
      action={
        <div className="flex gap-2">
          <button className="btn-ghost !py-1 !px-2 !text-xs" onClick={onInvestigate}><Icon name="search" size={12} /> Investigate</button>
          <button className="btn !py-1 !px-2 !text-xs" onClick={() => openIncidentReport(incident)}><Icon name="download" size={12} /> PDF</button>
        </div>
      }
    >
      {/* Status workflow */}
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <span className="text-xs text-slate-500">Status:</span>
        {STATUS_FLOW.map((s) => (
          <button
            key={s}
            onClick={() => { setStatus(incident.id, s); toast({ kind: "info", title: `${incident.id} → ${s}` }); }}
            className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-all ${
              incident.status === s ? "text-white" : "text-slate-400 bg-white/[0.03] hover:bg-white/[0.06]"
            }`}
            style={incident.status === s ? { background: STATUS_COLOR[s] } : undefined}
          >
            {s}
          </button>
        ))}
      </div>

      {/* Executive summary */}
      <div className="rounded-lg p-3 bg-black/20 border border-white/[0.06] mb-3">
        <div className="kpi-label mb-1">Executive summary</div>
        <p className="text-xs text-slate-300">{incidentExecutiveSummary(incident)}</p>
      </div>

      <div className="grid md:grid-cols-2 gap-3">
        {/* Evidence */}
        <div>
          <div className="kpi-label mb-1">Evidence</div>
          <div className="rounded-lg border border-white/[0.06] overflow-hidden">
            {evidence.map(([k, v], idx) => (
              <div key={k} className={`flex text-xs ${idx % 2 ? "" : "bg-white/[0.02]"}`}>
                <div className="w-32 shrink-0 text-slate-500 px-2.5 py-1.5">{k}</div>
                <div className="text-slate-200 px-2.5 py-1.5 truncate">{v}</div>
              </div>
            ))}
          </div>
          <div className="mt-2">
            <div className="kpi-label mb-1">Sanitized bytes</div>
            <code className="block text-[11px] text-slate-300 bg-black/30 rounded-lg px-2 py-1.5 break-all max-h-20 overflow-auto">
              {e.outcome.forward_text || "(empty)"}
            </code>
          </div>
        </div>

        {/* Timeline + notes */}
        <div>
          <div className="kpi-label mb-1">Timeline</div>
          <div className="space-y-1.5 mb-3">
            {incident.timeline.map((t, i) => (
              <div key={i} className="flex gap-2 text-xs">
                <span className="text-slate-600 tnum w-16 shrink-0">{clockTime(t.ts)}</span>
                <span className="w-1.5 h-1.5 rounded-full bg-aegis-accent mt-1.5 shrink-0" />
                <span className="text-slate-300">{t.label}</span>
              </div>
            ))}
          </div>
          <div className="kpi-label mb-1">Notes</div>
          {incident.notes.map((n, i) => (
            <div key={i} className="text-xs text-slate-300 bg-white/[0.02] rounded-lg px-2 py-1.5 mb-1">
              <span className="text-slate-600 mr-2">{clockTime(n.ts)}</span>{n.text}
            </div>
          ))}
          <div className="flex gap-2 mt-1">
            <input value={note} onChange={(ev) => setNote(ev.target.value)} placeholder="Add a note…" className="!py-1.5 !text-xs"
              onKeyDown={(ev) => { if (ev.key === "Enter") { addNote(incident.id, note); setNote(""); } }} />
            <button className="btn-ghost !py-1.5 !px-2 !text-xs" onClick={() => { addNote(incident.id, note); setNote(""); }}>Add</button>
          </div>
        </div>
      </div>

      <div className="flex justify-end mt-3">
        <button className="btn-ghost !py-1 !px-2 !text-xs text-sev-critical" onClick={() => { removeIncident(incident.id); onDeleted(); toast({ kind: "info", title: `${incident.id} deleted` }); }}>
          <Icon name="x" size={12} /> Delete case
        </button>
      </div>
    </Panel>
  );
}
