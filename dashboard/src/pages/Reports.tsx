// Reports — generate branded Executive / Technical / Incident reports (print to
// PDF) and export the raw event log as CSV. Built from the live event history.
import { useMemo } from "react";
import { useEvents, computeStats } from "../lib/store";
import { Panel, KpiCard } from "../components/ui";
import { Icon, type IconName } from "../components/icons";
import { openReport, exportEventsCSV, type ReportKind } from "../lib/reports";
import { useToast } from "../components/Toaster";

const REPORTS: { kind: ReportKind; title: string; icon: IconName; desc: string; audience: string }[] = [
  {
    kind: "executive",
    title: "Executive Report",
    icon: "shieldCheck",
    desc: "High-level posture summary: requests protected, attacks blocked, detection accuracy and threat narrative.",
    audience: "Leadership · Board · Investors",
  },
  {
    kind: "technical",
    title: "Technical Report",
    icon: "cpu",
    desc: "Per-event detection detail: pipeline layer contributions, severity, confidence and tripwires.",
    audience: "Security Engineering · SOC",
  },
  {
    kind: "incident",
    title: "Incident Report",
    icon: "alert",
    desc: "High-severity incidents requiring attention, with classification, source and recommended containment.",
    audience: "Incident Response · Compliance",
  },
];

export default function Reports() {
  const events = useEvents();
  const toast = useToast();
  const stats = useMemo(() => computeStats(events), [events]);

  const generate = (kind: ReportKind) => {
    openReport(kind, stats, events);
    toast({ kind: "success", title: "Report generated", body: "Use your browser's print dialog to save as PDF." });
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KpiCard label="Events in Report" value={stats.total} icon="file" tone="accent" />
        <KpiCard label="Attacks Blocked" value={stats.blocked} icon="ban" tone="danger" />
        <KpiCard label="Critical Incidents" value={stats.severity.critical} icon="alert" tone="warn" />
        <KpiCard label="Block Rate" value={`${(stats.detectionRate * 100).toFixed(0)}%`} icon="target" tone="ok" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {REPORTS.map((r) => (
          <div key={r.kind} className="card p-5 flex flex-col animate-slide-up">
            <div className="grid place-items-center w-11 h-11 rounded-xl bg-aegis-accent/15 text-aegis-accent mb-3">
              <Icon name={r.icon} size={22} />
            </div>
            <div className="text-base font-semibold text-slate-100">{r.title}</div>
            <p className="text-xs text-slate-400 mt-1 flex-1">{r.desc}</p>
            <div className="text-[11px] text-slate-500 mt-2 mb-3">
              <Icon name="users" size={11} className="inline mr-1" />
              {r.audience}
            </div>
            <button className="btn w-full" onClick={() => generate(r.kind)}>
              <Icon name="download" size={14} /> Generate PDF
            </button>
          </div>
        ))}
      </div>

      <Panel title="Raw Data Export" icon="database" subtitle="Full event log for SIEM ingestion or spreadsheet analysis">
        <div className="flex flex-wrap items-center gap-3">
          <button className="btn-ghost" onClick={() => { exportEventsCSV(events); toast({ kind: "success", title: "CSV exported", body: `${events.length} events written.` }); }}>
            <Icon name="download" size={14} /> Export events (CSV)
          </button>
          <span className="text-xs text-slate-500">{events.length} events available · columns include verdict, severity, category, OWASP, score, latency, source & reasons.</span>
        </div>
      </Panel>
    </div>
  );
}
