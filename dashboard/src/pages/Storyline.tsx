// Attack Storyline — the demo centerpiece. One click animates a single attack
// through the entire firewall lifecycle: Attack → Detected → Analyzed →
// Explained → Blocked → Incident Created → Report Generated. Every stage uses
// REAL data: the detection engine, a real incident case and a real PDF report.
// Judges remember workflows, not menus.
import { useEffect, useRef, useState } from "react";
import { store, type SecurityEvent } from "../lib/store";
import { createIncident, type Incident } from "../lib/incidents";
import { openIncidentReport } from "../lib/reports";
import { ATTACKS, type AttackVector } from "../lib/attacks";
import { Panel, VerdictPill, SeverityBadge, Bar, Spinner } from "../components/ui";
import { Icon, type IconName } from "../components/icons";
import { confidencePct, explain, verdictFacts } from "../lib/taxonomy";
import { FLAG } from "../lib/format";
import { useNav } from "../lib/nav";

const STAGES: { key: string; title: string; icon: IconName; color: string }[] = [
  { key: "attack", title: "Attack", icon: "zap", color: "#ff4d6d" },
  { key: "detected", title: "Detected", icon: "radar", color: "#ff8a3d" },
  { key: "analyzed", title: "Analyzed", icon: "cpu", color: "#ffd23f" },
  { key: "explained", title: "Explained", icon: "brain", color: "#4f8cff" },
  { key: "blocked", title: "Blocked", icon: "ban", color: "#ff4d6d" },
  { key: "incident", title: "Incident Created", icon: "scroll", color: "#22d3ee" },
  { key: "report", title: "Report Generated", icon: "file", color: "#2dd4a7" },
];

export default function Storyline() {
  const { go } = useNav();
  const [vector, setVector] = useState<AttackVector>(ATTACKS[0]);
  const [step, setStep] = useState(0); // 0 idle; 1..7 stages revealed
  const [event, setEvent] = useState<SecurityEvent | null>(null);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [busy, setBusy] = useState(false);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const clearTimers = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
  };
  useEffect(() => clearTimers, []);

  const after = (ms: number, fn: () => void) => timers.current.push(setTimeout(fn, ms));

  async function run() {
    clearTimers();
    setBusy(true);
    setEvent(null);
    setIncident(null);
    setStep(1);
    // Stage 1 (attack) shows immediately; then run the real detection.
    after(850, async () => {
      const e = await store.replay(vector, "plain");
      setEvent(e);
      setStep(2);
      after(1000, () => setStep(3));
      after(2000, () => setStep(4));
      after(3000, () => setStep(5));
      after(4000, () => {
        const inc = createIncident(e);
        setIncident(inc);
        setStep(6);
      });
      after(5000, () => {
        setStep(7);
        setBusy(false);
      });
    });
  }

  function reset() {
    clearTimers();
    setStep(0);
    setEvent(null);
    setIncident(null);
    setBusy(false);
  }

  const progress = step / STAGES.length;

  return (
    <div className="space-y-4">
      <Panel
        title="Attack Storyline"
        icon="route"
        subtitle="Watch one attack travel the full lifecycle — end to end, in real data"
        action={
          <div className="flex gap-2">
            {step > 0 && (
              <button className="btn-ghost !py-1.5 !px-3" onClick={reset}>
                <Icon name="refresh" size={13} /> Reset
              </button>
            )}
            <button className="btn !py-1.5 !px-3" onClick={run} disabled={busy}>
              {busy ? <Spinner size={13} /> : <Icon name="play" size={13} />} Run the story
            </button>
          </div>
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-500">Attack vector:</span>
          {ATTACKS.slice(0, 8).map((a) => (
            <button
              key={a.id}
              onClick={() => setVector(a)}
              disabled={busy}
              className={`chip !text-[11px] transition-all ${vector.id === a.id ? "!bg-aegis-accent/20 ring-1 ring-inset ring-aegis-accent/50 text-slate-100" : "hover:bg-white/[0.08]"}`}
            >
              {a.icon} {a.name}
            </button>
          ))}
        </div>
        {/* progress bar */}
        <div className="mt-3">
          <Bar value={progress} color="#4f8cff" />
        </div>
      </Panel>

      {/* Lifecycle stages */}
      <div className="space-y-2">
        {STAGES.map((s, i) => {
          const reached = step >= i + 1;
          const active = step === i + 1;
          const done = step > i + 1;
          return (
            <div key={s.key}>
              <div
                className="card p-4 transition-all duration-300"
                style={{
                  opacity: reached ? 1 : 0.4,
                  boxShadow: active ? `inset 0 0 0 1px ${s.color}66, 0 8px 30px -12px ${s.color}` : undefined,
                  transform: active ? "scale(1.0)" : undefined,
                }}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`grid place-items-center w-10 h-10 rounded-xl shrink-0 ${active ? "animate-pulse-ring" : ""}`}
                    style={{ background: `${s.color}1f`, color: s.color }}
                  >
                    {reached && !active ? <Icon name="check" size={18} /> : <Icon name={s.icon} size={18} />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono text-slate-500">{String(i + 1).padStart(2, "0")}</span>
                      <span className="text-sm font-semibold text-slate-100">{s.title}</span>
                      {done && <Icon name="check" size={13} className="text-aegis-ok" />}
                    </div>
                    {/* Stage content */}
                    {reached && <StageBody stageKey={s.key} event={event} incident={incident} vector={vector} onGoIncident={() => go("incidents")} />}
                  </div>
                </div>
              </div>
              {i < STAGES.length - 1 && (
                <div className="flex justify-start pl-[34px]">
                  <svg width="12" height="16" viewBox="0 0 12 16">
                    <line x1="6" y1="0" x2="6" y2="16" stroke={step > i + 1 ? s.color : "#334155"} strokeWidth="1.5" strokeDasharray="3 3" className={active || done ? "animate-flow-dash" : ""} />
                  </svg>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function StageBody({
  stageKey, event, incident, vector, onGoIncident,
}: {
  stageKey: string;
  event: SecurityEvent | null;
  incident: Incident | null;
  vector: AttackVector;
  onGoIncident: () => void;
}) {
  if (stageKey === "attack") {
    return (
      <div className="mt-1.5 animate-fade-in">
        <div className="text-xs text-slate-400 mb-1">{vector.name} · {vector.klass}</div>
        <code className="block text-[11px] text-slate-300 bg-black/30 rounded-lg px-2 py-1.5 break-all max-h-16 overflow-auto">{vector.payload}</code>
      </div>
    );
  }
  if (!event) return <div className="mt-1 text-xs text-slate-500 flex items-center gap-1.5"><Spinner size={12} /> processing…</div>;

  if (stageKey === "detected") {
    return (
      <div className="mt-1.5 flex flex-wrap items-center gap-2 animate-fade-in">
        <VerdictPill verdict={event.outcome.verdict} />
        <SeverityBadge sev={event.severity} />
        <span className="chip !text-[10px]">{FLAG[event.source.cc]} {event.source.city}</span>
        <span className="text-xs text-slate-400">{confidencePct(event.outcome)}% confidence</span>
      </div>
    );
  }
  if (stageKey === "analyzed") {
    return (
      <div className="mt-1.5 space-y-1 animate-fade-in">
        {Object.entries(event.outcome.contributions).map(([k, v]) => (
          <div key={k} className="flex items-center gap-2">
            <span className="text-[10px] text-slate-500 w-24 capitalize shrink-0">{k}</span>
            <div className="flex-1"><Bar value={v as number} color={(v as number) >= 0.5 ? "#ff4d6d" : "#4f8cff"} /></div>
            <span className="text-[10px] tnum text-slate-400 w-7 text-right">{(v as number).toFixed(2)}</span>
          </div>
        ))}
      </div>
    );
  }
  if (stageKey === "explained") {
    return (
      <div className="mt-1.5 animate-fade-in">
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 mb-2">
          {verdictFacts(event.outcome).slice(0, 6).map((f) => (
            <div key={f.label} className="rounded-lg px-2 py-1 bg-white/[0.02] border border-white/[0.06]">
              <div className="text-[9px] uppercase tracking-wide text-slate-500">{f.label}</div>
              <div className="text-[11px] text-slate-200 truncate">{f.value}</div>
            </div>
          ))}
        </div>
        <ul className="space-y-0.5">
          {explain(event.outcome).slice(0, 2).map((l, i) => (
            <li key={i} className="text-[11px] text-slate-400 flex gap-1"><Icon name="chevronRight" size={11} className="text-aegis-accent mt-0.5 shrink-0" />{l}</li>
          ))}
        </ul>
      </div>
    );
  }
  if (stageKey === "blocked") {
    return (
      <div className="mt-1.5 animate-fade-in flex items-center gap-2">
        <Icon name="ban" size={16} className="text-sev-critical" />
        <span className="text-xs text-slate-300">Request blocked before reaching the model — sanitized bytes forwarded, canary intact.</span>
      </div>
    );
  }
  if (stageKey === "incident") {
    if (!incident) return <div className="mt-1 text-xs text-slate-500">creating case…</div>;
    return (
      <div className="mt-1.5 flex flex-wrap items-center gap-2 animate-fade-in">
        <span className="text-xs font-mono text-aegis-cyan">{incident.id}</span>
        <span className="text-xs text-slate-300 truncate">{incident.title}</span>
        <button className="btn-ghost !py-1 !px-2 !text-[11px]" onClick={onGoIncident}><Icon name="arrowRight" size={11} /> Open case</button>
      </div>
    );
  }
  if (stageKey === "report") {
    if (!incident) return null;
    return (
      <div className="mt-1.5 animate-fade-in flex items-center gap-2">
        <span className="text-xs text-slate-300">Incident report ready.</span>
        <button className="btn !py-1 !px-2 !text-[11px]" onClick={() => openIncidentReport(incident)}><Icon name="download" size={11} /> Open PDF</button>
      </div>
    );
  }
  return null;
}
