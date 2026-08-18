// Detection Pipeline — an animated walk-through of the six-stage engine. Send a
// prompt (or auto-cycle attacks) and watch each stage light up with its real
// score. Great for live demos of "how a decision is made".
import { useEffect, useRef, useState } from "react";
import { inspect, type Outcome } from "../api";
import { store } from "../lib/store";
import { PipelineFlow } from "../components/Pipeline";
import { Panel, VerdictPill, SeverityBadge, Spinner } from "../components/ui";
import { Icon } from "../components/icons";
import { ATTACKS, BENIGN, EVASIONS } from "../lib/attacks";
import { severityOf, categoryOf, confidencePct } from "../lib/taxonomy";

export default function DetectionPipeline() {
  const [text, setText] = useState(ATTACKS[7].payload); // unicode smuggle — visually striking
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [pulse, setPulse] = useState(0);
  const [loading, setLoading] = useState(false);
  const [auto, setAuto] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  async function send(t = text) {
    setLoading(true);
    try {
      const o = await inspect(t);
      setOutcome(o);
      setPulse((p) => p + 1);
      store.pushManual(o, t);
    } finally {
      setLoading(false);
    }
  }

  // Auto-cycle: pick a random attack (sometimes evasion-wrapped) every 3.2s.
  useEffect(() => {
    if (!auto) {
      if (timer.current) clearInterval(timer.current);
      return;
    }
    const cycle = () => {
      const a = ATTACKS[Math.floor(Math.random() * ATTACKS.length)];
      const ev = EVASIONS[Math.floor(Math.random() * EVASIONS.length)];
      const t = ev.fn(a.payload);
      setText(t);
      send(t);
    };
    cycle();
    timer.current = setInterval(cycle, 3200);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto]);

  const sev = outcome ? severityOf(outcome) : null;
  const cat = outcome ? categoryOf(outcome) : null;
  const blocked = outcome?.blocked;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-4">
      <Panel
        title="Live Detection Pipeline"
        icon="flow"
        subtitle="Each stage shows its real signal strength for the current prompt"
        action={
          <button className={auto ? "btn-danger" : "btn-ghost"} onClick={() => setAuto((a) => !a)}>
            <Icon name={auto ? "pause" : "play"} size={13} /> {auto ? "Stop auto" : "Auto-cycle"}
          </button>
        }
      >
        <PipelineFlow outcome={outcome} pulseKey={pulse} />
      </Panel>

      <div className="space-y-4">
        <Panel title="Send a Prompt" icon="zap">
          <textarea rows={4} value={text} onChange={(e) => setText(e.target.value)} className="font-mono text-[11px]" />
          <button className="btn w-full mt-2" onClick={() => send()} disabled={loading}>
            {loading ? <Spinner /> : <Icon name="arrowRight" size={14} />} Run through pipeline
          </button>
          <div className="flex flex-wrap gap-1.5 mt-3">
            {ATTACKS.slice(0, 8).map((a) => (
              <button key={a.id} className="chip !text-[11px]" onClick={() => { setText(a.payload); send(a.payload); }}>
                {a.icon} {a.name}
              </button>
            ))}
            <button className="chip !text-[11px] text-aegis-ok" onClick={() => { const b = BENIGN[0]; setText(b); send(b); }}>
              ✓ benign
            </button>
          </div>
        </Panel>

        {outcome && (
          <Panel title="Final Decision" icon="target">
            <div
              className="rounded-xl p-4 text-center animate-slide-up"
              style={{
                background: blocked ? "rgba(255,77,109,0.1)" : "rgba(45,212,167,0.1)",
                boxShadow: `inset 0 0 0 1px ${blocked ? "rgba(255,77,109,0.3)" : "rgba(45,212,167,0.3)"}`,
              }}
            >
              <div className="flex justify-center mb-2">
                <Icon name={blocked ? "ban" : "shieldCheck"} size={34} className={blocked ? "text-sev-critical" : "text-aegis-ok"} />
              </div>
              <VerdictPill verdict={outcome.verdict} />
              <div className="mt-2 flex items-center justify-center gap-2">
                {sev && <SeverityBadge sev={sev} />}
                <span className="text-sm text-slate-300">{cat?.label}</span>
              </div>
              <div className="grid grid-cols-3 gap-2 mt-3 text-center">
                <div><div className="text-lg font-bold tnum text-slate-100">{confidencePct(outcome)}%</div><div className="text-[10px] text-slate-500">confidence</div></div>
                <div><div className="text-lg font-bold tnum text-slate-100">{(outcome.score ?? 0).toFixed(2)}</div><div className="text-[10px] text-slate-500">risk score</div></div>
                <div><div className="text-lg font-bold tnum text-slate-100">{(outcome.latency_ms ?? 0).toFixed(1)}</div><div className="text-[10px] text-slate-500">ms</div></div>
              </div>
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}
