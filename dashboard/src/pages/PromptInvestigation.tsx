// Prompt Investigation — the analyst's deep-dive. A split view walks a prompt
// through the firewall: Original (with smuggled tokens revealed) → Sanitized
// bytes → AI analysis & decision, plus the live pipeline strip. Runs the REAL
// engine via inspect().
import { useEffect, useMemo, useRef, useState } from "react";
import { inspect, type Outcome } from "../api";
import { store } from "../lib/store";
import { Panel, GaugeRing, SeverityBadge, VerdictPill, Spinner, EmptyState, Bar } from "../components/ui";
import { Icon } from "../components/icons";
import PromptHighlight from "../components/PromptHighlight";
import { PipelineStrip } from "../components/Pipeline";
import {
  categoryOf, severityOf, confidencePct, explain, recommendedAction, verdictFacts, SEV_COLOR,
} from "../lib/taxonomy";
import { ATTACKS, BENIGN, EVASIONS } from "../lib/attacks";
import { useNav } from "../lib/nav";
import { useToast } from "../components/Toaster";

const LAYER_LABEL: Record<string, string> = {
  signatures: "Rule signatures",
  classifiers: "ML classifiers",
  kad: "Known-attack detector",
  normalization: "Normalization risk",
};

export default function PromptInvestigation() {
  const { focus } = useNav();
  const toast = useToast();
  const [text, setText] = useState(ATTACKS[0].payload);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const lastFocus = useRef<string | null>(null);

  // Load an event handed over from another page (e.g. the live monitor).
  useEffect(() => {
    if (focus && focus.id !== lastFocus.current) {
      lastFocus.current = focus.id;
      setText(focus.prompt);
      setOutcome(focus.outcome);
      setErr("");
    }
  }, [focus]);

  async function run(t = text) {
    setLoading(true);
    setErr("");
    try {
      const o = await inspect(t);
      setOutcome(o);
      store.pushManual(o, t);
    } catch (e: any) {
      setErr(String(e?.message || e));
    } finally {
      setLoading(false);
    }
  }

  const hiddenChars = useMemo(() => {
    let n = 0;
    for (const ch of text) {
      const cp = ch.codePointAt(0)!;
      if (cp >= 0xe0000 && cp <= 0xe007f) n++;
      else if ([0x200b, 0x200c, 0x200d, 0xfeff, 0x2060].includes(cp)) n++;
      else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) n++;
    }
    return n;
  }, [text]);

  const sev = outcome ? severityOf(outcome) : null;
  const cat = outcome ? categoryOf(outcome) : null;
  const rec = outcome ? recommendedAction(outcome) : null;

  return (
    <div className="space-y-4">
      {/* Input */}
      <Panel title="Prompt Inspector" icon="search" subtitle="Run any prompt through the full detection pipeline">
        <textarea rows={3} value={text} onChange={(e) => setText(e.target.value)} className="font-mono text-xs" />
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <button className="btn" onClick={() => run()} disabled={loading}>
            {loading ? <Spinner /> : <Icon name="zap" size={14} />}
            {loading ? "Inspecting…" : "Inspect prompt"}
          </button>
          <span className="text-xs text-slate-500 mr-1">Apply evasion:</span>
          {EVASIONS.slice(1).map((ev) => (
            <button key={ev.id} className="chip hover:bg-white/[0.08]" onClick={() => setText(ev.fn(text))}>
              {ev.label}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-1.5 mt-2">
          <span className="text-xs text-slate-500 mr-1">Samples:</span>
          {BENIGN.slice(0, 2).map((b, i) => (
            <button key={i} className="chip !text-[11px] text-aegis-ok" onClick={() => setText(b)}>benign #{i + 1}</button>
          ))}
          {ATTACKS.slice(0, 6).map((a) => (
            <button key={a.id} className="chip !text-[11px] text-sev-high" onClick={() => setText(a.payload)}>
              {a.icon} {a.name}
            </button>
          ))}
        </div>
        {err && <div className="text-sev-critical text-sm mt-2">{err}</div>}
      </Panel>

      {/* Pipeline strip */}
      <Panel title="Detection Pipeline" icon="flow">
        <PipelineStrip outcome={outcome} />
      </Panel>

      {/* Split view */}
      {!outcome ? (
        <Panel>
          <EmptyState icon="search" title="No inspection yet" hint="Inspect a prompt to see the original, the sanitized bytes and the AI verdict side by side." />
        </Panel>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          {/* Original */}
          <Panel
            title="Original Prompt"
            icon="eye"
            subtitle={`${[...text].length} chars · ${hiddenChars} hidden codepoint(s)`}
          >
            <div className="rounded-lg bg-black/30 border border-white/[0.06] p-3 max-h-64 overflow-auto">
              <PromptHighlight text={text} />
            </div>
            {hiddenChars > 0 && (
              <div className="mt-2 text-xs text-sev-high flex items-center gap-1.5">
                <Icon name="alert" size={13} /> {hiddenChars} invisible smuggling codepoint(s) revealed above
              </div>
            )}
          </Panel>

          {/* Sanitized */}
          <Panel title="Sanitized Bytes" icon="sparkles" subtitle="What actually reaches the model">
            <div className="rounded-lg bg-black/30 border border-white/[0.06] p-3 max-h-64 overflow-auto font-mono text-xs whitespace-pre-wrap break-words text-slate-200">
              {outcome.forward_text || <span className="text-slate-600">(empty after sanitization)</span>}
            </div>
            {outcome.normalization?.reasons?.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {outcome.normalization.reasons.map((r) => (
                  <span key={r} className="pill bg-aegis-warn/15 text-aegis-warn">{r}</span>
                ))}
              </div>
            )}
            {outcome.normalization?.decoded_views?.length > 0 && (
              <div className="mt-2">
                <div className="kpi-label mb-1">Decoded payloads</div>
                {outcome.normalization.decoded_views.map((d, i) => (
                  <code key={i} className="block text-[11px] text-sev-high break-all bg-black/30 rounded px-2 py-1 mt-1">{d}</code>
                ))}
              </div>
            )}
          </Panel>

          {/* AI analysis & decision */}
          <Panel title="AI Analysis & Decision" icon="brain">
            <div className="flex items-center gap-4">
              <GaugeRing
                value={confidencePct(outcome) / 100}
                color={sev ? SEV_COLOR[sev] : "#4f8cff"}
                label={`${confidencePct(outcome)}%`}
                sub="confidence"
                size={104}
                stroke={9}
              />
              <div className="space-y-2 flex-1">
                <div className="flex items-center gap-2">
                  {sev && <SeverityBadge sev={sev} />}
                  <VerdictPill verdict={outcome.verdict} />
                </div>
                <div className="text-sm font-semibold text-slate-100">{cat?.label}</div>
                <div className="flex flex-wrap gap-1.5">
                  {cat?.owasp && <span className="chip !text-[10px]">{cat.owasp}</span>}
                  {cat?.mitre && <span className="chip !text-[10px]">MITRE {cat.mitre.id}</span>}
                  {outcome.judge_used && <span className="chip !text-[10px] text-aegis-warn">judge</span>}
                </div>
              </div>
            </div>

            {/* Verdict at a glance — structured explainability */}
            <div className="mt-3 grid grid-cols-2 gap-1.5">
              {verdictFacts(outcome).map((f) => (
                <div key={f.label} className="rounded-lg px-2.5 py-1.5 bg-white/[0.02] border border-white/[0.06]">
                  <div className="text-[10px] uppercase tracking-wide text-slate-500">{f.label}</div>
                  <div className={`text-xs truncate ${f.strong ? "font-semibold text-slate-100" : "text-slate-300"}`}>{f.value}</div>
                </div>
              ))}
            </div>

            {/* Layer contributions */}
            <div className="mt-3 space-y-1.5">
              <div className="kpi-label">Layer contributions</div>
              {Object.entries(outcome.contributions || {}).map(([k, v]) => (
                <div key={k} className="flex items-center gap-2">
                  <span className="text-[11px] text-slate-400 w-32 shrink-0">{LAYER_LABEL[k] ?? k}</span>
                  <div className="flex-1"><Bar value={v as number} color={(v as number) >= 0.5 ? "#ff4d6d" : "#4f8cff"} /></div>
                  <span className="text-[11px] tnum text-slate-400 w-8 text-right">{(v as number).toFixed(2)}</span>
                </div>
              ))}
            </div>

            {/* Tripwires */}
            {outcome.tripwires?.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {outcome.tripwires.map((t) => (
                  <span key={t} className="pill bg-sev-critical/15 text-sev-critical">⚡ {t}</span>
                ))}
              </div>
            )}

            {/* Explanation */}
            <div className="mt-3">
              <div className="kpi-label mb-1">Explanation</div>
              <ul className="space-y-1">
                {explain(outcome).map((line, i) => (
                  <li key={i} className="text-xs text-slate-300 flex gap-1.5">
                    <Icon name="chevronRight" size={12} className="text-aegis-accent mt-0.5 shrink-0" />
                    <span>{line}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Mitigation + recommended action */}
            <div className="mt-3 rounded-lg p-3 bg-black/20 border border-white/[0.06]">
              <div className="kpi-label mb-1">Recommended mitigation</div>
              <p className="text-xs text-slate-300">{cat?.mitigation}</p>
              {rec && (
                <button
                  className={`mt-2 w-full ${rec.tone === "danger" ? "btn-danger" : rec.tone === "warn" ? "btn" : "btn-ghost"}`}
                  onClick={() =>
                    toast({
                      kind: rec.tone === "danger" ? "alert" : "success",
                      title: rec.action,
                      body: `Applied to ${cat?.label} · confidence ${confidencePct(outcome)}%`,
                    })
                  }
                >
                  <Icon name="shieldCheck" size={14} /> {rec.action}
                </button>
              )}
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}
