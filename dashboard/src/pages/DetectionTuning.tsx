// Detection Tuning — live, hands-on control of the detection engine. Adjust
// thresholds, toggle pipeline layers, add custom signature rules and manage
// allow/deny lists; the test prompt re-evaluates instantly and the change flows
// to the whole live SOC (the simulator's next tick uses the new config).
import { useMemo, useState } from "react";
import {
  useDetectionConfig, patchDetectionConfig, applyPreset, resetDetectionConfig,
  PRESETS, type CustomRule, type PresetName, type DetectionConfig,
} from "../lib/detectionConfig";

type LayerKey = keyof DetectionConfig["layers"];
import { inspectLocal } from "../engine";
import { Panel, GaugeRing, VerdictPill, SeverityBadge, Bar, ErrorBanner } from "../components/ui";
import { Icon } from "../components/icons";
import { severityOf, categoryOf, confidencePct, SEV_COLOR } from "../lib/taxonomy";
import { EVASIONS, ATTACKS } from "../lib/attacks";
import { useToast } from "../components/Toaster";

function Switch({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={on}
      onClick={() => onChange(!on)}
      className={`relative w-10 h-5 rounded-full transition-colors shrink-0 ${on ? "bg-aegis-accent" : "bg-white/10"}`}
    >
      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${on ? "left-[22px]" : "left-0.5"}`} />
    </button>
  );
}

function Slider({ label, value, onChange, hint }: { label: string; value: number; onChange: (v: number) => void; hint?: string }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-slate-300">{label}</span>
        <span className="text-xs font-mono tnum text-aegis-accent">{value.toFixed(2)}</span>
      </div>
      <input
        type="range" min={0} max={1} step={0.01} value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        className="w-full accent-aegis-accent !p-0 !bg-transparent !border-0"
      />
      {hint && <div className="text-[10px] text-slate-600 mt-0.5">{hint}</div>}
    </div>
  );
}

const LAYERS: { key: LayerKey; label: string; desc: string }[] = [
  { key: "normalization", label: "Normalization", desc: "Strip unicode smuggling, decode payloads" },
  { key: "signatures", label: "Rule Engine", desc: "Signature & custom-rule matching" },
  { key: "classifiers", label: "ML Ensemble", desc: "Dual classifiers" },
  { key: "kad", label: "Known-Attack Detector", desc: "Behavioral hijack detection" },
];

export default function DetectionTuning() {
  const cfg = useDetectionConfig();
  const toast = useToast();
  const [test, setTest] = useState(ATTACKS[7].payload); // unicode smuggle — reacts strongly to the normalization toggle

  const result = useMemo(() => inspectLocal(test, cfg), [test, cfg]);
  const sev = severityOf(result);
  const cat = categoryOf(result);

  const setLayer = (k: LayerKey, v: boolean) => patchDetectionConfig({ layers: { ...cfg.layers, [k]: v } });
  const updateRule = (id: string, patch: Partial<CustomRule>) =>
    patchDetectionConfig({ customRules: cfg.customRules.map((r) => (r.id === id ? { ...r, ...patch } : r)) });
  const addRule = () =>
    patchDetectionConfig({
      customRules: [...cfg.customRules, { id: `r${Date.now()}`, pattern: "", weight: 0.7, category: "LLM01", enabled: true }],
    });
  const removeRule = (id: string) => patchDetectionConfig({ customRules: cfg.customRules.filter((r) => r.id !== id) });
  const listToText = (a: string[]) => a.join("\n");
  const textToList = (t: string) => t.split("\n").map((s) => s.trim()).filter(Boolean);

  const preset = (name: PresetName) => {
    applyPreset(name);
    toast({ kind: "success", title: `${PRESETS[name].label} profile applied`, body: "Detection thresholds updated live." });
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-4">
      {/* Controls */}
      <div className="space-y-4">
        <Panel
          title="Detection Profile"
          icon="sliders"
          subtitle="Changes apply live to the local engine and the whole feed"
          action={
            <button className="btn-ghost !py-1 !px-2 !text-xs" onClick={() => { resetDetectionConfig(); toast({ kind: "info", title: "Reset to defaults" }); }}>
              <Icon name="refresh" size={12} /> Reset
            </button>
          }
        >
          <div className="flex flex-wrap gap-2 mb-4">
            {(Object.keys(PRESETS) as PresetName[]).map((p) => (
              <button key={p} className="chip hover:bg-white/[0.08]" onClick={() => preset(p)}>
                <Icon name="shieldCheck" size={12} /> {PRESETS[p].label}
              </button>
            ))}
          </div>
          <div className="grid sm:grid-cols-2 gap-4">
            <Slider label="Block threshold" value={cfg.blockThreshold} onChange={(v) => patchDetectionConfig({ blockThreshold: v })} hint="fused score ≥ this → BLOCK" />
            <Slider label="Review threshold" value={cfg.reviewThreshold} onChange={(v) => patchDetectionConfig({ reviewThreshold: v })} hint="≥ this and below block → REVIEW" />
          </div>
        </Panel>

        <Panel title="Pipeline Layers" icon="flow" subtitle="Toggle detection stages — see the effect instantly on the right">
          <div className="space-y-2">
            {LAYERS.map((ly) => (
              <div key={ly.key} className="flex items-center gap-3 p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.06]">
                <Switch on={cfg.layers[ly.key]} onChange={(v) => setLayer(ly.key, v)} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-slate-200">{ly.label}</div>
                  <div className="text-[11px] text-slate-500">{ly.desc}</div>
                </div>
                {!cfg.layers[ly.key] && <span className="pill bg-sev-high/15 text-sev-high">off</span>}
              </div>
            ))}
          </div>
          {!cfg.layers.normalization && (
            <div className="mt-3">
              <ErrorBanner message="Normalization disabled — obfuscated (unicode-smuggled / homoglyph / base64) attacks can now bypass detection. This is the vulnerability the platform's normalization-first design closes." />
            </div>
          )}
        </Panel>

        <Panel title="Custom Signature Rules" icon="shield" subtitle="Regex rules teams can add to detect their own threats"
          action={<button className="btn-ghost !py-1 !px-2 !text-xs" onClick={addRule}><Icon name="sparkles" size={12} /> Add rule</button>}
        >
          {cfg.customRules.length === 0 ? (
            <div className="text-xs text-slate-500">No custom rules. Add one to extend the signature layer.</div>
          ) : (
            <div className="space-y-2">
              {cfg.customRules.map((r) => (
                <div key={r.id} className="flex flex-wrap items-center gap-2 p-2 rounded-lg bg-white/[0.02] border border-white/[0.06]">
                  <Switch on={r.enabled} onChange={(v) => updateRule(r.id, { enabled: v })} />
                  <input className="flex-1 min-w-[160px] font-mono !text-xs !py-1" value={r.pattern} placeholder="regex, e.g. exfiltrate|leak.*keys" onChange={(e) => updateRule(r.id, { pattern: e.target.value })} />
                  <input className="w-20 !text-xs !py-1" value={r.category} onChange={(e) => updateRule(r.id, { category: e.target.value })} title="category" />
                  <input className="w-16 !text-xs !py-1" type="number" min={0} max={1} step={0.05} value={r.weight} onChange={(e) => updateRule(r.id, { weight: parseFloat(e.target.value) || 0 })} title="weight" />
                  <button className="btn-ghost !p-1.5" onClick={() => removeRule(r.id)} aria-label="Delete rule"><Icon name="x" size={14} /></button>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <div className="grid sm:grid-cols-2 gap-4">
          <Panel title="Deny List" icon="ban" subtitle="Any match → force BLOCK">
            <textarea rows={4} className="font-mono text-xs" placeholder={"one term per line\ne.g. wire transfer"} value={listToText(cfg.denyList)} onChange={(e) => patchDetectionConfig({ denyList: textToList(e.target.value) })} />
          </Panel>
          <Panel title="Allow List" icon="check" subtitle="Any match → force ALLOW">
            <textarea rows={4} className="font-mono text-xs" placeholder={"one term per line\ne.g. status report"} value={listToText(cfg.allowList)} onChange={(e) => patchDetectionConfig({ allowList: textToList(e.target.value) })} />
          </Panel>
        </div>
      </div>

      {/* Live test */}
      <div className="space-y-4">
        <Panel title="Live Test" icon="zap" subtitle="Re-evaluates on every change" className="xl:sticky xl:top-20">
          <textarea rows={4} value={test} onChange={(e) => setTest(e.target.value)} className="font-mono text-xs" />
          <div className="flex flex-wrap gap-1.5 mt-2">
            {EVASIONS.slice(1).map((ev) => (
              <button key={ev.id} className="chip !text-[11px] hover:bg-white/[0.08]" onClick={() => setTest(ev.fn(test))}>{ev.label}</button>
            ))}
          </div>
          <div className="flex flex-wrap gap-1.5 mt-1.5">
            {ATTACKS.slice(0, 4).map((a) => (
              <button key={a.id} className="chip !text-[11px] text-sev-high" onClick={() => setTest(a.payload)}>{a.icon} {a.name}</button>
            ))}
          </div>

          <div className="mt-4 rounded-xl p-4 text-center" style={{ background: `${SEV_COLOR[sev]}12`, boxShadow: `inset 0 0 0 1px ${SEV_COLOR[sev]}33` }}>
            <div className="flex justify-center mb-2">
              <GaugeRing value={confidencePct(result) / 100} color={SEV_COLOR[sev]} label={`${confidencePct(result)}%`} sub={result.verdict} size={108} stroke={9} />
            </div>
            <div className="flex items-center justify-center gap-2">
              <VerdictPill verdict={result.verdict} />
              <SeverityBadge sev={sev} />
            </div>
            <div className="text-sm text-slate-300 mt-1">{cat.label}</div>
          </div>

          <div className="mt-3 space-y-1.5">
            <div className="kpi-label">Layer contributions</div>
            {Object.entries(result.contributions).map(([k, v]) => (
              <div key={k} className="flex items-center gap-2">
                <span className="text-[11px] text-slate-400 w-24 capitalize shrink-0">{k}</span>
                <div className="flex-1"><Bar value={v as number} color={(v as number) >= 0.5 ? "#ff4d6d" : "#4f8cff"} /></div>
                <span className="text-[11px] tnum text-slate-400 w-8 text-right">{(v as number).toFixed(2)}</span>
              </div>
            ))}
          </div>

          {result.tripwires.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {result.tripwires.map((t) => <span key={t} className="pill bg-sev-critical/15 text-sev-critical">⚡ {t.split(":")[0]}</span>)}
            </div>
          )}
          {result.reasons.length > 0 && (
            <div className="mt-2 text-[11px] text-slate-500">{result.reasons.join(" · ")}</div>
          )}
        </Panel>
      </div>
    </div>
  );
}
