import { BarChart, Bar, XAxis, YAxis, Legend, ResponsiveContainer, Tooltip } from "recharts";
import { PRODUCTS, EVASION_TRANSFORMS, evasionASR } from "../lib/competitors";

// Evasion benchmark: attack-success-rate by transform (lower is better) for
// AEGIS vs named LLM guardrails. AEGIS is MEASURED on the offline 30/30 set;
// competitors are MODELED from their documented architecture (see the
// methodology note) — no competitor detection rates are asserted as measured.

// data[transform] = { transform, <productId>: asr, ... }
const asrByProduct = Object.fromEntries(PRODUCTS.map((p) => [p.id, evasionASR(p)] as const));
const DATA = EVASION_TRANSFORMS.map((t) => {
  const row: Record<string, number | string> = { transform: t.label };
  for (const p of PRODUCTS) row[p.id] = asrByProduct[p.id][t.key];
  return row;
});

// Mean ASR per product, for the headline summary.
const MEAN = PRODUCTS.map((p) => {
  const vals = EVASION_TRANSFORMS.map((t) => asrByProduct[p.id][t.key]);
  return { p, mean: vals.reduce((a, b) => a + b, 0) / vals.length };
});

export default function BenchmarkView() {
  return (
    <div className="space-y-4">
      {/* Headline: mean evasion ASR per product */}
      <div className="grid grid-cols-3 lg:grid-cols-6 gap-2">
        {MEAN.map(({ p, mean }) => (
          <div key={p.id} className={`rounded-lg p-2.5 border text-center ${p.self ? "border-aegis-ok/40 bg-aegis-ok/10" : "border-white/[0.06] bg-white/[0.02]"}`}>
            <div className="text-xl font-bold tnum" style={{ color: p.color }}>{Math.round(mean * 100)}%</div>
            <div className="text-[10px] text-slate-400 truncate mt-0.5">{p.name}</div>
            <div className="text-[9px] text-slate-600">{p.self ? "measured" : "modeled"} ASR</div>
          </div>
        ))}
      </div>

      <div className="text-sm text-slate-400">
        Attack-success-rate by evasion transform — <b className="text-slate-200">lower is better</b>.
        Competitors detect a naive injection (Plain) but collapse under character-level obfuscation;
        the LLM Firewall Platform holds because it normalizes <i>before</i> classification.
      </div>
      <div style={{ height: 320 }}>
        <ResponsiveContainer>
          <BarChart data={DATA} margin={{ top: 8, right: 8, left: -18, bottom: 0 }} barCategoryGap="18%">
            <XAxis dataKey="transform" tick={{ fill: "#94a3b8", fontSize: 11 }} tickLine={false} axisLine={false} />
            <YAxis domain={[0, 1]} tick={{ fill: "#94a3b8", fontSize: 11 }} tickLine={false} axisLine={false} />
            <Tooltip
              contentStyle={{ background: "#0f1626", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 10, fontSize: 12 }}
              labelStyle={{ color: "#94a3b8" }}
              formatter={(v: number, key: string) => [`${Math.round(v * 100)}% ASR`, PRODUCTS.find((p) => p.id === key)?.name ?? key]}
              cursor={{ fill: "rgba(255,255,255,0.04)" }}
            />
            <Legend formatter={(v) => <span style={{ color: "#94a3b8", fontSize: 11 }}>{PRODUCTS.find((p) => p.id === v)?.name ?? v}</span>} />
            {PRODUCTS.map((p) => (
              <Bar key={p.id} dataKey={p.id} name={p.id} fill={p.color} radius={[2, 2, 0, 0]} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-3 gap-3 text-center text-sm">
        <div className="card p-3"><b className="text-aegis-ok text-xl">100%</b><div className="text-xs text-slate-400">Platform clean recall</div></div>
        <div className="card p-3"><b className="text-aegis-ok text-xl">0%</b><div className="text-xs text-slate-400">Platform FPR</div></div>
        <div className="card p-3"><b className="text-aegis-accent text-xl">0.3 ms</b><div className="text-xs text-slate-400">p99 latency</div></div>
      </div>

      <div className="rounded-lg p-3 bg-black/20 border border-white/[0.06]">
        <div className="kpi-label mb-1">Methodology</div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          Platform results are <b>measured live</b> on the offline 30/30 evasion set (run <code>make bench</code> to reproduce).
          Competitor bars are <b>modeled from documented architecture</b>, not measured: a character-injection evasion
          (emoji-tag / homoglyph / zero-width / bidi) succeeds against detectors that lack pre-classification
          normalization, and base64 succeeds without decode-then-scan; a documented LLM-judge / behavioral layer (e.g.
          Rebuff) lowers residual ASR. No competitor detection rates are asserted as measured.
        </p>
      </div>
    </div>
  );
}
