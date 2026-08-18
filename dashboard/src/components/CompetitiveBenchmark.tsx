// Competitive capability matrix: AEGIS vs named guardrails. Compares documented
// architecture (not fabricated performance numbers). AEGIS's own detection
// results are measured live elsewhere in the dashboard.
import { CAPABILITIES, PRODUCTS, CELL_STYLE, coverageScore } from "../lib/competitors";
import { Icon } from "./icons";

export default function CompetitiveBenchmark() {
  return (
    <div className="space-y-4">
      {/* Coverage summary */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
        {PRODUCTS.map((p) => {
          const score = coverageScore(p);
          const pctc = score / CAPABILITIES.length;
          return (
            <div
              key={p.id}
              className={`rounded-lg p-3 border ${p.self ? "border-aegis-accent/50 bg-aegis-accent/10" : "border-white/[0.06] bg-white/[0.02]"}`}
            >
              <div className="text-xs font-semibold text-slate-100 truncate">{p.name}</div>
              <div className="text-[10px] text-slate-500 mb-2">{p.vendor}</div>
              <div className="flex items-end gap-1">
                <span className={`text-xl font-bold tnum ${p.self ? "text-aegis-accent" : "text-slate-200"}`}>{score}</span>
                <span className="text-[10px] text-slate-500 mb-1">/ {CAPABILITIES.length} layers</span>
              </div>
              <div className="h-1.5 rounded-full bg-white/[0.06] overflow-hidden mt-1">
                <div className="h-full rounded-full" style={{ width: `${pctc * 100}%`, background: p.self ? "#4f8cff" : "#5f6d8f" }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Matrix */}
      <div className="overflow-x-auto -mx-1 px-1">
        <table className="w-full border-collapse min-w-[720px]">
          <thead>
            <tr>
              <th className="th sticky left-0 bg-aegis-panel z-10">Defensive capability</th>
              {PRODUCTS.map((p) => (
                <th key={p.id} className={`th text-center ${p.self ? "text-aegis-accent" : ""}`}>
                  {p.name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {CAPABILITIES.map((cap) => (
              <tr key={cap.key} className={cap.differentiator ? "bg-aegis-accent/[0.04]" : ""}>
                <td className="td sticky left-0 bg-aegis-panel z-10">
                  <div className="flex items-center gap-1.5">
                    {cap.differentiator && <Icon name="sparkles" size={12} className="text-aegis-accent shrink-0" />}
                    <span className="text-xs text-slate-300">{cap.label}</span>
                  </div>
                </td>
                {PRODUCTS.map((p) => {
                  const cell = p.caps[cap.key] ?? "unknown";
                  const s = CELL_STYLE[cell];
                  return (
                    <td key={p.id} className={`td text-center ${p.self ? "bg-aegis-accent/[0.06]" : ""}`}>
                      <span className="font-bold text-sm" style={{ color: s.color }} title={s.title}>{s.glyph}</span>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
        {(["full", "partial", "none", "unknown"] as const).map((c) => (
          <span key={c} className="flex items-center gap-1.5">
            <span className="font-bold" style={{ color: CELL_STYLE[c].color }}>{CELL_STYLE[c].glyph}</span>
            {CELL_STYLE[c].title}
          </span>
        ))}
        <span className="flex items-center gap-1.5"><Icon name="sparkles" size={11} className="text-aegis-accent" /> Platform differentiator</span>
      </div>

      {/* Methodology + sources */}
      <div className="rounded-lg p-3 bg-black/20 border border-white/[0.06]">
        <div className="kpi-label mb-1">Methodology</div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          Comparison reflects each product's <b>publicly documented architecture</b>, not measured detection rates.
          Platform results shown elsewhere in this dashboard are measured live on the evasion set. No competitor
          performance figures are claimed — single-classifier tools (Prompt Guard, DeBERTa) lack a pre-classification
          normalization layer, which is precisely the evasion exposure the benchmark below demonstrates.
        </p>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
          {PRODUCTS.filter((p) => !p.self).map((p) => (
            <span key={p.id} className="text-[10px] text-slate-500">
              <span className="text-slate-400">{p.name}:</span> {p.source}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
