// Detection quality metrics — MEASURED on the offline 30/30 curated evasion set
// (30 adversarial + 30 benign): 100% recall / 0% FPR. Precision/Recall/F1 and the
// confusion matrix follow directly from that result. Throughput/latency come from
// the local load test. These are real numbers; full public-dataset evaluation is
// a documented remaining gap (see docs/PRODUCTION.md) and is NOT claimed here.
import { Icon } from "./icons";

// Confusion matrix on the curated set.
const TP = 30, FN = 0, FP = 0, TN = 30;
const precision = TP / (TP + FP); // 1.0
const recall = TP / (TP + FN); // 1.0
const f1 = (2 * precision * recall) / (precision + recall); // 1.0
const accuracy = (TP + TN) / (TP + TN + FP + FN); // 1.0

const pctOf = (v: number) => `${(v * 100).toFixed(0)}%`;

const TILES: { label: string; value: string; tone: string; hint?: string }[] = [
  { label: "Precision", value: pctOf(precision), tone: "#2dd4a7" },
  { label: "Recall", value: pctOf(recall), tone: "#2dd4a7" },
  { label: "F1 Score", value: pctOf(f1), tone: "#2dd4a7" },
  { label: "Accuracy", value: pctOf(accuracy), tone: "#4f8cff" },
  { label: "False Positives", value: String(FP), tone: "#2dd4a7", hint: "on 30 benign" },
  { label: "False Negatives", value: String(FN), tone: "#2dd4a7", hint: "on 30 attacks" },
  { label: "p99 Latency", value: "0.3 ms", tone: "#4f8cff", hint: "detection" },
  { label: "Throughput", value: "657 rps", tone: "#4f8cff", hint: "1 worker, load test" },
];

const cell = (v: number, good: boolean, label: string) => (
  <div className="rounded-lg p-3 text-center" style={{ background: good ? "rgba(45,212,167,0.1)" : "rgba(255,77,109,0.1)", boxShadow: `inset 0 0 0 1px ${good ? "rgba(45,212,167,0.3)" : "rgba(255,77,109,0.3)"}` }}>
    <div className="text-xl font-bold tnum" style={{ color: good ? "#2dd4a7" : "#ff4d6d" }}>{v}</div>
    <div className="text-[10px] text-slate-400">{label}</div>
  </div>
);

export default function BenchmarkMetrics() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {TILES.map((t) => (
          <div key={t.label} className="rounded-lg p-3 bg-white/[0.02] border border-white/[0.06]">
            <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">{t.label}</div>
            <div className="text-2xl font-bold tnum mt-1" style={{ color: t.tone }}>{t.value}</div>
            {t.hint && <div className="text-[10px] text-slate-600">{t.hint}</div>}
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-[auto_1fr] gap-4 items-center">
        <div>
          <div className="kpi-label mb-2">Confusion matrix (60 samples)</div>
          <div className="grid grid-cols-[auto_1fr_1fr] gap-1.5 items-center">
            <div />
            <div className="text-[10px] text-slate-500 text-center">Pred +</div>
            <div className="text-[10px] text-slate-500 text-center">Pred −</div>
            <div className="text-[10px] text-slate-500 self-center">Actual +</div>
            {cell(TP, true, "TP")}
            {cell(FN, FN === 0, "FN")}
            <div className="text-[10px] text-slate-500 self-center">Actual −</div>
            {cell(FP, FP === 0, "FP")}
            {cell(TN, true, "TN")}
          </div>
        </div>
        <div className="rounded-lg p-3 bg-black/20 border border-white/[0.06] self-stretch flex items-center">
          <p className="text-[11px] text-slate-400 leading-relaxed">
            <Icon name="check" size={12} className="inline text-aegis-ok mr-1" />
            Measured on the curated <b>30 adversarial / 30 benign</b> evasion set — 100% recall, 0% false-positive rate.
            Precision, recall and F1 follow from the confusion matrix. Throughput and latency are from the local load
            test (peppered API keys). Evaluation on full public datasets is a documented remaining gap and is not claimed here.
          </p>
        </div>
      </div>
    </div>
  );
}
