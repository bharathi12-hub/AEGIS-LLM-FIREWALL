// Detection-pipeline visualization. Maps a real engine `Outcome` onto the six
// pipeline stages (Normalization → Rules → ML → LLM Judge → Policy → Decision),
// deriving each stage's score and pass/flag/block status. Two renderers: a
// compact strip and a full animated flow.
import { Fragment } from "react";
import type { Outcome } from "../api";
import { Icon, type IconName } from "./icons";

export interface Stage {
  id: string;
  name: string;
  icon: IconName;
  desc: string;
  score: number; // 0..1 signal strength at this stage
  status: "idle" | "pass" | "flag" | "block" | "skip";
  detail: string;
}

const STATUS_COLOR: Record<Stage["status"], string> = {
  idle: "#64748b",
  pass: "#2dd4a7",
  flag: "#ffb454",
  block: "#ff4d6d",
  skip: "#475569",
};

export function computeStages(o: Outcome | null): Stage[] {
  if (!o) {
    return BLUEPRINT.map((b) => ({ ...b, score: 0, status: "idle" as const, detail: "awaiting input" }));
  }
  const c = o.contributions || {};
  const nrisk = o.normalization?.risk ?? 0;
  const sig = c.signatures ?? 0;
  const ml = Math.max(c.classifiers ?? 0, c.kad ?? 0);
  const blocked = o.blocked;
  const st = (v: number, hi = 0.5): Stage["status"] => (v >= hi ? "flag" : "pass");
  return [
    {
      ...BLUEPRINT[0],
      score: nrisk,
      status: nrisk >= 0.4 ? "flag" : "pass",
      detail: o.normalization?.reasons?.length ? `${o.normalization.reasons.length} evasion(s) stripped` : "clean bytes",
    },
    { ...BLUEPRINT[1], score: sig, status: st(sig), detail: sig >= 0.5 ? "signature match" : "no rule hit" },
    { ...BLUEPRINT[2], score: ml, status: st(ml), detail: ml >= 0.5 ? "classifier flag" : "benign score" },
    {
      ...BLUEPRINT[3],
      score: o.judge_used ? 0.6 : 0,
      status: o.judge_used ? "flag" : "skip",
      detail: o.judge_used ? "escalated to judge" : "not required",
    },
    {
      ...BLUEPRINT[4],
      score: o.score ?? 0,
      status: blocked ? "block" : "pass",
      detail: (o.tripwires?.length ? `${o.tripwires.length} tripwire(s) · ` : "") + `score ${(o.score ?? 0).toFixed(2)}`,
    },
    {
      ...BLUEPRINT[5],
      score: o.score ?? 0,
      status: blocked ? "block" : "pass",
      detail: blocked ? "BLOCKED" : "ALLOWED",
    },
  ];
}

const BLUEPRINT: Omit<Stage, "score" | "status" | "detail">[] = [
  { id: "norm", name: "Normalization", icon: "sparkles", desc: "NFKC + strip unicode smuggling, decode payloads" },
  { id: "rules", name: "Rule Engine", icon: "shield", desc: "Signature & deny-list matching" },
  { id: "ml", name: "ML Ensemble", icon: "cpu", desc: "Dual classifiers + known-attack detector" },
  { id: "judge", name: "LLM Judge", icon: "brain", desc: "Escalation for borderline scores" },
  { id: "policy", name: "Policy Engine", icon: "sliders", desc: "Thresholds, tripwires, per-tenant fail mode" },
  { id: "decision", name: "Decision", icon: "target", desc: "Allow / review / block" },
];

/** Compact horizontal strip for the investigation view. */
export function PipelineStrip({ outcome }: { outcome: Outcome | null }) {
  const stages = computeStages(outcome);
  return (
    <div className="flex items-stretch gap-1 overflow-x-auto pb-1">
      {stages.map((s, i) => {
        const color = STATUS_COLOR[s.status];
        return (
          <Fragment key={s.id}>
            <div className="flex flex-col items-center gap-1 min-w-[84px]">
              <div
                className="grid place-items-center w-9 h-9 rounded-lg"
                style={{ background: `${color}1f`, color, boxShadow: `inset 0 0 0 1px ${color}44` }}
              >
                <Icon name={s.icon} size={16} />
              </div>
              <div className="text-[10px] text-center text-slate-400 leading-tight">{s.name}</div>
              <div className="text-[10px] font-semibold tnum" style={{ color }}>
                {s.status === "skip" ? "skip" : s.status === "idle" ? "—" : s.score.toFixed(2)}
              </div>
            </div>
            {i < stages.length - 1 && (
              <div className="flex items-center pt-3">
                <Icon name="chevronRight" size={14} className="text-slate-600" />
              </div>
            )}
          </Fragment>
        );
      })}
    </div>
  );
}

/** Full animated flow for the dedicated pipeline page. `pulseKey` retriggers the
 *  reveal animation whenever a new prompt is pushed through. */
export function PipelineFlow({ outcome, pulseKey = 0 }: { outcome: Outcome | null; pulseKey?: number }) {
  const stages = computeStages(outcome);
  return (
    <div className="space-y-1" key={pulseKey}>
      {stages.map((s, i) => {
        const color = STATUS_COLOR[s.status];
        const active = s.status !== "idle" && s.status !== "skip";
        return (
          <div key={s.id}>
            <div
              className="flex items-center gap-4 p-3 rounded-xl border animate-slide-up"
              style={{
                animationDelay: `${i * 90}ms`,
                borderColor: `${color}33`,
                background: active ? `${color}0d` : "rgba(255,255,255,0.02)",
              }}
            >
              <div className="grid place-items-center w-11 h-11 rounded-xl shrink-0" style={{ background: `${color}1f`, color }}>
                <Icon name={s.icon} size={20} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-slate-100">{s.name}</span>
                  <span
                    className="pill !text-[9px]"
                    style={{ background: `${color}22`, color, boxShadow: `inset 0 0 0 1px ${color}44` }}
                  >
                    {s.status.toUpperCase()}
                  </span>
                </div>
                <div className="text-xs text-slate-500 mt-0.5">{s.desc}</div>
              </div>
              <div className="w-40 shrink-0 hidden md:block">
                <div className="h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${Math.min(1, s.score) * 100}%`, background: color, transition: "width 600ms" }}
                  />
                </div>
                <div className="text-[10px] text-slate-500 mt-1 text-right">{s.detail}</div>
              </div>
            </div>
            {i < stages.length - 1 && (
              <div className="flex justify-start pl-[26px]">
                <svg width="12" height="20" viewBox="0 0 12 20">
                  <line
                    x1="6" y1="0" x2="6" y2="20"
                    stroke={active ? color : "#334155"}
                    strokeWidth="1.5"
                    strokeDasharray="3 3"
                    className={active ? "animate-flow-dash" : ""}
                  />
                </svg>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
