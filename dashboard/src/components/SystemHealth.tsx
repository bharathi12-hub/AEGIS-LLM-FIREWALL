// System-health panel (CPU / Memory / Queue / Throughput). Values are SIMULATED
// — clearly labeled — and drift with a small random walk, nudged upward by live
// attack pressure so the panel feels alive and correlated during a demo. No real
// host metrics are available in the offline dashboard.
import { useEffect, useRef, useState } from "react";
import { Panel, Sparkline } from "./ui";
import { Icon, type IconName } from "./icons";

interface Metric {
  key: string;
  label: string;
  icon: IconName;
  value: number;
  unit: string;
  max: number;
  hist: number[];
}

function color(pct: number): string {
  if (pct >= 0.85) return "#ff4d6d";
  if (pct >= 0.65) return "#ffb454";
  return "#2dd4a7";
}

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));

export default function SystemHealth({ activeAttacks }: { activeAttacks: number }) {
  const [metrics, setMetrics] = useState<Metric[]>(() => [
    { key: "cpu", label: "CPU", icon: "cpu", value: 32, unit: "%", max: 100, hist: [] },
    { key: "mem", label: "Memory", icon: "database", value: 54, unit: "%", max: 100, hist: [] },
    { key: "queue", label: "Queue", icon: "layers", value: 6, unit: "", max: 60, hist: [] },
    { key: "tps", label: "Throughput", icon: "activity", value: 340, unit: "/s", max: 800, hist: [] },
  ]);
  const load = useRef(activeAttacks);
  load.current = activeAttacks;

  useEffect(() => {
    const id = setInterval(() => {
      setMetrics((cur) =>
        cur.map((m) => {
          const a = load.current;
          let v = m.value;
          const jitter = (Math.random() - 0.5) * 2;
          if (m.key === "cpu") v = clamp(28 + a * 4 + jitter * 6, 8, 96);
          else if (m.key === "mem") v = clamp(m.value + jitter * 2 + (a > 4 ? 1 : -0.4), 40, 88);
          else if (m.key === "queue") v = clamp(Math.round(a * 1.6 + Math.random() * 6), 0, 60);
          else v = clamp(300 + a * 22 + jitter * 40, 120, 780);
          return { ...m, value: Math.round(v), hist: [...m.hist, v].slice(-24) };
        }),
      );
    }, 1500);
    return () => clearInterval(id);
  }, []);

  return (
    <Panel
      title="System Health"
      icon="server"
      subtitle="Resource utilization"
      action={<span className="chip !py-0.5 !px-2 !text-[10px] text-aegis-warn">simulated</span>}
    >
      <div className="grid grid-cols-2 gap-3">
        {metrics.map((m) => {
          const pct = m.value / m.max;
          const c = color(pct);
          return (
            <div key={m.key} className="rounded-lg p-2.5 bg-white/[0.02] border border-white/[0.06]">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-[11px] text-slate-400">
                  <Icon name={m.icon} size={12} /> {m.label}
                </span>
                <span className="text-sm font-bold tnum" style={{ color: c }}>
                  {m.value}
                  <span className="text-[10px] text-slate-500 ml-0.5">{m.unit}</span>
                </span>
              </div>
              <div className="mt-1.5">
                <Sparkline data={m.hist} color={c} height={22} />
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
