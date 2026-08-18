// Real-time attack map. Renders a stylized equirectangular world field with a
// dot-grid + graticule, plots recent threat sources by geography, and draws
// animated attack arcs converging on the protected "AEGIS core". Arc color
// encodes severity. Purely presentational — driven by the live event stream.
import { useMemo } from "react";
import type { SecurityEvent } from "../lib/store";
import { GEO, FLAG } from "../lib/format";
import { SEV_COLOR } from "../lib/taxonomy";

const VW = 100;
const VH = 56;
const CX = 50;
const CY = 27;
const sy = (y: number) => (y / 100) * VH;

export default function AttackMap({ events, max = 14 }: { events: SecurityEvent[]; max?: number }) {
  const blocked = useMemo(() => events.filter((e) => e.outcome.blocked).slice(0, max), [events, max]);

  // Count attacks per source for marker sizing / hotspot intensity.
  const heat = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of events) if (e.outcome.blocked) m.set(e.source.cc, (m.get(e.source.cc) ?? 0) + 1);
    return m;
  }, [events]);

  const dots = useMemo(() => {
    const arr: [number, number][] = [];
    for (let x = 4; x < VW; x += 4) for (let y = 4; y < VH; y += 3.4) arr.push([x, y]);
    return arr;
  }, []);

  return (
    <div className="relative w-full">
      <svg viewBox={`0 0 ${VW} ${VH}`} className="w-full" style={{ display: "block" }}>
        <defs>
          <radialGradient id="core-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#4f8cff" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#4f8cff" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* dot-grid backdrop */}
        <g fill="rgba(255,255,255,0.06)">
          {dots.map(([x, y], i) => (
            <circle key={i} cx={x} cy={y} r={0.28} />
          ))}
        </g>
        {/* graticule */}
        <g stroke="rgba(79,140,255,0.08)" strokeWidth={0.15}>
          {[14, 28, 42].map((y) => (
            <line key={y} x1={0} y1={y} x2={VW} y2={y} />
          ))}
          {[20, 40, 60, 80].map((x) => (
            <line key={x} x1={x} y1={0} x2={x} y2={VH} />
          ))}
        </g>

        {/* attack arcs */}
        <g fill="none" strokeWidth={0.4} strokeLinecap="round">
          {blocked.map((e, i) => {
            const s = e.source;
            const sX = s.x;
            const sYY = sy(s.y);
            const cx = (sX + CX) / 2;
            const cy = (sYY + CY) / 2 - Math.hypot(sX - CX, sYY - CY) * 0.28;
            const color = SEV_COLOR[e.severity];
            const opacity = Math.max(0.15, 1 - i / max);
            return (
              <g key={e.id} opacity={opacity}>
                <path
                  d={`M${sX} ${sYY} Q${cx} ${cy} ${CX} ${CY}`}
                  stroke={color}
                  strokeOpacity={0.5}
                  strokeDasharray="1.4 2.2"
                  className={i < 6 ? "animate-flow-dash" : ""}
                />
              </g>
            );
          })}
        </g>

        {/* source markers */}
        <g>
          {GEO.map((g) => {
            const n = heat.get(g.cc) ?? 0;
            if (n === 0) return null;
            const r = Math.min(1.6, 0.6 + n * 0.12);
            return (
              <g key={g.cc}>
                <circle cx={g.x} cy={sy(g.y)} r={r + 1.2} fill="#ff4d6d" opacity={0.12} className="animate-blip" />
                <circle cx={g.x} cy={sy(g.y)} r={r} fill="#ff6b85" />
              </g>
            );
          })}
        </g>

        {/* protected core */}
        <g>
          <circle cx={CX} cy={CY} r={6} fill="url(#core-glow)" />
          <circle cx={CX} cy={CY} r={2.6} fill="none" stroke="#4f8cff" strokeWidth={0.3} className="animate-pulse-ring" />
          <circle cx={CX} cy={CY} r={1.4} fill="#4f8cff" />
          <circle cx={CX} cy={CY} r={0.6} fill="#e6ecf7" />
        </g>
      </svg>

      {/* Top-source legend overlaid bottom-left */}
      <div className="absolute left-2 bottom-2 flex flex-wrap gap-1.5">
        {[...heat.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 4)
          .map(([cc, n]) => (
            <span key={cc} className="chip !py-0.5 !px-2 !text-[10px]">
              {FLAG[cc] ?? "🏴"} {cc} · {n}
            </span>
          ))}
      </div>
    </div>
  );
}
