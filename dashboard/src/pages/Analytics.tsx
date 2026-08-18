// Analytics — trends and breakdowns over the live event history: attack trend,
// detection rate, severity mix, top applications & users, and a latency
// distribution. All derived from real detection outcomes.
import { useMemo, useState } from "react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { useEvents, computeStats, timeseries } from "../lib/store";
import { Panel, KpiCard, GaugeRing, Bar as MeterBar, Segmented, EmptyState } from "../components/ui";
import { SEVERITY_ORDER, SEV_COLOR } from "../lib/taxonomy";
import { pct } from "../lib/format";

type Range = "1h" | "24h" | "7d";
const RANGE: Record<Range, { span: number; buckets: number }> = {
  "1h": { span: 60 * 60 * 1000, buckets: 20 },
  "24h": { span: 24 * 60 * 60 * 1000, buckets: 24 },
  "7d": { span: 7 * 24 * 60 * 60 * 1000, buckets: 14 },
};

export default function Analytics() {
  const events = useEvents();
  const [range, setRange] = useState<Range>("24h");
  const stats = useMemo(() => computeStats(events), [events]);

  const series = useMemo(() => {
    const { span, buckets } = RANGE[range];
    return timeseries(events, buckets, span);
  }, [events, range]);

  const topApps = useMemo(() => {
    const m = new Map<string, { app: string; total: number; blocked: number }>();
    for (const e of events) {
      const cur = m.get(e.app) ?? { app: e.app, total: 0, blocked: 0 };
      cur.total++;
      if (e.outcome.blocked) cur.blocked++;
      m.set(e.app, cur);
    }
    return [...m.values()].sort((a, b) => b.total - a.total).slice(0, 6);
  }, [events]);

  const topUsers = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of events) if (e.outcome.blocked) m.set(e.user, (m.get(e.user) ?? 0) + 1);
    return [...m.entries()].map(([user, n]) => ({ user, n })).sort((a, b) => b.n - a.n).slice(0, 6);
  }, [events]);

  const latencyHist = useMemo(() => {
    const buckets = [
      { label: "<0.2ms", lo: 0, hi: 0.2, n: 0 },
      { label: "0.2–0.5", lo: 0.2, hi: 0.5, n: 0 },
      { label: "0.5–1", lo: 0.5, hi: 1, n: 0 },
      { label: "1–2", lo: 1, hi: 2, n: 0 },
      { label: "2–5", lo: 2, hi: 5, n: 0 },
      { label: "5ms+", lo: 5, hi: Infinity, n: 0 },
    ];
    for (const e of events) {
      const l = e.outcome.latency_ms ?? 0;
      const b = buckets.find((x) => l >= x.lo && l < x.hi);
      if (b) b.n++;
    }
    return buckets;
  }, [events]);

  const sevData = SEVERITY_ORDER.map((s) => ({ name: s, value: stats.severity[s], color: SEV_COLOR[s] })).filter((d) => d.value > 0);
  const maxApp = Math.max(1, ...topApps.map((a) => a.total));
  const maxUser = Math.max(1, ...topUsers.map((u) => u.n));

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KpiCard label="Total Inspected" value={stats.total} icon="activity" tone="accent" />
        <KpiCard label="Blocked" value={stats.blocked} icon="ban" tone="danger" />
        <KpiCard label="Detection Rate" value={pct(stats.detectionRate, 0)} icon="target" tone="ok" />
        <KpiCard label="p95 Latency" value={`${stats.p95Latency.toFixed(1)}ms`} icon="clock" tone="warn" />
      </div>

      {/* Trend */}
      <Panel
        title="Attack Trend"
        icon="chart"
        subtitle="Inspected vs blocked over time"
        action={<Segmented value={range} onChange={setRange} options={[{ value: "1h", label: "1H" }, { value: "24h", label: "24H" }, { value: "7d", label: "7D" }]} />}
      >
        <div style={{ height: 220 }}>
          <ResponsiveContainer>
            <AreaChart data={series} margin={{ top: 6, right: 8, left: -16, bottom: 0 }}>
              <defs>
                <linearGradient id="aTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#4f8cff" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#4f8cff" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="aBlock" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ff4d6d" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#ff4d6d" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(255,255,255,0.04)" vertical={false} />
              <XAxis dataKey="label" tick={{ fill: "#64748b", fontSize: 10 }} interval="preserveStartEnd" tickLine={false} axisLine={false} />
              <YAxis tick={{ fill: "#64748b", fontSize: 10 }} tickLine={false} axisLine={false} width={28} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "#0f1626", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 10, fontSize: 12 }} labelStyle={{ color: "#94a3b8" }} />
              <Area type="monotone" dataKey="total" name="inspected" stroke="#4f8cff" strokeWidth={2} fill="url(#aTotal)" />
              <Area type="monotone" dataKey="blocked" name="blocked" stroke="#ff4d6d" strokeWidth={2} fill="url(#aBlock)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </Panel>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Detection rate + severity mix */}
        <Panel title="Detection Overview" icon="shieldCheck">
          <div className="flex items-center gap-4">
            <GaugeRing value={stats.detectionRate} color="#2dd4a7" label={pct(stats.detectionRate, 0)} sub="block rate" size={116} />
            <div className="flex-1 space-y-1.5">
              {sevData.length === 0 ? (
                <div className="text-xs text-slate-500">No severity data yet.</div>
              ) : (
                sevData.map((d) => (
                  <div key={d.name} className="flex items-center gap-2">
                    <span className="text-[11px] capitalize w-14 text-slate-400">{d.name}</span>
                    <div className="flex-1"><MeterBar value={d.value / stats.total} color={d.color} /></div>
                    <span className="text-[11px] tnum text-slate-400 w-6 text-right">{d.value}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </Panel>

        {/* Latency distribution */}
        <Panel title="Model Performance" icon="cpu" subtitle="Detection latency distribution">
          <div style={{ height: 160 }}>
            <ResponsiveContainer>
              <BarChart data={latencyHist} margin={{ top: 6, right: 6, left: -20, bottom: 0 }}>
                <XAxis dataKey="label" tick={{ fill: "#64748b", fontSize: 9 }} tickLine={false} axisLine={false} interval={0} angle={-12} dy={6} height={30} />
                <YAxis tick={{ fill: "#64748b", fontSize: 10 }} tickLine={false} axisLine={false} width={28} allowDecimals={false} />
                <Tooltip cursor={{ fill: "rgba(255,255,255,0.04)" }} contentStyle={{ background: "#0f1626", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 10, fontSize: 12 }} />
                <Bar dataKey="n" radius={[4, 4, 0, 0]}>
                  {latencyHist.map((_, i) => (
                    <Cell key={i} fill={i < 3 ? "#2dd4a7" : i < 5 ? "#ffb454" : "#ff4d6d"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        {/* Top applications */}
        <Panel title="Top Applications" icon="layers" subtitle="Traffic by protected surface">
          {topApps.length === 0 ? (
            <EmptyState icon="layers" title="No traffic yet" />
          ) : (
            <div className="space-y-2.5">
              {topApps.map((a) => (
                <div key={a.app}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-slate-300 truncate">{a.app}</span>
                    <span className="text-slate-500 tnum">{a.total} · <span className="text-sev-critical">{a.blocked} blk</span></span>
                  </div>
                  <MeterBar value={a.total / maxApp} color="#4f8cff" />
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {/* Top users */}
      <Panel title="Top Offending Users / Keys" icon="users" subtitle="Sessions with the most blocked requests">
        {topUsers.length === 0 ? (
          <EmptyState icon="users" title="No flagged users yet" />
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {topUsers.map((u) => (
              <div key={u.user} className="rounded-lg p-3 bg-white/[0.02] border border-white/[0.06] text-center">
                <div className="text-lg font-bold tnum text-sev-critical">{u.n}</div>
                <div className="text-[11px] text-slate-400 font-mono truncate">{u.user}</div>
                <MeterBar value={u.n / maxUser} color="#ff4d6d" />
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
