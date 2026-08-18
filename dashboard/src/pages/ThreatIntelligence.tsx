// Threat Intelligence — turns the live detection stream into intel: top attack
// classes, MITRE ATT&CK technique mapping, source geography, and an IOC feed
// synthesized from real blocked events. Framework coverage references OWASP
// LLM Top-10 and MITRE ATLAS (real, published frameworks).
import { useMemo } from "react";
import { useEvents, computeStats } from "../lib/store";
import { Panel, Bar, EmptyState, KpiCard } from "../components/ui";
import { Icon } from "../components/icons";
import { FLAG } from "../lib/format";
import { SEV_COLOR } from "../lib/taxonomy";
import AttackMap from "../components/AttackMap";

const OWASP_COVERAGE = [
  { id: "LLM01", name: "Prompt Injection", covered: true },
  { id: "LLM02", name: "Insecure Output Handling", covered: true },
  { id: "LLM06", name: "Sensitive Info Disclosure", covered: true },
  { id: "LLM07", name: "System Prompt Leakage", covered: true },
  { id: "LLM10", name: "Unbounded Consumption", covered: true },
];

const ATLAS = [
  { id: "AML.T0051", name: "LLM Prompt Injection", tactic: "Initial Access" },
  { id: "AML.T0054", name: "LLM Jailbreak", tactic: "Defense Evasion" },
  { id: "AML.T0057", name: "LLM Data Leakage", tactic: "Exfiltration" },
  { id: "T1027", name: "Obfuscated Payload", tactic: "Defense Evasion" },
];

export default function ThreatIntelligence() {
  const events = useEvents();
  const stats = useMemo(() => computeStats(events), [events]);

  const mitre = useMemo(() => {
    const m = new Map<string, { id: string; name: string; count: number }>();
    for (const e of events) {
      if (!e.outcome.blocked || !e.category.mitre) continue;
      const k = e.category.mitre.id;
      const cur = m.get(k) ?? { id: k, name: e.category.mitre.name, count: 0 };
      cur.count++;
      m.set(k, cur);
    }
    return [...m.values()].sort((a, b) => b.count - a.count);
  }, [events]);

  const sources = useMemo(() => {
    const m = new Map<string, { cc: string; city: string; count: number }>();
    for (const e of events) {
      if (!e.outcome.blocked) continue;
      const cur = m.get(e.source.cc) ?? { cc: e.source.cc, city: e.source.city, count: 0 };
      cur.count++;
      m.set(e.source.cc, cur);
    }
    return [...m.values()].sort((a, b) => b.count - a.count).slice(0, 8);
  }, [events]);

  // IOC feed: distinct indicators observed in blocked traffic.
  const iocs = useMemo(() => {
    const m = new Map<string, { kind: string; value: string; sev: string; count: number; ts: number }>();
    for (const e of events) {
      if (!e.outcome.blocked) continue;
      const push = (kind: string, value: string) => {
        const key = kind + value;
        const cur = m.get(key) ?? { kind, value, sev: e.severity, count: 0, ts: e.ts };
        cur.count++;
        cur.ts = Math.max(cur.ts, e.ts);
        m.set(key, cur);
      };
      if (e.evasion) push("evasion", e.evasion);
      push("technique", e.category.label);
      for (const t of e.outcome.tripwires ?? []) push("tripwire", t.split(":")[0]);
    }
    return [...m.values()].sort((a, b) => b.ts - a.ts).slice(0, 12);
  }, [events]);

  const maxCat = Math.max(1, ...stats.categories.map((c) => c.count));
  const maxSrc = Math.max(1, ...sources.map((s) => s.count));

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KpiCard label="Unique Techniques" value={mitre.length} icon="target" tone="accent" />
        <KpiCard label="Active Sources" value={sources.length} icon="globe" tone="warn" />
        <KpiCard label="Distinct IOCs" value={iocs.length} icon="radar" tone="danger" />
        <KpiCard label="OWASP Coverage" value={`${OWASP_COVERAGE.length}/10`} icon="shieldCheck" tone="ok" sub="LLM Top-10 classes" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top attack types */}
        <Panel title="Top Attack Types" icon="chart" subtitle="Blocked, by detection category">
          {stats.categories.length === 0 ? (
            <EmptyState icon="chart" title="No attacks recorded yet" />
          ) : (
            <div className="space-y-2.5">
              {stats.categories.slice(0, 7).map((c) => (
                <div key={c.label} className="flex items-center gap-3">
                  <span className="text-xs text-slate-300 w-40 shrink-0 truncate">{c.label}</span>
                  <div className="flex-1"><Bar value={c.count / maxCat} color={c.color} /></div>
                  <span className="text-xs tnum text-slate-400 w-8 text-right">{c.count}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* Attack sources */}
        <Panel title="Attack Sources" icon="globe" subtitle="Origin geography of blocked traffic">
          {sources.length === 0 ? (
            <EmptyState icon="globe" title="No sources yet" />
          ) : (
            <div className="space-y-2.5">
              {sources.map((s) => (
                <div key={s.cc} className="flex items-center gap-3">
                  <span className="text-sm w-6 text-center">{FLAG[s.cc] ?? "🏴"}</span>
                  <span className="text-xs text-slate-300 w-28 shrink-0 truncate">{s.city} ({s.cc})</span>
                  <div className="flex-1"><Bar value={s.count / maxSrc} color="#ff8a3d" /></div>
                  <span className="text-xs tnum text-slate-400 w-8 text-right">{s.count}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {/* MITRE + IOC */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.2fr] gap-4">
        <Panel title="MITRE ATT&CK / ATLAS Mapping" icon="target" subtitle="Observed techniques + framework coverage">
          <div className="grid grid-cols-2 gap-2">
            {(mitre.length ? mitre : ATLAS.map((a) => ({ id: a.id, name: a.name, count: 0 }))).slice(0, 6).map((t) => (
              <div key={t.id} className="rounded-lg p-2.5 bg-white/[0.02] border border-white/[0.06]">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-aegis-cyan">{t.id}</span>
                  {t.count > 0 && <span className="pill bg-sev-critical/15 text-sev-critical">{t.count}</span>}
                </div>
                <div className="text-[11px] text-slate-400 mt-1 leading-tight">{t.name}</div>
              </div>
            ))}
          </div>
          <div className="mt-3 pt-3 border-t border-white/[0.06]">
            <div className="kpi-label mb-2">OWASP LLM Top-10 coverage</div>
            <div className="flex flex-wrap gap-1.5">
              {OWASP_COVERAGE.map((o) => (
                <span key={o.id} className="chip !text-[10px] text-aegis-ok">
                  <Icon name="check" size={11} /> {o.id}
                </span>
              ))}
            </div>
          </div>
        </Panel>

        <Panel title="Indicators of Compromise (IOC)" icon="radar" subtitle="Synthesized from live blocked events">
          {iocs.length === 0 ? (
            <EmptyState icon="radar" title="No indicators yet" hint="Replay attacks or start the live feed." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr>
                    <th className="th">Type</th>
                    <th className="th">Indicator</th>
                    <th className="th text-center">Sev</th>
                    <th className="th text-right">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.map((i, idx) => (
                    <tr key={idx}>
                      <td className="td"><span className="chip !text-[10px] !py-0.5">{i.kind}</span></td>
                      <td className="td font-mono text-[11px] text-slate-300 truncate max-w-[220px]">{i.value}</td>
                      <td className="td text-center">
                        <span className="w-2 h-2 rounded-full inline-block" style={{ background: SEV_COLOR[i.sev as keyof typeof SEV_COLOR] }} />
                      </td>
                      <td className="td text-right tnum text-slate-400">{i.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Global Threat Origins" icon="globe">
        <AttackMap events={events} />
      </Panel>
    </div>
  );
}
