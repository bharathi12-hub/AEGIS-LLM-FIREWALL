// Attack Simulator — the demo control room. One click replays any of the known
// attack classes (optionally wrapped in an evasion transform) through the REAL
// engine and streams the result into the whole SOC. "Launch all" runs the full
// catalog for an instant, repeatable demo.
import { useState } from "react";
import { store, type SecurityEvent } from "../lib/store";
import { ATTACKS, EVASIONS, type AttackVector } from "../lib/attacks";
import { Panel, VerdictPill, SeverityBadge, Spinner, Segmented } from "../components/ui";
import { Icon } from "../components/icons";
import { confidencePct } from "../lib/taxonomy";
import { useNav } from "../lib/nav";
import { useToast } from "../components/Toaster";

export default function AttackSimulator() {
  const { investigate } = useNav();
  const toast = useToast();
  const [evasion, setEvasion] = useState("plain");
  const [results, setResults] = useState<Record<string, SecurityEvent>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);

  async function fire(v: AttackVector) {
    setBusy(v.id);
    try {
      const e = await store.replay(v, evasion);
      setResults((r) => ({ ...r, [v.id]: e }));
      toast({
        kind: e.outcome.blocked ? "success" : "alert",
        title: e.outcome.blocked ? `Blocked: ${v.name}` : `⚠ Allowed: ${v.name}`,
        body: `${e.category.label} · ${confidencePct(e.outcome)}% confidence${e.evasion ? ` · ${e.evasion}` : ""}`,
      });
      return e;
    } finally {
      setBusy(null);
    }
  }

  async function launchAll() {
    setLaunching(true);
    let blocked = 0;
    for (const v of ATTACKS) {
      const e = await fire(v);
      if (e?.outcome.blocked) blocked++;
      await new Promise((r) => setTimeout(r, 260));
    }
    setLaunching(false);
    toast({ kind: "success", title: "Attack campaign complete", body: `${blocked}/${ATTACKS.length} attacks neutralized by LLM Firewall Platform` });
  }

  const total = Object.keys(results).length;
  const blockedCount = Object.values(results).filter((e) => e.outcome.blocked).length;

  return (
    <div className="space-y-4">
      <Panel
        title="Attack Simulator"
        icon="zap"
        subtitle="Replay real attack vectors through the firewall — safe, deterministic, demo-ready"
        action={
          <button className="btn" onClick={launchAll} disabled={launching}>
            {launching ? <Spinner /> : <Icon name="play" size={14} />} Launch all attacks
          </button>
        }
      >
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-xs text-slate-400">Evasion transform:</span>
          <Segmented
            value={evasion}
            onChange={setEvasion}
            options={EVASIONS.map((e) => ({ value: e.id, label: e.label }))}
          />
          {total > 0 && (
            <span className="ml-auto text-xs text-slate-400">
              Neutralized <span className="text-aegis-ok font-semibold">{blockedCount}</span> / {total}
            </span>
          )}
        </div>
      </Panel>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
        {ATTACKS.map((v) => {
          const res = results[v.id];
          return (
            <div key={v.id} className="card p-4 flex flex-col animate-slide-up">
              <div className="flex items-start gap-3">
                <div className="grid place-items-center w-10 h-10 rounded-xl bg-white/[0.04] text-xl shrink-0">
                  {v.icon}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold text-slate-100">{v.name}</div>
                  <div className="text-xs text-slate-500">{v.klass}</div>
                </div>
                {res && <VerdictPill verdict={res.outcome.verdict} />}
              </div>
              <p className="text-xs text-slate-400 mt-2 flex-1">{v.desc}</p>

              {res ? (
                <div className="flex items-center gap-2 mt-3 text-xs">
                  <SeverityBadge sev={res.severity} small />
                  <span className="text-slate-500">{confidencePct(res.outcome)}% conf</span>
                  <span className="text-slate-600">·</span>
                  <span className="text-slate-500">{(res.outcome.latency_ms ?? 0).toFixed(1)}ms</span>
                </div>
              ) : (
                <div className="text-[11px] text-slate-600 mt-3">not yet replayed</div>
              )}

              <div className="flex gap-2 mt-3">
                <button className="btn !py-1.5 flex-1 !text-xs" onClick={() => fire(v)} disabled={busy === v.id}>
                  {busy === v.id ? <Spinner size={13} /> : <Icon name="play" size={13} />} Replay
                </button>
                {res && (
                  <button className="btn-ghost !py-1.5 !text-xs" onClick={() => investigate(res)}>
                    <Icon name="search" size={13} /> Inspect
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
