import { useEffect, useState } from "react";
import { verifyChain } from "../api";

export default function AuditView() {
  const [state, setState] = useState<any>(null);
  const [err, setErr] = useState("");

  function check() {
    verifyChain().then(setState).catch((e) => setErr(String(e.message || e)));
  }
  useEffect(check, []);

  return (
    <div className="card space-y-3">
      <div className="text-sm text-slate-400">Immutable audit — hash-chained, tamper-evident (S6/S7/S13)</div>
      <button className="btn" onClick={check}>Verify chain integrity</button>
      {err && <div className="text-aegis-danger text-sm">{err}</div>}
      {state && (
        <div className="flex items-center gap-4">
          <span className={`pill text-black ${state.chain_ok ? "bg-aegis-ok" : "bg-aegis-danger"}`}>
            {state.chain_ok ? "CHAIN VALID" : `TAMPERED @ #${state.first_bad_seq}`}
          </span>
          <span className="text-sm text-slate-400">{state.records} records</span>
        </div>
      )}
      <p className="text-xs text-slate-500">
        Each record's hash covers its content plus the previous record's hash, so any
        edit or deletion breaks the chain. Raw prompts are never stored — only a
        salted digest and a PII-redacted reason.
      </p>
    </div>
  );
}
