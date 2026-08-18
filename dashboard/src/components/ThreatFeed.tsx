import { useEffect, useState } from "react";
import { auditFeed } from "../api";

// Values from the audit trail are already server-side sanitized (S6); React also
// escapes by default, so rendering them as text is safe.
export default function ThreatFeed() {
  const [rows, setRows] = useState<any[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    const load = () => auditFeed().then((r) => setRows(r.slice().reverse())).catch((e) => setErr(String(e.message || e)));
    load();
    const id = setInterval(load, 3000);
    return () => clearInterval(id);
  }, []);

  if (err) return <div className="card text-aegis-danger text-sm">{err}</div>;
  return (
    <div className="card">
      <div className="text-sm text-slate-400 mb-2">Live security events (tenant-scoped)</div>
      <div className="space-y-1 max-h-96 overflow-auto text-sm">
        {rows.length === 0 && <div className="text-slate-500">No events yet — inspect a prompt.</div>}
        {rows.map((r) => (
          <div key={r.seq} className="flex items-center gap-2 border-b border-white/5 py-1">
            <span className="text-xs text-slate-600 w-8">#{r.seq}</span>
            <span className={`pill text-black ${r.verdict === "block" ? "bg-aegis-danger" : "bg-aegis-ok"}`}>
              {r.verdict}
            </span>
            <span className="text-xs text-slate-400">{r.layer}</span>
            <span className="text-xs text-slate-300 truncate flex-1">{r.reason}</span>
            <code className="text-[10px] text-slate-600">{r.record_hash}</code>
          </div>
        ))}
      </div>
    </div>
  );
}
