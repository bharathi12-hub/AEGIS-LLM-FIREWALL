import { useEffect, useState } from "react";
import { getPolicy, setPolicy } from "../api";

export default function PolicyEditor() {
  const [current, setCurrent] = useState<any>(null);
  const [yaml, setYaml] = useState("block_threshold: 0.75\nreview_threshold: 0.45\nfail_mode: closed");
  const [msg, setMsg] = useState("");

  function load() {
    getPolicy().then(setCurrent).catch((e) => setMsg(String(e.message || e)));
  }
  useEffect(load, []);

  async function save() {
    setMsg("");
    try {
      const r = await setPolicy(yaml);
      setMsg(`Applied policy v${r.version}`);
      load();
    } catch (e: any) {
      setMsg(String(e.message || e)); // validation errors (422) surface here (S13)
    }
  }

  return (
    <div className="grid md:grid-cols-2 gap-4">
      <div className="card space-y-2">
        <div className="text-sm text-slate-400">Edit policy YAML (validated, versioned, audited)</div>
        <textarea rows={8} value={yaml} onChange={(e) => setYaml(e.target.value)} className="font-mono text-xs" />
        <button className="btn" onClick={save}>Apply (hot reload)</button>
        {msg && <div className="text-sm text-aegis-warn">{msg}</div>}
      </div>
      <div className="card">
        <div className="text-sm text-slate-400 mb-2">Effective policy</div>
        {current ? (
          <pre className="text-xs text-slate-300 whitespace-pre-wrap">{JSON.stringify(current, null, 2)}</pre>
        ) : <div className="text-slate-500">Set an admin key to load.</div>}
      </div>
    </div>
  );
}
