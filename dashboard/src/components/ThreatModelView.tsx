const ROWS: [string, string, string][] = [
  ["S1", "Judge injection", "Data-not-instructions harness, JSON-only, off-schema ⇒ fail-closed"],
  ["S2", "Parser differential / TOCTOU", "Inspected bytes == forwarded bytes (parity test)"],
  ["S3", "Model supply chain", "safetensors-only, checksum pinning, CI scan"],
  ["S4", "Fail-open vs fail-closed", "Per-tenant; high-sec blocks on error, others alarm"],
  ["S5", "DoS / resource abuse", "Token-bucket rate limit + per-tenant judge budget + caps"],
  ["S6", "Log / dashboard XSS", "Store digest, render escaped, strip control chars"],
  ["S7", "PII at rest", "Raw prompt never stored; digest + redaction; optional encryption"],
  ["S8", "Auth / tenant isolation", "Hashed keys, rotation, cross-tenant reads denied"],
  ["S9", "Timing side-channel", "Response timing floor + jitter"],
  ["S10", "Secrets / transport", "Env secrets, separate admin key, CORS locked, headers"],
  ["S11", "Canary unpredictability", "High-entropy per-request/session, never logged clear"],
  ["S12", "Output DLP evasion", "Decode-then-scan output (base64/hex/rot13)"],
  ["S13", "Policy tampering", "Schema-validated, versioned, audited changes"],
  ["S14", "Prompt-stuffing / overflow", "Safe cap + truncate before scanning"],
];

export default function ThreatModelView() {
  return (
    <div className="card">
      <div className="text-sm text-slate-400 mb-3">
        Firewall self-security — the appliance defends its own attack surface (S1–S14).
        Every row has a mitigation and a test (see docs/THREAT_MODEL.md).
      </div>
      <table className="w-full text-sm">
        <tbody>
          {ROWS.map(([id, threat, mit]) => (
            <tr key={id} className="border-t border-white/5">
              <td className="py-2 pr-2 font-mono text-aegis-accent">{id}</td>
              <td className="pr-3 font-medium">{threat}</td>
              <td className="text-slate-400 text-xs">{mit}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
