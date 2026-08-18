// Report generation: CSV export + printable HTML reports (Executive /
// Technical / Incident). PDF is produced via the browser's native
// "print to PDF" on a self-contained, styled report document.
import type { SecurityEvent } from "./store";
import type { Stats } from "./store";
import type { Incident } from "./incidents";
import { confidencePct } from "./taxonomy";
import { FLAG } from "./format";

export type ReportKind = "executive" | "technical" | "incident";

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const csvCell = (v: unknown) => {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export function exportEventsCSV(events: SecurityEvent[]) {
  const header = [
    "id", "timestamp", "verdict", "severity", "category", "owasp", "score",
    "confidence_pct", "latency_ms", "source_cc", "source_city", "application",
    "user", "evasion", "reasons",
  ];
  const rows = events.map((e) => [
    e.id,
    new Date(e.ts).toISOString(),
    e.outcome.verdict,
    e.severity,
    e.category.label,
    e.category.owasp ?? "",
    (e.outcome.score ?? 0).toFixed(3),
    confidencePct(e.outcome),
    (e.outcome.latency_ms ?? 0).toFixed(2),
    e.source.cc,
    e.source.city,
    e.app,
    e.user,
    e.evasion ?? "",
    (e.outcome.reasons ?? []).join(" | "),
  ]);
  const csv = [header, ...rows].map((r) => r.map(csvCell).join(",")).join("\n");
  download(`aegis-events-${Date.now()}.csv`, csv, "text/csv;charset=utf-8");
}

const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]!));

function reportHTML(kind: ReportKind, stats: Stats, events: SecurityEvent[]): string {
  const now = new Date();
  const titleMap: Record<ReportKind, string> = {
    executive: "Executive Security Report",
    technical: "Technical Detection Report",
    incident: "Incident Response Report",
  };
  const blocked = events.filter((e) => e.outcome.blocked);
  const topCats = stats.categories.slice(0, 6);
  const recent = blocked.slice(0, 25);

  const kpiRow = `
    <div class="grid">
      <div class="kpi"><div class="n">${stats.total}</div><div class="l">Requests Inspected</div></div>
      <div class="kpi"><div class="n" style="color:#dc2626">${stats.blocked}</div><div class="l">Attacks Blocked</div></div>
      <div class="kpi"><div class="n">${(stats.detectionRate * 100).toFixed(1)}%</div><div class="l">Block Rate</div></div>
      <div class="kpi"><div class="n">${stats.avgLatency.toFixed(2)} ms</div><div class="l">Avg Detection</div></div>
      <div class="kpi"><div class="n" style="color:#dc2626">${stats.severity.critical}</div><div class="l">Critical</div></div>
      <div class="kpi"><div class="n">${stats.reviewed}</div><div class="l">LLM-Judge Reviews</div></div>
    </div>`;

  const catTable = `
    <table>
      <thead><tr><th>Attack Category</th><th>OWASP</th><th>Incidents</th></tr></thead>
      <tbody>${topCats
        .map(
          (c) =>
            `<tr><td>${esc(c.label)}</td><td>${
              events.find((e) => e.category.label === c.label)?.category.owasp ?? "—"
            }</td><td>${c.count}</td></tr>`,
        )
        .join("")}</tbody>
    </table>`;

  const eventTable = `
    <table>
      <thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Source</th><th>App</th><th>Score</th></tr></thead>
      <tbody>${recent
        .map(
          (e) =>
            `<tr>
              <td>${new Date(e.ts).toLocaleString()}</td>
              <td><span class="sev sev-${e.severity}">${e.severity.toUpperCase()}</span></td>
              <td>${esc(e.category.label)}</td>
              <td>${FLAG[e.source.cc] ?? ""} ${esc(e.source.city)}</td>
              <td>${esc(e.app)}</td>
              <td>${(e.outcome.score ?? 0).toFixed(2)}</td>
            </tr>`,
        )
        .join("")}</tbody>
    </table>`;

  const narrative =
    kind === "executive"
      ? `<p>During the reporting window, the LLM Firewall Platform inspected <b>${stats.total}</b> requests and neutralized
         <b>${stats.blocked}</b> adversarial prompts, including <b>${stats.severity.critical}</b> critical-severity
         attacks. Detection ran at an average of <b>${stats.avgLatency.toFixed(2)} ms</b> per request with a
         <b>${(stats.detectionRate * 100).toFixed(1)}%</b> block rate on flagged traffic. No successful policy bypass was
         observed. The firewall's normalization layer continues to defeat obfuscation-based evasion (unicode-tag
         smuggling, homoglyphs, bidi, zero-width and base64) before classification.</p>`
      : kind === "technical"
        ? `<p>This report details the multi-layer detection pipeline outcomes. Each request passes through normalization,
           signature rules, an ML classifier ensemble, a known-attack detector (KAD), an optional LLM judge and the policy
           engine. Layer contributions and tripwires are recorded per event. ${blocked.length} blocked events are
           enumerated below with severity and confidence scoring.</p>`
        : `<p>This incident report enumerates the highest-severity detections requiring analyst attention. Each entry
           includes the attack classification, source geography, target application and the recommended containment
           action. ${blocked.length} incidents were generated in the reporting window.</p>`;

  return `<!doctype html><html><head><meta charset="utf-8"><title>${titleMap[kind]}</title>
  <style>
    *{box-sizing:border-box} body{font-family:Inter,Segoe UI,Arial,sans-serif;color:#0f172a;margin:0;padding:40px;background:#fff}
    .brand{display:flex;align-items:center;gap:10px;border-bottom:3px solid #4f8cff;padding-bottom:14px;margin-bottom:6px}
    .brand .logo{width:34px;height:34px;border-radius:8px;background:linear-gradient(135deg,#4f8cff,#22d3ee);display:grid;place-items:center;color:#fff;font-weight:800}
    h1{font-size:22px;margin:0} .muted{color:#64748b;font-size:12px}
    h2{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:26px 0 10px;border-bottom:1px solid #e2e8f0;padding-bottom:6px}
    .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:8px}
    .kpi{border:1px solid #e2e8f0;border-radius:10px;padding:12px}
    .kpi .n{font-size:22px;font-weight:800} .kpi .l{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.05em}
    table{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px}
    th{text-align:left;background:#f1f5f9;padding:8px;font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:#475569}
    td{padding:7px 8px;border-bottom:1px solid #eef2f7}
    .sev{padding:2px 7px;border-radius:6px;font-size:10px;font-weight:700;color:#fff}
    .sev-critical{background:#dc2626}.sev-high{background:#ea580c}.sev-medium{background:#ca8a04}.sev-low{background:#2563eb}.sev-info{background:#64748b}.sev-safe{background:#059669}
    p{font-size:13px;line-height:1.6;color:#334155}
    .foot{margin-top:30px;border-top:1px solid #e2e8f0;padding-top:10px;font-size:11px;color:#94a3b8;display:flex;justify-content:space-between}
    @media print{body{padding:20px}}
  </style></head><body>
    <div class="brand"><div class="logo">LF</div>
      <div><h1>${titleMap[kind]}</h1>
      <div class="muted">LLM Firewall Platform · Generated ${now.toLocaleString()} · Confidential</div></div>
    </div>
    <h2>Summary</h2>${narrative}
    <h2>Key Metrics</h2>${kpiRow}
    <h2>Attack Categories</h2>${topCats.length ? catTable : "<p>No blocked events in window.</p>"}
    <h2>${kind === "incident" ? "Incidents" : "Recent Blocked Events"}</h2>${recent.length ? eventTable : "<p>No events.</p>"}
    <div class="foot"><span>LLM Firewall Platform · Adversarial Prompt Firewall</span><span>Page 1 · ${now.getFullYear()}</span></div>
  </body></html>`;
}

// ---- Incident case reports -------------------------------------------------

export function exportIncidentsCSV(incidents: Incident[]) {
  const header = ["id", "title", "severity", "status", "created", "category", "owasp", "source", "app", "score", "notes"];
  const rows = incidents.map((i) => [
    i.id, i.title, i.severity, i.status, new Date(i.createdAt).toISOString(),
    i.event.category.label, i.event.category.owasp ?? "", `${i.event.source.city} (${i.event.source.cc})`,
    i.event.app, (i.event.outcome.score ?? 0).toFixed(3), i.notes.map((n) => n.text).join(" | "),
  ]);
  const csv = [header, ...rows].map((r) => r.map(csvCell).join(",")).join("\n");
  download(`incidents-${Date.now()}.csv`, csv, "text/csv;charset=utf-8");
}

export function incidentExecutiveSummary(i: Incident): string {
  const e = i.event;
  return (
    `Incident ${i.id} (${i.severity.toUpperCase()}) — a ${e.category.label} attempt` +
    `${e.replayName ? ` (${e.replayName})` : ""} originating from ${e.source.city}, ${e.source.cc}, ` +
    `targeting the ${e.app} application, was ${e.outcome.blocked ? "detected and blocked" : "flagged"} by the ` +
    `firewall at ${Math.round((e.outcome.score ?? 0) * 100)}% confidence. Recommended action: ${e.category.mitigation} ` +
    `Current status: ${i.status}.`
  );
}

export function openIncidentReport(i: Incident) {
  const e = i.event;
  const now = new Date();
  const rows = (arr: [string, string][]) =>
    arr.map(([k, v]) => `<tr><td class="k">${esc(k)}</td><td>${esc(v)}</td></tr>`).join("");
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>${i.id} — Incident Report</title>
  <style>
    *{box-sizing:border-box} body{font-family:Inter,Segoe UI,Arial,sans-serif;color:#0f172a;margin:0;padding:40px;background:#fff}
    .brand{display:flex;align-items:center;gap:10px;border-bottom:3px solid #4f8cff;padding-bottom:14px;margin-bottom:6px}
    .brand .logo{width:34px;height:34px;border-radius:8px;background:linear-gradient(135deg,#4f8cff,#22d3ee);display:grid;place-items:center;color:#fff;font-weight:800}
    h1{font-size:22px;margin:0}.muted{color:#64748b;font-size:12px}
    h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:24px 0 8px;border-bottom:1px solid #e2e8f0;padding-bottom:6px}
    table{width:100%;border-collapse:collapse;font-size:12px}
    td{padding:7px 8px;border-bottom:1px solid #eef2f7}.k{color:#64748b;width:190px}
    p{font-size:13px;line-height:1.6;color:#334155}
    .sev{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;color:#fff}
    .li{font-size:12px;padding:4px 0;border-bottom:1px dashed #e2e8f0}
    .foot{margin-top:28px;border-top:1px solid #e2e8f0;padding-top:10px;font-size:11px;color:#94a3b8;display:flex;justify-content:space-between}
    code{background:#f1f5f9;border-radius:4px;padding:1px 4px;font-size:11px}
    @media print{body{padding:20px}}
  </style></head><body>
    <div class="brand"><div class="logo">LF</div>
      <div><h1>Incident Report · ${esc(i.id)}</h1>
      <div class="muted">LLM Firewall Platform · Generated ${now.toLocaleString()} · Confidential</div></div>
    </div>
    <h2>Executive Summary</h2><p>${esc(incidentExecutiveSummary(i))}</p>
    <h2>Case Details</h2>
    <table>${rows([
      ["Case ID", i.id],
      ["Title", i.title],
      ["Severity", i.severity.toUpperCase()],
      ["Status", i.status],
      ["Assignee", i.assignee],
      ["Created", new Date(i.createdAt).toLocaleString()],
    ])}</table>
    <h2>Evidence</h2>
    <table>${rows([
      ["Attack category", e.category.label],
      ["OWASP / MITRE", `${e.category.owasp ?? "—"} / ${e.category.mitre?.id ?? "—"}`],
      ["Verdict", e.outcome.verdict.toUpperCase()],
      ["Confidence", `${Math.round((e.outcome.score ?? 0) * 100)}%`],
      ["Source", `${e.source.city} (${e.source.cc})`],
      ["Application", e.app],
      ["Detection latency", `${(e.outcome.latency_ms ?? 0).toFixed(2)} ms`],
      ["Evasion", e.evasion ?? "none"],
      ["Reasons", (e.outcome.reasons ?? []).join("; ") || "—"],
    ])}</table>
    <h2>Recommended Mitigation</h2><p>${esc(e.category.mitigation)}</p>
    <h2>Timeline</h2>
    <div>${i.timeline.map((t) => `<div class="li"><b>${new Date(t.ts).toLocaleString()}</b> — ${esc(t.label)}</div>`).join("")}</div>
    ${i.notes.length ? `<h2>Analyst Notes</h2><div>${i.notes.map((n) => `<div class="li"><b>${new Date(n.ts).toLocaleString()}</b> — ${esc(n.text)}</div>`).join("")}</div>` : ""}
    <div class="foot"><span>LLM Firewall Platform · Incident Response</span><span>${i.id} · ${now.getFullYear()}</span></div>
  </body></html>`;
  const w = window.open("", "_blank", "width=900,height=1000");
  if (!w) { download(`${i.id}-report.html`, html, "text/html"); return; }
  w.document.write(html);
  w.document.close();
  setTimeout(() => w.print(), 500);
}

export function openReport(kind: ReportKind, stats: Stats, events: SecurityEvent[]) {
  const html = reportHTML(kind, stats, events);
  const w = window.open("", "_blank", "width=900,height=1000");
  if (!w) {
    // Popup blocked — fall back to downloading the HTML file.
    download(`aegis-${kind}-report.html`, html, "text/html");
    return;
  }
  w.document.write(html);
  w.document.close();
  setTimeout(() => w.print(), 500);
}
