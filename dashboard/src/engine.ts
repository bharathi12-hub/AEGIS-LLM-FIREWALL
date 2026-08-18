// Client-side detection engine (a faithful TS port of gateway/app/pipeline).
// Used whenever the gateway is unreachable, so the whole dashboard works with no
// backend running. The gateway remains authoritative when it is up.
//
// It reads the live DetectionConfig on every call, so tuning thresholds,
// toggling layers, adding custom rules or editing allow/deny lists re-shapes
// detection in real time.
import type { Outcome } from "./api";
import { getDetectionConfig, type DetectionConfig } from "./lib/detectionConfig";

const HOMO: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
  "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "г": "r", "ο": "o", "α": "a",
  "ι": "i", "ρ": "p", "τ": "t",
};

function isZW(cp: number) {
  return cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff || cp === 0x2060;
}
function isBidi(cp: number) {
  return (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200e || cp === 0x200f;
}

// When normalization is DISABLED, we still strip nothing and score no risk — so
// obfuscated payloads sail through to the classifier (which is exactly the
// failure mode that motivates normalization-first defense).
function normalize(text: string, enabled: boolean) {
  if (!enabled) {
    return { sanitized: text, scan: text, risk: 0, reasons: [] as string[],
             stripped: { zw: 0, bidi: 0, tag: 0, homo: 0 }, views: [] as string[] };
  }
  const c = { zw: 0, bidi: 0, tag: 0, homo: 0 };
  const out: string[] = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xe0000 && cp <= 0xe007f) { c.tag++; continue; }
    if (isZW(cp)) { c.zw++; continue; }
    if (isBidi(cp)) { c.bidi++; continue; }
    if (HOMO[ch]) { c.homo++; out.push(HOMO[ch]); continue; }
    out.push(ch);
  }
  const s = out.join("").normalize("NFKC");
  const views: string[] = [];
  const m = s.match(/[A-Za-z0-9+/]{16,}={0,2}/g) || [];
  for (const t of m) {
    try { const d = atob(t); if (d.length >= 4 && /^[\x20-\x7e\s]+$/.test(d)) views.push(d); } catch { /* not b64 */ }
  }
  let risk = 0;
  const reasons: string[] = [];
  if (c.tag) { risk += 0.6; reasons.push(`unicode-tag-smuggling:${c.tag}`); }
  if (c.bidi) { risk += 0.5; reasons.push(`bidi-override:${c.bidi}`); }
  if (c.zw) { risk += Math.min(0.4, 0.08 * c.zw); reasons.push(`zero-width:${c.zw}`); }
  if (c.homo) { risk += Math.min(0.5, 0.05 * c.homo); reasons.push(`homoglyph:${c.homo}`); }
  if (views.length) { risk += Math.min(0.4, 0.15 * views.length); reasons.push(`encoded-payload:${views.length}`); }
  return { sanitized: s, scan: s + "\n" + views.join("\n"), risk: Math.min(1, risk), reasons, stripped: c, views };
}

const SIGS: [RegExp, number, string][] = [
  [/ignore\b.{0,25}\b(previous|prior|above|all|any)\b.{0,20}\b(instruction|instructions|rule|rules|prompt)/i, 0.9, "LLM01"],
  [/(reveal|show|print|repeat|dump)\b.{0,35}\b(system\s*)?(prompt|instructions)/i, 0.85, "LLM07"],
  [/(you are now|act as|pretend|roleplay)\b.{0,40}\b(dan|jailbroken|unfiltered|unrestricted|no ethics|evil|hacker)/i, 0.85, "LLM01"],
  [/developer mode\s*(enabled|on)|do anything now|\bDAN\b/i, 0.85, "LLM01"],
  [/\b(build|make|create|write)\b.{0,30}\b(explosive|bomb|weapon|malware|virus)\b/i, 0.8, "LLM01"],
  [/bypass\b.{0,25}\b(content policy|safety|filter|guardrail|restriction)/i, 0.8, "LLM01"],
];

function compileCustom(rules: DetectionConfig["customRules"]): [RegExp, number, string][] {
  const out: [RegExp, number, string][] = [];
  for (const r of rules) {
    if (!r.enabled || !r.pattern.trim()) continue;
    try {
      out.push([new RegExp(r.pattern, "i"), Math.max(0, Math.min(1, r.weight)), r.category || "LLM01"]);
    } catch {
      /* invalid user regex — ignore rather than break detection */
    }
  }
  return out;
}

function sigs(t: string, extra: [RegExp, number, string][]) {
  let b = 0; const cats: string[] = []; let h = 0;
  for (const r of [...SIGS, ...extra]) if (r[0].test(t)) { h++; if (r[1] > b) b = r[1]; if (!cats.includes(r[2])) cats.push(r[2]); }
  return { score: b ? Math.min(1, b + Math.min(0.1, 0.03 * (h - 1))) : 0, cats, hits: h };
}
const LEX: Record<string, number> = {
  "ignore previous": 3, "ignore all previous": 3.2, "disregard": 2.2, "system prompt": 1.3,
  "developer mode": 1.6, "jailbroken": 3.2, "jailbreak": 3, "do anything now": 3.4,
  "unfiltered": 2.4, "unrestricted": 2.4, "no restrictions": 2.6, "build": 0.8,
  "explosive": 2.4, "weapon": 2, "malware": 2.4, "bypass content": 2.8, "reveal your": 1.8,
  "write a guide": 1.4,
};
const sg = (x: number) => 1 / (1 + Math.exp(-x));
function lex(t: string) { const lo = t.toLowerCase(); let a = -2.2; for (const k in LEX) if (lo.includes(k)) a += LEX[k]; return sg(a); }
function str(t: string, ob: number) {
  let a = -2.4;
  if (/\b(ignore|disregard|forget)\b.{0,30}\b(instruction|instructions|rule|prompt|above|previous)\b/i.test(t)) a += 3;
  if (/\b(build|make|write)\b.{0,30}\b(explosive|bomb|weapon|malware|guide)\b/i.test(t)) a += 1.6;
  a += 2.5 * ob; return sg(a);
}
const HIJACK = [
  /\b(ignore|disregard|forget)\b.{0,40}\b(above|previous|instruction|token|task|rule)\b/i,
  /\b(instead|rather)\b.{0,25}\b(output|print|say|write|reply)\b/i,
  /\b(output|print|say|reply with)\b.{0,25}\b(the word|the phrase|exactly|only)\b/i,
];
function kad(t: string) { let s = 0; for (const r of HIJACK) if (r.test(t)) s += 0.5; return s >= 0.5; }
function nor(a: number[]) { let p = 1; for (const x of a) p *= 1 - Math.max(0, Math.min(1, x)); return 1 - p; }

const CAT_NAMES: Record<string, string> = {
  LLM01: "LLM01:PromptInjection", LLM02: "LLM02:InsecureOutputHandling",
  LLM06: "LLM06:SensitiveInformationDisclosure", LLM07: "LLM07:SystemPromptLeakage",
  LLM10: "LLM10:UnboundedConsumption", none: "none",
};

const firstMatch = (list: string[], hay: string) =>
  list.map((s) => s.trim().toLowerCase()).filter(Boolean).find((s) => hay.includes(s));

export function inspectLocal(text: string, cfg: DetectionConfig = getDetectionConfig()): Outcome {
  const t0 = performance.now();
  const L = cfg.layers;
  const n = normalize(text, L.normalization);
  const lowScan = (n.scan + " " + text).toLowerCase();

  const s = L.signatures ? sigs(n.scan, compileCustom(cfg.customRules)) : { score: 0, cats: [] as string[], hits: 0 };
  const l = L.classifiers ? lex(n.scan) : 0;
  const st = L.classifiers ? str(n.scan, n.risk) : 0;
  const cm = Math.max(l, st);
  const k = L.kad ? kad(n.sanitized) : false;

  const contributions = { signatures: s.score, classifiers: cm, kad: k ? 0.85 : 0, normalization: n.risk };
  let fused = nor([s.score, cm, k ? 0.85 : 0, 0.5 * n.risk]);
  const tripwires: string[] = [];
  if (L.classifiers && Math.abs(l - st) >= 0.4) { tripwires.push(`classifier-disagreement:${Math.abs(l - st).toFixed(2)}`); fused = Math.min(1, fused + 0.1); }
  if (L.normalization && n.risk >= 0.55 && cm < 0.45) { tripwires.push("evasion-obfuscation-vs-benign-classifier"); fused = Math.min(1, fused + 0.3); }

  // Allow/deny list overrides (policy layer).
  const reasons = [...n.reasons];
  let forced: "block" | "allow" | null = null;
  const deny = firstMatch(cfg.denyList, lowScan);
  const allow = firstMatch(cfg.allowList, lowScan);
  if (deny) { fused = 1; forced = "block"; reasons.unshift(`deny-list:${deny}`); }
  else if (allow) { fused = 0; forced = "allow"; reasons.unshift(`allow-list:${allow}`); }

  const block = cfg.blockThreshold;
  const review = Math.min(cfg.reviewThreshold, block);
  let verdict: string;
  if (forced === "block") verdict = "block";
  else if (forced === "allow") verdict = "allow";
  else if (fused >= block) verdict = "block";
  else if (fused >= review) verdict = "review";
  else verdict = "allow";

  const judge = verdict === "review";
  const cat = (forced === "block" && deny ? "LLM01" : s.cats[0]) || (k ? "LLM01" : "none");

  return {
    verdict, blocked: verdict === "block", category: CAT_NAMES[cat] || cat, score: fused,
    reasons, contributions, tripwires,
    latency_ms: Math.round((performance.now() - t0) * 100) / 100, judge_used: judge,
    forward_text: n.sanitized,
    normalization: { risk: n.risk, reasons: n.reasons, stripped: n.stripped as any, decoded_views: n.views.slice(0, 3) },
    alarms: ["local-engine (gateway offline)"], kad_fingerprint: k ? "local" : "",
    matched_rules: s.hits,
  };
}
