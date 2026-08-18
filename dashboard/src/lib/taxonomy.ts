// Threat taxonomy & enrichment layer.
//
// The AEGIS engine (backend or the in-browser fallback) returns an `Outcome`
// with a numeric score, an OWASP-LLM category code, reasons and tripwires. The
// dashboard enriches that raw verdict — deterministically — into the fields a
// SOC analyst expects: a human-readable severity band, an attack-class label, a
// MITRE ATT&CK mapping and a concrete mitigation recommendation.
//
// This mapping is pure and testable; it invents no data, it only interprets what
// the detection engine already decided.
import type { Outcome } from "../api";

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "safe";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info", "safe"];

export const SEV_COLOR: Record<Severity, string> = {
  critical: "#ff4d6d",
  high: "#ff8a3d",
  medium: "#ffd23f",
  low: "#4f8cff",
  info: "#64748b",
  safe: "#2dd4a7",
};

export interface CategoryInfo {
  /** Short analyst-facing label. */
  label: string;
  /** OWASP LLM Top-10 identifier, when applicable. */
  owasp?: string;
  /** MITRE ATT&CK technique id + name most closely associated. */
  mitre?: { id: string; name: string };
  /** Concrete, actionable mitigation guidance. */
  mitigation: string;
  /** One-line description of the attack class. */
  about: string;
}

// Keyed by the OWASP code the engine emits (prefix match on the `LLMxx` part),
// plus a few internal classes derived from reasons/tripwires.
const CATALOG: Record<string, CategoryInfo> = {
  LLM01: {
    label: "Prompt Injection",
    owasp: "LLM01",
    mitre: { id: "T1059", name: "Command & Scripting Interpreter" },
    about: "Attacker overrides the system's instructions to hijack model behavior.",
    mitigation:
      "Block the request. Enforce instruction/data separation, keep the sanitized-bytes parity, and alert if the same session retries.",
  },
  LLM02: {
    label: "Insecure Output Handling",
    owasp: "LLM02",
    mitre: { id: "T1055", name: "Process Injection" },
    about: "Model output is consumed downstream without validation (XSS/SSRF/RCE).",
    mitigation: "Escape and validate all model output before rendering or executing it.",
  },
  LLM06: {
    label: "Sensitive Info Disclosure",
    owasp: "LLM06",
    mitre: { id: "T1552", name: "Unsecured Credentials" },
    about: "Response leaks secrets, PII or internal data.",
    mitigation: "Withhold the response. Run decode-then-scan DLP and rotate any exposed secret.",
  },
  LLM07: {
    label: "System Prompt Leakage",
    owasp: "LLM07",
    mitre: { id: "T1005", name: "Data from Local System" },
    about: "Attempt to extract the hidden system prompt or guardrail configuration.",
    mitigation: "Block extraction attempts and verify the canary token was not echoed downstream.",
  },
  LLM10: {
    label: "Model Theft / Abuse",
    owasp: "LLM10",
    mitre: { id: "T1567", name: "Exfiltration Over Web Service" },
    about: "Excessive extraction or tool abuse to exfiltrate model capability or data.",
    mitigation: "Rate-limit the key, quarantine the session and require human approval.",
  },
  EVASION: {
    label: "Obfuscation / Evasion",
    mitre: { id: "T1027", name: "Obfuscated Files or Information" },
    about: "Payload hidden via unicode-tag smuggling, homoglyphs, bidi, zero-width or base64.",
    mitigation:
      "Normalize (NFKC + strip smuggling codepoints) before classification; the evasion tripwire flags obfuscation-without-intent mismatches.",
  },
  // A block driven by the behavioral layers (KAD, multi-turn context, the
  // judge) carries no OWASP signature category, because no rule matched — the
  // decision came from behaviour, not vocabulary. Without this bucket those
  // events fell through to "Benign", so a critical block displayed as benign
  // and vanished from any category filter.
  BEHAVIORAL: {
    label: "Behavioral / Anomaly",
    mitre: { id: "AML.T0051", name: "LLM Prompt Injection" },
    about:
      "Blocked by a behavioral layer — known-answer detection, multi-turn crescendo, or the LLM judge — rather than by a signature match.",
    mitigation:
      "Review the decision trace: these are the adaptive attacks that carry no recognisable vocabulary, which is precisely why the behavioral layers exist.",
  },
  NONE: {
    label: "Benign",
    about: "No adversarial intent detected.",
    mitigation: "Allow. Forward sanitized bytes upstream.",
  },
};

/** Resolve the enriched category info for an engine outcome. */
export function categoryOf(outcome: Outcome): CategoryInfo {
  const code = (outcome.category || "none").toUpperCase();
  const key = code.slice(0, 5); // "LLM01:..." -> "LLM01"
  // A concrete OWASP category always wins.
  if (key !== "NONE" && CATALOG[key]) return CATALOG[key];

  // No category was assigned. Order matters here, and getting it wrong is how
  // the previous version mislabelled real detections: because "none" uppercases
  // to the literal CATALOG key "NONE", the lookup above used to match it and
  // return "Benign" immediately — so the evasion fallback below was unreachable
  // and every behavioral block displayed as benign.
  if (outcome.normalization?.risk >= 0.5 && CATALOG.EVASION) return CATALOG.EVASION;
  // A BLOCK with no OWASP category came from a behavioral layer (KAD, multi-turn
  // context, the judge) — no rule matched because the signal was behaviour, not
  // vocabulary. Calling that "Benign" contradicts the verdict on screen and
  // hides the detection from category filters.
  if (outcome.blocked && CATALOG.BEHAVIORAL) return CATALOG.BEHAVIORAL;
  return CATALOG.NONE;
}

/**
 * Derive a SOC severity band from the engine verdict. Deterministic: driven by
 * the fused score, the block/allow decision and whether an evasion tripwire
 * fired. Never upgrades a benign allow above "info".
 */
export function severityOf(outcome: Outcome): Severity {
  const s = outcome.score ?? 0;
  const blocked = outcome.blocked;
  const evasion = (outcome.tripwires || []).some((t) => t.toLowerCase().includes("evasion"));
  if (!blocked) {
    if (s >= 0.35 || outcome.judge_used) return "low"; // borderline / reviewed-and-allowed
    return outcome.normalization?.risk >= 0.4 ? "info" : "safe";
  }
  if (s >= 0.85 || evasion) return "critical";
  if (s >= 0.7) return "high";
  return "medium";
}

export function severityLabel(s: Severity): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Confidence % from the fused score, for display. */
export function confidencePct(outcome: Outcome): number {
  return Math.round(Math.max(0, Math.min(1, outcome.score ?? 0)) * 100);
}

/** Recommended one-click response action, given the verdict. */
export function recommendedAction(outcome: Outcome): {
  action: string;
  tone: "danger" | "warn" | "ok";
} {
  if (outcome.blocked) {
    const sev = severityOf(outcome);
    if (sev === "critical") return { action: "Block + Quarantine session", tone: "danger" };
    return { action: "Block request", tone: "danger" };
  }
  if (outcome.judge_used || (outcome.normalization?.risk ?? 0) >= 0.4)
    return { action: "Allow + Flag for review", tone: "warn" };
  return { action: "Allow (forward sanitized)", tone: "ok" };
}

/**
 * Turn the engine's terse reason codes into an English analyst explanation.
 * Ordering mirrors the pipeline so the story reads top-to-bottom.
 */
export function explain(outcome: Outcome): string[] {
  const out: string[] = [];
  const n = outcome.normalization;
  if (n?.reasons?.length) {
    const parts = n.reasons.map((r) => REASON_TEXT[r.split(":")[0]] ?? r);
    out.push(`Normalization neutralized ${n.reasons.length} evasion technique(s): ${parts.join(", ")}.`);
  }
  const contrib = outcome.contributions || {};
  const top = Object.entries(contrib)
    .filter(([, v]) => v >= 0.4)
    .sort((a, b) => b[1] - a[1]);
  for (const [layer, v] of top) {
    out.push(`${LAYER_TEXT[layer] ?? layer} scored ${(v as number).toFixed(2)} — a strong signal.`);
  }
  for (const t of outcome.tripwires || []) {
    out.push(`Tripwire fired: ${TRIPWIRE_TEXT[t.split(":")[0]] ?? t}.`);
  }
  if (!out.length) out.push("All detection layers scored low; no adversarial pattern matched.");
  return out;
}

/** Structured "verdict at a glance" facts for the explainability panel. */
export function verdictFacts(outcome: Outcome): { label: string; value: string; strong?: boolean }[] {
  const c = outcome.contributions || {};
  const classifier = Math.round((c.classifiers ?? 0) * 100);
  const facts: { label: string; value: string; strong?: boolean }[] = [
    { label: "Confidence", value: `${confidencePct(outcome)}%`, strong: true },
    { label: "Reason", value: categoryOf(outcome).label, strong: true },
  ];
  if (outcome.matched_rules != null) facts.push({ label: "Matched rules", value: String(outcome.matched_rules) });
  facts.push({ label: "Classifier signal", value: `${classifier}%` });
  facts.push({
    label: "LLM reasoning",
    value: outcome.judge_used ? "High risk (escalated)" : outcome.blocked ? "Not required" : "Low risk",
  });
  facts.push({ label: "Recommended action", value: recommendedAction(outcome).action, strong: true });
  return facts;
}

const REASON_TEXT: Record<string, string> = {
  "unicode-tag-smuggling": "unicode-tag smuggling",
  "bidi-override": "bidirectional override",
  "zero-width": "zero-width characters",
  homoglyph: "homoglyph substitution",
  "encoded-payload": "base64-encoded payload",
};
const LAYER_TEXT: Record<string, string> = {
  signatures: "Signature rules",
  classifiers: "ML classifier ensemble",
  kad: "Known-attack detector (KAD)",
  normalization: "Normalization risk",
};
const TRIPWIRE_TEXT: Record<string, string> = {
  "classifier-disagreement": "the two classifiers disagreed sharply (a hallmark of adversarial input)",
  "evasion-obfuscation-vs-benign-classifier":
    "input was heavily obfuscated yet scored benign — a classic evasion signature",
};
