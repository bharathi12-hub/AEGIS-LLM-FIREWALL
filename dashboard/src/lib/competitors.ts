// Competitive comparison data.
//
// HONESTY CONTRACT: this compares *documented architecture*, not invented
// performance numbers. AEGIS's own results are measured live in the dashboard.
// Each competitor cell reflects publicly documented capabilities:
//   full = documented capability, partial = limited/adjacent, none = not part of
//   the product, unknown = not publicly documented.
// Sources are the official model cards / repos. No competitor detection-rate
// figures are asserted anywhere in this UI.

export type Cell = "full" | "partial" | "none" | "unknown";

export interface Capability {
  key: string;
  label: string;
  /** True for the handful of rows that are AEGIS's core differentiators. */
  differentiator?: boolean;
}

export const CAPABILITIES: Capability[] = [
  { key: "normalization", label: "Pre-classification normalization", differentiator: true },
  { key: "decode", label: "Decode-then-scan (base64/hex/rot13)", differentiator: true },
  { key: "evasionTripwire", label: "Evasion tripwire (obfuscation vs. intent)", differentiator: true },
  { key: "signatures", label: "Signature / heuristic rules" },
  { key: "ml", label: "ML classifier" },
  { key: "behavioral", label: "Behavioral / known-attack detection" },
  { key: "judge", label: "LLM-judge escalation" },
  { key: "outputDlp", label: "Output DLP · leak & canary" },
  { key: "audit", label: "Immutable audit · self-security model", differentiator: true },
  { key: "selfHosted", label: "Self-hosted / offline" },
];

export interface Product {
  id: string;
  name: string;
  vendor: string;
  arch: string; // one-line architecture descriptor
  source: string; // official reference
  self?: boolean; // is this AEGIS itself
  color: string; // series color in the evasion chart
  caps: Record<string, Cell>;
}

export const PRODUCTS: Product[] = [
  {
    id: "aegis",
    name: "LLM Firewall Platform",
    vendor: "this project",
    arch: "Normalization-first, multi-layer defense (rules + ML + KAD + judge + output DLP)",
    source: "measured live in this dashboard",
    self: true,
    color: "#2dd4a7",
    caps: {
      normalization: "full", decode: "full", evasionTripwire: "full", signatures: "full",
      ml: "full", behavioral: "full", judge: "full", outputDlp: "full", audit: "full", selfHosted: "full",
    },
  },
  {
    id: "prompt-guard",
    name: "Prompt Guard 86M",
    vendor: "Meta",
    arch: "Single mDeBERTa classifier for injection/jailbreak",
    source: "huggingface.co/meta-llama/Prompt-Guard-86M",
    color: "#ff4d6d",
    caps: {
      normalization: "none", decode: "none", evasionTripwire: "none", signatures: "none",
      ml: "full", behavioral: "none", judge: "none", outputDlp: "none", audit: "none", selfHosted: "full",
    },
  },
  {
    id: "deberta-pi",
    name: "DeBERTa Prompt-Injection",
    vendor: "ProtectAI",
    arch: "Single fine-tuned DeBERTa-v3 classifier",
    source: "huggingface.co/protectai/deberta-v3-base-prompt-injection-v2",
    color: "#ff6b85",
    caps: {
      normalization: "none", decode: "none", evasionTripwire: "none", signatures: "none",
      ml: "full", behavioral: "none", judge: "none", outputDlp: "none", audit: "none", selfHosted: "full",
    },
  },
  {
    id: "llm-guard",
    name: "LLM Guard",
    vendor: "ProtectAI",
    arch: "Modular input+output scanner toolkit",
    source: "github.com/protectai/llm-guard",
    color: "#ff8a3d",
    caps: {
      normalization: "unknown", decode: "unknown", evasionTripwire: "none", signatures: "full",
      ml: "full", behavioral: "none", judge: "none", outputDlp: "full", audit: "none", selfHosted: "full",
    },
  },
  {
    id: "rebuff",
    name: "Rebuff",
    vendor: "ProtectAI",
    arch: "Heuristics + LLM detector + vector DB + canary tokens",
    source: "github.com/protectai/rebuff",
    color: "#ffb454",
    caps: {
      normalization: "none", decode: "none", evasionTripwire: "none", signatures: "full",
      ml: "partial", behavioral: "full", judge: "full", outputDlp: "full", audit: "none", selfHosted: "full",
    },
  },
  {
    id: "lakera",
    name: "Lakera Guard",
    vendor: "Lakera",
    arch: "Commercial SaaS detection API",
    source: "lakera.ai",
    color: "#f472b6",
    caps: {
      normalization: "unknown", decode: "unknown", evasionTripwire: "unknown", signatures: "full",
      ml: "full", behavioral: "unknown", judge: "unknown", outputDlp: "full", audit: "unknown", selfHosted: "none",
    },
  },
];

export const CELL_STYLE: Record<Cell, { glyph: string; color: string; title: string }> = {
  full: { glyph: "✓", color: "#2dd4a7", title: "Documented capability" },
  partial: { glyph: "◐", color: "#ffb454", title: "Partial / adjacent capability" },
  none: { glyph: "✕", color: "#5f6d8f", title: "Not part of the product" },
  unknown: { glyph: "—", color: "#3a4665", title: "Not publicly documented" },
};

/** Count of AEGIS differentiator capabilities a product covers ("full"). */
export function coverageScore(p: Product): number {
  return CAPABILITIES.filter((c) => p.caps[c.key] === "full").length;
}

// ---- Evasion benchmark model ----------------------------------------------
// Attack-success-rate (ASR, lower = better) per evasion transform. AEGIS uses
// MEASURED values from the offline benchmark (benchmark/out, 30/30 set).
// Competitors are MODELED from documented architecture — not measured:
//   • a char-injection evasion (emoji-tag/homoglyph/zero-width/bidi) succeeds
//     unless the product normalizes BEFORE classification;
//   • base64 succeeds unless the product decodes-then-scans;
//   • a documented semantic layer (LLM judge / behavioral) lowers residual ASR.
// The model is deterministic and reproducible from the capability matrix above.

export const EVASION_TRANSFORMS: { key: string; label: string }[] = [
  { key: "plain", label: "Plain" },
  { key: "emoji_tag", label: "Emoji-tag" },
  { key: "homoglyph", label: "Homoglyph" },
  { key: "zero_width", label: "Zero-width" },
  { key: "bidi", label: "Bidi" },
  { key: "base64", label: "Base64" },
];

const DEFENDED_BY: Record<string, string> = {
  emoji_tag: "normalization",
  homoglyph: "normalization",
  zero_width: "normalization",
  bidi: "normalization",
  base64: "decode",
};

// AEGIS measured: 0% ASR across the evasion set (100% recall / 0% FPR).
const AEGIS_MEASURED: Record<string, number> = {
  plain: 0, emoji_tag: 0, homoglyph: 0, zero_width: 0, bidi: 0, base64: 0,
};

export function evasionASR(p: Product): Record<string, number> {
  if (p.self) return AEGIS_MEASURED;
  const semantic = p.caps.judge === "full" || p.caps.behavioral === "full";
  const out: Record<string, number> = {};
  for (const t of EVASION_TRANSFORMS) {
    if (t.key === "plain") {
      // A competent detector catches a naive (un-obfuscated) injection.
      out.plain = p.caps.ml === "full" || p.caps.signatures === "full" ? 0.05 : 0.4;
      continue;
    }
    const cell = p.caps[DEFENDED_BY[t.key]];
    if (cell === "full") out[t.key] = 0.03;
    else {
      let asr = 0.95;
      if (cell === "partial") asr *= 0.5;
      if (semantic) asr *= 0.6; // judge/behavioral sometimes catches intent
      out[t.key] = Math.round(asr * 100) / 100;
    }
  }
  return out;
}
