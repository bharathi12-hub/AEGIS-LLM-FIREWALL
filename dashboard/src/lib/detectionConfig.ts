// Live detection configuration.
//
// A tunable, persisted config that the in-browser detection engine reads on
// every inspection. Changing it re-shapes detection in real time across the
// whole SOC (the live simulator picks up new settings on its next tick). Lets an
// analyst raise/lower thresholds, toggle detection layers, add custom signature
// rules and manage allow/deny lists — and immediately see the effect.
import { useSyncExternalStore } from "react";

export interface CustomRule {
  id: string;
  pattern: string; // JS regex source (compiled with the "i" flag)
  weight: number; // 0..1 contribution to the signature layer
  category: string; // OWASP-ish code shown on a match, e.g. "LLM01"
  enabled: boolean;
}

export interface DetectionConfig {
  blockThreshold: number; // fused >= block  → BLOCK
  reviewThreshold: number; // review <= fused < block → REVIEW (escalate)
  layers: {
    normalization: boolean;
    signatures: boolean;
    classifiers: boolean;
    kad: boolean;
  };
  customRules: CustomRule[];
  denyList: string[]; // any match → force BLOCK
  allowList: string[]; // any match (and no deny) → force ALLOW
}

export const DEFAULT_CONFIG: DetectionConfig = {
  blockThreshold: 0.45,
  reviewThreshold: 0.4,
  layers: { normalization: true, signatures: true, classifiers: true, kad: true },
  customRules: [
    { id: "seed-1", pattern: "corporate secrets?|internal only", weight: 0.7, category: "LLM06", enabled: false },
  ],
  denyList: [],
  allowList: [],
};

export type PresetName = "high-security" | "balanced" | "permissive";
export const PRESETS: Record<PresetName, { label: string; patch: Partial<DetectionConfig> }> = {
  "high-security": {
    label: "High-Security",
    patch: { blockThreshold: 0.3, reviewThreshold: 0.22, layers: { normalization: true, signatures: true, classifiers: true, kad: true } },
  },
  balanced: {
    label: "Balanced",
    patch: { blockThreshold: 0.45, reviewThreshold: 0.4 },
  },
  permissive: {
    label: "Permissive",
    patch: { blockThreshold: 0.65, reviewThreshold: 0.5 },
  },
};

const KEY = "aegis_detection_config";

function load(): DetectionConfig {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) return { ...DEFAULT_CONFIG, ...JSON.parse(raw) };
  } catch {
    /* ignore corrupt storage */
  }
  return structuredClone(DEFAULT_CONFIG);
}

let config: DetectionConfig = load();
const listeners = new Set<() => void>();

export function getDetectionConfig(): DetectionConfig {
  return config;
}
export function setDetectionConfig(next: DetectionConfig) {
  config = next;
  try {
    localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    /* storage may be unavailable */
  }
  for (const l of listeners) l();
}
export function patchDetectionConfig(patch: Partial<DetectionConfig>) {
  setDetectionConfig({ ...config, ...patch });
}
export function resetDetectionConfig() {
  setDetectionConfig(structuredClone(DEFAULT_CONFIG));
}
export function applyPreset(name: PresetName) {
  patchDetectionConfig(PRESETS[name].patch);
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useDetectionConfig(): DetectionConfig {
  return useSyncExternalStore(subscribe, getDetectionConfig, getDetectionConfig);
}
