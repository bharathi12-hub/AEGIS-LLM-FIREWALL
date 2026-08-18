// Small pure formatting + display helpers shared across pages.

export const nf = new Intl.NumberFormat("en-US");

export function compact(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return (n / 1000).toFixed(n < 10_000 ? 1 : 0) + "k";
  return (n / 1_000_000).toFixed(1) + "M";
}

export function pct(n: number, digits = 1): string {
  return `${(n * 100).toFixed(digits)}%`;
}

export function ms(n: number | undefined): string {
  if (n == null) return "—";
  return n < 1 ? `${(n).toFixed(2)} ms` : `${n.toFixed(n < 10 ? 1 : 0)} ms`;
}

export function timeAgo(ts: number): string {
  const s = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function clockTime(ts: number): string {
  return new Date(ts).toLocaleTimeString("en-US", { hour12: false });
}

/**
 * Synthetic threat-source geography. The offline demo has no real client IPs;
 * each event is assigned a plausible source so the attack map and "top sources"
 * panels have something meaningful to render. Coordinates are normalized 0..100
 * over an equirectangular world so they map straight onto an SVG viewBox.
 */
export interface GeoSource {
  cc: string;
  city: string;
  x: number; // 0..100 (lon)
  y: number; // 0..100 (lat)
}
export const GEO: GeoSource[] = [
  { cc: "RU", city: "Moscow", x: 58.5, y: 26 },
  { cc: "CN", city: "Shanghai", x: 80, y: 40 },
  { cc: "KP", city: "Pyongyang", x: 82, y: 37 },
  { cc: "IR", city: "Tehran", x: 60, y: 41 },
  { cc: "US", city: "Ashburn", x: 26, y: 39 },
  { cc: "BR", city: "São Paulo", x: 34, y: 68 },
  { cc: "NG", city: "Lagos", x: 49, y: 55 },
  { cc: "IN", city: "Mumbai", x: 69, y: 49 },
  { cc: "DE", city: "Frankfurt", x: 50, y: 30 },
  { cc: "NL", city: "Amsterdam", x: 49, y: 28 },
  { cc: "VN", city: "Hanoi", x: 78, y: 48 },
  { cc: "UA", city: "Kyiv", x: 55, y: 29 },
];
export const geoFor = (seed: number): GeoSource => GEO[Math.abs(seed) % GEO.length];

export const FLAG: Record<string, string> = {
  RU: "🇷🇺", CN: "🇨🇳", KP: "🇰🇵", IR: "🇮🇷", US: "🇺🇸", BR: "🇧🇷",
  NG: "🇳🇬", IN: "🇮🇳", DE: "🇩🇪", NL: "🇳🇱", VN: "🇻🇳", UA: "🇺🇦",
};

/** Deterministic small hash for stable per-string pseudo-randomness. */
export function hashStr(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
