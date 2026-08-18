// API client for the AEGIS gateway. Base URL from Vite env, defaults to :8000
// (the gateway's default uvicorn port; override with VITE_API_BASE).
import { inspectLocal } from "./engine";

const BASE = (import.meta as any).env?.VITE_API_BASE ?? "http://localhost:8000";

// Keys are entered in the UI (never hard-coded). Stored only in memory + session.
export function getKeys() {
  return {
    apiKey: sessionStorage.getItem("aegis_key") ?? "",
    adminKey: sessionStorage.getItem("aegis_admin") ?? "",
    tenant: sessionStorage.getItem("aegis_tenant") ?? "acme-highsec",
  };
}
export function setKeys(apiKey: string, adminKey: string, tenant: string) {
  sessionStorage.setItem("aegis_key", apiKey);
  sessionStorage.setItem("aegis_admin", adminKey);
  sessionStorage.setItem("aegis_tenant", tenant);
}

export interface Outcome {
  verdict: string; blocked: boolean; category: string; score: number;
  reasons: string[]; contributions: Record<string, number>; tripwires: string[];
  latency_ms: number; judge_used: boolean; forward_text: string;
  normalization: { risk: number; reasons: string[]; stripped: Record<string, number>;
                   decoded_views: string[] };
  alarms: string[]; kad_fingerprint: string;
  /** Number of signature/custom rules matched (in-browser engine only). */
  matched_rules?: number;
}

async function req(path: string, opts: RequestInit = {}) {
  const res = await fetch(BASE + path, opts);
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

export async function inspect(text: string): Promise<Outcome> {
  const { apiKey } = getKeys();
  try {
    return await req("/aegis/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ text }),
    });
  } catch {
    // Gateway unreachable (or no key): fall back to the in-browser engine so the
    // whole dashboard keeps working with no backend running.
    return inspectLocal(text);
  }
}

export async function gatewayUp(): Promise<boolean> {
  try {
    const res = await fetch(BASE + "/livez");
    return res.ok;
  } catch {
    return false;
  }
}

export function chat(content: string) {
  const { apiKey } = getKeys();
  return req("/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({ messages: [{ role: "user", content }] }),
  });
}

// --- real-time monitoring (deliverable 4) ---------------------------------

export interface LiveEvent {
  ts: number; tenant_id: string; verdict: string; category: string;
  atlas: string; score: number; latency_ms: number; layer: string;
  surface: string; reasons: string[]; seq: number;
}

/** Recent inspection events (poll fallback when SSE is unavailable). */
export function recentEvents(limit = 100): Promise<{ events: LiveEvent[]; stats: any }> {
  const { apiKey } = getKeys();
  return req(`/aegis/events?limit=${limit}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
}

/**
 * Subscribe to the live inspection stream. Returns an unsubscribe function.
 * EventSource cannot send an Authorization header, so the key rides as a query
 * param (over TLS in production). Falls back silently if the gateway is down —
 * the caller keeps whatever data it had.
 */
export function subscribeEvents(
  onEvent: (e: LiveEvent) => void,
  onError?: () => void,
  onOpen?: () => void,
): () => void {
  const { apiKey } = getKeys();
  let es: EventSource | null = null;
  try {
    es = new EventSource(`${BASE}/aegis/events/stream?token=${encodeURIComponent(apiKey)}`);
    // Connection state, not event arrival, is what "live" means. Waiting for a
    // first event would leave a connected-but-idle gateway reading as offline.
    es.onopen = () => { onOpen?.(); };
    es.onmessage = (m) => {
      try { onEvent(JSON.parse(m.data)); } catch { /* ignore malformed frame */ }
    };
    es.onerror = () => { onError?.(); };
  } catch {
    onError?.();
  }
  return () => es?.close();
}

export function auditFeed(): Promise<any[]> {
  const { adminKey, tenant } = getKeys();
  return req(`/admin/audit/${tenant}?limit=50`, { headers: { "X-Admin-Key": adminKey } });
}
export function verifyChain() {
  const { adminKey } = getKeys();
  return req("/admin/audit/verify/chain", { headers: { "X-Admin-Key": adminKey } });
}
export function metricsSummary() {
  const { adminKey } = getKeys();
  return req("/admin/metrics/summary", { headers: { "X-Admin-Key": adminKey } });
}
export interface MetricsSummary {
  n?: number;
  backend?: string;
  counters?: Record<string, number>;
  latency_ms?: { p50?: number; p95?: number; p99?: number };
}

export function health() {
  const { adminKey } = getKeys();
  return req("/admin/health", { headers: { "X-Admin-Key": adminKey } });
}
export function siemEvents(limit = 200): Promise<{ format: string; events: any[] }> {
  const { adminKey } = getKeys();
  return req(`/admin/siem/events?limit=${limit}`, { headers: { "X-Admin-Key": adminKey } });
}
export function listTenants(): Promise<any[]> {
  const { adminKey } = getKeys();
  return req("/admin/tenants", { headers: { "X-Admin-Key": adminKey } });
}

export function getPolicy() {
  const { adminKey, tenant } = getKeys();
  return req(`/admin/policy/${tenant}`, { headers: { "X-Admin-Key": adminKey } });
}
export function setPolicy(yaml: string) {
  const { adminKey, tenant } = getKeys();
  return req(`/admin/policy/${tenant}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Admin-Key": adminKey },
    body: JSON.stringify({ yaml }),
  });
}
