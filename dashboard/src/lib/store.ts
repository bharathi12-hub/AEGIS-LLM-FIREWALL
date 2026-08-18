// Live security-event store + traffic simulator.
//
// This is the shared source of truth for the whole SOC. It holds a rolling
// window of enriched `SecurityEvent`s and lets any component subscribe via
// `useSyncExternalStore`. A built-in simulator drives realistic mixed traffic
// through the REAL detection engine (`inspect()` — backend when reachable, the
// in-browser engine otherwise), so every panel stays live during a demo with no
// backend running. Manual inspections and one-click attack replays feed the
// same stream, so the entire dashboard reacts to a single analyst action.
import { useSyncExternalStore } from "react";
import { inspect, subscribeEvents, type LiveEvent, type Outcome } from "../api";
import { inspectLocal } from "../engine";
import {
  categoryOf,
  severityOf,
  SEV_COLOR,
  type CategoryInfo,
  type Severity,
} from "./taxonomy";
import { ATTACKS, BENIGN, EVASIONS, type AttackVector } from "./attacks";
import { geoFor, hashStr, type GeoSource } from "./format";

export interface SecurityEvent {
  id: string;
  ts: number;
  prompt: string;
  outcome: Outcome;
  severity: Severity;
  category: CategoryInfo;
  source: GeoSource;
  app: string;
  user: string;
  simulated: boolean;
  replayName?: string;
  evasion?: string;
}

const APPS = [
  "customer-support-bot",
  "code-assistant",
  "internal-copilot",
  "doc-summarizer",
  "sales-agent",
  "hr-helpdesk",
];
const MAX_EVENTS = 700;

let _seq = 0;
const uid = () => `evt_${Date.now().toString(36)}_${(_seq++).toString(36)}`;
const rand = <T,>(a: T[]): T => a[Math.floor(Math.random() * a.length)];
const userTag = () => `u_${(1000 + Math.floor(Math.random() * 8999)).toString()}`;

function enrich(
  outcome: Outcome,
  prompt: string,
  opts: Partial<SecurityEvent> = {},
): SecurityEvent {
  const severity = severityOf(outcome);
  const category = categoryOf(outcome);
  // Attackers cluster in adversarial regions; benign traffic in friendly ones.
  const seed = hashStr(prompt + (opts.replayName ?? ""));
  const source = outcome.blocked ? geoFor(seed + 3) : geoFor(seed);
  return {
    id: uid(),
    ts: Date.now(),
    prompt,
    outcome,
    severity,
    category,
    source,
    app: rand(APPS),
    user: userTag(),
    simulated: true,
    ...opts,
  };
}

class EventStore {
  events: SecurityEvent[] = [];
  private listeners = new Set<() => void>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private inFlight = false;
  running = false;
  demo = false;
  /** Optional alert sink (wired to the toast system) used in Demo Mode. */
  alert: ((e: SecurityEvent) => void) | null = null;

  constructor() {
    this.seed();
  }

  subscribe = (cb: () => void) => {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  };
  getSnapshot = () => this.events;
  private emit() {
    for (const l of this.listeners) l();
  }

  private push(e: SecurityEvent) {
    // New array reference so useSyncExternalStore sees a change.
    this.events = [e, ...this.events].slice(0, MAX_EVENTS);
    // In Demo Mode, surface critical blocks as live alerts (throttled).
    if (this.demo && e.outcome.blocked && e.severity === "critical" && Math.random() < 0.45) {
      this.alert?.(e);
    }
    this.emit();
  }

  // --- live gateway stream -------------------------------------------------
  //
  // When the gateway is reachable, every inspection it performs — from ANY
  // client, not just this dashboard — is streamed here over SSE and shown as a
  // real (non-simulated) event. That is what makes this a monitoring console
  // rather than a demo: an attack fired at the API from curl appears on screen.
  private unsubscribeLive: (() => void) | null = null;
  // Reference count, not a boolean guard. React StrictMode runs effects
  // mount → cleanup → mount in development, and the orderings interleave: a
  // plain "already connected? return" guard makes the second mount a no-op and
  // then the first cleanup closes the only stream, leaving the console silently
  // disconnected. Counting makes both orderings converge on "connected".
  private liveRefs = 0;
  live = false;

  /** True once at least one real gateway event has arrived. */
  isLive() {
    return this.live;
  }

  /**
   * Convert a gateway event into a dashboard event.
   *
   * The gateway deliberately does NOT ship the prompt (it stores a digest, not
   * the text), so there is nothing to display for `prompt` — showing a
   * placeholder is correct and honest rather than inventing content.
   */
  private fromGateway(ev: LiveEvent): SecurityEvent {
    const outcome: Outcome = {
      verdict: ev.verdict,
      blocked: ev.verdict === "block",
      category: ev.category,
      score: ev.score,
      reasons: ev.reasons ?? [],
      contributions: {},
      tripwires: [],
      latency_ms: ev.latency_ms,
      judge_used: false,
      forward_text: "",
      normalization: { risk: 0, reasons: [], stripped: {}, decoded_views: [] },
      alarms: [],
      kad_fingerprint: "",
    };
    const seed = hashStr(`${ev.seq}${ev.category}${ev.ts}`);
    return {
      id: `gw_${ev.seq}`,
      ts: (ev.ts ?? Date.now() / 1000) * 1000,
      prompt: "(not transmitted — the gateway stores a digest, not the text)",
      outcome,
      severity: severityOf(outcome),
      category: categoryOf(outcome),
      source: geoFor(seed),
      app: ev.layer === "console" ? "test-console" : "gateway",
      user: ev.tenant_id || "gateway",
      simulated: false,
    };
  }

  /** Start consuming the gateway's SSE stream. Idempotent + refcounted. */
  connectLive() {
    this.liveRefs += 1;
    if (this.unsubscribeLive) return;
    this.unsubscribeLive = subscribeEvents(
      (ev) => {
        this.live = true;
        this.push(this.fromGateway(ev));
      },
      () => {
        // Gateway unreachable: keep the simulator as the data source so the
        // console stays useful. The stream reconnects on its own via EventSource.
        this.live = false;
        this.emit();
      },
      () => {
        // Connected — flip to live immediately rather than waiting for traffic,
        // so an idle-but-connected gateway is not reported as offline.
        this.live = true;
        this.emit();
      },
    );
  }

  disconnectLive() {
    this.liveRefs = Math.max(0, this.liveRefs - 1);
    if (this.liveRefs > 0) return;   // another mount still wants the stream
    this.unsubscribeLive?.();
    this.unsubscribeLive = null;
    this.live = false;
    this.emit();
  }

  /** Instant, synchronous seed using the local engine (no network wait). */
  private seed() {
    const mix: { text: string; replay?: string }[] = [];
    for (let i = 0; i < 14; i++) mix.push({ text: rand(BENIGN) });
    for (const a of ATTACKS.slice(0, 6)) mix.push({ text: a.payload, replay: a.name });
    // Shuffle so the seed feed looks organic, then stagger timestamps backward.
    mix.sort(() => Math.random() - 0.5);
    const now = Date.now();
    this.events = mix.map((m, i) => {
      const o = inspectLocal(m.text);
      const e = enrich(o, m.text, { replayName: m.replay });
      e.ts = now - (mix.length - i) * 4200 - Math.floor(Math.random() * 1500);
      return e;
    });
  }

  /** Run one real inspection through the engine and stream the result. */
  private async tick() {
    if (this.inFlight) return;
    this.inFlight = true;
    try {
      const attack = Math.random() < (this.demo ? 0.62 : 0.38);
      let text: string;
      let replayName: string | undefined;
      let evasion: string | undefined;
      if (attack) {
        const v = rand(ATTACKS);
        const ev = Math.random() < 0.5 ? rand(EVASIONS) : EVASIONS[0];
        text = ev.fn(v.payload);
        replayName = v.name;
        evasion = ev.id === "plain" ? undefined : ev.label;
      } else {
        text = rand(BENIGN);
      }
      const outcome = await inspect(text);
      this.push(enrich(outcome, text, { replayName, evasion }));
    } finally {
      this.inFlight = false;
    }
  }

  start() {
    if (this.running) return;
    this.running = true;
    const loop = () => {
      this.tick();
      const delay = this.demo ? 700 + Math.random() * 700 : 1400 + Math.random() * 1600;
      this.timer = setTimeout(loop, delay);
    };
    this.timer = setTimeout(loop, 400);
    this.emit();
  }
  stop() {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.emit();
  }
  toggle() {
    this.running ? this.stop() : this.start();
  }

  /** Demo Mode: faster, attack-heavy simulated traffic + live alerts. */
  setDemo(on: boolean) {
    this.demo = on;
    if (on && !this.running) this.start();
    // Re-tick promptly so the cadence change is felt immediately.
    if (on && this.timer) {
      clearTimeout(this.timer);
      const loop = () => {
        this.tick();
        const delay = this.demo ? 700 + Math.random() * 700 : 1400 + Math.random() * 1600;
        this.timer = setTimeout(loop, delay);
      };
      this.timer = setTimeout(loop, 200);
    }
    this.emit();
  }
  toggleDemo() {
    this.setDemo(!this.demo);
  }

  /** One-click attack replay: runs the real engine and returns the event. */
  async replay(vector: AttackVector, evasionId = "plain"): Promise<SecurityEvent> {
    const ev = EVASIONS.find((e) => e.id === evasionId) ?? EVASIONS[0];
    const text = ev.fn(vector.payload);
    const outcome = await inspect(text);
    const e = enrich(outcome, text, {
      replayName: vector.name,
      evasion: ev.id === "plain" ? undefined : ev.label,
    });
    this.push(e);
    return e;
  }

  /** Push a manual (analyst-driven) inspection into the stream. */
  pushManual(outcome: Outcome, prompt: string): SecurityEvent {
    const e = enrich(outcome, prompt, { simulated: false, user: "analyst" });
    this.push(e);
    return e;
  }

  clear() {
    this.events = [];
    this.emit();
  }
}

export const store = new EventStore();

// ---- React bindings --------------------------------------------------------

export function useEvents(): SecurityEvent[] {
  return useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
}

/**
 * True when real gateway events are streaming in (as opposed to simulated
 * traffic). Panels use this to label their data source honestly — a console
 * that cannot tell an operator whether it is showing real detections is worse
 * than one that shows none.
 */
export function useLive(): boolean {
  return useSyncExternalStore(
    store.subscribe,
    () => store.isLive(),
    () => false,
  );
}

export function useSimRunning(): boolean {
  return useSyncExternalStore(
    store.subscribe,
    () => store.running,
    () => store.running,
  );
}

export function useDemo(): boolean {
  return useSyncExternalStore(
    store.subscribe,
    () => store.demo,
    () => store.demo,
  );
}

// ---- Derived analytics (pure selectors) ------------------------------------

export interface Stats {
  total: number;
  blocked: number;
  allowed: number;
  reviewed: number;
  detectionRate: number; // blocked / (attacks) — here blocked / total flagged
  avgLatency: number;
  p95Latency: number;
  severity: Record<Severity, number>;
  categories: { label: string; count: number; color: string }[];
  activeAttacks: number; // blocked in the last 60s
}

export function computeStats(events: SecurityEvent[]): Stats {
  const sev: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0, safe: 0,
  };
  const catMap = new Map<string, { count: number; color: string }>();
  let blocked = 0,
    reviewed = 0,
    latSum = 0,
    active = 0;
  const lats: number[] = [];
  const now = Date.now();
  for (const e of events) {
    sev[e.severity]++;
    if (e.outcome.blocked) blocked++;
    if (e.outcome.judge_used) reviewed++;
    const l = e.outcome.latency_ms ?? 0;
    latSum += l;
    lats.push(l);
    if (e.outcome.blocked && now - e.ts < 60_000) active++;
    if (e.outcome.blocked) {
      const key = e.category.label;
      const cur = catMap.get(key) ?? { count: 0, color: sevColorOf(e.severity) };
      cur.count++;
      catMap.set(key, cur);
    }
  }
  lats.sort((a, b) => a - b);
  const p95 = lats.length ? lats[Math.floor(lats.length * 0.95)] ?? lats[lats.length - 1] : 0;
  const total = events.length;
  return {
    total,
    blocked,
    allowed: total - blocked,
    reviewed,
    detectionRate: total ? blocked / total : 0,
    avgLatency: total ? latSum / total : 0,
    p95Latency: p95,
    severity: sev,
    categories: [...catMap.entries()]
      .map(([label, v]) => ({ label, count: v.count, color: v.color }))
      .sort((a, b) => b.count - a.count),
    activeAttacks: active,
  };
}

const sevColorOf = (s: Severity) => SEV_COLOR[s];

/** Bucket events into a per-interval timeseries for trend charts. */
export function timeseries(
  events: SecurityEvent[],
  buckets = 24,
  spanMs = 24 * 60 * 60 * 1000,
): { t: number; label: string; blocked: number; allowed: number; total: number }[] {
  const now = Date.now();
  const size = spanMs / buckets;
  const out = Array.from({ length: buckets }, (_, i) => {
    const t = now - (buckets - 1 - i) * size;
    return { t, label: bucketLabel(t, size), blocked: 0, allowed: 0, total: 0 };
  });
  for (const e of events) {
    const idx = buckets - 1 - Math.floor((now - e.ts) / size);
    if (idx >= 0 && idx < buckets) {
      out[idx].total++;
      e.outcome.blocked ? out[idx].blocked++ : out[idx].allowed++;
    }
  }
  return out;
}
function bucketLabel(t: number, size: number): string {
  const d = new Date(t);
  if (size >= 3600_000) return `${d.getHours().toString().padStart(2, "0")}:00`;
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit" });
}
