// Incident/case management store. Analysts promote a blocked security event into
// a tracked case with a status workflow, evidence (the triggering event), a
// timeline and notes. In-memory for the session (persisted to localStorage so a
// demo survives a reload).
import { useSyncExternalStore } from "react";
import type { SecurityEvent } from "./store";
import type { Severity } from "./taxonomy";

export type IncidentStatus = "open" | "investigating" | "contained" | "closed";

export const STATUS_FLOW: IncidentStatus[] = ["open", "investigating", "contained", "closed"];
export const STATUS_COLOR: Record<IncidentStatus, string> = {
  open: "#ff4d6d",
  investigating: "#ffb454",
  contained: "#4f8cff",
  closed: "#2dd4a7",
};

export interface TimelineEntry {
  ts: number;
  label: string;
}
export interface Note {
  ts: number;
  text: string;
}
export interface Incident {
  id: string; // INC-0001
  title: string;
  severity: Severity;
  status: IncidentStatus;
  createdAt: number;
  event: SecurityEvent;
  timeline: TimelineEntry[];
  notes: Note[];
  assignee: string;
}

const KEY = "aegis_incidents";
let seq = 0;

function load(): Incident[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const list = JSON.parse(raw) as Incident[];
      seq = list.reduce((m, i) => Math.max(m, parseInt(i.id.replace("INC-", ""), 10) || 0), 0);
      return list;
    }
  } catch {
    /* ignore */
  }
  return [];
}

let incidents: Incident[] = load();
const listeners = new Set<() => void>();

function persist() {
  try {
    localStorage.setItem(KEY, JSON.stringify(incidents));
  } catch {
    /* storage may be unavailable */
  }
  for (const l of listeners) l();
}

export function getIncidents(): Incident[] {
  return incidents;
}

export function createIncident(event: SecurityEvent): Incident {
  seq += 1;
  const inc: Incident = {
    id: `INC-${String(seq).padStart(4, "0")}`,
    title: `${event.replayName ?? event.category.label} from ${event.source.city}`,
    severity: event.severity,
    status: "open",
    createdAt: Date.now(),
    event,
    assignee: "unassigned",
    timeline: [
      { ts: event.ts, label: `Detected & ${event.outcome.blocked ? "blocked" : "flagged"} by the firewall` },
      { ts: Date.now(), label: "Case created" },
    ],
    notes: [],
  };
  incidents = [inc, ...incidents];
  persist();
  return inc;
}

export function setStatus(id: string, status: IncidentStatus) {
  incidents = incidents.map((i) =>
    i.id === id
      ? { ...i, status, timeline: [...i.timeline, { ts: Date.now(), label: `Status → ${status}` }] }
      : i,
  );
  persist();
}

export function addNote(id: string, text: string) {
  if (!text.trim()) return;
  incidents = incidents.map((i) =>
    i.id === id ? { ...i, notes: [...i.notes, { ts: Date.now(), text: text.trim() }] } : i,
  );
  persist();
}

export function removeIncident(id: string) {
  incidents = incidents.filter((i) => i.id !== id);
  persist();
}

export function useIncidents(): Incident[] {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    getIncidents,
    getIncidents,
  );
}
