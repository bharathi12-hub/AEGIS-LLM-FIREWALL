// Route registry for the SOC dashboard. Each route maps to a page component and
// is grouped into a sidebar section. Pages are lazy-loaded so heavy chart code
// (Recharts) only ships for the pages that actually use it — keeps first paint
// and the initial bundle small.
import { lazy, type ComponentType } from "react";
import type { IconName } from "./components/icons";

const ExecutiveDashboard = lazy(() => import("./pages/ExecutiveDashboard"));
const Storyline = lazy(() => import("./pages/Storyline"));
const LiveThreatMonitor = lazy(() => import("./pages/LiveThreatMonitor"));
const PromptInvestigation = lazy(() => import("./pages/PromptInvestigation"));
const DetectionPipeline = lazy(() => import("./pages/DetectionPipeline"));
const AttackSimulator = lazy(() => import("./pages/AttackSimulator"));
const DetectionTuning = lazy(() => import("./pages/DetectionTuning"));
const ThreatIntelligence = lazy(() => import("./pages/ThreatIntelligence"));
const Analytics = lazy(() => import("./pages/Analytics"));
const Benchmark = lazy(() => import("./pages/Benchmark"));
const PolicyManager = lazy(() => import("./pages/PolicyManager"));
const IncidentResponse = lazy(() => import("./pages/IncidentResponse"));
const AuditTrail = lazy(() => import("./pages/AuditTrail"));
const ThreatModel = lazy(() => import("./pages/ThreatModel"));
const Reports = lazy(() => import("./pages/Reports"));
const Settings = lazy(() => import("./pages/Settings"));

export type Section = "Operations" | "Intelligence" | "Governance" | "System";

export interface RouteDef {
  id: string;
  label: string;
  icon: IconName;
  section: Section;
  element: ComponentType;
  desc: string;
}

export const ROUTES: RouteDef[] = [
  { id: "executive", label: "Executive Dashboard", icon: "grid", section: "Operations", element: ExecutiveDashboard, desc: "Posture, KPIs & attack map" },
  { id: "storyline", label: "Attack Storyline", icon: "route", section: "Operations", element: Storyline, desc: "End-to-end attack lifecycle" },
  { id: "monitor", label: "Live Threat Monitor", icon: "radar", section: "Operations", element: LiveThreatMonitor, desc: "Real-time attack stream" },
  { id: "investigation", label: "Prompt Investigation", icon: "search", section: "Operations", element: PromptInvestigation, desc: "Split-view prompt inspector" },
  { id: "pipeline", label: "Detection Pipeline", icon: "flow", section: "Operations", element: DetectionPipeline, desc: "Animated engine walk-through" },
  { id: "simulator", label: "Attack Simulator", icon: "zap", section: "Operations", element: AttackSimulator, desc: "One-click attack replay" },
  { id: "tuning", label: "Detection Tuning", icon: "cpu", section: "Operations", element: DetectionTuning, desc: "Live thresholds, layers & rules" },

  { id: "intel", label: "Threat Intelligence", icon: "globe", section: "Intelligence", element: ThreatIntelligence, desc: "MITRE, IOCs & sources" },
  { id: "analytics", label: "Analytics", icon: "chart", section: "Intelligence", element: Analytics, desc: "Trends & breakdowns" },
  { id: "benchmark", label: "Benchmark", icon: "gauge", section: "Intelligence", element: Benchmark, desc: "Evasion resistance proof" },

  { id: "policy", label: "Policy Manager", icon: "sliders", section: "Governance", element: PolicyManager, desc: "Policy-as-code & compliance" },
  { id: "incidents", label: "Incident Response", icon: "alert", section: "Governance", element: IncidentResponse, desc: "Case management & investigations" },
  { id: "audit", label: "Audit Trail", icon: "scroll", section: "Governance", element: AuditTrail, desc: "Immutable audit log" },
  { id: "threatmodel", label: "Threat Model", icon: "shield", section: "Governance", element: ThreatModel, desc: "Firewall self-security" },
  { id: "reports", label: "Reports", icon: "file", section: "Governance", element: Reports, desc: "PDF & CSV export" },

  { id: "settings", label: "Settings", icon: "settings", section: "System", element: Settings, desc: "Connection & credentials" },
];

export const SECTIONS: Section[] = ["Operations", "Intelligence", "Governance", "System"];
export const routeById = (id: string) => ROUTES.find((r) => r.id === id) ?? ROUTES[0];
