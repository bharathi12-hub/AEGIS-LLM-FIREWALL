// AEGIS SOC — application root. Hash-based routing, navigation context, global
// command palette (Ctrl+K), toast provider, and auto-started live feed so the
// dashboard is alive the moment it loads.
import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { ROUTES, routeById } from "./routes";
import { NavContext } from "./lib/nav";
import { store, type SecurityEvent } from "./lib/store";
import { createIncident } from "./lib/incidents";
import { ToastProvider, useToast } from "./components/Toaster";
import Shell from "./components/Shell";
import CommandPalette from "./components/CommandPalette";
import ErrorBoundary from "./components/ErrorBoundary";
import { Modal, Skeleton } from "./components/ui";

/** Bridges Demo Mode critical blocks into toasts AND auto-creates incident cases
 *  (throttled + capped) so the Incident Response queue fills up during a demo. */
function DemoAlertsBridge() {
  const toast = useToast();
  const autoCases = useRef(0);
  useEffect(() => {
    store.alert = (e) => {
      toast({ kind: "alert", title: `Blocked: ${e.replayName ?? e.category.label}`, body: `${e.source.city} · ${e.severity} · ${Math.round((e.outcome.score ?? 0) * 100)}%` });
      if (autoCases.current < 6 && Math.random() < 0.5) {
        createIncident(e);
        autoCases.current += 1;
      }
    };
    return () => {
      store.alert = null;
    };
  }, [toast]);
  return null;
}

const SHORTCUTS: [string, string][] = [
  ["Ctrl / ⌘ + K", "Command palette · global search"],
  ["D", "Toggle Demo Mode"],
  ["F", "Toggle full-screen"],
  ["1 – 9", "Jump to a section"],
  ["?", "Show this help"],
];

function ShortcutsHelp({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Modal open={open} onClose={onClose} title="Keyboard shortcuts">
      <div className="space-y-1.5">
        {SHORTCUTS.map(([k, d]) => (
          <div key={k} className="flex items-center justify-between py-1.5 border-b border-white/[0.05] last:border-0">
            <span className="text-sm text-slate-300">{d}</span>
            <kbd className="text-[11px] font-mono border border-white/10 rounded px-2 py-0.5 text-slate-400">{k}</kbd>
          </div>
        ))}
      </div>
    </Modal>
  );
}

function PageFallback() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24 rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-64 rounded-xl" />
      <Skeleton className="h-40 rounded-xl" />
    </div>
  );
}

const VALID = new Set(ROUTES.map((r) => r.id));
const readHash = () => {
  const h = window.location.hash.replace(/^#\/?/, "");
  return VALID.has(h) ? h : "executive";
};

export default function App() {
  const [route, setRoute] = useState(readHash);
  const [focus, setFocus] = useState<SecurityEvent | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  // Keep route in sync with the URL hash (shareable + back button).
  useEffect(() => {
    const onHash = () => setRoute(readHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const go = useCallback((id: string) => {
    window.location.hash = id;
    setRoute(id);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const investigate = useCallback(
    (e: SecurityEvent) => {
      setFocus(e);
      go("investigation");
    },
    [go],
  );

  const openPalette = useCallback(() => setPaletteOpen(true), []);
  const openHelp = useCallback(() => setHelpOpen(true), []);

  // Global keyboard shortcuts.
  useEffect(() => {
    const toggleFullscreen = () => {
      if (document.fullscreenElement) document.exitFullscreen?.();
      else document.documentElement.requestFullscreen?.().catch(() => {});
    };
    const h = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      const el = e.target as HTMLElement | null;
      const typing = !!el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable);
      if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === "d" || e.key === "D") store.toggleDemo();
      else if (e.key === "f" || e.key === "F") toggleFullscreen();
      else if (e.key === "?") setHelpOpen(true);
      else if (/^[1-9]$/.test(e.key)) {
        const r = ROUTES[parseInt(e.key, 10) - 1];
        if (r) go(r.id);
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [go]);

  // Auto-start the live traffic feed once, so the SOC is populated on load.
  // Also open the gateway event stream: when a backend is reachable, real
  // detections from ANY client stream in alongside the simulated traffic and
  // are labelled as live. With no backend the stream stays closed and the
  // simulator carries the console on its own.
  useEffect(() => {
    store.start();
    store.connectLive();
    return () => {
      store.stop();
      store.disconnectLive();
    };
  }, []);

  const ActivePage = routeById(route).element;

  return (
    <ToastProvider>
      <DemoAlertsBridge />
      <NavContext.Provider value={{ route, go, focus, investigate, openPalette, openHelp }}>
        <Shell>
          <ErrorBoundary resetKey={route}>
            <Suspense fallback={<PageFallback />}>
              <ActivePage />
            </Suspense>
          </ErrorBoundary>
        </Shell>
        <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
        <ShortcutsHelp open={helpOpen} onClose={() => setHelpOpen(false)} />
      </NavContext.Provider>
    </ToastProvider>
  );
}
