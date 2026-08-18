// Application shell: SOC sidebar + top command bar + responsive drawer. Consumes
// the nav context and the live store so navigation, the feed toggle and the
// connection badge all stay in sync across pages.
import { useMemo, useState, type ReactNode } from "react";
import { ROUTES, SECTIONS, routeById } from "../routes";
import { Icon } from "./icons";
import { useNav } from "../lib/nav";
import { store, useEvents, useSimRunning, useDemo, useLive, computeStats } from "../lib/store";
import { useGateway } from "../lib/useGateway";
import { LiveDot } from "./ui";

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative grid place-items-center w-9 h-9 rounded-xl bg-gradient-to-br from-aegis-accent to-aegis-cyan shadow-glow">
        <Icon name="shieldCheck" size={20} className="text-white" />
      </div>
      <div className="leading-tight">
        <div className="font-bold text-slate-50 tracking-tight text-[15px]">LLM Firewall</div>
        <div className="text-[10px] font-semibold tracking-[0.2em] text-gradient -mt-0.5">PLATFORM</div>
      </div>
    </div>
  );
}

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const { route, go } = useNav();
  return (
    <div className="flex flex-col h-full">
      <div className="px-4 py-4">
        <Logo />
      </div>
      <nav className="flex-1 overflow-y-auto px-3 space-y-4 pb-4">
        {SECTIONS.map((section) => (
          <div key={section}>
            <div className="px-3 mb-1 text-[10px] uppercase tracking-wider text-slate-600 font-semibold">{section}</div>
            <div className="space-y-0.5">
              {ROUTES.filter((r) => r.section === section).map((r) => (
                <button
                  key={r.id}
                  onClick={() => { go(r.id); onNavigate?.(); }}
                  className={`navlink w-full ${route === r.id ? "navlink-active" : ""}`}
                >
                  <Icon name={r.icon} size={17} className="shrink-0" />
                  <span className="truncate">{r.label}</span>
                </button>
              ))}
            </div>
          </div>
        ))}
      </nav>
      <div className="px-4 py-3 border-t border-white/[0.06] text-[11px] text-slate-600">
        <div className="flex items-center justify-between">
          <span>LLM Firewall Platform</span>
          <span className="chip !py-0.5 !px-2 !text-[10px] text-aegis-ok">defensive</span>
        </div>
      </div>
    </div>
  );
}

export default function Shell({ children }: { children: ReactNode }) {
  const { route, go, openPalette, openHelp } = useNav();
  const running = useSimRunning();
  const live = useLive();
  const demo = useDemo();
  const events = useEvents();
  const gw = useGateway();
  const [drawer, setDrawer] = useState(false);
  const active = useMemo(() => computeStats(events).activeAttacks, [events]);
  const current = routeById(route);

  const gwColor = gw === "online" ? "#2dd4a7" : gw === "checking" ? "#ffb454" : "#64748b";

  return (
    <div className="min-h-screen flex">
      {/* Desktop sidebar */}
      <aside className="hidden lg:flex w-[248px] shrink-0 border-r border-white/[0.06] bg-aegis-panel/40 backdrop-blur-md flex-col sticky top-0 h-screen">
        <SidebarContent />
      </aside>

      {/* Mobile drawer */}
      {drawer && (
        <div className="lg:hidden fixed inset-0 z-50 flex">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setDrawer(false)} />
          <aside className="relative w-[248px] bg-aegis-panel border-r border-white/[0.06] animate-slide-in-right">
            <SidebarContent onNavigate={() => setDrawer(false)} />
          </aside>
        </div>
      )}

      {/* Main column */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="sticky top-0 z-40 h-14 flex items-center gap-3 px-4 border-b border-white/[0.06] bg-aegis-bg/70 backdrop-blur-md">
          <button className="lg:hidden btn-ghost !p-2" onClick={() => setDrawer(true)} aria-label="Menu">
            <Icon name="grid" size={18} />
          </button>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Icon name={current.icon} size={16} className="text-aegis-accent" />
              <h1 className="text-sm font-semibold text-slate-100 truncate">{current.label}</h1>
            </div>
          </div>

          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={openPalette}
              className="hidden sm:flex items-center gap-2 text-xs text-slate-400 border border-white/10 rounded-lg px-3 py-1.5 hover:bg-white/[0.04] transition-colors"
            >
              <Icon name="search" size={14} /> Search…
              <kbd className="text-[10px] border border-white/10 rounded px-1 py-0.5 text-slate-500">Ctrl K</kbd>
            </button>

            <button className="btn-ghost !p-2 hidden sm:flex" onClick={openHelp} aria-label="Keyboard shortcuts" title="Keyboard shortcuts (?)">
              <Icon name="keyboard" size={16} />
            </button>
            <button
              className="btn-ghost !p-2 hidden sm:flex"
              onClick={() => { if (document.fullscreenElement) document.exitFullscreen?.(); else document.documentElement.requestFullscreen?.().catch(() => {}); }}
              aria-label="Full-screen"
              title="Full-screen (F)"
            >
              <Icon name="expand" size={16} />
            </button>

            <button
              className={`!py-1.5 !px-3 ${demo ? "btn-danger" : "btn"}`}
              onClick={() => store.toggleDemo()}
              title="One-click presentation mode: simulated enterprise traffic, attacks & alerts"
            >
              <Icon name={demo ? "pause" : "sparkles"} size={13} />
              <span className="hidden sm:inline">{demo ? "Stop demo" : "Demo Mode"}</span>
            </button>

            <button className="btn-ghost !py-1.5 !px-3" onClick={() => store.toggle()} title={running ? "Pause the live feed" : "Start the live feed"}>
              <Icon name={running ? "pause" : "play"} size={13} />
              <span className="hidden lg:inline">{running ? "Pause" : "Go live"}</span>
            </button>

            <button
              onClick={() => go("monitor")}
              className="relative btn-ghost !p-2"
              aria-label="Alerts"
              title={`${active} active attacks`}
            >
              <Icon name="bell" size={17} />
              {active > 0 && (
                <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 grid place-items-center text-[9px] font-bold rounded-full bg-sev-critical text-white">
                  {active > 99 ? "99+" : active}
                </span>
              )}
            </button>

            <div className="hidden md:flex items-center gap-1.5 text-xs pl-1">
              <span className="w-2 h-2 rounded-full animate-pulse" style={{ background: gwColor }} />
              <span className="text-slate-400">{gw === "online" ? "Gateway" : gw === "checking" ? "…" : "Local"}</span>
            </div>
          </div>
        </header>

        <main className="flex-1 p-4 md:p-6 max-w-[1600px] w-full mx-auto">
          {demo && (
            <div
              className="mb-4 flex items-center gap-3 rounded-xl px-4 py-2.5 animate-slide-up"
              style={{ background: "rgba(79,140,255,0.1)", boxShadow: "inset 0 0 0 1px rgba(79,140,255,0.3)" }}
            >
              <span className="relative flex w-2.5 h-2.5">
                <span className="absolute inline-flex w-full h-full rounded-full bg-aegis-accent opacity-60 animate-ping" />
                <span className="relative inline-flex w-2.5 h-2.5 rounded-full bg-aegis-accent" />
              </span>
              <span className="text-sm font-semibold text-slate-100">Demo Mode active</span>
              <span className="text-xs text-slate-400 hidden sm:inline">
                Simulated enterprise traffic & attacks — detection is real, traffic is synthetic.
              </span>
              <button className="btn-ghost !py-1 !px-2 !text-xs ml-auto" onClick={() => store.toggleDemo()}>
                <Icon name="pause" size={12} /> Stop
              </button>
            </div>
          )}
          <div className="mb-4 flex items-center justify-between gap-2">
            <p className="text-xs text-slate-500 truncate">{current.desc}</p>
            <div className="flex items-center gap-2 shrink-0">
              {live ? (
                <span
                  className="chip !py-0.5 !px-2 !text-[10px] text-aegis-ok"
                  title="Connected to the AEGIS gateway — these are real detections streaming from the backend."
                >
                  <Icon name="radar" size={11} /> Live gateway
                </span>
              ) : (
                <span
                  className="chip !py-0.5 !px-2 !text-[10px] text-aegis-warn"
                  title="No gateway reachable: traffic is synthetic, but the detection engine and verdicts are real (in-browser port of the same pipeline)."
                >
                  <Icon name="eye" size={11} /> Simulated data
                </span>
              )}
              <LiveDot on={running} />
            </div>
          </div>
          {children}
        </main>
      </div>
    </div>
  );
}
