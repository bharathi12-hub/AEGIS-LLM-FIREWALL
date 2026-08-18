// Command Palette (Ctrl/Cmd+K): fuzzy-jump to any page or replay any attack
// vector. Keyboard-driven — arrows to move, Enter to run, Esc to close.
import { useEffect, useMemo, useRef, useState } from "react";
import { ROUTES } from "../routes";
import { ATTACKS } from "../lib/attacks";
import { store } from "../lib/store";
import { Icon, type IconName } from "./icons";
import { useNav } from "../lib/nav";
import { useToast } from "./Toaster";

interface Cmd {
  id: string;
  label: string;
  hint: string;
  icon: IconName;
  kind: "nav" | "attack";
  run: () => void | Promise<void>;
}

export default function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { go, investigate } = useNav();
  const toast = useToast();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const commands: Cmd[] = useMemo(() => {
    const nav: Cmd[] = ROUTES.map((r) => ({
      id: `nav:${r.id}`,
      label: r.label,
      hint: r.desc,
      icon: r.icon,
      kind: "nav",
      run: () => go(r.id),
    }));
    const atk: Cmd[] = ATTACKS.map((a) => ({
      id: `atk:${a.id}`,
      label: `Replay: ${a.name}`,
      hint: a.desc,
      icon: "zap",
      kind: "attack",
      run: async () => {
        const e = await store.replay(a, "plain");
        toast({ kind: e.outcome.blocked ? "success" : "alert", title: `${e.outcome.blocked ? "Blocked" : "Allowed"}: ${a.name}`, body: e.category.label });
        investigate(e);
      },
    }));
    return [...nav, ...atk];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase();
    if (!query) return commands;
    return commands.filter((c) => (c.label + " " + c.hint).toLowerCase().includes(query));
  }, [q, commands]);

  useEffect(() => {
    if (open) {
      setQ("");
      setSel(0);
      setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [open]);

  useEffect(() => setSel(0), [q]);

  if (!open) return null;

  const exec = (c: Cmd) => {
    onClose();
    c.run();
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(filtered.length - 1, s + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
    else if (e.key === "Enter") { e.preventDefault(); if (filtered[sel]) exec(filtered[sel]); }
    else if (e.key === "Escape") { onClose(); }
  };

  return (
    <div className="fixed inset-0 z-[70] bg-black/60 backdrop-blur-sm animate-fade-in flex items-start justify-center pt-[12vh] px-4" onClick={onClose}>
      <div className="card w-full max-w-xl overflow-hidden animate-slide-up" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 px-3 border-b border-white/[0.06]">
          <Icon name="search" size={16} className="text-slate-500" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
            placeholder="Jump to a page or replay an attack…"
            className="!border-0 !bg-transparent !ring-0 !px-1 py-3 text-sm"
          />
          <kbd className="text-[10px] text-slate-500 border border-white/10 rounded px-1.5 py-0.5">ESC</kbd>
        </div>
        <div ref={listRef} className="max-h-[52vh] overflow-auto p-1.5">
          {filtered.length === 0 && <div className="text-sm text-slate-500 text-center py-6">No commands match “{q}”.</div>}
          {filtered.map((c, i) => (
            <button
              key={c.id}
              onMouseEnter={() => setSel(i)}
              onClick={() => exec(c)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition-colors ${
                i === sel ? "bg-aegis-accent/15 ring-1 ring-inset ring-aegis-accent/40" : "hover:bg-white/[0.04]"
              }`}
            >
              <span className={`grid place-items-center w-8 h-8 rounded-lg shrink-0 ${c.kind === "attack" ? "bg-sev-critical/15 text-sev-critical" : "bg-white/[0.05] text-aegis-accent"}`}>
                <Icon name={c.icon} size={15} />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-sm text-slate-100 truncate">{c.label}</div>
                <div className="text-[11px] text-slate-500 truncate">{c.hint}</div>
              </div>
              {i === sel && <Icon name="arrowRight" size={14} className="text-slate-400" />}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
