// Notification system: a lightweight toast provider used app-wide for
// success/error/security alerts. `useToast()` returns a `push` function.
import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { Icon, type IconName } from "./icons";

type ToastKind = "info" | "success" | "error" | "alert";
interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  body?: string;
}

const KIND: Record<ToastKind, { color: string; icon: IconName }> = {
  info: { color: "#4f8cff", icon: "bell" },
  success: { color: "#2dd4a7", icon: "check" },
  error: { color: "#ff4d6d", icon: "x" },
  alert: { color: "#ff8a3d", icon: "alert" },
};

const Ctx = createContext<(t: Omit<Toast, "id">) => void>(() => {});
export const useToast = () => useContext(Ctx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const idRef = useRef(0);

  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = ++idRef.current;
    setToasts((cur) => [...cur, { ...t, id }].slice(-5));
    setTimeout(() => setToasts((cur) => cur.filter((x) => x.id !== id)), 4600);
  }, []);

  return (
    <Ctx.Provider value={push}>
      {children}
      <div className="fixed top-4 right-4 z-[60] flex flex-col gap-2 w-80 max-w-[calc(100vw-2rem)] pointer-events-none">
        {toasts.map((t) => {
          const k = KIND[t.kind];
          return (
            <div
              key={t.id}
              className="pointer-events-auto card p-3 flex items-start gap-3 animate-slide-in-right"
              style={{ boxShadow: `inset 0 0 0 1px ${k.color}33, 0 10px 30px -10px rgba(0,0,0,0.7)` }}
            >
              <span className="grid place-items-center w-7 h-7 rounded-lg shrink-0" style={{ background: `${k.color}1f`, color: k.color }}>
                <Icon name={k.icon} size={15} />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold text-slate-100">{t.title}</div>
                {t.body && <div className="text-xs text-slate-400 mt-0.5 break-words">{t.body}</div>}
              </div>
              <button
                className="text-slate-500 hover:text-slate-200 shrink-0"
                onClick={() => setToasts((cur) => cur.filter((x) => x.id !== t.id))}
                aria-label="Dismiss"
              >
                <Icon name="x" size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </Ctx.Provider>
  );
}
