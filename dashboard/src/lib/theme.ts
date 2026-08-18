// Theme (light / dark) store. Dark is the default enterprise SOC look; the user
// can switch in Settings. The choice is persisted and applied to
// <html data-theme> so CSS variable overrides flip the whole UI.
import { useSyncExternalStore } from "react";

export type Theme = "dark" | "light";
const KEY = "aegis_theme";

function read(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark") return v;
  } catch {
    /* ignore */
  }
  return "dark";
}

let theme: Theme = read();
const listeners = new Set<() => void>();

function apply(t: Theme) {
  const root = document.documentElement;
  root.setAttribute("data-theme", t);
  root.style.colorScheme = t;
}

// Apply immediately on import so there's no flash of the wrong theme.
apply(theme);

export function getTheme(): Theme {
  return theme;
}
export function setTheme(t: Theme) {
  theme = t;
  try {
    localStorage.setItem(KEY, t);
  } catch {
    /* ignore */
  }
  apply(t);
  for (const l of listeners) l();
}
export function toggleTheme() {
  setTheme(theme === "dark" ? "light" : "dark");
}

export function useTheme(): Theme {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    getTheme,
    getTheme,
  );
}
