// App navigation context: current route + cross-page actions (e.g. sending an
// event from the live monitor into the Prompt Investigation view).
import { createContext, useContext } from "react";
import type { SecurityEvent } from "./store";

export interface NavState {
  route: string;
  go: (route: string) => void;
  focus: SecurityEvent | null;
  investigate: (e: SecurityEvent) => void;
  openPalette: () => void;
  openHelp: () => void;
}

export const NavContext = createContext<NavState>({
  route: "executive",
  go: () => {},
  focus: null,
  investigate: () => {},
  openPalette: () => {},
  openHelp: () => {},
});

export const useNav = () => useContext(NavContext);
