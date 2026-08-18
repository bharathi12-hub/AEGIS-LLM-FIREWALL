// Polls the gateway liveness endpoint so the UI can show a live/offline badge
// and pages can decide between real backend data and the in-browser engine.
import { useEffect, useState } from "react";
import { gatewayUp } from "../api";

export type GatewayState = "checking" | "online" | "offline";

export function useGateway(intervalMs = 8000): GatewayState {
  const [state, setState] = useState<GatewayState>("checking");
  useEffect(() => {
    let alive = true;
    const check = async () => {
      const up = await gatewayUp();
      if (alive) setState(up ? "online" : "offline");
    };
    check();
    const id = setInterval(check, intervalMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [intervalMs]);
  return state;
}
