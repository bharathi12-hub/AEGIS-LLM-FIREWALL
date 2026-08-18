"""Zero-dependency demo gateway (stdlib only) for the live dashboard.

WHY THIS EXISTS
---------------
The production gateway is a FastAPI/ASGI app served by uvicorn (see the Docker
image and ``docker-compose.yml``). In an environment without uvicorn installed,
there is no way to bring the HTTP server up — and the dashboard then falls back
to its in-browser engine, which is fine but does not *show* the real firewall.

This is a thin ``http.server`` bridge that exposes exactly the endpoints the
dashboard talks to, calling straight into the same detection pipeline the real
gateway uses (``app.pipeline`` / ``app.surfaces``). It is NOT the production
server — no auth hardening, no TLS, no rate limiter — it exists so a demo can
run the live dashboard against the real engine with zero pip installs.

    PYTHONUTF8=1 python -m demo_server           # serves on :8000
    PYTHONUTF8=1 python demo_server.py --port 8000

Then open the dashboard (port 5173); it auto-detects the gateway via /livez.

Endpoints served:
    GET  /livez                     health probe the dashboard polls
    POST /aegis/inspect             single-prompt inspection (Test Console)
    GET  /aegis/events              recent inspection events (poll)
    GET  /aegis/events/stream       server-sent live event stream
    GET  /aegis/surfaces            enabled-surface map
    OPTIONS *                       CORS preflight
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from app import __version__
from app.observability import events
from app.pipeline.orchestrator import inspect_text
from app.surfaces import status as surface_status
from app.taxonomy import atlas_for


def _inspect_payload(text: str, session_id: str) -> dict:
    """Run the real pipeline and shape it like the gateway's /aegis/inspect."""
    result = inspect_text(text or "", session_id=session_id or "demo")
    d = result.decision
    verdict = d.verdict.value
    # Demo policy: an unresolved REVIEW blocks (fail-closed), mirroring the
    # high-security tenant default.
    if verdict == "review":
        verdict = "block"
    atlas_id, atlas_label = atlas_for(d.category.value or
                                      (d.reasons[0] if d.reasons else ""))
    outcome = {
        "verdict": verdict,
        "blocked": verdict == "block",
        "category": d.category.value,
        "atlas": atlas_id,
        "atlas_label": atlas_label,
        "score": d.score,
        "reasons": d.reasons[:12],
        "contributions": d.contributions,
        "tripwires": d.tripwires,
        "latency_ms": result.latency_ms,
        "judge_used": result.judge_used,
        "forward_text": result.forward_text,
        "normalization": {
            "risk": result.normalization.risk,
            "reasons": result.normalization.reasons,
            "stripped": result.normalization.stripped_counts,
            "decoded_views": result.normalization.decoded_views[:3],
        },
        "alarms": result.alarms,
        "kad_fingerprint": result.kad_fingerprint,
        "matched_rules": len(d.reasons),
    }
    events.publish_inspection(
        tenant_id="demo", verdict=verdict, category=d.category.value,
        score=d.score, latency_ms=result.latency_ms, reasons=d.reasons,
        layer="console")
    return outcome


class Handler(BaseHTTPRequestHandler):
    server_version = f"aegis-demo/{__version__}"

    # -- helpers --------------------------------------------------------
    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers",
                         "Authorization, Content-Type, X-Admin-Key, X-AEGIS-Session")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _json(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args) -> None:  # quieter console
        return

    # -- verbs ----------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/livez":
            return self._json(200, {"status": "ok", "version": __version__,
                                    "server": "demo"})
        if path == "/aegis/surfaces":
            return self._json(200, {"surfaces": surface_status()})
        if path == "/aegis/events":
            q = parse_qs(parsed.query)
            limit = int((q.get("limit", ["100"])[0]))
            return self._json(200, {
                "events": events.get_bus().recent(limit=min(max(limit, 1), 500)),
                "stats": events.get_bus().stats()})
        if path == "/aegis/events/stream":
            return self._stream()
        return self._json(404, {"detail": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw or b"{}")
        except (json.JSONDecodeError, ValueError):
            return self._json(400, {"detail": "invalid json"})

        if parsed.path == "/aegis/inspect":
            text = str(body.get("text", ""))[:200_000]
            return self._json(200, _inspect_payload(
                text, self.headers.get("X-AEGIS-Session", "demo")))
        if parsed.path == "/v1/chat/completions":
            messages = body.get("messages") or []
            user = next((m.get("content", "") for m in reversed(messages)
                         if m.get("role") == "user"), "")
            outcome = _inspect_payload(str(user), "demo-chat")
            content = ("[AEGIS] This request was blocked by the prompt firewall."
                       if outcome["blocked"] else
                       "This is a demo backend; inspection passed.")
            return self._json(200, {
                "id": "chatcmpl-demo", "object": "chat.completion",
                "choices": [{"index": 0,
                             "finish_reason": "content_filter" if outcome["blocked"]
                             else "stop",
                             "message": {"role": "assistant", "content": content}}],
                "aegis": outcome})
        return self._json(404, {"detail": "not found"})

    # -- SSE ------------------------------------------------------------
    def _stream(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self._cors()
        self.end_headers()
        q = events.get_bus().subscribe()
        try:
            self.wfile.write(b": aegis demo stream connected\n\n")
            self.wfile.flush()
            idle = 0
            while True:
                if q:
                    ev = q.popleft()
                    frame = f"data: {json.dumps(ev.as_dict())}\n\n".encode("utf-8")
                    self.wfile.write(frame)
                    self.wfile.flush()
                    idle = 0
                else:
                    time.sleep(0.25)
                    idle += 1
                    if idle >= 4:                    # ~1s heartbeat
                        self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
                        idle = 0
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                OSError):
            # A client navigating away or reloading aborts the socket. On
            # Windows that surfaces as ConnectionAbortedError (WinError 10053),
            # which is normal for a long-lived stream — not an error worth a
            # traceback. OSError catches the rest of the disconnect family.
            pass
        finally:
            events.get_bus().unsubscribe(q)


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS stdlib demo gateway")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"AEGIS demo gateway (stdlib) on http://{args.host}:{args.port} "
          f"— real detection engine, no dependencies. Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    return 0


if __name__ == "__main__":
    sys.exit(main())
