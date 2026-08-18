"""AEGIS v2 gateway — FastAPI application assembly.

Secure by default (R8): CORS locked to the dashboard origin, security headers on
every response, admin endpoints behind a separate admin key, secrets from env.
The pipeline, policy, storage, and observability modules are wired here; the app
runs fully offline against the mock upstream and in-memory stores, and lights up
Redis/Postgres/real-model layers when their env vars are set.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response

from app import __version__
from app.api import admin, proxy, stream, surfaces
from app.auth import bootstrap_default_tenants
from app.config import settings
from app.observability import metrics
from app.observability.logging import log_event


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio

    # Production preflight: refuse to boot with insecure config (non-offline only).
    from app.security.preflight import assert_production_safe
    report = assert_production_safe()
    for w in report.warnings:
        log_event("preflight_warning", msg=w)

    # S3: verify pinned model integrity BEFORE serving; fail-closed on mismatch.
    manifest = os.getenv("AEGIS_MODEL_MANIFEST", "")
    if manifest and os.path.exists(manifest):
        from app.security.registry import assert_registry_ok
        assert_registry_ok(manifest)  # raises -> app refuses to start
        log_event("model_registry_verified", manifest=manifest)

    # Seed demo tenants + keys for offline runs; print the keys once to the log.
    if os.getenv("AEGIS_BOOTSTRAP", "1") == "1":
        for tenant, raw in bootstrap_default_tenants().items():
            log_event("bootstrap_key", tenant=tenant, api_key=raw)
    if not settings.admin_api_key:
        log_event("warning", msg="AEGIS_ADMIN_API_KEY not set; admin API disabled")

    # S7: periodic retention purge of aged audit records.
    from app.observability.retention import retention_loop
    task = asyncio.create_task(retention_loop(interval_seconds=3600))
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="AEGIS v2 — Adversarial Prompt Firewall", version=__version__,
              lifespan=lifespan)

# CORS locked to the dashboard origin (S10).
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type", "X-Admin-Key", "X-AEGIS-Session"],
)


@app.middleware("http")
async def observability_and_headers(request: Request, call_next):
    import secrets
    import time

    # Correlation ID: propagate an inbound one or mint a new one (S6-safe: hex).
    rid = request.headers.get("x-request-id", "")
    if not rid or not all(c in "0123456789abcdefABCDEF-" for c in rid) or len(rid) > 64:
        rid = secrets.token_hex(8)

    start = time.perf_counter()
    response = await call_next(request)
    dur_ms = round((time.perf_counter() - start) * 1000, 2)

    response.headers["X-Request-ID"] = rid
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"

    # Structured access log (path only — never the body, which may be untrusted).
    log_event("access", request_id=rid, method=request.method,
              path=request.url.path, status=response.status_code, dur_ms=dur_ms)
    return response


app.include_router(proxy.router)
app.include_router(stream.router)
app.include_router(admin.router)
# v2.1 surfaces — additive routes; the v2.0 endpoints above are unchanged.
app.include_router(surfaces.router)
app.include_router(surfaces.meta_router)


@app.get("/livez")
async def livez():
    # Liveness: the process is up. Cheap, no dependency checks.
    return {"status": "ok", "version": __version__}


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "version": __version__, "offline": settings.offline}


@app.get("/readyz")
async def readyz(response: Response):
    """Readiness: rules loaded AND dependencies reachable. 503 when not ready so
    the load balancer/K8s drains this pod instead of sending it traffic."""
    from app.pipeline.signatures import _load_rules
    checks = {"rules": len(_load_rules()) > 0}

    # Durable store reachability (Postgres/SQLite) — a cheap query.
    try:
        from app.storage.db import get_store
        get_store().list_tenants()
        checks["store"] = True
    except Exception:  # noqa: BLE001
        checks["store"] = False

    # Redis reachability, only if configured.
    if settings.redis_url:
        try:
            import redis
            redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1).ping()
            checks["redis"] = True
        except Exception:  # noqa: BLE001
            checks["redis"] = False

    ready = all(checks.values())
    if not ready:
        response.status_code = 503
    return {"ready": ready, "checks": checks}


@app.get("/metrics")
async def prometheus_metrics():
    payload, content_type = metrics.render_latest()
    return Response(content=payload, media_type=content_type)


@app.get("/", response_class=PlainTextResponse)
async def root():
    return (f"AEGIS v2 firewall v{__version__} — POST /v1/chat/completions "
            f"(OpenAI-compatible). Admin under /admin. Metrics at /metrics.")
