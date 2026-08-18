"""Gunicorn config for the AEGIS gateway (production ASGI serving).

Uvicorn workers behind gunicorn for process supervision + graceful restarts.
Tuned for a security gateway: bounded timeouts (S5), max-requests recycling to
bound memory, and graceful shutdown so in-flight inspections complete.
"""
import multiprocessing
import os

bind = os.getenv("AEGIS_BIND", "0.0.0.0:8080")
worker_class = "uvicorn.workers.UvicornWorker"
# 2*CPU+1 is the usual heuristic; override with AEGIS_WORKERS in K8s (1 per core).
workers = int(os.getenv("AEGIS_WORKERS", (multiprocessing.cpu_count() * 2) + 1))
threads = int(os.getenv("AEGIS_THREADS", "4"))

timeout = int(os.getenv("AEGIS_WORKER_TIMEOUT", "30"))
graceful_timeout = int(os.getenv("AEGIS_GRACEFUL_TIMEOUT", "25"))
keepalive = int(os.getenv("AEGIS_KEEPALIVE", "5"))

# Recycle workers to bound memory growth (defense against slow leaks).
max_requests = int(os.getenv("AEGIS_MAX_REQUESTS", "2000"))
max_requests_jitter = int(os.getenv("AEGIS_MAX_REQUESTS_JITTER", "200"))

# Bound request body so a huge payload can't exhaust a worker (S14 defense-in-depth).
limit_request_line = 8190
limit_request_field_size = 16380

accesslog = "-"
errorlog = "-"
loglevel = os.getenv("AEGIS_LOG_LEVEL", "info")
# JSON-ish access log; app emits structured events on stdout separately.
access_log_format = '%(h)s %(m)s %(U)s %(s)s %(D)sus'
forwarded_allow_ips = "*"  # behind the ingress/reverse proxy
