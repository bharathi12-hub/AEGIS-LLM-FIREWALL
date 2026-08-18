# AEGIS v2 — Production Deployment & Operations

This is the runbook for deploying AEGIS as a real enterprise service. It documents
what makes the deployment production-grade beyond the hackathon/offline profile:
durable persistence, distributed state, federated identity, model integrity,
retention, and hardened orchestration.

## What changes vs. the offline profile

| Concern | Offline/dev | Production |
|---|---|---|
| Store | in-memory | **Postgres** (`AEGIS_DATABASE_URL`) via SQLAlchemy + Alembic migrations. Durable, hash-chained audit survives restart (proven in `test_persistence.py` against SQLite; Postgres uses the identical interface). |
| Rate limits / judge budget / sessions | per-process | **Redis** (`AEGIS_REDIS_URL`) — correct across replicas (Lua token bucket, atomic budget counters). |
| Identity | first-party API keys | **API keys OR OIDC/JWT** (Okta/Entra/Auth0/Keycloak) via JWKS; claims → tenant + RBAC role. |
| Detection models | heuristics | Real fine-tuned models via `AEGIS_MODEL_MANIFEST` + `AEGIS_HF_MODEL_DIR`, **checksum-pinned + safetensors-only** (S3), verified fail-closed at boot. |
| Serving | uvicorn | **gunicorn + uvicorn workers**, graceful shutdown, worker recycling, bounded timeouts. |
| Retention | none | in-process loop **+** K8s CronJob; PII digests only, configurable window (S7). |

## Deploy — Kubernetes (recommended)

```bash
# 1. Provision Postgres + Redis (managed or in-cluster), create the DB.
# 2. Put real secrets in a Secret via Vault/ExternalSecrets (see deploy/k8s/config.yaml).
# 3. Populate + pin models (optional but recommended):
cp models/manifest.example.json models/manifest.json   # set real commit-hash revisions
HF_TOKEN=... python scripts/fetch_models.py             # downloads + pins sha256
# 4. Deploy (migration runs in an initContainer before the app serves):
kubectl apply -k deploy/k8s
# or Helm:
helm install aegis deploy/helm/aegis -n aegis --create-namespace \
  --set image.repository=ghcr.io/you/aegis-gateway
```

Included: Deployment (3 replicas, rolling, non-root, read-only rootfs, seccomp),
HPA (3–20 on CPU/mem), PDB (minAvailable 2), NetworkPolicy (default-deny),
TLS Ingress + HSTS, ServiceMonitor + PrometheusRule alerts, retention CronJob.

## Deploy — single host (docker compose)

```bash
cd deploy && cp .env.prod.example .env.prod   # fill secrets
docker compose -f docker-compose.prod.yml --env-file .env.prod up --build \
  --scale gateway=3
```
Runs Postgres, Redis, a one-shot DB migration, 3 gateway replicas, and an nginx
TLS reverse proxy.

## Configuration reference

Secrets (from a secret manager, never committed): `AEGIS_ADMIN_API_KEY`,
`AEGIS_DATABASE_URL`, `AEGIS_AUDIT_KEY`, `AEGIS_OIDC_HS256_SECRET` (if HS256).
Key config: `AEGIS_REDIS_URL`, `AEGIS_OIDC_ISSUER/AUDIENCE/JWKS_URL`,
`AEGIS_MODEL_MANIFEST`, `AEGIS_HF_MODEL_DIR`, `AEGIS_DEFAULT_FAIL_MODE`,
`AEGIS_RESPONSE_FLOOR_MS/JITTER_MS`, `AEGIS_LOG_RETENTION_DAYS`. Full list in
`.env.example`.

## Performance (measured)

In-process single-worker load test (`python -m loadtest.run_load`, 5000 req @ 50
concurrency, `/aegis/inspect`, heuristic profile):

| | throughput | p50 | p99 |
|---|---|---|---|
| single worker | **657 req/s** | 57 ms | 124 ms |

This load test **caught a real bug**: API-key verification originally ran PBKDF2
(200k rounds) on every request, capping throughput at ~15 req/s with multi-second
latency. Fixed by hashing high-entropy API keys with a fast peppered HMAC-SHA256
(`AEGIS_KEY_PEPPER`) — the correct scheme for random tokens — a **43× speedup**.
Throughput scales ~linearly with gunicorn workers × replicas; the HPA targets 65%
CPU. Real ML models add tens of ms of CPU per request — size the model node pool
accordingly. Run a real-cluster test with `loadtest/k6.js` (SLO gate: p99 < 250ms).

## SLOs & alerting

- **Availability:** ≥ 99.9% (PDB keeps ≥2 replicas; rolling deploys are zero-downtime).
- **Latency:** p99 inspection < 250 ms (alert `AegisHighLatencyP99`). Heuristic
  path is sub-ms; real models add tens of ms on CPU — size replicas accordingly.
- **Security signal:** `AegisBlockRateSpike` fires on a 5× block-rate jump
  (campaign detection). `AegisPodDown` is critical.

## Scaling notes

- Gateway is **stateless** (state in Postgres/Redis) → scale horizontally via HPA.
- Redis makes rate limits and the judge budget global, so limits hold across pods.
- Judge budget caps expensive L4 escalation per tenant (S5) — the main cost lever.
- Real models are CPU-heavy; run a separate node pool (or GPU) and raise requests.

## Disaster recovery

- **Backups:** Postgres PITR (WAL archiving); audit is the system of record.
- **Tamper-evidence:** stream `record_hash` tips to an external WORM/SIEM sink so
  integrity is provable even after retention purges truncate the local chain.
- **RTO/RPO:** stateless app → RTO = image pull + migrate; RPO = Postgres backup
  interval. Redis is a cache (rebuilds); losing it costs only warm counters.

## Release & supply chain

`.github/workflows/release.yml`: pip-audit (CVEs), model scan (S3), Trivy image
scan (fail on HIGH/CRITICAL), CycloneDX SBOM, cosign keyless signing, push.

## Honest limitations (finish before calling it GA)

1. **Real-model eval.** Swap heuristics for the pinned HF models and re-run the
   benchmark on the *full* public datasets (thousands of rows). Expect recall/FPR
   to move off the perfect small-set numbers — publish the real figures.
2. **Cluster load & chaos testing.** Single-worker load test is done (657 rps,
   p99 124ms — see above) and it already caught+fixed the auth bottleneck. Still
   needed: k6 against a *live multi-node cluster* to validate the HPA under load,
   plus kill-pod drills to confirm fail-closed + PDB behavior in-cluster.
3. **Async store.** Store calls are sync (fast, pooled). Under very high QPS,
   move them to `run_in_threadpool` or an asyncpg store behind the same interface.
4. **External WORM audit sink** for regulatory-grade immutability.
5. **Pen test + threat-model review** by a security team before GA.
