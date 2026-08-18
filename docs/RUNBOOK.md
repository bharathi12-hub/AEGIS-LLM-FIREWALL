# AEGIS v2 — Operations Runbook

On-call reference for the AEGIS prompt firewall. The gateway is a **security
control in the request path**: when in doubt, prefer availability of *protection*
(fail-closed) over availability of *throughput*.

## Service map
- **gateway** (stateless, N replicas) — the firewall + proxy.
- **postgres** — durable store: tenants, keys, policies, hash-chained audit (system of record).
- **redis** — rate limits, judge budget, session/canary/context state (cache; rebuildable).
- **IdP** (external) — OIDC JWKS for JWT auth.
- **upstream LLM** (external/internal) — the model AEGIS guards.

## Health & signals
- `GET /livez` — process up. `GET /readyz` — 200 only if rules loaded + store + redis reachable (else 503 → drained).
- Metrics: `aegis_requests_total{verdict}`, `aegis_blocks_total{category}`, `aegis_judge_calls_total`, `aegis_latency_ms`.
- Alerts: `AegisHighLatencyP99` (>250ms), `AegisBlockRateSpike` (5× jump), `AegisPodDown` (<2 replicas).

## Common incidents

### 1. Latency high / p99 alert firing
- Check `aegis_judge_calls_total` rate — a judge-escalation flood raises latency. The per-tenant judge budget (S5) caps it; lower `AEGIS_JUDGE_BUDGET_PER_MIN` for the noisy tenant.
- Check CPU — real ML models are CPU-heavy. Scale replicas (HPA should) or move to a model node pool.
- **Known footgun:** ensure `AEGIS_KEY_PEPPER` is set — without it, API-key verification falls back to a slow KDF per request (load-tested: ~15 rps vs ~657 rps single worker). The preflight warns about this.

### 2. Block rate spiked (`AegisBlockRateSpike`)
- Usually a real attack campaign — inspect `GET /admin/siem/events` for the dominant category/tenant. This is the system working.
- If it's a false-positive surge after a policy/rules change: `GET /admin/policy/{tenant}` and roll back: `POST /admin/policy/{tenant}/rollback/{version}`.

### 3. Legitimate traffic being blocked (over-defense)
- Reproduce in the Test Console (`POST /aegis/inspect`) to see per-layer contributions.
- If a signature over-triggers, raise `block_threshold` for the tenant or add an `allow_list` entry via `PUT /admin/policy/{tenant}` (validated + audited). Prefer a scoped fix over disabling a layer.

### 4. A detection layer is failing (errors in logs)
- High-security (fail-closed) tenants will BLOCK — that's intended; protection is preserved. Alarms are logged (`fail-closed:<layer>`).
- Fix the layer (e.g. model dir / OOM), don't switch tenants to fail-open to "restore" traffic without approval.

### 5. Redis down
- Rate limits/budgets fall back to per-process (still enforced, just per-pod). `/readyz` reports redis:false. Non-fatal; restore Redis; no data loss (cache).

### 6. Postgres down
- `/readyz` → 503, pods drain. This is a hard dependency (audit + auth). Restore from the HA replica / backup (see BACKUP below). Auth fails closed → no unauthenticated access.

### 7. Suspected audit tampering
- `GET /admin/audit/verify/chain` recomputes the hash chain and returns the first bad sequence. Cross-check against the external WORM/SIEM sealed tips.

## Deploys & rollback
- Rolling, zero-downtime (maxUnavailable 0). DB migration runs in an initContainer before serving.
- Rollback: `kubectl rollout undo deploy/aegis-gateway` (or redeploy the prior image tag). Migrations are additive; a schema rollback needs a down-migration + coordinated app version.

## Config change safety
- Policy changes are validated (S13) — an invalid policy is rejected (422), never applied.
- Never set `AEGIS_DEFAULT_FAIL_MODE=open` or `AEGIS_CORS_ORIGINS=*` in prod — the preflight gate refuses to boot.
