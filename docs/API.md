# AEGIS v2 — API Reference

Base URL: `http://localhost:8080`. Auth: `Authorization: Bearer <tenant-key>`
for proxy endpoints; `X-Admin-Key: <admin-key>` for `/admin/*` writes.

## Proxy (OpenAI-compatible)

### `POST /v1/chat/completions`
Drop-in OpenAI chat completions. Blocks malicious input, forwards sanitized bytes
upstream, inspects the output. Response includes an `aegis` metadata block.

Optional headers: `X-AEGIS-Session: <id>` (groups turns for multi-turn context).

```json
{
  "id": "chatcmpl-...", "object": "chat.completion", "model": "aegis-guarded-gpt",
  "choices": [{"index":0,"message":{"role":"assistant","content":"..."},"finish_reason":"stop"}],
  "aegis": {
    "verdict": "allow|block", "category": "LLM01:PromptInjection", "score": 0.0,
    "contributions": {"signatures":0.0,"classifiers":0.0,"kad":0.0,"...":0.0},
    "tripwires": [], "normalization_risk": 0.0, "judge_used": false,
    "latency_ms": 0.2, "kad_fingerprint": "…", "output_block": null
  }
}
```
Blocked requests return HTTP 200 with `finish_reason: "content_filter"` and a
refusal message (so clients handle it gracefully), plus the `aegis` block.

### `POST /aegis/inspect`
Inspect-only (no upstream call). Body `{"text": "..."}`. Returns the full
per-layer outcome — powers the dashboard Test Console.

### `POST /v1/chat/completions/stream`
SSE variant. Inspects the full input **and** full output before streaming the
cleared answer (never streams un-inspected tokens).

### `GET /v1/models`
Lists the guarded model id.

## Whole-conversation inspection (v2.1 hardening)

`POST /v1/chat/completions` now inspects **every** message, not only the latest
user turn — see [HARDENING.md](HARDENING.md). No request or response field was
removed; one was added.

The `aegis` block gains a `conversation` object naming *which part* of the
request was hostile, because "blocked" is not actionable and
`message[2]:tool` is:

```json
"aegis": {
  "verdict": "block",
  "conversation": {
    "verdict": "block", "risk": 1.0, "inspected": 3,
    "quarantined_indices": [2],
    "reasons": ["tool-result-instructs@message[2]:tool"],
    "messages": [{"index": 2, "role": "tool", "risk": 1.0, "verdict": "block"}]
  }
}
```

Disable with `AEGIS_INSPECT_CONVERSATION=0` (restores exact v2.0 behaviour);
bound the window with `AEGIS_CONVERSATION_MAX_MESSAGES` (default 40).

Requests are also authorized (RBAC/ABAC/OPA) before inspection — a principal
lacking `chat:complete`, or whose trust score has decayed below the threshold
for the action, receives **403** rather than 401.

## Surfaces (v2.1 — indirect prompt injection)

Additive routes; the endpoints above are unchanged. Same bearer credential,
tenant policy, and rate limit as the proxy. Each call emits an audit record and
a sealed forensic trace, and returns `trace_id`. Full reference and the
design rationale: [SURFACES.md](SURFACES.md).

| Method | Path | Body | Returns (beyond the common fields) |
|--------|------|------|------------------------------------|
| POST | `/aegis/surface/browser` | `{html, source}` | `sanitized` — the human-visible page only |
| POST | `/aegis/surface/document` | `{content, encoding: text\|base64, filename, media_type}` | `sanitized` — visible body text only |
| POST | `/aegis/surface/rag` | `{chunks[], query, registry}` | `kept_chunks`, `quarantined_ids` |
| POST | `/aegis/surface/memory` | `{mode: write\|recall, records[], existing[]}` | `persist_allowed`, `requires_approval` |
| POST | `/aegis/surface/tool` | `{name, arguments, description, user_intent, tool_schema, policy}` | `execute_allowed`, `requires_approval` |
| POST | `/aegis/surface/agent` | `{content, sender, recipient, taint, hop}` | `deliver_allowed`, `propagated_taint` |
| POST | `/aegis/surface/multimodal` | `{content, encoding, filename, ocr_text, transcript}` | `coverage` — which channels were actually analysed |
| GET | `/aegis/surfaces` | — | enabled surfaces, thresholds, pinned MCP tools |
| GET | `/aegis/forensics/{trace_id}` | — | one sealed decision trace (tenant-scoped; 404 across tenants) |
| GET | `/aegis/forensics?limit=N` | — | recent traces for this tenant |

Common response fields on every surface route: `verdict` (`allow`/`review`/
`block`), `blocked`, `risk`, `category`, `quarantined`, `enabled`, `findings[]`,
`reasons[]`, `segments_scanned`, `segments_removed`, `latency_ms`, `trace_id`.

**Callers must branch on the action field, not just `verdict`** — `kept_chunks`
for RAG, `persist_allowed` for memory, `execute_allowed` for tools,
`deliver_allowed` for agent, and `sanitized` for browser/document.

`400` on undecodable base64 or an empty memory record set; `422` on schema
violations (oversized bodies, bad enums); `401`/`429` as elsewhere.

## Health & metrics
- `GET /healthz` — liveness.
- `GET /readyz` — readiness (rules loaded).
- `GET /metrics` — Prometheus exposition (or in-process fallback).

## Admin (`X-Admin-Key` required unless noted)
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/health` | audit chain status, counts |
| GET/POST | `/admin/tenants` | list / create tenants |
| POST | `/admin/keys` | issue a tenant API key (returned once) |
| POST | `/admin/keys/{key_id}/rotate` | rotate a key (old invalidated) |
| GET | `/admin/policy/{tenant}` | effective policy (admin **or** own-tenant key) |
| PUT | `/admin/policy/{tenant}` | set policy YAML (validated, versioned, audited) |
| POST | `/admin/policy/{tenant}/rollback/{v}` | rollback to version |
| GET | `/admin/policy/{tenant}/diff?v1=&v2=` | unified diff |
| GET | `/admin/audit/{tenant}` | tenant-scoped audit (cross-tenant denied) |
| GET | `/admin/audit/verify/chain` | recompute + verify the hash chain |
| GET | `/admin/siem/events` | structured JSON event export for SIEM |
| GET | `/admin/metrics/summary` | dashboard summary numbers |

## Error codes
`401` invalid/missing key · `403` admin/tenant scope violation · `413` prompt too
large (S14) · `429` rate limited (S5) · `422` invalid policy (S13).
