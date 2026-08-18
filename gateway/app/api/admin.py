"""Admin API (Section 6) — RBAC, policy-as-code, immutable audit, SIEM export.

Privileged operations require a SEPARATE admin key (S10) via the ``X-Admin-Key``
header. Tenant-scoped reads may alternatively use a tenant principal (Bearer
key); the store enforces that a principal can never read another tenant's data
(S8). Policy writes are schema-validated (S13) and audited (who/when/what).
"""
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Request

from app.auth import Principal, issue_key, rotate_key, verify_admin
from app.security.oidc import principal_from_token
from app.observability import audit, metrics
from app.observability.logging import sanitize_for_render
from app.policy.engine import get_engine
from app.policy.schema import PolicyValidationError
from app.storage.db import CrossTenantError, get_store
from app.storage.models import Tenant

router = APIRouter(prefix="/admin")


def _require_admin(x_admin_key: str | None) -> None:
    if not verify_admin(x_admin_key or ""):
        raise HTTPException(status_code=403, detail="admin key required")


def _principal(authorization: str | None) -> Principal | None:
    if authorization and authorization.lower().startswith("bearer "):
        return principal_from_token(authorization[7:].strip())
    return None


@router.get("/health")
async def health(x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    ok, bad = audit.verify_chain()
    store = get_store()
    return {"status": "ok", "tenants": len(store.list_tenants()),
            "audit_records": len(store.all_audit()),
            "audit_chain_ok": ok, "audit_first_bad": bad}


@router.get("/tenants")
async def list_tenants(x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    return [{"tenant_id": t.tenant_id, "name": t.name, "fail_mode": t.fail_mode,
             "policy_version": t.policy_version} for t in get_store().list_tenants()]


@router.post("/tenants")
async def create_tenant(request: Request, x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    body = await request.json()
    tid = body["tenant_id"]
    tenant = Tenant(tenant_id=tid, name=body.get("name", tid),
                    fail_mode=body.get("fail_mode", "closed"))
    get_store().put_tenant(tenant)
    return {"created": tid, "fail_mode": tenant.fail_mode}


@router.post("/keys")
async def create_key(request: Request, x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    body = await request.json()
    raw, record = issue_key(body["tenant_id"], body.get("role", "analyst"))
    # Raw key returned exactly once; only the hash is stored.
    return {"api_key": raw, "key_id": record.key_id, "role": record.role,
            "tenant_id": record.tenant_id}


@router.post("/keys/{key_id}/rotate")
async def rotate(key_id: str, x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    try:
        raw, record = rotate_key(key_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="key not found")
    return {"api_key": raw, "key_id": record.key_id, "rotated_from": key_id}


@router.get("/policy/{tenant_id}")
async def get_policy(tenant_id: str, x_admin_key: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)):
    principal = _principal(authorization)
    is_admin = verify_admin(x_admin_key or "")
    if not is_admin and (not principal or principal.tenant_id != tenant_id):
        raise HTTPException(status_code=403, detail="not authorized for this tenant")
    eff = get_engine().effective(tenant_id)
    return {"tenant_id": tenant_id, "version": eff.version, "fail_mode": eff.fail_mode,
            "block_threshold": eff.block_threshold, "review_threshold": eff.review_threshold,
            "judge_enabled": eff.judge_enabled, "allow_list": eff.allow_list,
            "deny_list": eff.deny_list, "versions": get_store().policy_versions(tenant_id)}


@router.put("/policy/{tenant_id}")
async def set_policy(tenant_id: str, request: Request,
                     x_admin_key: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)):
    principal = _principal(authorization)
    is_admin = verify_admin(x_admin_key or "")
    if not is_admin and not (principal and principal.tenant_id == tenant_id
                             and principal.can_write_policy()):
        raise HTTPException(status_code=403, detail="not authorized to write policy")
    body = await request.json()
    yaml_text = body.get("yaml", "")
    author = (principal.key_id if principal else "admin")
    try:
        eff = get_engine().set_policy(tenant_id, yaml_text, author)
    except PolicyValidationError as exc:
        raise HTTPException(status_code=422, detail=f"invalid policy: {exc}")
    return {"tenant_id": tenant_id, "version": eff.version, "applied": True}


@router.post("/policy/{tenant_id}/rollback/{version}")
async def rollback(tenant_id: str, version: int,
                   x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    try:
        eff = get_engine().rollback(tenant_id, version, "admin")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"tenant_id": tenant_id, "new_version": eff.version, "rolled_back_to": version}


@router.get("/policy/{tenant_id}/diff")
async def policy_diff(tenant_id: str, v1: int, v2: int,
                      x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    return {"diff": get_engine().diff(tenant_id, v1, v2)}


@router.get("/audit/{tenant_id}")
async def read_audit(tenant_id: str, limit: int = 100,
                     x_admin_key: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)):
    principal = _principal(authorization)
    is_admin = verify_admin(x_admin_key or "")
    requester = principal.tenant_id if principal else tenant_id
    try:
        rows = get_store().read_audit(tenant_id, requester, is_admin=is_admin, limit=limit)
    except CrossTenantError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return [{"seq": r.seq, "ts": r.ts, "event": r.event, "layer": r.layer,
             "verdict": r.verdict, "reason": sanitize_for_render(r.reason, 200),
             "record_hash": r.record_hash[:16], "payload_digest": r.payload_digest[:16]}
            for r in rows]


@router.get("/audit/verify/chain")
async def verify_audit(x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    ok, bad = audit.verify_chain()
    return {"chain_ok": ok, "first_bad_seq": bad,
            "records": len(get_store().all_audit())}


@router.get("/siem/events")
async def siem_export(x_admin_key: str | None = Header(default=None), limit: int = 500):
    """Structured JSON stream of security events for SIEM ingestion (Section 6)."""
    _require_admin(x_admin_key)
    rows = get_store().all_audit()[-limit:]
    return {"format": "aegis-json", "events": [
        {"seq": r.seq, "tenant": r.tenant_id, "ts": r.ts, "event": r.event,
         "layer": r.layer, "verdict": r.verdict,
         "reason": sanitize_for_render(r.reason, 200), "hash": r.record_hash}
        for r in rows]}


@router.get("/metrics/summary")
async def metrics_summary(x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    return metrics.summary()
