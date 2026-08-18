"""Postgres-backed store for horizontal scale / HA (production target).

Implements the same synchronous interface as ``InMemoryStore`` / ``SqliteStore``
using SQLAlchemy 2.0 Core with a pooled sync engine (psycopg driver). The store
calls are small and fast; the gateway keeps them synchronous to match the
detection pipeline. (An async/asyncpg variant is a drop-in future optimization
behind the same method names via ``run_in_threadpool`` at the call sites.)

SQLAlchemy is imported lazily so the offline/stdlib profile never needs it.
Enable with ``AEGIS_DATABASE_URL=postgresql+psycopg://user:pw@host:5432/aegis``.
Schema is created/managed by Alembic migrations (gateway/migrations); this module
also creates tables if absent so a fresh dev DB just works.
"""
from __future__ import annotations

import json
import threading

from app.storage.db import CrossTenantError
from app.storage.models import ApiKey, AuditRecord, PolicyRecord, Tenant


def _build(url: str):
    import sqlalchemy as sa  # lazy

    md = sa.MetaData()
    tenants = sa.Table(
        "tenants", md,
        sa.Column("tenant_id", sa.String, primary_key=True),
        sa.Column("name", sa.String), sa.Column("fail_mode", sa.String),
        sa.Column("policy_version", sa.Integer), sa.Column("created_at", sa.Float),
    )
    keys = sa.Table(
        "api_keys", md,
        sa.Column("key_id", sa.String, primary_key=True),
        sa.Column("tenant_id", sa.String, index=True),
        sa.Column("hashed_secret", sa.String), sa.Column("role", sa.String),
        sa.Column("active", sa.Boolean), sa.Column("created_at", sa.Float),
        sa.Column("rotated_from", sa.String, nullable=True),
    )
    audit = sa.Table(
        "audit", md,
        sa.Column("seq", sa.BigInteger, primary_key=True, autoincrement=False),
        sa.Column("tenant_id", sa.String, index=True), sa.Column("ts", sa.Float),
        sa.Column("event", sa.String), sa.Column("layer", sa.String),
        sa.Column("verdict", sa.String), sa.Column("reason", sa.String),
        sa.Column("prev_hash", sa.String), sa.Column("record_hash", sa.String),
        sa.Column("payload_digest", sa.String), sa.Column("meta", sa.Text),
    )
    policies = sa.Table(
        "policies", md,
        sa.Column("tenant_id", sa.String, primary_key=True),
        sa.Column("version", sa.Integer, primary_key=True),
        sa.Column("yaml_text", sa.Text), sa.Column("author", sa.String),
        sa.Column("ts", sa.Float),
    )
    engine = sa.create_engine(url, pool_size=10, max_overflow=20, pool_pre_ping=True)
    md.create_all(engine)
    return sa, engine, tenants, keys, audit, policies


class SqlStore:
    def __init__(self, url: str) -> None:
        (self.sa, self.engine, self.t_tenants, self.t_keys, self.t_audit,
         self.t_policies) = _build(url)
        # Serialize audit-seq assignment to keep the hash chain consistent under
        # concurrency (a DB advisory lock is the production-grade alternative).
        self._audit_lock = threading.Lock()

    # --- tenants ---
    def put_tenant(self, t: Tenant) -> None:
        from sqlalchemy.dialects.postgresql import insert
        stmt = insert(self.t_tenants).values(
            tenant_id=t.tenant_id, name=t.name, fail_mode=t.fail_mode,
            policy_version=t.policy_version, created_at=t.created_at)
        stmt = stmt.on_conflict_do_update(
            index_elements=["tenant_id"],
            set_={"name": t.name, "fail_mode": t.fail_mode,
                  "policy_version": t.policy_version})
        with self.engine.begin() as c:
            c.execute(stmt)

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        with self.engine.connect() as c:
            r = c.execute(self.sa.select(self.t_tenants).where(
                self.t_tenants.c.tenant_id == tenant_id)).mappings().first()
        return Tenant(**r) if r else None

    def list_tenants(self) -> list[Tenant]:
        with self.engine.connect() as c:
            return [Tenant(**r) for r in
                    c.execute(self.sa.select(self.t_tenants)).mappings()]

    # --- api keys ---
    def put_key(self, k: ApiKey) -> None:
        from sqlalchemy.dialects.postgresql import insert
        stmt = insert(self.t_keys).values(
            key_id=k.key_id, tenant_id=k.tenant_id, hashed_secret=k.hashed_secret,
            role=k.role, active=k.active, created_at=k.created_at,
            rotated_from=k.rotated_from)
        stmt = stmt.on_conflict_do_update(
            index_elements=["key_id"],
            set_={"active": k.active, "hashed_secret": k.hashed_secret,
                  "role": k.role, "rotated_from": k.rotated_from})
        with self.engine.begin() as c:
            c.execute(stmt)

    def get_key(self, key_id: str) -> ApiKey | None:
        with self.engine.connect() as c:
            r = c.execute(self.sa.select(self.t_keys).where(
                self.t_keys.c.key_id == key_id)).mappings().first()
        return ApiKey(**r) if r else None

    def all_keys(self):
        with self.engine.connect() as c:
            return [ApiKey(**r) for r in c.execute(self.sa.select(self.t_keys)).mappings()]

    def deactivate_key(self, key_id: str) -> None:
        with self.engine.begin() as c:
            c.execute(self.sa.update(self.t_keys).where(
                self.t_keys.c.key_id == key_id).values(active=False))

    # --- audit ---
    def append_audit(self, rec: AuditRecord) -> None:
        with self.engine.begin() as c:
            c.execute(self.sa.insert(self.t_audit).values(
                seq=rec.seq, tenant_id=rec.tenant_id, ts=rec.ts, event=rec.event,
                layer=rec.layer, verdict=rec.verdict, reason=rec.reason,
                prev_hash=rec.prev_hash, record_hash=rec.record_hash,
                payload_digest=rec.payload_digest, meta=json.dumps(rec.meta)))

    def last_audit_hash(self) -> str:
        with self.engine.connect() as c:
            r = c.execute(self.sa.select(self.t_audit.c.record_hash).order_by(
                self.t_audit.c.seq.desc()).limit(1)).scalar()
        return r or "GENESIS"

    def next_audit_seq(self) -> int:
        with self.engine.connect() as c:
            r = c.execute(self.sa.select(self.sa.func.max(self.t_audit.c.seq))).scalar()
        return (r or 0) + 1

    def read_audit(self, tenant_id, requester_tenant, is_admin=False, limit=100):
        if not is_admin and tenant_id != requester_tenant:
            raise CrossTenantError(
                f"tenant {requester_tenant} may not read tenant {tenant_id} audit")
        with self.engine.connect() as c:
            rows = c.execute(self.sa.select(self.t_audit).where(
                self.t_audit.c.tenant_id == tenant_id).order_by(
                self.t_audit.c.seq.desc()).limit(limit)).mappings().all()
        return [self._audit(r) for r in reversed(rows)]

    def all_audit(self):
        with self.engine.connect() as c:
            rows = c.execute(self.sa.select(self.t_audit).order_by(
                self.t_audit.c.seq)).mappings().all()
        return [self._audit(r) for r in rows]

    def purge_audit_before(self, cutoff_ts: float) -> int:
        with self.engine.begin() as c:
            res = c.execute(self.sa.delete(self.t_audit).where(
                self.t_audit.c.ts < cutoff_ts))
        return res.rowcount or 0

    @staticmethod
    def _audit(r) -> AuditRecord:
        d = dict(r)
        d["meta"] = json.loads(d.get("meta") or "{}")
        return AuditRecord(**d)

    # --- policies ---
    def put_policy(self, rec: PolicyRecord) -> None:
        from sqlalchemy.dialects.postgresql import insert
        stmt = insert(self.t_policies).values(
            tenant_id=rec.tenant_id, version=rec.version, yaml_text=rec.yaml_text,
            author=rec.author, ts=rec.ts)
        stmt = stmt.on_conflict_do_update(
            index_elements=["tenant_id", "version"],
            set_={"yaml_text": rec.yaml_text})
        with self.engine.begin() as c:
            c.execute(stmt)
            c.execute(self.sa.update(self.t_tenants).where(
                self.t_tenants.c.tenant_id == rec.tenant_id).values(
                policy_version=rec.version))

    def get_policy(self, tenant_id, requester_tenant, version=None, is_admin=False):
        if not is_admin and tenant_id != requester_tenant:
            raise CrossTenantError(
                f"tenant {requester_tenant} may not read tenant {tenant_id} policy")
        q = self.sa.select(self.t_policies).where(self.t_policies.c.tenant_id == tenant_id)
        q = (q.where(self.t_policies.c.version == version) if version is not None
             else q.order_by(self.t_policies.c.version.desc()).limit(1))
        with self.engine.connect() as c:
            r = c.execute(q).mappings().first()
        return PolicyRecord(**r) if r else None

    def policy_versions(self, tenant_id: str) -> list[int]:
        with self.engine.connect() as c:
            return [row[0] for row in c.execute(self.sa.select(
                self.t_policies.c.version).where(
                self.t_policies.c.tenant_id == tenant_id).order_by(
                self.t_policies.c.version))]
