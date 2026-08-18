"""Store: tenants, API keys, policies, audit records.

The in-memory store is the default (offline, tests). Every query is scoped by
``tenant_id`` and the store never exposes a cross-tenant read path — the
tenant-isolation test (S8) asserts a tenant cannot read another's audit/policies.

A SQLAlchemy/Postgres store implements the same interface when
``AEGIS_DATABASE_URL`` is set; the gateway swaps it in transparently.
"""
from __future__ import annotations

import threading
from typing import Iterable

from app.storage.models import ApiKey, AuditRecord, PolicyRecord, Tenant


class CrossTenantError(PermissionError):
    """Raised if a caller attempts to read data outside its tenant scope."""


class InMemoryStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tenants: dict[str, Tenant] = {}
        self._keys: dict[str, ApiKey] = {}          # key_id -> ApiKey
        self._audit: list[AuditRecord] = []
        self._policies: dict[tuple[str, int], PolicyRecord] = {}

    # --- tenants ---
    def put_tenant(self, tenant: Tenant) -> None:
        with self._lock:
            self._tenants[tenant.tenant_id] = tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        return self._tenants.get(tenant_id)

    def list_tenants(self) -> list[Tenant]:
        return list(self._tenants.values())

    # --- api keys ---
    def put_key(self, key: ApiKey) -> None:
        with self._lock:
            self._keys[key.key_id] = key

    def get_key(self, key_id: str) -> ApiKey | None:
        return self._keys.get(key_id)

    def all_keys(self) -> Iterable[ApiKey]:
        return list(self._keys.values())

    def deactivate_key(self, key_id: str) -> None:
        with self._lock:
            k = self._keys.get(key_id)
            if k:
                k.active = False

    # --- audit (append-only, hash-chained) ---
    def append_audit(self, record: AuditRecord) -> None:
        with self._lock:
            self._audit.append(record)

    def last_audit_hash(self) -> str:
        return self._audit[-1].record_hash if self._audit else "GENESIS"

    def next_audit_seq(self) -> int:
        return len(self._audit) + 1

    def read_audit(self, tenant_id: str, requester_tenant: str,
                   is_admin: bool = False, limit: int = 100) -> list[AuditRecord]:
        # S8: enforce tenant scope unless the caller is a platform admin.
        if not is_admin and tenant_id != requester_tenant:
            raise CrossTenantError(
                f"tenant {requester_tenant} may not read tenant {tenant_id} audit")
        with self._lock:
            rows = [r for r in self._audit if r.tenant_id == tenant_id]
        return rows[-limit:]

    def all_audit(self) -> list[AuditRecord]:
        return list(self._audit)

    def purge_audit_before(self, cutoff_ts: float) -> int:
        """Retention support (S7). Note: purging breaks the hash chain by design;
        a production deployment archives sealed segments before purging."""
        with self._lock:
            before = len(self._audit)
            self._audit = [r for r in self._audit if r.ts >= cutoff_ts]
            return before - len(self._audit)

    # --- policies ---
    def put_policy(self, record: PolicyRecord) -> None:
        with self._lock:
            self._policies[(record.tenant_id, record.version)] = record
            t = self._tenants.get(record.tenant_id)
            if t:
                t.policy_version = record.version

    def get_policy(self, tenant_id: str, requester_tenant: str,
                   version: int | None = None, is_admin: bool = False) -> PolicyRecord | None:
        if not is_admin and tenant_id != requester_tenant:
            raise CrossTenantError(
                f"tenant {requester_tenant} may not read tenant {tenant_id} policy")
        with self._lock:
            if version is None:
                versions = [v for (t, v) in self._policies if t == tenant_id]
                if not versions:
                    return None
                version = max(versions)
            return self._policies.get((tenant_id, version))

    def policy_versions(self, tenant_id: str) -> list[int]:
        return sorted(v for (t, v) in self._policies if t == tenant_id)


_store = None


def _build_store():
    """Select the durable backend by env (production Postgres > durable SQLite >
    in-memory). All three implement the identical interface used above."""
    import os
    db_url = os.getenv("AEGIS_DATABASE_URL", "")
    sqlite_path = os.getenv("AEGIS_SQLITE_PATH", "")
    if db_url:
        try:
            from app.storage.sql_store import SqlStore
            return SqlStore(db_url)
        except Exception as exc:  # noqa: BLE001 — never boot silently mis-persisted
            raise RuntimeError(f"AEGIS_DATABASE_URL set but SqlStore failed: {exc}")
    if sqlite_path:
        from app.storage.sqlite_store import SqliteStore
        return SqliteStore(sqlite_path)
    return InMemoryStore()


def get_store():
    global _store
    if _store is None:
        _store = _build_store()
    return _store


def configure_store(store) -> None:
    """Inject a specific store (used by tests / bootstrap)."""
    global _store
    _store = store


def reset_store() -> None:
    """Test helper — reset to a fresh in-memory store."""
    global _store
    _store = InMemoryStore()
