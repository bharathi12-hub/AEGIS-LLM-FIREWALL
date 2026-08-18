"""Policy engine (Section 6) — versioned, hot-reloadable, diff + rollback.

Loads the default policy, layers per-tenant overrides on top, and resolves an
``EffectivePolicy``. Policy writes are validated (S13), versioned, and recorded
to the immutable audit trail with who/when/what. Hot reload is just resolving the
latest version on each request — there is no process restart.
"""
from __future__ import annotations

import difflib
import os
import threading

from app.observability import audit
from app.policy.schema import EffectivePolicy, PolicyValidationError, to_effective, validate
from app.storage.db import InMemoryStore, get_store
from app.storage.models import PolicyRecord
from app.util_yaml import load_yaml, loads

_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "policies", "default.yaml",
)


class PolicyEngine:
    def __init__(self, store: InMemoryStore | None = None) -> None:
        self._store = store or get_store()
        self._lock = threading.Lock()
        self._default = load_yaml(_DEFAULT_PATH) or {}
        self._cache: dict[str, EffectivePolicy] = {}

    def _merged(self, tenant_doc: dict) -> dict:
        merged = dict(self._default)
        merged.update(tenant_doc or {})
        return merged

    def effective(self, tenant_id: str) -> EffectivePolicy:
        with self._lock:
            cached = self._cache.get(tenant_id)
            if cached:
                return cached
        record = None
        try:
            record = self._store.get_policy(tenant_id, tenant_id, is_admin=True)
        except Exception:  # noqa: BLE001
            record = None
        if record is None:
            eff = to_effective(tenant_id, self._default, version=1)
        else:
            doc = self._merged(loads(record.yaml_text) or {})
            eff = to_effective(tenant_id, doc, version=record.version)
        with self._lock:
            self._cache[tenant_id] = eff
        return eff

    def set_policy(self, tenant_id: str, yaml_text: str, author: str) -> EffectivePolicy:
        """Validate, version, persist, audit, and hot-reload a tenant policy."""
        doc = loads(yaml_text) or {}
        merged = self._merged(doc)
        errs = validate(merged)
        if errs:
            raise PolicyValidationError("; ".join(errs))
        versions = self._store.policy_versions(tenant_id)
        new_version = (max(versions) + 1) if versions else 1
        record = PolicyRecord(tenant_id=tenant_id, version=new_version,
                              yaml_text=yaml_text, author=author)
        self._store.put_policy(record)
        audit.record_event(
            tenant_id=tenant_id, event="policy_change", layer="policy",
            verdict="n/a", reason=f"policy v{new_version} by {author}",
            meta={"version": new_version, "author": author},
            store=self._store,
        )
        with self._lock:
            self._cache.pop(tenant_id, None)
        return self.effective(tenant_id)

    def rollback(self, tenant_id: str, to_version: int, author: str) -> EffectivePolicy:
        target = self._store.get_policy(tenant_id, tenant_id, version=to_version, is_admin=True)
        if not target:
            raise KeyError(f"no policy v{to_version} for {tenant_id}")
        return self.set_policy(tenant_id, target.yaml_text, f"rollback->v{to_version} by {author}")

    def diff(self, tenant_id: str, v1: int, v2: int) -> str:
        a = self._store.get_policy(tenant_id, tenant_id, version=v1, is_admin=True)
        b = self._store.get_policy(tenant_id, tenant_id, version=v2, is_admin=True)
        a_text = (a.yaml_text if a else "").splitlines(keepends=True)
        b_text = (b.yaml_text if b else "").splitlines(keepends=True)
        return "".join(difflib.unified_diff(a_text, b_text,
                                            fromfile=f"v{v1}", tofile=f"v{v2}"))


_engine: PolicyEngine | None = None


def get_engine() -> PolicyEngine:
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
    return _engine
