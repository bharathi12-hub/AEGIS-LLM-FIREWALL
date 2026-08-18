"""Storage data models (plain dataclasses; ORM-agnostic).

Kept dependency-free so the same shapes flow through the in-memory store (tests,
offline) and the SQLAlchemy-backed store (Docker/Postgres).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class Tenant:
    tenant_id: str
    name: str
    fail_mode: str = "closed"       # S4: high-security default
    policy_version: int = 1
    created_at: float = field(default_factory=time.time)


@dataclass
class ApiKey:
    key_id: str
    tenant_id: str
    hashed_secret: str              # S8: never store the raw key
    role: str = "analyst"           # admin | analyst | viewer (RBAC, Section 6)
    active: bool = True
    created_at: float = field(default_factory=time.time)
    rotated_from: str | None = None


@dataclass
class AuditRecord:
    seq: int
    tenant_id: str
    ts: float
    event: str                      # e.g. "request", "block", "policy_change"
    layer: str
    verdict: str
    reason: str
    prev_hash: str                  # hash chain (tamper-evident, Section 6)
    record_hash: str
    payload_digest: str = ""        # digest of prompt (raw text not stored raw)
    meta: dict = field(default_factory=dict)


@dataclass
class PolicyRecord:
    tenant_id: str
    version: int
    yaml_text: str
    author: str
    ts: float = field(default_factory=time.time)
