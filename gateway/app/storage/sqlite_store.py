"""Durable single-node store backed by stdlib ``sqlite3``.

This closes the biggest "not production" gap in the offline profile: the audit
trail, tenants, keys, and policies now SURVIVE A RESTART, and the hash chain is
re-verifiable against the persisted rows. It implements the exact same interface
as ``InMemoryStore`` (drop-in) and is fully testable offline (sqlite is stdlib).

For horizontal scale / HA use the Postgres-backed ``SqlStore`` instead
(``app/storage/sql_store.py``); the semantics are identical. Selection is done in
``db.get_store()`` from ``AEGIS_DATABASE_URL`` / ``AEGIS_SQLITE_PATH``.
"""
from __future__ import annotations

import json
import sqlite3
import threading

from app.storage.db import CrossTenantError
from app.storage.models import ApiKey, AuditRecord, PolicyRecord, Tenant

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
  tenant_id TEXT PRIMARY KEY, name TEXT, fail_mode TEXT,
  policy_version INTEGER, created_at REAL
);
CREATE TABLE IF NOT EXISTS api_keys (
  key_id TEXT PRIMARY KEY, tenant_id TEXT, hashed_secret TEXT, role TEXT,
  active INTEGER, created_at REAL, rotated_from TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY, tenant_id TEXT, ts REAL, event TEXT, layer TEXT,
  verdict TEXT, reason TEXT, prev_hash TEXT, record_hash TEXT,
  payload_digest TEXT, meta TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit(tenant_id);
CREATE TABLE IF NOT EXISTS policies (
  tenant_id TEXT, version INTEGER, yaml_text TEXT, author TEXT, ts REAL,
  PRIMARY KEY (tenant_id, version)
);
"""


class SqliteStore:
    def __init__(self, path: str) -> None:
        # check_same_thread=False + a lock: safe for the gateway's thread pool.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.RLock()

    # --- tenants ---
    def put_tenant(self, t: Tenant) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO tenants VALUES (?,?,?,?,?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET name=excluded.name, "
                "fail_mode=excluded.fail_mode, policy_version=excluded.policy_version",
                (t.tenant_id, t.name, t.fail_mode, t.policy_version, t.created_at))
            self._conn.commit()

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        row = self._conn.execute("SELECT * FROM tenants WHERE tenant_id=?",
                                 (tenant_id,)).fetchone()
        return self._tenant(row) if row else None

    def list_tenants(self) -> list[Tenant]:
        return [self._tenant(r) for r in self._conn.execute("SELECT * FROM tenants")]

    @staticmethod
    def _tenant(r: sqlite3.Row) -> Tenant:
        return Tenant(r["tenant_id"], r["name"], r["fail_mode"], r["policy_version"],
                      r["created_at"])

    # --- api keys ---
    def put_key(self, k: ApiKey) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO api_keys VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(key_id) DO UPDATE SET active=excluded.active, "
                "hashed_secret=excluded.hashed_secret, role=excluded.role, "
                "rotated_from=excluded.rotated_from",
                (k.key_id, k.tenant_id, k.hashed_secret, k.role, int(k.active),
                 k.created_at, k.rotated_from))
            self._conn.commit()

    def get_key(self, key_id: str) -> ApiKey | None:
        row = self._conn.execute("SELECT * FROM api_keys WHERE key_id=?",
                                 (key_id,)).fetchone()
        return self._key(row) if row else None

    def all_keys(self):
        return [self._key(r) for r in self._conn.execute("SELECT * FROM api_keys")]

    def deactivate_key(self, key_id: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE api_keys SET active=0 WHERE key_id=?", (key_id,))
            self._conn.commit()

    @staticmethod
    def _key(r: sqlite3.Row) -> ApiKey:
        return ApiKey(r["key_id"], r["tenant_id"], r["hashed_secret"], r["role"],
                      bool(r["active"]), r["created_at"], r["rotated_from"])

    # --- audit (append-only, hash-chained) ---
    def append_audit(self, rec: AuditRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (rec.seq, rec.tenant_id, rec.ts, rec.event, rec.layer, rec.verdict,
                 rec.reason, rec.prev_hash, rec.record_hash, rec.payload_digest,
                 json.dumps(rec.meta)))
            self._conn.commit()

    def last_audit_hash(self) -> str:
        row = self._conn.execute(
            "SELECT record_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row["record_hash"] if row else "GENESIS"

    def next_audit_seq(self) -> int:
        row = self._conn.execute("SELECT MAX(seq) AS m FROM audit").fetchone()
        return (row["m"] or 0) + 1

    def read_audit(self, tenant_id, requester_tenant, is_admin=False, limit=100):
        if not is_admin and tenant_id != requester_tenant:
            raise CrossTenantError(
                f"tenant {requester_tenant} may not read tenant {tenant_id} audit")
        rows = self._conn.execute(
            "SELECT * FROM audit WHERE tenant_id=? ORDER BY seq DESC LIMIT ?",
            (tenant_id, limit)).fetchall()
        return [self._audit(r) for r in reversed(rows)]

    def all_audit(self) -> list[AuditRecord]:
        return [self._audit(r) for r in self._conn.execute(
            "SELECT * FROM audit ORDER BY seq")]

    @staticmethod
    def _audit(r: sqlite3.Row) -> AuditRecord:
        return AuditRecord(r["seq"], r["tenant_id"], r["ts"], r["event"], r["layer"],
                           r["verdict"], r["reason"], r["prev_hash"], r["record_hash"],
                           r["payload_digest"], json.loads(r["meta"] or "{}"))

    def purge_audit_before(self, cutoff_ts: float) -> int:
        """Retention job support (S7): delete records older than cutoff."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM audit WHERE ts < ?", (cutoff_ts,))
            self._conn.commit()
            return cur.rowcount

    # --- policies ---
    def put_policy(self, rec: PolicyRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO policies VALUES (?,?,?,?,?) "
                "ON CONFLICT(tenant_id, version) DO UPDATE SET yaml_text=excluded.yaml_text",
                (rec.tenant_id, rec.version, rec.yaml_text, rec.author, rec.ts))
            self._conn.execute("UPDATE tenants SET policy_version=? WHERE tenant_id=?",
                               (rec.version, rec.tenant_id))
            self._conn.commit()

    def get_policy(self, tenant_id, requester_tenant, version=None, is_admin=False):
        if not is_admin and tenant_id != requester_tenant:
            raise CrossTenantError(
                f"tenant {requester_tenant} may not read tenant {tenant_id} policy")
        if version is None:
            row = self._conn.execute(
                "SELECT * FROM policies WHERE tenant_id=? ORDER BY version DESC LIMIT 1",
                (tenant_id,)).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM policies WHERE tenant_id=? AND version=?",
                (tenant_id, version)).fetchone()
        return self._policy(row) if row else None

    def policy_versions(self, tenant_id: str) -> list[int]:
        return [r["version"] for r in self._conn.execute(
            "SELECT version FROM policies WHERE tenant_id=? ORDER BY version",
            (tenant_id,))]

    @staticmethod
    def _policy(r: sqlite3.Row) -> PolicyRecord:
        return PolicyRecord(r["tenant_id"], r["version"], r["yaml_text"],
                            r["author"], r["ts"])

    def close(self) -> None:
        self._conn.close()
