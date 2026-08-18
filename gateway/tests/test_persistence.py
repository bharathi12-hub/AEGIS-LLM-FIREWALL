"""Durable persistence (production gap): audit chain survives a restart.

Proven against the stdlib sqlite backend (fully offline). The Postgres SqlStore
implements the identical interface for horizontal scale.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from app.observability import audit
from app.storage.db import CrossTenantError
from app.storage.models import PolicyRecord, Tenant
from app.storage.sqlite_store import SqliteStore


class TestDurableStore(unittest.TestCase):
    def setUp(self):
        self._fd, self._path = tempfile.mkstemp(suffix=".db")
        os.close(self._fd)

    def tearDown(self):
        try:
            os.remove(self._path)
        except OSError:
            pass

    def test_audit_chain_survives_restart(self):
        store = SqliteStore(self._path)
        store.put_tenant(Tenant("acme", "acme"))
        for i in range(5):
            audit.record_event(tenant_id="acme", event="block", layer="input",
                               verdict="block", reason=f"r{i}", store=store)
        ok, _ = audit.verify_chain(store)
        self.assertTrue(ok)
        store.close()

        # Reopen the SAME file — data + hash chain must persist and re-verify.
        reopened = SqliteStore(self._path)
        self.assertEqual(len(reopened.all_audit()), 5)
        ok2, bad2 = audit.verify_chain(reopened)
        self.assertTrue(ok2, f"chain broke across restart at {bad2}")
        # Appending continues the chain from the persisted tail.
        audit.record_event(tenant_id="acme", event="allow", layer="output",
                           verdict="allow", reason="clean", store=reopened)
        ok3, _ = audit.verify_chain(reopened)
        self.assertTrue(ok3)
        self.assertEqual(len(reopened.all_audit()), 6)
        reopened.close()

    def test_tenant_isolation_enforced_in_sql(self):
        store = SqliteStore(self._path)
        store.put_tenant(Tenant("acme", "acme"))
        store.put_policy(PolicyRecord("acme", 1, "fail_mode: closed", "admin"))
        audit.record_event(tenant_id="acme", event="block", layer="input",
                           verdict="block", reason="x", store=store)
        with self.assertRaises(CrossTenantError):
            store.read_audit("acme", requester_tenant="evil")
        with self.assertRaises(CrossTenantError):
            store.get_policy("acme", requester_tenant="evil")
        self.assertEqual(len(store.read_audit("acme", "acme")), 1)
        store.close()

    def test_retention_purge(self):
        store = SqliteStore(self._path)
        store.put_tenant(Tenant("acme", "acme"))
        r1 = audit.record_event(tenant_id="acme", event="block", layer="input",
                                verdict="block", reason="old", store=store)
        removed = store.purge_audit_before(r1.ts + 1e6)  # purge everything older
        self.assertGreaterEqual(removed, 1)
        store.close()


if __name__ == "__main__":
    unittest.main()
