"""Tenant isolation + hashed keys (S8)."""
from __future__ import annotations

import unittest

from app.auth import authenticate, hash_secret, issue_key, rotate_key, verify_secret
from app.observability import audit
from app.storage.db import CrossTenantError, InMemoryStore
from app.storage.models import Tenant


class TestApiKeyHashing(unittest.TestCase):
    def test_keys_stored_hashed(self):
        store = InMemoryStore()
        store.put_tenant(Tenant("acme", "acme"))
        raw, record = issue_key("acme", store=store)
        # The stored secret is a hash, never the raw key.
        self.assertNotIn(raw.split(".", 1)[1], record.hashed_secret)
        # Offline uses fast peppered HMAC for high-entropy keys; argon2/pbkdf2 are
        # the fallbacks when no pepper is configured.
        self.assertTrue(record.hashed_secret.startswith(("hmac$", "argon2$", "pbkdf2$")))

    def test_authenticate_roundtrip(self):
        store = InMemoryStore()
        store.put_tenant(Tenant("acme", "acme"))
        raw, _ = issue_key("acme", role="analyst", store=store)
        p = authenticate(raw, store=store)
        self.assertIsNotNone(p)
        self.assertEqual(p.tenant_id, "acme")
        self.assertIsNone(authenticate("ak_bogus.wrongsecret", store=store))

    def test_rotation_invalidates_old(self):
        store = InMemoryStore()
        store.put_tenant(Tenant("acme", "acme"))
        raw, rec = issue_key("acme", store=store)
        new_raw, _ = rotate_key(rec.key_id, store=store)
        self.assertIsNone(authenticate(raw, store=store))       # old dead
        self.assertIsNotNone(authenticate(new_raw, store=store))  # new works

    def test_hash_verify_helpers(self):
        h = hash_secret("s3cr3t")
        self.assertTrue(verify_secret("s3cr3t", h))
        self.assertFalse(verify_secret("wrong", h))


class TestCrossTenantIsolation(unittest.TestCase):
    def test_cross_tenant_audit_read_fails(self):
        store = InMemoryStore()
        store.put_tenant(Tenant("acme", "acme"))
        store.put_tenant(Tenant("evil", "evil"))
        audit.record_event(tenant_id="acme", event="block", layer="input",
                           verdict="block", reason="test", store=store)
        # Tenant 'evil' must NOT be able to read tenant 'acme' audit.
        with self.assertRaises(CrossTenantError):
            store.read_audit("acme", requester_tenant="evil")
        # Its own scope is fine.
        rows = store.read_audit("acme", requester_tenant="acme")
        self.assertEqual(len(rows), 1)

    def test_cross_tenant_policy_read_fails(self):
        store = InMemoryStore()
        from app.storage.models import PolicyRecord
        store.put_policy(PolicyRecord("acme", 1, "fail_mode: closed", "admin"))
        with self.assertRaises(CrossTenantError):
            store.get_policy("acme", requester_tenant="evil")


if __name__ == "__main__":
    unittest.main()
