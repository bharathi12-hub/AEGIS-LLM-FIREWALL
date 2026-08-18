"""Policy-as-code (S13) + immutable audit (Section 6)."""
from __future__ import annotations

import unittest

from app.observability import audit
from app.policy.engine import PolicyEngine
from app.policy.schema import PolicyValidationError, validate
from app.storage.db import InMemoryStore
from app.storage.models import Tenant


class TestPolicyValidation(unittest.TestCase):
    def test_rejects_bad_fail_mode(self):
        self.assertTrue(validate({"fail_mode": "banana"}))

    def test_rejects_out_of_range_threshold(self):
        self.assertTrue(validate({"block_threshold": 2.0}))

    def test_rejects_review_above_block(self):
        errs = validate({"block_threshold": 0.3, "review_threshold": 0.9})
        self.assertTrue(any("review_threshold" in e for e in errs))

    def test_accepts_valid(self):
        self.assertEqual(validate({"fail_mode": "open", "block_threshold": 0.8,
                                   "review_threshold": 0.4}), [])


class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()
        self.store.put_tenant(Tenant("acme", "acme"))
        self.engine = PolicyEngine(store=self.store)

    def test_set_validate_version_rollback(self):
        self.engine.set_policy("acme", "block_threshold: 0.9", "analyst-1")
        self.engine.set_policy("acme", "block_threshold: 0.6", "analyst-1")
        eff = self.engine.effective("acme")
        self.assertEqual(eff.block_threshold, 0.6)
        self.assertEqual(eff.version, 2)
        # Rollback to v1 creates v3 with v1's content.
        self.engine.rollback("acme", 1, "admin")
        self.assertEqual(self.engine.effective("acme").block_threshold, 0.9)

    def test_invalid_policy_rejected(self):
        with self.assertRaises(PolicyValidationError):
            self.engine.set_policy("acme", "fail_mode: nonsense", "analyst-1")

    def test_policy_change_is_audited(self):
        self.engine.set_policy("acme", "block_threshold: 0.8", "analyst-1")
        rows = self.store.read_audit("acme", "acme")
        self.assertTrue(any(r.event == "policy_change" for r in rows))


class TestImmutableAudit(unittest.TestCase):
    def test_hash_chain_valid_then_tamper_detected(self):
        store = InMemoryStore()
        store.put_tenant(Tenant("acme", "acme"))
        for i in range(4):
            audit.record_event(tenant_id="acme", event="block", layer="input",
                               verdict="block", reason=f"r{i}", store=store)
        ok, bad = audit.verify_chain(store)
        self.assertTrue(ok)
        self.assertIsNone(bad)
        # Tamper with a record in the middle.
        store.all_audit()[1].reason = "TAMPERED"
        ok2, bad2 = audit.verify_chain(store)
        self.assertFalse(ok2)
        self.assertEqual(bad2, 2)

    def test_raw_prompt_not_stored(self):
        store = InMemoryStore()
        store.put_tenant(Tenant("acme", "acme"))
        rec = audit.record_event(tenant_id="acme", event="block", layer="input",
                                 verdict="block", reason="x",
                                 prompt="my secret ssn is 123-45-6789", store=store)
        # Only a digest is retained, never the raw prompt.
        self.assertNotIn("123-45-6789", rec.payload_digest)
        self.assertEqual(len(rec.payload_digest), 64)


if __name__ == "__main__":
    unittest.main()
