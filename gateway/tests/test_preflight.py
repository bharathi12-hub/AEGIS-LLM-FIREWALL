"""Production preflight security gate + typed API validation."""
from __future__ import annotations

import os
import unittest

from app.config import Settings
from app.security.preflight import InsecureConfigError, assert_production_safe, evaluate


def _prod(**over):
    base = dict(offline=False, admin_api_key="a" * 40, cors_origins="https://x.example",
                default_fail_mode="closed", database_url="postgresql+psycopg://x",
                redis_url="redis://x", audit_encryption_key="k" * 32,
                response_floor_ms=8, redact_pii_in_logs=True)
    base.update(over)
    return Settings(**base)


class TestPreflight(unittest.TestCase):
    def setUp(self):
        os.environ["AEGIS_BOOTSTRAP"] = "0"  # secure default for these tests

    def test_offline_always_passes(self):
        self.assertTrue(evaluate(Settings(offline=True, admin_api_key="")).ok)

    def test_secure_prod_config_passes(self):
        self.assertTrue(evaluate(_prod()).ok, evaluate(_prod()).fatal)

    def test_weak_admin_key_fatal(self):
        self.assertFalse(evaluate(_prod(admin_api_key="change-me-admin-key")).ok)
        self.assertFalse(evaluate(_prod(admin_api_key="short")).ok)

    def test_wildcard_cors_fatal(self):
        self.assertFalse(evaluate(_prod(cors_origins="*")).ok)

    def test_fail_open_default_fatal(self):
        self.assertFalse(evaluate(_prod(default_fail_mode="open")).ok)

    def test_no_durable_store_fatal(self):
        self.assertFalse(evaluate(_prod(database_url="")).ok)

    def test_bootstrap_on_in_prod_fatal(self):
        os.environ["AEGIS_BOOTSTRAP"] = "1"
        try:
            self.assertFalse(evaluate(_prod()).ok)
        finally:
            os.environ["AEGIS_BOOTSTRAP"] = "0"

    def test_missing_audit_key_is_warning_not_fatal(self):
        rep = evaluate(_prod(audit_encryption_key=""))
        self.assertTrue(rep.ok)
        self.assertTrue(any("AUDIT_KEY" in w for w in rep.warnings))

    def test_assert_raises_on_insecure(self):
        with self.assertRaises(InsecureConfigError):
            assert_production_safe(_prod(cors_origins="*"))


class TestTypedValidation(unittest.TestCase):
    def test_request_model_extracts_latest_user_text(self):
        from app.api.schemas import ChatCompletionRequest
        req = ChatCompletionRequest(messages=[
            {"role": "system", "content": "be nice"},
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "second"},
        ])
        self.assertEqual(req.latest_user_text(), "second")

    def test_content_parts_form(self):
        from app.api.schemas import ChatCompletionRequest
        req = ChatCompletionRequest(messages=[
            {"role": "user", "content": [{"type": "text", "text": "hello"},
                                          {"type": "text", "text": "world"}]}])
        self.assertEqual(req.latest_user_text(), "hello world")

    def test_empty_messages_rejected(self):
        from pydantic import ValidationError
        from app.api.schemas import ChatCompletionRequest
        with self.assertRaises(ValidationError):
            ChatCompletionRequest(messages=[])


if __name__ == "__main__":
    unittest.main()
