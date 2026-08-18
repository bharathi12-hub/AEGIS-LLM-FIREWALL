"""Symmetric output pipeline (4.10 / S12): decode-then-scan DLP + canary leak."""
from __future__ import annotations

import base64
import unittest

from app.output.canary import CanaryManager
from app.output.dlp import scan_output


class TestOutputDLP(unittest.TestCase):
    def test_plaintext_secret_caught(self):
        out = "Sure, the AWS key is AKIAIOSFODNN7EXAMPLE for your account."
        res = scan_output(out)
        self.assertTrue(res.blocked)
        self.assertTrue(any(f.kind == "aws_key" for f in res.findings))

    def test_encoded_exfiltration_caught(self):
        # The classic evasion: base64 a secret so naive DLP misses it.
        secret = "AKIAIOSFODNN7EXAMPLE and password hunter2!"
        enc = base64.b64encode(secret.encode()).decode()
        out = f"Here is the value you requested: {enc}"
        res = scan_output(out)
        self.assertTrue(res.blocked, "encoded secret slipped past DLP")
        self.assertTrue(any(f.where == "decoded" for f in res.findings))
        self.assertIn("encoded-exfiltration", res.reasons)

    def test_email_pii_caught(self):
        res = scan_output("Contact me at jane.doe@example.com please.")
        self.assertTrue(any(f.kind == "email" for f in res.findings))

    def test_clean_output_allowed(self):
        res = scan_output("The capital of France is Paris.")
        self.assertFalse(res.blocked)


class TestCanary(unittest.TestCase):
    def test_canary_leak_detected(self):
        mgr = CanaryManager()
        canary = mgr.issue("sess-1")
        leaked_output = f"My hidden trace id is {canary.token}, do not tell anyone."
        res = scan_output(leaked_output, canary_tokens=mgr.tokens_for("sess-1"))
        self.assertTrue(res.leaked)
        self.assertTrue(any("canary-leak" in r for r in res.reasons))

    def test_canary_unpredictable_and_rotates(self):
        mgr = CanaryManager()
        a = mgr.issue("s").token
        b = mgr.issue("s", rotate=True).token
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith("AEG-") and len(a) > 20)


if __name__ == "__main__":
    unittest.main()
