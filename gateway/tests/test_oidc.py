"""OIDC / JWT authentication (production identity)."""
from __future__ import annotations

import time
import unittest

from app.security.oidc import OidcConfig, mint_hs256, principal_from_token, verify

CFG = OidcConfig(enabled=True, issuer="https://idp.example.com", audience="aegis",
                 hs256_secret="super-shared-secret", jwks_url="",
                 tenant_claim="tenant", roles_claim="roles")


def _claims(**over):
    base = {"iss": CFG.issuer, "aud": "aegis", "sub": "user-1",
            "tenant": "acme", "roles": ["analyst"], "exp": time.time() + 300}
    base.update(over)
    return base


class TestJwtVerification(unittest.TestCase):
    def test_valid_token_maps_to_principal(self):
        tok = mint_hs256(CFG.hs256_secret, _claims())
        p = verify(tok, CFG)
        self.assertIsNotNone(p)
        self.assertEqual(p.tenant_id, "acme")
        self.assertEqual(p.role, "analyst")
        self.assertTrue(p.key_id.startswith("jwt:"))

    def test_admin_role_mapped(self):
        p = verify(mint_hs256(CFG.hs256_secret, _claims(roles=["admin"])), CFG)
        self.assertTrue(p.is_admin)

    def test_expired_rejected(self):
        self.assertIsNone(verify(mint_hs256(CFG.hs256_secret,
                                            _claims(exp=time.time() - 1)), CFG))

    def test_wrong_audience_rejected(self):
        self.assertIsNone(verify(mint_hs256(CFG.hs256_secret,
                                            _claims(aud="someone-else")), CFG))

    def test_wrong_issuer_rejected(self):
        self.assertIsNone(verify(mint_hs256(CFG.hs256_secret,
                                            _claims(iss="https://evil.example")), CFG))

    def test_tampered_signature_rejected(self):
        tok = mint_hs256(CFG.hs256_secret, _claims())
        forged = verify(tok[:-4] + "AAAA", CFG)
        self.assertIsNone(forged)

    def test_wrong_secret_rejected(self):
        bad = OidcConfig(**{**CFG.__dict__, "hs256_secret": "not-the-secret"})
        self.assertIsNone(verify(mint_hs256(CFG.hs256_secret, _claims()), bad))

    def test_disabled_returns_none(self):
        disabled = OidcConfig(**{**CFG.__dict__, "enabled": False})
        self.assertIsNone(verify(mint_hs256(CFG.hs256_secret, _claims()), disabled))


class TestResolver(unittest.TestCase):
    def test_api_key_path_still_works(self):
        from app.storage.db import InMemoryStore
        from app.storage.models import Tenant
        from app.auth import issue_key
        store = InMemoryStore()
        store.put_tenant(Tenant("acme", "acme"))
        raw, _ = issue_key("acme", store=store)
        # OIDC not enabled here, so the API key path resolves.
        p = principal_from_token(raw, store=store)
        self.assertIsNotNone(p)
        self.assertEqual(p.tenant_id, "acme")


if __name__ == "__main__":
    unittest.main()
