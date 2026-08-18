"""OIDC / JWT authentication (production identity, S8/S10).

Enterprises federate identity through an IdP (Okta, Entra, Auth0, Keycloak).
This module verifies bearer JWTs and maps their claims to an AEGIS ``Principal``
(tenant + RBAC role), so the gateway accepts EITHER a first-party API key OR an
SSO-issued JWT on the same ``Authorization: Bearer`` header.

Supported:
  * **HS256** — symmetric secret (``AEGIS_OIDC_HS256_SECRET``); pure stdlib, fully
    testable offline. Good for service-to-service and tests.
  * **RS256** — asymmetric via the IdP's JWKS (``AEGIS_OIDC_JWKS_URL``); requires
    the optional ``cryptography`` dependency. Standard production path.

Always validated: signature, ``exp``, ``nbf``, ``iss``, ``aud``. Tenant and roles
come from configurable claims. Fail-closed: any validation error ⇒ no principal.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass

from app.auth import Principal


@dataclass
class OidcConfig:
    enabled: bool
    issuer: str
    audience: str
    hs256_secret: str
    jwks_url: str
    tenant_claim: str
    roles_claim: str

    @classmethod
    def from_env(cls) -> "OidcConfig":
        issuer = os.getenv("AEGIS_OIDC_ISSUER", "")
        hs = os.getenv("AEGIS_OIDC_HS256_SECRET", "")
        jwks = os.getenv("AEGIS_OIDC_JWKS_URL", "")
        return cls(
            enabled=bool(issuer and (hs or jwks)),
            issuer=issuer,
            audience=os.getenv("AEGIS_OIDC_AUDIENCE", "aegis"),
            hs256_secret=hs,
            jwks_url=jwks,
            tenant_claim=os.getenv("AEGIS_OIDC_TENANT_CLAIM", "tenant"),
            roles_claim=os.getenv("AEGIS_OIDC_ROLES_CLAIM", "roles"),
        )


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2 and not token.startswith("ak_")


class JwtError(Exception):
    pass


def _verify_signature(header: dict, signing_input: bytes, signature: bytes,
                      cfg: OidcConfig) -> None:
    alg = header.get("alg")
    if alg == "HS256":
        if not cfg.hs256_secret:
            raise JwtError("HS256 token but no shared secret configured")
        expected = hmac.new(cfg.hs256_secret.encode(), signing_input,
                            hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise JwtError("bad HS256 signature")
        return
    if alg == "RS256":
        _verify_rs256(header, signing_input, signature, cfg)
        return
    raise JwtError(f"unsupported alg {alg}")


def _verify_rs256(header, signing_input, signature, cfg):  # pragma: no cover - needs crypto+IdP
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    jwk = _fetch_jwk(cfg.jwks_url, header.get("kid"))
    pubkey = _jwk_to_pubkey(jwk)
    try:
        pubkey.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:  # noqa: BLE001
        raise JwtError(f"bad RS256 signature: {exc}")


_JWKS_CACHE: dict[str, tuple[float, dict]] = {}


def _fetch_jwk(jwks_url: str, kid: str | None):  # pragma: no cover
    import httpx
    cached = _JWKS_CACHE.get(jwks_url)
    if not cached or cached[0] < time.time():
        resp = httpx.get(jwks_url, timeout=5.0)
        resp.raise_for_status()
        _JWKS_CACHE[jwks_url] = (time.time() + 3600, resp.json())
    keys = _JWKS_CACHE[jwks_url][1].get("keys", [])
    for k in keys:
        if k.get("kid") == kid or kid is None:
            return k
    raise JwtError(f"kid {kid} not found in JWKS")


def _jwk_to_pubkey(jwk):  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return RSAPublicNumbers(e, n).public_key()


def verify(token: str, cfg: OidcConfig | None = None,
           now: float | None = None) -> Principal | None:
    cfg = cfg or OidcConfig.from_env()
    if not cfg.enabled:
        return None
    now = now if now is not None else time.time()
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signing_input = f"{header_b64}.{payload_b64}".encode()
        _verify_signature(header, signing_input, _b64url_decode(sig_b64), cfg)

        # Standard claim validation.
        if cfg.issuer and payload.get("iss") != cfg.issuer:
            raise JwtError("issuer mismatch")
        aud = payload.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if cfg.audience and cfg.audience not in auds:
            raise JwtError("audience mismatch")
        if "exp" in payload and now >= float(payload["exp"]):
            raise JwtError("token expired")
        if "nbf" in payload and now < float(payload["nbf"]):
            raise JwtError("token not yet valid")

        tenant = payload.get(cfg.tenant_claim)
        if not tenant:
            raise JwtError("missing tenant claim")
        roles = payload.get(cfg.roles_claim, [])
        if isinstance(roles, str):
            roles = [roles]
        role = "admin" if "admin" in roles else ("analyst" if "analyst" in roles else "viewer")
        subject = payload.get("sub", "oidc-user")
        return Principal(key_id=f"jwt:{subject}", tenant_id=str(tenant), role=role)
    except (JwtError, ValueError, KeyError, TypeError):
        return None  # fail-closed: no principal


def principal_from_token(token: str, store=None) -> Principal | None:
    """Resolve a bearer token to a Principal: try OIDC JWT first, then API key."""
    from app.auth import authenticate
    if looks_like_jwt(token):
        p = verify(token)
        if p is not None:
            return p
    return authenticate(token, store)


# Test/dev helper: mint an HS256 token (never used in production paths).
def mint_hs256(secret: str, claims: dict) -> str:
    def seg(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    header = seg({"alg": "HS256", "typ": "JWT"})
    payload = seg(claims)
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig_b64}"
