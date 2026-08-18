"""Authentication & tenant scoping (S8 / S10).

- API keys are stored HASHED (argon2 when available, else stdlib PBKDF2-HMAC).
- Keys carry an RBAC role (admin | analyst | viewer) and a tenant_id.
- Every authenticated principal is scoped to its tenant; admin endpoints require
  a separate admin key (S10).
- Key rotation issues a new secret and links it to the old key id.

The raw secret is shown to the operator exactly once at creation and never
stored or logged.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass

from app.config import settings
from app.storage.db import InMemoryStore, get_store
from app.storage.models import ApiKey, Tenant

_PBKDF2_ROUNDS = 200_000
# Offline/dev pepper so the fast HMAC path works with zero config. Production
# MUST set AEGIS_KEY_PEPPER (enforced by the preflight gate).
_DEV_PEPPER = "aegis-offline-dev-pepper-do-not-use-in-prod"

try:  # pragma: no cover - argon2 only present in Docker
    from argon2 import PasswordHasher  # type: ignore
    from argon2.exceptions import VerifyMismatchError  # type: ignore
    _ph = PasswordHasher()
except Exception:  # noqa: BLE001
    _ph = None
    VerifyMismatchError = Exception  # type: ignore


def _pepper() -> str:
    return settings.key_pepper or (_DEV_PEPPER if settings.offline else "")


def _hmac_key(secret: str, pepper: str) -> str:
    return hmac.new(pepper.encode(), secret.encode(), hashlib.sha256).hexdigest()


def hash_secret(secret: str) -> str:
    """Hash an API key for storage.

    API keys are 192-bit random tokens, so a fast keyed HMAC (peppered with a
    server secret) is the correct choice — a slow password KDF on every request
    is a self-inflicted DoS (surfaced by the load test). Falls back to argon2/
    PBKDF2 only if no pepper is available at all.
    """
    pepper = _pepper()
    if pepper:
        return "hmac$sha256$" + _hmac_key(secret, pepper)
    if _ph is not None:
        return "argon2$" + _ph.hash(secret)
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_secret(secret: str, stored: str) -> bool:
    try:
        scheme, rest = stored.split("$", 1)
    except ValueError:
        return False
    if scheme == "hmac":
        pepper = _pepper()
        if not pepper:
            return False
        _algo, expected = rest.split("$", 1)
        return hmac.compare_digest(_hmac_key(secret, pepper), expected)
    if scheme == "argon2":
        if _ph is None:
            return False
        try:
            return _ph.verify(rest, secret)
        except VerifyMismatchError:
            return False
        except Exception:  # noqa: BLE001
            return False
    if scheme == "pbkdf2":
        try:
            rounds_s, salt_hex, hash_hex = rest.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", secret.encode(),
                                     bytes.fromhex(salt_hex), int(rounds_s))
            return hmac.compare_digest(dk.hex(), hash_hex)
        except (ValueError, TypeError):
            return False
    return False


@dataclass
class Principal:
    key_id: str
    tenant_id: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def can_write_policy(self) -> bool:
        return self.role in {"admin", "analyst"}


# Raw keys are formatted "<key_id>.<secret>" so we can look up the record without
# scanning, then verify the secret against the stored hash in constant time.
def issue_key(tenant_id: str, role: str = "analyst",
              store: InMemoryStore | None = None) -> tuple[str, ApiKey]:
    store = store or get_store()
    key_id = "ak_" + secrets.token_hex(6)
    secret = secrets.token_urlsafe(24)
    record = ApiKey(key_id=key_id, tenant_id=tenant_id,
                    hashed_secret=hash_secret(secret), role=role)
    store.put_key(record)
    return f"{key_id}.{secret}", record


def rotate_key(old_key_id: str, store: InMemoryStore | None = None) -> tuple[str, ApiKey]:
    store = store or get_store()
    old = store.get_key(old_key_id)
    if not old:
        raise KeyError(old_key_id)
    raw, new = issue_key(old.tenant_id, old.role, store)
    new.rotated_from = old_key_id
    store.put_key(new)
    store.deactivate_key(old_key_id)
    return raw, new


def authenticate(raw_key: str, store: InMemoryStore | None = None) -> Principal | None:
    store = store or get_store()
    if not raw_key or "." not in raw_key:
        return None
    key_id, secret = raw_key.split(".", 1)
    record = store.get_key(key_id)
    if not record or not record.active:
        return None
    if not verify_secret(secret, record.hashed_secret):
        return None
    return Principal(key_id=record.key_id, tenant_id=record.tenant_id, role=record.role)


def verify_admin(admin_key: str) -> bool:
    """Separate admin key for privileged endpoints (S10). Constant-time compare."""
    expected = settings.admin_api_key or os.getenv("AEGIS_ADMIN_API_KEY", "")
    if not expected:
        return False
    return hmac.compare_digest(admin_key or "", expected)


def bootstrap_default_tenants(store: InMemoryStore | None = None) -> dict[str, str]:
    """Create demo tenants + keys for offline runs. Returns {name: raw_key}."""
    store = store or get_store()
    out: dict[str, str] = {}
    for tenant_id, fail_mode in (("acme-highsec", "closed"), ("beta-lowsec", "open")):
        store.put_tenant(Tenant(tenant_id=tenant_id, name=tenant_id, fail_mode=fail_mode))
        raw, _ = issue_key(tenant_id, role="analyst", store=store)
        out[tenant_id] = raw
    return out
