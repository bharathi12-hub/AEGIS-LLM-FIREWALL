"""Production preflight security gate.

A security appliance must refuse to start with insecure configuration. When
``AEGIS_OFFLINE=0`` (i.e. a real deployment), ``assert_production_safe`` aborts
startup on any FATAL misconfiguration — a weak/missing admin key, wildcard CORS,
fail-open default, missing audit encryption, demo bootstrap left on, or a
non-durable store. This turns "secure by default" into "cannot boot insecurely".

Offline/dev runs skip the gate (they are allowed relaxed defaults).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.config import Settings, settings

# Obvious placeholder/demo values that must never reach production.
_WEAK_SECRETS = {
    "", "change-me", "change-me-admin-key", "test-admin-key",
    "change-me-64-char-random-admin-key", "admin", "password", "secret",
}


@dataclass
class PreflightReport:
    fatal: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.fatal


def evaluate(cfg: Settings | None = None) -> PreflightReport:
    cfg = cfg or settings
    r = PreflightReport()
    if cfg.offline:
        # Dev/offline: everything is advisory.
        return r

    # --- FATAL: would materially weaken the security posture ---
    if not cfg.admin_api_key or cfg.admin_api_key in _WEAK_SECRETS:
        r.fatal.append("AEGIS_ADMIN_API_KEY is missing or a known weak/demo value")
    elif len(cfg.admin_api_key) < 24:
        r.fatal.append("AEGIS_ADMIN_API_KEY too short (< 24 chars)")

    if "*" in cfg.cors_origins:
        r.fatal.append("AEGIS_CORS_ORIGINS is a wildcard '*' — lock to the dashboard origin")

    if cfg.default_fail_mode != "closed":
        r.fatal.append("AEGIS_DEFAULT_FAIL_MODE is not 'closed' in production")

    if not cfg.database_url:
        r.fatal.append("no AEGIS_DATABASE_URL — production requires a durable store")

    import os
    if os.getenv("AEGIS_BOOTSTRAP", "1") == "1":
        r.fatal.append("AEGIS_BOOTSTRAP is on — demo tenants/keys would be seeded in prod")

    # --- WARNINGS: strongly recommended, not strictly fatal ---
    if not cfg.audit_encryption_key:
        r.warnings.append("AEGIS_AUDIT_KEY unset — audit meta stored unencrypted at rest")
    if not cfg.redis_url:
        r.warnings.append("no AEGIS_REDIS_URL — rate limits/budgets are per-process, "
                          "not shared across replicas")
    if not cfg.key_pepper:
        r.warnings.append("no AEGIS_KEY_PEPPER — API-key verification falls back to a "
                          "slow password KDF per request (throughput hit)")
    if cfg.response_floor_ms <= 0:
        r.warnings.append("AEGIS_RESPONSE_FLOOR_MS is 0 — timing side-channel undefended (S9)")
    if not cfg.redact_pii_in_logs:
        r.warnings.append("AEGIS_REDACT_PII disabled — PII may be retained in audit previews")
    return r


class InsecureConfigError(RuntimeError):
    pass


def assert_production_safe(cfg: Settings | None = None) -> PreflightReport:
    report = evaluate(cfg)
    if not report.ok:
        raise InsecureConfigError(
            "AEGIS refuses to start with insecure production config:\n  - "
            + "\n  - ".join(report.fatal))
    return report
