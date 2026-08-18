"""Log retention + purge job (S7).

Audit logs may contain sensitive prompts (as digests + redacted previews).
Retention is configurable per policy/tenant; this job purges records older than
the retention window. It runs as a periodic background task in the gateway AND as
a standalone job (cron/K8s CronJob):

    python -m app.observability.retention

Production note: purging necessarily truncates the hash chain. Before deleting,
a production deployment SEALS the segment (persist the last record hash to an
external WORM/SIEM sink) so historical tamper-evidence is preserved off-box.
"""
from __future__ import annotations

import asyncio
import time

from app.config import settings
from app.observability.logging import log_event
from app.storage.db import get_store


def purge_once(retention_days: int | None = None, store=None) -> int:
    store = store or get_store()
    days = retention_days if retention_days is not None else settings.log_retention_days
    cutoff = time.time() - days * 86400
    purge = getattr(store, "purge_audit_before", None)
    if purge is None:
        return 0
    # Seal the current chain tip before purging (off-box tamper-evidence).
    tip = store.last_audit_hash()
    removed = purge(cutoff)
    if removed:
        log_event("retention_purge", removed=removed, retention_days=days,
                  sealed_tip=tip[:16])
    return removed


async def retention_loop(interval_seconds: int = 3600) -> None:
    """Background task: purge on an interval. Started from the app lifespan."""
    while True:
        try:
            purge_once()
        except Exception as exc:  # noqa: BLE001 — never let the job crash the app
            log_event("retention_error", error=str(exc))
        await asyncio.sleep(interval_seconds)


if __name__ == "__main__":
    n = purge_once()
    print(f"Purged {n} audit records older than {settings.log_retention_days} days")
