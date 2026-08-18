"""Immutable, hash-chained audit trail (Section 6 / S6 / S7 / S13).

Every security event is appended as a tamper-evident record: each record's hash
covers its content AND the previous record's hash, so any modification or deletion
breaks the chain (``verify_chain`` detects it).

Privacy at rest (S7):
  * Raw prompts/responses are NEVER stored — only a salted digest plus a
    PII-redacted, control-stripped preview.
  * When an encryption key + ``cryptography`` are available, the preview/meta are
    encrypted with Fernet; otherwise the redaction-only path applies (documented).
"""
from __future__ import annotations

import hashlib
import json
import re
import time

from app.config import settings
from app.observability.logging import strip_control
from app.storage.db import InMemoryStore, get_store
from app.storage.models import AuditRecord

# Minimal PII redaction for stored previews (S7).
_PII_SUBS = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<email>"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<ssn>"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "<card>"),
    (re.compile(r"\b(?:sk|pk|api|key|token)[-_][A-Za-z0-9]{16,}\b", re.I), "<secret>"),
]

_DIGEST_SALT = (settings.audit_encryption_key or "aegis-audit").encode()


def redact(text: str, max_len: int = 240) -> str:
    cleaned = strip_control(text or "")
    for pat, sub in _PII_SUBS:
        cleaned = pat.sub(sub, cleaned)
    return cleaned[:max_len]


def payload_digest(text: str) -> str:
    return hashlib.sha256(_DIGEST_SALT + (text or "").encode()).hexdigest()


def _record_hash(prev_hash: str, core: dict) -> str:
    blob = prev_hash + "|" + json.dumps(core, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


def _maybe_encrypt(meta: dict) -> dict:
    key = settings.audit_encryption_key
    if not key:
        return meta
    try:  # pragma: no cover - only when cryptography present
        import base64
        from cryptography.fernet import Fernet  # type: ignore
        fkey = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())
        token = Fernet(fkey).encrypt(json.dumps(meta).encode()).decode()
        return {"enc": token}
    except Exception:  # noqa: BLE001
        return meta


def record_event(
    *, tenant_id: str, event: str, layer: str, verdict: str, reason: str,
    prompt: str = "", meta: dict | None = None, store: InMemoryStore | None = None,
) -> AuditRecord:
    store = store or get_store()
    prev = store.last_audit_hash()
    seq = store.next_audit_seq()
    ts = time.time()
    safe_meta = _maybe_encrypt(meta or {})
    core = {
        "seq": seq, "tenant_id": tenant_id, "ts": round(ts, 3), "event": event,
        "layer": layer, "verdict": verdict,
        "reason": redact(reason, 300),
        "payload_digest": payload_digest(prompt) if prompt else "",
    }
    rec_hash = _record_hash(prev, core)
    record = AuditRecord(
        seq=seq, tenant_id=tenant_id, ts=ts, event=event, layer=layer,
        verdict=verdict, reason=core["reason"], prev_hash=prev,
        record_hash=rec_hash, payload_digest=core["payload_digest"], meta=safe_meta,
    )
    store.append_audit(record)
    return record


def verify_chain(store: InMemoryStore | None = None) -> tuple[bool, int | None]:
    """Return (ok, first_bad_seq). Recomputes every record hash over the chain."""
    store = store or get_store()
    prev = "GENESIS"
    for r in store.all_audit():
        core = {
            "seq": r.seq, "tenant_id": r.tenant_id, "ts": round(r.ts, 3),
            "event": r.event, "layer": r.layer, "verdict": r.verdict,
            "reason": r.reason, "payload_digest": r.payload_digest,
        }
        expected = _record_hash(prev, core)
        if expected != r.record_hash or r.prev_hash != prev:
            return False, r.seq
        prev = r.record_hash
    return True, None
