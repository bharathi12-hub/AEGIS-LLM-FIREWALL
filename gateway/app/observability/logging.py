"""Structured logging + untrusted-text handling (S6 / R10).

All captured prompt/response text is UNTRUSTED. It is stored raw only as a digest,
and whenever a value derived from user input is logged or rendered it is passed
through ``sanitize_for_render``: control characters stripped, HTML-escaped. This
prevents log/dashboard injection (stored XSS) and terminal escape abuse.
"""
from __future__ import annotations

import html
import json
import re
import sys
import time

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def strip_control(text: str) -> str:
    return _CONTROL_RE.sub("", text or "")


def sanitize_for_render(text: str, max_len: int = 2000) -> str:
    """Make untrusted text safe to render in HTML/logs (S6)."""
    cleaned = strip_control(text or "")
    escaped = html.escape(cleaned, quote=True)
    return escaped[:max_len]


def log_event(event: str, **fields) -> None:
    """Emit a single-line JSON log record with sanitized string values."""
    safe_fields = {}
    for k, v in fields.items():
        safe_fields[k] = sanitize_for_render(v, 500) if isinstance(v, str) else v
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event, **safe_fields}
    sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
