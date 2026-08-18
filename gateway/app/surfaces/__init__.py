"""AEGIS v2.1 surface modules — untrusted content that is not the user's prompt.

AEGIS v2.0 defends the *prompt* channel. Real deployments lose data through the
other channels: a web page the agent browses, a PDF it summarises, a chunk the
retriever returns, a memory it wrote last week, an argument it passes to a tool.
Each of those is an independent attack surface with its own extraction problem
and its own trust prior.

Modules
-------
    browser     rendered pages: hidden CSS, comments, attributes, SVG, scripts
    documents   PDF / DOCX / PPTX / XLSX / CSV / MD / XML / JSON / email
    rag         retrieved chunks: trust scoring, provenance, quarantine
    memory      persistent memory writes and recalls
    tools       function / MCP / shell / filesystem / HTTP call arguments
    agent       multi-agent role integrity and instruction propagation
    multimodal  image and audio side channels (metadata, OCR/ASR transcripts)

All of them share :mod:`app.surfaces.base` (segment extraction -> pipeline
layers -> data-channel fusion) and :mod:`app.surfaces.imperative` (the
instruction-in-data primitive).

Every module is independently switchable via ``AEGIS_SURFACE_<NAME>=0``. When a
module is off it returns a ``SurfaceResult`` with ``enabled=False`` and an ALLOW
verdict, so callers need no conditional logic and the audit trail still records
that the layer was skipped. Backward compatibility is total: none of this runs
unless a caller invokes it or posts to one of the additive ``/aegis/*`` routes.
"""
from __future__ import annotations

from app.config import settings
from app.surfaces.base import (
    Segment,
    SurfaceFinding,
    SurfaceResult,
    assess_segment,
    disabled,
    scan_segments,
)

__all__ = [
    "Segment",
    "SurfaceFinding",
    "SurfaceResult",
    "assess_segment",
    "disabled",
    "scan_segments",
    "enabled",
    "status",
    "SURFACE_NAMES",
]

SURFACE_NAMES = (
    "browser", "documents", "rag", "memory", "tools", "agent", "multimodal",
)


def enabled(name: str) -> bool:
    """Is this surface switched on? Unknown names are treated as off."""
    return name in SURFACE_NAMES and settings.surfaces.enabled(name)


def status() -> dict[str, bool]:
    """Enable/disable map, surfaced on the admin API and in forensics records."""
    return {name: enabled(name) for name in SURFACE_NAMES}
